// Resume planning: for each file determines whether to skip, resume mid-file, or
// reprocess, using inode, size, mtime, and head fingerprints to identify files.

use std::io::{BufRead, BufReader, Read};

use super::*;
use crate::compression::CompressionType;
use crate::database::ParseState;
use crate::fingerprint::{
    compute_compressed_head_fingerprint, compute_decompressed_head_fingerprint,
};

// ── types ─────────────────────────────────────────────────────────────────────

/// All fingerprints relevant to a file, computed once up-front before any
/// branching.  `None` means the value is unknown (not applicable for this
/// compression type, or the file is too new to have a stored value).
#[derive(Debug, Clone, Copy, Default)]
struct Fingerprints {
    compressed_head: Option<u64>,
    uncompressed_head: Option<u64>,
    /// Zero for compressed files whose size is not yet known (we only read the
    /// raw compressed bytes in phase-1).
    uncompressed_size: u64,
}

/// What happened to this file relative to the stored parse state.
///
/// Variants are ordered from "most certain" to "least certain".  The
/// `classify_relation` function returns the first variant that matches.
#[derive(Debug, PartialEq, Eq)]
enum FileRelation {
    /// Inode, size, mtime, and fingerprints all match a completed record.
    /// Nothing to do.
    Identical,

    /// Different path on disk, but the content is the same completed file.
    AliasPath,

    /// A plain file that has grown since last seen (same head fingerprint,
    /// same inode or explicit head match, larger size).
    PlainExtended,

    /// A compressed file that has grown (same compressed head, same inode,
    /// larger compressed size).
    CompressedExtended,

    /// Was a plain file; now appears as a compressed file with the same
    /// content prefix (logrotate rename + gzip, same or different inode).
    RotatedPlainToGz,

    /// No direct inode/path match, but the same head fingerprint exists in a
    /// prior state.  The `u64` is the offset to resume from.
    HeadMatch(u64),

    /// No usable prior state.  Start from byte zero.
    Unrelated,
}

/// The resume action derived from a `FileRelation`.
#[derive(Debug, PartialEq, Eq)]
enum ResumePoint {
    /// File is fully processed; emit a skip record if the path changed.
    Skip,
    /// Read a plain file starting at this byte offset.
    PlainOffset(u64),
    /// Decompress the whole file but discard the first N decoded bytes.
    DecodedOffset(u64),
    /// (Re)process from the beginning.
    FromZero,
}

// ── public entry point ────────────────────────────────────────────────────────

/// Read the first parseable log line from `filepath` and return its Unix timestamp.
/// Returns `None` if the file cannot be opened, decompressed, or parsed.
pub(super) fn read_first_line_ts(filepath: &str) -> Option<i64> {
    let compression = CompressionType::from_path(filepath);
    let file = std::fs::File::open(filepath).ok()?;
    let limited = file.take(8192);

    let reader: Box<dyn Read> = match compression {
        CompressionType::Plain => Box::new(limited),
        CompressionType::Gz => Box::new(flate2::read::MultiGzDecoder::new(limited)),
        CompressionType::Bz2 => Box::new(bzip2::read::MultiBzDecoder::new(limited)),
        CompressionType::Br => Box::new(brotli::Decompressor::new(limited, 8192)),
    };

    let mut buf_reader = BufReader::new(reader);
    let mut line = String::new();
    for _ in 0..20 {
        line.clear();
        match buf_reader.read_line(&mut line) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
        if let Some(entry) = crate::parser::combined::parse_line(trimmed.to_string()) {
            return crate::parser::combined::parse_unix_timestamp(
                entry.time_str(),
                entry.month_num,
            );
        }
    }
    None
}

// ── ResolutionOutcome constructors ────────────────────────────────────────────

impl ResolutionOutcome {
    fn skip(
        skipped_parse_state: Option<ParseStateUpdate>,
        retired_parse_states: Vec<ParseStateUpdate>,
    ) -> Self {
        Self {
            plan: None,
            skipped_parse_state,
            retired_parse_states,
        }
    }

    fn resume(plan: FileResumePlan, retired_parse_states: Vec<ParseStateUpdate>) -> Self {
        Self {
            plan: Some(plan),
            skipped_parse_state: None,
            retired_parse_states,
        }
    }
}

// ── Processor impl ────────────────────────────────────────────────────────────

impl Processor {
    // ── cheap fast-path ───────────────────────────────────────────────────────

    /// Fast per-file pre-check: stat + 2 DB queries + in-memory comparison only.
    /// Returns `Some(outcome)` (plan=None) if inode+size+mtime match the stored
    /// completed state; `None` if a full resolve is needed.
    /// No file I/O beyond stat().
    pub(super) fn resolve_cheap(&mut self, filepath: &str) -> Result<Option<ResolutionOutcome>> {
        let meta = std::fs::metadata(filepath)?;
        let current_inode = meta.ino();
        let stat_size = meta.len();
        let mtime_ns = meta.mtime().saturating_mul(1_000_000_000) + meta.mtime_nsec();
        let compression = CompressionType::from_path(filepath);
        let is_compressed = compression.is_compressed();

        let state_by_path = self.db.get_parse_state(filepath)?;
        let state_by_inode = self.db.get_parse_state_by_inode(current_inode)?;
        let retired = collect_retired_states(
            &state_by_path,
            &state_by_inode,
            current_inode,
            stat_size,
            is_compressed,
            filepath,
        );

        let state = match choose_primary_state(
            state_by_path.as_ref(),
            state_by_inode.as_ref(),
            current_inode,
        ) {
            Some(s) => s,
            None => return Ok(None),
        };

        if !metadata_exact_match(state, current_inode, stat_size, mtime_ns, is_compressed) {
            return Ok(None);
        }

        let skipped = alias_update(
            state,
            filepath,
            current_inode,
            mtime_ns,
            compression,
            stat_size,
        );
        Ok(Some(ResolutionOutcome::skip(skipped, retired)))
    }

    // ── full resolve ──────────────────────────────────────────────────────────

    pub(super) fn resolve_resume_plan(&mut self, filepath: &str) -> Result<ResolutionOutcome> {
        // ── 1. gather context ─────────────────────────────────────────────────
        let meta = std::fs::metadata(filepath)?;
        let current_inode = meta.ino();
        let stat_size = meta.len();
        let mtime_ns = meta.mtime().saturating_mul(1_000_000_000) + meta.mtime_nsec();
        let compression = CompressionType::from_path(filepath);
        let is_compressed = compression.is_compressed();

        let state_by_path = self.db.get_parse_state(filepath)?;
        let state_by_inode = self.db.get_parse_state_by_inode(current_inode)?;
        let retired = collect_retired_states(
            &state_by_path,
            &state_by_inode,
            current_inode,
            stat_size,
            is_compressed,
            filepath,
        );

        // Inode changed but path record still exists (e.g. file was recreated).
        let inode_changed_for_path = state_by_path
            .as_ref()
            .map(|s| s.inode != current_inode)
            .unwrap_or(false);

        let primary = choose_primary_state(
            state_by_path.as_ref(),
            state_by_inode.as_ref(),
            current_inode,
        );

        // ── 2. metadata fast-path ─────────────────────────────────────────────
        if let Some(state) = primary {
            if metadata_exact_match(state, current_inode, stat_size, mtime_ns, is_compressed) {
                let skipped = alias_update(
                    state,
                    filepath,
                    current_inode,
                    mtime_ns,
                    compression,
                    stat_size,
                );
                return Ok(ResolutionOutcome::skip(skipped, retired));
            }
        }

        // ── 3. compute fingerprints ───────────────────────────────────────────
        let fps = self.compute_fingerprints(
            filepath,
            compression,
            is_compressed,
            primary,
            current_inode == primary.map(|s| s.inode).unwrap_or(0),
        )?;

        // ── 4. compressed fast-path (no decompression) ────────────────────────
        if let Some(state) = primary {
            if is_compressed {
                let same_inode = state.inode == current_inode;
                if state.completed
                    && same_inode
                    && (state.mtime_ns == 0 || state.mtime_ns == mtime_ns)
                    && state.compressed_size == stat_size
                    && state.compressed_head_fingerprint == fps.compressed_head
                {
                    let skipped = alias_update_with_fps(
                        state,
                        filepath,
                        current_inode,
                        mtime_ns,
                        compression,
                        stat_size,
                        &fps,
                    );
                    return Ok(ResolutionOutcome::skip(skipped, retired));
                }
            }
        }

        // ── 5. head-fingerprint fallback lookup ───────────────────────────────
        // Only when there is no direct path/inode match, or when the inode changed
        // (rotation/rename).  Direct inode matches are authoritative; a fingerprint
        // lookup would false-positive on the plain→gz rotation case.
        let head_match_state = if state_by_path.is_none() && state_by_inode.is_none() {
            self.find_head_match_state(is_compressed, fps.compressed_head, fps.uncompressed_head)?
        } else if inode_changed_for_path {
            self.find_head_match_state(is_compressed, fps.compressed_head, fps.uncompressed_head)?
        } else {
            None
        };

        // ── 6. classify the relationship ──────────────────────────────────────
        let relation = classify_relation(
            primary,
            head_match_state.as_ref(),
            filepath,
            current_inode,
            stat_size,
            mtime_ns,
            is_compressed,
            inode_changed_for_path,
            &fps,
        );

        // ── 7. global dedup check (before deriving action) ───────────────────
        //
        // Skip this when we have a direct inode-based match on a growing file —
        // the inode state is authoritative and the cross-format head check would
        // false-positive on the rotation case (plain file completed, then
        // rotated+compressed on same inode).
        let skip_global_dedup = state_by_path
            .as_ref()
            .map(|s| {
                let prev = if is_compressed {
                    s.compressed_size
                } else {
                    s.uncompressed_size
                };
                s.inode == current_inode && stat_size > prev
            })
            .unwrap_or(false)
            || state_by_inode.is_some() && !inode_changed_for_path;

        if !skip_global_dedup {
            if let Some(outcome) = self.check_global_dedup(
                filepath,
                current_inode,
                stat_size,
                mtime_ns,
                compression,
                is_compressed,
                &fps,
                &retired,
            )? {
                return Ok(outcome);
            }
        }

        // ── 8. derive resume action ───────────────────────────────────────────
        let skip_before_ts = state_by_path
            .as_ref()
            .and_then(|s| s.skip_before_ts)
            .or_else(|| state_by_inode.as_ref().and_then(|s| s.skip_before_ts));

        let resume_point = derive_resume_point(
            &relation,
            primary,
            head_match_state.as_ref(),
            stat_size,
            is_compressed,
        );

        match resume_point {
            ResumePoint::Skip => {
                let skipped = alias_update_with_fps(
                    primary.unwrap(),
                    filepath,
                    current_inode,
                    mtime_ns,
                    compression,
                    stat_size,
                    &fps,
                );
                Ok(ResolutionOutcome::skip(skipped, retired))
            }
            ResumePoint::PlainOffset(offset) => Ok(ResolutionOutcome::resume(
                FileResumePlan {
                    current_inode,
                    stat_size,
                    mtime_ns,
                    compression,
                    offset,
                    skip_decoded_prefix_bytes: 0,
                    uncompressed_size: Some(fps.uncompressed_size),
                    compressed_head_fingerprint: fps.compressed_head,
                    uncompressed_head_fingerprint: fps.uncompressed_head,
                    skip_before_ts,
                },
                retired,
            )),
            ResumePoint::DecodedOffset(prefix) => Ok(ResolutionOutcome::resume(
                FileResumePlan {
                    current_inode,
                    stat_size,
                    mtime_ns,
                    compression,
                    offset: 0,
                    skip_decoded_prefix_bytes: prefix,
                    uncompressed_size: Some(fps.uncompressed_size),
                    compressed_head_fingerprint: fps.compressed_head,
                    uncompressed_head_fingerprint: fps.uncompressed_head,
                    skip_before_ts,
                },
                retired,
            )),
            ResumePoint::FromZero => Ok(ResolutionOutcome::resume(
                FileResumePlan {
                    current_inode,
                    stat_size,
                    mtime_ns,
                    compression,
                    offset: 0,
                    skip_decoded_prefix_bytes: 0,
                    uncompressed_size: Some(fps.uncompressed_size),
                    compressed_head_fingerprint: fps.compressed_head,
                    uncompressed_head_fingerprint: fps.uncompressed_head,
                    skip_before_ts,
                },
                retired,
            )),
        }
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /// Compute all fingerprints using the minimum I/O required for the
    /// compression type and inode relationship.
    ///
    /// Strategy (preserves original phase-1 semantics):
    /// - Compressed, same inode:  reuse stored uncompressed values; read only the
    ///   compressed head (8 KB raw).
    /// - Compressed, new/changed inode:  read compressed head + 8 KB decompressed
    ///   head only; never do a full decompression here.
    /// - Plain files:  compute from the file (cheap sequential read).
    fn compute_fingerprints(
        &self,
        filepath: &str,
        compression: CompressionType,
        is_compressed: bool,
        primary_state: Option<&ParseState>,
        same_inode: bool,
    ) -> Result<Fingerprints> {
        if is_compressed {
            let compressed_head = compute_compressed_head_fingerprint(filepath)?;

            let (uncompressed_size, uncompressed_head) = if same_inode {
                // Reuse stored values — avoids all decompression.
                let size = primary_state.map(|s| s.uncompressed_size).unwrap_or(0);
                let head = primary_state.and_then(|s| s.uncompressed_head_fingerprint);
                (size, head)
            } else {
                // Only 8 KB of decompression needed for the head fingerprint.
                let head = compute_decompressed_head_fingerprint(filepath, compression)?;
                (0u64, head)
            };

            Ok(Fingerprints {
                compressed_head,
                uncompressed_head,
                uncompressed_size,
            })
        } else {
            let fingerprints = compute_fingerprints(filepath)?;
            Ok(Fingerprints {
                compressed_head: None,
                uncompressed_size: fingerprints.as_ref().map(|fp| fp.logical_size).unwrap_or(0),
                uncompressed_head: fingerprints.as_ref().map(|fp| fp.head),
            })
        }
    }

    /// Look up a prior parse state by head fingerprint.
    ///
    /// For compressed files, prefers an exact compressed-head match; falls back
    /// to uncompressed head so that a plain-file record (in-progress or
    /// completed) can seed the resume offset when the same content later appears
    /// as a gz.
    fn find_head_match_state(
        &mut self,
        is_compressed: bool,
        compressed_head: Option<u64>,
        uncompressed_head: Option<u64>,
    ) -> Result<Option<ParseState>> {
        if is_compressed {
            if let Some(fp) = compressed_head {
                let found = self
                    .db
                    .find_parse_state_by_compressed_head_fingerprint(fp)?;
                if found.is_some() {
                    return Ok(found);
                }
            }
        }
        // Plain files, or compressed files with no compressed-head match:
        // check uncompressed head to find prior plain-file records for the same content.
        if let Some(fp) = uncompressed_head {
            return Ok(self
                .db
                .find_parse_state_by_uncompressed_head_fingerprint(fp)?);
        }
        Ok(None)
    }

    /// Check the global dedup tables and return a `ResolutionOutcome` if the
    /// file is already fully covered by a completed record elsewhere.
    ///
    /// For compressed files, a cross-format match (plain→gz same content) sets
    /// `skip_decoded_prefix_bytes` rather than returning a full skip, because
    /// the gz may have grown past the completed plain-file size.
    fn check_global_dedup(
        &mut self,
        filepath: &str,
        current_inode: u64,
        stat_size: u64,
        mtime_ns: i64,
        compression: CompressionType,
        is_compressed: bool,
        fps: &Fingerprints,
        retired: &[ParseStateUpdate],
    ) -> Result<Option<ResolutionOutcome>> {
        if is_compressed {
            // Exact compressed identity (same raw bytes).
            if let Some(head_fp) = fps.compressed_head {
                if let Some(matched_uncompressed_size) = self
                    .db
                    .find_completed_by_compressed_identity(head_fp, stat_size)?
                {
                    return Ok(Some(ResolutionOutcome::skip(
                        Some(self.completed_parse_state_update(
                            filepath,
                            current_inode,
                            compression,
                            stat_size,
                            matched_uncompressed_size,
                            fps.compressed_head,
                            fps.uncompressed_head,
                            mtime_ns,
                        )),
                        retired.to_vec(),
                    )));
                }
            }
            // Cross-format dedup: the dedup match updates skip_decoded_prefix_bytes
            // rather than doing a full skip, handled downstream by the caller via
            // the `HeadMatchComplete` relation — nothing to return here.
        } else if let Some(head_fp) = fps.uncompressed_head {
            if fps.uncompressed_size > 0
                && self
                    .db
                    .find_completed_by_uncompressed_identity(head_fp, fps.uncompressed_size)?
            {
                return Ok(Some(ResolutionOutcome::skip(
                    Some(self.completed_parse_state_update(
                        filepath,
                        current_inode,
                        compression,
                        stat_size,
                        fps.uncompressed_size,
                        fps.compressed_head,
                        fps.uncompressed_head,
                        mtime_ns,
                    )),
                    retired.to_vec(),
                )));
            }
        }
        Ok(None)
    }

    fn completed_parse_state_update(
        &self,
        filepath: &str,
        inode: u64,
        compression: CompressionType,
        stat_size: u64,
        uncompressed_size: u64,
        compressed_head_fingerprint: Option<u64>,
        uncompressed_head_fingerprint: Option<u64>,
        mtime_ns: i64,
    ) -> ParseStateUpdate {
        let is_compressed = compression.is_compressed();
        ParseStateUpdate {
            filepath: filepath.to_string(),
            inode,
            compressed_size: if is_compressed { stat_size } else { 0 },
            uncompressed_size,
            compressed_head_fingerprint: if is_compressed {
                compressed_head_fingerprint
            } else {
                None
            },
            uncompressed_head_fingerprint,
            compressed_offset: if is_compressed { stat_size } else { 0 },
            uncompressed_offset: uncompressed_size,
            mtime_ns,
            completed: true,
            earliest_ts: None,
            latest_ts: None,
        }
    }
}

// ── pure helper functions ─────────────────────────────────────────────────────

/// Choose the single best parse state to use as the canonical prior record.
///
/// Preference order:
/// 1. Path record whose inode still matches (most specific).
/// 2. Inode record (file renamed/rotated to a new path).
/// 3. Path record with a stale inode (file was recreated; we'll check head fp
///    separately to decide whether content matches).
fn choose_primary_state<'a>(
    by_path: Option<&'a ParseState>,
    by_inode: Option<&'a ParseState>,
    current_inode: u64,
) -> Option<&'a ParseState> {
    match (by_path, by_inode) {
        (Some(s), _) if s.inode == current_inode => Some(s),
        (_, Some(s)) => Some(s),
        (Some(s), None) => Some(s),
        (None, None) => None,
    }
}

/// True when the stored state is completed and all identity fields match,
/// meaning there is nothing new to process.
fn metadata_exact_match(
    state: &ParseState,
    current_inode: u64,
    stat_size: u64,
    mtime_ns: i64,
    is_compressed: bool,
) -> bool {
    state.completed
        && state.inode == current_inode
        && state.mtime_ns == mtime_ns
        && if is_compressed {
            state.compressed_offset >= stat_size && state.compressed_size == stat_size
        } else {
            state.uncompressed_offset >= stat_size && state.uncompressed_size == stat_size
        }
}

/// Collect parse states that are now stale and should be retired from the DB.
fn collect_retired_states(
    by_path: &Option<ParseState>,
    by_inode: &Option<ParseState>,
    current_inode: u64,
    stat_size: u64,
    is_compressed: bool,
    filepath: &str,
) -> Vec<ParseStateUpdate> {
    let mut retired = Vec::new();
    if let Some(state) = by_path.as_ref() {
        let previous_size = if is_compressed {
            state.compressed_size
        } else {
            state.uncompressed_size
        };
        if state.inode != current_inode || stat_size < previous_size {
            retired.push(state.into());
        }
    }
    if let Some(state) = by_inode.as_ref() {
        if state.filepath != filepath {
            retired.push(state.into());
        }
    }
    retired
}

/// Classify the relationship between the on-disk file and the stored state.
#[allow(clippy::too_many_arguments)]
fn classify_relation(
    primary: Option<&ParseState>,
    head_match: Option<&ParseState>,
    filepath: &str,
    current_inode: u64,
    stat_size: u64,
    mtime_ns: i64,
    is_compressed: bool,
    inode_changed_for_path: bool,
    fps: &Fingerprints,
) -> FileRelation {
    let Some(state) = primary else {
        // No prior record at all: check for a head-match seed.
        return head_match_relation(head_match, is_compressed);
    };

    let same_inode = state.inode == current_inode;

    // ── Identical (already checked via metadata in the fast path, but covers
    //    the plain-file fingerprint case where mtime was 0) ──────────────────
    if state.completed {
        if !is_compressed
            && state.uncompressed_size == stat_size
            && state.uncompressed_head_fingerprint == fps.uncompressed_head
            && (state.mtime_ns == 0 || state.mtime_ns == mtime_ns)
        {
            return if state.filepath == filepath {
                FileRelation::Identical
            } else {
                FileRelation::AliasPath
            };
        }
    }

    let prev_size = if is_compressed {
        state.compressed_size
    } else {
        state.uncompressed_size
    };

    // ── Rotated: was plain, now compressed, same content prefix ───────────────
    //    Detected by: is_compressed, stored compressed_size == 0 (was plain),
    //    and matching uncompressed head fingerprint.
    if is_compressed
        && state.compressed_size == 0
        && fps.uncompressed_head.is_some()
        && fps.uncompressed_head == state.uncompressed_head_fingerprint
        && state.uncompressed_offset > 0
    {
        return FileRelation::RotatedPlainToGz;
    }

    // ── In-progress compressed file (same inode, not yet complete) ────────────
    if is_compressed
        && !state.completed
        && same_inode
        && state.uncompressed_offset > 0
        && stat_size >= state.compressed_size
    {
        return FileRelation::CompressedExtended;
    }

    // ── In-progress plain file (same inode, same size, not yet complete) ────────
    // Covers the resume-after-interruption case where the file didn't grow.
    if !is_compressed
        && !state.completed
        && same_inode
        && stat_size == prev_size
        && state.uncompressed_offset > 0
    {
        return FileRelation::PlainExtended;
    }

    // ── File grew ─────────────────────────────────────────────────────────────
    if stat_size > prev_size && prev_size > 0 {
        if is_compressed {
            // Compressed extension: same head fingerprint implies same prefix.
            if same_inode
                || (state.uncompressed_head_fingerprint.is_some()
                    && state.uncompressed_head_fingerprint == fps.uncompressed_head
                    && state.uncompressed_offset > 0)
            {
                return FileRelation::CompressedExtended;
            }
        } else {
            // Plain extension: same head and inode (or no inode change).
            if !inode_changed_for_path
                || (state.uncompressed_head_fingerprint.is_some()
                    && state.uncompressed_head_fingerprint == fps.uncompressed_head)
            {
                return FileRelation::PlainExtended;
            }
        }
    }

    // ── File shrank or head changed: must restart ─────────────────────────────
    if stat_size < prev_size {
        return FileRelation::Unrelated;
    }
    if !is_compressed
        && state.uncompressed_head_fingerprint.is_some()
        && state.uncompressed_head_fingerprint != fps.uncompressed_head
    {
        return FileRelation::Unrelated;
    }

    // ── No direct match: fall back to head-match seed ─────────────────────────
    head_match_relation(head_match, is_compressed)
}

fn head_match_relation(head_match: Option<&ParseState>, _is_compressed: bool) -> FileRelation {
    match head_match {
        Some(s) if s.uncompressed_offset > 0 => FileRelation::HeadMatch(s.uncompressed_offset),
        _ => FileRelation::Unrelated,
    }
}

/// Convert a `FileRelation` into the concrete bytes to skip / seek to.
fn derive_resume_point(
    relation: &FileRelation,
    primary: Option<&ParseState>,
    _head_match: Option<&ParseState>,
    stat_size: u64,
    is_compressed: bool,
) -> ResumePoint {
    match relation {
        FileRelation::Identical => ResumePoint::Skip,
        FileRelation::AliasPath => ResumePoint::Skip,

        FileRelation::PlainExtended => {
            let offset = primary
                .map(|s| s.uncompressed_offset.min(stat_size))
                .unwrap_or(0);
            ResumePoint::PlainOffset(offset)
        }

        FileRelation::CompressedExtended => {
            let prefix = primary.map(|s| s.uncompressed_offset).unwrap_or(0);
            ResumePoint::DecodedOffset(prefix)
        }

        FileRelation::RotatedPlainToGz => {
            let prefix = primary.map(|s| s.uncompressed_offset).unwrap_or(0);
            ResumePoint::DecodedOffset(prefix)
        }

        FileRelation::HeadMatch(offset) => {
            if is_compressed {
                ResumePoint::DecodedOffset(*offset)
            } else {
                ResumePoint::PlainOffset((*offset).min(stat_size))
            }
        }

        FileRelation::Unrelated => ResumePoint::FromZero,
    }
}

// ── alias / skip update helpers ───────────────────────────────────────────────

/// If the stored path differs from `filepath`, return a `ParseStateUpdate`
/// that records the alias under the new path.  Otherwise returns `None`.
fn alias_update(
    state: &ParseState,
    filepath: &str,
    current_inode: u64,
    mtime_ns: i64,
    _compression: CompressionType,
    _stat_size: u64,
) -> Option<ParseStateUpdate> {
    (state.filepath != filepath).then(|| ParseStateUpdate {
        filepath: filepath.to_string(),
        inode: current_inode,
        compressed_size: state.compressed_size,
        uncompressed_size: state.uncompressed_size,
        compressed_head_fingerprint: state.compressed_head_fingerprint,
        uncompressed_head_fingerprint: state.uncompressed_head_fingerprint,
        compressed_offset: state.compressed_offset,
        uncompressed_offset: state.uncompressed_offset,
        mtime_ns,
        completed: true,
        earliest_ts: state.earliest_ts,
        latest_ts: state.latest_ts,
    })
}

/// Alias update that uses freshly computed fingerprints instead of stored ones.
fn alias_update_with_fps(
    state: &ParseState,
    filepath: &str,
    current_inode: u64,
    mtime_ns: i64,
    compression: CompressionType,
    stat_size: u64,
    fps: &Fingerprints,
) -> Option<ParseStateUpdate> {
    (state.filepath != filepath).then(|| {
        let is_compressed = compression.is_compressed();
        ParseStateUpdate {
            filepath: filepath.to_string(),
            inode: current_inode,
            compressed_size: if is_compressed { stat_size } else { 0 },
            uncompressed_size: state.uncompressed_size,
            compressed_head_fingerprint: fps.compressed_head,
            uncompressed_head_fingerprint: fps
                .uncompressed_head
                .or(state.uncompressed_head_fingerprint),
            compressed_offset: if is_compressed { stat_size } else { 0 },
            uncompressed_offset: state.uncompressed_offset,
            mtime_ns,
            completed: true,
            earliest_ts: state.earliest_ts,
            latest_ts: state.latest_ts,
        }
    })
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::read_first_line_ts;
    use super::{
        choose_primary_state, classify_relation, derive_resume_point, FileRelation, Fingerprints,
        ResumePoint,
    };
    use crate::database::ParseState;
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use tempfile::NamedTempFile;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn log_line(ts: &str) -> String {
        format!(r#"1.2.3.4 - - [{ts}] "GET /index.html HTTP/1.1" 200 100 "-" "Mozilla/5.0""#)
    }

    fn write_plain(lines: &[&str]) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        for line in lines {
            writeln!(f, "{line}").unwrap();
        }
        f
    }

    fn write_gz(lines: &[&str]) -> NamedTempFile {
        let f = NamedTempFile::with_suffix(".gz").unwrap();
        let mut enc = GzEncoder::new(f.reopen().unwrap(), Compression::default());
        for line in lines {
            writeln!(enc, "{line}").unwrap();
        }
        enc.finish().unwrap();
        f
    }

    fn make_test_processor(db: crate::database::Database) -> super::super::Processor {
        super::super::Processor::new(
            db,
            crate::geo::Geo::new(None),
            super::super::ProcessorConfig {
                top_n: 10,
                bot_filter: false,
                enable_top_urls: false,
                enable_top_sites: false,
                enable_top_refs: false,
                enable_top_agents: false,
                rule_set: None,
            },
        )
    }

    fn blank_state(filepath: &str, inode: u64) -> ParseState {
        ParseState {
            filepath: filepath.into(),
            inode,
            compressed_size: 0,
            uncompressed_size: 0,
            compressed_head_fingerprint: None,
            uncompressed_head_fingerprint: None,
            compressed_offset: 0,
            uncompressed_offset: 0,
            mtime_ns: 0,
            completed: false,
            earliest_ts: None,
            latest_ts: None,
            skip_before_ts: None,
        }
    }

    // ── read_first_line_ts ────────────────────────────────────────────────────

    #[test]
    fn plain_file_returns_correct_timestamp() {
        let line = log_line("01/Jan/1970:00:00:00 +0000");
        let f = write_plain(&[&line]);
        let ts = read_first_line_ts(f.path().to_str().unwrap());
        assert_eq!(ts, Some(0));
    }

    #[test]
    fn gz_file_returns_correct_timestamp() {
        let line = log_line("01/Jan/1970:01:00:00 +0100");
        let f = write_gz(&[&line]);
        let ts = read_first_line_ts(f.path().to_str().unwrap());
        assert_eq!(ts, Some(0));
    }

    #[test]
    fn nonexistent_file_returns_none() {
        assert_eq!(read_first_line_ts("/nonexistent/path/access.log"), None);
    }

    #[test]
    fn all_garbage_lines_returns_none() {
        let f = write_plain(&["not a log line", "also not a log line", "garbage"]);
        assert_eq!(read_first_line_ts(f.path().to_str().unwrap()), None);
    }

    #[test]
    fn skips_garbage_prefix_to_find_parseable_line() {
        let good = log_line("01/Jan/1970:00:00:42 +0000");
        let f = write_plain(&["junk", "more junk", &good]);
        let ts = read_first_line_ts(f.path().to_str().unwrap());
        assert_eq!(ts, Some(42));
    }

    #[test]
    fn stops_at_twenty_line_limit() {
        let garbage: Vec<String> = (0..21).map(|i| format!("garbage line {i}")).collect();
        let refs: Vec<&str> = garbage.iter().map(String::as_str).collect();
        let f = write_plain(&refs);
        assert_eq!(read_first_line_ts(f.path().to_str().unwrap()), None);
    }

    // ── choose_primary_state ──────────────────────────────────────────────────

    #[test]
    fn primary_prefers_path_with_matching_inode() {
        let by_path = blank_state("/log/a", 42);
        let by_inode = blank_state("/log/b", 42);
        let chosen = choose_primary_state(Some(&by_path), Some(&by_inode), 42).unwrap();
        assert_eq!(chosen.filepath, "/log/a");
    }

    #[test]
    fn primary_falls_back_to_inode_when_path_inode_stale() {
        let by_path = blank_state("/log/a", 99); // stale inode
        let by_inode = blank_state("/log/b", 42);
        let chosen = choose_primary_state(Some(&by_path), Some(&by_inode), 42).unwrap();
        assert_eq!(chosen.filepath, "/log/b");
    }

    #[test]
    fn primary_returns_none_when_no_state() {
        assert!(choose_primary_state(None, None, 1).is_none());
    }

    // ── classify_relation ─────────────────────────────────────────────────────

    fn fps(uncompressed_head: Option<u64>) -> Fingerprints {
        Fingerprints {
            compressed_head: None,
            uncompressed_head,
            uncompressed_size: 100,
        }
    }

    #[test]
    fn classifies_plain_extension_correctly() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_size = 50;
        state.uncompressed_offset = 50;
        state.uncompressed_head_fingerprint = Some(0xaaaa);

        let relation = classify_relation(
            Some(&state),
            None,
            "/log/a",
            1,   // same inode
            200, // grew
            0,
            false, // plain
            false,
            &fps(Some(0xaaaa)),
        );
        assert_eq!(relation, FileRelation::PlainExtended);
    }

    #[test]
    fn classifies_rotation_plain_to_gz() {
        let mut state = blank_state("/log/access.log", 5);
        state.compressed_size = 0; // was plain
        state.uncompressed_size = 50;
        state.uncompressed_offset = 50;
        state.uncompressed_head_fingerprint = Some(0xbbbb);
        state.completed = true;

        let relation = classify_relation(
            Some(&state),
            None,
            "/log/access.log-20240101.gz",
            5,
            999, // gz is larger
            0,
            true, // now compressed
            false,
            &Fingerprints {
                compressed_head: Some(0x1234),
                uncompressed_head: Some(0xbbbb), // same content prefix
                uncompressed_size: 0,
            },
        );
        assert_eq!(relation, FileRelation::RotatedPlainToGz);
    }

    #[test]
    fn classifies_shrunk_file_as_unrelated() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_size = 500;
        state.uncompressed_offset = 500;

        let relation = classify_relation(
            Some(&state),
            None,
            "/log/a",
            1,
            100, // shrank
            0,
            false,
            false,
            &fps(Some(0xcccc)),
        );
        assert_eq!(relation, FileRelation::Unrelated);
    }

    // ── derive_resume_point ───────────────────────────────────────────────────

    #[test]
    fn plain_extended_returns_correct_offset() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_offset = 77;

        let point =
            derive_resume_point(&FileRelation::PlainExtended, Some(&state), None, 200, false);
        assert_eq!(point, ResumePoint::PlainOffset(77));
    }

    #[test]
    fn compressed_extended_returns_decoded_offset() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_offset = 42;

        let point = derive_resume_point(
            &FileRelation::CompressedExtended,
            Some(&state),
            None,
            999,
            true,
        );
        assert_eq!(point, ResumePoint::DecodedOffset(42));
    }

    #[test]
    fn rotated_plain_to_gz_returns_decoded_offset() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_offset = 55;

        let point = derive_resume_point(
            &FileRelation::RotatedPlainToGz,
            Some(&state),
            None,
            999,
            true,
        );
        assert_eq!(point, ResumePoint::DecodedOffset(55));
    }

    #[test]
    fn unrelated_returns_from_zero() {
        let point = derive_resume_point(&FileRelation::Unrelated, None, None, 100, false);
        assert_eq!(point, ResumePoint::FromZero);
    }

    // ── rotation regression tests (integration) ───────────────────────────────
    //
    // Scenario: access.log (plain) was fully processed to N bytes, stored as
    // completed=true with compressed_size=0.  Overnight nginx kept writing, then
    // logrotate renamed+gzipped the file to access.log-YYYYMMDD.gz (same inode,
    // larger uncompressed content).
    //
    // Bug 1 (global-dedup false positive): find_completed_by_uncompressed_head_only
    //   matched the old plain-file record (same uncompressed head fingerprint,
    //   compressed_head IS NULL) and returned plan=None, silently skipping the gz.
    //
    // Bug 2 (missing skip prefix): even if the global dedup were suppressed, the
    //   skip_decoded_prefix_bytes was not set for the plain→compressed case
    //   (previous_size=compressed_size=0, so the else-if branch was dead).

    #[test]
    fn fresh_gz_with_in_progress_plain_head_match_resumes_from_plain_offset() {
        let gz_file = write_gz(&["line one", "line two", "line three"]);
        let gz_path = gz_file.path().to_str().unwrap().to_string();

        let gz_head_fp = crate::fingerprint::compute_decompressed_head_fingerprint(
            &gz_path,
            crate::compression::CompressionType::Gz,
        )
        .unwrap()
        .unwrap();

        let partial_offset = 20u64;
        let db = crate::database::Database::open(":memory:").unwrap();
        db.set_parse_state(&crate::database::ParseState {
            filepath: "/old/access.log".into(),
            inode: 0xdead_beef_0000_0002,
            compressed_size: 0,
            uncompressed_size: partial_offset,
            compressed_head_fingerprint: None,
            uncompressed_head_fingerprint: Some(gz_head_fp),
            compressed_offset: 0,
            uncompressed_offset: partial_offset,
            mtime_ns: 0,
            completed: false,
            earliest_ts: None,
            latest_ts: None,
            skip_before_ts: None,
        })
        .unwrap();

        let mut processor = make_test_processor(db);
        let outcome = processor.resolve_resume_plan(&gz_path).unwrap();
        let plan = outcome.plan.expect("gz should produce a resume plan");
        assert_eq!(
            plan.skip_decoded_prefix_bytes, partial_offset,
            "must resume from the in-progress plain file's offset, not reprocess from 0",
        );
    }

    #[test]
    fn fresh_gz_with_completed_plain_head_match_resumes_not_skips() {
        let gz_file = write_gz(&["line one", "line two", "line three"]);
        let gz_path = gz_file.path().to_str().unwrap().to_string();

        let gz_head_fp = crate::fingerprint::compute_decompressed_head_fingerprint(
            &gz_path,
            crate::compression::CompressionType::Gz,
        )
        .unwrap()
        .unwrap();

        let plain_completed_offset = 20u64;
        let db = crate::database::Database::open(":memory:").unwrap();
        db.set_parse_state(&crate::database::ParseState {
            filepath: "/old/access.log".into(),
            inode: 0xdead_beef_0000_0001,
            compressed_size: 0,
            uncompressed_size: plain_completed_offset,
            compressed_head_fingerprint: None,
            uncompressed_head_fingerprint: Some(gz_head_fp),
            compressed_offset: 0,
            uncompressed_offset: plain_completed_offset,
            mtime_ns: 0,
            completed: true,
            earliest_ts: None,
            latest_ts: None,
            skip_before_ts: None,
        })
        .unwrap();

        let mut processor = make_test_processor(db);
        let outcome = processor.resolve_resume_plan(&gz_path).unwrap();
        let plan = outcome.plan.expect(
            "gz with same head as completed plain file must produce a resume plan, not be skipped",
        );
        assert_eq!(
            plan.skip_decoded_prefix_bytes, plain_completed_offset,
            "must resume from the plain file's completed offset to avoid losing appended lines",
        );
    }

    #[test]
    fn rotation_plain_to_gz_same_inode_not_falsely_skipped() {
        let gz_file = write_gz(&["line one", "line two", "line three"]);
        let gz_path = gz_file.path().to_str().unwrap().to_string();
        let gz_inode = std::fs::metadata(&gz_path).unwrap().ino();

        let partial_offset = 50u64;
        let db = crate::database::Database::open(":memory:").unwrap();
        db.set_parse_state(&crate::database::ParseState {
            filepath: "/var/log/nginx/access.log".into(),
            inode: gz_inode,
            compressed_size: 0,
            uncompressed_size: partial_offset,
            compressed_head_fingerprint: None,
            uncompressed_head_fingerprint: Some(0xaabb_ccdd_eeff_0011),
            compressed_offset: 0,
            uncompressed_offset: partial_offset,
            mtime_ns: 1_748_000_000_000_000_000,
            completed: true,
            earliest_ts: None,
            latest_ts: None,
            skip_before_ts: None,
        })
        .unwrap();

        let mut processor = make_test_processor(db);
        let outcome = processor.resolve_resume_plan(&gz_path).unwrap();
        assert!(
            outcome.plan.is_some(),
            "rotated gz file must not be falsely skipped via uncompressed-head global dedup"
        );
    }

    #[test]
    fn rotation_plain_to_gz_same_inode_sets_skip_decoded_prefix() {
        let gz_file = write_gz(&["line one", "line two", "line three"]);
        let gz_path = gz_file.path().to_str().unwrap().to_string();
        let gz_inode = std::fs::metadata(&gz_path).unwrap().ino();

        let partial_offset = 50u64;
        let db = crate::database::Database::open(":memory:").unwrap();
        db.set_parse_state(&crate::database::ParseState {
            filepath: "/var/log/nginx/access.log".into(),
            inode: gz_inode,
            compressed_size: 0,
            uncompressed_size: partial_offset,
            compressed_head_fingerprint: None,
            uncompressed_head_fingerprint: Some(0xaabb_ccdd_eeff_0011),
            compressed_offset: 0,
            uncompressed_offset: partial_offset,
            mtime_ns: 1_748_000_000_000_000_000,
            completed: true,
            earliest_ts: None,
            latest_ts: None,
            skip_before_ts: None,
        })
        .unwrap();

        let mut processor = make_test_processor(db);
        let outcome = processor.resolve_resume_plan(&gz_path).unwrap();
        let plan = outcome
            .plan
            .expect("rotated gz file must produce a resume plan");
        assert_eq!(
            plan.skip_decoded_prefix_bytes, partial_offset,
            "must skip already-processed uncompressed bytes to avoid double-counting"
        );
    }

    // ── invariant: Identical / AliasPath always → Skip ────────────────────────

    fn completed_plain_state(filepath: &str, inode: u64, size: u64, head: u64) -> ParseState {
        let mut s = blank_state(filepath, inode);
        s.completed = true;
        s.uncompressed_size = size;
        s.uncompressed_offset = size;
        s.uncompressed_head_fingerprint = Some(head);
        s
    }

    #[test]
    fn same_filepath_completed_plain_classifies_as_identical() {
        // When the stored state path equals the current filepath, classify_relation
        // must return Identical (not AliasPath).
        let state = completed_plain_state("/log/a", 1, 100, 0xabcd);
        let relation = classify_relation(
            Some(&state),
            None,
            "/log/a", // same path
            1,
            100,
            0,
            false,
            false,
            &fps(Some(0xabcd)),
        );
        assert_eq!(relation, FileRelation::Identical);
        assert_eq!(
            derive_resume_point(&relation, Some(&state), None, 100, false),
            ResumePoint::Skip
        );
    }

    #[test]
    fn different_filepath_completed_plain_classifies_as_alias_path() {
        // When the stored state path differs from the current filepath (e.g. symlink
        // or hardlink), classify_relation must return AliasPath, not Identical.
        let state = completed_plain_state("/log/old-name", 1, 100, 0xabcd);
        let relation = classify_relation(
            Some(&state),
            None,
            "/log/new-name", // different path, same content
            1,
            100,
            0,
            false,
            false,
            &fps(Some(0xabcd)),
        );
        assert_eq!(relation, FileRelation::AliasPath);
        assert_eq!(
            derive_resume_point(&relation, Some(&state), None, 100, false),
            ResumePoint::Skip
        );
    }

    // ── invariant: extended relations never return FromZero ───────────────────

    #[test]
    fn plain_extended_never_from_zero() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_offset = 50;
        let point =
            derive_resume_point(&FileRelation::PlainExtended, Some(&state), None, 200, false);
        assert!(
            !matches!(point, ResumePoint::FromZero),
            "PlainExtended must not restart from zero"
        );
    }

    #[test]
    fn compressed_extended_never_from_zero() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_offset = 50;
        let point = derive_resume_point(
            &FileRelation::CompressedExtended,
            Some(&state),
            None,
            999,
            true,
        );
        assert!(
            !matches!(point, ResumePoint::FromZero),
            "CompressedExtended must not restart from zero"
        );
    }

    #[test]
    fn rotated_plain_to_gz_never_from_zero() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_offset = 100;
        let point = derive_resume_point(
            &FileRelation::RotatedPlainToGz,
            Some(&state),
            None,
            999,
            true,
        );
        assert!(
            !matches!(point, ResumePoint::FromZero),
            "RotatedPlainToGz must not restart from zero"
        );
    }

    // ── invariant: compressed relations never yield PlainOffset ───────────────

    #[test]
    fn compressed_extended_never_plain_offset() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_offset = 42;
        let point = derive_resume_point(
            &FileRelation::CompressedExtended,
            Some(&state),
            None,
            999,
            true,
        );
        assert!(
            !matches!(point, ResumePoint::PlainOffset(_)),
            "CompressedExtended must never yield PlainOffset"
        );
    }

    #[test]
    fn rotated_plain_to_gz_never_plain_offset() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_offset = 42;
        let point = derive_resume_point(
            &FileRelation::RotatedPlainToGz,
            Some(&state),
            None,
            999,
            true,
        );
        assert!(
            !matches!(point, ResumePoint::PlainOffset(_)),
            "RotatedPlainToGz must never yield PlainOffset"
        );
    }

    #[test]
    fn head_match_compressed_never_plain_offset() {
        let point =
            derive_resume_point(&FileRelation::HeadMatch(100), None, None, 999, true);
        assert!(
            !matches!(point, ResumePoint::PlainOffset(_)),
            "HeadMatch on a compressed file must never yield PlainOffset"
        );
    }

    // ── invariant: shrinking files never reuse offsets ────────────────────────

    #[test]
    fn plain_shrunk_file_classified_unrelated() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_size = 500;
        state.uncompressed_offset = 500;
        state.uncompressed_head_fingerprint = Some(0xaaaa);

        let relation = classify_relation(
            Some(&state),
            None,
            "/log/a",
            1,
            100, // shrank to 100
            0,
            false,
            false,
            &fps(Some(0xaaaa)),
        );
        assert_eq!(relation, FileRelation::Unrelated);
        let point = derive_resume_point(&relation, Some(&state), None, 100, false);
        assert_eq!(point, ResumePoint::FromZero);
    }

    #[test]
    fn compressed_shrunk_file_classified_unrelated() {
        let mut state = blank_state("/log/a", 1);
        state.compressed_size = 1000;
        state.uncompressed_offset = 5000;
        state.compressed_head_fingerprint = Some(0xbbbb);

        let relation = classify_relation(
            Some(&state),
            None,
            "/log/a",
            1,
            200, // compressed size shrank
            0,
            true,
            false,
            &Fingerprints {
                compressed_head: Some(0xbbbb),
                uncompressed_head: None,
                uncompressed_size: 0,
            },
        );
        assert_eq!(relation, FileRelation::Unrelated);
        let point = derive_resume_point(&relation, Some(&state), None, 200, true);
        assert_eq!(point, ResumePoint::FromZero);
    }

    // ── invariant: plain in-progress (same size, not complete) resumes ────────

    #[test]
    fn plain_in_progress_same_size_resumes_from_offset() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_size = 200;
        state.uncompressed_offset = 150;
        state.uncompressed_head_fingerprint = Some(0xcccc);

        let relation = classify_relation(
            Some(&state),
            None,
            "/log/a",
            1,   // same inode
            200, // same size as stored — file didn't grow
            0,
            false,
            false,
            &fps(Some(0xcccc)),
        );
        assert_eq!(relation, FileRelation::PlainExtended);
        let point = derive_resume_point(&relation, Some(&state), None, 200, false);
        assert_eq!(point, ResumePoint::PlainOffset(150));
    }

    // ── invariant: HeadMatch routes offset correctly by compression ───────────

    #[test]
    fn head_match_plain_yields_plain_offset() {
        let point = derive_resume_point(&FileRelation::HeadMatch(80), None, None, 200, false);
        assert_eq!(point, ResumePoint::PlainOffset(80));
    }

    #[test]
    fn head_match_compressed_yields_decoded_offset() {
        let point = derive_resume_point(&FileRelation::HeadMatch(80), None, None, 999, true);
        assert_eq!(point, ResumePoint::DecodedOffset(80));
    }

    // ── invariant: plain offset is clamped to stat_size ──────────────────────

    #[test]
    fn plain_extended_clamps_offset_to_stat_size() {
        let mut state = blank_state("/log/a", 1);
        state.uncompressed_offset = 999; // stored offset larger than current file size
        let point =
            derive_resume_point(&FileRelation::PlainExtended, Some(&state), None, 100, false);
        assert_eq!(point, ResumePoint::PlainOffset(100));
    }

    #[test]
    fn head_match_plain_clamps_offset_to_stat_size() {
        let point = derive_resume_point(&FileRelation::HeadMatch(500), None, None, 100, false);
        assert_eq!(point, ResumePoint::PlainOffset(100));
    }
}
