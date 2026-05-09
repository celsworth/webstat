use super::*;
use crate::database::ParseState;
use crate::compression::CompressionType;
use crate::fingerprint::{compute_compressed_head_fingerprint, compute_decompressed_head_fingerprint};

impl Processor {
    #[allow(clippy::too_many_arguments)]
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
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn skip_parse_state_update_for_alias(
        &self,
        state: &ParseState,
        filepath: &str,
        inode: u64,
        compression: CompressionType,
        stat_size: u64,
        uncompressed_size: u64,
        compressed_head_fingerprint: Option<u64>,
        uncompressed_head_fingerprint: Option<u64>,
        mtime_ns: i64,
    ) -> Option<ParseStateUpdate> {
        (state.filepath != filepath).then(|| {
            self.completed_parse_state_update(
                filepath,
                inode,
                compression,
                stat_size,
                uncompressed_size,
                compressed_head_fingerprint,
                uncompressed_head_fingerprint,
                mtime_ns,
            )
        })
    }

    pub(super) fn resolve_resume_plan(&mut self, filepath: &str) -> Result<ResolutionOutcome> {
        let meta = std::fs::metadata(filepath)?;
        let current_inode = meta.ino();
        let stat_size = meta.len();
        let mtime_ns = meta.mtime().saturating_mul(1_000_000_000) + meta.mtime_nsec();
        let compression = CompressionType::from_path(filepath);
        let is_compressed = compression.is_compressed();

        let state_by_path = self.db.get_parse_state(filepath)?;
        let state_by_inode = self.db.get_parse_state_by_inode(current_inode)?;

        let mut retired_parse_states = Vec::new();
        if let Some(state) = state_by_path.as_ref() {
            let previous_size = if is_compressed {
                state.compressed_size
            } else {
                state.uncompressed_size
            };
            if state.inode != current_inode || stat_size < previous_size {
                retired_parse_states.push(state.into());
            }
        }
        if let Some(state) = state_by_inode.as_ref() {
            if state.filepath != filepath {
                retired_parse_states.push(state.into());
            }
        }

        let (mut offset, state, inode_changed_for_path) =
            match (state_by_path.as_ref(), state_by_inode.as_ref()) {
                (Some(state), _) if state.inode == current_inode => {
                    let stored_offset = if is_compressed { 0 } else { state.uncompressed_offset };
                    (stored_offset, Some(state), false)
                }
                (_, Some(state)) => {
                    let stored_offset = if is_compressed { 0 } else { state.uncompressed_offset };
                    (stored_offset, Some(state), false)
                }
                (Some(state), None) => (0, Some(state), true),
                (None, None) => (0, None, false),
            };

        if let Some(state) = state {
            let metadata_exact_match = state.completed
                && state.inode == current_inode
                && if is_compressed {
                    state.compressed_offset >= stat_size && state.compressed_size == stat_size
                } else {
                    state.uncompressed_offset >= stat_size && state.uncompressed_size == stat_size
                }
                && state.mtime_ns == mtime_ns;
            if metadata_exact_match {
                return Ok(ResolutionOutcome {
                    plan: None,
                    skipped_parse_state: (state.filepath != filepath).then(|| ParseStateUpdate {
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
                    }),
                    retired_parse_states,
                });
            }
        }

        // Phase-1 fingerprinting strategy (zero full-decompression for compressed files):
        //
        // Compressed files (gz, bz2):
        //   - ALWAYS compute compressed head only (8KB raw read, ~microseconds)
        //   - Use compressed_head + compressed_size for ALL identity checks
        //   - Reuse DB-stored uncompressed fingerprints when same inode (no decompression)
        //   - Never decompress in phase-1 for compressed files
        //
        // Plain files:
        //   - Compute full fingerprints (cheap, sequential read, no decompression)

        // Compressed head (single 8KB raw read)
        let compressed_head_fingerprint = if is_compressed {
            compute_compressed_head_fingerprint(filepath)?
        } else {
            None
        };

        let same_inode = state.map(|s| s.inode == current_inode).unwrap_or(false);

        // For compressed files: check exact_match using compressed head + size (no decompression needed)
        if let Some(state_ref) = state {
            if is_compressed {
                let exact_match = state_ref.completed
                    && same_inode
                    && (state_ref.mtime_ns == 0 || state_ref.mtime_ns == mtime_ns)
                    && state_ref.compressed_size == stat_size
                    && state_ref.compressed_head_fingerprint == compressed_head_fingerprint;

                if exact_match {
                    return Ok(ResolutionOutcome {
                        plan: None,
                        skipped_parse_state: self.skip_parse_state_update_for_alias(
                            state_ref,
                            filepath,
                            current_inode,
                            compression,
                            stat_size,
                            state_ref.uncompressed_size,
                            compressed_head_fingerprint,
                            state_ref.uncompressed_head_fingerprint,
                            mtime_ns,
                        ),
                        retired_parse_states,
                    });
                }
            }
        }

        // Uncompressed fingerprints:
        // - Compressed with same inode: reuse DB-stored values (no decompression)
        // - Compressed with new/changed inode or fresh: compute 8KB uncompressed head only (~ms)
        //   Needed for: cross-format dedup, and detecting shared prefix on inode-rotated files
        // - Plain files: compute from file (cheap sequential read)
        let (uncompressed_size, uncompressed_head_fingerprint) = if is_compressed {
            if same_inode {
                let size = state.map(|s| s.uncompressed_size).unwrap_or(0);
                let head = state.and_then(|s| s.uncompressed_head_fingerprint);
                (size, head)
            } else {
                // 8KB decompression only — no full-file scan
                let uncompressed_head =
                    compute_decompressed_head_fingerprint(filepath, compression)?;
                (0u64, uncompressed_head)
            }
        } else {
            let fingerprints = compute_fingerprints(filepath)?;
            let sz = fingerprints.as_ref().map(|fp| fp.logical_size).unwrap_or(0);
            let head = fingerprints.as_ref().map(|fp| fp.head);
            (sz, head)
        };

        let head_match_state = if state_by_path.is_none() && state_by_inode.is_none() {
            // No state by path or inode: try lookup by head fingerprint
            if is_compressed {
                if let Some(head_fp) = compressed_head_fingerprint {
                    self.db
                        .find_parse_state_by_compressed_head_fingerprint(head_fp)?
                } else {
                    None
                }
            } else if let Some(head_fp) = uncompressed_head_fingerprint {
                self.db
                    .find_parse_state_by_uncompressed_head_fingerprint(head_fp)?
            } else {
                None
            }
        } else if inode_changed_for_path {
            // Inode changed: also try fingerprint lookup to detect rename/rotation
            if is_compressed {
                if let Some(head_fp) = compressed_head_fingerprint {
                    self.db
                        .find_parse_state_by_compressed_head_fingerprint(head_fp)?
                } else {
                    None
                }
            } else if let Some(head_fp) = uncompressed_head_fingerprint {
                self.db
                    .find_parse_state_by_uncompressed_head_fingerprint(head_fp)?
            } else {
                None
            }
        } else {
            None
        };

        let mut skip_decoded_prefix_bytes = 0u64;

        if let Some(state) = state {
            // For compressed files, exact_match was already checked above (early return)
            // This block handles plain file exact_match
            let exact_match = state.completed
                && (state.mtime_ns == 0 || state.mtime_ns == mtime_ns)
                && if is_compressed {
                    // Already handled above for compressed files; this path means exact_match failed
                    false
                } else {
                    state.uncompressed_size == stat_size
                        && state.uncompressed_head_fingerprint == uncompressed_head_fingerprint
                };
            if exact_match {
                return Ok(ResolutionOutcome {
                    plan: None,
                    skipped_parse_state: self.skip_parse_state_update_for_alias(
                        state,
                        filepath,
                        current_inode,
                        compression,
                        stat_size,
                        uncompressed_size,
                        compressed_head_fingerprint,
                        uncompressed_head_fingerprint,
                        mtime_ns,
                    ),
                    retired_parse_states,
                });
            }

            let previous_size = if is_compressed {
                state.compressed_size
            } else {
                state.uncompressed_size
            };

            if is_compressed && !state.completed && state.uncompressed_offset > 0 {
                skip_decoded_prefix_bytes = state.uncompressed_offset;
                offset = 0;
            } else if previous_size > 0 {
                if stat_size < previous_size {
                    offset = 0;
                } else if stat_size > previous_size {
                    if is_compressed {
                        if !inode_changed_for_path {
                            skip_decoded_prefix_bytes = state.uncompressed_offset;
                            offset = 0;
                        } else if state.uncompressed_head_fingerprint.is_some()
                            && state.uncompressed_head_fingerprint == uncompressed_head_fingerprint
                            && state.uncompressed_offset > 0
                        {
                            skip_decoded_prefix_bytes = state.uncompressed_offset;
                            offset = 0;
                        } else {
                            offset = 0;
                        }
                    } else if !inode_changed_for_path {
                        offset = state.uncompressed_offset.min(stat_size);
                    } else if state.uncompressed_head_fingerprint.is_some()
                        && state.uncompressed_head_fingerprint == uncompressed_head_fingerprint
                    {
                        offset = state.uncompressed_offset.min(stat_size);
                    } else {
                        offset = 0;
                    }
                } else if !is_compressed
                    && state.uncompressed_head_fingerprint.is_some()
                    && state.uncompressed_head_fingerprint != uncompressed_head_fingerprint
                {
                    offset = 0;
                }
            }

            if !is_compressed && offset >= stat_size {
                if state.completed
                    && state.uncompressed_head_fingerprint == uncompressed_head_fingerprint
                    && state.uncompressed_size == stat_size
                {
                    return Ok(ResolutionOutcome {
                        plan: None,
                        skipped_parse_state: self.skip_parse_state_update_for_alias(
                            state,
                            filepath,
                            current_inode,
                            compression,
                            stat_size,
                            uncompressed_size,
                            compressed_head_fingerprint,
                            uncompressed_head_fingerprint,
                            mtime_ns,
                        ),
                        retired_parse_states,
                    });
                }
                offset = 0;
            }
        }

        if offset == 0 {
            if let Some(state) = head_match_state.as_ref() {
                if is_compressed && state.uncompressed_offset > 0 {
                    skip_decoded_prefix_bytes = state.uncompressed_offset;
                } else if !is_compressed && state.uncompressed_offset > 0 {
                    offset = state.uncompressed_offset.min(stat_size);
                }
            }
        }

        let should_check_global_dedupe = state_by_path
            .as_ref()
            .map(|s| {
                let previous_size = if is_compressed {
                    s.compressed_size
                } else {
                    s.uncompressed_size
                };
                !(s.inode == current_inode && stat_size > previous_size)
            })
            .unwrap_or(true);

        if should_check_global_dedupe {
            if is_compressed {
                // Compressed: first check compressed identity (zero decompression, exact same bytes)
                if let Some(head_fp) = compressed_head_fingerprint {
                    if let Some(matched_uncompressed_size) = self
                        .db
                        .find_completed_by_compressed_identity(head_fp, stat_size)?
                    {
                        return Ok(ResolutionOutcome {
                            plan: None,
                            skipped_parse_state: Some(self.completed_parse_state_update(
                                filepath,
                                current_inode,
                                compression,
                                stat_size,
                                matched_uncompressed_size,
                                compressed_head_fingerprint,
                                uncompressed_head_fingerprint,
                                mtime_ns,
                            )),
                            retired_parse_states,
                        });
                    }
                }
                // Also check uncompressed identity for cross-format dedup (plain→compressed same content)
                if let Some(head_fp) = uncompressed_head_fingerprint {
                    if let Some(matched_size) =
                        self.db.find_completed_by_uncompressed_head_only(head_fp)?
                    {
                        return Ok(ResolutionOutcome {
                            plan: None,
                            skipped_parse_state: Some(self.completed_parse_state_update(
                                filepath,
                                current_inode,
                                compression,
                                stat_size,
                                matched_size,
                                compressed_head_fingerprint,
                                uncompressed_head_fingerprint,
                                mtime_ns,
                            )),
                            retired_parse_states,
                        });
                    }
                }
            } else if let Some(head_fp) = uncompressed_head_fingerprint {
                // Plain files: use uncompressed head + size
                if uncompressed_size > 0
                    && self
                        .db
                        .find_completed_by_uncompressed_identity(head_fp, uncompressed_size)?
                {
                    return Ok(ResolutionOutcome {
                        plan: None,
                        skipped_parse_state: Some(self.completed_parse_state_update(
                            filepath,
                            current_inode,
                            compression,
                            stat_size,
                            uncompressed_size,
                            compressed_head_fingerprint,
                            uncompressed_head_fingerprint,
                            mtime_ns,
                        )),
                        retired_parse_states,
                    });
                }
            }
        }

        Ok(ResolutionOutcome {
            plan: Some(FileResumePlan {
                current_inode,
                stat_size,
                mtime_ns,
                compression,
                offset,
                skip_decoded_prefix_bytes,
                uncompressed_size: Some(uncompressed_size),
                compressed_head_fingerprint,
                uncompressed_head_fingerprint,
            }),
            skipped_parse_state: None,
            retired_parse_states,
        })
    }
}
