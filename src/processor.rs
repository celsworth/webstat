use std::collections::BTreeSet;
use std::fs::File;
use std::hash::Hasher;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use anyhow::Result;
use rayon::prelude::*;
use twox_hash::XxHash3_64;

use crate::compression::CompressionType;
use crate::database::{Database, ParseStateUpdate, VisitStateKey, VisitStateUpdate};
use crate::fingerprint::compute_fingerprints;
use crate::geo::Geo;
use crate::hll::HyperLogLog;
use crate::logging;
use crate::parser;
use crate::progress::{flush_shared_progress, print_dir_progress, SharedProgress};
use crate::run_accumulators::RunAccumulators;
use crate::topn::{
    CountryHitsMap, HourlyMap, PeriodCountMap, StatusHitsMap, TopHostsByBandwidth, TopHostsByHits,
    TopNCount, TopNHosts, TopNHostsByBandwidth, TopNUrls, TopNUrlsByBandwidth, TopUrlsByHits, TopUrlsByBandwidth
};
use crate::ua::UaParser;
use crate::util::{
    days_from_civil, extract_host_from_url, file_ext, parse_ipv4_u32, parse_ipv6_u128, strip_query,
    FILE_EXTS,
};

mod aggregation;
mod flush;
mod parallel;
mod progress_seed;
mod readers;
mod resume_policy;

// Minimum plain-text bytes before enabling per-file range parallelism.
const RANGE_PARALLEL_MIN_BYTES: u64 = 64 * 1024 * 1024;
const VISIT_TIMEOUT_SECONDS: i64 = 30 * 60;
const DEFAULT_GZ_RATIO: f64 = 5.0;

struct WorkResult {
    file_idx: usize,
    file_completed: bool,
    lines_processed: u64,
    run_acc: RunAccumulators,
    pending_parse_states: Vec<ParseStateUpdate>,
}

struct ProcessWithProgressResult {
    lines_processed: u64,
    file_completed: bool,
}

struct ResolutionOutcome {
    plan: Option<FileResumePlan>,
    skipped_parse_state: Option<ParseStateUpdate>,
    retired_parse_states: Vec<ParseStateUpdate>,
}

#[derive(Clone)]
struct FileResumePlan {
    current_inode: u64,
    stat_size: u64,
    mtime_ns: i64,
    compression: CompressionType,
    offset: u64,
    skip_decoded_prefix_bytes: u64,
    uncompressed_size: Option<u64>,
    compressed_head_fingerprint: Option<u64>,
    uncompressed_head_fingerprint: Option<u64>,
}

// ── Processor ─────────────────────────────────────────────────────────────────

pub struct Processor {
    db: Database,
    geo: Geo,
    ua: UaParser,
    db_path: String,
    geoip_db: Option<String>,
    file_workers: usize,
    top_n: usize,
    vacuum_after_prune: bool,
    enable_pruner: bool,
    bot_filter: bool,
    site_host: Option<String>,
    enable_top_urls: bool,
    enable_top_hosts: bool,
    enable_top_refs: bool,
    hll_precision: u8,
    topn_k: usize,
    checkpoint_every: Option<Duration>,
    /// Memoised time-period strings keyed by `year*1_000_000 + mon*10_000 + day*100 + hour`.
    /// Values are `Arc<str>` so cloning them in the hot loop is a single atomic increment.
    time_cache: AHashMap<u32, (Arc<str>, Arc<str>, Arc<str>)>,
    /// Memoised host extracted from a full referrer URL.
    referer_cache: AHashMap<String, Arc<str>>,
    /// Interning table for IPv4 addresses used by hourly unique-site sets.
    ip_ids_v4: AHashMap<u32, u32>,
    /// Interning table for IPv6 addresses used by hourly unique-site sets.
    ip_ids_v6: AHashMap<u128, u32>,
    /// Fallback interning table for malformed/unexpected address tokens.
    ip_ids_other: AHashMap<String, u32>,
    next_ip_id: u32,
    /// Last-seen timestamp per IP, persisted across checkpoints and restarts.
    visit_last_seen: AHashMap<VisitStateKey, i64>,
    /// Dirty visit-state rows to flush at checkpoints/end-of-run.
    visit_state_dirty: AHashMap<VisitStateKey, i64>,
    /// GeoIP lookup cache keyed by ip_id for efficient lookups without string allocation.
    geo_cache: AHashMap<u32, (Arc<str>, Arc<str>)>,
    /// Max timestamp seen in this run to anchor state pruning.
    visit_max_seen_ts: i64,
}

#[derive(Clone)]
pub struct ProcessorConfig {
    pub top_n: usize,
    pub vacuum_after_prune: bool,
    pub enable_pruner: bool,
    pub bot_filter: bool,
    pub site_host: Option<String>,
    pub enable_top_urls: bool,
    pub enable_top_hosts: bool,
    pub enable_top_refs: bool,
    pub hll_precision: u8,
    pub topn_k: usize,
}

impl Processor {
    pub fn new(
        db: Database,
        geo: Geo,
        ua: UaParser,
        db_path: String,
        geoip_db: Option<String>,
        file_workers: usize,
        config: ProcessorConfig,
    ) -> Self {
        Self {
            db,
            geo,
            ua,
            db_path,
            geoip_db,
            file_workers,
            top_n: config.top_n,
            vacuum_after_prune: config.vacuum_after_prune,
            enable_pruner: config.enable_pruner,
            bot_filter: config.bot_filter,
            site_host: config.site_host,
            enable_top_urls: config.enable_top_urls,
            enable_top_hosts: config.enable_top_hosts,
            enable_top_refs: config.enable_top_refs,
            hll_precision: config.hll_precision,
            topn_k: config.topn_k,
            checkpoint_every: None,
            time_cache: AHashMap::with_capacity(8_192),
            referer_cache: AHashMap::with_capacity(8_192),
            ip_ids_v4: AHashMap::with_capacity(262_144),
            ip_ids_v6: AHashMap::with_capacity(32_768),
            ip_ids_other: AHashMap::with_capacity(256),
            next_ip_id: 1,
            visit_last_seen: AHashMap::with_capacity(262_144),
            visit_state_dirty: AHashMap::with_capacity(262_144),
            geo_cache: AHashMap::with_capacity(262_144),
            visit_max_seen_ts: 0,
        }
    }

    pub(super) fn worker_config(&self) -> ProcessorConfig {
        ProcessorConfig {
            top_n: self.top_n,
            vacuum_after_prune: self.vacuum_after_prune,
            enable_pruner: self.enable_pruner,
            bot_filter: self.bot_filter,
            site_host: self.site_host.clone(),
            enable_top_urls: self.enable_top_urls,
            enable_top_hosts: self.enable_top_hosts,
            enable_top_refs: self.enable_top_refs,
            hll_precision: self.hll_precision,
            topn_k: self.topn_k,
        }
    }

    fn log_resolution_plan(&self, filepath: &str, outcome: &ResolutionOutcome, phase: &str) {
        if logging::debug_level() == 0 {
            return;
        }

        match &outcome.plan {
            Some(plan) => {
                let is_compressed = plan.compression.is_compressed();
                let (action, log_level) = if is_compressed {
                    if plan.skip_decoded_prefix_bytes > 0 {
                        ("resume_compressed_tail", 1)
                    } else if plan.offset > 0 {
                        ("resume_compressed_from_offset", 1)
                    } else {
                        ("start_compressed_from_zero", 2)
                    }
                } else if plan.offset > 0 {
                    ("resume_plain_from_offset", 1)
                } else {
                    ("start_plain_from_zero", 2)
                };

                logging::log_debug_at(log_level, &format!(
                    "[plan:{phase}] file={filepath} action={action} inode={} compression={:?} start_offset={} skip_decoded_prefix={} stat_size={} uncompressed_size={} retired_states={}",
                    plan.current_inode,
                    plan.compression,
                    plan.offset,
                    plan.skip_decoded_prefix_bytes,
                    plan.stat_size,
                    plan.uncompressed_size.unwrap_or(0),
                    outcome.retired_parse_states.len()
                ));
            }
            None => {
                if let Some(state) = &outcome.skipped_parse_state {
                    logging::log_debug(&format!(
                        "[plan:{phase}] file={filepath} action=skip_mark_completed inode={} is_gz={} planned_offset={} stat_size={} uncompressed_size={} retired_states={}",
                        state.inode,
                        state.compressed_size > 0,
                        state.uncompressed_offset,
                        if state.compressed_size > 0 {
                            state.compressed_size
                        } else {
                            state.uncompressed_size
                        },
                        state.uncompressed_size,
                        outcome.retired_parse_states.len()
                    ));
                } else {
                    logging::log_debug_at(
                        3,
                        &format!(
                            "[plan:{phase}] file={filepath} action=skip_no_work retired_states={}",
                            outcome.retired_parse_states.len()
                        ),
                    );
                }
            }
        }
    }

    pub fn set_checkpoint_interval_minutes(&mut self, minutes: u64) {
        self.checkpoint_every = if minutes == 0 {
            None
        } else {
            Some(Duration::from_secs(minutes.saturating_mul(60)))
        };
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /// Process every log file matching comma-separated glob patterns.
    /// Returns total new lines processed.
    pub fn process_globs(&mut self, glob_list: &str) -> Result<u64> {
        let patterns: Vec<&str> = glob_list
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .collect();

        let mut files_set = BTreeSet::new();
        for pattern in &patterns {
            for path in (glob::glob(pattern)?).flatten() {
                files_set.insert(path.to_string_lossy().into_owned());
            }
        }

        let files: Vec<String> = files_set.into_iter().collect();

        if files.is_empty() {
            logging::log(&format!(
                "No files found matching log_glob patterns: {glob_list}"
            ));
            return Ok(0);
        }

        let dir_started = Instant::now();

        self.load_visit_state_from_db()?;

        logging::log(&format!(
            "Found {} file(s) across {} pattern(s)",
            files.len(),
            patterns.len()
        ));
        let count = files.len();

        let workers = self.file_workers.max(1);
        logging::log_debug_at(1, &format!("Processing files with {} worker(s)", workers));

        // Pre-compute raw compressed sizes for each file.
        let file_sizes_and_inodes: Vec<(u64, u64)> = files
            .iter()
            .map(|f| {
                std::fs::metadata(f)
                    .map(|m| (m.len(), m.ino()))
                    .unwrap_or((0, 0))
            })
            .collect();
        let raw_file_sizes: Vec<u64> = file_sizes_and_inodes
            .iter()
            .map(|(size, _)| *size)
            .collect();
        let current_inodes: Vec<u64> = file_sizes_and_inodes
            .iter()
            .map(|(_, inode)| *inode)
            .collect();
        let is_compressed_vec: Vec<bool> = files
            .iter()
            .map(|f| CompressionType::from_path(f).is_compressed())
            .collect();
        let total_plain: u64 = raw_file_sizes
            .iter()
            .zip(&is_compressed_vec)
            .filter_map(|(sz, comp)| if !comp { Some(*sz) } else { None })
            .sum();
        let total_gz_comp: u64 = raw_file_sizes
            .iter()
            .zip(&is_compressed_vec)
            .filter_map(|(sz, comp)| if *comp { Some(*sz) } else { None })
            .sum();
        let seeded = self.compute_seeded_progress(
            &files,
            &current_inodes,
            &raw_file_sizes,
            &is_compressed_vec,
        )?;

        // Shared progress counters.
        // bytes_done = plain bytes read + gz decoded bytes (actual, not estimated).
        let files_done = Arc::new(AtomicUsize::new(0));
        let bytes_done = Arc::new(AtomicU64::new(seeded.bytes_done));
        let lines_done = Arc::new(AtomicU64::new(0));
        // gz_comp_done / gz_decoded_done let us refine the compression-ratio estimate.
        let gz_comp_done = Arc::new(AtomicU64::new(seeded.gz_comp_done));
        let gz_decoded_done = Arc::new(AtomicU64::new(seeded.gz_decoded_done));
        let checkpoint_last_elapsed = Arc::new(AtomicU64::new(u64::MAX));
        let progress_enabled = Arc::new(AtomicBool::new(false));
        let pause_progress = Arc::new(AtomicBool::new(false));
        let rendering_progress = Arc::new(AtomicBool::new(false));
        let stop_progress = Arc::new(AtomicBool::new(false));

        let final_files_done = files_done.clone();
        let final_bytes_done = bytes_done.clone();
        let final_lines_done = lines_done.clone();
        let final_gz_comp_done = gz_comp_done.clone();
        let final_gz_decoded_done = gz_decoded_done.clone();
        let final_checkpoint_last_elapsed = checkpoint_last_elapsed.clone();
        let final_progress_enabled = progress_enabled.clone();

        let progress_thread = self.spawn_progress_thread(
            files_done.clone(),
            bytes_done.clone(),
            lines_done.clone(),
            gz_comp_done.clone(),
            gz_decoded_done.clone(),
            checkpoint_last_elapsed.clone(),
            progress_enabled.clone(),
            pause_progress.clone(),
            rendering_progress.clone(),
            stop_progress.clone(),
            count,
            seeded.bytes_done,
            total_plain,
            total_gz_comp,
            dir_started,
        );

        let result = self.dispatch_parallel_files(
            &files,
            &raw_file_sizes,
            &is_compressed_vec,
            workers,
            bytes_done,
            lines_done,
            gz_comp_done,
            gz_decoded_done,
            files_done,
            checkpoint_last_elapsed,
            progress_enabled,
            pause_progress,
            rendering_progress,
            dir_started,
        );

        stop_progress.store(true, Ordering::Relaxed);
        let _ = progress_thread.join();

        if result.is_ok() && final_progress_enabled.load(Ordering::Relaxed) {
            print_dir_progress(
                final_files_done.load(Ordering::Relaxed),
                count,
                final_bytes_done.load(Ordering::Relaxed),
                seeded.bytes_done,
                total_plain,
                total_gz_comp,
                final_gz_comp_done.load(Ordering::Relaxed),
                final_gz_decoded_done.load(Ordering::Relaxed),
                final_lines_done.load(Ordering::Relaxed),
                dir_started,
                DEFAULT_GZ_RATIO,
                0.0,
                self.checkpoint_every.map(|d| d.as_secs()).unwrap_or(0),
                final_checkpoint_last_elapsed.load(Ordering::Relaxed),
            );
        }
        eprintln!();

        let (total, run_acc, pending_parse_states, retired_parse_states) = result?;

        self.flush_run(&run_acc, &pending_parse_states, &retired_parse_states)?;

        let total_elapsed = dir_started.elapsed().as_secs_f64();
        let lps = if total_elapsed > 0.0 {
            (total as f64 / total_elapsed).round() as u64
        } else {
            0
        };

        logging::log(&format!(
            "Processed {total} total new lines from {count} file(s) ({:.1}s, {} l/s)",
            total_elapsed, lps
        ));

        // Keep top_* tables bounded, even if no new lines were imported.
        self.prune_top_tables()?;

        Ok(total)
    }

    /// Run top-table pruning immediately.
    pub fn prune_top_tables(&mut self) -> Result<()> {
        if !self.enable_pruner {
            logging::log(
                "Pruner disabled; skipping top-N table pruning (database may grow larger)",
            );
            return Ok(());
        }

        logging::log_debug_at(2, "Pruning top_n tables…");
        let prune_started = std::time::Instant::now();
        self.db
            .trim_top_tables(self.top_n, self.topn_k, true, self.vacuum_after_prune)?;
        logging::log_debug_at(
            1,
            &format!(
                "Pruning top_n tables complete ({:.2}s)",
                prune_started.elapsed().as_secs_f64()
            ),
        );
        Ok(())
    }

    fn process_with_progress(
        &mut self,
        filepath: &str,
        file_num: usize,
        file_count: usize,
        plan: FileResumePlan,
        progress: Option<SharedProgress<'_>>,
        checkpoint_requested: Option<&AtomicBool>,
        run_acc: &mut RunAccumulators,
        pending_parse_states: &mut Vec<ParseStateUpdate>,
        progress_flush_last: &mut Instant,
    ) -> Result<ProcessWithProgressResult> {
        let FileResumePlan {
            current_inode,
            stat_size,
            mtime_ns,
            compression,
            offset,
            mut skip_decoded_prefix_bytes,
            uncompressed_size,
            compressed_head_fingerprint,
            uncompressed_head_fingerprint,
        } = plan;
        let is_compressed = compression.is_compressed();

        let total_bytes: Option<u64> = if !is_compressed && stat_size > offset {
            Some(stat_size - offset)
        } else {
            None
        };

        if false
            && !is_compressed
            && self.file_workers > 1
            && total_bytes.unwrap_or(0) >= RANGE_PARALLEL_MIN_BYTES
        {
            logging::log(&format!(
                "Processing single file in {} parallel ranges",
                self.file_workers
            ));
            logging::log("Range-parallel mode processes file in parallel byte ranges");

            let range_started = Instant::now();

            let (lines_processed, range_acc) =
                self.process_plain_in_parallel_ranges(filepath, offset, stat_size)?;
            run_acc.merge_from(range_acc, self.hll_precision, self.topn_k);

            pending_parse_states.push(ParseStateUpdate {
                filepath: filepath.to_string(),
                inode: current_inode,
                compressed_size: 0,
                uncompressed_size: uncompressed_size.unwrap_or(stat_size),
                compressed_head_fingerprint: None,
                uncompressed_head_fingerprint,
                compressed_offset: 0,
                uncompressed_offset: stat_size,
                mtime_ns,
                completed: true,
            });
            let sec = range_started.elapsed().as_secs_f64();
            let lps = if sec > 0.0 {
                (lines_processed as f64 / sec).round() as u64
            } else {
                0
            };

            logging::log(&format!(
                "Processed [{}/{}] {} lines via range parallelism ({:.1}s, {} l/s)",
                file_num, file_count, lines_processed, sec, lps
            ));
            return Ok(ProcessWithProgressResult {
                lines_processed,
                file_completed: true,
            });
        }

        let mut lines_processed: u64 = 0;
        let mut bytes_read: u64 = 0;
        let mut decoded_bytes_read: u64 = 0;
        let mut reported_bytes: u64 = 0;
        let mut reported_lines: u64 = 0;
        let mut checkpoint_ticker: u32 = 2_048;
        let mut interrupted_for_checkpoint = false;
        let skipped_decoded_prefix_initial = if is_compressed {
            skip_decoded_prefix_bytes
        } else {
            0
        };

        // ── Read file ─────────────────────────────────────────────────────────
        if is_compressed {
            let file = File::open(filepath)?;
            let decoder: Box<dyn Read> = match compression {
                CompressionType::Gz => Box::new(flate2::read::MultiGzDecoder::new(file)),
                CompressionType::Bz2 => Box::new(bzip2::read::MultiBzDecoder::new(file)),
                CompressionType::Plain => unreachable!(),
            };
            let mut reader = BufReader::with_capacity(1 << 20, decoder);
            let mut line = String::new();
            loop {
                line.clear();
                let n = reader.read_line(&mut line)?;
                if n == 0 {
                    break;
                }
                decoded_bytes_read += n as u64;
                if skip_decoded_prefix_bytes > 0 {
                    let consumed = (n as u64).min(skip_decoded_prefix_bytes);
                    skip_decoded_prefix_bytes -= consumed;
                    if skip_decoded_prefix_bytes > 0 || consumed == n as u64 {
                        continue;
                    }
                }
                if let Some(entry) = parser::parse_line(&line) {
                    self.aggregate_entry_with_hll_split(
                        entry,
                        &mut run_acc.hourly,
                        &mut run_acc.top_urls,
                        &mut run_acc.top_urls_bw,
                        &mut run_acc.top_hosts,
                        &mut run_acc.top_hosts_bw,
                        &mut run_acc.top_refs,
                        &mut run_acc.top_agents,
                        &mut run_acc.top_countries,
                        &mut run_acc.status_codes,
                        &mut run_acc.hll_site_counts,
                        run_acc.hll_all_time.as_mut(),
                        &mut run_acc.method_counts,
                        &mut run_acc.proto_counts,
                    );
                    lines_processed += 1;
                }
                let current_bytes =
                    decoded_bytes_read.saturating_sub(skipped_decoded_prefix_initial);
                flush_shared_progress(
                    progress.as_ref(),
                    current_bytes,
                    lines_processed,
                    &mut reported_bytes,
                    &mut reported_lines,
                    progress_flush_last,
                    false,
                    false,
                );
                if let Some(requested) = checkpoint_requested {
                    checkpoint_ticker -= 1;
                    if checkpoint_ticker == 0 {
                        checkpoint_ticker = 2_048;
                        if requested.load(Ordering::Relaxed) {
                            interrupted_for_checkpoint = true;
                            break;
                        }
                    }
                }
            }
        } else {
            let mut file = File::open(filepath)?;
            if offset > 0 {
                use std::io::Seek;
                file.seek(std::io::SeekFrom::Start(offset))?;
            }
            let mut reader = BufReader::with_capacity(1 << 20, file);
            let mut line = String::new();
            loop {
                line.clear();
                let n = reader.read_line(&mut line)?;
                if n == 0 {
                    break;
                }
                bytes_read += n as u64;
                if let Some(entry) = parser::parse_line(&line) {
                    self.aggregate_entry_with_hll_split(
                        entry,
                        &mut run_acc.hourly,
                        &mut run_acc.top_urls,
                        &mut run_acc.top_urls_bw,
                        &mut run_acc.top_hosts,
                        &mut run_acc.top_hosts_bw,
                        &mut run_acc.top_refs,
                        &mut run_acc.top_agents,
                        &mut run_acc.top_countries,
                        &mut run_acc.status_codes,
                        &mut run_acc.hll_site_counts,
                        run_acc.hll_all_time.as_mut(),
                        &mut run_acc.method_counts,
                        &mut run_acc.proto_counts,
                    );
                    lines_processed += 1;
                }
                let current_bytes = bytes_read;
                flush_shared_progress(
                    progress.as_ref(),
                    current_bytes,
                    lines_processed,
                    &mut reported_bytes,
                    &mut reported_lines,
                    progress_flush_last,
                    false,
                    false,
                );
                if let Some(requested) = checkpoint_requested {
                    checkpoint_ticker -= 1;
                    if checkpoint_ticker == 0 {
                        checkpoint_ticker = 2_048;
                        if requested.load(Ordering::Relaxed) {
                            interrupted_for_checkpoint = true;
                            break;
                        }
                    }
                }
            }
        }

        let final_bytes = if is_compressed {
            decoded_bytes_read.saturating_sub(skipped_decoded_prefix_initial)
        } else {
            bytes_read
        };
        let completed = if interrupted_for_checkpoint {
            false
        } else if lines_processed > 0 {
            if is_compressed {
                true
            } else {
                offset + bytes_read >= stat_size
            }
        } else {
            true
        };
        flush_shared_progress(
            progress.as_ref(),
            final_bytes,
            lines_processed,
            &mut reported_bytes,
            &mut reported_lines,
            progress_flush_last,
            true,
            completed,
        );

        let new_offset = if is_compressed {
            if interrupted_for_checkpoint {
                0
            } else {
                stat_size
            }
        } else {
            offset + bytes_read
        };
        let new_logical_offset = if is_compressed {
            decoded_bytes_read
        } else {
            new_offset
        };

        pending_parse_states.push(ParseStateUpdate {
            filepath: filepath.to_string(),
            inode: current_inode,
            compressed_size: if is_compressed { stat_size } else { 0 },
            uncompressed_size: if is_compressed {
                new_logical_offset
            } else {
                uncompressed_size.unwrap_or(stat_size)
            },
            compressed_head_fingerprint: if is_compressed {
                compressed_head_fingerprint
            } else {
                None
            },
            uncompressed_head_fingerprint,
            compressed_offset: if is_compressed { new_offset } else { 0 },
            uncompressed_offset: new_logical_offset,
            mtime_ns,
            completed,
        });
        Ok(ProcessWithProgressResult {
            lines_processed,
            file_completed: completed,
        })
    }

    #[inline]
    fn checkpoint_due(&self, last_checkpoint: &Instant) -> bool {
        self.checkpoint_every
            .map(|interval| last_checkpoint.elapsed() >= interval)
            .unwrap_or(false)
    }

    fn load_visit_state_from_db(&mut self) -> Result<()> {
        self.visit_last_seen.clear();
        self.visit_state_dirty.clear();
        self.visit_max_seen_ts = 0;

        for row in self.db.load_visit_state()? {
            if row.last_seen_ts > self.visit_max_seen_ts {
                self.visit_max_seen_ts = row.last_seen_ts;
            }
            self.visit_last_seen.insert(row.key, row.last_seen_ts);
        }

        Ok(())
    }

    fn collect_visit_state_flush(&mut self) -> (Vec<VisitStateUpdate>, Option<i64>) {
        let prune_before = if self.visit_max_seen_ts > 0 {
            Some(self.visit_max_seen_ts.saturating_sub(VISIT_TIMEOUT_SECONDS))
        } else {
            None
        };

        if let Some(cutoff) = prune_before {
            self.visit_last_seen.retain(|_, ts| *ts >= cutoff);
            self.visit_state_dirty.retain(|_, ts| *ts >= cutoff);
        }

        let mut updates = Vec::with_capacity(self.visit_state_dirty.len());
        for (key, ts) in self.visit_state_dirty.drain() {
            updates.push(VisitStateUpdate {
                key,
                last_seen_ts: ts,
            });
        }

        (updates, prune_before)
    }
}

#[cfg(test)]
mod tests;
