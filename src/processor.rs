use std::collections::BTreeSet;
use std::hash::Hasher;
use std::os::unix::fs::MetadataExt;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::AHashMap;
use anyhow::Result;

use crate::compression::CompressionType;
use crate::database::{Database, ParseStateUpdate, VisitStateKey, VisitStateUpdate};
use crate::fingerprint::compute_fingerprints;
use crate::geo::Geo;
use crate::hll::HyperLogLog;
use crate::logging;
use crate::parser;
use crate::progress::print_dir_progress;
use twox_hash::XxHash3_64;
use crate::run_accumulators::RunAccumulators;
use crate::topn::{
    CountryHitsMap, HourlyMap, PeriodCountMap, StatusHitsMap, TopHostsByBandwidth, TopHostsByHits,
    TopNCount, TopNHosts, TopNHostsByBandwidth, TopNUrls, TopNUrlsByBandwidth, TopUrlsByBandwidth,
    TopUrlsByHits,
};
use crate::ua::UaParser;
use crate::util::{
    days_from_civil, extract_host_from_url, file_ext, parse_ipv4_u32, parse_ipv6_u128, strip_query,
    FILE_EXTS,
};

mod aggregation;
mod flush;
mod loader;
mod messages;
mod parser_stage;
mod pipeline;
mod progress_seed;
mod resume_policy;

pub(super) const LOADER_BATCH_SIZE: usize = 256;
pub(super) const PARSER_BATCH_SIZE: usize = 256;
pub(super) const CHANNEL_CAPACITY: usize = 64;

const VISIT_TIMEOUT_SECONDS: i64 = 30 * 60;
const DEFAULT_GZ_RATIO: f64 = 5.0;

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
    time_cache: AHashMap<u32, (Arc<str>, Arc<str>, Arc<str>)>,
    referer_cache: AHashMap<String, Arc<str>>,
    ip_ids_v4: AHashMap<u32, u32>,
    ip_ids_v6: AHashMap<u128, u32>,
    ip_ids_other: AHashMap<String, u32>,
    next_ip_id: u32,
    visit_last_seen: AHashMap<VisitStateKey, i64>,
    visit_state_dirty: AHashMap<VisitStateKey, i64>,
    geo_cache: AHashMap<u32, (Arc<str>, Arc<str>)>,
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
        config: ProcessorConfig,
    ) -> Self {
        Self {
            db,
            geo,
            ua,
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

        let mut files: Vec<String> = files_set.into_iter().collect();

        if files.is_empty() {
            logging::log(&format!(
                "No files found matching log_glob patterns: {glob_list}"
            ));
            return Ok(0);
        }

        // Sort oldest-first so visit-state is accumulated in chronological order.
        files.sort_by_key(|f| {
            std::fs::metadata(f).map(|m| m.mtime()).unwrap_or(0)
        });

        let dir_started = Instant::now();

        self.load_visit_state_from_db()?;

        logging::log(&format!(
            "Found {} file(s) across {} pattern(s)",
            files.len(),
            patterns.len()
        ));
        let count = files.len();

        let file_sizes_and_inodes: Vec<(u64, u64)> = files
            .iter()
            .map(|f| {
                std::fs::metadata(f)
                    .map(|m| (m.len(), m.ino()))
                    .unwrap_or((0, 0))
            })
            .collect();
        let raw_file_sizes: Vec<u64> = file_sizes_and_inodes.iter().map(|(s, _)| *s).collect();
        let current_inodes: Vec<u64> = file_sizes_and_inodes.iter().map(|(_, i)| *i).collect();
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

        let files_done = Arc::new(AtomicUsize::new(0));
        let bytes_done = Arc::new(AtomicU64::new(seeded.bytes_done));
        let lines_done = Arc::new(AtomicU64::new(0));
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

        // Enable progress display only once planning has found work to do.
        progress_enabled.store(true, Ordering::Relaxed);

        let result = self.run_pipeline(
            &files,
            files_done,
            bytes_done,
            lines_done,
            gz_comp_done,
            gz_decoded_done,
            checkpoint_last_elapsed,
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

        self.prune_top_tables()?;

        Ok(total)
    }

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
            updates.push(VisitStateUpdate { key, last_seen_ts: ts });
        }

        (updates, prune_before)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn_progress_thread(
        &self,
        files_done: Arc<AtomicUsize>,
        bytes_done: Arc<AtomicU64>,
        lines_done: Arc<AtomicU64>,
        gz_comp_done: Arc<AtomicU64>,
        gz_decoded_done: Arc<AtomicU64>,
        checkpoint_last_elapsed: Arc<AtomicU64>,
        progress_enabled: Arc<AtomicBool>,
        pause_progress: Arc<AtomicBool>,
        rendering_progress: Arc<AtomicBool>,
        stop_progress: Arc<AtomicBool>,
        count: usize,
        seeded_bytes_done: u64,
        total_plain: u64,
        total_gz_comp: u64,
        dir_started: Instant,
    ) -> std::thread::JoinHandle<()> {
        let checkpoint_interval_secs = self.checkpoint_every.map(|d| d.as_secs()).unwrap_or(0);
        std::thread::spawn(move || {
            const EMA_TAU_SECS: f64 = 30.0;
            let mut ema_bytes_per_sec: f64 = 0.0;
            let mut last_tick_bytes: u64 = bytes_done.load(Ordering::Relaxed);
            let mut last_tick_time = Instant::now();

            while !stop_progress.load(Ordering::Relaxed) {
                if !progress_enabled.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                if pause_progress.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }

                let now = Instant::now();
                let current_bytes_done = bytes_done.load(Ordering::Relaxed);

                let dt = now.duration_since(last_tick_time).as_secs_f64();
                if dt > 0.0 {
                    let instant_rate =
                        current_bytes_done.saturating_sub(last_tick_bytes) as f64 / dt;
                    let alpha = 1.0 - (-dt / EMA_TAU_SECS).exp();
                    ema_bytes_per_sec = if ema_bytes_per_sec == 0.0 && instant_rate > 0.0 {
                        instant_rate
                    } else {
                        alpha * instant_rate + (1.0 - alpha) * ema_bytes_per_sec
                    };
                    last_tick_bytes = current_bytes_done;
                    last_tick_time = now;
                }

                rendering_progress.store(true, Ordering::Relaxed);
                print_dir_progress(
                    files_done.load(Ordering::Relaxed),
                    count,
                    current_bytes_done,
                    seeded_bytes_done,
                    total_plain,
                    total_gz_comp,
                    gz_comp_done.load(Ordering::Relaxed),
                    gz_decoded_done.load(Ordering::Relaxed),
                    lines_done.load(Ordering::Relaxed),
                    dir_started,
                    DEFAULT_GZ_RATIO,
                    ema_bytes_per_sec,
                    checkpoint_interval_secs,
                    checkpoint_last_elapsed.load(Ordering::Relaxed),
                );
                rendering_progress.store(false, Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        })
    }
}

/// Update a map keeping only the maximum timestamp per key.
pub(super) fn merge_max(map: &mut AHashMap<VisitStateKey, i64>, key: VisitStateKey, ts: i64) {
    map.entry(key)
        .and_modify(|v| {
            if ts > *v {
                *v = ts;
            }
        })
        .or_insert(ts);
}

#[cfg(test)]
mod tests;
