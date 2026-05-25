// Processor: top-level orchestration — file discovery, resume planning, progress thread,
// checkpoint scheduling, and the public process_globs entry point.

use std::collections::BTreeSet;
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
use crate::logging;
use crate::parser::days_from_civil;
use crate::progress::print_dir_progress;
use crate::rules::SharedRuleSet;
use crate::run_accumulators::RunAccumulators;

mod aggregation;
mod flush;
pub(crate) mod messages;
mod pipeline;
mod progress_seed;
mod resume;

pub(crate) const LOADER_BATCH_SIZE: usize = 256;
pub(crate) const PARSER_BATCH_SIZE: usize = 256;
pub(super) const CHANNEL_CAPACITY: usize = 64;

pub(crate) struct ProgressState {
    pub files_done: AtomicUsize,
    pub bytes_done: AtomicU64,
    pub lines_done: AtomicU64,
    pub gz_comp_done: AtomicU64,
    pub gz_decoded_done: AtomicU64,
    pub checkpoint_last_elapsed: AtomicU64,
    pub current_month: std::sync::Mutex<String>,
    pub enabled: AtomicBool,
    pub pause: AtomicBool,
    pub rendering: AtomicBool,
    pub stop: AtomicBool,
}

const VISIT_TIMEOUT_SECONDS: i64 = 30 * 60;
const DEFAULT_GZ_RATIO: f64 = 5.0;

struct ResolutionOutcome {
    plan: Option<FileResumePlan>,
    skipped_parse_state: Option<ParseStateUpdate>,
    retired_parse_states: Vec<ParseStateUpdate>,
}

#[derive(Clone)]
pub(crate) struct FileResumePlan {
    pub(crate) current_inode: u64,
    pub(crate) stat_size: u64,
    pub(crate) mtime_ns: i64,
    pub(crate) compression: CompressionType,
    pub(crate) offset: u64,
    pub(crate) skip_decoded_prefix_bytes: u64,
    pub(crate) uncompressed_size: Option<u64>,
    pub(crate) compressed_head_fingerprint: Option<u64>,
    pub(crate) uncompressed_head_fingerprint: Option<u64>,
}

// ── Processor ─────────────────────────────────────────────────────────────────

pub struct Processor {
    db: Database,
    geo: Geo,
    top_n: usize,
    bot_filter: bool,
    enable_top_urls: bool,
    enable_top_sites: bool,
    enable_top_refs: bool,
    enable_top_agents: bool,
    rule_set: Option<SharedRuleSet>,
    checkpoint_every: Option<Duration>,
    time_cache: AHashMap<u32, (Arc<str>, Arc<str>)>,
    referer_cache: AHashMap<String, Arc<str>>,
    visit_last_seen: AHashMap<VisitStateKey, i64>,
    visit_state_dirty: AHashMap<VisitStateKey, i64>,
    visit_max_seen_ts: i64,
}

#[derive(Clone)]
pub struct ProcessorConfig {
    pub top_n: usize,
    pub bot_filter: bool,
    pub enable_top_urls: bool,
    pub enable_top_sites: bool,
    pub enable_top_refs: bool,
    pub enable_top_agents: bool,
    pub rule_set: Option<SharedRuleSet>,
}

impl Processor {
    pub fn new(db: Database, geo: Geo, config: ProcessorConfig) -> Self {
        Self {
            db,
            geo,
            top_n: config.top_n,
            bot_filter: config.bot_filter,
            enable_top_urls: config.enable_top_urls,
            enable_top_sites: config.enable_top_sites,
            enable_top_refs: config.enable_top_refs,
            enable_top_agents: config.enable_top_agents,
            rule_set: config.rule_set,
            checkpoint_every: None,
            time_cache: AHashMap::with_capacity(8_192),
            referer_cache: AHashMap::with_capacity(8_192),
            visit_last_seen: AHashMap::with_capacity(262_144),
            visit_state_dirty: AHashMap::with_capacity(262_144),
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

        // Sort by the timestamp on the first parseable log line in each file so
        // files are processed in chronological order regardless of mtime.
        files.sort_by_key(|f| {
            resume::read_first_line_ts(f)
                .unwrap_or_else(|| std::fs::metadata(f).map(|m| m.mtime()).unwrap_or(0))
        });

        let dir_started = Instant::now();

        self.load_visit_state_from_db()?;

        let initial_month = self.db.get_meta("current_month")?.unwrap_or_default();

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

        let ps = Arc::new(ProgressState {
            files_done: AtomicUsize::new(0),
            bytes_done: AtomicU64::new(seeded.bytes_done),
            lines_done: AtomicU64::new(0),
            gz_comp_done: AtomicU64::new(seeded.gz_comp_done),
            gz_decoded_done: AtomicU64::new(seeded.gz_decoded_done),
            checkpoint_last_elapsed: AtomicU64::new(u64::MAX),
            current_month: std::sync::Mutex::new(String::new()),
            enabled: AtomicBool::new(false),
            pause: AtomicBool::new(false),
            rendering: AtomicBool::new(false),
            stop: AtomicBool::new(false),
        });

        let progress_thread = self.spawn_progress_thread(
            Arc::clone(&ps),
            count,
            seeded.bytes_done,
            total_plain,
            total_gz_comp,
            dir_started,
        );

        ps.enabled.store(true, Ordering::Relaxed);

        let result = self.run_pipeline(&files, initial_month, Arc::clone(&ps), dir_started);

        ps.stop.store(true, Ordering::Relaxed);
        let _ = progress_thread.join();

        if result.is_ok() && ps.enabled.load(Ordering::Relaxed) {
            let month_snap = ps.current_month.lock().unwrap().clone();
            print_dir_progress(
                ps.files_done.load(Ordering::Relaxed),
                count,
                ps.bytes_done.load(Ordering::Relaxed),
                seeded.bytes_done,
                total_plain,
                total_gz_comp,
                ps.gz_comp_done.load(Ordering::Relaxed),
                ps.gz_decoded_done.load(Ordering::Relaxed),
                ps.lines_done.load(Ordering::Relaxed),
                dir_started,
                DEFAULT_GZ_RATIO,
                0.0,
                self.checkpoint_every.map(|d| d.as_secs()).unwrap_or(0),
                ps.checkpoint_last_elapsed.load(Ordering::Relaxed),
                &month_snap,
            );
        }
        eprintln!();

        let (total, run_acc, pending_parse_states, retired_parse_states, rule_stats, bot_filtered) =
            result?;

        self.flush_run(&run_acc, &pending_parse_states, &retired_parse_states)?;

        let total_elapsed = dir_started.elapsed().as_secs_f64();
        let total_for_log = ps.lines_done.load(Ordering::Relaxed);
        let lps = if total_elapsed > 0.0 {
            (total_for_log as f64 / total_elapsed).round() as u64
        } else {
            0
        };

        logging::log(&format!(
            "Processed {total_for_log} total new lines from {count} file(s) ({:.1}s, {} l/s)",
            total_elapsed, lps
        ));

        if bot_filtered > 0 {
            logging::log(&format!("  {bot_filtered} lines filtered by bot filter"));
        }

        for (name, stats) in &rule_stats {
            if stats.ignored > 0 {
                logging::log(&format!("  {} lines ignored by rule {name}", stats.ignored));
            }
            if stats.hidden > 0 {
                logging::log(&format!("  {} lines hidden by rule {name}", stats.hidden));
            }
        }

        logging::log_debug_at(2, &format!("Vacuuming database"));
        let vacuum_start = Instant::now();
        self.db.vacuum()?;
        logging::log_debug_at(
            1,
            &format!(
                "Database vacuum complete ({:.1}s)",
                vacuum_start.elapsed().as_secs_f64()
            ),
        );

        Ok(total)
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

    pub(super) fn spawn_progress_thread(
        &self,
        ps: Arc<ProgressState>,
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
            let mut last_tick_bytes: u64 = ps.bytes_done.load(Ordering::Relaxed);
            let mut last_tick_time = Instant::now();

            while !ps.stop.load(Ordering::Relaxed) {
                if !ps.enabled.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                if ps.pause.load(Ordering::Relaxed) {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }

                let now = Instant::now();
                let current_bytes_done = ps.bytes_done.load(Ordering::Relaxed);

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

                let month_snap = ps.current_month.lock().unwrap().clone();
                ps.rendering.store(true, Ordering::Relaxed);
                print_dir_progress(
                    ps.files_done.load(Ordering::Relaxed),
                    count,
                    current_bytes_done,
                    seeded_bytes_done,
                    total_plain,
                    total_gz_comp,
                    ps.gz_comp_done.load(Ordering::Relaxed),
                    ps.gz_decoded_done.load(Ordering::Relaxed),
                    ps.lines_done.load(Ordering::Relaxed),
                    dir_started,
                    DEFAULT_GZ_RATIO,
                    ema_bytes_per_sec,
                    checkpoint_interval_secs,
                    ps.checkpoint_last_elapsed.load(Ordering::Relaxed),
                    &month_snap,
                );
                ps.rendering.store(false, Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        })
    }
}

#[cfg(test)]
mod tests;
