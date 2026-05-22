use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ahash::{AHashMap, AHashSet};
use anyhow::Result;

use super::messages::{pop_blocking, LoaderMsg, ParserMsg};
use super::{loader, parser_stage, FileResumePlan, Processor, CHANNEL_CAPACITY};
use crate::database::ParseStateUpdate;
use crate::run_accumulators::RunAccumulators;

/// Per-file state tracked by the aggregator while a file is being processed.
struct ActiveFile {
    path: String,
    plan: FileResumePlan,
    /// Most recent offset reported via a ParserMsg::Entries batch.
    last_offset: u64,
}

impl ActiveFile {
    /// Build a partial (not-completed) ParseStateUpdate for checkpointing mid-file.
    fn partial_parse_state(&self) -> ParseStateUpdate {
        let is_compressed = self.plan.compression.is_compressed();
        ParseStateUpdate {
            filepath: self.path.clone(),
            inode: self.plan.current_inode,
            compressed_size: if is_compressed {
                self.plan.stat_size
            } else {
                0
            },
            uncompressed_size: if is_compressed {
                self.last_offset
            } else {
                self.plan.uncompressed_size.unwrap_or(self.plan.stat_size)
            },
            compressed_head_fingerprint: if is_compressed {
                self.plan.compressed_head_fingerprint
            } else {
                None
            },
            uncompressed_head_fingerprint: self.plan.uncompressed_head_fingerprint,
            // compressed_offset=0 means "restart from start, skip decoded bytes on resume"
            compressed_offset: 0,
            uncompressed_offset: self.last_offset,
            mtime_ns: self.plan.mtime_ns,
            completed: false,
        }
    }
}

fn make_file_parse_state(
    path: &str,
    plan: &FileResumePlan,
    final_offset: u64,
    completed: bool,
) -> ParseStateUpdate {
    let is_compressed = plan.compression.is_compressed();
    ParseStateUpdate {
        filepath: path.to_string(),
        inode: plan.current_inode,
        compressed_size: if is_compressed { plan.stat_size } else { 0 },
        uncompressed_size: if is_compressed {
            final_offset
        } else {
            plan.uncompressed_size.unwrap_or(plan.stat_size)
        },
        compressed_head_fingerprint: if is_compressed {
            plan.compressed_head_fingerprint
        } else {
            None
        },
        uncompressed_head_fingerprint: plan.uncompressed_head_fingerprint,
        compressed_offset: if is_compressed && completed {
            plan.stat_size
        } else {
            0
        },
        uncompressed_offset: final_offset,
        mtime_ns: plan.mtime_ns,
        completed,
    }
}

impl Processor {
    /// Single-pipeline processing: Loader → Parser → Aggregator (this thread).
    /// Returns (total_lines, run_acc, pending_parse_states, retired_parse_states).
    /// The caller is responsible for the final flush_run.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn run_pipeline(
        &mut self,
        files: &[String],
        initial_month: String,
        files_done: Arc<AtomicUsize>,
        bytes_done: Arc<AtomicU64>,
        lines_done: Arc<AtomicU64>,
        gz_comp_done: Arc<AtomicU64>,
        gz_decoded_done: Arc<AtomicU64>,
        checkpoint_last_elapsed: Arc<AtomicU64>,
        current_month_progress: Arc<std::sync::Mutex<String>>,
        dir_started: Instant,
    ) -> Result<(
        u64,
        RunAccumulators,
        Vec<ParseStateUpdate>,
        Vec<ParseStateUpdate>,
    )> {
        let count = files.len();
        let mut run_acc = RunAccumulators::new(initial_month);
        let mut pending_parse_states: Vec<ParseStateUpdate> = Vec::with_capacity(count);
        let mut retired_parse_states: Vec<ParseStateUpdate> = Vec::with_capacity(count);
        let mut seen_retired: AHashSet<(String, u64)> = AHashSet::new();

        // ── Phase 0a: cheap metadata pre-check (stat+DB only, no file I/O) ───────
        // For each file check inode+size+mtime against stored state. Files that
        // match are confirmed done with zero file reads. Only the remainder need
        // the timestamp scan and full fingerprint resolve.
        let mut pending_indices: Vec<usize> = Vec::new();
        let t0a = std::time::Instant::now();

        for (idx, filepath) in files.iter().enumerate() {
            match self.resolve_cheap(filepath)? {
                Some(outcome) => {
                    self.log_resolution_plan(filepath, &outcome, "cheap");
                    if let Some(state) = outcome.skipped_parse_state {
                        pending_parse_states.push(state);
                    }
                    for retired in outcome.retired_parse_states {
                        if seen_retired.insert((retired.filepath.clone(), retired.inode)) {
                            retired_parse_states.push(retired);
                        }
                    }
                    files_done.fetch_add(1, Ordering::Relaxed);
                }
                None => {
                    pending_indices.push(idx);
                }
            }
        }

        {
            let cheap_done = files.len() - pending_indices.len();
            crate::logging::log_debug_at(
                2,
                &format!(
                    "[plan] phase-0a metadata pre-check: {cheap_done}/{} done in {:.1}ms",
                    files.len(),
                    t0a.elapsed().as_secs_f64() * 1000.0,
                ),
            );
        }

        // ── Phase 0b: order-based skip (only for pending files) ───────────────
        // Files are strictly ordered. If pending file[k]'s first-line timestamp
        // is strictly before last_log_ts, every pending file before k is
        // guaranteed entirely processed already.
        let mut order_skip: AHashSet<usize> = AHashSet::new();
        if pending_indices.len() > 1 {
            let last_log_ts = self.db.get_last_log_ts().unwrap_or(0);
            if last_log_ts > 0 {
                let t0b = std::time::Instant::now();
                let pending_first_tss: Vec<Option<i64>> = pending_indices
                    .iter()
                    .map(|&i| super::resume_policy::read_first_line_ts(&files[i]))
                    .collect();
                // Find the rightmost pending file whose first-line ts < last_log_ts.
                // Every pending file before that position is guaranteed fully processed.
                if let Some(pos) = pending_first_tss
                    .iter()
                    .rposition(|ts| ts.map_or(false, |t| t < last_log_ts))
                {
                    for &idx in &pending_indices[..pos] {
                        order_skip.insert(idx);
                    }
                    crate::logging::log_debug_at(2, &format!(
                        "[plan] order-based skip: {} file(s) before boundary (last_log_ts={last_log_ts})",
                        order_skip.len()
                    ));
                }
                crate::logging::log_debug_at(
                    2,
                    &format!(
                        "[plan] phase-0b order-skip: {} skipped/{} pending in {:.1}ms",
                        order_skip.len(),
                        pending_indices.len(),
                        t0b.elapsed().as_secs_f64() * 1000.0,
                    ),
                );
            }
        }

        // ── Phase 1: resolve remaining pending plans ───────────────────────────
        let mut work_files: Vec<(usize, String, FileResumePlan)> = Vec::new();
        let mut file_plans: AHashMap<usize, (String, FileResumePlan)> = AHashMap::new();
        let phase1_total = pending_indices.len() - order_skip.len();
        let t1 = std::time::Instant::now();

        for idx in pending_indices {
            if order_skip.contains(&idx) {
                crate::logging::log_debug_at(
                    2,
                    &format!(
                        "[plan:order_skip] file={} action=skip_order_ts",
                        &files[idx]
                    ),
                );
                files_done.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let filepath = &files[idx];
            let outcome = self.resolve_resume_plan(filepath)?;
            self.log_resolution_plan(filepath, &outcome, "initial");

            if let Some(state) = outcome.skipped_parse_state {
                pending_parse_states.push(state);
            }
            for retired in outcome.retired_parse_states {
                if seen_retired.insert((retired.filepath.clone(), retired.inode)) {
                    retired_parse_states.push(retired);
                }
            }
            if let Some(plan) = outcome.plan {
                file_plans.insert(idx, (filepath.clone(), plan.clone()));
                work_files.push((idx, filepath.clone(), plan));
            } else {
                files_done.fetch_add(1, Ordering::Relaxed);
            }
        }

        crate::logging::log_debug_at(
            2,
            &format!(
                "[plan] phase-1 full resolve: {}/{} to process, {} fingerprint-skipped in {:.1}ms",
                work_files.len(),
                phase1_total,
                phase1_total - work_files.len(),
                t1.elapsed().as_secs_f64() * 1000.0,
            ),
        );

        if work_files.is_empty() {
            return Ok((0, run_acc, pending_parse_states, retired_parse_states));
        }

        // ── Phase 2: create channels ───────────────────────────────────────────
        let (loader_tx, parser_rx) = rtrb::RingBuffer::<LoaderMsg>::new(CHANNEL_CAPACITY);
        let (parser_tx, mut agg_rx) = rtrb::RingBuffer::<ParserMsg>::new(CHANNEL_CAPACITY);

        // ── Phase 3: spawn loader and parser threads ───────────────────────────
        let bytes_done2 = bytes_done.clone();
        let gz_comp_done2 = gz_comp_done.clone();
        let gz_decoded_done2 = gz_decoded_done.clone();
        let loader_handle = std::thread::Builder::new()
            .name("loader".into())
            .spawn(move || {
                loader::run_loader(
                    work_files,
                    loader_tx,
                    bytes_done2,
                    gz_comp_done2,
                    gz_decoded_done2,
                )
            })?;

        let lines_done2 = lines_done.clone();
        let ua = crate::ua::UaParser::new();
        let bot_filter = self.bot_filter;
        let parser_handle = std::thread::Builder::new()
            .name("parser".into())
            .spawn(move || {
                parser_stage::run_parser(parser_rx, parser_tx, lines_done2, ua, bot_filter)
            })?;

        // ── Phase 4: aggregator loop (runs on this thread) ─────────────────────
        let mut total = 0u64;
        let mut last_checkpoint = Instant::now();
        let mut active: Option<ActiveFile> = None;

        loop {
            match pop_blocking(&mut agg_rx) {
                ParserMsg::FileStart { file_idx } => {
                    if let Some((path, plan)) = file_plans.get(&file_idx) {
                        let initial_offset = if plan.compression.is_compressed() {
                            plan.skip_decoded_prefix_bytes
                        } else {
                            plan.offset
                        };
                        active = Some(ActiveFile {
                            path: path.clone(),
                            plan: plan.clone(),
                            last_offset: initial_offset,
                        });
                    }
                }

                ParserMsg::Entries {
                    batch,
                    current_offset,
                } => {
                    if let Some(ref mut af) = active {
                        af.last_offset = current_offset;
                    }
                    total += batch.len() as u64;
                    for (parsed, entry_offset) in batch {
                        // Month boundary detection: when the entry's month differs
                        // from the current accumulator month, finalize the old month.
                        if let Some(entry_month) =
                            Self::entry_month(parsed.entry.time_str(), parsed.entry.month_num)
                        {
                            if !run_acc.current_month.is_empty()
                                && entry_month != run_acc.current_month
                            {
                                // Use this entry's start offset, not the batch end offset.
                                // Everything before entry_offset is already flushed; on
                                // resume we seek here and re-read this M2 entry correctly.
                                let partial = active.as_ref().map(|af| {
                                    let mut ps = af.partial_parse_state();
                                    ps.uncompressed_offset = entry_offset;
                                    ps
                                });
                                let mut ps = pending_parse_states.clone();
                                if let Some(p) = partial {
                                    ps.push(p);
                                }
                                let new_month = entry_month.clone();
                                self.finalize_and_advance_month(
                                    &mut run_acc,
                                    &ps,
                                    &retired_parse_states,
                                    new_month.clone(),
                                )?;
                                *current_month_progress.lock().unwrap() = new_month;
                                pending_parse_states.clear();
                                retired_parse_states.clear();
                                last_checkpoint = Instant::now();
                                checkpoint_last_elapsed
                                    .store(dir_started.elapsed().as_secs(), Ordering::Relaxed);
                            } else if run_acc.current_month.is_empty() {
                                run_acc.current_month = entry_month.clone();
                                *current_month_progress.lock().unwrap() = entry_month;
                                self.db.set_meta("current_month", &run_acc.current_month)?;
                            }
                        }
                        self.aggregate_entry(parsed, &mut run_acc);
                    }

                    if self.checkpoint_due(&last_checkpoint) {
                        if let Some(ref af) = active {
                            pending_parse_states.push(af.partial_parse_state());
                        }
                        self.flush_run(&run_acc, &pending_parse_states, &retired_parse_states)?;
                        let month = run_acc.current_month.clone();
                        run_acc.clear_for_new_month(month);
                        self.geo_cache = AHashMap::new();
                        self.referer_cache = AHashMap::new();
                        pending_parse_states.clear();
                        retired_parse_states.clear();
                        last_checkpoint = Instant::now();
                        checkpoint_last_elapsed
                            .store(dir_started.elapsed().as_secs(), Ordering::Relaxed);
                    }
                }

                ParserMsg::FileDone {
                    file_idx,
                    final_offset,
                    completed,
                } => {
                    if let Some((path, plan)) = file_plans.get(&file_idx) {
                        pending_parse_states.push(make_file_parse_state(
                            path,
                            plan,
                            final_offset,
                            completed,
                        ));
                    }
                    files_done.fetch_add(1, Ordering::Relaxed);
                    active = None;
                }

                ParserMsg::Done => break,
            }
        }

        // ── Phase 5: join worker threads ───────────────────────────────────────
        let loader_result = loader_handle.join().expect("loader thread panicked");
        let _ = parser_handle.join().expect("parser thread panicked");
        loader_result?;

        Ok((total, run_acc, pending_parse_states, retired_parse_states))
    }
}
