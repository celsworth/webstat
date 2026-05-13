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
            compressed_size: if is_compressed { self.plan.stat_size } else { 0 },
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
        compressed_offset: if is_compressed && completed { plan.stat_size } else { 0 },
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
        files_done: Arc<AtomicUsize>,
        bytes_done: Arc<AtomicU64>,
        lines_done: Arc<AtomicU64>,
        gz_comp_done: Arc<AtomicU64>,
        gz_decoded_done: Arc<AtomicU64>,
        checkpoint_last_elapsed: Arc<AtomicU64>,
        dir_started: Instant,
    ) -> Result<(u64, RunAccumulators, Vec<ParseStateUpdate>, Vec<ParseStateUpdate>)> {
        let count = files.len();
        let mut run_acc = RunAccumulators::new(
            64,
            self.hll_precision,
            self.enable_top_urls,
            self.enable_top_hosts,
            self.enable_top_refs,
        );
        let mut pending_parse_states: Vec<ParseStateUpdate> = Vec::with_capacity(count);
        let mut retired_parse_states: Vec<ParseStateUpdate> = Vec::with_capacity(count);
        let mut seen_retired: AHashSet<(String, u64)> = AHashSet::new();

        // ── Phase 1: resolve all resume plans ─────────────────────────────────
        let mut work_files: Vec<(usize, String, FileResumePlan)> = Vec::new();
        let mut file_plans: AHashMap<usize, (String, FileResumePlan)> = AHashMap::new();

        for (idx, filepath) in files.iter().enumerate() {
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
                loader::run_loader(work_files, loader_tx, bytes_done2, gz_comp_done2, gz_decoded_done2)
            })?;

        let lines_done2 = lines_done.clone();
        let parser_handle = std::thread::Builder::new()
            .name("parser".into())
            .spawn(move || parser_stage::run_parser(parser_rx, parser_tx, lines_done2))?;

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

                ParserMsg::Entries { batch, current_offset } => {
                    if let Some(ref mut af) = active {
                        af.last_offset = current_offset;
                    }
                    total += batch.len() as u64;
                    for entry in batch {
                        self.aggregate_owned(entry, &mut run_acc);
                    }

                    if self.checkpoint_due(&last_checkpoint) {
                        if let Some(ref af) = active {
                            pending_parse_states.push(af.partial_parse_state());
                        }
                        self.flush_run(&run_acc, &pending_parse_states, &retired_parse_states)?;
                        run_acc = RunAccumulators::new(
                            64,
                            self.hll_precision,
                            self.enable_top_urls,
                            self.enable_top_hosts,
                            self.enable_top_refs,
                        );
                        pending_parse_states.clear();
                        retired_parse_states.clear();
                        last_checkpoint = Instant::now();
                        checkpoint_last_elapsed
                            .store(dir_started.elapsed().as_secs(), Ordering::Relaxed);
                    }
                }

                ParserMsg::FileDone { file_idx, final_offset, completed } => {
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
