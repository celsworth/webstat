use super::*;
use ahash::{AHashMap, AHashSet};

use crate::progress::clear_progress_line;
use std::collections::VecDeque;
use std::sync::{mpsc, Condvar, Mutex};

struct CheckpointGateState {
    active_workers: usize,
    paused_workers: usize,
}

struct CheckpointGate {
    requested: AtomicBool,
    generation: AtomicU64,
    state: Mutex<CheckpointGateState>,
    cv: Condvar,
}

impl CheckpointGate {
    fn new(active_workers: usize) -> Self {
        Self {
            requested: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            state: Mutex::new(CheckpointGateState {
                active_workers,
                paused_workers: 0,
            }),
            cv: Condvar::new(),
        }
    }

    fn request_checkpoint(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.requested.store(true, Ordering::SeqCst);
        let mut state = self.state.lock().expect("checkpoint state poisoned");
        state.paused_workers = 0;
        self.cv.notify_all();
    }

    fn pause_if_requested(&self, seen_generation: &mut u64) {
        if !self.requested.load(Ordering::SeqCst) {
            return;
        }

        let generation = self.generation.load(Ordering::SeqCst);
        let mut state = self.state.lock().expect("checkpoint state poisoned");
        if *seen_generation != generation {
            state.paused_workers = state.paused_workers.saturating_add(1);
            *seen_generation = generation;
            self.cv.notify_all();
        }

        while self.requested.load(Ordering::SeqCst) {
            state = self.cv.wait(state).expect("checkpoint state poisoned");
        }
    }

    fn wait_all_paused(&self) {
        let mut state = self.state.lock().expect("checkpoint state poisoned");
        while state.paused_workers < state.active_workers {
            state = self.cv.wait(state).expect("checkpoint state poisoned");
        }
    }

    fn resume(&self) {
        self.requested.store(false, Ordering::SeqCst);
        let mut state = self.state.lock().expect("checkpoint state poisoned");
        state.paused_workers = 0;
        self.cv.notify_all();
    }

    fn worker_exiting(&self) {
        let mut state = self.state.lock().expect("checkpoint state poisoned");
        state.active_workers = state.active_workers.saturating_sub(1);
        self.cv.notify_all();
    }
}

struct SharedVisitState {
    last_seen: AHashMap<VisitStateKey, i64>,
    max_seen_ts: i64,
    dirty: AHashMap<VisitStateKey, i64>,
}

#[inline]
fn merge_max(map: &mut AHashMap<VisitStateKey, i64>, key: VisitStateKey, ts: i64) {
    map.entry(key)
        .and_modify(|v| {
            if ts > *v {
                *v = ts;
            }
        })
        .or_insert(ts);
}

enum WorkerMessage {
    Completed(WorkResult),
    Error(anyhow::Error),
}

impl Processor {
    fn absorb_shared_visit(&mut self, sv: &mut SharedVisitState) {
        if sv.max_seen_ts > self.visit_max_seen_ts {
            self.visit_max_seen_ts = sv.max_seen_ts;
        }
        for (key, ts) in sv.dirty.drain() {
            merge_max(&mut self.visit_last_seen, key.clone(), ts);
            merge_max(&mut self.visit_state_dirty, key, ts);
        }
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
            // Time-weighted EMA for throughput. Alpha is computed per-tick so
            // the smoothing is correct even if the sleep interval drifts.
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
                        instant_rate // seed on first real measurement
                    } else {
                        alpha * instant_rate + (1.0 - alpha) * ema_bytes_per_sec
                    };
                    last_tick_bytes = current_bytes_done;
                    last_tick_time = now;
                }

                let recent_bytes_per_sec = ema_bytes_per_sec;

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
                    recent_bytes_per_sec,
                    checkpoint_interval_secs,
                    checkpoint_last_elapsed.load(Ordering::Relaxed),
                );
                rendering_progress.store(false, Ordering::Relaxed);
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn dispatch_parallel_files(
        &mut self,
        files: &[String],
        raw_file_sizes: &[u64],
        is_compressed_vec: &[bool],
        workers: usize,
        bytes_done: Arc<AtomicU64>,
        lines_done: Arc<AtomicU64>,
        gz_comp_done: Arc<AtomicU64>,
        gz_decoded_done: Arc<AtomicU64>,
        files_done: Arc<AtomicUsize>,
        checkpoint_last_elapsed: Arc<AtomicU64>,
        progress_enabled: Arc<AtomicBool>,
        pause_progress: Arc<AtomicBool>,
        rendering_progress: Arc<AtomicBool>,
        dir_started: Instant,
    ) -> Result<(
        u64,
        RunAccumulators,
        Vec<ParseStateUpdate>,
        Vec<ParseStateUpdate>,
    )> {
        let count = files.len();
        if count == 0 {
            return Ok((
                0,
                RunAccumulators::new(
                    64,
                    self.hll_precision,
                    self.enable_top_urls,
                    self.enable_top_hosts,
                    self.enable_top_refs,
                ),
                Vec::new(),
                Vec::new(),
            ));
        }

        let mut total = 0u64;
        let mut run_acc = RunAccumulators::new(
            64,
            self.hll_precision,
            self.enable_top_urls,
            self.enable_top_hosts,
            self.enable_top_refs,
        );
        let mut pending_parse_states = Vec::with_capacity(count);
        let mut retired_parse_states = Vec::with_capacity(count);
        let mut paused_files = Vec::new();
        let mut last_checkpoint = Instant::now();
        let mut checkpoint_in_progress = false;
        let mut completed_files = 0usize;

        let mut resolved_plans = Vec::with_capacity(count);
        let mut work_queue = VecDeque::new();
        let mut seen_retired = AHashSet::new();

        for (idx, filepath) in files.iter().enumerate() {
            let resolution = self.resolve_resume_plan(filepath)?;
            self.log_resolution_plan(filepath, &resolution, "initial");

            if let Some(state) = resolution.skipped_parse_state {
                pending_parse_states.push(state);
            }
            if resolution.plan.is_none() {
                completed_files += 1;
                files_done.fetch_add(1, Ordering::Relaxed);
            }
            for retired in resolution.retired_parse_states {
                if seen_retired.insert((retired.filepath.clone(), retired.inode)) {
                    retired_parse_states.push(retired);
                }
            }
            if let Some(plan) = resolution.plan {
                resolved_plans.push(Some(plan));
                work_queue.push_back(idx);
            } else {
                resolved_plans.push(None);
            }
        }

        if work_queue.is_empty() {
            return Ok((0, run_acc, pending_parse_states, retired_parse_states));
        }

        // Show directory progress only once phase-one planning has produced runnable work.
        progress_enabled.store(true, Ordering::Relaxed);

        let db_path = self.db_path.clone();
        let geoip_db = self.geoip_db.clone();
        let worker_cfg = self.worker_config();
        let checkpoint_enabled = self.checkpoint_every.is_some();
        let shared_visit: Arc<Mutex<SharedVisitState>> = Arc::new(Mutex::new(SharedVisitState {
            last_seen: self.visit_last_seen.clone(),
            max_seen_ts: self.visit_max_seen_ts,
            dirty: AHashMap::new(),
        }));

        let worker_count = workers.max(1).min(work_queue.len());
        let gate = Arc::new(CheckpointGate::new(worker_count));
        let abort = Arc::new(AtomicBool::new(false));
        let queue = Arc::new(Mutex::new(work_queue));
        let files = Arc::new(files.to_vec());
        let plans = Arc::new(Mutex::new(resolved_plans));
        let raw_file_sizes = Arc::new(raw_file_sizes.to_vec());
        let is_compressed_vec = Arc::new(is_compressed_vec.to_vec());

        let (tx, rx) = mpsc::channel::<WorkerMessage>();
        let mut handles = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let tx = tx.clone();
            let gate = gate.clone();
            let abort = abort.clone();
            let queue = queue.clone();
            let files = files.clone();
            let plans = plans.clone();
            let raw_file_sizes = raw_file_sizes.clone();
            let is_compressed_vec = is_compressed_vec.clone();
            let db_path = db_path.clone();
            let geoip_db = geoip_db.clone();
            let worker_cfg = worker_cfg.clone();
            let bytes_done = bytes_done.clone();
            let lines_done = lines_done.clone();
            let gz_comp_done = gz_comp_done.clone();
            let gz_decoded_done = gz_decoded_done.clone();
            let shared_visit = shared_visit.clone();

            handles.push(std::thread::spawn(move || {
                let db = match Database::open(&db_path) {
                    Ok(db) => db,
                    Err(err) => {
                        let _ = tx.send(WorkerMessage::Error(err));
                        gate.worker_exiting();
                        return;
                    }
                };
                let geo = Geo::new(geoip_db.as_deref());
                let ua = UaParser::new();
                let mut worker = Processor::new(
                    db,
                    geo,
                    ua,
                    db_path.clone(),
                    geoip_db.clone(),
                    1,
                    worker_cfg,
                );

                let mut seen_generation = 0u64;
                let mut progress_flush_last = Instant::now();

                loop {
                    if abort.load(Ordering::Relaxed) {
                        break;
                    }

                    gate.pause_if_requested(&mut seen_generation);
                    if abort.load(Ordering::Relaxed) {
                        break;
                    }

                    let Some(idx) = ({ queue.lock().expect("work queue poisoned").pop_front() })
                    else {
                        break;
                    };

                    let filepath = &files[idx];
                    let plan = plans.lock().expect("plan queue poisoned")[idx]
                        .clone()
                        .expect("phase-one plan missing for queued file");

                    let sv = shared_visit.lock().expect("shared visit poisoned");
                    worker.visit_last_seen.clone_from(&sv.last_seen);
                    worker.visit_max_seen_ts = sv.max_seen_ts;
                    drop(sv);
                    worker.visit_state_dirty.clear();

                    let mut worker_run_acc = RunAccumulators::new(
                        64,
                        worker.hll_precision,
                        worker.enable_top_urls,
                        worker.enable_top_hosts,
                        worker.enable_top_refs,
                    );
                    let mut worker_pending_parse_states = Vec::with_capacity(1);

                    match worker.process_with_progress(
                        filepath,
                        idx + 1,
                        files.len(),
                        plan,
                        Some(SharedProgress {
                            bytes_done: &bytes_done,
                            lines_done: &lines_done,
                            gz_comp_done: &gz_comp_done,
                            gz_decoded_done: &gz_decoded_done,
                            is_compressed: is_compressed_vec[idx],
                            compressed_bytes: raw_file_sizes[idx],
                        }),
                        Some(&gate.requested),
                        &mut worker_run_acc,
                        &mut worker_pending_parse_states,
                        &mut progress_flush_last,
                    ) {
                        Ok(result) => {
                            if !worker.visit_state_dirty.is_empty() {
                                let mut sv = shared_visit.lock().expect("shared visit poisoned");
                                for (key, ts) in worker.visit_state_dirty.drain() {
                                    merge_max(&mut sv.last_seen, key.clone(), ts);
                                    merge_max(&mut sv.dirty, key, ts);
                                    if ts > sv.max_seen_ts {
                                        sv.max_seen_ts = ts;
                                    }
                                }
                            }
                            let _ = tx.send(WorkerMessage::Completed(WorkResult {
                                file_idx: idx,
                                file_completed: result.file_completed,
                                lines_processed: result.lines_processed,
                                run_acc: worker_run_acc,
                                pending_parse_states: worker_pending_parse_states,
                            }));
                        }
                        Err(err) => {
                            abort.store(true, Ordering::Relaxed);
                            gate.request_checkpoint();
                            let _ = tx.send(WorkerMessage::Error(err));
                            break;
                        }
                    }
                }

                gate.worker_exiting();
            }));
        }

        drop(tx);

        while completed_files < count {
            if checkpoint_enabled
                && !checkpoint_in_progress
                && self.checkpoint_due(&last_checkpoint)
            {
                checkpoint_in_progress = true;
                pause_progress.store(true, Ordering::Relaxed);
                while rendering_progress.load(Ordering::Relaxed) {
                    std::thread::yield_now();
                }
                clear_progress_line();
                eprintln!();
                gate.request_checkpoint();
            }

            match rx.recv_timeout(std::time::Duration::from_millis(50)) {
                Ok(WorkerMessage::Completed(work)) => {
                    total += work.lines_processed;
                    run_acc.merge_from(work.run_acc, self.hll_precision, self.topn_k);
                    pending_parse_states.extend(work.pending_parse_states);

                    if work.file_completed {
                        completed_files += 1;
                        files_done.fetch_add(1, Ordering::Relaxed);
                    } else {
                        paused_files.push(work.file_idx);
                    }
                }
                Ok(WorkerMessage::Error(err)) => {
                    abort.store(true, Ordering::Relaxed);
                    gate.request_checkpoint();
                    gate.resume();
                    for handle in handles {
                        let _ = handle.join();
                    }
                    return Err(err);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    break;
                }
            }

            if checkpoint_in_progress {
                gate.wait_all_paused();

                loop {
                    match rx.try_recv() {
                        Ok(WorkerMessage::Completed(work)) => {
                            total += work.lines_processed;
                            run_acc.merge_from(work.run_acc, self.hll_precision, self.topn_k);
                            pending_parse_states.extend(work.pending_parse_states);

                            if work.file_completed {
                                completed_files += 1;
                                files_done.fetch_add(1, Ordering::Relaxed);
                            } else {
                                paused_files.push(work.file_idx);
                            }
                        }
                        Ok(WorkerMessage::Error(err)) => {
                            abort.store(true, Ordering::Relaxed);
                            gate.resume();
                            for handle in handles {
                                let _ = handle.join();
                            }
                            return Err(err);
                        }
                        Err(mpsc::TryRecvError::Empty) => break,
                        Err(mpsc::TryRecvError::Disconnected) => break,
                    }
                }

                // Drain shared visit dirty into self before flushing to DB.
                let mut sv = shared_visit.lock().expect("shared visit poisoned");
                self.absorb_shared_visit(&mut sv);
                // Prune shared last_seen to match post-flush state.
                if self.visit_max_seen_ts > 0 {
                    let cutoff = self.visit_max_seen_ts.saturating_sub(VISIT_TIMEOUT_SECONDS);
                    sv.last_seen.retain(|_, ts| *ts >= cutoff);
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
                {
                    let mut plan_slots = plans.lock().expect("plan queue poisoned");
                    let mut q = queue.lock().expect("work queue poisoned");
                    for idx in paused_files.drain(..) {
                        let resolution = self.resolve_resume_plan(&files[idx])?;
                        self.log_resolution_plan(&files[idx], &resolution, "checkpoint");
                        if let Some(state) = resolution.skipped_parse_state {
                            pending_parse_states.push(state);
                            completed_files += 1;
                            files_done.fetch_add(1, Ordering::Relaxed);
                            plan_slots[idx] = None;
                        } else if let Some(plan) = resolution.plan {
                            plan_slots[idx] = Some(plan);
                            q.push_back(idx);
                        } else {
                            completed_files += 1;
                            files_done.fetch_add(1, Ordering::Relaxed);
                            plan_slots[idx] = None;
                        }
                        for retired in resolution.retired_parse_states {
                            if seen_retired.insert((retired.filepath.clone(), retired.inode)) {
                                retired_parse_states.push(retired);
                            }
                        }
                    }
                }
                last_checkpoint = Instant::now();
                checkpoint_last_elapsed.store(dir_started.elapsed().as_secs(), Ordering::Relaxed);
                checkpoint_in_progress = false;
                gate.resume();
                pause_progress.store(false, Ordering::Relaxed);
            }
        }

        gate.request_checkpoint();
        gate.resume();
        for handle in handles {
            let _ = handle.join();
        }

        // Drain any remaining shared visit dirty into self for the final flush_run.
        let mut sv = shared_visit.lock().expect("shared visit poisoned");
        self.absorb_shared_visit(&mut sv);

        Ok((total, run_acc, pending_parse_states, retired_parse_states))
    }
}
