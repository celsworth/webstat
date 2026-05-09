use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    fn make_shared<'a>(
        bytes_done: &'a AtomicU64,
        lines_done: &'a AtomicU64,
        gz_comp: &'a AtomicU64,
        gz_dec: &'a AtomicU64,
        is_compressed: bool,
        compressed_bytes: u64,
    ) -> SharedProgress<'a> {
        SharedProgress {
            bytes_done,
            lines_done,
            gz_comp_done: gz_comp,
            gz_decoded_done: gz_dec,
            is_compressed,
            compressed_bytes,
        }
    }

    #[test]
    fn flush_shared_none_is_noop() {
        let mut rb = 0u64;
        let mut rl = 0u64;
        let mut last = Instant::now();
        flush_shared_progress(None, 100, 10, &mut rb, &mut rl, &mut last, true, false);
        assert_eq!(rb, 0);
        assert_eq!(rl, 0);
    }

    #[test]
    fn flush_shared_force_flushes_immediately() {
        let bd = AtomicU64::new(0);
        let ld = AtomicU64::new(0);
        let gc = AtomicU64::new(0);
        let gd = AtomicU64::new(0);
        let shared = make_shared(&bd, &ld, &gc, &gd, false, 0);
        let mut rb = 0u64;
        let mut rl = 0u64;
        let mut last = Instant::now();

        flush_shared_progress(
            Some(&shared),
            500,
            50,
            &mut rb,
            &mut rl,
            &mut last,
            true,
            false,
        );
        assert_eq!(bd.load(Ordering::Relaxed), 500);
        assert_eq!(ld.load(Ordering::Relaxed), 50);
        assert_eq!(rb, 500);
        assert_eq!(rl, 50);
    }

    #[test]
    fn flush_shared_below_threshold_does_not_flush() {
        let bd = AtomicU64::new(0);
        let ld = AtomicU64::new(0);
        let gc = AtomicU64::new(0);
        let gd = AtomicU64::new(0);
        let shared = make_shared(&bd, &ld, &gc, &gd, false, 0);
        let mut rb = 0u64;
        let mut rl = 0u64;
        // Set last_flush to just-now so the 1 s timer doesn't fire.
        let mut last = Instant::now();

        // Only 100 bytes — well below the 8 MB threshold.
        flush_shared_progress(
            Some(&shared),
            100,
            5,
            &mut rb,
            &mut rl,
            &mut last,
            false,
            false,
        );
        assert_eq!(bd.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn flush_shared_gzip_force_without_completion_does_not_mark_comp_done() {
        let bd = AtomicU64::new(0);
        let ld = AtomicU64::new(0);
        let gc = AtomicU64::new(0);
        let gd = AtomicU64::new(0);
        let shared = make_shared(&bd, &ld, &gc, &gd, true, 12_345);
        let mut rb = 0u64;
        let mut rl = 0u64;
        let mut last = Instant::now();

        flush_shared_progress(
            Some(&shared),
            500,
            50,
            &mut rb,
            &mut rl,
            &mut last,
            true,
            false,
        );

        assert_eq!(gd.load(Ordering::Relaxed), 0);
        assert_eq!(gc.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn flush_shared_gzip_force_with_completion_marks_comp_done() {
        let bd = AtomicU64::new(0);
        let ld = AtomicU64::new(0);
        let gc = AtomicU64::new(0);
        let gd = AtomicU64::new(0);
        let shared = make_shared(&bd, &ld, &gc, &gd, true, 12_345);
        let mut rb = 0u64;
        let mut rl = 0u64;
        let mut last = Instant::now();

        flush_shared_progress(
            Some(&shared),
            500,
            50,
            &mut rb,
            &mut rl,
            &mut last,
            true,
            true,
        );

        assert_eq!(gd.load(Ordering::Relaxed), 500);
        assert_eq!(gc.load(Ordering::Relaxed), 12_345);
    }

    #[test]
    fn format_lines_formats_correctly() {
        assert_eq!(format_lines(0), "0");
        assert_eq!(format_lines(100), "100");
        assert_eq!(format_lines(999), "999");
        assert_eq!(format_lines(1_000), "1.00k");
        assert_eq!(format_lines(4_030), "4.03k");
        assert_eq!(format_lines(10_000), "10.0k");
        assert_eq!(format_lines(41_500), "41.5k");
        assert_eq!(format_lines(100_000), "100k");
        assert_eq!(format_lines(450_000), "450k");
        assert_eq!(format_lines(1_110_000), "1.11M");
        assert_eq!(format_lines(15_500_000), "15.5M");
        assert_eq!(format_lines(450_000_000), "450M");
    }

    #[test]
    fn format_lps_formats_correctly() {
        assert_eq!(format_lps(0), "0 l/s");
        assert_eq!(format_lps(999), "999 l/s");
        assert_eq!(format_lps(1_500), "2k l/s");
        assert_eq!(format_lps(2_000_000), "2.0M l/s");
    }

    #[test]
    fn format_eta_done_when_bytes_equal() {
        assert_eq!(format_eta(100, 100, 10.0), "done");
    }

    #[test]
    fn format_eta_unknown_when_zero_bps() {
        assert_eq!(format_eta(0, 100, 0.0), "--");
    }

    #[test]
    fn format_eta_seconds() {
        // 50 bytes remaining at 10 b/s = 5 s
        assert_eq!(format_eta(50, 100, 10.0), "5s to go");
    }

    #[test]
    fn format_eta_minutes() {
        // 120 bytes remaining at 1 b/s = 120 s = 2m0s
        assert_eq!(format_eta(0, 120, 1.0), "2m0s to go");
    }

    #[test]
    fn checkpoint_status_no_checkpoint_yet() {
        assert_eq!(
            format_checkpoint_status(10, 300, CHECKPOINT_NONE),
            "no checkpoint yet"
        );
    }

    #[test]
    fn checkpoint_status_due_before_first_checkpoint() {
        assert_eq!(
            format_checkpoint_status(301, 300, CHECKPOINT_NONE),
            "checkpoint due"
        );
    }

    #[test]
    fn checkpoint_status_reports_age_after_checkpoint() {
        assert_eq!(
            format_checkpoint_status(345, 300, 300),
            "checkpoint 45s ago"
        );
    }

    #[test]
    fn checkpoint_status_due_after_interval_from_last_checkpoint() {
        assert_eq!(format_checkpoint_status(700, 300, 300), "checkpoint due");
    }
}
