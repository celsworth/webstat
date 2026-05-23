use super::*;

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn checkpoint_status_disabled_when_interval_is_zero() {
        assert_eq!(
            format_checkpoint_status(100, 0, CHECKPOINT_NONE),
            "checkpoint disabled"
        );
    }

    #[test]
    fn format_elapsed_seconds() {
        assert_eq!(format_elapsed(0), "0s");
        assert_eq!(format_elapsed(30), "30s");
        assert_eq!(format_elapsed(59), "59s");
    }

    #[test]
    fn format_elapsed_minutes() {
        assert_eq!(format_elapsed(60), "1m0s");
        assert_eq!(format_elapsed(125), "2m5s");
        assert_eq!(format_elapsed(3599), "59m59s");
    }

    #[test]
    fn format_elapsed_hours() {
        assert_eq!(format_elapsed(3600), "1h0m");
        assert_eq!(format_elapsed(7325), "2h2m");
        assert_eq!(format_elapsed(86399), "23h59m");
    }

    #[test]
    fn format_eta_hours() {
        // 36000 bytes remaining at 1 b/s = 36000 s = 10h0m
        assert_eq!(format_eta(0, 36000, 1.0), "10h0m to go");
    }

    #[test]
    fn format_eta_done_when_bytes_exceed_total() {
        assert_eq!(format_eta(150, 100, 10.0), "done");
    }

    #[test]
    fn format_eta_negative_bps_treated_as_unknown() {
        assert_eq!(format_eta(50, 100, -5.0), "--");
    }

    #[test]
    fn format_lps_larger_values() {
        assert_eq!(format_lps(1_000), "1k l/s");
        assert_eq!(format_lps(10_000), "10k l/s");
        assert_eq!(format_lps(999_999), "1000k l/s");
        assert_eq!(format_lps(1_000_000), "1.0M l/s");
        assert_eq!(format_lps(10_000_000), "10.0M l/s");
    }

    #[test]
    fn format_lines_edge_cases() {
        assert_eq!(format_lines(999_999), "1000k");
        assert_eq!(format_lines(9_999_999), "10.00M");
    }

    #[test]
    fn checkpoint_status_with_zero_elapsed() {
        assert_eq!(
            format_checkpoint_status(0, 300, CHECKPOINT_NONE),
            "no checkpoint yet"
        );
    }

    #[test]
    fn checkpoint_status_large_interval() {
        assert_eq!(
            format_checkpoint_status(500, 3600, CHECKPOINT_NONE),
            "no checkpoint yet"
        );
    }

    #[test]
    fn checkpoint_status_recent_checkpoint_age() {
        assert_eq!(
            format_checkpoint_status(365, 300, 300),
            "checkpoint 1m5s ago"
        );
    }
}
