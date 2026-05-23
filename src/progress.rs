use std::io::{IsTerminal, Write};
use std::time::Instant;

use crate::util::current_log_timestamp;

const CHECKPOINT_NONE: u64 = u64::MAX;
const ANSI_CLEAR_LINE: &str = "\r\x1b[2K";

/// Write the aggregate directory-level progress line to stderr.
///
/// `gz_comp_done` / `gz_decoded_done` track completed gz files so we can
/// refine the compression-ratio estimate for files not yet processed.
/// `default_gz_ratio` is the fallback when no gz files have completed yet.
pub fn print_dir_progress(
    files_done: usize,
    files_total: usize,
    bytes_done: u64,
    resume_baseline_bytes: u64,
    total_plain: u64,
    total_gz_comp: u64,
    gz_comp_done: u64,
    gz_decoded_done: u64,
    lines_done: u64,
    started: Instant,
    default_gz_ratio: f64,
    recent_bytes_per_sec: f64,
    checkpoint_interval_secs: u64,
    checkpoint_last_elapsed_secs: u64,
    current_month: &str,
) {
    let gz_ratio = if gz_comp_done > 0 {
        gz_decoded_done as f64 / gz_comp_done as f64
    } else {
        default_gz_ratio
    };
    let bytes_total = total_plain + (total_gz_comp as f64 * gz_ratio) as u64;

    let elapsed = started.elapsed().as_secs_f64();
    let pct = if bytes_total > 0 {
        (bytes_done as f64 / bytes_total as f64 * 100.0).min(100.0)
    } else {
        0.0
    };
    let lps = if elapsed > 0.0 {
        (lines_done as f64 / elapsed) as u64
    } else {
        0
    };

    let run_bytes_done = bytes_done.saturating_sub(resume_baseline_bytes);
    let bytes_per_sec = if recent_bytes_per_sec > 0.0 {
        recent_bytes_per_sec
    } else if elapsed > 0.1 {
        run_bytes_done as f64 / elapsed
    } else {
        0.0
    };

    let lines_part = format!("{} lines", format_lines(lines_done));
    let eta_str = if files_done >= files_total {
        "done".to_string()
    } else {
        // Cap to prevent the byte-estimate overshoot from triggering "done" early.
        let effective_done = bytes_done.min(bytes_total.saturating_sub(1));
        format_eta(effective_done, bytes_total, bytes_per_sec)
    };
    let lps_str = format_lps(lps);
    let checkpoint_status = format_checkpoint_status(
        started.elapsed().as_secs(),
        checkpoint_interval_secs,
        checkpoint_last_elapsed_secs,
    );
    let ts = current_log_timestamp();

    let month_part = if current_month.is_empty() {
        String::new()
    } else {
        format!(" [{}]", current_month)
    };

    let msg = format!(
        "{}{} [{}/{} files] [{}] [{:.0}%] [{}] [{}] [{}]",
        ts,
        month_part,
        files_done,
        files_total,
        lines_part,
        pct,
        lps_str,
        eta_str,
        checkpoint_status
    );
    write_progress_line(&msg);
}

/// Clear the current in-place progress line from stderr.
pub fn clear_progress_line() {
    let mut stderr = std::io::stderr();
    if stderr.is_terminal() {
        let _ = write!(stderr, "{ANSI_CLEAR_LINE}\r");
    } else {
        let _ = write!(stderr, "\r");
    }
    let _ = stderr.flush();
}

// ── Shared formatting helpers ─────────────────────────────────────────────────

fn write_progress_line(msg: &str) {
    let mut stderr = std::io::stderr();
    if stderr.is_terminal() {
        let _ = write!(stderr, "{ANSI_CLEAR_LINE}{msg}");
    } else {
        let _ = write!(stderr, "\r{msg}");
    }
    let _ = stderr.flush();
}

fn format_lps(lps: u64) -> String {
    if lps >= 1_000_000 {
        format!("{:.1}M l/s", lps as f64 / 1_000_000.0)
    } else if lps >= 1_000 {
        format!("{:.0}k l/s", lps as f64 / 1_000.0)
    } else {
        format!("{} l/s", lps)
    }
}

fn format_lines(n: u64) -> String {
    if n < 1_000 {
        format!("{}", n)
    } else if n < 10_000 {
        format!("{:.2}k", n as f64 / 1_000.0)
    } else if n < 100_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else if n < 1_000_000 {
        format!("{:.0}k", n as f64 / 1_000.0)
    } else if n < 10_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n < 100_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else {
        format!("{:.0}M", n as f64 / 1_000_000.0)
    }
}

fn format_eta(bytes_done: u64, bytes_total: u64, bytes_per_sec: f64) -> String {
    if bytes_done >= bytes_total {
        return "done".to_string();
    }
    if bytes_per_sec <= 0.0 {
        return "--".to_string();
    }
    let eta_s = ((bytes_total - bytes_done) as f64 / bytes_per_sec) as u64;
    if eta_s >= 3600 {
        format!("{}h{}m to go", eta_s / 3600, (eta_s % 3600) / 60)
    } else if eta_s >= 60 {
        format!("{}m{}s to go", eta_s / 60, eta_s % 60)
    } else {
        format!("{}s to go", eta_s)
    }
}

fn format_checkpoint_status(
    elapsed_secs: u64,
    checkpoint_interval_secs: u64,
    checkpoint_last_elapsed_secs: u64,
) -> String {
    if checkpoint_interval_secs == 0 {
        return "checkpoint disabled".to_string();
    }

    if checkpoint_last_elapsed_secs == CHECKPOINT_NONE {
        if elapsed_secs >= checkpoint_interval_secs {
            "checkpoint due".to_string()
        } else {
            "no checkpoint yet".to_string()
        }
    } else {
        let since = elapsed_secs.saturating_sub(checkpoint_last_elapsed_secs);
        if since >= checkpoint_interval_secs {
            "checkpoint due".to_string()
        } else {
            format!("checkpoint {} ago", format_elapsed(since))
        }
    }
}

fn format_elapsed(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}s", secs)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

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
