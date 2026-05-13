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

    let msg = format!(
        "{} [{}/{} files] [{}] [{:.0}%] [{}] [{}] [{}]",
        ts, files_done, files_total, lines_part, pct, lps_str, eta_str, checkpoint_status
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
mod tests;
