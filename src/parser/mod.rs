// Log parser types and format dispatch.
// LogEntry is the common parsed-line representation used throughout the pipeline.

use std::ops::Range;

pub mod combined;

#[derive(Debug)]
pub struct LogEntry {
    raw: String,

    ip: Range<usize>,
    time: Range<usize>,
    method: Range<usize>,
    path: Range<usize>,
    proto: Range<usize>,
    referer: Range<usize>,
    user_agent: Range<usize>,

    pub month_num: u8,
    pub status: u16,
    pub bytes: u64,

    pub upstream_response_time_ms: Option<u32>,
}

impl LogEntry {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        raw: String,
        ip: Range<usize>,
        time: Range<usize>,
        method: Range<usize>,
        path: Range<usize>,
        proto: Range<usize>,
        referer: Range<usize>,
        user_agent: Range<usize>,
        month_num: u8,
        status: u16,
        bytes: u64,
        upstream_response_time_ms: Option<u32>,
    ) -> Self {
        Self {
            raw,
            ip,
            time,
            method,
            path,
            proto,
            referer,
            user_agent,
            month_num,
            status,
            bytes,
            upstream_response_time_ms,
        }
    }

    #[inline]
    fn slice(&self, r: Range<usize>) -> &str {
        &self.raw[r]
    }

    pub fn ip(&self) -> &str {
        self.slice(self.ip.clone())
    }

    pub fn path(&self) -> &str {
        self.slice(self.path.clone())
    }

    pub fn method(&self) -> &str {
        self.slice(self.method.clone())
    }

    pub fn proto(&self) -> &str {
        self.slice(self.proto.clone())
    }

    pub fn referer(&self) -> &str {
        self.slice(self.referer.clone())
    }

    pub fn user_agent(&self) -> &str {
        self.slice(self.user_agent.clone())
    }

    pub fn time_str(&self) -> &str {
        self.slice(self.time.clone())
    }
}

/// Selects which line parser to use for a set of log files.
#[derive(Clone, Copy, Debug)]
pub enum LogFormat {
    Combined,
}

impl LogFormat {
    pub fn parse(&self, line: String) -> Option<LogEntry> {
        match self {
            LogFormat::Combined => combined::parse_line(line),
        }
    }
}

// ── Timestamp arithmetic ──────────────────────────────────────────────────────

/// Convert a civil (proleptic Gregorian) date to a day count.
///
/// Day 0 = 1970-01-01. Uses the algorithm from Howard Hinnant's
/// "chrono-Compatible Low-Level Date Algorithms".
#[inline]
pub fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut y = year as i64;
    let m = month as i64;
    let d = day as i64;

    y -= (m <= 2) as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;

    era * 146_097 + doe - 719_468
}

pub mod stage;

#[cfg(test)]
mod tests;
