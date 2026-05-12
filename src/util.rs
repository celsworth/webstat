use std::net::Ipv6Addr;
use std::sync::Arc;

use chrono::Local;
use memchr::{memchr, memrchr};

// ── Extension tables ──────────────────────────────────────────────────────────

pub const FILE_EXTS: &[&str] = &[
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".otf", ".woff",
    ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar", ".gz", ".br", ".pdf", ".xml",
    ".json", ".txt",
];

// ── Path utilities ────────────────────────────────────────────────────────────

/// Strip the query string from a path (`/foo?bar=1` → `/foo`).
#[inline]
pub fn strip_query(path: &str) -> &str {
    match memchr(b'?', path.as_bytes()) {
        Some(i) => &path[..i],
        None => path,
    }
}

/// Return the file extension of a path (e.g. `".html"`), or `""` if none.
///
/// Searches only within the last path component to avoid matching dots in
/// directory names.
#[inline]
pub fn file_ext(path: &str) -> &str {
    let b = path.as_bytes();

    let start = memrchr(b'/', b).map_or(0, |p| p + 1);

    let filename = &path[start..];

    match memrchr(b'.', filename.as_bytes()) {
        Some(i) => &filename[i..],
        None => "",
    }
}

// ── URL utilities ─────────────────────────────────────────────────────────────

/// Extract just the hostname from a full URL using a byte scan.
///
/// Returns `None` if `url` has no `://` scheme or an empty host.
#[inline]
pub fn extract_host_from_url(url: &str) -> Option<Arc<str>> {
    let scheme = url.find("://")?;
    let start = scheme + 3;

    if start >= url.len() {
        return None;
    }

    let rest = &url[start..];

    let end = rest
        .as_bytes()
        .iter()
        .position(|&b| b == b'/' || b == b':' || b == b'?')
        .unwrap_or(rest.len());

    if end == 0 {
        return None;
    }

    Some(Arc::from(&rest[..end]))
}
// ── IP parsing ────────────────────────────────────────────────────────────────

/// Fast IPv4 parser — returns big-endian packed octets as `u32`.
#[inline]
pub fn parse_ipv4_u32(ip: &str) -> Option<u32> {
    let bytes = ip.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let mut octets = [0u8; 4];
    let mut octet_idx = 0usize;
    let mut value: u16 = 0;
    let mut saw_digit = false;

    for &b in bytes {
        match b {
            b'0'..=b'9' => {
                saw_digit = true;
                value = value * 10 + (b - b'0') as u16;
                if value > 255 {
                    return None;
                }
            }
            b'.' => {
                if !saw_digit || octet_idx >= 3 {
                    return None;
                }
                octets[octet_idx] = value as u8;
                octet_idx += 1;
                value = 0;
                saw_digit = false;
            }
            _ => return None,
        }
    }

    if !saw_digit || octet_idx != 3 {
        return None;
    }
    octets[3] = value as u8;
    Some(u32::from_be_bytes(octets))
}

/// Parse an IPv6 address string into a `u128`.
#[inline]
pub fn parse_ipv6_u128(ip: &str) -> Option<u128> {
    ip.parse::<Ipv6Addr>().ok().map(u128::from)
}

// ── Timestamp utilities ───────────────────────────────────────────────────────

/// Current local timestamp for log lines.
/// Format: `YYYY-MM-DD HH:MM:SS.mmm`
#[inline]
pub fn current_log_timestamp() -> String {
    Local::now().format("[%Y-%m-%d %H:%M:%S%.3f]").to_string()
}

/// Parse a nginx timestamp (`DD/Mon/YYYY:HH:MM:SS ±HHMM`) into a Unix
/// timestamp (seconds since epoch, UTC).
///
/// Only used in tests.
///
/// Returns `None` on any parse failure.
#[cfg(test)]
pub fn parse_unix_timestamp(time_str: &str, month_num: u8) -> Option<i64> {
    let b = time_str.as_bytes();
    if b.len() < 26 {
        return None;
    }

    let day: u32 = std::str::from_utf8(&b[0..2]).ok()?.parse().ok()?;
    let year: i32 = std::str::from_utf8(&b[7..11]).ok()?.parse().ok()?;
    let hour: i64 = std::str::from_utf8(&b[12..14]).ok()?.parse().ok()?;
    let minute: i64 = std::str::from_utf8(&b[15..17]).ok()?.parse().ok()?;
    let second: i64 = std::str::from_utf8(&b[18..20]).ok()?.parse().ok()?;

    let sign = b[21];
    let tz_hour: i64 = std::str::from_utf8(&b[22..24]).ok()?.parse().ok()?;
    let tz_min: i64 = std::str::from_utf8(&b[24..26]).ok()?.parse().ok()?;
    let offset = tz_hour * 3600 + tz_min * 60;
    let offset = match sign {
        b'+' => offset,
        b'-' => -offset,
        _ => return None,
    };

    let days = days_from_civil(year, month_num as u32, day);
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second - offset)
}

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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
