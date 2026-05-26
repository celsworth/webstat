// Combined Log Format parser: converts a raw nginx/Apache combined-format
// line into a LogEntry, plus timestamp parsing.

use super::LogEntry;

/// Parse one line of nginx combined-log format into an owned entry.
///
/// Nginx combined format:
///   IP IDENT USER [TIMESTAMP] "REQUEST" STATUS BYTES "REFERER" "UA"
///
/// Returns `None` for blank or malformed lines.
pub fn parse_line(line: impl Into<String>) -> Option<LogEntry> {
    let line = line.into();
    let b = line.as_bytes();
    let len = b.len();

    let mut i = 0;

    // ─────────────────────────────────────────────
    // IP
    let ip_start = 0;
    while i < len && b[i] != b' ' {
        i += 1;
    }
    if i == 0 {
        return None;
    }
    let ip = ip_start..i;

    i += 1;

    // ident
    while i < len && b[i] != b' ' {
        i += 1;
    }
    i += 1;

    // user
    while i < len && b[i] != b' ' {
        i += 1;
    }
    i += 1;

    // ─────────────────────────────────────────────
    // timestamp
    if i >= len || b[i] != b'[' {
        return None;
    }
    i += 1;

    let time_start = i;
    while i < len && b[i] != b']' {
        i += 1;
    }
    if i >= len {
        return None;
    }

    let time = time_start..i;

    if i + 2 >= len || b[i + 1] != b' ' {
        return None;
    }

    // Timestamp must be at least 26 chars: "DD/Mon/YYYY:HH:MM:SS ±HHMM"
    if time.len() < 26 {
        return None;
    }

    let month_num = month_num(b.get(time_start + 3..time_start + 6)?)?;

    i += 2; // "] "

    // ─────────────────────────────────────────────
    // request
    if i >= len || b[i] != b'"' {
        return None;
    }
    i += 1;

    let req_start = i;
    while i < len && b[i] != b'"' {
        i += 1;
    }
    if i >= len || i <= req_start {
        return None;
    }

    let req_end = i;
    let request = req_start..req_end;

    let req_b = &b[request.clone()];

    // reject non-ASCII characters in request
    if !req_b.is_ascii() {
        return None;
    }

    // reject non-HTTP / TLS / garbage
    if !(req_b.starts_with(b"GET ")
        || req_b.starts_with(b"HEAD ")
        || req_b.starts_with(b"OPTIONS ")
        || req_b.starts_with(b"POST ")
        || req_b.starts_with(b"PATCH ")
        || req_b.starts_with(b"PUT ")
        || req_b.starts_with(b"DELETE ")
        || req_b.starts_with(b"CONNECT ")
        || req_b.starts_with(b"PROPFIND ")
        || req_b.starts_with(b"PRI "))
    {
        return None;
    }

    i += 2; // "\" "

    // ─────────────────────────────────────────────
    // status
    while i < len && b[i] == b' ' {
        i += 1;
    }

    let status_start = i;
    while i < len && b[i] != b' ' {
        i += 1;
    }

    if i <= status_start {
        return None;
    }

    let status = parse_u16_3(b, status_start)?;
    i += 1;

    // ─────────────────────────────────────────────
    // bytes
    while i < len && b[i] == b' ' {
        i += 1;
    }

    let bytes_start = i;
    while i < len && b[i] != b' ' {
        i += 1;
    }

    let bytes = parse_u64(&b[bytes_start..i]).unwrap_or(0);
    i += 1;

    // ─────────────────────────────────────────────
    // referer
    while i < len && b[i] == b' ' {
        i += 1;
    }

    if i >= len || b[i] != b'"' {
        return None;
    }
    i += 1;

    let ref_start = i;
    while i < len && b[i] != b'"' {
        i += 1;
    }
    if i >= len {
        return None;
    }

    let referer = ref_start..i;
    i += 2; // "\" "

    // ─────────────────────────────────────────────
    // user agent
    while i < len && b[i] == b' ' {
        i += 1;
    }

    if i >= len || b[i] != b'"' {
        return None;
    }
    i += 1;

    let ua_start = i;
    while i < len && b[i] != b'"' {
        i += 1;
    }
    if i >= len {
        return None;
    }

    let user_agent = ua_start..i;
    i += 1; // skip closing "

    // ─────────────────────────────────────────────
    // optional extended fields:  rt=143 ...
    let tail = b.get(i..).unwrap_or(&[]);
    let upstream_response_time_ms = find_kv_ms(tail, b"us=");

    // ─────────────────────────────────────────────
    // split request (method / path / proto)
    let req = &b[request.clone()];

    let mut j = 0;
    while j < req.len() && req[j] != b' ' {
        j += 1;
    }
    if j == 0 || j >= req.len() {
        return None;
    }

    let method = request.start..request.start + j;

    j += 1;
    let path_start = j + request.start;

    while j < req.len() && req[j] != b' ' {
        j += 1;
    }
    if j >= req.len() {
        return None;
    }

    let path = path_start..request.start + j;

    j += 1;
    if j >= req.len() {
        return None;
    }

    let proto = request.start + j..request.end;

    Some(LogEntry::new(
        line,
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
    ))
}

#[inline]
fn find_kv_ms(b: &[u8], key: &[u8]) -> Option<u32> {
    let mut i = 0;
    while i + key.len() <= b.len() {
        if b[i..].starts_with(key) {
            let start = i + key.len();
            let end = b[start..]
                .iter()
                .position(|&c| !c.is_ascii_digit() && c != b'.')
                .map(|p| start + p)
                .unwrap_or(b.len());

            let slice = &b[start..end];
            if slice.is_empty() {
                return None;
            }

            return if slice.contains(&b'.') {
                // Nginx: float seconds → ms
                parse_float_ms(slice)
            } else {
                // Apache: microseconds → ms
                parse_u64(slice).map(|v| (v / 1_000) as u32)
            };
        }
        i += 1;
    }
    None
}

/// Parse a CLF timestamp (`DD/Mon/YYYY:HH:MM:SS ±HHMM`) into a Unix
/// timestamp (seconds since epoch, UTC).
pub(crate) fn parse_unix_timestamp(time_str: &str, month_num: u8) -> Option<i64> {
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

    let days = crate::parser::days_from_civil(year, month_num as u32, day);
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second - offset)
}

// ── helpers ──────────────────────────────────────────────────────────────────

#[inline]
fn month_num(m: &[u8]) -> Option<u8> {
    match m {
        b"Jan" => Some(1),
        b"Feb" => Some(2),
        b"Mar" => Some(3),
        b"Apr" => Some(4),
        b"May" => Some(5),
        b"Jun" => Some(6),
        b"Jul" => Some(7),
        b"Aug" => Some(8),
        b"Sep" => Some(9),
        b"Oct" => Some(10),
        b"Nov" => Some(11),
        b"Dec" => Some(12),
        _ => None,
    }
}

/// Parse `"N.FFF"` (seconds as ASCII bytes) → milliseconds, rounding at the
/// 4th decimal place. Avoids `f32::parse` for a ~3.7× speedup on this hot path.
#[inline]
pub(crate) fn parse_float_ms(slice: &[u8]) -> Option<u32> {
    let dot = slice.iter().position(|&c| c == b'.')?;
    let whole = parse_u64(&slice[..dot])? as u32;
    let frac = &slice[dot + 1..];
    let ms = match frac.len() {
        0 => 0u32,
        1 => parse_u64(frac)? as u32 * 100,
        2 => parse_u64(frac)? as u32 * 10,
        _ => {
            let top3 = parse_u64(&frac[..3])? as u32;
            if frac.len() > 3 && frac[3] >= b'5' {
                top3 + 1
            } else {
                top3
            }
        }
    };
    Some(whole * 1_000 + ms)
}

#[inline]
fn parse_u16_3(b: &[u8], pos: usize) -> Option<u16> {
    let a = b.get(pos)?.wrapping_sub(b'0');
    let c = b.get(pos + 1)?.wrapping_sub(b'0');
    let d = b.get(pos + 2)?.wrapping_sub(b'0');

    if a > 9 || c > 9 || d > 9 {
        return None;
    }

    Some((a as u16) * 100 + (c as u16) * 10 + d as u16)
}

#[inline]
fn parse_u64(bytes: &[u8]) -> Option<u64> {
    let mut n = 0u64;

    for &c in bytes {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (c - b'0') as u64;
    }

    Some(n)
}
