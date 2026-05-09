use memchr::memchr;

/// A single parsed nginx combined-log entry.
#[derive(Debug)]
#[allow(dead_code)]
pub struct LogEntry<'a> {
    pub ip: &'a str,
    pub time_str: &'a str,
    pub month_num: u8,
    pub method: Option<&'a str>,
    pub path: Option<&'a str>,
    pub status: u16,
    pub bytes: u64,
    pub referer: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// Parse one line of nginx combined-log format into a `LogEntry`.
///
/// Nginx combined format:
///   IP IDENT USER [TIMESTAMP] "REQUEST" STATUS BYTES "REFERER" "UA"
///
/// All positional searches use byte values; ASCII delimiters (`[`, `]`, `"`,
/// space) are never part of a multi-byte UTF-8 sequence, so slicing at those
/// positions is always on a valid char boundary.
///
/// Returns `None` for blank or malformed lines.
pub fn parse_line(line: &str) -> Option<LogEntry<'_>> {
    let b = line.as_bytes();
    if b.len() < 30 {
        return None;
    }

    // ── IP ──────────────────────────────────────────────────────────────────
    let sp1 = find_byte(b' ', b, 0)?;
    let ip = &line[..sp1];

    // ── ident (always '-', skip) ────────────────────────────────────────────
    let sp2 = find_byte(b' ', b, sp1 + 1)?;

    // ── user (skip) ─────────────────────────────────────────────────────────
    let sp3 = find_byte(b' ', b, sp2 + 1)?;

    // ── timestamp  [ DD/Mon/YYYY:HH:MM:SS ±HHMM ] ───────────────────────────
    let pos = sp3 + 1;
    if b.get(pos) != Some(&b'[') {
        return None;
    }
    let ts_start = pos + 1;
    let bracket_end = find_byte(b']', b, ts_start)?;
    let time_str = &line[ts_start..bracket_end];
    if time_str.len() < 26 {
        return None;
    }
    // month sanity check
    let month_num = month_num(&time_str.as_bytes()[3..6])?;

    // ── request  "METHOD PATH PROTO" ────────────────────────────────────────
    let pos = bracket_end + 2; // skip '] '
    if b.get(pos) != Some(&b'"') {
        return None;
    }
    let req_start = pos + 1;
    let req_end = find_byte(b'"', b, req_start)?;
    let request = &line[req_start..req_end];

    // ── status (3 ASCII digits) ──────────────────────────────────────────────
    let pos = req_end + 2; // skip '" '
    if pos + 3 > b.len() {
        return None;
    }
    let status: u16 = line[pos..pos + 3].parse().ok()?;
    let pos = pos + 4; // skip 'NNN '

    // ── bytes ────────────────────────────────────────────────────────────────
    let sp = find_byte(b' ', b, pos)?;
    let bytes: u64 = line[pos..sp].parse().unwrap_or(0);

    // ── referer  "..." ───────────────────────────────────────────────────────
    let pos = sp + 1;
    if b.get(pos) != Some(&b'"') {
        return None;
    }
    let ref_start = pos + 1;
    let ref_end = find_byte(b'"', b, ref_start)?;
    let referer_str = &line[ref_start..ref_end];

    // ── user agent  "..." ────────────────────────────────────────────────────
    let pos = ref_end + 2; // skip '" '
    if b.get(pos) != Some(&b'"') {
        return None;
    }
    let ua_start = pos + 1;
    let ua_end = find_byte(b'"', b, ua_start)?;
    let ua_str = &line[ua_start..ua_end];

    let (method, path) = split_request(request);

    Some(LogEntry {
        ip,
        time_str,
        month_num,
        method,
        path,
        status,
        bytes,
        referer: opt_str(referer_str),
        user_agent: opt_str(ua_str),
    })
}

/// Parse "DD/Mon/YYYY:HH:MM:SS ±HHMM" and return a month number (1-12).
#[inline]
pub fn month_num(m: &[u8]) -> Option<u8> {
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

// ── helpers ──────────────────────────────────────────────────────────────────

#[inline]
fn find_byte(needle: u8, haystack: &[u8], from: usize) -> Option<usize> {
    memchr(needle, &haystack[from..]).map(|p| p + from)
}

#[inline]
fn split_request(req: &str) -> (Option<&str>, Option<&str>) {
    if req.is_empty() {
        return (None, None);
    }
    match req.as_bytes().iter().position(|&c| c == b' ') {
        None => (None, Some(req)),
        Some(sp1) => {
            let method = &req[..sp1];
            let rest = &req[sp1 + 1..];
            let path = match rest.as_bytes().iter().position(|&c| c == b' ') {
                Some(sp2) => &rest[..sp2],
                None => rest,
            };
            (Some(method), Some(path))
        }
    }
}

#[inline]
fn opt_str(s: &str) -> Option<&str> {
    if s.is_empty() || s == "-" {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests;
