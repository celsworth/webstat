use memchr::memchr;

/// A single parsed nginx combined-log entry.
#[derive(Debug)]
pub struct LogEntry<'a> {
    pub ip: &'a str,
    pub time_str: &'a str,
    pub month_num: u8,
    pub method: &'a str,
    pub path: &'a str,
    pub proto: &'a str,
    pub status: u16,
    pub bytes: u64,
    /// Empty string when absent (nginx `-` sentinel or empty field).
    pub referer: &'a str,
    /// Empty string when absent (nginx `-` sentinel or empty field).
    pub user_agent: &'a str,
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
    let b_len = b.len();
    if b_len < 30 {
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
    if pos >= b_len || b[pos] != b'[' {
        return None;
    }
    let ts_start = pos + 1;
    let bracket_end = find_byte(b']', b, ts_start)?;
    let time_str = &line[ts_start..bracket_end];
    if bracket_end < ts_start + 26 {
        return None;
    }
    // month sanity check
    let month_num = month_num(&time_str.as_bytes()[3..6])?;

    // ── request  "METHOD PATH PROTO" ────────────────────────────────────────
    let pos = bracket_end + 2; // skip '] '
    if pos >= b_len || b[pos] != b'"' {
        return None;
    }
    let req_start = pos + 1;
    let req_end = find_byte(b'"', b, req_start)?;
    let request = &line[req_start..req_end];
    if b[req_start..req_end].iter().any(|&c| c < 32 || c > 126) {
        return None;
    }

    // ── status (3 ASCII digits) ──────────────────────────────────────────────
    let pos = req_end + 2; // skip '" '
    if pos + 3 > b_len {
        return None;
    }
    let status = parse_u16_3(b, pos)?;
    let pos = pos + 4; // skip 'NNN '

    // ── bytes ────────────────────────────────────────────────────────────────
    let sp = find_byte(b' ', b, pos)?;
    let bytes = parse_u64(&b[pos..sp]).unwrap_or(0);

    // ── referer  "..." ───────────────────────────────────────────────────────
    let pos = sp + 1;
    if pos >= b_len || b[pos] != b'"' {
        return None;
    }
    let ref_start = pos + 1;
    let ref_end = find_byte(b'"', b, ref_start)?;
    let referer_str = &line[ref_start..ref_end];

    // ── user agent  "..." ────────────────────────────────────────────────────
    let pos = ref_end + 2; // skip '" '
    if pos >= b_len || b[pos] != b'"' {
        return None;
    }
    let ua_start = pos + 1;
    let ua_end = find_byte(b'"', b, ua_start)?;
    let ua_str = &line[ua_start..ua_end];

    let (method, path, proto) = split_request(request);
    if !proto.starts_with("HTTP/") {
        return None;
    }

    Some(LogEntry {
        ip,
        time_str,
        month_num,
        method,
        path,
        proto,
        status,
        bytes,
        referer: if referer_str.is_empty() || referer_str == "-" {
            ""
        } else {
            referer_str
        },
        user_agent: if ua_str.is_empty() || ua_str == "-" {
            ""
        } else {
            ua_str
        },
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

#[inline]
fn split_request(req: &str) -> (&str, &str, &str) {
    let b = req.as_bytes();

    let Some(sp1) = memchr(b' ', b) else {
        return ("", req, "");
    };

    let method = &req[..sp1];

    let tail = &b[sp1 + 1..];

    let Some(rel_sp2) = memchr(b' ', tail) else {
        return (method, &req[sp1 + 1..], "");
    };

    let sp2 = sp1 + 1 + rel_sp2;

    (method, &req[sp1 + 1..sp2], &req[sp2 + 1..])
}

#[cfg(test)]
mod tests;
