// Per-entry aggregation: maps each ParsedEntry into the in-memory RunAccumulators
// (hourly stats, URLs, hosts, referrers, agents, countries, IPs, status codes, etc.).

use memchr::{memchr, memrchr};

use super::messages::ParsedEntry;
use super::*;
use crate::ip::Ip;
use crate::method_proto::{method_index, proto_index};
use crate::rules::HideMask;

// ── URL / path helpers ────────────────────────────────────────────────────────

const FILE_EXTS: &[&str] = &[
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".otf", ".woff",
    ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar", ".gz", ".br", ".pdf", ".xml",
    ".json", ".txt",
];

/// Strip the query string from a path (`/foo?bar=1` → `/foo`).
#[inline]
fn strip_query(path: &str) -> &str {
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
fn file_ext(path: &str) -> &str {
    let b = path.as_bytes();
    let start = memrchr(b'/', b).map_or(0, |p| p + 1);
    let filename = &path[start..];
    match memrchr(b'.', filename.as_bytes()) {
        Some(i) => &filename[i..],
        None => "",
    }
}

/// Extract just the hostname from a full URL using a byte scan.
///
/// Returns `None` if `url` has no `://` scheme or an empty host.
#[inline]
fn extract_host_from_url(url: &str) -> Option<Arc<str>> {
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

const MONTHS: [&str; 13] = [
    "", "01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12",
];

/// Update a map keeping only the maximum timestamp per key.
fn merge_max(map: &mut AHashMap<VisitStateKey, i64>, key: VisitStateKey, ts: i64) {
    if let Some(v) = map.get_mut(&key) {
        if ts > *v {
            *v = ts;
        }
    } else {
        map.insert(key, ts);
    }
}

/// Parse two ASCII decimal digits from `b[i..i+2]` without going through str.
#[inline]
pub(super) fn parse_2d(b: &[u8], i: usize) -> Option<u8> {
    let hi = b[i].wrapping_sub(b'0');
    let lo = b[i + 1].wrapping_sub(b'0');
    if hi > 9 || lo > 9 {
        return None;
    }
    Some(hi * 10 + lo)
}

/// Parse four ASCII decimal digits from `b[i..i+4]` without going through str.
#[inline]
pub(super) fn parse_4d(b: &[u8], i: usize) -> Option<i32> {
    let d0 = b[i].wrapping_sub(b'0') as i32;
    let d1 = b[i + 1].wrapping_sub(b'0') as i32;
    let d2 = b[i + 2].wrapping_sub(b'0') as i32;
    let d3 = b[i + 3].wrapping_sub(b'0') as i32;
    if d0 > 9 || d1 > 9 || d2 > 9 || d3 > 9 {
        return None;
    }
    Some(d0 * 1000 + d1 * 100 + d2 * 10 + d3)
}

impl Processor {
    fn visit_state_key(ip: &str) -> (VisitStateKey, Option<Ip>) {
        match Ip::parse(ip) {
            Some(Ip::V4(n)) => (
                VisitStateKey {
                    ip_kind: 1,
                    ip_hi: 0,
                    ip_lo: n as u64,
                    ip_text: String::new(),
                },
                Some(Ip::V4(n)),
            ),
            Some(Ip::V6(n)) => (
                VisitStateKey {
                    ip_kind: 2,
                    ip_hi: (n >> 64) as u64,
                    ip_lo: n as u64,
                    ip_text: String::new(),
                },
                Some(Ip::V6(n)),
            ),
            None => (
                VisitStateKey {
                    ip_kind: 0,
                    ip_hi: 0,
                    ip_lo: 0,
                    ip_text: ip.to_string(),
                },
                None,
            ),
        }
    }

    // ── Per-entry aggregation ─────────────────────────────────────────────────

    /// Extract "YYYY-MM" month string from a log timestamp and month number.
    pub(super) fn entry_month(time_str: &str, mon_num: u8) -> Option<String> {
        let b = time_str.as_bytes();
        if b.len() < 11 {
            return None;
        }
        let year = parse_4d(b, 7)?;
        Some(format!("{year}-{}", MONTHS[mon_num as usize]))
    }

    pub(super) fn aggregate_entry(&mut self, parsed: ParsedEntry, run_acc: &mut RunAccumulators) {
        let ParsedEntry {
            entry,
            ua_family: agent,
            hidden: hide,
        } = parsed;

        let (date, hour, _month_period, request_ts) = {
            match self.time_periods_with_timestamp(entry.time_str(), entry.month_num) {
                Some(v) => v,
                None => return,
            }
        };

        let status = entry.status;
        let bytes = entry.bytes;
        let ip = entry.ip();
        let path = entry.path();
        let clean_path = strip_query(path);

        // ── Hourly bucket ──────────────────────────────────────────────────────
        let h = run_acc
            .hourly
            .entry(Arc::clone(&date))
            .or_default()
            .entry(hour)
            .or_default();
        let stats = &mut h.stats;

        let (visit_key, parsed_ip) = Self::visit_state_key(ip);

        if let Some(ts) = request_ts {
            if ts > self.visit_max_seen_ts {
                self.visit_max_seen_ts = ts;
            }
            let (is_new_visit, dirty_ts) = match self.visit_last_seen.entry(visit_key.clone()) {
                std::collections::hash_map::Entry::Occupied(mut occ) => {
                    let last_seen = *occ.get();
                    let new_ts = last_seen.max(ts);
                    if new_ts > last_seen {
                        *occ.get_mut() = new_ts;
                    }
                    (ts.saturating_sub(last_seen) > VISIT_TIMEOUT_SECONDS, new_ts)
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(ts);
                    (true, ts)
                }
            };
            merge_max(&mut self.visit_state_dirty, visit_key, dirty_ts);
            if is_new_visit {
                stats.visits += 1;
            }
        }

        stats.hits += 1;
        stats.bandwidth += bytes;

        let status_class = status / 100;
        if status_class == 2 {
            stats.status_2xx += 1;
            let ext = file_ext(clean_path);
            if FILE_EXTS.contains(&ext) {
                stats.files += 1;
            } else {
                stats.pages += 1;
            }
        } else if status_class == 3 {
            stats.status_3xx += 1;
        } else if status_class == 4 {
            stats.status_4xx += 1;
        } else {
            stats.status_5xx += 1;
        }

        // ── GeoIP ──────────────────────────────────────────────────────────────
        let (country_code, _country_name) = match parsed_ip {
            Some(ip) => self.geo.lookup(ip),
            None => crate::geo::unknown(),
        };

        // ── Daily unique IPs ───────────────────────────────────────────────────
        if let Some(ip) = parsed_ip {
            run_acc
                .daily_ips
                .entry(date.to_string())
                .or_default()
                .insert(ip);
        }

        // ── Month-period aggregations ──────────────────────────────────────────
        if self.enable_top_urls && !hide.contains(HideMask::URLS) {
            if let Some(e) = run_acc.urls.get_mut(clean_path) {
                e.0 += 1;
                e.1 += bytes;
            } else {
                run_acc.urls.insert(clean_path.to_string(), (1, bytes));
            }
        }

        if self.enable_top_hosts && !hide.contains(HideMask::HOSTS) {
            if let Some(e) = run_acc.hosts.get_mut(ip) {
                e.0 += 1;
                e.1 += bytes;
            } else {
                run_acc.hosts.insert(ip.to_string(), (1, bytes));
            }
        }

        if !hide.contains(HideMask::AGENTS) {
            if let Some(v) = run_acc.agents.get_mut(agent.as_ref()) {
                *v += 1;
            } else {
                run_acc.agents.insert(agent.as_ref().to_string(), 1);
            }
        }

        if self.enable_top_refs && !hide.contains(HideMask::REFS) && !entry.referer().is_empty() {
            if let Some(host) = self.extract_host(entry.referer()) {
                if let Some(v) = run_acc.refs.get_mut(&*host) {
                    *v += 1;
                } else {
                    run_acc.refs.insert(host.to_string(), 1);
                }
            }
        }

        if !hide.contains(HideMask::COUNTRIES) {
            if let Some(v) = run_acc.countries.get_mut(&*country_code) {
                *v += 1;
            } else {
                run_acc.countries.insert(country_code.to_string(), 1);
            }
        }

        *run_acc.status_codes.entry(status).or_insert(0) += 1;
        run_acc.method_counts[method_index(entry.method())] += 1;
        run_acc.proto_counts[proto_index(entry.proto())] += 1;
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// Return `(date, hour, month_period, ts)` decoded from a nginx timestamp.
    /// Results are memoised by (year, month, day, hour) key.
    pub(super) fn time_periods_with_timestamp(
        &mut self,
        time_str: &str,
        mon_num: u8,
    ) -> Option<(Arc<str>, u8, Arc<str>, Option<i64>)> {
        let b = time_str.as_bytes();
        if b.len() < 26 {
            return None;
        }

        let day = parse_2d(b, 0)? as u32;
        let year = parse_4d(b, 7)?;
        let hour = parse_2d(b, 12)?;
        let minute = parse_2d(b, 15)? as i64;
        let second = parse_2d(b, 18)? as i64;

        let sign = b[21];
        let tz_hour = parse_2d(b, 22)? as i64;
        let tz_min = parse_2d(b, 24)? as i64;
        let offset = tz_hour * 3600 + tz_min * 60;
        let offset = match sign {
            b'+' => offset,
            b'-' => -offset,
            _ => return None,
        };

        let key = year as u32 * 1_000_000 + mon_num as u32 * 10_000 + day * 100 + hour as u32;

        if let Some(cached) = self.time_cache.get(&key) {
            let ts = days_from_civil(year, mon_num as u32, day) * 86_400
                + hour as i64 * 3_600
                + minute * 60
                + second
                - offset;
            return Some((Arc::clone(&cached.0), hour, Arc::clone(&cached.1), Some(ts)));
        }

        let mon_s = MONTHS[mon_num as usize];
        let date = Arc::from(format!("{year}-{mon_s}-{day:02}").as_str());
        let month = Arc::from(format!("{year}-{mon_s}").as_str());
        self.time_cache
            .insert(key, (Arc::clone(&date), Arc::clone(&month)));

        let ts = days_from_civil(year, mon_num as u32, day) * 86_400
            + hour as i64 * 3_600
            + minute * 60
            + second
            - offset;

        Some((date, hour, month, Some(ts)))
    }

    fn extract_host(&mut self, url: &str) -> Option<Arc<str>> {
        if let Some(cached) = self.referer_cache.get(url) {
            return Some(Arc::clone(cached));
        }
        let host = extract_host_from_url(url);
        if let Some(ref host_value) = host {
            self.referer_cache
                .insert(url.to_string(), Arc::clone(host_value));
        }
        host
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── strip_query ───────────────────────────────────────────────────────────

    #[test]
    fn strip_query_removes_query_string() {
        assert_eq!(strip_query("/foo?bar=1"), "/foo");
    }

    #[test]
    fn strip_query_no_query_returns_whole_path() {
        assert_eq!(strip_query("/foo/bar"), "/foo/bar");
    }

    #[test]
    fn strip_query_empty_path() {
        assert_eq!(strip_query(""), "");
    }

    #[test]
    fn strip_query_multiple_question_marks_splits_at_first() {
        assert_eq!(strip_query("/foo?a=1?b=2"), "/foo");
    }

    #[test]
    fn strip_query_leading_question_mark() {
        assert_eq!(strip_query("?foo=bar"), "");
    }

    // ── file_ext ──────────────────────────────────────────────────────────────

    #[test]
    fn file_ext_returns_extension() {
        assert_eq!(file_ext("/foo/bar.html"), ".html");
    }

    #[test]
    fn file_ext_no_extension_returns_empty() {
        assert_eq!(file_ext("/foo/bar"), "");
    }

    #[test]
    fn file_ext_dot_in_dir_not_matched() {
        assert_eq!(file_ext("/foo.d/bar"), "");
    }

    #[test]
    fn file_ext_trailing_slash() {
        assert_eq!(file_ext("/foo/"), "");
    }

    #[test]
    fn file_ext_multiple_dots_returns_last() {
        assert_eq!(file_ext("/foo/archive.tar.gz"), ".gz");
    }

    #[test]
    fn file_ext_leading_dot_filename() {
        // Hidden files: the leading dot is treated as extension start.
        assert_eq!(file_ext("/foo/.gitignore"), ".gitignore");
    }

    #[test]
    fn file_ext_root_path_empty() {
        assert_eq!(file_ext("/"), "");
    }

    #[test]
    fn file_ext_just_dot_in_filename() {
        assert_eq!(file_ext("/foo/."), ".");
    }

    // ── extract_host_from_url ─────────────────────────────────────────────────

    #[test]
    fn extract_host_basic() {
        let h = extract_host_from_url("https://example.com/path").unwrap();
        assert_eq!(h.as_ref(), "example.com");
    }

    #[test]
    fn extract_host_strips_port() {
        let h = extract_host_from_url("http://example.com:8080/").unwrap();
        assert_eq!(h.as_ref(), "example.com");
    }

    #[test]
    fn extract_host_no_scheme_returns_none() {
        assert!(extract_host_from_url("example.com/path").is_none());
    }

    #[test]
    fn extract_host_empty_host_returns_none() {
        assert!(extract_host_from_url("http:///path").is_none());
    }

    #[test]
    fn extract_host_no_trailing_slash() {
        let h = extract_host_from_url("https://example.com").unwrap();
        assert_eq!(h.as_ref(), "example.com");
    }

    #[test]
    fn extract_host_query_immediately_after_host() {
        let h = extract_host_from_url("https://example.com?foo=bar").unwrap();
        assert_eq!(h.as_ref(), "example.com");
    }

    #[test]
    fn extract_host_scheme_separator_only_returns_none() {
        assert!(extract_host_from_url("://").is_none());
    }
}
