use super::*;

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

    // ── parse_ipv4_u32 ────────────────────────────────────────────────────────

    #[test]
    fn parse_ipv4_valid() {
        assert!(parse_ipv4_u32("1.2.3.4").is_some());
        assert_eq!(parse_ipv4_u32("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4_u32("255.255.255.255"), Some(u32::MAX));
    }

    #[test]
    fn parse_ipv4_rejects_invalid() {
        assert!(parse_ipv4_u32("").is_none());
        assert!(parse_ipv4_u32("256.0.0.1").is_none());
        assert!(parse_ipv4_u32("1.2.3").is_none());
        assert!(parse_ipv4_u32("1.2.3.4.5").is_none());
        assert!(parse_ipv4_u32("::1").is_none());
    }

    // ── parse_ipv6_u128 ───────────────────────────────────────────────────────

    #[test]
    fn parse_ipv6_valid() {
        assert!(parse_ipv6_u128("::1").is_some());
        assert!(parse_ipv6_u128("2001:db8::1").is_some());
    }

    #[test]
    fn parse_ipv6_rejects_ipv4() {
        assert!(parse_ipv6_u128("1.2.3.4").is_none());
    }

    // ── parse_unix_timestamp ──────────────────────────────────────────────────

    #[test]
    fn parse_unix_timestamp_utc() {
        // 01/Jan/1970:00:00:00 +0000 → 0
        let ts = parse_unix_timestamp("01/Jan/1970:00:00:00 +0000", 1).unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn parse_unix_timestamp_positive_offset() {
        // 01/Jan/1970:01:00:00 +0100 → still 0 (UTC)
        let ts = parse_unix_timestamp("01/Jan/1970:01:00:00 +0100", 1).unwrap();
        assert_eq!(ts, 0);
    }

    #[test]
    fn parse_unix_timestamp_rejects_short() {
        assert!(parse_unix_timestamp("short", 1).is_none());
    }

    // ── days_from_civil ───────────────────────────────────────────────────────

    #[test]
    fn days_from_civil_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
    }

    #[test]
    fn days_from_civil_known_date() {
        // 2000-01-01 is 10957 days after 1970-01-01
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
    }
}
