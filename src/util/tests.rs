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
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
    }

    #[test]
    fn days_from_civil_second_day() {
        assert_eq!(days_from_civil(1970, 1, 2), 1);
    }

    #[test]
    fn days_from_civil_end_of_first_year() {
        // 1970 has 365 days; Dec 31 is day 364 (0-indexed from Jan 1).
        assert_eq!(days_from_civil(1970, 12, 31), 364);
    }

    #[test]
    fn days_from_civil_day_before_epoch() {
        assert_eq!(days_from_civil(1969, 12, 31), -1);
    }

    #[test]
    fn days_from_civil_leap_day_2000() {
        // 2000 is divisible by 400 → leap year; Feb 29 exists.
        // 2000-01-01=10957, +31 (Jan) +28 (Feb 1..28) = 10957+59 = 11016
        assert_eq!(days_from_civil(2000, 2, 29), 11016);
    }

    #[test]
    fn days_from_civil_march_1_after_leap_day() {
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
    }

    // ── parse_unix_timestamp additional ──────────────────────────────────────

    #[test]
    fn parse_unix_timestamp_negative_offset() {
        // 00:00 in UTC-01:00 = 01:00 UTC = 3600 s
        let ts = parse_unix_timestamp("01/Jan/1970:00:00:00 -0100", 1).unwrap();
        assert_eq!(ts, 3600);
    }

    #[test]
    fn parse_unix_timestamp_invalid_sign_returns_none() {
        let ts = parse_unix_timestamp("01/Jan/1970:00:00:00 *0000", 1);
        assert!(ts.is_none());
    }

    // ── strip_query additional ────────────────────────────────────────────────

    #[test]
    fn strip_query_multiple_question_marks_splits_at_first() {
        assert_eq!(strip_query("/foo?a=1?b=2"), "/foo");
    }

    #[test]
    fn strip_query_leading_question_mark() {
        assert_eq!(strip_query("?foo=bar"), "");
    }

    // ── file_ext additional ───────────────────────────────────────────────────

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

    // ── extract_host_from_url additional ─────────────────────────────────────

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

    // ── parse_ipv4_u32 additional ─────────────────────────────────────────────

    #[test]
    fn parse_ipv4_exact_value() {
        // 1.2.3.4 = (1<<24)|(2<<16)|(3<<8)|4 = 16909060
        assert_eq!(parse_ipv4_u32("1.2.3.4"), Some(16_909_060u32));
    }

    #[test]
    fn parse_ipv4_rejects_trailing_dot() {
        assert!(parse_ipv4_u32("1.2.3.4.").is_none());
    }

    #[test]
    fn parse_ipv4_rejects_leading_dot() {
        assert!(parse_ipv4_u32(".1.2.3.4").is_none());
    }

    #[test]
    fn parse_ipv4_rejects_empty_octet() {
        assert!(parse_ipv4_u32("1..2.3").is_none());
    }

    // ── parse_ipv6_u128 additional ────────────────────────────────────────────

    #[test]
    fn parse_ipv6_loopback_is_one() {
        assert_eq!(parse_ipv6_u128("::1"), Some(1u128));
    }

    #[test]
    fn parse_ipv6_all_zeros() {
        assert_eq!(parse_ipv6_u128("::"), Some(0u128));
    }
}
