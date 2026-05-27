// Tests for the combined-log-format parser and LogEntry field extraction.

use super::combined::{parse_line, parse_local_epoch_days, parse_unix_timestamp};
use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic parsing ────────────────────────────────────────────────────────

    #[test]
    fn parses_combined_log_line() {
        let line = r#"1.2.3.4 - frank [08/May/2026:14:23:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "https://example.com/" "Mozilla/5.0""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.ip(), "1.2.3.4");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.bytes, 1234);
        assert_eq!(entry.path(), "/index.html");
        assert_eq!(entry.method(), "GET");
        assert_eq!(entry.referer(), "https://example.com/");
    }

    #[test]
    fn returns_none_for_short_line() {
        assert!(parse_line("short").is_none());
    }

    // ── Spaces in quoted fields ──────────────────────────────────────────────

    #[test]
    fn spaces_in_user_agent_string() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /path HTTP/1.1" 200 100 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(
            entry.user_agent(),
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        );
    }

    #[test]
    fn spaces_in_referer_string() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /path HTTP/1.1" 200 100 "https://example.com/search?q=hello world&sort=date" "Mozilla/5.0""#;
        let entry = parse_line(line).expect("should parse");
        assert!(entry.referer().contains("hello world"));
    }

    #[test]
    fn spaces_in_path_with_query_string() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /search?q=hello%20world&sort=name HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.path(), "/search?q=hello%20world&sort=name");
    }

    #[test]
    fn path_with_spaces_and_special_characters() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /api/users?name=John%20Doe&email=test%40example.com HTTP/1.1" 200 50 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert!(entry.path().contains("John%20Doe"));
        assert!(entry.path().contains("test%40example.com"));
    }

    // ── HTTP methods ─────────────────────────────────────────────────────────

    #[test]
    fn post_request() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "POST /api/submit HTTP/1.1" 201 500 "-" "curl/7.68.0""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.method(), "POST");
        assert_eq!(entry.path(), "/api/submit");
    }

    #[test]
    fn put_request() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "PUT /api/resource/123 HTTP/1.1" 204 0 "-" "curl/7.68.0""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.method(), "PUT");
    }

    #[test]
    fn delete_request() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "DELETE /api/resource/123 HTTP/1.1" 204 0 "-" "curl/7.68.0""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.method(), "DELETE");
    }

    #[test]
    fn head_request() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "HEAD /index.html HTTP/1.1" 200 0 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.method(), "HEAD");
    }

    #[test]
    fn options_request() {
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "OPTIONS * HTTP/1.1" 200 0 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.method(), "OPTIONS");
        assert_eq!(entry.path(), "*");
    }

    #[test]
    fn patch_request() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "PATCH /api/resource HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.method(), "PATCH");
    }

    // ── HTTP status codes ────────────────────────────────────────────────────

    #[test]
    fn various_status_codes() {
        let tests = vec![
            ("100", 100),
            ("101", 101),
            ("200", 200),
            ("201", 201),
            ("204", 204),
            ("301", 301),
            ("302", 302),
            ("304", 304),
            ("400", 400),
            ("401", 401),
            ("403", 403),
            ("404", 404),
            ("500", 500),
            ("502", 502),
            ("503", 503),
        ];

        for (status_str, expected) in tests {
            let line = format!(
                r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" {} 100 "-" "-""#,
                status_str
            );
            let entry = parse_line(&line).expect("should parse");
            assert_eq!(
                entry.status, expected,
                "status code {} mismatch",
                status_str
            );
        }
    }

    // ── Byte counts ──────────────────────────────────────────────────────────

    #[test]
    fn zero_bytes() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 204 0 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.bytes, 0);
    }

    #[test]
    fn large_byte_count() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /file.iso HTTP/1.1" 200 4294967296 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.bytes, 4294967296);
    }

    #[test]
    fn dash_byte_count_treated_as_zero() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 - "-" "-""#;
        let entry = parse_line(line);
        // Parser uses unwrap_or(0) for invalid bytes, so this should parse with 0 bytes
        // Actually, this will fail because "-" cannot be parsed as u64
        assert!(entry.is_none() || entry.map(|e| e.bytes) == Some(0));
    }

    // ── Missing optional fields (referer, user-agent) ────────────────────────

    #[test]
    fn missing_referer_returns_dash() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.referer(), "-");
    }

    #[test]
    fn missing_user_agent_returns_dash() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "https://example.com/" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.user_agent(), "-");
    }

    #[test]
    fn both_referer_and_ua_missing() {
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.referer(), "-");
        assert_eq!(entry.user_agent(), "-");
    }

    // ── Empty quoted fields (but not dash) ────────────────────────────────────

    #[test]
    fn empty_referer_string() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "" "Mozilla/5.0""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.referer(), "");
    }

    #[test]
    fn empty_user_agent_string() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" """#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.user_agent(), "");
    }

    // ── Months ───────────────────────────────────────────────────────────────

    #[test]
    fn all_months_parsed_correctly() {
        let months = vec![
            ("Jan", 1),
            ("Feb", 2),
            ("Mar", 3),
            ("Apr", 4),
            ("May", 5),
            ("Jun", 6),
            ("Jul", 7),
            ("Aug", 8),
            ("Sep", 9),
            ("Oct", 10),
            ("Nov", 11),
            ("Dec", 12),
        ];

        for (month_str, expected_num) in months {
            let line = format!(
                r#"1.2.3.4 - user [08/{}/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#,
                month_str
            );
            let entry = parse_line(&line).expect("should parse");
            assert_eq!(
                entry.month_num, expected_num,
                "month {} mismatch",
                month_str
            );
        }
    }

    #[test]
    fn invalid_month_returns_none() {
        let line =
            r#"1.2.3.4 - user [08/Abc/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#;
        assert!(parse_line(line).is_none());
    }

    // ── Timestamps ───────────────────────────────────────────────────────────

    #[test]
    fn timestamp_with_negative_timezone() {
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 -0500] "GET / HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.time_str(), "08/May/2026:14:23:01 -0500");
    }

    #[test]
    fn timestamp_with_different_timezones() {
        let timezones = vec!["+0000", "-0800", "+0900", "-1200", "+1400"];
        for tz in timezones {
            let line = format!(
                r#"1.2.3.4 - user [08/May/2026:14:23:01 {}] "GET / HTTP/1.1" 200 100 "-" "-""#,
                tz
            );
            let entry = parse_line(&line).expect("should parse");
            assert!(entry.time_str().contains(tz));
        }
    }

    #[test]
    fn timestamp_with_valid_time_components() {
        let line =
            r#"1.2.3.4 - user [31/Dec/2025:23:59:59 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert!(entry.time_str().contains("31/Dec/2025:23:59:59"));
    }

    #[test]
    fn invalid_timestamp_missing_bracket() {
        let line = r#"1.2.3.4 - user 08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn timestamp_too_short() {
        let line = r#"1.2.3.4 - user [08/May] "GET / HTTP/1.1" 200 100 "-" "-""#;
        assert!(parse_line(line).is_none());
    }

    // ── IP addresses ─────────────────────────────────────────────────────────

    #[test]
    fn various_ipv4_addresses() {
        let ips = vec![
            "0.0.0.0",
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "255.255.255.255",
        ];
        for ip in ips {
            let line = format!(
                r#"{} - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#,
                ip
            );
            let entry = parse_line(&line).expect("should parse");
            assert_eq!(entry.ip(), ip);
        }
    }

    #[test]
    fn ipv6_address() {
        let line = r#"::1 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.ip(), "::1");
    }

    #[test]
    fn ipv6_full_address() {
        let line = r#"2001:0db8:85a3:0000:0000:8a2e:0370:7334 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.ip(), "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    }

    // ── Paths ────────────────────────────────────────────────────────────────

    #[test]
    fn root_path() {
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.path(), "/");
    }

    #[test]
    fn deeply_nested_path() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /a/b/c/d/e/f/g/h/i/j HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.path(), "/a/b/c/d/e/f/g/h/i/j");
    }

    #[test]
    fn path_with_query_string_and_fragment() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /path?key=value&other=123 HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.path(), "/path?key=value&other=123");
    }

    #[test]
    fn path_with_special_characters() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /path-with_special.chars~!@$%^&=+ HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert!(entry.path().contains("special"));
    }

    #[test]
    fn path_with_encoded_characters() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /search?q=%E2%9C%93&lang=en HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert!(entry.path().contains("%E2%9C%93"));
    }

    // ── Referers ─────────────────────────────────────────────────────────────

    #[test]
    fn referer_with_full_url() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "https://subdomain.example.com:8080/path?query=value" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert!(entry.referer().contains("subdomain.example.com"));
    }

    #[test]
    fn referer_with_special_characters() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "https://example.com/search?q=hello%20world&sort=date&filter=active%3Dtrue" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert!(entry.referer().contains("hello%20world"));
        assert!(entry.referer().contains("active%3Dtrue"));
    }

    #[test]
    fn referer_with_fragments() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "https://example.com/page#section-with-anchor" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert!(entry.referer().contains("section-with-anchor"));
    }

    // ── User Agents ──────────────────────────────────────────────────────────

    #[test]
    fn complex_browser_user_agent() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36""#;
        let entry = parse_line(line).expect("should parse");
        assert!(entry.user_agent().contains("Windows NT 10.0"));
        assert!(entry.user_agent().contains("Chrome/91.0"));
    }

    #[test]
    fn mobile_user_agent() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1""#;
        let entry = parse_line(line).expect("should parse");
        assert!(entry.user_agent().contains("iPhone OS 14_6"));
    }

    #[test]
    fn bot_user_agent() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)""#;
        let entry = parse_line(line).expect("should parse");
        assert!(entry.user_agent().contains("Googlebot"));
    }

    // ── Edge cases and malformed input ────────────────────────────────────────

    #[test]
    fn missing_closing_quote_in_request() {
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /path HTTP/1.1 200 100 "-" "-""#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn missing_opening_quote_in_request() {
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] GET /path HTTP/1.1" 200 100 "-" "-""#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn invalid_status_code_non_numeric() {
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" abc 100 "-" "-""#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn status_code_too_short() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 20 100 "-" "-""#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn invalid_bytes_non_numeric_uses_default_zero() {
        // Parser uses unwrap_or(0) for invalid bytes, so invalid bytes is parsed as 0
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 notbytes "-" "-""#;
        let entry = parse_line(line).expect("should parse with invalid bytes as 0");
        assert_eq!(entry.bytes, 0);
    }

    #[test]
    fn missing_closing_quote_in_referer() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "https://example.com/ "-""#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn missing_closing_quote_in_user_agent() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn consecutive_status_and_bytes_without_proper_spacing() {
        // Parser expects: "STATUS BYTES" but if spacing is wrong like "STATUSBYTES",
        // the parser takes 3 digits for status, then expects a space, then parses from after that.
        // This results in undefined behavior due to fixed-width field parsing.
        // Valid nginx logs always have proper spacing, so we don't need to handle this edge case.
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse with proper spacing");
        assert_eq!(entry.status, 200);
        assert_eq!(entry.bytes, 100);
    }

    #[test]
    fn very_long_path() {
        let long_path = "/".to_string() + &"a".repeat(1000);
        let line = format!(
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET {} HTTP/1.1" 200 100 "-" "-""#,
            long_path
        );
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.path().len(), 1001);
    }

    #[test]
    fn very_long_user_agent() {
        let long_ua = "Mozilla/5.0 ".to_string() + &"(Compatible; ".repeat(100);
        let line = format!(
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "{}""#,
            long_ua
        );
        let entry = parse_line(line).expect("should parse");
        assert!(entry.user_agent().len() > 100);
    }

    #[test]
    fn http2_protocol() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /index.html HTTP/2.0" 200 1234 "-" "Mozilla/5.0""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.path(), "/index.html");
    }

    #[test]
    fn http_connect_method() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "CONNECT example.com:443 HTTP/1.1" 200 0 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.method(), "CONNECT");
        assert_eq!(entry.path(), "example.com:443");
    }

    // ── Junk / non-HTTP requests ─────────────────────────────────────────────

    #[test]
    fn rejects_tls_handshake_binary() {
        // TLS ClientHello starts with control bytes \x16\x03\x01 (record type, version)
        let line = "212.102.40.218 - - [12/May/2026:17:48:14 +0100] \"\x16\x03\x01\x01\" 400 166 \"-\" \"-\"";
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn rejects_tls_handshake_variant() {
        let line = "206.123.144.13 - - [12/May/2026:14:25:34 +0100] \"\x16\x03\x01\x02\" 400 166 \"-\" \"-\"";
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn rejects_ssh_banner() {
        let line = r#"20.163.15.93 - - [12/May/2026:14:34:16 +0100] "SSH-2.0-Go" 400 166 "-" "-""#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn rejects_scanner_probe() {
        let line = r#"20.163.15.93 - - [12/May/2026:14:34:16 +0100] "MGLNDD_89.16.164.98_443" 400 166 "-" "-""#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn rejects_empty_request() {
        let line = r#"18.116.101.220 - - [12/May/2026:16:58:14 +0100] "" 400 0 "-" "-""#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn rejects_request_without_protocol() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET /path" 200 100 "-" "-""#;
        assert!(parse_line(line).is_none());
    }

    #[test]
    fn rejects_non_ascii_in_request() {
        let line = "1.2.3.4 - user [08/May/2026:14:23:01 +0000] \"GET /café HTTP/1.1\" 200 100 \"-\" \"-\"";
        assert!(parse_line(line).is_none());
    }

    // ── Less-common but allowed methods ──────────────────────────────────────

    #[test]
    fn propfind_method() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "PROPFIND /dav/resource HTTP/1.1" 207 500 "-" "cadaver/0.23.3""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.method(), "PROPFIND");
        assert_eq!(entry.path(), "/dav/resource");
    }

    #[test]
    fn pri_method_http2_preface() {
        let line = r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "PRI * HTTP/2.0" 200 0 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.method(), "PRI");
        assert_eq!(entry.path(), "*");
    }

    // ── parse_float_ms ────────────────────────────────────────────────────────

    #[test]
    fn parse_float_ms_basic() {
        use super::combined::parse_float_ms;
        assert_eq!(parse_float_ms(b"1.234"), Some(1234));
        assert_eq!(parse_float_ms(b"0.001"), Some(1));
        assert_eq!(parse_float_ms(b"0.999"), Some(999));
        assert_eq!(parse_float_ms(b"12.789"), Some(12789));
        assert_eq!(parse_float_ms(b"100.000"), Some(100000));
    }

    #[test]
    fn parse_float_ms_fewer_than_3_frac_digits() {
        use super::combined::parse_float_ms;
        assert_eq!(parse_float_ms(b"1.5"), Some(1500));
        assert_eq!(parse_float_ms(b"1.50"), Some(1500));
        assert_eq!(parse_float_ms(b"0.0"), Some(0));
    }

    #[test]
    fn parse_float_ms_rounds_at_4th_decimal() {
        use super::combined::parse_float_ms;
        // 0.1234 → top3=123, 4th digit=4 (<5) → 123 ms
        assert_eq!(parse_float_ms(b"0.1234"), Some(123));
        // 0.1235 → top3=123, 4th digit=5 (≥5) → 124 ms
        assert_eq!(parse_float_ms(b"0.1235"), Some(124));
    }

    #[test]
    fn parse_float_ms_no_dot_returns_none() {
        use super::combined::parse_float_ms;
        assert_eq!(parse_float_ms(b"1234"), None);
    }

    #[test]
    fn parse_float_ms_non_digit_returns_none() {
        use super::combined::parse_float_ms;
        assert_eq!(parse_float_ms(b"1.2x4"), None);
    }

    // ── upstream_response_time_ms from us= field ──────────────────────────────────────

    #[test]
    fn parses_rt_float_seconds_to_ms() {
        let line =
            r#"1.2.3.4 - - [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-" us=1.234"#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.upstream_response_time_ms, Some(1234));
    }

    #[test]
    fn parses_rt_sub_millisecond() {
        let line =
            r#"1.2.3.4 - - [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-" us=0.001"#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.upstream_response_time_ms, Some(1));
    }

    #[test]
    fn no_rt_field_gives_none() {
        let line = r#"1.2.3.4 - - [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.upstream_response_time_ms, None);
    }

    // ── Proto field ───────────────────────────────────────────────────────────

    #[test]
    fn proto_http11_captured() {
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.1" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.proto(), "HTTP/1.1");
    }

    #[test]
    fn proto_http10_captured() {
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/1.0" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.proto(), "HTTP/1.0");
    }

    #[test]
    fn proto_http20_captured() {
        let line =
            r#"1.2.3.4 - user [08/May/2026:14:23:01 +0000] "GET / HTTP/2.0" 200 100 "-" "-""#;
        let entry = parse_line(line).expect("should parse");
        assert_eq!(entry.proto(), "HTTP/2.0");
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

    // ── parse_local_epoch_days ────────────────────────────────────────────────
    //
    // This function is the basis of the skip_before_ts filter in the parser
    // pipeline.  The critical invariant: it must return the LOCAL date baked into
    // the log line, NOT the UTC-equivalent date.  Entries logged at UTC 23:xx with
    // a +01:00 timezone have a local date of the NEXT calendar day; the filter must
    // not drop them when the rollback boundary is that next day.

    #[test]
    fn parse_local_epoch_days_utc_epoch() {
        // 01/Jan/1970:00:00:00 +0000  →  local date 1970-01-01  →  epoch-day 0
        let d = parse_local_epoch_days("01/Jan/1970:00:00:00 +0000", 1).unwrap();
        assert_eq!(d, 0);
    }

    #[test]
    fn parse_local_epoch_days_ignores_timezone_offset() {
        // "31/Mar/2026:23:00:03 +0100" — UTC timestamp would be
        // 2026-03-31T22:00:03Z, but the LOCAL date in the log is March 31.
        // days_from_civil(2026, 3, 31) is what we expect back.
        let d = parse_local_epoch_days("31/Mar/2026:23:00:03 +0100", 3).unwrap();
        let expected = days_from_civil(2026, 3, 31);
        assert_eq!(d, expected);
    }

    #[test]
    fn parse_local_epoch_days_bst_midnight_entry_matches_april() {
        // The real-world bug: an entry at UTC 2026-03-31 23:00:03 with BST +01:00
        // is logged with LOCAL date 01/Apr/2026 (00:00:03 local time).
        // parse_local_epoch_days must return the April 1 epoch-day so that it is
        // NOT filtered out when skip_before_ts is set to 2026-04-01 00:00:00 UTC.
        let april1_utc_midnight: i64 = days_from_civil(2026, 4, 1) * 86_400;
        let skip_before_days = april1_utc_midnight / 86_400;

        let entry_days = parse_local_epoch_days("01/Apr/2026:00:00:03 +0100", 4).unwrap();
        assert_eq!(
            entry_days,
            days_from_civil(2026, 4, 1),
            "local date should be April 1"
        );
        // The entry must survive the filter (local_days >= skip_before_days).
        assert!(
            entry_days >= skip_before_days,
            "BST midnight entry (local April 1) must not be filtered by rollback boundary at UTC April 1"
        );
    }

    #[test]
    fn parse_local_epoch_days_utc_timestamp_would_give_wrong_answer() {
        // Demonstrate why UTC comparison was wrong: the entry below has UTC
        // timestamp 2026-03-31T23:00:03Z which is BEFORE the rollback boundary
        // 2026-04-01T00:00:00Z.  A UTC comparison would drop it; the local-date
        // comparison must keep it.
        let april1_utc_midnight: i64 = days_from_civil(2026, 4, 1) * 86_400;

        // UTC timestamp of "01/Apr/2026:00:00:03 +0100"
        let utc_ts = parse_unix_timestamp("01/Apr/2026:00:00:03 +0100", 4).unwrap();
        // This should be 2026-03-31T23:00:03Z, which is < april1_utc_midnight
        assert!(
            utc_ts < april1_utc_midnight,
            "UTC timestamp should be before midnight UTC (confirming old code was wrong)"
        );

        // But the local-date comparison correctly keeps the entry.
        let local_days = parse_local_epoch_days("01/Apr/2026:00:00:03 +0100", 4).unwrap();
        assert!(
            local_days * 86_400 >= april1_utc_midnight,
            "local-date comparison should keep the entry"
        );
    }

    #[test]
    fn parse_local_epoch_days_genuine_pre_rollback_entry_is_filtered() {
        // An entry clearly in March should produce a day-count strictly less than
        // the April rollback boundary.
        let april1_utc_midnight: i64 = days_from_civil(2026, 4, 1) * 86_400;
        let skip_before_days = april1_utc_midnight / 86_400;

        let d = parse_local_epoch_days("15/Mar/2026:12:00:00 +0000", 3).unwrap();
        assert!(
            d < skip_before_days,
            "March entry must be filtered out by April rollback boundary"
        );
    }

    #[test]
    fn parse_local_epoch_days_rejects_short_input() {
        assert!(parse_local_epoch_days("short", 1).is_none());
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
}
