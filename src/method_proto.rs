use std::sync::Arc;

use ahash::AHashMap;

pub const METHOD_COUNT: usize = 8;
pub const METHOD_GET: usize = 0;
pub const METHOD_POST: usize = 1;
pub const METHOD_HEAD: usize = 2;
pub const METHOD_PUT: usize = 3;
pub const METHOD_DELETE: usize = 4;
pub const METHOD_OPTIONS: usize = 5;
pub const METHOD_PATCH: usize = 6;
pub const METHOD_OTHER: usize = 7;

pub const METHOD_NAMES: [&str; METHOD_COUNT] = [
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "other",
];

pub const PROTO_COUNT: usize = 5;
pub const PROTO_1_0: usize = 0;
pub const PROTO_1_1: usize = 1;
pub const PROTO_2_0: usize = 2;
pub const PROTO_3_0: usize = 3;
pub const PROTO_OTHER: usize = 4;

pub const PROTO_NAMES: [&str; PROTO_COUNT] = ["1.0", "1.1", "2.0", "3.0", "other"];

/// period → per-method hit counts (indexed by METHOD_* constants)
pub type MethodCountsMap = AHashMap<Arc<str>, [u64; METHOD_COUNT]>;
/// period → per-proto hit counts (indexed by PROTO_* constants)
pub type ProtoCountsMap = AHashMap<Arc<str>, [u64; PROTO_COUNT]>;

#[inline]
pub fn method_index(method: &str) -> usize {
    match method {
        "GET" => METHOD_GET,
        "POST" => METHOD_POST,
        "HEAD" => METHOD_HEAD,
        "PUT" => METHOD_PUT,
        "DELETE" => METHOD_DELETE,
        "OPTIONS" => METHOD_OPTIONS,
        "PATCH" => METHOD_PATCH,
        _ => METHOD_OTHER,
    }
}

/// Strips the "HTTP/" prefix (e.g. "HTTP/1.1" → "1.1") then classifies.
#[inline]
pub fn proto_index(proto: &str) -> usize {
    match proto.as_bytes() {
        b"HTTP/1.0" => PROTO_1_0,
        b"HTTP/1.1" => PROTO_1_1,
        b"HTTP/2" | b"HTTP/2.0" => PROTO_2_0,
        b"HTTP/3" | b"HTTP/3.0" => PROTO_3_0,
        _ => PROTO_OTHER,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_index_classifies_all_known_methods() {
        assert_eq!(method_index("GET"), METHOD_GET);
        assert_eq!(method_index("POST"), METHOD_POST);
        assert_eq!(method_index("HEAD"), METHOD_HEAD);
        assert_eq!(method_index("PUT"), METHOD_PUT);
        assert_eq!(method_index("DELETE"), METHOD_DELETE);
        assert_eq!(method_index("OPTIONS"), METHOD_OPTIONS);
        assert_eq!(method_index("PATCH"), METHOD_PATCH);
    }

    #[test]
    fn method_index_unknown_maps_to_other() {
        assert_eq!(method_index("CONNECT"), METHOD_OTHER);
        assert_eq!(method_index("TRACE"), METHOD_OTHER);
        assert_eq!(method_index("get"), METHOD_OTHER); // case-sensitive
        assert_eq!(method_index(""), METHOD_OTHER);
    }

    #[test]
    fn proto_index_classifies_standard_versions() {
        assert_eq!(proto_index("HTTP/1.0"), PROTO_1_0);
        assert_eq!(proto_index("HTTP/1.1"), PROTO_1_1);
        assert_eq!(proto_index("HTTP/2.0"), PROTO_2_0);
        assert_eq!(proto_index("HTTP/2"), PROTO_2_0);
        assert_eq!(proto_index("HTTP/3.0"), PROTO_3_0);
        assert_eq!(proto_index("HTTP/3"), PROTO_3_0);
    }

    #[test]
    fn proto_index_unknown_maps_to_other() {
        assert_eq!(proto_index(""), PROTO_OTHER);
        assert_eq!(proto_index("HTTP/1.2"), PROTO_OTHER);
        assert_eq!(proto_index("SPDY/3"), PROTO_OTHER);
        assert_eq!(proto_index("http/1.1"), PROTO_OTHER); // case-sensitive
        assert_eq!(proto_index("1.1"), PROTO_OTHER); // no prefix — treated as unknown
    }

    #[test]
    fn method_names_match_constants() {
        assert_eq!(METHOD_NAMES[METHOD_GET], "GET");
        assert_eq!(METHOD_NAMES[METHOD_POST], "POST");
        assert_eq!(METHOD_NAMES[METHOD_HEAD], "HEAD");
        assert_eq!(METHOD_NAMES[METHOD_PUT], "PUT");
        assert_eq!(METHOD_NAMES[METHOD_DELETE], "DELETE");
        assert_eq!(METHOD_NAMES[METHOD_OPTIONS], "OPTIONS");
        assert_eq!(METHOD_NAMES[METHOD_PATCH], "PATCH");
        assert_eq!(METHOD_NAMES[METHOD_OTHER], "other");
        assert_eq!(METHOD_NAMES.len(), METHOD_COUNT);
    }

    #[test]
    fn proto_names_drop_http_prefix() {
        assert_eq!(PROTO_NAMES[PROTO_1_0], "1.0");
        assert_eq!(PROTO_NAMES[PROTO_1_1], "1.1");
        assert_eq!(PROTO_NAMES[PROTO_2_0], "2.0");
        assert_eq!(PROTO_NAMES[PROTO_3_0], "3.0");
        assert_eq!(PROTO_NAMES[PROTO_OTHER], "other");
        assert_eq!(PROTO_NAMES.len(), PROTO_COUNT);
        for name in &PROTO_NAMES {
            assert!(!name.starts_with("HTTP/"), "proto storage name must not include HTTP/ prefix");
        }
    }

    #[test]
    fn constants_are_within_array_bounds() {
        assert!(METHOD_GET < METHOD_COUNT);
        assert!(METHOD_POST < METHOD_COUNT);
        assert!(METHOD_HEAD < METHOD_COUNT);
        assert!(METHOD_PUT < METHOD_COUNT);
        assert!(METHOD_DELETE < METHOD_COUNT);
        assert!(METHOD_OPTIONS < METHOD_COUNT);
        assert!(METHOD_PATCH < METHOD_COUNT);
        assert!(METHOD_OTHER < METHOD_COUNT);

        assert!(PROTO_1_0 < PROTO_COUNT);
        assert!(PROTO_1_1 < PROTO_COUNT);
        assert!(PROTO_2_0 < PROTO_COUNT);
        assert!(PROTO_3_0 < PROTO_COUNT);
        assert!(PROTO_OTHER < PROTO_COUNT);
    }

    #[test]
    fn method_constants_are_all_distinct() {
        let indices = [
            METHOD_GET, METHOD_POST, METHOD_HEAD, METHOD_PUT,
            METHOD_DELETE, METHOD_OPTIONS, METHOD_PATCH, METHOD_OTHER,
        ];
        let unique: std::collections::HashSet<usize> = indices.iter().copied().collect();
        assert_eq!(unique.len(), METHOD_COUNT);
    }

    #[test]
    fn proto_constants_are_all_distinct() {
        let indices = [PROTO_1_0, PROTO_1_1, PROTO_2_0, PROTO_3_0, PROTO_OTHER];
        let unique: std::collections::HashSet<usize> = indices.iter().copied().collect();
        assert_eq!(unique.len(), PROTO_COUNT);
    }
}
