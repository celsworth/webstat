use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geo_without_database_returns_unknowns() {
        let mut geo = Geo::new(None);

        let (code, name) = geo.lookup("192.168.1.1");
        assert_eq!(code.as_ref(), "--");
        assert_eq!(name.as_ref(), "Unknown");
    }

    #[test]
    fn geo_with_missing_database_returns_unknowns() {
        let mut geo = Geo::new(Some("/nonexistent/path/to/db.mmdb"));

        let (code, name) = geo.lookup("8.8.8.8");
        assert_eq!(code.as_ref(), "--");
        assert_eq!(name.as_ref(), "Unknown");
    }

    #[test]
    fn empty_ip_returns_unknown() {
        let mut geo = Geo::new(None);

        let (code, name) = geo.lookup("");
        assert_eq!(code.as_ref(), "--");
        assert_eq!(name.as_ref(), "Unknown");
    }

    #[test]
    fn dash_ip_returns_unknown() {
        let mut geo = Geo::new(None);

        let (code, name) = geo.lookup("-");
        assert_eq!(code.as_ref(), "--");
        assert_eq!(name.as_ref(), "Unknown");
    }

    #[test]
    fn invalid_ip_returns_unknown() {
        let mut geo = Geo::new(None);

        let invalid_ips = vec!["not-an-ip", "999.999.999.999", "12345", "::invalid"];

        for ip in invalid_ips {
            let (code, name) = geo.lookup(ip);
            assert_eq!(code.as_ref(), "--");
            assert_eq!(name.as_ref(), "Unknown");
        }
    }

    #[test]
    fn cache_stores_results() {
        let mut geo = Geo::new(None);

        let ip = "192.168.1.1";
        geo.lookup(ip);
        assert_eq!(geo.mem_cache.len(), 1);

        geo.lookup(ip);
        assert_eq!(geo.mem_cache.len(), 1);

        let other_ip = "10.0.0.1";
        geo.lookup(other_ip);
        assert_eq!(geo.mem_cache.len(), 2);
    }

    #[test]
    fn cache_hit_returns_same_arc() {
        let mut geo = Geo::new(None);

        let ip = "172.16.0.1";
        let (code1, name1) = geo.lookup(ip);
        let (code2, name2) = geo.lookup(ip);

        let code_ptr1 = code1.as_ptr();
        let code_ptr2 = code2.as_ptr();
        assert_eq!(
            code_ptr1, code_ptr2,
            "Arc should point to same memory on cache hit"
        );

        let name_ptr1 = name1.as_ptr();
        let name_ptr2 = name2.as_ptr();
        assert_eq!(
            name_ptr1, name_ptr2,
            "Arc should point to same memory on cache hit"
        );
    }

    #[test]
    fn valid_ipv4_addresses_parsed() {
        let mut geo = Geo::new(None);

        let valid_ips = vec![
            "0.0.0.0",
            "8.8.8.8",
            "255.255.255.255",
            "127.0.0.1",
            "192.168.1.1",
        ];

        for ip in valid_ips {
            let (code, name) = geo.lookup(ip);
            assert_eq!(code.as_ref(), "--", "Should return unknown for IP: {}", ip);
            assert_eq!(
                name.as_ref(),
                "Unknown",
                "Should return unknown for IP: {}",
                ip
            );
            assert!(
                geo.mem_cache.contains_key(ip),
                "IP should be cached: {}",
                ip
            );
        }
    }

    #[test]
    fn valid_ipv6_addresses_parsed() {
        let mut geo = Geo::new(None);

        let valid_ips = vec!["::", "::1", "2001:db8::1", "fe80::1"];

        for ip in valid_ips {
            let (code, name) = geo.lookup(ip);
            assert_eq!(
                code.as_ref(),
                "--",
                "Should return unknown for IPv6: {}",
                ip
            );
            assert_eq!(
                name.as_ref(),
                "Unknown",
                "Should return unknown for IPv6: {}",
                ip
            );
            assert!(
                geo.mem_cache.contains_key(ip),
                "IPv6 should be cached: {}",
                ip
            );
        }
    }

    #[test]
    fn new_with_empty_string_path() {
        let geo = Geo::new(Some(""));
        assert!(geo.reader.is_none());
    }

    #[test]
    fn multiple_lookups_cache_independently() {
        let mut geo = Geo::new(None);

        let ips = vec!["1.1.1.1", "8.8.8.8", "1.0.0.1"];

        for ip in &ips {
            geo.lookup(ip);
        }

        assert_eq!(geo.mem_cache.len(), 3);

        for ip in &ips {
            let (code, name) = geo.lookup(ip);
            assert_eq!(code.as_ref(), "--");
            assert_eq!(name.as_ref(), "Unknown");
        }

        assert_eq!(geo.mem_cache.len(), 3);
    }
}
