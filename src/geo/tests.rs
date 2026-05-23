use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip::Ip;

    fn lookup(geo: &mut Geo, ip: &str) -> (Arc<str>, Arc<str>) {
        geo.lookup(Ip::parse(ip).unwrap())
    }

    #[test]
    fn geo_without_database_returns_unknowns() {
        let mut geo = Geo::new(None);

        let (code, name) = lookup(&mut geo, "192.168.1.1");
        assert_eq!(code.as_ref(), "--");
        assert_eq!(name.as_ref(), "Unknown");
    }

    #[test]
    fn geo_with_missing_database_returns_unknowns() {
        let mut geo = Geo::new(Some("/nonexistent/path/to/db.mmdb"));

        let (code, name) = lookup(&mut geo, "8.8.8.8");
        assert_eq!(code.as_ref(), "--");
        assert_eq!(name.as_ref(), "Unknown");
    }

    #[test]
    fn cache_stores_results() {
        let mut geo = Geo::new(None);

        lookup(&mut geo, "192.168.1.1");
        assert_eq!(geo.mem_cache.len(), 1);

        lookup(&mut geo, "192.168.1.1");
        assert_eq!(geo.mem_cache.len(), 1);

        lookup(&mut geo, "10.0.0.1");
        assert_eq!(geo.mem_cache.len(), 2);
    }

    #[test]
    fn cache_hit_returns_same_arc() {
        let mut geo = Geo::new(None);

        let (code1, name1) = lookup(&mut geo, "172.16.0.1");
        let (code2, name2) = lookup(&mut geo, "172.16.0.1");

        assert_eq!(
            code1.as_ptr(),
            code2.as_ptr(),
            "Arc should point to same memory on cache hit"
        );
        assert_eq!(
            name1.as_ptr(),
            name2.as_ptr(),
            "Arc should point to same memory on cache hit"
        );
    }

    #[test]
    fn valid_ipv4_addresses_parsed() {
        let mut geo = Geo::new(None);

        let valid_ips = [
            "0.0.0.0",
            "8.8.8.8",
            "255.255.255.255",
            "127.0.0.1",
            "192.168.1.1",
        ];

        for ip_str in valid_ips {
            let (code, name) = lookup(&mut geo, ip_str);
            assert_eq!(
                code.as_ref(),
                "--",
                "Should return unknown for IP: {}",
                ip_str
            );
            assert_eq!(
                name.as_ref(),
                "Unknown",
                "Should return unknown for IP: {}",
                ip_str
            );
            assert!(
                geo.mem_cache.contains_key(&Ip::parse(ip_str).unwrap()),
                "IP should be cached: {}",
                ip_str
            );
        }
    }

    #[test]
    fn valid_ipv6_addresses_parsed() {
        let mut geo = Geo::new(None);

        let valid_ips = ["::", "::1", "2001:db8::1", "fe80::1"];

        for ip_str in valid_ips {
            let (code, name) = lookup(&mut geo, ip_str);
            assert_eq!(
                code.as_ref(),
                "--",
                "Should return unknown for IPv6: {}",
                ip_str
            );
            assert_eq!(
                name.as_ref(),
                "Unknown",
                "Should return unknown for IPv6: {}",
                ip_str
            );
            assert!(
                geo.mem_cache.contains_key(&Ip::parse(ip_str).unwrap()),
                "IPv6 should be cached: {}",
                ip_str
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

        let ip_strs = ["1.1.1.1", "8.8.8.8", "1.0.0.1"];

        for ip_str in ip_strs {
            lookup(&mut geo, ip_str);
        }

        assert_eq!(geo.mem_cache.len(), 3);

        for ip_str in ip_strs {
            let (code, name) = lookup(&mut geo, ip_str);
            assert_eq!(code.as_ref(), "--");
            assert_eq!(name.as_ref(), "Unknown");
        }

        assert_eq!(geo.mem_cache.len(), 3);
    }
}
