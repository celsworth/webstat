use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn parse(ip: &str) -> IpAddr {
        ip.parse().unwrap()
    }

    #[test]
    fn geo_without_database_returns_unknowns() {
        let mut geo = Geo::new(None);

        let (code, name) = geo.lookup(parse("192.168.1.1"));
        assert_eq!(code.as_ref(), "--");
        assert_eq!(name.as_ref(), "Unknown");
    }

    #[test]
    fn geo_with_missing_database_returns_unknowns() {
        let mut geo = Geo::new(Some("/nonexistent/path/to/db.mmdb"));

        let (code, name) = geo.lookup(parse("8.8.8.8"));
        assert_eq!(code.as_ref(), "--");
        assert_eq!(name.as_ref(), "Unknown");
    }

    #[test]
    fn cache_stores_results() {
        let mut geo = Geo::new(None);

        let ip = parse("192.168.1.1");
        geo.lookup(ip);
        assert_eq!(geo.mem_cache.len(), 1);

        geo.lookup(ip);
        assert_eq!(geo.mem_cache.len(), 1);

        let other_ip = parse("10.0.0.1");
        geo.lookup(other_ip);
        assert_eq!(geo.mem_cache.len(), 2);
    }

    #[test]
    fn cache_hit_returns_same_arc() {
        let mut geo = Geo::new(None);

        let ip = parse("172.16.0.1");
        let (code1, name1) = geo.lookup(ip);
        let (code2, name2) = geo.lookup(ip);

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

        let valid_ips = ["0.0.0.0", "8.8.8.8", "255.255.255.255", "127.0.0.1", "192.168.1.1"];

        for ip_str in valid_ips {
            let ip = parse(ip_str);
            let (code, name) = geo.lookup(ip);
            assert_eq!(code.as_ref(), "--", "Should return unknown for IP: {}", ip_str);
            assert_eq!(name.as_ref(), "Unknown", "Should return unknown for IP: {}", ip_str);
            assert!(geo.mem_cache.contains_key(&ip), "IP should be cached: {}", ip_str);
        }
    }

    #[test]
    fn valid_ipv6_addresses_parsed() {
        let mut geo = Geo::new(None);

        let valid_ips = ["::", "::1", "2001:db8::1", "fe80::1"];

        for ip_str in valid_ips {
            let ip = parse(ip_str);
            let (code, name) = geo.lookup(ip);
            assert_eq!(code.as_ref(), "--", "Should return unknown for IPv6: {}", ip_str);
            assert_eq!(name.as_ref(), "Unknown", "Should return unknown for IPv6: {}", ip_str);
            assert!(geo.mem_cache.contains_key(&ip), "IPv6 should be cached: {}", ip_str);
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

        let ips: Vec<IpAddr> = ["1.1.1.1", "8.8.8.8", "1.0.0.1"].iter().map(|s| parse(s)).collect();

        for &ip in &ips {
            geo.lookup(ip);
        }

        assert_eq!(geo.mem_cache.len(), 3);

        for &ip in &ips {
            let (code, name) = geo.lookup(ip);
            assert_eq!(code.as_ref(), "--");
            assert_eq!(name.as_ref(), "Unknown");
        }

        assert_eq!(geo.mem_cache.len(), 3);
    }
}
