// GeoIP lookup: wraps maxminddb with an AHashMap cache to map IPs to ISO country codes.

use ahash::AHashMap;
use std::sync::Arc;

use crate::ip::Ip;

const UNKNOWN_CODE: &str = "--";
const UNKNOWN_NAME: &str = "Unknown";

pub fn unknown() -> (Arc<str>, Arc<str>) {
    (Arc::from(UNKNOWN_CODE), Arc::from(UNKNOWN_NAME))
}

pub struct Geo {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    pub(crate) mem_cache: AHashMap<Ip, (Arc<str>, Arc<str>)>,
}

impl Geo {
    /// Create a new `Geo` instance.  If `mmdb_path` is `None`, empty, or the
    /// file does not exist, all lookups return `("--", "Unknown")`.
    pub fn new(mmdb_path: Option<&str>) -> Self {
        let reader = mmdb_path
            .filter(|p| !p.is_empty())
            .filter(|p| std::path::Path::new(p).exists())
            .and_then(|p| maxminddb::Reader::open_readfile(p).ok());

        Self {
            reader,
            mem_cache: AHashMap::with_capacity(65_536),
        }
    }

    /// Return `(country_code, country_name)` for the given IP.
    pub fn lookup(&mut self, ip: Ip) -> (Arc<str>, Arc<str>) {
        if let Some(result) = self.mem_cache.get(&ip) {
            return (Arc::clone(&result.0), Arc::clone(&result.1));
        }

        let result = self.resolve(ip);
        self.mem_cache
            .insert(ip, (Arc::clone(&result.0), Arc::clone(&result.1)));
        result
    }

    fn resolve(&self, ip: Ip) -> (Arc<str>, Arc<str>) {
        let reader = match &self.reader {
            Some(r) => r,
            None => return unknown(),
        };

        let country: maxminddb::geoip2::Country = match reader.lookup(ip.to_std()) {
            Ok(c) => c,
            Err(_) => return unknown(),
        };

        let code = country
            .country
            .as_ref()
            .and_then(|c| c.iso_code)
            .unwrap_or(UNKNOWN_CODE);

        let name = country
            .country
            .as_ref()
            .and_then(|c| c.names.as_ref())
            .and_then(|n| n.get("en").copied())
            .unwrap_or(UNKNOWN_NAME);

        (Arc::from(code), Arc::from(name))
    }
}

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
