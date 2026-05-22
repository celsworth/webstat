use ahash::AHashMap;
use std::net::IpAddr;
use std::sync::Arc;

const UNKNOWN_CODE: &str = "--";
const UNKNOWN_NAME: &str = "Unknown";

pub fn unknown() -> (Arc<str>, Arc<str>) {
    (Arc::from(UNKNOWN_CODE), Arc::from(UNKNOWN_NAME))
}

pub struct Geo {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    mem_cache: AHashMap<IpAddr, (Arc<str>, Arc<str>)>,
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

    /// Return `(country_code, country_name)` for the given `IpAddr`.
    ///
    /// Results are held in an in-memory map; the first lookup per IP hits the
    /// mmdb file and every subsequent call is O(1).
    pub fn lookup(&mut self, addr: IpAddr) -> (Arc<str>, Arc<str>) {
        if let Some(result) = self.mem_cache.get(&addr) {
            return (Arc::clone(&result.0), Arc::clone(&result.1));
        }

        let result = self.resolve(addr);
        self.mem_cache
            .insert(addr, (Arc::clone(&result.0), Arc::clone(&result.1)));
        result
    }

    fn resolve(&self, addr: IpAddr) -> (Arc<str>, Arc<str>) {
        let reader = match &self.reader {
            Some(r) => r,
            None => return unknown(),
        };

        let country: maxminddb::geoip2::Country = match reader.lookup(addr) {
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
mod tests;
