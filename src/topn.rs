use std::sync::Arc;

use ahash::{AHashMap, AHashSet};

// ── Map type aliases ──────────────────────────────────────────────────────────

#[derive(Debug, Default)]
pub struct HourlyStats {
    pub hits: u64,
    pub visits: u64,
    pub bandwidth: u64,
    pub files: u64,
    pub pages: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
}

#[derive(Debug, Default)]
pub struct HourlyAcc {
    pub stats: HourlyStats,
    pub ip_set: AHashSet<u32>,
}

/// Outer key is `Arc<str>` so cloning a period string in the hot loop is a
/// single atomic ref-count increment rather than a heap allocation.
pub type HourlyMap = AHashMap<Arc<str>, AHashMap<u8, HourlyAcc>>;
/// period → url → (hits, bandwidth) — bounded by Space-Saving TopN
pub type TopUrlsByHits = AHashMap<Arc<str>, TopNUrls>;
/// period → url → (hits, bandwidth) — bounded by Space-Saving TopN (bandwidth-ranked)
pub type TopUrlsByBandwidth = AHashMap<Arc<str>, TopNUrlsByBandwidth>;
/// period → host → (hits, bandwidth, country_code, country_name) — bounded by Space-Saving TopN
pub type TopHostsByHits = AHashMap<Arc<str>, TopNHosts>;
/// period → host → (hits, bandwidth, country_code, country_name) — bounded by Space-Saving TopN (bandwidth-ranked)
pub type TopHostsByBandwidth = AHashMap<Arc<str>, TopNHostsByBandwidth>;
/// period → key → hits — bounded by Space-Saving TopN (for refs and agents)
pub type PeriodCountMap = AHashMap<Arc<str>, TopNCount>;
/// period → country_code → hits (exact, not Space-Saving)
pub type CountryHitsMap = AHashMap<Arc<str>, AHashMap<String, u64>>;
/// period → status_code → hits (exact, not Space-Saving)
pub type StatusHitsMap = AHashMap<Arc<str>, AHashMap<u16, u64>>;

// ── Space-Saving top-N trackers ───────────────────────────────────────────────

/// Top-N tracker for simple count metrics (refs, agents).
///
/// Uses the Space-Saving algorithm: when the tracker is full and a new key
/// arrives, the entry with the minimum count is evicted and the new key is
/// inserted with `min_count + delta` — a conservative lower bound that ensures
/// true top-N items accumulate counts far above eviction noise.
pub struct TopNCount {
    map: AHashMap<String, u64>,
    capacity: usize,
    cached_min: Option<(u64, String)>,
}

impl TopNCount {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(capacity),
            capacity,
            cached_min: None,
        }
    }

    #[inline]
    pub fn add(&mut self, key: &str, delta: u64) {
        if self.capacity == 0 {
            return;
        }
        if let Some(v) = self.map.get_mut(key) {
            *v += delta;
            return;
        }
        if self.map.len() < self.capacity {
            // New entry: update cached min if this is lower (or cache is empty).
            if self
                .cached_min
                .as_ref()
                .map_or(true, |(min_val, _)| delta < *min_val)
            {
                self.cached_min = Some((delta, key.to_string()));
            }
            self.map.insert(key.to_string(), delta);
            return;
        }
        let (min_key, min_val) = self.resolve_min_entry();
        self.map.remove(&min_key);
        let new_val = min_val + delta;
        self.map.insert(key.to_string(), new_val);
        // After eviction and insert, minimum may be elsewhere (ties at old min).
        self.cached_min = None;
    }

    #[cold]
    #[inline(never)]
    fn resolve_min_entry(&mut self) -> (String, u64) {
        if let Some((min_val, min_key)) = self.cached_min.take() {
            if self.map.get(min_key.as_str()).copied() == Some(min_val) {
                return (min_key, min_val);
            }
        }

        self.map
            .iter()
            .min_by_key(|(_, &v)| v)
            .map(|(k, &v)| {
                self.cached_min = Some((v, k.clone()));
                (k.clone(), v)
            })
            .unwrap()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> + '_ {
        self.map.iter().map(|(k, v)| (k.as_str(), *v))
    }

    #[cfg(test)]
    pub fn get(&self, key: &str) -> Option<&u64> {
        self.map.get(key)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }
}

// ── TopNUrls ────────────────────────────────────────────────────────────────

/// Top-N tracker for URL metrics (stores hits, bandwidth).
pub struct TopNUrls {
    map: AHashMap<String, (u64, u64)>,
    capacity: usize,
    cached_min_hits: Option<(u64, String)>,
}

/// Top-N tracker for URL metrics ranked by bandwidth (not hits).
pub struct TopNUrlsByBandwidth {
    map: AHashMap<String, (u64, u64)>,
    capacity: usize,
    cached_min_bw: Option<(u64, String)>,
}

impl TopNUrlsByBandwidth {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(capacity),
            capacity,
            cached_min_bw: None,
        }
    }

    #[inline]
    pub fn add(&mut self, url: &str, bw: u64) {
        self.add_hits_bw(url, 1, bw);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, url: &str, hits: u64, bw: u64) {
        if self.capacity == 0 {
            return;
        }
        if let Some(v) = self.map.get_mut(url) {
            v.0 += hits;
            v.1 += bw;
            return;
        }

        if self.map.len() < self.capacity {
            if self
                .cached_min_bw
                .as_ref()
                .map_or(true, |(min_bw, _)| bw < *min_bw)
            {
                self.cached_min_bw = Some((bw, url.to_string()));
            }
            self.map.insert(url.to_string(), (hits, bw));
            return;
        }

        let (min_key, min_bw) = self.resolve_min_entry();

        self.map.remove(&min_key);
        let new_bw = min_bw + bw;
        self.map.insert(url.to_string(), (hits, new_bw));
        self.cached_min_bw = None;
    }

    #[cold]
    #[inline(never)]
    fn resolve_min_entry(&mut self) -> (String, u64) {
        if let Some((min_bw, min_key)) = self.cached_min_bw.take() {
            if self.map.get(min_key.as_str()).map(|(_, bw)| *bw) == Some(min_bw) {
                return (min_key, min_bw);
            }
        }

        self.map
            .iter()
            .min_by_key(|(_, (_, bw))| *bw)
            .map(|(k, (_, bw))| {
                self.cached_min_bw = Some((*bw, k.clone()));
                (k.clone(), *bw)
            })
            .unwrap()
    }

    pub fn merge_from(&mut self, other: TopNUrlsByBandwidth) {
        for (url, (hits, bw)) in other.map {
            if let Some(existing) = self.map.get_mut(&url) {
                existing.0 += hits;
                existing.1 += bw;
            } else {
                self.map.insert(url, (hits, bw));
            }
        }
        self.trim_to_capacity();
        self.cached_min_bw = None;
    }

    fn trim_to_capacity(&mut self) {
        if self.capacity == 0 {
            self.map.clear();
            return;
        }
        if self.map.len() <= self.capacity {
            return;
        }
        let mut entries: Vec<_> = self.map.drain().collect();
        entries.select_nth_unstable_by(
            self.capacity - 1,
            |(url_a, (hits_a, bw_a)), (url_b, (hits_b, bw_b))| {
                bw_b
                    .cmp(bw_a)
                    .then_with(|| hits_b.cmp(hits_a))
                    .then_with(|| url_a.cmp(url_b))
            },
        );
        entries.truncate(self.capacity);
        self.map = entries.into_iter().collect();
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.map
            .iter()
            .map(|(k, (hits, bw))| (k.as_str(), *hits, *bw))
    }
}

impl TopNUrls {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(capacity),
            capacity,
            cached_min_hits: None,
        }
    }

    /// Record one hit for `key` with `bw` bytes transferred.
    #[inline]
    pub fn add(&mut self, key: &str, bw: u64) {
        self.add_hits_bw(key, 1, bw);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, key: &str, hits: u64, bw: u64) {
        if self.capacity == 0 {
            return;
        }
        if let Some(v) = self.map.get_mut(key) {
            v.0 += hits;
            v.1 += bw;
            return;
        }
        if self.map.len() < self.capacity {
            if self
                .cached_min_hits
                .as_ref()
                .map_or(true, |(min_hits, _)| hits < *min_hits)
            {
                self.cached_min_hits = Some((hits, key.to_string()));
            }
            self.map.insert(key.to_string(), (hits, bw));
            return;
        }
        let (min_key, min_hits) = self.resolve_min_entry();
        self.map.remove(&min_key);
        let new_hits = min_hits + hits;
        self.map.insert(key.to_string(), (new_hits, bw));
        self.cached_min_hits = None;
    }

    #[cold]
    #[inline(never)]
    fn resolve_min_entry(&mut self) -> (String, u64) {
        if let Some((min_hits, min_key)) = self.cached_min_hits.take() {
            if self.map.get(min_key.as_str()).map(|(h, _)| *h) == Some(min_hits) {
                return (min_key, min_hits);
            }
        }

        self.map
            .iter()
            .min_by_key(|(_, (h, _))| *h)
            .map(|(k, (h, _))| {
                self.cached_min_hits = Some((*h, k.clone()));
                (k.clone(), *h)
            })
            .unwrap()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.map
            .iter()
            .map(|(k, (hits, bw))| (k.as_str(), *hits, *bw))
    }

    #[cfg(test)]
    pub fn get(&self, key: &str) -> Option<&(u64, u64)> {
        self.map.get(key)
    }
}

// ── TopNHosts ─────────────────────────────────────────────────────────────────

/// Top-N tracker for host metrics (hits, bandwidth, country).
pub struct TopNHosts {
    map: AHashMap<String, (u64, u64, Arc<str>, Arc<str>)>,
    capacity: usize,
    cached_min_hits: Option<(u64, String)>,
}

/// Top-N tracker for host metrics ranked by bandwidth (not hits).
pub struct TopNHostsByBandwidth {
    map: AHashMap<String, (u64, u64, Arc<str>, Arc<str>)>,
    capacity: usize,
    cached_min_bw: Option<(u64, String)>,
}

impl TopNHostsByBandwidth {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(capacity),
            capacity,
            cached_min_bw: None,
        }
    }

    #[inline]
    pub fn add(&mut self, host: &str, bw: u64, cc: &Arc<str>, cn: &Arc<str>) {
        self.add_hits_bw(host, 1, bw, cc, cn);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, host: &str, hits: u64, bw: u64, cc: &Arc<str>, cn: &Arc<str>) {
        if self.capacity == 0 {
            return;
        }
        if let Some(v) = self.map.get_mut(host) {
            v.0 += hits;
            v.1 += bw;
            if v.2.as_ref() == "--" && cc.as_ref() != "--" {
                v.2 = Arc::clone(cc);
                v.3 = Arc::clone(cn);
            }
            return;
        }

        if self.map.len() < self.capacity {
            if self
                .cached_min_bw
                .as_ref()
                .map_or(true, |(min_bw, _)| bw < *min_bw)
            {
                self.cached_min_bw = Some((bw, host.to_string()));
            }
            self.map
                .insert(host.to_string(), (hits, bw, Arc::clone(cc), Arc::clone(cn)));
            return;
        }

        let (min_key, min_bw) = self.resolve_min_entry();

        self.map.remove(&min_key);
        let new_bw = min_bw + bw;
        self.map.insert(
            host.to_string(),
            (hits, new_bw, Arc::clone(cc), Arc::clone(cn)),
        );
        self.cached_min_bw = None;
    }

    #[cold]
    #[inline(never)]
    fn resolve_min_entry(&mut self) -> (String, u64) {
        if let Some((min_bw, min_key)) = self.cached_min_bw.take() {
            if self.map.get(min_key.as_str()).map(|(_, bw, _, _)| *bw) == Some(min_bw) {
                return (min_key, min_bw);
            }
        }

        self.map
            .iter()
            .min_by_key(|(_, (_, bw, _, _))| *bw)
            .map(|(k, (_, bw, _, _))| {
                self.cached_min_bw = Some((*bw, k.clone()));
                (k.clone(), *bw)
            })
            .unwrap()
    }

    pub fn merge_from(&mut self, other: TopNHostsByBandwidth) {
        for (host, (hits, bw, cc, cn)) in other.map {
            if let Some(existing) = self.map.get_mut(&host) {
                existing.0 += hits;
                existing.1 += bw;
                if existing.2.as_ref() == "--" && cc.as_ref() != "--" {
                    existing.2 = cc;
                    existing.3 = cn;
                }
            } else {
                self.map.insert(host, (hits, bw, cc, cn));
            }
        }
        self.trim_to_capacity();
        self.cached_min_bw = None;
    }

    fn trim_to_capacity(&mut self) {
        if self.capacity == 0 {
            self.map.clear();
            return;
        }
        if self.map.len() <= self.capacity {
            return;
        }
        let mut entries: Vec<_> = self.map.drain().collect();
        entries.select_nth_unstable_by(
            self.capacity - 1,
            |(host_a, (hits_a, bw_a, _, _)), (host_b, (hits_b, bw_b, _, _))| {
                bw_b.cmp(bw_a)
                    .then_with(|| hits_b.cmp(hits_a))
                    .then_with(|| host_a.cmp(host_b))
            },
        );
        entries.truncate(self.capacity);
        self.map = entries.into_iter().collect();
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64, &Arc<str>, &Arc<str>)> + '_ {
        self.map
            .iter()
            .map(|(k, (hits, bw, cc, cn))| (k.as_str(), *hits, *bw, cc, cn))
    }
}

impl TopNHosts {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(capacity),
            capacity,
            cached_min_hits: None,
        }
    }

    #[inline]
    pub fn add(&mut self, host: &str, bw: u64, cc: &Arc<str>, cn: &Arc<str>) {
        self.add_hits_bw(host, 1, bw, cc, cn);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, host: &str, hits: u64, bw: u64, cc: &Arc<str>, cn: &Arc<str>) {
        if self.capacity == 0 {
            return;
        }
        if let Some(v) = self.map.get_mut(host) {
            v.0 += hits;
            v.1 += bw;
            if v.2.as_ref() == "--" && cc.as_ref() != "--" {
                v.2 = Arc::clone(cc);
                v.3 = Arc::clone(cn);
            }
            return;
        }
        if self.map.len() < self.capacity {
            if self
                .cached_min_hits
                .as_ref()
                .map_or(true, |(min_hits, _)| hits < *min_hits)
            {
                self.cached_min_hits = Some((hits, host.to_string()));
            }
            self.map
                .insert(host.to_string(), (hits, bw, Arc::clone(cc), Arc::clone(cn)));
            return;
        }
        let (min_key, min_hits) = self.resolve_min_entry();
        self.map.remove(&min_key);
        let new_hits = min_hits + hits;
        self.map.insert(
            host.to_string(),
            (new_hits, bw, Arc::clone(cc), Arc::clone(cn)),
        );
        self.cached_min_hits = None;
    }

    #[cold]
    #[inline(never)]
    fn resolve_min_entry(&mut self) -> (String, u64) {
        if let Some((min_hits, min_key)) = self.cached_min_hits.take() {
            if self.map.get(min_key.as_str()).map(|(h, _, _, _)| *h) == Some(min_hits) {
                return (min_key, min_hits);
            }
        }

        self.map
            .iter()
            .min_by_key(|(_, (h, _, _, _))| *h)
            .map(|(k, (h, _, _, _))| {
                self.cached_min_hits = Some((*h, k.clone()));
                (k.clone(), *h)
            })
            .unwrap()
    }

    pub fn merge_from(&mut self, other: TopNHosts) {
        for (host, (hits, bw, cc, cn)) in other.map {
            if let Some(existing) = self.map.get_mut(&host) {
                existing.0 += hits;
                existing.1 += bw;
                if existing.2.as_ref() == "--" && cc.as_ref() != "--" {
                    existing.2 = cc;
                    existing.3 = cn;
                }
            } else {
                self.map.insert(host, (hits, bw, cc, cn));
            }
        }
        self.trim_to_capacity();
        // After a merge+trim the minimum is unknown; invalidate the cache.
        self.cached_min_hits = None;
    }

    fn trim_to_capacity(&mut self) {
        if self.capacity == 0 {
            self.map.clear();
            return;
        }
        if self.map.len() <= self.capacity {
            return;
        }
        let mut entries: Vec<_> = self.map.drain().collect();
        entries.select_nth_unstable_by(
            self.capacity - 1,
            |(host_a, (hits_a, bw_a, _, _)), (host_b, (hits_b, bw_b, _, _))| {
                hits_b
                    .cmp(hits_a)
                    .then_with(|| bw_b.cmp(bw_a))
                    .then_with(|| host_a.cmp(host_b))
            },
        );
        entries.truncate(self.capacity);
        self.map = entries.into_iter().collect();
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64, &Arc<str>, &Arc<str>)> + '_ {
        self.map
            .iter()
            .map(|(k, (hits, bw, cc, cn))| (k.as_str(), *hits, *bw, cc, cn))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests;
