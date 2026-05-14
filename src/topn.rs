use std::{
    hash::{BuildHasher, Hash, Hasher},
    marker::PhantomData,
    sync::Arc,
};

use ahash::AHashMap;
use crate::hll::HyperLogLog;

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

#[derive(Debug)]
pub struct HourlyAcc {
    pub stats: HourlyStats,
    pub ip_set: HyperLogLog,
}

impl Default for HourlyAcc {
    fn default() -> Self {
        Self {
            stats: HourlyStats::default(),
            ip_set: HyperLogLog::new(12),
        }
    }
}

pub type HourlyMap = AHashMap<Arc<str>, AHashMap<u8, HourlyAcc>>;

pub type TopUrlsByHits = AHashMap<Arc<str>, TopNUrls>;
pub type TopUrlsByBandwidth = AHashMap<Arc<str>, TopNUrlsByBandwidth>;

pub type TopHostsByHits = AHashMap<Arc<str>, TopNHosts>;
pub type TopHostsByBandwidth = AHashMap<Arc<str>, TopNHostsByBandwidth>;

pub type PeriodCountMap = AHashMap<Arc<str>, TopNCount>; // refs, agents

pub type CountryHitsMap = AHashMap<Arc<str>, AHashMap<String, u64>>;
pub type StatusHitsMap = AHashMap<Arc<str>, AHashMap<u16, u64>>;

#[inline]
fn arcstr(s: &str) -> Arc<str> {
    Arc::<str>::from(s)
}

// ── Count-Min Sketch ──────────────────────────────────────────────────────────

const CMS_WIDTH: usize = 16_384;
const CMS_DEPTH: usize = 4;
const CMS_MASK: usize = CMS_WIDTH - 1;

#[inline(always)]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x = x.wrapping_mul(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    x
}

const ROW_SEEDS: [u64; CMS_DEPTH] = [
    0x9e3779b97f4a7c15,
    0xc2b2ae3d27d4eb4f,
    0x165667b19e3779f9,
    0x85ebca77c2b2ae63,
];

struct CountMinSketch<K> {
    table: Box<[[u64; CMS_WIDTH]; CMS_DEPTH]>,
    hasher: ahash::RandomState,
    _marker: PhantomData<K>,
}

impl<K: Hash> CountMinSketch<K> {
    fn new() -> Self {
        Self {
            table: Box::new([[0u64; CMS_WIDTH]; CMS_DEPTH]),
            hasher: ahash::RandomState::with_seeds(
                0x1a2b3c4d5e6f7a8b,
                0x9c0d1e2f3a4b5c6d,
                0x7e8f9a0b1c2d3e4f,
                0x5a6b7c8d9e0f1a2b,
            ),
            _marker: PhantomData,
        }
    }

    #[inline(always)]
    fn hash_key(&self, key: &K) -> u64 {
        let mut h = self.hasher.build_hasher();
        key.hash(&mut h);
        h.finish()
    }

    #[inline(always)]
    fn col(hash: u64, row: usize) -> usize {
        (mix64(hash ^ ROW_SEEDS[row]) as usize) & CMS_MASK
    }

    #[inline]
    fn update(&mut self, key: &K, delta: u64) {
        let hash = self.hash_key(key);
        for row in 0..CMS_DEPTH {
            let col = Self::col(hash, row);
            self.table[row][col] = self.table[row][col].saturating_add(delta);
        }
    }

    #[inline]
    fn estimate(&self, key: &K) -> u64 {
        let hash = self.hash_key(key);
        let mut min = u64::MAX;
        for row in 0..CMS_DEPTH {
            let col = Self::col(hash, row);
            min = min.min(self.table[row][col]);
        }
        min
    }
}

// ── CmsTopN ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
pub enum SortBy {
    Hits,
    Bandwidth,
}

struct CmsTopN<K>
where
    K: Hash + Eq + Clone,
{
    cms: CountMinSketch<K>,
    map: AHashMap<K, (u64, u64)>,
    capacity: usize,
    sort_by: SortBy,
    /// Cached lower bound on the minimum sort value currently in the map.
    /// Always ≤ actual minimum, so `estimate <= cached_min` safely skips the scan.
    cached_min: u64,
}

impl<K> CmsTopN<K>
where
    K: Hash + Eq + Clone,
{
    fn new(capacity: usize, sort_by: SortBy) -> Self {
        Self {
            cms: CountMinSketch::new(),
            map: AHashMap::with_capacity(capacity),
            capacity,
            sort_by,
            cached_min: 0,
        }
    }

    #[inline]
    fn add(&mut self, key: K, hits: u64, bw: u64) {
        if self.capacity == 0 {
            return;
        }

        let cms_delta = match self.sort_by {
            SortBy::Hits => hits,
            SortBy::Bandwidth => bw,
        };

        self.cms.update(&key, cms_delta);

        if let Some(existing) = self.map.get_mut(&key) {
            existing.0 += hits;
            existing.1 += bw;
            return;
        }

        if self.map.len() < self.capacity {
            self.map.insert(key, (hits, bw));
            return;
        }

        // Fast pre-filter: CMS estimate vs cached minimum — no map scan needed.
        let estimate = self.cms.estimate(&key);
        if estimate <= self.cached_min {
            return;
        }

        // Scan to confirm and obtain the key to evict.
        let (min_key, actual_min) = self.find_min();
        if estimate <= actual_min {
            self.cached_min = actual_min;
            return;
        }

        let min_key = min_key.clone();
        self.map.remove(&min_key);

        let (init_hits, init_bw) = match self.sort_by {
            SortBy::Hits => (estimate, bw),
            SortBy::Bandwidth => (hits, estimate),
        };
        self.map.insert(key, (init_hits, init_bw));

        // Refresh cache: one more scan after eviction, but evictions are rare.
        self.cached_min = self.find_min().1;
    }

    #[cold]
    fn find_min(&self) -> (&K, u64) {
        let sort_by = self.sort_by;

        self.map
            .iter()
            .map(|(k, &(hits, bw))| {
                let v = match sort_by {
                    SortBy::Hits => hits,
                    SortBy::Bandwidth => bw,
                };

                (k, v)
            })
            .min_by_key(|&(_, v)| v)
            .unwrap()
    }

    #[allow(dead_code)]
    #[inline]
    fn len(&self) -> usize {
        self.map.len()
    }

    #[allow(dead_code)]
    #[inline]
    fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[allow(dead_code)]
    #[inline]
    fn clear(&mut self) {
        self.map.clear();
    }

    fn iter(&self) -> impl Iterator<Item = (&K, u64, u64)> + '_ {
        self.map.iter().map(|(k, &(hits, bw))| (k, hits, bw))
    }
}

// ── Public types ──────────────────────────────────────────────────────────────

pub struct TopNCount(AHashMap<Arc<str>, u64>);

impl TopNCount {
    pub fn new(_capacity: usize) -> Self {
        Self(AHashMap::new())
    }

    #[inline]
    pub fn add(&mut self, key: &str, delta: u64) {
        if let Some(v) = self.0.get_mut(key) {
            *v += delta;
            return;
        }
        self.0.insert(arcstr(key), delta);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> + '_ {
        self.0.iter().map(|(k, &v)| (k.as_ref(), v))
    }
}

pub struct TopNUrls(CmsTopN<Arc<str>>);

impl TopNUrls {
    pub fn new(capacity: usize) -> Self {
        Self(CmsTopN::new(capacity, SortBy::Hits))
    }

    #[inline]
    pub fn add(&mut self, url: &str, bw: u64) {
        self.0.add(arcstr(url), 1, bw);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, url: &str, hits: u64, bw: u64) {
        self.0.add(arcstr(url), hits, bw);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.0.iter().map(|(k, hits, bw)| (k.as_ref(), hits, bw))
    }
}

pub struct TopNUrlsByBandwidth(CmsTopN<Arc<str>>);

impl TopNUrlsByBandwidth {
    pub fn new(capacity: usize) -> Self {
        Self(CmsTopN::new(capacity, SortBy::Bandwidth))
    }

    #[inline]
    pub fn add(&mut self, url: &str, bw: u64) {
        self.0.add(arcstr(url), 1, bw);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, url: &str, hits: u64, bw: u64) {
        self.0.add(arcstr(url), hits, bw);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.0.iter().map(|(k, hits, bw)| (k.as_ref(), hits, bw))
    }
}

pub struct TopNHosts(CmsTopN<Arc<str>>);

impl TopNHosts {
    pub fn new(capacity: usize) -> Self {
        Self(CmsTopN::new(capacity, SortBy::Hits))
    }

    #[inline]
    pub fn add(&mut self, host: &str, bw: u64) {
        self.0.add(arcstr(host), 1, bw);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, host: &str, hits: u64, bw: u64) {
        self.0.add(arcstr(host), hits, bw);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.0.iter().map(|(k, hits, bw)| (k.as_ref(), hits, bw))
    }
}

pub struct TopNHostsByBandwidth(CmsTopN<Arc<str>>);

impl TopNHostsByBandwidth {
    pub fn new(capacity: usize) -> Self {
        Self(CmsTopN::new(capacity, SortBy::Bandwidth))
    }

    #[inline]
    pub fn add(&mut self, host: &str, bw: u64) {
        self.0.add(arcstr(host), 1, bw);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, host: &str, hits: u64, bw: u64) {
        self.0.add(arcstr(host), hits, bw);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.0.iter().map(|(k, hits, bw)| (k.as_ref(), hits, bw))
    }
}

pub struct TopNIps(CmsTopN<u32>);

impl TopNIps {
    pub fn new(capacity: usize) -> Self {
        Self(CmsTopN::new(capacity, SortBy::Hits))
    }

    #[inline]
    pub fn add(&mut self, ip: u32, bw: u64) {
        self.0.add(ip, 1, bw);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, ip: u32, hits: u64, bw: u64) {
        self.0.add(ip, hits, bw);
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, u64, u64)> + '_ {
        self.0.iter().map(|(&k, hits, bw)| (k, hits, bw))
    }
}

pub struct TopNIpsByBandwidth(CmsTopN<u32>);

impl TopNIpsByBandwidth {
    pub fn new(capacity: usize) -> Self {
        Self(CmsTopN::new(capacity, SortBy::Bandwidth))
    }

    #[inline]
    pub fn add(&mut self, ip: u32, bw: u64) {
        self.0.add(ip, 1, bw);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, ip: u32, hits: u64, bw: u64) {
        self.0.add(ip, hits, bw);
    }

    pub fn iter(&self) -> impl Iterator<Item = (u32, u64, u64)> + '_ {
        self.0.iter().map(|(&k, hits, bw)| (k, hits, bw))
    }
}

#[cfg(test)]
mod tests;
