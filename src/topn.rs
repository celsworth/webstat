use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    hash::{BuildHasher, Hash, Hasher},
    sync::Arc,
};

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

pub type HourlyMap = AHashMap<Arc<str>, AHashMap<u8, HourlyAcc>>;

pub type TopUrlsByHits = AHashMap<Arc<str>, TopNUrls>;
pub type TopUrlsByBandwidth = AHashMap<Arc<str>, TopNUrlsByBandwidth>;

pub type TopHostsByHits = AHashMap<Arc<str>, TopNHosts>;
pub type TopHostsByBandwidth = AHashMap<Arc<str>, TopNHostsByBandwidth>;

pub type PeriodCountMap = AHashMap<Arc<str>, TopNCount>;

pub type CountryHitsMap = AHashMap<Arc<str>, AHashMap<String, u64>>;
pub type StatusHitsMap = AHashMap<Arc<str>, AHashMap<u16, u64>>;

#[inline]
fn arcstr(s: &str) -> Arc<str> {
    Arc::<str>::from(s)
}

// ── Generic TopN core ─────────────────────────────────────────────────────────

trait TopNValue: Sized {
    fn sort_key(&self) -> u64;
    fn merge_into(&mut self, other: Self);
    fn on_evict(self, evicted_key: u64) -> Self;
}

struct TopN<V> {
    map: AHashMap<Arc<str>, V>,
    min_heap: BinaryHeap<Reverse<(u64, Arc<str>)>>,
    capacity: usize,
}

impl<V: TopNValue> TopN<V> {
    fn new(capacity: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(capacity),
            min_heap: BinaryHeap::with_capacity(capacity),
            capacity,
        }
    }

    #[inline]
    fn add(&mut self, key: &str, val: V) {
        if self.capacity == 0 {
            return;
        }

        if let Some(existing) = self.map.get_mut(key) {
            existing.merge_into(val);
            return;
        }

        let sort_key = val.sort_key();

        if self.map.len() < self.capacity {
            let key_arc = arcstr(key);
            self.map.insert(Arc::clone(&key_arc), val);
            self.min_heap.push(Reverse((sort_key, key_arc)));
            return;
        }

        let (min_key, min_sort_key) = self.resolve_min_entry();
        self.map.remove(min_key.as_ref());

        let new_val = val.on_evict(min_sort_key);
        let new_sort_key = new_val.sort_key();
        let key_arc = arcstr(key);
        self.map.insert(Arc::clone(&key_arc), new_val);
        self.min_heap.push(Reverse((new_sort_key, key_arc)));
    }

    #[cold]
    fn resolve_min_entry(&mut self) -> (Arc<str>, u64) {
        loop {
            while let Some(Reverse((sort_key, key))) = self.min_heap.pop() {
                if let Some(v) = self.map.get(key.as_ref()) {
                    if v.sort_key() == sort_key {
                        return (key, sort_key);
                    }
                }
            }

            self.min_heap.reserve(self.map.len());
            for (key, val) in &self.map {
                self.min_heap
                    .push(Reverse((val.sort_key(), Arc::clone(key))));
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = (&Arc<str>, &V)> + '_ {
        self.map.iter()
    }
}

// ── Value types ───────────────────────────────────────────────────────────────

struct CountVal(u64);

impl TopNValue for CountVal {
    fn sort_key(&self) -> u64 {
        self.0
    }
    fn merge_into(&mut self, other: Self) {
        self.0 += other.0;
    }
    fn on_evict(self, evicted_key: u64) -> Self {
        CountVal(evicted_key + self.0)
    }
}

struct UrlByHitsVal(u64, u64); // (hits, bw)

impl TopNValue for UrlByHitsVal {
    fn sort_key(&self) -> u64 {
        self.0
    }
    fn merge_into(&mut self, other: Self) {
        self.0 += other.0;
        self.1 += other.1;
    }
    fn on_evict(self, evicted_key: u64) -> Self {
        UrlByHitsVal(evicted_key + self.0, self.1)
    }
}

struct UrlByBwVal(u64, u64); // (hits, bw)

impl TopNValue for UrlByBwVal {
    fn sort_key(&self) -> u64 {
        self.1
    }
    fn merge_into(&mut self, other: Self) {
        self.0 += other.0;
        self.1 += other.1;
    }
    fn on_evict(self, evicted_key: u64) -> Self {
        UrlByBwVal(self.0, evicted_key + self.1)
    }
}

// ── Count-Min Sketch ──────────────────────────────────────────────────────────

const CMS_WIDTH: usize = 8192; // power of 2; error ≤ total/8192 per key
const CMS_DEPTH: usize = 7; // failure probability ≈ e^(-7) ≈ 0.09%

struct CountMinSketch {
    table: Box<[[u64; CMS_WIDTH]; CMS_DEPTH]>,
    hashers: [ahash::RandomState; CMS_DEPTH],
}

impl CountMinSketch {
    fn new() -> Self {
        Self {
            table: Box::new([[0u64; CMS_WIDTH]; CMS_DEPTH]),
            hashers: [
                ahash::RandomState::with_seeds(
                    0x1a2b3c4d5e6f7a8b,
                    0x9c0d1e2f3a4b5c6d,
                    0x7e8f9a0b1c2d3e4f,
                    0x5a6b7c8d9e0f1a2b,
                ),
                ahash::RandomState::with_seeds(
                    0x3c4d5e6f7a8b9c0d,
                    0x1e2f3a4b5c6d7e8f,
                    0x9a0b1c2d3e4f5a6b,
                    0x7c8d9e0f1a2b3c4d,
                ),
                ahash::RandomState::with_seeds(
                    0x5e6f7a8b9c0d1e2f,
                    0x3a4b5c6d7e8f9a0b,
                    0x1c2d3e4f5a6b7c8d,
                    0x9e0f1a2b3c4d5e6f,
                ),
                ahash::RandomState::with_seeds(
                    0x7a8b9c0d1e2f3a4b,
                    0x5c6d7e8f9a0b1c2d,
                    0x3e4f5a6b7c8d9e0f,
                    0x1a2b3c4d5e6f7a8b,
                ),
                ahash::RandomState::with_seeds(
                    0x9c0d1e2f3a4b5c6d,
                    0x7e8f9a0b1c2d3e4f,
                    0x5a6b7c8d9e0f1a2b,
                    0x3c4d5e6f7a8b9c0d,
                ),
                ahash::RandomState::with_seeds(
                    0x1e2f3a4b5c6d7e8f,
                    0x9a0b1c2d3e4f5a6b,
                    0x7c8d9e0f1a2b3c4d,
                    0x5e6f7a8b9c0d1e2f,
                ),
                ahash::RandomState::with_seeds(
                    0x3a4b5c6d7e8f9a0b,
                    0x1c2d3e4f5a6b7c8d,
                    0x9e0f1a2b3c4d5e6f,
                    0x7a8b9c0d1e2f3a4b,
                ),
            ],
        }
    }

    #[inline]
    fn update(&mut self, key: &str, delta: u64) {
        for i in 0..CMS_DEPTH {
            let col = self.col(i, key);
            self.table[i][col] = self.table[i][col].saturating_add(delta);
        }
    }

    #[inline]
    fn estimate(&self, key: &str) -> u64 {
        let mut min = u64::MAX;
        for i in 0..CMS_DEPTH {
            let col = self.col(i, key);
            let v = self.table[i][col];
            if v < min {
                min = v;
            }
        }
        min
    }

    #[inline]
    fn col(&self, row: usize, key: &str) -> usize {
        let mut h = self.hashers[row].build_hasher();
        key.hash(&mut h);
        (h.finish() as usize) & (CMS_WIDTH - 1)
    }
}

// ── CmsTopN ───────────────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum SortBy {
    Hits,
    Bandwidth,
}

struct CmsTopN {
    cms: CountMinSketch,
    map: AHashMap<Arc<str>, (u64, u64)>, // (hits, bw)
    min_heap: BinaryHeap<Reverse<(u64, Arc<str>)>>,
    capacity: usize,
    sort_by: SortBy,
}

impl CmsTopN {
    fn new(capacity: usize, sort_by: SortBy) -> Self {
        Self {
            cms: CountMinSketch::new(),
            map: AHashMap::with_capacity(capacity),
            min_heap: BinaryHeap::with_capacity(capacity),
            capacity,
            sort_by,
        }
    }

    #[inline]
    fn sort_val(&self, hits: u64, bw: u64) -> u64 {
        match self.sort_by {
            SortBy::Hits => hits,
            SortBy::Bandwidth => bw,
        }
    }

    #[inline]
    fn add(&mut self, key: &str, hits: u64, bw: u64) {
        if self.capacity == 0 {
            return;
        }

        let cms_delta = match self.sort_by {
            SortBy::Hits => hits,
            SortBy::Bandwidth => bw,
        };
        self.cms.update(key, cms_delta);

        if let Some(existing) = self.map.get_mut(key) {
            existing.0 += hits;
            existing.1 += bw;
            return;
        }

        if self.map.len() < self.capacity {
            let key_arc = arcstr(key);
            let sort_val = self.sort_val(hits, bw);
            self.map.insert(Arc::clone(&key_arc), (hits, bw));
            self.min_heap.push(Reverse((sort_val, key_arc)));
            return;
        }

        // Map is full: use CMS estimate to decide whether to promote this key.
        let estimate = self.cms.estimate(key);
        let (min_key, min_sort_key) = self.resolve_min_entry();

        if estimate <= min_sort_key {
            return;
        }

        self.map.remove(min_key.as_ref());

        // Seed sort field from CMS estimate; other field starts from current delta.
        let (init_hits, init_bw) = match self.sort_by {
            SortBy::Hits => (estimate, bw),
            SortBy::Bandwidth => (hits, estimate),
        };
        let key_arc = arcstr(key);
        let sort_val = self.sort_val(init_hits, init_bw);
        self.map.insert(Arc::clone(&key_arc), (init_hits, init_bw));
        self.min_heap.push(Reverse((sort_val, key_arc)));
    }

    #[cold]
    fn resolve_min_entry(&mut self) -> (Arc<str>, u64) {
        loop {
            while let Some(Reverse((sort_key, key))) = self.min_heap.pop() {
                if let Some(&(hits, bw)) = self.map.get(key.as_ref()) {
                    if self.sort_val(hits, bw) == sort_key {
                        return (key, sort_key);
                    }
                }
            }

            self.min_heap.reserve(self.map.len());
            for (key, &(hits, bw)) in &self.map {
                self.min_heap
                    .push(Reverse((self.sort_val(hits, bw), Arc::clone(key))));
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.map
            .iter()
            .map(|(k, &(hits, bw))| (k.as_ref(), hits, bw))
    }
}

// ── Public types ──────────────────────────────────────────────────────────────

pub struct TopNCount(TopN<CountVal>);

impl TopNCount {
    pub fn new(capacity: usize) -> Self {
        Self(TopN::new(capacity))
    }

    #[inline]
    pub fn add(&mut self, key: &str, delta: u64) {
        self.0.add(key, CountVal(delta));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_ref(), v.0))
    }
}

pub struct TopNUrls(TopN<UrlByHitsVal>);

impl TopNUrls {
    pub fn new(capacity: usize) -> Self {
        Self(TopN::new(capacity))
    }

    #[inline]
    pub fn add(&mut self, url: &str, bw: u64) {
        self.0.add(url, UrlByHitsVal(1, bw));
    }

    #[inline]
    pub fn add_hits_bw(&mut self, url: &str, hits: u64, bw: u64) {
        self.0.add(url, UrlByHitsVal(hits, bw));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_ref(), v.0, v.1))
    }
}

pub struct TopNUrlsByBandwidth(TopN<UrlByBwVal>);

impl TopNUrlsByBandwidth {
    pub fn new(capacity: usize) -> Self {
        Self(TopN::new(capacity))
    }

    #[inline]
    pub fn add(&mut self, url: &str, bw: u64) {
        self.0.add(url, UrlByBwVal(1, bw));
    }

    #[inline]
    pub fn add_hits_bw(&mut self, url: &str, hits: u64, bw: u64) {
        self.0.add(url, UrlByBwVal(hits, bw));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_ref(), v.0, v.1))
    }
}

pub struct TopNHosts(CmsTopN);

impl TopNHosts {
    pub fn new(capacity: usize) -> Self {
        Self(CmsTopN::new(capacity, SortBy::Hits))
    }

    #[inline]
    pub fn add(&mut self, host: &str, bw: u64) {
        self.0.add(host, 1, bw);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, host: &str, hits: u64, bw: u64) {
        self.0.add(host, hits, bw);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.0.iter()
    }
}

pub struct TopNHostsByBandwidth(CmsTopN);

impl TopNHostsByBandwidth {
    pub fn new(capacity: usize) -> Self {
        Self(CmsTopN::new(capacity, SortBy::Bandwidth))
    }

    #[inline]
    pub fn add(&mut self, host: &str, bw: u64) {
        self.0.add(host, 1, bw);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, host: &str, hits: u64, bw: u64) {
        self.0.add(host, hits, bw);
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests;
