use std::{cmp::Reverse, collections::BinaryHeap, sync::Arc};

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
    fn trim_cmp(ak: &Arc<str>, a: &Self, bk: &Arc<str>, b: &Self) -> std::cmp::Ordering;
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
                self.min_heap.push(Reverse((val.sort_key(), Arc::clone(key))));
            }
        }
    }

    fn iter(&self) -> impl Iterator<Item = (&Arc<str>, &V)> + '_ {
        self.map.iter()
    }

    fn merge_from(&mut self, other: TopN<V>) {
        for (key, val) in other.map {
            if let Some(existing) = self.map.get_mut(key.as_ref()) {
                existing.merge_into(val);
            } else {
                let sort_key = val.sort_key();
                self.map.insert(Arc::clone(&key), val);
                self.min_heap.push(Reverse((sort_key, key)));
            }
        }
        self.trim_to_capacity();
    }

    fn trim_to_capacity(&mut self) {
        if self.capacity == 0 {
            self.map.clear();
            self.min_heap.clear();
            return;
        }

        if self.map.len() <= self.capacity {
            return;
        }

        let mut entries: Vec<_> = self.map.drain().collect();
        entries.select_nth_unstable_by(self.capacity - 1, |(ak, a), (bk, b)| {
            V::trim_cmp(ak, a, bk, b)
        });
        entries.truncate(self.capacity);
        self.min_heap.clear();

        for (key, val) in entries {
            let sort_key = val.sort_key();
            self.min_heap.push(Reverse((sort_key, Arc::clone(&key))));
            self.map.insert(key, val);
        }
    }
}

// ── Value types ───────────────────────────────────────────────────────────────

struct CountVal(u64);

impl TopNValue for CountVal {
    fn sort_key(&self) -> u64 { self.0 }
    fn merge_into(&mut self, other: Self) { self.0 += other.0; }
    fn on_evict(self, evicted_key: u64) -> Self { CountVal(evicted_key + self.0) }
    fn trim_cmp(ak: &Arc<str>, a: &Self, bk: &Arc<str>, b: &Self) -> std::cmp::Ordering {
        b.0.cmp(&a.0).then_with(|| ak.cmp(bk))
    }
}

struct UrlByHitsVal(u64, u64); // (hits, bw)

impl TopNValue for UrlByHitsVal {
    fn sort_key(&self) -> u64 { self.0 }
    fn merge_into(&mut self, other: Self) { self.0 += other.0; self.1 += other.1; }
    fn on_evict(self, evicted_key: u64) -> Self { UrlByHitsVal(evicted_key + self.0, self.1) }
    fn trim_cmp(ak: &Arc<str>, a: &Self, bk: &Arc<str>, b: &Self) -> std::cmp::Ordering {
        b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)).then_with(|| ak.cmp(bk))
    }
}

struct UrlByBwVal(u64, u64); // (hits, bw)

impl TopNValue for UrlByBwVal {
    fn sort_key(&self) -> u64 { self.1 }
    fn merge_into(&mut self, other: Self) { self.0 += other.0; self.1 += other.1; }
    fn on_evict(self, evicted_key: u64) -> Self { UrlByBwVal(self.0, evicted_key + self.1) }
    fn trim_cmp(ak: &Arc<str>, a: &Self, bk: &Arc<str>, b: &Self) -> std::cmp::Ordering {
        b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)).then_with(|| ak.cmp(bk))
    }
}

struct HostByHitsVal(u64, u64, Arc<str>, Arc<str>); // (hits, bw, cc, cn)

impl TopNValue for HostByHitsVal {
    fn sort_key(&self) -> u64 { self.0 }
    fn merge_into(&mut self, other: Self) {
        self.0 += other.0;
        self.1 += other.1;
        if self.2.as_ref() == "--" && other.2.as_ref() != "--" {
            self.2 = other.2;
            self.3 = other.3;
        }
    }
    fn on_evict(self, evicted_key: u64) -> Self {
        HostByHitsVal(evicted_key + self.0, self.1, self.2, self.3)
    }
    fn trim_cmp(ak: &Arc<str>, a: &Self, bk: &Arc<str>, b: &Self) -> std::cmp::Ordering {
        b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)).then_with(|| ak.cmp(bk))
    }
}

struct HostByBwVal(u64, u64, Arc<str>, Arc<str>); // (hits, bw, cc, cn)

impl TopNValue for HostByBwVal {
    fn sort_key(&self) -> u64 { self.1 }
    fn merge_into(&mut self, other: Self) {
        self.0 += other.0;
        self.1 += other.1;
        if self.2.as_ref() == "--" && other.2.as_ref() != "--" {
            self.2 = other.2;
            self.3 = other.3;
        }
    }
    fn on_evict(self, evicted_key: u64) -> Self {
        HostByBwVal(self.0, evicted_key + self.1, self.2, self.3)
    }
    fn trim_cmp(ak: &Arc<str>, a: &Self, bk: &Arc<str>, b: &Self) -> std::cmp::Ordering {
        b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)).then_with(|| ak.cmp(bk))
    }
}

// ── Public types ──────────────────────────────────────────────────────────────

pub struct TopNCount(TopN<CountVal>);

impl TopNCount {
    pub fn new(capacity: usize) -> Self { Self(TopN::new(capacity)) }

    #[inline]
    pub fn add(&mut self, key: &str, delta: u64) { self.0.add(key, CountVal(delta)); }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_ref(), v.0))
    }

    pub fn merge_from(&mut self, other: TopNCount) { self.0.merge_from(other.0); }
}

pub struct TopNUrls(TopN<UrlByHitsVal>);

impl TopNUrls {
    pub fn new(capacity: usize) -> Self { Self(TopN::new(capacity)) }

    #[inline]
    pub fn add(&mut self, url: &str, bw: u64) { self.0.add(url, UrlByHitsVal(1, bw)); }

    #[inline]
    pub fn add_hits_bw(&mut self, url: &str, hits: u64, bw: u64) {
        self.0.add(url, UrlByHitsVal(hits, bw));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_ref(), v.0, v.1))
    }

    pub fn merge_from(&mut self, other: TopNUrls) { self.0.merge_from(other.0); }
}

pub struct TopNUrlsByBandwidth(TopN<UrlByBwVal>);

impl TopNUrlsByBandwidth {
    pub fn new(capacity: usize) -> Self { Self(TopN::new(capacity)) }

    #[inline]
    pub fn add(&mut self, url: &str, bw: u64) { self.0.add(url, UrlByBwVal(1, bw)); }

    #[inline]
    pub fn add_hits_bw(&mut self, url: &str, hits: u64, bw: u64) {
        self.0.add(url, UrlByBwVal(hits, bw));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_ref(), v.0, v.1))
    }

    pub fn merge_from(&mut self, other: TopNUrlsByBandwidth) { self.0.merge_from(other.0); }
}

pub struct TopNHosts(TopN<HostByHitsVal>);

impl TopNHosts {
    pub fn new(capacity: usize) -> Self { Self(TopN::new(capacity)) }

    #[inline]
    pub fn add(&mut self, host: &str, bw: u64, cc: &Arc<str>, cn: &Arc<str>) {
        self.add_hits_bw(host, 1, bw, cc, cn);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, host: &str, hits: u64, bw: u64, cc: &Arc<str>, cn: &Arc<str>) {
        self.0.add(host, HostByHitsVal(hits, bw, Arc::clone(cc), Arc::clone(cn)));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64, &Arc<str>, &Arc<str>)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_ref(), v.0, v.1, &v.2, &v.3))
    }

    pub fn merge_from(&mut self, other: TopNHosts) { self.0.merge_from(other.0); }
}

pub struct TopNHostsByBandwidth(TopN<HostByBwVal>);

impl TopNHostsByBandwidth {
    pub fn new(capacity: usize) -> Self { Self(TopN::new(capacity)) }

    #[inline]
    pub fn add(&mut self, host: &str, bw: u64, cc: &Arc<str>, cn: &Arc<str>) {
        self.add_hits_bw(host, 1, bw, cc, cn);
    }

    #[inline]
    pub fn add_hits_bw(&mut self, host: &str, hits: u64, bw: u64, cc: &Arc<str>, cn: &Arc<str>) {
        self.0.add(host, HostByBwVal(hits, bw, Arc::clone(cc), Arc::clone(cn)));
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64, &Arc<str>, &Arc<str>)> + '_ {
        self.0.iter().map(|(k, v)| (k.as_ref(), v.0, v.1, &v.2, &v.3))
    }

    pub fn merge_from(&mut self, other: TopNHostsByBandwidth) { self.0.merge_from(other.0); }
}

#[cfg(test)]
mod tests;
