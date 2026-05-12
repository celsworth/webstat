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

// ── TopNCount ────────────────────────────────────────────────────────────────

pub struct TopNCount {
    map: AHashMap<Arc<str>, u64>,
    min_heap: BinaryHeap<Reverse<(u64, Arc<str>)>>,
    capacity: usize,
}

impl TopNCount {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(capacity),
            min_heap: BinaryHeap::with_capacity(capacity),
            capacity,
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
            let key_arc = arcstr(key);

            self.map.insert(Arc::clone(&key_arc), delta);
            self.min_heap.push(Reverse((delta, key_arc)));

            return;
        }

        let (min_key, min_val) = self.resolve_min_entry();

        self.map.remove(min_key.as_ref());

        let new_val = min_val + delta;
        let key_arc = arcstr(key);

        self.map.insert(Arc::clone(&key_arc), new_val);
        self.min_heap.push(Reverse((new_val, key_arc)));
    }

    #[cold]
    fn resolve_min_entry(&mut self) -> (Arc<str>, u64) {
        loop {
            while let Some(Reverse((val, key))) = self.min_heap.pop() {
                match self.map.get(key.as_ref()) {
                    Some(actual) if *actual == val => {
                        return (key, val);
                    }
                    _ => {}
                }
            }

            self.min_heap.reserve(self.map.len());

            for (key, val) in &self.map {
                self.min_heap.push(Reverse((*val, Arc::clone(key))));
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64)> + '_ {
        self.map.iter().map(|(k, v)| (k.as_ref(), *v))
    }

    pub fn merge_from(&mut self, other: TopNCount) {
        for (key, val) in other.map {
            if let Some(existing) = self.map.get_mut(key.as_ref()) {
                *existing += val;
            } else {
                self.map.insert(Arc::clone(&key), val);
                self.min_heap.push(Reverse((val, key)));
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

        entries.select_nth_unstable_by(self.capacity - 1, |(k1, v1), (k2, v2)| {
            v2.cmp(v1).then_with(|| k1.cmp(k2))
        });

        entries.truncate(self.capacity);

        self.min_heap.clear();

        for (key, val) in entries {
            self.min_heap.push(Reverse((val, Arc::clone(&key))));
            self.map.insert(key, val);
        }
    }
}

// ── TopNUrls ─────────────────────────────────────────────────────────────────

pub struct TopNUrls {
    map: AHashMap<Arc<str>, (u64, u64)>,
    min_heap: BinaryHeap<Reverse<(u64, Arc<str>)>>,
    capacity: usize,
}

impl TopNUrls {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(capacity),
            min_heap: BinaryHeap::with_capacity(capacity),
            capacity,
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
            let url_arc = arcstr(url);

            self.map.insert(Arc::clone(&url_arc), (hits, bw));

            self.min_heap.push(Reverse((hits, url_arc)));

            return;
        }

        let (min_key, min_hits) = self.resolve_min_entry();

        self.map.remove(min_key.as_ref());

        let new_hits = min_hits + hits;
        let url_arc = arcstr(url);

        self.map.insert(Arc::clone(&url_arc), (new_hits, bw));

        self.min_heap.push(Reverse((new_hits, url_arc)));
    }

    #[cold]
    fn resolve_min_entry(&mut self) -> (Arc<str>, u64) {
        loop {
            while let Some(Reverse((hits, key))) = self.min_heap.pop() {
                match self.map.get(key.as_ref()) {
                    Some((actual_hits, _)) if *actual_hits == hits => {
                        return (key, hits);
                    }
                    _ => {}
                }
            }

            self.min_heap.reserve(self.map.len());

            for (key, (hits, _)) in &self.map {
                self.min_heap.push(Reverse((*hits, Arc::clone(key))));
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.map
            .iter()
            .map(|(k, (hits, bw))| (k.as_ref(), *hits, *bw))
    }

    pub fn merge_from(&mut self, other: TopNUrls) {
        for (url, (hits, bw)) in other.map {
            if let Some(existing) = self.map.get_mut(url.as_ref()) {
                existing.0 += hits;
                existing.1 += bw;
            } else {
                self.map.insert(Arc::clone(&url), (hits, bw));

                self.min_heap.push(Reverse((hits, url)));
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

        entries.select_nth_unstable_by(
            self.capacity - 1,
            |(url_a, (hits_a, bw_a)), (url_b, (hits_b, bw_b))| {
                hits_b
                    .cmp(hits_a)
                    .then_with(|| bw_b.cmp(bw_a))
                    .then_with(|| url_a.cmp(url_b))
            },
        );

        entries.truncate(self.capacity);

        self.min_heap.clear();

        for (url, (hits, bw)) in entries {
            self.min_heap.push(Reverse((hits, Arc::clone(&url))));

            self.map.insert(url, (hits, bw));
        }
    }
}

// ── TopNUrlsByBandwidth ──────────────────────────────────────────────────────

pub struct TopNUrlsByBandwidth {
    map: AHashMap<Arc<str>, (u64, u64)>,
    min_heap: BinaryHeap<Reverse<(u64, Arc<str>)>>,
    capacity: usize,
}

impl TopNUrlsByBandwidth {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(capacity),
            min_heap: BinaryHeap::with_capacity(capacity),
            capacity,
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
            let url_arc = arcstr(url);

            self.map.insert(Arc::clone(&url_arc), (hits, bw));

            self.min_heap.push(Reverse((bw, url_arc)));

            return;
        }

        let (min_key, min_bw) = self.resolve_min_entry();

        self.map.remove(min_key.as_ref());

        let new_bw = min_bw + bw;
        let url_arc = arcstr(url);

        self.map.insert(Arc::clone(&url_arc), (hits, new_bw));

        self.min_heap.push(Reverse((new_bw, url_arc)));
    }

    #[cold]
    fn resolve_min_entry(&mut self) -> (Arc<str>, u64) {
        loop {
            while let Some(Reverse((bw, key))) = self.min_heap.pop() {
                match self.map.get(key.as_ref()) {
                    Some((_, actual_bw)) if *actual_bw == bw => {
                        return (key, bw);
                    }
                    _ => {}
                }
            }

            self.min_heap.reserve(self.map.len());

            for (key, (_, bw)) in &self.map {
                self.min_heap.push(Reverse((*bw, Arc::clone(key))));
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64)> + '_ {
        self.map
            .iter()
            .map(|(k, (hits, bw))| (k.as_ref(), *hits, *bw))
    }

    pub fn merge_from(&mut self, other: TopNUrlsByBandwidth) {
        for (url, (hits, bw)) in other.map {
            if let Some(existing) = self.map.get_mut(url.as_ref()) {
                existing.0 += hits;
                existing.1 += bw;
            } else {
                self.map.insert(Arc::clone(&url), (hits, bw));

                self.min_heap.push(Reverse((bw, url)));
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

        entries.select_nth_unstable_by(
            self.capacity - 1,
            |(url_a, (hits_a, bw_a)), (url_b, (hits_b, bw_b))| {
                bw_b.cmp(bw_a)
                    .then_with(|| hits_b.cmp(hits_a))
                    .then_with(|| url_a.cmp(url_b))
            },
        );

        entries.truncate(self.capacity);

        self.min_heap.clear();

        for (url, (hits, bw)) in entries {
            self.min_heap.push(Reverse((bw, Arc::clone(&url))));

            self.map.insert(url, (hits, bw));
        }
    }
}

// ── TopNHosts ────────────────────────────────────────────────────────────────

type HostEntry = (u64, u64, Arc<str>, Arc<str>);

pub struct TopNHosts {
    map: AHashMap<Arc<str>, HostEntry>,
    min_heap: BinaryHeap<Reverse<(u64, Arc<str>)>>,
    capacity: usize,
}

impl TopNHosts {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(capacity),
            min_heap: BinaryHeap::with_capacity(capacity),
            capacity,
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
            let host_arc = arcstr(host);

            self.map.insert(
                Arc::clone(&host_arc),
                (hits, bw, Arc::clone(cc), Arc::clone(cn)),
            );

            self.min_heap.push(Reverse((hits, host_arc)));

            return;
        }

        let (min_key, min_hits) = self.resolve_min_entry();

        self.map.remove(min_key.as_ref());

        let new_hits = min_hits + hits;
        let host_arc = arcstr(host);

        self.map.insert(
            Arc::clone(&host_arc),
            (new_hits, bw, Arc::clone(cc), Arc::clone(cn)),
        );

        self.min_heap.push(Reverse((new_hits, host_arc)));
    }

    #[cold]
    fn resolve_min_entry(&mut self) -> (Arc<str>, u64) {
        loop {
            while let Some(Reverse((hits, key))) = self.min_heap.pop() {
                match self.map.get(key.as_ref()) {
                    Some((actual_hits, _, _, _)) if *actual_hits == hits => {
                        return (key, hits);
                    }
                    _ => {}
                }
            }

            self.min_heap.reserve(self.map.len());

            for (key, (hits, _, _, _)) in &self.map {
                self.min_heap.push(Reverse((*hits, Arc::clone(key))));
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64, &Arc<str>, &Arc<str>)> + '_ {
        self.map
            .iter()
            .map(|(k, (hits, bw, cc, cn))| (k.as_ref(), *hits, *bw, cc, cn))
    }

    pub fn merge_from(&mut self, other: TopNHosts) {
        for (host, (hits, bw, cc, cn)) in other.map {
            if let Some(existing) = self.map.get_mut(host.as_ref()) {
                existing.0 += hits;
                existing.1 += bw;

                if existing.2.as_ref() == "--" && cc.as_ref() != "--" {
                    existing.2 = cc;
                    existing.3 = cn;
                }
            } else {
                self.map.insert(
                    Arc::clone(&host),
                    (hits, bw, Arc::clone(&cc), Arc::clone(&cn)),
                );

                self.min_heap.push(Reverse((hits, host)));
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

        self.min_heap.clear();

        for (host, (hits, bw, cc, cn)) in entries {
            self.min_heap.push(Reverse((hits, Arc::clone(&host))));

            self.map.insert(host, (hits, bw, cc, cn));
        }
    }
}

// ── TopNHostsByBandwidth ─────────────────────────────────────────────────────

pub struct TopNHostsByBandwidth {
    map: AHashMap<Arc<str>, HostEntry>,
    min_heap: BinaryHeap<Reverse<(u64, Arc<str>)>>,
    capacity: usize,
}

impl TopNHostsByBandwidth {
    pub fn new(capacity: usize) -> Self {
        Self {
            map: AHashMap::with_capacity(capacity),
            min_heap: BinaryHeap::with_capacity(capacity),
            capacity,
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
            let host_arc = arcstr(host);

            self.map.insert(
                Arc::clone(&host_arc),
                (hits, bw, Arc::clone(cc), Arc::clone(cn)),
            );

            self.min_heap.push(Reverse((bw, host_arc)));

            return;
        }

        let (min_key, min_bw) = self.resolve_min_entry();

        self.map.remove(min_key.as_ref());

        let new_bw = min_bw + bw;
        let host_arc = arcstr(host);

        self.map.insert(
            Arc::clone(&host_arc),
            (hits, new_bw, Arc::clone(cc), Arc::clone(cn)),
        );

        self.min_heap.push(Reverse((new_bw, host_arc)));
    }

    #[cold]
    fn resolve_min_entry(&mut self) -> (Arc<str>, u64) {
        loop {
            while let Some(Reverse((bw, key))) = self.min_heap.pop() {
                match self.map.get(key.as_ref()) {
                    Some((_, actual_bw, _, _)) if *actual_bw == bw => {
                        return (key, bw);
                    }
                    _ => {}
                }
            }

            self.min_heap.reserve(self.map.len());

            for (key, (_, bw, _, _)) in &self.map {
                self.min_heap.push(Reverse((*bw, Arc::clone(key))));
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, u64, u64, &Arc<str>, &Arc<str>)> + '_ {
        self.map
            .iter()
            .map(|(k, (hits, bw, cc, cn))| (k.as_ref(), *hits, *bw, cc, cn))
    }

    pub fn merge_from(&mut self, other: TopNHostsByBandwidth) {
        for (host, (hits, bw, cc, cn)) in other.map {
            if let Some(existing) = self.map.get_mut(host.as_ref()) {
                existing.0 += hits;
                existing.1 += bw;

                if existing.2.as_ref() == "--" && cc.as_ref() != "--" {
                    existing.2 = cc;
                    existing.3 = cn;
                }
            } else {
                self.map.insert(
                    Arc::clone(&host),
                    (hits, bw, Arc::clone(&cc), Arc::clone(&cn)),
                );

                self.min_heap.push(Reverse((bw, host)));
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

        entries.select_nth_unstable_by(
            self.capacity - 1,
            |(host_a, (hits_a, bw_a, _, _)), (host_b, (hits_b, bw_b, _, _))| {
                bw_b.cmp(bw_a)
                    .then_with(|| hits_b.cmp(hits_a))
                    .then_with(|| host_a.cmp(host_b))
            },
        );

        entries.truncate(self.capacity);

        self.min_heap.clear();

        for (host, (hits, bw, cc, cn)) in entries {
            self.min_heap.push(Reverse((bw, Arc::clone(&host))));

            self.map.insert(host, (hits, bw, cc, cn));
        }
    }
}

#[cfg(test)]
mod tests;
