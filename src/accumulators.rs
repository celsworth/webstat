// HourlyStats, HourlyAcc, and HourlyMap: per-hour traffic counters keyed by (site, hour).

use std::sync::Arc;

use ahash::AHashMap;

#[derive(Debug, Default)]
pub struct HourlyStats {
    pub hits: u64,
    pub visits: u64,
    pub bandwidth: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
}

#[derive(Debug, Default)]
pub struct HourlyAcc {
    pub stats: HourlyStats,
}

pub type HourlyMap = AHashMap<Arc<str>, AHashMap<u8, HourlyAcc>>;
