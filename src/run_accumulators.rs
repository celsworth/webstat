// RunAccumulators: in-memory aggregation buffers (hourly, URLs, hosts, refs, agents, countries,
// IPs, status codes, etc.) flushed to SQLite at checkpoints and end-of-run.

use std::sync::Arc;

use ahash::AHashMap;

use crate::ip::IpBitmaps;

use crate::accumulators::HourlyMap;
use crate::method_proto::{METHOD_COUNT, PROTO_COUNT};
use crate::response_time::ResponseTimeHistogram;

#[derive(Default)]
pub(crate) struct UrlStats {
    pub(crate) hits: u64,
    pub(crate) bandwidth: u64,
    pub(crate) rt_sum: u64,
    pub(crate) rt_count: u64,
    pub(crate) rt_max: u32,
}

/// Per-URL error counters for the "top erroring URLs" report. Keyed by URL.
/// c4xx/c5xx are overflow buckets for codes not individually tracked.
#[derive(Default)]
pub(crate) struct ErrUrlStats {
    /// status code -> (hits, bandwidth). Every 4xx/5xx code is recorded individually;
    /// folding into report columns happens at report time.
    pub(crate) codes: AHashMap<u16, (u64, u64)>,
}

impl ErrUrlStats {
    /// Total error hits across all recorded codes for this URL.
    pub(crate) fn total_hits(&self) -> u64 {
        self.codes.values().map(|(h, _)| *h).sum()
    }

    /// Total bandwidth across all recorded codes for this URL.
    pub(crate) fn total_bandwidth(&self) -> u64 {
        self.codes.values().map(|(_, b)| *b).sum()
    }
}


/// Per-bucket accumulator: mirrors a subset of RunAccumulators for a single named bucket.
#[derive(Default)]
pub(crate) struct BucketAcc {
    pub(crate) hits: u64,
    pub(crate) bandwidth: u64,
    pub(crate) rt_sum: u64,
    pub(crate) rt_count: u64,
    pub(crate) rt_max: u32,
    pub(crate) url_stats: AHashMap<String, UrlStats>,
    pub(crate) status_codes: AHashMap<u16, u64>,
    pub(crate) agents: AHashMap<Arc<str>, (u64, u64)>,
    pub(crate) countries: AHashMap<Arc<str>, (u64, u64)>,
    pub(crate) method_counts: [u64; METHOD_COUNT],
    pub(crate) protocol_counts: [u64; PROTO_COUNT],
    pub(crate) rt_histogram: Option<ResponseTimeHistogram>,
    /// date → hour → (hits, bandwidth)
    pub(crate) hourly: AHashMap<Arc<str>, AHashMap<u8, (u64, u64)>>,
    /// date → daily RT histogram
    pub(crate) daily_hists: AHashMap<Arc<str>, ResponseTimeHistogram>,
    /// date → unique IPs bitmap
    pub(crate) daily_ips: AHashMap<Arc<str>, IpBitmaps>,
}

pub(crate) struct RunAccumulators {
    pub(crate) current_month: String,
    pub(crate) hourly: HourlyMap,
    pub(crate) url_stats: AHashMap<String, UrlStats>,
    pub(crate) error_urls: AHashMap<String, ErrUrlStats>,
    pub(crate) hosts: AHashMap<String, (u64, u64)>,
    pub(crate) refs: AHashMap<String, u64>,
    pub(crate) agents: AHashMap<String, (u64, u64)>,
    pub(crate) daily_ips: AHashMap<Arc<str>, IpBitmaps>,
    pub(crate) daily_hists: AHashMap<Arc<str>, ResponseTimeHistogram>,
    pub(crate) countries: AHashMap<String, (u64, u64)>,
    pub(crate) status_codes: AHashMap<u16, u64>,
    pub(crate) method_counts: [u64; METHOD_COUNT],
    pub(crate) protocol_counts: [u64; PROTO_COUNT],
    /// Per-bucket stats; keyed by the same Arc<str> used in Action::Bucket.
    pub(crate) bucket_stats: AHashMap<Arc<str>, BucketAcc>,
}

impl RunAccumulators {
    pub(crate) fn new(current_month: String) -> Self {
        Self {
            current_month,
            hourly: AHashMap::with_capacity(32),
            url_stats: AHashMap::with_capacity(65_536),
            error_urls: AHashMap::with_capacity(4_096),
            hosts: AHashMap::with_capacity(65_536),
            refs: AHashMap::with_capacity(4_096),
            agents: AHashMap::with_capacity(256),
            daily_ips: AHashMap::with_capacity(32),
            daily_hists: AHashMap::with_capacity(32),
            countries: AHashMap::with_capacity(256),
            status_codes: AHashMap::with_capacity(32),
            method_counts: [0; METHOD_COUNT],
            protocol_counts: [0; PROTO_COUNT],
            bucket_stats: AHashMap::with_capacity(32),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.hourly.is_empty()
            && self.url_stats.is_empty()
            && self.error_urls.is_empty()
            && self.hosts.is_empty()
            && self.refs.is_empty()
            && self.agents.is_empty()
            && self.countries.is_empty()
            && self.status_codes.is_empty()
            && self.method_counts.iter().all(|&c| c == 0)
            && self.protocol_counts.iter().all(|&c| c == 0)
            && self.bucket_stats.is_empty()
    }

    pub(crate) fn clear_for_new_month(&mut self, new_month: String) {
        *self = Self::new(new_month);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulators::HourlyAcc;
    use crate::method_proto::{METHOD_GET, PROTO_1_1};
    #[test]
    fn new_is_empty() {
        let acc = RunAccumulators::new("2026-05".to_string());
        assert!(acc.is_empty());
        assert_eq!(acc.current_month, "2026-05");
    }

    #[test]
    fn status_codes_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.status_codes.insert(200u16, 1u64);
        assert!(!acc.is_empty());
    }

    #[test]
    fn method_counts_nonzero_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.method_counts[METHOD_GET] = 5;
        assert!(!acc.is_empty());
    }

    #[test]
    fn protocol_counts_nonzero_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.protocol_counts[PROTO_1_1] = 3;
        assert!(!acc.is_empty());
    }

    #[test]
    fn hourly_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        let mut hourly_acc = HourlyAcc::default();
        hourly_acc.stats.hits = 1;
        acc.hourly
            .entry(std::sync::Arc::from("2026-05-10"))
            .or_default()
            .insert(10, hourly_acc);
        assert!(!acc.is_empty());
    }

    #[test]
    fn urls_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.url_stats.insert("/index.html".to_string(), UrlStats { hits: 5, bandwidth: 1024, ..Default::default() });
        assert!(!acc.is_empty());
    }

    #[test]
    fn hosts_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.hosts.insert("1.2.3.4".to_string(), (3, 512));
        assert!(!acc.is_empty());
    }

    #[test]
    fn refs_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.refs.insert("example.com".to_string(), 7);
        assert!(!acc.is_empty());
    }

    #[test]
    fn agents_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.agents.insert("Chrome".to_string(), (4, 1024));
        assert!(!acc.is_empty());
    }

    #[test]
    fn countries_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.countries.insert("US".to_string(), (100, 4096));
        assert!(!acc.is_empty());
    }

    #[test]
    fn clear_for_new_month_resets_all_and_updates_month() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.url_stats.insert("/index.html".to_string(), UrlStats { hits: 5, bandwidth: 1024, ..Default::default() });
        acc.method_counts[METHOD_GET] = 10;
        acc.protocol_counts[PROTO_1_1] = 10;
        acc.clear_for_new_month("2026-06".to_string());
        assert!(acc.is_empty());
        assert_eq!(acc.current_month, "2026-06");
    }

    #[test]
    fn daily_ips_not_counted_in_is_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.daily_ips
            .entry(Arc::from("2026-05-01"))
            .or_default()
            .insert(crate::ip::Ip::V4(0x01020304_u32));
        // daily_ips does not affect is_empty (it's just a write buffer)
        assert!(acc.is_empty());
    }

    #[test]
    fn bucket_stats_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.bucket_stats
            .insert(Arc::from("api"), BucketAcc { hits: 1, ..Default::default() });
        assert!(!acc.is_empty());
    }

    #[test]
    fn clear_for_new_month_clears_bucket_stats() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.bucket_stats
            .insert(Arc::from("api"), BucketAcc { hits: 100, ..Default::default() });
        acc.url_stats.insert(
            "/index.html".to_string(),
            UrlStats { hits: 5, bandwidth: 1024, ..Default::default() },
        );
        assert!(!acc.is_empty());
        acc.clear_for_new_month("2026-06".to_string());
        assert!(acc.is_empty(), "bucket_stats must be cleared");
        assert_eq!(acc.current_month, "2026-06");
    }
}
