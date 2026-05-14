use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method_proto::{METHOD_COUNT, METHOD_GET, PROTO_1_1, PROTO_COUNT};
    use crate::topn::{HourlyAcc, TopNCount, TopNHosts, TopNUrls};

    fn arc(s: &str) -> Arc<str> {
        Arc::from(s)
    }

    #[test]
    fn new_and_is_empty_behave_as_expected() {
        let mut acc = RunAccumulators::new(16, 12, false, false, false);
        assert!(acc.is_empty());

        // Any populated bucket should make the accumulator non-empty.
        let period = arc("2026-05");
        let mut codes = AHashMap::new();
        codes.insert(200u16, 1u64);
        acc.status_codes.insert(period, codes);
        assert!(!acc.is_empty());
    }

    #[test]
    fn new_accumulator_has_empty_method_and_proto_counts() {
        let acc = RunAccumulators::new(16, 12, false, false, false);
        assert!(acc.method_counts.is_empty());
        assert!(acc.proto_counts.is_empty());
    }

    #[test]
    fn method_counts_populated_bucket_makes_is_empty_false() {
        let mut acc = RunAccumulators::new(16, 12, false, false, false);
        let mut counts = [0u64; METHOD_COUNT];
        counts[METHOD_GET] = 5;
        acc.method_counts.insert(arc("2026-05"), counts);
        assert!(!acc.is_empty());
    }

    #[test]
    fn proto_counts_populated_bucket_makes_is_empty_false() {
        let mut acc = RunAccumulators::new(16, 12, false, false, false);
        let mut counts = [0u64; PROTO_COUNT];
        counts[PROTO_1_1] = 3;
        acc.proto_counts.insert(arc("2026-05"), counts);
        assert!(!acc.is_empty());
    }

    #[test]
    fn hourly_populated_bucket_makes_is_empty_false() {
        let mut acc = RunAccumulators::new(16, 12, false, false, false);
        let mut hourly_acc = HourlyAcc::default();
        hourly_acc.stats.hits = 1;
        acc.hourly
            .entry(arc("2026-05-10"))
            .or_default()
            .insert(10, hourly_acc);
        assert!(!acc.is_empty());
    }

    #[test]
    fn top_urls_populated_bucket_makes_is_empty_false() {
        let mut acc = RunAccumulators::new(16, 12, true, false, false);
        let mut urls = TopNUrls::new(10);
        urls.add_hits_bw("/index.html", 5, 1024);
        acc.top_urls.insert(arc("2026-05"), urls);
        assert!(!acc.is_empty());
    }

    #[test]
    fn top_urls_bw_populated_bucket_makes_is_empty_false() {
        let mut acc = RunAccumulators::new(16, 12, true, false, false);
        let mut urls_bw = crate::topn::TopNUrlsByBandwidth::new(10);
        urls_bw.add_hits_bw("/download.zip", 2, 5000);
        acc.top_urls_bw.insert(arc("2026-05"), urls_bw);
        assert!(!acc.is_empty());
    }

    #[test]
    fn top_hosts_populated_bucket_makes_is_empty_false() {
        let mut acc = RunAccumulators::new(16, 12, false, true, false);
        let mut hosts = TopNHosts::new(10);
        hosts.add_hits_bw("1.2.3.4", 3, 512);
        acc.top_hosts.insert(arc("2026-05"), hosts);
        assert!(!acc.is_empty());
    }

    #[test]
    fn top_hosts_bw_populated_bucket_makes_is_empty_false() {
        let mut acc = RunAccumulators::new(16, 12, false, true, false);
        let mut hosts_bw = crate::topn::TopNHostsByBandwidth::new(10);
        hosts_bw.add_hits_bw("5.6.7.8", 1, 8192);
        acc.top_hosts_bw.insert(arc("2026-05"), hosts_bw);
        assert!(!acc.is_empty());
    }

    #[test]
    fn top_refs_populated_bucket_makes_is_empty_false() {
        let mut acc = RunAccumulators::new(16, 12, false, false, true);
        let mut refs = TopNCount::new(10);
        refs.add("https://example.com/", 7);
        acc.top_refs.insert(arc("2026-05"), refs);
        assert!(!acc.is_empty());
    }

    #[test]
    fn top_agents_populated_bucket_makes_is_empty_false() {
        let mut acc = RunAccumulators::new(16, 12, false, false, false);
        let mut agents = TopNCount::new(10);
        agents.add("Mozilla/5.0", 4);
        acc.top_agents.insert(arc("2026-05"), agents);
        assert!(!acc.is_empty());
    }

    #[test]
    fn top_countries_populated_bucket_makes_is_empty_false() {
        let mut acc = RunAccumulators::new(16, 12, false, false, false);
        let mut countries = AHashMap::new();
        countries.insert("US".to_string(), 100u64);
        acc.top_countries.insert(arc("2026-05"), countries);
        assert!(!acc.is_empty());
    }

    #[test]
    fn hll_site_counts_populated_bucket_makes_is_empty_false() {
        let mut acc = RunAccumulators::new(16, 12, false, false, false);
        let mut hll = HyperLogLog::new(12);
        hll.add_hash(12345);
        acc.hll_site_counts.insert(arc("2026-05"), hll);
        assert!(!acc.is_empty());
    }

    #[test]
    fn new_with_all_features_enabled_has_nonzero_capacities() {
        let acc = RunAccumulators::new(32, 14, true, true, true);
        assert!(acc.top_urls.capacity() > 0);
        assert!(acc.top_urls_bw.capacity() > 0);
        assert!(acc.top_hosts.capacity() > 0);
        assert!(acc.top_hosts_bw.capacity() > 0);
        assert!(acc.top_refs.capacity() > 0);
    }

    #[test]
    fn new_with_features_disabled_has_zero_capacity() {
        let acc = RunAccumulators::new(32, 14, false, false, false);
        assert_eq!(acc.top_urls.capacity(), 0);
        assert_eq!(acc.top_hosts.capacity(), 0);
        assert_eq!(acc.top_refs.capacity(), 0);
    }
}
