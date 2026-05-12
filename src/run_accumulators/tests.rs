use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method_proto::{
        METHOD_COUNT, METHOD_GET, METHOD_OTHER, METHOD_POST, PROTO_1_1, PROTO_2_0, PROTO_COUNT,
        PROTO_OTHER,
    };
    use crate::topn::{HourlyAcc, TopNCount, TopNHitsBw, TopNHosts};

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
    fn merge_from_adds_method_counts_element_wise() {
        let mut left = RunAccumulators::new(8, 12, false, false, false);
        let mut right = RunAccumulators::new(8, 12, false, false, false);
        let period = arc("2026-05");

        let mut lm = [0u64; METHOD_COUNT];
        lm[METHOD_GET] = 10;
        lm[METHOD_POST] = 3;
        left.method_counts.insert(Arc::clone(&period), lm);

        let mut rm = [0u64; METHOD_COUNT];
        rm[METHOD_GET] = 5;
        rm[METHOD_OTHER] = 2;
        right.method_counts.insert(Arc::clone(&period), rm);

        left.merge_from(right, 12, 10);

        let merged = left.method_counts.get("2026-05").unwrap();
        assert_eq!(merged[METHOD_GET], 15);
        assert_eq!(merged[METHOD_POST], 3);
        assert_eq!(merged[METHOD_OTHER], 2);
    }

    #[test]
    fn merge_from_adds_proto_counts_element_wise() {
        let mut left = RunAccumulators::new(8, 12, false, false, false);
        let mut right = RunAccumulators::new(8, 12, false, false, false);
        let period = arc("2026-05");

        let mut lp = [0u64; PROTO_COUNT];
        lp[PROTO_1_1] = 100;
        left.proto_counts.insert(Arc::clone(&period), lp);

        let mut rp = [0u64; PROTO_COUNT];
        rp[PROTO_1_1] = 50;
        rp[PROTO_2_0] = 20;
        right.proto_counts.insert(Arc::clone(&period), rp);

        left.merge_from(right, 12, 10);

        let merged = left.proto_counts.get("2026-05").unwrap();
        assert_eq!(merged[PROTO_1_1], 150);
        assert_eq!(merged[PROTO_2_0], 20);
        assert_eq!(merged[PROTO_OTHER], 0);
    }

    #[test]
    fn merge_from_creates_new_period_entries_when_absent_in_left() {
        let mut left = RunAccumulators::new(8, 12, false, false, false);
        let mut right = RunAccumulators::new(8, 12, false, false, false);

        let mut rm = [0u64; METHOD_COUNT];
        rm[METHOD_GET] = 7;
        right.method_counts.insert(arc("2026-06"), rm);

        let mut rp = [0u64; PROTO_COUNT];
        rp[PROTO_2_0] = 4;
        right.proto_counts.insert(arc("2026-06"), rp);

        left.merge_from(right, 12, 10);

        assert_eq!(left.method_counts.get("2026-06").unwrap()[METHOD_GET], 7);
        assert_eq!(left.proto_counts.get("2026-06").unwrap()[PROTO_2_0], 4);
    }

    #[test]
    fn merge_from_combines_all_tracked_data() {
        let mut left = RunAccumulators::new(8, 12, true, true, true);
        let mut right = RunAccumulators::new(8, 12, true, true, true);

        let date = arc("2026-05-10");
        let period = arc("2026-05");

        // Hourly merge: stats and unique-ip set should combine.
        let mut left_hour = HourlyAcc::default();
        left_hour.stats.hits = 2;
        left_hour.ip_set.insert(1);
        left.hourly
            .entry(Arc::clone(&date))
            .or_default()
            .insert(10, left_hour);

        let mut right_hour = HourlyAcc::default();
        right_hour.stats.hits = 3;
        right_hour.ip_set.insert(2);
        right
            .hourly
            .entry(Arc::clone(&date))
            .or_default()
            .insert(10, right_hour);

        // Top URLs / refs / agents / countries.
        let mut left_urls = TopNHitsBw::new(10);
        left_urls.add_hits_bw("/a", 1, 100);
        left.top_urls.insert(Arc::clone(&period), left_urls);

        let mut right_urls = TopNHitsBw::new(10);
        right_urls.add_hits_bw("/a", 2, 50);
        right.top_urls.insert(Arc::clone(&period), right_urls);

        let mut left_refs = TopNCount::new(10);
        left_refs.add("google.com", 1);
        left.top_refs.insert(Arc::clone(&period), left_refs);

        let mut right_refs = TopNCount::new(10);
        right_refs.add("google.com", 2);
        right.top_refs.insert(Arc::clone(&period), right_refs);

        let mut left_agents = TopNCount::new(10);
        left_agents.add("Firefox", 1);
        left.top_agents.insert(Arc::clone(&period), left_agents);

        let mut right_agents = TopNCount::new(10);
        right_agents.add("Firefox", 3);
        right.top_agents.insert(Arc::clone(&period), right_agents);

        let mut left_countries = AHashMap::new();
        left_countries.insert("US".to_string(), 1);
        left.top_countries
            .insert(Arc::clone(&period), left_countries);

        let mut right_countries = AHashMap::new();
        right_countries.insert("US".to_string(), 4);
        right
            .top_countries
            .insert(Arc::clone(&period), right_countries);

        // Top hosts.
        let cc = arc("US");
        let cn = arc("United States");
        let mut left_hosts = TopNHosts::new(10);
        left_hosts.add_hits_bw("1.2.3.4", 1, 100, &cc, &cn);
        left.top_hosts.insert(Arc::clone(&period), left_hosts);

        let mut right_hosts = TopNHosts::new(10);
        right_hosts.add_hits_bw("1.2.3.4", 2, 50, &cc, &cn);
        right.top_hosts.insert(Arc::clone(&period), right_hosts);

        // Status codes.
        let mut left_codes = AHashMap::new();
        left_codes.insert(200u16, 2u64);
        left.status_codes.insert(Arc::clone(&period), left_codes);

        let mut right_codes = AHashMap::new();
        right_codes.insert(200u16, 3u64);
        right.status_codes.insert(Arc::clone(&period), right_codes);

        // HLL sketches.
        let mut left_hll = HyperLogLog::new(12);
        left_hll.add_hash(123);
        left.hll_site_counts.insert(Arc::clone(&period), left_hll);

        let mut right_hll = HyperLogLog::new(12);
        right_hll.add_hash(456);
        right.hll_site_counts.insert(Arc::clone(&period), right_hll);

        if let Some(all_time) = left.hll_all_time.as_mut() {
            all_time.add_hash(777);
        }
        if let Some(all_time) = right.hll_all_time.as_mut() {
            all_time.add_hash(888);
        }

        left.merge_from(right, 12, 10);

        let hour = left.hourly.get("2026-05-10").unwrap().get(&10).unwrap();
        assert_eq!(hour.stats.hits, 5);
        assert_eq!(hour.ip_set.len(), 2);

        let urls = left.top_urls.get("2026-05").unwrap();
        let url_row = urls.get("/a").unwrap();
        assert_eq!(url_row.0, 3);
        assert_eq!(url_row.1, 150);

        assert_eq!(
            *left
                .top_refs
                .get("2026-05")
                .unwrap()
                .get("google.com")
                .unwrap(),
            3
        );
        assert_eq!(
            *left
                .top_agents
                .get("2026-05")
                .unwrap()
                .get("Firefox")
                .unwrap(),
            4
        );
        assert_eq!(
            *left
                .top_countries
                .get("2026-05")
                .unwrap()
                .get("US")
                .unwrap(),
            5
        );

        let host_hits = left
            .top_hosts
            .get("2026-05")
            .unwrap()
            .iter()
            .find(|(h, _, _, _, _)| *h == "1.2.3.4")
            .map(|(_, hits, bw, _, _)| (hits, bw))
            .unwrap();
        assert_eq!(host_hits.0, 3);
        assert_eq!(host_hits.1, 150);

        assert_eq!(
            left.status_codes.get("2026-05").unwrap().get(&200).copied(),
            Some(5)
        );

        // Not checking exact estimate because HLL is approximate, just merged/non-empty.
        assert!(left.hll_site_counts.get("2026-05").unwrap().estimate() > 0);
        assert!(left.hll_all_time.as_ref().unwrap().estimate() > 0);
    }
}
