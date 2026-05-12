use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn get_count(t: &TopNCount, key: &str) -> Option<u64> {
        t.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    fn count_len(t: &TopNCount) -> usize {
        t.iter().count()
    }

    fn get_url(t: &TopNUrls, url: &str) -> Option<(u64, u64)> {
        t.iter()
            .find(|(k, _, _)| *k == url)
            .map(|(_, h, bw)| (h, bw))
    }

    fn get_url_bw(t: &TopNUrlsByBandwidth, url: &str) -> Option<(u64, u64)> {
        t.iter()
            .find(|(k, _, _)| *k == url)
            .map(|(_, h, bw)| (h, bw))
    }

    fn get_host(t: &TopNHosts, host: &str) -> Option<(u64, u64)> {
        t.iter()
            .find(|(k, _, _, _, _)| *k == host)
            .map(|(_, h, bw, _, _)| (h, bw))
    }

    fn get_host_bw(t: &TopNHostsByBandwidth, host: &str) -> Option<(u64, u64)> {
        t.iter()
            .find(|(k, _, _, _, _)| *k == host)
            .map(|(_, h, bw, _, _)| (h, bw))
    }

    fn cc(s: &str) -> Arc<str> {
        Arc::from(s)
    }

    // ── TopNCount ─────────────────────────────────────────────────────────────

    #[test]
    fn topn_count_below_capacity_accumulates_exact() {
        let mut t = TopNCount::new(3);
        t.add("a", 5);
        t.add("b", 3);
        t.add("a", 2);
        assert_eq!(get_count(&t, "a").unwrap(), 7);
        assert_eq!(get_count(&t, "b").unwrap(), 3);
        assert_eq!(count_len(&t), 2);
    }

    #[test]
    fn topn_count_evicts_minimum_on_overflow() {
        let mut t = TopNCount::new(2);
        t.add("a", 10);
        t.add("b", 1);
        // map full; "c" should evict "b" (min=1), inserting at 1+1=2
        t.add("c", 1);
        assert!(get_count(&t, "b").is_none(), "b should be evicted");
        assert_eq!(get_count(&t, "a").unwrap(), 10);
        assert_eq!(get_count(&t, "c").unwrap(), 2);

        // One more overflow exercises the cached-min state after eviction.
        t.add("d", 1);
        assert_eq!(count_len(&t), 2);
    }

    #[test]
    fn topn_count_second_overflow_after_tied_min_keeps_correct_minimum() {
        let mut t = TopNCount::new(2);
        t.add("a", 1);
        t.add("b", 1);
        t.add("c", 1);
        t.add("d", 1);

        let mut values: Vec<u64> = t.iter().map(|(_, v)| v).collect();
        values.sort_unstable();
        assert_eq!(values, vec![2, 2]);
    }

    #[test]
    fn topn_count_cached_min_invalidated_on_existing_key_increment() {
        let mut t = TopNCount::new(2);
        t.add("a", 1);
        t.add("b", 1);
        // Raise "a" — cached_min (1) should be invalidated.
        t.add("a", 5);
        // Now add "c" — triggers eviction, must not panic when looking for min.
        t.add("c", 1);
        // "b" had the smallest count (1) so it should be evicted.
        assert!(get_count(&t, "b").is_none());
        assert!(get_count(&t, "a").is_some());
        assert!(get_count(&t, "c").is_some());
    }

    #[test]
    fn topn_count_iter_yields_all_entries() {
        let mut t = TopNCount::new(5);
        t.add("x", 3);
        t.add("y", 7);
        let mut pairs: Vec<_> = t.iter().map(|(k, v)| (k.to_string(), v)).collect();
        pairs.sort();
        assert_eq!(pairs, vec![("x".to_string(), 3), ("y".to_string(), 7)]);
    }

    #[test]
    fn topn_count_zero_capacity_ignores_all() {
        let mut t = TopNCount::new(0);
        t.add("a", 100);
        assert_eq!(count_len(&t), 0);
    }

    #[test]
    fn topn_count_merge_from_trims_to_capacity() {
        let mut a = TopNCount::new(2);
        a.add("a", 10);
        a.add("b", 5);

        let mut b = TopNCount::new(2);
        b.add("c", 1);
        b.add("a", 3);

        a.merge_from(b);
        // After merge: a=13, b=5, c=1 → trim to 2 → keep a and b
        assert_eq!(count_len(&a), 2);
        assert_eq!(get_count(&a, "a").unwrap(), 13);
        assert_eq!(get_count(&a, "b").unwrap(), 5);
        assert!(get_count(&a, "c").is_none());
    }

    // ── TopNUrls ────────────────────────────────────────────────────────────

    #[test]
    fn topn_urls_add_accumulates_hits_and_bandwidth() {
        let mut t = TopNUrls::new(3);
        t.add("/foo", 1000);
        t.add("/foo", 500);
        t.add("/bar", 200);
        let entry = get_url(&t, "/foo").unwrap();
        assert_eq!(entry.0, 2); // hits
        assert_eq!(entry.1, 1500); // bandwidth
    }

    #[test]
    fn topn_urls_evicts_lowest_hits_on_overflow() {
        let mut t = TopNUrls::new(2);
        t.add_hits_bw("/a", 10, 100);
        t.add_hits_bw("/b", 1, 50);
        // "/c" should evict "/b" (min_hits=1), inserting at 1+3=4
        t.add_hits_bw("/c", 3, 200);
        assert!(get_url(&t, "/b").is_none());
        assert_eq!(get_url(&t, "/a").unwrap().0, 10);
        assert_eq!(get_url(&t, "/c").unwrap().0, 4);
    }

    #[test]
    fn topn_urls_cached_min_invalidated_on_existing_increment() {
        let mut t = TopNUrls::new(2);
        t.add_hits_bw("/a", 1, 0);
        t.add_hits_bw("/b", 1, 0);
        // Raise /a — invalidates cached min.
        t.add_hits_bw("/a", 9, 0);
        // /c should evict /b (hits=1), not panic.
        t.add_hits_bw("/c", 1, 0);
        assert!(get_url(&t, "/b").is_none());
    }

    #[test]
    fn topn_urls_second_overflow_after_tied_min_keeps_correct_minimum() {
        let mut t = TopNUrls::new(2);
        t.add_hits_bw("/a", 1, 0);
        t.add_hits_bw("/b", 1, 0);
        t.add_hits_bw("/c", 1, 0);
        t.add_hits_bw("/d", 1, 0);

        let mut hits: Vec<u64> = t.iter().map(|(_, h, _)| h).collect();
        hits.sort_unstable();
        assert_eq!(hits, vec![2, 2]);
    }

    #[test]
    fn topn_urls_merge_from_accumulates_bandwidth() {
        let mut a = TopNUrls::new(5);
        a.add_hits_bw("/x", 2, 1000);

        let mut b = TopNUrls::new(5);
        b.add_hits_bw("/x", 3, 500);
        b.add_hits_bw("/y", 1, 200);

        a.merge_from(b);
        let x = get_url(&a, "/x").unwrap();
        assert_eq!(x.0, 5);    // hits merged
        assert_eq!(x.1, 1500); // bandwidth merged
        assert!(get_url(&a, "/y").is_some());
    }

    #[test]
    fn topn_urls_merge_from_trims_to_capacity() {
        let mut a = TopNUrls::new(2);
        a.add_hits_bw("/a", 10, 0);
        a.add_hits_bw("/b", 5, 0);

        let mut b = TopNUrls::new(2);
        b.add_hits_bw("/c", 1, 0);

        a.merge_from(b);
        assert_eq!(a.iter().count(), 2);
        assert!(get_url(&a, "/c").is_none());
    }

    // ── TopNUrlsByBandwidth ──────────────────────────────────────────────────

    #[test]
    fn topn_urls_bw_add_accumulates_hits_and_bandwidth() {
        let mut t = TopNUrlsByBandwidth::new(3);
        t.add("/foo", 1000);
        t.add("/foo", 500);
        t.add("/bar", 200);
        let entry = get_url_bw(&t, "/foo").unwrap();
        assert_eq!(entry.0, 2);    // hits
        assert_eq!(entry.1, 1500); // bandwidth
    }

    #[test]
    fn topn_urls_bw_evicts_lowest_bandwidth_on_overflow() {
        let mut t = TopNUrlsByBandwidth::new(2);
        t.add_hits_bw("/a", 1, 1000);
        t.add_hits_bw("/b", 1, 10);
        // "/c" should evict "/b" (min_bw=10), inserting bw at 10+500=510
        t.add_hits_bw("/c", 1, 500);
        assert!(get_url_bw(&t, "/b").is_none(), "/b should be evicted");
        assert_eq!(get_url_bw(&t, "/a").unwrap().1, 1000);
        assert_eq!(get_url_bw(&t, "/c").unwrap().1, 510);
    }

    #[test]
    fn topn_urls_bw_not_evicted_by_high_hits_low_bandwidth() {
        // A URL with many hits but tiny bandwidth should lose to one with big bandwidth.
        let mut t = TopNUrlsByBandwidth::new(2);
        t.add_hits_bw("/big-bw", 1, 9999);
        t.add_hits_bw("/high-hits", 100, 1);
        // overflow: evict by bw, so "/high-hits" (bw=1) evicts
        t.add_hits_bw("/new", 1, 500);
        assert!(get_url_bw(&t, "/high-hits").is_none());
        assert!(get_url_bw(&t, "/big-bw").is_some());
    }

    #[test]
    fn topn_urls_bw_cached_min_invalidated_on_existing_increment() {
        let mut t = TopNUrlsByBandwidth::new(2);
        t.add_hits_bw("/a", 1, 1);
        t.add_hits_bw("/b", 1, 1);
        // Raise /a bandwidth — invalidates cached min.
        t.add_hits_bw("/a", 1, 9999);
        // /c should evict /b (bw=1), not panic.
        t.add_hits_bw("/c", 1, 1);
        assert!(get_url_bw(&t, "/b").is_none());
        assert!(get_url_bw(&t, "/a").is_some());
    }

    #[test]
    fn topn_urls_bw_second_overflow_after_tied_min() {
        let mut t = TopNUrlsByBandwidth::new(2);
        t.add_hits_bw("/a", 1, 1);
        t.add_hits_bw("/b", 1, 1);
        t.add_hits_bw("/c", 1, 1);
        t.add_hits_bw("/d", 1, 1);

        let mut bws: Vec<u64> = t.iter().map(|(_, _, bw)| bw).collect();
        bws.sort_unstable();
        assert_eq!(bws, vec![2, 2]);
    }

    #[test]
    fn topn_urls_bw_zero_capacity_ignores_all() {
        let mut t = TopNUrlsByBandwidth::new(0);
        t.add("/anything", 9999);
        assert_eq!(t.iter().count(), 0);
    }

    #[test]
    fn topn_urls_bw_merge_from_accumulates_and_trims() {
        let mut a = TopNUrlsByBandwidth::new(2);
        a.add_hits_bw("/a", 1, 1000);
        a.add_hits_bw("/b", 1, 500);

        let mut b = TopNUrlsByBandwidth::new(2);
        b.add_hits_bw("/a", 1, 200);
        b.add_hits_bw("/c", 1, 1);

        a.merge_from(b);
        // After merge: /a=1200, /b=500, /c=1 → trim to 2 → keep /a and /b
        assert_eq!(a.iter().count(), 2);
        assert_eq!(get_url_bw(&a, "/a").unwrap().1, 1200);
        assert!(get_url_bw(&a, "/c").is_none());
    }

    // ── TopNHosts ─────────────────────────────────────────────────────────────

    #[test]
    fn topn_hosts_add_accumulates_and_upgrades_country() {
        let mut t = TopNHosts::new(5);
        let unknown = cc("--");
        let de = cc("DE");
        let germany = cc("Germany");
        t.add("1.2.3.4", 100, &unknown, &cc("Unknown"));
        t.add("1.2.3.4", 200, &de, &germany);
        let mut iter = t.iter();
        let (_, hits, bw, c, _) = iter.next().unwrap();
        assert_eq!(hits, 2);
        assert_eq!(bw, 300);
        assert_eq!(c.as_ref(), "DE");
    }

    #[test]
    fn topn_hosts_evicts_minimum_hits_on_overflow() {
        let mut t = TopNHosts::new(2);
        let uk = cc("UK");
        let us = cc("US");
        t.add_hits_bw("host_a", 10, 0, &uk, &cc("UK"));
        t.add_hits_bw("host_b", 1, 0, &us, &cc("US"));
        t.add_hits_bw("host_c", 2, 0, &uk, &cc("UK"));
        // host_b (hits=1) should be evicted.
        assert!(t.iter().all(|(h, _, _, _, _)| h != "host_b"));
    }

    #[test]
    fn topn_hosts_merge_from_trims_and_invalidates_cache() {
        let cc_uk = cc("UK");
        let cc_us = cc("US");
        let mut a = TopNHosts::new(2);
        a.add_hits_bw("x", 5, 0, &cc_uk, &cc("UK"));
        a.add_hits_bw("y", 3, 0, &cc_us, &cc("US"));

        let mut b = TopNHosts::new(2);
        b.add_hits_bw("z", 1, 0, &cc_uk, &cc("UK"));

        a.merge_from(b);
        // After merge+trim to capacity=2, "z" (hits=1) should be dropped.
        assert_eq!(a.iter().count(), 2);
        assert!(a.iter().all(|(h, _, _, _, _)| h != "z"));
        // Add a new entry to confirm no panic (cache must be invalidated).
        a.add_hits_bw("w", 1, 0, &cc_uk, &cc("UK"));
    }

    #[test]
    fn topn_hosts_second_overflow_after_tied_min_keeps_correct_minimum() {
        let mut t = TopNHosts::new(2);
        let uk = cc("UK");
        t.add_hits_bw("a", 1, 0, &uk, &cc("UK"));
        t.add_hits_bw("b", 1, 0, &uk, &cc("UK"));
        t.add_hits_bw("c", 1, 0, &uk, &cc("UK"));
        t.add_hits_bw("d", 1, 0, &uk, &cc("UK"));

        let mut hits: Vec<u64> = t.iter().map(|(_, h, _, _, _)| h).collect();
        hits.sort_unstable();
        assert_eq!(hits, vec![2, 2]);
    }

    // ── TopNHostsByBandwidth ──────────────────────────────────────────────────

    #[test]
    fn topn_hosts_bw_add_accumulates_hits_and_bandwidth() {
        let mut t = TopNHostsByBandwidth::new(5);
        let us = cc("US");
        t.add("1.1.1.1", 1000, &us, &cc("United States"));
        t.add("1.1.1.1", 500, &us, &cc("United States"));
        let entry = get_host_bw(&t, "1.1.1.1").unwrap();
        assert_eq!(entry.0, 2);    // hits
        assert_eq!(entry.1, 1500); // bandwidth
    }

    #[test]
    fn topn_hosts_bw_evicts_lowest_bandwidth_on_overflow() {
        let mut t = TopNHostsByBandwidth::new(2);
        let uk = cc("UK");
        t.add_hits_bw("a", 1, 1000, &uk, &cc("UK"));
        t.add_hits_bw("b", 1, 10, &uk, &cc("UK"));
        // "c" should evict "b" (min_bw=10), new bw = 10+500=510
        t.add_hits_bw("c", 1, 500, &uk, &cc("UK"));
        assert!(get_host_bw(&t, "b").is_none(), "b should be evicted");
        assert_eq!(get_host_bw(&t, "a").unwrap().1, 1000);
        assert_eq!(get_host_bw(&t, "c").unwrap().1, 510);
    }

    #[test]
    fn topn_hosts_bw_not_evicted_by_high_hits_low_bandwidth() {
        let mut t = TopNHostsByBandwidth::new(2);
        let uk = cc("UK");
        t.add_hits_bw("big-bw", 1, 9999, &uk, &cc("UK"));
        t.add_hits_bw("high-hits", 100, 1, &uk, &cc("UK"));
        t.add_hits_bw("new", 1, 500, &uk, &cc("UK"));
        assert!(get_host_bw(&t, "high-hits").is_none());
        assert!(get_host_bw(&t, "big-bw").is_some());
    }

    #[test]
    fn topn_hosts_bw_upgrades_country_on_existing_host() {
        let mut t = TopNHostsByBandwidth::new(5);
        t.add("10.0.0.1", 100, &cc("--"), &cc("Unknown"));
        t.add("10.0.0.1", 200, &cc("DE"), &cc("Germany"));
        let (_, hits, bw, cc_val, _) = t.iter().find(|(h, _, _, _, _)| *h == "10.0.0.1").unwrap();
        assert_eq!(hits, 2);
        assert_eq!(bw, 300);
        assert_eq!(cc_val.as_ref(), "DE");
    }

    #[test]
    fn topn_hosts_bw_cached_min_invalidated_on_existing_increment() {
        let mut t = TopNHostsByBandwidth::new(2);
        let uk = cc("UK");
        t.add_hits_bw("a", 1, 1, &uk, &cc("UK"));
        t.add_hits_bw("b", 1, 1, &uk, &cc("UK"));
        // Raise "a" bandwidth — invalidates cached min.
        t.add_hits_bw("a", 1, 9999, &uk, &cc("UK"));
        // "c" should evict "b" (bw=1), not panic.
        t.add_hits_bw("c", 1, 1, &uk, &cc("UK"));
        assert!(get_host_bw(&t, "b").is_none());
        assert!(get_host_bw(&t, "a").is_some());
    }

    #[test]
    fn topn_hosts_bw_second_overflow_after_tied_min() {
        let mut t = TopNHostsByBandwidth::new(2);
        let uk = cc("UK");
        t.add_hits_bw("a", 1, 1, &uk, &cc("UK"));
        t.add_hits_bw("b", 1, 1, &uk, &cc("UK"));
        t.add_hits_bw("c", 1, 1, &uk, &cc("UK"));
        t.add_hits_bw("d", 1, 1, &uk, &cc("UK"));

        let mut bws: Vec<u64> = t.iter().map(|(_, _, bw, _, _)| bw).collect();
        bws.sort_unstable();
        assert_eq!(bws, vec![2, 2]);
    }

    #[test]
    fn topn_hosts_bw_zero_capacity_ignores_all() {
        let mut t = TopNHostsByBandwidth::new(0);
        t.add("any", 9999, &cc("US"), &cc("United States"));
        assert_eq!(t.iter().count(), 0);
    }

    #[test]
    fn topn_hosts_bw_merge_from_accumulates_and_trims() {
        let uk = cc("UK");
        let us = cc("US");
        let mut a = TopNHostsByBandwidth::new(2);
        a.add_hits_bw("x", 1, 1000, &uk, &cc("UK"));
        a.add_hits_bw("y", 1, 500, &us, &cc("US"));

        let mut b = TopNHostsByBandwidth::new(2);
        b.add_hits_bw("x", 1, 200, &uk, &cc("UK"));
        b.add_hits_bw("z", 1, 1, &us, &cc("US"));

        a.merge_from(b);
        // After merge: x=1200, y=500, z=1 → trim to 2 → keep x and y
        assert_eq!(a.iter().count(), 2);
        assert_eq!(get_host_bw(&a, "x").unwrap().1, 1200);
        assert!(get_host_bw(&a, "z").is_none());
    }
}
