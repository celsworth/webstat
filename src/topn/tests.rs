use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    // ── TopNCount ─────────────────────────────────────────────────────────────

    #[test]
    fn topn_count_below_capacity_accumulates_exact() {
        let mut t = TopNCount::new(3);
        t.add("a", 5);
        t.add("b", 3);
        t.add("a", 2);
        assert_eq!(*t.get("a").unwrap(), 7);
        assert_eq!(*t.get("b").unwrap(), 3);
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn topn_count_evicts_minimum_on_overflow() {
        let mut t = TopNCount::new(2);
        t.add("a", 10);
        t.add("b", 1);
        // map full; "c" should evict "b" (min=1), inserting at 1+1=2
        t.add("c", 1);
        assert!(t.get("b").is_none(), "b should be evicted");
        assert_eq!(*t.get("a").unwrap(), 10);
        assert_eq!(*t.get("c").unwrap(), 2);

        // One more overflow exercises the cached-min state after eviction.
        t.add("d", 1);
        assert_eq!(t.len(), 2);
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
        // Fill to capacity so the next add must evict.
        let mut t = TopNCount::new(2);
        t.add("a", 1);
        t.add("b", 1);
        // Raise "a" — cached_min (1) should be invalidated.
        t.add("a", 5);
        // Now add "c" — triggers eviction, must not panic when looking for min.
        t.add("c", 1);
        // "b" had the smallest count (1) so it should be evicted.
        assert!(t.get("b").is_none());
        assert!(t.get("a").is_some());
        assert!(t.get("c").is_some());
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

    // ── TopNHitsBw ────────────────────────────────────────────────────────────

    #[test]
    fn topn_hitsbw_add_accumulates_hits_and_bandwidth() {
        let mut t = TopNHitsBw::new(3);
        t.add("/foo", 1000);
        t.add("/foo", 500);
        t.add("/bar", 200);
        let entry = t.get("/foo").unwrap();
        assert_eq!(entry.0, 2); // hits
        assert_eq!(entry.1, 1500); // bandwidth
    }

    #[test]
    fn topn_hitsbw_evicts_lowest_hits_on_overflow() {
        let mut t = TopNHitsBw::new(2);
        t.add_hits_bw("/a", 10, 100);
        t.add_hits_bw("/b", 1, 50);
        // "/c" should evict "/b" (min_hits=1), inserting at 1+3=4
        t.add_hits_bw("/c", 3, 200);
        assert!(t.get("/b").is_none());
        assert_eq!(t.get("/a").unwrap().0, 10);
        assert_eq!(t.get("/c").unwrap().0, 4);
    }

    #[test]
    fn topn_hitsbw_cached_min_invalidated_on_existing_increment() {
        let mut t = TopNHitsBw::new(2);
        t.add_hits_bw("/a", 1, 0);
        t.add_hits_bw("/b", 1, 0);
        // Raise /a — invalidates cached min.
        t.add_hits_bw("/a", 9, 0);
        // /c should evict /b (hits=1), not panic.
        t.add_hits_bw("/c", 1, 0);
        assert!(t.get("/b").is_none());
    }

    #[test]
    fn topn_hitsbw_second_overflow_after_tied_min_keeps_correct_minimum() {
        let mut t = TopNHitsBw::new(2);
        t.add_hits_bw("/a", 1, 0);
        t.add_hits_bw("/b", 1, 0);
        t.add_hits_bw("/c", 1, 0);
        t.add_hits_bw("/d", 1, 0);

        let mut hits: Vec<u64> = t.iter().map(|(_, h, _)| h).collect();
        hits.sort_unstable();
        assert_eq!(hits, vec![2, 2]);
    }

    // ── TopNHosts ─────────────────────────────────────────────────────────────

    fn cc(s: &str) -> Arc<str> {
        Arc::from(s)
    }

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
}
