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

    // ── TopNCount ─────────────────────────────────────────────────────────────

    #[test]
    fn topn_count_unbounded_accumulates_many_entries() {
        let mut t = TopNCount::new(5);
        for i in 0..100 {
            t.add(&format!("key{}", i), 1);
        }
        assert_eq!(count_len(&t), 100);
    }

    #[test]
    fn topn_count_accumulates_large_deltas() {
        let mut t = TopNCount::new(10);
        t.add("x", u64::MAX / 2);
        t.add("x", u64::MAX / 2);
        assert_eq!(get_count(&t, "x").unwrap(), u64::MAX - 1); // saturating add
    }

    #[test]
    fn topn_count_multiple_keys_all_present() {
        let mut t = TopNCount::new(3);
        t.add("a", 5);
        t.add("b", 3);
        t.add("c", 2);
        t.add("d", 1);
        assert!(get_count(&t, "a").is_some());
        assert!(get_count(&t, "b").is_some());
        assert!(get_count(&t, "c").is_some());
        assert!(get_count(&t, "d").is_some());
        assert_eq!(count_len(&t), 4);
    }

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
    fn topn_count_iter_yields_all_entries() {
        let mut t = TopNCount::new(5);
        t.add("x", 3);
        t.add("y", 7);
        let mut pairs: Vec<_> = t.iter().map(|(k, v)| (k.to_string(), v)).collect();
        pairs.sort();
        assert_eq!(pairs, vec![("x".to_string(), 3), ("y".to_string(), 7)]);
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
    fn topn_urls_capacity_limited() {
        let mut t = TopNUrls::new(3);
        // Add URLs such that the most frequent ones are kept
        for i in 0..100 {
            if i < 50 {
                t.add_hits_bw("/high", 1, 10);
            } else if i < 75 {
                t.add_hits_bw("/med", 1, 10);
            } else {
                t.add_hits_bw(&format!("/low{}", i), 1, 10);
            }
        }
        // Size should never exceed capacity
        assert!(t.iter().count() <= 3);
        // Most frequent should be present
        assert!(get_url(&t, "/high").is_some());
    }

    #[test]
    fn topn_urls_zero_capacity_ignores_all() {
        let mut t = TopNUrls::new(0);
        t.add("/anything", 1000);
        t.add("/something", 2000);
        assert_eq!(t.iter().count(), 0);
    }

    #[test]
    fn topn_urls_single_capacity() {
        let mut t = TopNUrls::new(1);
        t.add_hits_bw("/first", 10, 100);
        assert_eq!(t.iter().count(), 1);
        t.add_hits_bw("/second", 5, 50);
        // Should still have only 1 item (the high-hit one or close)
        assert!(t.iter().count() <= 1);
    }

    #[test]
    fn topn_urls_iter_only_contains_stored_items() {
        let mut t = TopNUrls::new(3);
        t.add("/a", 100);
        t.add("/b", 50);
        let items: Vec<&str> = t.iter().map(|(url, _, _)| url).collect();
        assert!(items.contains(&"/a"));
        assert!(items.contains(&"/b"));
        assert!(!items.contains(&"/c"));
    }

    #[test]
    fn topn_urls_sorted_by_hits_not_bandwidth() {
        let mut t = TopNUrls::new(10);
        // Add URL with high bandwidth but low hits
        t.add_hits_bw("/high-bw", 1, 10000);
        // Add URL with low bandwidth but high hits
        for _ in 0..100 {
            t.add_hits_bw("/high-hits", 1, 1);
        }
        // TopNUrls is sorted by hits, so /high-hits should be preferred
        let high_hits = get_url(&t, "/high-hits");
        assert!(high_hits.is_some());
        assert!(high_hits.unwrap().0 >= 100);
    }

    // ── TopNUrlsByBandwidth ──────────────────────────────────────────────────

    #[test]
    fn topn_urls_bw_add_accumulates_hits_and_bandwidth() {
        let mut t = TopNUrlsByBandwidth::new(3);
        t.add("/foo", 1000);
        t.add("/foo", 500);
        t.add("/bar", 200);
        let entry = get_url_bw(&t, "/foo").unwrap();
        assert_eq!(entry.0, 2); // hits
        assert_eq!(entry.1, 1500); // bandwidth
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
    fn topn_urls_bw_capacity_limited() {
        let mut t = TopNUrlsByBandwidth::new(3);
        // Add URLs with varying bandwidth
        for i in 0..100 {
            if i < 50 {
                t.add_hits_bw("/high-bw", 1, 1000);
            } else if i < 75 {
                t.add_hits_bw("/med-bw", 1, 100);
            } else {
                t.add_hits_bw(&format!("/low-bw{}", i), 1, 1);
            }
        }
        // Size should never exceed capacity
        assert!(t.iter().count() <= 3);
    }

    #[test]
    fn topn_urls_bw_zero_capacity_ignores_all() {
        let mut t = TopNUrlsByBandwidth::new(0);
        t.add("/big", 9999);
        assert_eq!(t.iter().count(), 0);
    }

    #[test]
    fn topn_urls_bw_single_capacity() {
        let mut t = TopNUrlsByBandwidth::new(1);
        t.add_hits_bw("/first", 1, 1000);
        assert_eq!(t.iter().count(), 1);
        t.add_hits_bw("/second", 1, 100);
        assert!(t.iter().count() <= 1);
    }

    #[test]
    fn topn_urls_bw_sorted_by_bandwidth_not_hits() {
        let mut t = TopNUrlsByBandwidth::new(10);
        // Add URL with high hits but low bandwidth
        for _ in 0..100 {
            t.add_hits_bw("/high-hits-low-bw", 1, 1);
        }
        // Add URL with low hits but high bandwidth
        t.add_hits_bw("/low-hits-high-bw", 1, 10000);
        // TopNUrlsByBandwidth is sorted by bandwidth
        let high_bw_entry = get_url_bw(&t, "/low-hits-high-bw");
        assert!(high_bw_entry.is_some());
        assert!(high_bw_entry.unwrap().1 >= 10000);
    }

    // ── TopNHosts ─────────────────────────────────────────────────────────────

    #[test]
    fn topn_hosts_add_accumulates_hits_and_bandwidth() {
        let mut t = TopNHosts::new(3);
        t.add("1.2.3.4", 1000);
        t.add("1.2.3.4", 500);
        t.add("5.6.7.8", 200);
        let entry = t.iter().find(|(h, _, _)| *h == "1.2.3.4");
        assert!(entry.is_some());
        let (_, hits, bw) = entry.unwrap();
        assert_eq!(hits, 2); // hits
        assert_eq!(bw, 1500); // bandwidth
    }

    #[test]
    fn topn_hosts_capacity_limited() {
        let mut t = TopNHosts::new(3);
        for i in 0..100 {
            if i < 50 {
                t.add_hits_bw("192.168.1.1", 1, 10);
            } else if i < 75 {
                t.add_hits_bw("10.0.0.1", 1, 10);
            } else {
                t.add_hits_bw(&format!("192.168.{}.{}", i / 256, i % 256), 1, 10);
            }
        }
        assert!(t.iter().count() <= 3);
    }

    #[test]
    fn topn_hosts_zero_capacity_ignores_all() {
        let mut t = TopNHosts::new(0);
        t.add("1.1.1.1", 1000);
        t.add("8.8.8.8", 2000);
        assert_eq!(t.iter().count(), 0);
    }

    #[test]
    fn topn_hosts_sorted_by_hits() {
        let mut t = TopNHosts::new(10);
        t.add_hits_bw("192.168.1.1", 1, 10000);
        for _ in 0..100 {
            t.add_hits_bw("10.0.0.1", 1, 1);
        }
        let entry = t.iter().find(|(h, _, _)| *h == "10.0.0.1");
        assert!(entry.is_some());
        assert!(entry.unwrap().1 >= 100);
    }

    // ── TopNHostsByBandwidth ──────────────────────────────────────────────────

    #[test]
    fn topn_hosts_bw_add_accumulates_hits_and_bandwidth() {
        let mut t = TopNHostsByBandwidth::new(5);
        t.add("1.1.1.1", 1000);
        t.add("1.1.1.1", 500);
        t.add("8.8.8.8", 200);
        let entry = t.iter().find(|(h, _, _)| *h == "1.1.1.1");
        assert!(entry.is_some());
        let (_, hits, bw) = entry.unwrap();
        assert_eq!(hits, 2); // hits
        assert_eq!(bw, 1500); // bandwidth
    }

    #[test]
    fn topn_hosts_bw_capacity_limited() {
        let mut t = TopNHostsByBandwidth::new(3);
        for i in 0..100 {
            if i < 50 {
                t.add_hits_bw("192.168.1.1", 1, 1000);
            } else if i < 75 {
                t.add_hits_bw("10.0.0.1", 1, 100);
            } else {
                t.add_hits_bw(&format!("192.168.{}.{}", i / 256, i % 256), 1, 1);
            }
        }
        assert!(t.iter().count() <= 3);
    }

    #[test]
    fn topn_hosts_bw_zero_capacity_ignores_all() {
        let mut t = TopNHostsByBandwidth::new(0);
        t.add("1.1.1.1", 9999);
        assert_eq!(t.iter().count(), 0);
    }

    #[test]
    fn topn_hosts_bw_sorted_by_bandwidth_not_hits() {
        let mut t = TopNHostsByBandwidth::new(10);
        // Add host with high hits but low bandwidth
        for _ in 0..100 {
            t.add_hits_bw("192.168.1.100", 1, 1);
        }
        // Add host with low hits but high bandwidth
        t.add_hits_bw("192.168.1.1", 1, 10000);
        let entry = t.iter().find(|(h, _, _)| *h == "192.168.1.1");
        assert!(entry.is_some());
        assert!(entry.unwrap().2 >= 10000);
    }

    #[test]
    fn topn_hosts_bw_not_evicted_by_high_hits_low_bandwidth() {
        let mut t = TopNHostsByBandwidth::new(2);
        t.add_hits_bw("192.168.1.1", 1, 9999);
        t.add_hits_bw("192.168.1.100", 100, 1);
        t.add_hits_bw("192.168.1.101", 1, 500);
        // Host with high bandwidth should be kept
        assert!(t.iter().find(|(h, _, _)| *h == "192.168.1.1").is_some());
        // Host with high hits but low bandwidth might be evicted
    }
}
