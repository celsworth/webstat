// Flush: writes RunAccumulators to SQLite, handles month-boundary finalisation,
// and saves parse/visit state after each checkpoint.

use std::sync::Arc;
use std::time::Instant;

use ahash::AHashMap;

use super::*;
use crate::database::writer::FlushData;
use crate::run_accumulators::RunAccumulators;

impl Processor {
    pub(super) fn flush_run(
        &mut self,
        run_acc: &RunAccumulators,
        pending_parse_states: &[ParseStateUpdate],
        retired_parse_states: &[ParseStateUpdate],
    ) -> Result<()> {
        let (visit_state_updates, visit_state_prune_before_ts) = self.collect_visit_state_flush();

        if run_acc.is_empty()
            && pending_parse_states.is_empty()
            && retired_parse_states.is_empty()
            && visit_state_updates.is_empty()
        {
            return Ok(());
        }

        // Build geo lookup for every host being flushed.
        let mut host_geo: AHashMap<String, (Arc<str>, Arc<str>)> = AHashMap::new();
        for host in run_acc.hosts.keys() {
            if !host_geo.contains_key(host) {
                let geo_result = match crate::ip::Ip::parse(host) {
                    Some(ip) => self.geo.lookup(ip),
                    None => crate::geo::unknown(),
                };
                host_geo.insert(host.clone(), geo_result);
            }
        }

        let period = run_acc.current_month.as_str();

        let flush_start = Instant::now();
        crate::logging::log_debug_at(2, "Flushing run aggregates and parse state to database...");

        self.db.flush(FlushData {
            period,
            hourly: &run_acc.hourly,
            urls: &run_acc.urls,
            hosts: &run_acc.hosts,
            host_geo: &host_geo,
            refs: &run_acc.refs,
            agents: &run_acc.agents,
            daily_ips: &run_acc.daily_ips,
            countries: &run_acc.countries,
            status_codes: &run_acc.status_codes,
            method_counts: &run_acc.method_counts,
            protocol_counts: &run_acc.protocol_counts,
            parse_states: pending_parse_states,
            retired_parse_states,
            visit_states: &visit_state_updates,
            visit_state_prune_before_ts,
        })?;

        if self.visit_max_seen_ts > 0 {
            self.db.set_last_log_ts(self.visit_max_seen_ts)?;
        }

        let flush_elapsed = flush_start.elapsed().as_secs_f64();
        crate::logging::log_debug_at(
            2,
            &format!("Database flush completed in {:.1}s", flush_elapsed),
        );
        Ok(())
    }

    /// Flush accumulated data for a completed month, finalize it in the DB,
    /// then reset the accumulators for the new month.
    pub(super) fn finalize_and_advance_month(
        &mut self,
        run_acc: &mut RunAccumulators,
        pending_parse_states: &[ParseStateUpdate],
        retired_parse_states: &[ParseStateUpdate],
        new_month: String,
    ) -> Result<()> {
        pretrim_for_month_end(run_acc, self.top_n);
        self.flush_run(run_acc, pending_parse_states, retired_parse_states)?;
        let old_month = run_acc.current_month.clone();
        if !old_month.is_empty() {
            self.db.finalize_month(&old_month, self.top_n, self.enable_all_time_unique_hosts)?;
            if old_month.len() >= 4 && new_month.len() >= 4 && old_month[..4] != new_month[..4] {
                self.db.finalize_year(&old_month[..4])?;
            }
            self.db.set_meta("current_month", &new_month)?;
        }
        run_acc.clear_for_new_month(new_month);
        Ok(())
    }
}

fn pretrim_for_month_end(run_acc: &mut RunAccumulators, top_n: usize) {
    if top_n == 0 {
        return;
    }
    pretrim_hits_bw_map(&mut run_acc.urls, top_n);
    pretrim_hits_bw_map(&mut run_acc.hosts, top_n);
    pretrim_count_map(&mut run_acc.refs, top_n);
    pretrim_count_map(&mut run_acc.agents, top_n);
}

/// Keep the union of top_n by hits and top_n by bandwidth.
fn pretrim_hits_bw_map(map: &mut ahash::AHashMap<String, (u64, u64)>, top_n: usize) {
    if map.len() <= top_n {
        return;
    }
    let n = top_n.min(map.len());
    let mut entries: Vec<(String, u64, u64)> =
        map.iter().map(|(k, &(h, b))| (k.clone(), h, b)).collect();

    entries.sort_unstable_by_key(|a| std::cmp::Reverse(a.1));
    let mut keep: ahash::AHashSet<String> = ahash::AHashSet::with_capacity(n * 2);
    for (k, _, _) in &entries[..n] {
        keep.insert(k.clone());
    }

    // O(n) average: partition so entries[..n] hold the top-n by bandwidth.
    entries.select_nth_unstable_by_key(n - 1, |a| std::cmp::Reverse(a.2));
    for (k, _, _) in &entries[..n] {
        keep.insert(k.clone());
    }

    map.retain(|k, _| keep.contains(k.as_str()));
}

/// Keep top_n by hit count.
fn pretrim_count_map(map: &mut ahash::AHashMap<String, u64>, top_n: usize) {
    if map.len() <= top_n {
        return;
    }
    let mut entries: Vec<(String, u64)> = map.iter().map(|(k, &v)| (k.clone(), v)).collect();
    entries.sort_unstable_by_key(|a| std::cmp::Reverse(a.1));
    let keep: ahash::AHashSet<String> = entries.into_iter().take(top_n).map(|(k, _)| k).collect();
    map.retain(|k, _| keep.contains(k.as_str()));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hits_bw(pairs: &[(&str, u64, u64)]) -> ahash::AHashMap<String, (u64, u64)> {
        pairs.iter().map(|&(k, h, b)| (k.to_string(), (h, b))).collect()
    }

    fn make_counts(pairs: &[(&str, u64)]) -> ahash::AHashMap<String, u64> {
        pairs.iter().map(|&(k, v)| (k.to_string(), v)).collect()
    }

    fn sorted_keys(map: &ahash::AHashMap<String, (u64, u64)>) -> Vec<String> {
        let mut v: Vec<_> = map.keys().cloned().collect();
        v.sort();
        v
    }

    #[test]
    fn hits_bw_no_op_when_at_or_below_top_n() {
        let mut map = make_hits_bw(&[("a", 10, 1), ("b", 20, 2)]);
        pretrim_hits_bw_map(&mut map, 2);
        assert_eq!(map.len(), 2);
        pretrim_hits_bw_map(&mut map, 5);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn hits_bw_drops_entry_low_on_both() {
        // d is bottom by both hits and bw; all others are top-2 by one criterion
        // hits top-2: a(100), b(90); bw top-2: a(100), b(90); d(1,1) dropped
        let mut map = make_hits_bw(&[("a", 100, 100), ("b", 90, 90), ("c", 5, 5), ("d", 1, 1)]);
        pretrim_hits_bw_map(&mut map, 2);
        assert_eq!(sorted_keys(&map), ["a", "b"]);
    }

    #[test]
    fn hits_bw_high_bw_entry_kept_despite_low_hits() {
        // c has low hits but top bw → saved; d is bottom on both → dropped
        // hits top-2: a(100), b(90); bw top-2: c(200), b(20); union: a,b,c
        let mut map =
            make_hits_bw(&[("a", 100, 10), ("b", 90, 20), ("c", 5, 200), ("d", 3, 1)]);
        pretrim_hits_bw_map(&mut map, 2);
        assert_eq!(sorted_keys(&map), ["a", "b", "c"]);
    }

    #[test]
    fn hits_bw_high_hits_entry_kept_despite_low_bw() {
        // c has low bw but top hits → saved; d is bottom on both → dropped
        // hits top-2: c(200), b(20); bw top-2: a(100), b(90); union: a,b,c
        let mut map =
            make_hits_bw(&[("a", 10, 100), ("b", 20, 90), ("c", 200, 5), ("d", 1, 3)]);
        pretrim_hits_bw_map(&mut map, 2);
        assert_eq!(sorted_keys(&map), ["a", "b", "c"]);
    }

    #[test]
    fn hits_bw_keeps_union_of_top_n_by_hits_and_bw() {
        // hits ranking: b(50) > a(40) > d(30) > c(10)  → top-2: b, a
        // bw   ranking: c(200) > d(150) > a(100) > b(5) → top-2: c, d
        // union: a, b, c, d — all four kept; e(1,1) dropped
        let mut map = make_hits_bw(&[
            ("a", 40, 100),
            ("b", 50, 5),
            ("c", 10, 200),
            ("d", 30, 150),
            ("e", 1, 1),
        ]);
        pretrim_hits_bw_map(&mut map, 2);
        assert_eq!(sorted_keys(&map), ["a", "b", "c", "d"]);
    }

    #[test]
    fn hits_bw_exact_top_n_overlap() {
        // hits top-2: a(100), b(90); bw top-2: a(500), b(400) — same two entries
        let mut map = make_hits_bw(&[("a", 100, 500), ("b", 90, 400), ("c", 1, 1)]);
        pretrim_hits_bw_map(&mut map, 2);
        assert_eq!(sorted_keys(&map), ["a", "b"]);
    }

    #[test]
    fn count_map_no_op_when_at_or_below_top_n() {
        let mut map = make_counts(&[("a", 1), ("b", 2)]);
        pretrim_count_map(&mut map, 2);
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn count_map_keeps_top_n_by_count() {
        let mut map = make_counts(&[("a", 5), ("b", 50), ("c", 20), ("d", 1)]);
        pretrim_count_map(&mut map, 2);
        let mut keys: Vec<_> = map.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["b", "c"]);
    }
}
