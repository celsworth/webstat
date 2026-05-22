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
                let geo_result = if let Ok(addr) = host.parse::<std::net::IpAddr>() {
                    self.geo.lookup(addr)
                } else {
                    crate::geo::unknown()
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
            proto_counts: &run_acc.proto_counts,
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
            self.db.finalize_month(&old_month, self.top_n)?;
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
    let mut by_hits: Vec<(String, u64)> = map.iter().map(|(k, &(h, _))| (k.clone(), h)).collect();
    by_hits.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    let mut by_bw: Vec<(String, u64)> = map.iter().map(|(k, &(_, b))| (k.clone(), b)).collect();
    by_bw.sort_unstable_by(|a, b| b.1.cmp(&a.1));

    let mut keep: ahash::AHashSet<String> = ahash::AHashSet::with_capacity(top_n * 2);
    for (k, _) in by_hits.into_iter().take(top_n) {
        keep.insert(k);
    }
    for (k, _) in by_bw.into_iter().take(top_n) {
        keep.insert(k);
    }
    map.retain(|k, _| keep.contains(k.as_str()));
}

/// Keep top_n by hit count.
fn pretrim_count_map(map: &mut ahash::AHashMap<String, u64>, top_n: usize) {
    if map.len() <= top_n {
        return;
    }
    let mut entries: Vec<(String, u64)> = map.iter().map(|(k, &v)| (k.clone(), v)).collect();
    entries.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    let keep: ahash::AHashSet<String> = entries.into_iter().take(top_n).map(|(k, _)| k).collect();
    map.retain(|k, _| keep.contains(k.as_str()));
}
