use std::sync::Arc;

use ahash::AHashMap;

use crate::hll::HyperLogLog;
use crate::method_proto::{MethodCountsMap, ProtoCountsMap, METHOD_COUNT, PROTO_COUNT};
use crate::topn::{
    CountryCountMap, HostBwMap, HostHitsMap, HourlyMap, PeriodCountMap, PeriodHitsMap, StatusMap,
    TopNCount, TopNHitsBw, TopNHosts, TopNHostsByBandwidth,
};

pub(crate) struct RunAccumulators {
    pub(crate) hourly: HourlyMap,
    pub(crate) top_urls: PeriodHitsMap,
    pub(crate) top_hosts: HostHitsMap,
    pub(crate) top_hosts_bw: HostBwMap,
    pub(crate) top_refs: PeriodCountMap,
    pub(crate) top_agents: PeriodCountMap,
    pub(crate) top_countries: CountryCountMap,
    pub(crate) status_codes: StatusMap,
    pub(crate) hll_site_counts: AHashMap<Arc<str>, HyperLogLog>,
    pub(crate) hll_all_time: Option<HyperLogLog>,
    pub(crate) method_counts: MethodCountsMap,
    pub(crate) proto_counts: ProtoCountsMap,
}

impl RunAccumulators {
    pub(crate) fn new(
        base_capacity: usize,
        hll_precision: u8,
        enable_top_urls: bool,
        enable_top_hosts: bool,
        enable_top_refs: bool,
    ) -> Self {
        Self {
            hourly: AHashMap::with_capacity(base_capacity),
            top_urls: AHashMap::with_capacity(if enable_top_urls { base_capacity } else { 0 }),
            top_hosts: AHashMap::with_capacity(if enable_top_hosts { base_capacity } else { 0 }),
            top_hosts_bw: AHashMap::with_capacity(if enable_top_hosts { base_capacity } else { 0 }),
            top_refs: AHashMap::with_capacity(if enable_top_refs { base_capacity } else { 0 }),
            top_agents: AHashMap::with_capacity(base_capacity),
            top_countries: AHashMap::with_capacity(base_capacity),
            status_codes: AHashMap::with_capacity(base_capacity),
            hll_site_counts: AHashMap::with_capacity(base_capacity),
            hll_all_time: Some(HyperLogLog::new(hll_precision)),
            method_counts: AHashMap::with_capacity(base_capacity),
            proto_counts: AHashMap::with_capacity(base_capacity),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.hourly.is_empty()
            && self.top_urls.is_empty()
            && self.top_hosts.is_empty()
            && self.top_hosts_bw.is_empty()
            && self.top_refs.is_empty()
            && self.top_agents.is_empty()
            && self.top_countries.is_empty()
            && self.status_codes.is_empty()
            && self.hll_site_counts.is_empty()
            && self.method_counts.is_empty()
            && self.proto_counts.is_empty()
    }

    pub(crate) fn merge_from(&mut self, other: RunAccumulators, hll_precision: u8, topn_k: usize) {
        for (date, hours) in other.hourly {
            let dst_hours = self.hourly.entry(date).or_default();
            for (hour, acc) in hours {
                let dst = dst_hours.entry(hour).or_default();
                dst.stats.hits += acc.stats.hits;
                dst.stats.visits += acc.stats.visits;
                dst.stats.bandwidth += acc.stats.bandwidth;
                dst.stats.files += acc.stats.files;
                dst.stats.pages += acc.stats.pages;
                dst.stats.status_2xx += acc.stats.status_2xx;
                dst.stats.status_3xx += acc.stats.status_3xx;
                dst.stats.status_4xx += acc.stats.status_4xx;
                dst.stats.status_5xx += acc.stats.status_5xx;
                dst.ip_set.extend(acc.ip_set);
            }
        }

        for (period, urls) in other.top_urls {
            let dst = self
                .top_urls
                .entry(period)
                .or_insert_with(|| TopNHitsBw::new(topn_k));
            for (url, hits, bw) in urls.iter() {
                dst.add_hits_bw(url, hits, bw);
            }
        }

        for (period, hosts) in other.top_hosts {
            let dst = self
                .top_hosts
                .entry(period)
                .or_insert_with(|| TopNHosts::new(topn_k));
            dst.merge_from(hosts);
        }

        for (period, hosts) in other.top_hosts_bw {
            let dst = self
                .top_hosts_bw
                .entry(period)
                .or_insert_with(|| TopNHostsByBandwidth::new(topn_k));
            dst.merge_from(hosts);
        }

        for (period, refs) in other.top_refs {
            let dst = self
                .top_refs
                .entry(period)
                .or_insert_with(|| TopNCount::new(topn_k));
            for (referrer, hits) in refs.iter() {
                dst.add(referrer, hits);
            }
        }

        for (period, agents) in other.top_agents {
            let dst = self
                .top_agents
                .entry(period)
                .or_insert_with(|| TopNCount::new(topn_k));
            for (agent, hits) in agents.iter() {
                dst.add(agent, hits);
            }
        }

        for (period, countries) in other.top_countries {
            let dst = self.top_countries.entry(period).or_default();
            for (country, hits) in countries {
                *dst.entry(country).or_insert(0) += hits;
            }
        }

        for (period, codes) in other.status_codes {
            let dst = self.status_codes.entry(period).or_default();
            for (status, hits) in codes {
                *dst.entry(status).or_insert(0) += hits;
            }
        }

        for (scope, incoming) in other.hll_site_counts {
            self.hll_site_counts
                .entry(scope)
                .or_insert_with(|| HyperLogLog::new(hll_precision))
                .merge(&incoming);
        }

        if let Some(incoming) = other.hll_all_time {
            self.hll_all_time
                .get_or_insert_with(|| HyperLogLog::new(hll_precision))
                .merge(&incoming);
        }

        for (period, counts) in other.method_counts {
            let dst = self.method_counts.entry(period).or_insert([0u64; METHOD_COUNT]);
            for i in 0..METHOD_COUNT {
                dst[i] += counts[i];
            }
        }

        for (period, counts) in other.proto_counts {
            let dst = self.proto_counts.entry(period).or_insert([0u64; PROTO_COUNT]);
            for i in 0..PROTO_COUNT {
                dst[i] += counts[i];
            }
        }
    }
}

#[cfg(test)]
mod tests;
