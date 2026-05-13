use std::sync::Arc;

use ahash::AHashMap;

use crate::hll::HyperLogLog;
use crate::method_proto::{MethodCountsMap, ProtoCountsMap};
use crate::topn::{
    CountryHitsMap, HourlyMap, PeriodCountMap, StatusHitsMap, TopHostsByBandwidth, TopHostsByHits,
    TopUrlsByBandwidth, TopUrlsByHits,
};

pub(crate) struct RunAccumulators {
    pub(crate) hourly: HourlyMap,
    pub(crate) top_urls: TopUrlsByHits,
    pub(crate) top_urls_bw: TopUrlsByBandwidth,
    pub(crate) top_hosts: TopHostsByHits,
    pub(crate) top_hosts_bw: TopHostsByBandwidth,
    pub(crate) top_refs: PeriodCountMap,
    pub(crate) top_agents: PeriodCountMap,
    pub(crate) top_countries: CountryHitsMap,
    pub(crate) status_codes: StatusHitsMap,
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
            top_urls_bw: AHashMap::with_capacity(if enable_top_urls { base_capacity } else { 0 }),
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
            && self.top_urls_bw.is_empty()
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

}

#[cfg(test)]
mod tests;
