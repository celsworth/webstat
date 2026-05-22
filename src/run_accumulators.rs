use std::net::IpAddr;

use ahash::{AHashMap, AHashSet};

use crate::accumulators::HourlyMap;
use crate::method_proto::{METHOD_COUNT, PROTO_COUNT};

pub(crate) struct RunAccumulators {
    pub(crate) current_month: String,
    pub(crate) hourly: HourlyMap,
    pub(crate) urls: AHashMap<String, (u64, u64)>,
    pub(crate) hosts: AHashMap<String, (u64, u64)>,
    pub(crate) refs: AHashMap<String, u64>,
    pub(crate) agents: AHashMap<String, u64>,
    pub(crate) daily_ips: AHashMap<String, AHashSet<IpAddr>>,
    pub(crate) countries: AHashMap<String, u64>,
    pub(crate) status_codes: AHashMap<u16, u64>,
    pub(crate) method_counts: [u64; METHOD_COUNT],
    pub(crate) proto_counts: [u64; PROTO_COUNT],
}

impl RunAccumulators {
    pub(crate) fn new(current_month: String) -> Self {
        Self {
            current_month,
            hourly: AHashMap::with_capacity(32),
            urls: AHashMap::with_capacity(65_536),
            hosts: AHashMap::with_capacity(65_536),
            refs: AHashMap::with_capacity(4_096),
            agents: AHashMap::with_capacity(256),
            daily_ips: AHashMap::with_capacity(32),
            countries: AHashMap::with_capacity(256),
            status_codes: AHashMap::with_capacity(32),
            method_counts: [0; METHOD_COUNT],
            proto_counts: [0; PROTO_COUNT],
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.hourly.is_empty()
            && self.urls.is_empty()
            && self.hosts.is_empty()
            && self.refs.is_empty()
            && self.agents.is_empty()
            && self.countries.is_empty()
            && self.status_codes.is_empty()
            && self.method_counts.iter().all(|&c| c == 0)
            && self.proto_counts.iter().all(|&c| c == 0)
    }

    pub(crate) fn clear_for_new_month(&mut self, new_month: String) {
        *self = Self::new(new_month);
    }
}

#[cfg(test)]
mod tests;
