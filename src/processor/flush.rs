use super::*;
use ahash::AHashSet;

struct PreFlushTopMaps {
    top_urls: TopUrlsByHits,
    top_urls_bw: TopUrlsByBandwidth,
    top_hosts: TopHostsByHits,
    top_hosts_bw: TopHostsByBandwidth,
    top_refs: PeriodCountMap,
    top_agents: PeriodCountMap,
    top_countries: CountryHitsMap,
}

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

        let prefiltered = if self.enable_pruner && self.top_n > 0 && self.top_n < self.topn_k {
            Some(self.prefilter_top_maps_for_flush(run_acc))
        } else {
            None
        };

        let (top_urls, top_urls_bw, top_hosts, top_hosts_bw, top_refs, top_agents, top_countries) =
            if let Some(maps) = prefiltered.as_ref() {
                (
                    &maps.top_urls,
                    &maps.top_urls_bw,
                    &maps.top_hosts,
                    &maps.top_hosts_bw,
                    &maps.top_refs,
                    &maps.top_agents,
                    &maps.top_countries,
                )
            } else {
                (
                    &run_acc.top_urls,
                    &run_acc.top_urls_bw,
                    &run_acc.top_hosts,
                    &run_acc.top_hosts_bw,
                    &run_acc.top_refs,
                    &run_acc.top_agents,
                    &run_acc.top_countries,
                )
            };

        let flush_start = Instant::now();
        crate::logging::log_debug_at(2, "Flushing run aggregates and parse state to database...");
        self.db.flush_all_with_parse_states_split(
            &run_acc.hourly,
            top_urls,
            top_urls_bw,
            top_hosts,
            top_hosts_bw,
            top_refs,
            top_agents,
            top_countries,
            &run_acc.status_codes,
            &run_acc.hll_site_counts,
            run_acc.hll_all_time.as_ref(),
            pending_parse_states,
            retired_parse_states,
            &visit_state_updates,
            visit_state_prune_before_ts,
            &run_acc.method_counts,
            &run_acc.proto_counts,
        )?;

        let flush_elapsed = flush_start.elapsed().as_secs_f64();
        crate::logging::log_debug_at(
            1,
            &format!("Database flush completed in {:.1}s", flush_elapsed),
        );
        Ok(())
    }

    fn prefilter_top_maps_for_flush(&self, run_acc: &RunAccumulators) -> PreFlushTopMaps {
        PreFlushTopMaps {
            top_urls: self.filter_top_urls_for_flush(&run_acc.top_urls),
            top_urls_bw: self.filter_top_urls_bw_for_flush(&run_acc.top_urls_bw),
            top_hosts: self.filter_top_hosts_for_flush(&run_acc.top_hosts),
            top_hosts_bw: self.filter_top_hosts_bw_for_flush(&run_acc.top_hosts_bw),
            top_refs: self.filter_top_count_map_for_flush(&run_acc.top_refs),
            top_agents: self.filter_top_count_map_for_flush(&run_acc.top_agents),
            top_countries: self.filter_top_countries_for_flush(&run_acc.top_countries),
        }
    }

    fn latest_periods<'a, I>(&self, periods: I) -> (Option<&'a str>, Option<&'a str>)
    where
        I: Iterator<Item = &'a Arc<str>>,
    {
        let mut latest_month: Option<&'a str> = None;
        let mut latest_year: Option<&'a str> = None;

        for period in periods {
            let p = period.as_ref();
            if p.len() == 7 && latest_month.map_or(true, |curr| p > curr) {
                latest_month = Some(p);
            } else if p.len() == 4 && latest_year.map_or(true, |curr| p > curr) {
                latest_year = Some(p);
            }
        }

        (latest_month, latest_year)
    }

    fn should_pretrim_period(
        &self,
        period: &str,
        latest_month: Option<&str>,
        latest_year: Option<&str>,
    ) -> bool {
        match period.len() {
            7 => latest_month.is_some_and(|curr| period < curr),
            4 => latest_year.is_some_and(|curr| period < curr),
            _ => false,
        }
    }

    pub(super) fn filter_top_urls_for_flush(&self, top_urls: &TopUrlsByHits) -> TopUrlsByHits {
        let (latest_month, latest_year) = self.latest_periods(top_urls.keys());
        let mut filtered = TopUrlsByHits::with_capacity(top_urls.len());

        for (period, urls) in top_urls {
            if !self.should_pretrim_period(period.as_ref(), latest_month, latest_year) {
                filtered.insert(Arc::clone(period), self.clone_top_hits_bw(urls));
                continue;
            }

            let mut entries: Vec<_> = urls.iter().collect();
            if entries.len() <= self.top_n {
                filtered.insert(Arc::clone(period), self.clone_top_hits_bw(urls));
                continue;
            }

            let mut selected = AHashSet::with_capacity(self.top_n.saturating_mul(2));

            entries.sort_unstable_by(|(url_a, hits_a, bw_a), (url_b, hits_b, bw_b)| {
                hits_b
                    .cmp(hits_a)
                    .then_with(|| bw_b.cmp(bw_a))
                    .then_with(|| url_a.cmp(url_b))
            });
            for (url, _, _) in entries.iter().take(self.top_n) {
                selected.insert((*url).to_string());
            }

            entries.sort_unstable_by(|(url_a, hits_a, bw_a), (url_b, hits_b, bw_b)| {
                bw_b.cmp(bw_a)
                    .then_with(|| hits_b.cmp(hits_a))
                    .then_with(|| url_a.cmp(url_b))
            });
            for (url, _, _) in entries.iter().take(self.top_n) {
                selected.insert((*url).to_string());
            }

            let mut out = TopNUrls::new(selected.len());
            for (url, hits, bw) in entries {
                if selected.contains(url) {
                    out.add_hits_bw(url, hits, bw);
                }
            }
            filtered.insert(Arc::clone(period), out);
        }

        filtered
    }

    fn filter_top_urls_bw_for_flush(
        &self,
        top_urls_bw: &TopUrlsByBandwidth,
    ) -> TopUrlsByBandwidth {
        let (latest_month, latest_year) = self.latest_periods(top_urls_bw.keys());
        let mut filtered = TopUrlsByBandwidth::with_capacity(top_urls_bw.len());

        for (period, urls) in top_urls_bw {
            if !self.should_pretrim_period(period.as_ref(), latest_month, latest_year) {
                filtered.insert(Arc::clone(period), self.clone_top_urls_bw(urls));
                continue;
            }

            let mut entries: Vec<_> = urls.iter().collect();
            if entries.len() > self.top_n {
                entries.sort_unstable_by(|(url_a, hits_a, bw_a), (url_b, hits_b, bw_b)| {
                    bw_b.cmp(bw_a)
                        .then_with(|| hits_b.cmp(hits_a))
                        .then_with(|| url_a.cmp(url_b))
                });
                entries.truncate(self.top_n);
            }

            let mut out = TopNUrlsByBandwidth::new(entries.len());
            for (url, hits, bw) in entries {
                out.add_hits_bw(url, hits, bw);
            }
            filtered.insert(Arc::clone(period), out);
        }

        filtered
    }

    fn filter_top_hosts_for_flush(&self, top_hosts: &TopHostsByHits) -> TopHostsByHits {
        let (latest_month, latest_year) = self.latest_periods(top_hosts.keys());
        let mut filtered = TopHostsByHits::with_capacity(top_hosts.len());

        for (period, hosts) in top_hosts {
            if !self.should_pretrim_period(period.as_ref(), latest_month, latest_year) {
                filtered.insert(Arc::clone(period), self.clone_top_hosts(hosts));
                continue;
            }

            let mut entries: Vec<_> = hosts.iter().collect();
            if entries.len() > self.top_n {
                entries.sort_unstable_by(
                    |(host_a, hits_a, bw_a, _, _), (host_b, hits_b, bw_b, _, _)| {
                        hits_b
                            .cmp(hits_a)
                            .then_with(|| bw_b.cmp(bw_a))
                            .then_with(|| host_a.cmp(host_b))
                    },
                );
                entries.truncate(self.top_n);
            }

            let mut out = TopNHosts::new(entries.len());
            for (host, hits, bw, cc, cn) in entries {
                out.add_hits_bw(host, hits, bw, cc, cn);
            }
            filtered.insert(Arc::clone(period), out);
        }

        filtered
    }

    fn filter_top_hosts_bw_for_flush(
        &self,
        top_hosts_bw: &TopHostsByBandwidth,
    ) -> TopHostsByBandwidth {
        let (latest_month, latest_year) = self.latest_periods(top_hosts_bw.keys());
        let mut filtered = TopHostsByBandwidth::with_capacity(top_hosts_bw.len());

        for (period, hosts) in top_hosts_bw {
            if !self.should_pretrim_period(period.as_ref(), latest_month, latest_year) {
                filtered.insert(Arc::clone(period), self.clone_top_hosts_bw(hosts));
                continue;
            }

            let mut entries: Vec<_> = hosts.iter().collect();
            if entries.len() > self.top_n {
                entries.sort_unstable_by(
                    |(host_a, hits_a, bw_a, _, _), (host_b, hits_b, bw_b, _, _)| {
                        bw_b.cmp(bw_a)
                            .then_with(|| hits_b.cmp(hits_a))
                            .then_with(|| host_a.cmp(host_b))
                    },
                );
                entries.truncate(self.top_n);
            }

            let mut out = TopNHostsByBandwidth::new(entries.len());
            for (host, hits, bw, cc, cn) in entries {
                out.add_hits_bw(host, hits, bw, cc, cn);
            }
            filtered.insert(Arc::clone(period), out);
        }

        filtered
    }

    fn filter_top_count_map_for_flush(&self, map: &PeriodCountMap) -> PeriodCountMap {
        let (latest_month, latest_year) = self.latest_periods(map.keys());
        let mut filtered = PeriodCountMap::with_capacity(map.len());

        for (period, counts) in map {
            if !self.should_pretrim_period(period.as_ref(), latest_month, latest_year) {
                filtered.insert(Arc::clone(period), self.clone_top_count(counts));
                continue;
            }

            let mut entries: Vec<_> = counts.iter().collect();
            if entries.len() > self.top_n {
                entries.sort_unstable_by(|(key_a, hits_a), (key_b, hits_b)| {
                    hits_b.cmp(hits_a).then_with(|| key_a.cmp(key_b))
                });
                entries.truncate(self.top_n);
            }

            let mut out = TopNCount::new(entries.len());
            for (key, hits) in entries {
                out.add(key, hits);
            }
            filtered.insert(Arc::clone(period), out);
        }

        filtered
    }

    fn filter_top_countries_for_flush(&self, map: &CountryHitsMap) -> CountryHitsMap {
        let (latest_month, latest_year) = self.latest_periods(map.keys());
        let mut filtered = CountryHitsMap::with_capacity(map.len());

        for (period, countries) in map {
            if !self.should_pretrim_period(period.as_ref(), latest_month, latest_year)
                || countries.len() <= self.top_n
            {
                filtered.insert(Arc::clone(period), countries.clone());
                continue;
            }

            let mut entries: Vec<_> = countries.iter().collect();
            entries.sort_unstable_by(|(cc_a, hits_a), (cc_b, hits_b)| {
                hits_b.cmp(hits_a).then_with(|| cc_a.cmp(cc_b))
            });

            let mut out = AHashMap::with_capacity(self.top_n);
            for (cc, hits) in entries.into_iter().take(self.top_n) {
                out.insert(cc.clone(), *hits);
            }
            filtered.insert(Arc::clone(period), out);
        }

        filtered
    }

    fn clone_top_hits_bw(&self, src: &TopNUrls) -> TopNUrls {
        let mut out = TopNUrls::new(src.iter().count());
        for (key, hits, bw) in src.iter() {
            out.add_hits_bw(key, hits, bw);
        }
        out
    }

    fn clone_top_urls_bw(&self, src: &TopNUrlsByBandwidth) -> TopNUrlsByBandwidth {
        let mut out = TopNUrlsByBandwidth::new(src.iter().count());
        for (key, hits, bw) in src.iter() {
            out.add_hits_bw(key, hits, bw);
        }
        out
    }

    fn clone_top_hosts(&self, src: &TopNHosts) -> TopNHosts {
        let mut out = TopNHosts::new(src.iter().count());
        for (key, hits, bw, cc, cn) in src.iter() {
            out.add_hits_bw(key, hits, bw, cc, cn);
        }
        out
    }

    fn clone_top_hosts_bw(&self, src: &TopNHostsByBandwidth) -> TopNHostsByBandwidth {
        let mut out = TopNHostsByBandwidth::new(src.iter().count());
        for (key, hits, bw, cc, cn) in src.iter() {
            out.add_hits_bw(key, hits, bw, cc, cn);
        }
        out
    }

    fn clone_top_count(&self, src: &TopNCount) -> TopNCount {
        let mut out = TopNCount::new(src.iter().count());
        for (key, hits) in src.iter() {
            out.add(key, hits);
        }
        out
    }
}
