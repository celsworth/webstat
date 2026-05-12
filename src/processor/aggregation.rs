use super::*;

impl Processor {
    fn visit_state_key(ip: &str) -> VisitStateKey {
        if let Some(ipv4) = parse_ipv4_u32(ip) {
            return VisitStateKey {
                ip_kind: 1,
                ip_hi: 0,
                ip_lo: ipv4 as u64,
                ip_text: String::new(),
            };
        }

        if let Some(ipv6) = parse_ipv6_u128(ip) {
            return VisitStateKey {
                ip_kind: 2,
                ip_hi: (ipv6 >> 64) as u64,
                ip_lo: ipv6 as u64,
                ip_text: String::new(),
            };
        }

        VisitStateKey {
            ip_kind: 0,
            ip_hi: 0,
            ip_lo: 0,
            ip_text: ip.to_string(),
        }
    }

    // ── Per-entry aggregation ─────────────────────────────────────────────────

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(super) fn aggregate_entry(
        &mut self,
        entry: parser::LogEntry<'_>,
        hourly: &mut HourlyMap,
        top_urls: &mut PeriodHitsMap,
        top_hosts: &mut HostHitsMap,
        top_refs: &mut PeriodCountMap,
        top_agents: &mut PeriodCountMap,
        top_countries: &mut CountryCountMap,
        status_codes: &mut StatusMap,
    ) {
        let mut hll_site_counts = AHashMap::new();
        let mut top_hosts_bw: HostBwMap = AHashMap::new();
        self.aggregate_entry_with_hll_split(
            entry,
            hourly,
            top_urls,
            top_hosts,
            &mut top_hosts_bw,
            top_refs,
            top_agents,
            top_countries,
            status_codes,
            &mut hll_site_counts,
            None,
        );
    }

    #[allow(clippy::too_many_arguments)]
    #[allow(dead_code)]
    pub(super) fn aggregate_entry_with_hll(
        &mut self,
        entry: parser::LogEntry<'_>,
        hourly: &mut HourlyMap,
        top_urls: &mut PeriodHitsMap,
        top_hosts: &mut HostHitsMap,
        top_refs: &mut PeriodCountMap,
        top_agents: &mut PeriodCountMap,
        top_countries: &mut CountryCountMap,
        status_codes: &mut StatusMap,
        hll_site_counts: &mut AHashMap<Arc<str>, HyperLogLog>,
        hll_all_time: Option<&mut HyperLogLog>,
    ) {
        let mut top_hosts_bw: HostBwMap = AHashMap::new();
        self.aggregate_entry_with_hll_split(
            entry,
            hourly,
            top_urls,
            top_hosts,
            &mut top_hosts_bw,
            top_refs,
            top_agents,
            top_countries,
            status_codes,
            hll_site_counts,
            hll_all_time,
        );
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn aggregate_entry_with_hll_split(
        &mut self,
        entry: parser::LogEntry<'_>,
        hourly: &mut HourlyMap,
        top_urls: &mut PeriodHitsMap,
        top_hosts: &mut HostHitsMap,
        top_hosts_bw: &mut HostBwMap,
        top_refs: &mut PeriodCountMap,
        top_agents: &mut PeriodCountMap,
        top_countries: &mut CountryCountMap,
        status_codes: &mut StatusMap,
        hll_site_counts: &mut AHashMap<Arc<str>, HyperLogLog>,
        hll_all_time: Option<&mut HyperLogLog>,
    ) {
        let ua_result = self.ua.parse(entry.user_agent);
        if self.bot_filter && ua_result.is_bot {
            return;
        }

        let (date, hour, month_period, year_period, request_ts) = if self.track_visits {
            match self.time_periods_with_timestamp(entry.time_str, entry.month_num) {
                Some((date, hour, month_period, year_period, request_ts)) => {
                    (date, hour, month_period, year_period, Some(request_ts))
                }
                None => return,
            }
        } else {
            match self.time_periods(entry.time_str, entry.month_num) {
                Some((date, hour, month_period, year_period)) => {
                    (date, hour, month_period, year_period, None)
                }
                None => return,
            }
        };

        let status = entry.status;
        let bytes = entry.bytes;
        let path = entry.path;
        let clean_path = strip_query(path);
        let ip = entry.ip;
        let ip_id = self.intern_ip_id(ip);
        let agent = ua_result.family;

        // ── Hourly bucket ──────────────────────────────────────────────────────
        let h = hourly
            .entry(Arc::clone(&date))
            .or_default()
            .entry(hour)
            .or_default();
        h.ip_set.insert(ip_id);
        let stats = &mut h.stats;

        if self.track_visits {
            if let Some(ts) = request_ts {
                if ts > self.visit_max_seen_ts {
                    self.visit_max_seen_ts = ts;
                }
                let visit_key = Self::visit_state_key(ip);
                let is_new_visit = match self.visit_last_seen.entry(visit_key.clone()) {
                    std::collections::hash_map::Entry::Occupied(mut occupied) => {
                        let last_seen = *occupied.get();
                        if ts > last_seen {
                            *occupied.get_mut() = ts;
                        }
                        ts.saturating_sub(last_seen) > VISIT_TIMEOUT_SECONDS
                    }
                    std::collections::hash_map::Entry::Vacant(vacant) => {
                        vacant.insert(ts);
                        true
                    }
                };
                let dirty_ts = self.visit_last_seen.get(&visit_key).copied().unwrap_or(ts);
                self.visit_state_dirty
                    .entry(visit_key)
                    .and_modify(|v| {
                        if dirty_ts > *v {
                            *v = dirty_ts;
                        }
                    })
                    .or_insert(dirty_ts);
                if is_new_visit {
                    stats.visits += 1;
                }
            }
        }

        stats.hits += 1;
        stats.bandwidth += bytes;

        if (200..300).contains(&status) {
            let ext = file_ext(clean_path);
            if FILE_EXTS.contains(&ext) {
                stats.files += 1;
            } else {
                stats.pages += 1;
            }
            stats.status_2xx += 1;
        } else if status < 400 {
            stats.status_3xx += 1;
        } else if status < 500 {
            stats.status_4xx += 1;
        } else {
            stats.status_5xx += 1;
        }

        // ── GeoIP ──────────────────────────────────────────────────────────────
        let (country_code, country_name) = if let Some(cached) = self.geo_cache.get(&ip_id) {
            (Arc::clone(&cached.0), Arc::clone(&cached.1))
        } else {
            let result = self.geo.lookup(ip);
            self.geo_cache
                .insert(ip_id, (Arc::clone(&result.0), Arc::clone(&result.1)));
            result
        };

        // ── Month-period ───────────────────────────────────────────────────────
        let topn_k = self.topn_k;
        if self.enable_top_urls {
            top_urls
                .entry(Arc::clone(&month_period))
                .or_insert_with(|| TopNHitsBw::new(topn_k))
                .add(clean_path, bytes);
        }

        if self.enable_top_hosts {
            top_hosts
                .entry(Arc::clone(&month_period))
                .or_insert_with(|| TopNHosts::new(topn_k))
                .add(ip, bytes, &country_code, &country_name);

            top_hosts_bw
                .entry(Arc::clone(&month_period))
                .or_insert_with(|| TopNHostsByBandwidth::new(topn_k))
                .add(ip, bytes, &country_code, &country_name);
        }

        *status_codes
            .entry(Arc::clone(&month_period))
            .or_default()
            .entry(status)
            .or_insert(0) += 1;

        top_agents
            .entry(Arc::clone(&month_period))
            .or_insert_with(|| TopNCount::new(topn_k))
            .add(agent.as_ref(), 1);

        // ── Year-period ────────────────────────────────────────────────────────
        if self.enable_top_urls {
            top_urls
                .entry(Arc::clone(&year_period))
                .or_insert_with(|| TopNHitsBw::new(topn_k))
                .add(clean_path, bytes);
        }

        if self.enable_top_hosts {
            top_hosts
                .entry(Arc::clone(&year_period))
                .or_insert_with(|| TopNHosts::new(topn_k))
                .add(ip, bytes, &country_code, &country_name);

            top_hosts_bw
                .entry(Arc::clone(&year_period))
                .or_insert_with(|| TopNHostsByBandwidth::new(topn_k))
                .add(ip, bytes, &country_code, &country_name);
        }

        *status_codes
            .entry(Arc::clone(&year_period))
            .or_default()
            .entry(status)
            .or_insert(0) += 1;

        top_agents
            .entry(Arc::clone(&year_period))
            .or_insert_with(|| TopNCount::new(topn_k))
            .add(agent.as_ref(), 1);

        // ── Referrer ───────────────────────────────────────────────────────────
        if self.enable_top_refs {
            if !entry.referer.is_empty() {
                if let Some(host) = self.extract_host(entry.referer) {
                    if !self.own_host(&host) {
                        top_refs
                            .entry(Arc::clone(&month_period))
                            .or_insert_with(|| TopNCount::new(topn_k))
                            .add(&host, 1);

                        top_refs
                            .entry(Arc::clone(&year_period))
                            .or_insert_with(|| TopNCount::new(topn_k))
                            .add(&host, 1);
                    }
                }
            }
        }

        *top_countries
            .entry(Arc::clone(&month_period))
            .or_default()
            .entry(country_code.to_string())
            .or_insert(0) += 1;

        *top_countries
            .entry(Arc::clone(&year_period))
            .or_default()
            .entry(country_code.to_string())
            .or_insert(0) += 1;

        let ip_hash = {
            let mut h = XxHash3_64::default();
            h.write(ip.as_bytes());
            h.finish()
        };
        for scope in [&date, &month_period, &year_period] {
            hll_site_counts
                .entry(Arc::clone(scope))
                .or_insert_with(|| HyperLogLog::new(self.hll_precision))
                .add_hash(ip_hash);
        }
        if let Some(all_time) = hll_all_time {
            all_time.add_hash(ip_hash);
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    /// Return `(date, hour, month_period, year_period)` decoded from a nginx
    /// timestamp string "DD/Mon/YYYY:HH:MM:SS ±HHMM".  Results are memoised.
    ///
    /// Returns `Arc<str>` values so cloning them in the hot loop costs only an
    /// atomic ref-count increment rather than a heap allocation.
    fn time_periods(
        &mut self,
        time_str: &str,
        mon_num: u8,
    ) -> Option<(Arc<str>, u8, Arc<str>, Arc<str>)> {
        let b = time_str.as_bytes();
        if b.len() < 26 {
            return None;
        }
        let day: u32 = std::str::from_utf8(&b[0..2]).ok()?.parse().ok()?;
        let year: u32 = std::str::from_utf8(&b[7..11]).ok()?.parse().ok()?;
        let hour: u8 = std::str::from_utf8(&b[12..14]).ok()?.parse().ok()?;

        let key = year * 1_000_000 + mon_num as u32 * 10_000 + day * 100 + hour as u32;

        if let Some(cached) = self.time_cache.get(&key) {
            // Arc::clone × 3 = 3 atomic increments, not 3 heap allocations.
            return Some((
                Arc::clone(&cached.0),
                hour,
                Arc::clone(&cached.1),
                Arc::clone(&cached.2),
            ));
        }

        let mon_s = format!("{mon_num:02}");
        let result = (
            Arc::from(format!("{year}-{mon_s}-{day:02}").as_str()),
            hour,
            Arc::from(format!("{year}-{mon_s}").as_str()),
            Arc::from(format!("{year}").as_str()),
        );
        self.time_cache.insert(
            key,
            (
                Arc::clone(&result.0),
                Arc::clone(&result.2),
                Arc::clone(&result.3),
            ),
        );
        Some(result)
    }

    /// Parse the same timestamp once and return both the memoised periods and
    /// the Unix timestamp used for visit tracking.
    fn time_periods_with_timestamp(
        &mut self,
        time_str: &str,
        mon_num: u8,
    ) -> Option<(Arc<str>, u8, Arc<str>, Arc<str>, i64)> {
        let b = time_str.as_bytes();
        if b.len() < 26 {
            return None;
        }

        let day: u32 = std::str::from_utf8(&b[0..2]).ok()?.parse().ok()?;
        let year: i32 = std::str::from_utf8(&b[7..11]).ok()?.parse().ok()?;
        let hour: u8 = std::str::from_utf8(&b[12..14]).ok()?.parse().ok()?;
        let minute: i64 = std::str::from_utf8(&b[15..17]).ok()?.parse().ok()?;
        let second: i64 = std::str::from_utf8(&b[18..20]).ok()?.parse().ok()?;

        let sign = b[21];
        let tz_hour: i64 = std::str::from_utf8(&b[22..24]).ok()?.parse().ok()?;
        let tz_min: i64 = std::str::from_utf8(&b[24..26]).ok()?.parse().ok()?;
        let offset = tz_hour * 3600 + tz_min * 60;
        let offset = match sign {
            b'+' => offset,
            b'-' => -offset,
            _ => return None,
        };

        let key = year as u32 * 1_000_000 + mon_num as u32 * 10_000 + day * 100 + hour as u32;

        if let Some(cached) = self.time_cache.get(&key) {
            let ts = days_from_civil(year, mon_num as u32, day) * 86_400
                + hour as i64 * 3_600
                + minute * 60
                + second
                - offset;
            return Some((
                Arc::clone(&cached.0),
                hour,
                Arc::clone(&cached.1),
                Arc::clone(&cached.2),
                ts,
            ));
        }

        let mon_s = format!("{mon_num:02}");
        let date = Arc::from(format!("{year}-{mon_s}-{day:02}").as_str());
        let month = Arc::from(format!("{year}-{mon_s}").as_str());
        let year_arc = Arc::from(format!("{year}").as_str());
        self.time_cache.insert(
            key,
            (Arc::clone(&date), Arc::clone(&month), Arc::clone(&year_arc)),
        );

        let ts = days_from_civil(year, mon_num as u32, day) * 86_400
            + hour as i64 * 3_600
            + minute * 60
            + second
            - offset;

        Some((date, hour, month, year_arc, ts))
    }

    /// Extract and memoise the host portion of a referrer URL.
    fn extract_host(&mut self, url: &str) -> Option<Arc<str>> {
        if let Some(cached) = self.referer_cache.get(url) {
            return Some(Arc::clone(cached));
        }
        let host = extract_host_from_url(url);
        if let Some(ref host_value) = host {
            self.referer_cache
                .insert(url.to_string(), Arc::clone(host_value));
        }
        host
    }

    fn own_host(&self, host: &str) -> bool {
        self.site_host.as_deref().map_or(false, |own| own == host)
    }

    /// Return a stable, exact integer ID for an IP string.
    ///
    /// This preserves exact unique-IP semantics while avoiding per-line String
    /// clones inside hourly uniqueness sets.
    fn intern_ip_id(&mut self, ip: &str) -> u32 {
        if let Some(ipv4) = parse_ipv4_u32(ip) {
            if let Some(id) = self.ip_ids_v4.get(&ipv4) {
                return *id;
            }

            let id = self.next_ip_id;
            self.next_ip_id = self.next_ip_id.saturating_add(1);
            self.ip_ids_v4.insert(ipv4, id);
            return id;
        }

        if let Some(ipv6) = parse_ipv6_u128(ip) {
            if let Some(id) = self.ip_ids_v6.get(&ipv6) {
                return *id;
            }

            let id = self.next_ip_id;
            self.next_ip_id = self.next_ip_id.saturating_add(1);
            self.ip_ids_v6.insert(ipv6, id);
            return id;
        }

        if let Some(id) = self.ip_ids_other.get(ip) {
            return *id;
        }

        let id = self.next_ip_id;
        self.next_ip_id = self.next_ip_id.saturating_add(1);
        self.ip_ids_other.insert(ip.to_string(), id);
        id
    }
}
