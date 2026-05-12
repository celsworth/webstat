use super::*;

impl Database {
    #[cfg(test)]
    pub fn flush_all(
        &mut self,
        hourly: &HourlyMap,
        top_urls: &TopUrlsByHits,
        top_hosts: &TopHostsByHits,
        top_refs: &PeriodCountMap,
        top_agents: &PeriodCountMap,
        top_countries: &CountryHitsMap,
        status_codes: &StatusHitsMap,
    ) -> Result<()> {
        let empty_hosts_bw: TopHostsByBandwidth = AHashMap::new();
        self.flush_all_with_parse_states_split(
            hourly,
            top_urls,
            top_hosts,
            &empty_hosts_bw,
            top_refs,
            top_agents,
            top_countries,
            status_codes,
            &AHashMap::new(),
            None,
            &[],
            &[],
            &[],
            None,
            &AHashMap::new(),
            &AHashMap::new(),
        )
    }

    #[cfg(test)]
    pub fn flush_all_with_parse_states(
        &mut self,
        hourly: &HourlyMap,
        top_urls: &TopUrlsByHits,
        top_hosts: &TopHostsByHits,
        top_refs: &PeriodCountMap,
        top_agents: &PeriodCountMap,
        top_countries: &CountryHitsMap,
        status_codes: &StatusHitsMap,
        hll_site_counts: &AHashMap<Arc<str>, HyperLogLog>,
        hll_all_time: Option<&HyperLogLog>,
        parse_states: &[ParseStateUpdate],
    ) -> Result<()> {
        let empty_hosts_bw: TopHostsByBandwidth = AHashMap::new();
        self.flush_all_with_parse_states_split(
            hourly,
            top_urls,
            top_hosts,
            &empty_hosts_bw,
            top_refs,
            top_agents,
            top_countries,
            status_codes,
            hll_site_counts,
            hll_all_time,
            parse_states,
            &[],
            &[],
            None,
            &AHashMap::new(),
            &AHashMap::new(),
        )
    }

    pub fn flush_all_with_parse_states_split(
        &mut self,
        hourly: &HourlyMap,
        top_urls: &TopUrlsByHits,
        top_hosts: &TopHostsByHits,
        top_hosts_bw: &TopHostsByBandwidth,
        top_refs: &PeriodCountMap,
        top_agents: &PeriodCountMap,
        top_countries: &CountryHitsMap,
        status_codes: &StatusHitsMap,
        hll_site_counts: &AHashMap<Arc<str>, HyperLogLog>,
        hll_all_time: Option<&HyperLogLog>,
        parse_states: &[ParseStateUpdate],
        retired_parse_states: &[ParseStateUpdate],
        visit_states: &[VisitStateUpdate],
        visit_state_prune_before_ts: Option<i64>,
        method_counts: &MethodCountsMap,
        proto_counts: &ProtoCountsMap,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;

        // hourly_stats
        {
            let sql = "INSERT INTO hourly_stats \
                                             (date,hour,hits,visits,files,pages,bandwidth,status_2xx,status_3xx,status_4xx,status_5xx,sites) \
                                             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12) \
                       ON CONFLICT (date,hour) DO UPDATE SET \
                                                 hits=hits+excluded.hits, visits=visits+excluded.visits, files=files+excluded.files, \
                         pages=pages+excluded.pages, bandwidth=bandwidth+excluded.bandwidth, \
                         status_2xx=status_2xx+excluded.status_2xx, \
                         status_3xx=status_3xx+excluded.status_3xx, \
                         status_4xx=status_4xx+excluded.status_4xx, \
                         status_5xx=status_5xx+excluded.status_5xx, \
                         sites=sites+excluded.sites";
            let mut stmt = tx.prepare_cached(sql)?;
            for (date, hours) in hourly {
                for (hr, s) in hours {
                    let sites = s.ip_set.len() as i64;
                    stmt.execute(params![
                        date.as_ref(),
                        *hr as i64,
                        s.stats.hits as i64,
                        s.stats.visits as i64,
                        s.stats.files as i64,
                        s.stats.pages as i64,
                        s.stats.bandwidth as i64,
                        s.stats.status_2xx as i64,
                        s.stats.status_3xx as i64,
                        s.stats.status_4xx as i64,
                        s.stats.status_5xx as i64,
                        sites
                    ])?;
                }
            }
        }

        // top_urls_hits
        {
            let sql = "INSERT INTO top_urls_hits (period,url,hits,bandwidth) VALUES (?1,?2,?3,?4) \
                       ON CONFLICT (period,url) DO UPDATE SET \
                         hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth";
            let mut stmt = tx.prepare_cached(sql)?;
            for (period, urls) in top_urls {
                for (url, hits, bw) in urls.iter() {
                    stmt.execute(params![period.as_ref(), url, hits as i64, bw as i64])?;
                }
            }
        }

        // top_urls_bandwidth
        {
            let sql =
                "INSERT INTO top_urls_bandwidth (period,url,hits,bandwidth) VALUES (?1,?2,?3,?4) \
                       ON CONFLICT (period,url) DO UPDATE SET \
                         hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth";
            let mut stmt = tx.prepare_cached(sql)?;
            for (period, urls) in top_urls {
                for (url, hits, bw) in urls.iter() {
                    stmt.execute(params![period.as_ref(), url, hits as i64, bw as i64])?;
                }
            }
        }

        // top_hosts
        {
            let sql = "INSERT INTO top_hosts \
                                             (period,host_kind,host_hi,host_lo,host_text,hits,bandwidth,country_code) \
                                             VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
                       ON CONFLICT (period,host_kind,host_hi,host_lo,host_text) DO UPDATE SET \
                         hits=hits+excluded.hits, \
                         bandwidth=bandwidth+excluded.bandwidth, \
                                                 country_code=COALESCE(NULLIF(excluded.country_code,'--'),country_code)";
            let mut stmt = tx.prepare_cached(sql)?;
            let mut all_hosts = AHashSet::new();
            for (period, hosts) in top_hosts {
                for (host, hits, bw, cc, _cn) in hosts.iter() {
                    let host_key = encode_host_key(host);
                    stmt.execute(params![
                        period.as_ref(),
                        host_key.kind as i64,
                        host_key.hi as i64,
                        host_key.lo as i64,
                        &host_key.text,
                        hits as i64,
                        bw as i64,
                        cc.as_ref()
                    ])?;
                    all_hosts.insert(host_key);
                }
            }

            drop(stmt);

            let mut host_stmt = tx.prepare_cached(
                "INSERT OR IGNORE INTO all_time_hosts (host_kind, host_hi, host_lo, host_text) VALUES (?1, ?2, ?3, ?4)",
            )?;
            for host in all_hosts {
                host_stmt.execute(params![
                    host.kind as i64,
                    host.hi as i64,
                    host.lo as i64,
                    host.text,
                ])?;
            }
        }

        // top_hosts_hits
        {
            let sql = "INSERT INTO top_hosts_hits \
                                             (period,host_kind,host_hi,host_lo,host_text,hits,bandwidth,country_code) \
                                             VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
                       ON CONFLICT (period,host_kind,host_hi,host_lo,host_text) DO UPDATE SET \
                         hits=hits+excluded.hits, \
                         bandwidth=bandwidth+excluded.bandwidth, \
                                                 country_code=COALESCE(NULLIF(excluded.country_code,'--'),country_code)";
            let mut stmt = tx.prepare_cached(sql)?;
            for (period, hosts) in top_hosts {
                for (host, hits, bw, cc, _cn) in hosts.iter() {
                    let host_key = encode_host_key(host);
                    stmt.execute(params![
                        period.as_ref(),
                        host_key.kind as i64,
                        host_key.hi as i64,
                        host_key.lo as i64,
                        &host_key.text,
                        hits as i64,
                        bw as i64,
                        cc.as_ref()
                    ])?;
                }
            }
        }

        // top_hosts_bandwidth
        {
            let sql = "INSERT INTO top_hosts_bandwidth \
                                             (period,host_kind,host_hi,host_lo,host_text,hits,bandwidth,country_code) \
                                             VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
                       ON CONFLICT (period,host_kind,host_hi,host_lo,host_text) DO UPDATE SET \
                         hits=hits+excluded.hits, \
                         bandwidth=bandwidth+excluded.bandwidth, \
                                                 country_code=COALESCE(NULLIF(excluded.country_code,'--'),country_code)";
            let mut stmt = tx.prepare_cached(sql)?;
            for (period, hosts) in top_hosts_bw {
                for (host, hits, bw, cc, _cn) in hosts.iter() {
                    let host_key = encode_host_key(host);
                    stmt.execute(params![
                        period.as_ref(),
                        host_key.kind as i64,
                        host_key.hi as i64,
                        host_key.lo as i64,
                        &host_key.text,
                        hits as i64,
                        bw as i64,
                        cc.as_ref()
                    ])?;
                }
            }
        }

        // country_code_names
        {
            let sql = "INSERT INTO country_code_names (country_code, country_name) VALUES (?1, ?2)
                       ON CONFLICT (country_code) DO UPDATE SET
                         country_name = CASE
                           WHEN country_code_names.country_name = 'Unknown' AND excluded.country_name <> 'Unknown'
                             THEN excluded.country_name
                           ELSE country_code_names.country_name
                         END";
            let mut stmt = tx.prepare_cached(sql)?;
            for hosts in top_hosts.values() {
                for (_, _, _, cc, cn) in hosts.iter() {
                    stmt.execute(params![cc.as_ref(), cn.as_ref()])?;
                }
            }
            for hosts in top_hosts_bw.values() {
                for (_, _, _, cc, cn) in hosts.iter() {
                    stmt.execute(params![cc.as_ref(), cn.as_ref()])?;
                }
            }
        }

        // top_refs
        {
            let sql = "INSERT INTO top_refs (period,referrer,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,referrer) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (period, refs) in top_refs {
                for (referrer, hits) in refs.iter() {
                    stmt.execute(params![period.as_ref(), referrer, hits as i64])?;
                }
            }
        }

        // top_agents
        {
            let sql = "INSERT INTO top_agents (period,agent_family,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,agent_family) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (period, agents) in top_agents {
                for (agent, hits) in agents.iter() {
                    stmt.execute(params![period.as_ref(), agent, hits as i64])?;
                }
            }
        }

        // top_countries
        {
            let sql = "INSERT INTO top_countries (period,country_code,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,country_code) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (period, countries) in top_countries {
                for (cc, hits) in countries.iter() {
                    stmt.execute(params![period.as_ref(), cc, *hits as i64])?;
                }
            }
        }

        // status_codes
        {
            let sql = "INSERT INTO status_codes (period,status,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,status) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (period, codes) in status_codes {
                for (status, hits) in codes {
                    stmt.execute(params![period.as_ref(), *status as i64, *hits as i64])?;
                }
            }
        }

        // method_counts
        {
            let sql = "INSERT INTO method_counts (period,method,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,method) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (period, counts) in method_counts {
                for (i, &hits) in counts.iter().enumerate() {
                    if hits > 0 {
                        stmt.execute(params![
                            period.as_ref(),
                            crate::method_proto::METHOD_NAMES[i],
                            hits as i64
                        ])?;
                    }
                }
            }
        }

        // proto_counts
        {
            let sql = "INSERT INTO proto_counts (period,proto,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,proto) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (period, counts) in proto_counts {
                for (i, &hits) in counts.iter().enumerate() {
                    if hits > 0 {
                        stmt.execute(params![
                            period.as_ref(),
                            crate::method_proto::PROTO_NAMES[i],
                            hits as i64
                        ])?;
                    }
                }
            }
        }

        if !retired_parse_states.is_empty() {
            let mut archive_stmt = tx.prepare_cached(
                "INSERT INTO parse_state_archive (filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT (filepath, inode) DO UPDATE SET
                   inode = ?2,
                   compressed_size = ?3,
                   uncompressed_size = ?4,
                   compressed_head_fingerprint = ?5,
                   uncompressed_head_fingerprint = ?6,
                   compressed_offset = ?7,
                   uncompressed_offset = ?8,
                   mtime_ns = ?9,
                   completed = ?10",
            )?;
            let mut delete_stmt =
                tx.prepare_cached("DELETE FROM parse_state WHERE filepath = ?1 AND inode = ?2")?;
            for state in retired_parse_states {
                archive_stmt.execute(params![
                    &state.filepath,
                    state.inode as i64,
                    state.compressed_size as i64,
                    state.uncompressed_size as i64,
                    state.compressed_head_fingerprint.map(|f| f as i64),
                    state.uncompressed_head_fingerprint.map(|f| f as i64),
                    state.compressed_offset as i64,
                    state.uncompressed_offset as i64,
                    state.mtime_ns,
                    state.completed as i64,
                ])?;
                delete_stmt.execute(params![&state.filepath, state.inode as i64])?;
            }
        }

        if !parse_states.is_empty() {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO parse_state (filepath, inode, compressed_size, uncompressed_size, compressed_head_fingerprint, uncompressed_head_fingerprint, compressed_offset, uncompressed_offset, mtime_ns, completed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
                 ON CONFLICT (filepath) DO UPDATE SET
                   inode = ?2,
                   compressed_size = ?3,
                   uncompressed_size = ?4,
                   compressed_head_fingerprint = ?5,
                   uncompressed_head_fingerprint = ?6,
                   compressed_offset = ?7,
                   uncompressed_offset = ?8,
                   mtime_ns = ?9,
                   completed = ?10",
            )?;
            for state in parse_states {
                stmt.execute(params![
                    &state.filepath,
                    state.inode as i64,
                    state.compressed_size as i64,
                    state.uncompressed_size as i64,
                    state.compressed_head_fingerprint.map(|f| f as i64),
                    state.uncompressed_head_fingerprint.map(|f| f as i64),
                    state.compressed_offset as i64,
                    state.uncompressed_offset as i64,
                    state.mtime_ns,
                    state.completed as i64,
                ])?;
            }
        }

        if !hll_site_counts.is_empty() || hll_all_time.is_some() {
            Self::upsert_site_count_hlls(&tx, hll_site_counts, hll_all_time)?;
        }

        if !visit_states.is_empty() {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO visit_state (ip_kind, ip_hi, ip_lo, ip_text, last_seen_ts)
                 VALUES (?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT (ip_kind, ip_hi, ip_lo, ip_text) DO UPDATE SET
                   last_seen_ts = CASE
                     WHEN excluded.last_seen_ts > visit_state.last_seen_ts
                       THEN excluded.last_seen_ts
                     ELSE visit_state.last_seen_ts
                   END",
            )?;
            for state in visit_states {
                stmt.execute(params![
                    state.key.ip_kind as i64,
                    state.key.ip_hi as i64,
                    state.key.ip_lo as i64,
                    &state.key.ip_text,
                    state.last_seen_ts,
                ])?;
            }
        }

        if let Some(prune_before_ts) = visit_state_prune_before_ts {
            tx.execute(
                "DELETE FROM visit_state WHERE last_seen_ts < ?1",
                params![prune_before_ts],
            )?;
        }

        tx.commit().context("Failed to commit flush transaction")?;
        Ok(())
    }
}
