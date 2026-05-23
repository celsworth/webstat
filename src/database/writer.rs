use std::sync::Arc;

use ahash::{AHashMap, AHashSet};
use anyhow::Context;

use super::*;
use crate::accumulators::HourlyMap;
use crate::ip::Ip;
use crate::method_proto::{METHOD_NAMES, PROTO_NAMES};

pub struct FlushData<'a> {
    pub period: &'a str,
    pub hourly: &'a HourlyMap,
    pub urls: &'a AHashMap<String, (u64, u64)>,
    pub hosts: &'a AHashMap<String, (u64, u64)>,
    pub host_geo: &'a AHashMap<String, (Arc<str>, Arc<str>)>,
    pub refs: &'a AHashMap<String, u64>,
    pub agents: &'a AHashMap<String, u64>,
    pub daily_ips: &'a AHashMap<String, AHashSet<Ip>>,
    pub countries: &'a AHashMap<String, u64>,
    pub status_codes: &'a AHashMap<u16, u64>,
    pub method_counts: &'a [u64],
    pub proto_counts: &'a [u64],
    pub parse_states: &'a [ParseStateUpdate],
    pub retired_parse_states: &'a [ParseStateUpdate],
    pub visit_states: &'a [VisitStateUpdate],
    pub visit_state_prune_before_ts: Option<i64>,
}

impl Database {
    pub fn flush(&mut self, data: FlushData<'_>) -> Result<()> {
        let tx = self.conn.transaction()?;

        // hourly_stats
        {
            let sql = "INSERT INTO hourly_stats \
                       (date,hour,hits,visits,files,pages,bandwidth,\
                        status_2xx,status_3xx,status_4xx,status_5xx) \
                       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) \
                       ON CONFLICT (date,hour) DO UPDATE SET \
                         hits=hits+excluded.hits, visits=visits+excluded.visits, \
                         files=files+excluded.files, pages=pages+excluded.pages, \
                         bandwidth=bandwidth+excluded.bandwidth, \
                         status_2xx=status_2xx+excluded.status_2xx, \
                         status_3xx=status_3xx+excluded.status_3xx, \
                         status_4xx=status_4xx+excluded.status_4xx, \
                         status_5xx=status_5xx+excluded.status_5xx";
            let mut stmt = tx.prepare_cached(sql)?;
            for (date, hours) in data.hourly {
                for (hr, acc) in hours {
                    let s = &acc.stats;
                    stmt.execute(params![
                        date.as_ref(),
                        *hr as i64,
                        s.hits as i64,
                        s.visits as i64,
                        s.files as i64,
                        s.pages as i64,
                        s.bandwidth as i64,
                        s.status_2xx as i64,
                        s.status_3xx as i64,
                        s.status_4xx as i64,
                        s.status_5xx as i64,
                    ])?;
                }
            }
        }

        // monthly_urls_hits and monthly_urls_bandwidth (same data, different tables)
        if !data.urls.is_empty() {
            let sql_hits = "INSERT INTO monthly_urls_hits (period,url,hits,bandwidth) \
                            VALUES (?1,?2,?3,?4) \
                            ON CONFLICT (period,url) DO UPDATE SET \
                              hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth";
            let sql_bw = "INSERT INTO monthly_urls_bandwidth (period,url,hits,bandwidth) \
                          VALUES (?1,?2,?3,?4) \
                          ON CONFLICT (period,url) DO UPDATE SET \
                            hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth";
            let mut stmt_hits = tx.prepare_cached(sql_hits)?;
            let mut stmt_bw = tx.prepare_cached(sql_bw)?;
            for (url, (hits, bw)) in data.urls {
                stmt_hits.execute(params![data.period, url, *hits as i64, *bw as i64])?;
                stmt_bw.execute(params![data.period, url, *hits as i64, *bw as i64])?;
            }
        }

        let unknown_geo: (Arc<str>, Arc<str>) = (Arc::from("--"), Arc::from("Unknown"));

        // monthly_hosts_hits and monthly_hosts_bandwidth
        if !data.hosts.is_empty() {
            let sql_hits = "INSERT INTO monthly_hosts_hits \
                            (period,host_kind,host_hi,host_lo,host_text,hits,bandwidth,country_code) \
                            VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
                            ON CONFLICT (period,host_kind,host_hi,host_lo,host_text) DO UPDATE SET \
                              hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth, \
                              country_code=COALESCE(NULLIF(excluded.country_code,'--'),country_code)";
            let sql_bw = "INSERT INTO monthly_hosts_bandwidth \
                          (period,host_kind,host_hi,host_lo,host_text,hits,bandwidth,country_code) \
                          VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
                          ON CONFLICT (period,host_kind,host_hi,host_lo,host_text) DO UPDATE SET \
                            hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth, \
                            country_code=COALESCE(NULLIF(excluded.country_code,'--'),country_code)";
            let mut stmt_hits = tx.prepare_cached(sql_hits)?;
            let mut stmt_bw = tx.prepare_cached(sql_bw)?;
            let mut cn_stmt = tx.prepare_cached(
                "INSERT INTO country_code_names (country_code, country_name) VALUES (?1, ?2)
                 ON CONFLICT (country_code) DO UPDATE SET
                   country_name = CASE
                     WHEN country_code_names.country_name = 'Unknown'
                          AND excluded.country_name <> 'Unknown'
                       THEN excluded.country_name
                     ELSE country_code_names.country_name
                   END",
            )?;

            for (host, (hits, bw)) in data.hosts {
                let (cc, cn) = data.host_geo.get(host).unwrap_or(&unknown_geo);
                let hk = encode_host_key(host);
                stmt_hits.execute(params![
                    data.period,
                    hk.kind as i64,
                    hk.hi as i64,
                    hk.lo as i64,
                    &hk.text,
                    *hits as i64,
                    *bw as i64,
                    cc.as_ref()
                ])?;
                stmt_bw.execute(params![
                    data.period,
                    hk.kind as i64,
                    hk.hi as i64,
                    hk.lo as i64,
                    &hk.text,
                    *hits as i64,
                    *bw as i64,
                    cc.as_ref()
                ])?;
                cn_stmt.execute(params![cc.as_ref(), cn.as_ref()])?;
            }
        }

        // monthly_refs
        if !data.refs.is_empty() {
            let sql = "INSERT INTO monthly_refs (period,referrer,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,referrer) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (referrer, hits) in data.refs {
                stmt.execute(params![data.period, referrer, *hits as i64])?;
            }
        }

        // monthly_agents
        if !data.agents.is_empty() {
            let sql = "INSERT INTO monthly_agents (period,agent_family,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,agent_family) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (agent, hits) in data.agents {
                stmt.execute(params![data.period, agent, *hits as i64])?;
            }
        }

        // daily_ip_log — INSERT OR IGNORE for deduplication across flushes/resumes
        if !data.daily_ips.is_empty() {
            let sql = "INSERT OR IGNORE INTO daily_ip_log (date,ip_kind,ip_hi,ip_lo) \
                       VALUES (?1,?2,?3,?4)";
            let mut stmt = tx.prepare_cached(sql)?;
            for (date, ips) in data.daily_ips {
                for ip in ips {
                    stmt.execute(params![date, ip.kind() as i64, ip.hi() as i64, ip.lo() as i64])?;
                }
            }
        }

        // top_countries
        if !data.countries.is_empty() {
            let sql = "INSERT INTO top_countries (period,country_code,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,country_code) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (cc, hits) in data.countries {
                stmt.execute(params![data.period, cc, *hits as i64])?;
            }
        }

        // status_codes
        if !data.status_codes.is_empty() {
            let sql = "INSERT INTO status_codes (period,status,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,status) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (status, hits) in data.status_codes {
                stmt.execute(params![data.period, *status as i64, *hits as i64])?;
            }
        }

        // method_counts
        {
            let sql = "INSERT INTO method_counts (period,method,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,method) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (i, &hits) in data.method_counts.iter().enumerate() {
                if hits > 0 {
                    stmt.execute(params![data.period, METHOD_NAMES[i], hits as i64])?;
                }
            }
        }

        // proto_counts
        {
            let sql = "INSERT INTO proto_counts (period,proto,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,proto) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (i, &hits) in data.proto_counts.iter().enumerate() {
                if hits > 0 {
                    stmt.execute(params![data.period, PROTO_NAMES[i], hits as i64])?;
                }
            }
        }

        // retired parse_states → archive
        if !data.retired_parse_states.is_empty() {
            let mut archive_stmt = tx.prepare_cached(
                "INSERT INTO parse_state_archive \
                 (filepath,inode,compressed_size,uncompressed_size,\
                  compressed_head_fingerprint,uncompressed_head_fingerprint,\
                  compressed_offset,uncompressed_offset,mtime_ns,completed) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) \
                 ON CONFLICT (filepath,inode) DO UPDATE SET \
                   inode=?2, compressed_size=?3, uncompressed_size=?4, \
                   compressed_head_fingerprint=?5, uncompressed_head_fingerprint=?6, \
                   compressed_offset=?7, uncompressed_offset=?8, \
                   mtime_ns=?9, completed=?10",
            )?;
            let mut del_stmt =
                tx.prepare_cached("DELETE FROM parse_state WHERE filepath=?1 AND inode=?2")?;
            for s in data.retired_parse_states {
                archive_stmt.execute(params![
                    &s.filepath,
                    s.inode as i64,
                    s.compressed_size as i64,
                    s.uncompressed_size as i64,
                    s.compressed_head_fingerprint.map(|f| f as i64),
                    s.uncompressed_head_fingerprint.map(|f| f as i64),
                    s.compressed_offset as i64,
                    s.uncompressed_offset as i64,
                    s.mtime_ns,
                    s.completed as i64,
                ])?;
                del_stmt.execute(params![&s.filepath, s.inode as i64])?;
            }
        }

        // active parse_states
        if !data.parse_states.is_empty() {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO parse_state \
                 (filepath,inode,compressed_size,uncompressed_size,\
                  compressed_head_fingerprint,uncompressed_head_fingerprint,\
                  compressed_offset,uncompressed_offset,mtime_ns,completed) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10) \
                 ON CONFLICT (filepath) DO UPDATE SET \
                   inode=?2, compressed_size=?3, uncompressed_size=?4, \
                   compressed_head_fingerprint=?5, uncompressed_head_fingerprint=?6, \
                   compressed_offset=?7, uncompressed_offset=?8, \
                   mtime_ns=?9, completed=?10",
            )?;
            for s in data.parse_states {
                stmt.execute(params![
                    &s.filepath,
                    s.inode as i64,
                    s.compressed_size as i64,
                    s.uncompressed_size as i64,
                    s.compressed_head_fingerprint.map(|f| f as i64),
                    s.uncompressed_head_fingerprint.map(|f| f as i64),
                    s.compressed_offset as i64,
                    s.uncompressed_offset as i64,
                    s.mtime_ns,
                    s.completed as i64,
                ])?;
            }
        }

        // visit_state
        if !data.visit_states.is_empty() {
            let mut stmt = tx.prepare_cached(
                "INSERT INTO visit_state (ip_kind,ip_hi,ip_lo,ip_text,last_seen_ts) \
                 VALUES (?1,?2,?3,?4,?5) \
                 ON CONFLICT (ip_kind,ip_hi,ip_lo,ip_text) DO UPDATE SET \
                   last_seen_ts = CASE \
                     WHEN excluded.last_seen_ts > visit_state.last_seen_ts \
                       THEN excluded.last_seen_ts \
                     ELSE visit_state.last_seen_ts \
                   END",
            )?;
            for vs in data.visit_states {
                stmt.execute(params![
                    vs.key.ip_kind as i64,
                    vs.key.ip_hi as i64,
                    vs.key.ip_lo as i64,
                    &vs.key.ip_text,
                    vs.last_seen_ts,
                ])?;
            }
        }

        if let Some(prune_ts) = data.visit_state_prune_before_ts {
            tx.execute(
                "DELETE FROM visit_state WHERE last_seen_ts < ?1",
                params![prune_ts],
            )?;
        }

        tx.commit().context("Failed to commit flush transaction")?;
        Ok(())
    }

    /// Finalize a completed month: populate all_time_hosts and yearly_ip_log,
    /// prune monthly tables to top_n rows, mark month complete in meta.
    pub fn finalize_month(&mut self, period: &str, top_n: usize) -> Result<()> {
        let tx = self.conn.transaction()?;

        let like_pattern = format!("{}-%", period);
        tx.execute(
            "INSERT OR IGNORE INTO all_time_hosts (host_kind,host_hi,host_lo,host_text) \
             SELECT ip_kind, ip_hi, ip_lo, '' FROM daily_ip_log WHERE date LIKE ?1",
            params![like_pattern],
        )?;

        let year = &period[..4];
        tx.execute(
            "INSERT OR IGNORE INTO yearly_ip_log (year,ip_kind,ip_hi,ip_lo) \
             SELECT ?1, ip_kind, ip_hi, ip_lo FROM daily_ip_log WHERE date LIKE ?2",
            params![year, like_pattern],
        )?;

        // Cache monthly unique-IP count so reports don't need to run DISTINCT at query time.
        tx.execute(
            "INSERT OR REPLACE INTO site_count_cache (period, count) \
             SELECT ?1, COUNT(*) FROM (
               SELECT DISTINCT ip_kind, ip_hi, ip_lo FROM daily_ip_log WHERE date LIKE ?2
             )",
            params![period, like_pattern],
        )?;

        // Update yearly cached count from yearly_ip_log, which accumulates all finalized months.
        tx.execute(
            "INSERT OR REPLACE INTO site_count_cache (period, count) \
             SELECT ?1, COUNT(*) FROM yearly_ip_log WHERE year = ?1",
            params![year],
        )?;

        // Cache per-day unique-IP counts then prune daily_ip_log for this month.
        tx.execute(
            "INSERT OR REPLACE INTO daily_site_counts (date, count) \
             SELECT date, COUNT(*) FROM daily_ip_log WHERE date LIKE ?1 GROUP BY date",
            params![like_pattern],
        )?;
        tx.execute(
            "DELETE FROM daily_ip_log WHERE date LIKE ?1",
            params![like_pattern],
        )?;

        for (table, col) in [
            ("monthly_urls_hits", "hits"),
            ("monthly_urls_bandwidth", "bandwidth"),
            ("monthly_hosts_hits", "hits"),
            ("monthly_hosts_bandwidth", "bandwidth"),
            ("monthly_refs", "hits"),
            ("monthly_agents", "hits"),
        ] {
            Self::prune_monthly_table(&tx, table, period, col, top_n)?;
        }

        tx.execute(
            "INSERT INTO meta (key, value) VALUES (?1, '1') \
             ON CONFLICT (key) DO UPDATE SET value = '1'",
            params![format!("month_{}_complete", period)],
        )?;

        tx.commit()
            .context("Failed to commit finalize_month transaction")?;
        Ok(())
    }

    /// Finalize a completed year: write the definitive yearly site count and
    /// discard the yearly_ip_log rows (all_time_hosts already has them).
    pub fn finalize_year(&mut self, year: &str) -> Result<()> {
        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT OR REPLACE INTO site_count_cache (period, count) \
             SELECT ?1, COUNT(*) FROM yearly_ip_log WHERE year = ?1",
            params![year],
        )?;
        tx.execute(
            "DELETE FROM yearly_ip_log WHERE year = ?1",
            params![year],
        )?;

        tx.commit().context("Failed to commit finalize_year transaction")?;
        Ok(())
    }

    fn prune_monthly_table(
        tx: &rusqlite::Transaction<'_>,
        table: &str,
        period: &str,
        order_col: &str,
        top_n: usize,
    ) -> Result<()> {
        let sql = format!(
            "DELETE FROM {table} \
             WHERE period = ?1 \
             AND rowid NOT IN ( \
               SELECT rowid FROM {table} \
               WHERE period = ?1 \
               ORDER BY {order_col} DESC \
               LIMIT ?2 \
             )"
        );
        tx.execute(&sql, params![period, top_n as i64])?;
        Ok(())
    }
}

