// flush_data and finalize_month: writes RunAccumulators to SQLite and prunes top-N tables.

use std::sync::Arc;

use ahash::AHashMap;
use anyhow::Context;
use roaring::{RoaringBitmap, RoaringTreemap};
use rusqlite::OptionalExtension;

use super::*;
use crate::accumulators::HourlyMap;
use crate::ip::IpBitmaps;
use crate::method_proto::{METHOD_NAMES, PROTO_NAMES};
use crate::response_time::ResponseTimeHistogram;

pub struct FlushData<'a> {
    pub period: &'a str,
    pub hourly: &'a HourlyMap,
    pub urls: &'a AHashMap<String, (u64, u64)>,
    pub hosts: &'a AHashMap<String, (u64, u64)>,
    pub host_geo: &'a AHashMap<String, (Arc<str>, Arc<str>)>,
    pub refs: &'a AHashMap<String, u64>,
    pub agents: &'a AHashMap<String, u64>,
    pub daily_ips: &'a AHashMap<Arc<str>, IpBitmaps>,
    pub countries: &'a AHashMap<String, u64>,
    pub status_codes: &'a AHashMap<u16, u64>,
    pub method_counts: &'a [u64],
    pub protocol_counts: &'a [u64],
    pub daily_hists: &'a AHashMap<Arc<str>, ResponseTimeHistogram>,
    pub url_rt: &'a AHashMap<String, (u64, u64)>,
    pub parse_states: &'a [ParseStateUpdate],
    pub retired_parse_states: &'a [ParseStateUpdate],
    pub visit_states: &'a [VisitStateUpdate],
    pub visit_state_prune_before_ts: Option<i64>,
}

fn encode_host_key(host: &str) -> HostKey {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => HostKey {
            kind: 1,
            hi: 0,
            lo: u32::from(v4) as u64,
        },
        Ok(IpAddr::V6(v6)) => {
            let n = u128::from(v6);
            HostKey {
                kind: 2,
                hi: (n >> 64) as u64,
                lo: n as u64,
            }
        }
        Err(_) => HostKey {
            kind: 0,
            hi: 0,
            lo: 0,
        },
    }
}

// ── Bitmap helpers ────────────────────────────────────────────────────────────

fn deserialize_v4(blob: &[u8]) -> Result<RoaringBitmap> {
    RoaringBitmap::deserialize_from(blob).context("deserialize v4 bitmap")
}

fn deserialize_v6(blob: &[u8]) -> Result<RoaringTreemap> {
    RoaringTreemap::deserialize_from(blob).context("deserialize v6 bitmap")
}

fn serialize_v4(bm: &RoaringBitmap) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    bm.serialize_into(&mut buf).context("serialize v4 bitmap")?;
    Ok(buf)
}

fn serialize_v6(tm: &RoaringTreemap) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    tm.serialize_into(&mut buf).context("serialize v6 bitmap")?;
    Ok(buf)
}

/// Load and OR all bitmap rows matching a WHERE clause into accumulated v4/v6 maps.
///
/// `rows` is a `Vec<(ip_kind, ip_hi, blob)>` pre-fetched inside the transaction.
fn or_bitmap_rows(
    rows: Vec<(u8, u64, Vec<u8>)>,
    v4: &mut RoaringBitmap,
    v6: &mut AHashMap<u64, RoaringTreemap>,
) -> Result<()> {
    for (kind, hi, blob) in rows {
        match kind {
            1 => *v4 |= deserialize_v4(&blob)?,
            2 => *v6.entry(hi).or_default() |= deserialize_v6(&blob)?,
            _ => {}
        }
    }
    Ok(())
}

fn bitmap_cardinality(v4: &RoaringBitmap, v6: &AHashMap<u64, RoaringTreemap>) -> u64 {
    v4.len() + v6.values().map(|t| t.len()).sum::<u64>()
}

// ── Database impl ─────────────────────────────────────────────────────────────

impl Database {
    pub fn flush(&mut self, data: FlushData<'_>) -> Result<()> {
        let tx = self.conn.transaction()?;

        // hourly_stats
        {
            let sql = "INSERT INTO hourly_stats \
                       (date,hour,hits,visits,bandwidth,\
                        status_2xx,status_3xx,status_4xx,status_5xx) \
                       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) \
                       ON CONFLICT (date,hour) DO UPDATE SET \
                         hits=hits+excluded.hits, visits=visits+excluded.visits, \
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
                        s.bandwidth as i64,
                        s.status_2xx as i64,
                        s.status_3xx as i64,
                        s.status_4xx as i64,
                        s.status_5xx as i64,
                    ])?;
                }
            }
        }

        // monthly_top_urls_hits and monthly_top_urls_bandwidth (same data, different tables)
        if !data.urls.is_empty() {
            let sql_hits = "INSERT INTO monthly_top_urls_hits (period,url,hits,bandwidth) \
                            VALUES (?1,?2,?3,?4) \
                            ON CONFLICT (period,url) DO UPDATE SET \
                              hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth";
            let sql_bw = "INSERT INTO monthly_top_urls_bandwidth (period,url,hits,bandwidth) \
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

        // monthly_top_ips_hits and monthly_top_ips_bandwidth
        if !data.hosts.is_empty() {
            let sql_hits = "INSERT INTO monthly_top_ips_hits \
                            (period,host_kind,host_hi,host_lo,hits,bandwidth,country_code) \
                            VALUES (?1,?2,?3,?4,?5,?6,?7) \
                            ON CONFLICT (period,host_kind,host_hi,host_lo) DO UPDATE SET \
                              hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth, \
                              country_code=COALESCE(NULLIF(excluded.country_code,'--'),country_code)";
            let sql_bw = "INSERT INTO monthly_top_ips_bandwidth \
                          (period,host_kind,host_hi,host_lo,hits,bandwidth,country_code) \
                          VALUES (?1,?2,?3,?4,?5,?6,?7) \
                          ON CONFLICT (period,host_kind,host_hi,host_lo) DO UPDATE SET \
                            hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth, \
                            country_code=COALESCE(NULLIF(excluded.country_code,'--'),country_code)";
            let mut stmt_hits = tx.prepare_cached(sql_hits)?;
            let mut stmt_bw = tx.prepare_cached(sql_bw)?;
            let mut cn_stmt = tx.prepare_cached(
                "INSERT INTO countries (country_code, country_name) VALUES (?1, ?2)
                 ON CONFLICT (country_code) DO UPDATE SET
                   country_name = CASE
                     WHEN countries.country_name = 'Unknown'
                          AND excluded.country_name <> 'Unknown'
                       THEN excluded.country_name
                     ELSE countries.country_name
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
                    *hits as i64,
                    *bw as i64,
                    cc.as_ref()
                ])?;
                stmt_bw.execute(params![
                    data.period,
                    hk.kind as i64,
                    hk.hi as i64,
                    hk.lo as i64,
                    *hits as i64,
                    *bw as i64,
                    cc.as_ref()
                ])?;
                cn_stmt.execute(params![cc.as_ref(), cn.as_ref()])?;
            }
        }

        // monthly_referrers
        if !data.refs.is_empty() {
            let sql = "INSERT INTO monthly_referrers (period,referrer,hits) VALUES (?1,?2,?3) \
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

        // daily_unique_ips — read-modify-write per (date, ip_kind, ip_hi) group
        for (date, bitmaps) in data.daily_ips {
            if !bitmaps.v4.is_empty() {
                let existing: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT bitmap FROM daily_unique_ips \
                         WHERE date=?1 AND ip_kind=1 AND ip_hi=0",
                        params![date.as_ref()],
                        |r| r.get(0),
                    )
                    .optional()?;
                let mut bm = match existing {
                    Some(blob) => deserialize_v4(&blob)?,
                    None => RoaringBitmap::new(),
                };
                bm |= &bitmaps.v4;
                let count = bm.len() as i64;
                let buf = serialize_v4(&bm)?;
                tx.execute(
                    "INSERT OR REPLACE INTO daily_unique_ips \
                     (date,ip_kind,ip_hi,count,bitmap) VALUES (?1,1,0,?2,?3)",
                    params![date.as_ref(), count, buf],
                )?;
            }

            for (hi, treemap) in &bitmaps.v6 {
                if treemap.is_empty() {
                    continue;
                }
                let hi_i = *hi as i64;
                let existing: Option<Vec<u8>> = tx
                    .query_row(
                        "SELECT bitmap FROM daily_unique_ips \
                         WHERE date=?1 AND ip_kind=2 AND ip_hi=?2",
                        params![date.as_ref(), hi_i],
                        |r| r.get(0),
                    )
                    .optional()?;
                let mut tm = match existing {
                    Some(blob) => deserialize_v6(&blob)?,
                    None => RoaringTreemap::new(),
                };
                tm |= treemap;
                let count = tm.len() as i64;
                let buf = serialize_v6(&tm)?;
                tx.execute(
                    "INSERT OR REPLACE INTO daily_unique_ips \
                     (date,ip_kind,ip_hi,count,bitmap) VALUES (?1,2,?2,?3,?4)",
                    params![date.as_ref(), hi_i, count, buf],
                )?;
            }
        }

        // daily_response_time_histograms — read-modify-write per date
        for (date, hist) in data.daily_hists {
            let existing: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT data FROM daily_response_time_histograms WHERE date=?1",
                    params![date.as_ref()],
                    |r| r.get(0),
                )
                .optional()?;
            let mut merged = match existing {
                Some(blob) => ResponseTimeHistogram::deserialize(&blob)
                    .context("deserialize response time histogram")?,
                None => ResponseTimeHistogram::new(),
            };
            merged.merge(hist);
            let blob = merged.serialize();
            tx.execute(
                "INSERT OR REPLACE INTO daily_response_time_histograms (date, data) \
                 VALUES (?1, ?2)",
                params![date.as_ref(), blob],
            )?;
        }

        // monthly_top_urls_avg_rt
        if !data.url_rt.is_empty() {
            let sql = "INSERT INTO monthly_top_urls_avg_rt \
                       (period,url,rt_sum,rt_count) VALUES (?1,?2,?3,?4) \
                       ON CONFLICT (period,url) DO UPDATE SET \
                         rt_sum=rt_sum+excluded.rt_sum, \
                         rt_count=rt_count+excluded.rt_count";
            let mut stmt = tx.prepare_cached(sql)?;
            for (url, (sum, count)) in data.url_rt {
                stmt.execute(params![data.period, url, *sum as i64, *count as i64])?;
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

        // protocol_counts
        {
            let sql = "INSERT INTO protocol_counts (period,proto,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,proto) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (i, &hits) in data.protocol_counts.iter().enumerate() {
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

    /// Finalize a completed month: OR daily bitmaps into yearly and all-time, compute
    /// unique-visitor counts, prune monthly tables, and mark month complete in meta.
    pub fn finalize_month(
        &mut self,
        period: &str,
        top_n: usize,
    ) -> Result<()> {
        let tx = self.conn.transaction()?;

        let like_pattern = format!("{}-%", period);
        let year = &period[..4];

        // ── Load all daily bitmaps for this month ─────────────────────────────
        let daily_rows: Vec<(u8, u64, Vec<u8>)> = {
            let mut stmt = tx.prepare(
                "SELECT ip_kind, ip_hi, bitmap FROM daily_unique_ips WHERE date LIKE ?1",
            )?;
            let mapped = stmt.query_map(params![like_pattern], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u8,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            let mut rows = Vec::new();
            for row in mapped {
                rows.push(row?);
            }
            rows
        };

        let mut monthly_v4 = RoaringBitmap::new();
        let mut monthly_v6: AHashMap<u64, RoaringTreemap> = AHashMap::new();
        or_bitmap_rows(daily_rows, &mut monthly_v4, &mut monthly_v6)?;

        // Monthly unique count
        let monthly_count = bitmap_cardinality(&monthly_v4, &monthly_v6);
        tx.execute(
            "INSERT OR REPLACE INTO unique_visitor_counts (period, count) VALUES (?1, ?2)",
            params![period, monthly_count as i64],
        )?;

        // ── Load existing yearly bitmaps, OR with monthly, write back ─────────
        let yearly_rows: Vec<(u8, u64, Vec<u8>)> = {
            let mut stmt = tx.prepare(
                "SELECT ip_kind, ip_hi, bitmap FROM yearly_unique_ips WHERE year = ?1",
            )?;
            let mapped = stmt.query_map(params![year], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u8,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            let mut rows = Vec::new();
            for row in mapped {
                rows.push(row?);
            }
            rows
        };

        let mut yearly_v4 = monthly_v4.clone();
        let mut yearly_v6: AHashMap<u64, RoaringTreemap> = monthly_v6.clone();
        or_bitmap_rows(yearly_rows, &mut yearly_v4, &mut yearly_v6)?;

        if !yearly_v4.is_empty() {
            tx.execute(
                "INSERT OR REPLACE INTO yearly_unique_ips (year,ip_kind,ip_hi,bitmap) \
                 VALUES (?1,1,0,?2)",
                params![year, serialize_v4(&yearly_v4)?],
            )?;
        }
        for (hi, tm) in &yearly_v6 {
            if tm.is_empty() {
                continue;
            }
            tx.execute(
                "INSERT OR REPLACE INTO yearly_unique_ips (year,ip_kind,ip_hi,bitmap) \
                 VALUES (?1,2,?2,?3)",
                params![year, *hi as i64, serialize_v6(tm)?],
            )?;
        }

        // Yearly unique count (each row is an independent group — just sum cardinalities)
        let yearly_count = bitmap_cardinality(&yearly_v4, &yearly_v6);
        tx.execute(
            "INSERT OR REPLACE INTO unique_visitor_counts (period, count) VALUES (?1, ?2)",
            params![year, yearly_count as i64],
        )?;

        // ── all_time_ips ──────────────────────────────────────────────────────
        {
            let at_rows: Vec<(u8, u64, Vec<u8>)> = {
                let mut stmt =
                    tx.prepare("SELECT ip_kind, ip_hi, bitmap FROM all_time_ips")?;
                let mapped = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)? as u8,
                        row.get::<_, i64>(1)? as u64,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                })?;
                let mut rows = Vec::new();
                for row in mapped {
                    rows.push(row?);
                }
                rows
            };

            let mut at_v4 = monthly_v4.clone();
            let mut at_v6: AHashMap<u64, RoaringTreemap> = monthly_v6.clone();
            or_bitmap_rows(at_rows, &mut at_v4, &mut at_v6)?;

            if !at_v4.is_empty() {
                tx.execute(
                    "INSERT OR REPLACE INTO all_time_ips (ip_kind,ip_hi,bitmap) VALUES (1,0,?1)",
                    params![serialize_v4(&at_v4)?],
                )?;
            }
            for (hi, tm) in &at_v6 {
                if tm.is_empty() {
                    continue;
                }
                tx.execute(
                    "INSERT OR REPLACE INTO all_time_ips (ip_kind,ip_hi,bitmap) \
                     VALUES (2,?1,?2)",
                    params![*hi as i64, serialize_v6(tm)?],
                )?;
            }
        }

        // ── Populate daily_visitor_counts then delete daily rows ──────────────
        tx.execute(
            "INSERT OR REPLACE INTO daily_visitor_counts (date, count) \
             SELECT date, SUM(count) FROM daily_unique_ips WHERE date LIKE ?1 GROUP BY date",
            params![like_pattern],
        )?;
        tx.execute(
            "DELETE FROM daily_unique_ips WHERE date LIKE ?1",
            params![like_pattern],
        )?;

        // ── Response time histograms: compute daily stats, build monthly, delete daily ──
        {
            let daily_rt_rows: Vec<(String, Vec<u8>)> = {
                let mut stmt = tx.prepare(
                    "SELECT date, data FROM daily_response_time_histograms \
                     WHERE date LIKE ?1",
                )?;
                let mapped = stmt.query_map(params![like_pattern], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })?;
                let mut rows = Vec::new();
                for row in mapped {
                    rows.push(row?);
                }
                rows
            };

            if !daily_rt_rows.is_empty() {
                let mut monthly_hist = ResponseTimeHistogram::new();
                for (date, blob) in &daily_rt_rows {
                    let hist = ResponseTimeHistogram::deserialize(blob)
                        .context("deserialize daily rt histogram in finalize_month")?;
                    if hist.count > 0 {
                        let avg_ms = hist.sum_ms as f64 / hist.count as f64;
                        let p95_ms = hist.percentile(95.0);
                        tx.execute(
                            "INSERT OR REPLACE INTO daily_response_time_stats \
                             (date, avg_ms, p95_ms) VALUES (?1, ?2, ?3)",
                            params![date, avg_ms, p95_ms as i64],
                        )?;
                        monthly_hist.merge(&hist);
                    }
                }

                if monthly_hist.count > 0 {
                    tx.execute(
                        "INSERT OR REPLACE INTO monthly_response_time_histograms \
                         (period, data) VALUES (?1, ?2)",
                        params![period, monthly_hist.serialize()],
                    )?;
                }

                tx.execute(
                    "DELETE FROM daily_response_time_histograms WHERE date LIKE ?1",
                    params![like_pattern],
                )?;
            }
        }

        for (table, col) in [
            ("monthly_top_urls_hits", "hits"),
            ("monthly_top_urls_bandwidth", "bandwidth"),
            ("monthly_top_ips_hits", "hits"),
            ("monthly_top_ips_bandwidth", "bandwidth"),
            ("monthly_referrers", "hits"),
            ("monthly_agents", "hits"),
        ] {
            Self::prune_monthly_table(&tx, table, period, col, top_n)?;
        }

        if top_n > 0 {
            tx.execute(
                "DELETE FROM monthly_top_urls_avg_rt \
                 WHERE period=?1 AND rt_count>0 \
                 AND url NOT IN ( \
                   SELECT url FROM monthly_top_urls_avg_rt \
                   WHERE period=?1 AND rt_count>0 \
                   ORDER BY rt_sum*1.0/rt_count DESC LIMIT ?2 \
                 )",
                params![period, top_n as i64],
            )?;
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

    /// Finalize a completed year: compute the definitive yearly unique-visitor count
    /// from the accumulated yearly bitmaps and discard those rows.
    pub fn finalize_year(&mut self, year: &str) -> Result<()> {
        let tx = self.conn.transaction()?;

        let yearly_rows: Vec<(u8, u64, Vec<u8>)> = {
            let mut stmt = tx.prepare(
                "SELECT ip_kind, ip_hi, bitmap FROM yearly_unique_ips WHERE year = ?1",
            )?;
            let mapped = stmt.query_map(params![year], |row| {
                Ok((
                    row.get::<_, i64>(0)? as u8,
                    row.get::<_, i64>(1)? as u64,
                    row.get::<_, Vec<u8>>(2)?,
                ))
            })?;
            let mut rows = Vec::new();
            for row in mapped {
                rows.push(row?);
            }
            rows
        };

        // The yearly bitmaps are already the OR of all finalized months; each
        // (ip_kind, ip_hi) group is disjoint, so just sum cardinalities.
        let mut count = 0u64;
        for (kind, _hi, blob) in yearly_rows {
            count += match kind {
                1 => deserialize_v4(&blob)?.len(),
                2 => deserialize_v6(&blob)?.len(),
                _ => 0,
            };
        }

        tx.execute(
            "INSERT OR REPLACE INTO unique_visitor_counts (period, count) VALUES (?1, ?2)",
            params![year, count as i64],
        )?;
        tx.execute("DELETE FROM yearly_unique_ips WHERE year = ?1", params![year])?;

        tx.commit()
            .context("Failed to commit finalize_year transaction")?;
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
