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
use crate::run_accumulators::{BucketAcc, ErrUrlStats, UrlStats};

pub struct FlushData<'a> {
    pub period: &'a str,
    pub hourly: &'a HourlyMap,
    pub url_stats: &'a AHashMap<String, UrlStats>,
    pub error_urls: &'a AHashMap<String, ErrUrlStats>,
    pub hosts: &'a AHashMap<String, (u64, u64)>,
    pub host_geo: &'a AHashMap<String, (Arc<str>, Arc<str>)>,
    pub refs: &'a AHashMap<String, u64>,
    pub agents: &'a AHashMap<String, (u64, u64)>,
    pub daily_ips: &'a AHashMap<Arc<str>, IpBitmaps>,
    pub countries: &'a AHashMap<String, (u64, u64)>,
    pub status_codes: &'a AHashMap<u16, u64>,
    pub method_counts: &'a [u64],
    pub protocol_counts: &'a [u64],
    pub daily_hists: &'a AHashMap<Arc<str>, ResponseTimeHistogram>,
    pub bucket_stats: &'a AHashMap<Arc<str>, BucketAcc>,
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

        // top_urls — unified hits/bandwidth/rt
        if !data.url_stats.is_empty() {
            let sql = "INSERT INTO top_urls \
                       (period,url,hits,bandwidth,rt_sum,rt_count,rt_max) \
                       VALUES (?1,?2,?3,?4,?5,?6,?7) \
                       ON CONFLICT (period,url) DO UPDATE SET \
                         hits=hits+excluded.hits, \
                         bandwidth=bandwidth+excluded.bandwidth, \
                         rt_sum=rt_sum+excluded.rt_sum, \
                         rt_count=rt_count+excluded.rt_count, \
                         rt_max=MAX(rt_max,excluded.rt_max)";
            let mut stmt = tx.prepare_cached(sql)?;
            for (url, stats) in data.url_stats {
                stmt.execute(params![
                    data.period,
                    url,
                    stats.hits as i64,
                    stats.bandwidth as i64,
                    stats.rt_sum as i64,
                    stats.rt_count as i64,
                    stats.rt_max as i64,
                ])?;
            }
        }

        // top_error_urls — per-code counters keyed by URL
        if !data.error_urls.is_empty() {
            let sql = "INSERT INTO top_error_urls \
                       (period,url,c400,c401,c403,c404,c422,c429,c4xx,\
                        c500,c502,c503,c5xx,bandwidth) \
                       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) \
                       ON CONFLICT (period,url) DO UPDATE SET \
                         c400=c400+excluded.c400, \
                         c401=c401+excluded.c401, \
                         c403=c403+excluded.c403, \
                         c404=c404+excluded.c404, \
                         c422=c422+excluded.c422, \
                         c429=c429+excluded.c429, \
                         c4xx=c4xx+excluded.c4xx, \
                         c500=c500+excluded.c500, \
                         c502=c502+excluded.c502, \
                         c503=c503+excluded.c503, \
                         c5xx=c5xx+excluded.c5xx, \
                         bandwidth=bandwidth+excluded.bandwidth";
            let mut stmt = tx.prepare_cached(sql)?;
            for (url, stats) in data.error_urls {
                stmt.execute(params![
                    data.period,
                    url,
                    stats.c400 as i64,
                    stats.c401 as i64,
                    stats.c403 as i64,
                    stats.c404 as i64,
                    stats.c422 as i64,
                    stats.c429 as i64,
                    stats.c4xx as i64,
                    stats.c500 as i64,
                    stats.c502 as i64,
                    stats.c503 as i64,
                    stats.c5xx as i64,
                    stats.bandwidth as i64,
                ])?;
            }
        }

        let unknown_geo: (Arc<str>, Arc<str>) = (Arc::from("--"), Arc::from("Unknown"));

        // top_ips
        if !data.hosts.is_empty() {
            let sql = "INSERT INTO top_ips \
                       (period,host_kind,host_hi,host_lo,hits,bandwidth,country_code) \
                       VALUES (?1,?2,?3,?4,?5,?6,?7) \
                       ON CONFLICT (period,host_kind,host_hi,host_lo) DO UPDATE SET \
                         hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth, \
                         country_code=COALESCE(NULLIF(excluded.country_code,'--'),country_code)";
            let mut stmt = tx.prepare_cached(sql)?;
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
                stmt.execute(params![
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

        // top_referrers
        if !data.refs.is_empty() {
            let sql = "INSERT INTO top_referrers (period,referrer,hits) VALUES (?1,?2,?3) \
                       ON CONFLICT (period,referrer) DO UPDATE SET hits=hits+excluded.hits";
            let mut stmt = tx.prepare_cached(sql)?;
            for (referrer, hits) in data.refs {
                stmt.execute(params![data.period, referrer, *hits as i64])?;
            }
        }

        // top_agents
        if !data.agents.is_empty() {
            let sql = "INSERT INTO top_agents (period,agent_family,hits,bandwidth) VALUES (?1,?2,?3,?4) \
                       ON CONFLICT (period,agent_family) DO UPDATE SET \
                       hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth";
            let mut stmt = tx.prepare_cached(sql)?;
            for (agent, (hits, bw)) in data.agents {
                stmt.execute(params![data.period, agent, *hits as i64, *bw as i64])?;
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


        // top_countries
        if !data.countries.is_empty() {
            let sql = "INSERT INTO top_countries (period,country_code,hits,bandwidth) VALUES (?1,?2,?3,?4) \
                       ON CONFLICT (period,country_code) DO UPDATE SET \
                       hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth";
            let mut stmt = tx.prepare_cached(sql)?;
            for (cc, (hits, bw)) in data.countries {
                stmt.execute(params![data.period, cc, *hits as i64, *bw as i64])?;
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

        // bucket_period_stats + per-bucket sub-tables
        if !data.bucket_stats.is_empty() {
            let bps_sql = "INSERT INTO bucket_period_stats \
                           (period,bucket,hits,bandwidth,rt_sum,rt_count,rt_max) \
                           VALUES (?1,?2,?3,?4,?5,?6,?7) \
                           ON CONFLICT (period,bucket) DO UPDATE SET \
                             hits=hits+excluded.hits, \
                             bandwidth=bandwidth+excluded.bandwidth, \
                             rt_sum=rt_sum+excluded.rt_sum, \
                             rt_count=rt_count+excluded.rt_count, \
                             rt_max=MAX(rt_max,excluded.rt_max)";
            let bu_sql = "INSERT INTO bucket_urls \
                          (period,bucket,url,hits,bandwidth,rt_sum,rt_count,rt_max) \
                          VALUES (?1,?2,?3,?4,?5,?6,?7,?8) \
                          ON CONFLICT (period,bucket,url) DO UPDATE SET \
                            hits=hits+excluded.hits, \
                            bandwidth=bandwidth+excluded.bandwidth, \
                            rt_sum=rt_sum+excluded.rt_sum, \
                            rt_count=rt_count+excluded.rt_count, \
                            rt_max=MAX(rt_max,excluded.rt_max)";
            let bsc_sql = "INSERT INTO bucket_status_codes (period,bucket,status,hits) \
                           VALUES (?1,?2,?3,?4) \
                           ON CONFLICT (period,bucket,status) DO UPDATE SET hits=hits+excluded.hits";
            let ba_sql = "INSERT INTO bucket_agents \
                          (period,bucket,agent_family,hits,bandwidth) \
                          VALUES (?1,?2,?3,?4,?5) \
                          ON CONFLICT (period,bucket,agent_family) DO UPDATE SET \
                            hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth";
            let bc_sql = "INSERT INTO bucket_countries \
                          (period,bucket,country_code,hits,bandwidth) \
                          VALUES (?1,?2,?3,?4,?5) \
                          ON CONFLICT (period,bucket,country_code) DO UPDATE SET \
                            hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth";
            let bm_sql = "INSERT INTO bucket_method_counts (period,bucket,method,hits) \
                          VALUES (?1,?2,?3,?4) \
                          ON CONFLICT (period,bucket,method) DO UPDATE SET hits=hits+excluded.hits";
            let bp_sql = "INSERT INTO bucket_protocol_counts (period,bucket,proto,hits) \
                          VALUES (?1,?2,?3,?4) \
                          ON CONFLICT (period,bucket,proto) DO UPDATE SET hits=hits+excluded.hits";

            let mut bps_stmt = tx.prepare_cached(bps_sql)?;
            let mut bu_stmt = tx.prepare_cached(bu_sql)?;
            let mut bsc_stmt = tx.prepare_cached(bsc_sql)?;
            let mut ba_stmt = tx.prepare_cached(ba_sql)?;
            let mut bc_stmt = tx.prepare_cached(bc_sql)?;
            let mut bm_stmt = tx.prepare_cached(bm_sql)?;
            let mut bp_stmt = tx.prepare_cached(bp_sql)?;

            let mut brth_stmt = tx.prepare_cached(
                "SELECT data FROM bucket_response_time_histograms WHERE period=?1 AND bucket=?2",
            )?;
            let mut brth_upsert = tx.prepare_cached(
                "INSERT OR REPLACE INTO bucket_response_time_histograms (period,bucket,data) \
                 VALUES (?1,?2,?3)",
            )?;

            for (bucket_name, acc) in data.bucket_stats {
                let bn = bucket_name.as_ref();
                bps_stmt.execute(params![
                    data.period, bn,
                    acc.hits as i64, acc.bandwidth as i64,
                    acc.rt_sum as i64, acc.rt_count as i64, acc.rt_max as i64,
                ])?;

                if let Some(hist) = &acc.rt_histogram {
                    let existing: Option<Vec<u8>> = brth_stmt
                        .query_row(params![data.period, bn], |r| r.get(0))
                        .optional()?;
                    let mut merged = match existing {
                        Some(blob) => ResponseTimeHistogram::deserialize(&blob)
                            .context("deserialize bucket rt histogram")?,
                        None => ResponseTimeHistogram::new(),
                    };
                    merged.merge(hist);
                    brth_upsert.execute(params![data.period, bn, merged.serialize()])?;
                }
                for (url, s) in &acc.url_stats {
                    bu_stmt.execute(params![
                        data.period, bn, url,
                        s.hits as i64, s.bandwidth as i64,
                        s.rt_sum as i64, s.rt_count as i64, s.rt_max as i64,
                    ])?;
                }
                for (status, hits) in &acc.status_codes {
                    bsc_stmt.execute(params![data.period, bn, *status as i64, *hits as i64])?;
                }
                for (agent, (hits, bw)) in &acc.agents {
                    ba_stmt.execute(params![data.period, bn, agent.as_ref(), *hits as i64, *bw as i64])?;
                }
                for (cc, (hits, bw)) in &acc.countries {
                    bc_stmt.execute(params![data.period, bn, cc.as_ref(), *hits as i64, *bw as i64])?;
                }
                for (i, &hits) in acc.method_counts.iter().enumerate() {
                    if hits > 0 {
                        bm_stmt.execute(params![data.period, bn, METHOD_NAMES[i], hits as i64])?;
                    }
                }
                for (i, &hits) in acc.protocol_counts.iter().enumerate() {
                    if hits > 0 {
                        bp_stmt.execute(params![data.period, bn, PROTO_NAMES[i], hits as i64])?;
                    }
                }

                // bucket_hourly_stats
                for (date, hours) in &acc.hourly {
                    for (&hour, &(hits, bw)) in hours {
                        tx.execute(
                            "INSERT INTO bucket_hourly_stats (bucket,date,hour,hits,bandwidth) \
                             VALUES (?1,?2,?3,?4,?5) \
                             ON CONFLICT (bucket,date,hour) DO UPDATE SET \
                               hits=hits+excluded.hits, bandwidth=bandwidth+excluded.bandwidth",
                            params![bn, date.as_ref(), hour as i64, hits as i64, bw as i64],
                        )?;
                    }
                }

                // bucket_daily_unique_ips (read-modify-write per bucket+date+ip group)
                for (date, bitmaps) in &acc.daily_ips {
                    if !bitmaps.v4.is_empty() {
                        let existing: Option<Vec<u8>> = tx
                            .query_row(
                                "SELECT bitmap FROM bucket_daily_unique_ips \
                                 WHERE bucket=?1 AND date=?2 AND ip_kind=1 AND ip_hi=0",
                                params![bn, date.as_ref()],
                                |r| r.get(0),
                            )
                            .optional()?;
                        let mut bm = match existing {
                            Some(blob) => deserialize_v4(&blob)?,
                            None => RoaringBitmap::new(),
                        };
                        bm |= &bitmaps.v4;
                        let count = bm.len() as i64;
                        tx.execute(
                            "INSERT OR REPLACE INTO bucket_daily_unique_ips \
                             (bucket,date,ip_kind,ip_hi,count,bitmap) VALUES (?1,?2,1,0,?3,?4)",
                            params![bn, date.as_ref(), count, serialize_v4(&bm)?],
                        )?;
                    }
                    for (hi, treemap) in &bitmaps.v6 {
                        if treemap.is_empty() { continue; }
                        let hi_i = *hi as i64;
                        let existing: Option<Vec<u8>> = tx
                            .query_row(
                                "SELECT bitmap FROM bucket_daily_unique_ips \
                                 WHERE bucket=?1 AND date=?2 AND ip_kind=2 AND ip_hi=?3",
                                params![bn, date.as_ref(), hi_i],
                                |r| r.get(0),
                            )
                            .optional()?;
                        let mut tm = match existing {
                            Some(blob) => deserialize_v6(&blob)?,
                            None => RoaringTreemap::new(),
                        };
                        tm |= treemap;
                        let count = tm.len() as i64;
                        tx.execute(
                            "INSERT OR REPLACE INTO bucket_daily_unique_ips \
                             (bucket,date,ip_kind,ip_hi,count,bitmap) VALUES (?1,?2,2,?3,?4,?5)",
                            params![bn, date.as_ref(), hi_i, count, serialize_v6(&tm)?],
                        )?;
                    }
                }

                // bucket_daily_response_time_histograms (read-modify-write per date)
                for (date, hist) in &acc.daily_hists {
                    let existing: Option<Vec<u8>> = tx
                        .query_row(
                            "SELECT data FROM bucket_daily_response_time_histograms \
                             WHERE bucket=?1 AND date=?2",
                            params![bn, date.as_ref()],
                            |r| r.get(0),
                        )
                        .optional()?;
                    let mut merged = match existing {
                        Some(blob) => ResponseTimeHistogram::deserialize(&blob)
                            .context("deserialize bucket daily rt histogram")?,
                        None => ResponseTimeHistogram::new(),
                    };
                    merged.merge(hist);
                    tx.execute(
                        "INSERT OR REPLACE INTO bucket_daily_response_time_histograms \
                         (bucket,date,data) VALUES (?1,?2,?3)",
                        params![bn, date.as_ref(), merged.serialize()],
                    )?;
                }
            }
        }

        // retired parse_states → archive
        if !data.retired_parse_states.is_empty() {
            let mut archive_stmt = tx.prepare_cached(
                "INSERT INTO parse_state_archive \
                 (filepath,inode,compressed_size,uncompressed_size,\
                  compressed_head_fingerprint,uncompressed_head_fingerprint,\
                  compressed_offset,uncompressed_offset,mtime_ns,completed,\
                  earliest_ts,latest_ts,skip_before_ts) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) \
                 ON CONFLICT (filepath,inode) DO UPDATE SET \
                   inode=?2, compressed_size=?3, uncompressed_size=?4, \
                   compressed_head_fingerprint=?5, uncompressed_head_fingerprint=?6, \
                   compressed_offset=?7, uncompressed_offset=?8, \
                   mtime_ns=?9, completed=?10, \
                   earliest_ts=COALESCE(?11,earliest_ts), \
                   latest_ts=COALESCE(?12,latest_ts), \
                   skip_before_ts=NULL",
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
                    s.earliest_ts,
                    s.latest_ts,
                    Option::<i64>::None,
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
                  compressed_offset,uncompressed_offset,mtime_ns,completed,\
                  earliest_ts,latest_ts,skip_before_ts) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) \
                 ON CONFLICT (filepath) DO UPDATE SET \
                   inode=?2, compressed_size=?3, uncompressed_size=?4, \
                   compressed_head_fingerprint=?5, uncompressed_head_fingerprint=?6, \
                   compressed_offset=?7, uncompressed_offset=?8, \
                   mtime_ns=?9, completed=?10, \
                   earliest_ts=COALESCE(?11,earliest_ts), \
                   latest_ts=COALESCE(?12,latest_ts), \
                   skip_before_ts=NULL",
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
                    s.earliest_ts,
                    s.latest_ts,
                    Option::<i64>::None,
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

        // Only update the period timestamp when actual log data was written.
        // Parse-state-only flushes (e.g. already-completed files carried as
        // pending_parse_states) must not advance the timestamp or stale-page
        // detection would incorrectly mark up-to-date HTML pages as stale.
        if !data.period.is_empty() && !data.hourly.is_empty() {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            tx.execute(
                "INSERT INTO period_last_updated (period, updated_at) VALUES (?1, ?2)
                 ON CONFLICT (period) DO UPDATE SET updated_at = excluded.updated_at",
                params![data.period, now],
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

        // ── Persist per-month bitmap snapshot ─────────────────────────────────
        if !monthly_v4.is_empty() {
            tx.execute(
                "INSERT OR REPLACE INTO monthly_unique_ips (period,ip_kind,ip_hi,bitmap) \
                 VALUES (?1,1,0,?2)",
                params![period, serialize_v4(&monthly_v4)?],
            )?;
        }
        for (hi, tm) in &monthly_v6 {
            if tm.is_empty() {
                continue;
            }
            tx.execute(
                "INSERT OR REPLACE INTO monthly_unique_ips (period,ip_kind,ip_hi,bitmap) \
                 VALUES (?1,2,?2,?3)",
                params![period, *hi as i64, serialize_v6(tm)?],
            )?;
        }

        // ── Recompute yearly count from all monthly snapshots for this year ───
        {
            let year_rows: Vec<(u8, u64, Vec<u8>)> = {
                let mut stmt = tx.prepare(
                    "SELECT ip_kind, ip_hi, bitmap FROM monthly_unique_ips \
                     WHERE period LIKE ?1",
                )?;
                let mapped = stmt.query_map(params![format!("{year}-%")], |row| {
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
            let mut yearly_v4 = RoaringBitmap::new();
            let mut yearly_v6: AHashMap<u64, RoaringTreemap> = AHashMap::new();
            or_bitmap_rows(year_rows, &mut yearly_v4, &mut yearly_v6)?;
            let yearly_count = bitmap_cardinality(&yearly_v4, &yearly_v6);
            tx.execute(
                "INSERT OR REPLACE INTO unique_visitor_counts (period, count) VALUES (?1, ?2)",
                params![year, yearly_count as i64],
            )?;
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

        // ── Per-bucket unique IP finalization ─────────────────────────────────
        {
            let bucket_names: Vec<String> = {
                let mut stmt = tx.prepare(
                    "SELECT DISTINCT bucket FROM bucket_daily_unique_ips WHERE date LIKE ?1",
                )?;
                let rows = stmt
                    .query_map(params![like_pattern], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                rows
            };
            for bn in &bucket_names {
                let daily_ip_rows: Vec<(u8, u64, Vec<u8>)> = {
                    let mut stmt = tx.prepare(
                        "SELECT ip_kind, ip_hi, bitmap FROM bucket_daily_unique_ips \
                         WHERE bucket=?1 AND date LIKE ?2",
                    )?;
                    let rows = stmt
                        .query_map(params![bn, like_pattern], |r| {
                            Ok((
                                r.get::<_, i64>(0)? as u8,
                                r.get::<_, i64>(1)? as u64,
                                r.get::<_, Vec<u8>>(2)?,
                            ))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    rows
                };
                let mut monthly_v4 = RoaringBitmap::new();
                let mut monthly_v6: AHashMap<u64, RoaringTreemap> = AHashMap::new();
                or_bitmap_rows(daily_ip_rows, &mut monthly_v4, &mut monthly_v6)?;
                let monthly_count = bitmap_cardinality(&monthly_v4, &monthly_v6);
                tx.execute(
                    "INSERT OR REPLACE INTO bucket_unique_visitor_counts \
                     (bucket,period,count) VALUES (?1,?2,?3)",
                    params![bn, period, monthly_count as i64],
                )?;
                // Save monthly bitmap snapshot so yearly counts can be computed correctly.
                if !monthly_v4.is_empty() {
                    tx.execute(
                        "INSERT OR REPLACE INTO bucket_monthly_unique_ips \
                         (bucket,period,ip_kind,ip_hi,bitmap) VALUES (?1,?2,1,0,?3)",
                        params![bn, period, serialize_v4(&monthly_v4)?],
                    )?;
                }
                for (hi, tm) in &monthly_v6 {
                    if tm.is_empty() {
                        continue;
                    }
                    tx.execute(
                        "INSERT OR REPLACE INTO bucket_monthly_unique_ips \
                         (bucket,period,ip_kind,ip_hi,bitmap) VALUES (?1,?2,2,?3,?4)",
                        params![bn, period, *hi as i64, serialize_v6(tm)?],
                    )?;
                }
                // Recompute yearly count by ORing all surviving monthly snapshots.
                {
                    let year_rows: Vec<(u8, u64, Vec<u8>)> = {
                        let mut stmt = tx.prepare(
                            "SELECT ip_kind, ip_hi, bitmap FROM bucket_monthly_unique_ips \
                             WHERE bucket=?1 AND period LIKE ?2",
                        )?;
                        let rows = stmt.query_map(params![bn, format!("{year}-%")], |r| {
                            Ok((
                                r.get::<_, i64>(0)? as u8,
                                r.get::<_, i64>(1)? as u64,
                                r.get::<_, Vec<u8>>(2)?,
                            ))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                        rows
                    };
                    let mut yearly_v4 = RoaringBitmap::new();
                    let mut yearly_v6: AHashMap<u64, RoaringTreemap> = AHashMap::new();
                    or_bitmap_rows(year_rows, &mut yearly_v4, &mut yearly_v6)?;
                    let yearly_count = bitmap_cardinality(&yearly_v4, &yearly_v6);
                    tx.execute(
                        "INSERT OR REPLACE INTO bucket_unique_visitor_counts \
                         (bucket,period,count) VALUES (?1,?2,?3)",
                        params![bn, year, yearly_count as i64],
                    )?;
                }
                tx.execute(
                    "INSERT OR REPLACE INTO bucket_daily_visitor_counts (bucket,date,count) \
                     SELECT bucket, date, SUM(count) \
                     FROM bucket_daily_unique_ips \
                     WHERE bucket=?1 AND date LIKE ?2 \
                     GROUP BY date",
                    params![bn, like_pattern],
                )?;
                tx.execute(
                    "DELETE FROM bucket_daily_unique_ips WHERE bucket=?1 AND date LIKE ?2",
                    params![bn, like_pattern],
                )?;
            }
        }

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

        if top_n > 0 {
            tx.execute(
                "DELETE FROM top_urls \
                 WHERE period=?1 \
                 AND url NOT IN (SELECT url FROM top_urls WHERE period=?1 ORDER BY hits DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_urls WHERE period=?1 ORDER BY bandwidth DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_urls WHERE period=?1 AND rt_count>0 ORDER BY rt_sum*1.0/rt_count DESC LIMIT ?2)",
                params![period, top_n as i64],
            )?;
        }

        if top_n > 0 {
            tx.execute(
                "DELETE FROM top_error_urls \
                 WHERE period=?1 \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY c400 DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY c401 DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY c403 DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY c404 DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY c422 DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY c429 DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY c4xx DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY c500 DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY c502 DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY c503 DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY c5xx DESC LIMIT ?2) \
                 AND url NOT IN (SELECT url FROM top_error_urls WHERE period=?1 ORDER BY bandwidth DESC LIMIT ?2)",
                params![period, top_n as i64],
            )?;
        }

        if top_n > 0 {
            tx.execute(
                "DELETE FROM top_ips \
                 WHERE period=?1 \
                 AND (host_kind,host_hi,host_lo) NOT IN (SELECT host_kind,host_hi,host_lo FROM top_ips WHERE period=?1 ORDER BY hits DESC LIMIT ?2) \
                 AND (host_kind,host_hi,host_lo) NOT IN (SELECT host_kind,host_hi,host_lo FROM top_ips WHERE period=?1 ORDER BY bandwidth DESC LIMIT ?2)",
                params![period, top_n as i64],
            )?;
        }

        Self::prune_monthly_table(&tx, "top_referrers", "referrer", period, "hits", top_n)?;

        if top_n > 0 {
            tx.execute(
                "DELETE FROM top_agents \
                 WHERE period=?1 \
                 AND agent_family NOT IN (SELECT agent_family FROM top_agents WHERE period=?1 ORDER BY hits DESC LIMIT ?2) \
                 AND agent_family NOT IN (SELECT agent_family FROM top_agents WHERE period=?1 ORDER BY bandwidth DESC LIMIT ?2)",
                params![period, top_n as i64],
            )?;
        }

        // ── Bucket daily RT: compute stats, delete daily histograms ──────────────
        {
            let buckets_with_daily_rt: Vec<String> = {
                let mut stmt = tx.prepare(
                    "SELECT DISTINCT bucket FROM bucket_daily_response_time_histograms \
                     WHERE date LIKE ?1",
                )?;
                let rows = stmt
                    .query_map(params![like_pattern], |r| r.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                rows
            };
            for bn in &buckets_with_daily_rt {
                let daily_rows: Vec<(String, Vec<u8>)> = {
                    let mut stmt = tx.prepare(
                        "SELECT date, data FROM bucket_daily_response_time_histograms \
                         WHERE bucket=?1 AND date LIKE ?2 ORDER BY date",
                    )?;
                    let rows = stmt
                        .query_map(params![bn, like_pattern], |r| {
                            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
                        })?
                        .collect::<rusqlite::Result<Vec<_>>>()?;
                    rows
                };
                for (date, blob) in &daily_rows {
                    let hist = ResponseTimeHistogram::deserialize(blob)
                        .context("deserialize bucket daily rt histogram in finalize_month")?;
                    if hist.count > 0 {
                        let avg_ms = hist.sum_ms as f64 / hist.count as f64;
                        let p95_ms = hist.percentile(95.0);
                        tx.execute(
                            "INSERT OR REPLACE INTO bucket_daily_response_time_stats \
                             (bucket,date,avg_ms,p95_ms) VALUES (?1,?2,?3,?4)",
                            params![bn, date, avg_ms, p95_ms as i64],
                        )?;
                    }
                }
                tx.execute(
                    "DELETE FROM bucket_daily_response_time_histograms \
                     WHERE bucket=?1 AND date LIKE ?2",
                    params![bn, like_pattern],
                )?;
            }
        }

        // Prune bucket_urls per (period, bucket) to top_n.
        if top_n > 0 {
            let bucket_names: Vec<String> = {
                let mut stmt = tx.prepare(
                    "SELECT DISTINCT bucket FROM bucket_period_stats WHERE period=?1",
                )?;
                let rows = stmt.query_map(params![period], |r| r.get::<_, String>(0))?;
                let mut names = Vec::new();
                for r in rows {
                    names.push(r?);
                }
                names
            };
            for bn in &bucket_names {
                tx.execute(
                    "DELETE FROM bucket_urls \
                     WHERE period=?1 AND bucket=?2 \
                     AND url NOT IN (SELECT url FROM bucket_urls WHERE period=?1 AND bucket=?2 ORDER BY hits DESC LIMIT ?3) \
                     AND url NOT IN (SELECT url FROM bucket_urls WHERE period=?1 AND bucket=?2 ORDER BY bandwidth DESC LIMIT ?3) \
                     AND url NOT IN (SELECT url FROM bucket_urls WHERE period=?1 AND bucket=?2 AND rt_count>0 ORDER BY rt_sum*1.0/rt_count DESC LIMIT ?3)",
                    params![period, bn, top_n as i64],
                )?;
            }
        }

        tx.execute(
            "INSERT INTO meta (key, value) VALUES (?1, '1') \
             ON CONFLICT (key) DO UPDATE SET value = '1'",
            params![format!("month_{}_complete", period)],
        )?;

        {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            tx.execute(
                "INSERT INTO period_last_updated (period, updated_at) VALUES (?1, ?2)
                 ON CONFLICT (period) DO UPDATE SET updated_at = excluded.updated_at",
                params![period, now],
            )?;
        }

        tx.commit()
            .context("Failed to commit finalize_month transaction")?;
        Ok(())
    }

    /// Finalize a completed year. The yearly unique-visitor count is already kept
    /// current in `unique_visitor_counts` by `finalize_month`, so this is a no-op.
    pub fn finalize_year(&mut self, _year: &str) -> Result<()> {
        Ok(())
    }

    /// Remove rows from top-N tables that have no realistic chance of reaching
    /// the top `top_n` by end of month. A row is culled when every tracked metric
    /// is below 1/10th of the current N-th-best value for that metric.
    /// Per-table guard: only runs when row count exceeds `top_n * CULL_THRESHOLD_FACTOR`.
    pub fn cull_period(&mut self, period: &str, top_n: usize) -> Result<()> {
        const CULL_THRESHOLD_FACTOR: usize = 50;
        const CULL_FRACTION: i64 = 10;

        if top_n == 0 {
            return Ok(());
        }
        let threshold = (top_n * CULL_THRESHOLD_FACTOR) as i64;
        let offset = (top_n - 1) as i64;
        let tx = self.conn.transaction()?;

        // ── top_urls ──────────────────────────────────────────────────────────
        {
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM top_urls WHERE period=?1",
                params![period],
                |r| r.get(0),
            )?;
            if count > threshold {
                let hits_nth: i64 = tx
                    .query_row(
                        "SELECT hits FROM top_urls WHERE period=?1 \
                         ORDER BY hits DESC LIMIT 1 OFFSET ?2",
                        params![period, offset],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                let bw_nth: i64 = tx
                    .query_row(
                        "SELECT bandwidth FROM top_urls WHERE period=?1 \
                         ORDER BY bandwidth DESC LIMIT 1 OFFSET ?2",
                        params![period, offset],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                let rt_nth: Option<f64> = tx
                    .query_row(
                        "SELECT rt_sum * 1.0 / rt_count FROM top_urls \
                         WHERE period=?1 AND rt_count > 0 \
                         ORDER BY rt_sum * 1.0 / rt_count DESC LIMIT 1 OFFSET ?2",
                        params![period, offset],
                        |r| r.get(0),
                    )
                    .optional()?;

                let hits_thresh = hits_nth / CULL_FRACTION;
                let bw_thresh = bw_nth / CULL_FRACTION;

                if let Some(rt) = rt_nth {
                    let rt_thresh = rt / CULL_FRACTION as f64;
                    tx.execute(
                        "DELETE FROM top_urls WHERE period=?1 \
                         AND hits < ?2 AND bandwidth < ?3 \
                         AND (CASE WHEN rt_count > 0 \
                                   THEN rt_sum * 1.0 / rt_count \
                                   ELSE 0.0 END) < ?4",
                        params![period, hits_thresh, bw_thresh, rt_thresh],
                    )?;
                } else {
                    tx.execute(
                        "DELETE FROM top_urls WHERE period=?1 \
                         AND hits < ?2 AND bandwidth < ?3",
                        params![period, hits_thresh, bw_thresh],
                    )?;
                }
            }
        }

        // ── top_error_urls ────────────────────────────────────────────────────
        {
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM top_error_urls WHERE period=?1",
                params![period],
                |r| r.get(0),
            )?;
            if count > threshold {
                let err_total = "c400+c401+c403+c404+c422+c429+c4xx+c500+c502+c503+c5xx";
                let err_nth: i64 = tx
                    .query_row(
                        &format!(
                            "SELECT {err_total} FROM top_error_urls WHERE period=?1 \
                             ORDER BY ({err_total}) DESC LIMIT 1 OFFSET ?2"
                        ),
                        params![period, offset],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                let bw_nth: i64 = tx
                    .query_row(
                        "SELECT bandwidth FROM top_error_urls WHERE period=?1 \
                         ORDER BY bandwidth DESC LIMIT 1 OFFSET ?2",
                        params![period, offset],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                tx.execute(
                    &format!(
                        "DELETE FROM top_error_urls WHERE period=?1 \
                         AND ({err_total}) < ?2 AND bandwidth < ?3"
                    ),
                    params![period, err_nth / CULL_FRACTION, bw_nth / CULL_FRACTION],
                )?;
            }
        }

        // ── top_ips ───────────────────────────────────────────────────────────
        {
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM top_ips WHERE period=?1",
                params![period],
                |r| r.get(0),
            )?;
            if count > threshold {
                let hits_nth: i64 = tx
                    .query_row(
                        "SELECT hits FROM top_ips WHERE period=?1 \
                         ORDER BY hits DESC LIMIT 1 OFFSET ?2",
                        params![period, offset],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                let bw_nth: i64 = tx
                    .query_row(
                        "SELECT bandwidth FROM top_ips WHERE period=?1 \
                         ORDER BY bandwidth DESC LIMIT 1 OFFSET ?2",
                        params![period, offset],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                tx.execute(
                    "DELETE FROM top_ips WHERE period=?1 AND hits < ?2 AND bandwidth < ?3",
                    params![period, hits_nth / CULL_FRACTION, bw_nth / CULL_FRACTION],
                )?;
            }
        }

        // ── top_referrers ─────────────────────────────────────────────────────
        {
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM top_referrers WHERE period=?1",
                params![period],
                |r| r.get(0),
            )?;
            if count > threshold {
                let hits_nth: i64 = tx
                    .query_row(
                        "SELECT hits FROM top_referrers WHERE period=?1 \
                         ORDER BY hits DESC LIMIT 1 OFFSET ?2",
                        params![period, offset],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                tx.execute(
                    "DELETE FROM top_referrers WHERE period=?1 AND hits < ?2",
                    params![period, hits_nth / CULL_FRACTION],
                )?;
            }
        }

        // ── top_agents ────────────────────────────────────────────────────────
        {
            let count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM top_agents WHERE period=?1",
                params![period],
                |r| r.get(0),
            )?;
            if count > threshold {
                let hits_nth: i64 = tx
                    .query_row(
                        "SELECT hits FROM top_agents WHERE period=?1 \
                         ORDER BY hits DESC LIMIT 1 OFFSET ?2",
                        params![period, offset],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                let bw_nth: i64 = tx
                    .query_row(
                        "SELECT bandwidth FROM top_agents WHERE period=?1 \
                         ORDER BY bandwidth DESC LIMIT 1 OFFSET ?2",
                        params![period, offset],
                        |r| r.get(0),
                    )
                    .optional()?
                    .unwrap_or(0);
                tx.execute(
                    "DELETE FROM top_agents WHERE period=?1 AND hits < ?2 AND bandwidth < ?3",
                    params![period, hits_nth / CULL_FRACTION, bw_nth / CULL_FRACTION],
                )?;
            }
        }

        // ── bucket_urls (per bucket) ──────────────────────────────────────────
        {
            let bucket_names: Vec<String> = {
                let mut stmt = tx.prepare(
                    "SELECT DISTINCT bucket FROM bucket_period_stats WHERE period=?1",
                )?;
                let rows = stmt.query_map(params![period], |r| r.get::<_, String>(0))?;
                let mut names = Vec::new();
                for r in rows { names.push(r?); }
                names
            };
            for bn in &bucket_names {
                let count: i64 = tx.query_row(
                    "SELECT COUNT(*) FROM bucket_urls WHERE period=?1 AND bucket=?2",
                    params![period, bn],
                    |r| r.get(0),
                )?;
                if count > threshold {
                    let hits_nth: i64 = tx
                        .query_row(
                            "SELECT hits FROM bucket_urls WHERE period=?1 AND bucket=?2 \
                             ORDER BY hits DESC LIMIT 1 OFFSET ?3",
                            params![period, bn, offset],
                            |r| r.get(0),
                        )
                        .optional()?
                        .unwrap_or(0);
                    let bw_nth: i64 = tx
                        .query_row(
                            "SELECT bandwidth FROM bucket_urls WHERE period=?1 AND bucket=?2 \
                             ORDER BY bandwidth DESC LIMIT 1 OFFSET ?3",
                            params![period, bn, offset],
                            |r| r.get(0),
                        )
                        .optional()?
                        .unwrap_or(0);
                    let rt_nth: Option<f64> = tx
                        .query_row(
                            "SELECT rt_sum * 1.0 / rt_count FROM bucket_urls \
                             WHERE period=?1 AND bucket=?2 AND rt_count > 0 \
                             ORDER BY rt_sum * 1.0 / rt_count DESC LIMIT 1 OFFSET ?3",
                            params![period, bn, offset],
                            |r| r.get(0),
                        )
                        .optional()?
                        .flatten();
                    let rt_filter = rt_nth.map(|n| n / CULL_FRACTION as f64).unwrap_or(0.0);
                    tx.execute(
                        "DELETE FROM bucket_urls \
                         WHERE period=?1 AND bucket=?2 \
                         AND hits < ?3 AND bandwidth < ?4 \
                         AND (rt_count = 0 OR rt_sum * 1.0 / rt_count < ?5)",
                        params![
                            period, bn,
                            hits_nth / CULL_FRACTION,
                            bw_nth / CULL_FRACTION,
                            rt_filter,
                        ],
                    )?;
                }
            }
        }

        tx.commit().context("Failed to commit cull_period transaction")?;
        Ok(())
    }

    fn prune_monthly_table(
        tx: &rusqlite::Transaction<'_>,
        table: &str,
        key_col: &str,
        period: &str,
        order_col: &str,
        top_n: usize,
    ) -> Result<()> {
        let sql = format!(
            "DELETE FROM {table} \
             WHERE period = ?1 \
             AND {key_col} NOT IN ( \
               SELECT {key_col} FROM {table} \
               WHERE period = ?1 \
               ORDER BY {order_col} DESC \
               LIMIT ?2 \
             )"
        );
        tx.execute(&sql, params![period, top_n as i64])?;
        Ok(())
    }
}
