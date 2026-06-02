// Rollback: delete all aggregated data from the start of a given month onward and
// reset parse state so the next ingest re-processes the affected files.

use anyhow::{bail, Context, Result};
use rusqlite::params;

use crate::database::Database;

/// Roll back all ingested data to the start of `target_month` (format "YYYY-MM").
///
/// Everything from the first second of that month onward is deleted from all
/// aggregated tables, visit state is trimmed, and parse state is reset for any
/// file whose `latest_ts` falls on or after the rollback boundary.
///
/// When `dry_run` is true the function prints what would be affected and returns
/// without writing anything.
pub fn rollback(db: &mut Database, target_month: &str, dry_run: bool) -> Result<()> {
    validate_month(target_month)?;

    let rollback_ts = month_start_unix(target_month)?;
    let year = &target_month[..4];
    let date_prefix = format!("{}-", target_month); // "YYYY-MM-"

    if dry_run {
        print_dry_run(db, target_month, rollback_ts, year, &date_prefix)?;
        return Ok(());
    }

    let conn = db.conn_mut();
    let tx = conn.transaction().context("begin rollback transaction")?;

    // ── Aggregated time-series data ───────────────────────────────────────────
    for table in &[
        "hourly_stats",
        "daily_response_time_histograms",
        "daily_response_time_stats",
        "daily_visitor_counts",
        "daily_unique_ips",
        "bucket_hourly_stats",
        "bucket_daily_response_time_histograms",
        "bucket_daily_response_time_stats",
        "bucket_daily_unique_ips",
        "bucket_daily_visitor_counts",
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE date >= ?1"),
            params![format!("{target_month}-01")],
        )?;
    }

    // ── Monthly aggregated tables ─────────────────────────────────────────────
    for table in &[
        "top_urls",
        "top_error_urls",
        "top_ips",
        "top_referrers",
        "top_agents",
        "status_codes",
        "method_counts",
        "protocol_counts",
        "top_countries",
        "monthly_response_time_histograms",
        "bucket_period_stats",
        "bucket_urls",
        "bucket_status_codes",
        "bucket_agents",
        "bucket_countries",
        "bucket_method_counts",
        "bucket_protocol_counts",
        "bucket_response_time_histograms",
        "monthly_unique_ips",
        "bucket_monthly_unique_ips",
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE period >= ?1"),
            params![target_month],
        )?;
    }

    // Prune URL strings no longer referenced by any surviving error-URL row.
    tx.execute(
        "DELETE FROM urls WHERE id NOT IN (SELECT DISTINCT url_id FROM top_error_urls)",
        [],
    )?;

    // bucket_unique_visitor_counts has both monthly ("YYYY-MM") and yearly ("YYYY")
    // entries that need separate handling.
    tx.execute(
        "DELETE FROM bucket_unique_visitor_counts WHERE length(period) = 7 AND period >= ?1",
        params![target_month],
    )?;
    tx.execute(
        "DELETE FROM bucket_unique_visitor_counts WHERE length(period) = 4 AND period >= ?1",
        params![year],
    )?;
    recompute_yearly_bucket_counts(&tx, year)?;

    // ── Unique visitor count cache ────────────────────────────────────────────
    // Delete monthly entries >= target_month and yearly entries for affected years.
    tx.execute(
        "DELETE FROM unique_visitor_counts WHERE length(period) = 7 AND period >= ?1",
        params![target_month],
    )?;
    tx.execute(
        "DELETE FROM unique_visitor_counts WHERE length(period) = 4 AND period >= ?1",
        params![year],
    )?;

    // Recompute yearly count for the partial year (year == YYYY and target month
    // is not January, so some earlier months in that year are still present).
    recompute_yearly_count(&tx, year)?;

    // ── Visit state ───────────────────────────────────────────────────────────
    tx.execute(
        "DELETE FROM visit_state WHERE last_seen_ts >= ?1",
        params![rollback_ts],
    )?;

    // ── Parse state reset ─────────────────────────────────────────────────────
    // Files entirely within the rollback range (earliest_ts >= rollback_ts): reset fully.
    // Files spanning the boundary (earliest_ts < rollback_ts, latest_ts >= rollback_ts):
    //   reset offsets to 0 and set skip_before_ts so the parser drops pre-rollback entries.
    // Files with NULL latest_ts (unknown range): reset conservatively with skip_before_ts.
    tx.execute(
        "UPDATE parse_state SET \
         compressed_offset = 0, uncompressed_offset = 0, completed = 0, \
         skip_before_ts = CASE \
           WHEN earliest_ts IS NOT NULL AND earliest_ts < ?1 THEN ?1 \
           WHEN earliest_ts IS NULL THEN ?1 \
           ELSE NULL \
         END \
         WHERE latest_ts >= ?1 OR latest_ts IS NULL",
        params![rollback_ts],
    )?;

    // Move matching archive entries back to parse_state with reset offsets.
    tx.execute(
        "INSERT OR REPLACE INTO parse_state \
         (filepath, inode, compressed_size, uncompressed_size, \
          compressed_head_fingerprint, uncompressed_head_fingerprint, \
          compressed_offset, uncompressed_offset, mtime_ns, completed, \
          earliest_ts, latest_ts, skip_before_ts) \
         SELECT filepath, inode, compressed_size, uncompressed_size, \
                compressed_head_fingerprint, uncompressed_head_fingerprint, \
                0, 0, mtime_ns, 0, \
                earliest_ts, latest_ts, \
                CASE \
                  WHEN earliest_ts IS NOT NULL AND earliest_ts < ?1 THEN ?1 \
                  WHEN earliest_ts IS NULL THEN ?1 \
                  ELSE NULL \
                END \
         FROM parse_state_archive \
         WHERE latest_ts >= ?1 OR latest_ts IS NULL",
        params![rollback_ts],
    )?;
    tx.execute(
        "DELETE FROM parse_state_archive WHERE latest_ts >= ?1 OR latest_ts IS NULL",
        params![rollback_ts],
    )?;

    // ── Meta ──────────────────────────────────────────────────────────────────
    // Delete month_complete markers for all months >= target_month.
    // SQLite doesn't support LIKE with a parameter in DELETE easily; use a subquery.
    tx.execute(
        "DELETE FROM meta \
         WHERE key LIKE 'month_%_complete' \
           AND substr(key, 7, 7) >= ?1",
        params![target_month],
    )?;
    // Reset current_month to the target month so that re-ingestion starts
    // accumulating into target_month directly. Setting it to prev_month would
    // cause finalize_month to be called for the already-finalized prev_month
    // during the next process run, which zeroes out its unique_visitor_counts.
    tx.execute(
        "INSERT INTO meta (key, value) VALUES ('current_month', ?1) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![target_month],
    )?;
    // Reset last_log_ts to one second before the rollback boundary.
    tx.execute(
        "INSERT INTO meta (key, value) VALUES ('last_log_ts', ?1) \
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        params![(rollback_ts - 1).to_string()],
    )?;

    tx.commit().context("commit rollback transaction")?;

    println!(
        "Rolled back to start of {target_month}. \
         Re-run 'webstat process' to re-ingest."
    );
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn validate_month(s: &str) -> Result<()> {
    if s.len() != 7 {
        bail!("--month must be in YYYY-MM format, got: {s}");
    }
    let (year, month) = s.split_once('-').unwrap();
    let y: u32 = year
        .parse()
        .with_context(|| format!("invalid year in {s}"))?;
    let m: u32 = month
        .parse()
        .with_context(|| format!("invalid month in {s}"))?;
    if y < 2000 || y > 2100 {
        bail!("year out of range in {s}");
    }
    if m < 1 || m > 12 {
        bail!("month out of range in {s}");
    }
    Ok(())
}

fn month_start_unix(month: &str) -> Result<i64> {
    // Parse YYYY-MM and return unix timestamp of midnight on the 1st.
    let year: i32 = month[..4]
        .parse()
        .with_context(|| format!("parse year from {month}"))?;
    let mon: u32 = month[5..7]
        .parse()
        .with_context(|| format!("parse month from {month}"))?;
    let days = crate::parser::days_from_civil(year, mon, 1);
    Ok(days * 86400)
}

/// Recompute and store the yearly unique-visitor count from surviving monthly
/// bitmap snapshots.  If no snapshots remain for the year the row is deleted.
fn recompute_yearly_count(tx: &rusqlite::Transaction<'_>, year: &str) -> Result<()> {
    use ahash::AHashMap;
    use roaring::{RoaringBitmap, RoaringTreemap};

    let rows: Vec<(u8, u64, Vec<u8>)> = {
        let mut stmt = tx.prepare(
            "SELECT ip_kind, ip_hi, bitmap FROM monthly_unique_ips WHERE period LIKE ?1",
        )?;
        let mapped = stmt.query_map(params![format!("{year}-%")], |row| {
            Ok((
                row.get::<_, i64>(0)? as u8,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })?;
        let mut v = Vec::new();
        for row in mapped {
            v.push(row?);
        }
        v
    };

    if rows.is_empty() {
        tx.execute(
            "DELETE FROM unique_visitor_counts WHERE period = ?1",
            params![year],
        )?;
        return Ok(());
    }

    let mut v4 = RoaringBitmap::new();
    let mut v6: AHashMap<u64, RoaringTreemap> = AHashMap::new();
    for (kind, hi, blob) in rows {
        match kind {
            1 => {
                v4 |= RoaringBitmap::deserialize_from(&blob[..])
                    .context("deserialize monthly v4 bitmap")?
            }
            2 => {
                *v6.entry(hi).or_default() |=
                    RoaringTreemap::deserialize_from(&blob[..])
                        .context("deserialize monthly v6 bitmap")?
            }
            _ => {}
        }
    }
    let count = v4.len() + v6.values().map(|t| t.len()).sum::<u64>();
    tx.execute(
        "INSERT OR REPLACE INTO unique_visitor_counts (period, count) VALUES (?1, ?2)",
        params![year, count as i64],
    )?;
    Ok(())
}

/// Recompute yearly bucket unique-visitor counts from surviving monthly snapshots.
/// Iterates over all buckets that have snapshots for the year; deletes stale
/// yearly entries for buckets that have none remaining.
fn recompute_yearly_bucket_counts(tx: &rusqlite::Transaction<'_>, year: &str) -> Result<()> {
    use ahash::AHashMap;
    use roaring::{RoaringBitmap, RoaringTreemap};

    // Find all buckets that still have monthly snapshots for this year.
    let buckets: Vec<String> = {
        let mut stmt = tx.prepare(
            "SELECT DISTINCT bucket FROM bucket_monthly_unique_ips WHERE period LIKE ?1",
        )?;
        let rows = stmt.query_map(params![format!("{year}-%")], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };

    // Delete all existing yearly entries for this year so we start clean.
    tx.execute(
        "DELETE FROM bucket_unique_visitor_counts WHERE length(period)=4 AND period=?1",
        params![year],
    )?;

    for bn in &buckets {
        let rows: Vec<(u8, u64, Vec<u8>)> = {
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
        if rows.is_empty() {
            continue;
        }
        let mut v4 = RoaringBitmap::new();
        let mut v6: AHashMap<u64, RoaringTreemap> = AHashMap::new();
        for (kind, hi, blob) in rows {
            match kind {
                1 => {
                    v4 |= RoaringBitmap::deserialize_from(&blob[..])
                        .context("deserialize bucket monthly v4 bitmap")?
                }
                2 => {
                    *v6.entry(hi).or_default() |=
                        RoaringTreemap::deserialize_from(&blob[..])
                            .context("deserialize bucket monthly v6 bitmap")?
                }
                _ => {}
            }
        }
        let count = v4.len() + v6.values().map(|t| t.len()).sum::<u64>();
        tx.execute(
            "INSERT OR REPLACE INTO bucket_unique_visitor_counts \
             (bucket,period,count) VALUES (?1,?2,?3)",
            params![bn, year, count as i64],
        )?;
    }
    Ok(())
}

fn print_dry_run(
    db: &mut Database,
    target_month: &str,
    rollback_ts: i64,
    year: &str,
    _date_prefix: &str,
) -> Result<()> {
    let conn = db.conn_ref();

    let hourly_rows: i64 = conn.query_row(
        "SELECT COUNT(*) FROM hourly_stats WHERE date >= ?1",
        params![format!("{target_month}-01")],
        |r| r.get(0),
    )?;
    let monthly_url_rows: i64 = conn.query_row(
        "SELECT COUNT(*) FROM top_urls WHERE period >= ?1",
        params![target_month],
        |r| r.get(0),
    )?;
    let visit_rows: i64 = conn.query_row(
        "SELECT COUNT(*) FROM visit_state WHERE last_seen_ts >= ?1",
        params![rollback_ts],
        |r| r.get(0),
    )?;
    let ps_rows: i64 = conn.query_row(
        "SELECT COUNT(*) FROM parse_state WHERE latest_ts >= ?1 OR latest_ts IS NULL",
        params![rollback_ts],
        |r| r.get(0),
    )?;
    let psa_rows: i64 = conn.query_row(
        "SELECT COUNT(*) FROM parse_state_archive WHERE latest_ts >= ?1 OR latest_ts IS NULL",
        params![rollback_ts],
        |r| r.get(0),
    )?;
    let monthly_bitmaps: i64 = conn.query_row(
        "SELECT COUNT(*) FROM monthly_unique_ips WHERE period >= ?1",
        params![target_month],
        |r| r.get(0),
    )?;

    println!("Dry run — rollback to start of {target_month} (unix ts {rollback_ts})");
    println!("  hourly_stats rows to delete:         {hourly_rows}");
    println!("  top_urls rows to delete:     {monthly_url_rows}");
    println!("  monthly_unique_ips rows to delete:   {monthly_bitmaps}");
    println!("  visit_state rows to delete:          {visit_rows}");
    println!("  parse_state entries to reset:        {ps_rows}");
    println!("  parse_state_archive entries to move: {psa_rows}");
    println!("  yearly count for {year} will be recomputed from remaining months");
    println!("Run without --dry-run to apply.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use rusqlite::OptionalExtension;

    use crate::ip::{Ip, IpBitmaps};
    use crate::database::Database;
    use crate::run_accumulators::BucketAcc;
    use crate::method_proto::{METHOD_COUNT, PROTO_COUNT};

    fn open_db() -> Database {
        Database::open(":memory:").expect("open in-memory db")
    }

    fn flush_bucket_with_ips(db: &mut Database, period: &str, bucket: &str, date: &str, ips: Vec<Ip>) {
        let mut bm = IpBitmaps::default();
        for ip in ips {
            bm.insert(ip);
        }
        let mut daily_ips = ahash::AHashMap::new();
        daily_ips.insert(Arc::from(date), bm);
        let mut buckets = ahash::AHashMap::new();
        buckets.insert(
            Arc::from(bucket),
            BucketAcc { hits: 1, daily_ips, ..Default::default() },
        );
        db.flush(crate::database::writer::FlushData {
            period,
            hourly: &ahash::AHashMap::new(),
            url_stats: &ahash::AHashMap::new(),
            error_urls: &ahash::AHashMap::new(),
            hosts: &ahash::AHashMap::new(),
            host_geo: &ahash::AHashMap::new(),
            refs: &ahash::AHashMap::new(),
            agents: &ahash::AHashMap::new(),
            daily_ips: &ahash::AHashMap::new(),
            daily_hists: &ahash::AHashMap::new(),
            countries: &ahash::AHashMap::new(),
            status_codes: &ahash::AHashMap::new(),
            method_counts: &[0u64; METHOD_COUNT],
            protocol_counts: &[0u64; PROTO_COUNT],
            bucket_stats: &buckets,
            parse_states: &[],
            retired_parse_states: &[],
            visit_states: &[],
            visit_state_prune_before_ts: None,
        })
        .expect("flush");
    }

    fn bucket_yearly_count(db: &Database, year: &str, bucket: &str) -> Option<i64> {
        db.conn_ref()
            .query_row(
                "SELECT count FROM bucket_unique_visitor_counts WHERE bucket=?1 AND period=?2",
                rusqlite::params![bucket, year],
                |r| r.get(0),
            )
            .optional()
            .expect("query")
    }

    fn bucket_monthly_snapshot_rows(db: &Database, period: &str, bucket: &str) -> i64 {
        db.conn_ref()
            .query_row(
                "SELECT COUNT(*) FROM bucket_monthly_unique_ips WHERE period=?1 AND bucket=?2",
                rusqlite::params![period, bucket],
                |r| r.get(0),
            )
            .expect("snapshot count")
    }

    #[test]
    fn rollback_removes_bucket_monthly_snapshots_from_target_month() {
        let mut db = open_db();
        flush_bucket_with_ips(&mut db, "2026-04", "api", "2026-04-01", vec![Ip::V4(0x01010101)]);
        db.finalize_month("2026-04", 10).expect("finalize apr");
        flush_bucket_with_ips(&mut db, "2026-05", "api", "2026-05-01", vec![Ip::V4(0x02020202)]);
        db.finalize_month("2026-05", 10).expect("finalize may");

        super::rollback(&mut db, "2026-05", false).expect("rollback");

        assert_eq!(
            bucket_monthly_snapshot_rows(&db, "2026-05", "api"),
            0,
            "May snapshot must be deleted"
        );
        assert!(
            bucket_monthly_snapshot_rows(&db, "2026-04", "api") > 0,
            "April snapshot must survive"
        );
    }

    #[test]
    fn rollback_recomputes_bucket_yearly_count_from_surviving_months() {
        let mut db = open_db();
        let ip_jan = Ip::V4(0x01010101);
        let ip_feb = Ip::V4(0x02020202);
        let ip_mar = Ip::V4(0x03030303);

        flush_bucket_with_ips(&mut db, "2026-01", "api", "2026-01-01", vec![ip_jan]);
        db.finalize_month("2026-01", 10).expect("finalize jan");
        flush_bucket_with_ips(&mut db, "2026-02", "api", "2026-02-01", vec![ip_feb]);
        db.finalize_month("2026-02", 10).expect("finalize feb");
        flush_bucket_with_ips(&mut db, "2026-03", "api", "2026-03-01", vec![ip_mar]);
        db.finalize_month("2026-03", 10).expect("finalize mar");

        // Before rollback: yearly count is 3.
        assert_eq!(bucket_yearly_count(&db, "2026", "api"), Some(3));

        // Roll back March — yearly should drop to 2.
        super::rollback(&mut db, "2026-03", false).expect("rollback");

        assert_eq!(
            bucket_yearly_count(&db, "2026", "api"),
            Some(2),
            "yearly count must be recomputed from Jan+Feb after rolling back March"
        );
    }

    #[test]
    fn rollback_removes_bucket_yearly_count_when_all_months_gone() {
        let mut db = open_db();
        flush_bucket_with_ips(&mut db, "2026-05", "api", "2026-05-01", vec![Ip::V4(0xAAAAAAAA)]);
        db.finalize_month("2026-05", 10).expect("finalize");

        assert_eq!(bucket_yearly_count(&db, "2026", "api"), Some(1));

        super::rollback(&mut db, "2026-05", false).expect("rollback");

        assert_eq!(
            bucket_yearly_count(&db, "2026", "api"),
            None,
            "yearly entry must be absent when no monthly snapshots remain"
        );
    }

    #[test]
    fn rollback_preserves_bucket_yearly_count_for_earlier_year() {
        let mut db = open_db();
        flush_bucket_with_ips(&mut db, "2025-12", "api", "2025-12-01", vec![Ip::V4(0x01010101)]);
        db.finalize_month("2025-12", 10).expect("finalize 2025-12");
        flush_bucket_with_ips(&mut db, "2026-01", "api", "2026-01-01", vec![Ip::V4(0x02020202)]);
        db.finalize_month("2026-01", 10).expect("finalize 2026-01");

        super::rollback(&mut db, "2026-01", false).expect("rollback");

        assert_eq!(
            bucket_yearly_count(&db, "2025", "api"),
            Some(1),
            "2025 yearly count must be untouched by a 2026 rollback"
        );
    }
}
