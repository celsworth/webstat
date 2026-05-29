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
    tx.execute(
        "DELETE FROM hourly_stats WHERE date >= ?1",
        params![format!("{target_month}-01")],
    )?;
    tx.execute(
        "DELETE FROM daily_response_time_histograms WHERE date >= ?1",
        params![format!("{target_month}-01")],
    )?;
    tx.execute(
        "DELETE FROM daily_response_time_stats WHERE date >= ?1",
        params![format!("{target_month}-01")],
    )?;
    tx.execute(
        "DELETE FROM daily_visitor_counts WHERE date >= ?1",
        params![format!("{target_month}-01")],
    )?;
    tx.execute(
        "DELETE FROM daily_unique_ips WHERE date >= ?1",
        params![format!("{target_month}-01")],
    )?;

    // ── Monthly aggregated tables ─────────────────────────────────────────────
    for table in &[
        "top_urls",
        "top_ips",
        "top_referrers",
        "top_agents",
        "status_codes",
        "method_counts",
        "protocol_counts",
        "top_countries",
        "monthly_response_time_histograms",
    ] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE period >= ?1"),
            params![target_month],
        )?;
    }

    // ── Monthly bitmap snapshots ──────────────────────────────────────────────
    tx.execute(
        "DELETE FROM monthly_unique_ips WHERE period >= ?1",
        params![target_month],
    )?;

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
