// Report aggregation: SQL queries that summarise the database into per-period statistics for templates.

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

use roaring::{RoaringBitmap, RoaringTreemap};

use anyhow::{Context, Result};
use chrono::{Datelike, NaiveDate, Weekday};
use rusqlite::{params, Connection, OptionalExtension};

use crate::response_time::ResponseTimeHistogram;

use super::{
    count_fmt, flag_emoji, format_bytes, format_ms, format_totals, month_name, percent_str,
    status_label, BucketIndexRow, BucketPageData, DailyAvgMax, DailyRow, DailyRtStat, ErrorUrlRow,
    HeatCell, HourlyAvgMax, HourlyRow, MethodRow, MonthRow, MonthlyRtStat, MonthlySummary,
    OverallSummary, PeriodMonth, ProtoRow, StatusRow, TopAgentRow, TopCountryRow, TopHostRow,
    TopRefRow, TopUrlRow, TotalsView, WeekdayRow, YearAggregateRow, YearlySummary,
};

// Returns ("= ?1", period) for monthly (7-char) periods, ("LIKE ?1", "YYYY-%") for yearly.
fn period_clause(period: &str) -> (&'static str, String) {
    if period.len() == 7 {
        ("= ?1", period.to_string())
    } else {
        ("LIKE ?1", format!("{}-%", period))
    }
}

/// Returns (total_hits, total_bandwidth) for a period from hourly_stats.
/// Works for both monthly ("YYYY-MM") and yearly ("YYYY") periods.
fn period_hits_bw_totals(conn: &Connection, period: &str) -> Result<(f64, f64)> {
    let mut stmt = conn.prepare(
        "SELECT COALESCE(SUM(hits), 0), COALESCE(SUM(bandwidth), 0)
         FROM hourly_stats
         WHERE date LIKE ?1",
    )?;
    let (hits, bw) = stmt.query_row(params![format!("{period}-%")], |row| {
        Ok((row.get::<_, i64>(0)? as f64, row.get::<_, i64>(1)? as f64))
    })?;
    Ok((hits, bw))
}

/// Returns (total_hits, total_bandwidth) across all time from hourly_stats.
fn all_time_hits_bw_totals(conn: &Connection) -> Result<(f64, f64)> {
    let mut stmt = conn.prepare(
        "SELECT COALESCE(SUM(hits), 0), COALESCE(SUM(bandwidth), 0) FROM hourly_stats",
    )?;
    let (hits, bw) = stmt.query_row([], |row| {
        Ok((row.get::<_, i64>(0)? as f64, row.get::<_, i64>(1)? as f64))
    })?;
    Ok((hits, bw))
}

fn build_status_rows(raw: Vec<(u16, u64)>, compact_counts: bool, total: f64) -> Vec<StatusRow> {
    raw.into_iter()
        .map(|(status, hits)| StatusRow {
            status,
            label: status_label(status),
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, total),
        })
        .collect()
}

fn or_into_bitmaps(
    rows: Vec<(u8, u64, Vec<u8>)>,
    label: &str,
    v4: &mut RoaringBitmap,
    v6: &mut HashMap<u64, RoaringTreemap>,
) -> Result<()> {
    for (kind, hi, blob) in rows {
        match kind {
            1 => {
                *v4 |= RoaringBitmap::deserialize_from(&blob[..])
                    .with_context(|| format!("deserialize {label} v4"))?;
            }
            2 => {
                *v6.entry(hi).or_default() |= RoaringTreemap::deserialize_from(&blob[..])
                    .with_context(|| format!("deserialize {label} v6"))?;
            }
            _ => {}
        }
    }
    Ok(())
}

pub(super) fn available_years(conn: &Connection) -> Result<Vec<i32>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT substr(date, 1, 4) AS yr
         FROM hourly_stats
         ORDER BY yr DESC",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
    let mut years = Vec::new();
    for yr in rows {
        years.push(yr?.parse::<i32>().unwrap_or(0));
    }
    years.retain(|y| *y > 0);
    Ok(years)
}

pub(super) fn available_months(conn: &Connection) -> Result<Vec<PeriodMonth>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT substr(date, 1, 7) AS ym
         FROM hourly_stats
         ORDER BY ym",
    )?;
    let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;

    let mut out = Vec::new();
    for ym in rows {
        let ym = ym?;
        let parts: Vec<&str> = ym.split('-').collect();
        if parts.len() != 2 {
            continue;
        }

        let Ok(year) = parts[0].parse::<i32>() else {
            continue;
        };
        let Ok(month) = parts[1].parse::<u32>() else {
            continue;
        };

        out.push(PeriodMonth {
            path: format!("{year}/{month:02}"),
            year,
            month,
            month_name: month_name(month).to_string(),
            period: ym,
        });
    }

    Ok(out)
}

pub(super) fn monthly_summary(
    conn: &Connection,
    year: i32,
    month: i32,
    top_n: usize,
    compact_counts: bool,
    anonymise_ips: bool,
) -> Result<MonthlySummary> {
    let period = format!("{year:04}-{month:02}");

    let daily = daily_stats(conn, year, month, compact_counts)?;
    let hourly = hourly_distribution(conn, year, month, compact_counts)?;
    let mut totals = monthly_totals(conn, year, month, compact_counts)?;
    if let Some((avg, p95)) = monthly_rt(conn, &period)? {
        totals.avg_rt_ms = Some(format_ms(avg));
        totals.p95_rt_ms = Some(format_ms(p95 as f64));
    }

    let top_urls = top_urls_union(conn, &period, top_n, compact_counts)?;
    let top_error_urls = top_error_urls_period(conn, &period, top_n, compact_counts)?;
    let top_ips = top_ips_union(conn, &period, top_n, compact_counts, anonymise_ips)?;
    let top_refs = top_refs(conn, &period, top_n, compact_counts)?;
    let top_agents = top_agents_union(conn, &period, top_n, compact_counts)?;
    let top_countries = top_countries_union(conn, &period, top_n, compact_counts)?;

    let status_codes = status_codes(conn, &period, compact_counts)?;
    let proto_codes = proto_codes(conn, &period, compact_counts)?;
    let method_codes = method_codes(conn, &period, compact_counts)?;
    let daily_avg_max = daily_avg_max_from_rows(&daily, compact_counts);
    let hourly_avg_max = hourly_avg_max(conn, year, month, compact_counts)?;
    let daily_rt_stats = daily_rt_stats_for_month(conn, year, month)?;
    let rt_distribution_buckets = monthly_rt_histogram_buckets(conn, &period)?;
    let buckets = bucket_index_rows(conn, &period, compact_counts)?;
    let weekday_hour = weekday_hour_grid(conn, &format!("{period}-%"), compact_counts)?;

    Ok(MonthlySummary {
        period,
        year,
        month_name: month_name(month as u32).to_string(),
        daily,
        hourly,
        totals,
        top_urls,
        top_error_urls,
        top_ips,
        top_refs,
        top_agents,
        top_countries,
        status_codes,
        proto_codes,
        method_codes,
        daily_avg_max,
        hourly_avg_max,
        daily_rt_stats,
        rt_distribution_buckets,
        buckets,
        weekday_hour,
    })
}

pub(super) fn yearly_summary(
    conn: &Connection,
    year: i32,
    top_n: usize,
    compact_counts: bool,
    anonymise_ips: bool,
) -> Result<YearlySummary> {
    let period = year.to_string();
    let monthly_rows = monthly_rows(conn, year, compact_counts)?;
    let mut totals = yearly_totals(conn, year, compact_counts)?;
    if let Some((avg, p95)) = yearly_rt(conn, year)? {
        totals.avg_rt_ms = Some(format_ms(avg));
        totals.p95_rt_ms = Some(format_ms(p95 as f64));
    }

    let top_urls = top_urls_union(conn, &period, top_n, compact_counts)?;
    let top_error_urls = top_error_urls_period(conn, &period, top_n, compact_counts)?;
    let top_ips = top_ips_union(conn, &period, top_n, compact_counts, anonymise_ips)?;
    let top_refs = top_refs(conn, &period, top_n, compact_counts)?;
    let top_agents = top_agents_union(conn, &period, top_n, compact_counts)?;
    let top_countries = top_countries_union(conn, &period, top_n, compact_counts)?;

    let status_codes = status_codes(conn, &period, compact_counts)?;
    let proto_codes = proto_codes(conn, &period, compact_counts)?;
    let method_codes = method_codes(conn, &period, compact_counts)?;
    let monthly_rt_stats = monthly_rt_stats_for_year(conn, year)?;
    let buckets = bucket_index_rows(conn, &period, compact_counts)?;
    let weekday_hour = weekday_hour_grid(conn, &format!("{period}-%"), compact_counts)?;

    Ok(YearlySummary {
        year,
        monthly_rows,
        top_urls,
        top_error_urls,
        top_ips,
        top_refs,
        top_agents,
        top_countries,
        status_codes,
        proto_codes,
        method_codes,
        totals,
        monthly_rt_stats,
        buckets,
        weekday_hour,
    })
}

pub(super) fn overall_summary(
    conn: &Connection,
    top_n: usize,
    compact_counts: bool,
) -> Result<OverallSummary> {
    let yearly_rows = yearly_rows(conn, compact_counts)?;
    let totals = overall_totals(conn, compact_counts)?;

    let top_error_urls = top_error_urls_all(conn, top_n, compact_counts)?;
    let top_agents = top_agents_union_all(conn, top_n, compact_counts)?;
    let top_countries = top_countries_union_all(conn, top_n, compact_counts)?;

    let status_codes = status_codes_all(conn, compact_counts)?;
    let all_time_available = all_time_visitor_count(conn)? > 0;
    // All-time heatmap: "%" matches every date in hourly_stats.
    let weekday_hour = weekday_hour_grid(conn, "%", compact_counts)?;

    Ok(OverallSummary {
        yearly_rows,
        top_error_urls,
        top_agents,
        top_countries,
        status_codes,
        totals,
        all_time_available,
        weekday_hour,
    })
}

fn daily_stats(
    conn: &Connection,
    year: i32,
    month: i32,
    compact_counts: bool,
) -> Result<Vec<DailyRow>> {
    let prefix = format!("{year:04}-{month:02}");
    let like = format!("{prefix}-%");

    // Batch-fetch daily IP counts: live bitmap rows for the current month (SUM of per-group
    // cardinalities stored in the count column), cached rows for pruned months.
    let mut ip_stmt = conn.prepare(
        "SELECT date, SUM(count) FROM daily_unique_ips WHERE date LIKE ?1 GROUP BY date
         UNION ALL
         SELECT date, count FROM daily_visitor_counts WHERE date LIKE ?1
           AND date NOT IN (SELECT DISTINCT date FROM daily_unique_ips WHERE date LIKE ?1)",
    )?;
    let ip_rows = ip_stmt.query_map(params![like], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })?;
    let mut daily_visitors: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for row in ip_rows {
        let (date, count) = row?;
        daily_visitors.insert(date, count);
    }

    let mut stmt = conn.prepare(
        "SELECT date,
                SUM(hits) AS hits,
                SUM(visits) AS visits,
                SUM(bandwidth) AS bandwidth
         FROM hourly_stats
         WHERE date LIKE ?1
         GROUP BY date
         ORDER BY date",
    )?;

    let mut rows = stmt.query_map(params![like], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, i64>(2)? as u64,
            row.get::<_, i64>(3)? as u64,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows.by_ref() {
        let (date, hits, visits, bandwidth) = row?;
        let visitors = daily_visitors.get(&date).copied().unwrap_or(0);
        out.push(DailyRow {
            is_weekend: is_weekend_date(&date),
            date,
            hits,
            visits,
            visitors,
            bandwidth,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            visits_fmt: count_fmt(visits, compact_counts),
            visits_exact_fmt: super::number_fmt(visits),
            visitors_fmt: count_fmt(visitors, compact_counts),
            visitors_exact_fmt: super::number_fmt(visitors),
            bandwidth_fmt: format_bytes(bandwidth),
        });
    }

    Ok(out)
}

fn is_weekend_date(date: &str) -> bool {
    NaiveDate::parse_from_str(date, "%Y-%m-%d")
        .map(|d| matches!(d.weekday(), Weekday::Sat | Weekday::Sun))
        .unwrap_or(false)
}

fn hourly_distribution(
    conn: &Connection,
    year: i32,
    month: i32,
    compact_counts: bool,
) -> Result<Vec<HourlyRow>> {
    let prefix = format!("{year:04}-{month:02}");

    let mut stmt = conn.prepare(
        "SELECT hour,
                SUM(hits) AS hits,
                SUM(visits) AS visits,
                SUM(bandwidth) AS bandwidth
         FROM hourly_stats
         WHERE date LIKE ?1
         GROUP BY hour
         ORDER BY hour",
    )?;

    let rows = stmt.query_map(params![format!("{prefix}-%")], |row| {
        Ok((
            row.get::<_, i64>(0)? as u8,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, i64>(2)? as u64,
            row.get::<_, i64>(3)? as u64,
        ))
    })?;

    let mut by_hour = BTreeMap::<u8, (u64, u64, u64)>::new();
    for row in rows {
        let (hour, hits, visits, bandwidth) = row?;
        by_hour.insert(hour, (hits, visits, bandwidth));
    }

    let mut out = Vec::with_capacity(24);
    for hour in 0u8..24u8 {
        let (hits, visits, bandwidth) = by_hour.get(&hour).copied().unwrap_or((0, 0, 0));
        out.push(HourlyRow {
            hour,
            label: format!("{hour:02}:00"),
            hits,
            visits,
            bandwidth,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            visits_fmt: count_fmt(visits, compact_counts),
            visits_exact_fmt: super::number_fmt(visits),
            bandwidth_fmt: format_bytes(bandwidth),
        });
    }

    Ok(out)
}

/// Build a weekday (Mon–Sun) × hour (0–23) heatmap of hits for a period.
///
/// `date_like` is a `LIKE` pattern over `hourly_stats.date` (e.g. `"2026-05-%"`
/// for a month or `"2026-%"` for a year). Each cell's `intensity` is its hit
/// count divided by the busiest cell, giving a 0.0–1.0 colour scale. Returns an
/// empty vec when the period has no traffic, so the template can hide the panel.
fn weekday_hour_grid(
    conn: &Connection,
    date_like: &str,
    compact_counts: bool,
) -> Result<Vec<WeekdayRow>> {
    let mut stmt = conn.prepare(
        "SELECT date, hour, SUM(hits)
         FROM hourly_stats
         WHERE date LIKE ?1
         GROUP BY date, hour",
    )?;
    let rows = stmt.query_map(params![date_like], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)? as usize,
            row.get::<_, i64>(2)? as u64,
        ))
    })?;

    // grid[weekday 0=Mon..6=Sun][hour 0..23]
    let mut grid = [[0u64; 24]; 7];
    let mut max_hits = 0u64;
    for row in rows {
        let (date, hour, hits) = row?;
        if hour >= 24 {
            continue;
        }
        let Ok(d) = NaiveDate::parse_from_str(&date, "%Y-%m-%d") else {
            continue;
        };
        let wd = d.weekday().num_days_from_monday() as usize;
        grid[wd][hour] += hits;
        max_hits = max_hits.max(grid[wd][hour]);
    }

    if max_hits == 0 {
        return Ok(Vec::new());
    }

    const LABELS: [&str; 7] = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
    let out = grid
        .iter()
        .enumerate()
        .map(|(wd, hours)| {
            let cells = hours
                .iter()
                .map(|&hits| HeatCell {
                    hits,
                    hits_fmt: count_fmt(hits, compact_counts),
                    intensity: hits as f64 / max_hits as f64,
                })
                .collect();
            WeekdayRow {
                label: LABELS[wd].to_string(),
                cells,
            }
        })
        .collect();
    Ok(out)
}

fn monthly_totals(
    conn: &Connection,
    year: i32,
    month: i32,
    compact_counts: bool,
) -> Result<TotalsView> {
    let prefix = format!("{year:04}-{month:02}");
    let mut stmt = conn.prepare(
        "SELECT COALESCE(SUM(hits), 0),
                COALESCE(SUM(visits), 0),
                COALESCE(SUM(bandwidth), 0)
         FROM hourly_stats
         WHERE date LIKE ?1",
    )?;

    let row = stmt.query_row(params![format!("{prefix}-%")], |row| {
        Ok((
            row.get::<_, i64>(0)? as u64,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, i64>(2)? as u64,
        ))
    })?;

    let visitors = monthly_visitor_count(conn, &prefix)?;

    Ok(format_totals(row.0, row.1, visitors, row.2, compact_counts))
}

fn yearly_totals(conn: &Connection, year: i32, compact_counts: bool) -> Result<TotalsView> {
    let mut stmt = conn.prepare(
        "SELECT COALESCE(SUM(hits), 0),
                COALESCE(SUM(visits), 0),
                COALESCE(SUM(bandwidth), 0)
         FROM hourly_stats
         WHERE date LIKE ?1",
    )?;

    let row = stmt.query_row(params![format!("{year}-%")], |row| {
        Ok((
            row.get::<_, i64>(0)? as u64,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, i64>(2)? as u64,
        ))
    })?;

    let visitors = yearly_visitor_count(conn, &year.to_string())?;

    Ok(format_totals(row.0, row.1, visitors, row.2, compact_counts))
}

fn monthly_rows(conn: &Connection, year: i32, compact_counts: bool) -> Result<Vec<MonthRow>> {
    // Pre-fetch all cached monthly visitor counts for the year in one query.
    let visitor_cache: HashMap<String, u64> = {
        let mut stmt = conn.prepare(
            "SELECT period, count FROM unique_visitor_counts WHERE period LIKE ?1",
        )?;
        let rows = stmt.query_map(params![format!("{year}-%")], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        let mut m = HashMap::new();
        for row in rows {
            let (k, v) = row?;
            m.insert(k, v);
        }
        m
    };

    let mut stmt = conn.prepare(
        "SELECT substr(date, 1, 7) AS ym,
                SUM(hits) AS hits,
                SUM(visits) AS visits,
                SUM(bandwidth) AS bandwidth
         FROM hourly_stats
         WHERE date LIKE ?1
         GROUP BY ym
         ORDER BY ym",
    )?;

    let rows = stmt.query_map(params![format!("{year}-%")], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, i64>(2)? as u64,
            row.get::<_, i64>(3)? as u64,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (ym, hits, visits, bandwidth) = row?;
        let visitors = if let Some(&v) = visitor_cache.get(&ym) {
            v
        } else {
            or_count_daily_bitmaps(conn, &format!("{ym}-%"))?
        };
        let month = ym
            .split('-')
            .nth(1)
            .and_then(|m| m.parse::<u32>().ok())
            .unwrap_or(1);

        out.push(MonthRow {
            period: ym,
            month,
            month_str: format!("{month:02}"),
            month_name: month_name(month).to_string(),
            hits,
            visits,
            visitors,
            bandwidth,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            visits_fmt: count_fmt(visits, compact_counts),
            visits_exact_fmt: super::number_fmt(visits),
            visitors_fmt: count_fmt(visitors, compact_counts),
            visitors_exact_fmt: super::number_fmt(visitors),
            bandwidth_fmt: format_bytes(bandwidth),
        });
    }

    Ok(out)
}

fn yearly_rows(conn: &Connection, compact_counts: bool) -> Result<Vec<YearAggregateRow>> {
    // Pre-fetch all cached yearly visitor counts in one query.
    let visitor_cache: HashMap<String, u64> = {
        let mut stmt = conn.prepare(
            "SELECT period, count FROM unique_visitor_counts WHERE length(period) = 4",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        let mut m = HashMap::new();
        for row in rows {
            let (k, v) = row?;
            m.insert(k, v);
        }
        m
    };

    let mut stmt = conn.prepare(
        "SELECT substr(date, 1, 4) AS yr,
                SUM(hits) AS hits,
                SUM(visits) AS visits,
                SUM(bandwidth) AS bandwidth
         FROM hourly_stats
         GROUP BY yr
         ORDER BY yr",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, i64>(2)? as u64,
            row.get::<_, i64>(3)? as u64,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (yr, hits, visits, bandwidth) = row?;
        let year = yr.parse::<i32>().unwrap_or(0);
        if year <= 0 {
            continue;
        }
        let visitors = if let Some(&v) = visitor_cache.get(&yr) {
            v
        } else {
            or_count_bitmaps_for_year(conn, &yr)?
        };

        out.push(YearAggregateRow {
            year,
            hits,
            visits,
            visitors,
            bandwidth,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            visits_fmt: count_fmt(visits, compact_counts),
            visits_exact_fmt: super::number_fmt(visits),
            visitors_fmt: count_fmt(visitors, compact_counts),
            visitors_exact_fmt: super::number_fmt(visitors),
            bandwidth_fmt: format_bytes(bandwidth),
        });
    }

    Ok(out)
}

fn overall_totals(conn: &Connection, compact_counts: bool) -> Result<TotalsView> {
    let mut stmt = conn.prepare(
        "SELECT COALESCE(SUM(hits), 0),
                COALESCE(SUM(visits), 0),
                COALESCE(SUM(bandwidth), 0)
         FROM hourly_stats",
    )?;

    let row = stmt.query_row([], |row| {
        Ok((
            row.get::<_, i64>(0)? as u64,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, i64>(2)? as u64,
        ))
    })?;

    let visitors = all_time_visitor_count(conn)?;

    Ok(format_totals(row.0, row.1, visitors, row.2, compact_counts))
}

fn monthly_visitor_count(conn: &Connection, period: &str) -> Result<u64> {
    let cached: Option<i64> = conn
        .query_row(
            "SELECT count FROM unique_visitor_counts WHERE period = ?1",
            params![period],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(n) = cached {
        return Ok(n as u64);
    }
    or_count_daily_bitmaps(conn, &format!("{}-%", period))
}

fn yearly_visitor_count(conn: &Connection, year: &str) -> Result<u64> {
    let cached: Option<i64> = conn
        .query_row(
            "SELECT count FROM unique_visitor_counts WHERE period = ?1",
            params![year],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(n) = cached {
        return Ok(n as u64);
    }
    // Fallback: OR all monthly snapshots for this year + in-progress daily bitmaps.
    or_count_bitmaps_for_year(conn, year)
}

/// OR all daily_unique_ips bitmaps matching `like` and return the distinct IP count.
fn or_count_daily_bitmaps(conn: &Connection, like: &str) -> Result<u64> {
    let mut stmt = conn.prepare(
        "SELECT ip_kind, ip_hi, bitmap FROM daily_unique_ips WHERE date LIKE ?1",
    )?;
    let mapped = stmt.query_map(params![like], |row| {
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

    let mut v4 = RoaringBitmap::new();
    let mut v6: HashMap<u64, RoaringTreemap> = HashMap::new();
    or_into_bitmaps(rows, "daily", &mut v4, &mut v6)?;
    Ok(v4.len() + v6.values().map(|t| t.len()).sum::<u64>())
}

/// OR monthly_unique_ips snapshots for `year` plus in-progress daily bitmaps.
fn or_count_bitmaps_for_year(conn: &Connection, year: &str) -> Result<u64> {
    let mut v4 = RoaringBitmap::new();
    let mut v6: HashMap<u64, RoaringTreemap> = HashMap::new();

    let monthly_rows: Vec<(u8, u64, Vec<u8>)> = {
        let mut stmt = conn.prepare(
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
    or_into_bitmaps(monthly_rows, "monthly", &mut v4, &mut v6)?;

    let daily_rows: Vec<(u8, u64, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT ip_kind, ip_hi, bitmap FROM daily_unique_ips WHERE date LIKE ?1",
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
    or_into_bitmaps(daily_rows, "daily", &mut v4, &mut v6)?;

    Ok(v4.len() + v6.values().map(|t| t.len()).sum::<u64>())
}

fn all_time_visitor_count(conn: &Connection) -> Result<u64> {
    let mut v4 = RoaringBitmap::new();
    let mut v6: HashMap<u64, RoaringTreemap> = HashMap::new();

    let monthly_rows: Vec<(u8, u64, Vec<u8>)> = {
        let mut stmt =
            conn.prepare("SELECT ip_kind, ip_hi, bitmap FROM monthly_unique_ips")?;
        let mapped = stmt.query_map([], |row| {
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
    or_into_bitmaps(monthly_rows, "monthly", &mut v4, &mut v6)?;

    let daily_rows: Vec<(u8, u64, Vec<u8>)> = {
        let mut stmt =
            conn.prepare("SELECT ip_kind, ip_hi, bitmap FROM daily_unique_ips")?;
        let mapped = stmt.query_map([], |row| {
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
    or_into_bitmaps(daily_rows, "daily", &mut v4, &mut v6)?;

    Ok(v4.len() + v6.values().map(|t| t.len()).sum::<u64>())
}

fn build_url_row(
    url: String, hits: u64, bandwidth: u64,
    rt_sum: u64, rt_count: u64, rt_max: u32,
    compact_counts: bool, hits_total: f64, bw_total: f64,
) -> TopUrlRow {
    let (avg_ms_fmt, max_ms_fmt) = rt_display(rt_sum, rt_count, rt_max);
    TopUrlRow {
        url,
        hits,
        bandwidth,
        hits_fmt: count_fmt(hits, compact_counts),
        hits_exact_fmt: super::number_fmt(hits),
        bandwidth_fmt: format_bytes(bandwidth),
        pct_fmt: percent_str(hits as f64, hits_total),
        bandwidth_pct_fmt: percent_str(bandwidth as f64, bw_total),
        avg_ms_fmt,
        max_ms_fmt,
        avg_ms_raw: if rt_count > 0 { Some(rt_sum / rt_count) } else { None },
        max_ms_raw: rt_max,
    }
}

/// Compute avg and max display strings from rt fields.
fn rt_display(rt_sum: u64, rt_count: u64, rt_max: u32) -> (Option<String>, Option<String>) {
    if rt_count == 0 {
        return (None, None);
    }
    (
        Some(format_ms(rt_sum as f64 / rt_count as f64)),
        Some(format_ms(rt_max as f64)),
    )
}

// ── Union query helpers ───────────────────────────────────────────────────────
// Each function runs multiple sort-order queries, deduplicates by key, and
// returns a single Vec sorted by hits descending.  This ensures every column
// in the sortable table has its top-N represented in the DOM.

fn top_urls_union(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopUrlRow>> {
    if top_n == 0 {
        return Ok(Vec::new());
    }
    let is_monthly = period.len() == 7;
    let (op, param) = period_clause(period);
    type Raw = (String, u64, u64, u64, u64, u32);
    let mut seen: ahash::AHashMap<String, Raw> = ahash::AHashMap::new();

    for order_col in ["hits", "bandwidth"] {
        let sql = if is_monthly {
            format!("SELECT url,hits,bandwidth,rt_sum,rt_count,rt_max \
                     FROM top_urls WHERE period {op} ORDER BY {order_col} DESC LIMIT ?2")
        } else {
            format!("SELECT url,SUM(hits),SUM(bandwidth),SUM(rt_sum),SUM(rt_count),MAX(rt_max) \
                     FROM top_urls WHERE period {op} GROUP BY url \
                     ORDER BY SUM({order_col}) DESC LIMIT ?2")
        };
        let mut stmt = conn.prepare(&sql)?;
        for row in stmt.query_map(params![param, top_n as i64], |r| {
            Ok((r.get::<_,String>(0)?, r.get::<_,i64>(1)? as u64, r.get::<_,i64>(2)? as u64,
                r.get::<_,i64>(3)? as u64, r.get::<_,i64>(4)? as u64, r.get::<_,i64>(5)? as u32))
        })? {
            let r = row?;
            seen.entry(r.0.clone()).or_insert(r);
        }
    }
    // avg RT sort
    let rt_sql = if is_monthly {
        format!("SELECT url,hits,bandwidth,rt_sum,rt_count,rt_max \
                 FROM top_urls WHERE period {op} AND rt_count>0 \
                 ORDER BY rt_sum*1.0/rt_count DESC LIMIT ?2")
    } else {
        format!("SELECT url,SUM(hits),SUM(bandwidth),SUM(rt_sum),SUM(rt_count),MAX(rt_max) \
                 FROM top_urls WHERE period {op} GROUP BY url HAVING SUM(rt_count)>0 \
                 ORDER BY SUM(rt_sum)*1.0/SUM(rt_count) DESC LIMIT ?2")
    };
    let mut stmt = conn.prepare(&rt_sql)?;
    for row in stmt.query_map(params![param, top_n as i64], |r| {
        Ok((r.get::<_,String>(0)?, r.get::<_,i64>(1)? as u64, r.get::<_,i64>(2)? as u64,
            r.get::<_,i64>(3)? as u64, r.get::<_,i64>(4)? as u64, r.get::<_,i64>(5)? as u32))
    })? {
        let r = row?;
        seen.entry(r.0.clone()).or_insert(r);
    }

    let (hits_total, bw_total) = period_hits_bw_totals(conn, period)?;
    let mut raw: Vec<Raw> = seen.into_values().collect();
    raw.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| b.2.cmp(&a.2)));
    Ok(raw.into_iter()
        .map(|(url, hits, bw, rt_sum, rt_count, rt_max)|
            build_url_row(url, hits, bw, rt_sum, rt_count, rt_max, compact_counts, hits_total, bw_total))
        .collect())
}

fn top_ips_union(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
    anonymise_ips: bool,
) -> Result<Vec<TopHostRow>> {
    let (op, param) = period_clause(period);
    type Raw = (u8, u64, u64, u64, u64, String, String);
    let mut seen: ahash::AHashMap<(u8, u64, u64), Raw> = ahash::AHashMap::new();

    for order_col in ["hits", "bandwidth"] {
        let sql = format!(
            "SELECT t.host_kind,t.host_hi,t.host_lo,SUM(t.hits),SUM(t.bandwidth),\
             COALESCE(MAX(t.country_code),'--'),COALESCE(MAX(cn.country_name),'Unknown') \
             FROM top_ips t LEFT JOIN countries cn ON cn.country_code=t.country_code \
             WHERE t.period {op} GROUP BY t.host_kind,t.host_hi,t.host_lo \
             ORDER BY {order_col} DESC,hits DESC LIMIT ?2"
        );
        let mut stmt = conn.prepare(&sql)?;
        for row in stmt.query_map(params![param, top_n as i64], |r| {
            Ok((r.get::<_,i64>(0)? as u8, r.get::<_,i64>(1)? as u64, r.get::<_,i64>(2)? as u64,
                r.get::<_,i64>(3)? as u64, r.get::<_,i64>(4)? as u64,
                r.get::<_,String>(5)?, r.get::<_,String>(6)?))
        })? {
            let r = row?;
            seen.entry((r.0, r.1, r.2)).or_insert(r);
        }
    }

    let (hits_total, bw_total) = period_hits_bw_totals(conn, period)?;
    let mut raw: Vec<Raw> = seen.into_values().collect();
    raw.sort_unstable_by(|a, b| b.3.cmp(&a.3).then_with(|| b.4.cmp(&a.4)));
    Ok(raw.into_iter().map(|(hk, hh, hl, hits, bw, cc, cn)| TopHostRow {
        host: decode_host(hk, hh, hl, anonymise_ips),
        hits, bandwidth: bw,
        country_flag: flag_emoji(&cc),
        country_code: cc, country_name: cn,
        hits_fmt: count_fmt(hits, compact_counts),
        hits_exact_fmt: super::number_fmt(hits),
        bandwidth_fmt: format_bytes(bw),
        pct_fmt: percent_str(hits as f64, hits_total),
        bandwidth_pct_fmt: percent_str(bw as f64, bw_total),
    }).collect())
}

fn top_agents_union(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopAgentRow>> {
    if top_n == 0 { return Ok(Vec::new()); }
    let (op, param) = period_clause(period);
    let mut seen: ahash::AHashMap<String, (u64, u64)> = ahash::AHashMap::new();

    for order_col in ["hits", "bandwidth"] {
        let sql = format!(
            "SELECT agent_family,SUM(hits),SUM(bandwidth) FROM top_agents \
             WHERE period {op} GROUP BY agent_family ORDER BY {order_col} DESC LIMIT ?2"
        );
        let mut stmt = conn.prepare(&sql)?;
        for row in stmt.query_map(params![param, top_n as i64], |r| {
            Ok((r.get::<_,String>(0)?, r.get::<_,i64>(1)? as u64, r.get::<_,i64>(2)? as u64))
        })? {
            let (agent, hits, bw) = row?;
            seen.entry(agent).or_insert((hits, bw));
        }
    }

    let (hits_total, bw_total) = period_hits_bw_totals(conn, period)?;
    let mut raw: Vec<(String, u64, u64)> = seen.into_iter().map(|(k,(h,b))| (k,h,b)).collect();
    raw.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| b.2.cmp(&a.2)));
    Ok(build_agent_rows(raw, compact_counts, hits_total, bw_total))
}

fn top_agents_union_all(
    conn: &Connection,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopAgentRow>> {
    if top_n == 0 { return Ok(Vec::new()); }
    let mut seen: ahash::AHashMap<String, (u64, u64)> = ahash::AHashMap::new();

    for order_col in ["hits", "bandwidth"] {
        let sql = format!(
            "SELECT agent_family,SUM(hits),SUM(bandwidth) FROM top_agents \
             GROUP BY agent_family ORDER BY {order_col} DESC LIMIT ?1"
        );
        let mut stmt = conn.prepare(&sql)?;
        for row in stmt.query_map(params![top_n as i64], |r| {
            Ok((r.get::<_,String>(0)?, r.get::<_,i64>(1)? as u64, r.get::<_,i64>(2)? as u64))
        })? {
            let (agent, hits, bw) = row?;
            seen.entry(agent).or_insert((hits, bw));
        }
    }

    let (hits_total, bw_total) = all_time_hits_bw_totals(conn)?;
    let mut raw: Vec<(String, u64, u64)> = seen.into_iter().map(|(k,(h,b))| (k,h,b)).collect();
    raw.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| b.2.cmp(&a.2)));
    Ok(build_agent_rows(raw, compact_counts, hits_total, bw_total))
}

fn top_countries_union(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopCountryRow>> {
    if top_n == 0 { return Ok(Vec::new()); }
    let (op, param) = period_clause(period);
    let mut seen: ahash::AHashMap<String, (String, u64, u64)> = ahash::AHashMap::new();

    for order_col in ["hits", "bandwidth"] {
        let sql = format!(
            "SELECT c.country_code,COALESCE(n.country_name,'Unknown'),SUM(c.hits),SUM(c.bandwidth) \
             FROM top_countries c LEFT JOIN countries n ON n.country_code=c.country_code \
             WHERE c.period {op} GROUP BY c.country_code ORDER BY {order_col} DESC LIMIT ?2"
        );
        let mut stmt = conn.prepare(&sql)?;
        for row in stmt.query_map(params![param, top_n as i64], |r| {
            Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,i64>(2)? as u64, r.get::<_,i64>(3)? as u64))
        })? {
            let (cc, cn, hits, bw) = row?;
            seen.entry(cc).or_insert((cn, hits, bw));
        }
    }

    let (hits_total, bw_total) = period_hits_bw_totals(conn, period)?;
    let mut raw: Vec<(String, String, u64, u64)> = seen.into_iter().map(|(cc,(cn,h,b))| (cc,cn,h,b)).collect();
    raw.sort_unstable_by(|a, b| b.2.cmp(&a.2).then_with(|| b.3.cmp(&a.3)));
    Ok(build_country_rows(raw, compact_counts, hits_total, bw_total))
}

fn top_countries_union_all(
    conn: &Connection,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopCountryRow>> {
    if top_n == 0 { return Ok(Vec::new()); }
    let mut seen: ahash::AHashMap<String, (String, u64, u64)> = ahash::AHashMap::new();

    for order_col in ["hits", "bandwidth"] {
        let sql = format!(
            "WITH agg AS (SELECT country_code,SUM(hits) AS hits,SUM(bandwidth) AS bandwidth \
             FROM top_countries GROUP BY country_code) \
             SELECT a.country_code,COALESCE(n.country_name,'Unknown'),a.hits,a.bandwidth \
             FROM agg a LEFT JOIN countries n ON n.country_code=a.country_code \
             ORDER BY {order_col} DESC LIMIT ?1"
        );
        let mut stmt = conn.prepare(&sql)?;
        for row in stmt.query_map(params![top_n as i64], |r| {
            Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,i64>(2)? as u64, r.get::<_,i64>(3)? as u64))
        })? {
            let (cc, cn, hits, bw) = row?;
            seen.entry(cc).or_insert((cn, hits, bw));
        }
    }

    let (hits_total, bw_total) = all_time_hits_bw_totals(conn)?;
    let mut raw: Vec<(String, String, u64, u64)> = seen.into_iter().map(|(cc,(cn,h,b))| (cc,cn,h,b)).collect();
    raw.sort_unstable_by(|a, b| b.2.cmp(&a.2).then_with(|| b.3.cmp(&a.3)));
    Ok(build_country_rows(raw, compact_counts, hits_total, bw_total))
}

fn bucket_top_urls_union(
    conn: &Connection,
    period: &str,
    bucket: &str,
    top_n: usize,
    compact_counts: bool,
    hits_total: f64,
    bw_total: f64,
) -> Result<Vec<TopUrlRow>> {
    if top_n == 0 { return Ok(Vec::new()); }
    let is_monthly = period.len() == 7;
    let (op, param) = period_clause(period);
    type Raw = (String, u64, u64, u64, u64, u32);
    let mut seen: ahash::AHashMap<String, Raw> = ahash::AHashMap::new();

    for order_col in ["hits", "bandwidth"] {
        let sql = if is_monthly {
            format!("SELECT url,hits,bandwidth,rt_sum,rt_count,rt_max \
                     FROM bucket_urls WHERE period {op} AND bucket=?2 \
                     ORDER BY {order_col} DESC LIMIT ?3")
        } else {
            format!("SELECT url,SUM(hits),SUM(bandwidth),SUM(rt_sum),SUM(rt_count),MAX(rt_max) \
                     FROM bucket_urls WHERE period {op} AND bucket=?2 GROUP BY url \
                     ORDER BY SUM({order_col}) DESC LIMIT ?3")
        };
        let mut stmt = conn.prepare(&sql)?;
        for row in stmt.query_map(params![param, bucket, top_n as i64], |r| {
            Ok((r.get::<_,String>(0)?, r.get::<_,i64>(1)? as u64, r.get::<_,i64>(2)? as u64,
                r.get::<_,i64>(3)? as u64, r.get::<_,i64>(4)? as u64, r.get::<_,i64>(5)? as u32))
        })? {
            let r = row?;
            seen.entry(r.0.clone()).or_insert(r);
        }
    }
    let rt_sql = if is_monthly {
        format!("SELECT url,hits,bandwidth,rt_sum,rt_count,rt_max \
                 FROM bucket_urls WHERE period {op} AND bucket=?2 AND rt_count>0 \
                 ORDER BY rt_sum*1.0/rt_count DESC LIMIT ?3")
    } else {
        format!("SELECT url,SUM(hits),SUM(bandwidth),SUM(rt_sum),SUM(rt_count),MAX(rt_max) \
                 FROM bucket_urls WHERE period {op} AND bucket=?2 GROUP BY url \
                 HAVING SUM(rt_count)>0 ORDER BY SUM(rt_sum)*1.0/SUM(rt_count) DESC LIMIT ?3")
    };
    let mut stmt = conn.prepare(&rt_sql)?;
    for row in stmt.query_map(params![param, bucket, top_n as i64], |r| {
        Ok((r.get::<_,String>(0)?, r.get::<_,i64>(1)? as u64, r.get::<_,i64>(2)? as u64,
            r.get::<_,i64>(3)? as u64, r.get::<_,i64>(4)? as u64, r.get::<_,i64>(5)? as u32))
    })? {
        let r = row?;
        seen.entry(r.0.clone()).or_insert(r);
    }

    let mut raw: Vec<Raw> = seen.into_values().collect();
    raw.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| b.2.cmp(&a.2)));
    Ok(raw.into_iter()
        .map(|(url, hits, bw, rt_sum, rt_count, rt_max)|
            build_url_row(url, hits, bw, rt_sum, rt_count, rt_max, compact_counts, hits_total, bw_total))
        .collect())
}

fn bucket_agents_union(
    conn: &Connection,
    period: &str,
    bucket: &str,
    top_n: usize,
    compact_counts: bool,
    hits_total: f64,
    bw_total: f64,
) -> Result<Vec<TopAgentRow>> {
    if top_n == 0 { return Ok(Vec::new()); }
    let (op, param) = period_clause(period);
    let mut seen: ahash::AHashMap<String, (u64, u64)> = ahash::AHashMap::new();

    for order_col in ["hits", "bandwidth"] {
        let sql = format!(
            "SELECT agent_family,SUM(hits),SUM(bandwidth) FROM bucket_agents \
             WHERE period {op} AND bucket=?2 GROUP BY agent_family \
             ORDER BY SUM({order_col}) DESC LIMIT ?3"
        );
        let mut stmt = conn.prepare(&sql)?;
        for row in stmt.query_map(params![param, bucket, top_n as i64], |r| {
            Ok((r.get::<_,String>(0)?, r.get::<_,i64>(1)? as u64, r.get::<_,i64>(2)? as u64))
        })? {
            let (agent, hits, bw) = row?;
            seen.entry(agent).or_insert((hits, bw));
        }
    }

    let mut raw: Vec<(String, u64, u64)> = seen.into_iter().map(|(k,(h,b))| (k,h,b)).collect();
    raw.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| b.2.cmp(&a.2)));
    Ok(build_agent_rows(raw, compact_counts, hits_total, bw_total))
}

fn bucket_countries_union(
    conn: &Connection,
    period: &str,
    bucket: &str,
    top_n: usize,
    compact_counts: bool,
    hits_total: f64,
    bw_total: f64,
) -> Result<Vec<TopCountryRow>> {
    if top_n == 0 { return Ok(Vec::new()); }
    let (op, param) = period_clause(period);
    let mut seen: ahash::AHashMap<String, (String, u64, u64)> = ahash::AHashMap::new();

    for order_col in ["hits", "bandwidth"] {
        let sql = format!(
            "SELECT bc.country_code,COALESCE(n.country_name,'Unknown'),SUM(bc.hits),SUM(bc.bandwidth) \
             FROM bucket_countries bc LEFT JOIN countries n ON n.country_code=bc.country_code \
             WHERE bc.period {op} AND bc.bucket=?2 GROUP BY bc.country_code \
             ORDER BY SUM(bc.{order_col}) DESC LIMIT ?3"
        );
        let mut stmt = conn.prepare(&sql)?;
        for row in stmt.query_map(params![param, bucket, top_n as i64], |r| {
            Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,i64>(2)? as u64, r.get::<_,i64>(3)? as u64))
        })? {
            let (cc, cn, hits, bw) = row?;
            seen.entry(cc).or_insert((cn, hits, bw));
        }
    }

    let mut raw: Vec<(String, String, u64, u64)> = seen.into_iter().map(|(cc,(cn,h,b))| (cc,cn,h,b)).collect();
    raw.sort_unstable_by(|a, b| b.2.cmp(&a.2).then_with(|| b.3.cmp(&a.3)));
    Ok(build_country_rows(raw, compact_counts, hits_total, bw_total))
}

/// SQL ORDER BY expression for the error-URL sort `key`, for monthly (raw rows)
const ERR_SORT_KEYS: &[&str] = &[
    "c400", "c401", "c403", "c404", "c422", "c429", "c4xx",
    "c500", "c502", "c503", "c5xx", "bandwidth",
];

struct RawErrRow {
    url: String,
    c400: u64,
    c401: u64,
    c403: u64,
    c404: u64,
    c422: u64,
    c429: u64,
    c4xx: u64,
    c500: u64,
    c502: u64,
    c503: u64,
    c5xx: u64,
    bandwidth: u64,
}

impl RawErrRow {
    fn total_errors(&self) -> u64 {
        self.c400
            + self.c401
            + self.c403
            + self.c404
            + self.c422
            + self.c429
            + self.c4xx
            + self.c500
            + self.c502
            + self.c503
            + self.c5xx
    }
}

fn parse_raw_err_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawErrRow> {
    Ok(RawErrRow {
        url:       row.get::<_, String>(0)?,
        c400:      row.get::<_, i64>(1)? as u64,
        c401:      row.get::<_, i64>(2)? as u64,
        c403:      row.get::<_, i64>(3)? as u64,
        c404:      row.get::<_, i64>(4)? as u64,
        c422:      row.get::<_, i64>(5)? as u64,
        c429:      row.get::<_, i64>(6)? as u64,
        c4xx:      row.get::<_, i64>(7)? as u64,
        c500:      row.get::<_, i64>(8)? as u64,
        c502:      row.get::<_, i64>(9)? as u64,
        c503:      row.get::<_, i64>(10)? as u64,
        c5xx:      row.get::<_, i64>(11)? as u64,
        bandwidth: row.get::<_, i64>(12)? as u64,
    })
}

fn build_error_url_row(r: RawErrRow, compact_counts: bool) -> ErrorUrlRow {
    ErrorUrlRow {
        c400_fmt: count_fmt(r.c400, compact_counts),
        c401_fmt: count_fmt(r.c401, compact_counts),
        c403_fmt: count_fmt(r.c403, compact_counts),
        c404_fmt: count_fmt(r.c404, compact_counts),
        c422_fmt: count_fmt(r.c422, compact_counts),
        c429_fmt: count_fmt(r.c429, compact_counts),
        c4xx_fmt: count_fmt(r.c4xx, compact_counts),
        c500_fmt: count_fmt(r.c500, compact_counts),
        c502_fmt: count_fmt(r.c502, compact_counts),
        c503_fmt: count_fmt(r.c503, compact_counts),
        c5xx_fmt: count_fmt(r.c5xx, compact_counts),
        bandwidth_fmt: format_bytes(r.bandwidth),
        url: r.url,
        c400: r.c400,
        c401: r.c401,
        c403: r.c403,
        c404: r.c404,
        c422: r.c422,
        c429: r.c429,
        c4xx: r.c4xx,
        c500: r.c500,
        c502: r.c502,
        c503: r.c503,
        c5xx: r.c5xx,
        bandwidth: r.bandwidth,
    }
}

fn finish_error_url_union(
    seen: ahash::AHashMap<String, RawErrRow>,
    compact_counts: bool,
) -> Vec<ErrorUrlRow> {
    let mut rows: Vec<RawErrRow> = seen.into_values().collect();
    rows.sort_unstable_by(|a, b| {
        b.c404.cmp(&a.c404).then_with(|| b.total_errors().cmp(&a.total_errors()))
    });
    rows.into_iter()
        .map(|r| build_error_url_row(r, compact_counts))
        .collect()
}

/// Top erroring URLs for a monthly ("YYYY-MM") or yearly ("YYYY") period.
/// Returns the union of top-N for every sort key so any column can be sorted client-side.
fn top_error_urls_period(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<ErrorUrlRow>> {
    if top_n == 0 {
        return Ok(Vec::new());
    }
    let is_monthly = period.len() == 7;
    let (op, param) = period_clause(period);
    let mut seen: ahash::AHashMap<String, RawErrRow> = ahash::AHashMap::new();

    for key in ERR_SORT_KEYS {
        let sql = if is_monthly {
            format!(
                "SELECT url,c400,c401,c403,c404,c422,c429,c4xx,\
                 c500,c502,c503,c5xx,bandwidth \
                 FROM top_error_urls WHERE period {op} \
                 ORDER BY {key} DESC LIMIT ?2"
            )
        } else {
            format!(
                "SELECT url,SUM(c400),SUM(c401),SUM(c403),SUM(c404),\
                 SUM(c422),SUM(c429),SUM(c4xx),\
                 SUM(c500),SUM(c502),SUM(c503),SUM(c5xx),SUM(bandwidth) \
                 FROM top_error_urls WHERE period {op} \
                 GROUP BY url ORDER BY SUM({key}) DESC LIMIT ?2"
            )
        };
        let mut stmt = conn.prepare(&sql)?;
        for row in stmt.query_map(params![param, top_n as i64], parse_raw_err_row)? {
            let r = row?;
            seen.entry(r.url.clone()).or_insert(r);
        }
    }
    Ok(finish_error_url_union(seen, compact_counts))
}

/// All-time top erroring URLs (summed across every period).
/// Returns the union of top-N for every sort key so any column can be sorted client-side.
fn top_error_urls_all(
    conn: &Connection,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<ErrorUrlRow>> {
    if top_n == 0 {
        return Ok(Vec::new());
    }
    let mut seen: ahash::AHashMap<String, RawErrRow> = ahash::AHashMap::new();

    for key in ERR_SORT_KEYS {
        let sql = format!(
            "SELECT url,SUM(c400),SUM(c401),SUM(c403),SUM(c404),\
             SUM(c422),SUM(c429),SUM(c4xx),\
             SUM(c500),SUM(c502),SUM(c503),SUM(c5xx),SUM(bandwidth) \
             FROM top_error_urls \
             GROUP BY url ORDER BY SUM({key}) DESC LIMIT ?1"
        );
        let mut stmt = conn.prepare(&sql)?;
        for row in stmt.query_map(params![top_n as i64], parse_raw_err_row)? {
            let r = row?;
            seen.entry(r.url.clone()).or_insert(r);
        }
    }
    Ok(finish_error_url_union(seen, compact_counts))
}

fn decode_host(kind: u8, hi: u64, lo: u64, anonymise: bool) -> String {
    match kind {
        1 => {
            let addr = if anonymise {
                lo as u32 & 0xFFFF_FF00
            } else {
                lo as u32
            };
            Ipv4Addr::from(addr).to_string()
        }
        2 => {
            let (hi, lo) = if anonymise {
                (hi & 0xFFFF_FFFF_FFFF_0000, 0u64)
            } else {
                (hi, lo)
            };
            let n = ((hi as u128) << 64) | lo as u128;
            Ipv6Addr::from(n).to_string()
        }
        _ => String::new(),
    }
}

fn top_refs(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopRefRow>> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT referrer, SUM(hits) AS hits
         FROM top_referrers
         WHERE period {op}
         GROUP BY referrer
         ORDER BY hits DESC
         LIMIT ?2"
    );
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![param, top_n as i64], |row| {
        let hits = row.get::<_, i64>(1)? as u64;
        Ok(TopRefRow {
            referrer: row.get::<_, String>(0)?,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn build_agent_rows(raw: Vec<(String, u64, u64)>, compact_counts: bool, hits_total: f64, bw_total: f64) -> Vec<TopAgentRow> {
    raw.into_iter()
        .map(|(agent, hits, bandwidth)| TopAgentRow {
            agent,
            hits,
            bandwidth,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            bandwidth_fmt: format_bytes(bandwidth),
            pct_fmt: percent_str(hits as f64, hits_total),
            bandwidth_pct_fmt: percent_str(bandwidth as f64, bw_total),
        })
        .collect()
}

fn build_country_rows(raw: Vec<(String, String, u64, u64)>, compact_counts: bool, hits_total: f64, bw_total: f64) -> Vec<TopCountryRow> {
    raw.into_iter()
        .map(|(country_code, country_name, hits, bandwidth)| TopCountryRow {
            country_flag: flag_emoji(&country_code),
            country_code,
            country_name,
            hits,
            bandwidth,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            bandwidth_fmt: format_bytes(bandwidth),
            pct_fmt: percent_str(hits as f64, hits_total),
            bandwidth_pct_fmt: percent_str(bandwidth as f64, bw_total),
        })
        .collect()
}

fn status_codes(conn: &Connection, period: &str, compact_counts: bool) -> Result<Vec<StatusRow>> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT status, SUM(hits) AS hits
         FROM status_codes
         WHERE period {op}
         GROUP BY status
         ORDER BY hits DESC"
    );
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![param], |row| {
        Ok((row.get::<_, i64>(0)? as u16, row.get::<_, i64>(1)? as u64))
    })?;

    let mut raw = Vec::new();
    for row in rows {
        raw.push(row?);
    }
    let (total, _) = period_hits_bw_totals(conn, period)?;
    Ok(build_status_rows(raw, compact_counts, total))
}

fn status_codes_all(conn: &Connection, compact_counts: bool) -> Result<Vec<StatusRow>> {
    let mut stmt = conn.prepare(
        "SELECT status, SUM(hits) AS hits
         FROM status_codes
         GROUP BY status
         ORDER BY hits DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, i64>(0)? as u16, row.get::<_, i64>(1)? as u64))
    })?;

    let mut raw = Vec::new();
    for row in rows {
        raw.push(row?);
    }
    let (total, _) = all_time_hits_bw_totals(conn)?;
    Ok(build_status_rows(raw, compact_counts, total))
}

fn proto_codes(conn: &Connection, period: &str, compact_counts: bool) -> Result<Vec<ProtoRow>> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT proto, SUM(hits) AS hits
         FROM protocol_counts
         WHERE period {op}
         GROUP BY proto
         ORDER BY hits DESC"
    );
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![param], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })?;

    let mut raw = Vec::<(String, u64)>::new();
    for row in rows {
        raw.push(row?);
    }

    let (total, _) = period_hits_bw_totals(conn, period)?;
    let out = raw
        .into_iter()
        .map(|(proto, hits)| ProtoRow {
            proto,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, total),
        })
        .collect();
    Ok(out)
}

fn method_codes(conn: &Connection, period: &str, compact_counts: bool) -> Result<Vec<MethodRow>> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT method, SUM(hits) AS hits
         FROM method_counts
         WHERE period {op}
         GROUP BY method
         ORDER BY hits DESC"
    );
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![param], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })?;

    let mut raw = Vec::<(String, u64)>::new();
    for row in rows {
        raw.push(row?);
    }

    let (total, _) = period_hits_bw_totals(conn, period)?;
    let out = raw
        .into_iter()
        .map(|(method, hits)| MethodRow {
            method,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, total),
        })
        .collect();
    Ok(out)
}

fn daily_avg_max_from_rows(daily: &[DailyRow], compact_counts: bool) -> DailyAvgMax {
    if daily.is_empty() {
        return DailyAvgMax::default();
    }

    let days = daily.len() as u64;

    let avg_hits = daily.iter().map(|r| r.hits).sum::<u64>() / days;
    let max_hits = daily.iter().map(|r| r.hits).max().unwrap_or(0);
    let avg_visits = daily.iter().map(|r| r.visits).sum::<u64>() / days;
    let max_visits = daily.iter().map(|r| r.visits).max().unwrap_or(0);
    let avg_visitors = daily.iter().map(|r| r.visitors).sum::<u64>() / days;
    let max_visitors = daily.iter().map(|r| r.visitors).max().unwrap_or(0);
    let avg_bandwidth = daily.iter().map(|r| r.bandwidth).sum::<u64>() / days;
    let max_bandwidth = daily.iter().map(|r| r.bandwidth).max().unwrap_or(0);

    DailyAvgMax {
        avg_hits,
        max_hits,
        avg_hits_fmt: count_fmt(avg_hits, compact_counts),
        avg_hits_exact_fmt: super::number_fmt(avg_hits),
        max_hits_fmt: count_fmt(max_hits, compact_counts),
        max_hits_exact_fmt: super::number_fmt(max_hits),
        avg_visits,
        max_visits,
        avg_visits_fmt: count_fmt(avg_visits, compact_counts),
        avg_visits_exact_fmt: super::number_fmt(avg_visits),
        max_visits_fmt: count_fmt(max_visits, compact_counts),
        max_visits_exact_fmt: super::number_fmt(max_visits),
        avg_visitors,
        max_visitors,
        avg_visitors_fmt: count_fmt(avg_visitors, compact_counts),
        avg_visitors_exact_fmt: super::number_fmt(avg_visitors),
        max_visitors_fmt: count_fmt(max_visitors, compact_counts),
        max_visitors_exact_fmt: super::number_fmt(max_visitors),
        avg_bandwidth,
        max_bandwidth,
        avg_bandwidth_fmt: format_bytes(avg_bandwidth),
        max_bandwidth_fmt: format_bytes(max_bandwidth),
    }
}

fn hourly_avg_max(
    conn: &Connection,
    year: i32,
    month: i32,
    compact_counts: bool,
) -> Result<HourlyAvgMax> {
    let prefix = format!("{year:04}-{month:02}");
    let mut stmt = conn.prepare(
        "SELECT AVG(hits) AS avg_hits,
            MAX(hits) AS max_hits,
            AVG(visits) AS avg_visits,
            MAX(visits) AS max_visits
         FROM hourly_stats
         WHERE date LIKE ?1",
    )?;

    let row = stmt.query_row(params![format!("{prefix}-%")], |row| {
        let avg_hits = row.get::<_, Option<f64>>(0)?.unwrap_or(0.0).round() as u64;
        let max_hits = row.get::<_, Option<i64>>(1)?.unwrap_or(0) as u64;
        let avg_visits = row.get::<_, Option<f64>>(2)?.unwrap_or(0.0).round() as u64;
        let max_visits = row.get::<_, Option<i64>>(3)?.unwrap_or(0) as u64;
        Ok(HourlyAvgMax {
            avg_hits,
            max_hits,
            avg_hits_fmt: count_fmt(avg_hits, compact_counts),
            avg_hits_exact_fmt: super::number_fmt(avg_hits),
            max_hits_fmt: count_fmt(max_hits, compact_counts),
            max_hits_exact_fmt: super::number_fmt(max_hits),
            avg_visits,
            max_visits,
            avg_visits_fmt: count_fmt(avg_visits, compact_counts),
            avg_visits_exact_fmt: super::number_fmt(avg_visits),
            max_visits_fmt: count_fmt(max_visits, compact_counts),
            max_visits_exact_fmt: super::number_fmt(max_visits),
        })
    })?;

    Ok(row)
}

// ── Response time helpers ─────────────────────────────────────────────────────

fn load_monthly_rt_histogram(conn: &Connection, period: &str) -> Result<Option<ResponseTimeHistogram>> {
    // Try the pre-computed monthly histogram first (finalized months).
    let blob: Option<Vec<u8>> = conn
        .query_row(
            "SELECT data FROM monthly_response_time_histograms WHERE period=?1",
            params![period],
            |r| r.get(0),
        )
        .optional()?;

    if let Some(b) = blob {
        return Ok(Some(
            ResponseTimeHistogram::deserialize(&b)
                .context("deserialize monthly rt histogram")?,
        ));
    }

    // Fallback: merge in-progress daily blobs for the current month.
    let like = format!("{}-%%", period);
    let mut stmt = conn.prepare(
        "SELECT data FROM daily_response_time_histograms WHERE date LIKE ?1",
    )?;
    let rows = stmt
        .query_map(params![like], |r| r.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    if rows.is_empty() {
        return Ok(None);
    }

    let mut merged = ResponseTimeHistogram::new();
    for blob in &rows {
        merged.merge(
            &ResponseTimeHistogram::deserialize(blob)
                .context("deserialize daily rt histogram for fallback merge")?,
        );
    }
    Ok(Some(merged))
}

fn monthly_rt(conn: &Connection, period: &str) -> Result<Option<(f64, u32)>> {
    let hist = load_monthly_rt_histogram(conn, period)?;
    Ok(hist.and_then(|h| h.avg().map(|avg| (avg, h.percentile(95.0)))))
}

fn yearly_rt(conn: &Connection, year: i32) -> Result<Option<(f64, u32)>> {
    let like = format!("{year}-%%");
    let mut stmt = conn.prepare(
        "SELECT data FROM monthly_response_time_histograms WHERE period LIKE ?1",
    )?;
    let rows = stmt
        .query_map(params![like], |r| r.get::<_, Vec<u8>>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    if rows.is_empty() {
        return Ok(None);
    }

    let mut merged = ResponseTimeHistogram::new();
    for blob in &rows {
        merged.merge(
            &ResponseTimeHistogram::deserialize(blob)
                .context("deserialize monthly rt histogram for yearly merge")?,
        );
    }
    Ok(merged.avg().map(|avg| (avg, merged.percentile(95.0))))
}

fn daily_rt_stats_for_month(conn: &Connection, year: i32, month: i32) -> Result<Vec<DailyRtStat>> {
    let prefix = format!("{year:04}-{month:02}");
    let like = format!("{prefix}-%%");

    // Prefer pre-computed stats (finalized months).
    let mut stmt = conn.prepare(
        "SELECT date, avg_ms, p95_ms FROM daily_response_time_stats \
         WHERE date LIKE ?1 ORDER BY date",
    )?;
    let rows = stmt
        .query_map(params![like], |r| {
            Ok(DailyRtStat {
                date: r.get::<_, String>(0)?,
                avg_ms: r.get::<_, f64>(1)?,
                p95_ms: r.get::<_, i64>(2)? as u32,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    if !rows.is_empty() {
        return Ok(rows);
    }

    // Fallback: compute from in-progress daily blobs.
    let mut stmt2 = conn.prepare(
        "SELECT date, data FROM daily_response_time_histograms \
         WHERE date LIKE ?1 ORDER BY date",
    )?;
    let rows2 = stmt2
        .query_map(params![like], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut out = Vec::with_capacity(rows2.len());
    for (date, blob) in rows2 {
        let hist = ResponseTimeHistogram::deserialize(&blob)
            .context("deserialize daily rt histogram for fallback stats")?;
        if hist.count > 0 {
            out.push(DailyRtStat {
                date,
                avg_ms: hist.avg().unwrap_or(0.0),
                p95_ms: hist.percentile(95.0),
            });
        }
    }
    Ok(out)
}

fn monthly_rt_stats_for_year(conn: &Connection, year: i32) -> Result<Vec<MonthlyRtStat>> {
    let like = format!("{year}-%%");
    let mut stmt = conn.prepare(
        "SELECT period, data FROM monthly_response_time_histograms \
         WHERE period LIKE ?1 ORDER BY period",
    )?;
    let rows = stmt
        .query_map(params![like], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    let mut out = Vec::with_capacity(rows.len());
    for (period, blob) in rows {
        let hist = ResponseTimeHistogram::deserialize(&blob)
            .context("deserialize monthly rt histogram for yearly stats")?;
        if hist.count > 0 {
            let month_num: u32 = period[5..7].parse().unwrap_or(0);
            out.push(MonthlyRtStat {
                label: month_name(month_num).to_string(),
                avg_ms: hist.avg().unwrap_or(0.0),
                p95_ms: hist.percentile(95.0),
            });
        }
    }
    Ok(out)
}

fn monthly_rt_histogram_buckets(conn: &Connection, period: &str) -> Result<Vec<(String, u64)>> {
    let hist = match load_monthly_rt_histogram(conn, period)? {
        Some(h) if h.count > 0 => h,
        _ => return Ok(Vec::new()),
    };

    // Group 1ms buckets into 10ms display buckets: [0,10), [10,20), …, [190,200), [200,∞)
    const BUCKET_SIZE: usize = 10;
    const NUM_BUCKETS: usize = 20; // 0–199ms in 10ms steps
    let mut buckets = vec![0u64; NUM_BUCKETS + 1]; // +1 for "200ms+"

    for (ms, &count) in hist.buckets.iter().enumerate() {
        if count == 0 {
            continue;
        }
        let idx = if ms >= NUM_BUCKETS * BUCKET_SIZE {
            NUM_BUCKETS
        } else {
            ms / BUCKET_SIZE
        };
        buckets[idx] += count as u64;
    }
    buckets[NUM_BUCKETS] += hist.overflow as u64;

    let mut out: Vec<(String, u64)> = (0..NUM_BUCKETS)
        .map(|i| {
            let lo = i * BUCKET_SIZE;
            let hi = lo + BUCKET_SIZE - 1;
            (format!("{lo}–{hi}ms"), buckets[i])
        })
        .collect();
    out.push((format!("{}ms+", NUM_BUCKETS * BUCKET_SIZE), buckets[NUM_BUCKETS]));

    // Drop trailing zero-count buckets for cleaner chart.
    while out.last().map_or(false, |(_, c)| *c == 0) {
        out.pop();
    }

    Ok(out)
}

// ── Bucket aggregation ────────────────────────────────────────────────────────

/// Return (hits, bandwidth) totals for a specific bucket+period.
fn bucket_totals(conn: &Connection, period: &str, bucket: &str) -> Result<(f64, f64)> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT COALESCE(SUM(hits),0), COALESCE(SUM(bandwidth),0) \
         FROM bucket_period_stats WHERE period {op} AND bucket = ?2"
    );
    let mut stmt = conn.prepare(&sql)?;
    let (h, b) = stmt.query_row(params![param, bucket], |r| {
        Ok((r.get::<_, i64>(0)? as f64, r.get::<_, i64>(1)? as f64))
    })?;
    Ok((h, b))
}

/// List all buckets active in a period, ordered by hits descending.
pub(super) fn bucket_index_rows(
    conn: &Connection,
    period: &str,
    compact_counts: bool,
) -> Result<Vec<BucketIndexRow>> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT bucket, SUM(hits), SUM(bandwidth), SUM(rt_sum), SUM(rt_count), MAX(rt_max) \
         FROM bucket_period_stats WHERE period {op} \
         GROUP BY bucket ORDER BY SUM(hits) DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params![param], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, i64>(3)? as u64,
                r.get::<_, i64>(4)? as u64,
                r.get::<_, i64>(5)? as u32,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    rows.into_iter()
        .map(|(bucket, hits, bandwidth, rt_sum, rt_count, _rt_max)| {
            let avg_rt_ms = if rt_count > 0 {
                Some(format_ms(rt_sum as f64 / rt_count as f64))
            } else {
                None
            };
            let unique_sites = bucket_visitor_count(conn, period, &bucket)?;
            let unique_sites_fmt = unique_sites.map(|v| count_fmt(v, compact_counts));
            let slug = crate::rules::make_slug(&bucket);
            Ok(BucketIndexRow {
                bucket,
                slug,
                hits,
                bandwidth,
                hits_fmt: count_fmt(hits, compact_counts),
                hits_exact_fmt: super::number_fmt(hits),
                bandwidth_fmt: format_bytes(bandwidth),
                avg_rt_ms,
                unique_sites,
                unique_sites_fmt,
            })
        })
        .collect()
}

/// Build full data for a single bucket sub-page.
pub(super) fn bucket_page_data(
    conn: &Connection,
    period: &str,
    bucket_name: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<BucketPageData> {
    let (hits_total, bw_total) = bucket_totals(conn, period, bucket_name)?;
    let (op, param) = period_clause(period);

    // Summary stats
    let (hits, bandwidth, rt_sum, rt_count, _rt_max) = {
        let sql = format!(
            "SELECT COALESCE(SUM(hits),0), COALESCE(SUM(bandwidth),0), \
                    COALESCE(SUM(rt_sum),0), COALESCE(SUM(rt_count),0), COALESCE(MAX(rt_max),0) \
             FROM bucket_period_stats WHERE period {op} AND bucket = ?2"
        );
        conn.prepare(&sql)?.query_row(params![param, bucket_name], |r| {
            Ok((
                r.get::<_, i64>(0)? as u64,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
                r.get::<_, i64>(3)? as u64,
                r.get::<_, i64>(4)? as u32,
            ))
        })?
    };
    let avg_rt_ms = if rt_count > 0 {
        Some(format_ms(rt_sum as f64 / rt_count as f64))
    } else {
        None
    };
    let p95_rt_ms = bucket_p95(conn, period, bucket_name)?;

    // Top URLs
    let top_urls = bucket_top_urls_union(conn, period, bucket_name, top_n, compact_counts, hits_total, bw_total)?;

    // Status codes (percent of bucket hits)
    let status_codes = bucket_status_rows(conn, period, bucket_name, compact_counts, hits_total)?;

    // Agents and countries
    let agents = bucket_agents_union(conn, period, bucket_name, top_n, compact_counts, hits_total, bw_total)?;
    let countries = bucket_countries_union(conn, period, bucket_name, top_n, compact_counts, hits_total, bw_total)?;

    // Methods and protocols
    let method_codes = bucket_method_rows(conn, period, bucket_name, compact_counts, hits_total)?;
    let proto_codes = bucket_proto_rows(conn, period, bucket_name, compact_counts, hits_total)?;

    // RT distribution
    let rt_distribution_buckets = bucket_rt_distribution(conn, period, bucket_name)?;

    let is_yearly = period.len() == 4;

    // Daily/hourly activity (monthly pages) or monthly breakdown (yearly pages).
    let daily = if is_yearly { Vec::new() } else {
        bucket_daily_stats(conn, period, bucket_name, compact_counts)?
    };
    let hourly = if is_yearly { Vec::new() } else {
        bucket_hourly_distribution(conn, period, bucket_name, compact_counts)?
    };
    let monthly_rows = if is_yearly {
        bucket_monthly_rows(conn, period.parse::<i32>().unwrap_or(0), bucket_name, compact_counts)?
    } else {
        Vec::new()
    };
    // RT over time: daily stats for monthly pages, monthly stats for yearly pages.
    let daily_rt_stats = bucket_daily_rt_stats(conn, period, bucket_name)?;
    let visitors = bucket_visitor_count(conn, period, bucket_name)?;

    let slug = crate::rules::make_slug(bucket_name);
    Ok(BucketPageData {
        bucket: bucket_name.to_string(),
        slug,
        period: period.to_string(),
        hits_fmt: count_fmt(hits, compact_counts),
        hits_exact_fmt: super::number_fmt(hits),
        bandwidth_fmt: format_bytes(bandwidth),
        visitors_fmt: visitors.map(|v| count_fmt(v, compact_counts)),
        visitors_exact_fmt: visitors.map(|v| super::number_fmt(v)),
        avg_rt_ms,
        p95_rt_ms,
        daily,
        hourly,
        monthly_rows,
        daily_rt_stats,
        top_urls,
        status_codes,
        agents,
        countries,
        method_codes,
        proto_codes,
        rt_distribution_buckets,
    })
}

/// Load and compute p95 RT for a bucket+period from stored histograms.
/// Monthly: loads one row. Yearly: merges all monthly rows.
fn bucket_p95(conn: &Connection, period: &str, bucket: &str) -> Result<Option<String>> {
    let rows: Vec<Vec<u8>> = if period.len() == 7 {
        // Monthly — single row.
        let blob: Option<Vec<u8>> = conn
            .query_row(
                "SELECT data FROM bucket_response_time_histograms WHERE period=?1 AND bucket=?2",
                params![period, bucket],
                |r| r.get(0),
            )
            .optional()?;
        blob.into_iter().collect()
    } else {
        // Yearly — merge all monthly rows.
        let like = format!("{period}-%%");
        let mut stmt = conn.prepare(
            "SELECT data FROM bucket_response_time_histograms WHERE period LIKE ?1 AND bucket=?2",
        )?;
        let blobs = stmt
            .query_map(params![like, bucket], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        blobs
    };

    if rows.is_empty() {
        return Ok(None);
    }
    let mut merged = ResponseTimeHistogram::new();
    for blob in &rows {
        merged.merge(
            &ResponseTimeHistogram::deserialize(blob)
                .context("deserialize bucket rt histogram for p95")?,
        );
    }
    Ok(merged.avg().map(|_| format_ms(merged.percentile(95.0) as f64)))
}

fn bucket_status_rows(
    conn: &Connection,
    period: &str,
    bucket: &str,
    compact_counts: bool,
    hits_total: f64,
) -> Result<Vec<StatusRow>> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT status, SUM(hits) FROM bucket_status_codes \
         WHERE period {op} AND bucket = ?2 GROUP BY status ORDER BY SUM(hits) DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let raw = stmt
        .query_map(params![param, bucket], |r| {
            Ok((r.get::<_, i64>(0)? as u16, r.get::<_, i64>(1)? as u64))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(build_status_rows(raw, compact_counts, hits_total))
}

fn bucket_method_rows(
    conn: &Connection,
    period: &str,
    bucket: &str,
    compact_counts: bool,
    hits_total: f64,
) -> Result<Vec<MethodRow>> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT method, SUM(hits) FROM bucket_method_counts \
         WHERE period {op} AND bucket = ?2 GROUP BY method ORDER BY SUM(hits) DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let raw = stmt
        .query_map(params![param, bucket], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(raw
        .into_iter()
        .map(|(method, hits)| MethodRow {
            method,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, hits_total),
        })
        .collect())
}

fn bucket_monthly_rows(
    conn: &Connection,
    year: i32,
    bucket: &str,
    compact_counts: bool,
) -> Result<Vec<MonthRow>> {
    let like = format!("{year}-%");

    // Pre-fetch finalized monthly unique counts.
    let visitor_cache: std::collections::HashMap<String, u64> = {
        let mut stmt = conn.prepare(
            "SELECT period, count FROM bucket_unique_visitor_counts \
             WHERE bucket=?1 AND period LIKE ?2",
        )?;
        let rows = stmt
            .query_map(params![bucket, like], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().collect()
    };

    let mut stmt = conn.prepare(
        "SELECT substr(date,1,7) AS ym, SUM(hits), SUM(bandwidth) \
         FROM bucket_hourly_stats \
         WHERE date LIKE ?1 AND bucket=?2 \
         GROUP BY ym ORDER BY ym",
    )?;
    let rows = stmt
        .query_map(params![like, bucket], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    rows.into_iter()
        .map(|(ym, hits, bandwidth)| {
            let visitors = if let Some(&v) = visitor_cache.get(&ym) {
                v
            } else {
                // Fall back to summing cached daily counts for the month.
                let month_like = format!("{ym}-%");
                conn.query_row(
                    "SELECT COALESCE(SUM(count),0) FROM bucket_daily_visitor_counts \
                     WHERE bucket=?1 AND date LIKE ?2",
                    params![bucket, month_like],
                    |r| r.get::<_, i64>(0).map(|v| v as u64),
                )
                .unwrap_or(0)
            };
            let month = ym.split('-').nth(1).and_then(|m| m.parse::<u32>().ok()).unwrap_or(1);
            Ok(MonthRow {
                period: ym,
                month,
                month_str: format!("{month:02}"),
                month_name: month_name(month).to_string(),
                hits,
                visits: 0,
                visitors,
                bandwidth,
                hits_fmt: count_fmt(hits, compact_counts),
                hits_exact_fmt: super::number_fmt(hits),
                bandwidth_fmt: format_bytes(bandwidth),
                visits_fmt: String::new(),
                visits_exact_fmt: String::new(),
                visitors_fmt: count_fmt(visitors, compact_counts),
                visitors_exact_fmt: super::number_fmt(visitors),
            })
        })
        .collect()
}

fn bucket_daily_stats(
    conn: &Connection,
    period: &str,
    bucket: &str,
    compact_counts: bool,
) -> Result<Vec<DailyRow>> {
    let like = format!("{period}-%");

    // Batch-fetch daily unique IP counts: cached rows for finalized months,
    // live bitmap count column for the current in-progress month.
    let visitor_cache: std::collections::HashMap<String, u64> = {
        let mut stmt = conn.prepare(
            "SELECT date, SUM(count) \
             FROM ( \
               SELECT date, count FROM bucket_daily_visitor_counts WHERE bucket=?1 AND date LIKE ?2 \
               UNION ALL \
               SELECT date, SUM(count) AS count FROM bucket_daily_unique_ips \
                 WHERE bucket=?1 AND date LIKE ?2 GROUP BY date \
             ) GROUP BY date",
        )?;
        let rows = stmt
            .query_map(params![bucket, like], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().collect()
    };

    let mut stmt = conn.prepare(
        "SELECT date, SUM(hits), SUM(bandwidth) \
         FROM bucket_hourly_stats \
         WHERE date LIKE ?1 AND bucket = ?2 \
         GROUP BY date ORDER BY date",
    )?;
    let rows = stmt
        .query_map(params![like, bucket], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    rows.into_iter()
        .map(|(date, hits, bandwidth)| {
            let is_weekend = NaiveDate::parse_from_str(&date, "%Y-%m-%d")
                .map(|d| matches!(d.weekday(), Weekday::Sat | Weekday::Sun))
                .unwrap_or(false);
            let visitors = visitor_cache.get(&date).copied().unwrap_or(0);
            Ok(DailyRow {
                is_weekend,
                hits,
                bandwidth,
                visits: 0,
                visitors,
                hits_fmt: count_fmt(hits, compact_counts),
                hits_exact_fmt: super::number_fmt(hits),
                bandwidth_fmt: format_bytes(bandwidth),
                visits_fmt: String::new(),
                visits_exact_fmt: String::new(),
                visitors_fmt: count_fmt(visitors, compact_counts),
                visitors_exact_fmt: super::number_fmt(visitors),
                date,
            })
        })
        .collect()
}

/// Total unique IPs for a bucket in a period.
/// Returns None if no data is available yet.
fn bucket_visitor_count(conn: &Connection, period: &str, bucket: &str) -> Result<Option<u64>> {
    // Try cached monthly count first.
    let cached: Option<u64> = conn
        .query_row(
            "SELECT count FROM bucket_unique_visitor_counts WHERE bucket=?1 AND period=?2",
            params![bucket, period],
            |r| r.get::<_, i64>(0).map(|v| v as u64),
        )
        .optional()?;
    if let Some(v) = cached {
        return Ok(Some(v));
    }
    // Fall back to summing the count column from live bitmap rows.
    let like = format!("{period}-%");
    let live: Option<u64> = conn
        .query_row(
            "SELECT SUM(count) FROM bucket_daily_unique_ips WHERE bucket=?1 AND date LIKE ?2",
            params![bucket, like],
            |r| Ok(r.get::<_, Option<i64>>(0)?.map(|v| v as u64)),
        )
        .optional()?
        .flatten();
    Ok(live)
}

fn bucket_hourly_distribution(
    conn: &Connection,
    period: &str,
    bucket: &str,
    compact_counts: bool,
) -> Result<Vec<HourlyRow>> {
    let like = format!("{period}-%");
    let mut stmt = conn.prepare(
        "SELECT hour, SUM(hits), SUM(bandwidth) \
         FROM bucket_hourly_stats \
         WHERE date LIKE ?1 AND bucket = ?2 \
         GROUP BY hour ORDER BY hour",
    )?;
    let rows = stmt
        .query_map(params![like, bucket], |r| {
            Ok((
                r.get::<_, i64>(0)? as u8,
                r.get::<_, i64>(1)? as u64,
                r.get::<_, i64>(2)? as u64,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    rows.into_iter()
        .map(|(hour, hits, bandwidth)| {
            Ok(HourlyRow {
                hour,
                label: format!("{hour:02}:00"),
                hits,
                bandwidth,
                visits: 0,
                visits_fmt: String::new(),
                visits_exact_fmt: String::new(),
                hits_fmt: count_fmt(hits, compact_counts),
                hits_exact_fmt: super::number_fmt(hits),
                bandwidth_fmt: format_bytes(bandwidth),
            })
        })
        .collect()
}

fn bucket_daily_rt_stats(
    conn: &Connection,
    period: &str,
    bucket: &str,
) -> Result<Vec<DailyRtStat>> {
    let like = format!("{period}-%");
    // Prefer persisted stats (finalized months); fall back to live daily histograms.
    let persisted: Vec<(String, f64, u32)> = {
        let mut stmt = conn.prepare(
            "SELECT date, avg_ms, p95_ms \
             FROM bucket_daily_response_time_stats \
             WHERE date LIKE ?1 AND bucket = ?2 ORDER BY date",
        )?;
        let rows = stmt
            .query_map(params![like, bucket], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, f64>(1)?,
                    r.get::<_, i64>(2)? as u32,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };

    if !persisted.is_empty() {
        return Ok(persisted
            .into_iter()
            .map(|(date, avg_ms, p95_ms)| DailyRtStat { date, avg_ms, p95_ms })
            .collect());
    }

    // Current month — load live histograms.
    let blobs: Vec<(String, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT date, data FROM bucket_daily_response_time_histograms \
             WHERE date LIKE ?1 AND bucket = ?2 ORDER BY date",
        )?;
        let rows = stmt
            .query_map(params![like, bucket], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };

    blobs
        .into_iter()
        .filter_map(|(date, blob)| {
            let hist = ResponseTimeHistogram::deserialize(&blob).ok()?;
            let avg_ms = hist.avg()?;
            let p95_ms = hist.percentile(95.0);
            Some(Ok(DailyRtStat { date, avg_ms, p95_ms }))
        })
        .collect()
}

/// Compute RT distribution display buckets from stored bucket histograms.
/// Mirrors `monthly_rt_histogram_buckets` logic.
fn bucket_rt_distribution(
    conn: &Connection,
    period: &str,
    bucket: &str,
) -> Result<Vec<(String, u64)>> {
    // Load and merge histogram blobs for this bucket+period.
    let blobs: Vec<Vec<u8>> = if period.len() == 7 {
        let blob: Option<Vec<u8>> = conn
            .query_row(
                "SELECT data FROM bucket_response_time_histograms WHERE period=?1 AND bucket=?2",
                params![period, bucket],
                |r| r.get(0),
            )
            .optional()?;
        blob.into_iter().collect()
    } else {
        let like = format!("{period}-%%");
        let mut stmt = conn.prepare(
            "SELECT data FROM bucket_response_time_histograms WHERE period LIKE ?1 AND bucket=?2",
        )?;
        let rows = stmt
            .query_map(params![like, bucket], |r| r.get::<_, Vec<u8>>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };

    if blobs.is_empty() {
        return Ok(Vec::new());
    }
    let mut hist = ResponseTimeHistogram::new();
    for blob in &blobs {
        hist.merge(
            &ResponseTimeHistogram::deserialize(blob)
                .context("deserialize bucket rt histogram for distribution")?,
        );
    }
    if hist.count == 0 {
        return Ok(Vec::new());
    }

    const BUCKET_SIZE: usize = 10;
    const NUM_BUCKETS: usize = 20;
    let mut out_buckets = vec![0u64; NUM_BUCKETS + 1];
    for (ms, &count) in hist.buckets.iter().enumerate() {
        if count == 0 {
            continue;
        }
        let idx = if ms >= NUM_BUCKETS * BUCKET_SIZE { NUM_BUCKETS } else { ms / BUCKET_SIZE };
        out_buckets[idx] += count as u64;
    }
    out_buckets[NUM_BUCKETS] += hist.overflow as u64;

    let mut out: Vec<(String, u64)> = (0..NUM_BUCKETS)
        .map(|i| {
            let lo = i * BUCKET_SIZE;
            let hi = lo + BUCKET_SIZE - 1;
            (format!("{lo}–{hi}ms"), out_buckets[i])
        })
        .collect();
    out.push((format!("{}ms+", NUM_BUCKETS * BUCKET_SIZE), out_buckets[NUM_BUCKETS]));
    while out.last().map_or(false, |(_, c)| *c == 0) {
        out.pop();
    }
    Ok(out)
}

fn bucket_proto_rows(
    conn: &Connection,
    period: &str,
    bucket: &str,
    compact_counts: bool,
    hits_total: f64,
) -> Result<Vec<ProtoRow>> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT proto, SUM(hits) FROM bucket_protocol_counts \
         WHERE period {op} AND bucket = ?2 GROUP BY proto ORDER BY SUM(hits) DESC"
    );
    let mut stmt = conn.prepare(&sql)?;
    let raw = stmt
        .query_map(params![param, bucket], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(raw
        .into_iter()
        .map(|(proto, hits)| ProtoRow {
            proto,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, hits_total),
        })
        .collect())
}

/// Returns a map of period → unix timestamp (seconds) for all periods that have
/// been written since the last run. Used by `generate_html` to skip up-to-date pages.
pub(super) fn period_last_updated(conn: &Connection) -> Result<HashMap<String, u64>> {
    let mut stmt = conn.prepare(
        "SELECT period, updated_at FROM period_last_updated",
    )?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? as u64)))?
        .collect::<rusqlite::Result<HashMap<String, u64>>>()?;
    Ok(rows)
}

#[cfg(test)]
mod tests;
