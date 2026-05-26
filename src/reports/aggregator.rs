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
    status_label, DailyAvgMax, DailyRow, DailyRtStat, HourlyAvgMax, HourlyRow, MethodRow,
    MonthRow, MonthlyRtStat, MonthlySummary, OverallSummary, PeriodMonth, ProtoRow,
    StatusRow, TopAgentRow, TopCountryRow, TopHostRow, TopRefRow, TopUrlRow, TotalsView,
    YearAggregateRow, YearlySummary,
};

// Returns ("= ?1", period) for monthly (7-char) periods, ("LIKE ?1", "YYYY-%") for yearly.
fn period_clause(period: &str) -> (&'static str, String) {
    if period.len() == 7 {
        ("= ?1", period.to_string())
    } else {
        ("LIKE ?1", format!("{}-%", period))
    }
}

fn build_status_rows(raw: Vec<(u16, u64)>, compact_counts: bool) -> Vec<StatusRow> {
    let total = raw.iter().map(|(_, hits)| *hits).sum::<u64>() as f64;
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

    let top_urls_hits = top_urls_hits(conn, &period, top_n, compact_counts)?;
    let top_urls_bandwidth = top_urls_bandwidth(conn, &period, top_n, compact_counts)?;
    let top_ips_hits = top_ips_hits(conn, &period, top_n, compact_counts, anonymise_ips)?;
    let top_ips_bandwidth = top_ips_bandwidth(conn, &period, top_n, compact_counts, anonymise_ips)?;
    let top_refs = top_refs(conn, &period, top_n, compact_counts)?;

    let top_agents_raw = top_agents_raw(conn, &period, top_n)?;
    let top_countries_raw = top_countries_raw(conn, &period, top_n)?;

    let top_agents_total = top_agents_raw.iter().map(|(_, hits)| *hits).sum::<u64>() as f64;
    let top_countries_total = top_countries_raw
        .iter()
        .map(|(_, _, hits)| *hits)
        .sum::<u64>() as f64;

    let top_agents = top_agents_raw
        .into_iter()
        .map(|(agent, hits)| TopAgentRow {
            agent,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, top_agents_total),
        })
        .collect();

    let top_countries = top_countries_raw
        .into_iter()
        .map(|(country_code, country_name, hits)| TopCountryRow {
            country_flag: flag_emoji(&country_code),
            country_code,
            country_name,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, top_countries_total),
        })
        .collect();

    let status_codes = status_codes(conn, &period, compact_counts)?;
    let proto_codes = proto_codes(conn, &period, compact_counts)?;
    let method_codes = method_codes(conn, &period, compact_counts)?;
    let daily_avg_max = daily_avg_max_from_rows(&daily, compact_counts);
    let hourly_avg_max = hourly_avg_max(conn, year, month, compact_counts)?;
    let top_slow_urls = top_urls_avg_rt(conn, &period, top_n, compact_counts)?;
    let daily_rt_stats = daily_rt_stats_for_month(conn, year, month)?;
    let rt_distribution_buckets = monthly_rt_histogram_buckets(conn, &period)?;

    Ok(MonthlySummary {
        period,
        year,
        month_name: month_name(month as u32).to_string(),
        daily,
        hourly,
        totals,
        top_urls_hits,
        top_urls_bandwidth,
        top_ips_hits,
        top_ips_bandwidth,
        top_refs,
        top_agents,
        top_countries,
        status_codes,
        proto_codes,
        method_codes,
        daily_avg_max,
        hourly_avg_max,
        top_slow_urls,
        daily_rt_stats,
        rt_distribution_buckets,
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

    let top_urls_hits = top_urls_hits(conn, &period, top_n, compact_counts)?;
    let top_urls_bandwidth = top_urls_bandwidth(conn, &period, top_n, compact_counts)?;
    let top_ips_hits = top_ips_hits(conn, &period, top_n, compact_counts, anonymise_ips)?;
    let top_ips_bandwidth = top_ips_bandwidth(conn, &period, top_n, compact_counts, anonymise_ips)?;
    let top_refs = top_refs(conn, &period, top_n, compact_counts)?;
    let top_agents_raw = top_agents_raw(conn, &period, top_n)?;
    let top_countries_raw = top_countries_raw(conn, &period, top_n)?;

    let top_agents_total = top_agents_raw.iter().map(|(_, hits)| *hits).sum::<u64>() as f64;
    let top_countries_total = top_countries_raw
        .iter()
        .map(|(_, _, hits)| *hits)
        .sum::<u64>() as f64;

    let top_agents = top_agents_raw
        .into_iter()
        .map(|(agent, hits)| TopAgentRow {
            agent,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, top_agents_total),
        })
        .collect();

    let top_countries = top_countries_raw
        .into_iter()
        .map(|(country_code, country_name, hits)| TopCountryRow {
            country_flag: flag_emoji(&country_code),
            country_code,
            country_name,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, top_countries_total),
        })
        .collect();

    let status_codes = status_codes(conn, &period, compact_counts)?;
    let proto_codes = proto_codes(conn, &period, compact_counts)?;
    let method_codes = method_codes(conn, &period, compact_counts)?;
    let monthly_rt_stats = monthly_rt_stats_for_year(conn, year)?;
    let top_slow_urls = top_urls_avg_rt(conn, &period, top_n, compact_counts)?;

    Ok(YearlySummary {
        year,
        monthly_rows,
        top_urls_hits,
        top_urls_bandwidth,
        top_ips_hits,
        top_ips_bandwidth,
        top_refs,
        top_agents,
        top_countries,
        status_codes,
        proto_codes,
        method_codes,
        totals,
        monthly_rt_stats,
        top_slow_urls,
    })
}

pub(super) fn overall_summary(
    conn: &Connection,
    top_n: usize,
    compact_counts: bool,
) -> Result<OverallSummary> {
    let yearly_rows = yearly_rows(conn, compact_counts)?;
    let totals = overall_totals(conn, compact_counts)?;

    let top_agents_raw = top_agents_all_raw(conn, top_n)?;
    let top_countries_raw = top_countries_all_raw(conn, top_n)?;

    let top_agents_total = top_agents_raw.iter().map(|(_, hits)| *hits).sum::<u64>() as f64;
    let top_countries_total = top_countries_raw
        .iter()
        .map(|(_, _, hits)| *hits)
        .sum::<u64>() as f64;

    let top_agents = top_agents_raw
        .into_iter()
        .map(|(agent, hits)| TopAgentRow {
            agent,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, top_agents_total),
        })
        .collect();

    let top_countries = top_countries_raw
        .into_iter()
        .map(|(country_code, country_name, hits)| TopCountryRow {
            country_flag: flag_emoji(&country_code),
            country_code,
            country_name,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, top_countries_total),
        })
        .collect();

    let status_codes = status_codes_all(conn, compact_counts)?;
    let all_time_available = all_time_visitor_count(conn)? > 0;

    Ok(OverallSummary {
        yearly_rows,
        top_agents,
        top_countries,
        status_codes,
        totals,
        all_time_available,
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
            or_count_yearly_and_daily_bitmaps(conn, &yr, &format!("{yr}-%"))?
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
    or_count_yearly_and_daily_bitmaps(conn, year, &format!("{}-%", year))
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

/// OR yearly_unique_ips (completed months) with daily_unique_ips (in-progress month)
/// for the given year and return the distinct IP count.
fn or_count_yearly_and_daily_bitmaps(
    conn: &Connection,
    year: &str,
    daily_like: &str,
) -> Result<u64> {
    let mut v4 = RoaringBitmap::new();
    let mut v6: HashMap<u64, RoaringTreemap> = HashMap::new();

    let yearly_rows: Vec<(u8, u64, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT ip_kind, ip_hi, bitmap FROM yearly_unique_ips WHERE year = ?1",
        )?;
        let mapped = stmt.query_map(params![year], |row| {
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
    or_into_bitmaps(yearly_rows, "yearly", &mut v4, &mut v6)?;

    let daily_rows: Vec<(u8, u64, Vec<u8>)> = {
        let mut stmt = conn.prepare(
            "SELECT ip_kind, ip_hi, bitmap FROM daily_unique_ips WHERE date LIKE ?1",
        )?;
        let mapped = stmt.query_map(params![daily_like], |row| {
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
    or_into_bitmaps(daily_rows, "daily (yearly fallback)", &mut v4, &mut v6)?;

    Ok(v4.len() + v6.values().map(|t| t.len()).sum::<u64>())
}

fn all_time_visitor_count(conn: &Connection) -> Result<u64> {
    let rows: Vec<(u8, Vec<u8>)> = {
        let mut stmt = conn.prepare("SELECT ip_kind, bitmap FROM all_time_ips")?;
        let mapped = stmt.query_map([], |row| {
            Ok((row.get::<_, i64>(0)? as u8, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut v = Vec::new();
        for row in mapped {
            v.push(row?);
        }
        v
    };
    let mut total = 0u64;
    for (kind, blob) in rows {
        total += match kind {
            1 => RoaringBitmap::deserialize_from(&blob[..])
                .context("deserialize all_time v4")?
                .len(),
            2 => RoaringTreemap::deserialize_from(&blob[..])
                .context("deserialize all_time v6")?
                .len(),
            _ => 0,
        };
    }
    Ok(total)
}

fn top_urls_hits(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopUrlRow>> {
    top_urls_sorted(conn, period, top_n, compact_counts, "hits")
}

fn top_urls_bandwidth(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopUrlRow>> {
    top_urls_sorted(conn, period, top_n, compact_counts, "bandwidth")
}

fn top_urls_sorted(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
    order_col: &str,
) -> Result<Vec<TopUrlRow>> {
    if top_n == 0 {
        return Ok(Vec::new());
    }
    let is_monthly = period.len() == 7;
    let (op, param) = period_clause(period);

    // For monthly: read rt_hist blob to compute P95. For yearly: GROUP BY SUM, no blob.
    let sql = if is_monthly {
        format!(
            "SELECT url, hits, bandwidth, rt_sum, rt_count, rt_max \
             FROM monthly_top_urls WHERE period {op} \
             ORDER BY {order_col} DESC LIMIT ?2"
        )
    } else {
        format!(
            "SELECT url, SUM(hits), SUM(bandwidth), SUM(rt_sum), SUM(rt_count), MAX(rt_max) \
             FROM monthly_top_urls WHERE period {op} \
             GROUP BY url ORDER BY {order_col} DESC LIMIT ?2"
        )
    };

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params![param, top_n as i64], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)? as u64,
                row.get::<_, i64>(2)? as u64,
                row.get::<_, i64>(3)? as u64,
                row.get::<_, i64>(4)? as u64,
                row.get::<_, i64>(5)? as u32,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;

    rows.into_iter()
        .map(|(url, hits, bandwidth, rt_sum, rt_count, rt_max)| {
            let (avg_ms_fmt, max_ms_fmt) = rt_display(rt_sum, rt_count, rt_max);
            Ok(TopUrlRow {
                url,
                hits,
                bandwidth,
                hits_fmt: count_fmt(hits, compact_counts),
                hits_exact_fmt: super::number_fmt(hits),
                bandwidth_fmt: format_bytes(bandwidth),
                avg_ms_fmt,
                max_ms_fmt,
            })
        })
        .collect()
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

fn top_ips_hits(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
    anonymise_ips: bool,
) -> Result<Vec<TopHostRow>> {
    top_ips_sorted(conn, period, top_n, compact_counts, "hits", anonymise_ips)
}

fn top_ips_bandwidth(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
    anonymise_ips: bool,
) -> Result<Vec<TopHostRow>> {
    top_ips_sorted(conn, period, top_n, compact_counts, "bandwidth", anonymise_ips)
}

fn top_ips_sorted(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
    order_col: &str,
    anonymise_ips: bool,
) -> Result<Vec<TopHostRow>> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT t.host_kind, t.host_hi, t.host_lo,
                SUM(t.hits) AS hits, SUM(t.bandwidth) AS bandwidth,
                COALESCE(MAX(t.country_code), '--'),
                COALESCE(MAX(cn.country_name), 'Unknown')
         FROM monthly_top_ips t
         LEFT JOIN countries cn ON cn.country_code = t.country_code
         WHERE t.period {op}
         GROUP BY t.host_kind, t.host_hi, t.host_lo
         ORDER BY {order_col} DESC, hits DESC
         LIMIT ?2"
    );
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![param, top_n as i64], |row| {
        let host_kind = row.get::<_, i64>(0)? as u8;
        let host_hi = row.get::<_, i64>(1)? as u64;
        let host_lo = row.get::<_, i64>(2)? as u64;
        let hits = row.get::<_, i64>(3)? as u64;
        let bandwidth = row.get::<_, i64>(4)? as u64;
        let country_code = row.get::<_, String>(5)?;
        Ok(TopHostRow {
            host: decode_host(host_kind, host_hi, host_lo, anonymise_ips),
            hits,
            bandwidth,
            country_flag: flag_emoji(&country_code),
            country_code: country_code.clone(),
            country_name: row.get::<_, String>(6)?,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            bandwidth_fmt: format_bytes(bandwidth),
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
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

#[cfg(test)]
fn encode_host(host: &str) -> (u8, u64, u64, String) {
    if let Ok(v4) = host.parse::<Ipv4Addr>() {
        return (1, 0, u32::from(v4) as u64, String::new());
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        let n = u128::from(v6);
        return (2, (n >> 64) as u64, n as u64, String::new());
    }
    (0, 0, 0, host.to_string())
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
         FROM monthly_referrers
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

fn top_agents_raw(conn: &Connection, period: &str, top_n: usize) -> Result<Vec<(String, u64)>> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT agent_family, SUM(hits) AS hits
         FROM monthly_agents
         WHERE period {op}
         GROUP BY agent_family
         ORDER BY hits DESC
         LIMIT ?2"
    );
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![param, top_n as i64], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn top_agents_all_raw(conn: &Connection, top_n: usize) -> Result<Vec<(String, u64)>> {
    let mut stmt = conn.prepare(
        "SELECT agent_family, SUM(hits) AS hits
         FROM monthly_agents
         GROUP BY agent_family
         ORDER BY hits DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map(params![top_n as i64], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn top_countries_raw(
    conn: &Connection,
    period: &str,
    limit: usize,
) -> Result<Vec<(String, String, u64)>> {
    let (op, param) = period_clause(period);
    let sql = format!(
        "SELECT c.country_code,
                COALESCE(n.country_name, 'Unknown') AS country_name,
                SUM(c.hits) AS hits
         FROM top_countries c
         LEFT JOIN countries n ON n.country_code = c.country_code
         WHERE c.period {op}
         GROUP BY c.country_code
         ORDER BY hits DESC
         LIMIT ?2"
    );
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![param, limit as i64], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)? as u64,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn top_countries_all_raw(conn: &Connection, limit: usize) -> Result<Vec<(String, String, u64)>> {
    let mut stmt = conn.prepare(
        "WITH country_hits AS (
             SELECT country_code, SUM(hits) AS hits
             FROM top_countries
             GROUP BY country_code
         )
         SELECT h.country_code,
                COALESCE(n.country_name, 'Unknown') AS country_name,
                h.hits
         FROM country_hits h
         LEFT JOIN countries n ON n.country_code = h.country_code
         ORDER BY h.hits DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map(params![limit as i64], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)? as u64,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
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
    Ok(build_status_rows(raw, compact_counts))
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
    Ok(build_status_rows(raw, compact_counts))
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

    let total = raw.iter().map(|(_, hits)| *hits).sum::<u64>() as f64;
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

    let total = raw.iter().map(|(_, hits)| *hits).sum::<u64>() as f64;
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

fn top_urls_avg_rt(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopUrlRow>> {
    if top_n == 0 {
        return Ok(Vec::new());
    }
    let (op, param) = period_clause(period);
    let sql = if period.len() == 7 {
        format!(
            "SELECT url, hits, bandwidth, rt_sum, rt_count, rt_max \
             FROM monthly_top_urls WHERE period {op} AND rt_count>0 \
             ORDER BY rt_sum*1.0/rt_count DESC LIMIT ?2"
        )
    } else {
        format!(
            "SELECT url, SUM(hits), SUM(bandwidth), SUM(rt_sum), SUM(rt_count), MAX(rt_max) \
             FROM monthly_top_urls WHERE period {op} \
             GROUP BY url HAVING SUM(rt_count)>0 \
             ORDER BY SUM(rt_sum)*1.0/SUM(rt_count) DESC LIMIT ?2"
        )
    };
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(params![param, top_n as i64], |r| {
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
        .map(|(url, hits, bandwidth, rt_sum, rt_count, rt_max)| {
            let (avg_ms_fmt, max_ms_fmt) = rt_display(rt_sum, rt_count, rt_max);
            Ok(TopUrlRow {
                url,
                hits,
                bandwidth,
                hits_fmt: count_fmt(hits, compact_counts),
                hits_exact_fmt: super::number_fmt(hits),
                bandwidth_fmt: format_bytes(bandwidth),
                avg_ms_fmt,
                max_ms_fmt,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
