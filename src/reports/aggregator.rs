// Report aggregation: SQL queries that summarise the database into per-period statistics for templates.

use std::collections::{BTreeMap, HashMap};
use std::net::{Ipv4Addr, Ipv6Addr};

use roaring::{RoaringBitmap, RoaringTreemap};

use anyhow::{Context, Result};
use chrono::{Datelike, NaiveDate, Weekday};
use rusqlite::{params, Connection, OptionalExtension};

use super::{
    count_fmt, flag_emoji, format_bytes, format_totals, month_name, percent_str, status_label,
    DailyAvgMax, DailyRow, HourlyAvgMax, HourlyRow, MethodRow, MonthRow, MonthlySummary,
    OverallSummary, PeriodMonth, ProtoRow, StatusRow, TopAgentRow, TopCountryRow, TopHostRow,
    TopRefRow, TopUrlRow, TotalsView, YearAggregateRow, YearlySummary,
};

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
    let totals = monthly_totals(conn, year, month, compact_counts)?;

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
    let totals = yearly_totals(conn, year, compact_counts)?;

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

    let visitors = visitor_count_for_scope(conn, &prefix)?;

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

    let visitors = visitor_count_for_scope(conn, &year.to_string())?;

    Ok(format_totals(row.0, row.1, visitors, row.2, compact_counts))
}

fn monthly_rows(conn: &Connection, year: i32, compact_counts: bool) -> Result<Vec<MonthRow>> {
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
        let visitors = visitor_count_for_scope(conn, &ym)?;
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
        let visitors = visitor_count_for_scope(conn, &yr)?;
        let year = yr.parse::<i32>().unwrap_or(0);
        if year <= 0 {
            continue;
        }

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

fn visitor_count_for_scope(conn: &Connection, scope: &str) -> Result<u64> {
    match scope.len() {
        10 => {
            // Daily: SUM of bitmap cardinalities in the count column, falling back to archive.
            let count: i64 = conn.query_row(
                "SELECT COALESCE(
                    (SELECT SUM(count) FROM daily_unique_ips WHERE date = ?1),
                    (SELECT count FROM daily_visitor_counts WHERE date = ?1),
                    0
                 )",
                params![scope],
                |row| row.get(0),
            )?;
            Ok(count as u64)
        }
        7 => {
            // Monthly: use precomputed cache; for the in-progress month OR daily bitmaps in Rust.
            let cached: Option<i64> = conn.query_row(
                "SELECT count FROM unique_visitor_counts WHERE period = ?1",
                params![scope],
                |row| row.get(0),
            )
            .optional()?;
            if let Some(n) = cached {
                return Ok(n as u64);
            }
            let like = format!("{}-%", scope);
            or_count_daily_bitmaps(conn, &like)
        }
        4 => {
            // Yearly: use precomputed cache; for the in-progress year combine yearly and daily bitmaps.
            let cached: Option<i64> = conn.query_row(
                "SELECT count FROM unique_visitor_counts WHERE period = ?1",
                params![scope],
                |row| row.get(0),
            )
            .optional()?;
            if let Some(n) = cached {
                return Ok(n as u64);
            }
            let like = format!("{}-%", scope);
            or_count_yearly_and_daily_bitmaps(conn, scope, &like)
        }
        _ => Ok(0),
    }
}

/// OR all daily_unique_ips bitmaps matching `like` and return the distinct IP count.
fn or_count_daily_bitmaps(conn: &Connection, like: &str) -> Result<u64> {
    let rows: Vec<(u8, u64, Vec<u8>)> = {
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
        let mut v = Vec::new();
        for row in mapped {
            v.push(row?);
        }
        v
    };

    let mut v4 = RoaringBitmap::new();
    let mut v6: HashMap<u64, RoaringTreemap> = HashMap::new();
    for (kind, hi, blob) in rows {
        match kind {
            1 => {
                v4 |= RoaringBitmap::deserialize_from(&blob[..])
                    .context("deserialize daily v4")?;
            }
            2 => {
                *v6.entry(hi).or_default() |=
                    RoaringTreemap::deserialize_from(&blob[..])
                        .context("deserialize daily v6")?;
            }
            _ => {}
        }
    }
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

    // Yearly bitmaps (already OR'd across finalized months)
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
    for (kind, hi, blob) in yearly_rows {
        match kind {
            1 => {
                v4 |= RoaringBitmap::deserialize_from(&blob[..])
                    .context("deserialize yearly v4")?;
            }
            2 => {
                *v6.entry(hi).or_default() |=
                    RoaringTreemap::deserialize_from(&blob[..])
                        .context("deserialize yearly v6")?;
            }
            _ => {}
        }
    }

    // Daily bitmaps (in-progress current month)
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
    for (kind, hi, blob) in daily_rows {
        match kind {
            1 => {
                v4 |= RoaringBitmap::deserialize_from(&blob[..])
                    .context("deserialize daily v4 (yearly fallback)")?;
            }
            2 => {
                *v6.entry(hi).or_default() |=
                    RoaringTreemap::deserialize_from(&blob[..])
                        .context("deserialize daily v6 (yearly fallback)")?;
            }
            _ => {}
        }
    }

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
    top_urls_from_table(
        conn,
        "monthly_top_urls_hits",
        period,
        top_n,
        compact_counts,
        "hits",
    )
}

fn top_urls_bandwidth(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopUrlRow>> {
    top_urls_from_table(
        conn,
        "monthly_top_urls_bandwidth",
        period,
        top_n,
        compact_counts,
        "bandwidth",
    )
}

fn top_urls_from_table(
    conn: &Connection,
    table: &str,
    period: &str,
    top_n: usize,
    compact_counts: bool,
    order_metric: &str,
) -> Result<Vec<TopUrlRow>> {
    let (sql, period_param) = if period.len() == 7 {
        (
            format!(
                "SELECT url, hits, bandwidth
                 FROM {table}
                 WHERE period = ?1
                 ORDER BY {order_metric} DESC, hits DESC
                 LIMIT ?2"
            ),
            period.to_string(),
        )
    } else {
        (
            format!(
                "SELECT url, SUM(hits) AS hits, SUM(bandwidth) AS bandwidth
                 FROM {table}
                 WHERE period LIKE ?1
                 GROUP BY url
                 ORDER BY {order_metric} DESC, hits DESC
                 LIMIT ?2"
            ),
            format!("{}-%", period),
        )
    };
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![period_param, top_n as i64], |row| {
        Ok(TopUrlRow {
            url: row.get::<_, String>(0)?,
            hits: row.get::<_, i64>(1)? as u64,
            bandwidth: row.get::<_, i64>(2)? as u64,
            hits_fmt: String::new(),
            hits_exact_fmt: String::new(),
            bandwidth_fmt: String::new(),
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        let mut row = row?;
        row.hits_fmt = count_fmt(row.hits, compact_counts);
        row.hits_exact_fmt = super::number_fmt(row.hits);
        row.bandwidth_fmt = format_bytes(row.bandwidth);
        out.push(row);
    }

    Ok(out)
}

fn top_ips_hits(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
    anonymise_ips: bool,
) -> Result<Vec<TopHostRow>> {
    top_ips_from_table(
        conn,
        "monthly_top_ips_hits",
        period,
        top_n,
        compact_counts,
        "hits",
        anonymise_ips,
    )
}

fn top_ips_bandwidth(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
    anonymise_ips: bool,
) -> Result<Vec<TopHostRow>> {
    top_ips_from_table(
        conn,
        "monthly_top_ips_bandwidth",
        period,
        top_n,
        compact_counts,
        "bandwidth",
        anonymise_ips,
    )
}

fn top_ips_from_table(
    conn: &Connection,
    table: &str,
    period: &str,
    top_n: usize,
    compact_counts: bool,
    order_metric: &str,
    anonymise_ips: bool,
) -> Result<Vec<TopHostRow>> {
    let (sql, period_param) = if period.len() == 7 {
        (
            format!(
                "SELECT t.host_kind, t.host_hi, t.host_lo,
                        t.hits, t.bandwidth,
                        COALESCE(t.country_code, '--'),
                        COALESCE(cn.country_name, 'Unknown')
                 FROM {table} t
                 LEFT JOIN countries cn ON cn.country_code = t.country_code
                 WHERE t.period = ?1
                 ORDER BY {order_metric} DESC, t.hits DESC
                 LIMIT ?2"
            ),
            period.to_string(),
        )
    } else {
        (
            format!(
                "SELECT t.host_kind, t.host_hi, t.host_lo,
                        SUM(t.hits) AS hits, SUM(t.bandwidth) AS bandwidth,
                        COALESCE(MAX(t.country_code), '--'),
                        COALESCE(MAX(cn.country_name), 'Unknown')
                 FROM {table} t
                 LEFT JOIN countries cn ON cn.country_code = t.country_code
                 WHERE t.period LIKE ?1
                 GROUP BY t.host_kind, t.host_hi, t.host_lo
                 ORDER BY {order_metric} DESC, hits DESC
                 LIMIT ?2"
            ),
            format!("{}-%", period),
        )
    };
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![period_param, top_n as i64], |row| {
        let host_kind = row.get::<_, i64>(0)? as u8;
        let host_hi = row.get::<_, i64>(1)? as u64;
        let host_lo = row.get::<_, i64>(2)? as u64;
        let country_code = row.get::<_, String>(5)?;
        Ok(TopHostRow {
            host: decode_host(host_kind, host_hi, host_lo, anonymise_ips),
            hits: row.get::<_, i64>(3)? as u64,
            bandwidth: row.get::<_, i64>(4)? as u64,
            country_flag: flag_emoji(&country_code),
            country_code: country_code.clone(),
            country_name: row.get::<_, String>(6)?,
            hits_fmt: String::new(),
            hits_exact_fmt: String::new(),
            bandwidth_fmt: String::new(),
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        let mut row = row?;
        row.hits_fmt = count_fmt(row.hits, compact_counts);
        row.hits_exact_fmt = super::number_fmt(row.hits);
        row.bandwidth_fmt = format_bytes(row.bandwidth);
        out.push(row);
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
    let (sql, period_param) = if period.len() == 7 {
        (
            "SELECT referrer, hits
             FROM monthly_referrers
             WHERE period = ?1
             ORDER BY hits DESC
             LIMIT ?2"
                .to_string(),
            period.to_string(),
        )
    } else {
        (
            "SELECT referrer, SUM(hits) AS hits
             FROM monthly_referrers
             WHERE period LIKE ?1
             GROUP BY referrer
             ORDER BY hits DESC
             LIMIT ?2"
                .to_string(),
            format!("{}-%", period),
        )
    };
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![period_param, top_n as i64], |row| {
        Ok(TopRefRow {
            referrer: row.get::<_, String>(0)?,
            hits: row.get::<_, i64>(1)? as u64,
            hits_fmt: String::new(),
            hits_exact_fmt: String::new(),
        })
    })?;

    let mut out = Vec::new();
    for row in rows {
        let mut row = row?;
        row.hits_fmt = count_fmt(row.hits, compact_counts);
        row.hits_exact_fmt = super::number_fmt(row.hits);
        out.push(row);
    }

    Ok(out)
}

fn top_agents_raw(conn: &Connection, period: &str, top_n: usize) -> Result<Vec<(String, u64)>> {
    let (sql, period_param) = if period.len() == 7 {
        (
            "SELECT agent_family, hits
             FROM monthly_agents
             WHERE period = ?1
             ORDER BY hits DESC
             LIMIT ?2"
                .to_string(),
            period.to_string(),
        )
    } else {
        (
            "SELECT agent_family, SUM(hits) AS hits
             FROM monthly_agents
             WHERE period LIKE ?1
             GROUP BY agent_family
             ORDER BY hits DESC
             LIMIT ?2"
                .to_string(),
            format!("{}-%", period),
        )
    };
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![period_param, top_n as i64], |row| {
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
    let (sql, period_param) = if period.len() == 7 {
        (
            "SELECT c.country_code,
                    COALESCE(n.country_name, 'Unknown') AS country_name,
                    c.hits
             FROM top_countries c
             LEFT JOIN countries n ON n.country_code = c.country_code
             WHERE c.period = ?1
             ORDER BY c.hits DESC
             LIMIT ?2"
                .to_string(),
            period.to_string(),
        )
    } else {
        (
            "SELECT c.country_code,
                    COALESCE(n.country_name, 'Unknown') AS country_name,
                    SUM(c.hits) AS hits
             FROM top_countries c
             LEFT JOIN countries n ON n.country_code = c.country_code
             WHERE c.period LIKE ?1
             GROUP BY c.country_code
             ORDER BY hits DESC
             LIMIT ?2"
                .to_string(),
            format!("{}-%", period),
        )
    };
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![period_param, limit as i64], |row| {
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
    let (sql, period_param) = if period.len() == 7 {
        (
            "SELECT status, hits FROM status_codes WHERE period = ?1 ORDER BY hits DESC"
                .to_string(),
            period.to_string(),
        )
    } else {
        (
            "SELECT status, SUM(hits) AS hits FROM status_codes WHERE period LIKE ?1 GROUP BY status ORDER BY hits DESC".to_string(),
            format!("{}-%", period),
        )
    };
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![period_param], |row| {
        Ok((row.get::<_, i64>(0)? as u16, row.get::<_, i64>(1)? as u64))
    })?;

    let mut raw = Vec::<(u16, u64)>::new();
    for row in rows {
        raw.push(row?);
    }

    let total = raw.iter().map(|(_, hits)| *hits).sum::<u64>() as f64;

    let mut out = Vec::new();
    for (status, hits) in raw {
        out.push(StatusRow {
            status,
            label: status_label(status),
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, total),
        });
    }

    Ok(out)
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

    let mut raw = Vec::<(u16, u64)>::new();
    for row in rows {
        raw.push(row?);
    }

    let total = raw.iter().map(|(_, hits)| *hits).sum::<u64>() as f64;

    let mut out = Vec::new();
    for (status, hits) in raw {
        out.push(StatusRow {
            status,
            label: status_label(status),
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, total),
        });
    }

    Ok(out)
}

fn proto_codes(conn: &Connection, period: &str, compact_counts: bool) -> Result<Vec<ProtoRow>> {
    let (sql, period_param) = if period.len() == 7 {
        (
            "SELECT proto, hits FROM protocol_counts WHERE period = ?1 ORDER BY hits DESC".to_string(),
            period.to_string(),
        )
    } else {
        (
            "SELECT proto, SUM(hits) AS hits FROM protocol_counts WHERE period LIKE ?1 GROUP BY proto ORDER BY hits DESC".to_string(),
            format!("{}-%", period),
        )
    };
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![period_param], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })?;

    let mut raw = Vec::<(String, u64)>::new();
    for row in rows {
        raw.push(row?);
    }

    let total = raw.iter().map(|(_, hits)| *hits).sum::<u64>() as f64;

    let mut out = Vec::new();
    for (proto, hits) in raw {
        out.push(ProtoRow {
            proto,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, total),
        });
    }

    Ok(out)
}

fn method_codes(conn: &Connection, period: &str, compact_counts: bool) -> Result<Vec<MethodRow>> {
    let (sql, period_param) = if period.len() == 7 {
        (
            "SELECT method, hits FROM method_counts WHERE period = ?1 ORDER BY hits DESC"
                .to_string(),
            period.to_string(),
        )
    } else {
        (
            "SELECT method, SUM(hits) AS hits FROM method_counts WHERE period LIKE ?1 GROUP BY method ORDER BY hits DESC".to_string(),
            format!("{}-%", period),
        )
    };
    let mut stmt = conn.prepare(&sql)?;

    let rows = stmt.query_map(params![period_param], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
    })?;

    let mut raw = Vec::<(String, u64)>::new();
    for row in rows {
        raw.push(row?);
    }

    let total = raw.iter().map(|(_, hits)| *hits).sum::<u64>() as f64;

    let mut out = Vec::new();
    for (method, hits) in raw {
        out.push(MethodRow {
            method,
            hits,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            pct_fmt: percent_str(hits as f64, total),
        });
    }

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

#[cfg(test)]
mod tests;
