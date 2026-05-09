use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::Result;
use chrono::{Datelike, NaiveDate, Weekday};
use rusqlite::{params, Connection};

use super::{
    count_fmt, flag_emoji, format_bytes, format_totals, month_name, percent_str, status_label,
    DailyAvgMax, DailyRow, HourlyAvgMax, HourlyRow, MonthRow, MonthlySummary, OverallSummary,
    PeriodMonth, StatusRow, TopAgentRow, TopCountryRow, TopHostRow, TopRefRow, TopUrlRow,
    TotalsView, YearAggregateRow, YearlySummary,
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
         ORDER BY ym DESC",
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
) -> Result<MonthlySummary> {
    let period = format!("{year:04}-{month:02}");

    let daily = daily_stats(conn, year, month, compact_counts)?;
    let hourly = hourly_distribution(conn, year, month, compact_counts)?;
    let totals = monthly_totals(conn, year, month, compact_counts)?;

    let top_urls_hits = top_urls_hits(conn, &period, top_n, compact_counts)?;
    let top_urls_bandwidth = top_urls_bandwidth(conn, &period, top_n, compact_counts)?;
    let top_sites_hits = top_sites_hits(conn, &period, top_n, compact_counts)?;
    let top_sites_bandwidth = top_sites_bandwidth(conn, &period, top_n, compact_counts)?;
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
    let daily_avg_max = daily_avg_max(conn, year, month, compact_counts)?;
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
        top_sites_hits,
        top_sites_bandwidth,
        top_refs,
        top_agents,
        top_countries,
        status_codes,
        daily_avg_max,
        hourly_avg_max,
    })
}

pub(super) fn yearly_summary(
    conn: &Connection,
    year: i32,
    top_n: usize,
    compact_counts: bool,
) -> Result<YearlySummary> {
    let period = year.to_string();
    let monthly_rows = monthly_rows(conn, year, compact_counts)?;
    let totals = yearly_totals(conn, year, compact_counts)?;

    let top_urls_hits = top_urls_hits(conn, &period, top_n, compact_counts)?;
    let top_urls_bandwidth = top_urls_bandwidth(conn, &period, top_n, compact_counts)?;
    let top_sites_hits = top_sites_hits(conn, &period, top_n, compact_counts)?;
    let top_sites_bandwidth = top_sites_bandwidth(conn, &period, top_n, compact_counts)?;
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

    Ok(YearlySummary {
        year,
        monthly_rows,
        top_urls_hits,
        top_urls_bandwidth,
        top_sites_hits,
        top_sites_bandwidth,
        top_agents,
        top_countries,
        status_codes,
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

    Ok(OverallSummary {
        yearly_rows,
        top_agents,
        top_countries,
        status_codes,
        totals,
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

    let mut stmt = conn.prepare(
        "SELECT date,
                SUM(hits) AS hits,
                SUM(visits) AS visits,
                SUM(files) AS files,
                SUM(pages) AS pages,
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
            row.get::<_, i64>(4)? as u64,
            row.get::<_, i64>(5)? as u64,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows.by_ref() {
        let (date, hits, visits, files, pages, bandwidth) = row?;
        let sites = site_count_for_scope(conn, &date)?;
        out.push(DailyRow {
            is_weekend: is_weekend_date(&date),
            date,
            hits,
            visits,
            files,
            pages,
            sites,
            bandwidth,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            visits_fmt: count_fmt(visits, compact_counts),
            visits_exact_fmt: super::number_fmt(visits),
            files_fmt: count_fmt(files, compact_counts),
            files_exact_fmt: super::number_fmt(files),
            pages_fmt: count_fmt(pages, compact_counts),
            pages_exact_fmt: super::number_fmt(pages),
            sites_fmt: count_fmt(sites, compact_counts),
            sites_exact_fmt: super::number_fmt(sites),
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
                SUM(files) AS files,
                SUM(pages) AS pages,
                SUM(bandwidth) AS bandwidth,
                SUM(sites) AS sites
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
            row.get::<_, i64>(4)? as u64,
            row.get::<_, i64>(5)? as u64,
            row.get::<_, i64>(6)? as u64,
        ))
    })?;

    let mut by_hour = BTreeMap::<u8, (u64, u64, u64, u64, u64, u64)>::new();
    for row in rows {
        let (hour, hits, visits, files, pages, bandwidth, sites) = row?;
        by_hour.insert(hour, (hits, visits, files, pages, bandwidth, sites));
    }

    let mut out = Vec::with_capacity(24);
    for hour in 0u8..24u8 {
        let (hits, visits, files, pages, bandwidth, sites) =
            by_hour.get(&hour).copied().unwrap_or((0, 0, 0, 0, 0, 0));
        out.push(HourlyRow {
            hour,
            label: format!("{hour:02}:00"),
            hits,
            visits,
            files,
            pages,
            sites,
            bandwidth,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            visits_fmt: count_fmt(visits, compact_counts),
            visits_exact_fmt: super::number_fmt(visits),
            files_fmt: count_fmt(files, compact_counts),
            files_exact_fmt: super::number_fmt(files),
            pages_fmt: count_fmt(pages, compact_counts),
            pages_exact_fmt: super::number_fmt(pages),
            sites_fmt: count_fmt(sites, compact_counts),
            sites_exact_fmt: super::number_fmt(sites),
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
                COALESCE(SUM(files), 0),
                COALESCE(SUM(sites), 0),
                COALESCE(SUM(pages), 0),
                COALESCE(SUM(bandwidth), 0)
         FROM hourly_stats
         WHERE date LIKE ?1",
    )?;

    let row = stmt.query_row(params![format!("{prefix}-%")], |row| {
        Ok((
            row.get::<_, i64>(0)? as u64,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, i64>(2)? as u64,
            row.get::<_, i64>(3)? as u64,
            row.get::<_, i64>(4)? as u64,
            row.get::<_, i64>(5)? as u64,
        ))
    })?;

    let sites = site_count_for_scope(conn, &prefix)?;

    Ok(format_totals(
        row.0,
        row.1,
        row.2,
        sites,
        row.4,
        row.5,
        compact_counts,
    ))
}

fn yearly_totals(conn: &Connection, year: i32, compact_counts: bool) -> Result<TotalsView> {
    let mut stmt = conn.prepare(
        "SELECT COALESCE(SUM(hits), 0),
                COALESCE(SUM(visits), 0),
                COALESCE(SUM(files), 0),
                COALESCE(SUM(sites), 0),
                COALESCE(SUM(pages), 0),
                COALESCE(SUM(bandwidth), 0)
         FROM hourly_stats
         WHERE date LIKE ?1",
    )?;

    let row = stmt.query_row(params![format!("{year}-%")], |row| {
        Ok((
            row.get::<_, i64>(0)? as u64,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, i64>(2)? as u64,
            row.get::<_, i64>(3)? as u64,
            row.get::<_, i64>(4)? as u64,
            row.get::<_, i64>(5)? as u64,
        ))
    })?;

    let sites = site_count_for_scope(conn, &year.to_string())?;

    Ok(format_totals(
        row.0,
        row.1,
        row.2,
        sites,
        row.4,
        row.5,
        compact_counts,
    ))
}

fn monthly_rows(conn: &Connection, year: i32, compact_counts: bool) -> Result<Vec<MonthRow>> {
    let mut stmt = conn.prepare(
        "SELECT substr(date, 1, 7) AS ym,
                SUM(hits) AS hits,
                SUM(visits) AS visits,
                SUM(files) AS files,
                SUM(pages) AS pages,
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
            row.get::<_, i64>(4)? as u64,
            row.get::<_, i64>(5)? as u64,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (ym, hits, visits, files, pages, bandwidth) = row?;
        let sites = site_count_for_scope(conn, &ym)?;
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
            files,
            pages,
            sites,
            bandwidth,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            visits_fmt: count_fmt(visits, compact_counts),
            visits_exact_fmt: super::number_fmt(visits),
            files_fmt: count_fmt(files, compact_counts),
            files_exact_fmt: super::number_fmt(files),
            pages_fmt: count_fmt(pages, compact_counts),
            pages_exact_fmt: super::number_fmt(pages),
            sites_fmt: count_fmt(sites, compact_counts),
            sites_exact_fmt: super::number_fmt(sites),
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
                SUM(files) AS files,
                SUM(pages) AS pages,
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
            row.get::<_, i64>(4)? as u64,
            row.get::<_, i64>(5)? as u64,
        ))
    })?;

    let mut out = Vec::new();
    for row in rows {
        let (yr, hits, visits, files, pages, bandwidth) = row?;
        let sites = site_count_for_scope(conn, &yr)?;
        let year = yr.parse::<i32>().unwrap_or(0);
        if year <= 0 {
            continue;
        }

        out.push(YearAggregateRow {
            year,
            hits,
            visits,
            files,
            pages,
            sites,
            bandwidth,
            hits_fmt: count_fmt(hits, compact_counts),
            hits_exact_fmt: super::number_fmt(hits),
            visits_fmt: count_fmt(visits, compact_counts),
            visits_exact_fmt: super::number_fmt(visits),
            files_fmt: count_fmt(files, compact_counts),
            files_exact_fmt: super::number_fmt(files),
            pages_fmt: count_fmt(pages, compact_counts),
            pages_exact_fmt: super::number_fmt(pages),
            sites_fmt: count_fmt(sites, compact_counts),
            sites_exact_fmt: super::number_fmt(sites),
            bandwidth_fmt: format_bytes(bandwidth),
        });
    }

    Ok(out)
}

fn overall_totals(conn: &Connection, compact_counts: bool) -> Result<TotalsView> {
    let mut stmt = conn.prepare(
        "SELECT COALESCE(SUM(hits), 0),
                COALESCE(SUM(visits), 0),
                COALESCE(SUM(files), 0),
                COALESCE(SUM(pages), 0),
                COALESCE(SUM(bandwidth), 0)
         FROM hourly_stats",
    )?;

    let row = stmt.query_row([], |row| {
        Ok((
            row.get::<_, i64>(0)? as u64,
            row.get::<_, i64>(1)? as u64,
            row.get::<_, i64>(2)? as u64,
            row.get::<_, i64>(3)? as u64,
            row.get::<_, i64>(4)? as u64,
        ))
    })?;

    let sites = all_time_site_count(conn)?;

    Ok(format_totals(
        row.0,
        row.1,
        row.2,
        sites,
        row.3,
        row.4,
        compact_counts,
    ))
}

fn site_count_for_scope(conn: &Connection, scope: &str) -> Result<u64> {
    // Try HLL estimate first
    let mut hll_stmt = conn.prepare(
        "SELECT estimate
         FROM site_counts_hll
         WHERE scope = ?1",
    )?;
    let stored = hll_stmt.query_row(params![scope], |row| row.get::<_, i64>(0));
    match stored {
        Ok(sites) => return Ok(sites as u64),
        Err(rusqlite::Error::QueryReturnedNoRows) => {}
        Err(err) => return Err(err.into()),
    }

    // Fallback to top_hosts_hits count for scopes that don't have HLL yet
    let mut fallback = conn.prepare(
        "SELECT COUNT(*)
            FROM top_hosts_hits
         WHERE period = ?1",
    )?;
    let sites = fallback.query_row(params![scope], |row| row.get::<_, i64>(0))? as u64;
    Ok(sites)
}

fn all_time_site_count(conn: &Connection) -> Result<u64> {
    // Try HLL estimate first
    let mut stmt = conn.prepare(
        "SELECT estimate
         FROM site_counts_hll
         WHERE scope = '__all__'",
    )?;
    let stored = stmt.query_row([], |row| row.get::<_, i64>(0));
    match stored {
        Ok(sites) => return Ok(sites as u64),
        Err(rusqlite::Error::QueryReturnedNoRows) => {}
        Err(err) => return Err(err.into()),
    }

    // Fallback to all_time_hosts count
    let mut stmt = conn.prepare("SELECT COUNT(*) FROM all_time_hosts")?;
    let sites = stmt.query_row([], |row| row.get::<_, i64>(0))? as u64;
    if sites > 0 {
        return Ok(sites);
    }

    // Final fallback to top_hosts_hits
    let mut fallback = conn.prepare(
        "SELECT COUNT(*) FROM (
             SELECT host_kind, host_hi, host_lo, host_text
             FROM top_hosts_hits
             GROUP BY host_kind, host_hi, host_lo, host_text
         )",
    )?;
    let fallback_sites = fallback.query_row([], |row| row.get::<_, i64>(0))?;
    Ok(fallback_sites as u64)
}

fn top_urls_hits(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopUrlRow>> {
    top_urls_from_table(conn, "top_urls_hits", period, top_n, compact_counts, "hits")
}

fn top_urls_bandwidth(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopUrlRow>> {
    top_urls_from_table(
        conn,
        "top_urls_bandwidth",
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
    let mut stmt = conn.prepare(&format!(
        "SELECT url, hits, bandwidth
         FROM {table}
         WHERE period = ?1
         ORDER BY {order_metric} DESC, hits DESC
         LIMIT ?2"
    ))?;

    let rows = stmt.query_map(params![period, top_n as i64], |row| {
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

fn top_sites_hits(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopHostRow>> {
    top_sites_from_table(
        conn,
        "top_hosts_hits",
        period,
        top_n,
        compact_counts,
        "hits",
    )
}

fn top_sites_bandwidth(
    conn: &Connection,
    period: &str,
    top_n: usize,
    compact_counts: bool,
) -> Result<Vec<TopHostRow>> {
    top_sites_from_table(
        conn,
        "top_hosts_bandwidth",
        period,
        top_n,
        compact_counts,
        "bandwidth",
    )
}

fn top_sites_from_table(
    conn: &Connection,
    table: &str,
    period: &str,
    top_n: usize,
    compact_counts: bool,
    order_metric: &str,
) -> Result<Vec<TopHostRow>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT t.host_kind,
            t.host_hi,
            t.host_lo,
            t.host_text,
            t.hits,
            t.bandwidth,
            COALESCE(t.country_code, '--'),
            COALESCE(cn.country_name, 'Unknown')
         FROM {table} t
         LEFT JOIN country_code_names cn ON cn.country_code = t.country_code
         WHERE t.period = ?1
         ORDER BY {order_metric} DESC, hits DESC
         LIMIT ?2"
    ))?;

    let rows = stmt.query_map(params![period, top_n as i64], |row| {
        let host_kind = row.get::<_, i64>(0)? as u8;
        let host_hi = row.get::<_, i64>(1)? as u64;
        let host_lo = row.get::<_, i64>(2)? as u64;
        let host_text = row.get::<_, String>(3)?;
        let country_code = row.get::<_, String>(6)?;
        Ok(TopHostRow {
            host: decode_host(host_kind, host_hi, host_lo, &host_text),
            hits: row.get::<_, i64>(4)? as u64,
            bandwidth: row.get::<_, i64>(5)? as u64,
            country_flag: flag_emoji(&country_code),
            country_code: country_code.clone(),
            country_name: row.get::<_, String>(7)?,
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

fn decode_host(kind: u8, hi: u64, lo: u64, text: &str) -> String {
    match kind {
        1 => Ipv4Addr::from(lo as u32).to_string(),
        2 => {
            let n = ((hi as u128) << 64) | lo as u128;
            Ipv6Addr::from(n).to_string()
        }
        _ => text.to_string(),
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
    let mut stmt = conn.prepare(
        "SELECT referrer, hits
         FROM top_refs
         WHERE period = ?1
         ORDER BY hits DESC
         LIMIT ?2",
    )?;

    let rows = stmt.query_map(params![period, top_n as i64], |row| {
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
    let mut stmt = conn.prepare(
        "SELECT agent_family, hits
         FROM top_agents
         WHERE period = ?1
         ORDER BY hits DESC
         LIMIT ?2",
    )?;

    let rows = stmt.query_map(params![period, top_n as i64], |row| {
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
         FROM top_agents
         WHERE LENGTH(period) = 4
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
    let mut stmt = conn.prepare(
        "SELECT c.country_code,
              COALESCE(n.country_name, 'Unknown') AS country_name,
                c.hits
         FROM top_countries c
          LEFT JOIN country_code_names n ON n.country_code = c.country_code
         WHERE c.period = ?1
         ORDER BY hits DESC
         LIMIT ?2",
    )?;

    let rows = stmt.query_map(params![period, limit as i64], |row| {
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
             WHERE LENGTH(period) = 4
             GROUP BY country_code
         )
         SELECT h.country_code,
                COALESCE(n.country_name, 'Unknown') AS country_name,
                h.hits
         FROM country_hits h
         LEFT JOIN country_code_names n ON n.country_code = h.country_code
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
    let mut stmt = conn.prepare(
        "SELECT status, hits
         FROM status_codes
         WHERE period = ?1
         ORDER BY hits DESC",
    )?;

    let rows = stmt.query_map(params![period], |row| {
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
         WHERE LENGTH(period) = 4
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

fn daily_avg_max(
    conn: &Connection,
    year: i32,
    month: i32,
    compact_counts: bool,
) -> Result<DailyAvgMax> {
    let daily = daily_stats(conn, year, month, compact_counts)?;
    if daily.is_empty() {
        return Ok(DailyAvgMax::default());
    }

    let days = daily.len() as u64;

    let avg_hits = daily.iter().map(|row| row.hits).sum::<u64>() / days;
    let max_hits = daily.iter().map(|row| row.hits).max().unwrap_or(0);
    let avg_visits = daily.iter().map(|row| row.visits).sum::<u64>() / days;
    let max_visits = daily.iter().map(|row| row.visits).max().unwrap_or(0);
    let avg_files = daily.iter().map(|row| row.files).sum::<u64>() / days;
    let max_files = daily.iter().map(|row| row.files).max().unwrap_or(0);
    let avg_pages = daily.iter().map(|row| row.pages).sum::<u64>() / days;
    let max_pages = daily.iter().map(|row| row.pages).max().unwrap_or(0);
    let avg_sites = daily.iter().map(|row| row.sites).sum::<u64>() / days;
    let max_sites = daily.iter().map(|row| row.sites).max().unwrap_or(0);
    let avg_bandwidth = daily.iter().map(|row| row.bandwidth).sum::<u64>() / days;
    let max_bandwidth = daily.iter().map(|row| row.bandwidth).max().unwrap_or(0);

    Ok(DailyAvgMax {
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
        avg_files,
        max_files,
        avg_files_fmt: count_fmt(avg_files, compact_counts),
        avg_files_exact_fmt: super::number_fmt(avg_files),
        max_files_fmt: count_fmt(max_files, compact_counts),
        max_files_exact_fmt: super::number_fmt(max_files),
        avg_pages,
        max_pages,
        avg_pages_fmt: count_fmt(avg_pages, compact_counts),
        avg_pages_exact_fmt: super::number_fmt(avg_pages),
        max_pages_fmt: count_fmt(max_pages, compact_counts),
        max_pages_exact_fmt: super::number_fmt(max_pages),
        avg_sites,
        max_sites,
        avg_sites_fmt: count_fmt(avg_sites, compact_counts),
        avg_sites_exact_fmt: super::number_fmt(avg_sites),
        max_sites_fmt: count_fmt(max_sites, compact_counts),
        max_sites_exact_fmt: super::number_fmt(max_sites),
        avg_bandwidth,
        max_bandwidth,
        avg_bandwidth_fmt: format_bytes(avg_bandwidth),
        max_bandwidth_fmt: format_bytes(max_bandwidth),
    })
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
