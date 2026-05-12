use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::Serialize;
use tera::{Context as TeraContext, Tera};

use crate::config::Config;
use crate::logging;

mod aggregator;
mod charts;

const MONTH_NAMES: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];

const PALETTE: [&str; 10] = [
    "#52c493", "#66ddff", "#ff7a7a", "#ffc055", "#7090ff", "#ffea66", "#b0a8e6", "#808080",
    "#a8a8a8", "#d0d0d0",
];

const EMBEDDED_ASSETS: [(&str, &[u8]); 3] = [
    (
        "style.css",
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/style.css")) as &[u8],
    ),
    (
        "chart.min.js",
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/chart.min.js")) as &[u8],
    ),
    (
        "app.js",
        include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/assets/app.js")) as &[u8],
    ),
];

#[derive(Debug, Clone, Serialize)]
struct PeriodMonth {
    year: i32,
    month: u32,
    month_name: String,
    period: String,
}

#[derive(Debug, Clone, Serialize, Default)]
struct TotalsView {
    hits: u64,
    visits: u64,
    files: u64,
    sites: u64,
    pages: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    visits_fmt: String,
    visits_exact_fmt: String,
    files_fmt: String,
    files_exact_fmt: String,
    sites_fmt: String,
    sites_exact_fmt: String,
    pages_fmt: String,
    pages_exact_fmt: String,
    bandwidth_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
struct DailyRow {
    date: String,
    is_weekend: bool,
    hits: u64,
    visits: u64,
    files: u64,
    pages: u64,
    sites: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    visits_fmt: String,
    visits_exact_fmt: String,
    files_fmt: String,
    files_exact_fmt: String,
    pages_fmt: String,
    pages_exact_fmt: String,
    sites_fmt: String,
    sites_exact_fmt: String,
    bandwidth_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
struct HourlyRow {
    hour: u8,
    label: String,
    hits: u64,
    visits: u64,
    files: u64,
    pages: u64,
    sites: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    visits_fmt: String,
    visits_exact_fmt: String,
    files_fmt: String,
    files_exact_fmt: String,
    pages_fmt: String,
    pages_exact_fmt: String,
    sites_fmt: String,
    sites_exact_fmt: String,
    bandwidth_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
struct MonthRow {
    period: String,
    month: u32,
    month_name: String,
    hits: u64,
    visits: u64,
    files: u64,
    pages: u64,
    sites: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    visits_fmt: String,
    visits_exact_fmt: String,
    files_fmt: String,
    files_exact_fmt: String,
    pages_fmt: String,
    pages_exact_fmt: String,
    sites_fmt: String,
    sites_exact_fmt: String,
    bandwidth_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
struct TopUrlRow {
    url: String,
    hits: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    bandwidth_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
struct TopHostRow {
    host: String,
    country_code: String,
    country_name: String,
    country_flag: String,
    hits: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    bandwidth_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
struct TopRefRow {
    referrer: String,
    hits: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
struct TopAgentRow {
    agent: String,
    hits: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    pct_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
struct TopCountryRow {
    country_code: String,
    country_name: String,
    country_flag: String,
    hits: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    pct_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
struct StatusRow {
    status: u16,
    label: String,
    hits: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    pct_fmt: String,
}

#[derive(Debug, Clone, Serialize, Default)]
struct DailyAvgMax {
    avg_hits: u64,
    max_hits: u64,
    avg_hits_fmt: String,
    avg_hits_exact_fmt: String,
    max_hits_fmt: String,
    max_hits_exact_fmt: String,
    avg_visits: u64,
    max_visits: u64,
    avg_visits_fmt: String,
    avg_visits_exact_fmt: String,
    max_visits_fmt: String,
    max_visits_exact_fmt: String,
    avg_files: u64,
    max_files: u64,
    avg_files_fmt: String,
    avg_files_exact_fmt: String,
    max_files_fmt: String,
    max_files_exact_fmt: String,
    avg_pages: u64,
    max_pages: u64,
    avg_pages_fmt: String,
    avg_pages_exact_fmt: String,
    max_pages_fmt: String,
    max_pages_exact_fmt: String,
    avg_sites: u64,
    max_sites: u64,
    avg_sites_fmt: String,
    avg_sites_exact_fmt: String,
    max_sites_fmt: String,
    max_sites_exact_fmt: String,
    avg_bandwidth: u64,
    max_bandwidth: u64,
    avg_bandwidth_fmt: String,
    max_bandwidth_fmt: String,
}

#[derive(Debug, Clone, Serialize, Default)]
struct HourlyAvgMax {
    avg_hits: u64,
    max_hits: u64,
    avg_hits_fmt: String,
    avg_hits_exact_fmt: String,
    max_hits_fmt: String,
    max_hits_exact_fmt: String,
    avg_visits: u64,
    max_visits: u64,
    avg_visits_fmt: String,
    avg_visits_exact_fmt: String,
    max_visits_fmt: String,
    max_visits_exact_fmt: String,
}

#[derive(Debug, Clone)]
struct MonthlySummary {
    period: String,
    year: i32,
    month_name: String,
    daily: Vec<DailyRow>,
    hourly: Vec<HourlyRow>,
    totals: TotalsView,
    top_urls_hits: Vec<TopUrlRow>,
    top_urls_bandwidth: Vec<TopUrlRow>,
    top_sites_hits: Vec<TopHostRow>,
    top_sites_bandwidth: Vec<TopHostRow>,
    top_refs: Vec<TopRefRow>,
    top_agents: Vec<TopAgentRow>,
    top_countries: Vec<TopCountryRow>,
    status_codes: Vec<StatusRow>,
    daily_avg_max: DailyAvgMax,
    hourly_avg_max: HourlyAvgMax,
}

#[derive(Debug, Clone)]
struct YearlySummary {
    year: i32,
    monthly_rows: Vec<MonthRow>,
    top_urls_hits: Vec<TopUrlRow>,
    top_urls_bandwidth: Vec<TopUrlRow>,
    top_sites_hits: Vec<TopHostRow>,
    top_sites_bandwidth: Vec<TopHostRow>,
    top_agents: Vec<TopAgentRow>,
    top_countries: Vec<TopCountryRow>,
    status_codes: Vec<StatusRow>,
    totals: TotalsView,
}

#[derive(Debug, Clone, Serialize)]
struct YearAggregateRow {
    year: i32,
    hits: u64,
    visits: u64,
    files: u64,
    pages: u64,
    sites: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    visits_fmt: String,
    visits_exact_fmt: String,
    files_fmt: String,
    files_exact_fmt: String,
    pages_fmt: String,
    pages_exact_fmt: String,
    sites_fmt: String,
    sites_exact_fmt: String,
    bandwidth_fmt: String,
}

#[derive(Debug, Clone)]
struct OverallSummary {
    yearly_rows: Vec<YearAggregateRow>,
    top_agents: Vec<TopAgentRow>,
    top_countries: Vec<TopCountryRow>,
    status_codes: Vec<StatusRow>,
    totals: TotalsView,
}

pub fn generate_html(cfg: &Config) -> Result<()> {
    let gen_start = std::time::Instant::now();
    logging::log_debug_at(2, "Starting HTML report generation…");

    let conn = Connection::open(&cfg.database)
        .with_context(|| format!("Failed to open database for reports: {}", cfg.database))?;

    let tera = load_templates()?;
    let output_dir = Path::new(&cfg.output_dir);
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory {}", cfg.output_dir))?;

    copy_assets(output_dir)?;

    let years = aggregator::available_years(&conn)?;
    let months = aggregator::available_months(&conn)?;

    if years.is_empty() {
        logging::log("No data in database; skipping report generation");
        return Ok(());
    }

    logging::log_debug_at(
        1,
        &format!("Generating reports for {} year(s)", years.len()),
    );

    let compact_counts = should_use_compact_counts(cfg.hll_precision);

    for year in &years {
        let year_start = std::time::Instant::now();
        let mut month_count = 0;
        for m in months.iter().filter(|m| m.year == *year) {
            let summary = aggregator::monthly_summary(
                &conn,
                m.year,
                m.month as i32,
                cfg.top_n,
                compact_counts,
            )?;
            render_month_page(&tera, cfg, output_dir, &summary)?;
            logging::log_debug_at(2, &format!("  Wrote {}/index.html", summary.period));
            month_count += 1;
        }

        let yearly = aggregator::yearly_summary(&conn, *year, cfg.top_n, compact_counts)?;
        render_year_page(&tera, cfg, output_dir, &yearly)?;
        logging::log_debug_at(
            1,
            &format!(
                "  Wrote {}/index.html ({} months, {:.2}s)",
                year,
                month_count,
                year_start.elapsed().as_secs_f64()
            ),
        );
    }

    let overall = aggregator::overall_summary(&conn, cfg.top_n, compact_counts)?;

    render_index_page(&tera, cfg, output_dir, &years, &months, &overall)?;
    logging::log_debug_at(1, &format!("Wrote {}/index.html", cfg.output_dir));

    let total_elapsed = gen_start.elapsed().as_secs_f64();
    logging::log_debug_at(
        1,
        &format!("Report generation complete ({:.2}s)", total_elapsed),
    );
    Ok(())
}

fn load_templates() -> Result<Tera> {
    let mut tera = Tera::default();
    tera.add_raw_template(
        "layout.html.tera",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/layout.html.tera"
        )),
    )?;
    tera.add_raw_template(
        "index.html.tera",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/index.html.tera"
        )),
    )?;
    tera.add_raw_template(
        "year.html.tera",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/year.html.tera"
        )),
    )?;
    tera.add_raw_template(
        "month.html.tera",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/month.html.tera"
        )),
    )?;
    Ok(tera)
}

fn render_index_page(
    tera: &Tera,
    cfg: &Config,
    output_dir: &Path,
    years: &[i32],
    months: &[PeriodMonth],
    overall: &OverallSummary,
) -> Result<()> {
    let mut page_ctx = TeraContext::new();
    page_ctx.insert("site_name", &cfg.site_name);
    page_ctx.insert("years", years);
    page_ctx.insert("months", months);
    page_ctx.insert("totals", &overall.totals);
    page_ctx.insert("status_codes", &overall.status_codes);
    page_ctx.insert("top_countries", &overall.top_countries);
    page_ctx.insert("top_agents", &overall.top_agents);
    page_ctx.insert(
        "overview_chart",
        &charts::yearly_overview_chart(&overall.yearly_rows)?,
    );
    page_ctx.insert(
        "overview_visits_chart",
        &charts::yearly_visits_chart(&overall.yearly_rows)?,
    );
    page_ctx.insert(
        "status_chart",
        &charts::status_chart(&overall.status_codes)?,
    );
    page_ctx.insert(
        "country_chart",
        &charts::countries_chart(&overall.top_countries)?,
    );
    page_ctx.insert("agents_chart", &charts::agents_chart(&overall.top_agents)?);

    let page = tera.render("index.html.tera", &page_ctx)?;
    let html = render_layout(tera, cfg, "assets", "index.html", page)?;
    fs::write(output_dir.join("index.html"), html)?;
    Ok(())
}

fn render_year_page(
    tera: &Tera,
    cfg: &Config,
    output_dir: &Path,
    summary: &YearlySummary,
) -> Result<()> {
    let mut page_ctx = TeraContext::new();
    page_ctx.insert("year", &summary.year);
    page_ctx.insert("monthly_rows", &summary.monthly_rows);
    page_ctx.insert("top_urls_hits", &summary.top_urls_hits);
    page_ctx.insert("top_urls_bandwidth", &summary.top_urls_bandwidth);
    page_ctx.insert("top_sites_hits", &summary.top_sites_hits);
    page_ctx.insert("top_sites_bandwidth", &summary.top_sites_bandwidth);
    page_ctx.insert("top_agents", &summary.top_agents);
    page_ctx.insert("top_countries", &summary.top_countries);
    page_ctx.insert("status_codes", &summary.status_codes);
    page_ctx.insert("totals", &summary.totals);

    page_ctx.insert(
        "overview_chart",
        &charts::monthly_overview_chart(&summary.monthly_rows)?,
    );
    page_ctx.insert(
        "overview_visits_chart",
        &charts::monthly_visits_chart(&summary.monthly_rows)?,
    );
    page_ctx.insert(
        "status_chart",
        &charts::status_chart(&summary.status_codes)?,
    );
    page_ctx.insert(
        "country_chart",
        &charts::countries_chart(&summary.top_countries)?,
    );
    page_ctx.insert("agents_chart", &charts::agents_chart(&summary.top_agents)?);

    let page = tera.render("year.html.tera", &page_ctx)?;
    let html = render_layout(tera, cfg, "../assets", "../index.html", page)?;

    let year_dir = output_dir.join(summary.year.to_string());
    fs::create_dir_all(&year_dir)?;
    fs::write(year_dir.join("index.html"), html)?;
    Ok(())
}

fn render_month_page(
    tera: &Tera,
    cfg: &Config,
    output_dir: &Path,
    summary: &MonthlySummary,
) -> Result<()> {
    let mut page_ctx = TeraContext::new();
    page_ctx.insert("period", &summary.period);
    page_ctx.insert("year", &summary.year);
    page_ctx.insert("month_name", &summary.month_name);
    page_ctx.insert("daily", &summary.daily);
    page_ctx.insert("hourly", &summary.hourly);
    page_ctx.insert("totals", &summary.totals);
    page_ctx.insert("top_urls_hits", &summary.top_urls_hits);
    page_ctx.insert("top_urls_bandwidth", &summary.top_urls_bandwidth);
    page_ctx.insert("top_sites_hits", &summary.top_sites_hits);
    page_ctx.insert("top_sites_bandwidth", &summary.top_sites_bandwidth);
    page_ctx.insert("top_refs", &summary.top_refs);
    page_ctx.insert("top_agents", &summary.top_agents);
    page_ctx.insert("top_countries", &summary.top_countries);
    page_ctx.insert("status_codes", &summary.status_codes);
    page_ctx.insert("daily_avg_max", &summary.daily_avg_max);
    page_ctx.insert("hourly_avg_max", &summary.hourly_avg_max);

    page_ctx.insert("daily_chart", &charts::daily_chart(&summary.daily)?);
    page_ctx.insert(
        "daily_visits_chart",
        &charts::daily_visits_chart(&summary.daily)?,
    );
    page_ctx.insert("hourly_chart", &charts::hourly_chart(&summary.hourly)?);
    page_ctx.insert(
        "status_chart",
        &charts::status_chart(&summary.status_codes)?,
    );
    page_ctx.insert(
        "country_chart",
        &charts::countries_chart(&summary.top_countries)?,
    );
    page_ctx.insert("agents_chart", &charts::agents_chart(&summary.top_agents)?);

    let page = tera.render("month.html.tera", &page_ctx)?;
    let html = render_layout(tera, cfg, "../assets", "../index.html", page)?;

    let month_dir = output_dir.join(&summary.period);
    fs::create_dir_all(&month_dir)?;
    fs::write(month_dir.join("index.html"), html)?;
    Ok(())
}

fn render_layout(
    tera: &Tera,
    cfg: &Config,
    assets_path: &str,
    overview_path: &str,
    page_content: String,
) -> Result<String> {
    let mut layout = TeraContext::new();
    layout.insert("site_name", &cfg.site_name);
    layout.insert("assets_path", assets_path);
    layout.insert("overview_path", overview_path);
    layout.insert("generated_at", &generated_timestamp());
    layout.insert("content", &page_content);
    Ok(tera.render("layout.html.tera", &layout)?)
}

fn generated_timestamp() -> String {
    let now = std::time::SystemTime::now();
    let datetime: chrono::DateTime<chrono::Local> = now.into();
    datetime.format("%Y-%m-%d %H:%M").to_string()
}

fn copy_assets(output_dir: &Path) -> Result<()> {
    let destination = output_dir.join("assets");
    fs::create_dir_all(&destination)?;

    for (name, bytes) in EMBEDDED_ASSETS {
        fs::write(destination.join(name), bytes)
            .with_context(|| format!("Failed to write embedded asset '{}'", name))?;
    }

    Ok(())
}

fn format_totals(
    hits: u64,
    visits: u64,
    files: u64,
    sites: u64,
    pages: u64,
    bandwidth: u64,
    compact_counts: bool,
) -> TotalsView {
    TotalsView {
        hits,
        visits,
        files,
        sites,
        pages,
        bandwidth,
        hits_fmt: count_fmt(hits, compact_counts),
        hits_exact_fmt: number_fmt(hits),
        visits_fmt: count_fmt(visits, compact_counts),
        visits_exact_fmt: number_fmt(visits),
        files_fmt: count_fmt(files, compact_counts),
        files_exact_fmt: number_fmt(files),
        sites_fmt: count_fmt(sites, compact_counts),
        sites_exact_fmt: number_fmt(sites),
        pages_fmt: count_fmt(pages, compact_counts),
        pages_exact_fmt: number_fmt(pages),
        bandwidth_fmt: format_bytes(bandwidth),
    }
}

fn month_name(month: u32) -> &'static str {
    MONTH_NAMES
        .get((month.saturating_sub(1)) as usize)
        .copied()
        .unwrap_or("Unknown")
}

fn percent_str(value: f64, total: f64) -> String {
    format!("{:.1}%", percent_1dp(value, total))
}

pub(super) fn percent_1dp(value: f64, total: f64) -> f64 {
    if total <= 0.0 {
        return 0.0;
    }
    ((value / total) * 1000.0).round() / 10.0
}

fn number_fmt(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let chars: Vec<char> = s.chars().collect();
    for (i, c) in chars.iter().enumerate() {
        out.push(*c);
        let remain = chars.len() - i - 1;
        if remain > 0 && remain.is_multiple_of(3) {
            out.push(',');
        }
    }
    out
}

fn count_fmt(n: u64, compact: bool) -> String {
    if compact {
        compact_3sf(n)
    } else {
        number_fmt(n)
    }
}

fn compact_3sf(n: u64) -> String {
    if n < 1000 {
        return n.to_string();
    }

    const UNITS: [&str; 5] = ["", "k", "m", "b", "t"];
    let mut unit_idx = 0usize;
    let mut value = n as f64;

    while value >= 1000.0 && unit_idx + 1 < UNITS.len() {
        value /= 1000.0;
        unit_idx += 1;
    }

    let mut decimals = if value >= 100.0 {
        0usize
    } else if value >= 10.0 {
        1usize
    } else {
        2usize
    };

    let mut factor = 10f64.powi(decimals as i32);
    let mut rounded = (value * factor).round() / factor;

    if rounded >= 1000.0 && unit_idx + 1 < UNITS.len() {
        unit_idx += 1;
        value = rounded / 1000.0;
        decimals = if value >= 100.0 {
            0usize
        } else if value >= 10.0 {
            1usize
        } else {
            2usize
        };
        factor = 10f64.powi(decimals as i32);
        rounded = (value * factor).round() / factor;
    }

    let mut num = format!("{rounded:.decimals$}");
    while num.contains('.') && num.ends_with('0') {
        num.pop();
    }
    if num.ends_with('.') {
        num.pop();
    }

    format!("{}{}", num, UNITS[unit_idx])
}

fn should_use_compact_counts(hll_precision: u8) -> bool {
    // HyperLogLog relative standard error is approximately 1.04/sqrt(m), where m=2^p.
    let m = (1usize << hll_precision) as f64;
    let rse = 1.04 / m.sqrt();
    rse > 0.001
}

fn format_bytes(n: u64) -> String {
    if n < 1_024 {
        return format!("{} B", n);
    }
    if n < 1_048_576 {
        return format!("{:.1} KB", n as f64 / 1_024.0);
    }
    if n < 1_073_741_824 {
        return format!("{:.1} MB", n as f64 / 1_048_576.0);
    }
    if n < 1_099_511_627_776 {
        return format!("{:.2} GB", n as f64 / 1_073_741_824.0);
    }
    if n < 1_125_899_906_842_624 {
        return format!("{:.2} TB", n as f64 / 1_099_511_627_776.0);
    }
    format!("{:.2} PB", n as f64 / 1_125_899_906_842_624.0)
}

fn status_label(code: u16) -> String {
    let label = match code {
        0 => "Undefined response code",
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        410 => "Gone",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    };

    if code == 0 {
        label.to_string()
    } else if label.is_empty() {
        format!("Code {}", code)
    } else {
        format!("Code {} - {}", code, label)
    }
}

pub(super) fn short_status_label(code: u16) -> String {
    match code {
        0 => "Unknown".to_string(),
        200 => "200 OK".to_string(),
        201 => "201 Created".to_string(),
        202 => "202 Accepted".to_string(),
        204 => "204 No Content".to_string(),
        206 => "206 Partial".to_string(),
        301 => "301 Moved".to_string(),
        302 => "302 Found".to_string(),
        304 => "304 Not Modified".to_string(),
        307 => "307 Temp Redirect".to_string(),
        308 => "308 Perm Redirect".to_string(),
        400 => "400 Bad Request".to_string(),
        401 => "401 Unauthorized".to_string(),
        403 => "403 Forbidden".to_string(),
        404 => "404 Not Found".to_string(),
        405 => "405 Not Allowed".to_string(),
        406 => "406 Not Acceptable".to_string(),
        410 => "410 Gone".to_string(),
        429 => "429 Too Many Reqs".to_string(),
        500 => "500 Server Error".to_string(),
        502 => "502 Bad Gateway".to_string(),
        503 => "503 Unavailable".to_string(),
        504 => "504 Gateway Timeout".to_string(),
        _ => code.to_string(),
    }
}

fn flag_emoji(code: &str) -> String {
    if code.len() != 2 || code == "--" {
        return String::new();
    }

    let upper = code.to_ascii_uppercase();
    if !upper.chars().all(|c| c.is_ascii_alphabetic()) {
        return String::new();
    }

    let mut out = String::new();
    for c in upper.chars() {
        let v = 0x1F1E6 + (c as u32 - 'A' as u32);
        if let Some(ch) = char::from_u32(v) {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests;
