// HTML report generation: renders Tera templates with per-site statistics from the database.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::Connection;
use serde::Serialize;
use tera::{Context as TeraContext, Tera};

use crate::config::{Config, StyleConfig};
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
    visitors: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    visits_fmt: String,
    visits_exact_fmt: String,
    visitors_fmt: String,
    visitors_exact_fmt: String,
    bandwidth_fmt: String,
    avg_rt_ms: Option<String>,
    p95_rt_ms: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct DailyRtStat {
    date: String,
    avg_ms: f64,
    p95_ms: u32,
}

#[derive(Debug, Clone)]
struct MonthlyRtStat {
    label: String, // "Jan", "Feb", etc.
    avg_ms: f64,
    p95_ms: u32,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct DailyRow {
    date: String,
    is_weekend: bool,
    hits: u64,
    visits: u64,
    visitors: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    visits_fmt: String,
    visits_exact_fmt: String,
    visitors_fmt: String,
    visitors_exact_fmt: String,
    bandwidth_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HourlyRow {
    hour: u8,
    label: String,
    hits: u64,
    visits: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    visits_fmt: String,
    visits_exact_fmt: String,
    bandwidth_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MonthRow {
    period: String,
    month: u32,
    month_name: String,
    hits: u64,
    visits: u64,
    visitors: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    visits_fmt: String,
    visits_exact_fmt: String,
    visitors_fmt: String,
    visitors_exact_fmt: String,
    bandwidth_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TopUrlRow {
    url: String,
    hits: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    bandwidth_fmt: String,
    pct_fmt: String,
    bandwidth_pct_fmt: String,
    avg_ms_fmt: Option<String>,
    max_ms_fmt: Option<String>,
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
    pct_fmt: String,
    bandwidth_pct_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
struct TopRefRow {
    referrer: String,
    hits: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TopAgentRow {
    agent: String,
    hits: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    bandwidth_fmt: String,
    pct_fmt: String,
    bandwidth_pct_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TopCountryRow {
    country_code: String,
    country_name: String,
    country_flag: String,
    hits: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    bandwidth_fmt: String,
    pct_fmt: String,
    bandwidth_pct_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StatusRow {
    status: u16,
    label: String,
    hits: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    pct_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProtoRow {
    proto: String,
    hits: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    pct_fmt: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MethodRow {
    method: String,
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
    avg_visitors: u64,
    max_visitors: u64,
    avg_visitors_fmt: String,
    avg_visitors_exact_fmt: String,
    max_visitors_fmt: String,
    max_visitors_exact_fmt: String,
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

/// Summary row for the "Buckets" section on period pages.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct BucketIndexRow {
    pub bucket: String,
    pub slug: String,
    pub hits: u64,
    pub bandwidth: u64,
    pub hits_fmt: String,
    pub hits_exact_fmt: String,
    pub bandwidth_fmt: String,
    pub avg_rt_ms: Option<String>,
    pub unique_sites: Option<u64>,
    pub unique_sites_fmt: Option<String>,
}

/// Full data for a bucket sub-page.
pub(crate) struct BucketPageData {
    pub(crate) bucket: String,
    pub(crate) slug: String,
    pub(crate) period: String,
    pub(crate) hits_fmt: String,
    pub(crate) hits_exact_fmt: String,
    pub(crate) bandwidth_fmt: String,
    pub(crate) visitors_fmt: Option<String>,
    pub(crate) visitors_exact_fmt: Option<String>,
    pub(crate) avg_rt_ms: Option<String>,
    pub(crate) p95_rt_ms: Option<String>,
    /// Populated for monthly periods (YYYY-MM).
    pub(crate) daily: Vec<DailyRow>,
    pub(crate) hourly: Vec<HourlyRow>,
    pub(crate) daily_rt_stats: Vec<DailyRtStat>,
    /// Populated for yearly periods (YYYY) — one row per month.
    pub(crate) monthly_rows: Vec<MonthRow>,
    pub(crate) top_urls_hits: Vec<TopUrlRow>,
    pub(crate) top_urls_bandwidth: Vec<TopUrlRow>,
    pub(crate) top_slow_urls: Vec<TopUrlRow>,
    pub(crate) status_codes: Vec<StatusRow>,
    pub(crate) agents_hits: Vec<TopAgentRow>,
    pub(crate) agents_bandwidth: Vec<TopAgentRow>,
    pub(crate) countries_hits: Vec<TopCountryRow>,
    pub(crate) countries_bandwidth: Vec<TopCountryRow>,
    pub(crate) method_codes: Vec<MethodRow>,
    pub(crate) proto_codes: Vec<ProtoRow>,
    pub(crate) rt_distribution_buckets: Vec<(String, u64)>,
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
    top_ips_hits: Vec<TopHostRow>,
    top_ips_bandwidth: Vec<TopHostRow>,
    top_refs: Vec<TopRefRow>,
    top_agents_hits: Vec<TopAgentRow>,
    top_agents_bandwidth: Vec<TopAgentRow>,
    top_countries_hits: Vec<TopCountryRow>,
    top_countries_bandwidth: Vec<TopCountryRow>,
    status_codes: Vec<StatusRow>,
    proto_codes: Vec<ProtoRow>,
    method_codes: Vec<MethodRow>,
    daily_avg_max: DailyAvgMax,
    hourly_avg_max: HourlyAvgMax,
    top_slow_urls: Vec<TopUrlRow>,
    daily_rt_stats: Vec<DailyRtStat>,
    rt_distribution_buckets: Vec<(String, u64)>,
    buckets: Vec<BucketIndexRow>,
}

#[derive(Debug, Clone)]
struct YearlySummary {
    year: i32,
    monthly_rows: Vec<MonthRow>,
    top_urls_hits: Vec<TopUrlRow>,
    top_urls_bandwidth: Vec<TopUrlRow>,
    top_ips_hits: Vec<TopHostRow>,
    top_ips_bandwidth: Vec<TopHostRow>,
    top_refs: Vec<TopRefRow>,
    top_agents_hits: Vec<TopAgentRow>,
    top_agents_bandwidth: Vec<TopAgentRow>,
    top_countries_hits: Vec<TopCountryRow>,
    top_countries_bandwidth: Vec<TopCountryRow>,
    status_codes: Vec<StatusRow>,
    proto_codes: Vec<ProtoRow>,
    method_codes: Vec<MethodRow>,
    totals: TotalsView,
    monthly_rt_stats: Vec<MonthlyRtStat>,
    top_slow_urls: Vec<TopUrlRow>,
    buckets: Vec<BucketIndexRow>,
}

#[derive(Debug, Clone, Serialize)]
struct YearAggregateRow {
    year: i32,
    hits: u64,
    visits: u64,
    visitors: u64,
    bandwidth: u64,
    hits_fmt: String,
    hits_exact_fmt: String,
    visits_fmt: String,
    visits_exact_fmt: String,
    visitors_fmt: String,
    visitors_exact_fmt: String,
    bandwidth_fmt: String,
}

#[derive(Debug, Clone)]
struct OverallSummary {
    yearly_rows: Vec<YearAggregateRow>,
    top_agents_hits: Vec<TopAgentRow>,
    top_agents_bandwidth: Vec<TopAgentRow>,
    top_countries_hits: Vec<TopCountryRow>,
    top_countries_bandwidth: Vec<TopCountryRow>,
    status_codes: Vec<StatusRow>,
    totals: TotalsView,
    all_time_available: bool,
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

    let compact_counts = false;

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
                cfg.anonymise_ips,
            )?;
            render_month_page(&tera, cfg, output_dir, &summary)?;
            for b in &summary.buckets {
                let data = aggregator::bucket_page_data(
                    &conn,
                    &summary.period,
                    &b.bucket,
                    cfg.top_n,
                    compact_counts,
                )?;
                render_bucket_page(&tera, cfg, output_dir, &data)?;
                logging::log_debug_at(
                    2,
                    &format!("  Wrote {}/buckets/{}/index.html", summary.period, b.slug),
                );
            }
            logging::log_debug_at(2, &format!("  Wrote {}/index.html", summary.period));
            month_count += 1;
        }

        let yearly =
            aggregator::yearly_summary(&conn, *year, cfg.top_n, compact_counts, cfg.anonymise_ips)?;
        render_year_page(&tera, cfg, output_dir, &yearly)?;
        for b in &yearly.buckets {
            let data = aggregator::bucket_page_data(
                &conn,
                &year.to_string(),
                &b.bucket,
                cfg.top_n,
                compact_counts,
            )?;
            render_bucket_page(&tera, cfg, output_dir, &data)?;
        }
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
    let mut tera = Tera::new("**/*.tera")?;
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
    tera.add_raw_template(
        "bucket_month.html.tera",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/bucket_month.html.tera"
        )),
    )?;
    tera.add_raw_template(
        "bucket_year.html.tera",
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/templates/bucket_year.html.tera"
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
    page_ctx.insert("yearly_rows", &overall.yearly_rows);
    page_ctx.insert("months", months);
    page_ctx.insert("totals", &overall.totals);
    page_ctx.insert("all_time_available", &overall.all_time_available);
    page_ctx.insert("status_codes", &overall.status_codes);
    page_ctx.insert("top_countries_hits", &overall.top_countries_hits);
    page_ctx.insert("top_countries_bandwidth", &overall.top_countries_bandwidth);
    page_ctx.insert("top_agents_hits", &overall.top_agents_hits);
    page_ctx.insert("top_agents_bandwidth", &overall.top_agents_bandwidth);
    page_ctx.insert(
        "overview_chart",
        &charts::yearly_overview_chart(&overall.yearly_rows, &cfg.style)?,
    );
    page_ctx.insert(
        "overview_visits_chart",
        &charts::yearly_visits_chart(&overall.yearly_rows, &cfg.style)?,
    );
    page_ctx.insert(
        "status_chart",
        &charts::status_chart(&overall.status_codes, &cfg.style)?,
    );
    page_ctx.insert(
        "country_chart",
        &charts::countries_chart(&overall.top_countries_hits)?,
    );
    page_ctx.insert(
        "agents_chart",
        &charts::agents_chart(&overall.top_agents_hits)?,
    );

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
    page_ctx.insert("top_ips_hits", &summary.top_ips_hits);
    page_ctx.insert("top_ips_bandwidth", &summary.top_ips_bandwidth);
    page_ctx.insert("top_refs", &summary.top_refs);
    page_ctx.insert("top_agents_hits", &summary.top_agents_hits);
    page_ctx.insert("top_agents_bandwidth", &summary.top_agents_bandwidth);
    page_ctx.insert("top_countries_hits", &summary.top_countries_hits);
    page_ctx.insert("top_countries_bandwidth", &summary.top_countries_bandwidth);
    page_ctx.insert("status_codes", &summary.status_codes);
    page_ctx.insert("proto_codes", &summary.proto_codes);
    page_ctx.insert("method_codes", &summary.method_codes);
    page_ctx.insert("totals", &summary.totals);
    page_ctx.insert("top_slow_urls", &summary.top_slow_urls);

    page_ctx.insert(
        "overview_chart",
        &charts::monthly_overview_chart(&summary.monthly_rows, &cfg.style)?,
    );
    page_ctx.insert(
        "overview_visits_chart",
        &charts::monthly_visits_chart(&summary.monthly_rows, &cfg.style)?,
    );
    page_ctx.insert(
        "status_chart",
        &charts::status_chart(&summary.status_codes, &cfg.style)?,
    );
    page_ctx.insert(
        "country_chart",
        &charts::countries_chart(&summary.top_countries_hits)?,
    );
    page_ctx.insert(
        "agents_chart",
        &charts::agents_chart(&summary.top_agents_hits)?,
    );
    if !summary.monthly_rt_stats.is_empty() {
        let labels: Vec<&str> = summary
            .monthly_rt_stats
            .iter()
            .map(|r| r.label.as_str())
            .collect();
        let avgs: Vec<f64> = summary.monthly_rt_stats.iter().map(|r| r.avg_ms).collect();
        let p95s: Vec<u32> = summary.monthly_rt_stats.iter().map(|r| r.p95_ms).collect();
        page_ctx.insert(
            "rt_over_time_chart",
            &charts::response_time_over_time_chart(&labels, &avgs, &p95s)?,
        );
    }

    if !summary.buckets.is_empty() {
        page_ctx.insert("buckets", &summary.buckets);
    }

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
    page_ctx.insert("top_ips_hits", &summary.top_ips_hits);
    page_ctx.insert("top_ips_bandwidth", &summary.top_ips_bandwidth);
    page_ctx.insert("top_refs", &summary.top_refs);
    page_ctx.insert("top_agents_hits", &summary.top_agents_hits);
    page_ctx.insert("top_agents_bandwidth", &summary.top_agents_bandwidth);
    page_ctx.insert("top_countries_hits", &summary.top_countries_hits);
    page_ctx.insert("top_countries_bandwidth", &summary.top_countries_bandwidth);
    page_ctx.insert("status_codes", &summary.status_codes);
    page_ctx.insert("proto_codes", &summary.proto_codes);
    page_ctx.insert("method_codes", &summary.method_codes);
    page_ctx.insert("daily_avg_max", &summary.daily_avg_max);
    page_ctx.insert("hourly_avg_max", &summary.hourly_avg_max);

    page_ctx.insert("top_slow_urls", &summary.top_slow_urls);

    if !summary.daily_rt_stats.is_empty() {
        let labels: Vec<&str> = summary
            .daily_rt_stats
            .iter()
            .map(|r| r.date.as_str())
            .collect();
        let avgs: Vec<f64> = summary.daily_rt_stats.iter().map(|r| r.avg_ms).collect();
        let p95s: Vec<u32> = summary.daily_rt_stats.iter().map(|r| r.p95_ms).collect();
        page_ctx.insert(
            "rt_over_time_chart",
            &charts::response_time_over_time_chart(&labels, &avgs, &p95s)?,
        );
    }
    if !summary.rt_distribution_buckets.is_empty() {
        let labels: Vec<&str> = summary
            .rt_distribution_buckets
            .iter()
            .map(|(l, _)| l.as_str())
            .collect();
        let counts: Vec<u64> = summary
            .rt_distribution_buckets
            .iter()
            .map(|(_, c)| *c)
            .collect();
        page_ctx.insert(
            "rt_distribution_chart",
            &charts::response_time_distribution_chart(&labels, &counts)?,
        );
    }

    page_ctx.insert(
        "daily_chart",
        &charts::daily_chart(&summary.daily, &cfg.style)?,
    );
    page_ctx.insert(
        "daily_visits_chart",
        &charts::daily_visits_chart(&summary.daily, &cfg.style)?,
    );
    page_ctx.insert(
        "hourly_chart",
        &charts::hourly_chart(&summary.hourly, &cfg.style)?,
    );
    page_ctx.insert(
        "status_chart",
        &charts::status_chart(&summary.status_codes, &cfg.style)?,
    );
    page_ctx.insert(
        "country_chart",
        &charts::countries_chart(&summary.top_countries_hits)?,
    );
    page_ctx.insert(
        "agents_chart",
        &charts::agents_chart(&summary.top_agents_hits)?,
    );

    if !summary.buckets.is_empty() {
        page_ctx.insert("buckets", &summary.buckets);
    }

    let page = tera.render("month.html.tera", &page_ctx)?;
    let html = render_layout(tera, cfg, "../assets", "../index.html", page)?;

    let month_dir = output_dir.join(&summary.period);
    fs::create_dir_all(&month_dir)?;
    fs::write(month_dir.join("index.html"), html)?;
    Ok(())
}

fn render_bucket_page(
    tera: &Tera,
    cfg: &Config,
    output_dir: &Path,
    data: &BucketPageData,
) -> Result<()> {
    let mut ctx = TeraContext::new();
    ctx.insert("bucket", &data.bucket);
    ctx.insert("slug", &data.slug);
    ctx.insert("period", &data.period);
    ctx.insert("hits_fmt", &data.hits_fmt);
    ctx.insert("hits_exact_fmt", &data.hits_exact_fmt);
    ctx.insert("bandwidth_fmt", &data.bandwidth_fmt);
    ctx.insert("visitors_fmt", &data.visitors_fmt);
    ctx.insert("visitors_exact_fmt", &data.visitors_exact_fmt);
    ctx.insert("avg_rt_ms", &data.avg_rt_ms);
    ctx.insert("p95_rt_ms", &data.p95_rt_ms);
    ctx.insert("top_urls_hits", &data.top_urls_hits);
    ctx.insert("top_urls_bandwidth", &data.top_urls_bandwidth);
    ctx.insert("top_slow_urls", &data.top_slow_urls);
    ctx.insert("status_codes", &data.status_codes);
    ctx.insert("agents_hits", &data.agents_hits);
    ctx.insert("agents_bandwidth", &data.agents_bandwidth);
    ctx.insert("countries_hits", &data.countries_hits);
    ctx.insert("countries_bandwidth", &data.countries_bandwidth);
    ctx.insert("method_codes", &data.method_codes);
    ctx.insert("proto_codes", &data.proto_codes);

    if !data.status_codes.is_empty() {
        ctx.insert(
            "status_chart",
            &charts::status_chart(&data.status_codes, &cfg.style)?,
        );
    }
    if !data.agents_hits.is_empty() {
        ctx.insert("agents_chart", &charts::agents_chart(&data.agents_hits)?);
    }
    if !data.countries_hits.is_empty() {
        ctx.insert("country_chart", &charts::countries_chart(&data.countries_hits)?);
    }
    if !data.rt_distribution_buckets.is_empty() {
        let labels: Vec<&str> = data
            .rt_distribution_buckets
            .iter()
            .map(|(l, _)| l.as_str())
            .collect();
        let counts: Vec<u64> = data
            .rt_distribution_buckets
            .iter()
            .map(|(_, c)| *c)
            .collect();
        ctx.insert(
            "rt_distribution_chart",
            &charts::response_time_distribution_chart(&labels, &counts)?,
        );
    }
    let is_yearly = data.period.len() == 4;

    if is_yearly {
        ctx.insert("monthly_rows", &data.monthly_rows);
        if !data.monthly_rows.is_empty() {
            ctx.insert("overview_chart", &charts::monthly_overview_chart(&data.monthly_rows, &cfg.style)?);
            if data.monthly_rows.iter().any(|r| r.visitors > 0) {
                ctx.insert("overview_sites_chart", &charts::bucket_monthly_sites_chart(&data.monthly_rows, &cfg.style)?);
            }
        }
        if !data.daily_rt_stats.is_empty() {
            let labels: Vec<&str> = data.daily_rt_stats.iter().map(|r| r.date.as_str()).collect();
            let avgs: Vec<f64> = data.daily_rt_stats.iter().map(|r| r.avg_ms).collect();
            let p95s: Vec<u32> = data.daily_rt_stats.iter().map(|r| r.p95_ms).collect();
            ctx.insert("rt_over_time_chart", &charts::response_time_over_time_chart(&labels, &avgs, &p95s)?);
        }
    } else {
        if !data.daily.is_empty() {
            ctx.insert("daily_chart", &charts::daily_chart(&data.daily, &cfg.style)?);
            if data.daily.iter().any(|r| r.visitors > 0) {
                ctx.insert("daily_sites_chart", &charts::bucket_daily_sites_chart(&data.daily, &cfg.style)?);
            }
        }
        if !data.hourly.is_empty() {
            ctx.insert("hourly_chart", &charts::hourly_chart(&data.hourly, &cfg.style)?);
        }
        if !data.daily_rt_stats.is_empty() {
            let labels: Vec<&str> = data.daily_rt_stats.iter().map(|r| r.date.as_str()).collect();
            let avgs: Vec<f64> = data.daily_rt_stats.iter().map(|r| r.avg_ms).collect();
            let p95s: Vec<u32> = data.daily_rt_stats.iter().map(|r| r.p95_ms).collect();
            ctx.insert("rt_over_time_chart", &charts::response_time_over_time_chart(&labels, &avgs, &p95s)?);
        }
    }

    let template = if is_yearly { "bucket_year.html.tera" } else { "bucket_month.html.tera" };
    let page = tera.render(template, &ctx)?;
    // Bucket pages live at {output}/{period}/buckets/{slug}/index.html
    // → assets at ../../../assets, overview at ../../../index.html
    let html = render_layout(tera, cfg, "../../../assets", "../../../index.html", page)?;

    let bucket_dir = output_dir
        .join(&data.period)
        .join("buckets")
        .join(&data.slug);
    fs::create_dir_all(&bucket_dir)?;
    fs::write(bucket_dir.join("index.html"), html)?;
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
    layout.insert("custom_style", &css_overrides(&cfg.style));
    Ok(tera.render("layout.html.tera", &layout)?)
}

fn css_overrides(style: &StyleConfig) -> String {
    let mut vars: Vec<String> = Vec::new();
    macro_rules! v {
        ($opt:expr, $name:literal) => {
            if let Some(val) = &$opt {
                vars.push(format!("    {}: {};", $name, val));
            }
        };
    }
    v!(style.bg, "--bg");
    v!(style.surface, "--surface");
    v!(style.surface_alt, "--surface-alt");
    v!(style.border, "--border");
    v!(style.text, "--text");
    v!(style.text_muted, "--text-muted");
    v!(style.accent, "--accent");
    v!(style.accent_hover, "--accent-h");
    v!(style.metric_hits, "--metric-hits");
    v!(style.metric_files, "--metric-files");
    v!(style.metric_pages, "--metric-pages");
    v!(style.metric_visits, "--metric-visits");
    v!(style.metric_sites, "--metric-sites");
    v!(style.metric_bandwidth, "--metric-bandwidth");
    v!(style.status_2xx_bg, "--status-2xx-bg");
    v!(style.status_3xx_bg, "--status-3xx-bg");
    v!(style.status_4xx_bg, "--status-4xx-bg");
    v!(style.status_5xx_bg, "--status-5xx-bg");
    v!(style.status_other_bg, "--status-other-bg");
    v!(style.weekend_bg, "--daily-weekend-bg");

    if vars.is_empty() {
        return String::new();
    }
    format!("<style>\n:root {{\n{}\n}}\n</style>", vars.join("\n"))
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
    visitors: u64,
    bandwidth: u64,
    compact_counts: bool,
) -> TotalsView {
    format_totals_with_rt(
        hits,
        visits,
        visitors,
        bandwidth,
        compact_counts,
        None,
        None,
    )
}

fn format_totals_with_rt(
    hits: u64,
    visits: u64,
    visitors: u64,
    bandwidth: u64,
    compact_counts: bool,
    avg_rt: Option<f64>,
    p95_rt: Option<u32>,
) -> TotalsView {
    TotalsView {
        hits,
        visits,
        visitors,
        bandwidth,
        hits_fmt: count_fmt(hits, compact_counts),
        hits_exact_fmt: number_fmt(hits),
        visits_fmt: count_fmt(visits, compact_counts),
        visits_exact_fmt: number_fmt(visits),
        visitors_fmt: count_fmt(visitors, compact_counts),
        visitors_exact_fmt: number_fmt(visitors),
        bandwidth_fmt: format_bytes(bandwidth),
        avg_rt_ms: avg_rt.map(format_ms),
        p95_rt_ms: p95_rt.map(|ms| format_ms(ms as f64)),
    }
}

pub(super) fn format_ms(ms: f64) -> String {
    if ms < 1.0 {
        format!("<1ms")
    } else if ms < 1000.0 {
        format!("{:.0}ms", ms)
    } else {
        format!("{:.2}s", ms / 1000.0)
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
