// Integration tests for end-to-end report generation: log ingestion via
// process_globs followed by generate_html.  Tests here cross module boundaries
// (aggregator + reports + templates) and verify the HTML output on disk.

use crate::aggregator::{Processor, ProcessorConfig};
use crate::config::Config;
use crate::database::Database;
use crate::geo::Geo;
use crate::reports::generate_html;
use crate::rules::{RawAction, RawCondition, RawRule, RawWhen, RuleSet};
use rusqlite::Connection;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::time::SystemTime;
use tempfile::TempDir;

fn sample_line_at(
    ip: &str,
    timestamp: &str,
    path: &str,
    status: u16,
    bytes: u64,
    referer: &str,
    user_agent: &str,
) -> String {
    format!(
        r#"{ip} - frank [{timestamp}] "GET {path} HTTP/1.1" {status} {bytes} "{referer}" "{user_agent}""#,
    )
}

fn write_plain_file(path: &Path, lines: &[String]) {
    let mut file = File::create(path).expect("create plain log");
    for line in lines {
        writeln!(file, "{line}").expect("write plain log line");
    }
}

fn base_cfg(temp: &TempDir) -> Config {
    Config {
        site_name: "Test Site".to_string(),
        log_glob: temp.path().join("access.log").to_string_lossy().into_owned(),
        database: temp.path().join("webstat.db").to_string_lossy().into_owned(),
        output_dir: temp.path().join("output").to_string_lossy().into_owned(),
        ..Default::default()
    }
}

fn process_logs(cfg: &Config) -> u64 {
    let db = Database::open(&cfg.database).expect("open db");
    let geo = Geo::new(cfg.geoip_db.as_deref());

    let mut processor = Processor::new(
        db,
        geo,
        ProcessorConfig {
            top_n: cfg.top_n,
            bot_filter: cfg.bot_filter,
            enable_top_urls: cfg.enable_top_urls,
            enable_top_sites: cfg.enable_top_sites,
            enable_top_refs: cfg.enable_top_refs,
            enable_top_agents: cfg.enable_top_agents,
            enable_top_error_urls: cfg.enable_top_error_urls,
            rule_set: if cfg.rules.is_empty() {
                None
            } else {
                Some(std::sync::Arc::new(
                    RuleSet::compile(&cfg.rules).expect("compile rules"),
                ))
            },
        },
    );
    processor.set_checkpoint_interval_minutes(cfg.checkpoint_minutes);

    processor
        .process_globs(&cfg.log_glob)
        .expect("process logs")
}

#[test]
fn report_generation_e2e_multi_year_outputs_pages_and_filters_referrers() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("webstat.db");
    let output_dir = temp.path().join("output");
    let log_a = temp.path().join("access-a.log");
    let log_b = temp.path().join("access-b.log");

    let lines_a = vec![
        sample_line_at(
            "10.0.0.1",
            "31/Dec/2024:23:55:00 +0000",
            "/archive.html",
            200,
            100,
            "https://news.ycombinator.com/item?id=1",
            "Mozilla/5.0",
        ),
        sample_line_at(
            "10.0.0.2",
            "15/Jul/2025:12:00:00 +0000",
            "/missing",
            404,
            25,
            "https://google.com/search?q=missing",
            "Mozilla/5.0",
        ),
    ];
    let lines_b = vec![
        sample_line_at(
            "10.0.0.3",
            "09/May/2026:08:00:00 +0000",
            "/boom",
            503,
            5,
            "https://google.com/search?q=boom",
            "Mozilla/5.0",
        ),
        sample_line_at(
            "10.0.0.3",
            "09/May/2026:08:20:00 +0000",
            "/index.html",
            200,
            70,
            "https://mysite.test/about",
            "Mozilla/5.0",
        ),
        sample_line_at(
            "10.0.0.3",
            "09/May/2026:09:00:00 +0000",
            "/index.html",
            200,
            70,
            "https://google.com/search?q=index",
            "Mozilla/5.0",
        ),
        sample_line_at(
            "10.0.0.99",
            "09/May/2026:09:10:00 +0000",
            "/bot.html",
            200,
            999,
            "https://crawler.test/",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
        ),
    ];

    write_plain_file(&log_a, &lines_a);
    write_plain_file(&log_b, &lines_b);

    let cfg = Config {
        site_name: "E2E Site".to_string(),
        log_glob: format!(
            "{},{}",
            log_a.to_str().expect("log_a utf-8"),
            log_b.to_str().expect("log_b utf-8")
        ),
        database: db_path.to_string_lossy().into_owned(),
        output_dir: output_dir.to_string_lossy().into_owned(),
        rules: vec![RawRule {
            name: "Self-referrals".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "referer".into(),
                op: "contains".into(),
                value: serde_yaml::Value::String("mysite.test".into()),
            }]),
            action: RawAction::Hide(vec!["top_refs".into()]),
        }],
        ..base_cfg(&temp)
    };

    let imported = process_logs(&cfg);
    assert_eq!(imported, 5); // 6 lines total, 1 Googlebot filtered out by bot_filter
    generate_html(&cfg).expect("generate html");

    assert!(output_dir.join("index.html").exists());
    assert!(output_dir.join("2024").join("index.html").exists());
    assert!(output_dir.join("2025").join("index.html").exists());
    assert!(output_dir.join("2026").join("index.html").exists());
    assert!(output_dir.join("2024").join("12").join("index.html").exists());
    assert!(output_dir.join("2025").join("07").join("index.html").exists());
    assert!(output_dir.join("2026").join("05").join("index.html").exists());
    assert!(output_dir.join("assets").join("style.css").exists());
    assert!(output_dir.join("assets").join("chart.min.js").exists());
    assert!(output_dir.join("assets").join("app.js").exists());

    let index_html = fs::read_to_string(output_dir.join("index.html")).expect("read index");
    assert!(index_html.contains("E2E Site - Web Statistics"));
    assert!(index_html.contains("2024/index.html"));
    assert!(index_html.contains("2026/05/index.html"));
    // Overview's Top Erroring URLs panel is a closed-by-default accordion.
    assert!(index_html.contains("<summary>Top Erroring URLs</summary>"));
    assert!(index_html.contains(r#"class="stats-panel collapsible-section""#));

    let may_html =
        fs::read_to_string(output_dir.join("2026").join("05").join("index.html")).expect("read may");
    assert!(may_html.contains("Sites per Day"));
    assert!(may_html.contains("Bandwidth per Day"));
    assert!(may_html.contains("status-row--5xx"));
    assert!(may_html.contains("Code 503 - Service Unavailable"));
    // Top erroring URLs panel: sortable table with per-code columns.
    assert!(may_html.contains(r#"id="err-url-table""#));
    assert!(may_html.contains(r#"data-col="11""#)); // 503 column header
    // Month page wraps the table in an inner collapsible <details> (not overview-style outer).
    assert!(may_html.contains("<summary>Top Erroring URLs</summary>"));
    assert!(may_html.contains(r#"class="collapsible-section__body""#));
    assert!(may_html.contains("google.com"));
    assert!(!may_html.contains("mysite.test"));
    assert!(!may_html.contains("bot.html"));

    // ── Weekday × hour heatmap ────────────────────────────────────────────────
    // All May hits land on Sat 9 May 2026: two at 08:00, one at 09:00 (the
    // Googlebot 09:10 hit is bot-filtered). The busiest cell (Sat 08:00) must
    // render at full intensity, and the grid must carry all seven weekday rows.
    assert!(may_html.contains("Hits by Day &amp; Hour"));
    assert!(may_html.contains(r#"class="heatmap""#));
    for day in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] {
        assert!(
            may_html.contains(&format!(r#"heatmap__day">{day}"#)),
            "heatmap missing weekday row {day}"
        );
    }
    // 7 weekday rows × 24 hours = 168 cells.
    assert_eq!(may_html.matches("heatmap__cell").count(), 168);
    // Busiest cell (Sat 08:00) is rendered at intensity 1.
    assert!(
        may_html.contains(r#"--heat: 1""#),
        "heatmap should have a full-intensity cell"
    );
    assert!(may_html.contains(r#"title="Sat 8:00 — 2 hits""#));
    assert!(may_html.contains(r#"title="Sat 9:00 — 1 hits""#));

    // The yearly page carries the same heatmap (aggregated across the year).
    let year_html =
        fs::read_to_string(output_dir.join("2026").join("index.html")).expect("read 2026");
    assert!(year_html.contains("Hits by Day &amp; Hour"));
    assert_eq!(year_html.matches("heatmap__cell").count(), 168);

    // The all-time overview page also carries the full-width heatmap.
    assert!(index_html.contains("Hits by Day &amp; Hour"));
    assert_eq!(index_html.matches("heatmap__cell").count(), 168);

    let conn = Connection::open(&cfg.database).expect("open db for checks");
    let total_hits: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(hits),0) FROM hourly_stats",
            [],
            |row| row.get(0),
        )
        .expect("sum hits");
    let total_bw: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(bandwidth),0) FROM hourly_stats",
            [],
            |row| row.get(0),
        )
        .expect("sum bandwidth");
    assert_eq!(total_hits, 5);
    assert_eq!(total_bw, 270);
}

#[test]
fn report_generation_e2e_second_run_without_changes_is_idempotent() {
    let temp = TempDir::new().expect("tempdir");
    let db_path = temp.path().join("webstat.db");
    let output_dir = temp.path().join("output");
    let log_path = temp.path().join("access.log");

    write_plain_file(
        &log_path,
        &[
            sample_line_at(
                "10.5.0.1",
                "09/May/2026:08:00:00 +0000",
                "/index.html",
                200,
                42,
                "https://google.com/search?q=home",
                "Mozilla/5.0",
            ),
            sample_line_at(
                "10.5.0.2",
                "09/May/2026:08:30:00 +0000",
                "/boom",
                503,
                7,
                "https://google.com/search?q=boom",
                "Mozilla/5.0",
            ),
        ],
    );

    let cfg = Config {
        site_name: "Incremental Site".to_string(),
        log_glob: log_path.to_string_lossy().into_owned(),
        database: db_path.to_string_lossy().into_owned(),
        output_dir: output_dir.to_string_lossy().into_owned(),
        ..base_cfg(&temp)
    };

    assert_eq!(process_logs(&cfg), 2);
    generate_html(&cfg).expect("generate first html");

    let conn = Connection::open(&cfg.database).expect("open db");
    let hits_before: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(hits),0) FROM hourly_stats",
            [],
            |row| row.get(0),
        )
        .expect("hits before");
    assert_eq!(hits_before, 2);

    assert_eq!(process_logs(&cfg), 0);
    generate_html(&cfg).expect("generate second html");

    let hits_after: i64 = conn
        .query_row(
            "SELECT COALESCE(SUM(hits),0) FROM hourly_stats",
            [],
            |row| row.get(0),
        )
        .expect("hits after");
    assert_eq!(hits_after, hits_before);

    let may_html =
        fs::read_to_string(output_dir.join("2026").join("05").join("index.html")).expect("read may");
    assert!(may_html.contains("Code 503 - Service Unavailable"));
    assert!(may_html.contains("/boom"));
}

#[test]
fn style_overrides_appear_in_html_output() {
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("access.log");
    write_plain_file(
        &log_path,
        &[sample_line_at(
            "10.0.0.1",
            "09/May/2026:08:00:00 +0000",
            "/index.html",
            200,
            42,
            "-",
            "Mozilla/5.0",
        )],
    );

    let cfg = Config {
        site_name: "Style Test".to_string(),
        log_glob: log_path.to_string_lossy().into_owned(),
        style: crate::config::StyleConfig {
            accent: Some("#facade".to_string()),
            bar_hits: Some("#abcdef".to_string()),
            ..Default::default()
        },
        ..base_cfg(&temp)
    };

    process_logs(&cfg);
    generate_html(&cfg).expect("generate html");

    let index_html = fs::read_to_string(temp.path().join("output").join("index.html"))
        .expect("read index");
    assert!(index_html.contains("--accent: #facade"), "accent CSS var missing");
    assert!(index_html.contains("#abcdef"), "bar_hits chart colour missing");
}

fn mtime(path: &Path) -> SystemTime {
    fs::metadata(path)
        .expect("metadata")
        .modified()
        .expect("mtime")
}

// ── Staleness / incremental generation tests ──────────────────────────────────

#[test]
fn period_last_updated_populated_after_processing() {
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("access.log");
    write_plain_file(
        &log_path,
        &[
            sample_line_at(
                "10.0.0.1",
                "09/May/2026:08:00:00 +0000",
                "/a",
                200,
                100,
                "-",
                "Mozilla/5.0",
            ),
            sample_line_at(
                "10.0.0.1",
                "10/Jun/2026:08:00:00 +0000",
                "/b",
                200,
                200,
                "-",
                "Mozilla/5.0",
            ),
        ],
    );
    let cfg = Config {
        site_name: "Timestamps".to_string(),
        log_glob: log_path.to_string_lossy().into_owned(),
        ..base_cfg(&temp)
    };

    process_logs(&cfg);

    let conn = Connection::open(&cfg.database).expect("open db");
    let rows: Vec<(String, i64)> = {
        let mut stmt = conn
            .prepare("SELECT period, updated_at FROM period_last_updated ORDER BY period")
            .expect("prepare");
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .expect("query")
            .map(|r| r.expect("row"))
            .collect()
    };

    // The in-progress month (2026-06) is written by flush; 2026-05 is finalized.
    let periods: Vec<&str> = rows.iter().map(|(p, _)| p.as_str()).collect();
    assert!(
        periods.contains(&"2026-05"),
        "finalized month must have a timestamp"
    );
    assert!(
        periods.contains(&"2026-06"),
        "in-progress month must have a timestamp"
    );
    for (_, ts) in &rows {
        assert!(*ts > 0, "timestamp must be positive");
    }
}

#[test]
fn second_generate_skips_current_pages() {
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("access.log");
    write_plain_file(
        &log_path,
        &[sample_line_at(
            "10.0.0.1",
            "09/May/2026:08:00:00 +0000",
            "/index.html",
            200,
            42,
            "-",
            "Mozilla/5.0",
        )],
    );
    let cfg = Config {
        site_name: "Skip Test".to_string(),
        log_glob: log_path.to_string_lossy().into_owned(),
        ..base_cfg(&temp)
    };

    process_logs(&cfg);
    generate_html(&cfg).expect("first generate");

    let output = temp.path().join("output");
    let month_html = output.join("2026").join("05").join("index.html");
    let year_html = output.join("2026").join("index.html");
    let index_html = output.join("index.html");

    let month_mtime_before = mtime(&month_html);
    let year_mtime_before = mtime(&year_html);
    // index is always regenerated, so we don't check it

    // Sleep long enough for the filesystem clock to advance if any file is rewritten.
    std::thread::sleep(std::time::Duration::from_millis(100));

    generate_html(&cfg).expect("second generate");

    assert_eq!(
        mtime(&month_html),
        month_mtime_before,
        "month page must not be rewritten on second generate"
    );
    assert_eq!(
        mtime(&year_html),
        year_mtime_before,
        "year page must not be rewritten on second generate"
    );
    // index.html always regenerates
    assert!(index_html.exists());
}

#[test]
fn new_month_data_triggers_regeneration_of_that_month_only() {
    let temp = TempDir::new().expect("tempdir");
    let log_a = temp.path().join("access-a.log");
    let log_b = temp.path().join("access-b.log");

    write_plain_file(
        &log_a,
        &[sample_line_at(
            "10.0.0.1",
            "09/May/2026:08:00:00 +0000",
            "/may",
            200,
            10,
            "-",
            "Mozilla/5.0",
        )],
    );
    write_plain_file(&log_b, &[]);

    let cfg_a = Config {
        site_name: "Incremental".to_string(),
        log_glob: log_a.to_string_lossy().into_owned(),
        ..base_cfg(&temp)
    };

    process_logs(&cfg_a);
    generate_html(&cfg_a).expect("first generate");

    let output = temp.path().join("output");
    let may_html = output.join("2026").join("05").join("index.html");
    let year_html = output.join("2026").join("index.html");
    let may_mtime_before = mtime(&may_html);
    let year_mtime_before = mtime(&year_html);

    std::thread::sleep(std::time::Duration::from_millis(100));

    // Add a new log file for June.
    write_plain_file(
        &log_b,
        &[sample_line_at(
            "10.0.0.2",
            "15/Jun/2026:10:00:00 +0000",
            "/jun",
            200,
            20,
            "-",
            "Mozilla/5.0",
        )],
    );
    let cfg_b = Config {
        site_name: "Incremental".to_string(),
        log_glob: format!(
            "{},{}",
            log_a.to_str().unwrap(),
            log_b.to_str().unwrap()
        ),
        ..base_cfg(&temp)
    };

    process_logs(&cfg_b);
    generate_html(&cfg_b).expect("second generate");

    // May page: not touched by second run, must be skipped (mtime unchanged).
    assert_eq!(
        mtime(&may_html),
        may_mtime_before,
        "may page must not be rewritten when only june data was added"
    );

    // June page: must now exist (new).
    let jun_html = output.join("2026").join("06").join("index.html");
    assert!(jun_html.exists(), "june page must be generated");

    // Year page: stale because june is new, must be rewritten.
    assert!(
        mtime(&year_html) > year_mtime_before,
        "year page must be rewritten when a new month is added"
    );
}

#[test]
fn deleted_page_regenerated_even_if_db_timestamp_old() {
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("access.log");
    write_plain_file(
        &log_path,
        &[sample_line_at(
            "10.0.0.1",
            "09/May/2026:08:00:00 +0000",
            "/index.html",
            200,
            42,
            "-",
            "Mozilla/5.0",
        )],
    );
    let cfg = Config {
        site_name: "Delete Test".to_string(),
        log_glob: log_path.to_string_lossy().into_owned(),
        ..base_cfg(&temp)
    };

    process_logs(&cfg);
    generate_html(&cfg).expect("first generate");

    let output = temp.path().join("output");
    let month_html = output.join("2026").join("05").join("index.html");
    assert!(month_html.exists());

    // Delete the month page.
    fs::remove_file(&month_html).expect("remove month html");
    assert!(!month_html.exists());

    // Second generate — no new data, but page is missing.
    generate_html(&cfg).expect("second generate after delete");
    assert!(
        month_html.exists(),
        "deleted month page must be regenerated even with no new data"
    );
}

#[test]
fn year_page_skipped_when_all_months_current() {
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("access.log");
    write_plain_file(
        &log_path,
        &[sample_line_at(
            "10.0.0.1",
            "09/May/2026:08:00:00 +0000",
            "/index.html",
            200,
            42,
            "-",
            "Mozilla/5.0",
        )],
    );
    let cfg = Config {
        site_name: "Year Skip".to_string(),
        log_glob: log_path.to_string_lossy().into_owned(),
        ..base_cfg(&temp)
    };

    process_logs(&cfg);
    generate_html(&cfg).expect("first generate");

    let year_html = temp.path().join("output").join("2026").join("index.html");
    let year_mtime_before = mtime(&year_html);

    std::thread::sleep(std::time::Duration::from_millis(100));

    generate_html(&cfg).expect("second generate");

    assert_eq!(
        mtime(&year_html),
        year_mtime_before,
        "year page must not be rewritten when all months are current"
    );
}

#[test]
fn generate_without_db_timestamps_regenerates_everything() {
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("access.log");
    write_plain_file(
        &log_path,
        &[sample_line_at(
            "10.0.0.1",
            "09/May/2026:08:00:00 +0000",
            "/index.html",
            200,
            42,
            "-",
            "Mozilla/5.0",
        )],
    );
    let cfg = Config {
        site_name: "No Timestamps".to_string(),
        log_glob: log_path.to_string_lossy().into_owned(),
        ..base_cfg(&temp)
    };

    process_logs(&cfg);
    generate_html(&cfg).expect("first generate");

    let output = temp.path().join("output");
    let month_html = output.join("2026").join("05").join("index.html");
    let year_html = output.join("2026").join("index.html");

    // Wipe period_last_updated to simulate an old DB with no timestamps.
    let conn = Connection::open(&cfg.database).expect("open db");
    conn.execute("DELETE FROM period_last_updated", [])
        .expect("delete timestamps");
    drop(conn);

    std::thread::sleep(std::time::Duration::from_millis(100));

    let month_mtime_before = mtime(&month_html);
    let year_mtime_before = mtime(&year_html);

    generate_html(&cfg).expect("second generate without timestamps");

    assert!(
        mtime(&month_html) > month_mtime_before,
        "month page must be regenerated when DB timestamps are absent"
    );
    assert!(
        mtime(&year_html) > year_mtime_before,
        "year page must be regenerated when DB timestamps are absent"
    );
}

#[test]
fn bucket_pages_render_without_errors() {
    // Regression: bucket_month.html.tera and bucket_year.html.tera used to
    // reference `agents_hits` / `countries_hits` (old tab-split variable names)
    // which were removed when tables became single sortable unions.  This test
    // exercises full bucket page generation so template variable mismatches are
    // caught at test time.
    let temp = TempDir::new().expect("tempdir");
    let log_path = temp.path().join("access.log");

    // Two months of requests so both a bucket_month and a bucket_year page are
    // generated.  Some hits go to /api/* (tagged "api") and some to /static/*
    // (tagged "static") to populate agents, countries, and URL tables.
    let lines: Vec<String> = vec![
        // May 2026 — api bucket hits
        sample_line_at("1.1.1.1", "10/May/2026:10:00:00 +0000", "/api/users",  200, 500, "-", "Mozilla/5.0"),
        sample_line_at("1.1.1.2", "10/May/2026:10:01:00 +0000", "/api/orders", 200, 300, "-", "Chrome/120"),
        sample_line_at("2.2.2.2", "10/May/2026:10:02:00 +0000", "/api/users",  404,  50, "-", "Mozilla/5.0"),
        // May 2026 — static bucket hits
        sample_line_at("1.1.1.1", "10/May/2026:11:00:00 +0000", "/static/app.js", 200, 2000, "-", "Mozilla/5.0"),
        // June 2026 — forces a second month (and thus year page)
        sample_line_at("3.3.3.3", "05/Jun/2026:09:00:00 +0000", "/api/ping",  200, 10, "-", "Firefox/120"),
    ];
    write_plain_file(&log_path, &lines);

    let cfg = Config {
        site_name: "Bucket Test".to_string(),
        log_glob: log_path.to_str().unwrap().to_string(),
        rules: vec![
            RawRule {
                name: "api bucket".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: serde_yaml::Value::String("/api/".into()),
                }]),
                action: RawAction::Bucket("api".into()),
            },
            RawRule {
                name: "static bucket".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "url".into(),
                    op: "starts_with".into(),
                    value: serde_yaml::Value::String("/static/".into()),
                }]),
                action: RawAction::Bucket("static".into()),
            },
        ],
        ..base_cfg(&temp)
    };

    process_logs(&cfg);
    // Must not panic — template variable mismatches cause a descriptive error here.
    generate_html(&cfg).expect("bucket page generation must succeed");

    let output_dir = temp.path().join("output");

    // Both bucket sub-pages must exist.
    assert!(
        output_dir.join("2026").join("05").join("buckets").join("api").join("index.html").exists(),
        "bucket month page for api must be generated"
    );
    assert!(
        output_dir.join("2026").join("buckets").join("api").join("index.html").exists(),
        "bucket year page for api must be generated"
    );

    // Spot-check that the rendered bucket month page contains sortable-table
    // markup (agents and countries now use makeSortable, not data-tabs).
    let bucket_may = fs::read_to_string(
        output_dir.join("2026").join("05").join("buckets").join("api").join("index.html")
    ).expect("read bucket may");
    assert!(
        bucket_may.contains("bucket-agents-table") || !bucket_may.contains("Browser Family"),
        "agents table must use sortable id or be absent"
    );
    assert!(
        !bucket_may.contains("bucket-agents-hits"),
        "old tab-split variable name must not appear in rendered output"
    );
}
