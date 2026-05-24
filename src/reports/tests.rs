// Tests for HTML report rendering and template correctness.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::database::Database;
    use crate::geo::Geo;
    use crate::aggregator::{Processor, ProcessorConfig};
    use crate::rules::{RawAction, RawCondition, RawRule, RawWhen, RuleSet};
    use rusqlite::Connection;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Path;
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

    fn process_logs(cfg: &Config) -> u64 {
        let db = Database::open(&cfg.database).expect("open db");
        let geo = Geo::new(cfg.geoip_db.as_deref());

        let mut processor = Processor::new(
            db,
            geo,
            ProcessorConfig {
                top_n: cfg.top_n,
                vacuum_after_prune: cfg.vacuum_after_prune,
                bot_filter: cfg.bot_filter,
                enable_top_urls: cfg.enable_top_urls,
                enable_top_hosts: cfg.enable_top_hosts,
                enable_top_refs: cfg.enable_top_refs,
                enable_top_agents: cfg.enable_top_agents,
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
            geoip_db: None,
            top_n: 20,
            enable_top_urls: true,
            enable_top_hosts: true,
            enable_top_refs: true,
            enable_top_agents: true,
            vacuum_after_prune: false,
            bot_filter: true,
            checkpoint_minutes: 0,
            anonymise_ips: false,
            rules: vec![RawRule {
                name: "Self-referrals".into(),
                enabled: true,
                when: RawWhen::List(vec![RawCondition {
                    field: "referer".into(),
                    op: "contains".into(),
                    value: serde_yaml::Value::String("mysite.test".into()),
                }]),
                action: RawAction::Hide(vec!["refs".into()]),
            }],
        };

        let imported = process_logs(&cfg);
        assert_eq!(imported, 5); // 6 lines total, 1 Googlebot filtered out by bot_filter
        generate_html(&cfg).expect("generate html");

        assert!(output_dir.join("index.html").exists());
        assert!(output_dir.join("2024").join("index.html").exists());
        assert!(output_dir.join("2025").join("index.html").exists());
        assert!(output_dir.join("2026").join("index.html").exists());
        assert!(output_dir.join("2024-12").join("index.html").exists());
        assert!(output_dir.join("2025-07").join("index.html").exists());
        assert!(output_dir.join("2026-05").join("index.html").exists());
        assert!(output_dir.join("assets").join("style.css").exists());
        assert!(output_dir.join("assets").join("chart.min.js").exists());
        assert!(output_dir.join("assets").join("app.js").exists());

        let index_html = fs::read_to_string(output_dir.join("index.html")).expect("read index");
        assert!(index_html.contains("E2E Site - Web Statistics"));
        assert!(index_html.contains("2024/index.html"));
        assert!(index_html.contains("2026-05/index.html"));

        let may_html =
            fs::read_to_string(output_dir.join("2026-05").join("index.html")).expect("read may");
        assert!(may_html.contains("Sites per Day"));
        assert!(may_html.contains("Bandwidth per Day"));
        assert!(may_html.contains("status-row--5xx"));
        assert!(may_html.contains("Code 503 - Service Unavailable"));
        assert!(may_html.contains("google.com"));
        assert!(!may_html.contains("mysite.test"));
        assert!(!may_html.contains("bot.html"));

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
            geoip_db: None,
            top_n: 20,
            enable_top_urls: true,
            enable_top_hosts: true,
            enable_top_refs: true,
            enable_top_agents: true,
            vacuum_after_prune: false,
            bot_filter: true,
            checkpoint_minutes: 0,
            anonymise_ips: false,
            rules: vec![],
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
            fs::read_to_string(output_dir.join("2026-05").join("index.html")).expect("read may");
        assert!(may_html.contains("Code 503 - Service Unavailable"));
        assert!(may_html.contains("/boom"));
    }
}
