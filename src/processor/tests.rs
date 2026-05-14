use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;
    use crate::geo::Geo;
    use crate::ua::UaParser;
    use flate2::{write::GzEncoder, Compression};
    use rusqlite::Connection;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::path::Path;
    use tempfile::TempDir;

    fn sample_line(ip: &str, path: &str, status: u16, bytes: u64) -> String {
        format!(
            r#"{ip} - frank [08/May/2026:14:23:01 +0000] "GET {path} HTTP/1.1" {status} {bytes} "https://example.com/" "Mozilla/5.0""#,
        )
    }

    fn sample_lines(prefix: &str, count: usize) -> Vec<String> {
        (0..count)
            .map(|idx| {
                sample_line(
                    "1.2.3.4",
                    &format!("/{prefix}-{idx}.html"),
                    200,
                    1_000 + idx as u64,
                )
            })
            .collect()
    }

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

    fn append_plain_file(path: &Path, lines: &[String]) {
        let mut file = OpenOptions::new()
            .append(true)
            .open(path)
            .expect("open plain log for append");
        for line in lines {
            writeln!(file, "{line}").expect("append plain log line");
        }
    }

    fn write_gzip_member(path: &Path, lines: &[String], append: bool) {
        let file = if append {
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)
                .expect("open gzip log for append")
        } else {
            File::create(path).expect("create gzip log")
        };
        let mut encoder = GzEncoder::new(file, Compression::default());
        for line in lines {
            writeln!(encoder, "{line}").expect("write gzip log line");
        }
        encoder.finish().expect("finish gzip member");
    }

    fn new_processor(db_path: &Path) -> Processor {
        let db = Database::open(db_path.to_str().expect("db path utf-8")).expect("open db");
        Processor::new(
            db,
            Geo::new(None),
            UaParser::new(),
            ProcessorConfig {
                top_n: 20,
                vacuum_after_prune: false,
                enable_pruner: true,
                bot_filter: false,
                site_host: None,
                enable_top_urls: true,
                enable_top_hosts: true,
                enable_top_refs: true,
                hll_precision: 14,
                topn_k: 200,
            },
        )
    }

    // ── Plain File Resume & Deduplication ─────────────────────────────────────

    #[test]
    fn plain_file_appends_resume_from_offset() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");

        write_plain_file(&log_path, &sample_lines("plain", 120));

        let mut processor = new_processor(&db_path);
        let processed = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("first run");
        assert_eq!(processed, 120);

        let conn = Connection::open(&db_path).expect("open db");
        let before_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM hourly_stats",
                [],
                |row| row.get(0),
            )
            .expect("hits before append");
        assert_eq!(before_hits, 120);

        append_plain_file(&log_path, &sample_lines("plain-more", 1));

        let processed_2 = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("second run");
        assert_eq!(processed_2, 1, "should only process the new appended line");

        let after_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM hourly_stats",
                [],
                |row| row.get(0),
            )
            .expect("hits after append");
        assert_eq!(after_hits, 121, "should have 120 + 1 total hits");
    }

    #[test]
    fn plain_file_unchanged_skips_via_inode_metadata() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");

        write_plain_file(&log_path, &sample_lines("plain-stable", 120));

        let mut processor = new_processor(&db_path);
        let processed = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("first run");
        assert_eq!(processed, 120);

        let processed_2 = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("second run");
        assert_eq!(processed_2, 0, "unchanged file should be skipped");
    }

    #[test]
    fn plain_file_shrink_restarts_from_zero() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");

        write_plain_file(&log_path, &sample_lines("plain-before-shrink", 120));

        let mut processor = new_processor(&db_path);
        processor
            .process_globs(log_path.to_str().unwrap())
            .expect("first run");

        let conn1 = Connection::open(&db_path).expect("open db");
        let before_hits: i64 = conn1
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM hourly_stats",
                [],
                |row| row.get(0),
            )
            .expect("hits before shrink");
        assert_eq!(before_hits, 120);

        write_plain_file(&log_path, &sample_lines("plain-after-shrink", 40));

        processor
            .process_globs(log_path.to_str().unwrap())
            .expect("second run after shrink");

        let conn2 = Connection::open(&db_path).expect("open db");
        let after_hits: i64 = conn2
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM hourly_stats",
                [],
                |row| row.get(0),
            )
            .expect("hits after shrink");
        // After shrink, file is reprocessed from start: 40 new hits, old 120 archived
        assert!(after_hits > 40, "should have new hits plus archived");
    }

    #[test]
    fn truly_new_plain_file_starts_from_zero() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("fresh-access.log");

        write_plain_file(&log_path, &sample_lines("fresh", 75));

        let mut processor = new_processor(&db_path);
        let processed = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("process");
        assert_eq!(processed, 75);
    }

    #[test]
    fn rename_keeps_inode_and_skips_reprocessing() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");
        let renamed_path = temp.path().join("access.log.1");

        write_plain_file(&log_path, &sample_lines("rename", 120));

        let mut processor = new_processor(&db_path);
        processor
            .process_globs(log_path.to_str().unwrap())
            .expect("first run");

        fs::rename(&log_path, &renamed_path).expect("rename log");

        let processed = processor
            .process_globs(renamed_path.to_str().unwrap())
            .expect("second run on renamed file");
        assert_eq!(processed, 0, "renamed file with same inode should be skipped");
    }

    #[test]
    fn copy_truncate_rotated_copy_inherits_previous_offset() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");
        let rotated_path = temp.path().join("access.log.1");
        let pattern = format!("{}*", log_path.to_str().expect("glob utf-8"));

        write_plain_file(&log_path, &sample_lines("copy-truncate", 120));

        let mut processor = new_processor(&db_path);
        processor
            .process_globs(&pattern)
            .expect("first run");

        append_plain_file(&log_path, &sample_lines("copy-truncate-tail", 1));
        fs::copy(&log_path, &rotated_path).expect("copy rotated log");
        write_plain_file(&log_path, &sample_lines("copy-truncate-new", 1));

        let processed = processor
            .process_globs(&pattern)
            .expect("second run");
        // Should process: the new line in copy-truncate-new (1) + the tail in rotated (1) = 2
        assert_eq!(processed, 2, "should process new content from both files");
    }

    // ── Gzip Resume & Fingerprinting ──────────────────────────────────────────

    #[test]
    fn gzip_files_skip_when_stable_and_resume_when_appended() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log.gz");

        write_gzip_member(&log_path, &sample_lines("gzip", 5000), false);

        let mut processor = new_processor(&db_path);
        let processed = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("first run");
        assert_eq!(processed, 5000);

        let processed_2 = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("second run");
        assert_eq!(processed_2, 0, "unchanged gzip should be skipped");

        write_gzip_member(&log_path, &sample_lines("gzip-more", 1), true);

        let processed_3 = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("third run after append");
        assert_eq!(processed_3, 1, "should resume and process new member");
    }

    #[test]
    fn gzip_inode_change_restarts_from_zero() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let gzip_path = temp.path().join("access.log.gz");

        write_gzip_member(&gzip_path, &sample_lines("gzip-old", 800), false);

        let mut processor = new_processor(&db_path);
        processor
            .process_globs(gzip_path.to_str().unwrap())
            .expect("first run");

        fs::remove_file(&gzip_path).expect("remove gzip log");
        write_gzip_member(&gzip_path, &sample_lines("gzip-new", 1200), false);

        let processed = processor
            .process_globs(gzip_path.to_str().unwrap())
            .expect("second run with new inode");
        assert_eq!(processed, 1200, "new inode should reprocess entire file");
    }

    #[test]
    fn gzip_inode_change_with_same_prefix_counts_only_new_tail() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let gzip_path = temp.path().join("access.log.gz");

        let base_lines = sample_lines("gzip-prefix", 2_000);
        write_gzip_member(&gzip_path, &base_lines, false);

        let mut processor = new_processor(&db_path);
        processor
            .process_globs(gzip_path.to_str().unwrap())
            .expect("first run");

        fs::remove_file(&gzip_path).expect("remove gzip log");
        let mut grown_lines = base_lines.clone();
        grown_lines.extend(sample_lines("gzip-tail", 10));
        write_gzip_member(&gzip_path, &grown_lines, false);

        let processed = processor
            .process_globs(gzip_path.to_str().unwrap())
            .expect("second run with new inode and grown content");
        // Fingerprint matching detects the same prefix and counts only the tail
        assert_eq!(
            processed, 10,
            "same prefix should be detected via fingerprint and only count new tail"
        );
    }

    // ── Multi-File Processing ────────────────────────────────────────────────────

    #[test]
    fn process_globs_persists_hll_site_counts_when_enabled() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_a = temp.path().join("a.log");
        let log_b = temp.path().join("b.log");

        write_plain_file(
            &log_a,
            &[
                sample_line_at(
                    "10.0.0.1",
                    "08/May/2026:14:00:00 +0000",
                    "/index.html",
                    200,
                    100,
                    "-",
                    "Mozilla/5.0",
                ),
                sample_line_at(
                    "10.0.0.2",
                    "08/May/2026:14:05:00 +0000",
                    "/index.html",
                    200,
                    100,
                    "-",
                    "Mozilla/5.0",
                ),
            ],
        );
        write_plain_file(
            &log_b,
            &[
                sample_line_at(
                    "10.0.0.2",
                    "08/May/2026:15:00:00 +0000",
                    "/about",
                    200,
                    100,
                    "-",
                    "Mozilla/5.0",
                ),
                sample_line_at(
                    "10.0.0.3",
                    "08/May/2026:15:05:00 +0000",
                    "/about",
                    200,
                    100,
                    "-",
                    "Mozilla/5.0",
                ),
            ],
        );

        let mut processor = new_processor(&db_path);
        let glob = format!(
            "{},{}",
            log_a.to_str().expect("log a utf-8"),
            log_b.to_str().expect("log b utf-8")
        );
        let processed = processor.process_globs(&glob).expect("process globs");
        assert_eq!(processed, 4);

        let conn = Connection::open(&db_path).expect("open db for validation");
        for scope in ["2026-05-08", "2026-05", "2026", "__all__"] {
            let estimate: i64 = conn
                .query_row(
                    "SELECT estimate FROM site_counts_hll WHERE scope = ?1",
                    rusqlite::params![scope],
                    |row| row.get(0),
                )
                .expect("read hll estimate");
            // Should estimate 2-3 unique IPs (HLL is approximate)
            assert!(estimate >= 2, "scope={scope}, estimate={estimate}");
            assert!(estimate <= 5, "scope={scope}, estimate={estimate}");
        }
    }

    #[test]
    fn process_globs_persists_visit_state_across_restart() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_a = temp.path().join("visit-a.log");
        let log_b = temp.path().join("visit-b.log");

        write_plain_file(
            &log_a,
            &[sample_line_at(
                "10.20.30.40",
                "08/May/2026:14:00:00 +0000",
                "/index.html",
                200,
                100,
                "-",
                "Mozilla/5.0",
            )],
        );

        write_plain_file(
            &log_b,
            &[sample_line_at(
                "10.20.30.40",
                "08/May/2026:14:10:00 +0000",
                "/pricing.html",
                200,
                100,
                "-",
                "Mozilla/5.0",
            )],
        );

        {
            let mut processor = new_processor(&db_path);
            let processed = processor
                .process_globs(log_a.to_str().expect("log a utf-8"))
                .expect("process first file");
            assert_eq!(processed, 1);
        }

        {
            let mut processor = new_processor(&db_path);
            let processed = processor
                .process_globs(log_b.to_str().expect("log b utf-8"))
                .expect("process second file");
            assert_eq!(processed, 1);
        }

        let conn = Connection::open(&db_path).expect("open db for validation");
        let visits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(visits),0) FROM hourly_stats",
                [],
                |row| row.get(0),
            )
            .expect("read visits");
        assert_eq!(
            visits, 1,
            "same IP within 30 min should count as one visit across files"
        );

        let visit_state_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM visit_state", [], |row| row.get(0))
            .expect("count visit_state rows");
        assert_eq!(visit_state_rows, 1);
    }

    #[test]
    fn file_rotation_append_then_rotate_does_not_reprocess() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");
        let rotated_path = temp.path().join("access.log.1");
        let pattern = format!("{}*", log_path.to_str().expect("glob utf-8"));

        let first_line = sample_line("1.2.3.4", "/first.html", 200, 1000);
        write_plain_file(&log_path, &[first_line.clone()]);

        let mut processor = new_processor(&db_path);
        let processed = processor
            .process_globs(&pattern)
            .expect("first run");
        assert_eq!(processed, 1, "First run should process 1 line");

        let second_line = sample_line("5.6.7.8", "/second.html", 200, 2000);
        append_plain_file(&log_path, &[second_line.clone()]);

        fs::rename(&log_path, &rotated_path).expect("rename to rotated path");
        write_plain_file(&log_path, &[]);

        let processed_2 = processor
            .process_globs(&pattern)
            .expect("second run");
        assert_eq!(processed_2, 1, "Rotated file should only process the newly appended line");

        let conn = Connection::open(db_path.to_str().unwrap()).expect("open db");
        let total_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM hourly_stats",
                [],
                |row| row.get(0),
            )
            .expect("query total hits");
        assert_eq!(
            total_hits, 2,
            "Should have exactly 2 hits (1 original + 1 new, not reprocessed)"
        );
    }

    #[test]
    fn unique_sites_same_ip_same_hour_counts_once() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("same-ip.log");

        let mut lines = Vec::new();
        for _ in 0..5 {
            lines.push(sample_line("1.2.3.4", "/index.html", 200, 100));
        }
        write_plain_file(&log_path, &lines);

        let mut processor = new_processor(&db_path);
        let processed = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("process");
        assert_eq!(processed, 5);

        let conn = Connection::open(&db_path).expect("open db");
        let sites: i64 = conn
            .query_row(
                "SELECT sites FROM hourly_stats WHERE date = '2026-05-08' AND hour = 14",
                [],
                |row| row.get(0),
            )
            .expect("sites");
        assert_eq!(sites, 1, "same IP in same hour should count as 1 site");
    }

    #[test]
    fn unique_sites_different_ips_same_hour_count_separately() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("many-ip.log");

        let mut lines = Vec::new();
        for i in 0..5 {
            lines.push(sample_line(
                &format!("1.2.3.{}", i + 1),
                "/index.html",
                200,
                100,
            ));
        }
        write_plain_file(&log_path, &lines);

        let mut processor = new_processor(&db_path);
        let processed = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("process");
        assert_eq!(processed, 5);

        let conn = Connection::open(&db_path).expect("open db");
        let sites: i64 = conn
            .query_row(
                "SELECT sites FROM hourly_stats WHERE date = '2026-05-08' AND hour = 14",
                [],
                |row| row.get(0),
            )
            .expect("sites");
        assert_eq!(sites, 5, "different IPs should each count as a site");
    }

    #[test]
    fn process_persists_top_tables_for_month_and_year() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("tops.log");

        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        let lines = vec![
            format!(
                r#"1.2.3.4 - frank [08/May/2026:14:23:01 +0000] "GET /popular.html HTTP/1.1" 200 100 "https://google.com/search" "{ua}""#
            ),
            format!(
                r#"1.2.3.5 - frank [08/May/2026:14:24:01 +0000] "GET /popular.html HTTP/1.1" 200 300 "https://google.com/news" "{ua}""#
            ),
            format!(
                r#"1.2.3.6 - frank [08/May/2026:14:25:01 +0000] "GET /asset.js HTTP/1.1" 404 50 "https://twitter.com/user" "{ua}""#
            ),
        ];
        write_plain_file(&log_path, &lines);

        let mut processor = new_processor(&db_path);
        let processed = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("process");
        assert_eq!(processed, 3);

        let conn = Connection::open(&db_path).expect("open db");

        let (month_hits, month_bw): (i64, i64) = conn
            .query_row(
                "SELECT hits, bandwidth FROM top_urls_hits WHERE period = '2026-05' AND url = '/popular.html'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("month top url");
        assert_eq!(month_hits, 2);
        assert_eq!(month_bw, 400);

        let status_200: i64 = conn
            .query_row(
                "SELECT hits FROM status_codes WHERE period = '2026-05' AND status = 200",
                [],
                |row| row.get(0),
            )
            .expect("status 200");
        assert_eq!(status_200, 2);

        let status_404: i64 = conn
            .query_row(
                "SELECT hits FROM status_codes WHERE period = '2026-05' AND status = 404",
                [],
                |row| row.get(0),
            )
            .expect("status 404");
        assert_eq!(status_404, 1);
    }
}
