// Integration tests for the aggregator pipeline, resume logic, and accumulator flushing.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::Database;
    use crate::geo::Geo;
    use crate::rules::{RawAction, RawCondition, RawRule, RawWhen, RuleSet};
    use flate2::{write::GzEncoder, Compression};
    use rusqlite::Connection;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
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
        new_processor_with_rules(db_path, None)
    }

    fn new_processor_with_rules(
        db_path: &Path,
        rule_set: Option<crate::rules::SharedRuleSet>,
    ) -> Processor {
        let db = Database::open(db_path.to_str().expect("db path utf-8")).expect("open db");
        Processor::new(
            db,
            Geo::new(None),
            ProcessorConfig {
                top_n: 20,
                vacuum_after_prune: false,
                bot_filter: false,
                enable_top_urls: true,
                enable_top_hosts: true,
                enable_top_refs: true,
                enable_top_agents: true,
                enable_all_time_unique_hosts: true,
                rule_set,
            },
        )
    }

    fn new_processor_with_agents_flag(db_path: &Path, enable_top_agents: bool) -> Processor {
        let db = Database::open(db_path.to_str().expect("db path utf-8")).expect("open db");
        Processor::new(
            db,
            Geo::new(None),
            ProcessorConfig {
                top_n: 20,
                vacuum_after_prune: false,
                bot_filter: false,
                enable_top_urls: true,
                enable_top_hosts: true,
                enable_top_refs: true,
                enable_top_agents,
                enable_all_time_unique_hosts: true,
                rule_set: None,
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
        assert_eq!(
            processed, 0,
            "renamed file with same inode should be skipped"
        );
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
        processor.process_globs(&pattern).expect("first run");

        append_plain_file(&log_path, &sample_lines("copy-truncate-tail", 1));
        fs::copy(&log_path, &rotated_path).expect("copy rotated log");
        write_plain_file(&log_path, &sample_lines("copy-truncate-new", 1));

        let processed = processor.process_globs(&pattern).expect("second run");
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

    // ── Month boundary hit counting ───────────────────────────────────────────

    fn jan_line(i: usize) -> String {
        format!(
            r#"1.2.3.{i} - - [15/Jan/2026:10:00:00 +0000] "GET /jan/{i} HTTP/1.1" 200 100 "-" "Mozilla/5.0""#
        )
    }

    fn feb_line(i: usize) -> String {
        format!(
            r#"1.2.3.{i} - - [15/Feb/2026:10:00:00 +0000] "GET /feb/{i} HTTP/1.1" 200 100 "-" "Mozilla/5.0""#
        )
    }

    #[test]
    fn month_boundary_clean_run_counts_all_entries() {
        // Sanity check: a single file spanning two months is fully processed.
        let temp = TempDir::new().unwrap();
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");

        let lines: Vec<String> = (0..10).map(jan_line).chain((0..10).map(feb_line)).collect();
        write_plain_file(&log_path, &lines);

        let mut processor = new_processor(&db_path);
        let processed = processor.process_globs(log_path.to_str().unwrap()).unwrap();
        assert_eq!(processed, 20);

        let conn = Connection::open(&db_path).unwrap();
        let hits: i64 = conn
            .query_row("SELECT COALESCE(SUM(hits),0) FROM hourly_stats", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(hits, 20);
    }

    #[test]
    fn month_boundary_resume_from_mid_batch_offset_counts_all_entries() {
        // Regression test for the mid-batch month-boundary offset bug.
        //
        // When a month boundary is detected mid-batch, the old code saved the parse
        // state at `last_offset` = end of the entire batch. Any entries from the new
        // month that were in the same batch would be in memory but never flushed. On
        // resume, those entries were skipped because the saved offset pointed past them.
        //
        // The fix: at a month boundary, save `entry_offset` (the start byte of the
        // first new-month entry) instead of `last_offset` (end of batch). On resume
        // the processor seeks to that exact byte and re-reads all new-month entries.
        //
        // This test simulates the post-interruption DB state by injecting a parse_state
        // row with `uncompressed_offset` pointing to the start of the Feb entries, then
        // verifies the processor resumes from there and processes exactly the Feb lines.
        // With the old (buggy) code the injected offset would have been `file_size`
        // (end of batch = end of file when all entries fit in one batch), causing the
        // resume run to process 0 lines and lose the Feb entries permanently.
        let temp = TempDir::new().unwrap();
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");

        let jan_lines: Vec<String> = (0..10).map(jan_line).collect();
        let feb_lines: Vec<String> = (0..10).map(feb_line).collect();

        // Write Jan then Feb — all 20 entries fit in one parser batch (PARSER_BATCH_SIZE=256),
        // so the month boundary is mid-batch.
        let mut all_lines = jan_lines.clone();
        all_lines.extend(feb_lines.clone());
        write_plain_file(&log_path, &all_lines);

        // Byte offset where Feb entries start (= end of Jan entries including newlines).
        let jan_bytes: u64 = jan_lines.iter().map(|l| l.len() as u64 + 1).sum();
        let file_size: u64 = jan_bytes + feb_lines.iter().map(|l| l.len() as u64 + 1).sum::<u64>();

        let meta = std::fs::metadata(&log_path).unwrap();
        let inode = meta.ino();
        let mtime_ns = meta.mtime() * 1_000_000_000 + meta.mtime_nsec();

        // Initialise the DB schema (processor opens and creates tables).
        let _ = new_processor(&db_path);

        // Inject a parse_state row that simulates being interrupted right after
        // the month-boundary flush: Jan was committed, offset is at start of Feb.
        // The old buggy code would have saved uncompressed_offset = file_size here,
        // causing the resume to skip all Feb entries.
        let conn = Connection::open(&db_path).unwrap();
        conn.execute(
            "INSERT INTO parse_state
             (filepath, inode, compressed_size, uncompressed_size,
              compressed_head_fingerprint, uncompressed_head_fingerprint,
              compressed_offset, uncompressed_offset, mtime_ns, completed)
             VALUES (?1, ?2, 0, ?3, NULL, NULL, 0, ?4, ?5, 0)",
            rusqlite::params![
                log_path.to_str().unwrap(),
                inode as i64,
                file_size as i64,
                jan_bytes as i64, // correct resume offset = start of Feb entries
                mtime_ns,
            ],
        )
        .unwrap();
        drop(conn);

        // Resume run: should pick up from jan_bytes and process exactly the 10 Feb lines.
        let mut processor = new_processor(&db_path);
        let processed = processor.process_globs(log_path.to_str().unwrap()).unwrap();
        assert_eq!(
            processed, 10,
            "resume from start-of-Feb offset should process exactly the 10 Feb entries"
        );

        let conn = Connection::open(&db_path).unwrap();
        let hits: i64 = conn
            .query_row("SELECT COALESCE(SUM(hits),0) FROM hourly_stats", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(hits, 10, "only Feb entries should be in DB after resume");
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
        let processed = processor.process_globs(&pattern).expect("first run");
        assert_eq!(processed, 1, "First run should process 1 line");

        let second_line = sample_line("5.6.7.8", "/second.html", 200, 2000);
        append_plain_file(&log_path, &[second_line.clone()]);

        fs::rename(&log_path, &rotated_path).expect("rename to rotated path");
        write_plain_file(&log_path, &[]);

        let processed_2 = processor.process_globs(&pattern).expect("second run");
        assert_eq!(
            processed_2, 1,
            "Rotated file should only process the newly appended line"
        );

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
        let visitors: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM daily_unique_ips WHERE date = '2026-05-08'",
                [],
                |row| row.get(0),
            )
            .expect("sites");
        assert_eq!(visitors, 1, "same IP in same hour should count as 1 site");
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
        let visitors: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM daily_unique_ips WHERE date = '2026-05-08'",
                [],
                |row| row.get(0),
            )
            .expect("sites");
        assert_eq!(visitors, 5, "different IPs should each count as a site");
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
                "SELECT hits, bandwidth FROM monthly_top_urls_hits WHERE period = '2026-05' AND url = '/popular.html'",
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

    // ── Hide action ───────────────────────────────────────────────────────────

    fn hide_ruleset_for_url_prefix(prefix: &str, tables: &[&str]) -> crate::rules::SharedRuleSet {
        let rs = RuleSet::compile(&[RawRule {
            name: "hide".into(),
            enabled: true,
            when: RawWhen::List(vec![RawCondition {
                field: "url".into(),
                op: "starts_with".into(),
                value: serde_yaml::Value::String(prefix.into()),
            }]),
            action: RawAction::Hide(tables.iter().map(|s| s.to_string()).collect()),
        }])
        .expect("compile hide ruleset");
        std::sync::Arc::new(rs)
    }

    #[test]
    fn hide_action_counts_hits_but_not_top_urls() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("hide.log");

        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        // Two hidden entries (/static/) and one visible entry (/page.html).
        let lines = vec![
            format!(
                r#"1.2.3.4 - - [08/May/2026:14:00:00 +0000] "GET /static/app.js HTTP/1.1" 200 500 "https://ref.example.com/" "{ua}""#
            ),
            format!(
                r#"1.2.3.5 - - [08/May/2026:14:01:00 +0000] "GET /static/style.css HTTP/1.1" 200 300 "https://ref.example.com/" "{ua}""#
            ),
            format!(
                r#"1.2.3.6 - - [08/May/2026:14:02:00 +0000] "GET /page.html HTTP/1.1" 200 100 "https://ref.example.com/" "{ua}""#
            ),
        ];
        write_plain_file(&log_path, &lines);

        let rule_set = Some(hide_ruleset_for_url_prefix(
            "/static/",
            &["urls", "hosts", "refs", "agents", "countries"],
        ));
        let mut processor = new_processor_with_rules(&db_path, rule_set);
        let processed = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("process");
        assert_eq!(processed, 3);

        let conn = Connection::open(&db_path).expect("open db");

        // All 3 hits reach hourly_stats.
        let hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits), 0) FROM hourly_stats",
                [],
                |row| row.get(0),
            )
            .expect("hits");
        assert_eq!(hits, 3, "hidden entries must still count as hits");

        // Both hidden IPs appear in daily_unique_ips (unique site counting).
        let site_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM daily_unique_ips WHERE date = '2026-05-08'",
                [],
                |row| row.get(0),
            )
            .expect("site count");
        assert_eq!(
            site_count, 3,
            "hidden entries must still count as unique sites"
        );

        // Hidden URLs must not appear in top URLs.
        let hidden_url_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM monthly_top_urls_hits WHERE url LIKE '/static/%'",
                [],
                |row| row.get(0),
            )
            .expect("hidden url rows");
        assert_eq!(
            hidden_url_rows, 0,
            "hidden URLs must not appear in top URLs"
        );

        // The visible URL must appear normally.
        let visible_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits), 0) FROM monthly_top_urls_hits WHERE url = '/page.html'",
                [],
                |row| row.get(0),
            )
            .expect("visible url hits");
        assert_eq!(visible_hits, 1, "non-hidden URL must appear in top URLs");
    }

    // ── enable_top_agents flag ────────────────────────────────────────────────

    fn agent_log_lines() -> Vec<String> {
        // Three entries with a recognisable UA; bot_filter is off so they go through.
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        (0..3)
            .map(|i| {
                format!(
                    r#"1.2.3.{i} - - [08/May/2026:14:00:0{i} +0000] "GET /page.html HTTP/1.1" 200 100 "-" "{ua}""#
                )
            })
            .collect()
    }

    #[test]
    fn enable_top_agents_true_persists_agents_table() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("agents.log");

        write_plain_file(&log_path, &agent_log_lines());

        let mut processor = new_processor_with_agents_flag(&db_path, true);
        let processed = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("process");
        assert_eq!(processed, 3);

        let conn = Connection::open(&db_path).expect("open db");
        let agent_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM monthly_agents WHERE period = '2026-05'",
                [],
                |row| row.get(0),
            )
            .expect("count agent rows");
        assert!(agent_rows > 0, "enable_top_agents=true must populate monthly_agents");

        let total_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits), 0) FROM monthly_agents WHERE period = '2026-05'",
                [],
                |row| row.get(0),
            )
            .expect("sum agent hits");
        assert_eq!(total_hits, 3, "all 3 entries should be counted in monthly_agents");
    }

    #[test]
    fn enable_top_agents_false_skips_agents_table() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("agents-off.log");

        write_plain_file(&log_path, &agent_log_lines());

        let mut processor = new_processor_with_agents_flag(&db_path, false);
        let processed = processor
            .process_globs(log_path.to_str().unwrap())
            .expect("process");
        assert_eq!(processed, 3);

        let conn = Connection::open(&db_path).expect("open db");

        // Hits must still be counted.
        let hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits), 0) FROM hourly_stats",
                [],
                |row| row.get(0),
            )
            .expect("sum hourly hits");
        assert_eq!(hits, 3, "hits must be recorded regardless of enable_top_agents");

        // But monthly_agents must remain empty.
        let agent_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM monthly_agents WHERE period = '2026-05'",
                [],
                |row| row.get(0),
            )
            .expect("count agent rows");
        assert_eq!(agent_rows, 0, "enable_top_agents=false must not populate monthly_agents");
    }

    #[test]
    fn hide_action_excludes_from_refs_agents_hosts_countries() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("hide-tops.log");

        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        // One hidden entry, one visible entry from a different IP/referrer.
        let lines = vec![
            format!(
                r#"10.0.0.1 - - [08/May/2026:14:00:00 +0000] "GET /static/x.js HTTP/1.1" 200 999 "https://hidden-ref.example.com/" "{ua}""#
            ),
            format!(
                r#"10.0.0.2 - - [08/May/2026:14:01:00 +0000] "GET /page.html HTTP/1.1" 200 100 "https://visible-ref.example.com/" "{ua}""#
            ),
        ];
        write_plain_file(&log_path, &lines);

        let rule_set = Some(hide_ruleset_for_url_prefix(
            "/static/",
            &["urls", "hosts", "refs", "agents", "countries"],
        ));
        let mut processor = new_processor_with_rules(&db_path, rule_set);
        processor
            .process_globs(log_path.to_str().unwrap())
            .expect("process");

        let conn = Connection::open(&db_path).expect("open db");

        // Hidden referrer must not appear; visible one must.
        let hidden_ref: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM monthly_referrers WHERE referrer LIKE '%hidden-ref%'",
                [],
                |row| row.get(0),
            )
            .expect("hidden ref");
        assert_eq!(
            hidden_ref, 0,
            "hidden entry referrer must not appear in top refs"
        );

        let visible_ref: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM monthly_referrers WHERE referrer LIKE '%visible-ref%'",
                [],
                |row| row.get(0),
            )
            .expect("visible ref");
        assert_eq!(
            visible_ref, 1,
            "non-hidden entry referrer must appear in top refs"
        );

        // Exactly one host row (the visible entry); the hidden one must be absent.
        let host_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM monthly_top_ips_hits WHERE period = '2026-05'",
                [],
                |row| row.get(0),
            )
            .expect("host rows");
        assert_eq!(
            host_rows, 1,
            "only the non-hidden host must appear in top hosts"
        );
    }
}
