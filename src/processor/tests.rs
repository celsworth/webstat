use super::*;

#[cfg(test)]
impl Processor {
    fn resolve_for_processing_test(
        &mut self,
        filepath: &str,
        pending_parse_states: &mut Vec<ParseStateUpdate>,
        retired_parse_states: &mut Vec<ParseStateUpdate>,
    ) -> Result<Option<FileResumePlan>> {
        let resolution = self.resolve_resume_plan(filepath)?;
        if let Some(state) = resolution.skipped_parse_state {
            pending_parse_states.push(state);
        }
        retired_parse_states.extend(resolution.retired_parse_states);
        Ok(resolution.plan)
    }

    /// Test helper for processing a single file and flushing results.
    pub fn process(&mut self, filepath: &str, file_num: usize, file_count: usize) -> Result<u64> {
        let mut run_acc = RunAccumulators::new(
            64,
            self.hll_precision,
            self.enable_top_urls,
            self.enable_top_hosts,
            self.enable_top_refs,
        );
        let mut pending_parse_states = Vec::with_capacity(1);
        let mut retired_parse_states = Vec::with_capacity(1);
        let Some(plan) = self.resolve_for_processing_test(
            filepath,
            &mut pending_parse_states,
            &mut retired_parse_states,
        )?
        else {
            self.flush_run(&run_acc, &pending_parse_states, &retired_parse_states)?;
            return Ok(0);
        };
        let mut flush_last = Instant::now();
        let result = self.process_with_progress(
            filepath,
            file_num,
            file_count,
            plan,
            None,
            None,
            &mut run_acc,
            &mut pending_parse_states,
            &mut flush_last,
        )?;
        self.flush_run(&run_acc, &pending_parse_states, &retired_parse_states)?;
        Ok(result.lines_processed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database::ParseState;
    use crate::util::parse_unix_timestamp;
    use flate2::{write::GzEncoder, Compression};
    use rusqlite::Connection;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    #[derive(Debug, PartialEq, Eq)]
    struct DbSnapshot {
        hourly_hits: i64,
        hourly_visits: i64,
        hourly_pages: i64,
        hourly_files: i64,
        hourly_bandwidth: i64,
        top_urls_hits: i64,
        top_refs_hits: i64,
        top_agents_hits: i64,
        top_countries_hits: i64,
        status_hits: i64,
        parse_state_rows: i64,
        parse_state_completed_rows: i64,
        all_time_sites_estimate: i64,
    }

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
            db_path.to_string_lossy().into_owned(),
            None,
            1,
            ProcessorConfig {
                top_n: 20,
                vacuum_after_prune: false,
                enable_pruner: true,
                bot_filter: true,
                site_host: None,
                enable_top_urls: true,
                enable_top_hosts: true,
                enable_top_refs: true,
                hll_precision: 14,
                topn_k: 200,
            },
        )
    }

    fn new_processor_with_options(
        db_path: &Path,
        bot_filter: bool,
        site_host: Option<&str>,
    ) -> Processor {
        let db = Database::open(db_path.to_str().expect("db path utf-8")).expect("open db");
        Processor::new(
            db,
            Geo::new(None),
            UaParser::new(),
            db_path.to_string_lossy().into_owned(),
            None,
            1,
            ProcessorConfig {
                top_n: 20,
                vacuum_after_prune: false,
                enable_pruner: true,
                bot_filter,
                site_host: site_host.map(str::to_string),
                enable_top_urls: true,
                enable_top_hosts: true,
                enable_top_refs: true,
                hll_precision: 14,
                topn_k: 200,
            },
        )
    }

    fn snapshot_db(path: &Path) -> DbSnapshot {
        let conn = Connection::open(path).expect("open db snapshot");

        let (hourly_hits, hourly_visits, hourly_pages, hourly_files, hourly_bandwidth):
            (i64, i64, i64, i64, i64) = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0), COALESCE(SUM(visits),0), COALESCE(SUM(pages),0), COALESCE(SUM(files),0), COALESCE(SUM(bandwidth),0) FROM hourly_stats",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .expect("read hourly snapshot");

        let top_urls_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM top_urls_hits",
                [],
                |row| row.get(0),
            )
            .expect("read top_urls_hits sum");
        let top_refs_hits: i64 = conn
            .query_row("SELECT COALESCE(SUM(hits),0) FROM top_refs", [], |row| {
                row.get(0)
            })
            .expect("read top_refs sum");
        let top_agents_hits: i64 = conn
            .query_row("SELECT COALESCE(SUM(hits),0) FROM top_agents", [], |row| {
                row.get(0)
            })
            .expect("read top_agents sum");
        let top_countries_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM top_countries",
                [],
                |row| row.get(0),
            )
            .expect("read top_countries sum");
        let status_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM status_codes",
                [],
                |row| row.get(0),
            )
            .expect("read status_codes sum");

        let (parse_state_rows, parse_state_completed_rows): (i64, i64) = conn
            .query_row(
                "SELECT COUNT(*), COALESCE(SUM(completed),0) FROM parse_state",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("read parse_state summary");

        let all_time_sites_estimate: i64 = conn
            .query_row(
                "SELECT COALESCE(estimate,0) FROM site_counts_hll WHERE scope = '__all__'",
                [],
                |row| row.get(0),
            )
            .expect("read __all__ hll estimate");

        DbSnapshot {
            hourly_hits,
            hourly_visits,
            hourly_pages,
            hourly_files,
            hourly_bandwidth,
            top_urls_hits,
            top_refs_hits,
            top_agents_hits,
            top_countries_hits,
            status_hits,
            parse_state_rows,
            parse_state_completed_rows,
            all_time_sites_estimate,
        }
    }

    fn log_entry(
        ip: &'static str,
        time_str: &'static str,
        path: &'static str,
        status: u16,
        bytes: u64,
        referer: &'static str,
        user_agent: &'static str,
    ) -> parser::LogEntry<'static> {
        parser::LogEntry {
            ip,
            time_str,
            month_num: 5,
            method: "GET",
            path,
            proto: "HTTP/1.1",
            status,
            bytes,
            referer,
            user_agent,
        }
    }

    fn state_for(processor: &Processor, path: &Path) -> ParseState {
        processor
            .db
            .get_parse_state(path.to_str().expect("path utf-8"))
            .expect("read parse state")
            .expect("parse state exists")
    }

    #[test]
    fn plain_file_appends_resume_from_offset() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");

        write_plain_file(&log_path, &sample_lines("plain", 120));

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            120
        );
        let first_state = state_for(&processor, &log_path);
        assert_eq!(
            first_state.uncompressed_offset,
            fs::metadata(&log_path).unwrap().len()
        );
        assert_eq!(
            first_state.uncompressed_size,
            fs::metadata(&log_path).unwrap().len()
        );

        append_plain_file(&log_path, &sample_lines("plain-more", 1));

        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            1
        );
        let second_state = state_for(&processor, &log_path);
        assert_eq!(
            second_state.uncompressed_offset,
            fs::metadata(&log_path).unwrap().len()
        );
        assert_eq!(
            second_state.uncompressed_size,
            fs::metadata(&log_path).unwrap().len()
        );
        assert!(second_state.completed);
    }

    #[test]
    fn plain_file_unchanged_skips_via_inode_metadata() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");

        write_plain_file(&log_path, &sample_lines("plain-stable", 120));

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            120
        );

        let first_state = state_for(&processor, &log_path);
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            0
        );
        let second_state = state_for(&processor, &log_path);

        assert_eq!(first_state.inode, second_state.inode);
        assert_eq!(
            first_state.uncompressed_size,
            second_state.uncompressed_size
        );
        assert_eq!(
            first_state.uncompressed_offset,
            second_state.uncompressed_offset
        );
        assert_eq!(first_state.mtime_ns, second_state.mtime_ns);
        assert!(second_state.completed);
    }

    #[test]
    fn plain_file_shrink_archives_previous_state_and_restarts_from_zero() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");

        write_plain_file(&log_path, &sample_lines("plain-before-shrink", 120));

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            120
        );

        let before = state_for(&processor, &log_path);

        write_plain_file(&log_path, &sample_lines("plain-after-shrink", 40));

        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            40
        );

        let after = state_for(&processor, &log_path);
        assert!(after.uncompressed_size < before.uncompressed_size);
        assert_eq!(
            after.uncompressed_offset,
            fs::metadata(&log_path).expect("metadata").len()
        );
        assert!(after.completed);

        let conn = Connection::open(&db_path).expect("open db for archive validation");
        let archived_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM parse_state_archive", [], |row| {
                row.get(0)
            })
            .expect("count archived rows");
        assert!(archived_rows >= 1);

        let archived_old_size: i64 = conn
            .query_row(
                "SELECT uncompressed_size FROM parse_state_archive WHERE filepath = ?1",
                rusqlite::params![log_path.to_str().expect("path utf-8")],
                |row| row.get(0),
            )
            .expect("read archived size");
        assert_eq!(archived_old_size as u64, before.uncompressed_size);
    }

    #[test]
    fn truly_new_plain_file_starts_from_zero() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("fresh-access.log");

        write_plain_file(&log_path, &sample_lines("fresh", 75));

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            75
        );

        let state = state_for(&processor, &log_path);
        assert_eq!(state.uncompressed_offset, state.uncompressed_size);
        assert!(state.completed);
    }

    #[test]
    fn rename_keeps_inode_and_skips_reprocessing() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");
        let renamed_path = temp.path().join("access.log.1");

        write_plain_file(&log_path, &sample_lines("rename", 120));

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            120
        );

        fs::rename(&log_path, &renamed_path).expect("rename log");
        assert_eq!(
            processor
                .process(renamed_path.to_str().unwrap(), 1, 1)
                .unwrap(),
            0
        );
    }

    #[test]
    fn copy_truncate_rotated_copy_inherits_previous_offset() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");
        let rotated_path = temp.path().join("access.log.1");

        write_plain_file(&log_path, &sample_lines("copy-truncate", 120));

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            120
        );

        append_plain_file(&log_path, &sample_lines("copy-truncate-tail", 1));
        fs::copy(&log_path, &rotated_path).expect("copy rotated log");

        write_plain_file(&log_path, &sample_lines("copy-truncate-new", 1));

        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 2).unwrap(),
            1
        );
        assert_eq!(
            processor
                .process(rotated_path.to_str().unwrap(), 2, 2)
                .unwrap(),
            1
        );
    }

    #[test]
    fn gzip_files_skip_when_stable_and_resume_when_appended() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log.gz");

        write_gzip_member(&log_path, &sample_lines("gzip", 5000), false);

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            5000
        );
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            0
        );

        write_gzip_member(&log_path, &sample_lines("gzip-more", 1), true);

        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            1
        );
    }

    #[test]
    fn gzip_incomplete_logical_offset_resumes_from_tail() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log.gz");

        let lines = sample_lines("gzip-mid-checkpoint", 500);
        write_gzip_member(&log_path, &lines, false);

        let resume_after = 320usize;
        let logical_offset: u64 = lines
            .iter()
            .take(resume_after)
            .map(|line| (line.len() + 1) as u64)
            .sum();

        let metadata = fs::metadata(&log_path).expect("gzip metadata");
        let inode = metadata.ino();
        let compressed_size = metadata.len();
        let mtime_ns = metadata.mtime().saturating_mul(1_000_000_000) + metadata.mtime_nsec();

        let mut processor = new_processor(&db_path);
        processor
            .db
            .set_parse_state(
                log_path.to_str().expect("path utf-8"),
                inode,
                compressed_size,
                logical_offset,
                None,
                None,
                0,
                logical_offset,
                mtime_ns,
                false,
            )
            .expect("seed parse state");

        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            (lines.len() - resume_after) as u64
        );
    }

    #[test]
    fn gzip_resume_progress_counts_only_new_tail_bytes() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log.gz");

        let lines = sample_lines("gzip-progress-tail", 500);
        write_gzip_member(&log_path, &lines, false);

        let resume_after = 320usize;
        let logical_offset: u64 = lines
            .iter()
            .take(resume_after)
            .map(|line| (line.len() + 1) as u64)
            .sum();
        let tail_decoded_bytes: u64 = lines
            .iter()
            .skip(resume_after)
            .map(|line| (line.len() + 1) as u64)
            .sum();

        let metadata = fs::metadata(&log_path).expect("gzip metadata");
        let inode = metadata.ino();
        let compressed_size = metadata.len();
        let mtime_ns = metadata.mtime().saturating_mul(1_000_000_000) + metadata.mtime_nsec();

        let mut processor = new_processor(&db_path);
        processor
            .db
            .set_parse_state(
                log_path.to_str().expect("path utf-8"),
                inode,
                compressed_size,
                logical_offset,
                None,
                None,
                0,
                logical_offset,
                mtime_ns,
                false,
            )
            .expect("seed parse state");

        let bytes_done = AtomicU64::new(0);
        let lines_done = AtomicU64::new(0);
        let gz_comp_done = AtomicU64::new(0);
        let gz_decoded_done = AtomicU64::new(0);
        let mut run_acc = RunAccumulators::new(
            64,
            processor.hll_precision,
            processor.enable_top_urls,
            processor.enable_top_hosts,
            processor.enable_top_refs,
        );
        let mut pending_parse_states = Vec::with_capacity(1);
        let mut retired_parse_states = Vec::with_capacity(1);
        let plan = processor
            .resolve_for_processing_test(
                log_path.to_str().expect("path utf-8"),
                &mut pending_parse_states,
                &mut retired_parse_states,
            )
            .expect("resolve")
            .expect("plan should exist");
        let mut flush_last = Instant::now();
        let result = processor
            .process_with_progress(
                log_path.to_str().expect("path utf-8"),
                1,
                1,
                plan,
                Some(SharedProgress {
                    bytes_done: &bytes_done,
                    lines_done: &lines_done,
                    gz_comp_done: &gz_comp_done,
                    gz_decoded_done: &gz_decoded_done,
                    is_compressed: true,
                    compressed_bytes: compressed_size,
                }),
                None,
                &mut run_acc,
                &mut pending_parse_states,
                &mut flush_last,
            )
            .expect("process with shared progress");

        assert!(result.file_completed);
        assert_eq!(result.lines_processed, (lines.len() - resume_after) as u64);
        assert_eq!(bytes_done.load(Ordering::Relaxed), tail_decoded_bytes);
        assert_eq!(gz_decoded_done.load(Ordering::Relaxed), tail_decoded_bytes);
        assert_eq!(gz_comp_done.load(Ordering::Relaxed), compressed_size);
    }

    #[test]
    fn checkpoint_request_interrupts_mid_file_and_marks_incomplete_state() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");

        let lines = sample_lines("checkpoint-mid-file", 5_000);
        write_plain_file(&log_path, &lines);

        let mut processor = new_processor(&db_path);
        let mut run_acc = RunAccumulators::new(
            64,
            processor.hll_precision,
            processor.enable_top_urls,
            processor.enable_top_hosts,
            processor.enable_top_refs,
        );
        let mut pending_parse_states = Vec::with_capacity(1);
        let mut retired_parse_states = Vec::with_capacity(1);
        let checkpoint_requested = AtomicBool::new(true);
        let plan = processor
            .resolve_for_processing_test(
                log_path.to_str().expect("path utf-8"),
                &mut pending_parse_states,
                &mut retired_parse_states,
            )
            .expect("resolve")
            .expect("plan should exist");

        let mut flush_last = Instant::now();
        let result = processor
            .process_with_progress(
                log_path.to_str().expect("path utf-8"),
                1,
                1,
                plan,
                None,
                Some(&checkpoint_requested),
                &mut run_acc,
                &mut pending_parse_states,
                &mut flush_last,
            )
            .expect("process with checkpoint request");

        assert!(!result.file_completed);
        assert!(result.lines_processed > 0);
        assert!(result.lines_processed < lines.len() as u64);

        let state = pending_parse_states
            .last()
            .expect("pending parse state should exist");
        assert!(!state.completed);
        assert!(state.uncompressed_offset > 0);
        assert_eq!(
            state.uncompressed_size,
            fs::metadata(&log_path).unwrap().len()
        );
    }

    #[test]
    fn gzip_version_of_processed_plain_file_is_skipped_by_fingerprint() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let plain_path = temp.path().join("access.log");
        let gzip_path = temp.path().join("access.log.gz");
        let lines = sample_lines("plain-to-gzip", 400);

        write_plain_file(&plain_path, &lines);
        write_gzip_member(&gzip_path, &lines, false);

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor
                .process(plain_path.to_str().unwrap(), 1, 2)
                .unwrap(),
            400
        );
        assert_eq!(
            processor
                .process(gzip_path.to_str().unwrap(), 2, 2)
                .unwrap(),
            0
        );

        let gzip_state = state_for(&processor, &gzip_path);
        assert!(gzip_state.completed);
        assert_eq!(
            gzip_state.compressed_offset,
            fs::metadata(&gzip_path).unwrap().len()
        );
        assert!(gzip_state.uncompressed_offset > 0);
    }

    #[test]
    fn gzip_inode_change_restarts_from_zero_instead_of_reusing_old_offset() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let gzip_path = temp.path().join("access.log.gz");

        write_gzip_member(&gzip_path, &sample_lines("gzip-old", 800), false);

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor
                .process(gzip_path.to_str().unwrap(), 1, 1)
                .unwrap(),
            800
        );

        fs::remove_file(&gzip_path).expect("remove gzip log");
        write_gzip_member(&gzip_path, &sample_lines("gzip-new", 1200), false);

        assert_eq!(
            processor
                .process(gzip_path.to_str().unwrap(), 1, 1)
                .unwrap(),
            1200
        );
    }

    #[test]
    fn gzip_inode_change_with_same_prefix_counts_only_new_tail_lines() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let gzip_path = temp.path().join("access.log.gz");

        let base_lines = sample_lines("gzip-prefix", 2_000);
        write_gzip_member(&gzip_path, &base_lines, false);

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor
                .process(gzip_path.to_str().unwrap(), 1, 1)
                .unwrap(),
            2_000
        );

        fs::remove_file(&gzip_path).expect("remove gzip log");
        let mut grown_lines = base_lines.clone();
        grown_lines.extend(sample_lines("gzip-tail", 10));
        write_gzip_member(&gzip_path, &grown_lines, false);

        assert_eq!(
            processor
                .process(gzip_path.to_str().unwrap(), 1, 1)
                .unwrap(),
            10
        );
    }

    #[test]
    fn gzip_inode_change_same_content_is_skipped_by_global_fingerprint() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let gzip_path = temp.path().join("access.log.2.gz");

        let lines = sample_lines("gzip-same-content", 2_000);
        write_gzip_member(&gzip_path, &lines, false);

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor
                .process(gzip_path.to_str().unwrap(), 1, 1)
                .unwrap(),
            2_000
        );

        fs::remove_file(&gzip_path).expect("remove gzip log");
        write_gzip_member(&gzip_path, &lines, false);

        assert_eq!(
            processor
                .process(gzip_path.to_str().unwrap(), 1, 1)
                .unwrap(),
            0
        );
    }

    #[test]
    fn aggregate_entry_tracks_pages_files_status_and_referrers() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let mut processor = new_processor_with_options(&db_path, false, None);

        let mut hourly: HourlyMap = AHashMap::new();
        let mut top_urls: PeriodHitsMap = AHashMap::new();
        let mut top_hosts: HostHitsMap = AHashMap::new();
        let mut top_refs: PeriodCountMap = AHashMap::new();
        let mut top_agents: PeriodCountMap = AHashMap::new();
        let mut top_countries: CountryCountMap = AHashMap::new();
        let mut status_codes: StatusMap = AHashMap::new();

        processor.aggregate_entry(
            log_entry(
                "1.2.3.4",
                "08/May/2026:14:23:01 +0000",
                "/index.html?utm=1",
                200,
                1200,
                "https://news.ycombinator.com/item?id=1",
                "Mozilla/5.0",
            ),
            &mut hourly,
            &mut top_urls,
            &mut top_hosts,
            &mut top_refs,
            &mut top_agents,
            &mut top_countries,
            &mut status_codes,
        );

        processor.aggregate_entry(
            log_entry(
                "1.2.3.4",
                "08/May/2026:14:24:01 +0000",
                "/app.js?v=42",
                200,
                300,
                "https://news.ycombinator.com/item?id=2",
                "Mozilla/5.0",
            ),
            &mut hourly,
            &mut top_urls,
            &mut top_hosts,
            &mut top_refs,
            &mut top_agents,
            &mut top_countries,
            &mut status_codes,
        );

        let stats = &hourly
            .get("2026-05-08")
            .expect("date bucket")
            .get(&14)
            .expect("hour bucket")
            .stats;
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.bandwidth, 1500);
        assert_eq!(stats.pages, 1);
        assert_eq!(stats.files, 1);
        assert_eq!(stats.status_2xx, 2);

        let month_urls = top_urls.get("2026-05").expect("month urls");
        assert_eq!(month_urls.get("/index.html"), Some(&(1, 1200)));
        assert_eq!(month_urls.get("/app.js"), Some(&(1, 300)));

        let month_refs = top_refs.get("2026-05").expect("month refs");
        assert_eq!(month_refs.get("news.ycombinator.com"), Some(&2));

        let month_status = status_codes.get("2026-05").expect("month status");
        assert_eq!(month_status.get(&200), Some(&2));
    }

    #[test]
    fn aggregate_entry_skips_bot_traffic_when_filter_enabled() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let mut processor = new_processor_with_options(&db_path, true, None);

        let mut hourly: HourlyMap = AHashMap::new();
        let mut top_urls: PeriodHitsMap = AHashMap::new();
        let mut top_hosts: HostHitsMap = AHashMap::new();
        let mut top_refs: PeriodCountMap = AHashMap::new();
        let mut top_agents: PeriodCountMap = AHashMap::new();
        let mut top_countries: CountryCountMap = AHashMap::new();
        let mut status_codes: StatusMap = AHashMap::new();

        processor.aggregate_entry(
            log_entry(
                "1.2.3.4",
                "08/May/2026:14:23:01 +0000",
                "/index.html",
                200,
                1200,
                "https://google.com/",
                "Googlebot/2.1 (+http://www.google.com/bot.html)",
            ),
            &mut hourly,
            &mut top_urls,
            &mut top_hosts,
            &mut top_refs,
            &mut top_agents,
            &mut top_countries,
            &mut status_codes,
        );

        assert!(hourly.is_empty());
        assert!(top_urls.is_empty());
        assert!(top_hosts.is_empty());
        assert!(top_refs.is_empty());
        assert!(top_agents.is_empty());
        assert!(top_countries.is_empty());
        assert!(status_codes.is_empty());
    }

    #[test]
    fn aggregate_entry_visit_timeout_creates_new_visit_after_30_minutes() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let mut processor = new_processor_with_options(&db_path, false, None);

        let mut hourly: HourlyMap = AHashMap::new();
        let mut top_urls: PeriodHitsMap = AHashMap::new();
        let mut top_hosts: HostHitsMap = AHashMap::new();
        let mut top_refs: PeriodCountMap = AHashMap::new();
        let mut top_agents: PeriodCountMap = AHashMap::new();
        let mut top_countries: CountryCountMap = AHashMap::new();
        let mut status_codes: StatusMap = AHashMap::new();

        for ts in [
            "08/May/2026:14:00:00 +0000",
            "08/May/2026:14:20:00 +0000",
            "08/May/2026:15:01:00 +0000",
        ] {
            processor.aggregate_entry(
                log_entry(
                    "1.2.3.4",
                    ts,
                    "/index.html",
                    200,
                    100,
                    "",
                    "Mozilla/5.0",
                ),
                &mut hourly,
                &mut top_urls,
                &mut top_hosts,
                &mut top_refs,
                &mut top_agents,
                &mut top_countries,
                &mut status_codes,
            );
        }

        let total_visits: u64 = hourly
            .values()
            .flat_map(|hours| hours.values())
            .map(|acc| acc.stats.visits)
            .sum();
        assert_eq!(total_visits, 2);
    }

    #[test]
    fn aggregate_entry_excludes_referrers_from_own_host() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let mut processor = new_processor_with_options(&db_path, false, Some("example.com"));

        let mut hourly: HourlyMap = AHashMap::new();
        let mut top_urls: PeriodHitsMap = AHashMap::new();
        let mut top_hosts: HostHitsMap = AHashMap::new();
        let mut top_refs: PeriodCountMap = AHashMap::new();
        let mut top_agents: PeriodCountMap = AHashMap::new();
        let mut top_countries: CountryCountMap = AHashMap::new();
        let mut status_codes: StatusMap = AHashMap::new();

        processor.aggregate_entry(
            log_entry(
                "1.2.3.4",
                "08/May/2026:14:23:01 +0000",
                "/index.html",
                200,
                1200,
                "https://example.com/about",
                "Mozilla/5.0",
            ),
            &mut hourly,
            &mut top_urls,
            &mut top_hosts,
            &mut top_refs,
            &mut top_agents,
            &mut top_countries,
            &mut status_codes,
        );

        processor.aggregate_entry(
            log_entry(
                "1.2.3.4",
                "08/May/2026:14:24:01 +0000",
                "/index.html",
                200,
                1200,
                "https://external.example.org/post",
                "Mozilla/5.0",
            ),
            &mut hourly,
            &mut top_urls,
            &mut top_hosts,
            &mut top_refs,
            &mut top_agents,
            &mut top_countries,
            &mut status_codes,
        );

        let month_refs = top_refs.get("2026-05").expect("month refs");
        assert_eq!(month_refs.len(), 1);
        assert_eq!(month_refs.get("external.example.org"), Some(&1));
    }

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

        let db = Database::open(db_path.to_str().expect("db utf-8")).expect("open db");
        let geo = Geo::new(None);
        let ua = UaParser::new();
        let mut processor = Processor::new(
            db,
            geo,
            ua,
            db_path.to_string_lossy().into_owned(),
            None,
            2,
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
        );

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
        assert_eq!(visits, 1);

        let visit_state_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM visit_state", [], |row| row.get(0))
            .expect("count visit_state rows");
        assert_eq!(visit_state_rows, 1);
    }

    #[test]
    fn process_globs_checkpoint_flush_resume_matches_baseline_output() {
        let temp = TempDir::new().expect("tempdir");
        let db_baseline = temp.path().join("baseline.db");
        let db_checkpoint = temp.path().join("checkpoint.db");
        let plain_path = temp.path().join("checkpoint-plain.log");
        let gzip_path = temp.path().join("checkpoint-gzip.log.gz");

        let plain_lines: Vec<String> = (0..60_000)
            .map(|idx| {
                sample_line(
                    "1.2.3.4",
                    &format!("/checkpoint-plain-{}.html", idx % 20),
                    200,
                    1_000 + idx as u64,
                )
            })
            .collect();
        let gzip_lines: Vec<String> = (0..60_000)
            .map(|idx| {
                sample_line(
                    "1.2.3.4",
                    &format!("/checkpoint-gzip-{}.html", idx % 20),
                    200,
                    2_000 + idx as u64,
                )
            })
            .collect();
        write_plain_file(&plain_path, &plain_lines);
        write_gzip_member(&gzip_path, &gzip_lines, false);

        let glob = format!(
            "{},{}",
            plain_path.to_str().expect("plain utf-8"),
            gzip_path.to_str().expect("gzip utf-8")
        );

        let mut baseline = {
            let db = Database::open(db_baseline.to_str().expect("baseline db utf-8"))
                .expect("open baseline db");
            Processor::new(
                db,
                Geo::new(None),
                UaParser::new(),
                db_baseline.to_string_lossy().into_owned(),
                None,
                2,
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
        };

        let mut checkpointed = {
            let db = Database::open(db_checkpoint.to_str().expect("checkpoint db utf-8"))
                .expect("open checkpoint db");
            Processor::new(
                db,
                Geo::new(None),
                UaParser::new(),
                db_checkpoint.to_string_lossy().into_owned(),
                None,
                2,
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
        };

        // Force frequent checkpoint requests so workers pause/resume mid-file.
        checkpointed.checkpoint_every = Some(Duration::from_millis(1));

        let baseline_lines = baseline
            .process_globs(&glob)
            .expect("baseline process_globs");
        let checkpoint_lines = checkpointed
            .process_globs(&glob)
            .expect("checkpointed process_globs");

        assert_eq!(baseline_lines, 120_000);
        assert_eq!(checkpoint_lines, baseline_lines);

        let baseline_snapshot = snapshot_db(&db_baseline);
        let checkpoint_snapshot = snapshot_db(&db_checkpoint);
        assert_eq!(checkpoint_snapshot, baseline_snapshot);
    }

    #[test]
    fn aggregate_entry_timeout_boundary_of_30_minutes_is_same_visit() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let mut processor = new_processor_with_options(&db_path, false, None);

        let mut hourly: HourlyMap = AHashMap::new();
        let mut top_urls: PeriodHitsMap = AHashMap::new();
        let mut top_hosts: HostHitsMap = AHashMap::new();
        let mut top_refs: PeriodCountMap = AHashMap::new();
        let mut top_agents: PeriodCountMap = AHashMap::new();
        let mut top_countries: CountryCountMap = AHashMap::new();
        let mut status_codes: StatusMap = AHashMap::new();

        processor.aggregate_entry(
            log_entry(
                "1.2.3.4",
                "08/May/2026:14:00:00 +0000",
                "/index.html",
                200,
                100,
                "",
                "Mozilla/5.0",
            ),
            &mut hourly,
            &mut top_urls,
            &mut top_hosts,
            &mut top_refs,
            &mut top_agents,
            &mut top_countries,
            &mut status_codes,
        );
        processor.aggregate_entry(
            log_entry(
                "1.2.3.4",
                "08/May/2026:14:30:00 +0000",
                "/index.html",
                200,
                100,
                "",
                "Mozilla/5.0",
            ),
            &mut hourly,
            &mut top_urls,
            &mut top_hosts,
            &mut top_refs,
            &mut top_agents,
            &mut top_countries,
            &mut status_codes,
        );

        let total_visits: u64 = hourly
            .values()
            .flat_map(|hours| hours.values())
            .map(|acc| acc.stats.visits)
            .sum();
        assert_eq!(total_visits, 1);
    }

    #[test]
    fn aggregate_entry_with_tracking_disabled_keeps_visits_at_zero() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let mut processor = new_processor_with_options(&db_path, false, None);
        processor.track_visits = false;

        let mut hourly: HourlyMap = AHashMap::new();
        let mut top_urls: PeriodHitsMap = AHashMap::new();
        let mut top_hosts: HostHitsMap = AHashMap::new();
        let mut top_refs: PeriodCountMap = AHashMap::new();
        let mut top_agents: PeriodCountMap = AHashMap::new();
        let mut top_countries: CountryCountMap = AHashMap::new();
        let mut status_codes: StatusMap = AHashMap::new();

        for ts in [
            "08/May/2026:14:00:00 +0000",
            "08/May/2026:15:30:00 +0000",
            "08/May/2026:17:00:00 +0000",
        ] {
            processor.aggregate_entry(
                log_entry(
                    "1.2.3.4",
                    ts,
                    "/index.html",
                    200,
                    100,
                    "",
                    "Mozilla/5.0",
                ),
                &mut hourly,
                &mut top_urls,
                &mut top_hosts,
                &mut top_refs,
                &mut top_agents,
                &mut top_countries,
                &mut status_codes,
            );
        }

        let total_visits: u64 = hourly
            .values()
            .flat_map(|hours| hours.values())
            .map(|acc| acc.stats.visits)
            .sum();
        assert_eq!(total_visits, 0);
    }

    #[test]
    fn aggregate_entry_status_buckets_cover_3xx_4xx_and_5xx() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let mut processor = new_processor_with_options(&db_path, false, None);

        let mut hourly: HourlyMap = AHashMap::new();
        let mut top_urls: PeriodHitsMap = AHashMap::new();
        let mut top_hosts: HostHitsMap = AHashMap::new();
        let mut top_refs: PeriodCountMap = AHashMap::new();
        let mut top_agents: PeriodCountMap = AHashMap::new();
        let mut top_countries: CountryCountMap = AHashMap::new();
        let mut status_codes: StatusMap = AHashMap::new();

        for status in [302u16, 404u16, 503u16] {
            processor.aggregate_entry(
                log_entry(
                    "1.2.3.4",
                    "08/May/2026:14:23:01 +0000",
                    "/index.html",
                    status,
                    10,
                    "",
                    "Mozilla/5.0",
                ),
                &mut hourly,
                &mut top_urls,
                &mut top_hosts,
                &mut top_refs,
                &mut top_agents,
                &mut top_countries,
                &mut status_codes,
            );
        }

        let stats = &hourly
            .get("2026-05-08")
            .expect("date bucket")
            .get(&14)
            .expect("hour bucket")
            .stats;
        assert_eq!(stats.status_2xx, 0);
        assert_eq!(stats.status_3xx, 1);
        assert_eq!(stats.status_4xx, 1);
        assert_eq!(stats.status_5xx, 1);
        assert_eq!(stats.pages, 0);
        assert_eq!(stats.files, 0);
    }

    #[test]
    fn helper_strip_query_and_file_ext_handle_common_edge_cases() {
        assert_eq!(strip_query("/docs/page.html?utm=1"), "/docs/page.html");
        assert_eq!(strip_query("/docs/page.html"), "/docs/page.html");

        assert_eq!(file_ext("/assets/app.min.js"), ".js");
        assert_eq!(file_ext("/a.b.c/index"), "");
        assert_eq!(file_ext("/a.b.c/index.html"), ".html");
    }

    #[test]
    fn helper_extract_host_from_url_parses_port_path_and_query() {
        assert_eq!(
            extract_host_from_url("https://example.com:8443/path?a=1").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            extract_host_from_url("https://ref.example.org?src=home").as_deref(),
            Some("ref.example.org")
        );
        assert!(extract_host_from_url("mailto:test@example.com").is_none());
        assert!(extract_host_from_url("https:///missing-host").is_none());
    }

    #[test]
    fn helper_parse_unix_timestamp_honors_timezone_and_rejects_invalid() {
        let utc = parse_unix_timestamp("08/May/2026:14:00:00 +0000", 5).expect("utc ts");
        let plus_two = parse_unix_timestamp("08/May/2026:16:00:00 +0200", 5).expect("+0200 ts");
        let minus_two = parse_unix_timestamp("08/May/2026:12:00:00 -0200", 5).expect("-0200 ts");

        assert_eq!(utc, plus_two);
        assert_eq!(utc, minus_two);
        assert!(parse_unix_timestamp("08/May/2026:14:00:00 *0000", 5).is_none());
        assert!(parse_unix_timestamp("bad", 5).is_none());
    }

    #[test]
    fn process_log_end_to_end_populates_wide_date_range_aggregates() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("wide-range.log");

        let lines = vec![
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
                "10.0.0.1",
                "01/Jan/2025:00:05:00 +0000",
                "/asset.js?v=1",
                200,
                50,
                "https://news.ycombinator.com/item?id=2",
                "Mozilla/5.0",
            ),
            sample_line_at(
                "10.0.0.2",
                "01/Jan/2025:00:10:00 +0000",
                "/redirect",
                302,
                0,
                "-",
                "Mozilla/5.0",
            ),
            sample_line_at(
                "10.0.0.3",
                "15/Jul/2025:12:00:00 +0000",
                "/missing",
                404,
                25,
                "https://google.com/search?q=missing",
                "Mozilla/5.0",
            ),
            sample_line_at(
                "10.0.0.4",
                "09/May/2026:08:00:00 +0000",
                "/boom",
                503,
                5,
                "https://google.com/search?q=boom",
                "Mozilla/5.0",
            ),
            sample_line_at(
                "10.0.0.4",
                "09/May/2026:08:20:00 +0000",
                "/index.html",
                200,
                70,
                "https://mysite.test/about",
                "Mozilla/5.0",
            ),
            sample_line_at(
                "10.0.0.4",
                "09/May/2026:09:00:00 +0000",
                "/index.html",
                200,
                70,
                "https://google.com/search?q=index",
                "Mozilla/5.0",
            ),
        ];
        write_plain_file(&log_path, &lines);

        let mut processor = new_processor_with_options(&db_path, true, Some("mysite.test"));
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            lines.len() as u64
        );

        let conn = Connection::open(&db_path).expect("open db");

        let (hits, visits, pages, files, bandwidth): (i64, i64, i64, i64, i64) = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0), COALESCE(SUM(visits),0), COALESCE(SUM(pages),0), COALESCE(SUM(files),0), COALESCE(SUM(bandwidth),0) FROM hourly_stats",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .expect("read hourly totals");
        assert_eq!(hits, 7);
        assert_eq!(visits, 5);
        assert_eq!(pages, 3);
        assert_eq!(files, 1);
        assert_eq!(bandwidth, 320);

        let y2024_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM hourly_stats WHERE date LIKE '2024-%'",
                [],
                |row| row.get(0),
            )
            .expect("2024 hits");
        let y2025_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM hourly_stats WHERE date LIKE '2025-%'",
                [],
                |row| row.get(0),
            )
            .expect("2025 hits");
        let y2026_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM hourly_stats WHERE date LIKE '2026-%'",
                [],
                |row| row.get(0),
            )
            .expect("2026 hits");
        assert_eq!(y2024_hits, 1);
        assert_eq!(y2025_hits, 3);
        assert_eq!(y2026_hits, 3);

        let may_2026_google_refs: i64 = conn
            .query_row(
                "SELECT hits FROM top_refs WHERE period = '2026-05' AND referrer = 'google.com'",
                [],
                |row| row.get(0),
            )
            .expect("2026-05 google refs");
        assert_eq!(may_2026_google_refs, 2);

        let may_2026_self_refs: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM top_refs WHERE period = '2026-05' AND referrer = 'mysite.test'",
                [],
                |row| row.get(0),
            )
            .expect("2026-05 self refs");
        assert_eq!(may_2026_self_refs, 0);

        let (index_hits, index_bw): (i64, i64) = conn
            .query_row(
                "SELECT hits, bandwidth FROM top_urls_hits WHERE period = '2026-05' AND url = '/index.html'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .expect("2026-05 index url");
        assert_eq!(index_hits, 2);
        assert_eq!(index_bw, 140);

        let year_2025_404: i64 = conn
            .query_row(
                "SELECT hits FROM status_codes WHERE period = '2025' AND status = 404",
                [],
                |row| row.get(0),
            )
            .expect("2025 status 404");
        let year_2026_503: i64 = conn
            .query_row(
                "SELECT hits FROM status_codes WHERE period = '2026' AND status = 503",
                [],
                |row| row.get(0),
            )
            .expect("2026 status 503");
        assert_eq!(year_2025_404, 1);
        assert_eq!(year_2026_503, 1);
    }

    #[test]
    fn process_globs_multiple_files_across_years_aggregates_once() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_a = temp.path().join("access-a.log");
        let log_b = temp.path().join("access-b.log");

        let lines_a = vec![
            sample_line_at(
                "10.1.0.1",
                "05/Jan/2024:10:00:00 +0000",
                "/a.html",
                200,
                10,
                "https://example.org/a",
                "Mozilla/5.0",
            ),
            sample_line_at(
                "10.1.0.2",
                "05/Jan/2024:10:10:00 +0000",
                "/b.js",
                200,
                20,
                "https://example.org/b",
                "Mozilla/5.0",
            ),
            sample_line_at(
                "10.1.0.2",
                "06/Jan/2024:11:00:00 +0000",
                "/missing",
                404,
                1,
                "https://example.org/c",
                "Mozilla/5.0",
            ),
        ];
        let lines_b = vec![
            sample_line_at(
                "10.2.0.1",
                "03/Mar/2026:09:00:00 +0000",
                "/index.html",
                200,
                30,
                "https://google.com/search?q=index",
                "Mozilla/5.0",
            ),
            sample_line_at(
                "10.2.0.1",
                "03/Mar/2026:09:40:00 +0000",
                "/index.html",
                200,
                30,
                "https://google.com/search?q=index2",
                "Mozilla/5.0",
            ),
            sample_line_at(
                "10.2.0.3",
                "04/Mar/2026:09:00:00 +0000",
                "/redirect",
                302,
                0,
                "-",
                "Mozilla/5.0",
            ),
        ];

        write_plain_file(&log_a, &lines_a);
        write_plain_file(&log_b, &lines_b);

        let mut processor = new_processor_with_options(&db_path, true, None);
        let pattern = format!(
            "{},{}",
            log_a.to_str().expect("log_a utf-8"),
            log_b.to_str().expect("log_b utf-8")
        );

        assert_eq!(processor.process_globs(&pattern).unwrap(), 6);
        assert_eq!(processor.process_globs(&pattern).unwrap(), 0);

        let conn = Connection::open(&db_path).expect("open db");
        let (hits, visits, pages, files, bandwidth): (i64, i64, i64, i64, i64) = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0), COALESCE(SUM(visits),0), COALESCE(SUM(pages),0), COALESCE(SUM(files),0), COALESCE(SUM(bandwidth),0) FROM hourly_stats",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .expect("read totals");
        assert_eq!(hits, 6);
        assert_eq!(visits, 6);
        assert_eq!(pages, 3);
        assert_eq!(files, 1);
        assert_eq!(bandwidth, 91);

        let jan_2024_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM hourly_stats WHERE date LIKE '2024-01-%'",
                [],
                |row| row.get(0),
            )
            .expect("jan 2024 hits");
        let mar_2026_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM hourly_stats WHERE date LIKE '2026-03-%'",
                [],
                |row| row.get(0),
            )
            .expect("mar 2026 hits");
        assert_eq!(jan_2024_hits, 3);
        assert_eq!(mar_2026_hits, 3);

        let year_2024_404: i64 = conn
            .query_row(
                "SELECT hits FROM status_codes WHERE period = '2024' AND status = 404",
                [],
                |row| row.get(0),
            )
            .expect("2024 status 404");
        let year_2026_302: i64 = conn
            .query_row(
                "SELECT hits FROM status_codes WHERE period = '2026' AND status = 302",
                [],
                |row| row.get(0),
            )
            .expect("2026 status 302");
        assert_eq!(year_2024_404, 1);
        assert_eq!(year_2026_302, 1);

        let index_hits_2026_03: i64 = conn
            .query_row(
                "SELECT hits FROM top_urls_hits WHERE period = '2026-03' AND url = '/index.html'",
                [],
                |row| row.get(0),
            )
            .expect("2026-03 index hits");
        assert_eq!(index_hits_2026_03, 2);
    }

    #[test]
    fn pruner_retains_top_n_and_removes_rest() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let _ = new_processor(&db_path);
        let conn = Connection::open(&db_path).expect("open db");
        for i in 0..30 {
            conn.execute(
                "INSERT OR REPLACE INTO top_urls_hits (period, url, hits, bandwidth) VALUES ('2020-01', ?1, ?2, 100)",
                rusqlite::params![format!("/page-{:02}.html", i), 30 - i],
            )
            .expect("insert url");
        }
        conn.execute(
            "INSERT OR REPLACE INTO top_urls_hits (period, url, hits, bandwidth) VALUES ('2020-02', '/latest.html', 1, 100)",
            [],
        )
        .expect("insert latest period url");

        drop(conn);
        let mut processor = new_processor(&db_path);
        processor.prune_top_tables().expect("prune");

        let conn = Connection::open(&db_path).expect("open db after prune");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM top_urls_hits WHERE period = '2020-01'",
                [],
                |row| row.get(0),
            )
            .expect("count urls");
        assert_eq!(count, 20);
    }

    #[test]
    fn pruner_keeps_latest_period_untrimmed() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let _ = new_processor(&db_path);
        let conn = Connection::open(&db_path).expect("open db");

        for i in 0..30 {
            conn.execute(
                "INSERT OR REPLACE INTO top_urls_hits (period, url, hits, bandwidth) VALUES (?1, ?2, ?3, 100)",
                rusqlite::params!["2020-02", format!("/archive-{:02}.html", i), i + 1],
            )
            .expect("insert archived url");
        }

        drop(conn);
        let mut processor = new_processor(&db_path);
        processor.prune_top_tables().expect("prune");

        let conn = Connection::open(&db_path).expect("open db after prune");
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM top_urls_hits WHERE period = ?1",
                rusqlite::params!["2020-02"],
                |row| row.get(0),
            )
            .expect("count archived urls");
        assert_eq!(count, 30);
    }

    #[test]
    fn preflush_filter_trims_non_current_periods_for_top_urls() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let mut processor = new_processor(&db_path);
        processor.top_n = 2;
        processor.topn_k = 5;

        let mut top_urls: PeriodHitsMap = AHashMap::new();

        let mut old_period = TopNHitsBw::new(5);
        old_period.add_hits_bw("/a", 100, 1);
        old_period.add_hits_bw("/b", 90, 2);
        old_period.add_hits_bw("/c", 5, 1_000);
        old_period.add_hits_bw("/d", 4, 900);
        old_period.add_hits_bw("/e", 50, 50);

        let mut current_period = TopNHitsBw::new(5);
        current_period.add_hits_bw("/n1", 10, 10);
        current_period.add_hits_bw("/n2", 9, 9);
        current_period.add_hits_bw("/n3", 8, 8);
        current_period.add_hits_bw("/n4", 7, 7);
        current_period.add_hits_bw("/n5", 6, 6);

        top_urls.insert(Arc::<str>::from("2026-01"), old_period);
        top_urls.insert(Arc::<str>::from("2026-02"), current_period);

        let filtered = processor.filter_top_urls_for_flush(&top_urls);

        let old_urls: Vec<String> = filtered
            .get("2026-01")
            .expect("old period present")
            .iter()
            .map(|(url, _, _)| url.to_string())
            .collect();
        assert_eq!(old_urls.len(), 4);
        assert!(old_urls.iter().any(|url| url == "/a"));
        assert!(old_urls.iter().any(|url| url == "/b"));
        assert!(old_urls.iter().any(|url| url == "/c"));
        assert!(old_urls.iter().any(|url| url == "/d"));
        assert!(!old_urls.iter().any(|url| url == "/e"));

        let current_count = filtered
            .get("2026-02")
            .expect("current period present")
            .iter()
            .count();
        assert_eq!(current_count, 5);
    }

    #[test]
    fn preflush_filter_disabled_when_pruner_disabled_preserves_all_urls() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let mut processor = new_processor(&db_path);
        processor.top_n = 2;
        processor.topn_k = 5;
        processor.enable_pruner = false;

        let log_path = temp.path().join("out-of-order.log");
        write_plain_file(&log_path, &[sample_line("1.2.3.4", "/dummy", 200, 100)]);

        let mut processor_run_acc =
            RunAccumulators::new(64, processor.hll_precision, true, false, false);
        let mut pending_parse_states = Vec::new();
        let mut retired_parse_states = Vec::new();
        let plan = processor
            .resolve_for_processing_test(
                log_path.to_str().unwrap(),
                &mut pending_parse_states,
                &mut retired_parse_states,
            )
            .expect("resolve")
            .expect("plan should exist");
        let mut flush_last = Instant::now();
        processor
            .process_with_progress(
                log_path.to_str().unwrap(),
                1,
                1,
                plan,
                None,
                None,
                &mut processor_run_acc,
                &mut pending_parse_states,
                &mut flush_last,
            )
            .expect("process");

        let mut old_period = TopNHitsBw::new(5);
        old_period.add_hits_bw("/a", 100, 1);
        old_period.add_hits_bw("/b", 90, 2);
        old_period.add_hits_bw("/c", 5, 1_000);
        old_period.add_hits_bw("/d", 4, 900);
        old_period.add_hits_bw("/e", 50, 50);

        processor_run_acc
            .top_urls
            .insert(Arc::<str>::from("2026-01"), old_period);

        processor
            .flush_run(
                &processor_run_acc,
                &pending_parse_states,
                &retired_parse_states,
            )
            .expect("flush");

        let conn = Connection::open(&db_path).expect("open db after flush");
        let old_period_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM top_urls_hits WHERE period = '2026-01'",
                [],
                |row| row.get(0),
            )
            .expect("count old period urls");

        assert_eq!(
            old_period_count, 5,
            "All 5 URLs should be flushed when pruner is disabled"
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
        let processed = processor.process(log_path.to_str().unwrap(), 1, 1).unwrap();
        assert_eq!(processed, 5);

        let conn = Connection::open(&db_path).expect("open db");
        let sites: i64 = conn
            .query_row(
                "SELECT sites FROM hourly_stats WHERE date = '2026-05-08' AND hour = 14",
                [],
                |row| row.get(0),
            )
            .expect("sites");
        assert_eq!(sites, 1);
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
        let processed = processor.process(log_path.to_str().unwrap(), 1, 1).unwrap();
        assert_eq!(processed, 5);

        let conn = Connection::open(&db_path).expect("open db");
        let sites: i64 = conn
            .query_row(
                "SELECT sites FROM hourly_stats WHERE date = '2026-05-08' AND hour = 14",
                [],
                |row| row.get(0),
            )
            .expect("sites");
        assert_eq!(sites, 5);
    }

    #[test]
    fn process_persists_top_tables_for_month_and_year() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("tops.log");

        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";
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
        let processed = processor.process(log_path.to_str().unwrap(), 1, 1).unwrap();
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

        let year_hits: i64 = conn
            .query_row(
                "SELECT hits FROM top_urls_hits WHERE period = '2026' AND url = '/popular.html'",
                [],
                |row| row.get(0),
            )
            .expect("year top url");
        assert_eq!(year_hits, 2);

        let top_host_hits: i64 = conn
            .query_row(
                "SELECT SUM(hits) FROM top_hosts WHERE period = '2026-05'",
                [],
                |row| row.get(0),
            )
            .expect("top host hits");
        assert_eq!(top_host_hits, 3);

        let google_refs: i64 = conn
            .query_row(
                "SELECT hits FROM top_refs WHERE period = '2026-05' AND referrer = 'google.com'",
                [],
                |row| row.get(0),
            )
            .expect("google refs");
        let twitter_refs: i64 = conn
            .query_row(
                "SELECT hits FROM top_refs WHERE period = '2026-05' AND referrer = 'twitter.com'",
                [],
                |row| row.get(0),
            )
            .expect("twitter refs");
        assert_eq!(google_refs, 2);
        assert_eq!(twitter_refs, 1);

        let agent_hits: i64 = conn
            .query_row(
                "SELECT SUM(hits) FROM top_agents WHERE period = '2026-05'",
                [],
                |row| row.get(0),
            )
            .expect("agent hits");
        assert_eq!(agent_hits, 3);

        let country_hits: i64 = conn
            .query_row(
                "SELECT hits FROM top_countries WHERE period = '2026-05' AND country_code = '--'",
                [],
                |row| row.get(0),
            )
            .expect("country hits");
        assert_eq!(country_hits, 3);

        let status_200: i64 = conn
            .query_row(
                "SELECT hits FROM status_codes WHERE period = '2026-05' AND status = 200",
                [],
                |row| row.get(0),
            )
            .expect("status 200");
        let status_404: i64 = conn
            .query_row(
                "SELECT hits FROM status_codes WHERE period = '2026-05' AND status = 404",
                [],
                |row| row.get(0),
            )
            .expect("status 404");
        assert_eq!(status_200, 2);
        assert_eq!(status_404, 1);
    }

    #[test]
    fn file_rotation_append_then_rotate_does_not_reprocess() {
        // Real-world scenario:
        // 1. First run: access.log has 1 line, fully processed and offset stored
        // 2. Before next run:
        //    - A new line is APPENDED to access.log (now 2 lines)
        //    - File is rotated: access.log → access.log.1 (may preserve same inode on move)
        //    - New empty access.log is created
        // 3. Second run: we find access.log and access.log.1
        //    - access.log.1 has 2 lines total: 1 old (already processed) + 1 new
        //    - Should use inode-based offset tracking to skip the old line
        //    - Should only process the new appended line
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");
        let rotated_path = temp.path().join("access.log.1");

        // First run: process access.log with 1 line
        let first_line = sample_line("1.2.3.4", "/first.html", 200, 1000);
        write_plain_file(&log_path, &[first_line.clone()]);

        let mut processor = new_processor(&db_path);
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 1).unwrap(),
            1,
            "First run should process 1 line"
        );

        // Get the byte offset where we stopped
        let inode_before = fs::metadata(&log_path).unwrap().ino();

        // Simulate what happens before rotation: append a new line to access.log
        let second_line = sample_line("5.6.7.8", "/second.html", 200, 2000);
        append_plain_file(&log_path, &[second_line.clone()]);

        // Now simulate the rotation: move (not copy) access.log to access.log.1
        // This preserves the inode, which is the key for offset-based tracking
        fs::rename(&log_path, &rotated_path).expect("rename to rotated path");

        // Create new empty access.log
        write_plain_file(&log_path, &[]);

        // Verify inode was preserved through the rename (this is key for real logrotate behavior)
        let inode_rotated = fs::metadata(&rotated_path).unwrap().ino();
        assert_eq!(
            inode_before, inode_rotated,
            "Rotation should preserve inode via move operation"
        );

        // Second run: process both files
        // With proper inode-based offset tracking:
        // - access.log is empty, 0 lines
        // - access.log.1 should use saved offset to skip already-processed content, 1 line
        assert_eq!(
            processor.process(log_path.to_str().unwrap(), 1, 2).unwrap(),
            0,
            "New access.log is empty"
        );

        assert_eq!(
            processor
                .process(rotated_path.to_str().unwrap(), 2, 2)
                .unwrap(),
            1,
            "Rotated file should only process the newly appended line using offset tracking"
        );

        // Verify we processed exactly 2 lines total (1 processed twice = bug, vs 1 old + 1 new = correct)
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
    fn process_globs_rotation_resolution_is_order_independent() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");
        let rotated_path = temp.path().join("access.log.1");
        let pattern = format!("{}*", log_path.to_str().expect("glob utf-8"));

        write_plain_file(
            &log_path,
            &[sample_line("1.2.3.4", "/first.html", 200, 1000)],
        );

        let mut processor = new_processor(&db_path);
        assert_eq!(processor.process_globs(&pattern).expect("first run"), 1);

        append_plain_file(
            &log_path,
            &[sample_line("5.6.7.8", "/second.html", 200, 2000)],
        );
        fs::rename(&log_path, &rotated_path).expect("rename rotated log");
        write_plain_file(&log_path, &[]);

        assert_eq!(
            processor.process_globs(&pattern).expect("second run"),
            1,
            "phase-one resolution should avoid ordering bugs when access.log sorts before access.log.1"
        );

        let conn = Connection::open(db_path.to_str().unwrap()).expect("open db");
        let total_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(hits),0) FROM hourly_stats",
                [],
                |row| row.get(0),
            )
            .expect("query total hits");
        assert_eq!(total_hits, 2);
    }

    fn line_with_method_proto(
        method: &str,
        proto: &str,
        path: &str,
        status: u16,
        bytes: u64,
    ) -> String {
        format!(
            r#"1.2.3.4 - - [08/May/2026:14:23:01 +0000] "{method} {path} {proto}" {status} {bytes} "-" "Mozilla/5.0""#
        )
    }

    #[test]
    fn process_globs_stores_method_counts_per_period() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");
        let pattern = log_path.to_str().expect("utf-8").to_string();

        let lines = vec![
            line_with_method_proto("GET", "HTTP/1.1", "/a.html", 200, 100),
            line_with_method_proto("GET", "HTTP/1.1", "/b.html", 200, 200),
            line_with_method_proto("POST", "HTTP/1.1", "/submit", 201, 0),
            line_with_method_proto("HEAD", "HTTP/2.0", "/c.html", 200, 0),
        ];
        write_plain_file(&log_path, &lines);

        let mut processor = new_processor(&db_path);
        let processed = processor.process_globs(&pattern).expect("process");
        assert_eq!(processed, 4);

        let conn = Connection::open(db_path.to_str().unwrap()).expect("open db");

        let get_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM method_counts WHERE period='2026-05' AND method='GET'",
                [],
                |r| r.get(0),
            )
            .expect("GET month");
        assert_eq!(get_hits, 2);

        let post_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM method_counts WHERE period='2026-05' AND method='POST'",
                [],
                |r| r.get(0),
            )
            .expect("POST month");
        assert_eq!(post_hits, 1);

        let head_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM method_counts WHERE period='2026-05' AND method='HEAD'",
                [],
                |r| r.get(0),
            )
            .expect("HEAD month");
        assert_eq!(head_hits, 1);

        // Year period should also be written.
        let get_year: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM method_counts WHERE period='2026' AND method='GET'",
                [],
                |r| r.get(0),
            )
            .expect("GET year");
        assert_eq!(get_year, 2);
    }

    #[test]
    fn process_globs_stores_proto_counts_per_period() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");
        let pattern = log_path.to_str().expect("utf-8").to_string();

        let lines = vec![
            line_with_method_proto("GET", "HTTP/1.1", "/a.html", 200, 100),
            line_with_method_proto("GET", "HTTP/1.1", "/b.html", 200, 200),
            line_with_method_proto("GET", "HTTP/1.1", "/c.html", 200, 300),
            line_with_method_proto("POST", "HTTP/2.0", "/submit", 200, 0),
            line_with_method_proto("GET", "HTTP/2", "/d.html", 200, 400),
        ];
        write_plain_file(&log_path, &lines);

        let mut processor = new_processor(&db_path);
        processor.process_globs(&pattern).expect("process");

        let conn = Connection::open(db_path.to_str().unwrap()).expect("open db");

        let h11: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM proto_counts WHERE period='2026-05' AND proto='1.1'",
                [],
                |r| r.get(0),
            )
            .expect("1.1 month");
        assert_eq!(h11, 3);

        // HTTP/2.0 and HTTP/2 both map to "2.0".
        let h2: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM proto_counts WHERE period='2026-05' AND proto='2.0'",
                [],
                |r| r.get(0),
            )
            .expect("2.0 month");
        assert_eq!(h2, 2);

        // No HTTP/ prefix in the stored values.
        let bad_rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM proto_counts WHERE proto LIKE 'HTTP/%'",
                [],
                |r| r.get(0),
            )
            .expect("prefix check");
        assert_eq!(bad_rows, 0);

        // Year period.
        let h11_year: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM proto_counts WHERE period='2026' AND proto='1.1'",
                [],
                |r| r.get(0),
            )
            .expect("1.1 year");
        assert_eq!(h11_year, 3);
    }

    #[test]
    fn process_globs_method_and_proto_accumulate_across_runs() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");
        let pattern = log_path.to_str().expect("utf-8").to_string();

        write_plain_file(
            &log_path,
            &[line_with_method_proto("GET", "HTTP/1.1", "/a.html", 200, 100)],
        );

        let mut processor = new_processor(&db_path);
        processor.process_globs(&pattern).expect("first run");

        // Append a new line.
        append_plain_file(
            &log_path,
            &[line_with_method_proto("POST", "HTTP/2.0", "/form", 201, 0)],
        );
        processor.process_globs(&pattern).expect("second run");

        let conn = Connection::open(db_path.to_str().unwrap()).expect("open db");

        let get_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM method_counts WHERE period='2026-05' AND method='GET'",
                [],
                |r| r.get(0),
            )
            .expect("GET after two runs");
        assert_eq!(get_hits, 1);

        let post_hits: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM method_counts WHERE period='2026-05' AND method='POST'",
                [],
                |r| r.get(0),
            )
            .expect("POST after two runs");
        assert_eq!(post_hits, 1);

        let h11: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM proto_counts WHERE period='2026-05' AND proto='1.1'",
                [],
                |r| r.get(0),
            )
            .expect("1.1 after two runs");
        assert_eq!(h11, 1);

        let h2: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM proto_counts WHERE period='2026-05' AND proto='2.0'",
                [],
                |r| r.get(0),
            )
            .expect("2.0 after two runs");
        assert_eq!(h2, 1);
    }

    #[test]
    fn process_globs_unknown_method_and_proto_map_to_other() {
        let temp = TempDir::new().expect("tempdir");
        let db_path = temp.path().join("webstat.db");
        let log_path = temp.path().join("access.log");
        let pattern = log_path.to_str().expect("utf-8").to_string();

        write_plain_file(
            &log_path,
            &[
                line_with_method_proto("CONNECT", "HTTP/1.1", "/tunnel", 200, 0),
                line_with_method_proto("GET", "SPDY/3", "/a.html", 200, 100),
            ],
        );

        let mut processor = new_processor(&db_path);
        processor.process_globs(&pattern).expect("process");

        let conn = Connection::open(db_path.to_str().unwrap()).expect("open db");

        let other_method: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM method_counts WHERE period='2026-05' AND method='other'",
                [],
                |r| r.get(0),
            )
            .expect("other method");
        assert_eq!(other_method, 1, "CONNECT should map to 'other'");

        let other_proto: i64 = conn
            .query_row(
                "SELECT COALESCE(hits,0) FROM proto_counts WHERE period='2026-05' AND proto='other'",
                [],
                |r| r.get(0),
            )
            .expect("other proto");
        assert_eq!(other_proto, 1, "SPDY/3 should map to 'other'");
    }
}
