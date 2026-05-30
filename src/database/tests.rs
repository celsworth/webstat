// Integration tests for database schema, state persistence, and writer correctness.

use super::*;

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::ip::{Ip, IpBitmaps};
    use crate::method_proto::{
        METHOD_COUNT, METHOD_GET, METHOD_POST, PROTO_1_1, PROTO_2_0, PROTO_COUNT,
    };

    fn open_test_db() -> Database {
        Database::open(":memory:").expect("open in-memory db")
    }

    fn empty_flush(db: &mut Database, period: &str, method_counts: &[u64], protocol_counts: &[u64]) {
        let empty_hourly = ahash::AHashMap::new();
        let empty_url_stats = ahash::AHashMap::new();
        let empty_hosts = ahash::AHashMap::new();
        let empty_host_geo = ahash::AHashMap::new();
        let empty_refs = ahash::AHashMap::new();
        let empty_agents = ahash::AHashMap::new();
        let empty_ips = ahash::AHashMap::new();
        let empty_hists = ahash::AHashMap::new();
        let empty_countries = ahash::AHashMap::new();
        let empty_status = ahash::AHashMap::new();
        db.flush(crate::database::writer::FlushData {
            period,
            hourly: &empty_hourly,
            url_stats: &empty_url_stats,
            hosts: &empty_hosts,
            host_geo: &empty_host_geo,
            refs: &empty_refs,
            agents: &empty_agents,
            daily_ips: &empty_ips,
            daily_hists: &empty_hists,
            countries: &empty_countries,
            status_codes: &empty_status,
            method_counts,
            protocol_counts,
            parse_states: &[],
            retired_parse_states: &[],
            visit_states: &[],
            visit_state_prune_before_ts: None,
        })
        .expect("flush");
    }

    #[test]
    fn method_counts_stored_with_correct_names_and_values() {
        let mut db = open_test_db();

        let mut counts = [0u64; METHOD_COUNT];
        counts[METHOD_GET] = 100;
        counts[METHOD_POST] = 42;
        empty_flush(&mut db, "2026-05", &counts, &[0u64; PROTO_COUNT]);

        let get_hits: i64 = db
            .conn
            .query_row(
                "SELECT hits FROM method_counts WHERE period='2026-05' AND method='GET'",
                [],
                |r| r.get(0),
            )
            .expect("GET row");
        assert_eq!(get_hits, 100);

        let post_hits: i64 = db
            .conn
            .query_row(
                "SELECT hits FROM method_counts WHERE period='2026-05' AND method='POST'",
                [],
                |r| r.get(0),
            )
            .expect("POST row");
        assert_eq!(post_hits, 42);
    }

    #[test]
    fn method_counts_zero_slots_are_not_stored() {
        let mut db = open_test_db();

        let mut counts = [0u64; METHOD_COUNT];
        counts[METHOD_GET] = 5;
        empty_flush(&mut db, "2026-05", &counts, &[0u64; PROTO_COUNT]);

        let row_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM method_counts WHERE period='2026-05'",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(row_count, 1, "only non-zero slots should be stored");
    }

    #[test]
    fn method_counts_accumulate_across_flushes() {
        let mut db = open_test_db();

        let mut c1 = [0u64; METHOD_COUNT];
        c1[METHOD_GET] = 100;
        empty_flush(&mut db, "2026-05", &c1, &[0u64; PROTO_COUNT]);

        let mut c2 = [0u64; METHOD_COUNT];
        c2[METHOD_GET] = 50;
        c2[METHOD_POST] = 10;
        empty_flush(&mut db, "2026-05", &c2, &[0u64; PROTO_COUNT]);

        let get_hits: i64 = db
            .conn
            .query_row(
                "SELECT hits FROM method_counts WHERE period='2026-05' AND method='GET'",
                [],
                |r| r.get(0),
            )
            .expect("GET after second flush");
        assert_eq!(get_hits, 150);

        let post_hits: i64 = db
            .conn
            .query_row(
                "SELECT hits FROM method_counts WHERE period='2026-05' AND method='POST'",
                [],
                |r| r.get(0),
            )
            .expect("POST after second flush");
        assert_eq!(post_hits, 10);
    }

    #[test]
    fn protocol_counts_stored_with_version_strings_not_http_prefix() {
        let mut db = open_test_db();

        let mut counts = [0u64; PROTO_COUNT];
        counts[PROTO_1_1] = 80;
        counts[PROTO_2_0] = 20;
        empty_flush(&mut db, "2026-05", &[0u64; METHOD_COUNT], &counts);

        let h11: i64 = db
            .conn
            .query_row(
                "SELECT hits FROM protocol_counts WHERE period='2026-05' AND proto='1.1'",
                [],
                |r| r.get(0),
            )
            .expect("1.1 row");
        assert_eq!(h11, 80);

        let h2: i64 = db
            .conn
            .query_row(
                "SELECT hits FROM protocol_counts WHERE period='2026-05' AND proto='2.0'",
                [],
                |r| r.get(0),
            )
            .expect("2.0 row");
        assert_eq!(h2, 20);

        let http_rows: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM protocol_counts WHERE proto LIKE 'HTTP/%'",
                [],
                |r| r.get(0),
            )
            .expect("http prefix check");
        assert_eq!(http_rows, 0);
    }

    #[test]
    fn protocol_counts_accumulate_across_flushes() {
        let mut db = open_test_db();

        let mut p1 = [0u64; PROTO_COUNT];
        p1[PROTO_1_1] = 200;
        empty_flush(&mut db, "2026-05", &[0u64; METHOD_COUNT], &p1);

        let mut p2 = [0u64; PROTO_COUNT];
        p2[PROTO_1_1] = 100;
        p2[PROTO_2_0] = 30;
        empty_flush(&mut db, "2026-05", &[0u64; METHOD_COUNT], &p2);

        let h11: i64 = db
            .conn
            .query_row(
                "SELECT hits FROM protocol_counts WHERE period='2026-05' AND proto='1.1'",
                [],
                |r| r.get(0),
            )
            .expect("1.1 after second flush");
        assert_eq!(h11, 300);

        let h2: i64 = db
            .conn
            .query_row(
                "SELECT hits FROM protocol_counts WHERE period='2026-05' AND proto='2.0'",
                [],
                |r| r.get(0),
            )
            .expect("2.0 after second flush");
        assert_eq!(h2, 30);
    }

    #[test]
    fn daily_unique_ips_deduplicates_across_flushes() {
        let mut db = open_test_db();

        let ip1 = Ip::V4(0x01020304);
        let ip2 = Ip::V4(0x05060708);

        let mut bm1 = IpBitmaps::default();
        bm1.insert(ip1);
        bm1.insert(ip2);
        let mut daily1 = ahash::AHashMap::new();
        daily1.insert(Arc::from("2026-05-01"), bm1);

        let mut bm2 = IpBitmaps::default();
        bm2.insert(ip1); // duplicate
        let mut daily2 = ahash::AHashMap::new();
        daily2.insert(Arc::from("2026-05-01"), bm2);

        let empty_urls: ahash::AHashMap<String, crate::run_accumulators::UrlStats> =
            ahash::AHashMap::new();
        let empty_hosts: ahash::AHashMap<String, (u64, u64)> = ahash::AHashMap::new();
        let empty_geo: ahash::AHashMap<String, (std::sync::Arc<str>, std::sync::Arc<str>)> =
            ahash::AHashMap::new();
        let empty_refs: ahash::AHashMap<String, u64> = ahash::AHashMap::new();
        let empty_agents: ahash::AHashMap<String, (u64, u64)> = ahash::AHashMap::new();
        let empty_countries: ahash::AHashMap<String, (u64, u64)> = ahash::AHashMap::new();
        let empty_status: ahash::AHashMap<u16, u64> = ahash::AHashMap::new();
        for daily in [&daily1, &daily2] {
            db.flush(crate::database::writer::FlushData {
                period: "2026-05",
                hourly: &ahash::AHashMap::new(),
                url_stats: &empty_urls,
                hosts: &empty_hosts,
                host_geo: &empty_geo,
                refs: &empty_refs,
                agents: &empty_agents,
                daily_ips: daily,
                daily_hists: &ahash::AHashMap::new(),
                countries: &empty_countries,
                status_codes: &empty_status,
                method_counts: &[0u64; METHOD_COUNT],
                protocol_counts: &[0u64; PROTO_COUNT],
                parse_states: &[],
                retired_parse_states: &[],
                visit_states: &[],
                visit_state_prune_before_ts: None,
            })
            .expect("flush");
        }

        // The count column holds the bitmap cardinality for the (date, ip_kind=1, ip_hi=0) row.
        let count: i64 = db
            .conn
            .query_row(
                "SELECT SUM(count) FROM daily_unique_ips WHERE date='2026-05-01'",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(count, 2, "duplicate IP must not inflate the count");
    }

    fn flush_ips(db: &mut Database, period: &str, date: &str, ips: Vec<Ip>) {
        let mut bm = IpBitmaps::default();
        for ip in ips {
            bm.insert(ip);
        }
        let mut daily = ahash::AHashMap::new();
        daily.insert(Arc::from(date), bm);
        db.flush(crate::database::writer::FlushData {
            period,
            hourly: &ahash::AHashMap::new(),
            url_stats: &ahash::AHashMap::new(),
            hosts: &ahash::AHashMap::new(),
            host_geo: &ahash::AHashMap::new(),
            refs: &ahash::AHashMap::new(),
            agents: &ahash::AHashMap::new(),
            daily_ips: &daily,
            daily_hists: &ahash::AHashMap::new(),
            countries: &ahash::AHashMap::new(),
            status_codes: &ahash::AHashMap::new(),
            method_counts: &[0u64; METHOD_COUNT],
            protocol_counts: &[0u64; PROTO_COUNT],
            parse_states: &[],
            retired_parse_states: &[],
            visit_states: &[],
            visit_state_prune_before_ts: None,
        })
        .expect("flush");
    }

    #[test]
    fn finalize_month_populates_all_time_ips_and_yearly_unique_ips() {
        let mut db = open_test_db();

        let ip1 = Ip::V4(0x01020304);
        let ip2 = Ip::V4(0x05060708);

        let mut bm = IpBitmaps::default();
        bm.insert(ip1);
        bm.insert(ip2);
        let mut daily = ahash::AHashMap::new();
        daily.insert(Arc::from("2026-05-01"), bm);

        let empty_hosts: ahash::AHashMap<String, (u64, u64)> = ahash::AHashMap::new();
        let empty_geo: ahash::AHashMap<String, (std::sync::Arc<str>, std::sync::Arc<str>)> =
            ahash::AHashMap::new();

        let mut url_stats: ahash::AHashMap<String, crate::run_accumulators::UrlStats> =
            ahash::AHashMap::new();
        for i in 0..30u64 {
            url_stats.insert(
                format!("/page-{}.html", i),
                crate::run_accumulators::UrlStats {
                    hits: 100 - i,
                    bandwidth: (100 - i) * 1024,
                    ..Default::default()
                },
            );
        }

        db.flush(crate::database::writer::FlushData {
            period: "2026-05",
            hourly: &ahash::AHashMap::new(),
            url_stats: &url_stats,
            hosts: &empty_hosts,
            host_geo: &empty_geo,
            refs: &ahash::AHashMap::new(),
            agents: &ahash::AHashMap::new(),
            daily_ips: &daily,
            daily_hists: &ahash::AHashMap::new(),
            countries: &ahash::AHashMap::new(),
            status_codes: &ahash::AHashMap::new(),
            method_counts: &[0u64; METHOD_COUNT],
            protocol_counts: &[0u64; PROTO_COUNT],
            parse_states: &[],
            retired_parse_states: &[],
            visit_states: &[],
            visit_state_prune_before_ts: None,
        })
        .expect("flush");

        db.finalize_month("2026-05", 20).expect("finalize");

        // monthly_unique_ips should have one blob row for the month with both IPs.
        let monthly_count: i64 = db
            .conn
            .query_row(
                "SELECT count FROM unique_visitor_counts WHERE period='2026-05'",
                [],
                |r| r.get(0),
            )
            .expect("monthly count");
        assert_eq!(monthly_count, 2);

        let blob: Vec<u8> = db
            .conn
            .query_row(
                "SELECT bitmap FROM monthly_unique_ips WHERE period='2026-05' AND ip_kind=1 AND ip_hi=0",
                [],
                |r| r.get(0),
            )
            .expect("monthly_unique_ips bitmap");
        let bm = roaring::RoaringBitmap::deserialize_from(&blob[..]).expect("deserialize");
        assert_eq!(bm.len(), 2, "monthly_unique_ips should contain 2 IPv4 addresses");

        // yearly count for 2026 should also be 2 (only one month so far)
        let yearly_count: i64 = db
            .conn
            .query_row(
                "SELECT count FROM unique_visitor_counts WHERE period='2026'",
                [],
                |r| r.get(0),
            )
            .expect("yearly count");
        assert_eq!(yearly_count, 2, "yearly count should equal monthly count when only one month exists");

        let url_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM top_urls WHERE period='2026-05'",
                [],
                |r| r.get(0),
            )
            .expect("url count after prune");
        assert_eq!(url_count, 20, "should be pruned to top_n=20");
    }

    #[test]
    fn finalize_year_counts_distinct_across_months_and_cleans_up() {
        let mut db = open_test_db();

        let ip1 = Ip::V4(0x01020304);
        let ip2 = Ip::V4(0x05060708);
        let ip3 = Ip::V4(0x09101112);

        // Jan: ip1 + ip2; Feb: ip2 + ip3 (ip2 shared across months)
        flush_ips(&mut db, "2026-01", "2026-01-15", vec![ip1, ip2]);
        db.finalize_month("2026-01", 20).expect("finalize jan");

        flush_ips(&mut db, "2026-02", "2026-02-10", vec![ip2, ip3]);
        db.finalize_month("2026-02", 20).expect("finalize feb");

        // yearly cache after Feb should reflect 3 distinct IPs, not 2
        let cached: i64 = db
            .conn
            .query_row(
                "SELECT COALESCE((SELECT count FROM unique_visitor_counts WHERE period='2026'), 0)",
                [],
                |r| r.get(0),
            )
            .expect("yearly cache");
        assert_eq!(
            cached, 3,
            "yearly cache should deduplicate ip2 across months"
        );

        // finalize_year is now a no-op (yearly count is kept current by finalize_month)
        db.finalize_year("2026").expect("finalize year");

        // monthly_unique_ips snapshots should still exist for both months
        let monthly_rows: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM monthly_unique_ips WHERE period LIKE '2026-%'",
                [],
                |r| r.get(0),
            )
            .expect("monthly_unique_ips rows after finalize_year");
        assert_eq!(monthly_rows, 2, "monthly snapshots should be retained");

        // unique_visitor_counts should still have the final count
        let final_count: i64 = db
            .conn
            .query_row(
                "SELECT COALESCE((SELECT count FROM unique_visitor_counts WHERE period='2026'), 0)",
                [],
                |r| r.get(0),
            )
            .expect("yearly cache after finalize_year");
        assert_eq!(final_count, 3);
    }

    #[test]
    fn set_parse_state_roundtrips_fields() {
        let db = open_test_db();

        db.set_parse_state(&ParseState {
            filepath: "access.log".into(),
            inode: 42,
            compressed_size: 789,
            uncompressed_size: 456,
            compressed_head_fingerprint: Some(11),
            uncompressed_head_fingerprint: Some(22),
            compressed_offset: 123,
            uncompressed_offset: 456,
            mtime_ns: 1_700_000_000,
            completed: true,
            earliest_ts: Some(1_700_000_000),
            latest_ts: Some(1_700_086_400),
            skip_before_ts: None,
        })
        .expect("set parse state");

        let state = db
            .get_parse_state("access.log")
            .expect("get parse state")
            .expect("parse state exists");
        assert_eq!(state.inode, 42);
        assert_eq!(state.compressed_size, 789);
        assert_eq!(state.uncompressed_size, 456);
        assert_eq!(state.compressed_head_fingerprint, Some(11));
        assert_eq!(state.uncompressed_head_fingerprint, Some(22));
        assert_eq!(state.compressed_offset, 123);
        assert_eq!(state.uncompressed_offset, 456);
        assert_eq!(state.mtime_ns, 1_700_000_000);
        assert!(state.completed);
    }

    // ── parse state lookup helpers ────────────────────────────────────────────

    fn bare_parse_state(filepath: &str, inode: u64) -> ParseState {
        ParseState {
            filepath: filepath.into(),
            inode,
            compressed_size: 0,
            uncompressed_size: 0,
            compressed_head_fingerprint: None,
            uncompressed_head_fingerprint: None,
            compressed_offset: 0,
            uncompressed_offset: 0,
            mtime_ns: 0,
            completed: false,
            earliest_ts: None,
            latest_ts: None,
            skip_before_ts: None,
        }
    }

    fn insert_archive(db: &Database, state: &ParseState) {
        db.conn.execute(
            "INSERT INTO parse_state_archive \
             (filepath, inode, compressed_size, uncompressed_size, \
              compressed_head_fingerprint, uncompressed_head_fingerprint, \
              compressed_offset, uncompressed_offset, mtime_ns, completed, \
              earliest_ts, latest_ts, skip_before_ts) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            rusqlite::params![
                state.filepath,
                state.inode as i64,
                state.compressed_size as i64,
                state.uncompressed_size as i64,
                state.compressed_head_fingerprint.map(|f| f as i64),
                state.uncompressed_head_fingerprint.map(|f| f as i64),
                state.compressed_offset as i64,
                state.uncompressed_offset as i64,
                state.mtime_ns,
                state.completed as i64,
                state.earliest_ts,
                state.latest_ts,
                state.skip_before_ts,
            ],
        )
        .unwrap();
    }

    // ── get_parse_state_by_inode ──────────────────────────────────────────────

    #[test]
    fn get_parse_state_by_inode_finds_active_entry() {
        let db = open_test_db();
        db.set_parse_state(&bare_parse_state("a.log", 99)).unwrap();
        let s = db.get_parse_state_by_inode(99).unwrap().expect("should find");
        assert_eq!(s.filepath, "a.log");
        assert_eq!(s.inode, 99);
    }

    #[test]
    fn get_parse_state_by_inode_falls_back_to_archive() {
        let db = open_test_db();
        insert_archive(&db, &bare_parse_state("arch.log", 77));
        let s = db.get_parse_state_by_inode(77).unwrap().expect("should find in archive");
        assert_eq!(s.filepath, "arch.log");
    }

    #[test]
    fn get_parse_state_by_inode_returns_none_when_absent() {
        let db = open_test_db();
        assert!(db.get_parse_state_by_inode(999).unwrap().is_none());
    }

    #[test]
    fn get_parse_state_by_inode_prefers_active_over_archive() {
        let db = open_test_db();
        db.set_parse_state(&bare_parse_state("active.log", 55)).unwrap();
        insert_archive(&db, &bare_parse_state("archive.log", 55));
        let s = db.get_parse_state_by_inode(55).unwrap().expect("should find");
        assert_eq!(s.filepath, "active.log", "active entry should take priority");
    }

    // ── find_completed_by_uncompressed_identity ───────────────────────────────

    #[test]
    fn find_completed_by_uncompressed_identity_true_on_match() {
        let db = open_test_db();
        db.set_parse_state(&ParseState {
            uncompressed_head_fingerprint: Some(0xABCD),
            uncompressed_size: 1024,
            completed: true,
            ..bare_parse_state("plain.log", 1)
        })
        .unwrap();
        assert!(db.find_completed_by_uncompressed_identity(0xABCD, 1024).unwrap());
    }

    #[test]
    fn find_completed_by_uncompressed_identity_false_when_incomplete() {
        let db = open_test_db();
        db.set_parse_state(&ParseState {
            uncompressed_head_fingerprint: Some(0xABCD),
            uncompressed_size: 1024,
            completed: false,
            ..bare_parse_state("plain.log", 1)
        })
        .unwrap();
        assert!(!db.find_completed_by_uncompressed_identity(0xABCD, 1024).unwrap());
    }

    #[test]
    fn find_completed_by_uncompressed_identity_false_wrong_size() {
        let db = open_test_db();
        db.set_parse_state(&ParseState {
            uncompressed_head_fingerprint: Some(0xABCD),
            uncompressed_size: 1024,
            completed: true,
            ..bare_parse_state("plain.log", 1)
        })
        .unwrap();
        assert!(!db.find_completed_by_uncompressed_identity(0xABCD, 2048).unwrap());
    }

    #[test]
    fn find_completed_by_uncompressed_identity_searches_archive() {
        let db = open_test_db();
        insert_archive(&db, &ParseState {
            uncompressed_head_fingerprint: Some(0xDEAD),
            uncompressed_size: 512,
            completed: true,
            ..bare_parse_state("old.log", 2)
        });
        assert!(db.find_completed_by_uncompressed_identity(0xDEAD, 512).unwrap());
    }

    // ── find_completed_by_compressed_identity ────────────────────────────────

    #[test]
    fn find_completed_by_compressed_identity_returns_uncompressed_size_on_match() {
        let db = open_test_db();
        db.set_parse_state(&ParseState {
            compressed_head_fingerprint: Some(0x1234),
            compressed_size: 300,
            uncompressed_size: 900,
            completed: true,
            ..bare_parse_state("file.log.gz", 3)
        })
        .unwrap();
        assert_eq!(
            db.find_completed_by_compressed_identity(0x1234, 300).unwrap(),
            Some(900)
        );
    }

    #[test]
    fn find_completed_by_compressed_identity_none_when_incomplete() {
        let db = open_test_db();
        db.set_parse_state(&ParseState {
            compressed_head_fingerprint: Some(0x1234),
            compressed_size: 300,
            uncompressed_size: 900,
            completed: false,
            ..bare_parse_state("file.log.gz", 3)
        })
        .unwrap();
        assert!(db.find_completed_by_compressed_identity(0x1234, 300).unwrap().is_none());
    }

    #[test]
    fn find_completed_by_compressed_identity_none_wrong_size() {
        let db = open_test_db();
        db.set_parse_state(&ParseState {
            compressed_head_fingerprint: Some(0x1234),
            compressed_size: 300,
            uncompressed_size: 900,
            completed: true,
            ..bare_parse_state("file.log.gz", 3)
        })
        .unwrap();
        assert!(db.find_completed_by_compressed_identity(0x1234, 999).unwrap().is_none());
    }

    #[test]
    fn find_completed_by_compressed_identity_searches_archive() {
        let db = open_test_db();
        insert_archive(&db, &ParseState {
            compressed_head_fingerprint: Some(0xBEEF),
            compressed_size: 200,
            uncompressed_size: 600,
            completed: true,
            ..bare_parse_state("old.log.gz", 4)
        });
        assert_eq!(
            db.find_completed_by_compressed_identity(0xBEEF, 200).unwrap(),
            Some(600)
        );
    }

    // ── find_parse_state_by_uncompressed_head_fingerprint ────────────────────

    #[test]
    fn find_by_uncompressed_head_prefers_completed_over_incomplete() {
        let db = open_test_db();
        db.set_parse_state(&ParseState {
            uncompressed_head_fingerprint: Some(0xCAFE),
            uncompressed_offset: 100,
            completed: false,
            ..bare_parse_state("in-progress.log", 10)
        })
        .unwrap();
        insert_archive(&db, &ParseState {
            uncompressed_head_fingerprint: Some(0xCAFE),
            uncompressed_offset: 50,
            completed: true,
            ..bare_parse_state("done.log", 11)
        });
        let s = db.find_parse_state_by_uncompressed_head_fingerprint(0xCAFE).unwrap().expect("found");
        assert_eq!(s.filepath, "done.log", "completed entry should be preferred");
    }

    #[test]
    fn find_by_uncompressed_head_prefers_higher_offset_among_incomplete() {
        let db = open_test_db();
        db.set_parse_state(&ParseState {
            uncompressed_head_fingerprint: Some(0xCAFE),
            uncompressed_offset: 200,
            completed: false,
            ..bare_parse_state("bigger.log", 12)
        })
        .unwrap();
        insert_archive(&db, &ParseState {
            uncompressed_head_fingerprint: Some(0xCAFE),
            uncompressed_offset: 50,
            completed: false,
            ..bare_parse_state("smaller.log", 13)
        });
        let s = db.find_parse_state_by_uncompressed_head_fingerprint(0xCAFE).unwrap().expect("found");
        assert_eq!(s.filepath, "bigger.log", "higher offset should win");
    }

    // ── find_parse_state_by_compressed_head_fingerprint ──────────────────────

    #[test]
    fn find_by_compressed_head_prefers_completed_over_incomplete() {
        let db = open_test_db();
        db.set_parse_state(&ParseState {
            compressed_head_fingerprint: Some(0xF00D),
            compressed_offset: 100,
            completed: false,
            ..bare_parse_state("in-progress.log.gz", 20)
        })
        .unwrap();
        insert_archive(&db, &ParseState {
            compressed_head_fingerprint: Some(0xF00D),
            compressed_offset: 50,
            completed: true,
            ..bare_parse_state("done.log.gz", 21)
        });
        let s = db.find_parse_state_by_compressed_head_fingerprint(0xF00D).unwrap().expect("found");
        assert_eq!(s.filepath, "done.log.gz", "completed entry should be preferred");
    }

    #[test]
    fn find_by_compressed_head_prefers_higher_offset_among_incomplete() {
        let db = open_test_db();
        db.set_parse_state(&ParseState {
            compressed_head_fingerprint: Some(0xF00D),
            compressed_offset: 300,
            completed: false,
            ..bare_parse_state("big.log.gz", 22)
        })
        .unwrap();
        insert_archive(&db, &ParseState {
            compressed_head_fingerprint: Some(0xF00D),
            compressed_offset: 100,
            completed: false,
            ..bare_parse_state("small.log.gz", 23)
        });
        let s = db.find_parse_state_by_compressed_head_fingerprint(0xF00D).unwrap().expect("found");
        assert_eq!(s.filepath, "big.log.gz", "higher offset should win");
    }

    #[test]
    fn meta_get_set_roundtrip() {
        let mut db = open_test_db();
        assert!(db.get_meta("current_month").expect("get").is_none());
        db.set_meta("current_month", "2026-05").expect("set");
        assert_eq!(
            db.get_meta("current_month").expect("get"),
            Some("2026-05".to_string())
        );
        db.set_meta("current_month", "2026-06").expect("update");
        assert_eq!(
            db.get_meta("current_month").expect("get"),
            Some("2026-06".to_string())
        );
    }

    // ── cull_period helpers ───────────────────────────────────────────────────

    fn insert_url(db: &mut Database, period: &str, url: &str, hits: i64, bw: i64, rt_sum: i64, rt_count: i64) {
        db.conn.execute(
            "INSERT INTO top_urls (period,url,hits,bandwidth,rt_sum,rt_count,rt_max) \
             VALUES (?1,?2,?3,?4,?5,?6,0)",
            rusqlite::params![period, url, hits, bw, rt_sum, rt_count],
        ).unwrap();
    }

    fn insert_ip(db: &mut Database, period: &str, lo: i64, hits: i64, bw: i64) {
        db.conn.execute(
            "INSERT INTO top_ips (period,host_kind,host_hi,host_lo,hits,bandwidth,country_code) \
             VALUES (?1,0,0,?2,?3,?4,'--')",
            rusqlite::params![period, lo, hits, bw],
        ).unwrap();
    }

    fn insert_ref(db: &mut Database, period: &str, referrer: &str, hits: i64) {
        db.conn.execute(
            "INSERT INTO top_referrers (period,referrer,hits) VALUES (?1,?2,?3)",
            rusqlite::params![period, referrer, hits],
        ).unwrap();
    }

    fn insert_agent(db: &mut Database, period: &str, family: &str, hits: i64, bw: i64) {
        db.conn.execute(
            "INSERT INTO top_agents (period,agent_family,hits,bandwidth) VALUES (?1,?2,?3,?4)",
            rusqlite::params![period, family, hits, bw],
        ).unwrap();
    }

    fn count_table(db: &Database, table: &str, period: &str) -> i64 {
        db.conn.query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE period=?1"),
            rusqlite::params![period],
            |r| r.get(0),
        ).unwrap()
    }

    fn url_exists(db: &Database, period: &str, url: &str) -> bool {
        let n: i64 = db.conn.query_row(
            "SELECT COUNT(*) FROM top_urls WHERE period=?1 AND url=?2",
            rusqlite::params![period, url],
            |r| r.get(0),
        ).unwrap();
        n > 0
    }

    fn ip_lo_exists(db: &Database, period: &str, lo: i64) -> bool {
        let n: i64 = db.conn.query_row(
            "SELECT COUNT(*) FROM top_ips \
             WHERE period=?1 AND host_kind=0 AND host_hi=0 AND host_lo=?2",
            rusqlite::params![period, lo],
            |r| r.get(0),
        ).unwrap();
        n > 0
    }

    // Insert n rows into top_urls: hits=1..=n, bw=hits*100, rt_sum=hits, rt_count=1.
    // All metrics are proportional so the same rows rank lowest across every metric.
    fn seed_urls(db: &mut Database, period: &str, n: i64) {
        for i in 1..=n {
            insert_url(db, period, &format!("/url-{i}"), i, i * 100, i, 1);
        }
    }

    // ── cull_period tests ─────────────────────────────────────────────────────
    //
    // Logic: delete rows where every metric is below 1/10th of the current
    // top_n-th best value. Guard: only fires when count > top_n * 50.
    //
    // Test datasets use top_n=1, so the guard threshold is 50 rows (need 51+).
    // The "top" row always has hits=1000, bw=100_000, rt_avg=10_000.
    // Thresholds: hits<100, bw<10_000, rt<1_000.
    // "Junk" rows (hits=1, bw=10, rt_avg=1) fall below all three → culled.

    #[test]
    fn cull_period_no_op_when_top_n_is_zero() {
        let mut db = open_test_db();
        seed_urls(&mut db, "2026-05", 200);
        db.cull_period("2026-05", 0).unwrap();
        assert_eq!(count_table(&db, "top_urls", "2026-05"), 200);
    }

    #[test]
    fn cull_top_urls_no_op_at_threshold() {
        // threshold = top_n*50 = 50; exactly 50 rows → count > 50 is false.
        let mut db = open_test_db();
        insert_url(&mut db, "2026-05", "/top", 1000, 100_000, 10_000, 1);
        for i in 1i64..=49 {
            insert_url(&mut db, "2026-05", &format!("/junk-{i}"), 1, 10, 1, 1);
        }
        db.cull_period("2026-05", 1).unwrap();
        assert_eq!(count_table(&db, "top_urls", "2026-05"), 50);
    }

    #[test]
    fn cull_top_urls_removes_junk_below_fraction_of_nth_best() {
        // 51 rows (1 top + 50 junk). Top-1 hits=1000 → thresh=100.
        // Junk has hits=1 < 100, bw=10 < 10_000, rt=1 < 1_000 → all culled.
        let mut db = open_test_db();
        insert_url(&mut db, "2026-05", "/top", 1000, 100_000, 10_000, 1);
        for i in 1i64..=50 {
            insert_url(&mut db, "2026-05", &format!("/junk-{i}"), 1, 10, 1, 1);
        }
        db.cull_period("2026-05", 1).unwrap();
        assert!(url_exists(&db, "2026-05", "/top"), "/top must survive");
        assert!(!url_exists(&db, "2026-05", "/junk-1"), "junk must be culled");
        assert_eq!(count_table(&db, "top_urls", "2026-05"), 1);
    }

    #[test]
    fn cull_top_urls_spares_low_hits_entry_with_high_bandwidth() {
        // /mixed has hits=1 (below thresh=100) but bw=200_000 (above thresh=10_000).
        // bw condition fails → not culled.
        let mut db = open_test_db();
        insert_url(&mut db, "2026-05", "/top", 1000, 100_000, 10_000, 1);
        insert_url(&mut db, "2026-05", "/mixed", 1, 200_000, 1, 1);
        for i in 1i64..=49 {
            insert_url(&mut db, "2026-05", &format!("/junk-{i}"), 1, 10, 1, 1);
        }
        db.cull_period("2026-05", 1).unwrap();
        assert!(url_exists(&db, "2026-05", "/mixed"), "/mixed should survive (high bw)");
    }

    #[test]
    fn cull_top_urls_spares_low_bw_entry_with_high_hits() {
        // /mixed has bw=1 (below thresh) but hits=999 (above thresh=100).
        // hits condition fails → not culled.
        let mut db = open_test_db();
        insert_url(&mut db, "2026-05", "/top", 1000, 100_000, 10_000, 1);
        insert_url(&mut db, "2026-05", "/mixed", 999, 1, 1, 1);
        for i in 1i64..=49 {
            insert_url(&mut db, "2026-05", &format!("/junk-{i}"), 1, 10, 1, 1);
        }
        db.cull_period("2026-05", 1).unwrap();
        assert!(url_exists(&db, "2026-05", "/mixed"), "/mixed should survive (high hits)");
    }

    #[test]
    fn cull_top_urls_zero_rt_treated_as_worst() {
        // /zero-rt has rt_count=0 → rt_avg=0.0, below thresh=1_000.
        // Also has low hits and bw → all conditions met → culled.
        let mut db = open_test_db();
        insert_url(&mut db, "2026-05", "/top", 1000, 100_000, 10_000, 1);
        insert_url(&mut db, "2026-05", "/zero-rt", 1, 10, 0, 0);
        for i in 1i64..=49 {
            insert_url(&mut db, "2026-05", &format!("/junk-{i}"), 1, 10, 1, 1);
        }
        db.cull_period("2026-05", 1).unwrap();
        assert!(!url_exists(&db, "2026-05", "/zero-rt"), "/zero-rt should be culled");
    }

    #[test]
    fn cull_top_urls_zero_rt_spared_by_high_hits() {
        // /zero-rt has rt_count=0 but hits=999 ≥ thresh=100 → not culled.
        let mut db = open_test_db();
        insert_url(&mut db, "2026-05", "/top", 1000, 100_000, 10_000, 1);
        insert_url(&mut db, "2026-05", "/zero-rt", 999, 100_000, 0, 0);
        for i in 1i64..=49 {
            insert_url(&mut db, "2026-05", &format!("/junk-{i}"), 1, 10, 1, 1);
        }
        db.cull_period("2026-05", 1).unwrap();
        assert!(url_exists(&db, "2026-05", "/zero-rt"), "/zero-rt should survive (high hits)");
    }

    #[test]
    fn cull_top_ips_removes_junk_below_fraction_of_nth_best() {
        let mut db = open_test_db();
        insert_ip(&mut db, "2026-05", 0, 1000, 100_000); // top
        for i in 1i64..=50 {
            insert_ip(&mut db, "2026-05", i, 1, 10); // junk
        }
        db.cull_period("2026-05", 1).unwrap();
        assert!(ip_lo_exists(&db, "2026-05", 0), "top ip must survive");
        assert!(!ip_lo_exists(&db, "2026-05", 1), "junk ip must be culled");
        assert_eq!(count_table(&db, "top_ips", "2026-05"), 1);
    }

    #[test]
    fn cull_top_referrers_removes_junk_below_fraction_of_nth_best() {
        let mut db = open_test_db();
        insert_ref(&mut db, "2026-05", "https://top.example", 1000);
        for i in 1i64..=50 {
            insert_ref(&mut db, "2026-05", &format!("https://junk-{i}.example"), 1);
        }
        db.cull_period("2026-05", 1).unwrap();
        assert_eq!(count_table(&db, "top_referrers", "2026-05"), 1);
        let n: i64 = db.conn.query_row(
            "SELECT COUNT(*) FROM top_referrers \
             WHERE period='2026-05' AND referrer='https://top.example'",
            [],
            |r| r.get(0),
        ).unwrap();
        assert_eq!(n, 1, "top referrer must survive");
    }

    #[test]
    fn cull_top_agents_removes_junk_below_fraction_of_nth_best() {
        let mut db = open_test_db();
        insert_agent(&mut db, "2026-05", "TopAgent", 1000, 100_000);
        for i in 1i64..=50 {
            insert_agent(&mut db, "2026-05", &format!("JunkAgent/{i}"), 1, 10);
        }
        db.cull_period("2026-05", 1).unwrap();
        assert_eq!(count_table(&db, "top_agents", "2026-05"), 1);
    }

    #[test]
    fn cull_period_does_not_affect_other_periods() {
        let mut db = open_test_db();
        insert_url(&mut db, "2026-05", "/top", 1000, 100_000, 10_000, 1);
        insert_url(&mut db, "2026-06", "/top", 1000, 100_000, 10_000, 1);
        for i in 1i64..=50 {
            insert_url(&mut db, "2026-05", &format!("/junk-{i}"), 1, 10, 1, 1);
            insert_url(&mut db, "2026-06", &format!("/junk-{i}"), 1, 10, 1, 1);
        }
        db.cull_period("2026-05", 1).unwrap();
        assert_eq!(count_table(&db, "top_urls", "2026-06"), 51, "2026-06 must be untouched");
        assert_eq!(count_table(&db, "top_urls", "2026-05"), 1, "2026-05 junk must be culled");
    }
}
