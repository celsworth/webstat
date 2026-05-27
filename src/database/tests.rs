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
        let empty_agents: ahash::AHashMap<String, u64> = ahash::AHashMap::new();
        let empty_countries: ahash::AHashMap<String, u64> = ahash::AHashMap::new();
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
                "SELECT COUNT(*) FROM monthly_top_urls WHERE period='2026-05'",
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
}
