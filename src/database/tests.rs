use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method_proto::{
        METHOD_COUNT, METHOD_GET, METHOD_POST, PROTO_1_1, PROTO_2_0, PROTO_COUNT,
    };
    use ahash::AHashSet;

    fn open_test_db() -> Database {
        Database::open(":memory:").expect("open in-memory db")
    }

    fn empty_flush(db: &mut Database, period: &str, method_counts: &[u64], proto_counts: &[u64]) {
        let empty_hourly = ahash::AHashMap::new();
        let empty_urls = ahash::AHashMap::new();
        let empty_hosts = ahash::AHashMap::new();
        let empty_host_geo = ahash::AHashMap::new();
        let empty_refs = ahash::AHashMap::new();
        let empty_agents = ahash::AHashMap::new();
        let empty_ips = ahash::AHashMap::new();
        let empty_countries = ahash::AHashMap::new();
        let empty_status = ahash::AHashMap::new();
        db.flush(crate::database::writer::FlushData {
            period,
            hourly: &empty_hourly,
            urls: &empty_urls,
            hosts: &empty_hosts,
            host_geo: &empty_host_geo,
            refs: &empty_refs,
            agents: &empty_agents,
            daily_ips: &empty_ips,
            countries: &empty_countries,
            status_codes: &empty_status,
            method_counts,
            proto_counts,
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
    fn proto_counts_stored_with_version_strings_not_http_prefix() {
        let mut db = open_test_db();

        let mut counts = [0u64; PROTO_COUNT];
        counts[PROTO_1_1] = 80;
        counts[PROTO_2_0] = 20;
        empty_flush(&mut db, "2026-05", &[0u64; METHOD_COUNT], &counts);

        let h11: i64 = db
            .conn
            .query_row(
                "SELECT hits FROM proto_counts WHERE period='2026-05' AND proto='1.1'",
                [],
                |r| r.get(0),
            )
            .expect("1.1 row");
        assert_eq!(h11, 80);

        let h2: i64 = db
            .conn
            .query_row(
                "SELECT hits FROM proto_counts WHERE period='2026-05' AND proto='2.0'",
                [],
                |r| r.get(0),
            )
            .expect("2.0 row");
        assert_eq!(h2, 20);

        let http_rows: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM proto_counts WHERE proto LIKE 'HTTP/%'",
                [],
                |r| r.get(0),
            )
            .expect("http prefix check");
        assert_eq!(http_rows, 0);
    }

    #[test]
    fn proto_counts_accumulate_across_flushes() {
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
                "SELECT hits FROM proto_counts WHERE period='2026-05' AND proto='1.1'",
                [],
                |r| r.get(0),
            )
            .expect("1.1 after second flush");
        assert_eq!(h11, 300);

        let h2: i64 = db
            .conn
            .query_row(
                "SELECT hits FROM proto_counts WHERE period='2026-05' AND proto='2.0'",
                [],
                |r| r.get(0),
            )
            .expect("2.0 after second flush");
        assert_eq!(h2, 30);
    }

    #[test]
    fn daily_ip_log_deduplicates_across_flushes() {
        let mut db = open_test_db();

        let ip1 = crate::ip::Ip::V4(0x01020304);
        let ip2 = crate::ip::Ip::V4(0x05060708);

        let mut ips1: AHashSet<crate::ip::Ip> = AHashSet::new();
        ips1.insert(ip1);
        ips1.insert(ip2);
        let mut daily1 = ahash::AHashMap::new();
        daily1.insert("2026-05-01".to_string(), ips1);

        let mut ips2: AHashSet<crate::ip::Ip> = AHashSet::new();
        ips2.insert(ip1); // duplicate
        let mut daily2 = ahash::AHashMap::new();
        daily2.insert("2026-05-01".to_string(), ips2);

        let empty_urls: ahash::AHashMap<String, (u64, u64)> = ahash::AHashMap::new();
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
                urls: &empty_urls,
                hosts: &empty_hosts,
                host_geo: &empty_geo,
                refs: &empty_refs,
                agents: &empty_agents,
                daily_ips: daily,
                countries: &empty_countries,
                status_codes: &empty_status,
                method_counts: &[0u64; METHOD_COUNT],
                proto_counts: &[0u64; PROTO_COUNT],
                parse_states: &[],
                retired_parse_states: &[],
                visit_states: &[],
                visit_state_prune_before_ts: None,
            })
            .expect("flush");
        }

        let count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM daily_ip_log WHERE date='2026-05-01'",
                [],
                |r| r.get(0),
            )
            .expect("count");
        assert_eq!(count, 2, "duplicate IP must not be double-inserted");
    }

    fn flush_ips(db: &mut Database, period: &str, date: &str, ips: Vec<crate::ip::Ip>) {
        let mut ip_set: AHashSet<crate::ip::Ip> = AHashSet::new();
        for ip in ips {
            ip_set.insert(ip);
        }
        let mut daily = ahash::AHashMap::new();
        daily.insert(date.to_string(), ip_set);
        db.flush(crate::database::writer::FlushData {
            period,
            hourly: &ahash::AHashMap::new(),
            urls: &ahash::AHashMap::new(),
            hosts: &ahash::AHashMap::new(),
            host_geo: &ahash::AHashMap::new(),
            refs: &ahash::AHashMap::new(),
            agents: &ahash::AHashMap::new(),
            daily_ips: &daily,
            countries: &ahash::AHashMap::new(),
            status_codes: &ahash::AHashMap::new(),
            method_counts: &[0u64; METHOD_COUNT],
            proto_counts: &[0u64; PROTO_COUNT],
            parse_states: &[],
            retired_parse_states: &[],
            visit_states: &[],
            visit_state_prune_before_ts: None,
        })
        .expect("flush");
    }

    #[test]
    fn finalize_month_populates_all_time_hosts_and_yearly_ip_log() {
        let mut db = open_test_db();

        let ip1 = crate::ip::Ip::V4(0x01020304);
        let ip2 = crate::ip::Ip::V4(0x05060708);

        let mut ips: AHashSet<crate::ip::Ip> = AHashSet::new();
        ips.insert(ip1);
        ips.insert(ip2);
        let mut daily = ahash::AHashMap::new();
        daily.insert("2026-05-01".to_string(), ips);

        let empty_hosts: ahash::AHashMap<String, (u64, u64)> = ahash::AHashMap::new();
        let empty_geo: ahash::AHashMap<String, (std::sync::Arc<str>, std::sync::Arc<str>)> =
            ahash::AHashMap::new();

        // Flush with some URLs too so pruning runs
        let mut urls = ahash::AHashMap::new();
        for i in 0..30u64 {
            urls.insert(format!("/page-{}.html", i), (100 - i, (100 - i) * 1024));
        }

        db.flush(crate::database::writer::FlushData {
            period: "2026-05",
            hourly: &ahash::AHashMap::new(),
            urls: &urls,
            hosts: &empty_hosts,
            host_geo: &empty_geo,
            refs: &ahash::AHashMap::new(),
            agents: &ahash::AHashMap::new(),
            daily_ips: &daily,
            countries: &ahash::AHashMap::new(),
            status_codes: &ahash::AHashMap::new(),
            method_counts: &[0u64; METHOD_COUNT],
            proto_counts: &[0u64; PROTO_COUNT],
            parse_states: &[],
            retired_parse_states: &[],
            visit_states: &[],
            visit_state_prune_before_ts: None,
        })
        .expect("flush");

        db.finalize_month("2026-05", 20).expect("finalize");

        let host_count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM all_time_hosts", [], |r| r.get(0))
            .expect("all_time_hosts count");
        assert_eq!(host_count, 2);

        let yearly_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM yearly_ip_log WHERE year='2026'",
                [],
                |r| r.get(0),
            )
            .expect("yearly_ip_log count");
        assert_eq!(yearly_count, 2);

        let url_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM monthly_urls_hits WHERE period='2026-05'",
                [],
                |r| r.get(0),
            )
            .expect("url count after prune");
        assert_eq!(url_count, 20, "should be pruned to top_n=20");
    }

    #[test]
    fn finalize_year_counts_distinct_across_months_and_cleans_up() {
        let mut db = open_test_db();

        let ip1 = crate::ip::Ip::V4(0x01020304);
        let ip2 = crate::ip::Ip::V4(0x05060708);
        let ip3 = crate::ip::Ip::V4(0x09101112);

        // Jan: ip1 + ip2; Feb: ip2 + ip3 (ip2 shared across months)
        flush_ips(&mut db, "2026-01", "2026-01-15", vec![ip1, ip2]);
        db.finalize_month("2026-01", 20).expect("finalize jan");

        flush_ips(&mut db, "2026-02", "2026-02-10", vec![ip2, ip3]);
        db.finalize_month("2026-02", 20).expect("finalize feb");

        // yearly cache after Feb should reflect 3 distinct IPs, not 2
        let cached: i64 = db
            .conn
            .query_row(
                "SELECT COALESCE((SELECT count FROM site_count_cache WHERE period='2026'), 0)",
                [],
                |r| r.get(0),
            )
            .expect("yearly cache");
        assert_eq!(
            cached, 3,
            "yearly cache should deduplicate ip2 across months"
        );

        db.finalize_year("2026").expect("finalize year");

        // yearly_ip_log for 2026 should be cleared
        let remaining: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM yearly_ip_log WHERE year='2026'",
                [],
                |r| r.get(0),
            )
            .expect("yearly_ip_log after finalize_year");
        assert_eq!(remaining, 0);

        // site_count_cache should still have the final count
        let final_count: i64 = db
            .conn
            .query_row(
                "SELECT COALESCE((SELECT count FROM site_count_cache WHERE period='2026'), 0)",
                [],
                |r| r.get(0),
            )
            .expect("yearly cache after finalize_year");
        assert_eq!(final_count, 3);
    }

    #[test]
    fn set_parse_state_roundtrips_fields() {
        let db = open_test_db();

        db.set_parse_state(
            "access.log",
            42,
            789,
            456,
            Some(11),
            Some(22),
            123,
            456,
            1_700_000_000,
            true,
        )
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
