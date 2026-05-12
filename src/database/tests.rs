use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method_proto::{
        METHOD_COUNT, METHOD_GET, METHOD_POST, PROTO_1_1, PROTO_2_0, PROTO_COUNT,
    };

    fn open_test_db() -> Database {
        Database::open(":memory:").expect("open in-memory db")
    }

    fn empty_flush(
        db: &mut Database,
        method_counts: &MethodCountsMap,
        proto_counts: &ProtoCountsMap,
    ) {
        db.flush_all_with_parse_states_split(
            &AHashMap::new(),
            &AHashMap::new(),
            &AHashMap::new(),
            &AHashMap::new(),
            &AHashMap::new(),
            &AHashMap::new(),
            &AHashMap::new(),
            &AHashMap::new(),
            &AHashMap::new(),
            &AHashMap::new(),
            None,
            &[],
            &[],
            &[],
            None,
            method_counts,
            proto_counts,
        )
        .expect("flush");
    }

    #[test]
    fn method_counts_stored_with_correct_names_and_values() {
        let mut db = open_test_db();
        let period = Arc::<str>::from("2026-05");

        let mut counts = [0u64; METHOD_COUNT];
        counts[METHOD_GET] = 100;
        counts[METHOD_POST] = 42;
        let mut method_counts = AHashMap::new();
        method_counts.insert(Arc::clone(&period), counts);

        empty_flush(&mut db, &method_counts, &AHashMap::new());

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
        let period = Arc::<str>::from("2026-05");

        let mut counts = [0u64; METHOD_COUNT];
        counts[METHOD_GET] = 5; // only GET is non-zero
        let mut method_counts = AHashMap::new();
        method_counts.insert(Arc::clone(&period), counts);

        empty_flush(&mut db, &method_counts, &AHashMap::new());

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
        let period = Arc::<str>::from("2026-05");

        let mut c1 = [0u64; METHOD_COUNT];
        c1[METHOD_GET] = 100;
        let mut m1 = AHashMap::new();
        m1.insert(Arc::clone(&period), c1);
        empty_flush(&mut db, &m1, &AHashMap::new());

        let mut c2 = [0u64; METHOD_COUNT];
        c2[METHOD_GET] = 50;
        c2[METHOD_POST] = 10;
        let mut m2 = AHashMap::new();
        m2.insert(Arc::clone(&period), c2);
        empty_flush(&mut db, &m2, &AHashMap::new());

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
        let period = Arc::<str>::from("2026-05");

        let mut counts = [0u64; PROTO_COUNT];
        counts[PROTO_1_1] = 80;
        counts[PROTO_2_0] = 20;
        let mut proto_counts = AHashMap::new();
        proto_counts.insert(Arc::clone(&period), counts);

        empty_flush(&mut db, &AHashMap::new(), &proto_counts);

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

        // Confirm "HTTP/..." keys are never stored.
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
        let period = Arc::<str>::from("2026-05");

        let mut p1 = [0u64; PROTO_COUNT];
        p1[PROTO_1_1] = 200;
        let mut pc1 = AHashMap::new();
        pc1.insert(Arc::clone(&period), p1);
        empty_flush(&mut db, &AHashMap::new(), &pc1);

        let mut p2 = [0u64; PROTO_COUNT];
        p2[PROTO_1_1] = 100;
        p2[PROTO_2_0] = 30;
        let mut pc2 = AHashMap::new();
        pc2.insert(Arc::clone(&period), p2);
        empty_flush(&mut db, &AHashMap::new(), &pc2);

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

    fn insert_top_url(db: &Database, period: &str, url: &str, hits: i64) {
        db.conn
            .execute(
                "INSERT OR REPLACE INTO top_urls_hits (period, url, hits, bandwidth)
                     VALUES (?1, ?2, ?3, 100)",
                params![period, url, hits],
            )
            .expect("insert top url");
    }

    #[test]
    fn trim_top_tables_keeps_latest_month_period_in_db_untrimmed() {
        let mut db = open_test_db();

        for i in 0..30 {
            insert_top_url(&db, "2001-01", &format!("/old-{:02}.html", i), 100 - i);
            insert_top_url(&db, "2001-02", &format!("/new-{:02}.html", i), 100 - i);
        }

        db.trim_top_tables(20, 200, true, false)
            .expect("trim top urls");

        let old_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM top_urls_hits WHERE period = '2001-01'",
                [],
                |row| row.get(0),
            )
            .expect("count old month rows");
        let latest_count: i64 = db
            .conn
            .query_row(
                "SELECT COUNT(*) FROM top_urls_hits WHERE period = '2001-02'",
                [],
                |row| row.get(0),
            )
            .expect("count latest month rows");

        assert_eq!(old_count, 20);
        assert_eq!(latest_count, 30);
    }

    #[test]
    fn flush_all_populates_all_time_hosts_uniquely() {
        let mut db = open_test_db();

        let hourly: HourlyMap = AHashMap::new();
        let top_urls: TopUrlsByHits = AHashMap::new();
        let top_refs: PeriodCountMap = AHashMap::new();
        let top_agents: PeriodCountMap = AHashMap::new();
        let top_countries: CountryHitsMap = AHashMap::new();
        let status_codes: StatusHitsMap = AHashMap::new();

        let mut first_hosts: TopHostsByHits = AHashMap::new();
        let us = Arc::<str>::from("US");
        let us_name = Arc::<str>::from("United States");
        let mut month_hosts = TopNHosts::new(200);
        month_hosts.add("site-a", 100, &us, &us_name);
        month_hosts.add("site-b", 100, &us, &us_name);
        first_hosts.insert(Arc::<str>::from("2026-05"), month_hosts);

        let mut year_hosts = TopNHosts::new(200);
        year_hosts.add("site-a", 100, &us, &us_name);
        year_hosts.add("site-a", 100, &us, &us_name);
        first_hosts.insert(Arc::<str>::from("2026"), year_hosts);

        db.flush_all(
            &hourly,
            &top_urls,
            &first_hosts,
            &top_refs,
            &top_agents,
            &top_countries,
            &status_codes,
        )
        .expect("first flush");

        let first_count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM all_time_hosts", [], |row| row.get(0))
            .expect("count all_time_hosts after first flush");
        assert_eq!(first_count, 2);

        let mut second_hosts: TopHostsByHits = AHashMap::new();
        let mut next_month_hosts = TopNHosts::new(200);
        next_month_hosts.add("site-b", 100, &us, &us_name);
        next_month_hosts.add("site-c", 100, &us, &us_name);
        second_hosts.insert(Arc::<str>::from("2026-06"), next_month_hosts);

        db.flush_all(
            &hourly,
            &top_urls,
            &second_hosts,
            &top_refs,
            &top_agents,
            &top_countries,
            &status_codes,
        )
        .expect("second flush");

        let second_count: i64 = db
            .conn
            .query_row("SELECT COUNT(*) FROM all_time_hosts", [], |row| row.get(0))
            .expect("count all_time_hosts after second flush");
        assert_eq!(second_count, 3);
    }

    #[test]
    fn flush_all_with_parse_states_merges_hll_site_counts() {
        let mut db = open_test_db();

        let hourly: HourlyMap = AHashMap::new();
        let top_urls: TopUrlsByHits = AHashMap::new();
        let top_hosts: TopHostsByHits = AHashMap::new();
        let top_refs: PeriodCountMap = AHashMap::new();
        let top_agents: PeriodCountMap = AHashMap::new();
        let top_countries: CountryHitsMap = AHashMap::new();
        let status_codes: StatusHitsMap = AHashMap::new();

        let mut first = AHashMap::new();
        let mut first_hll = HyperLogLog::new(10);
        first_hll.add_str("site-a");
        first_hll.add_str("site-b");
        first.insert(Arc::<str>::from("2026-05"), first_hll);
        let mut first_all = HyperLogLog::new(10);
        first_all.add_str("site-a");
        first_all.add_str("site-b");

        db.flush_all_with_parse_states(
            &hourly,
            &top_urls,
            &top_hosts,
            &top_refs,
            &top_agents,
            &top_countries,
            &status_codes,
            &first,
            Some(&first_all),
            &[],
        )
        .expect("first hll flush");

        let mut second = AHashMap::new();
        let mut second_hll = HyperLogLog::new(10);
        second_hll.add_str("site-b");
        second_hll.add_str("site-c");
        second.insert(Arc::<str>::from("2026-05"), second_hll);
        let mut second_all = HyperLogLog::new(10);
        second_all.add_str("site-b");
        second_all.add_str("site-c");

        db.flush_all_with_parse_states(
            &hourly,
            &top_urls,
            &top_hosts,
            &top_refs,
            &top_agents,
            &top_countries,
            &status_codes,
            &second,
            Some(&second_all),
            &[],
        )
        .expect("second hll flush");

        let period_estimate: i64 = db
            .conn
            .query_row(
                "SELECT estimate FROM site_counts_hll WHERE scope = '2026-05'",
                [],
                |row| row.get(0),
            )
            .expect("period estimate");
        let all_time_estimate: i64 = db
            .conn
            .query_row(
                "SELECT estimate FROM site_counts_hll WHERE scope = '__all__'",
                [],
                |row| row.get(0),
            )
            .expect("all time estimate");

        assert!(period_estimate >= 2);
        assert!(period_estimate <= 5);
        assert!(all_time_estimate >= 2);
        assert!(all_time_estimate <= 5);
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
}
