// Tests for report aggregator SQL queries and summary structures.

use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE hourly_stats (
                 date       TEXT NOT NULL,
                 hour       INTEGER NOT NULL,
                 hits       INTEGER DEFAULT 0,
                 visits     INTEGER DEFAULT 0,
                 bandwidth  INTEGER DEFAULT 0,
                 status_2xx INTEGER DEFAULT 0,
                 status_3xx INTEGER DEFAULT 0,
                 status_4xx INTEGER DEFAULT 0,
                 status_5xx INTEGER DEFAULT 0,
                 PRIMARY KEY (date, hour)
             );
             CREATE TABLE daily_unique_ips (
                 date    TEXT    NOT NULL,
                 ip_kind INTEGER NOT NULL,
                 ip_hi   INTEGER NOT NULL,
                 count   INTEGER NOT NULL DEFAULT 0,
                 bitmap  BLOB    NOT NULL,
                 PRIMARY KEY (date, ip_kind, ip_hi)
             );
             CREATE TABLE monthly_unique_ips (
                 period  TEXT    NOT NULL,
                 ip_kind INTEGER NOT NULL,
                 ip_hi   INTEGER NOT NULL DEFAULT 0,
                 bitmap  BLOB    NOT NULL,
                 PRIMARY KEY (period, ip_kind, ip_hi)
             );
             CREATE TABLE countries (
                 country_code TEXT PRIMARY KEY,
                 country_name TEXT NOT NULL DEFAULT 'Unknown'
             );
             CREATE TABLE unique_visitor_counts (
                 period TEXT PRIMARY KEY,
                 count  INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE daily_visitor_counts (
                 date  TEXT PRIMARY KEY,
                 count INTEGER NOT NULL DEFAULT 0
             );
             ",
        )
        .expect("create test schema");
        conn
    }

    fn insert_hourly(conn: &Connection, date: &str, hour: i64, hits: i64, visits: i64) {
        conn.execute(
            "INSERT INTO hourly_stats
             (date, hour, hits, visits, bandwidth, status_2xx, status_3xx, status_4xx, status_5xx)
             VALUES (?1, ?2, ?3, ?4, 100, 1, 0, 0, 0)",
            params![date, hour, hits, visits],
        )
        .expect("insert hourly row");
    }

    /// Insert a single IPv4 address into daily_unique_ips, merging with any existing bitmap.
    fn insert_daily_ip(conn: &Connection, date: &str, ip_lo: u32) {
        use roaring::RoaringBitmap;
        use rusqlite::OptionalExtension;
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT bitmap FROM daily_unique_ips WHERE date=?1 AND ip_kind=1 AND ip_hi=0",
                params![date],
                |r| r.get(0),
            )
            .optional()
            .expect("query existing");
        let mut bm = match existing {
            Some(blob) => RoaringBitmap::deserialize_from(&blob[..]).expect("deserialize"),
            None => RoaringBitmap::new(),
        };
        bm.insert(ip_lo);
        let count = bm.len() as i64;
        let mut buf = Vec::new();
        bm.serialize_into(&mut buf).expect("serialize");
        conn.execute(
            "INSERT OR REPLACE INTO daily_unique_ips (date, ip_kind, ip_hi, count, bitmap) \
             VALUES (?1, 1, 0, ?2, ?3)",
            params![date, count, buf],
        )
        .expect("insert daily ip");
    }

    /// Insert a single IPv4 address into monthly_unique_ips, merging with any existing bitmap.
    fn insert_monthly_ip(conn: &Connection, period: &str, ip_lo: u32) {
        use roaring::RoaringBitmap;
        use rusqlite::OptionalExtension;
        let existing: Option<Vec<u8>> = conn
            .query_row(
                "SELECT bitmap FROM monthly_unique_ips WHERE period=?1 AND ip_kind=1 AND ip_hi=0",
                params![period],
                |r| r.get(0),
            )
            .optional()
            .expect("query existing");
        let mut bm = match existing {
            Some(blob) => RoaringBitmap::deserialize_from(&blob[..]).expect("deserialize"),
            None => RoaringBitmap::new(),
        };
        bm.insert(ip_lo);
        let mut buf = Vec::new();
        bm.serialize_into(&mut buf).expect("serialize");
        conn.execute(
            "INSERT OR REPLACE INTO monthly_unique_ips (period, ip_kind, ip_hi, bitmap) \
             VALUES (?1, 1, 0, ?2)",
            params![period, buf],
        )
        .expect("insert monthly ip");
    }

    fn finalize_unique_visitor_counts(conn: &Connection, period: &str) {
        // OR daily bitmaps for the period and store the cardinality.
        let like = format!("{}-%", period);
        let count = or_count_daily_bitmaps(conn, &like).expect("or_count_daily_bitmaps");
        conn.execute(
            "INSERT OR REPLACE INTO unique_visitor_counts (period, count) VALUES (?1, ?2)",
            params![period, count as i64],
        )
        .expect("finalize site count cache");
    }

    #[test]
    fn visitor_count_for_scope_daily() {
        let conn = setup_conn();
        insert_daily_ip(&conn, "2026-05-01", 1);
        insert_daily_ip(&conn, "2026-05-01", 2);
        insert_daily_ip(&conn, "2026-05-02", 3);

        let visitors = or_count_daily_bitmaps(&conn, "2026-05-01").expect("daily site count");
        assert_eq!(visitors, 2);
    }

    #[test]
    fn visitor_count_for_scope_monthly_deduplicates() {
        let conn = setup_conn();
        insert_daily_ip(&conn, "2026-05-01", 1);
        insert_daily_ip(&conn, "2026-05-01", 2);
        insert_daily_ip(&conn, "2026-05-02", 1); // duplicate IP across days
        insert_daily_ip(&conn, "2026-05-02", 3);
        finalize_unique_visitor_counts(&conn, "2026-05");

        let visitors = monthly_visitor_count(&conn, "2026-05").expect("monthly site count");
        assert_eq!(visitors, 3, "should deduplicate across days");
    }

    #[test]
    fn visitor_count_for_scope_yearly() {
        let conn = setup_conn();
        insert_daily_ip(&conn, "2026-01-15", 10);
        insert_daily_ip(&conn, "2026-06-01", 10); // same IP different month
        insert_daily_ip(&conn, "2026-06-01", 20);
        finalize_unique_visitor_counts(&conn, "2026");

        let visitors = yearly_visitor_count(&conn, "2026").expect("yearly site count");
        assert_eq!(visitors, 2, "should deduplicate across months");
    }

    #[test]
    fn visitor_count_for_scope_monthly_fallback_to_daily_unique_ips() {
        let conn = setup_conn();
        insert_daily_ip(&conn, "2026-05-01", 1);
        insert_daily_ip(&conn, "2026-05-01", 2);
        insert_daily_ip(&conn, "2026-05-02", 1); // duplicate across days
        insert_daily_ip(&conn, "2026-05-02", 3);
        // no cache entry — simulates in-progress month

        let visitors = monthly_visitor_count(&conn, "2026-05").expect("monthly fallback");
        assert_eq!(visitors, 3, "should fall back to daily_unique_ips and deduplicate");
    }

    #[test]
    fn visitor_count_for_scope_yearly_fallback_to_yearly_unique_ips_and_daily_unique_ips() {
        let conn = setup_conn();
        // Finalized months in monthly_unique_ips
        insert_monthly_ip(&conn, "2026-03", 10);
        insert_monthly_ip(&conn, "2026-04", 20);
        // In-progress month still in daily_unique_ips
        insert_daily_ip(&conn, "2026-05-01", 30);
        // no cache entry — simulates in-progress year

        let visitors = yearly_visitor_count(&conn, "2026").expect("yearly fallback");
        assert_eq!(visitors, 3, "should union monthly_unique_ips and daily_unique_ips");
    }

    #[test]
    fn visitor_count_for_scope_yearly_fallback_deduplicates_across_sources() {
        let conn = setup_conn();
        // IP 10 appears in both monthly_unique_ips (prior months) and daily_unique_ips (current month)
        insert_monthly_ip(&conn, "2026-03", 10);
        insert_monthly_ip(&conn, "2026-04", 20);
        insert_daily_ip(&conn, "2026-05-01", 10); // duplicate of monthly ip 10
        insert_daily_ip(&conn, "2026-05-01", 30);

        let visitors = yearly_visitor_count(&conn, "2026").expect("yearly dedup");
        assert_eq!(
            visitors, 3,
            "should deduplicate ip 10 across monthly_unique_ips and daily_unique_ips"
        );
    }

    #[test]
    fn overall_totals_uses_monthly_unique_ips() {
        let conn = setup_conn();
        insert_hourly(&conn, "2026-05-01", 0, 100, 10);

        // Insert bitmaps with IPv4 addresses into monthly_unique_ips across two months.
        insert_monthly_ip(&conn, "2026-04", 1);
        insert_monthly_ip(&conn, "2026-05", 2);
        // Also insert ip 1 in the current month — should be deduplicated.
        insert_monthly_ip(&conn, "2026-05", 1);

        let totals = overall_totals(&conn, false).expect("overall totals");
        assert_eq!(totals.visitors, 2);
    }
}

/// Percentage regression tests.
///
/// Every table with a `pct_fmt` field must express each row as a fraction of the
/// **total hits/bandwidth for the period** (from `hourly_stats`), not as a fraction
/// of the rows that happen to be in the top-N table.  These tests enforce that
/// invariant by inserting 1 000 total hits into `hourly_stats` but only 500 hits
/// worth of rows into the top-N table, so any function that divides by the in-table
/// sum would produce 60 % / 40 % instead of the correct 30 % / 20 %.
#[cfg(test)]
mod pct_tests {
    use super::*;

    // ── schema ────────────────────────────────────────────────────────────────

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().expect("open in-memory sqlite");
        conn.execute_batch(
            "CREATE TABLE hourly_stats (
                 date TEXT NOT NULL, hour INTEGER NOT NULL,
                 hits INTEGER DEFAULT 0, visits INTEGER DEFAULT 0,
                 bandwidth INTEGER DEFAULT 0,
                 status_2xx INTEGER DEFAULT 0, status_3xx INTEGER DEFAULT 0,
                 status_4xx INTEGER DEFAULT 0, status_5xx INTEGER DEFAULT 0,
                 PRIMARY KEY (date, hour));
             CREATE TABLE top_urls (
                 period TEXT NOT NULL, url TEXT NOT NULL,
                 hits INTEGER DEFAULT 0, bandwidth INTEGER DEFAULT 0,
                 rt_sum INTEGER DEFAULT 0, rt_count INTEGER DEFAULT 0,
                 rt_max INTEGER DEFAULT 0,
                 PRIMARY KEY (period, url));
             CREATE TABLE top_agents (
                 period TEXT NOT NULL, agent_family TEXT NOT NULL,
                 hits INTEGER DEFAULT 0, bandwidth INTEGER DEFAULT 0,
                 PRIMARY KEY (period, agent_family));
             CREATE TABLE top_countries (
                 period TEXT NOT NULL, country_code TEXT NOT NULL,
                 hits INTEGER DEFAULT 0, bandwidth INTEGER DEFAULT 0,
                 PRIMARY KEY (period, country_code));
             CREATE TABLE countries (
                 country_code TEXT PRIMARY KEY,
                 country_name TEXT NOT NULL DEFAULT 'Unknown');
             CREATE TABLE status_codes (
                 period TEXT NOT NULL, status INTEGER NOT NULL,
                 hits INTEGER DEFAULT 0,
                 PRIMARY KEY (period, status));
             CREATE TABLE protocol_counts (
                 period TEXT NOT NULL, proto TEXT NOT NULL,
                 hits INTEGER DEFAULT 0,
                 PRIMARY KEY (period, proto));
             CREATE TABLE method_counts (
                 period TEXT NOT NULL, method TEXT NOT NULL,
                 hits INTEGER DEFAULT 0,
                 PRIMARY KEY (period, method));",
        )
        .expect("create pct test schema");
        conn
    }

    /// Insert one hourly_stats row contributing `hits` and `bandwidth` to a date.
    fn add_hourly(conn: &Connection, date: &str, hits: i64, bandwidth: i64) {
        conn.execute(
            "INSERT OR REPLACE INTO hourly_stats
             (date, hour, hits, visits, bandwidth,
              status_2xx, status_3xx, status_4xx, status_5xx)
             VALUES (?1, 0, ?2, 0, ?3, 0, 0, 0, 0)",
            params![date, hits, bandwidth],
        )
        .unwrap();
    }

    // ── top_urls ──────────────────────────────────────────────────────────────

    #[test]
    fn top_urls_pct_is_of_period_total_not_table_sum() {
        let conn = setup();
        // 1 000 total hits, 10 000 total bandwidth for the period.
        add_hourly(&conn, "2026-05-01", 1000, 10000);
        // Only 500 hits / 5 000 bw represented in top_urls (simulates pruning).
        conn.execute_batch(
            "INSERT INTO top_urls VALUES ('2026-05', '/a', 300, 3000, 0, 0, 0);
             INSERT INTO top_urls VALUES ('2026-05', '/b', 200, 2000, 0, 0, 0);",
        )
        .unwrap();

        let rows = top_urls_hits(&conn, "2026-05", 10, false).unwrap();
        assert_eq!(rows.len(), 2);
        // /a: 300/1000 = 30 %, /b: 200/1000 = 20 %
        assert_eq!(rows[0].pct_fmt, "30.0%", "/a hits pct");
        assert_eq!(rows[0].bandwidth_pct_fmt, "30.0%", "/a bw pct");
        assert_eq!(rows[1].pct_fmt, "20.0%", "/b hits pct");
        assert_eq!(rows[1].bandwidth_pct_fmt, "20.0%", "/b bw pct");
    }

    // ── top_agents ────────────────────────────────────────────────────────────

    #[test]
    fn top_agents_pct_is_of_period_total_not_table_sum() {
        let conn = setup();
        add_hourly(&conn, "2026-05-01", 1000, 10000);
        // Only 500 hits / 5 000 bw in top_agents (simulates pruning of tail agents).
        conn.execute_batch(
            "INSERT INTO top_agents VALUES ('2026-05', 'Chrome', 300, 3000);
             INSERT INTO top_agents VALUES ('2026-05', 'Firefox', 200, 2000);",
        )
        .unwrap();

        let rows = top_agents_sorted(&conn, "2026-05", 10, false, "hits").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pct_fmt, "30.0%", "Chrome hits pct");
        assert_eq!(rows[0].bandwidth_pct_fmt, "30.0%", "Chrome bw pct");
        assert_eq!(rows[1].pct_fmt, "20.0%", "Firefox hits pct");
        assert_eq!(rows[1].bandwidth_pct_fmt, "20.0%", "Firefox bw pct");
    }

    #[test]
    fn top_agents_all_pct_is_of_all_time_total_not_table_sum() {
        let conn = setup();
        // Two months of data, 500 hits each = 1 000 total.
        add_hourly(&conn, "2026-04-01", 500, 5000);
        add_hourly(&conn, "2026-05-01", 500, 5000);
        // top_agents contains only 600 hits / 6 000 bw (simulates pruning).
        conn.execute_batch(
            "INSERT INTO top_agents VALUES ('2026-05', 'Chrome', 300, 3000);
             INSERT INTO top_agents VALUES ('2026-05', 'Firefox', 300, 3000);",
        )
        .unwrap();

        let rows = top_agents_sorted_all(&conn, 10, false, "hits").unwrap();
        assert_eq!(rows.len(), 2);
        // 300/1000 = 30 % each
        assert_eq!(rows[0].pct_fmt, "30.0%");
        assert_eq!(rows[1].pct_fmt, "30.0%");
    }

    // ── top_countries ─────────────────────────────────────────────────────────

    #[test]
    fn top_countries_pct_is_of_period_total_not_table_sum() {
        let conn = setup();
        add_hourly(&conn, "2026-05-01", 1000, 10000);
        // Only 500 hits / 5 000 bw present (e.g. ungeolocated hits not in table).
        conn.execute_batch(
            "INSERT INTO countries VALUES ('GB', 'United Kingdom');
             INSERT INTO countries VALUES ('DE', 'Germany');
             INSERT INTO top_countries VALUES ('2026-05', 'GB', 300, 3000);
             INSERT INTO top_countries VALUES ('2026-05', 'DE', 200, 2000);",
        )
        .unwrap();

        let rows = top_countries_sorted(&conn, "2026-05", 10, false, "hits").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pct_fmt, "30.0%", "GB hits pct");
        assert_eq!(rows[0].bandwidth_pct_fmt, "30.0%", "GB bw pct");
        assert_eq!(rows[1].pct_fmt, "20.0%", "DE hits pct");
        assert_eq!(rows[1].bandwidth_pct_fmt, "20.0%", "DE bw pct");
    }

    #[test]
    fn top_countries_all_pct_is_of_all_time_total_not_table_sum() {
        let conn = setup();
        add_hourly(&conn, "2026-04-01", 500, 5000);
        add_hourly(&conn, "2026-05-01", 500, 5000);
        conn.execute_batch(
            "INSERT INTO countries VALUES ('GB', 'United Kingdom');
             INSERT INTO countries VALUES ('DE', 'Germany');
             INSERT INTO top_countries VALUES ('2026-05', 'GB', 300, 3000);
             INSERT INTO top_countries VALUES ('2026-05', 'DE', 300, 3000);",
        )
        .unwrap();

        let rows = top_countries_sorted_all(&conn, 10, false, "hits").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pct_fmt, "30.0%");
        assert_eq!(rows[1].pct_fmt, "30.0%");
    }

    // ── status_codes ──────────────────────────────────────────────────────────

    #[test]
    fn status_codes_pct_is_of_period_total_not_table_sum() {
        let conn = setup();
        // 1 000 total hits; status table accounts for all of them.
        add_hourly(&conn, "2026-05-01", 1000, 0);
        conn.execute_batch(
            "INSERT INTO status_codes VALUES ('2026-05', 200, 600);
             INSERT INTO status_codes VALUES ('2026-05', 404, 400);",
        )
        .unwrap();

        let rows = status_codes(&conn, "2026-05", false).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pct_fmt, "60.0%", "200 pct");
        assert_eq!(rows[1].pct_fmt, "40.0%", "404 pct");
    }

    // ── proto_codes ───────────────────────────────────────────────────────────

    #[test]
    fn proto_codes_pct_is_of_period_total_not_table_sum() {
        let conn = setup();
        add_hourly(&conn, "2026-05-01", 1000, 0);
        conn.execute_batch(
            "INSERT INTO protocol_counts VALUES ('2026-05', 'HTTP/2.0', 700);
             INSERT INTO protocol_counts VALUES ('2026-05', 'HTTP/1.1', 300);",
        )
        .unwrap();

        let rows = proto_codes(&conn, "2026-05", false).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pct_fmt, "70.0%", "HTTP/2.0 pct");
        assert_eq!(rows[1].pct_fmt, "30.0%", "HTTP/1.1 pct");
    }

    // ── method_codes ──────────────────────────────────────────────────────────

    #[test]
    fn method_codes_pct_is_of_period_total_not_table_sum() {
        let conn = setup();
        add_hourly(&conn, "2026-05-01", 1000, 0);
        conn.execute_batch(
            "INSERT INTO method_counts VALUES ('2026-05', 'GET', 800);
             INSERT INTO method_counts VALUES ('2026-05', 'POST', 200);",
        )
        .unwrap();

        let rows = method_codes(&conn, "2026-05", false).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pct_fmt, "80.0%", "GET pct");
        assert_eq!(rows[1].pct_fmt, "20.0%", "POST pct");
    }

    // ── yearly sort order ─────────────────────────────────────────────────────

    /// Regression: yearly top_urls was sorting by per-period `hits` instead of
    /// `SUM(hits)`, so a URL whose hits were spread across two months could rank
    /// below a URL with fewer total hits concentrated in a single month.
    #[test]
    fn top_urls_yearly_sorted_by_summed_hits_not_per_period_hits() {
        let conn = setup();
        // /a: 400 hits in Jan + 700 hits in Feb = 1100 total — should be #1.
        // /b: 900 hits in Jan only = 900 total — should be #2.
        // /c: 50 hits in Jan only = 50 total — should be #3.
        // Total hourly hits needed so pct math doesn't divide by zero.
        add_hourly(&conn, "2026-01-01", 950, 0);
        add_hourly(&conn, "2026-02-01", 700, 0);
        conn.execute_batch(
            "INSERT INTO top_urls VALUES ('2026-01', '/a', 400, 0, 0, 0, 0);
             INSERT INTO top_urls VALUES ('2026-02', '/a', 700, 0, 0, 0, 0);
             INSERT INTO top_urls VALUES ('2026-01', '/b', 900, 0, 0, 0, 0);
             INSERT INTO top_urls VALUES ('2026-01', '/c',  50, 0, 0, 0, 0);",
        )
        .unwrap();

        let rows = top_urls_hits(&conn, "2026", 10, false).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].url, "/a", "/a (1100 total) should be #1");
        assert_eq!(rows[1].url, "/b", "/b (900 total) should be #2");
        assert_eq!(rows[2].url, "/c", "/c (50 total) should be #3");
        assert_eq!(rows[0].hits, 1100);
        assert_eq!(rows[1].hits, 900);
        assert_eq!(rows[2].hits, 50);
    }

    #[test]
    fn top_urls_yearly_sorted_by_summed_bandwidth_not_per_period_bandwidth() {
        let conn = setup();
        add_hourly(&conn, "2026-01-01", 100, 0);
        add_hourly(&conn, "2026-02-01", 100, 0);
        conn.execute_batch(
            "INSERT INTO top_urls VALUES ('2026-01', '/a', 10, 400, 0, 0, 0);
             INSERT INTO top_urls VALUES ('2026-02', '/a', 10, 700, 0, 0, 0);
             INSERT INTO top_urls VALUES ('2026-01', '/b', 10, 900, 0, 0, 0);
             INSERT INTO top_urls VALUES ('2026-01', '/c', 10,  50, 0, 0, 0);",
        )
        .unwrap();

        let rows = top_urls_bandwidth(&conn, "2026", 10, false).unwrap();
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].url, "/a", "/a (1100 bw) should be #1");
        assert_eq!(rows[1].url, "/b", "/b (900 bw) should be #2");
        assert_eq!(rows[2].url, "/c", "/c (50 bw) should be #3");
        assert_eq!(rows[0].bandwidth, 1100);
        assert_eq!(rows[1].bandwidth, 900);
        assert_eq!(rows[2].bandwidth, 50);
    }

    // ── yearly variants ───────────────────────────────────────────────────────

    #[test]
    fn top_urls_yearly_pct_is_of_year_total_not_table_sum() {
        let conn = setup();
        // Two months contribute to the year total.
        add_hourly(&conn, "2026-01-15", 600, 6000);
        add_hourly(&conn, "2026-03-10", 400, 4000);
        // Only 300 + 200 = 500 hits represented in top_urls.
        conn.execute_batch(
            "INSERT INTO top_urls VALUES ('2026-01', '/a', 300, 3000, 0, 0, 0);
             INSERT INTO top_urls VALUES ('2026-01', '/b', 200, 2000, 0, 0, 0);",
        )
        .unwrap();

        let rows = top_urls_hits(&conn, "2026", 10, false).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pct_fmt, "30.0%", "yearly /a hits pct");
        assert_eq!(rows[1].pct_fmt, "20.0%", "yearly /b hits pct");
    }

    #[test]
    fn top_agents_yearly_pct_is_of_year_total_not_table_sum() {
        let conn = setup();
        add_hourly(&conn, "2026-01-15", 600, 6000);
        add_hourly(&conn, "2026-03-10", 400, 4000);
        conn.execute_batch(
            "INSERT INTO top_agents VALUES ('2026-01', 'Chrome', 300, 3000);
             INSERT INTO top_agents VALUES ('2026-01', 'Firefox', 200, 2000);",
        )
        .unwrap();

        let rows = top_agents_sorted(&conn, "2026", 10, false, "hits").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pct_fmt, "30.0%");
        assert_eq!(rows[1].pct_fmt, "20.0%");
    }

    #[test]
    fn top_countries_yearly_pct_is_of_year_total_not_table_sum() {
        let conn = setup();
        add_hourly(&conn, "2026-01-15", 600, 6000);
        add_hourly(&conn, "2026-03-10", 400, 4000);
        conn.execute_batch(
            "INSERT INTO countries VALUES ('GB', 'United Kingdom');
             INSERT INTO countries VALUES ('DE', 'Germany');
             INSERT INTO top_countries VALUES ('2026-01', 'GB', 300, 3000);
             INSERT INTO top_countries VALUES ('2026-01', 'DE', 200, 2000);",
        )
        .unwrap();

        let rows = top_countries_sorted(&conn, "2026", 10, false, "hits").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pct_fmt, "30.0%");
        assert_eq!(rows[1].pct_fmt, "20.0%");
    }
}
