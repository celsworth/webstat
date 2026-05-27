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
