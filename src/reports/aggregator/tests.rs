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
                 date    TEXT NOT NULL,
                 ip_kind INTEGER NOT NULL,
                 ip_hi   INTEGER NOT NULL DEFAULT 0,
                 ip_lo   INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (date, ip_kind, ip_hi, ip_lo)
             );
             CREATE TABLE all_time_ips (
                 host_kind INTEGER NOT NULL,
                 host_hi   INTEGER NOT NULL,
                 host_lo   INTEGER NOT NULL,
                 PRIMARY KEY (host_kind, host_hi, host_lo)
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
             CREATE TABLE yearly_unique_ips (
                 year    TEXT    NOT NULL,
                 ip_kind INTEGER NOT NULL,
                 ip_hi   INTEGER NOT NULL DEFAULT 0,
                 ip_lo   INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (year, ip_kind, ip_hi, ip_lo)
             );",
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

    fn insert_daily_ip(conn: &Connection, date: &str, ip_lo: i64) {
        conn.execute(
            "INSERT OR IGNORE INTO daily_unique_ips (date, ip_kind, ip_hi, ip_lo) VALUES (?1, 1, 0, ?2)",
            params![date, ip_lo],
        )
        .expect("insert daily ip");
    }

    fn insert_yearly_ip(conn: &Connection, year: &str, ip_lo: i64) {
        conn.execute(
            "INSERT OR IGNORE INTO yearly_unique_ips (year, ip_kind, ip_hi, ip_lo) VALUES (?1, 1, 0, ?2)",
            params![year, ip_lo],
        )
        .expect("insert yearly ip");
    }

    fn finalize_unique_visitor_counts(conn: &Connection, period: &str) {
        let like = format!("{}-%", period);
        conn.execute(
            "INSERT OR REPLACE INTO unique_visitor_counts (period, count)
             SELECT ?1, COUNT(*) FROM (
               SELECT DISTINCT ip_kind, ip_hi, ip_lo FROM daily_unique_ips WHERE date LIKE ?2
             )",
            params![period, like],
        )
        .expect("finalize site count cache");
    }

    #[test]
    fn visitor_count_for_scope_daily() {
        let conn = setup_conn();
        insert_daily_ip(&conn, "2026-05-01", 1);
        insert_daily_ip(&conn, "2026-05-01", 2);
        insert_daily_ip(&conn, "2026-05-02", 3);

        let visitors = visitor_count_for_scope(&conn, "2026-05-01").expect("daily site count");
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

        let visitors = visitor_count_for_scope(&conn, "2026-05").expect("monthly site count");
        assert_eq!(visitors, 3, "should deduplicate across days");
    }

    #[test]
    fn visitor_count_for_scope_yearly() {
        let conn = setup_conn();
        insert_daily_ip(&conn, "2026-01-15", 10);
        insert_daily_ip(&conn, "2026-06-01", 10); // same IP different month
        insert_daily_ip(&conn, "2026-06-01", 20);
        finalize_unique_visitor_counts(&conn, "2026");

        let visitors = visitor_count_for_scope(&conn, "2026").expect("yearly site count");
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

        let visitors = visitor_count_for_scope(&conn, "2026-05").expect("monthly fallback");
        assert_eq!(visitors, 3, "should fall back to daily_unique_ips and deduplicate");
    }

    #[test]
    fn visitor_count_for_scope_yearly_fallback_to_yearly_unique_ips_and_daily_unique_ips() {
        let conn = setup_conn();
        // Finalized months in yearly_unique_ips
        insert_yearly_ip(&conn, "2026", 10);
        insert_yearly_ip(&conn, "2026", 20);
        // In-progress month still in daily_unique_ips
        insert_daily_ip(&conn, "2026-05-01", 30);
        // no cache entry — simulates in-progress year

        let visitors = visitor_count_for_scope(&conn, "2026").expect("yearly fallback");
        assert_eq!(visitors, 3, "should union yearly_unique_ips and daily_unique_ips");
    }

    #[test]
    fn visitor_count_for_scope_yearly_fallback_deduplicates_across_sources() {
        let conn = setup_conn();
        // IP 10 appears in both yearly_unique_ips (prior months) and daily_unique_ips (current month)
        insert_yearly_ip(&conn, "2026", 10);
        insert_yearly_ip(&conn, "2026", 20);
        insert_daily_ip(&conn, "2026-05-01", 10); // duplicate of yearly ip 10
        insert_daily_ip(&conn, "2026-05-01", 30);

        let visitors = visitor_count_for_scope(&conn, "2026").expect("yearly dedup");
        assert_eq!(
            visitors, 3,
            "should deduplicate ip 10 across yearly_unique_ips and daily_unique_ips"
        );
    }

    #[test]
    fn overall_totals_uses_all_time_ips() {
        let conn = setup_conn();
        insert_hourly(&conn, "2026-05-01", 0, 100, 10);
        conn.execute(
            "INSERT INTO all_time_ips (host_kind, host_hi, host_lo) VALUES (1, 0, 1)",
            [],
        )
        .expect("insert all_time host a");
        conn.execute(
            "INSERT INTO all_time_ips (host_kind, host_hi, host_lo) VALUES (1, 0, 2)",
            [],
        )
        .expect("insert all_time host b");

        let totals = overall_totals(&conn, false).expect("overall totals");
        assert_eq!(totals.visitors, 2);
    }
}
