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
                 files      INTEGER DEFAULT 0,
                 pages      INTEGER DEFAULT 0,
                 bandwidth  INTEGER DEFAULT 0,
                 status_2xx INTEGER DEFAULT 0,
                 status_3xx INTEGER DEFAULT 0,
                 status_4xx INTEGER DEFAULT 0,
                 status_5xx INTEGER DEFAULT 0,
                 sites      INTEGER DEFAULT 0,
                 PRIMARY KEY (date, hour)
             );
             CREATE TABLE top_hosts (
                 period       TEXT,
                 host_kind    INTEGER NOT NULL,
                 host_hi      INTEGER NOT NULL,
                 host_lo      INTEGER NOT NULL,
                 host_text    TEXT    NOT NULL DEFAULT '',
                 hits         INTEGER DEFAULT 0,
                 bandwidth    INTEGER DEFAULT 0,
                 country_code TEXT DEFAULT '--',
                 PRIMARY KEY (period, host_kind, host_hi, host_lo, host_text)
             );
             CREATE TABLE top_hosts_hits (
                 period       TEXT,
                 host_kind    INTEGER NOT NULL,
                 host_hi      INTEGER NOT NULL,
                 host_lo      INTEGER NOT NULL,
                 host_text    TEXT    NOT NULL DEFAULT '',
                 hits         INTEGER DEFAULT 0,
                 bandwidth    INTEGER DEFAULT 0,
                 country_code TEXT DEFAULT '--',
                 PRIMARY KEY (period, host_kind, host_hi, host_lo, host_text)
             );
             CREATE TABLE country_code_names (
                 country_code TEXT PRIMARY KEY,
                 country_name TEXT NOT NULL DEFAULT 'Unknown'
             );
             CREATE TABLE daily_site_counts (
                 date  TEXT PRIMARY KEY,
                 sites INTEGER DEFAULT 0
             );
             CREATE TABLE period_site_counts (
                 period TEXT PRIMARY KEY,
                 sites  INTEGER DEFAULT 0
             );
             CREATE TABLE site_counts_hll (
                 scope    TEXT PRIMARY KEY,
                 estimate INTEGER DEFAULT 0,
                 sketch   BLOB NOT NULL
             );
             CREATE TABLE all_time_hosts (
                 host_kind INTEGER NOT NULL,
                 host_hi   INTEGER NOT NULL,
                 host_lo   INTEGER NOT NULL,
                 host_text TEXT    NOT NULL DEFAULT '',
                 PRIMARY KEY (host_kind, host_hi, host_lo, host_text)
             );",
        )
        .expect("create test schema");
        conn
    }

    fn insert_hourly(conn: &Connection, date: &str, hour: i64, hits: i64, visits: i64, sites: i64) {
        conn.execute(
            "INSERT INTO hourly_stats
             (date, hour, hits, visits, files, pages, bandwidth, status_2xx, status_3xx, status_4xx, status_5xx, sites)
             VALUES (?1, ?2, ?3, ?4, 1, 1, 100, 1, 0, 0, 0, ?5)",
            params![date, hour, hits, visits, sites],
        )
        .expect("insert hourly row");
    }

    fn insert_top_host(conn: &Connection, period: &str, host: &str) {
        let (kind, hi, lo, text) = encode_host(host);
        conn.execute(
            "INSERT OR REPLACE INTO country_code_names (country_code, country_name)
             VALUES ('US', 'United States')",
            [],
        )
        .expect("insert country name lookup");
        conn.execute(
            "INSERT OR REPLACE INTO top_hosts (period, host_kind, host_hi, host_lo, host_text, hits, bandwidth, country_code)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, 100, 'US')",
            params![period, kind as i64, hi as i64, lo as i64, text],
        )
        .expect("insert top host");
        conn.execute(
            "INSERT OR REPLACE INTO top_hosts_hits (period, host_kind, host_hi, host_lo, host_text, hits, bandwidth, country_code)
             VALUES (?1, ?2, ?3, ?4, ?5, 1, 100, 'US')",
            params![period, kind as i64, hi as i64, lo as i64, text],
        )
        .expect("insert top host hits");
    }

    #[test]
    fn site_count_for_scope_falls_back_to_top_hosts_when_missing() {
        let conn = setup_conn();
        insert_top_host(&conn, "2026-05", "site-a");
        insert_top_host(&conn, "2026-05", "site-b");
        insert_top_host(&conn, "2026-05", "site-c");

        let sites = site_count_for_scope(&conn, "2026-05").expect("fallback site count");
        assert_eq!(sites, 3);
    }

    #[test]
    fn overall_totals_prefer_all_time_hosts() {
        let conn = setup_conn();
        insert_hourly(&conn, "2026-05-01", 0, 100, 10, 2);
        conn.execute(
            "INSERT INTO all_time_hosts (host_kind, host_hi, host_lo, host_text) VALUES (0, 0, 0, 'site-a')",
            [],
        )
            .expect("insert all_time host a");
        conn.execute(
            "INSERT INTO all_time_hosts (host_kind, host_hi, host_lo, host_text) VALUES (0, 0, 0, 'site-b')",
            [],
        )
            .expect("insert all_time host b");
        conn.execute(
            "INSERT INTO all_time_hosts (host_kind, host_hi, host_lo, host_text) VALUES (0, 0, 0, 'site-c')",
            [],
        )
            .expect("insert all_time host c");
        insert_top_host(&conn, "2026-05", "site-a");
        insert_top_host(&conn, "2026-05", "site-d");
        insert_top_host(&conn, "2026", "site-e");

        let totals = overall_totals(&conn, false).expect("overall totals");
        assert_eq!(totals.sites, 3);
    }

    #[test]
    fn overall_totals_fall_back_to_distinct_top_hosts() {
        let conn = setup_conn();
        insert_hourly(&conn, "2026-05-01", 0, 100, 10, 2);
        insert_top_host(&conn, "2026-05", "site-a");
        insert_top_host(&conn, "2026-05", "site-b");
        insert_top_host(&conn, "2026", "site-a");

        let totals = overall_totals(&conn, false).expect("overall totals fallback");
        assert_eq!(totals.sites, 2);
    }

    #[test]
    fn site_count_for_scope_prefers_hll() {
        let conn = setup_conn();
        conn.execute(
            "INSERT INTO site_counts_hll (scope, estimate, sketch) VALUES ('2026-05', 42, X'0A' || zeroblob(1024))",
            [],
        )
        .expect("insert hll estimate");

        let sites = site_count_for_scope(&conn, "2026-05").expect("hll period site count");
        assert_eq!(sites, 42);
    }

    #[test]
    fn overall_totals_prefers_hll() {
        let conn = setup_conn();
        insert_hourly(&conn, "2026-05-01", 0, 100, 10, 2);
        conn.execute(
            "INSERT INTO site_counts_hll (scope, estimate, sketch) VALUES ('__all__', 7, X'0A' || zeroblob(1024))",
            [],
        )
        .expect("insert all-time hll estimate");

        let totals = overall_totals(&conn, false).expect("overall totals hll");
        assert_eq!(totals.sites, 7);
    }
}
