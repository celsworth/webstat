// SQLite connection wrapper: schema initialisation, WAL mode, and module re-exports.

use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};

mod maintenance;
mod parse_state;
mod visit_state;
pub(crate) mod writer;

#[derive(Debug, Clone)]
pub struct ParseState {
    pub filepath: String,
    pub inode: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compressed_head_fingerprint: Option<u64>,
    pub uncompressed_head_fingerprint: Option<u64>,
    pub compressed_offset: u64,
    pub uncompressed_offset: u64,
    pub mtime_ns: i64,
    pub completed: bool,
    pub earliest_ts: Option<i64>,
    pub latest_ts: Option<i64>,
    pub skip_before_ts: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ParseStateUpdate {
    pub filepath: String,
    pub inode: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compressed_head_fingerprint: Option<u64>,
    pub uncompressed_head_fingerprint: Option<u64>,
    pub compressed_offset: u64,
    pub uncompressed_offset: u64,
    pub mtime_ns: i64,
    pub completed: bool,
    pub earliest_ts: Option<i64>,
    pub latest_ts: Option<i64>,
}

impl From<&ParseState> for ParseStateUpdate {
    fn from(state: &ParseState) -> Self {
        Self {
            filepath: state.filepath.clone(),
            inode: state.inode,
            compressed_size: state.compressed_size,
            uncompressed_size: state.uncompressed_size,
            compressed_head_fingerprint: state.compressed_head_fingerprint,
            uncompressed_head_fingerprint: state.uncompressed_head_fingerprint,
            compressed_offset: state.compressed_offset,
            uncompressed_offset: state.uncompressed_offset,
            mtime_ns: state.mtime_ns,
            completed: state.completed,
            earliest_ts: state.earliest_ts,
            latest_ts: state.latest_ts,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VisitStateKey {
    pub ip_kind: u8,
    pub ip_hi: u64,
    pub ip_lo: u64,
    pub ip_text: String,
}

#[derive(Debug, Clone)]
pub struct VisitStateUpdate {
    pub key: VisitStateKey,
    pub last_seen_ts: i64,
}

// ── Schema ────────────────────────────────────────────────────────────────────

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS hourly_stats (
    date       TEXT    NOT NULL,
    hour       INTEGER NOT NULL,
    hits       INTEGER DEFAULT 0,
    visits     INTEGER DEFAULT 0,
    bandwidth  INTEGER DEFAULT 0,
    status_2xx INTEGER DEFAULT 0,
    status_3xx INTEGER DEFAULT 0,
    status_4xx INTEGER DEFAULT 0,
    status_5xx INTEGER DEFAULT 0,
    PRIMARY KEY (date, hour)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS top_urls (
    period    TEXT    NOT NULL,
    url       TEXT    NOT NULL,
    hits      INTEGER NOT NULL DEFAULT 0,
    bandwidth INTEGER NOT NULL DEFAULT 0,
    rt_sum    INTEGER NOT NULL DEFAULT 0,
    rt_count  INTEGER NOT NULL DEFAULT 0,
    rt_max    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, url)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS top_ips (
    period       TEXT    NOT NULL,
    host_kind    INTEGER NOT NULL,
    host_hi      INTEGER NOT NULL,
    host_lo      INTEGER NOT NULL,
    hits         INTEGER NOT NULL DEFAULT 0,
    bandwidth    INTEGER NOT NULL DEFAULT 0,
    country_code TEXT    NOT NULL DEFAULT '--',
    PRIMARY KEY (period, host_kind, host_hi, host_lo)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS top_referrers (
    period   TEXT NOT NULL,
    referrer TEXT NOT NULL,
    hits     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, referrer)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS top_agents (
    period       TEXT    NOT NULL,
    agent_family TEXT    NOT NULL,
    hits         INTEGER NOT NULL DEFAULT 0,
    bandwidth    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, agent_family)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS top_countries (
    period       TEXT    NOT NULL,
    country_code TEXT    NOT NULL,
    hits         INTEGER NOT NULL DEFAULT 0,
    bandwidth    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, country_code)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS status_codes (
    period TEXT    NOT NULL,
    status INTEGER NOT NULL,
    hits   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, status)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS method_counts (
    period TEXT NOT NULL,
    method TEXT NOT NULL,
    hits   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, method)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS protocol_counts (
    period TEXT NOT NULL,
    proto  TEXT NOT NULL,
    hits   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, proto)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_period_stats (
    period    TEXT NOT NULL,
    bucket    TEXT NOT NULL,
    hits      INTEGER NOT NULL DEFAULT 0,
    bandwidth INTEGER NOT NULL DEFAULT 0,
    rt_sum    INTEGER NOT NULL DEFAULT 0,
    rt_count  INTEGER NOT NULL DEFAULT 0,
    rt_max    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, bucket)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_urls (
    period    TEXT NOT NULL,
    bucket    TEXT NOT NULL,
    url       TEXT NOT NULL,
    hits      INTEGER NOT NULL DEFAULT 0,
    bandwidth INTEGER NOT NULL DEFAULT 0,
    rt_sum    INTEGER NOT NULL DEFAULT 0,
    rt_count  INTEGER NOT NULL DEFAULT 0,
    rt_max    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, bucket, url)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_status_codes (
    period TEXT    NOT NULL,
    bucket TEXT    NOT NULL,
    status INTEGER NOT NULL,
    hits   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, bucket, status)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_agents (
    period       TEXT NOT NULL,
    bucket       TEXT NOT NULL,
    agent_family TEXT NOT NULL,
    hits         INTEGER NOT NULL DEFAULT 0,
    bandwidth    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, bucket, agent_family)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_countries (
    period       TEXT NOT NULL,
    bucket       TEXT NOT NULL,
    country_code TEXT NOT NULL,
    hits         INTEGER NOT NULL DEFAULT 0,
    bandwidth    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, bucket, country_code)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_method_counts (
    period TEXT NOT NULL,
    bucket TEXT NOT NULL,
    method TEXT NOT NULL,
    hits   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, bucket, method)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_protocol_counts (
    period TEXT NOT NULL,
    bucket TEXT NOT NULL,
    proto  TEXT NOT NULL,
    hits   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (period, bucket, proto)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_response_time_histograms (
    period TEXT NOT NULL,
    bucket TEXT NOT NULL,
    data   BLOB NOT NULL,
    PRIMARY KEY (period, bucket)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_daily_unique_ips (
    bucket  TEXT    NOT NULL,
    date    TEXT    NOT NULL,
    ip_kind INTEGER NOT NULL,
    ip_hi   INTEGER NOT NULL,
    count   INTEGER NOT NULL DEFAULT 0,
    bitmap  BLOB    NOT NULL,
    PRIMARY KEY (bucket, date, ip_kind, ip_hi)
);
CREATE TABLE IF NOT EXISTS bucket_daily_visitor_counts (
    bucket TEXT NOT NULL,
    date   TEXT NOT NULL,
    count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, date)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_unique_visitor_counts (
    bucket TEXT NOT NULL,
    period TEXT NOT NULL,
    count  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, period)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_hourly_stats (
    bucket    TEXT    NOT NULL,
    date      TEXT    NOT NULL,
    hour      INTEGER NOT NULL,
    hits      INTEGER NOT NULL DEFAULT 0,
    bandwidth INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket, date, hour)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_daily_response_time_histograms (
    bucket TEXT NOT NULL,
    date   TEXT NOT NULL,
    data   BLOB NOT NULL,
    PRIMARY KEY (bucket, date)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bucket_daily_response_time_stats (
    bucket TEXT NOT NULL,
    date   TEXT NOT NULL,
    avg_ms REAL NOT NULL,
    p95_ms INTEGER NOT NULL,
    PRIMARY KEY (bucket, date)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS daily_unique_ips (
    date    TEXT    NOT NULL,
    ip_kind INTEGER NOT NULL,
    ip_hi   INTEGER NOT NULL,
    count   INTEGER NOT NULL DEFAULT 0,
    bitmap  BLOB    NOT NULL,
    PRIMARY KEY (date, ip_kind, ip_hi)
);
CREATE TABLE IF NOT EXISTS monthly_unique_ips (
    period  TEXT    NOT NULL,
    ip_kind INTEGER NOT NULL,
    ip_hi   INTEGER NOT NULL DEFAULT 0,
    bitmap  BLOB    NOT NULL,
    PRIMARY KEY (period, ip_kind, ip_hi)
);
CREATE TABLE IF NOT EXISTS bucket_monthly_unique_ips (
    bucket  TEXT    NOT NULL,
    period  TEXT    NOT NULL,
    ip_kind INTEGER NOT NULL,
    ip_hi   INTEGER NOT NULL DEFAULT 0,
    bitmap  BLOB    NOT NULL,
    PRIMARY KEY (bucket, period, ip_kind, ip_hi)
);
CREATE TABLE IF NOT EXISTS unique_visitor_counts (
    period TEXT PRIMARY KEY,
    count  INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS daily_visitor_counts (
    date  TEXT PRIMARY KEY,
    count INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS countries (
    country_code TEXT PRIMARY KEY,
    country_name TEXT NOT NULL DEFAULT 'Unknown'
);
CREATE TABLE IF NOT EXISTS parse_state (
    filepath    TEXT PRIMARY KEY,
    inode       INTEGER,
    compressed_size INTEGER,
    uncompressed_size INTEGER,
    compressed_head_fingerprint INTEGER,
    uncompressed_head_fingerprint INTEGER,
    compressed_offset INTEGER,
    uncompressed_offset INTEGER,
    mtime_ns    INTEGER,
    completed   INTEGER NOT NULL DEFAULT 0,
    earliest_ts INTEGER,
    latest_ts   INTEGER,
    skip_before_ts INTEGER
);
CREATE TABLE IF NOT EXISTS parse_state_archive (
    filepath    TEXT NOT NULL,
    inode       INTEGER,
    compressed_size INTEGER,
    uncompressed_size INTEGER,
    compressed_head_fingerprint INTEGER,
    uncompressed_head_fingerprint INTEGER,
    compressed_offset INTEGER,
    uncompressed_offset INTEGER,
    mtime_ns    INTEGER,
    completed   INTEGER NOT NULL DEFAULT 0,
    earliest_ts INTEGER,
    latest_ts   INTEGER,
    skip_before_ts INTEGER,
    PRIMARY KEY (filepath, inode)
);
CREATE UNIQUE INDEX IF NOT EXISTS parse_state_inode ON parse_state (inode);
CREATE INDEX IF NOT EXISTS parse_state_uncompressed_identity
    ON parse_state (uncompressed_head_fingerprint, uncompressed_size)
    WHERE completed = 1;
CREATE INDEX IF NOT EXISTS parse_state_archive_uncompressed_head_fingerprint
    ON parse_state_archive (uncompressed_head_fingerprint);
CREATE INDEX IF NOT EXISTS parse_state_archive_compressed_head_fingerprint
    ON parse_state_archive (compressed_head_fingerprint);
CREATE INDEX IF NOT EXISTS parse_state_archive_inode
    ON parse_state_archive (inode);
CREATE TABLE IF NOT EXISTS visit_state (
    ip_kind      INTEGER NOT NULL,
    ip_hi        INTEGER NOT NULL,
    ip_lo        INTEGER NOT NULL,
    ip_text      TEXT    NOT NULL DEFAULT '',
    last_seen_ts INTEGER NOT NULL,
    PRIMARY KEY (ip_kind, ip_hi, ip_lo, ip_text)
);
CREATE INDEX IF NOT EXISTS visit_state_last_seen_idx
    ON visit_state (last_seen_ts);
CREATE TABLE IF NOT EXISTS daily_response_time_histograms (
    date TEXT NOT NULL PRIMARY KEY,
    data BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS daily_response_time_stats (
    date   TEXT NOT NULL PRIMARY KEY,
    avg_ms REAL NOT NULL,
    p95_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS monthly_response_time_histograms (
    period TEXT NOT NULL PRIMARY KEY,
    data   BLOB NOT NULL
);
"#;

// ── Database ──────────────────────────────────────────────────────────────────

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &str) -> Result<Self> {
        let conn =
            Connection::open(path).with_context(|| format!("Failed to open database: {path}"))?;
        conn.busy_timeout(Duration::from_secs(60))?;
        conn.execute_batch("PRAGMA page_size = 65536; PRAGMA temp_store = MEMORY; PRAGMA mmap_size = 1073741824; PRAGMA cache_size = -262144; PRAGMA wal_autocheckpoint = 4000; PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        let mut db = Self { conn };
        db.apply_schema()?;
        Ok(db)
    }

    fn apply_schema(&mut self) -> Result<()> {
        self.conn.execute_batch(SCHEMA)?;
        Ok(())
    }

    pub(crate) fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }

    pub(crate) fn conn_ref(&self) -> &Connection {
        &self.conn
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT value FROM meta WHERE key = ?1")?;
        match stmt.query_row(params![key], |row| row.get::<_, String>(0)) {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn set_meta(&mut self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

// ── Host key encoding ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct HostKey {
    pub(crate) kind: u8,
    pub(crate) hi: u64,
    pub(crate) lo: u64,
}

#[cfg(test)]
mod tests;
