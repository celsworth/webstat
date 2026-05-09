use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use ahash::{AHashMap, AHashSet};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};

use crate::hll::HyperLogLog;
#[cfg(test)]
use crate::topn::TopNHosts;
use crate::topn::{
    CountryCountMap, HostBwMap, HostHitsMap, HourlyMap, PeriodCountMap, PeriodHitsMap, StatusMap,
};

mod maintenance;
mod parse_state;
mod visit_state;
mod writer;

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
CREATE TABLE IF NOT EXISTS top_urls_hits (
    period    TEXT,
    url       TEXT,
    hits      INTEGER DEFAULT 0,
    bandwidth INTEGER DEFAULT 0,
    PRIMARY KEY (period, url)
);
CREATE TABLE IF NOT EXISTS top_urls_bandwidth (
    period    TEXT,
    url       TEXT,
    hits      INTEGER DEFAULT 0,
    bandwidth INTEGER DEFAULT 0,
    PRIMARY KEY (period, url)
);
CREATE TABLE IF NOT EXISTS top_hosts (
    period       TEXT,
    host_kind    INTEGER NOT NULL,
    host_hi      INTEGER NOT NULL,
    host_lo      INTEGER NOT NULL,
    host_text    TEXT    NOT NULL DEFAULT '',
    hits         INTEGER DEFAULT 0,
    bandwidth    INTEGER DEFAULT 0,
    country_code TEXT    DEFAULT '--',
    PRIMARY KEY (period, host_kind, host_hi, host_lo, host_text)
);
CREATE TABLE IF NOT EXISTS top_hosts_hits (
    period       TEXT,
    host_kind    INTEGER NOT NULL,
    host_hi      INTEGER NOT NULL,
    host_lo      INTEGER NOT NULL,
    host_text    TEXT    NOT NULL DEFAULT '',
    hits         INTEGER DEFAULT 0,
    bandwidth    INTEGER DEFAULT 0,
    country_code TEXT    DEFAULT '--',
    PRIMARY KEY (period, host_kind, host_hi, host_lo, host_text)
);
CREATE TABLE IF NOT EXISTS top_hosts_bandwidth (
    period       TEXT,
    host_kind    INTEGER NOT NULL,
    host_hi      INTEGER NOT NULL,
    host_lo      INTEGER NOT NULL,
    host_text    TEXT    NOT NULL DEFAULT '',
    hits         INTEGER DEFAULT 0,
    bandwidth    INTEGER DEFAULT 0,
    country_code TEXT    DEFAULT '--',
    PRIMARY KEY (period, host_kind, host_hi, host_lo, host_text)
);
CREATE TABLE IF NOT EXISTS country_code_names (
    country_code TEXT PRIMARY KEY,
    country_name TEXT NOT NULL DEFAULT 'Unknown'
);
CREATE TABLE IF NOT EXISTS top_refs (
    period   TEXT,
    referrer TEXT,
    hits     INTEGER DEFAULT 0,
    PRIMARY KEY (period, referrer)
);
CREATE TABLE IF NOT EXISTS top_agents (
    period       TEXT,
    agent_family TEXT,
    hits         INTEGER DEFAULT 0,
    PRIMARY KEY (period, agent_family)
);
CREATE TABLE IF NOT EXISTS top_countries (
    period       TEXT,
    country_code TEXT,
    hits         INTEGER DEFAULT 0,
    PRIMARY KEY (period, country_code)
);
CREATE TABLE IF NOT EXISTS status_codes (
    period TEXT,
    status INTEGER,
    hits   INTEGER DEFAULT 0,
    PRIMARY KEY (period, status)
);

CREATE TABLE IF NOT EXISTS site_counts_hll (
    scope    TEXT PRIMARY KEY,
    estimate INTEGER DEFAULT 0,
    sketch   BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS all_time_hosts (
    host_kind INTEGER NOT NULL,
    host_hi   INTEGER NOT NULL,
    host_lo   INTEGER NOT NULL,
    host_text TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (host_kind, host_hi, host_lo, host_text)
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
    completed   INTEGER NOT NULL DEFAULT 0
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
        conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;")?;
        let mut db = Self { conn };
        db.apply_schema()?;
        Ok(db)
    }

    // ── Schema management ─────────────────────────────────────────────────────

    fn apply_schema(&mut self) -> Result<()> {
        self.conn.execute_batch(SCHEMA)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HostKey {
    kind: u8,
    hi: u64,
    lo: u64,
    text: String,
}

fn encode_host_key(host: &str) -> HostKey {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => HostKey {
            kind: 1,
            hi: 0,
            lo: u32::from(v4) as u64,
            text: String::new(),
        },
        Ok(IpAddr::V6(v6)) => {
            let n = u128::from(v6);
            HostKey {
                kind: 2,
                hi: (n >> 64) as u64,
                lo: n as u64,
                text: String::new(),
            }
        }
        Err(_) => HostKey {
            kind: 0,
            hi: 0,
            lo: 0,
            text: host.to_string(),
        },
    }
}

#[cfg(test)]
mod tests;
