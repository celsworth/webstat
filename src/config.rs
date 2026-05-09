use anyhow::{Context, Result};
use serde::Deserialize;
use serde_yaml::Value;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    pub site_name: String,
    /// Comma-separated glob patterns for source logs.
    pub log_glob: String,
    pub database: String,
    pub output_dir: String,
    /// Path to a MaxMind GeoLite2-Country.mmdb file (optional).
    pub geoip_db: Option<String>,
    /// Number of worker threads for processing multiple files in parallel.
    /// `1` keeps existing single-thread behavior.
    pub file_workers: usize,
    pub top_n: usize,
    /// Enable Top URLs tracking.
    pub enable_top_urls: bool,
    /// Enable Top Hosts tracking.
    pub enable_top_hosts: bool,
    /// Enable Top Referrers tracking.
    pub enable_top_refs: bool,
    /// Run SQLite VACUUM after pruning top tables.
    pub vacuum_after_prune: bool,
    /// When false, top-table pruning is skipped after imports.
    pub enable_pruner: bool,
    pub bot_filter: bool,
    /// Hostname of the site being analysed; referrers matching this host are
    /// excluded from `top_refs`.
    pub site_host: Option<String>,
    /// HyperLogLog precision for unique-visitor (Sites) counting.
    /// Valid range: 4–16 (higher = more accurate, more RAM; precision 14 uses ~16 KiB per period).
    ///
    /// WARNING: This value is baked into the HLL register blobs stored in SQLite.
    /// Changing it on an existing database will cause the new sketches to be incompatible
    /// with the stored ones and will corrupt unique-visitor counts. Only change this
    /// before the first `process` run, or after wiping the database.
    pub hll_precision: u8,
    /// Space-Saving algorithm capacity (k) for approximate top tables
    /// (URLs, hosts, referrers, user-agents).
    /// A higher k improves accuracy at the cost of more memory per period.
    /// Set to 0 to auto-derive from `top_n × 100` (the default).
    pub topn_k: usize,
    /// Periodic database checkpoint interval in minutes.
    /// `0` disables checkpointing (flush only at end of run/file).
    pub checkpoint_minutes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            site_name: "My Site".into(),
            log_glob: String::new(),
            database: "./webstat.db".into(),
            output_dir: "./output".into(),
            geoip_db: None,
            file_workers: 1,
            top_n: 20,
            enable_top_urls: true,
            enable_top_hosts: true,
            enable_top_refs: true,
            vacuum_after_prune: false,
            enable_pruner: true,
            bot_filter: true,
            site_host: None,
            hll_precision: 14,
            topn_k: 0,
            checkpoint_minutes: 0,
        }
    }
}

pub fn load(path: &str) -> Result<Config> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("Cannot read config file '{path}'"))?;
    let parsed: Value = serde_yaml::from_str(&raw)
        .with_context(|| format!("Failed to parse config file '{path}'"))?;
    reject_legacy_log_keys(path, &parsed)?;
    let mut cfg: Config = serde_yaml::from_value(parsed)
        .with_context(|| format!("Failed to parse config file '{path}'"))?;

    let base = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    cfg.database = resolve_path(base, &cfg.database);
    cfg.output_dir = resolve_path(base, &cfg.output_dir);
    cfg.log_glob = resolve_glob_list(base, &cfg.log_glob);
    cfg.geoip_db = cfg.geoip_db.as_deref().map(|p| resolve_path(base, p));

    Ok(cfg)
}

fn reject_legacy_log_keys(path: &str, parsed: &Value) -> Result<()> {
    let Value::Mapping(map) = parsed else {
        return Ok(());
    };

    let has_log_file = map.contains_key(Value::String("log_file".into()));
    let has_log_dir = map.contains_key(Value::String("log_dir".into()));
    if has_log_file || has_log_dir {
        anyhow::bail!(
            "{path} uses removed keys 'log_file'/'log_dir'. Use only 'log_glob' (comma-separated patterns), e.g. log_glob: /var/log/nginx/access.log,/dump/logs/access*"
        );
    }

    Ok(())
}

fn resolve_glob_list(base: &Path, globs: &str) -> String {
    globs
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|g| resolve_path(base, g))
        .collect::<Vec<_>>()
        .join(",")
}

fn resolve_path(base: &Path, path: &str) -> String {
    let p = Path::new(path);
    if p.is_absolute() {
        return path.to_string();
    }

    let joined: PathBuf = base.join(p);
    joined.to_string_lossy().into_owned()
}
