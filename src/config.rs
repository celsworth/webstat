// YAML config parsing: deserialises webstat.yaml into Config and resolves relative paths.

use anyhow::{Context, Result};
use serde::Deserialize;
use serde_yaml::Value;
use std::path::{Path, PathBuf};

pub use crate::rules::RawRule;

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
    pub top_n: usize,
    /// Enable Top URLs tracking.
    pub enable_top_urls: bool,
    /// Enable Top Hosts tracking.
    pub enable_top_hosts: bool,
    /// Enable Top Referrers tracking.
    pub enable_top_refs: bool,
    /// Enable Top Agents tracking.
    pub enable_top_agents: bool,
    /// Enable all-time unique hosts (all_time_ips) tracking.
    /// Disable to save space — the all_time_ips table can grow very large.
    pub enable_all_time_unique_hosts: bool,
    /// Run SQLite VACUUM after pruning top tables.
    pub vacuum_after_prune: bool,
    pub bot_filter: bool,
    /// Periodic database checkpoint interval in minutes.
    /// `0` disables checkpointing (flush only at end of run/file).
    pub checkpoint_minutes: u64,
    /// Anonymise IP addresses by zeroing out the last octet (IPv4) or last 80 bits (IPv6).
    pub anonymise_ips: bool,
    /// Optional per-entry filtering rules evaluated in the parser thread.
    #[serde(default)]
    pub rules: Vec<RawRule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            site_name: "My Site".into(),
            log_glob: String::new(),
            database: "./webstat.db".into(),
            output_dir: "./output".into(),
            geoip_db: None,
            top_n: 20,
            enable_top_urls: true,
            enable_top_hosts: true,
            enable_top_refs: true,
            enable_top_agents: true,
            enable_all_time_unique_hosts: true,
            vacuum_after_prune: false,
            bot_filter: true,
            checkpoint_minutes: 0,
            anonymise_ips: false,
            rules: Vec::new(),
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
