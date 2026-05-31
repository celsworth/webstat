// CLI entry point: parses arguments with clap, loads config, and dispatches to subcommands.

mod accumulators;
mod aggregator;
mod compression;
mod config;
mod database;
mod fingerprint;
mod geo;
mod ip;
mod loader;
mod logging;
mod method_proto;
mod parser;
mod progress;
mod reports;
mod response_time;
mod rollback;
mod rules;
mod run_accumulators;
mod ua;
mod update;

#[cfg(test)]
mod tests;

use anyhow::{bail, Result};
use clap::{ArgAction, Parser, Subcommand};

use aggregator::{Processor, ProcessorConfig};
use database::Database;
use geo::Geo;

/// Webstat — web access-log processor
#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to config file
    #[arg(short, long, global = true)]
    config: Option<String>,

    /// Site name used in generated reports (default: My Site)
    #[arg(long, global = true)]
    site_name: Option<String>,

    /// Comma-separated log glob patterns (example: /var/log/nginx/access.log,/dump/logs/access*)
    #[arg(long, global = true)]
    log_glob: Option<String>,

    /// SQLite database path (default: ./webstat.db)
    #[arg(long, global = true)]
    database: Option<String>,

    /// Output directory for generated HTML (default: ./output)
    #[arg(long, global = true)]
    output_dir: Option<String>,

    /// Path to GeoLite2 country database
    #[arg(long, global = true)]
    geoip_db: Option<String>,

    /// Number of rows to keep in top tables (default: 20)
    #[arg(long, global = true)]
    top_n: Option<usize>,

    /// Enable top URLs tracking (true/false, default: true)
    #[arg(long, global = true)]
    enable_top_urls: Option<bool>,

    /// Enable top hosts tracking (true/false, default: true)
    #[arg(long, global = true)]
    enable_top_sites: Option<bool>,

    /// Enable top referrers tracking (true/false, default: true)
    #[arg(long, global = true)]
    enable_top_refs: Option<bool>,

    /// Enable top agents tracking (true/false, default: true)
    #[arg(long, global = true)]
    enable_top_agents: Option<bool>,

    /// Periodic database checkpoint interval in minutes (0 = disabled)
    #[arg(long, global = true)]
    checkpoint_minutes: Option<u64>,

    /// Anonymise IP addresses in reports (true/false, default: false)
    #[arg(long, global = true)]
    anonymise_ips: Option<bool>,

    /// Exclude known bots from primary statistics (true/false, default: true)
    #[arg(long, global = true)]
    bot_filter: Option<bool>,

    /// Verbosity level: -v (verbose), -vv (debug=1), -vvv (debug=2)
    #[arg(short, long, global = true, action = ArgAction::Count)]
    verbose: u8,
}

impl Args {
    #[inline]
    fn verbose_enabled(&self) -> bool {
        self.verbose > 0
    }

    #[inline]
    fn debug_level(&self) -> u8 {
        self.verbose.saturating_sub(1).min(2)
    }
}

#[derive(Subcommand, Debug, Clone)]
enum Command {
    /// Process logs into the SQLite database
    Process,
    /// Generate static HTML reports from the SQLite database
    Generate,
    /// Process logs and then generate static HTML reports
    All,
    /// Roll back all ingested data to the start of a given month
    Rollback {
        /// Month to roll back to, in YYYY-MM format (e.g. 2026-03)
        #[arg(long)]
        month: String,
        /// Print what would be changed without modifying the database
        #[arg(long)]
        dry_run: bool,
    },
    /// Update webstat to the latest GitHub release
    Update {
        /// Check for an available update without installing it
        #[arg(long)]
        check: bool,
    },
}

fn main() -> Result<()> {
    let args = Args::parse();
    let cfg = build_config(&args)?;
    logging::init(args.verbose_enabled(), args.debug_level());

    match args.command.unwrap_or(Command::All) {
        Command::Process => run_processing(&cfg),
        Command::Generate => reports::generate_html(&cfg),
        Command::All => {
            run_processing(&cfg)?;
            reports::generate_html(&cfg)
        }
        Command::Rollback { month, dry_run } => {
            let mut db = Database::open(&cfg.database)?;
            rollback::rollback(&mut db, &month, dry_run)
        }
        Command::Update { check } => update::run(check),
    }
}

fn build_config(args: &Args) -> Result<config::Config> {
    const AUTO_CONFIG_PATHS: &[&str] = &["webstat.yaml", "webstat.yml"];

    let explicit_config = args.config.as_deref();
    let auto_config: Option<&str> = if explicit_config.is_none() {
        AUTO_CONFIG_PATHS
            .iter()
            .copied()
            .find(|p| std::path::Path::new(p).exists())
    } else {
        None
    };

    let mut cfg = match explicit_config.or(auto_config) {
        Some(path) => config::load(path)?,
        None => config::Config::default(),
    };

    if let Some(v) = &args.site_name {
        cfg.site_name = v.clone();
    }
    if let Some(v) = &args.log_glob {
        cfg.log_glob = v.clone();
    }
    if let Some(v) = &args.database {
        cfg.database = v.clone();
    }
    if let Some(v) = &args.output_dir {
        cfg.output_dir = v.clone();
    }
    if let Some(v) = &args.geoip_db {
        cfg.geoip_db = Some(v.clone());
    }
    if let Some(v) = args.top_n {
        cfg.top_n = v;
    }
    if let Some(v) = args.enable_top_urls {
        cfg.enable_top_urls = v;
    }
    if let Some(v) = args.enable_top_sites {
        cfg.enable_top_sites = v;
    }
    if let Some(v) = args.enable_top_refs {
        cfg.enable_top_refs = v;
    }
    if let Some(v) = args.enable_top_agents {
        cfg.enable_top_agents = v;
    }
    if let Some(v) = args.checkpoint_minutes {
        cfg.checkpoint_minutes = v;
    }
    if let Some(v) = args.anonymise_ips {
        cfg.anonymise_ips = v;
    }
    if let Some(v) = args.bot_filter {
        cfg.bot_filter = v;
    }

    if explicit_config.is_none()
        && auto_config.is_none()
        && args
            .log_glob
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .is_empty()
    {
        bail!(
            "No config file provided and required option '--log-glob' is missing. \
             Provide --log-glob, pass --config <FILE>, or place a webstat.yaml in the current directory."
        );
    }

    if cfg.log_glob.trim().is_empty() {
        if let Some(path) = args.config.as_deref() {
            bail!(
                "No log source configured. Set 'log_glob' in {} or pass --log-glob.",
                path
            );
        }
        bail!("No log source configured. Set --log-glob.");
    }

    Ok(cfg)
}

fn run_processing(cfg: &config::Config) -> Result<()> {
    let db = Database::open(&cfg.database)?;
    let geo = Geo::new(cfg.geoip_db.as_deref());
    if geo.db_unavailable {
        bail!(
            "GeoIP database could not be opened: {}",
            cfg.geoip_db.as_deref().unwrap_or("")
        );
    }

    let rule_set = if cfg.rules.is_empty() {
        None
    } else {
        Some(std::sync::Arc::new(rules::RuleSet::compile(&cfg.rules)?))
    };

    let mut processor = Processor::new(
        db,
        geo,
        ProcessorConfig {
            top_n: cfg.top_n,
            bot_filter: cfg.bot_filter,
            enable_top_urls: cfg.enable_top_urls,
            enable_top_sites: cfg.enable_top_sites,
            enable_top_refs: cfg.enable_top_refs,
            enable_top_agents: cfg.enable_top_agents,
            rule_set,
        },
    );
    processor.set_checkpoint_interval_minutes(cfg.checkpoint_minutes);

    processor.process_globs(&cfg.log_glob)?;

    Ok(())
}
