mod compression;
mod config;
mod database;
mod fingerprint;
mod geo;
mod hll;
mod logging;
mod parser;
mod processor;
mod progress;
mod reports;
mod run_accumulators;
mod topn;
mod ua;
mod util;

use anyhow::{bail, Context, Result};
use clap::{ArgAction, Parser, Subcommand};

use database::Database;
use geo::Geo;
use processor::{Processor, ProcessorConfig};
use ua::UaParser;

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

    /// Number of worker threads for file processing (default: 1)
    #[arg(long, global = true)]
    file_workers: Option<usize>,

    /// Number of rows to keep in top tables (default: 20)
    #[arg(long, global = true)]
    top_n: Option<usize>,

    /// Enable top URLs tracking (true/false, default: true)
    #[arg(long, global = true)]
    enable_top_urls: Option<bool>,

    /// Enable top hosts tracking (true/false, default: true)
    #[arg(long, global = true)]
    enable_top_hosts: Option<bool>,

    /// Enable top referrers tracking (true/false, default: true)
    #[arg(long, global = true)]
    enable_top_refs: Option<bool>,

    /// HyperLogLog precision for unique-visitor counting (valid: 4-16, default: 14)
    #[arg(long, global = true)]
    hll_precision: Option<u8>,

    /// Space-Saving capacity k for approximate top tables
    /// (URLs, hosts, referrers, user-agents).
    /// Status codes are tracked exactly. (0 = auto from top_n * 100)
    #[arg(long, global = true)]
    topn_k: Option<usize>,

    /// Periodic database checkpoint interval in minutes (0 = disabled)
    #[arg(long, global = true)]
    checkpoint_minutes: Option<u64>,

    /// Run SQLite VACUUM after pruning (true/false, default: false)
    #[arg(long, global = true)]
    vacuum_after_prune: Option<bool>,

    /// Enable top-table pruning after imports (true/false, default: true; set false to disable)
    #[arg(long, global = true)]
    enable_pruner: Option<bool>,

    /// Exclude known bots from primary statistics (true/false, default: true)
    #[arg(long, global = true)]
    bot_filter: Option<bool>,

    /// Site hostname used to filter self-referrers
    #[arg(long, global = true)]
    site_host: Option<String>,

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

#[derive(Subcommand, Debug, Clone, Copy)]
enum Command {
    /// Process logs into the SQLite database
    Process,
    /// Generate static HTML reports from the SQLite database
    Generate,
    /// Process logs and then generate static HTML reports
    All,
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

    let mut cfg = if let Some(path) = explicit_config {
        config::load(path)?
    } else if let Some(path) = auto_config {
        config::load(path)?
    } else {
        config::Config::default()
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
    if let Some(v) = args.file_workers {
        cfg.file_workers = v;
    }
    if let Some(v) = args.top_n {
        cfg.top_n = v;
    }
    if let Some(v) = args.enable_top_urls {
        cfg.enable_top_urls = v;
    }
    if let Some(v) = args.enable_top_hosts {
        cfg.enable_top_hosts = v;
    }
    if let Some(v) = args.enable_top_refs {
        cfg.enable_top_refs = v;
    }
    if let Some(v) = args.hll_precision {
        cfg.hll_precision = v;
    }
    if let Some(v) = args.topn_k {
        cfg.topn_k = v;
    }
    if let Some(v) = args.checkpoint_minutes {
        cfg.checkpoint_minutes = v;
    }
    if let Some(v) = args.vacuum_after_prune {
        cfg.vacuum_after_prune = v;
    }
    if let Some(v) = args.enable_pruner {
        cfg.enable_pruner = v;
    }
    if let Some(v) = args.bot_filter {
        cfg.bot_filter = v;
    }
    if let Some(v) = &args.site_host {
        cfg.site_host = Some(v.clone());
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

    if !(4..=16).contains(&cfg.hll_precision) {
        bail!(
            "Invalid hll_precision {}: must be between 4 and 16",
            cfg.hll_precision
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
    rayon::ThreadPoolBuilder::new()
        .num_threads(cfg.file_workers.max(1))
        .build_global()
        .context("Failed to configure global rayon thread pool")?;

    let db = Database::open(&cfg.database)?;
    let geo = Geo::new(cfg.geoip_db.as_deref());
    let ua = UaParser::new();

    let mut processor = Processor::new(
        db,
        geo,
        ua,
        cfg.database.clone(),
        cfg.geoip_db.clone(),
        cfg.file_workers,
        ProcessorConfig {
            top_n: cfg.top_n,
            vacuum_after_prune: cfg.vacuum_after_prune,
            enable_pruner: cfg.enable_pruner,
            bot_filter: cfg.bot_filter,
            site_host: cfg.site_host.clone(),
            enable_top_urls: cfg.enable_top_urls,
            enable_top_hosts: cfg.enable_top_hosts,
            enable_top_refs: cfg.enable_top_refs,
            hll_precision: cfg.hll_precision,
            topn_k: effective_topn_k(cfg.top_n, cfg.topn_k),
        },
    );
    processor.set_checkpoint_interval_minutes(cfg.checkpoint_minutes);

    processor.process_globs(&cfg.log_glob)?;

    Ok(())
}

#[inline]
fn effective_topn_k(top_n: usize, topn_k: usize) -> usize {
    if topn_k == 0 {
        top_n.saturating_mul(100).max(1)
    } else {
        topn_k.max(1)
    }
}
