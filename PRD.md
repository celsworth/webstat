# Webstat PRD (Current State)

Last updated: 2026-05-22

## 1. Product Summary

Webstat is a self-hosted, static web analytics pipeline for nginx access logs.

It is implemented as a single Rust binary that:

1. Ingests logs incrementally into SQLite.
2. Aggregates monthly/yearly analytics views.
3. Generates static HTML reports.

Primary deployment model is scheduled execution (for example via cron) on one host for one site/log namespace.

## 2. Goals

- Provide Webalizer-style analytics without SaaS dependencies.
- Keep operations simple: one binary + YAML config + SQLite + static output.
- Support large daily log volumes with predictable runtime.
- Keep reports fully static (no backend service required for viewing).
- Keep report templates editable in-repo.

## 3. Non-Goals

- Multi-tenant dashboards.
- Real-time streaming analytics UI.
- Distributed ingestion/storage.
- Dynamic server-rendered report backend.

## 4. Users and Use Cases

Users:

- Operators of personal sites, blogs, and small production properties.
- Engineers who want local ownership of traffic analytics.

Core use cases:

- Hourly/daily cron ingestion of rotated nginx logs.
- On-demand or scheduled regeneration of monthly/yearly reports.
- Historical trend inspection (hits, pages, bandwidth, status codes, top entities).

## 5. Functional Requirements

### 5.1 Ingestion

- Parse nginx combined log lines (plain / bz2 / gzip files).
- Incrementally process from last known byte offset.
- Detect rotation via inode and resume safely.
- Support one or more source patterns via comma-separated `log_glob`
  (single files and glob patterns are both valid).

### 5.2 Enrichment

- Optional GeoIP country lookup via GeoLite2-Country mmdb.
- User-agent family classification (runs in the parser thread).
- Optional bot filtering in the parser stage — bots are dropped before reaching the aggregator.
- Optional self-referrer filtering via `site_host`.

### 5.3 Aggregation and Storage

- Store rolled-up hourly stats.
- Maintain top-N tables for URLs, hosts, referrers, agents, countries, status codes.
  - Top-N tables accumulate exact counts during ingestion.
  - When a month is finalised, each table is pruned to the top `top_n` rows per period.
- Per-day unique IP addresses are recorded exactly in `daily_ip_log` (INSERT OR IGNORE on a composite PK enforces deduplication).
- Monthly and yearly unique-IP counts are precomputed into `site_count_cache` when a month is finalised.
- Optional post-prune VACUUM.
- Allow disabling top URLs/hosts/referrers tracking to reduce processing overhead.

### 5.4 Report Generation

- Generate static pages:
  - overview index
  - per-year pages
  - per-month pages
- Render through Tera templates under `templates/`.
- Include summary tables and chart datasets.
- Emit local assets to `output/assets` at generation time.
- Omit top/chart sections when their datasets are empty (no empty placeholder sections).

### 5.5 CLI

- `process`: ingest/update SQLite
- `generate`: render HTML from SQLite
- `all`: process then generate
- default command behavior: `all`

Global flags:

- `-c, --config` (optional)
- `-v, --verbose` (counted)
  - `-v`: verbose output
  - `-vv`: debug level 1
  - `-vvv`: debug level 2
- All config keys can also be supplied as CLI flags.

## 6. Architecture

### 6.1 Runtime Components

- `src/main.rs`: CLI entrypoint and command dispatch.
- `src/config.rs`: YAML parsing + config-relative path resolution.
- `src/parser.rs`: log line parsing → `OwnedLogEntry`.
- `src/processor.rs`: orchestration, file discovery, resume planning, progress thread.
- `src/processor/pipeline.rs`: 3-stage Loader→Parser→Aggregator pipeline.
- `src/processor/loader.rs`: raw file reading and decompression.
- `src/processor/parser_stage.rs`: text→struct parsing, UA classification, bot filtering.
- `src/processor/aggregation.rs`: per-entry aggregation into `RunAccumulators`.
- `src/processor/flush.rs`: flushing accumulators to SQLite.
- `src/processor/resume_policy.rs`: per-file skip/resume decisions.
- `src/processor/progress_seed.rs`: initial progress seeding from DB state.
- `src/accumulators.rs`: `HourlyStats`, `HourlyAcc`, `HourlyMap` types.
- `src/run_accumulators.rs`: `RunAccumulators` — in-memory aggregation buffers.
- `src/database.rs`: SQLite schema and connection wrapper.
- `src/database/writer.rs`: flush, finalize_month, pruning.
- `src/database/parse_state.rs`: parse state queries.
- `src/database/visit_state.rs`: visit state queries.
- `src/database/maintenance.rs`: vacuum, meta ops.
- `src/geo.rs`: GeoIP lookup/cache integration.
- `src/ua.rs`: user-agent normalisation and bot detection (parser thread only).
- `src/fingerprint.rs`: file content fingerprinting for parse-state dedupe.
- `src/progress.rs`: progress display helpers.
- `src/util.rs`: date/ip/url utility helpers.
- `src/reports.rs`: report orchestration, template rendering, asset extraction.
- `src/reports/aggregator.rs`: report-specific SQL summarisation.
- `src/reports/charts.rs`: Chart.js dataset assembly.

### 6.2 Templates and Assets

- Templates: `templates/layout.html.tera`, `templates/index.html.tera`, `templates/year.html.tera`, `templates/month.html.tera`
- Static assets: `assets/style.css`, `assets/chart.min.js`, `assets/app.js`
- Assets are embedded at compile time and written during `generate`/`all`.

### 6.3 Data Flow

1. Read config.
2. Process logs into SQLite (optional for `generate`).
3. Query summaries for months/years.
4. Render HTML pages with Tera.
5. Write output tree and extracted assets.

## 7. Data Model (High-Level)

Primary SQLite tables:

- `hourly_stats` — (date, hour) keyed hourly aggregates (hits, visits, pages, files, bandwidth, status buckets)
- `monthly_urls_hits` — top URLs by hits per period
- `monthly_urls_bandwidth` — top URLs by bandwidth per period
- `monthly_hosts_hits` — top hosts/IPs by hits per period (structured IP storage)
- `monthly_hosts_bandwidth` — top hosts/IPs by bandwidth per period
- `monthly_refs` — top referrers per period
- `monthly_agents` — top user-agent families per period
- `top_countries` — country hit counts per period
- `status_codes` — HTTP status code counts per period
- `method_counts` — HTTP method counts per period
- `proto_counts` — HTTP protocol counts per period
- `daily_ip_log` — exact unique IP records per day; composite PK `(date, ip_kind, ip_hi, ip_lo)` deduplicates naturally
- `site_count_cache` — precomputed monthly/yearly distinct-IP counts
- `all_time_hosts` — all-time host records for overall unique-visitor count
- `country_code_names` — country code→name mapping
- `meta` — key-value store (e.g. `current_month`)
- `parse_state` — per-file resume state (inode, offsets, fingerprints, completed flag)
- `parse_state_archive` — superseded file states kept for fingerprint-based dedup
- `visit_state` — per-IP last-seen timestamps for session tracking

Counting model:

- Unique IP counts are **exact**. `daily_ip_log` stores every unique `(date, ip)` tuple. `site_count_cache` holds precomputed `SELECT DISTINCT` results per month and year, populated by `finalize_month`.
- Top-N tables hold exact counts, pruned to `top_n` rows per period at month finalisation.

Period conventions:

- monthly: `YYYY-MM`
- yearly: `YYYY`

## 8. Configuration Contract

Config file: `webstat.yml` (optional)

Fields:

- `site_name`
- `log_glob`
- `database`
- `output_dir`
- `geoip_db`
- `file_workers` (parsed; parallel multi-file dispatch not yet wired)
- `top_n` (default 20)
- `enable_top_urls` (default true)
- `enable_top_hosts` (default true)
- `enable_top_refs` (default true)
- `vacuum_after_prune` (default false)
- `bot_filter` (default true)
- `site_host`
- `checkpoint_minutes` (default 0)

Relative paths are resolved relative to the config file directory.

## 9. Performance and Reliability Requirements

- Must handle daily volumes on the order of millions of lines.
- Must be restart-safe and idempotent under repeated scheduled runs.
- Must generate reports deterministically from DB state.

## 10. Operational Model

- Typical run cadence: cron job.
- Deployment artifact: one compiled binary plus config and optional mmdb file.
