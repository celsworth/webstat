# Webstat PRD (Current State)

Last updated: 2026-05-10

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
- User-agent family classification.
- Optional bot filtering from primary stats.
- Optional self-referrer filtering via `site_host`.

### 5.3 Aggregation and Storage

- Store rolled-up hourly stats.
- Maintain top-N tables for URLs, hosts, referrers, agents, countries, status codes.
- Top-N heavy hitters are maintained with Space-Saving (`topn_k`, default auto from `top_n * 10`).
- Per-period unique-site counts are estimated via persisted HyperLogLog sketches (`hll_precision`, default 14).
- Prune archived top-host rows while preserving current-period fidelity.
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

## 6.1 Runtime Components

- `src/main.rs`: CLI entrypoint and command dispatch.
- `src/config.rs`: YAML parsing + config-relative path resolution.
- `src/parser.rs`: log line parsing.
- `src/processor.rs`: incremental ingestion, parallel file processing, pruning orchestration.
- `src/run_accumulators.rs`: shared in-memory accumulator state and merge logic for worker/range processing.
- `src/database.rs`: SQLite schema and write/query primitives for ingestion.
- `src/geo.rs`: GeoIP lookup/cache integration.
- `src/ua.rs`: user-agent normalization.
- `src/hll.rs`: HyperLogLog implementation used for approximate unique-site counting.
- `src/topn.rs`: Space-Saving top-N structures and period maps.
- `src/fingerprint.rs`: file content/head/tail fingerprinting used by parse-state dedupe.
- `src/progress.rs`: shared progress output helpers.
- `src/util.rs`: date/ip/url utility helpers.
- `src/reports.rs`: report orchestration, template rendering, asset extraction.
- `src/reports/aggregator.rs`: report-specific SQL summarization.
- `src/reports/charts.rs`: Chart.js dataset assembly.

## 6.2 Templates and Assets

- Templates: `templates/layout.html.tera`, `templates/index.html.tera`, `templates/year.html.tera`, `templates/month.html.tera`
- Static assets: `assets/style.css`, `assets/chart.min.js`, `assets/app.js`
- Assets are embedded at compile time and written during `generate`/`all`.

## 6.3 Data Flow

1. Read config.
2. Process logs into SQLite (optional for `generate`).
3. Query summaries for months/years.
4. Render HTML pages with Tera.
5. Write output tree and extracted assets.

## 7. Data Model (High-Level)

Primary SQLite entities include:

- `hourly_stats`
- `top_urls`
- `top_hosts`
- `top_refs`
- `top_agents`
- `top_countries`
- `status_codes`
- `daily_site_counts`
- `geo_cache`
- `parse_state`

Approximation model:

- `daily_site_counts` stores HyperLogLog blobs for mergeable unique-site estimates.
- Top-N entities are approximate heavy hitters (Space-Saving) with configurable capacity `k`.

Period conventions:

- monthly: `YYYY-MM`
- yearly: `YYYY`

## 8. Configuration Contract

Config file: `webstat.yml` (optional)

Representative fields:

- `site_name`
- `log_glob`
- `database`
- `output_dir`
- `geoip_db`
- `file_workers`
- `top_n`
- `topn_k`
- `hll_precision`
- `enable_top_urls`
- `enable_top_hosts`
- `enable_top_refs`
- `vacuum_after_prune`
- `enable_pruner`
- `bot_filter`
- `site_host`

Relative paths are resolved relative to the config file directory.

## 9. Performance and Reliability Requirements

- Must handle daily volumes on the order of millions of lines.
- Must be restart-safe and idempotent under repeated scheduled runs.
- Must avoid unbounded growth in archival top-host detail rows.
- Must generate reports deterministically from DB state.

## 10. Operational Model

- Typical run cadence: cron job.
- Deployment artifact: one compiled binary plus config and optional mmdb file.
