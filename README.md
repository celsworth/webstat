# Webstat

Webstat is a single-binary Rust web log analyzer, inspired by Webalizer.

It parses nginx access logs incrementally into SQLite, then generates static HTML reports from that database using Tera templates and Chart.js.

## Program Flow

### `process` command

- Parse CLI args and load config — `src/main.rs`, `src/config.rs`
- Initialise logging (verbosity globals) — `src/logging.rs`
- Open SQLite database and initialise schema — `src/database.rs`
- Expand glob patterns into a file list, sort by first-line timestamp — `src/processor.rs` (`process_globs`)
- For each file, fingerprint it and decide what to skip/resume — `src/fingerprint.rs`, `src/processor/resume_policy.rs`
- Seed initial progress counters from already-processed offsets — `src/processor/progress_seed.rs`
- Spawn a progress display thread — `src/processor.rs`, `src/progress.rs`
- Run the 3-stage pipeline — `src/processor/pipeline.rs`:
  - **Loader thread** — reads raw bytes, decompresses if needed, emits line batches — `src/processor/loader.rs`, `src/compression.rs`
  - **Parser thread** — parses combined-log-format lines into structured entries, runs UA classification and bot filtering; bots are dropped here — `src/processor/parser_stage.rs`, `src/parser.rs`, `src/ua.rs`
  - **Aggregator (main thread)** — consumes `ParsedEntry` values, updates in-memory accumulators, detects month boundaries and triggers `finalize_month` — `src/processor/aggregation.rs`, `src/processor/flush.rs`, `src/geo.rs`
- On month finalisation: prune top-N tables to `top_n` rows, compute and cache unique-IP counts — `src/database/writer.rs`
- Flush accumulators to SQLite at checkpoints and on completion — `src/processor/flush.rs`, `src/database.rs`
- Update per-file parse state for resume tracking — `src/database.rs`

### `generate` command

- Query aggregated data from SQLite — `src/database.rs`
- Render Tera templates into static HTML — `src/reports.rs`
- Write HTML and copy bundled assets to `output_dir` — `src/reports.rs`

## Repository Layout

- `src/` Rust source (ingestion, aggregation, report rendering)
- `templates/` editable Tera templates
- `assets/` static CSS/JS bundled into the binary
- `webstat.yml` runtime configuration
- `webstat.yml.example` example configuration
- `GeoLite2-Country.mmdb` optional local GeoIP database

## Build

```bash
cargo build --release
```

Binary path:

```bash
./target/release/webstat
```

## Commands

```bash
# Process logs into SQLite (default command)
./target/release/webstat process -c webstat.yml -v

# Generate static HTML from SQLite
./target/release/webstat generate -c webstat.yml -v

# Process then generate (default if no subcommand supplied)
./target/release/webstat all -c webstat.yml -v

# No YAML required: pass config on the command line
./target/release/webstat all \
  --log-glob /var/log/nginx/access.log,/dump/logs/access* \
  --database /var/lib/webstat/webstat.db \
  --output-dir /var/www/webstat \
  --site-name "My Site" \
  -v
```

Global flags:

- `-c, --config <FILE>` optional config file path
- `-v, --verbose` counted verbosity levels:
  - `-v` verbose progress/log output
  - `-vv` enables debug level 1 (most planning/debug lines)
  - `-vvv` enables debug level 2 (includes extra noisy planning lines)
- `--site-name <TEXT>`
- `--log-glob <PATTERNS>` comma-separated glob patterns
- `--database <PATH>`
- `--output-dir <PATH>`
- `--geoip-db <PATH>`
- `--file-workers <N>`
- `--checkpoint-minutes <N>` (`0` disables periodic checkpoints)
- `--top-n <N>`
- `--vacuum-after-prune <true|false>`
- `--enable-top-urls <true|false>`
- `--enable-top-hosts <true|false>`
- `--enable-top-refs <true|false>`
- `--bot-filter <true|false>`
- `--site-host <HOST>`

## Configuration

Copy and edit the example as needed:

```bash
cp webstat.yml.example webstat.yml
```

### Required Settings

- **`site_name`** — Display name in HTML reports (e.g., `"My Site"`).

- **`log_glob`** — Required log source patterns (comma-separated):
  - Example: `"/var/log/nginx/access.log,/dump/logs/access*"`
  - Each entry can be a single file path or a glob pattern.
  - Relative entries are resolved relative to the config file location.

- **`database`** — SQLite database path (will be created if absent). Can be relative.

- **`output_dir`** — Directory where static HTML reports are written. Can be relative.

### Optional Settings

- **`geoip_db`** — Path to MaxMind GeoLite2-Country `.mmdb` file. Leave unset to skip GeoIP lookups. Can be relative.

- **`file_workers`** — Number of parallel worker threads. Default: `1`. (Multi-file parallel dispatch is not yet wired; this setting is accepted but currently has no effect.)

- **`checkpoint_minutes`** — Periodic SQLite checkpoint interval in minutes. Default: `0` (disabled).
  - Set to a positive value to flush partial aggregates and parse progress during long runs.
  - Helps reduce lost work if processing is interrupted.

- **`top_n`** — Number of rows to keep in top-N tables (URLs, hosts, referrers, agents, countries). Default: `20`.
  - When a month is finalised, each top-N table is pruned to this many rows per period.

- **`vacuum_after_prune`** — Run `VACUUM` on the database after pruning old top-N rows. Default: `false`.
  - Reclaims disk space but is expensive on large databases.

- **`bot_filter`** — Exclude known bots/crawlers from all statistics. Default: `true`.
  - Bot detection runs in the parser thread; filtered entries are discarded before reaching the aggregator and are not counted anywhere.

- **`enable_top_urls`** — Enable tracking of top URLs. Default: `true`.

- **`enable_top_hosts`** — Enable tracking of top hosts/IPs. Default: `true`.

- **`enable_top_refs`** — Enable tracking of top referrers. Default: `true`.

### Backfill Order Requirement

If you are doing the initial population of a new database across multiple import runs, run those imports strictly in date order (oldest to newest).

Out-of-order backfills can cause period snapshot behavior to retain or freeze the wrong periods, which can produce unexpected aggregates.

### File Change Detection

Webstat makes significant efforts not to re-import duplicates. To do this, it tracks each source file with an SQLite state record. The current rules are:

- `inode` is the primary identity signal. If the same inode appears under a new name (file rename), Webstat treats it as the same stream and does not reprocess it.
- `file_size` and `mtime_ns` are stored for the last processed view of the file.
- A head fingerprint is stored from the content stream using first 8 KiB samples.
  For plain logs this is raw file bytes; for `.gz`/`.bz2` logs this is decompressed bytes.
- A content fingerprint is stored when a file is fully processed, which allows exact skip of already-seen content.

For plain text logs:

- If `file_size` grows, Webstat resumes from the stored byte offset and processes only the new tail data.
- If `file_size` shrinks, Webstat treats that as truncation/copy-truncate and restarts that live path from offset `0`.
- If a rotated file later appears with the same fingerprints as a previously seen file, Webstat can inherit the prior byte offset from the archived state and avoid reprocessing the already-seen data.

For bz2/gzip logs:

- A `.bz2` or `.gz` file with the same decompressed content as a previously processed plain log is skipped via content fingerprint dedupe.
- A stable `.bz2` or `.gz` file is skipped after a successful full pass.
- If a `.bz2` or `.gz` file grows and inode is unchanged, Webstat seeks to the stored compressed offset and resumes from there.

### Example Config

```yaml
site_name: "My Site"
log_glob: logs/access.log,logs/access.log.*
database: webstat.db
output_dir: output
geoip_db: GeoLite2-Country.mmdb
top_n: 20
bot_filter: true
```

## Runtime Outputs

- SQLite DB at `database` path (often `./webstat.db`)
- Generated site at `output_dir` (often `./output`)
- Extracted report assets at `output_dir/assets`

## Assumptions and Limitations

### Unique visitor counts are exact

Unique visitor counts (displayed as "Sites" in reports) are counted exactly. Every unique IP address seen on a given day is recorded in the `daily_ip_log` table; the composite primary key `(date, ip_kind, ip_hi, ip_lo)` deduplicates naturally via `INSERT OR IGNORE`. Monthly and yearly unique-IP counts are precomputed into `site_count_cache` using `SELECT DISTINCT` when each month is finalised.

IPv4 and IPv6 addresses are stored in decomposed numeric form (`ip_hi`/`ip_lo` as integers), not as text, for efficient deduplication and compact storage.

### Visits Metric Tradeoff

Webstat defines a visit using a 30-minute inactivity window per remote host.

Visit state is loaded from SQLite at the start of each run and written back on completion. This means visit continuity is correctly maintained across separate process invocations, but a single visit that crosses a logfile boundary within a single run may be counted as two visits if files are not processed in strict chronological order.

### Top tables

URL, hostname, referrer, user-agent, and country tables accumulate exact counts during ingestion. When a month is finalised, each table is pruned to the `top_n` highest-count rows for that period. Items outside the top N are discarded at finalisation time and are not recoverable.
