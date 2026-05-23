# Webstat

Webstat is a single-binary Rust web log analyzer, inspired by Webalizer.

It parses nginx access logs incrementally into SQLite, then generates static HTML reports from that database using Tera templates and Chart.js.

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
- `--anonymise-ips <true|false>`
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

- **`checkpoint_minutes`** — Periodic SQLite checkpoint interval in minutes. Default: `0` (disabled).
  - Set to a positive value to flush partial aggregates and parse progress during long runs.
  - Checkpoints run after every month is finalised but this can help if you have a very large backlog of logs.
  - Helps reduce lost work if processing is interrupted.

- **`anonymise_ips`** — Anonymise IP addresses in the HTML reports by zeroing out the last octet (IPv4) or last 80 bits (IPv6). Default: `false`.

- **`top_n`** — Number of rows to keep in top-N tables (URLs, hosts, referrers, agents, countries). Default: `20`.
  - When a month is finalised, each top-N table is pruned to this many rows per period.

- **`vacuum_after_prune`** — Run `VACUUM` on the database after pruning old top-N rows. Default: `false`.
  - Reclaims disk space but is expensive on large databases.

- **`bot_filter`** — Exclude known bots/crawlers from all statistics. Default: `true`.
  - Bot detection runs in the parser thread; filtered entries are discarded before reaching the aggregator and are not counted anywhere.
  - This uses woothee crawler detection and a list of known bot user agent substrings.

- **`enable_top_urls`** — Enable tracking of top URLs. Default: `true`.

- **`enable_top_hosts`** — Enable tracking of top hosts/IPs. Default: `true`.

- **`enable_top_refs`** — Enable tracking of top referrers. Default: `true`.

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

## Program Flow

### `process` command

- Parse CLI args and load config — `src/main.rs`, `src/config.rs`
- Initialise logging (verbosity globals) — `src/logging.rs`
- Open SQLite database and initialise schema — `src/database.rs`
- Expand glob patterns into a file list, sort by first-line timestamp — `src/aggregator/mod.rs` (`process_globs`)
- For each file, fingerprint it and decide what to skip/resume — `src/fingerprint.rs`, `src/aggregator/resume.rs`
- Seed initial progress counters from already-processed offsets — `src/aggregator/progress_seed.rs`
- Spawn a progress display thread — `src/aggregator/mod.rs`, `src/progress.rs`
- Run the 3-stage pipeline — `src/aggregator/pipeline.rs`:
  - **Loader thread** — reads raw bytes, decompresses if needed, emits line batches — `src/loader.rs`, `src/compression.rs`
  - **Parser thread** — parses combined-log-format lines into structured entries, runs UA classification and bot filtering; bots are dropped here — `src/parser/stage.rs`, `src/parser/mod.rs`, `src/ua.rs`
  - **Aggregator (main thread)** — consumes `ParsedEntry` values, updates in-memory accumulators, detects month boundaries and triggers `finalize_month` — `src/aggregator/aggregation.rs`, `src/aggregator/flush.rs`, `src/geo.rs`
- On month finalisation: prune top-N tables to `top_n` rows, compute and cache unique-IP counts — `src/database/writer.rs`
- Flush accumulators to SQLite at checkpoints and on completion — `src/aggregator/flush.rs`, `src/database.rs`
- Update per-file parse state for resume tracking — `src/database.rs`

### `generate` command

- Query aggregated data from SQLite — `src/database.rs`
- Render Tera templates into static HTML — `src/reports.rs`
- Write HTML and copy bundled assets to `output_dir` — `src/reports.rs`
