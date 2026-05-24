# Webstat

AI disclamer: yes, all of it. Max vibes.

A single-binary Rust web log analyser, inspired by Webalizer. Parses nginx access logs incrementally into SQLite, then generates static HTML reports using Tera templates and Chart.js.

## Build

```bash
cargo build --release
# binary at ./target/release/webstat
```

## Usage

```bash
webstat process      # parse logs into SQLite
webstat generate     # generate HTML from SQLite
webstat all          # parse then generate
webstat              # same as `all`

# Most config can be passed on the command line
webstat \
  --log-glob /var/log/nginx/access.log,/dump/logs/access* \
  --database /var/lib/webstat/webstat.db \
  --output-dir /var/www/webstat \
  --site-name "My Site" \
  -v
```

### Flags

| Flag | Description |
|---|---|
| `-c, --config <FILE>` | Config file (default: `./webstat.yml`) |
| `-v` / `-vv` / `-vvv` | Verbosity: level 1 / 2 / 3|
| `--site-name <TEXT>` | |
| `--log-glob <PATTERNS>` | Comma-separated glob patterns |
| `--database <PATH>` | |
| `--output-dir <PATH>` | |
| `--geoip-db <PATH>` | |
| `--checkpoint-minutes <N>` | `0` disables periodic checkpoints |
| `--anonymise-ips <true\|false>` | |
| `--top-n <N>` | |
| `--vacuum-after-prune <true\|false>` | |
| `--enable-top-urls <true\|false>` | |
| `--enable-top-sites <true\|false>` | |
| `--enable-top-refs <true\|false>` | |
| `--enable-all-time-unique-sites <true\|false>` | |
| `--bot-filter <true\|false>` | |
| `--site-host <HOST>` | |

## Configuration

```bash
cp webstat.yml.example webstat.yml
```

### Required

| Key | Description |
|---|---|
| `log_glob` | Comma-separated file paths or glob patterns. Relative paths resolve from the config file location. |

### Optional

| Key | Default | Description |
|---|---|---|
| `site_name` | `My Site` | Display name in HTML reports |
| `database` | `./webstat.db` | SQLite database path (created if absent) |
| `output_dir` | `./output` | Directory for generated HTML reports |
| `geoip_db` | — | Path to a MaxMind GeoLite2-Country `.mmdb` file |
| `checkpoint_minutes` | `0` | Flush partial progress to SQLite periodically. Useful for large backlogs. `0` disables. |
| `anonymise_ips` | `false` | Zero out the last IPv4 octet / last 80 IPv6 bits in reports |
| `top_n` | `20` | Rows kept per top-N table (URLs, hosts, referrers, agents, countries) when a month is finalised |
| `vacuum_after_prune` | `false` | Run `VACUUM` after pruning top-N rows. Reclaims space but is expensive. |
| `bot_filter` | `true` | Drop known bots/crawlers before aggregation (woothee + substring list) |
| `enable_top_urls` | `true` | |
| `enable_top_sites` | `true` | |
| `enable_top_refs` | `true` | |
| `enable_top_agents` | `true` | |
| `enable_all_time_unique_sites` | `true` | Store data for the All-time Unique Sites stat |

#### enable_all_time_unique_sites

This option controls whether Webstat tracks the set of unique hosts (IP addresses) that have ever visited the site across all time. This can consume significant storage space, as the number of IPs grows.

If disabled, Webstat will not track this data, and the Unique Sites stat box will be hidden from the overview report. Note that this does not affect the Unique Sites stat for individual months, which is computed from the aggregated data for that month and does not require tracking all-time unique hosts.


### Rules

Webstat supports a comprehensive rule system for ignoring requests based on URL patterns, user agents, referrers, and more.

See RULES.md for details.

### File change detection

Webstat tracks each source file in SQLite to avoid re-importing duplicates.
Before processing, each file passes through a skip hierarchy:

1. **Metadata match** — if inode, size, and mtime all match the stored state,
   the file is skipped with no reads at all.
2. **Order-based skip** — if a file's first log entry predates the most recently
   processed timestamp, and a later file in the sorted list also does, everything
   before that boundary is considered fully processed and skipped.
3. **Fingerprint match** — head fingerprints (first 8 KiB) are compared against
   stored state. Two separate fingerprints are maintained: one of the raw
   compressed bytes and one of the decompressed content. This enables
   cross-format deduplication — a `.gz` file whose decompressed content matches
   a previously processed plain log is skipped outright.
4. **Resume** — if none of the above apply, Webstat resumes from the last known
   position. For plain files this is a byte offset; for compressed files it reads
   from the start and skips the previously decoded byte count.

Inode is the primary file identity signal, so renamed or rotated files are
recognised as the same stream and not reprocessed.

## Program flow

### `process`

1. Parse CLI args and config (`src/main.rs`, `src/config.rs`)
2. Open SQLite and initialise schema (`src/database.rs`)
3. Expand globs into a file list sorted by first-line timestamp (`src/aggregator/mod.rs`)
4. Fingerprint each file and decide what to skip or resume (`src/fingerprint.rs`, `src/aggregator/resume.rs`)
5. Run a three-stage pipeline (`src/aggregator/pipeline.rs`):
   - **Loader** — reads and decompresses raw bytes into line batches (`src/loader.rs`, `src/compression.rs`)
   - **Parser** — parses combined-log-format lines, classifies user agents, drops bots (`src/parser/`)
   - **Aggregator** — updates in-memory accumulators, detects month boundaries, triggers finalisation (`src/aggregator/aggregation.rs`, `src/aggregator/flush.rs`)
6. On month finalisation: prune top-N tables, compute unique-IP counts (`src/database/writer.rs`)
7. Flush accumulators and update per-file parse state (`src/aggregator/flush.rs`, `src/database.rs`)

### `generate`

1. Query aggregated data from SQLite (`src/database.rs`)
2. Render Tera templates into static HTML (`src/reports.rs`)
3. Write HTML to `output_dir` (`src/reports.rs`)
