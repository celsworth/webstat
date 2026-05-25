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
| `bot_filter` | `true` | Drop known bots/crawlers before aggregation (woothee + substring list) |
| `enable_top_urls` | `true` | |
| `enable_top_sites` | `true` | |
| `enable_top_refs` | `true` | |
| `enable_top_agents` | `true` | |

### Style

All report colours can be overridden under the `style:` key. Any key omitted uses the built-in default. Overrides apply to both light and dark mode.

```yaml
style:
  bar_hits: "#52c493"
  accent: "#2f61d4"
```

#### Theme

| Key | Default | Affects |
|---|---|---|
| `bg` | `#eef1f5` | Page background |
| `surface` | `#ffffff` | Card / panel backgrounds |
| `surface_alt` | `#f4f6fa` | Table header backgrounds, hover |
| `border` | `#d7dce5` | All borders and dividers |
| `text` | `#1f2532` | Body text |
| `text_muted` | `#60697a` | Labels, secondary text |
| `accent` | `#2f61d4` | Links, heading highlight, focus ring |
| `accent_hover` | `#244ca7` | Hovered links |

#### Metric UI colours

Used for stat card top borders and table header text.

| Key | Default | Metric |
|---|---|---|
| `metric_hits` | `#52c493` | Hits |
| `metric_files` | `#7090ff` | Files |
| `metric_pages` | `#66ddff` | Pages |
| `metric_visits` | `#bfa800` | Visits |
| `metric_sites` | `#ffc055` | Sites |
| `metric_bandwidth` | `#ff7a7a` | Bandwidth |

#### Status table row backgrounds

| Key | Default |
|---|---|
| `status_2xx_bg` | `#52c49324` |
| `status_3xx_bg` | `#7090ff24` |
| `status_4xx_bg` | `#ffc0552e` |
| `status_5xx_bg` | `#ff7a7a29` |
| `status_other_bg` | `#a0a0a01f` |
| `weekend_bg` | `#2f61d414` |

#### Chart bar / line colours

| Key | Default | Used in |
|---|---|---|
| `bar_hits` | `#52c493` | Hits bars (daily, hourly, monthly, yearly) |
| `bar_hits_weekend` | `#5bb4b3` | Hits bars on weekend days |
| `bar_visits` | `#ffea66` | Visits bars |
| `bar_visits_weekend` | `#d4cf94` | Visits bars on weekend days |
| `bar_sites` | `#ffc055` | Sites bars |
| `bar_sites_weekend` | `#d4b288` | Sites bars on weekend days |
| `line_bandwidth` | `#ff7a7a` | Bandwidth line overlay |

#### Status doughnut chart colours

| Key | Default |
|---|---|
| `status_2xx_color` | `#52c493` |
| `status_3xx_color` | `#7090ff` |
| `status_4xx_color` | `#ffc055` |
| `status_5xx_color` | `#ff7a7a` |
| `status_other_color` | `#bab0ac` |

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
