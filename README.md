# Webstat

Webstat is a single-binary Rust web log analyzer, inspired by Webalizer.

It parses nginx access logs incrementally into SQLite, then generates static HTML reports from that database using Tera templates and Chart.js.

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
- `--topn-k <N>` (`0` means auto from `top_n × 100`)
- `--hll-precision <4..16>`
- `--vacuum-after-prune <true|false>`
- `--enable-pruner <true|false>`
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

- **`file_workers`** — Number of parallel worker threads for processing multiple log files. Default: `1`.
  - Set to `2`–`4` for faster multi-file ingestion (e.g., in `log_dir` mode).
  - Increases memory use; benchmark on your machine.

- **`checkpoint_minutes`** — Periodic SQLite checkpoint interval in minutes. Default: `0` (disabled).
  - Set to a positive value to flush partial aggregates and parse progress during long runs.
  - Helps reduce lost work if processing is interrupted.

- **`top_n`** — Number of rows to keep in top-N tables (URLs, hosts, referrers, agents, countries). Default: `20`.
  - Smaller values reduce DB size; larger values preserve more history for reports.

- **`topn_k`** — Space-Saving algorithm capacity (k) for approximate top tables (URLs, hosts, referrers, user-agents). Default: `0` (auto-derives as `top_n × 100`).
  - Higher values improve accuracy at the cost of more in-memory sketch size per period. The default is already conservative; most deployments can leave this unset.

- **`vacuum_after_prune`** — Run `VACUUM` on the database after pruning old top-N rows. Default: `false`.
  - Reclaims disk space but is expensive on large databases.

- **`enable_pruner`** — Enable top-N table pruning after imports. Default: `true`.
  - Set to `false` during initial backfills when data cannot be imported strictly in date order.
  - Disabling pruning can significantly increase SQLite database size.

- **`bot_filter`** — Exclude known bots/crawlers from primary statistics. Default: `true`.
  - Bots are still recorded but in separate tracking; reports focus on human traffic.

- **`enable_top_urls`** — Enable tracking of top URLs. Default: `true`.
  - Set to `false` to skip URL heavy-hitter tracking and reduce processing CPU/memory if you do not use top-URLs reports.

- **`enable_top_hosts`** — Enable tracking of top hosts/IPs. Default: `true`.
  - Set to `false` to skip host heavy-hitter tracking and reduce processing CPU/memory if host ranking is not needed.

- **`enable_top_refs`** — Enable tracking of top referrers. Default: `true`.
  - Set to `false` to skip referrer heavy-hitter tracking and reduce processing CPU/memory if referrer analysis is not important.

- **`site_host`** — Hostname of the site (e.g., `"example.com"`). Optional.
  - If set, referrers matching this host are excluded from `top_refs` to reduce noise.

- **`hll_precision`** — HyperLogLog precision for unique-visitor (Sites) counting. Valid range: 4–16. Default: `14` (~16 KiB RAM per period, ~1–2% typical error).
  - Higher values reduce error but increase memory and SQLite blob size.
  - **WARNING:** This value is baked into the HLL register blobs stored in SQLite. Do **not** change it on an existing database — doing so corrupts unique-visitor counts. Only set this before the first `process` run, or after wiping the database.


### Backfill Order Requirement

If you are doing the initial population of a new database across multiple import runs, run those imports strictly in date order (oldest to newest).

Out-of-order backfills can cause pruning and period snapshot behavior to retain or freeze the wrong periods, which can produce unexpected aggregates.

If strict ordering is not possible, set `enable_pruner: false` (or pass `--enable-pruner false`) during initial imports, then re-enable pruning afterwards. Note that this can significantly increase SQLite database size while pruning is disabled.

### File Change Detection

Webstat makes significant efforts not to re-import duplicates. To do this, it tracks each source file with an SQLite state record. The current rules are:

- `inode` is the primary identity signal. If the same inode appears under a new name (file rename), Webstat treats it as the same stream and does not reprocess it.
- `file_size` and `mtime_ns` are stored for the last processed view of the file.
- A head fingerprint and a tail fingerprint are stored from the content stream using first/last 8 KiB samples.
  For plain logs this is raw file bytes; for `.gz` logs this is decompressed bytes.
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
file_workers: 2
top_n: 20
enable_pruner: true
bot_filter: true
```

## Runtime Outputs

- SQLite DB at `database` path (often `./webstat.db`)
- Generated site at `output_dir` (often `./output`)
- Extracted report assets at `output_dir/assets`

## Assumptions and Limitations

### Unique visitor counts are approximate

Unique visitor counts (displayed as "Sites" in reports) are estimated using a custom [HyperLogLog](https://algo.inria.fr/flajolet/Publications/FlFuGaMe07.pdf) sketch per time period, stored as a compact byte blob in SQLite. HLL is a probabilistic cardinality estimator: it uses a small fixed amount of memory (16 KiB at precision 14) regardless of traffic volume, at the cost of a typical error rate of around 1–2%. The estimates are unbiased — they are equally likely to be slightly high as slightly low — and are accurate enough for web analytics purposes.

The sketches are mergeable: per-day sketches are combined into monthly and yearly counts without re-reading raw IP data.

### Visits Metric Tradeoff

Webstat defines a visit using a 30-minute inactivity window per remote host.

To preserve multi-file parsing throughput, visit continuity is tracked within each processed file stream and is not stitched across different files. This means a single visit that crosses a logfile boundary may be counted as two visits.

This is an intentional speed-vs-accuracy tradeoff for multi-file parallel ingestion and in practise shouldn't matter much.

### Top tables and approximation

URL, hostname, referrer, and user-agent tables are maintained using the [Space-Saving algorithm](https://www.cs.ucsb.edu/research/tech-reports/2005-23) (also known as the "frequent items" algorithm). Space-Saving guarantees that every item whose true count exceeds `1/k` of the total is tracked, and that stored counts overestimate true counts by at most `ε × N` where `ε = 1/k` and `N` is the stream length. In practice the overcount is tiny and the top items are exact. The only approximation is at the margins: items near the eviction threshold may be slightly over- or under-counted relative to one another.

The capacity `k` defaults to `top_n × 100`, and can be adjusted in the config.

