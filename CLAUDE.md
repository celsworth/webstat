# webstat

A Rust web access-log processor. Parses nginx/Apache combined-format logs, aggregates traffic statistics, and stores results in SQLite.

## Build & test

```
cargo build
cargo test
```

## Architecture

- **`src/main.rs`** — CLI entry point (clap), subcommands, config loading
- **`src/config.rs`** — YAML config parsing and path resolution
- **`src/loader.rs`** — reads raw bytes, decompresses if needed, emits `LoaderMsg::Lines` batches
- **`src/parser/mod.rs`** — `LogEntry` type and string-slice accessors; `LogFormat` enum and dispatch; timestamp arithmetic (`days_from_civil`, `parse_unix_timestamp`); no pipeline, UA, or rule dependencies
- **`src/parser/combined.rs`** — combined-log-format line parser; also parses extended `us=` upstream-response-time fields
- **`src/parser/stage.rs`** — parser pipeline thread: parses lines, applies UA classification, bot filtering, and rules, forwards batches to the aggregator
- **`src/aggregator/mod.rs`** — `Processor` struct: file discovery, resume planning, progress thread, checkpoint scheduling, and the public `process_globs` entry point
- **`src/aggregator/pipeline.rs`** — 3-stage Loader→Parser→Aggregator pipeline; aggregator runs on the calling thread; drives checkpointing and file-done accounting
- **`src/aggregator/aggregation.rs`** — per-entry aggregation into `RunAccumulators`; visit (session) counting
- **`src/aggregator/flush.rs`** — flushes `RunAccumulators` to SQLite; handles month-boundary finalisation and saves parse/visit state after each checkpoint
- **`src/aggregator/messages.rs`** — `LoaderMsg`, `ParserMsg`, `ParsedEntry` channel types; push/pop blocking helpers
- **`src/aggregator/resume.rs`** — per-file skip/resume decisions using fingerprints and stored state
- **`src/aggregator/progress_seed.rs`** — seeds initial progress counters from DB state
- **`src/accumulators.rs`** — `HourlyStats`, `HourlyAcc`, `HourlyMap` types
- **`src/run_accumulators.rs`** — `RunAccumulators`: in-memory aggregation buffers (hourly, URLs, hosts, refs, agents, countries, IPs, status codes, buckets, etc.)
- **`src/ip.rs`** — `Ip` enum: IPv4 as `u32`, IPv6 as `u128`. Also `IpBitmaps`: per-date accumulator using `RoaringBitmap` (IPv4) and `AHashMap<u64, RoaringTreemap>` (IPv6, keyed by upper-64 prefix)
- **`src/rules.rs`** — YAML-configured per-entry filtering rules (`ignore`, `hide`, `sample`, `bucket` actions); compiled from `RawRule` in config and evaluated in the parser thread
- **`src/database.rs`** — SQLite connection wrapper: schema initialisation, WAL mode, and module re-exports
- **`src/database/writer.rs`** — `flush_data`, `finalize_month`, `cull_period`, per-period pruning
- **`src/database/parse_state.rs`** — parse state load/save
- **`src/database/visit_state.rs`** — visit state load/save
- **`src/database/maintenance.rs`** — vacuum, meta key-value ops
- **`src/compression.rs`** — `CompressionType` enum (`Plain`, `Gz`, `Bz2`, `Br`) and extension detection
- **`src/fingerprint.rs`** — file identity: head-hash fingerprints and logical sizes for plain and compressed files
- **`src/geo.rs`** — GeoIP lookup and per-run cache
- **`src/ua.rs`** — UA family classification and bot detection; runs in the parser thread
- **`src/response_time.rs`** — `ResponseTimeHistogram`: 1 ms-bucket histogram (0–60,000 ms); supports `record`, `merge`, `percentile`, `avg`, and binary serialize/deserialize for SQLite storage
- **`src/rollback.rs`** — `rollback` subcommand: deletes all aggregated data from a given month boundary onward, resets parse state so the next `process` run re-ingests affected files
- **`src/reports.rs`** — HTML report generation via Tera templates
- **`src/reports/aggregator.rs`** — report-specific SQL summarisation; includes `weekday_hour_grid` (Mon–Sun × 0–23h hits heatmap, derived from `hourly_stats` at report time — no stored table)
- **`src/reports/charts.rs`** — Chart.js dataset assembly
- **`src/tests/mod.rs`** — integration test suite root; unit tests stay co-located with their modules
- **`src/tests/pipeline.rs`** — integration tests: file resume, gzip fingerprinting, month boundaries, rules, rollback + re-ingest cycles
- **`src/tests/reports.rs`** — integration tests: end-to-end report generation via `process_globs` + `generate_html`

## Pipeline

Each run of `process_globs` spawns a 3-stage pipeline:

```
Loader thread  →(LoaderMsg)→  Parser thread  →(ParserMsg)→  Aggregator (main thread)
```

- **Loader** reads files sequentially, decompresses if needed, emits `LoaderMsg::Lines` batches of `(String, offset)` pairs.
- **Parser** calls `LogEntry::parse`, then `UaParser::parse` for each line. Bot entries are dropped immediately if `bot_filter` is enabled. Rules are evaluated here; entries can be ignored, hidden from top-N tables, sampled, or tagged into a bucket. Non-bot entries are wrapped in `ParsedEntry { entry, ua_family }` and sent as `ParserMsg::Entries` batches.
- **Aggregator** calls `aggregate_entry` for each `ParsedEntry`, updating `RunAccumulators`. It detects month boundaries and calls `finalize_and_advance_month` as needed.

`UaParser` lives entirely in the parser thread; `Processor` does not own one.

## Compression

Supported formats detected by file extension:

| Extension | Decoder |
|-----------|---------|
| `.gz`     | `flate2::read::MultiGzDecoder` |
| `.bz2`    | `bzip2::read::MultiBzDecoder` |
| `.br`     | `brotli::Decompressor` |
| (none)    | plain read with seek |

Compressed files have no random access — they resume by decoding from the start and skipping already-processed bytes (`skip_decoded_prefix_bytes`). Plain files resume via byte offset seek.

## Unique IP / site counting

Unique IP counting is exact, not approximate, and uses roaring bitmaps for compact storage.

**In-memory accumulation**: `RunAccumulators.daily_ips` maps each date to an `IpBitmaps`. IPv4 addresses (u32) go into a `RoaringBitmap`; IPv6 addresses are split at 64 bits — the upper 64 select a `RoaringTreemap` entry, the lower 64 are stored in it.

**SQLite layout** (`daily_unique_ips`): one row per `(date, ip_kind, ip_hi)` group. A `count` column mirrors the bitmap cardinality so SQL can aggregate per-day counts without deserialising blobs. Flush is a read-modify-write: load existing blob, OR in new data, write back.

**`finalize_month`**: ORs all `daily_unique_ips` blobs for the month into a monthly bitmap. Saves that bitmap to `monthly_unique_ips` (one row per `(period, ip_kind, ip_hi)`). Recomputes the yearly count by ORing all `monthly_unique_ips` rows for the year and writes it to `unique_visitor_counts`. Writes the monthly count to `unique_visitor_counts` as well. Populates `daily_visitor_counts` from the `count` column, then deletes `daily_unique_ips` rows for the month. `finalize_year` is a no-op — the yearly count is kept current by `finalize_month`.

**Reports**: daily counts use `SUM(count)` SQL. Monthly/yearly counts read from `unique_visitor_counts` cache; for in-progress periods (no cache entry yet), fall back to loading and ORing blobs in Rust.

**Per-bucket unique IP counting** mirrors the global flow. `BucketAcc.daily_ips` accumulates per-date bitmaps; `flush` writes them to `bucket_daily_unique_ips`. `finalize_month` ORs those into a monthly bitmap, writes the count to `bucket_unique_visitor_counts` (period `YYYY-MM`), saves the snapshot to `bucket_monthly_unique_ips`, then ORs all of that year's snapshots and writes a yearly entry to `bucket_unique_visitor_counts` (period `YYYY`). Rollback deletes affected `bucket_monthly_unique_ips` rows and calls `recompute_yearly_bucket_counts` to rebuild yearly entries from surviving snapshots.

## Visit / session counting

A *visit* is a sequence of requests from the same IP with no gap longer than 30 minutes (`VISIT_TIMEOUT_SECONDS = 30 * 60`). The aggregator maintains a `visit_last_seen` map (`VisitStateKey → timestamp`) in memory. Each entry increments `hourly_stats.visits` only when the gap since last seen exceeds the timeout.

Visit state is persisted to the `visit_state` SQLite table (columns: `ip_kind`, `ip_hi`, `ip_lo`, `ip_text`, `last_seen_ts`) and reloaded at startup, so the session window survives process restarts and cross-file gaps. Stale entries (last seen before `visit_max_seen_ts - timeout`) are pruned from the table at each checkpoint.

## Bucket system

Rules with `action: bucket: <name>` tag matching entries into named buckets (e.g. `api`, `static`). Bucketing is additive — an entry is still counted in all global tables. The first matching `bucket` rule wins.

**In-memory**: `RunAccumulators.bucket_stats` maps bucket name to `BucketAcc`, which carries hits, bandwidth, RT histogram, status codes, agents, countries, method/protocol counts, URL stats, and per-date `IpBitmaps`.

**SQLite tables**: `bucket_period_stats`, `bucket_urls`, `bucket_status_codes`, `bucket_agents`, `bucket_countries`, `bucket_method_counts`, `bucket_protocol_counts`, `bucket_response_time_histograms`, `bucket_hourly_stats`, `bucket_daily_unique_ips`, `bucket_daily_visitor_counts`, `bucket_monthly_unique_ips`, `bucket_unique_visitor_counts`, `bucket_daily_response_time_histograms`, `bucket_daily_response_time_stats`.

**Reports**: each period page shows a Buckets summary table (hits, bandwidth, avg RT, unique sites). Each bucket has a sub-page (`buckets/<slug>/index.html`) with the same breakdown panels as a period page. Unique sites on yearly pages come from the `bucket_unique_visitor_counts` yearly cache written by `finalize_month`.

## Top-N tables

Top-N tables (`top_urls`, `top_ips`, `top_referrers`, `top_agents`) accumulate exact counts during ingestion. Two cleanup operations keep them from growing unbounded:

**Culling** (`cull_period`, called at each checkpoint and end-of-run): removes rows with no realistic chance of appearing in the final top `top_n`. A row is culled when every tracked metric is below 1/10th of the current N-th-best value. The guard `row_count > top_n * 50` ensures culling only fires when the table is well above the safety margin, making it safe to run mid-month.

**Trimming** (`finalize_month`): prunes each table to exactly the top `top_n` rows per period.

Each table can be individually disabled via config flags (`enable_top_urls`, `enable_top_sites`, `enable_top_refs`, `enable_top_agents`).

**Top erroring URLs** (`top_error_urls`, gated by `enable_top_error_urls`): a separate per-period table keyed by URL, splitting 4xx/5xx counts (`c4xx`, `c5xx`) plus `bandwidth`. Populated in `aggregate_entry` for any `status >= 400` (respecting `HideMask::TOP_URLS`). Uses the same bounding machinery as `top_urls`: `pretrim_error_urls` at month-end, a `cull_period` block (by `c4xx+c5xx` and `bandwidth`), and a `finalize_month` trim to the union of top-N by `c4xx+c5xx` and top-N by `bandwidth`. Reports render a sortable panel (4xx / 5xx / Bandwidth tabs) on the month, year, and overview pages.

## Resume / dedup system

Each processed file gets a `ParseState` row in SQLite keyed by path and inode. Fields tracked: compressed size, uncompressed size, compressed/uncompressed head fingerprints, offsets, mtime, completed flag.

Phase-1 fingerprinting avoids full decompression: compressed files get an 8 KB raw-bytes hash; the uncompressed head is reused from DB when the inode is unchanged. On inode change, if the new file shares the same uncompressed prefix, only the tail is reprocessed.

## Progress display

One progress line, printed by a dedicated thread spawned in `process_globs`. Format:

```
[2026-05-11 21:22:44] [0/487 files] [2024k/118403k lines] [2%] [267k l/s] [7m3s to go] [no checkpoint yet]
```

The pipeline writes into `Arc<Atomic*>` counters; the progress thread reads them and calls `print_dir_progress`. There is no per-file line.

## Key types

- `ParsedEntry` — output of the parser stage: `LogEntry` + `ua_family: Arc<str>`
- `RunAccumulators` — in-memory aggregation buffers flushed to SQLite at checkpoints and end-of-run
- `BucketAcc` — per-bucket accumulation buffers within `RunAccumulators`
- `FileResumePlan` — per-file resume plan from `resolve_resume_plan`; carries `CompressionType`, offsets, fingerprints
- `VisitStateKey` — `(ip_kind, ip_hi, ip_lo, ip_text)` used to track per-IP last-seen timestamps
