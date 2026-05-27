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
- **`src/parser/mod.rs`** — combined-log-format line parser → `LogEntry`; plus timestamp arithmetic; no pipeline, UA, or rule dependencies
- **`src/parser/stage.rs`** — parser pipeline thread: receives raw lines from the loader, parses them, applies UA classification, bot filtering, and rules, then forwards batches to the aggregator
- **`src/loader.rs`** — reads raw bytes, decompresses if needed, emits `LoaderMsg::Lines` batches
- **`src/aggregator/mod.rs`** — `Processor` struct: top-level orchestration — file discovery, resume planning, progress thread, checkpoint scheduling, and the public `process_globs` entry point
- **`src/aggregator/pipeline.rs`** — 3-stage Loader→Parser→Aggregator pipeline; aggregator runs on the calling thread; drives checkpointing and file-done accounting
- **`src/aggregator/aggregation.rs`** — per-entry aggregation into `RunAccumulators`
- **`src/aggregator/flush.rs`** — flushes `RunAccumulators` to SQLite; handles month-boundary finalisation and saves parse/visit state after each checkpoint
- **`src/aggregator/messages.rs`** — `LoaderMsg`, `ParserMsg`, `ParsedEntry` channel types; push/pop blocking helpers
- **`src/aggregator/resume.rs`** — per-file skip/resume decisions using fingerprints and stored state
- **`src/aggregator/progress_seed.rs`** — seeds initial progress counters from DB state
- **`src/accumulators.rs`** — `HourlyStats`, `HourlyAcc`, `HourlyMap` types
- **`src/run_accumulators.rs`** — `RunAccumulators`: in-memory aggregation buffers (hourly, URLs, hosts, refs, agents, countries, IPs, status codes, etc.) flushed to SQLite at checkpoints and end-of-run
- **`src/compression.rs`** — `CompressionType` enum (`Plain`, `Gz`, `Bz2`) and extension detection
- **`src/fingerprint.rs`** — file identity (head hash, logical size); decompressed/compressed head fingerprints
- **`src/geo.rs`** — GeoIP lookup and cache
- **`src/ua.rs`** — UA family classification and bot detection; runs in the parser thread
- **`src/database.rs`** — SQLite connection wrapper: schema initialisation, WAL mode, and module re-exports
- **`src/database/writer.rs`** — `flush_data`, `finalize_month`, `cull_period`, per-period pruning
- **`src/database/parse_state.rs`** — parse state load/save
- **`src/database/visit_state.rs`** — visit state load/save
- **`src/database/maintenance.rs`** — vacuum, meta key-value ops
- **`src/progress.rs`** — `print_dir_progress`: the single progress-line formatter
- **`src/ip.rs`** — `Ip` enum: IPv4 stored as `u32`, IPv6 as `u128`; used as hash key for geo lookups. Also contains `IpBitmaps`: per-date in-memory accumulator using `RoaringBitmap` (IPv4) and `AHashMap<u64, RoaringTreemap>` (IPv6, keyed by upper-64 prefix)
- **`src/rules.rs`** — YAML-configured per-entry filtering rules (`ignore`, `hide`, `sample` actions); compiled from `RawRule` in config and evaluated in the parser thread
- **`src/logging.rs`** — verbosity control: atomic log-level flag and helpers that interleave safely with the progress line
- **`src/method_proto.rs`** — HTTP method/protocol index arrays
- **`src/reports.rs`** — HTML report generation via Tera templates
- **`src/reports/aggregator.rs`** — report-specific SQL summarisation
- **`src/reports/charts.rs`** — Chart.js dataset assembly

## Pipeline

Each run of `process_globs` spawns a 3-stage pipeline:

```
Loader thread  →(LoaderMsg)→  Parser thread  →(ParserMsg)→  Aggregator (main thread)
```

- **Loader** reads files sequentially, decompresses if needed, emits `LoaderMsg::Lines` batches of `(String, offset)` pairs.
- **Parser** calls `LogEntry::parse`, then `UaParser::parse` for each line. If `bot_filter` is enabled, bot entries are dropped immediately — they never enter the ring buffer or reach the aggregator. Compiled `rules` (from config) are also evaluated here; entries can be ignored, hidden from top-N tables, or sampled. Non-bot entries are wrapped in `ParsedEntry { entry, ua_family }` and sent as `ParserMsg::Entries` batches.
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

`CompressionType` (`Plain`, `Gz`, `Bz2`, `Br`) lives in `compression.rs`. Use `CompressionType::from_path(filepath)` to detect, `compression.is_compressed()` to branch.

Compressed files have no random access — they resume by decoding from the start and skipping already-processed bytes (`skip_decoded_prefix_bytes`). Plain files resume via byte offset seek.

## Unique IP / site counting

Unique IP counting is exact, not approximate, and uses roaring bitmaps for compact storage.

**In-memory accumulation**: `RunAccumulators.daily_ips` maps each date to an `IpBitmaps`. IPv4 addresses (u32) go into a `RoaringBitmap`; IPv6 addresses are split at 64 bits — the upper 64 select a `RoaringTreemap` entry, the lower 64 are stored in it.

**SQLite layout** (`daily_unique_ips`): one row per `(date, ip_kind, ip_hi)` group. `ip_kind=1/ip_hi=0` holds the IPv4 bitmap; `ip_kind=2/ip_hi=<prefix>` holds the IPv6 lower-64 treemap. A `count` column mirrors the bitmap cardinality so SQL can aggregate per-day counts without deserialising blobs. Flush is a read-modify-write: load existing blob, OR in new data, write back.

**`finalize_month`**: loads all daily blobs for the month into Rust, ORs them to produce a monthly union, ORs that into `yearly_unique_ips` (same blob-per-group schema), optionally ORs into `all_time_ips`. Writes distinct-IP counts to `unique_visitor_counts`. Populates `daily_visitor_counts` from the `count` column, then deletes `daily_unique_ips` rows for the month.

**`finalize_year`**: sums cardinalities of the accumulated `yearly_unique_ips` rows (each group is disjoint, no further ORing needed), writes the yearly count, deletes yearly rows.

**Reports**: daily counts use `SUM(count)` SQL. Monthly/yearly counts read from `unique_visitor_counts` cache; for in-progress periods (no cache entry), fall back to loading and ORing blobs in Rust.

## Top-N tables

Top-N tables (`top_urls`, `top_ips`, `top_referrers`, `top_agents`) accumulate exact counts during ingestion. Two distinct cleanup operations keep them from growing unbounded:

**Culling** (`cull_period`, called at each checkpoint and at end-of-run): removes rows that have no realistic chance of appearing in the final top `top_n`. A row is culled when every tracked metric (hits, bandwidth, avg response time where available) is below 1/10th of the current N-th-best value for that metric. The guard condition `row_count > top_n * 50` ensures culling only fires when the table is well above the safety margin, making it safe to run mid-month.

**Trimming** (`finalize_month`): at month end, prunes each table to exactly the top `top_n` rows per period via `DELETE … WHERE … NOT IN (SELECT … ORDER BY … LIMIT top_n)`.

Each table can be individually disabled via config flags (`enable_top_urls`, `enable_top_sites`, `enable_top_refs`, `enable_top_agents`). All-time unique IP tracking (`all_time_ips` table) is always enabled.

## Resume / dedup system

Each processed file gets a `ParseState` row in SQLite keyed by path and inode. Fields tracked: compressed size, uncompressed size, compressed/uncompressed head fingerprints, offsets, mtime, completed flag.

Phase-1 fingerprinting avoids full decompression: compressed files get an 8KB raw-bytes hash; uncompressed head is reused from DB when the inode is unchanged.

## Progress display

There is exactly one progress display: a directory-level line printed by a dedicated progress thread spawned in `process_globs`. It always runs. Format:

```
[2026-05-11 21:22:44] [0/487 files] [2024k/118403k lines] [2%] [267k l/s] [7m3s to go] [no checkpoint yet]
```

The pipeline writes into `Arc<Atomic*>` counters (`files_done`, `bytes_done`, `lines_done`, etc.); the progress thread reads those counters and calls `print_dir_progress`. There is no per-file progress line.

## Key types

- `FileResumePlan` — per-file plan produced by `resolve_resume_plan`; carries `compression: CompressionType`, offsets, fingerprints
- `ParsedEntry` — output of the parser stage: `LogEntry` + `ua_family: Arc<str>`
- `RunAccumulators` — in-memory aggregation buffers flushed to SQLite at checkpoints and end-of-run
- `VisitStateKey` — `(ip_kind, ip_hi, ip_lo, ip_text)` used to track per-IP visit timestamps
