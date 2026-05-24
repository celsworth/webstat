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
- **`src/database/writer.rs`** — `flush_data`, `finalize_month`, per-period pruning
- **`src/database/parse_state.rs`** — parse state load/save
- **`src/database/visit_state.rs`** — visit state load/save
- **`src/database/maintenance.rs`** — vacuum, meta key-value ops
- **`src/progress.rs`** — `print_dir_progress`: the single progress-line formatter
- **`src/ip.rs`** — `Ip` enum: IPv4 stored as `u32`, IPv6 as `u128`; used as hash key for geo lookups and daily-unique-IP sets
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
| (none)    | plain read with seek |

`CompressionType` (`Plain`, `Gz`, `Bz2`) lives in `compression.rs`. Use `CompressionType::from_path(filepath)` to detect, `compression.is_compressed()` to branch.

Compressed files have no random access — they resume by decoding from the start and skipping already-processed bytes (`skip_decoded_prefix_bytes`). Plain files resume via byte offset seek.

## Unique IP / site counting

Unique IP counting is exact, not approximate. Every unique `(date, ip_kind, ip_hi, ip_lo)` tuple is written to `daily_ip_log` via `INSERT OR IGNORE` — the primary key enforces deduplication at the SQLite level.

When `finalize_month` runs, it computes and stores monthly and yearly distinct-IP counts into `site_count_cache` using `SELECT DISTINCT`. Report queries read from this cache rather than recomputing from `daily_ip_log`.

## Top-N tables

Top-N tables (`monthly_urls_hits`, `monthly_urls_bandwidth`, `monthly_sites_hits`, `monthly_sites_bandwidth`, `monthly_refs`, `monthly_agents`) accumulate exact counts during ingestion. `finalize_month` prunes each table to the top `top_n` rows per period via `DELETE … WHERE … NOT IN (SELECT … ORDER BY … LIMIT top_n)`. Each table can be individually disabled via config flags (`enable_top_urls`, `enable_top_sites`, `enable_top_refs`, `enable_top_agents`). All-time unique IP tracking (`all_time_ips` table) can be disabled via `enable_all_time_unique_sites` to save space.

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
