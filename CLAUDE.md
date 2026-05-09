# webstat

A Rust web access-log processor. Parses nginx/Apache combined-format logs, aggregates traffic statistics, and stores results in SQLite.

## Build & test

```
cargo build
cargo test
```

## Architecture

- **`src/main.rs`** — CLI entry point (clap), subcommands, config loading
- **`src/processor.rs`** — core orchestration: file discovery, resume planning, reading, aggregation
- **`src/processor/resume_policy.rs`** — decides what to skip/resume per file using fingerprints and stored state
- **`src/processor/readers.rs`** — parallel range reading for large plain files
- **`src/processor/parallel.rs`** — multi-file parallel worker dispatch
- **`src/compression.rs`** — `CompressionType` enum (`Plain`, `Gz`, `Bz2`) and extension detection
- **`src/fingerprint.rs`** — file identity (head hash, logical size); decompressed/compressed head fingerprints
- **`src/parser.rs`** — combined-log-format line parser
- **`src/database.rs`** — SQLite via rusqlite; stores parse state, hourly aggregates, top-N tables
- **`src/progress.rs`** — terminal progress display (single directory-level line, updated by progress thread)
- **`src/reports.rs`** — HTML report generation via Tera templates

## Compression

Supported formats detected by file extension:

| Extension | Decoder |
|-----------|---------|
| `.gz`     | `flate2::read::MultiGzDecoder` |
| `.bz2`    | `bzip2::read::MultiBzDecoder` |
| (none)    | plain read with seek |

`CompressionType` (`Plain`, `Gz`, `Bz2`) lives in `compression.rs`. Use `CompressionType::from_path(filepath)` to detect, `compression.is_compressed()` to branch.

Compressed files have no random access — they resume by decoding from the start and skipping already-processed bytes (`skip_decoded_prefix_bytes`). Plain files resume via byte offset seek.

## Resume / dedup system

Each processed file gets a `ParseState` row in SQLite keyed by path and inode. Fields tracked: compressed size, uncompressed size, compressed/uncompressed head fingerprints, offsets, mtime, completed flag.

Phase-1 fingerprinting avoids full decompression: compressed files get an 8KB raw-bytes hash; uncompressed head is reused from DB when the inode is unchanged.

## Progress display

There is exactly one progress display: a directory-level line printed by a dedicated progress thread spawned in `process_globs`. It always runs, even for a single worker. Format:

```
[2026-05-11 21:22:44] [0/487 files] [2024k/118403k lines] [2%] [267k l/s] [7m3s to go] [no checkpoint yet]
```

Worker threads write into `SharedProgress` atomic counters via `flush_shared_progress`; the progress thread reads those counters and calls `print_dir_progress`. There is no per-file progress printer — `print_single_progress` was removed. Do not add it back.

## Key types

- `FileResumePlan` — per-file plan produced by `resolve_resume_plan`; carries `compression: CompressionType`, offsets, fingerprints
- `SharedProgress` — atomic counters written by worker threads, read by the progress display thread
- `RunAccumulators` — in-memory aggregation buffers merged into the DB at flush time
