/// Benchmark the individual operations that make up the resume/skip decision,
/// to establish which order minimises wall-time for the common "already done" case.
///
/// Usage (from repo root):
///   cargo run --release --bin bench_resume
///
/// Files used are logs/ relative to the working directory.
use std::hash::Hasher;
use std::hint::black_box;
use std::io::{BufRead, BufReader, Read};
use std::time::{Duration, Instant};

use twox_hash::XxHash3_64;

const ITERS: usize = 500;
const SAMPLE: usize = 8_192;

// ── helpers ───────────────────────────────────────────────────────────────────

fn hash8k(bytes: &[u8]) -> u64 {
    let mut h = XxHash3_64::default();
    h.write(bytes);
    h.finish()
}

/// Read raw first 8KB and hash them (compressed-head fingerprint).
fn compressed_head(path: &str) -> Option<u64> {
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; SAMPLE];
    let n = f.read(&mut buf).ok()?;
    if n == 0 {
        return None;
    }
    Some(hash8k(&buf[..n]))
}

/// Decompress until 8KB of plaintext accumulated, then hash (uncompressed-head fingerprint).
fn gz_decompressed_head(path: &str) -> Option<u64> {
    let f = std::fs::File::open(path).ok()?;
    let mut dec = flate2::read::MultiGzDecoder::new(f);
    let mut head = Vec::with_capacity(SAMPLE);
    let mut buf = [0u8; SAMPLE];
    while head.len() < SAMPLE {
        let n = dec.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        let take = (SAMPLE - head.len()).min(n);
        head.extend_from_slice(&buf[..take]);
    }
    if head.is_empty() {
        return None;
    }
    Some(hash8k(&head))
}

/// Read first 8KB of compressed bytes, decompress, scan for a parseable timestamp.
/// Mirrors the Phase-0 read_first_line_ts logic (compressed input limit = 8KB).
fn gz_first_line_ts(path: &str) -> Option<i64> {
    let f = std::fs::File::open(path).ok()?;
    let limited = f.take(SAMPLE as u64);
    let dec = flate2::read::MultiGzDecoder::new(limited);
    let mut reader = BufReader::new(dec);
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) | Err(_) => return None,
            Ok(_) => {}
        }
        // Quick heuristic: combined-log timestamps look like "01/Jan/2025:00:00:00"
        // We just need to confirm a non-empty line exists; for timing we skip real parsing.
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            // Pretend we parsed a timestamp — the hash is just to prevent optimization.
            return Some(hash8k(trimmed.as_bytes()) as i64);
        }
    }
}

// ── timing infrastructure ─────────────────────────────────────────────────────

struct Stats {
    label: String,
    min: Duration,
    mean: Duration,
    max: Duration,
}

fn measure<F: FnMut()>(label: &str, n: usize, mut f: F) -> Stats {
    let mut times = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        f();
        times.push(t.elapsed());
    }
    let min = *times.iter().min().unwrap();
    let max = *times.iter().max().unwrap();
    let mean =
        Duration::from_nanos((times.iter().map(|d| d.as_nanos()).sum::<u128>() / n as u128) as u64);
    Stats {
        label: label.to_string(),
        min,
        mean,
        max,
    }
}

fn fmt_dur(d: Duration) -> String {
    let ns = d.as_nanos();
    if ns < 1_000 {
        format!("{ns}ns")
    } else if ns < 1_000_000 {
        format!("{:.1}µs", ns as f64 / 1_000.0)
    } else {
        format!("{:.2}ms", ns as f64 / 1_000_000.0)
    }
}

fn print_stats(rows: &[Stats]) {
    let w = rows.iter().map(|s| s.label.len()).max().unwrap_or(40);
    println!(
        "\n{:<width$}  {:>9}  {:>9}  {:>9}",
        "operation",
        "min",
        "mean",
        "max",
        width = w
    );
    println!("{}", "─".repeat(w + 33));
    for s in rows {
        println!(
            "{:<width$}  {:>9}  {:>9}  {:>9}",
            s.label,
            fmt_dur(s.min),
            fmt_dur(s.mean),
            fmt_dur(s.max),
            width = w
        );
    }
}

// ── main ──────────────────────────────────────────────────────────────────────

fn main() {
    let gz_path = "logs/access.log-20260509.gz";
    let plain_path = "logs/access.log";

    // Verify files exist.
    for p in [gz_path, plain_path] {
        if !std::path::Path::new(p).exists() {
            eprintln!("missing: {p}  (run from repo root)");
            std::process::exit(1);
        }
    }

    println!("N={ITERS} per operation");
    println!(
        "gz:    {gz_path}  ({:.1} MB)",
        std::fs::metadata(gz_path).unwrap().len() as f64 / 1e6
    );
    println!(
        "plain: {plain_path}  ({:.1} MB)",
        std::fs::metadata(plain_path).unwrap().len() as f64 / 1e6
    );

    // ── DB setup ──────────────────────────────────────────────────────────────
    // Use a temp file-based SQLite so queries go through real SQLite I/O paths
    // (in-memory would be unrealistically fast).
    let db_dir = tempdir();
    let db_path = format!("{}/bench.db", db_dir);
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute_batch(
        "
        CREATE TABLE parse_state (
            filepath TEXT PRIMARY KEY,
            inode INTEGER NOT NULL,
            compressed_size INTEGER,
            uncompressed_size INTEGER,
            compressed_head_fingerprint INTEGER,
            uncompressed_head_fingerprint INTEGER,
            compressed_offset INTEGER,
            uncompressed_offset INTEGER,
            mtime_ns INTEGER,
            completed INTEGER
        );
        CREATE INDEX idx_ps_inode ON parse_state(inode);
        CREATE TABLE parse_state_archive (
            filepath TEXT,
            inode INTEGER NOT NULL,
            compressed_size INTEGER,
            uncompressed_size INTEGER,
            compressed_head_fingerprint INTEGER,
            uncompressed_head_fingerprint INTEGER,
            compressed_offset INTEGER,
            uncompressed_offset INTEGER,
            mtime_ns INTEGER,
            completed INTEGER
        );
    ",
    )
    .unwrap();

    // Insert a completed row for the gz file so we can time the "hit" path.
    let gz_meta = std::fs::metadata(gz_path).unwrap();
    let gz_inode = {
        use std::os::unix::fs::MetadataExt;
        gz_meta.ino()
    };
    let gz_size = gz_meta.len() as i64;
    let gz_mtime = {
        use std::os::unix::fs::MetadataExt;
        gz_meta.mtime().saturating_mul(1_000_000_000) + gz_meta.mtime_nsec()
    };
    conn.execute(
        "INSERT INTO parse_state
         (filepath,inode,compressed_size,uncompressed_size,
          compressed_head_fingerprint,uncompressed_head_fingerprint,
          compressed_offset,uncompressed_offset,mtime_ns,completed)
         VALUES (?1,?2,?3,5000000,111111,222222,?3,5000000,?4,1)",
        rusqlite::params![gz_path, gz_inode as i64, gz_size, gz_mtime],
    )
    .unwrap();

    let mut rows: Vec<Stats> = Vec::new();

    // ── 1: stat() only ────────────────────────────────────────────────────────
    rows.push(measure("stat() gz", ITERS, || {
        let _ = black_box(std::fs::metadata(black_box(gz_path)).unwrap());
    }));

    // ── 2: DB query by path (miss) ────────────────────────────────────────────
    rows.push(measure("DB query by path (miss)", ITERS, || {
        let mut st = conn
            .prepare_cached("SELECT filepath FROM parse_state WHERE filepath = ?")
            .unwrap();
        let mut rows = st.query(rusqlite::params!["nonexistent/path.gz"]).unwrap();
        let _ = black_box(rows.next().unwrap());
    }));

    // ── 3: DB query by path (hit) ─────────────────────────────────────────────
    rows.push(measure("DB query by path (hit)", ITERS, || {
        let mut st = conn
            .prepare_cached(
                "SELECT filepath,inode,compressed_size,uncompressed_size,
                  compressed_head_fingerprint,uncompressed_head_fingerprint,
                  compressed_offset,uncompressed_offset,mtime_ns,completed
                  FROM parse_state WHERE filepath = ?",
            )
            .unwrap();
        let mut rs = st.query(rusqlite::params![gz_path]).unwrap();
        let _ = black_box(rs.next().unwrap());
    }));

    // ── 4: DB query by inode (hit) ────────────────────────────────────────────
    rows.push(measure("DB query by inode (hit)", ITERS, || {
        let mut st = conn
            .prepare_cached(
                "SELECT filepath,inode,compressed_size,uncompressed_size,
                  compressed_head_fingerprint,uncompressed_head_fingerprint,
                  compressed_offset,uncompressed_offset,mtime_ns,completed
                  FROM parse_state WHERE inode = ? LIMIT 1",
            )
            .unwrap();
        let mut rs = st.query(rusqlite::params![gz_inode as i64]).unwrap();
        let _ = black_box(rs.next().unwrap());
    }));

    // ── 5: in-memory exact-match comparison (stat + stored values) ────────────
    // This is what happens after the two DB queries return; it's pure integer math.
    {
        let stored_size = gz_size as u64;
        let stored_mtime = gz_mtime;
        let stored_inode = gz_inode;
        rows.push(measure(
            "in-memory exact-match (inode+size+mtime)",
            ITERS,
            || {
                let meta = std::fs::metadata(black_box(gz_path)).unwrap();
                use std::os::unix::fs::MetadataExt;
                let matched = black_box(
                    meta.ino() == stored_inode
                        && meta.len() == stored_size
                        && (meta.mtime().saturating_mul(1_000_000_000) + meta.mtime_nsec())
                            == stored_mtime,
                );
                let _ = matched;
            },
        ));
    }

    // ── separator ─────────────────────────────────────────────────────────────
    rows.push(Stats {
        label: "── file I/O operations ──".to_string(),
        min: Duration::ZERO,
        mean: Duration::ZERO,
        max: Duration::ZERO,
    });

    // ── 6: compressed head fingerprint (gz) — raw 8KB read + hash ────────────
    rows.push(measure(
        "compressed head fingerprint (gz, 8KB raw+hash)",
        ITERS,
        || {
            let _ = black_box(compressed_head(black_box(gz_path)));
        },
    ));

    // ── 7: decompressed head fingerprint (gz) — 8KB decompress + hash ─────────
    rows.push(measure(
        "decompressed head fingerprint (gz, 8KB decomp+hash)",
        ITERS,
        || {
            let _ = black_box(gz_decompressed_head(black_box(gz_path)));
        },
    ));

    // ── 8: read_first_line_ts (gz) — 8KB compressed in, decompress, scan lines ─
    rows.push(measure(
        "first-line timestamp scan (gz, 8KB compressed input)",
        ITERS,
        || {
            let _ = black_box(gz_first_line_ts(black_box(gz_path)));
        },
    ));

    // ── 9: plain file — stat + 8KB read + hash ────────────────────────────────
    rows.push(measure(
        "compressed head fingerprint (plain, 8KB read+hash)",
        ITERS,
        || {
            let _ = black_box(compressed_head(black_box(plain_path)));
        },
    ));

    // ── 10: find_completed_by_compressed_identity (global dedup DB query) ─────
    rows.push(measure("DB find_completed_by_compressed_identity", ITERS, || {
        let fp: i64 = 111111;
        let sz: i64 = gz_size;
        let mut st = conn.prepare_cached(
            "SELECT uncompressed_size
             FROM (
               SELECT compressed_head_fingerprint, compressed_size, uncompressed_size, completed FROM parse_state
               UNION ALL
               SELECT compressed_head_fingerprint, compressed_size, uncompressed_size, completed FROM parse_state_archive
             )
             WHERE compressed_head_fingerprint = ? AND compressed_size = ? AND completed = 1
             LIMIT 1",
        ).unwrap();
        let mut rs = st.query(rusqlite::params![fp, sz]).unwrap();
        let _ = black_box(rs.next().unwrap());
    }));

    print_stats(&rows);

    println!("\nKey question: is Phase-0 (first-line timestamp scan) faster or slower");
    println!("than Phase-1 metadata exact-match (stat+DB hit+in-memory compare)?");
    println!("If [8] >> [3]+[5], Phase-0 is wasting time on already-done files.");

    // Cleanup.
    drop(conn);
    let _ = std::fs::remove_dir_all(&db_dir);
}

fn tempdir() -> String {
    let p = std::env::temp_dir().join(format!("bench_resume_{}", std::process::id()));
    std::fs::create_dir_all(&p).unwrap();
    p.to_string_lossy().into_owned()
}
