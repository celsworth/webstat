// Benchmark f32::parse() vs manual byte parser for nginx response-time fields.
// Usage: cargo run --release --bin bench_response_time

use std::hint::black_box;
use std::time::Instant;

// Mirrors parse_u64 from combined.rs
#[inline]
fn parse_u64(bytes: &[u8]) -> Option<u64> {
    let mut n = 0u64;
    for &c in bytes {
        if !c.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (c - b'0') as u64;
    }
    Some(n)
}

// Current approach: std f32 parse
#[inline]
fn parse_ms_f32(slice: &[u8]) -> Option<u32> {
    let s = std::str::from_utf8(slice).ok()?;
    let secs: f32 = s.parse().ok()?;
    Some((secs * 1_000.0).round() as u32)
}

// Alternative: manual integer parse of whole + fractional parts
#[inline]
fn parse_ms_manual(slice: &[u8]) -> Option<u32> {
    let dot = slice.iter().position(|&c| c == b'.')?;
    let whole = parse_u64(&slice[..dot])? as u32;
    let frac_bytes = &slice[dot + 1..];

    // Parse up to 3 decimal places → milliseconds
    let ms = match frac_bytes.len() {
        0 => 0u32,
        1 => parse_u64(frac_bytes)? as u32 * 100,
        2 => parse_u64(frac_bytes)? as u32 * 10,
        _ => {
            // Use first 3 digits, round on the 4th if present
            let top3 = parse_u64(&frac_bytes[..3])? as u32;
            if frac_bytes.len() > 3 && frac_bytes[3] >= b'5' {
                top3 + 1
            } else {
                top3
            }
        }
    };

    Some(whole * 1_000 + ms)
}

fn bench<F: Fn(&[u8]) -> Option<u32>>(label: &str, inputs: &[&[u8]], iters: u64, f: F) {
    // Warmup
    for _ in 0..10_000 {
        for &s in inputs {
            let _ = black_box(f(black_box(s)));
        }
    }

    let start = Instant::now();
    let mut sum = 0u64;
    for _ in 0..iters {
        for &s in inputs {
            if let Some(v) = f(black_box(s)) {
                sum += v as u64;
            }
        }
    }
    let elapsed = start.elapsed();
    let total_ops = iters * inputs.len() as u64;
    println!(
        "{:<20} {:>8.3} ns/op   (sum={}, elapsed={:.3?})",
        label,
        elapsed.as_nanos() as f64 / total_ops as f64,
        sum,
        elapsed,
    );
}

fn main() {
    let inputs: &[&[u8]] = &[
        b"0.001",
        b"0.123",
        b"1.456",
        b"12.789",
        b"0.010",
        b"0.999",
        b"3.141",
        b"0.0001",   // sub-ms, 4 frac digits
        b"0.1234",   // 4 frac digits
        b"100.000",  // large whole
    ];

    let iters = 5_000_000u64;

    println!("Inputs: {} values, {} iterations each\n", inputs.len(), iters);

    // Verify outputs match
    println!("Correctness check:");
    for &s in inputs {
        let f32_result  = parse_ms_f32(s);
        let man_result  = parse_ms_manual(s);
        let ok = f32_result == man_result;
        println!(
            "  {:>12}  f32={:?}  manual={:?}  {}",
            std::str::from_utf8(s).unwrap(),
            f32_result,
            man_result,
            if ok { "OK" } else { "MISMATCH" },
        );
    }
    println!();

    bench("f32::parse",    inputs, iters, parse_ms_f32);
    bench("manual bytes",  inputs, iters, parse_ms_manual);
}
