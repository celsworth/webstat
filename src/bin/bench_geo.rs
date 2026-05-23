/// Quick benchmark: direct mmdb lookups vs AHashMap cache.
///
/// Usage: cargo run --release --bin bench_geo -- /path/to/GeoLite2-Country.mmdb
use std::hint::black_box;
use std::net::Ipv4Addr;
use std::time::Instant;

use maxminddb::geoip2;

fn main() {
    let mmdb_path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: bench_geo <path/to/GeoLite2-Country.mmdb>");
        std::process::exit(1);
    });

    let reader = maxminddb::Reader::<Vec<u8>>::open_readfile(&mmdb_path)
        .unwrap_or_else(|e| panic!("failed to open mmdb: {e}"));

    // Generate a pool of IPv4 addresses spread across the routable space.
    // We avoid RFC-1918 / loopback blocks so most map to real countries.
    let make_ip = |i: u32| -> std::net::IpAddr {
        // spread across 1.0.0.0 – 223.255.255.255, skipping obvious private ranges
        let raw = 0x0100_0000u32 + (i * 7919) % (0xDF00_0000u32 - 1);
        Ipv4Addr::from(raw).into()
    };

    // Convert to strings once so string parsing is included in both paths.
    let pool_size = 10_000usize;
    let ip_strings: Vec<String> = (0..pool_size as u32)
        .map(|i| make_ip(i).to_string())
        .collect();

    // ---------- scenarios ----------
    let scenarios: &[(&str, usize, usize)] = &[
        // (label, unique IPs in pool, total lookups)
        ("10 unique / 100k lookups  (hot cache)", 10, 100_000),
        ("100 unique / 100k lookups             ", 100, 100_000),
        ("1k unique / 100k lookups              ", 1_000, 100_000),
        ("10k unique / 100k lookups (cold cache)", 10_000, 100_000),
    ];

    println!(
        "{:<42} {:>12} {:>12} {:>10}",
        "scenario", "direct (ms)", "cached (ms)", "speedup"
    );
    println!("{}", "-".repeat(80));

    for &(label, unique, total) in scenarios {
        let unique = unique.min(pool_size);

        // --- direct: parse + mmdb lookup every time ---
        let direct_ms = {
            let t = Instant::now();
            for idx in 0..total {
                let ip_str = &ip_strings[idx % unique];
                let ip: std::net::IpAddr = ip_str.parse().unwrap();
                let _: Result<geoip2::Country, _> = black_box(reader.lookup(black_box(ip)));
            }
            t.elapsed().as_secs_f64() * 1000.0
        };

        // --- cached: first pass warms the AHashMap, second pass measures ---
        let cached_ms = {
            let mut cache: ahash::AHashMap<String, (String, String)> =
                ahash::AHashMap::with_capacity(unique);

            // warm-up (not timed)
            for idx in 0..unique {
                let ip_str = ip_strings[idx].clone();
                let ip: std::net::IpAddr = ip_str.parse().unwrap();
                let result: Result<geoip2::Country, _> = reader.lookup(ip);
                let (code, name) = match result {
                    Ok(c) => {
                        let code = c.country.as_ref().and_then(|x| x.iso_code).unwrap_or("--");
                        let name = c
                            .country
                            .as_ref()
                            .and_then(|x| x.names.as_ref())
                            .and_then(|n| n.get("en").copied())
                            .unwrap_or("Unknown");
                        (code.to_string(), name.to_string())
                    }
                    Err(_) => ("--".to_string(), "Unknown".to_string()),
                };
                cache.insert(ip_str, (code, name));
            }

            // timed: all lookups are cache hits
            let t = Instant::now();
            for idx in 0..total {
                let ip_str = &ip_strings[idx % unique];
                let _ = black_box(cache.get(black_box(ip_str.as_str())));
            }
            t.elapsed().as_secs_f64() * 1000.0
        };

        let speedup = direct_ms / cached_ms;
        println!(
            "{:<42} {:>12.1} {:>12.1} {:>9.1}x",
            label, direct_ms, cached_ms, speedup
        );
    }
}
