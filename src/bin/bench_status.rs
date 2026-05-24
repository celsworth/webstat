// Benchmark status-code index lookup strategies to validate the chosen array approach.

use std::time::Instant;

fn main() {
    // Test with realistic status code distribution
    let statuses: Vec<u16> = vec![
        // 200s - most common
        200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
        200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
        200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200, 200,
        200, 200, 200, 200, 200, 200, 200, 201, 204, 206, 200, 200, 200, 200, 200, 200,
        // 300s
        301, 302, 304, 304, 304, 304, 304, 301, 302, 304, // 400s
        404, 404, 404, 404, 404, 403, 403, 400, 404, 404, // 500s
        500, 502, 503, 500, 500, 502, 503, 500, 500, 502,
    ];

    let iterations = 10_000_000;

    // Warm up
    let mut dummy = [0u64; 4];
    for _ in 0..1000 {
        for &status in &statuses {
            if (200..300).contains(&status) {
                dummy[0] += 1;
            } else if (300..400).contains(&status) {
                dummy[1] += 1;
            } else if (400..500).contains(&status) {
                dummy[2] += 1;
            } else {
                dummy[3] += 1;
            }
        }
    }

    // Test range.contains()
    let start = Instant::now();
    let mut counts1 = [0u64; 4];
    for _ in 0..iterations {
        for &status in &statuses {
            if (200..300).contains(&status) {
                counts1[0] += 1;
            } else if (300..400).contains(&status) {
                counts1[1] += 1;
            } else if (400..500).contains(&status) {
                counts1[2] += 1;
            } else {
                counts1[3] += 1;
            }
        }
    }
    let duration1 = start.elapsed();

    // Test match division
    let start = Instant::now();
    let mut counts2 = [0u64; 4];
    for _ in 0..iterations {
        for &status in &statuses {
            match status / 100 {
                2 => counts2[0] += 1,
                3 => counts2[1] += 1,
                4 => counts2[2] += 1,
                _ => counts2[3] += 1,
            }
        }
    }
    let duration2 = start.elapsed();

    // Test if-else division
    let start = Instant::now();
    let mut counts3 = [0u64; 4];
    for _ in 0..iterations {
        for &status in &statuses {
            let category = status / 100;
            if category == 2 {
                counts3[0] += 1;
            } else if category == 3 {
                counts3[1] += 1;
            } else if category == 4 {
                counts3[2] += 1;
            } else {
                counts3[3] += 1;
            }
        }
    }
    let duration3 = start.elapsed();

    // Test if-else chain (original)
    let start = Instant::now();
    let mut counts4 = [0u64; 4];
    for _ in 0..iterations {
        for &status in &statuses {
            if status < 300 {
                counts4[0] += 1;
            } else if status < 400 {
                counts4[1] += 1;
            } else if status < 500 {
                counts4[2] += 1;
            } else {
                counts4[3] += 1;
            }
        }
    }
    let duration4 = start.elapsed();

    // Test lookup table
    let start = Instant::now();
    let mut counts5 = [0u64; 4];
    let table: [u8; 600] = {
        let mut t = [0u8; 600];
        t[300..400].fill(1);
        t[400..500].fill(2);
        t[500..600].fill(3);
        t
    };
    for _ in 0..iterations {
        for &status in &statuses {
            let idx = table[status as usize] as usize;
            counts5[idx] += 1;
        }
    }
    let duration5 = start.elapsed();

    // Test lookup table (safe with bounds check)
    let start = Instant::now();
    let mut counts6 = [0u64; 4];
    for _ in 0..iterations {
        for &status in &statuses {
            let idx = match status as usize {
                s if (200..300).contains(&(s as u16)) => 0,
                s if (300..400).contains(&(s as u16)) => 1,
                s if (400..500).contains(&(s as u16)) => 2,
                _ => 3,
            };
            counts6[idx] += 1;
        }
    }
    let duration6 = start.elapsed();

    println!("Results verification:");
    println!(
        "Range.contains:    {:?} (matches: {:?})",
        counts1,
        counts1 == counts2
    );
    println!("Match division:    {:?}", counts2);
    println!(
        "If-else division:  {:?} (matches: {:?})",
        counts3,
        counts3 == counts2
    );
    println!(
        "If-else chain:     {:?} (matches: {:?})",
        counts4,
        counts4 == counts2
    );
    println!(
        "Lookup table:      {:?} (matches: {:?})",
        counts5,
        counts5 == counts2
    );
    println!(
        "Safe lookup:       {:?} (matches: {:?})",
        counts6,
        counts6 == counts2
    );

    println!(
        "\nTimings ({} iterations × {} statuses = {} operations):",
        iterations,
        statuses.len(),
        iterations * statuses.len()
    );
    println!("Range.contains:    {:?}", duration1);
    println!("Match division:    {:?}", duration2);
    println!("If-else division:  {:?}", duration3);
    println!("If-else chain:     {:?}", duration4);
    println!("Lookup table:      {:?}", duration5);
    println!("Safe lookup:       {:?}", duration6);
}
