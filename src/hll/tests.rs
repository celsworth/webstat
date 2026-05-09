use super::*;

#[cfg(test)]
mod tests {
    use super::HyperLogLog;

    #[test]
    fn merge_and_roundtrip_preserve_reasonable_estimate() {
        let mut left = HyperLogLog::new(10);
        let mut right = HyperLogLog::new(10);
        for i in 0..500u64 {
            left.add_str(&format!("left-{i}"));
            right.add_str(&format!("right-{i}"));
        }
        for i in 0..100u64 {
            left.add_str(&format!("shared-{i}"));
            right.add_str(&format!("shared-{i}"));
        }

        let mut merged = HyperLogLog::from_bytes(&left.to_bytes()).expect("decode hll");
        merged.merge(&right);

        let estimate = merged.estimate();
        assert!(estimate > 800);
        assert!(estimate < 1_200);
    }

    // In hll.rs tests
    #[test]
    fn estimates_distinct_values_reasonably() {
        let mut hll = HyperLogLog::new(14);
        for i in 0..5_000_000u64 {
            hll.add_str(&format!("host-{i}"));
        }
        let estimate = hll.estimate() as i64;
        let error = (estimate - 5_000_000).abs() as f64 / 5_000_000.0;
        assert!(error < 0.02, "estimate={estimate}, error={error}");
    }
}
