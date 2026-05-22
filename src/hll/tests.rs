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

    #[test]
    fn empty_hll_estimate_is_zero() {
        let hll = HyperLogLog::new(12);
        assert_eq!(hll.estimate(), 0);
    }

    #[test]
    fn single_item_estimate_is_near_one() {
        let mut hll = HyperLogLog::new(12);
        hll.add_str("only-item");
        let est = hll.estimate();
        assert!(est >= 1 && est <= 5, "estimate for 1 item was {est}");
    }

    #[test]
    fn add_hash_directly() {
        let mut hll = HyperLogLog::new(12);
        hll.add_hash(0xdead_beef_cafe_1234);
        hll.add_hash(0x1234_5678_9abc_def0);
        let est = hll.estimate();
        assert!(est >= 1 && est <= 10, "estimate for 2 items was {est}");
    }

    #[test]
    fn from_bytes_roundtrip_precision_4() {
        let mut hll = HyperLogLog::new(4);
        for i in 0..20u64 {
            hll.add_str(&format!("item-{i}"));
        }
        let bytes = hll.to_bytes();
        let restored = HyperLogLog::from_bytes(&bytes).expect("should decode");
        assert_eq!(hll.estimate(), restored.estimate());
    }

    #[test]
    fn from_bytes_roundtrip_precision_16() {
        let mut hll = HyperLogLog::new(16);
        for i in 0..1_000u64 {
            hll.add_str(&format!("item-{i}"));
        }
        let bytes = hll.to_bytes();
        let restored = HyperLogLog::from_bytes(&bytes).expect("should decode");
        assert_eq!(hll.estimate(), restored.estimate());
    }

    #[test]
    fn from_bytes_empty_returns_none() {
        assert!(HyperLogLog::from_bytes(&[]).is_none());
    }

    #[test]
    fn from_bytes_single_precision_byte_returns_none() {
        // precision=4 expects 2^4=16 register bytes after it; giving 0 is wrong.
        assert!(HyperLogLog::from_bytes(&[4u8]).is_none());
    }

    #[test]
    fn from_bytes_wrong_register_count_returns_none() {
        // precision=10 → 1024 registers; supply only 5.
        let mut bytes = vec![10u8];
        bytes.extend_from_slice(&[0u8; 5]);
        assert!(HyperLogLog::from_bytes(&bytes).is_none());
    }

    #[test]
    fn merge_self_is_idempotent() {
        let mut hll = HyperLogLog::new(10);
        for i in 0..200u64 {
            hll.add_str(&format!("item-{i}"));
        }
        let before = hll.estimate();
        let clone = hll.clone();
        hll.merge(&clone);
        assert_eq!(hll.estimate(), before);
    }

    #[test]
    fn to_bytes_first_byte_is_precision() {
        let hll = HyperLogLog::new(8);
        let bytes = hll.to_bytes();
        assert_eq!(bytes[0], 8);
        assert_eq!(bytes.len(), 1 + (1 << 8)); // 1 precision byte + 256 registers
    }
}
