// ResponseTimeHistogram: 1ms-bucket histogram for response time tracking.
// Supports merge, percentile, and avg computation. Serializes to/from raw bytes for SQLite.
//
// CompactHistogram: 16-bucket log-scale histogram for per-URL P95 tracking (~64 bytes/URL).

use anyhow::{bail, Result};

const BUCKET_COUNT: usize = 60_001; // 0..=60_000 ms (up to 1 minute)
const SERIAL_LEN: usize = 8 + 8 + 4 + BUCKET_COUNT * 4; // count + sum_ms + overflow + buckets

pub struct ResponseTimeHistogram {
    pub buckets: Vec<u32>, // index = response time in ms
    pub overflow: u32,
    pub count: u64,
    pub sum_ms: u64,
}

impl ResponseTimeHistogram {
    pub fn new() -> Self {
        Self {
            buckets: vec![0u32; BUCKET_COUNT],
            overflow: 0,
            count: 0,
            sum_ms: 0,
        }
    }

    pub fn record(&mut self, ms: u32) {
        self.count += 1;
        self.sum_ms += ms as u64;
        match self.buckets.get_mut(ms as usize) {
            Some(b) => *b += 1,
            None => self.overflow += 1,
        }
    }

    pub fn avg(&self) -> Option<f64> {
        if self.count == 0 {
            None
        } else {
            Some(self.sum_ms as f64 / self.count as f64)
        }
    }

    pub fn percentile(&self, p: f64) -> u32 {
        let target = ((self.count as f64 * p / 100.0).ceil() as u64).max(1);
        let mut seen = 0u64;
        for (ms, &count) in self.buckets.iter().enumerate() {
            seen += count as u64;
            if seen >= target {
                return ms as u32;
            }
        }
        u32::MAX
    }

    pub fn merge(&mut self, other: &ResponseTimeHistogram) {
        for (a, b) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *a += b;
        }
        self.overflow += other.overflow;
        self.count += other.count;
        self.sum_ms += other.sum_ms;
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(SERIAL_LEN);
        buf.extend_from_slice(&self.count.to_le_bytes());
        buf.extend_from_slice(&self.sum_ms.to_le_bytes());
        buf.extend_from_slice(&self.overflow.to_le_bytes());
        for &b in &self.buckets {
            buf.extend_from_slice(&b.to_le_bytes());
        }
        buf
    }

    pub fn deserialize(blob: &[u8]) -> Result<Self> {
        if blob.len() != SERIAL_LEN {
            bail!(
                "response time histogram blob length {} != expected {}",
                blob.len(),
                SERIAL_LEN
            );
        }
        let count = u64::from_le_bytes(blob[0..8].try_into().unwrap());
        let sum_ms = u64::from_le_bytes(blob[8..16].try_into().unwrap());
        let overflow = u32::from_le_bytes(blob[16..20].try_into().unwrap());
        let mut buckets = vec![0u32; BUCKET_COUNT];
        let base = 20;
        for (i, b) in buckets.iter_mut().enumerate() {
            let off = base + i * 4;
            *b = u32::from_le_bytes(blob[off..off + 4].try_into().unwrap());
        }
        Ok(Self { buckets, overflow, count, sum_ms })
    }
}

// ── CompactHistogram ──────────────────────────────────────────────────────────

const COMPACT_BOUNDS: [u32; 16] =
    [0, 1, 5, 10, 25, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 30000, 60000];
const COMPACT_BUCKETS: usize = 16;
const COMPACT_SERIAL_LEN: usize = COMPACT_BUCKETS * 4;

#[derive(Clone)]
pub struct CompactHistogram {
    buckets: [u32; COMPACT_BUCKETS],
}

impl CompactHistogram {
    pub fn new() -> Self {
        Self { buckets: [0u32; COMPACT_BUCKETS] }
    }

    pub fn record(&mut self, ms: u32) {
        let idx = COMPACT_BOUNDS.partition_point(|&b| b <= ms).saturating_sub(1);
        self.buckets[idx] += 1;
    }

    pub fn merge(&mut self, other: &CompactHistogram) {
        for (a, b) in self.buckets.iter_mut().zip(other.buckets.iter()) {
            *a += b;
        }
    }

    pub fn percentile(&self, p: f64) -> u32 {
        let total: u64 = self.buckets.iter().map(|&c| c as u64).sum();
        if total == 0 {
            return 0;
        }
        let target = ((total as f64 * p / 100.0).ceil() as u64).max(1);
        let mut seen = 0u64;
        for (i, &count) in self.buckets.iter().enumerate() {
            seen += count as u64;
            if seen >= target {
                return COMPACT_BOUNDS[i];
            }
        }
        COMPACT_BOUNDS[COMPACT_BUCKETS - 1]
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(COMPACT_SERIAL_LEN);
        for &b in &self.buckets {
            buf.extend_from_slice(&b.to_le_bytes());
        }
        buf
    }

    pub fn deserialize(blob: &[u8]) -> Result<Self> {
        if blob.len() != COMPACT_SERIAL_LEN {
            bail!(
                "compact histogram blob length {} != expected {}",
                blob.len(),
                COMPACT_SERIAL_LEN
            );
        }
        let mut buckets = [0u32; COMPACT_BUCKETS];
        for (i, b) in buckets.iter_mut().enumerate() {
            *b = u32::from_le_bytes(blob[i * 4..(i + 1) * 4].try_into().unwrap());
        }
        Ok(Self { buckets })
    }
}

impl Default for CompactHistogram {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_avg() {
        let mut h = ResponseTimeHistogram::new();
        h.record(100);
        h.record(200);
        assert_eq!(h.count, 2);
        assert_eq!(h.sum_ms, 300);
        assert_eq!(h.avg(), Some(150.0));
    }

    #[test]
    fn percentile_p50() {
        let mut h = ResponseTimeHistogram::new();
        for ms in [10, 20, 30, 40, 50] {
            h.record(ms);
        }
        assert_eq!(h.percentile(50.0), 30);
    }

    #[test]
    fn percentile_p95_overflow() {
        let mut h = ResponseTimeHistogram::new();
        for _ in 0..95 {
            h.record(100);
        }
        for _ in 0..5 {
            h.record(61_000); // overflow
        }
        assert_eq!(h.percentile(95.0), 100);
        assert_eq!(h.percentile(99.0), u32::MAX);
    }

    #[test]
    fn merge_combines_counts() {
        let mut a = ResponseTimeHistogram::new();
        a.record(10);
        let mut b = ResponseTimeHistogram::new();
        b.record(20);
        a.merge(&b);
        assert_eq!(a.count, 2);
        assert_eq!(a.sum_ms, 30);
        assert_eq!(a.buckets[10], 1);
        assert_eq!(a.buckets[20], 1);
    }

    #[test]
    fn round_trip_serialize() {
        let mut h = ResponseTimeHistogram::new();
        h.record(42);
        h.record(61_000);
        let blob = h.serialize();
        let h2 = ResponseTimeHistogram::deserialize(&blob).unwrap();
        assert_eq!(h2.count, 2);
        assert_eq!(h2.sum_ms, h.sum_ms);
        assert_eq!(h2.overflow, 1);
        assert_eq!(h2.buckets[42], 1);
    }

    #[test]
    fn deserialize_wrong_length_errors() {
        assert!(ResponseTimeHistogram::deserialize(&[0u8; 10]).is_err());
    }

    #[test]
    fn compact_percentile_p95() {
        let mut h = CompactHistogram::new();
        for _ in 0..95 {
            h.record(80); // bucket [50, 100) → lower bound 50
        }
        for _ in 0..5 {
            h.record(500);
        }
        assert_eq!(h.percentile(95.0), 50);
        assert_eq!(h.percentile(99.0), 500);
    }

    #[test]
    fn compact_round_trip() {
        let mut h = CompactHistogram::new();
        h.record(150);
        h.record(1500);
        let blob = h.serialize();
        let h2 = CompactHistogram::deserialize(&blob).unwrap();
        assert_eq!(h2.percentile(50.0), 100); // 150 → bucket [100, 200)
        assert_eq!(h2.percentile(100.0), 1000); // 1500 → bucket [1000, 2000)
    }

    #[test]
    fn compact_merge() {
        let mut a = CompactHistogram::new();
        a.record(10);
        let mut b = CompactHistogram::new();
        b.record(100);
        a.merge(&b);
        assert_eq!(a.percentile(50.0), 10);
        assert_eq!(a.percentile(100.0), 100);
    }
}
