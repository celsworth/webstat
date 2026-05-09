#[cfg(test)]
use std::hash::Hasher;

#[cfg(test)]
use twox_hash::XxHash3_64;

#[derive(Debug, Clone)]
pub struct HyperLogLog {
    precision: u8,
    registers: Vec<u8>,
}

impl HyperLogLog {
    pub fn new(precision: u8) -> Self {
        assert!((4..=16).contains(&precision));
        Self {
            precision,
            registers: vec![0; 1usize << precision],
        }
    }

    #[cfg(test)]
    pub fn add_str(&mut self, value: &str) {
        let mut hasher = XxHash3_64::default();
        hasher.write(value.as_bytes());
        self.add_hash(hasher.finish());
    }

    pub fn add_hash(&mut self, hash: u64) {
        let idx = (hash >> (64 - self.precision)) as usize;
        let shifted = hash << self.precision;
        let max_rank = 64 - self.precision as u32 + 1;
        let rank = (shifted.leading_zeros() + 1).min(max_rank) as u8;
        self.registers[idx] = self.registers[idx].max(rank);
    }

    pub fn merge(&mut self, other: &Self) {
        assert_eq!(self.precision, other.precision);
        for (dst, src) in self.registers.iter_mut().zip(&other.registers) {
            *dst = (*dst).max(*src);
        }
    }

    pub fn estimate(&self) -> u64 {
        let m = self.registers.len() as f64;
        let alpha = match self.registers.len() {
            16 => 0.673,
            32 => 0.697,
            64 => 0.709,
            _ => 0.7213 / (1.0 + 1.079 / m),
        };
        let sum: f64 = self
            .registers
            .iter()
            .map(|&rank| 2f64.powi(-(rank as i32)))
            .sum();
        let raw = alpha * m * m / sum;

        let zero_count = self.registers.iter().filter(|&&r| r == 0).count() as f64;

        let estimate = if raw <= 2.5 * m && zero_count > 0.0 {
            // Small range correction: linear counting
            m * (m / zero_count).ln()
        } else if raw <= (1u64 << 32) as f64 / 30.0 {
            // Mid range: no correction needed
            raw
        } else {
            // Large range correction
            -((1u64 << 32) as f64) * (1.0 - raw / (1u64 << 32) as f64).ln()
        };

        estimate.round() as u64
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 + self.registers.len());
        bytes.push(self.precision);
        bytes.extend_from_slice(&self.registers);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let (&precision, registers) = bytes.split_first()?;
        let expected_len = 1usize << precision;
        if registers.len() != expected_len {
            return None;
        }

        Some(Self {
            precision,
            registers: registers.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests;
