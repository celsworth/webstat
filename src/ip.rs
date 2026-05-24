// Ip type: a parsed IPv4/IPv6 address stored as an integer for efficient hashing and geo lookups.

use std::net::Ipv6Addr;

/// A parsed IP address stored as its integer value.
///
/// Used as hash key for geo lookups and daily-unique-IP sets.
/// Avoids round-tripping through `std::net::IpAddr` except where
/// external APIs (maxminddb) require it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Ip {
    V4(u32),
    V6(u128),
}

impl Ip {
    pub fn parse(s: &str) -> Option<Self> {
        if let Some(n) = parse_ipv4_u32(s) {
            return Some(Ip::V4(n));
        }
        parse_ipv6_u128(s).map(Ip::V6)
    }

    /// `ip_kind` column value for the database schema (1=v4, 2=v6).
    pub fn kind(self) -> u8 {
        match self {
            Ip::V4(_) => 1,
            Ip::V6(_) => 2,
        }
    }

    /// `ip_hi` column value (high 64 bits; always 0 for IPv4).
    pub fn hi(self) -> u64 {
        match self {
            Ip::V4(_) => 0,
            Ip::V6(n) => (n >> 64) as u64,
        }
    }

    /// `ip_lo` column value (low 64 bits; full u32 for IPv4).
    pub fn lo(self) -> u64 {
        match self {
            Ip::V4(n) => n as u64,
            Ip::V6(n) => n as u64,
        }
    }

    /// Convert to `std::net::IpAddr` for APIs that require it (e.g. maxminddb).
    pub(crate) fn to_std(self) -> std::net::IpAddr {
        match self {
            Ip::V4(n) => std::net::IpAddr::V4(std::net::Ipv4Addr::from(n)),
            Ip::V6(n) => std::net::IpAddr::V6(std::net::Ipv6Addr::from(n)),
        }
    }
}

// ── Parsers ───────────────────────────────────────────────────────────────────

/// Fast IPv4 parser — returns big-endian packed octets as `u32`.
#[inline]
pub fn parse_ipv4_u32(ip: &str) -> Option<u32> {
    let bytes = ip.as_bytes();
    if bytes.is_empty() {
        return None;
    }

    let mut octets = [0u8; 4];
    let mut octet_idx = 0usize;
    let mut value: u16 = 0;
    let mut saw_digit = false;

    for &b in bytes {
        match b {
            b'0'..=b'9' => {
                saw_digit = true;
                value = value * 10 + (b - b'0') as u16;
                if value > 255 {
                    return None;
                }
            }
            b'.' => {
                if !saw_digit || octet_idx >= 3 {
                    return None;
                }
                octets[octet_idx] = value as u8;
                octet_idx += 1;
                value = 0;
                saw_digit = false;
            }
            _ => return None,
        }
    }

    if !saw_digit || octet_idx != 3 {
        return None;
    }
    octets[3] = value as u8;
    Some(u32::from_be_bytes(octets))
}

/// Parse an IPv6 address string into a `u128`.
#[inline]
pub fn parse_ipv6_u128(ip: &str) -> Option<u128> {
    ip.parse::<Ipv6Addr>().ok().map(u128::from)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_valid() {
        assert!(parse_ipv4_u32("1.2.3.4").is_some());
        assert_eq!(parse_ipv4_u32("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4_u32("255.255.255.255"), Some(u32::MAX));
    }

    #[test]
    fn parse_ipv4_rejects_invalid() {
        assert!(parse_ipv4_u32("").is_none());
        assert!(parse_ipv4_u32("256.0.0.1").is_none());
        assert!(parse_ipv4_u32("1.2.3").is_none());
        assert!(parse_ipv4_u32("1.2.3.4.5").is_none());
        assert!(parse_ipv4_u32("::1").is_none());
    }

    #[test]
    fn parse_ipv4_exact_value() {
        // 1.2.3.4 = (1<<24)|(2<<16)|(3<<8)|4 = 16909060
        assert_eq!(parse_ipv4_u32("1.2.3.4"), Some(16_909_060u32));
    }

    #[test]
    fn parse_ipv4_rejects_trailing_dot() {
        assert!(parse_ipv4_u32("1.2.3.4.").is_none());
    }

    #[test]
    fn parse_ipv4_rejects_leading_dot() {
        assert!(parse_ipv4_u32(".1.2.3.4").is_none());
    }

    #[test]
    fn parse_ipv4_rejects_empty_octet() {
        assert!(parse_ipv4_u32("1..2.3").is_none());
    }

    #[test]
    fn parse_ipv6_valid() {
        assert!(parse_ipv6_u128("::1").is_some());
        assert!(parse_ipv6_u128("2001:db8::1").is_some());
    }

    #[test]
    fn parse_ipv6_rejects_ipv4() {
        assert!(parse_ipv6_u128("1.2.3.4").is_none());
    }

    #[test]
    fn parse_ipv6_loopback_is_one() {
        assert_eq!(parse_ipv6_u128("::1"), Some(1u128));
    }

    #[test]
    fn parse_ipv6_all_zeros() {
        assert_eq!(parse_ipv6_u128("::"), Some(0u128));
    }
}
