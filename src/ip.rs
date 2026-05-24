// Ip type: a parsed IPv4/IPv6 address stored as an integer for efficient hashing and geo lookups.

use crate::util::{parse_ipv4_u32, parse_ipv6_u128};

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
