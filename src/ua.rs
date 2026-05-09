use std::sync::Arc;

use ahash::AHashMap;
use regex::Regex;
use woothee::parser::Parser as WootheeParser;

/// Result of parsing a User-Agent string.
pub struct UaResult {
    /// Cheap to clone — backed by an `Arc`.
    pub family: Arc<str>,
    pub is_bot: bool,
}

/// UA family names (lowercased) that are always considered bots.
const BOT_FAMILIES: &[&str] = &[
    "googlebot",
    "bingbot",
    "slurp",
    "duckduckbot",
    "baiduspider",
    "yandexbot",
    "sogou",
    "exabot",
    "ia_archiver",
    "facebot",
    "ahrefsbot",
    "semrushbot",
    "mj12bot",
    "dotbot",
    "blexbot",
    "petalbot",
    "crawlerng",
    "rogerbot",
    "linkdreamer",
    "screaming frog",
    "libwww-perl",
    "python-urllib",
    "python-requests",
    "curl",
    "wget",
    "java",
    "apache-httpclient",
    "go-http-client",
];

pub struct UaParser {
    woothee: WootheeParser,
    bot_re: Regex,
    cache: AHashMap<String, UaResultCached>,
}

#[derive(Clone)]
struct UaResultCached {
    family: Arc<str>,
    is_bot: bool,
}

impl UaParser {
    pub fn new() -> Self {
        let bot_re = Regex::new(
            r"(?xi)
            bot\b | crawl | spider | scraper | archiver | checker |
            monitor | validator | fetcher | reader | slurp | indexer
            ",
        )
        .expect("bot regex is valid");

        Self {
            woothee: WootheeParser::new(),
            bot_re,
            cache: AHashMap::with_capacity(1024),
        }
    }

    /// Parse a raw UA string and return its family name and bot flag.
    /// Results are memoised — log files typically have O(hundreds) of unique
    /// UAs repeated thousands of times.
    ///
    /// The returned `family` is an `Arc<str>`, so cloning it on every log line
    /// costs only an atomic reference-count increment rather than a heap allocation.
    pub fn parse(&mut self, ua: &str) -> UaResult {
        if ua.is_empty() {
            return UaResult {
                family: Arc::from("Unknown"),
                is_bot: false,
            };
        }

        if let Some(cached) = self.cache.get(ua) {
            // Arc::clone is a single atomic increment — not a heap allocation.
            return UaResult {
                family: Arc::clone(&cached.family),
                is_bot: cached.is_bot,
            };
        }

        let (family, is_bot) = self.classify(ua);
        self.cache.insert(
            ua.to_string(),
            UaResultCached {
                family: Arc::clone(&family),
                is_bot,
            },
        );
        UaResult { family, is_bot }
    }

    /// Parse once, derive both family name and bot flag from the single result.
    /// Previously this called `woothee.parse()` twice per unique UA.
    fn classify(&self, ua: &str) -> (Arc<str>, bool) {
        let parsed = self.woothee.parse(ua);

        let family: Arc<str> = match &parsed {
            Some(r) if !r.name.is_empty() && r.name != "UNKNOWN" => Arc::from(r.name),
            _ => Arc::from("Unknown"),
        };

        let is_crawler = parsed.map_or(false, |r| r.category == "crawler");
        let is_bot = is_crawler || self.is_bot_heuristic(&family, ua);
        (family, is_bot)
    }

    fn is_bot_heuristic(&self, family: &str, raw_ua: &str) -> bool {
        let fam_lc = family.to_lowercase();
        if BOT_FAMILIES.iter().any(|&p| fam_lc.contains(p)) {
            return true;
        }
        self.bot_re.is_match(raw_ua)
    }
}

#[cfg(test)]
mod tests;
