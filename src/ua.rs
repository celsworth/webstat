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

        let is_crawler = parsed.is_some_and(|r| r.category == "crawler");
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
mod tests {
    use super::*;

    #[test]
    fn empty_ua_returns_unknown() {
        let mut parser = UaParser::new();
        let result = parser.parse("");
        assert_eq!(result.family.as_ref(), "Unknown");
        assert!(!result.is_bot);
    }

    #[test]
    fn known_bot_families_detected() {
        let mut parser = UaParser::new();

        let bots = vec![
            "Googlebot/2.1",
            "Mozilla/5.0 (compatible; Bingbot/2.0)",
            "AhrefsBot/7.0",
            "Mozilla/5.0 (compatible; YandexBot/3.0)",
        ];

        for bot_ua in bots {
            let result = parser.parse(bot_ua);
            assert!(result.is_bot, "Expected bot detection for: {}", bot_ua);
        }
    }

    #[test]
    fn regex_patterns_detect_bots() {
        let mut parser = UaParser::new();

        let pattern_bots = vec![
            "Mozilla/5.0 RandomBot/1.0",
            "Mozilla/5.0 Spider Agent",
            "Mozilla/5.0 Crawler/2.0",
            "Mozilla/5.0 Scraper Tool/1.0",
        ];

        for bot_ua in pattern_bots {
            let result = parser.parse(bot_ua);
            assert!(result.is_bot, "Expected bot detection for: {}", bot_ua);
        }
    }

    #[test]
    fn human_user_agents_not_bots() {
        let mut parser = UaParser::new();

        let humans = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6)",
            "Mozilla/5.0 (Linux; Android 11)",
        ];

        for human_ua in humans {
            let result = parser.parse(human_ua);
            assert!(!result.is_bot, "Expected non-bot for: {}", human_ua);
        }
    }

    #[test]
    fn cache_prevents_reparse() {
        let mut parser = UaParser::new();

        let ua = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36";

        let result1 = parser.parse(ua);
        assert_eq!(parser.cache.len(), 1);

        let result2 = parser.parse(ua);
        assert_eq!(parser.cache.len(), 1);

        assert_eq!(result1.family.as_ref(), result2.family.as_ref());
        assert_eq!(result1.is_bot, result2.is_bot);
    }

    #[test]
    fn multiple_different_uas_build_cache() {
        let mut parser = UaParser::new();

        let uas = vec![
            "Mozilla/5.0 Chrome/90",
            "Mozilla/5.0 Firefox/88",
            "Mozilla/5.0 Safari/14",
        ];

        for ua in &uas {
            parser.parse(ua);
        }

        assert_eq!(parser.cache.len(), 3);
    }

    #[test]
    fn arc_clone_is_efficient() {
        let mut parser = UaParser::new();

        let ua = "Mozilla/5.0 Chrome/90";
        let result1 = parser.parse(ua);
        let result2 = parser.parse(ua);

        let ptr1 = result1.family.as_ptr();
        let ptr2 = result2.family.as_ptr();
        assert_eq!(ptr1, ptr2, "Arc should point to same memory");
    }

    #[test]
    fn unknown_ua_returns_unknown_family() {
        let mut parser = UaParser::new();
        let unknown_uas = vec!["SomeRandomUA", "???"];
        for ua in unknown_uas {
            let result = parser.parse(ua);
            assert_eq!(result.family.as_ref(), "Unknown");
        }
    }

    #[test]
    fn dash_ua_is_not_a_bot() {
        let mut parser = UaParser::new();
        let result = parser.parse("-");
        assert!(!result.is_bot, "dash '-' UA should not be flagged as bot");
    }

    #[test]
    fn monitor_keyword_triggers_bot_regex() {
        let mut parser = UaParser::new();
        // "monitor" is in the regex pattern
        let result = parser.parse("StatusMonitor/2.0 uptime-checker");
        assert!(result.is_bot);
    }

    #[test]
    fn slurp_keyword_triggers_bot_regex() {
        let mut parser = UaParser::new();
        // "slurp" is in the regex pattern (case-insensitive flag (?i) is set)
        let result = parser.parse("Yahoo! Slurp/3.1");
        assert!(result.is_bot);
    }

    #[test]
    fn validator_keyword_triggers_bot_regex() {
        let mut parser = UaParser::new();
        let result = parser.parse("W3C_Validator/1.3");
        assert!(result.is_bot);
    }

    #[test]
    fn indexer_keyword_triggers_bot_regex() {
        let mut parser = UaParser::new();
        let result = parser.parse("SiteIndexer/1.0");
        assert!(result.is_bot);
    }

    #[test]
    fn fetcher_keyword_triggers_bot_regex() {
        let mut parser = UaParser::new();
        let result = parser.parse("ContentFetcher/2.0");
        assert!(result.is_bot);
    }
}
