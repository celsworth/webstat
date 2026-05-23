use super::*;

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
