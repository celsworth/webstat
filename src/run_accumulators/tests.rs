use super::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accumulators::HourlyAcc;
    use crate::method_proto::{METHOD_GET, PROTO_1_1};
    #[test]
    fn new_is_empty() {
        let acc = RunAccumulators::new("2026-05".to_string());
        assert!(acc.is_empty());
        assert_eq!(acc.current_month, "2026-05");
    }

    #[test]
    fn status_codes_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.status_codes.insert(200u16, 1u64);
        assert!(!acc.is_empty());
    }

    #[test]
    fn method_counts_nonzero_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.method_counts[METHOD_GET] = 5;
        assert!(!acc.is_empty());
    }

    #[test]
    fn proto_counts_nonzero_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.proto_counts[PROTO_1_1] = 3;
        assert!(!acc.is_empty());
    }

    #[test]
    fn hourly_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        let mut hourly_acc = HourlyAcc::default();
        hourly_acc.stats.hits = 1;
        acc.hourly
            .entry(std::sync::Arc::from("2026-05-10"))
            .or_default()
            .insert(10, hourly_acc);
        assert!(!acc.is_empty());
    }

    #[test]
    fn urls_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.urls.insert("/index.html".to_string(), (5, 1024));
        assert!(!acc.is_empty());
    }

    #[test]
    fn hosts_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.hosts.insert("1.2.3.4".to_string(), (3, 512));
        assert!(!acc.is_empty());
    }

    #[test]
    fn refs_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.refs.insert("example.com".to_string(), 7);
        assert!(!acc.is_empty());
    }

    #[test]
    fn agents_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.agents.insert("Chrome".to_string(), 4);
        assert!(!acc.is_empty());
    }

    #[test]
    fn countries_populated_makes_non_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.countries.insert("US".to_string(), 100);
        assert!(!acc.is_empty());
    }

    #[test]
    fn clear_for_new_month_resets_all_and_updates_month() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.urls.insert("/index.html".to_string(), (5, 1024));
        acc.method_counts[METHOD_GET] = 10;
        acc.proto_counts[PROTO_1_1] = 10;
        acc.clear_for_new_month("2026-06".to_string());
        assert!(acc.is_empty());
        assert_eq!(acc.current_month, "2026-06");
    }

    #[test]
    fn daily_ips_not_counted_in_is_empty() {
        let mut acc = RunAccumulators::new("2026-05".to_string());
        acc.daily_ips
            .entry("2026-05-01".to_string())
            .or_default()
            .insert(crate::ip::Ip::V4(0x01020304));
        // daily_ips does not affect is_empty (it's just a write buffer)
        assert!(acc.is_empty());
    }
}
