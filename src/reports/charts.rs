// Chart.js dataset assembly: builds JSON series for traffic, status-code, and bandwidth charts.

use anyhow::{Context, Result};
use serde_json::json;

use super::{
    percent_1dp, short_status_label, DailyRow, HourlyRow, MonthRow, StatusRow, TopAgentRow,
    TopCountryRow, YearAggregateRow, PALETTE,
};
use crate::config::StyleConfig;

pub(super) fn daily_chart(daily: &[DailyRow], style: &StyleConfig) -> Result<String> {
    let bar_hits = style.bar_hits.as_deref().unwrap_or(PALETTE[0]);
    let bar_hits_weekend = style.bar_hits_weekend.as_deref().unwrap_or("#5bb4b3");
    let bar_bandwidth = style.line_bandwidth.as_deref().unwrap_or(PALETTE[2]);

    let labels: Vec<String> = daily
        .iter()
        .map(|d| d.date.split('-').next_back().unwrap_or("").to_string())
        .collect();
    let hits: Vec<u64> = daily.iter().map(|d| d.hits).collect();
    let hits_colors: Vec<&str> = daily
        .iter()
        .map(|d| if d.is_weekend { bar_hits_weekend } else { bar_hits })
        .collect();
    let bandwidth: Vec<f64> = daily
        .iter()
        .map(|d| ((d.bandwidth as f64) / 1_048_576.0 * 100.0).round() / 100.0)
        .collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Hits", "data": hits, "backgroundColor": hits_colors, "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2, "order": 1 },
          { "label": "Bandwidth (MB)", "data": bandwidth, "backgroundColor": bar_bandwidth, "yAxisID": "y1", "type": "line", "borderColor": bar_bandwidth, "tension": 0.3, "pointRadius": 2, "fill": false, "order": 0 }
        ]
      },
      "options": dual_axis_options("Daily Activity")
    }))
    .context("Failed to build daily chart JSON")
}

pub(super) fn daily_visits_chart(daily: &[DailyRow], style: &StyleConfig) -> Result<String> {
    let bar_visits = style.bar_visits.as_deref().unwrap_or(PALETTE[5]);
    let bar_visits_weekend = style.bar_visits_weekend.as_deref().unwrap_or("#d4cf94");
    let bar_sites = style.bar_sites.as_deref().unwrap_or(PALETTE[3]);
    let bar_sites_weekend = style.bar_sites_weekend.as_deref().unwrap_or("#d4b288");

    let labels: Vec<String> = daily
        .iter()
        .map(|d| d.date.split('-').next_back().unwrap_or("").to_string())
        .collect();
    let visits: Vec<u64> = daily.iter().map(|d| d.visits).collect();
    let visits_colors: Vec<&str> = daily
        .iter()
        .map(|d| if d.is_weekend { bar_visits_weekend } else { bar_visits })
        .collect();
    let visitors: Vec<u64> = daily.iter().map(|d| d.visitors).collect();
    let visitors_colors: Vec<&str> = daily
        .iter()
        .map(|d| if d.is_weekend { bar_sites_weekend } else { bar_sites })
        .collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Visits", "data": visits, "backgroundColor": visits_colors, "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Sites", "data": visitors, "backgroundColor": visitors_colors, "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 }
        ]
      },
      "options": simple_bar_options("Visits & Sites")
    }))
    .context("Failed to build daily visits chart JSON")
}

pub(super) fn hourly_chart(hourly: &[HourlyRow], style: &StyleConfig) -> Result<String> {
    let bar_hits = style.bar_hits.as_deref().unwrap_or(PALETTE[0]);
    let bar_bandwidth = style.line_bandwidth.as_deref().unwrap_or(PALETTE[2]);

    let labels: Vec<String> = hourly.iter().map(|h| h.label.clone()).collect();
    let hits: Vec<u64> = hourly.iter().map(|h| h.hits).collect();
    let bandwidth: Vec<f64> = hourly
        .iter()
        .map(|h| ((h.bandwidth as f64) / 1_048_576.0 * 100.0).round() / 100.0)
        .collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Hits", "data": hits, "backgroundColor": bar_hits, "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2, "order": 1 },
          { "label": "Bandwidth (MB)", "data": bandwidth, "backgroundColor": bar_bandwidth, "yAxisID": "y1", "type": "line", "borderColor": bar_bandwidth, "tension": 0.3, "pointRadius": 2, "fill": false, "order": 0 }
        ]
      },
      "options": dual_axis_options("Hourly Distribution")
    }))
    .context("Failed to build hourly chart JSON")
}

pub(super) fn monthly_overview_chart(monthly: &[MonthRow], style: &StyleConfig) -> Result<String> {
    let bar_hits = style.bar_hits.as_deref().unwrap_or(PALETTE[0]);
    let bar_bandwidth = style.line_bandwidth.as_deref().unwrap_or(PALETTE[2]);

    let labels: Vec<String> = monthly
        .iter()
        .map(|m| m.month_name.chars().take(3).collect::<String>())
        .collect();
    let hits: Vec<u64> = monthly.iter().map(|m| m.hits).collect();
    let bandwidth: Vec<f64> = monthly
        .iter()
        .map(|m| ((m.bandwidth as f64) / 1_048_576.0 * 100.0).round() / 100.0)
        .collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Hits", "data": hits, "backgroundColor": bar_hits, "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2, "order": 1 },
          { "label": "Bandwidth (MB)", "data": bandwidth, "backgroundColor": bar_bandwidth, "yAxisID": "y1", "type": "line", "borderColor": bar_bandwidth, "tension": 0.3, "pointRadius": 3, "fill": false, "order": 0 }
        ]
      },
      "options": dual_axis_options("Monthly Overview")
    }))
    .context("Failed to build monthly overview chart JSON")
}

pub(super) fn monthly_visits_chart(monthly: &[MonthRow], style: &StyleConfig) -> Result<String> {
    let bar_visits = style.bar_visits.as_deref().unwrap_or(PALETTE[5]);
    let bar_sites = style.bar_sites.as_deref().unwrap_or(PALETTE[3]);

    let labels: Vec<String> = monthly
        .iter()
        .map(|m| m.month_name.chars().take(3).collect::<String>())
        .collect();
    let visits: Vec<u64> = monthly.iter().map(|m| m.visits).collect();
    let visitors: Vec<u64> = monthly.iter().map(|m| m.visitors).collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Visits", "data": visits, "backgroundColor": bar_visits, "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Sites", "data": visitors, "backgroundColor": bar_sites, "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 }
        ]
      },
      "options": simple_bar_options("Visits & Sites")
    }))
    .context("Failed to build monthly visits chart JSON")
}

pub(super) fn yearly_overview_chart(yearly: &[YearAggregateRow], style: &StyleConfig) -> Result<String> {
    let bar_hits = style.bar_hits.as_deref().unwrap_or(PALETTE[0]);
    let bar_bandwidth = style.line_bandwidth.as_deref().unwrap_or(PALETTE[2]);

    let labels: Vec<String> = yearly.iter().map(|y| y.year.to_string()).collect();
    let hits: Vec<u64> = yearly.iter().map(|y| y.hits).collect();
    let bandwidth: Vec<f64> = yearly
        .iter()
        .map(|y| ((y.bandwidth as f64) / 1_048_576.0 * 100.0).round() / 100.0)
        .collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Hits", "data": hits, "backgroundColor": bar_hits, "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2, "order": 1 },
          { "label": "Bandwidth (MB)", "data": bandwidth, "backgroundColor": bar_bandwidth, "yAxisID": "y1", "type": "line", "borderColor": bar_bandwidth, "tension": 0.3, "pointRadius": 3, "fill": false, "order": 0 }
        ]
      },
      "options": dual_axis_options("Yearly Overview")
    }))
    .context("Failed to build yearly overview chart JSON")
}

pub(super) fn yearly_visits_chart(yearly: &[YearAggregateRow], style: &StyleConfig) -> Result<String> {
    let bar_visits = style.bar_visits.as_deref().unwrap_or(PALETTE[5]);
    let bar_sites = style.bar_sites.as_deref().unwrap_or(PALETTE[3]);

    let labels: Vec<String> = yearly.iter().map(|y| y.year.to_string()).collect();
    let visits: Vec<u64> = yearly.iter().map(|y| y.visits).collect();
    let visitors: Vec<u64> = yearly.iter().map(|y| y.visitors).collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Visits", "data": visits, "backgroundColor": bar_visits, "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Sites", "data": visitors, "backgroundColor": bar_sites, "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 }
        ]
      },
      "options": simple_bar_options("Visits & Sites")
    }))
    .context("Failed to build yearly visits chart JSON")
}

pub(super) fn status_chart(status_codes: &[StatusRow], style: &StyleConfig) -> Result<String> {
    let total = status_codes.iter().map(|s| s.hits).sum::<u64>();
    let mut main = status_codes.to_vec();
    main.sort_by_key(|s| std::cmp::Reverse(s.hits));
    main.truncate(5);

    let main_sum = main.iter().map(|s| s.hits).sum::<u64>();
    let other_sum = total.saturating_sub(main_sum);

    let mut labels = Vec::new();
    let mut data = Vec::new();
    let mut colors = Vec::new();

    for (i, s) in main.iter().enumerate() {
        let pct = percent_1dp(s.hits as f64, total as f64);
        labels.push(format!("{} ({:.1}%)", short_status_label(s.status), pct));
        data.push(s.hits);
        colors.push(status_color(s.status, style, i).to_string());
    }

    if other_sum > 0 {
        labels.push(format!(
            "Other ({:.1}%)",
            percent_1dp(other_sum as f64, total as f64)
        ));
        data.push(other_sum);
        colors.push(
            style
                .status_other_color
                .as_deref()
                .unwrap_or("#bab0ac")
                .to_string(),
        );
    }

    serde_json::to_string(&json!({
      "type": "doughnut",
      "data": {
        "labels": labels,
        "datasets": [{ "data": data, "backgroundColor": colors, "borderWidth": 1 }]
      },
      "options": doughnut_options("HTTP Status Codes")
    }))
    .context("Failed to build status chart JSON")
}

pub(super) fn countries_chart(countries: &[TopCountryRow]) -> Result<String> {
    let total = countries.iter().map(|c| c.hits).sum::<u64>();
    let mut main = countries.to_vec();
    main.sort_by_key(|c| std::cmp::Reverse(c.hits));
    let others = if main.len() > 9 {
        main.split_off(9).iter().map(|c| c.hits).sum::<u64>()
    } else {
        0
    };

    let mut labels = Vec::new();
    let mut data = Vec::new();
    for c in &main {
        labels.push(format!(
            "{} ({:.1}%)",
            c.country_code,
            percent_1dp(c.hits as f64, total as f64)
        ));
        data.push(c.hits);
    }

    if others > 0 {
        labels.push(format!(
            "Other ({:.1}%)",
            percent_1dp(others as f64, total as f64)
        ));
        data.push(others);
    }

    let colors: Vec<&str> = (0..data.len())
        .map(|i| PALETTE[i % PALETTE.len()])
        .collect();

    serde_json::to_string(&json!({
      "type": "doughnut",
      "data": {
        "labels": labels,
        "datasets": [{ "data": data, "backgroundColor": colors, "borderWidth": 1 }]
      },
      "options": doughnut_options("Top Countries")
    }))
    .context("Failed to build countries chart JSON")
}

pub(super) fn agents_chart(agents: &[TopAgentRow]) -> Result<String> {
    let total = agents.iter().map(|a| a.hits).sum::<u64>();
    let mut main = agents.to_vec();
    main.sort_by_key(|a| std::cmp::Reverse(a.hits));
    let others = if main.len() > 9 {
        main.split_off(9).iter().map(|a| a.hits).sum::<u64>()
    } else {
        0
    };

    let mut labels = Vec::new();
    let mut data = Vec::new();
    for a in &main {
        labels.push(format!(
            "{} ({:.1}%)",
            a.agent,
            percent_1dp(a.hits as f64, total as f64)
        ));
        data.push(a.hits);
    }
    if others > 0 {
        labels.push(format!(
            "Other ({:.1}%)",
            percent_1dp(others as f64, total as f64)
        ));
        data.push(others);
    }

    let colors: Vec<&str> = (0..data.len())
        .map(|i| PALETTE[i % PALETTE.len()])
        .collect();

    serde_json::to_string(&json!({
      "type": "doughnut",
      "data": {
        "labels": labels,
        "datasets": [{ "data": data, "backgroundColor": colors, "borderWidth": 1 }]
      },
      "options": doughnut_options("Browser Families")
    }))
    .context("Failed to build agents chart JSON")
}

fn doughnut_options(title: &str) -> serde_json::Value {
    json!({
      "responsive": true,
      "maintainAspectRatio": false,
      "plugins": {
        "legend": {
          "position": "bottom",
          "align": "center",
          "maxHeight": 96,
          "labels": {
            "boxWidth": 10,
            "boxHeight": 10,
            "padding": 8,
            "usePointStyle": true,
            "font": { "size": 10 }
          }
        },
        "title": { "display": true, "text": title }
      }
    })
}

fn simple_bar_options(title: &str) -> serde_json::Value {
    json!({
      "responsive": true,
      "maintainAspectRatio": false,
      "plugins": {
        "legend": { "position": "top" },
        "title": { "display": true, "text": title }
      },
      "scales": {
        "x": { "stacked": false },
        "y": { "beginAtZero": true }
      }
    })
}

fn dual_axis_options(title: &str) -> serde_json::Value {
    json!({
      "responsive": true,
      "maintainAspectRatio": false,
      "plugins": {
        "legend": { "position": "top" },
        "title": { "display": true, "text": title }
      },
      "scales": {
        "x": { "stacked": false },
        "y": { "beginAtZero": true, "position": "left", "title": { "display": true, "text": "Count" } },
        "y1": { "beginAtZero": true, "position": "right", "title": { "display": true, "text": "MB" }, "grid": { "drawOnChartArea": false } }
      }
    })
}

pub(super) fn response_time_over_time_chart(
    labels: &[&str],
    avgs: &[f64],
    p95s: &[u32],
) -> Result<String> {
    let p95s_f: Vec<f64> = p95s.iter().map(|&v| v as f64).collect();
    serde_json::to_string(&json!({
      "type": "line",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Avg (ms)", "data": avgs, "borderColor": PALETTE[0], "backgroundColor": PALETTE[0],
            "tension": 0.3, "pointRadius": 3, "fill": false, "yAxisID": "y" },
          { "label": "p95 (ms)", "data": p95s_f, "borderColor": PALETTE[2], "backgroundColor": PALETTE[2],
            "tension": 0.3, "pointRadius": 3, "fill": false, "borderDash": [4, 3], "yAxisID": "y" }
        ]
      },
      "options": {
        "responsive": true,
        "maintainAspectRatio": false,
        "plugins": {
          "legend": { "position": "top" },
          "title": { "display": true, "text": "Response Time" }
        },
        "scales": {
          "y": { "beginAtZero": true, "title": { "display": true, "text": "ms" } }
        }
      }
    }))
    .context("Failed to build response time over time chart JSON")
}

pub(super) fn response_time_distribution_chart(
    bucket_labels: &[&str],
    counts: &[u64],
) -> Result<String> {
    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": bucket_labels,
        "datasets": [{
          "label": "Requests",
          "data": counts,
          "backgroundColor": PALETTE[1],
          "borderColor": "#999",
          "borderWidth": 1,
          "borderRadius": 2
        }]
      },
      "options": simple_bar_options("Response Time Distribution")
    }))
    .context("Failed to build response time distribution chart JSON")
}

fn status_color(status: u16, style: &StyleConfig, index: usize) -> &str {
    match status {
        200..=299 => style.status_2xx_color.as_deref().unwrap_or("#52c493"),
        300..=399 => style.status_3xx_color.as_deref().unwrap_or("#7090ff"),
        400..=499 => style.status_4xx_color.as_deref().unwrap_or("#ffc055"),
        500..=599 => style.status_5xx_color.as_deref().unwrap_or("#ff7a7a"),
        _ => style
            .status_other_color
            .as_deref()
            .unwrap_or(PALETTE[index % PALETTE.len()]),
    }
}
