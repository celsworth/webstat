use anyhow::{Context, Result};
use serde_json::json;

use super::{
    percent_1dp, short_status_label, DailyRow, HourlyRow, MonthRow, StatusRow, TopAgentRow,
    TopCountryRow, YearAggregateRow, PALETTE,
};

pub(super) fn daily_chart(daily: &[DailyRow]) -> Result<String> {
    let labels: Vec<String> = daily
        .iter()
        .map(|d| d.date.split('-').next_back().unwrap_or("").to_string())
        .collect();
    let hits: Vec<u64> = daily.iter().map(|d| d.hits).collect();
    let pages: Vec<u64> = daily.iter().map(|d| d.pages).collect();
    let files: Vec<u64> = daily.iter().map(|d| d.files).collect();
    let bandwidth: Vec<f64> = daily
        .iter()
        .map(|d| ((d.bandwidth as f64) / 1_048_576.0 * 100.0).round() / 100.0)
        .collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Hits", "data": hits, "backgroundColor": PALETTE[0], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Pages", "data": pages, "backgroundColor": PALETTE[1], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Files", "data": files, "backgroundColor": PALETTE[4], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Bandwidth (MB)", "data": bandwidth, "backgroundColor": PALETTE[2], "yAxisID": "y1", "type": "line", "borderColor": PALETTE[2], "tension": 0.3, "pointRadius": 2, "fill": false }
        ]
      },
      "options": dual_axis_options("Daily Activity")
    }))
    .context("Failed to build daily chart JSON")
}

pub(super) fn daily_visits_chart(daily: &[DailyRow]) -> Result<String> {
    let labels: Vec<String> = daily
        .iter()
        .map(|d| d.date.split('-').next_back().unwrap_or("").to_string())
        .collect();
    let visits: Vec<u64> = daily.iter().map(|d| d.visits).collect();
    let sites: Vec<u64> = daily.iter().map(|d| d.sites).collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Visits", "data": visits, "backgroundColor": PALETTE[5], "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Sites", "data": sites, "backgroundColor": PALETTE[3], "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 }
        ]
      },
      "options": simple_bar_options("Visits & Sites")
    }))
    .context("Failed to build daily visits chart JSON")
}

pub(super) fn hourly_chart(hourly: &[HourlyRow]) -> Result<String> {
    let labels: Vec<String> = hourly.iter().map(|h| h.label.clone()).collect();
    let hits: Vec<u64> = hourly.iter().map(|h| h.hits).collect();
    let pages: Vec<u64> = hourly.iter().map(|h| h.pages).collect();
    let files: Vec<u64> = hourly.iter().map(|h| h.files).collect();
    let bandwidth: Vec<f64> = hourly
        .iter()
        .map(|h| ((h.bandwidth as f64) / 1_048_576.0 * 100.0).round() / 100.0)
        .collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Hits", "data": hits, "backgroundColor": PALETTE[0], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Pages", "data": pages, "backgroundColor": PALETTE[1], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Files", "data": files, "backgroundColor": PALETTE[4], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Bandwidth (MB)", "data": bandwidth, "backgroundColor": PALETTE[2], "yAxisID": "y1", "type": "line", "borderColor": PALETTE[2], "tension": 0.3, "pointRadius": 2, "fill": false }
        ]
      },
      "options": dual_axis_options("Hourly Distribution")
    }))
    .context("Failed to build hourly chart JSON")
}

pub(super) fn monthly_overview_chart(monthly: &[MonthRow]) -> Result<String> {
    let labels: Vec<String> = monthly
        .iter()
        .map(|m| m.month_name.chars().take(3).collect::<String>())
        .collect();
    let hits: Vec<u64> = monthly.iter().map(|m| m.hits).collect();
    let pages: Vec<u64> = monthly.iter().map(|m| m.pages).collect();
    let files: Vec<u64> = monthly.iter().map(|m| m.files).collect();
    let bandwidth: Vec<f64> = monthly
        .iter()
        .map(|m| ((m.bandwidth as f64) / 1_048_576.0 * 100.0).round() / 100.0)
        .collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Hits", "data": hits, "backgroundColor": PALETTE[0], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Pages", "data": pages, "backgroundColor": PALETTE[1], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Files", "data": files, "backgroundColor": PALETTE[4], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Bandwidth (MB)", "data": bandwidth, "backgroundColor": PALETTE[2], "yAxisID": "y1", "type": "line", "borderColor": PALETTE[2], "tension": 0.3, "pointRadius": 3, "fill": false }
        ]
      },
      "options": dual_axis_options("Monthly Overview")
    }))
    .context("Failed to build monthly overview chart JSON")
}

pub(super) fn monthly_visits_chart(monthly: &[MonthRow]) -> Result<String> {
    let labels: Vec<String> = monthly
        .iter()
        .map(|m| m.month_name.chars().take(3).collect::<String>())
        .collect();
    let visits: Vec<u64> = monthly.iter().map(|m| m.visits).collect();
    let sites: Vec<u64> = monthly.iter().map(|m| m.sites).collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Visits", "data": visits, "backgroundColor": PALETTE[5], "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Sites", "data": sites, "backgroundColor": PALETTE[3], "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 }
        ]
      },
      "options": simple_bar_options("Visits & Sites")
    }))
    .context("Failed to build monthly visits chart JSON")
}

pub(super) fn yearly_overview_chart(yearly: &[YearAggregateRow]) -> Result<String> {
    let labels: Vec<String> = yearly.iter().map(|y| y.year.to_string()).collect();
    let hits: Vec<u64> = yearly.iter().map(|y| y.hits).collect();
    let pages: Vec<u64> = yearly.iter().map(|y| y.pages).collect();
    let files: Vec<u64> = yearly.iter().map(|y| y.files).collect();
    let bandwidth: Vec<f64> = yearly
        .iter()
        .map(|y| ((y.bandwidth as f64) / 1_048_576.0 * 100.0).round() / 100.0)
        .collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Hits", "data": hits, "backgroundColor": PALETTE[0], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Pages", "data": pages, "backgroundColor": PALETTE[1], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Files", "data": files, "backgroundColor": PALETTE[4], "yAxisID": "y", "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Bandwidth (MB)", "data": bandwidth, "backgroundColor": PALETTE[2], "yAxisID": "y1", "type": "line", "borderColor": PALETTE[2], "tension": 0.3, "pointRadius": 3, "fill": false }
        ]
      },
      "options": dual_axis_options("Yearly Overview")
    }))
    .context("Failed to build yearly overview chart JSON")
}

pub(super) fn yearly_visits_chart(yearly: &[YearAggregateRow]) -> Result<String> {
    let labels: Vec<String> = yearly.iter().map(|y| y.year.to_string()).collect();
    let visits: Vec<u64> = yearly.iter().map(|y| y.visits).collect();
    let sites: Vec<u64> = yearly.iter().map(|y| y.sites).collect();

    serde_json::to_string(&json!({
      "type": "bar",
      "data": {
        "labels": labels,
        "datasets": [
          { "label": "Visits", "data": visits, "backgroundColor": PALETTE[5], "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 },
          { "label": "Sites", "data": sites, "backgroundColor": PALETTE[3], "borderColor": "#999", "borderWidth": 1, "borderRadius": 2 }
        ]
      },
      "options": simple_bar_options("Visits & Sites")
    }))
    .context("Failed to build yearly visits chart JSON")
}

pub(super) fn status_chart(status_codes: &[StatusRow]) -> Result<String> {
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
        colors.push(status_color(s.status, i).to_string());
    }

    if other_sum > 0 {
        labels.push(format!(
            "Other ({:.1}%)",
            percent_1dp(other_sum as f64, total as f64)
        ));
        data.push(other_sum);
        colors.push("#bab0ac".to_string());
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

fn status_color(status: u16, index: usize) -> &'static str {
    match status {
        200..=299 => "#52c493",
        300..=399 => "#7090ff",
        400..=499 => "#ffc055",
        500..=599 => "#ff7a7a",
        _ => PALETTE[index % PALETTE.len()],
    }
}
