use std::{collections::HashMap, sync::RwLock, time::Duration};

use serde::Serialize;

use crate::transport::RouteKind;

#[derive(Default)]
pub struct RouteMetricsRegistry {
    inner: RwLock<HashMap<RouteKind, RouteMetricInner>>,
}

#[derive(Default, Clone)]
struct RouteMetricInner {
    attempts: u64,
    successes: u64,
    failures: u64,
    total_latency_ms: u128,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteMetricsSnapshot {
    pub route: String,
    pub attempts: u64,
    pub successes: u64,
    pub failures: u64,
    pub success_rate: Option<f32>,
    pub avg_latency_ms: Option<f32>,
    pub last_error: Option<String>,
}

impl RouteMetricsRegistry {
    pub fn record(&self, route: RouteKind, latency: Duration, success: bool, error: Option<&str>) {
        if let Ok(mut guard) = self.inner.write() {
            let entry = guard.entry(route).or_default();
            entry.attempts = entry.attempts.saturating_add(1);
            if success {
                entry.successes = entry.successes.saturating_add(1);
                entry.total_latency_ms = entry.total_latency_ms.saturating_add(latency.as_millis());
                if error.is_some() {
                    entry.last_error = error.map(|s| s.to_string());
                }
            } else {
                entry.failures = entry.failures.saturating_add(1);
                if let Some(message) = error {
                    entry.last_error = Some(message.to_string());
                }
            }
        }
    }

    pub fn avg_latency(&self, route: &RouteKind) -> Option<Duration> {
        self.inner
            .read()
            .ok()
            .and_then(|map| map.get(route).cloned())
            .and_then(|stats| {
                if stats.successes > 0 {
                    Some(Duration::from_millis(
                        (stats.total_latency_ms / stats.successes as u128) as u64,
                    ))
                } else {
                    None
                }
            })
    }

    pub fn snapshot(&self) -> Vec<RouteMetricsSnapshot> {
        let guard = self.inner.read().ok();
        let map = guard.map(|inner| inner.clone()).unwrap_or_default();
        let mut items: Vec<_> = map
            .into_iter()
            .map(|(route, stats)| RouteMetricsSnapshot {
                route: route.label().to_string(),
                attempts: stats.attempts,
                successes: stats.successes,
                failures: stats.failures,
                success_rate: if stats.attempts > 0 {
                    Some(stats.successes as f32 / stats.attempts as f32)
                } else {
                    None
                },
                avg_latency_ms: if stats.successes > 0 {
                    Some((stats.total_latency_ms as f32) / stats.successes as f32)
                } else {
                    None
                },
                last_error: stats.last_error.clone(),
            })
            .collect();
        items.sort_by(|a, b| a.route.cmp(&b.route));
        items
    }

    pub fn success_rate(&self, route: &RouteKind) -> Option<f32> {
        self.inner
            .read()
            .ok()
            .and_then(|map| map.get(route).cloned())
            .and_then(|stats| {
                if stats.attempts > 0 {
                    Some(stats.successes as f32 / stats.attempts as f32)
                } else {
                    None
                }
            })
    }
}
