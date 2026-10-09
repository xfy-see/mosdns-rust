//! Go forward collector names and labels, fed by optional upstream callbacks.
#![cfg(feature = "full")]

use crate::pkg::{
    metrics::{Counter, Gauge, Histogram, MetricRegistry},
    upstream::{Event, EventObserver, QueryOutcome},
};
use anyhow::Result;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

pub const LATENCY_BOUNDS: &[f64] = &[
    1.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0, 2000.0, 5000.0,
];
pub(crate) struct ForwardMetrics {
    registry: MetricRegistry,
    next_owner: AtomicU64,
}
impl ForwardMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            registry: MetricRegistry::new(),
            next_owner: AtomicU64::new(1),
        })
    }
    pub fn text(&self) -> String {
        self.registry.text()
    }
    pub fn begin(self: &Arc<Self>) -> MetricsScope {
        MetricsScope {
            store: self.clone(),
            owner: self.next_owner.fetch_add(1, Ordering::Relaxed),
            active: Arc::new(AtomicBool::new(true)),
            committed: false,
        }
    }
}
/// A failed Forward constructor must not retain partial families or conflict
/// with a later retry. Committed dependency collectors survive caller rollback.
pub(crate) struct MetricsScope {
    store: Arc<ForwardMetrics>,
    owner: u64,
    active: Arc<AtomicBool>,
    committed: bool,
}
impl MetricsScope {
    pub fn observer(&self, tag: &str, upstream: &str) -> Result<Arc<dyn EventObserver>> {
        let r = self
            .store
            .registry
            .owned_registerer(self.owner, self.active.clone())
            .with_prefix("mosdns_forward_")
            .with_const_label("tag", tag)?
            .with_const_label("upstream", upstream)?;
        Ok(Arc::new(UpstreamMetrics {
            queries: r.counter(
                "query_total",
                "The total number of queries processed by this upstream",
            )?,
            errors: r.counter("err_total", "The total number of queries failed")?,
            active: r.gauge(
                "thread",
                "The number of threads (queries) that are currently being processed",
            )?,
            latency: r.histogram(
                "response_latency_millisecond",
                "The response latency in millisecond",
                LATENCY_BOUNDS,
            )?,
            opened: r.counter(
                "conn_opened_total",
                "The total number of connections that are opened",
            )?,
            closed: r.counter(
                "conn_closed_total",
                "The total number of connections that are closed",
            )?,
        }))
    }
    pub fn commit(mut self) {
        self.committed = true;
    }
}
impl Drop for MetricsScope {
    fn drop(&mut self) {
        if !self.committed {
            self.active.store(false, Ordering::Release);
            self.store.registry.unregister_owner(self.owner);
        }
    }
}
struct UpstreamMetrics {
    queries: Counter,
    errors: Counter,
    active: Gauge,
    latency: Histogram,
    opened: Counter,
    closed: Counter,
}
impl EventObserver for UpstreamMetrics {
    fn on_event(&self, event: Event) {
        let _ = match event {
            Event::ConnOpen => self.opened.inc(),
            Event::ConnClose => self.closed.inc(),
        };
    }
    fn query_started(&self) {
        let _ = self.queries.inc();
        let _ = self.active.inc();
    }
    fn query_finished(&self, outcome: QueryOutcome, elapsed: Duration) {
        let _ = self.active.dec();
        match outcome {
            QueryOutcome::Success => {
                let _ = self.latency.observe(elapsed.as_millis() as f64);
            }
            QueryOutcome::Error | QueryOutcome::Cancelled => {
                let _ = self.errors.inc();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_scope_rolls_back_partial_collectors_and_retry_keeps_committed_dependency() {
        let store = ForwardMetrics::new();
        let dependency = store.begin();
        dependency.observer("dependency", "primary").unwrap();
        dependency.commit();
        {
            let failed = store.begin();
            failed.observer("retry", "primary").unwrap();
            assert!(failed.observer("retry", "primary").is_err());
        }
        assert!(!store.text().contains("tag=\"retry\""));
        assert!(store.text().contains("tag=\"dependency\""));
        let retry = store.begin();
        retry.observer("retry", "primary").unwrap();
        retry.commit();
        let text = store.text();
        assert!(text.contains("tag=\"retry\""));
        assert_eq!(
            text.matches("# TYPE mosdns_forward_query_total counter\n")
                .count(),
            1
        );
    }
    #[test]
    fn callbacks_count_all_queries_but_only_success_observes_truncated_milliseconds() {
        let store = ForwardMetrics::new();
        let scope = store.begin();
        let observer = scope.observer("fixture", "primary").unwrap();
        scope.commit();
        for outcome in [
            QueryOutcome::Success,
            QueryOutcome::Error,
            QueryOutcome::Cancelled,
        ] {
            observer.query_started();
            observer.query_finished(outcome, Duration::from_micros(1999));
        }
        observer.on_event(Event::ConnOpen);
        observer.on_event(Event::ConnClose);
        let text = store.text();
        for (name, value) in [
            ("query_total", 3),
            ("err_total", 2),
            ("thread", 0),
            ("response_latency_millisecond_count", 1),
            ("response_latency_millisecond_sum", 1),
            ("conn_opened_total", 1),
            ("conn_closed_total", 1),
        ] {
            assert!(
                text.contains(&format!(
                    "mosdns_forward_{name}{{tag=\"fixture\",upstream=\"primary\"}} {value}\n"
                )),
                "{text}"
            );
        }
        assert!(text.contains("le=\"1\"} 1\n"));
    }
}
