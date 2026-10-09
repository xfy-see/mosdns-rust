// SPDX-License-Identifier: GPL-3.0-or-later
//! Stateless adapters for call sites shared with the full build. Minimal builds
//! do not register collectors, retain labels, read process data, or count events.
use anyhow::Result;
use std::sync::{atomic::AtomicBool, Arc};

#[derive(Clone, Copy, Default)]
pub struct MetricRegistry;
#[derive(Clone, Copy, Default)]
pub struct Registerer;
#[derive(Clone, Copy, Default)]
pub struct Counter;
#[derive(Clone, Copy, Default)]
pub struct Gauge;
#[derive(Clone, Copy, Default)]
pub struct Histogram;

impl MetricRegistry {
    pub fn new() -> Self {
        Self
    }
    pub fn registerer(&self) -> Registerer {
        Registerer
    }
    pub(crate) fn owned_registerer(&self, _owner: u64, _active: Arc<AtomicBool>) -> Registerer {
        Registerer
    }
    pub(crate) fn unregister_owner(&self, _owner: u64) {}
    pub fn reserve_names(&self, _names: &[&str]) -> Result<()> {
        Ok(())
    }
    pub fn text(&self) -> String {
        String::new()
    }
}

impl Registerer {
    pub fn with_prefix(&self, _prefix: &str) -> Self {
        *self
    }
    pub fn with_const_label(&self, _name: &str, _value: &str) -> Result<Self> {
        Ok(*self)
    }
    pub fn counter(&self, _name: &str, _help: &str) -> Result<Counter> {
        Ok(Counter)
    }
    pub fn gauge(&self, _name: &str, _help: &str) -> Result<Gauge> {
        Ok(Gauge)
    }
    pub fn histogram(&self, _name: &str, _help: &str, _bounds: &[f64]) -> Result<Histogram> {
        Ok(Histogram)
    }
}

impl Counter {
    pub fn inc(&self) -> Result<()> {
        Ok(())
    }
    pub fn add(&self, _amount: f64) -> Result<()> {
        Ok(())
    }
    pub fn get(&self) -> f64 {
        0.0
    }
}
impl Gauge {
    pub fn set(&self, _amount: f64) -> Result<()> {
        Ok(())
    }
    pub fn add(&self, _amount: f64) -> Result<()> {
        Ok(())
    }
    pub fn inc(&self) -> Result<()> {
        Ok(())
    }
    pub fn dec(&self) -> Result<()> {
        Ok(())
    }
    pub fn get(&self) -> f64 {
        0.0
    }
}
impl Histogram {
    pub fn observe(&self, _amount: f64) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_collectors_have_no_business_metric_storage() {
        assert_eq!(std::mem::size_of::<MetricRegistry>(), 0);
        assert_eq!(std::mem::size_of::<Registerer>(), 0);
        assert_eq!(std::mem::size_of::<Counter>(), 0);
        assert_eq!(std::mem::size_of::<Gauge>(), 0);
        assert_eq!(std::mem::size_of::<Histogram>(), 0);
        let registry = MetricRegistry::new();
        let registerer = registry
            .registerer()
            .with_prefix("mosdns_")
            .with_const_label("tag", "minimal")
            .unwrap();
        let counter = registerer.counter("queries", "queries").unwrap();
        let gauge = registerer.gauge("active", "active").unwrap();
        let histogram = registerer.histogram("latency", "latency", &[]).unwrap();
        counter.inc().unwrap();
        counter.add(100.0).unwrap();
        gauge.set(100.0).unwrap();
        gauge.inc().unwrap();
        histogram.observe(1.0).unwrap();
        assert_eq!(counter.get(), 0.0);
        assert_eq!(gauge.get(), 0.0);
        assert!(registry.text().is_empty());
        assert!(crate::pkg::metrics::process_metrics().is_empty());
    }
}
