// SPDX-License-Identifier: GPL-3.0-or-later
//! Instance-local Prometheus collectors for plugin BP registration.
use anyhow::{bail, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

type Labels = BTreeMap<String, String>;
type Key = (String, Labels);
#[derive(Clone, PartialEq)]
enum Kind {
    Counter,
    Gauge,
    Histogram(Vec<f64>),
}
#[derive(Clone, PartialEq)]
struct Descriptor {
    help: String,
    label_names: Vec<String>,
    kind: Kind,
}
struct Registered {
    owner: u64,
    metric: Arc<Metric>,
}
struct Metric {
    name: String,
    labels: Labels,
    value: Value,
}
enum Value {
    Counter(AtomicU64),
    Gauge(AtomicU64),
    Histogram(Mutex<Observations>),
}
struct Observations {
    bounds: Vec<f64>,
    buckets: Vec<u64>,
    count: u64,
    sum: f64,
}
#[derive(Default)]
struct Store {
    series: BTreeMap<Key, Registered>,
    families: BTreeMap<String, Descriptor>,
    occupied: BTreeMap<String, String>,
    reserved: BTreeSet<String>,
}
#[derive(Clone, Default)]
pub struct MetricRegistry {
    store: Arc<Mutex<Store>>,
}
#[derive(Clone)]
pub struct Registerer {
    registry: MetricRegistry,
    prefix: String,
    labels: Labels,
    owner: u64,
    active: Arc<AtomicBool>,
}
#[derive(Clone)]
pub struct Counter(Arc<Metric>);
#[derive(Clone)]
pub struct Gauge(Arc<Metric>);
#[derive(Clone)]
pub struct Histogram(Arc<Metric>);

impl MetricRegistry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn registerer(&self) -> Registerer {
        self.owned_registerer(0, Arc::new(AtomicBool::new(true)))
    }
    pub(crate) fn owned_registerer(&self, owner: u64, active: Arc<AtomicBool>) -> Registerer {
        Registerer {
            registry: self.clone(),
            prefix: String::new(),
            labels: Labels::new(),
            owner,
            active,
        }
    }
    pub(crate) fn unregister_owner(&self, owner: u64) {
        let mut store = self.store.lock().unwrap();
        store
            .series
            .retain(|_, registered| registered.owner != owner);
        let names: std::collections::HashSet<_> =
            store.series.keys().map(|(name, _)| name.clone()).collect();
        store.families.retain(|name, _| names.contains(name));
        store.occupied.retain(|_, family| names.contains(family));
    }
    /// Reserve exact family/sample names exported by collectors outside this
    /// registry. Histogram callers must include their derived sample names.
    /// The operation is atomic and repeating a reservation is harmless.
    pub fn reserve_names(&self, names: &[&str]) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        for name in names {
            if !valid_name(name) || store.occupied.contains_key(*name) {
                bail!("invalid or already registered reserved metric name {name}");
            }
        }
        store
            .reserved
            .extend(names.iter().map(|name| (*name).to_owned()));
        Ok(())
    }
    /// Descriptor/series membership is one registry snapshot. Each histogram
    /// is then copied under its own lock, so buckets, sum and count agree even
    /// while observations continue. Slow formatting never holds the registry
    /// lock and cannot block factory rollback or unrelated registration.
    pub fn text(&self) -> String {
        let families = {
            let store = self.store.lock().unwrap();
            let mut families = BTreeMap::<String, (Descriptor, Vec<Arc<Metric>>)>::new();
            for registered in store.series.values() {
                let metric = &registered.metric;
                families
                    .entry(metric.name.clone())
                    .or_insert_with(|| (store.families[&metric.name].clone(), Vec::new()))
                    .1
                    .push(metric.clone());
            }
            families
        };
        let mut text = String::new();
        for (name, (descriptor, metrics)) in families {
            let kind = match descriptor.kind {
                Kind::Counter => "counter",
                Kind::Gauge => "gauge",
                Kind::Histogram(_) => "histogram",
            };
            let _ = writeln!(text, "# HELP {name} {}", escape(&descriptor.help, false));
            let _ = writeln!(text, "# TYPE {name} {kind}");
            for metric in metrics {
                let labels = label_text(&metric.labels, None);
                match &metric.value {
                    Value::Counter(value) | Value::Gauge(value) => {
                        let number = number(f64::from_bits(value.load(Ordering::Relaxed)));
                        let _ = writeln!(text, "{name}{labels} {number}");
                    }
                    Value::Histogram(value) => {
                        let (bounds, buckets, sum, count) = {
                            let value = value.lock().unwrap();
                            (
                                value.bounds.clone(),
                                value.buckets.clone(),
                                value.sum,
                                value.count,
                            )
                        };
                        for (bound, bucket) in bounds.iter().zip(buckets) {
                            let labels = label_text(&metric.labels, Some(("le", &number(*bound))));
                            let _ = writeln!(text, "{name}_bucket{labels} {bucket}");
                        }
                        let inf_labels = label_text(&metric.labels, Some(("le", "+Inf")));
                        let _ = writeln!(text, "{name}_bucket{inf_labels} {count}");
                        let _ = writeln!(text, "{name}_sum{labels} {}", number(sum));
                        let _ = writeln!(text, "{name}_count{labels} {count}");
                    }
                }
            }
        }
        text
    }
}
impl Registerer {
    pub fn with_prefix(&self, prefix: &str) -> Self {
        let mut next = self.clone();
        next.prefix.push_str(prefix);
        next
    }
    pub fn with_const_label(&self, name: &str, value: &str) -> Result<Self> {
        if !valid_label(name) || self.labels.contains_key(name) {
            bail!("invalid or duplicate metric label {name}");
        }
        let mut next = self.clone();
        next.labels.insert(name.into(), value.into());
        Ok(next)
    }
    pub fn counter(&self, name: &str, help: &str) -> Result<Counter> {
        Ok(Counter(self.register(name, help, Kind::Counter)?))
    }
    pub fn gauge(&self, name: &str, help: &str) -> Result<Gauge> {
        Ok(Gauge(self.register(name, help, Kind::Gauge)?))
    }
    pub fn histogram(&self, name: &str, help: &str, bounds: &[f64]) -> Result<Histogram> {
        let bounds = if bounds.is_empty() {
            vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            ]
        } else {
            bounds.to_vec()
        };
        if bounds.iter().any(|value| !value.is_finite())
            || bounds.windows(2).any(|pair| pair[0] >= pair[1])
            || self.labels.contains_key("le")
        {
            bail!("histogram bounds must be finite and increasing; le is reserved");
        }
        Ok(Histogram(self.register(
            name,
            help,
            Kind::Histogram(bounds),
        )?))
    }
    fn register(&self, name: &str, help: &str, kind: Kind) -> Result<Arc<Metric>> {
        let name = format!("{}{name}", self.prefix);
        if !valid_name(&name) {
            bail!("invalid metric name {name}");
        }
        let descriptor = Descriptor {
            help: help.into(),
            label_names: self.labels.keys().cloned().collect(),
            kind: kind.clone(),
        };
        let mut store = self.registry.store.lock().unwrap();
        if !self.active.load(Ordering::Acquire) {
            bail!("metric registration scope is no longer active");
        }
        let key = (name.clone(), self.labels.clone());
        if store.series.contains_key(&key) {
            bail!("duplicate metric series {name}");
        }
        if store
            .families
            .get(&name)
            .is_some_and(|old| old != &descriptor)
        {
            bail!("inconsistent metric family {name}");
        }
        let outputs = match kind {
            Kind::Histogram(_) => vec![
                name.clone(),
                format!("{name}_bucket"),
                format!("{name}_sum"),
                format!("{name}_count"),
            ],
            _ => vec![name.clone()],
        };
        if outputs.iter().any(|output| {
            store.reserved.contains(output)
                || store
                    .occupied
                    .get(output)
                    .is_some_and(|family| family != &name)
        }) {
            bail!("metric output name conflicts with another family or reserved name {name}");
        }
        let value = match kind {
            Kind::Counter => Value::Counter(AtomicU64::new(0f64.to_bits())),
            Kind::Gauge => Value::Gauge(AtomicU64::new(0f64.to_bits())),
            Kind::Histogram(bounds) => Value::Histogram(Mutex::new(Observations {
                buckets: vec![0; bounds.len()],
                bounds,
                count: 0,
                sum: 0.0,
            })),
        };
        let metric = Arc::new(Metric {
            name: name.clone(),
            labels: self.labels.clone(),
            value,
        });
        store.families.insert(name.clone(), descriptor);
        for output in outputs {
            store.occupied.insert(output, name.clone());
        }
        store.series.insert(
            key,
            Registered {
                owner: self.owner,
                metric: metric.clone(),
            },
        );
        Ok(metric)
    }
}
fn valid_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || b"_:".contains(&c))
        && bytes.all(|c| c.is_ascii_alphanumeric() || b"_:".contains(&c))
}
fn valid_label(value: &str) -> bool {
    valid_name(value) && !value.contains(':') && !value.starts_with("__")
}
fn escape(value: &str, label: bool) -> String {
    let mut output = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '"' if label => output.push_str("\\\""),
            ch => output.push(ch),
        }
    }
    output
}
fn label_text(labels: &Labels, extra: Option<(&str, &str)>) -> String {
    if labels.is_empty() && extra.is_none() {
        return String::new();
    }
    let mut output = String::from("{");
    for (index, (name, value)) in labels
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .chain(extra)
        .enumerate()
    {
        if index != 0 {
            output.push(',');
        }
        let _ = write!(output, "{name}=\"{}\"", escape(value, true));
    }
    output.push('}');
    output
}
fn number(value: f64) -> String {
    // IEEE +/- zero compare equal as bucket boundaries. Expose the same label
    // spelling for both, including across differently labelled family series.
    if value == 0.0 {
        String::from("0")
    } else {
        value.to_string()
    }
}
fn add(value: &AtomicU64, amount: f64, nonnegative: bool) -> Result<()> {
    if !amount.is_finite() || (nonnegative && amount < 0.0) {
        bail!("invalid metric increment");
    }
    let mut bits = value.load(Ordering::Relaxed);
    loop {
        let next = f64::from_bits(bits) + amount;
        if !next.is_finite() {
            bail!("metric value overflow");
        }
        match value.compare_exchange_weak(
            bits,
            next.to_bits(),
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(()),
            Err(current) => bits = current,
        }
    }
}
impl Counter {
    pub fn inc(&self) -> Result<()> {
        self.add(1.0)
    }
    pub fn add(&self, amount: f64) -> Result<()> {
        let Value::Counter(value) = &self.0.value else {
            unreachable!()
        };
        add(value, amount, true)
    }
    pub fn get(&self) -> f64 {
        let Value::Counter(value) = &self.0.value else {
            unreachable!()
        };
        f64::from_bits(value.load(Ordering::Relaxed))
    }
}
impl Gauge {
    pub fn set(&self, amount: f64) -> Result<()> {
        if !amount.is_finite() {
            bail!("invalid gauge value");
        }
        let Value::Gauge(value) = &self.0.value else {
            unreachable!()
        };
        value.store(amount.to_bits(), Ordering::Relaxed);
        Ok(())
    }
    pub fn add(&self, amount: f64) -> Result<()> {
        let Value::Gauge(value) = &self.0.value else {
            unreachable!()
        };
        add(value, amount, false)
    }
    pub fn inc(&self) -> Result<()> {
        self.add(1.0)
    }
    pub fn dec(&self) -> Result<()> {
        self.add(-1.0)
    }
    pub fn get(&self) -> f64 {
        let Value::Gauge(value) = &self.0.value else {
            unreachable!()
        };
        f64::from_bits(value.load(Ordering::Relaxed))
    }
}
impl Histogram {
    pub fn observe(&self, amount: f64) -> Result<()> {
        if !amount.is_finite() {
            bail!("invalid histogram observation");
        }
        let Value::Histogram(value) = &self.0.value else {
            unreachable!()
        };
        let mut value = value.lock().unwrap();
        let sum = value.sum + amount;
        let count = value
            .count
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("histogram count overflow"))?;
        if !sum.is_finite() {
            bail!("histogram sum overflow");
        }
        value.count = count;
        value.sum = sum;
        for index in 0..value.bounds.len() {
            if amount <= value.bounds[index] {
                value.buckets[index] += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn typed_collectors_export_prefix_labels_and_consistent_histogram() {
        let registry = MetricRegistry::new();
        let registerer = registry
            .registerer()
            .with_prefix("mosdns_")
            .with_const_label("tag", "a\"\\\nb")
            .unwrap();
        let counter = registerer
            .counter("example_query_total", "line one\nline two\\")
            .unwrap();
        counter.inc().unwrap();
        counter.add(2.5).unwrap();
        let gauge = registerer.gauge("example_active", "active").unwrap();
        gauge.set(-1.0).unwrap();
        gauge.inc().unwrap();
        let histogram = registerer
            .histogram("example_latency", "latency", &[1.0, 5.0])
            .unwrap();
        for value in [0.5, 2.0, 6.0] {
            histogram.observe(value).unwrap();
        }
        let text = registry.text();
        assert!(text.contains("# TYPE mosdns_example_query_total counter\n"));
        assert!(text.contains("# HELP mosdns_example_query_total line one\\nline two\\\\\n"));
        let label = "{tag=\"a\\\"\\\\\\nb\"}";
        assert!(text.contains(&format!("mosdns_example_query_total{label} 3.5\n")));
        assert!(text.contains(&format!("mosdns_example_active{label} 0\n")));
        assert!(text.contains("mosdns_example_latency_bucket{tag=\"a\\\"\\\\\\nb\",le=\"1\"} 1\n"));
        assert!(text.contains("le=\"5\"} 2\n") && text.contains("le=\"+Inf\"} 3\n"));
        assert!(
            text.contains(&format!("mosdns_example_latency_sum{label} 8.5\n"))
                && text.contains(&format!("mosdns_example_latency_count{label} 3\n"))
        );
    }
    #[test]
    fn registration_rejects_duplicate_series_inconsistent_families_and_derived_collisions() {
        let registry = MetricRegistry::new();
        let r = registry.registerer();
        r.with_const_label("tag", "a")
            .unwrap()
            .counter("queries", "queries")
            .unwrap();
        assert!(r
            .with_const_label("tag", "a")
            .unwrap()
            .counter("queries", "queries")
            .is_err());
        r.with_const_label("tag", "b")
            .unwrap()
            .counter("queries", "queries")
            .unwrap();
        assert!(r.counter("queries", "queries").is_err());
        assert!(r
            .with_const_label("tag", "c")
            .unwrap()
            .gauge("queries", "queries")
            .is_err());
        assert!(r
            .with_const_label("tag", "c")
            .unwrap()
            .counter("queries", "different help")
            .is_err());
        r.histogram("latency", "latency", &[1.0]).unwrap();
        assert!(r.counter("latency_count", "count").is_err());
        r.counter("second_sum", "sum").unwrap();
        assert!(r.histogram("second", "second", &[1.0]).is_err());
    }
    #[test]
    fn invalid_registration_and_updates_do_not_change_previous_values() {
        let registry = MetricRegistry::new();
        let r = registry.registerer();
        assert!(r.counter("bad name", "bad").is_err());
        assert!(r.with_const_label("__reserved", "x").is_err());
        assert!(r
            .with_const_label("x", "a")
            .unwrap()
            .with_const_label("x", "b")
            .is_err());
        for bounds in [vec![2.0, 1.0], vec![1.0, 1.0], vec![f64::INFINITY]] {
            assert!(r.histogram("bad", "bad", &bounds).is_err());
        }
        let counter = r.counter("counter", "counter").unwrap();
        counter.inc().unwrap();
        for value in [-1.0, f64::NAN, f64::INFINITY] {
            assert!(counter.add(value).is_err());
        }
        assert_eq!(counter.get(), 1.0);
        let gauge = r.gauge("gauge", "gauge").unwrap();
        gauge.set(4.0).unwrap();
        assert!(gauge.set(f64::NAN).is_err());
        assert_eq!(gauge.get(), 4.0);
    }
    #[test]
    fn concurrent_clones_share_atomic_values() {
        let registry = MetricRegistry::new();
        let counter = registry.registerer().counter("count", "count").unwrap();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let counter = counter.clone();
                scope.spawn(move || {
                    for _ in 0..1000 {
                        counter.inc().unwrap();
                    }
                });
            }
        });
        assert_eq!(counter.get(), 8000.0);
    }
    #[test]
    fn rollback_removes_only_its_series_and_disables_retained_registerer() {
        let registry = MetricRegistry::new();
        let active = Arc::new(AtomicBool::new(true));
        let failed = registry
            .owned_registerer(7, active.clone())
            .with_const_label("tag", "failed")
            .unwrap();
        failed.counter("queries", "queries").unwrap();
        let survivor = registry.registerer().with_const_label("tag", "ok").unwrap();
        survivor.counter("queries", "queries").unwrap();
        active.store(false, Ordering::Release);
        registry.unregister_owner(7);
        assert!(failed.counter("late", "late").is_err());
        assert!(!registry.text().contains("failed"));
        assert!(registry.text().contains("tag=\"ok\""));
    }
    #[test]
    fn text_groups_each_family_once_and_preserves_unicode_and_empty_labels() {
        let registry = MetricRegistry::new();
        let r = registry.registerer();
        r.with_const_label("zone", "日本")
            .unwrap()
            .with_const_label("empty", "")
            .unwrap()
            .gauge("z_value", "quote \" and slash \\")
            .unwrap()
            .set(1.25)
            .unwrap();
        r.with_const_label("zone", "中国")
            .unwrap()
            .with_const_label("empty", "")
            .unwrap()
            .gauge("z_value", "quote \" and slash \\")
            .unwrap()
            .set(-2.0)
            .unwrap();
        r.counter("a_count", "").unwrap();
        let text = registry.text();
        assert_eq!(text.matches("# TYPE z_value gauge\n").count(), 1);
        assert_eq!(text.matches("# HELP z_value ").count(), 1);
        assert!(text.starts_with("# HELP a_count \n# TYPE a_count counter\na_count 0\n"));
        assert!(text.contains(concat!("# HELP z_value quote \" and slash ", r"\\", "\n")));
        assert!(text.contains("z_value{empty=\"\",zone=\"中国\"} -2\n"));
        assert!(text.contains("z_value{empty=\"\",zone=\"日本\"} 1.25\n"));
        assert!(text.ends_with('\n'));
    }
    #[test]
    fn histograms_include_boundary_values_zero_samples_and_canonical_zero_bounds() {
        let registry = MetricRegistry::new();
        let r = registry.registerer();
        let h = r.histogram("signed", "signed", &[-1.0, -0.0, 0.5]).unwrap();
        for value in [-2.0, -1.0, 0.0, 0.5, 9.0] {
            h.observe(value).unwrap();
        }
        r.histogram("empty", "empty", &[1.0]).unwrap();
        let text = registry.text();
        for line in [
            "signed_bucket{le=\"-1\"} 2\n",
            "signed_bucket{le=\"0\"} 3\n",
            "signed_bucket{le=\"0.5\"} 4\n",
            "signed_bucket{le=\"+Inf\"} 5\n",
            "signed_sum 6.5\n",
            "signed_count 5\n",
            "empty_bucket{le=\"1\"} 0\n",
            "empty_bucket{le=\"+Inf\"} 0\n",
            "empty_sum 0\n",
            "empty_count 0\n",
        ] {
            assert!(text.contains(line), "missing {line} in {text}");
        }
    }
    #[test]
    fn overflow_and_nonfinite_histogram_updates_are_transactional() {
        let registry = MetricRegistry::new();
        let r = registry.registerer();
        let c = r.counter("counter", "counter").unwrap();
        c.add(f64::MAX).unwrap();
        assert!(c.add(f64::MAX).is_err());
        assert_eq!(c.get(), f64::MAX);
        let g = r.gauge("gauge", "gauge").unwrap();
        g.set(f64::MAX).unwrap();
        assert!(g.add(f64::MAX).is_err());
        assert_eq!(g.get(), f64::MAX);
        let h = r.histogram("histogram", "histogram", &[0.0]).unwrap();
        h.observe(f64::MAX).unwrap();
        let before = registry.text();
        for amount in [f64::MAX, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(h.observe(amount).is_err());
        }
        assert_eq!(registry.text(), before);
        let Value::Histogram(value) = &h.0.value else {
            unreachable!()
        };
        value.lock().unwrap().count = u64::MAX;
        assert!(h.observe(-1.0).is_err());
        let value = value.lock().unwrap();
        assert_eq!(value.count, u64::MAX);
        assert_eq!(value.buckets, [0]);
        assert_eq!(value.sum, f64::MAX);
    }
    #[test]
    fn histogram_scrapes_are_coherent_during_concurrent_observation() {
        let registry = MetricRegistry::new();
        let h = registry
            .registerer()
            .histogram("latency", "latency", &[0.0, 1.0, 2.0])
            .unwrap();
        std::thread::scope(|scope| {
            for _ in 0..4 {
                let h = h.clone();
                scope.spawn(move || {
                    for _ in 0..1000 {
                        h.observe(1.0).unwrap();
                    }
                });
            }
            for _ in 0..50 {
                let text = registry.text();
                let sample = |prefix: &str| -> f64 {
                    text.lines()
                        .find_map(|line| line.strip_prefix(prefix))
                        .unwrap()
                        .parse()
                        .unwrap()
                };
                let count = sample("latency_count ");
                assert_eq!(sample("latency_bucket{le=\"0\"} "), 0.0);
                for prefix in [
                    "latency_bucket{le=\"1\"} ",
                    "latency_bucket{le=\"2\"} ",
                    "latency_bucket{le=\"+Inf\"} ",
                    "latency_sum ",
                ] {
                    assert_eq!(sample(prefix), count);
                }
            }
        });
        assert!(registry.text().contains("latency_count 4000\n"));
    }
    #[test]
    fn concurrent_rollback_cannot_leave_late_registrations_or_remove_other_owners() {
        let registry = MetricRegistry::new();
        let active = Arc::new(AtomicBool::new(true));
        let r = registry.owned_registerer(9, active.clone());
        let survivor = registry
            .registerer()
            .with_const_label("tag", "survivor")
            .unwrap()
            .counter("shared", "shared")
            .unwrap();
        survivor.add(17.0).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(9));
        std::thread::scope(|scope| {
            for worker in 0..8 {
                let r = r.clone();
                let barrier = barrier.clone();
                scope.spawn(move || {
                    let r = r.with_const_label("tag", &worker.to_string()).unwrap();
                    barrier.wait();
                    for i in 0..100 {
                        let _ = r.counter(&format!("owned_{i}"), "owned");
                    }
                    let _ = r.counter("shared", "shared");
                });
            }
            barrier.wait();
            active.store(false, Ordering::Release);
            registry.unregister_owner(9);
        });
        let text = registry.text();
        assert!(!text.contains("owned_"));
        assert!(!text.contains("tag=\"0\""));
        assert!(text.contains("shared{tag=\"survivor\"} 17\n"));
        assert!(r.counter("late", "late").is_err());
    }
    #[test]
    fn rollback_releases_unused_family_descriptors_and_histogram_output_names() {
        let registry = MetricRegistry::new();
        let active = Arc::new(AtomicBool::new(true));
        let old = registry
            .owned_registerer(12, active.clone())
            .histogram("sample", "old", &[1.0])
            .unwrap();
        old.observe(1.0).unwrap();
        active.store(false, Ordering::Release);
        registry.unregister_owner(12);
        assert_eq!(registry.text(), "");
        old.observe(2.0).unwrap();
        assert_eq!(registry.text(), "");
        registry
            .registerer()
            .counter("sample_count", "new")
            .unwrap()
            .add(3.0)
            .unwrap();
        registry
            .registerer()
            .gauge("sample", "new gauge")
            .unwrap()
            .set(-4.0)
            .unwrap();
        let text = registry.text();
        assert!(text.contains("# TYPE sample gauge\n"));
        assert!(text.contains("sample -4\n"));
        assert!(text.contains("sample_count 3\n"));
        assert!(!text.contains("sample_bucket"));
    }
    #[test]
    fn reserved_names_prevent_external_collisions_without_partial_reservation() {
        let registry = MetricRegistry::new();
        let r = registry.registerer();
        registry
            .reserve_names(&["process_cpu_seconds_total", "internal_bucket"])
            .unwrap();
        registry
            .reserve_names(&["process_cpu_seconds_total"])
            .unwrap();
        assert!(r.counter("process_cpu_seconds_total", "collision").is_err());
        assert!(r.histogram("internal", "collision", &[1.0]).is_err());
        r.gauge("existing", "existing").unwrap();
        assert!(registry.reserve_names(&["free", "existing"]).is_err());
        r.counter("free", "atomic failure leaves name free")
            .unwrap();
        assert!(registry
            .reserve_names(&["another_free", "bad name"])
            .is_err());
        r.counter("another_free", "atomic failure leaves name free")
            .unwrap();
        let active = Arc::new(AtomicBool::new(true));
        registry
            .owned_registerer(31, active.clone())
            .counter("temporary", "temporary")
            .unwrap();
        active.store(false, Ordering::Release);
        registry.unregister_owner(31);
        assert!(r
            .counter("process_cpu_seconds_total", "still reserved")
            .is_err());
    }
    #[test]
    fn histogram_default_buckets_and_equal_signed_zero_series_keep_consistent_labels() {
        let registry = MetricRegistry::new();
        let r = registry.registerer();
        r.histogram("default", "default", &[]).unwrap();
        r.with_const_label("tag", "positive")
            .unwrap()
            .histogram("zero", "zero", &[0.0])
            .unwrap();
        r.with_const_label("tag", "negative")
            .unwrap()
            .histogram("zero", "zero", &[-0.0])
            .unwrap();
        let text = registry.text();
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with("default_bucket"))
                .count(),
            12
        );
        assert!(text.contains("default_bucket{le=\"0.005\"} 0\n"));
        assert!(text.contains("default_bucket{le=\"10\"} 0\n"));
        assert!(text.contains("zero_bucket{tag=\"positive\",le=\"0\"} 0\n"));
        assert!(text.contains("zero_bucket{tag=\"negative\",le=\"0\"} 0\n"));
        assert!(!text.contains("le=\"-0\""));
    }
}
