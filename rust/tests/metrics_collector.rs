//! Original Go collector descriptors and integer millisecond observation semantics.
#![cfg(feature = "full")]
use mosdns_rs::{
    coremain::{Config, Engine},
    plugin::executable::stateful::Metrics,
};
use serde::Deserialize;
use std::time::Duration;

#[derive(Deserialize)]
struct Fixture {
    format_version: u32,
    prefix: String,
    label_names: Vec<String>,
    names: Vec<Name>,
    latency_bounds: Vec<u64>,
    metrics: Vec<Descriptor>,
    observations: Vec<Observation>,
    expected: Expected,
}
#[derive(Deserialize)]
struct Name {
    raw: String,
    escaped: String,
}
#[derive(Deserialize)]
struct Descriptor {
    name: String,
    kind: String,
    help: String,
}
#[derive(Deserialize)]
struct Observation {
    elapsed_us: u64,
    failed: bool,
    has_response: bool,
}
#[derive(Deserialize)]
struct Expected {
    queries: u64,
    errors: u64,
    thread: u64,
    latency_count: u64,
    latency_sum_ms: u64,
    bucket_counts: Vec<u64>,
}
fn fixture() -> Fixture {
    serde_json::from_str(include_str!("../../tests/fixtures/metrics_collector.json")).unwrap()
}
fn sample(text: &str, prefix: &str) -> f64 {
    text.lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("missing {prefix}: {text}"))
        .trim()
        .parse()
        .unwrap()
}

#[tokio::test]
async fn shared_collector_descriptors_merge_two_names_with_one_header_per_family() {
    let fixture = fixture();
    assert_eq!(fixture.format_version, 1);
    assert_eq!(fixture.label_names, ["name"]);
    let config = serde_json::json!({"plugins": fixture.names.iter().enumerate().map(|(i, name)| {
        serde_json::json!({"tag": format!("sequence{i}"), "type": "sequence", "args": [
            {"exec": format!("metrics_collector {}", name.raw)}
        ]})
    }).collect::<Vec<_>>()});
    let engine = Engine::new(Config::from_yaml(&config.to_string()).unwrap()).unwrap();
    let text = engine.metrics_text();
    engine.shutdown().await.unwrap();
    for descriptor in fixture.metrics {
        let name = format!("{}{}", fixture.prefix, descriptor.name);
        assert_eq!(
            text.matches(&format!("# TYPE {name} {}\n", descriptor.kind))
                .count(),
            1,
            "missing or duplicated TYPE: {text}"
        );
        assert_eq!(
            text.matches(&format!("# HELP {name} {}\n", descriptor.help))
                .count(),
            1,
            "missing or duplicated HELP: {text}"
        );
        let sample_name = if descriptor.kind == "histogram" {
            format!("{name}_count")
        } else {
            name.clone()
        };
        assert_eq!(
            text.lines()
                .filter(|line| line.starts_with(&format!("{sample_name}{{")))
                .count(),
            2,
            "missing instance sample: {text}"
        );
        for collector in &fixture.names {
            assert_eq!(
                sample(
                    &text,
                    &format!("{sample_name}{{name=\"{}\"}} ", collector.escaped)
                ),
                0.0
            );
            if descriptor.kind == "histogram" {
                for bound in &fixture.latency_bounds {
                    assert_eq!(
                        sample(
                            &text,
                            &format!(
                                "{name}_bucket{{name=\"{}\",le=\"{bound}\"}} ",
                                collector.escaped
                            )
                        ),
                        0.0
                    );
                }
            }
        }
    }
}

#[test]
fn shared_collector_observes_only_responses_and_truncates_each_duration_before_sum() {
    let fixture = fixture();
    let metrics = Metrics::new(fixture.names[0].raw.clone());
    for observation in fixture.observations {
        let guard = metrics.begin();
        metrics.end(
            observation.failed,
            observation.has_response,
            Duration::from_micros(observation.elapsed_us),
        );
        drop(guard);
    }
    let text = metrics.text();
    let label = format!("{{name=\"{}\"}} ", fixture.names[0].escaped);
    for (name, expected) in [
        ("query_total", fixture.expected.queries),
        ("err_total", fixture.expected.errors),
        ("thread", fixture.expected.thread),
        (
            "response_latency_millisecond_count",
            fixture.expected.latency_count,
        ),
        (
            "response_latency_millisecond_sum",
            fixture.expected.latency_sum_ms,
        ),
    ] {
        assert_eq!(
            sample(&text, &format!("{}{name}{label}", fixture.prefix)),
            expected as f64,
            "{name}: {text}"
        );
    }
    for (bound, expected) in fixture
        .latency_bounds
        .iter()
        .zip(&fixture.expected.bucket_counts)
    {
        assert_eq!(
            sample(
                &text,
                &format!(
                    "{}response_latency_millisecond_bucket{{name=\"{}\",le=\"{bound}\"}} ",
                    fixture.prefix, fixture.names[0].escaped
                )
            ),
            *expected as f64
        );
    }
    assert_eq!(
        sample(
            &text,
            &format!(
                "{}response_latency_millisecond_bucket{{name=\"{}\",le=\"+Inf\"}} ",
                fixture.prefix, fixture.names[0].escaped
            )
        ),
        fixture.expected.latency_count as f64
    );
}

#[tokio::test]
async fn unregistered_collector_does_not_export_empty_families() {
    let engine = Engine::new(Config::from_yaml("plugins: []\n").unwrap()).unwrap();
    let text = engine.metrics_text();
    engine.shutdown().await.unwrap();
    assert!(!text.contains("mosdns_metrics_collector_"));
}
