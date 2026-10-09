//! Descriptor and label parity with the shared original Go cache fixture.
use super::*;
use crate::coremain::Config;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    format_version: u32,
    prefix: String,
    label_names: Vec<String>,
    tags: Vec<Tag>,
    metrics: Vec<Descriptor>,
}
#[derive(Deserialize)]
struct Tag {
    raw: String,
    escaped: String,
}
#[derive(Deserialize)]
struct Descriptor {
    name: String,
    kind: String,
    help: String,
}

#[tokio::test]
async fn shared_cache_metric_descriptors_and_escaped_tags_have_one_header_per_family() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../../tests/fixtures/cache_metrics.json")).unwrap();
    assert_eq!(fixture.format_version, 1);
    assert_eq!(fixture.label_names, ["tag"]);
    assert_eq!(fixture.tags.len(), 2);
    let config = serde_json::json!({
        "plugins": fixture.tags.iter().map(|tag| {
            serde_json::json!({"tag": tag.raw, "type": "cache"})
        }).collect::<Vec<_>>()
    });
    let engine = Engine::new(Config::from_yaml(&config.to_string()).unwrap()).unwrap();
    let text = metrics(&engine);
    engine.shutdown().await.unwrap();
    for descriptor in fixture.metrics {
        let name = format!("{}{}", fixture.prefix, descriptor.name);
        let type_line = format!("# TYPE {name} {}\n", descriptor.kind);
        let help_line = format!("# HELP {name} {}\n", descriptor.help);
        assert_eq!(
            text.matches(&type_line).count(),
            1,
            "missing or duplicated TYPE: {text}"
        );
        assert_eq!(
            text.matches(&help_line).count(),
            1,
            "missing or duplicated HELP: {text}"
        );
        let samples = text
            .lines()
            .filter(|line| line.starts_with(&format!("{name}{{")))
            .count();
        assert_eq!(samples, 2, "each cache must contribute one sample: {text}");
        for tag in &fixture.tags {
            assert!(
                text.contains(&format!("{name}{{tag=\"{}\"}} 0\n", tag.escaped)),
                "incorrect escaping: {text}"
            );
        }
    }
}

#[tokio::test]
async fn cache_headers_are_absent_when_no_configured_cache_is_registered() {
    let engine = Engine::new(Config::from_yaml("plugins: []\n").unwrap()).unwrap();
    let text = metrics(&engine);
    engine.shutdown().await.unwrap();
    assert!(
        !text.contains("mosdns_cache_"),
        "unregistered cache families: {text}"
    );
}
