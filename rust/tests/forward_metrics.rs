// SPDX-License-Identifier: GPL-3.0-or-later
#![cfg(feature = "full")]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{rdata::A, Name, RData, Record, RecordType},
};
use mosdns_rs::coremain::{Config, Engine};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
    sync::Notify,
};

#[derive(Deserialize)]
struct Fixture {
    format_version: usize,
    prefix: String,
    tag: String,
    upstream: String,
    label_names: Vec<String>,
    latency_bounds: Vec<u64>,
    metrics: Vec<Descriptor>,
}
#[derive(Deserialize)]
struct Descriptor {
    name: String,
    kind: String,
    help: String,
}
fn config(upstreams: serde_json::Value, concurrent: usize) -> Config {
    Config::from_yaml(&serde_yaml::to_string(&serde_json::json!({"plugins":[{"tag":"fixture","type":"forward","args":{"upstreams":upstreams,"concurrent":concurrent}},{"tag":"main","type":"sequence","args":[{"exec":"$fixture"},{"exec":"accept"}]},{"tag":"only_primary","type":"sequence","args":[{"exec":"$fixture primary"},{"exec":"accept"}]}]})).unwrap()).unwrap()
}
fn query() -> Message {
    let mut q = Message::new();
    q.set_id(123).add_query(Query::query(
        Name::from_ascii("example.org.").unwrap(),
        RecordType::A,
    ));
    q
}
fn response(q: Message) -> Message {
    let mut r = mosdns_rs::plugin::query_context::reply(&q, ResponseCode::NoError);
    r.add_answer(Record::from_rdata(
        q.queries()[0].name().clone(),
        60,
        RData::A(A("192.0.2.1".parse().unwrap())),
    ));
    r
}
fn value(engine: &Engine, name: &str, upstream: &str) -> f64 {
    let prefix = format!("mosdns_forward_{name}{{tag=\"fixture\",upstream=\"{upstream}\"}}");
    engine
        .metrics_text()
        .lines()
        .find_map(|line| {
            line.strip_prefix(&prefix)
                .map(|value| value.trim().parse().unwrap())
        })
        .unwrap_or_else(|| panic!("missing {prefix} in {}", engine.metrics_text()))
}
async fn controlled_tcp(
    release: Arc<Notify>,
) -> (SocketAddr, Arc<Notify>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(Notify::new());
    let notify = seen.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let notify = notify.clone();
            let release = release.clone();
            tokio::spawn(async move {
                loop {
                    let Ok(length) = stream.read_u16().await else {
                        return;
                    };
                    let mut payload = vec![0; length as usize];
                    if stream.read_exact(&mut payload).await.is_err() {
                        return;
                    };
                    let q = Message::from_vec(&payload).unwrap();
                    notify.notify_one();
                    release.notified().await;
                    let payload = response(q).to_vec().unwrap();
                    if stream.write_u16(payload.len() as u16).await.is_err()
                        || stream.write_all(&payload).await.is_err()
                    {
                        return;
                    };
                }
            });
        }
    });
    (address, seen, task)
}

#[tokio::test]
async fn shared_forward_descriptors_zero_series_and_only_tagged_upstreams() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../tests/fixtures/forward_metrics.json")).unwrap();
    assert_eq!(fixture.format_version, 1);
    assert_eq!(fixture.label_names, ["tag", "upstream"]);
    let engine=Engine::new(config(serde_json::json!([{"tag":fixture.upstream,"addr":"udp://127.0.0.1:1"},{"addr":"udp://127.0.0.1:2"}]),1)).unwrap();
    let text = engine.metrics_text();
    for descriptor in fixture.metrics {
        let name = format!("{}{}", fixture.prefix, descriptor.name);
        assert!(
            text.contains(&format!("# HELP {name} {}\n", descriptor.help)),
            "missing {name}: {text}"
        );
        assert!(text.contains(&format!("# TYPE {name} {}\n", descriptor.kind)));
        if descriptor.kind != "histogram" {
            assert!(text.contains(&format!(
                "{name}{{tag=\"{}\",upstream=\"primary\"}} 0\n",
                fixture.tag
            )));
        }
    }
    for bound in fixture.latency_bounds {
        assert!(text.contains(&format!("mosdns_forward_response_latency_millisecond_bucket{{tag=\"fixture\",upstream=\"primary\",le=\"{bound}\"}} 0\n")));
    }
    assert!(!text.contains("upstream=\"\""));
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn bp_extensions_cannot_collide_with_builtin_forward_families_or_derived_samples() {
    let mut registry = mosdns_rs::coremain::Registry::new();
    registry
        .register_plugin_type("collisions", |context, _| {
            for name in [
                "forward_query_total",
                "forward_err_total",
                "forward_thread",
                "forward_response_latency_millisecond",
                "forward_response_latency_millisecond_bucket",
                "forward_response_latency_millisecond_sum",
                "forward_response_latency_millisecond_count",
                "forward_conn_opened_total",
                "forward_conn_closed_total",
            ] {
                assert!(
                    context.metrics().counter(name, "collision").is_err(),
                    "accepted collision {name}"
                );
            }
            context.metrics().counter("custom_total", "custom")?.inc()?;
            Ok(mosdns_rs::coremain::Plugin::Data(Arc::new(())))
        })
        .unwrap();
    let engine = Engine::new_with_registry(
        Config::from_yaml("plugins: [{tag: custom, type: collisions}]").unwrap(),
        registry,
    )
    .unwrap();
    assert!(engine.metrics_text().contains("mosdns_custom_total 1\n"));
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn tagged_quick_setup_shares_queries_success_histogram_and_connection_reuse() {
    let release = Arc::new(Notify::new());
    let (address, seen, task) = controlled_tcp(release.clone()).await;
    let engine=Engine::new(config(serde_json::json!([{"tag":"primary","addr":format!("tcp://{address}")},{"tag":"backup","addr":"udp://127.0.0.1:1"}]),1)).unwrap();
    for _ in 0..2 {
        let e = engine.clone();
        let request = tokio::spawn(async move {
            e.handle(query(), "127.0.0.1".parse().unwrap(), "only_primary")
                .await
        });
        seen.notified().await;
        assert_eq!(value(&engine, "thread", "primary"), 1.0);
        release.notify_one();
        assert!(request.await.unwrap().is_ok());
    }
    assert_eq!(value(&engine, "query_total", "primary"), 2.0);
    assert_eq!(value(&engine, "err_total", "primary"), 0.0);
    assert_eq!(value(&engine, "thread", "primary"), 0.0);
    assert_eq!(
        value(&engine, "response_latency_millisecond_count", "primary"),
        2.0
    );
    assert_eq!(value(&engine, "conn_opened_total", "primary"), 1.0);
    assert_eq!(value(&engine, "query_total", "backup"), 0.0);
    engine.shutdown().await.unwrap();
    assert_eq!(value(&engine, "conn_closed_total", "primary"), 1.0);
    task.abort();
}

#[tokio::test]
async fn connection_failure_increments_error_without_success_latency() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let engine = Engine::new(config(
        serde_json::json!([{"tag":"primary","addr":format!("tcp://{address}")}]),
        1,
    ))
    .unwrap();
    assert!(engine
        .handle(query(), "127.0.0.1".parse().unwrap(), "main")
        .await
        .is_err());
    for (metric, expected) in [
        ("query_total", 1.0),
        ("err_total", 1.0),
        ("thread", 0.0),
        ("response_latency_millisecond_count", 0.0),
        ("conn_opened_total", 0.0),
    ] {
        assert_eq!(value(&engine, metric, "primary"), expected);
    }
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn caller_cancellation_does_not_cancel_background_upstream_and_shutdown_drains_it() {
    let release = Arc::new(Notify::new());
    let (address, seen, task) = controlled_tcp(release.clone()).await;
    let engine = Engine::new(config(
        serde_json::json!([{"tag":"primary","addr":format!("tcp://{address}")}]),
        1,
    ))
    .unwrap();
    let e = engine.clone();
    let request = tokio::spawn(async move {
        e.handle(query(), "127.0.0.1".parse().unwrap(), "main")
            .await
    });
    seen.notified().await;
    request.abort();
    let _ = request.await;
    assert_eq!(value(&engine, "thread", "primary"), 1.0);
    let e = engine.clone();
    let mut closing = tokio::spawn(async move { e.shutdown().await });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut closing)
            .await
            .is_err()
    );
    release.notify_one();
    closing.await.unwrap().unwrap();
    assert_eq!(value(&engine, "thread", "primary"), 0.0);
    assert_eq!(value(&engine, "err_total", "primary"), 0.0);
    assert_eq!(
        value(&engine, "response_latency_millisecond_count", "primary"),
        1.0
    );
    assert_eq!(value(&engine, "conn_closed_total", "primary"), 1.0);
    task.abort();
}

#[tokio::test]
async fn fast_winner_returns_while_slow_loser_completes_and_is_drained() {
    let fast_release = Arc::new(Notify::new());
    let slow_release = Arc::new(Notify::new());
    let (fast, fast_seen, fast_task) = controlled_tcp(fast_release.clone()).await;
    let (slow, slow_seen, slow_task) = controlled_tcp(slow_release.clone()).await;
    let engine=Engine::new(config(serde_json::json!([{"tag":"primary","addr":format!("tcp://{fast}")},{"tag":"slow","addr":format!("tcp://{slow}")}]),2)).unwrap();
    let e = engine.clone();
    let mut request = tokio::spawn(async move {
        e.handle(query(), "127.0.0.1".parse().unwrap(), "main")
            .await
    });
    tokio::join!(fast_seen.notified(), slow_seen.notified());
    fast_release.notify_one();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut request)
            .await
            .unwrap()
            .unwrap()
            .is_ok()
    );
    assert_eq!(value(&engine, "thread", "slow"), 1.0);
    let e = engine.clone();
    let mut closing = tokio::spawn(async move { e.shutdown().await });
    assert!(
        tokio::time::timeout(Duration::from_millis(30), &mut closing)
            .await
            .is_err()
    );
    slow_release.notify_one();
    closing.await.unwrap().unwrap();
    assert_eq!(
        value(&engine, "response_latency_millisecond_count", "slow"),
        1.0
    );
    assert_eq!(value(&engine, "thread", "slow"), 0.0);
    assert_eq!(value(&engine, "conn_closed_total", "slow"), 1.0);
    fast_task.abort();
    slow_task.abort();
}

#[tokio::test(start_paused = true)]
async fn detached_query_keeps_original_five_second_deadline_and_timeout_accounting() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let seen = Arc::new(Notify::new());
    let notify = seen.clone();
    let task = tokio::spawn(async move {
        let mut data = vec![0; 4096];
        socket.recv_from(&mut data).await.unwrap();
        notify.notify_one();
        std::future::pending::<()>().await;
    });
    let engine = Engine::new(config(
        serde_json::json!([{"tag":"primary","addr":format!("udp://{address}")}]),
        1,
    ))
    .unwrap();
    let e = engine.clone();
    let request = tokio::spawn(async move {
        e.handle(query(), "127.0.0.1".parse().unwrap(), "main")
            .await
    });
    seen.notified().await;
    request.abort();
    let _ = request.await;
    tokio::time::advance(Duration::from_millis(4999)).await;
    assert_eq!(value(&engine, "thread", "primary"), 1.0);
    let e = engine.clone();
    let closing = tokio::spawn(async move { e.shutdown().await });
    tokio::time::advance(Duration::from_millis(1)).await;
    closing.await.unwrap().unwrap();
    assert_eq!(value(&engine, "thread", "primary"), 0.0);
    assert_eq!(value(&engine, "err_total", "primary"), 1.0);
    assert_eq!(
        value(&engine, "response_latency_millisecond_count", "primary"),
        0.0
    );
    task.abort();
}
