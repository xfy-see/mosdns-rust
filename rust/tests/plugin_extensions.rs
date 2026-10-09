//! BP API mounts, collectors, logging and transactional factory failure.
#![cfg(feature = "full")]
use anyhow::{bail, Result};
use bytes::Bytes;
use futures::future::BoxFuture;
use hyper::{Method, Request, Response, StatusCode};
use mosdns_rs::{
    coremain::{Config, Engine, Plugin, PluginApi, PluginCloser, PluginObject, Registry},
    pkg::metrics::Registerer,
};
use serde::Deserialize;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::{net::TcpListener, sync::Notify};

struct Echo;
impl PluginApi for Echo {
    fn handle<'a>(
        &'a self,
        request: Request<Bytes>,
        path: String,
    ) -> BoxFuture<'a, Result<Response<Bytes>>> {
        Box::pin(async move {
            if path != "/value" {
                return Ok(Response::builder().status(404).body(Bytes::new())?);
            }
            if !matches!(*request.method(), Method::GET | Method::POST) {
                return Ok(Response::builder().status(405).body(Bytes::new())?);
            }
            let value =
                url::form_urlencoded::parse(request.uri().query().unwrap_or_default().as_bytes())
                    .find_map(|(key, value)| (key == "value").then(|| value.into_owned()))
                    .unwrap_or_default();
            Ok(Response::builder()
                .header("X-Plugin", "echo")
                .body(Bytes::from(format!(
                    "{}|{}|{value}|{}",
                    request.method(),
                    request.uri().path(),
                    String::from_utf8_lossy(request.body())
                )))?)
        })
    }
}
async fn server(engine: Arc<Engine>) -> (String, tokio::task::JoinHandle<Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    (
        url,
        tokio::spawn(mosdns_rs::api::serve_listener(listener, engine)),
    )
}
fn echo_engine() -> Arc<Engine> {
    let mut registry = Registry::new();
    registry
        .register_plugin_type("echo_api", |ctx, _| {
            ctx.register_api(Arc::new(Echo))?;
            ctx.metrics()
                .with_const_label("tag", ctx.tag())?
                .counter("extension_queries_total", "extension queries")?
                .add(3.0)?;
            Ok(Plugin::Data(Arc::new(())))
        })
        .unwrap();
    Arc::new(
        Engine::new_with_registry(
            Config::from_yaml("plugins: [{tag: echo, type: echo_api}]").unwrap(),
            registry,
        )
        .unwrap(),
    )
}
#[derive(Deserialize)]
struct Case {
    method: String,
    url: String,
    body: String,
    status: u16,
    response: Option<String>,
}
#[tokio::test]
async fn shared_go_api_mount_fixture_preserves_request_and_response() {
    let engine = echo_engine();
    let (url, task) = server(engine.clone()).await;
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("../../tests/fixtures/plugin_api.json")).unwrap();
    let client = reqwest::Client::new();
    for case in cases {
        let response = client
            .request(case.method.parse().unwrap(), format!("{url}{}", case.url))
            .body(case.body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status().as_u16(),
            case.status,
            "{} {}",
            case.method,
            case.url
        );
        if let Some(body) = case.response {
            assert_eq!(response.headers()["X-Plugin"], "echo");
            assert_eq!(response.text().await.unwrap(), body);
        }
    }
    let text = client
        .get(format!("{url}/metrics"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(text.contains("# TYPE mosdns_extension_queries_total counter\n"));
    assert!(text.contains("mosdns_extension_queries_total{tag=\"echo\"} 3\n"));
    task.abort();
    task.await.unwrap_err();
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn recovered_error_or_panic_rolls_back_only_its_api_and_metrics() {
    for panic_first in [false, true] {
        let mut registry = Registry::new();
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempt = attempts.clone();
        let retained: Arc<Mutex<Option<Registerer>>> = Arc::new(Mutex::new(None));
        let kept = retained.clone();
        registry
            .register_plugin_type("fragile", move |ctx, _| {
                ctx.register_api(Arc::new(Echo))?;
                let metrics = ctx.metrics().with_const_label("tag", ctx.tag())?;
                metrics
                    .counter("extension_queries_total", "extension queries")?
                    .add(7.0)?;
                if attempt.fetch_add(1, Ordering::SeqCst) == 0 {
                    *kept.lock().unwrap() = Some(metrics);
                    ctx.get_plugin("stable")?;
                    if panic_first {
                        panic!("factory panic fixture");
                    }
                    bail!("factory error fixture");
                }
                Ok(Plugin::Data(Arc::new(())))
            })
            .unwrap();
        registry
            .register_plugin_type("stable_api", |ctx, _| {
                ctx.register_api(Arc::new(Echo))?;
                ctx.metrics()
                    .with_const_label("tag", ctx.tag())?
                    .counter("extension_queries_total", "extension queries")?
                    .add(11.0)?;
                Ok(Plugin::Data(Arc::new(())))
            })
            .unwrap();
        registry
            .register_plugin_type("recover", |ctx, _| {
                assert!(ctx.get_plugin("echo").is_err());
                ctx.get_plugin("echo")
            })
            .unwrap();
        let config = Config::from_yaml("plugins: [{tag: parent, type: recover}, {tag: echo, type: fragile}, {tag: stable, type: stable_api}]").unwrap();
        let engine = Arc::new(Engine::new_with_registry(config, registry).unwrap());
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(retained
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .counter("late", "late")
            .is_err());
        let metrics = engine.metrics_text();
        assert!(
            metrics.contains("tag=\"echo\"} 7\n") && metrics.contains("tag=\"stable\"} 11\n"),
            "{metrics}"
        );
        assert_eq!(
            metrics
                .matches("# TYPE mosdns_extension_queries_total")
                .count(),
            1
        );
        let (url, task) = server(engine.clone()).await;
        for tag in ["echo", "stable"] {
            assert_eq!(
                reqwest::get(format!("{url}/plugins/{tag}/value"))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        task.abort();
        task.await.unwrap_err();
        engine.shutdown().await.unwrap();
    }
}

#[test]
fn whole_startup_failure_invalidates_committed_registerer() {
    let retained: Arc<Mutex<Option<Registerer>>> = Arc::new(Mutex::new(None));
    let kept = retained.clone();
    let mut registry = Registry::new();
    registry
        .register_plugin_type("first", move |ctx, _| {
            let metrics = ctx.metrics();
            metrics.counter("committed", "committed")?.inc()?;
            *kept.lock().unwrap() = Some(metrics);
            Ok(Plugin::Data(Arc::new(())))
        })
        .unwrap();
    registry
        .register_plugin_type("second", |_, _| bail!("abort startup"))
        .unwrap();
    assert!(Engine::new_with_registry(
        Config::from_yaml("plugins: [{tag: one, type: first}, {tag: two, type: second}]").unwrap(),
        registry
    )
    .is_err());
    assert!(retained
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .counter("late", "late")
        .is_err());
}

#[tokio::test]
async fn failed_sequence_retries_without_leaving_successful_quick_registrations() {
    let mut registry = Registry::new();
    registry
        .register_exec("quick_api", |ctx, _| {
            ctx.register_api(Arc::new(Echo))?;
            ctx.metrics()
                .counter("quick_registration", "quick registration")?
                .inc()?;
            Ok(mosdns_rs::plugin::executable::Executable::Accept)
        })
        .unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = attempts.clone();
    registry
        .register_exec("once_fail", move |_, _| {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                bail!("later quick setup failed");
            }
            Ok(mosdns_rs::plugin::executable::Executable::Accept)
        })
        .unwrap();
    registry
        .register_plugin_type("recover", |ctx, _| {
            assert!(ctx.get_plugin("echo").is_err());
            ctx.get_plugin("echo")
        })
        .unwrap();
    let config = Config::from_yaml("plugins: [{tag: parent, type: recover}, {tag: echo, type: sequence, args: [{exec: quick_api}, {exec: once_fail}]}]").unwrap();
    let engine = Engine::new_with_registry(config, registry).unwrap();
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    assert!(engine
        .metrics_text()
        .contains("mosdns_quick_registration 1\n"));
    engine.shutdown().await.unwrap();
}

#[test]
fn duplicate_mount_and_builtin_metrics_are_rejected_during_initialization() {
    let mut registry = Registry::new();
    registry
        .register_plugin_type("duplicate", |ctx, _| {
            ctx.register_api(Arc::new(Echo))?;
            assert!(ctx.register_api(Arc::new(Echo)).is_err());
            for name in [
                "cache_query_total",
                "metrics_collector_thread",
                "metrics_collector_response_latency_millisecond_bucket",
            ] {
                assert!(ctx.metrics().counter(name, "collision").is_err());
            }
            Ok(Plugin::Data(Arc::new(())))
        })
        .unwrap();
    Engine::new_with_registry(
        Config::from_yaml("plugins: [{tag: one, type: duplicate}]").unwrap(),
        registry,
    )
    .unwrap();
}

struct FailedApi(bool);
impl PluginApi for FailedApi {
    fn handle<'a>(
        &'a self,
        _: Request<Bytes>,
        _: String,
    ) -> BoxFuture<'a, Result<Response<Bytes>>> {
        // True panics before constructing a future; false panics while polling.
        if self.0 {
            panic!("synchronous API panic fixture");
        }
        Box::pin(async {
            panic!("async API panic fixture");
        })
    }
}
#[tokio::test]
async fn handler_panics_return_500_and_release_shutdown_guard() {
    for immediate in [false, true] {
        let mut registry = Registry::new();
        registry
            .register_plugin_type("failed_api", move |ctx, _| {
                ctx.register_api(Arc::new(FailedApi(immediate)))?;
                Ok(Plugin::Data(Arc::new(())))
            })
            .unwrap();
        let engine = Arc::new(
            Engine::new_with_registry(
                Config::from_yaml("plugins: [{tag: failed, type: failed_api}]").unwrap(),
                registry,
            )
            .unwrap(),
        );
        let (url, task) = server(engine.clone()).await;
        assert_eq!(
            reqwest::get(format!("{url}/plugins/failed/"))
                .await
                .unwrap()
                .status(),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        tokio::time::timeout(std::time::Duration::from_secs(2), engine.shutdown())
            .await
            .unwrap()
            .unwrap();
        task.abort();
        task.await.unwrap_err();
    }
}

struct SlowApi {
    entered: Arc<Notify>,
    release: Arc<Notify>,
    closed: Arc<AtomicUsize>,
}
impl PluginApi for SlowApi {
    fn handle<'a>(
        &'a self,
        _: Request<Bytes>,
        _: String,
    ) -> BoxFuture<'a, Result<Response<Bytes>>> {
        Box::pin(async move {
            self.entered.notify_one();
            self.release.notified().await;
            assert_eq!(self.closed.load(Ordering::SeqCst), 0);
            Ok(Response::new(Bytes::from_static(b"finished")))
        })
    }
}
impl PluginCloser for SlowApi {
    fn close(&self) -> Result<()> {
        self.closed.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[tokio::test]
async fn shutdown_drains_active_api_before_closer_and_rejects_new_api() {
    let api = Arc::new(SlowApi {
        entered: Arc::new(Notify::new()),
        release: Arc::new(Notify::new()),
        closed: Arc::new(AtomicUsize::new(0)),
    });
    let mut registry = Registry::new();
    let plugin = api.clone();
    registry
        .register_plugin_type("slow_api", move |ctx, _| {
            ctx.register_api(plugin.clone())?;
            Ok(Plugin::Custom(Arc::new(PluginObject {
                closer: Some(plugin.clone()),
                ..Default::default()
            })))
        })
        .unwrap();
    let engine = Arc::new(
        Engine::new_with_registry(
            Config::from_yaml("plugins: [{tag: slow, type: slow_api}]").unwrap(),
            registry,
        )
        .unwrap(),
    );
    let (url, task) = server(engine.clone()).await;
    let pending_url = format!("{url}/plugins/slow/");
    let request = tokio::spawn(async move {
        reqwest::get(pending_url)
            .await
            .unwrap()
            .text()
            .await
            .unwrap()
    });
    tokio::time::timeout(std::time::Duration::from_secs(2), api.entered.notified())
        .await
        .unwrap();
    engine.request_shutdown(None);
    let closing = engine.clone();
    let shutdown = tokio::spawn(async move { closing.shutdown().await });
    assert_eq!(
        reqwest::get(format!("{url}/plugins/slow/"))
            .await
            .unwrap()
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(api.closed.load(Ordering::SeqCst), 0);
    api.release.notify_one();
    assert_eq!(request.await.unwrap(), "finished");
    shutdown.await.unwrap().unwrap();
    assert_eq!(api.closed.load(Ordering::SeqCst), 1);
    task.abort();
    task.await.unwrap_err();
}

#[test]
fn named_logger_uses_level_file_and_production_settings() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("plugin.log");
    let mut config = Config::from_yaml(
        "log: {level: warn, production: true}\nplugins: [{tag: logger, type: logging}]",
    )
    .unwrap();
    config.log.file = path.to_string_lossy().into_owned();
    let mut registry = Registry::new();
    registry
        .register_plugin_type("logging", |ctx, _| {
            let logger = ctx.logger();
            assert_eq!(logger.tag(), "logger");
            logger.info("filtered", Default::default())?;
            let fields = serde_json::json!({"count":3,"nested":{"ok":true}})
                .as_object()
                .unwrap()
                .clone();
            logger.warn("message \"with\" newline\n", fields)?;
            assert!(logger
                .error(
                    "invalid",
                    serde_json::json!({"tag":"spoof"})
                        .as_object()
                        .unwrap()
                        .clone()
                )
                .is_err());
            Ok(Plugin::Data(Arc::new(())))
        })
        .unwrap();
    let _engine = Engine::new_with_registry(config, registry).unwrap();
    let text = std::fs::read_to_string(path).unwrap();
    assert_eq!(text.lines().count(), 1);
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["tag"], "logger");
    assert_eq!(value["level"], "warn");
    assert_eq!(value["count"], 3);
    assert_eq!(value["nested"]["ok"], true);
    assert_eq!(value["msg"], "message \"with\" newline\n");
}
