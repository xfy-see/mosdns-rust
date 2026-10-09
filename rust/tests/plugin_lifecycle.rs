//! Extension lifecycle and shared Engine shutdown regressions.
#![cfg(feature = "full")]
use anyhow::{bail, Result};
use futures::future::BoxFuture;
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RecordType},
};
use mosdns_rs::{
    coremain::{
        Config, Engine, ExecutablePlugin, MatcherPlugin, Plugin, PluginCloser, PluginObject,
        Registry,
    },
    plugin::{
        executable::Executable,
        matcher::Matcher,
        query_context::{reply, QueryContext},
    },
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tokio::sync::Notify;

fn query() -> Message {
    let mut q = Message::new();
    q.add_query(Query::query(
        Name::from_ascii("lifecycle.example.").unwrap(),
        RecordType::A,
    ));
    q
}
fn config(text: &str) -> Config {
    Config::from_yaml(text).unwrap()
}
fn resource(name: &str, log: Arc<Mutex<Vec<String>>>, fail: bool, panic: bool) -> Arc<Resource> {
    Arc::new(Resource {
        name: name.into(),
        log,
        fail,
        panic,
    })
}
struct Resource {
    name: String,
    log: Arc<Mutex<Vec<String>>>,
    fail: bool,
    panic: bool,
}
impl PluginCloser for Resource {
    fn close(&self) -> Result<()> {
        self.log.lock().unwrap().push(self.name.clone());
        assert!(!self.panic, "closer panic");
        if self.fail {
            bail!("closer error");
        }
        Ok(())
    }
}

#[test]
fn initialization_failure_closes_completed_and_partial_resources_once() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let first = resource("first", log.clone(), false, false);
    let partial = resource("partial", log.clone(), false, false);
    let mut registry = Registry::new();
    registry
        .register_plugin_type("ready", move |ctx, _| {
            ctx.register_closer(first.clone())?;
            ctx.register_closer(first.clone())?;
            Ok(Plugin::Data(first.clone()))
        })
        .unwrap();
    registry
        .register_plugin_type("broken", move |ctx, _| {
            ctx.register_closer(partial.clone())?;
            bail!("factory error")
        })
        .unwrap();
    let error = Engine::new_with_registry(
        config("plugins: [{tag: a, type: ready}, {tag: b, type: broken}]"),
        registry,
    )
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("factory error"));
    assert_eq!(*log.lock().unwrap(), ["partial", "first"]);
}

#[tokio::test]
async fn failed_sequence_rolls_back_builtin_collector_but_keeps_dependency_collector() {
    let mut registry = Registry::new();
    let attempts = Arc::new(AtomicUsize::new(0));
    let count = attempts.clone();
    registry
        .register_exec("fail_once", move |_, _| {
            if count.fetch_add(1, Ordering::SeqCst) == 0 {
                bail!("later setup failure");
            }
            Ok(Executable::Accept)
        })
        .unwrap();
    registry
        .register_plugin_type("recover", |ctx, _| {
            ctx.get_plugin("stable")?;
            assert!(ctx.get_plugin("retry").is_err());
            ctx.get_plugin("retry")
        })
        .unwrap();
    let engine = Engine::new_with_registry(config("plugins: [{tag: root, type: recover}, {tag: retry, type: sequence, args: [{exec: 'metrics_collector recovered'}, {exec: fail_once}]}, {tag: stable, type: sequence, args: [{exec: 'metrics_collector stable'}, {exec: accept}]}]"),registry).unwrap();
    let metrics = engine.metrics_text();
    for name in ["recovered", "stable"] {
        assert_eq!(
            metrics
                .matches(&format!(
                    "mosdns_metrics_collector_query_total{{name=\"{name}\"}}"
                ))
                .count(),
            1,
            "{metrics}"
        );
    }
    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    engine.shutdown().await.unwrap();
}

struct PanickingQuick {
    attempts: Arc<AtomicUsize>,
}
impl ExecutablePlugin for PanickingQuick {
    fn exec<'a>(&'a self, _: &'a mut QueryContext) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn quick_configure(&self, _: &str) -> Result<Option<Executable>> {
        if self.attempts.fetch_add(1, Ordering::SeqCst) == 0 {
            panic!("quick configure fixture panic");
        }
        Ok(None)
    }
}
#[tokio::test]
async fn tagged_quick_panic_becomes_error_and_rolls_back_before_retry() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let mut registry = Registry::new();
    let quick_attempts = Arc::new(AtomicUsize::new(0));
    let count = quick_attempts.clone();
    let closer = resource("tagged", log.clone(), false, false);
    let quick = Arc::new(PanickingQuick {
        attempts: quick_attempts.clone(),
    });
    registry
        .register_plugin_type("panicking_quick", move |ctx, _| {
            ctx.register_closer(closer.clone())?;
            Ok(Plugin::Exec(Executable::Custom(quick.clone())))
        })
        .unwrap();
    let managed_attempts = Arc::new(AtomicUsize::new(0));
    let attempts = managed_attempts.clone();
    let output = log.clone();
    registry
        .register_exec("managed", move |ctx, _| {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            ctx.register_closer(resource(
                &format!("managed{attempt}"),
                output.clone(),
                false,
                false,
            ))?;
            Ok(Executable::Accept)
        })
        .unwrap();
    registry
        .register_plugin_type("recover", |ctx, _| {
            let error = ctx.get_plugin("retry").err().unwrap();
            assert!(format!("{error:#}").contains("quick configure fixture panic"));
            ctx.get_plugin("retry")
        })
        .unwrap();
    let engine = Engine::new_with_registry(config("plugins: [{tag: root, type: recover}, {tag: retry, type: sequence, args: [{exec: managed}, {exec: '$tagged'}]}, {tag: tagged, type: panicking_quick}]"),registry).unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 2);
    assert_eq!(managed_attempts.load(Ordering::SeqCst), 2);
    assert_eq!(*log.lock().unwrap(), ["managed0"]);
    engine.shutdown().await.unwrap();
    let log = log.lock().unwrap();
    for name in ["managed0", "managed1", "tagged"] {
        assert_eq!(
            log.iter().filter(|item| *item == name).count(),
            1,
            "{log:?}"
        );
    }
}

#[tokio::test]
async fn recovered_factory_failure_only_closes_its_new_partial_resources() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let own = resource("outer", log.clone(), false, false);
    let partial = resource("nested_partial", log.clone(), false, false);
    let ready = resource("nested_ready", log.clone(), false, false);
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut registry = Registry::new();
    registry
        .register_plugin_type("outer", move |ctx, _| {
            ctx.register_closer(own.clone())?;
            assert!(ctx.get_plugin("nested").is_err());
            Ok(Plugin::Data(own.clone()))
        })
        .unwrap();
    registry
        .register_plugin_type("nested", move |ctx, _| {
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                ctx.register_closer(partial.clone())?;
                bail!("optional failure");
            }
            ctx.register_closer(ready.clone())?;
            Ok(Plugin::Data(ready.clone()))
        })
        .unwrap();
    let engine = Engine::new_with_registry(
        config("plugins: [{tag: outer, type: outer}, {tag: nested, type: nested}]"),
        registry,
    )
    .unwrap();
    assert_eq!(*log.lock().unwrap(), ["nested_partial"]);
    engine.shutdown().await.unwrap();
    assert_eq!(
        *log.lock().unwrap(),
        ["nested_partial", "nested_ready", "outer"]
    );
}

#[tokio::test]
async fn failed_sequence_closes_committed_quick_resources_and_discards_its_services() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let stable = resource("stable", log.clone(), false, false);
    let mut registry = Registry::new();
    let shared = stable.clone();
    registry
        .register_plugin_type("stable", move |ctx, _| {
            ctx.register_closer(shared.clone())?;
            Ok(Plugin::Data(shared.clone()))
        })
        .unwrap();
    let quick_attempts = Arc::new(AtomicUsize::new(0));
    let attempts = quick_attempts.clone();
    let service_runs = Arc::new(AtomicUsize::new(0));
    let runs = service_runs.clone();
    let started = Arc::new(Notify::new());
    let signal = started.clone();
    let close_log = log.clone();
    registry
        .register_exec("managed_quick", move |ctx, _| {
            let attempt = attempts.fetch_add(1, Ordering::SeqCst);
            ctx.get_plugin("stable")?;
            ctx.register_closer(stable.clone())?;
            ctx.register_closer(resource(
                &format!("quick{attempt}"),
                close_log.clone(),
                false,
                false,
            ))?;
            let runs = runs.clone();
            let started = signal.clone();
            let mut shutdown = ctx.shutdown_signal();
            ctx.attach_service(async move {
                runs.fetch_add(1, Ordering::SeqCst);
                started.notify_one();
                if !*shutdown.borrow() {
                    shutdown.changed().await?;
                }
                Ok(())
            })?;
            Ok(Executable::Accept)
        })
        .unwrap();
    let failed = Arc::new(AtomicUsize::new(0));
    let failures = failed.clone();
    registry
        .register_exec("fail_once", move |_, _| {
            if failures.fetch_add(1, Ordering::SeqCst) == 0 {
                bail!("late sequence failure");
            }
            Ok(Executable::Accept)
        })
        .unwrap();
    registry
        .register_plugin_type("recover", |ctx, _| {
            assert!(ctx.get_plugin("sequence").is_err());
            ctx.get_plugin("sequence")
        })
        .unwrap();
    let engine = Engine::new_with_registry(config("plugins: [{tag: root, type: recover}, {tag: sequence, type: sequence, args: [{exec: managed_quick}, {exec: fail_once}]}, {tag: stable, type: stable}]"),registry).unwrap();
    assert_eq!(*log.lock().unwrap(), ["quick0"]);
    tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
        .await
        .unwrap();
    assert_eq!(service_runs.load(Ordering::SeqCst), 1);
    assert_eq!(quick_attempts.load(Ordering::SeqCst), 2);
    engine.shutdown().await.unwrap();
    assert_eq!(*log.lock().unwrap(), ["quick0", "quick1", "stable"]);
}

#[test]
fn factory_and_closer_panics_are_reported_without_skipping_remaining_cleanup() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let first = resource("first", log.clone(), false, false);
    let panics = resource("panics", log.clone(), false, true);
    let mut registry = Registry::new();
    registry
        .register_plugin_type("ready", move |ctx, _| {
            ctx.register_closer(first.clone())?;
            Ok(Plugin::Data(Arc::new(())))
        })
        .unwrap();
    registry
        .register_plugin_type("panic_factory", move |ctx, _| {
            ctx.register_closer(panics.clone())?;
            panic!("factory panic");
        })
        .unwrap();
    let error = Engine::new_with_registry(
        config("plugins: [{tag: a, type: ready}, {tag: b, type: panic_factory}]"),
        registry,
    )
    .err()
    .unwrap();
    let text = format!("{error:#}");
    assert!(text.contains("factory panic"));
    assert!(text.contains("closer panic"));
    assert_eq!(*log.lock().unwrap(), ["panics", "first"]);
}

struct Multi {
    hits: AtomicUsize,
    closes: AtomicUsize,
    entered: Notify,
    release: Notify,
    block: bool,
}
impl Multi {
    fn new(block: bool) -> Arc<Self> {
        Arc::new(Self {
            hits: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
            entered: Notify::new(),
            release: Notify::new(),
            block,
        })
    }
}
impl ExecutablePlugin for Multi {
    fn exec<'a>(&'a self, ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.hits.fetch_add(1, Ordering::SeqCst);
            self.entered.notify_one();
            if self.block {
                self.release.notified().await;
            }
            assert_eq!(self.closes.load(Ordering::SeqCst), 0, "closed during query");
            ctx.set_response(Some(reply(&ctx.query, ResponseCode::NXDomain)));
            Ok(())
        })
    }
}
impl MatcherPlugin for Multi {
    fn matches<'a>(&'a self, _ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move { Ok(self.hits.load(Ordering::SeqCst) == 1) })
    }
}
impl PluginCloser for Multi {
    fn close(&self) -> Result<()> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn managed(object: Arc<Multi>) -> Plugin {
    Plugin::Custom(Arc::new(PluginObject {
        executable: Some(Executable::Custom(object.clone())),
        matcher: Some(Matcher::Custom(object.clone())),
        data: Some(object.clone()),
        closer: Some(object),
        ..Default::default()
    }))
}
fn multi_engine(object: Arc<Multi>) -> Engine {
    let mut registry = Registry::new();
    registry
        .register_plugin_type("multi", move |_, _| Ok(managed(object.clone())))
        .unwrap();
    Engine::new_with_registry(config("plugins: [{tag: multi, type: multi}, {tag: main, type: sequence, args: [{exec: '$multi'}, {matches: '$multi', exec: reject 3}]}]"), registry).unwrap()
}

#[tokio::test]
async fn one_object_exposes_exec_match_provider_and_close_without_duplicate_close() {
    let object = Multi::new(false);
    let engine = multi_engine(object.clone());
    let response = engine
        .handle(query(), "127.0.0.1".parse().unwrap(), "main")
        .await
        .unwrap();
    assert_eq!(response.response_code(), ResponseCode::NXDomain);
    let data = engine
        .get_plugin("multi")
        .unwrap()
        .data()
        .unwrap()
        .downcast::<Multi>()
        .unwrap();
    assert!(Arc::ptr_eq(&data, &object));
    let clone = engine.clone();
    drop(clone);
    assert_eq!(object.closes.load(Ordering::SeqCst), 0);
    engine.shutdown().await.unwrap();
    engine.shutdown().await.unwrap();
    assert_eq!(object.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn shutdown_waits_for_active_clone_query_and_rejects_new_queries() {
    let object = Multi::new(true);
    let engine = multi_engine(object.clone());
    let query_engine = engine.clone();
    let active = tokio::spawn(async move {
        query_engine
            .handle(query(), "127.0.0.1".parse().unwrap(), "main")
            .await
    });
    object.entered.notified().await;
    let mut signal = engine.shutdown_signal();
    let close_engine = engine.clone();
    let closing = tokio::spawn(async move { close_engine.shutdown().await });
    signal.changed().await.unwrap();
    assert!(engine
        .handle(query(), "127.0.0.1".parse().unwrap(), "main")
        .await
        .is_err());
    assert_eq!(object.closes.load(Ordering::SeqCst), 0);
    assert!(!closing.is_finished());
    object.release.notify_one();
    active.await.unwrap().unwrap();
    closing.await.unwrap().unwrap();
    assert_eq!(object.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn detached_fallback_loser_is_drained_before_plugin_close() {
    let object = Multi::new(true);
    let mut registry = Registry::new();
    let background = object.clone();
    registry
        .register_plugin_type("multi", move |_, _| Ok(managed(background.clone())))
        .unwrap();
    let engine = Engine::new_with_registry(config("plugins:\n - {tag: multi, type: multi}\n - {tag: primary, type: sequence, args: [{exec: sleep 1}, {exec: reject 3}]}\n - {tag: main, type: fallback, args: {primary: primary, secondary: multi, always_standby: true, threshold: 1000}}"), registry).unwrap();
    engine
        .handle(query(), "127.0.0.1".parse().unwrap(), "main")
        .await
        .unwrap();
    object.entered.notified().await;
    let close_engine = engine.clone();
    let mut signal = engine.shutdown_signal();
    let closing = tokio::spawn(async move { close_engine.shutdown().await });
    signal.changed().await.unwrap();
    assert_eq!(object.closes.load(Ordering::SeqCst), 0);
    assert!(!closing.is_finished());
    object.release.notify_one();
    closing.await.unwrap().unwrap();
    assert_eq!(object.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn attached_services_receive_signal_and_finish_before_close() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let plugin = resource("close", log.clone(), false, false);
    let events = log.clone();
    let mut registry = Registry::new();
    registry
        .register_plugin_type("service", move |ctx, _| {
            let mut signal = ctx.shutdown_signal();
            let events = events.clone();
            ctx.attach_service(async move {
                signal.changed().await.unwrap();
                tokio::task::yield_now().await;
                events.lock().unwrap().push("service_done".into());
                Ok(())
            })?;
            ctx.register_closer(plugin.clone())?;
            Ok(Plugin::Data(plugin.clone()))
        })
        .unwrap();
    let engine =
        Engine::new_with_registry(config("plugins: [{tag: service, type: service}]"), registry)
            .unwrap();
    engine.shutdown().await.unwrap();
    assert_eq!(*log.lock().unwrap(), ["service_done", "close"]);
}

#[tokio::test]
async fn concurrent_waiters_observe_same_close_errors_and_panics_finish_state() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let one = resource("one", log.clone(), true, false);
    let two = resource("two", log.clone(), false, true);
    let mut registry = Registry::new();
    registry
        .register_preset("one", move |ctx| {
            ctx.register_closer(one.clone())?;
            Ok(Plugin::Data(one.clone()))
        })
        .unwrap();
    registry
        .register_preset("two", move |ctx| {
            ctx.register_closer(two.clone())?;
            Ok(Plugin::Data(two.clone()))
        })
        .unwrap();
    let engine = Engine::new_with_registry(Config::default(), registry).unwrap();
    assert!(engine.request_shutdown(Some("first fatal".into())));
    assert!(!engine.request_shutdown(Some("ignored fatal".into())));
    let a = engine.clone();
    let b = engine.clone();
    let (a, b) = tokio::join!(a.wait_closed(), b.shutdown());
    let a = a.unwrap_err().to_string();
    let b = b.unwrap_err().to_string();
    assert_eq!(a, b);
    assert!(a.contains("first fatal") && a.contains("closer error") && a.contains("closer panic"));
    assert!(!a.contains("ignored fatal"));
    assert_eq!(*log.lock().unwrap(), ["two", "one"]);
    assert_eq!(engine.wait_closed().await.unwrap_err().to_string(), a);
}

#[tokio::test]
async fn service_failure_requests_shutdown_and_failed_startup_does_not_spawn_services() {
    let runs = Arc::new(AtomicUsize::new(0));
    let mut registry = Registry::new();
    let counter = runs.clone();
    registry
        .register_plugin_type("service", move |ctx, _| {
            let counter = counter.clone();
            ctx.attach_service(async move {
                counter.fetch_add(1, Ordering::SeqCst);
                bail!("service failure")
            })?;
            Ok(Plugin::Data(Arc::new(())))
        })
        .unwrap();
    let error = Engine::new_with_registry(
        config("plugins: [{tag: service, type: service}, {tag: invalid, type: missing}]"),
        registry.clone(),
    )
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("missing"));
    tokio::task::yield_now().await;
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    let engine =
        Engine::new_with_registry(config("plugins: [{tag: service, type: service}]"), registry)
            .unwrap();
    assert!(engine
        .wait_closed()
        .await
        .unwrap_err()
        .to_string()
        .contains("service failure"));
    assert_eq!(runs.load(Ordering::SeqCst), 1);
}

#[test]
fn retrying_a_rolled_back_arc_is_rejected_without_a_second_close() {
    for explicit in [true, false] {
        let log = Arc::new(Mutex::new(Vec::new()));
        let shared = resource("once", log.clone(), false, false);
        let attempts = Arc::new(AtomicUsize::new(0));
        let mut registry = Registry::new();
        registry
            .register_plugin_type("outer", |ctx, _| {
                assert!(ctx.get_plugin("nested").is_err());
                Ok(Plugin::Data(Arc::new(())))
            })
            .unwrap();
        registry
            .register_plugin_type("retry", move |ctx, _| {
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    ctx.register_closer(shared.clone())?;
                    bail!("partial init failed");
                }
                if explicit {
                    ctx.register_closer(shared.clone())?;
                    Ok(Plugin::Data(shared.clone()))
                } else {
                    Ok(Plugin::Custom(Arc::new(PluginObject {
                        closer: Some(shared.clone()),
                        ..Default::default()
                    })))
                }
            })
            .unwrap();
        let error = Engine::new_with_registry(
            config("plugins: [{tag: outer, type: outer}, {tag: nested, type: retry}]"),
            registry,
        )
        .err()
        .unwrap();
        assert!(format!("{error:#}").contains("already closed during startup rollback"));
        assert_eq!(*log.lock().unwrap(), ["once"]);
    }
}

#[tokio::test]
async fn a_nested_failed_registration_does_not_close_an_outer_owned_arc() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let shared = resource("shared", log.clone(), false, false);
    let outer = shared.clone();
    let child = shared.clone();
    let attempts = Arc::new(AtomicUsize::new(0));
    let mut registry = Registry::new();
    registry
        .register_plugin_type("outer", move |ctx, _| {
            ctx.register_closer(outer.clone())?;
            assert!(ctx.get_plugin("child").is_err());
            Ok(Plugin::Data(outer.clone()))
        })
        .unwrap();
    registry
        .register_plugin_type("child", move |ctx, _| {
            ctx.register_closer(child.clone())?;
            if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                bail!("optional init failure");
            }
            Ok(Plugin::Data(child.clone()))
        })
        .unwrap();
    let engine = Engine::new_with_registry(
        config("plugins: [{tag: outer, type: outer}, {tag: child, type: child}]"),
        registry,
    )
    .unwrap();
    assert!(log.lock().unwrap().is_empty());
    engine.shutdown().await.unwrap();
    assert_eq!(*log.lock().unwrap(), ["shared"]);
}

#[tokio::test]
async fn a_service_error_after_normal_close_request_is_still_a_cleanup_error() {
    let mut registry = Registry::new();
    registry
        .register_plugin_type("service", |ctx, _| {
            let mut signal = ctx.shutdown_signal();
            ctx.attach_service(async move {
                signal.changed().await?;
                bail!("service drain failure")
            })?;
            Ok(Plugin::Data(Arc::new(())))
        })
        .unwrap();
    let engine =
        Engine::new_with_registry(config("plugins: [{tag: service, type: service}]"), registry)
            .unwrap();
    assert!(engine.request_shutdown(None));
    assert!(!engine.request_shutdown(Some("late request ignored".into())));
    let error = engine.wait_closed().await.unwrap_err().to_string();
    assert!(error.contains("service drain failure"));
    assert!(!error.contains("late request ignored"));
}

struct BlockingCloser {
    entered: Notify,
    allowed: Mutex<bool>,
    condition: std::sync::Condvar,
    closes: AtomicUsize,
}
impl PluginCloser for BlockingCloser {
    fn close(&self) -> Result<()> {
        self.entered.notify_one();
        let mut allowed = self.allowed.lock().unwrap();
        while !*allowed {
            allowed = self.condition.wait(allowed).unwrap();
        }
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[tokio::test]
async fn cancelling_a_shutdown_waiter_does_not_cancel_close_or_block_the_executor() {
    let closer = Arc::new(BlockingCloser {
        entered: Notify::new(),
        allowed: Mutex::new(false),
        condition: std::sync::Condvar::new(),
        closes: AtomicUsize::new(0),
    });
    let object = closer.clone();
    let mut registry = Registry::new();
    registry
        .register_preset("blocking", move |ctx| {
            ctx.register_closer(object.clone())?;
            Ok(Plugin::Data(object.clone()))
        })
        .unwrap();
    let engine = Engine::new_with_registry(Config::default(), registry).unwrap();
    let first = engine.clone();
    let waiter = tokio::spawn(async move { first.shutdown().await });
    closer.entered.notified().await;
    waiter.abort();
    assert_eq!(closer.closes.load(Ordering::SeqCst), 0);
    // A Tokio task on this current-thread test still runs while close blocks.
    tokio::task::yield_now().await;
    *closer.allowed.lock().unwrap() = true;
    closer.condition.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(2), engine.wait_closed())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(closer.closes.load(Ordering::SeqCst), 1);
}
