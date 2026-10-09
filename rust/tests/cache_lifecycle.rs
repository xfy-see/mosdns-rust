//! A retained plugin Arc must not keep its automatic cleaner alive after shutdown.
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use mosdns_rs::{
    coremain::{Config, Engine},
    plugin::executable::Executable,
};
use std::time::Duration;

#[cfg(feature = "full")]
fn cache_engine() -> Engine {
    Engine::new(Config::from_yaml("plugins:\n  - tag: configured\n    type: cache\n    args: {size: 128}\n  - tag: main\n    type: sequence\n    args:\n      - exec: cache 128\n      - exec: $configured\n      - exec: black_hole 192.0.2.1\n      - exec: ttl 1\n").unwrap()).unwrap()
}

#[cfg(not(feature = "full"))]
fn cache_engine() -> Engine {
    use mosdns_rs::{
        coremain::{ExecutablePlugin, Registry},
        plugin::query_context::{reply, QueryContext},
    };
    struct Answer;
    impl ExecutablePlugin for Answer {
        fn exec<'a>(
            &'a self,
            ctx: &'a mut QueryContext,
        ) -> futures::future::BoxFuture<'a, anyhow::Result<()>> {
            Box::pin(async move {
                let mut response = reply(&ctx.query, hickory_proto::op::ResponseCode::NoError);
                response.add_answer(hickory_proto::rr::Record::from_rdata(
                    ctx.query.queries()[0].name().clone(),
                    1,
                    hickory_proto::rr::RData::A(hickory_proto::rr::rdata::A(
                        "192.0.2.1".parse().unwrap(),
                    )),
                ));
                ctx.response = Some(response);
                Ok(())
            })
        }
    }
    let mut registry = Registry::new();
    registry
        .register_exec("fixture_answer", |_, _| {
            Ok(Executable::Custom(std::sync::Arc::new(Answer)))
        })
        .unwrap();
    Engine::new_with_registry(Config::from_yaml("plugins:\n  - tag: configured\n    type: cache\n    args: {size: 128}\n  - tag: main\n    type: sequence\n    args:\n      - exec: cache 128\n      - exec: $configured\n      - exec: fixture_answer\n").unwrap(), registry).unwrap()
}

#[tokio::test(start_paused = true)]
async fn shutdown_stops_configured_and_quick_cache_cleaners_even_with_retained_arcs() {
    let engine = cache_engine();
    let Some(Executable::Cache(configured)) = engine.get_plugin("configured").unwrap().executable()
    else {
        panic!("configured cache missing")
    };
    let Some(Executable::Sequence(sequence)) = engine.get_plugin("main").unwrap().executable()
    else {
        panic!("sequence missing")
    };
    let Executable::Cache(quick) = &sequence[0].exec else {
        panic!("quick cache missing")
    };
    let quick = quick.clone();
    drop(sequence);
    let mut query = Message::new();
    query.add_query(Query::query(
        Name::from_ascii("example.org.").unwrap(),
        RecordType::A,
    ));
    assert!(engine
        .handle(query, "127.0.0.1".parse().unwrap(), "main")
        .await
        .is_ok());
    assert_eq!(configured.entry_count(), 1);
    assert_eq!(quick.entry_count(), 1);
    engine.shutdown().await.unwrap();
    drop(engine);
    // Cache expiry uses std::Instant; only the cleaner's 10s ticker uses Tokio.
    // Once entries really expire, advancing the ticker exposes a leaked cleaner.
    std::thread::sleep(Duration::from_millis(1100));
    tokio::time::advance(Duration::from_secs(20)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        configured.entry_count(),
        1,
        "configured cleaner still ran after shutdown"
    );
    assert_eq!(
        quick.entry_count(),
        1,
        "quick cleaner still ran after shutdown"
    );
    configured.close_and_wait().await;
    quick.close_and_wait().await;
}
