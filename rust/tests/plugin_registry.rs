//! Public extension contracts, ported from coremain/plugin.go and sequence interfaces.
#[cfg(feature = "full")]
use anyhow::bail;
use anyhow::Result;
use futures::future::BoxFuture;
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
#[cfg(feature = "full")]
use mosdns_rs::coremain::{MatcherPlugin, Next, RecursiveExecutablePlugin};
use mosdns_rs::{
    coremain::{Config, Engine, ExecutablePlugin, Plugin, Registry},
    plugin::{
        executable::Executable,
        matcher::Matcher,
        query_context::{reg_key, QueryContext},
    },
};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn query() -> Message {
    let mut query = Message::new();
    query.set_id(42).add_query(Query::query(
        Name::from_ascii("registry.example.").unwrap(),
        RecordType::A,
    ));
    query
}
fn context() -> QueryContext {
    QueryContext::new(query(), "127.0.0.1".parse().unwrap())
}

#[test]
fn registered_keys_and_context_copy_keep_independent_maps_shared_values() {
    let a = reg_key();
    let b = reg_key();
    assert_ne!(a, 0);
    assert_ne!(a, b);
    let mut source = context();
    assert!(source.get_value(a).is_none());
    source.store_value(a, AtomicUsize::new(3));
    source.store_value(b, String::from("original"));
    let mut copied = source.clone();
    copied
        .get_value_as::<AtomicUsize>(a)
        .unwrap()
        .store(9, Ordering::SeqCst);
    assert_eq!(
        source
            .get_value_as::<AtomicUsize>(a)
            .unwrap()
            .load(Ordering::SeqCst),
        9
    );
    copied.store_value(b, String::from("copy"));
    copied.delete_value(a);
    assert_eq!(source.get_value_as::<String>(b).unwrap(), "original");
    assert_eq!(copied.get_value_as::<String>(b).unwrap(), "copy");
    assert!(copied.get_value(a).is_none());
    assert!(source.get_value_as::<AtomicUsize>(a).is_some());
    assert!(source.get_value_as::<String>(a).is_none());
    let fresh = context();
    assert!(fresh.get_value(b).is_none());
}

struct Store {
    key: u32,
    value: usize,
}
impl ExecutablePlugin for Store {
    fn exec<'a>(&'a self, ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            ctx.store_value(self.key, self.value);
            Ok(())
        })
    }
    fn quick_configure(&self, args: &str) -> Result<Option<Executable>> {
        Ok(Some(Executable::Custom(Arc::new(Store {
            key: self.key,
            value: args.parse()?,
        }))))
    }
}
#[cfg(feature = "full")]
struct Check {
    key: u32,
    value: usize,
}
#[cfg(feature = "full")]
impl MatcherPlugin for Check {
    fn matches<'a>(&'a self, ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move { Ok(ctx.get_value_as::<usize>(self.key) == Some(&self.value)) })
    }
    fn quick_configure(&self, args: &str) -> Result<Option<Matcher>> {
        Ok(Some(Matcher::Custom(Arc::new(Check {
            key: self.key,
            value: args.parse()?,
        }))))
    }
}
#[cfg(feature = "full")]
struct After {
    visits: Arc<AtomicUsize>,
    fail: bool,
}
#[cfg(feature = "full")]
impl RecursiveExecutablePlugin for After {
    fn exec<'a>(&'a self, ctx: &'a mut QueryContext, next: Next<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.fail {
                bail!("recursive error");
            }
            next.exec(ctx).await?;
            if let Some(response) = &mut ctx.response {
                for answer in response.answers_mut() {
                    answer.set_ttl(123);
                }
            }
            self.visits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}
#[cfg(feature = "full")]
struct ErrorMatch;
#[cfg(feature = "full")]
impl MatcherPlugin for ErrorMatch {
    fn matches<'a>(&'a self, _ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async { bail!("matcher error") })
    }
}

#[tokio::test]
#[cfg(feature = "full")]
async fn config_factories_quick_setup_tagged_reconfigure_and_recursive_tail() {
    let key = reg_key();
    let visits = Arc::new(AtomicUsize::new(0));
    let mut registry = Registry::new();
    registry
        .register_plugin_type("extension_data", |ctx, args| {
            assert_eq!(ctx.tag(), "data");
            Ok(Plugin::Data(Arc::new(
                args["value"].as_u64().unwrap() as usize
            )))
        })
        .unwrap();
    registry
        .register_plugin_type("extension_store", move |ctx, _| {
            let Plugin::Data(data) = ctx.get_plugin("data")? else {
                bail!("expected provider");
            };
            Ok(Plugin::Exec(Executable::Custom(Arc::new(Store {
                key,
                value: *data.downcast_ref::<usize>().unwrap(),
            }))))
        })
        .unwrap();
    registry
        .register_matcher("extension_check", move |_, args| {
            Ok(Matcher::Custom(Arc::new(Check {
                key,
                value: args.parse()?,
            })))
        })
        .unwrap();
    registry
        .register_preset("preset_matcher", move |_| {
            Ok(Plugin::Match(Matcher::Custom(Arc::new(Check {
                key,
                value: 0,
            }))))
        })
        .unwrap();
    let after_visits = visits.clone();
    registry
        .register_exec("extension_after", move |_, _| {
            Ok(Executable::RecursiveCustom(Arc::new(After {
                visits: after_visits.clone(),
                fail: false,
            })))
        })
        .unwrap();
    let yaml = "plugins:\n  - {tag: store, type: extension_store}\n  - {tag: data, type: extension_data, args: {value: 7}}\n  - tag: main\n    type: sequence\n    args:\n      - exec: $store 9\n      - matches: ['extension_check 9', '! extension_check 7', '$preset_matcher 9']\n        exec: extension_after\n      - exec: black_hole 192.0.2.9\n";
    let engine = Engine::new_with_registry(Config::from_yaml(yaml).unwrap(), registry).unwrap();
    let response = engine
        .handle(query(), "127.0.0.1".parse().unwrap(), "main")
        .await
        .unwrap();
    assert_eq!(response.id(), 42);
    assert_eq!(response.answers()[0].ttl(), 123);
    assert_eq!(visits.load(Ordering::SeqCst), 1);
    assert!(matches!(engine.get_plugin("data"), Some(Plugin::Data(_))));
}

#[test]
#[cfg(feature = "full")]
fn duplicate_reserved_names_and_removal_are_explicit() {
    let mut registry = Registry::new();
    registry
        .register_plugin_type("sample", |_, _| Ok(Plugin::Data(Arc::new(()))))
        .unwrap();
    assert!(registry
        .register_plugin_type("sample", |_, _| Ok(Plugin::Data(Arc::new(()))))
        .is_err());
    assert!(registry
        .register_plugin_type("cache", |_, _| Ok(Plugin::Data(Arc::new(()))))
        .is_err());
    assert!(registry
        .register_exec("accept", |_, _| Ok(Executable::Accept))
        .is_err());
    assert!(registry
        .register_matcher("qname", |_, _| Ok(Matcher::Constant(true)))
        .is_err());
    assert!(registry
        .register_preset("_sleep_500ms", |_| Ok(Plugin::Exec(Executable::Accept)))
        .is_err());
    assert!(registry.plugin_types().contains(&"sample".to_owned()));
    assert!(registry.plugin_types().contains(&"cache".to_owned()));
    assert!(registry.remove_plugin_type("sample"));
    assert!(!registry.remove_plugin_type("sample"));
    assert!(!registry.remove_plugin_type("cache"));
    registry
        .register_plugin_type("sample", |_, _| Ok(Plugin::Data(Arc::new(()))))
        .unwrap();
}

#[tokio::test]
#[cfg(feature = "full")]
async fn matcher_errors_propagate_through_reverse_and_and_short_circuits() {
    for (matches, want_error) in [
        ("['! extension_error']", true),
        ("['_false', 'extension_error']", false),
    ] {
        let mut registry = Registry::new();
        registry
            .register_matcher("extension_error", |_, _| {
                Ok(Matcher::Custom(Arc::new(ErrorMatch)))
            })
            .unwrap();
        let config = Config::from_yaml(&format!("plugins:\n - tag: main\n   type: sequence\n   args:\n    - matches: {matches}\n      exec: reject 3\n    - exec: black_hole 192.0.2.1\n")).unwrap();
        let engine = Engine::new_with_registry(config, registry).unwrap();
        let result = engine
            .handle(query(), "127.0.0.1".parse().unwrap(), "main")
            .await;
        assert_eq!(result.is_err(), want_error);
        if let Err(error) = result {
            assert!(error.to_string().contains("matcher error"));
        }
    }
}

#[test]
#[cfg(feature = "full")]
fn factory_errors_dependency_cycles_and_preset_config_collisions_fail_startup() {
    let mut registry = Registry::new();
    registry
        .register_plugin_type("broken", |_, _| bail!("factory error"))
        .unwrap();
    let error = Engine::new_with_registry(
        Config::from_yaml("plugins: [{tag: x, type: broken}]").unwrap(),
        registry,
    )
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("factory error"));
    let mut registry = Registry::new();
    registry
        .register_plugin_type("cycle", |ctx, _| ctx.get_plugin("x"))
        .unwrap();
    let error = Engine::new_with_registry(
        Config::from_yaml("plugins: [{tag: x, type: cycle}]").unwrap(),
        registry,
    )
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("dependency cycle"));
    let mut registry = Registry::new();
    registry
        .register_preset("x", |_| Ok(Plugin::Data(Arc::new(()))))
        .unwrap();
    let error = Engine::new_with_registry(
        Config::from_yaml("plugins: [{tag: x, type: sleep, args: {duration: 0}}]").unwrap(),
        registry,
    )
    .err()
    .unwrap();
    assert!(format!("{error:#}").contains("duplicated plugin tag"));
}

#[tokio::test]
#[cfg(feature = "full")]
async fn recursive_extensions_can_stop_chain_and_propagate_tail_errors() {
    struct Stop;
    impl RecursiveExecutablePlugin for Stop {
        fn exec<'a>(
            &'a self,
            ctx: &'a mut QueryContext,
            _next: Next<'a>,
        ) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                ctx.set_response(Some(mosdns_rs::plugin::query_context::reply(
                    &ctx.query,
                    hickory_proto::op::ResponseCode::NXDomain,
                )));
                Ok(())
            })
        }
    }
    let mut registry = Registry::new();
    registry
        .register_exec("extension_stop", |_, _| {
            Ok(Executable::RecursiveCustom(Arc::new(Stop)))
        })
        .unwrap();
    let config = Config::from_yaml("plugins: [{tag: main, type: sequence, args: [{exec: extension_stop}, {exec: black_hole 192.0.2.1}]}]").unwrap();
    let engine = Engine::new_with_registry(config, registry).unwrap();
    assert_eq!(
        engine
            .handle(query(), "127.0.0.1".parse().unwrap(), "main")
            .await
            .unwrap()
            .response_code(),
        hickory_proto::op::ResponseCode::NXDomain
    );
    let visits = Arc::new(AtomicUsize::new(0));
    let mut registry = Registry::new();
    let count = visits.clone();
    registry
        .register_exec("extension_after", move |_, _| {
            Ok(Executable::RecursiveCustom(Arc::new(After {
                visits: count.clone(),
                fail: false,
            })))
        })
        .unwrap();
    registry
        .register_exec("extension_fail", |_, _| {
            Ok(Executable::RecursiveCustom(Arc::new(After {
                visits: Arc::new(AtomicUsize::new(0)),
                fail: true,
            })))
        })
        .unwrap();
    let config = Config::from_yaml("plugins: [{tag: main, type: sequence, args: [{exec: extension_after}, {exec: extension_fail}]}]").unwrap();
    let engine = Engine::new_with_registry(config, registry).unwrap();
    assert!(engine
        .handle(query(), "127.0.0.1".parse().unwrap(), "main")
        .await
        .unwrap_err()
        .to_string()
        .contains("recursive error"));
    assert_eq!(visits.load(Ordering::SeqCst), 0);
}

#[test]
fn registries_are_isolated_and_quick_configuration_errors_fail_startup() {
    let mut registry = Registry::new();
    registry
        .register_exec("extension_only", |_, _| Ok(Executable::Accept))
        .unwrap();
    assert!(registry
        .register_exec("extension_only", |_, _| Ok(Executable::Accept))
        .is_err());
    registry
        .register_matcher("extension_only", |_, _| Ok(Matcher::Constant(true)))
        .unwrap();
    assert!(registry
        .register_matcher("extension_only", |_, _| Ok(Matcher::Constant(true)))
        .is_err());
    // The exec and matcher namespaces are independent, as in Go.
    let config = Config::from_yaml("plugins: [{tag: main, type: sequence, args: [{matches: extension_only, exec: extension_only}]}]").unwrap();
    assert!(Engine::new_with_registry(config.clone(), registry.clone()).is_ok());
    assert!(Engine::new(config.clone()).is_err());
    assert!(registry.remove_exec("extension_only"));
    assert!(registry.remove_matcher("extension_only"));
    assert!(Engine::new_with_registry(config, registry).is_err());
    let mut registry = Registry::new();
    let key = reg_key();
    registry
        .register_preset("store", move |_| {
            Ok(Plugin::Exec(Executable::Custom(Arc::new(Store {
                key,
                value: 0,
            }))))
        })
        .unwrap();
    let config = Config::from_yaml(
        "plugins: [{tag: main, type: sequence, args: [{exec: '$store invalid'}]}]",
    )
    .unwrap();
    assert!(Engine::new_with_registry(config, registry).is_err());
}

#[test]
fn prewrapped_kv_values_retain_the_original_arc_identity() {
    let key = reg_key();
    let value = Arc::new(AtomicUsize::new(7));
    let mut ctx = context();
    ctx.store_shared_value(key, value.clone());
    let copied = ctx.clone();
    let shared = copied
        .get_value(key)
        .unwrap()
        .clone()
        .downcast::<AtomicUsize>()
        .unwrap();
    assert!(Arc::ptr_eq(&value, &shared));
    ctx.delete_value(key);
    assert_eq!(shared.load(Ordering::SeqCst), 7);
    assert!(copied.get_value_as::<AtomicUsize>(key).is_some());
}

#[test]
#[cfg(feature = "full")]
fn a_factory_can_repeat_a_missing_dependency_lookup_without_a_false_cycle() {
    let mut registry = Registry::new();
    registry
        .register_plugin_type("optional_dependency", |ctx, _| {
            for _ in 0..2 {
                let error = ctx.get_plugin("missing").err().unwrap();
                assert_eq!(error.to_string(), "cannot find plugin missing");
            }
            Ok(Plugin::Data(Arc::new(7usize)))
        })
        .unwrap();
    let config = Config::from_yaml("plugins: [{tag: a, type: optional_dependency}]").unwrap();
    let engine = Engine::new_with_registry(config, registry).unwrap();
    let Some(Plugin::Data(value)) = engine.get_plugin("a") else {
        panic!("factory did not keep its fallback provider");
    };
    assert_eq!(value.downcast_ref::<usize>(), Some(&7));
}

#[test]
#[cfg(feature = "full")]
fn a_factory_can_recover_from_a_dependency_cycle_then_initialize_the_dependency() {
    let mut registry = Registry::new();
    let b_calls = Arc::new(AtomicUsize::new(0));
    registry
        .register_plugin_type("recover_a", |ctx, _| {
            // B cannot initialize yet: its dependency A is actively building.
            let first = ctx.get_plugin("b").err().unwrap();
            assert_eq!(first.to_string(), "plugin dependency cycle at a");
            // Recovering B's marker must not clear the active A marker.
            let still_building = ctx.get_plugin("a").err().unwrap();
            assert_eq!(still_building.to_string(), "plugin dependency cycle at a");
            Ok(Plugin::Data(Arc::new(7usize)))
        })
        .unwrap();
    let visits = b_calls.clone();
    registry
        .register_plugin_type("depends_on_a", move |ctx, _| {
            visits.fetch_add(1, Ordering::SeqCst);
            let Plugin::Data(a) = ctx.get_plugin("a")? else {
                bail!("A is not a provider");
            };
            let value = *a.downcast_ref::<usize>().unwrap();
            Ok(Plugin::Data(Arc::new(value + 1)))
        })
        .unwrap();
    let config =
        Config::from_yaml("plugins: [{tag: a, type: recover_a}, {tag: b, type: depends_on_a}]")
            .unwrap();
    let engine = Engine::new_with_registry(config, registry).unwrap();
    let Some(Plugin::Data(b)) = engine.get_plugin("b") else {
        panic!("B was not retried after A completed");
    };
    assert_eq!(b.downcast_ref::<usize>(), Some(&8));
    assert_eq!(b_calls.load(Ordering::SeqCst), 2);
}
