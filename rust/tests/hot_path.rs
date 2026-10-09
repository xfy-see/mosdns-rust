//! No-network execution profiling and boundary checks for sequence entry shortcuts.
#![cfg(feature = "full")]
use anyhow::{bail, Result};
use futures::future::BoxFuture;
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use mosdns_rs::{
    coremain::{Config, Engine, MatcherPlugin, Registry},
    plugin::{matcher::Matcher, query_context::QueryContext},
};
use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::Cell,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

thread_local! {
    static TRACK_ALLOCATIONS: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
    static ALLOCATED_BYTES: Cell<u64> = const { Cell::new(0) };
}

struct CountingAllocator;
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        count_allocation(layout.size());
        System.alloc(layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        count_allocation(layout.size());
        System.alloc_zeroed(layout)
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        count_allocation(size);
        System.realloc(pointer, layout, size)
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        System.dealloc(pointer, layout)
    }
}

fn count_allocation(size: usize) {
    if TRACK_ALLOCATIONS.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        let _ = ALLOCATED_BYTES.try_with(|bytes| bytes.set(bytes.get() + size as u64));
    }
}

#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

fn query(id: u16) -> Message {
    let mut query = Message::new();
    query.set_id(id).add_query(Query::query(
        Name::from_ascii("hot-cache.example.").unwrap(),
        RecordType::A,
    ));
    query
}

struct ObservedMatcher {
    visits: Arc<AtomicUsize>,
    fail: bool,
}
impl MatcherPlugin for ObservedMatcher {
    fn matches<'a>(&'a self, ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            tokio::task::yield_now().await;
            self.visits.fetch_add(1, Ordering::Relaxed);
            if self.fail {
                bail!("observed matcher failed");
            }
            ctx.response.as_mut().unwrap().answers_mut()[0].set_ttl(123);
            Ok(true)
        })
    }
}

#[tokio::test]
async fn acceptance_preserves_and_short_circuit_custom_mutation_and_error() {
    for (condition, fail, calls, ttl) in [
        ("_false", false, 0, 300),
        ("_true", false, 1, 123),
        ("_true", true, 1, 0),
    ] {
        let visits = Arc::new(AtomicUsize::new(0));
        let counter = visits.clone();
        let mut registry = Registry::new();
        registry
            .register_matcher("observed", move |_, _| {
                Ok(Matcher::Custom(Arc::new(ObservedMatcher {
                    visits: counter.clone(),
                    fail,
                })))
            })
            .unwrap();
        let yaml = format!("plugins:\n  - tag: main\n    type: sequence\n    args:\n      - {{exec: 'black_hole 192.0.2.1'}}\n      - {{matches: ['has_resp', '{condition}', observed], exec: accept}}\n      - {{exec: 'black_hole 192.0.2.2'}}\n");
        let engine =
            Engine::new_with_registry(Config::from_yaml(&yaml).unwrap(), registry).unwrap();
        let response = engine
            .handle(query(22), "127.0.0.1".parse().unwrap(), "main")
            .await;
        if fail {
            assert!(response
                .unwrap_err()
                .to_string()
                .contains("observed matcher failed"));
        } else {
            let response = response.unwrap();
            assert_eq!(response.answers()[0].ttl(), ttl);
            let expected = if calls == 0 { "192.0.2.2" } else { "192.0.2.1" };
            assert_eq!(response.answers()[0].data().unwrap().to_string(), expected);
        }
        assert_eq!(visits.load(Ordering::Relaxed), calls);
        engine.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn terminal_conditions_preserve_false_negation_and_all_matches() {
    for (initial, conditions, expected) in [
        (false, vec!["has_resp"], Some("192.0.2.2")),
        (false, vec!["_false"], Some("192.0.2.2")),
        (true, vec!["has_resp", "_false"], Some("192.0.2.2")),
        (true, vec!["!has_resp"], Some("192.0.2.2")),
        (false, vec!["!has_resp"], None),
        (false, vec!["!_false"], None),
        (false, vec!["_true"], None),
        (true, vec!["has_resp", "_true"], Some("192.0.2.1")),
    ] {
        let prefix = if initial {
            "      - {exec: 'black_hole 192.0.2.1'}\n"
        } else {
            ""
        };
        let matches = conditions
            .iter()
            .map(|condition| format!("'{condition}'"))
            .collect::<Vec<_>>()
            .join(", ");
        let yaml = format!("plugins:\n  - tag: main\n    type: sequence\n    args:\n{prefix}      - {{matches: [{matches}], exec: accept}}\n      - {{exec: 'black_hole 192.0.2.2'}}\n");
        let engine = Engine::new(Config::from_yaml(&yaml).unwrap()).unwrap();
        let response = engine
            .handle(query(22), "127.0.0.1".parse().unwrap(), "main")
            .await
            .unwrap();
        assert_eq!(
            response.answers().len(),
            usize::from(expected.is_some()),
            "{conditions:?}"
        );
        if let Some(expected) = expected {
            assert_eq!(
                response.answers()[0].data().unwrap().to_string(),
                expected,
                "{conditions:?}"
            );
        }
        engine.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn terminal_accept_still_completes_recursive_logging_and_metrics() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("completion.log");
    let yaml = format!("log: {{file: '{}'}}\nplugins:\n  - tag: terminal\n    type: sequence\n    args: [{{matches: ['has_resp', '_true'], exec: accept}}]\n  - tag: main\n    type: sequence\n    args:\n      - {{exec: 'metrics_collector completion'}}\n      - {{exec: 'query_summary terminal-summary'}}\n      - {{exec: 'black_hole 192.0.2.1'}}\n      - {{exec: 'jump terminal'}}\n      - {{exec: 'reject 5'}}\n", path.display());
    let engine = Engine::new(Config::from_yaml(&yaml).unwrap()).unwrap();
    let response = engine
        .handle(query(32), "127.0.0.1".parse().unwrap(), "main")
        .await
        .unwrap();
    assert_eq!(
        response.answers()[0].data().unwrap().to_string(),
        "192.0.2.1"
    );
    assert!(engine
        .metrics_text()
        .contains("metrics_collector_query_total{name=\"completion\"} 1\n"));
    assert!(engine
        .metrics_text()
        .contains("metrics_collector_thread{name=\"completion\"} 0\n"));
    engine.shutdown().await.unwrap();
    let log = std::fs::read_to_string(path).unwrap();
    assert_eq!(
        log.lines()
            .filter(|line| line.starts_with("terminal-summary:"))
            .count(),
        1
    );
}

#[test]
fn entry_sequence_preserves_the_depth_limit_at_128() {
    // Both config construction and polling 128 nested plugin frames need more
    // stack than the test harness's small default; no production stack changes.
    std::thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                for (depth, allowed) in [(128, true), (129, false)] {
                    let mut yaml = String::from("plugins:\n");
                    for i in 0..depth {
                        let tag = if i == 0 {
                            "main".to_owned()
                        } else {
                            format!("s{i}")
                        };
                        let exec = if i + 1 == depth {
                            "black_hole 192.0.2.1".to_owned()
                        } else {
                            format!("$s{}", i + 1)
                        };
                        yaml.push_str(&format!(
                            "  - {{tag: {tag}, type: sequence, args: [{{exec: '{exec}'}}]}}\n"
                        ));
                    }
                    let engine = Engine::new(Config::from_yaml(&yaml).unwrap()).unwrap();
                    let response = engine
                        .handle(query(19), "127.0.0.1".parse().unwrap(), "main")
                        .await;
                    assert_eq!(response.is_ok(), allowed, "entry depth {depth}");
                    if !allowed {
                        assert!(response
                            .unwrap_err()
                            .to_string()
                            .contains("maximum sequence depth"));
                    }
                    engine.shutdown().await.unwrap();
                }
            });
        })
        .unwrap()
        .join()
        .unwrap();
}

/// Excludes query construction, parsing, socket I/O and serialization. The thread
/// local allocator counter includes only the engine call on this current thread.
#[test]
#[ignore = "manual no-network CPU and allocation profile; not a throughput claim"]
fn hot_cache_cpu_profile() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let engine = Engine::new(Config::from_yaml(
            "plugins:\n  - {tag: cache, type: cache, args: {size: 8192}}\n  - tag: main\n    type: sequence\n    args:\n      - {exec: '$cache'}\n      - {matches: has_resp, exec: accept}\n      - {exec: 'black_hole 192.0.2.1'}\n"
        ).unwrap()).unwrap();
        let client = "127.0.0.1".parse().unwrap();
        let original = query(31);
        for _ in 0..100 {
            engine.handle(original.clone(), client, "main").await.unwrap();
        }
        for round in 1..=3 {
            let mut elapsed = Duration::ZERO;
            for _ in 0..10 {
                let queries = (0..50_000).map(|_| original.clone()).collect::<Vec<_>>();
                let start = Instant::now();
                for query in queries {
                    let response = engine.handle(query, client, "main").await.unwrap();
                    std::hint::black_box(response);
                }
                elapsed += start.elapsed();
            }
            println!("round={round} queries=500000 ns_per_query={:.2} allocator_tracking=false",
                elapsed.as_nanos() as f64 / 500_000.0);
        }
        let queries = (0..50_000).map(|_| original.clone()).collect::<Vec<_>>();
        ALLOCATIONS.with(|count| count.set(0));
        ALLOCATED_BYTES.with(|bytes| bytes.set(0));
        TRACK_ALLOCATIONS.with(|track| track.set(true));
        for query in queries {
            std::hint::black_box(engine.handle(query, client, "main").await.unwrap());
        }
        TRACK_ALLOCATIONS.with(|track| track.set(false));
        println!("allocation_queries=50000 allocations_per_query={:.3} allocated_bytes_per_query={:.1}",
            ALLOCATIONS.with(Cell::get) as f64 / 50_000.0, ALLOCATED_BYTES.with(Cell::get) as f64 / 50_000.0);
        assert_eq!(engine.cache_stats("cache").unwrap().hits, 1_550_099);
        engine.shutdown().await.unwrap();
    });
}
