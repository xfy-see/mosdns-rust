// SPDX-License-Identifier: GPL-3.0-or-later
//! Go mosdns_minimal profile contracts. Peers use only loopback; no service or
//! kernel set is installed. Counting extensions replace privileged finalization.
#![cfg(not(feature = "full"))]

use anyhow::{bail, Result};
use futures::future::BoxFuture;
use hickory_proto::{
    op::{Edns, Message, Query, ResponseCode},
    rr::{
        rdata::{
            opt::{ClientSubnet, EdnsCode, EdnsOption},
            A, AAAA, SOA, TXT,
        },
        DNSClass, Name, RData, Record, RecordType,
    },
};
use mosdns_rs::{
    coremain::{
        Config, Engine, ExecutablePlugin, MatcherPlugin, Plugin, PluginCloser, PluginObject,
        Registry,
    },
    pkg::{
        kernel_sets::{nft, response_elements, wire, TimeoutPolicy},
        upstream::{Options, Upstream},
    },
    plugin::{
        executable::Executable,
        matcher::Matcher,
        query_context::{reply, QueryContext},
    },
};
use std::{
    path::Path,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::Notify, task::JoinHandle};

fn query(name: &str, typ: RecordType, id: u16) -> Message {
    let mut q = Message::new();
    q.set_id(id)
        .set_recursion_desired(true)
        .add_query(Query::query(Name::from_ascii(name).unwrap(), typ));
    q
}

fn response(q: &Message, branch: u8, ttl: u32) -> Message {
    let question = &q.queries()[0];
    let mut r = reply(q, ResponseCode::NoError);
    if question.name().to_ascii().starts_with("missing.") {
        r.set_response_code(ResponseCode::NXDomain);
        r.add_name_server(Record::from_rdata(
            Name::from_ascii("test.").unwrap(),
            ttl,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.test.").unwrap(),
                Name::from_ascii("hostmaster.test.").unwrap(),
                1,
                60,
                60,
                60,
                60,
            )),
        ));
        return r;
    }
    let data = match question.query_type() {
        RecordType::A => RData::A(A(if branch == 1 {
            "198.18.0.1"
        } else {
            "203.0.113.2"
        }
        .parse()
        .unwrap())),
        RecordType::AAAA => RData::AAAA(AAAA(format!("2001:db8::{branch}").parse().unwrap())),
        RecordType::TXT => RData::TXT(TXT::new(vec![branch.to_string()])),
        other => panic!("unexpected fixture type {other}"),
    };
    let mut record = Record::from_rdata(question.name().clone(), ttl, data);
    record.set_dns_class(question.query_class());
    r.add_answer(record);
    r
}

struct Mock {
    address: std::net::SocketAddr,
    calls: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Mock {
    async fn new(branch: u8) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            loop {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                let q = Message::from_vec(&buffer[..length]).unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                socket
                    .send_to(&response(&q, branch, 60).to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        Self {
            address,
            calls,
            task,
        }
    }
}
impl Drop for Mock {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct Trace {
    name: String,
    calls: Arc<Mutex<Vec<String>>>,
}
impl ExecutablePlugin for Trace {
    fn exec<'a>(&'a self, _ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.calls.lock().unwrap().push(self.name.clone());
            Ok(())
        })
    }
}
struct Answer {
    branch: u8,
    ttl: u32,
}
impl ExecutablePlugin for Answer {
    fn exec<'a>(&'a self, ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            ctx.response = Some(response(&ctx.query, self.branch, self.ttl));
            Ok(())
        })
    }
}
fn fixture_registry(calls: Arc<Mutex<Vec<String>>>) -> Registry {
    let mut registry = Registry::new();
    registry
        .register_exec("fixture_trace", move |_, args| {
            Ok(Executable::Custom(Arc::new(Trace {
                name: args.into(),
                calls: calls.clone(),
            })))
        })
        .unwrap();
    registry
        .register_exec("fixture_answer", |_, args| {
            let (branch, ttl) = args.split_once(' ').unwrap_or((args, "60"));
            Ok(Executable::Custom(Arc::new(Answer {
                branch: branch.parse()?,
                ttl: ttl.parse()?,
            })))
        })
        .unwrap();
    registry
}
async fn handle(engine: &Engine, name: &str, typ: RecordType, id: u16) -> Message {
    tokio::time::timeout(
        Duration::from_secs(3),
        engine.handle(query(name, typ, id), "127.0.0.1".parse().unwrap(), "main"),
    )
    .await
    .unwrap()
    .unwrap()
}

#[test]
fn minimal_static_registry_is_exact_and_keeps_only_profile_quick_syntax() {
    let r = Registry::new();
    assert_eq!(
        r.plugin_types(),
        [
            "cache",
            "domain_set",
            "forward",
            "sequence",
            "tcp_server",
            "udp_server"
        ]
    );
    assert_eq!(
        r.exec_types(),
        ["accept", "cache", "forward", "goto", "jump", "nftset", "reject", "return"]
    );
    assert_eq!(r.matcher_types(), ["_false", "_true", "has_resp", "qname"]);
    assert!(r.preset_tags().is_empty());
}

#[derive(Default)]
struct ManagedAnswer {
    queries: AtomicUsize,
    closes: AtomicUsize,
}
impl ExecutablePlugin for ManagedAnswer {
    fn exec<'a>(&'a self, ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.queries.fetch_add(1, Ordering::SeqCst);
            ctx.response = Some(response(&ctx.query, 1, 60));
            Ok(())
        })
    }
}
impl PluginCloser for ManagedAnswer {
    fn close(&self) -> Result<()> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[tokio::test]
async fn custom_library_plugin_keeps_execution_and_one_time_resource_shutdown() {
    let resource = Arc::new(ManagedAnswer::default());
    let shared = resource.clone();
    let mut registry = Registry::new();
    registry
        .register_plugin_type("fixture_resource", move |_, _| {
            Ok(Plugin::Custom(Arc::new(PluginObject {
                executable: Some(Executable::Custom(shared.clone())),
                closer: Some(shared.clone()),
                ..Default::default()
            })))
        })
        .unwrap();
    let yaml = "plugins: [{tag: resource, type: fixture_resource}, {tag: main, type: sequence, args: [{exec: '$resource'}]}]";
    let config = Config::from_yaml(yaml).unwrap();
    assert!(
        Engine::new(config.clone()).is_err(),
        "unregistered custom type accepted"
    );
    let engine = Engine::new_with_registry(config, registry).unwrap();
    assert_eq!(
        handle(&engine, "custom.test.", RecordType::A, 71)
            .await
            .id(),
        71
    );
    assert_eq!(resource.queries.load(Ordering::SeqCst), 1);
    engine.shutdown().await.unwrap();
    engine.clone().shutdown().await.unwrap();
    assert_eq!(resource.closes.load(Ordering::SeqCst), 1);
    assert!(engine
        .handle(
            query("custom.test.", RecordType::A, 72),
            "127.0.0.1".parse().unwrap(),
            "main"
        )
        .await
        .is_err());
    assert_eq!(resource.queries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn removed_full_aliases_dispatch_to_explicit_minimal_extensions() {
    let type_calls = Arc::new(AtomicUsize::new(0));
    let matcher_calls = Arc::new(AtomicUsize::new(0));
    let exec_calls = Arc::new(AtomicUsize::new(0));
    let trace = Arc::new(Mutex::new(Vec::new()));
    let resource = Arc::new(ManagedAnswer::default());
    let mut registry = Registry::new();
    let calls = type_calls.clone();
    let shared = resource.clone();
    registry
        .register_plugin_type("quic_server", move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Plugin::Custom(Arc::new(PluginObject {
                executable: Some(Executable::Custom(shared.clone())),
                closer: Some(shared.clone()),
                ..Default::default()
            })))
        })
        .unwrap();
    let calls = matcher_calls.clone();
    registry
        .register_matcher("cname", move |_, args| {
            assert_eq!(args, "full:never.test");
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Matcher::Constant(true))
        })
        .unwrap();
    let calls = exec_calls.clone();
    let events = trace.clone();
    registry
        .register_exec("ipset", move |_, args| {
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(Executable::Custom(Arc::new(Trace {
                name: args.into(),
                calls: events.clone(),
            })))
        })
        .unwrap();
    let engine = Engine::new_with_registry(
        Config::from_yaml(
            "plugins: [{tag: resource, type: quic_server}, {tag: main, type: sequence, args: [{matches: 'cname full:never.test', exec: 'ipset extension-ran'}, {exec: '$resource'}, {exec: accept}]}]",
        )
        .unwrap(),
        registry,
    )
    .unwrap();
    assert!(engine.servers().is_empty());
    assert_eq!(type_calls.load(Ordering::SeqCst), 1);
    assert_eq!(matcher_calls.load(Ordering::SeqCst), 1);
    assert_eq!(exec_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        handle(&engine, "custom.test.", RecordType::A, 73)
            .await
            .id(),
        73
    );
    assert_eq!(*trace.lock().unwrap(), ["extension-ran"]);
    assert_eq!(resource.queries.load(Ordering::SeqCst), 1);
    engine.shutdown().await.unwrap();
    assert_eq!(resource.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn site_only_rules_choose_two_mock_upstreams_and_finalize_cached_answers() {
    let cn = Mock::new(1).await;
    let foreign = Mock::new(2).await;
    let finalized = Arc::new(Mutex::new(Vec::new()));
    // Mirror tests/profiles/site_only_test.go, including domain/full boundaries,
    // regexp/keyword rules, A/AAAA/TXT, NXDOMAIN and finalization on cache hits.
    let yaml = format!(
        r#"plugins:
- {{tag: cn_site, type: domain_set, args: {{exps: ['domain:cn.test', 'full:only.test', 'regexp:^regex[0-9]+\.test$', 'keyword:cnkeyword']}}}}
- {{tag: cached, type: cache, args: {{size: 1024, lazy_cache_ttl: 0}}}}
- {{tag: cn_forward, type: forward, args: {{upstreams: [{{addr: '{}'}}]}}}}
- {{tag: foreign_forward, type: forward, args: {{upstreams: [{{addr: '{}'}}]}}}}
- tag: finalize
  type: sequence
  args:
  - {{matches: 'qname $cn_site', exec: 'fixture_trace finalized'}}
  - {{exec: accept}}
- {{tag: resolve_cn, type: sequence, args: [{{exec: '$cn_forward'}}, {{exec: 'goto finalize'}}]}}
- tag: main
  type: sequence
  args:
  - {{exec: '$cached'}}
  - {{matches: has_resp, exec: 'goto finalize'}}
  - {{matches: 'qname $cn_site', exec: 'goto resolve_cn'}}
  - {{exec: '$foreign_forward'}}
  - {{exec: 'goto finalize'}}
"#,
        cn.address, foreign.address
    );
    let engine = Engine::new_with_registry(
        Config::from_yaml(&yaml).unwrap(),
        fixture_registry(finalized.clone()),
    )
    .unwrap();
    for (index, (name, typ, domestic, negative)) in [
        ("www.cn.test.", RecordType::A, true, false),
        ("www.cn.test.", RecordType::AAAA, true, false),
        ("www.cn.test.", RecordType::TXT, true, false),
        ("only.test.", RecordType::A, true, false),
        ("regex123.test.", RecordType::A, true, false),
        ("www.cnkeyword.test.", RecordType::A, true, false),
        ("www.cn.test.evil.", RecordType::A, false, false),
        ("x.only.test.", RecordType::AAAA, false, false),
        ("foreign.test.", RecordType::A, false, false),
        ("foreign.test.", RecordType::AAAA, false, false),
        ("missing.foreign.test.", RecordType::A, false, true),
    ]
    .into_iter()
    .enumerate()
    {
        let before_cn = cn.calls.load(Ordering::SeqCst);
        let before_foreign = foreign.calls.load(Ordering::SeqCst);
        let before_finalized = finalized.lock().unwrap().len();
        for repeat in 0..2 {
            let id = 1000 + (index * 2 + repeat) as u16;
            let r = handle(&engine, name, typ, id).await;
            assert_eq!(r.id(), id, "{name}");
            assert_eq!(r.queries(), query(name, typ, id).queries());
            assert_eq!(
                r.response_code(),
                if negative {
                    ResponseCode::NXDomain
                } else {
                    ResponseCode::NoError
                }
            );
            if negative {
                assert!(r.answers().is_empty());
                assert_eq!(r.name_servers().len(), 1);
                assert_eq!(r.name_servers()[0].record_type(), RecordType::SOA);
            } else {
                assert_eq!(r.answers().len(), 1);
                let answer = &r.answers()[0];
                assert_eq!(answer.name(), query(name, typ, id).queries()[0].name());
                assert_eq!(answer.record_type(), typ);
                assert_eq!(answer.dns_class(), DNSClass::IN);
                assert!((59..=60).contains(&answer.ttl()));
                let want = response(&query(name, typ, id), if domestic { 1 } else { 2 }, 60);
                assert_eq!(answer.data(), want.answers()[0].data());
            }
        }
        assert_eq!(
            cn.calls.load(Ordering::SeqCst) - before_cn,
            usize::from(domestic),
            "{name}"
        );
        assert_eq!(
            foreign.calls.load(Ordering::SeqCst) - before_foreign,
            usize::from(!domestic),
            "{name}"
        );
        assert_eq!(
            finalized.lock().unwrap().len() - before_finalized,
            if domestic { 2 } else { 0 },
            "{name}"
        );
    }
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn sequence_jump_return_tagged_sequence_and_goto_keep_go_stack_semantics() {
    for (flow, expected) in [
        ("jump child", vec!["main", "child", "tail"]),
        ("$child", vec!["main", "child", "tail"]),
        ("goto child", vec!["main", "child"]),
    ] {
        let trace = Arc::new(Mutex::new(Vec::new()));
        let yaml = format!("plugins:\n- {{tag: child, type: sequence, args: [{{exec: 'fixture_trace child'}}, {{exec: 'fixture_answer 1'}}, {{exec: return}}, {{exec: 'fixture_trace unreachable'}}]}}\n- {{tag: main, type: sequence, args: [{{exec: 'fixture_trace main'}}, {{exec: '{flow}'}}, {{exec: 'fixture_trace tail'}}]}}\n");
        let e = Engine::new_with_registry(
            Config::from_yaml(&yaml).unwrap(),
            fixture_registry(trace.clone()),
        )
        .unwrap();
        assert_eq!(handle(&e, "flow.test.", RecordType::A, 42).await.id(), 42);
        assert_eq!(*trace.lock().unwrap(), expected);
        e.shutdown().await.unwrap();
    }
    let trace = Arc::new(Mutex::new(Vec::new()));
    let yaml = "plugins:\n- {tag: final, type: sequence, args: [{exec: 'fixture_trace final'}, {exec: 'fixture_answer 1'}, {exec: return}]}\n- {tag: child, type: sequence, args: [{exec: 'goto final'}, {exec: 'fixture_trace child-tail'}]}\n- {tag: main, type: sequence, args: [{exec: 'jump child'}, {exec: 'fixture_trace main-tail'}]}\n";
    let e = Engine::new_with_registry(
        Config::from_yaml(yaml).unwrap(),
        fixture_registry(trace.clone()),
    )
    .unwrap();
    handle(&e, "flow.test.", RecordType::A, 7).await;
    assert_eq!(*trace.lock().unwrap(), ["final"]);
    e.shutdown().await.unwrap();
}

struct ErrorMatcher(Arc<AtomicUsize>);
impl MatcherPlugin for ErrorMatcher {
    fn matches<'a>(&'a self, _ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::SeqCst);
            bail!("fixture matcher failed")
        })
    }
}
#[tokio::test]
async fn and_negation_short_circuit_and_reject_propagate_without_full_matchers() {
    for (conditions, calls, fails) in [
        ("['_false', fixture_error]", 0, false),
        ("['!_true', fixture_error]", 0, false),
        ("['_true', '! fixture_error']", 1, true),
    ] {
        let invoked = Arc::new(AtomicUsize::new(0));
        let count = invoked.clone();
        let mut r = fixture_registry(Arc::new(Mutex::new(Vec::new())));
        r.register_matcher("fixture_error", move |_, _| {
            Ok(Matcher::Custom(Arc::new(ErrorMatcher(count.clone()))))
        })
        .unwrap();
        let yaml = format!("plugins:\n- {{tag: main, type: sequence, args: [{{matches: {conditions}, exec: 'reject 5'}}, {{matches: ['_true', '!_false'], exec: 'reject 3'}}]}}\n");
        let e = Engine::new_with_registry(Config::from_yaml(&yaml).unwrap(), r).unwrap();
        let result = e
            .handle(
                query("flow.test.", RecordType::A, 8),
                "127.0.0.1".parse().unwrap(),
                "main",
            )
            .await;
        if fails {
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("fixture matcher failed"));
        } else {
            assert_eq!(result.unwrap().response_code(), ResponseCode::NXDomain);
        }
        assert_eq!(invoked.load(Ordering::SeqCst), calls);
        e.shutdown().await.unwrap();
    }
    let e = Engine::new(
        Config::from_yaml(
            "plugins: [{tag: main, type: sequence, args: [{exec: reject}, {exec: 'reject 3'}]}]",
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        handle(&e, "flow.test.", RecordType::A, 9)
            .await
            .response_code(),
        ResponseCode::Refused
    );
    e.shutdown().await.unwrap();
}

struct Refresh {
    calls: Arc<AtomicUsize>,
    release: Arc<Notify>,
}
impl ExecutablePlugin for Refresh {
    fn exec<'a>(&'a self, ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let fill = self.calls.fetch_add(1, Ordering::SeqCst);
            assert!(
                ctx.response.is_none(),
                "refresh saw the installed stale response"
            );
            if fill > 0 {
                self.release.notified().await;
            }
            ctx.response = Some(response(&ctx.query, if fill == 0 { 1 } else { 2 }, 1));
            Ok(())
        })
    }
}
#[tokio::test]
async fn memory_cache_lazy_refresh_is_singleflight_and_preserves_request_identity() {
    let calls = Arc::new(AtomicUsize::new(0));
    let release = Arc::new(Notify::new());
    let mut registry = Registry::new();
    let c = calls.clone();
    let gate = release.clone();
    registry
        .register_exec("fixture_refresh", move |_, _| {
            Ok(Executable::Custom(Arc::new(Refresh {
                calls: c.clone(),
                release: gate.clone(),
            })))
        })
        .unwrap();
    let yaml = "plugins:\n- {tag: cached, type: cache, args: {size: 16, lazy_cache_ttl: 60}}\n- {tag: main, type: sequence, args: [{exec: '$cached'}, {matches: has_resp, exec: accept}, {exec: fixture_refresh}]}\n";
    let engine = Engine::new_with_registry(Config::from_yaml(yaml).unwrap(), registry).unwrap();
    assert_eq!(
        handle(&engine, "lazy.test.", RecordType::A, 1)
            .await
            .answers()[0]
            .ttl(),
        1
    );
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let replies = futures::future::join_all(
        (2..22).map(|id| handle(&engine, "lazy.test.", RecordType::A, id)),
    )
    .await;
    for (id, r) in (2..22).zip(replies) {
        assert_eq!(r.id(), id);
        assert_eq!(r.answers()[0].ttl(), 5);
        assert_eq!(r.answers()[0].data().unwrap().to_string(), "198.18.0.1");
    }
    tokio::time::timeout(Duration::from_secs(1), async {
        while calls.load(Ordering::SeqCst) < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let r = handle(&engine, "lazy.test.", RecordType::A, 22).await;
            if r.answers()[0].data().unwrap().to_string() == "203.0.113.2" {
                assert_eq!(r.answers()[0].ttl(), 1);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn cache_answers_keep_edns_do_and_do_not_echo_client_subnet() {
    let fills = Arc::new(Mutex::new(Vec::new()));
    let registry = fixture_registry(fills.clone());
    let e = Engine::new_with_registry(Config::from_yaml("plugins: [{tag: main, type: sequence, args: [{exec: 'cache 16'}, {matches: has_resp, exec: accept}, {exec: 'fixture_trace fill'}, {exec: 'fixture_answer 1'}]}]").unwrap(), registry).unwrap();
    for (id, subnet, do_bit, count) in [
        (11, "192.0.2.0", true, 1),
        (12, "198.51.100.0", true, 1),
        // Go strips client OPT before cache lookup; client DO changes must still
        // use the cached data while response EDNS reflects the current client.
        (13, "203.0.113.0", false, 1),
    ] {
        let mut q = query("cache.test.", RecordType::A, id);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(do_bit).set_max_payload(4096);
        edns.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                subnet.parse().unwrap(),
                24,
                0,
            )));
        q.set_edns(edns);
        let r = e
            .handle(q, "127.0.0.1".parse().unwrap(), "main")
            .await
            .unwrap();
        assert_eq!(r.id(), id);
        let edns = r.extensions().as_ref().unwrap();
        assert_eq!(edns.dnssec_ok(), do_bit);
        assert!(edns.options().get(EdnsCode::Subnet).is_none());
        assert_eq!(fills.lock().unwrap().len(), count);
    }
    e.shutdown().await.unwrap();
}

#[tokio::test]
async fn profile_rejects_api_dump_full_plugins_matchers_and_listener_tls() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("must-not-be-created.log");
    let yaml = format!(
        "api: {{http: '127.0.0.1:0'}}\nlog: {{file: '{}'}}\n",
        log.display()
    );
    let error = Engine::new(Config::from_yaml(&yaml).unwrap())
        .err()
        .expect("API accepted");
    assert!(format!("{error:#}").contains("API"));
    assert!(!log.exists(), "unsupported API opened the logger");
    for yaml in [
        "plugins: [{tag: c, type: cache, args: {dump_file: cache.dump}}]",
        "plugins: [{tag: c, type: cache, args: {dump_interval: 600}}]",
        "plugins: [{tag: c, type: cache, args: {dump_interval: -1}}]",
        "plugins: [{tag: s, type: tcp_server, args: {listen: '127.0.0.1:0', entry: main, cert: missing.pem}}]",
        "plugins: [{tag: s, type: tcp_server, args: {listen: '127.0.0.1:0', entry: main, key: missing.pem}}]",
        "plugins: [{tag: s, type: http_server}]",
        "plugins: [{tag: ips, type: ip_set}]",
        "plugins: [{tag: main, type: sequence, args: [{exec: 'arbitrary example.test. A 192.0.2.1'}]}]",
        "plugins: [{tag: main, type: sequence, args: [{exec: 'black_hole 192.0.2.1'}]}]",
        "plugins: [{tag: main, type: sequence, args: [{exec: ipset}]}]",
        "plugins: [{tag: main, type: sequence, args: [{matches: 'resp_ip 192.0.2.0/24', exec: accept}]}]",
        "plugins: [{tag: main, type: sequence, args: [{matches: 'qclass 1', exec: accept}]}]",
    ] {
        assert!(Engine::new(Config::from_yaml(yaml).unwrap()).is_err(), "accepted {yaml}");
    }
}

#[test]
fn yaml_json_and_include_decode_without_losing_profile_rejections() {
    let dir = tempfile::tempdir().unwrap();
    for (name, text) in [
        (
            "config.yaml",
            "plugins: [{tag: main, type: sequence, args: [{exec: 'reject 3'}]}]\n",
        ),
        (
            "config.yml",
            "plugins: [{tag: main, type: sequence, args: [{exec: 'reject 3'}]}]\n",
        ),
        (
            "config.json",
            r#"{"plugins":[{"tag":"main","type":"sequence","args":[{"exec":"reject 3"}]}]}"#,
        ),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, text).unwrap();
        let cfg = Config::load(&path).unwrap();
        assert_eq!(cfg.plugins[0].tag, "main");
        cfg.validate_profile().unwrap();
    }
    let inc = dir.path().join("included.yaml");
    std::fs::write(&inc, "api: {http: '127.0.0.1:0'}\n").unwrap();
    let path = dir.path().join("include.yaml");
    std::fs::write(&path, format!("include: ['{}']\n", inc.display())).unwrap();
    let err = Config::load(&path).unwrap_err();
    assert!(format!("{err:#}").contains("API"));
    let path = dir.path().join("cycle.yaml");
    std::fs::write(&path, format!("include: ['{}']\n", path.display())).unwrap();
    assert!(Config::load(&path).is_err());
}

#[tokio::test]
async fn unsupported_transports_and_options_fail_closed_but_numeric_dial_override_is_allowed() {
    for addr in [
        "tls://127.0.0.1",
        "tls+pipeline://127.0.0.1",
        "https://127.0.0.1/dns-query",
        "h3://127.0.0.1/dns-query",
        "quic://127.0.0.1",
        "doq://127.0.0.1",
        "ftp://127.0.0.1",
        "udp://localhost:53",
        "tcp://localhost:53",
    ] {
        assert!(
            Upstream::new(addr, Duration::from_secs(1)).is_err(),
            "accepted {addr}"
        );
    }
    for options in [
        Options {
            enable_http3: true,
            ..Default::default()
        },
        Options {
            socks5: "127.0.0.1:1080".into(),
            ..Default::default()
        },
        Options {
            bootstrap: "127.0.0.1:53".into(),
            ..Default::default()
        },
        Options {
            bootstrap_version: 6,
            ..Default::default()
        },
        Options {
            insecure_skip_verify: true,
            ..Default::default()
        },
        Options {
            dial_addr: "localhost:53".into(),
            ..Default::default()
        },
    ] {
        assert!(
            Upstream::new_with_options("127.0.0.1:53", Duration::from_secs(1), options).is_err()
        );
    }
    for address in [
        "udp://127.0.0.1:53",
        "tcp://127.0.0.1:53",
        "tcp+pipeline://127.0.0.1:53",
        "udp://[::1]:53",
    ] {
        Upstream::new(address, Duration::from_secs(1))
            .unwrap()
            .close()
            .await
            .unwrap();
    }
    let peer = Mock::new(1).await;
    let upstream = Upstream::new_with_options(
        "udp://original.invalid:53",
        Duration::from_secs(1),
        Options {
            dial_addr: peer.address.to_string(),
            ..Default::default()
        },
    )
    .unwrap();
    let r = upstream
        .exchange(&query("override.test.", RecordType::A, 51))
        .await
        .unwrap();
    assert_eq!(r.id(), 51);
    assert_eq!(peer.calls.load(Ordering::SeqCst), 1);
    upstream.close().await.unwrap();
}

#[test]
fn nftset_wire_keeps_ip_families_and_set_timeout_without_kernel_mutation() {
    let mut r = response(&query("set.test.", RecordType::A, 1), 1, 60);
    r.add_answer(Record::from_rdata(
        Name::from_ascii("set.test.").unwrap(),
        60,
        RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
    ));
    let (v4, v6) = response_elements(&r, 24, 48, TimeoutPolicy::SetDefault).unwrap();
    assert_eq!(v4.len(), 1);
    assert_eq!(v6.len(), 1);
    assert!(v4[0].timeout.is_none());
    assert!(v6[0].timeout.is_none());
    for (ipv6, elements, expected) in [(false, v4, "198.18.0.1"), (true, v6, "2001:db8::1")] {
        let metadata = nft::Metadata {
            family: nft::TableFamily::Inet,
            table: "fixture_only".into(),
            name: "fixture_only".into(),
            flags: 0,
            key_type: if ipv6 { 8 } else { 7 },
            key_length: if ipv6 { 16 } else { 4 },
            id: None,
            default_timeout: Some(Duration::from_secs(60)),
        };
        let encoded = nft::add_elements(&metadata, &elements, 10, 20)
            .unwrap()
            .encode()
            .unwrap();
        let decoded = wire::messages(&encoded).unwrap();
        let top = wire::attributes(&decoded[0].payload[4..]).unwrap();
        let list = top.iter().find(|v| v.kind == 3).unwrap();
        let list = wire::attributes(list.payload).unwrap();
        assert_eq!(list.len(), 1);
        let item = wire::attributes(list[0].payload).unwrap();
        assert!(item.iter().all(|v| v.kind != 4));
        let key = wire::attributes(item.iter().find(|v| v.kind == 1).unwrap().payload).unwrap();
        let want = match expected.parse::<std::net::IpAddr>().unwrap() {
            std::net::IpAddr::V4(ip) => ip.octets().to_vec(),
            std::net::IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        assert_eq!(key[0].payload, want);
    }
}

fn cli(args: &[&str], directory: &Path) -> std::process::Output {
    let binary = std::env::var_os("MOSDNS_RS_TEST_BIN")
        .or_else(|| std::env::var_os("MOSDNS_TEST_BINARY"))
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_mosdns-rs").into());
    let mut child = Command::new(binary)
        .args(args)
        .current_dir(directory)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() {
            return child.wait_with_output().unwrap();
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("CLI timed out for {args:?}");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn minimal_cli_help_version_check_and_formats_do_not_initialize_runtime_resources() {
    let dir = tempfile::tempdir().unwrap();
    let config = serde_json::json!({"log":{"file":"must-not-be-created.log"},"plugins":[
        {"tag":"site","type":"domain_set","args":{"files":["must-not-be-read.txt"]}},
        {"tag":"dns","type":"forward","args":{"upstreams":[{"addr":"192.0.2.1:53"}]}},
        {"tag":"cache","type":"cache","args":{"size":128,"lazy_cache_ttl":60}},
        {"tag":"main","type":"sequence","args":[{"exec":"$cache"},{"matches":"qname $site","exec":"$dns"},{"exec":"nftset inet,fixture_only,v4,ipv4_addr,24"}]},
        {"tag":"udp","type":"udp_server","args":{"listen":"127.0.0.1:1","entry":"main"}},
        {"tag":"tcp","type":"tcp_server","args":{"listen":"127.0.0.1:1","entry":"main"}}
    ]});
    for name in ["valid.yaml", "valid.yml", "valid.json"] {
        let bytes = if name.ends_with(".json") {
            serde_json::to_string(&config).unwrap()
        } else {
            serde_yaml::to_string(&config).unwrap()
        };
        std::fs::write(dir.path().join(name), bytes).unwrap();
        let out = cli(&["check", "-c", name], dir.path());
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    for (name, sequence) in [
        (
            "empty-sequence-missing.yaml",
            "  - tag: empty\n    type: sequence\n",
        ),
        (
            "empty-sequence-null.yaml",
            "  - tag: empty\n    type: sequence\n    args: null\n",
        ),
    ] {
        std::fs::write(
            dir.path().join(name),
            format!("log:\n  file: must-not-be-created.log\nplugins:\n{sequence}"),
        )
        .unwrap();
        let out = cli(&["check", "-c", name], dir.path());
        assert!(
            out.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    for args in [vec!["--help"], vec!["version"]] {
        let out = cli(&args, dir.path());
        assert!(out.status.success());
        assert!(!out.stdout.is_empty());
    }
    assert!(!dir.path().join("must-not-be-created.log").exists());
}

#[test]
fn minimal_cli_rejects_full_commands_extra_arguments_and_invalid_profile_options() {
    let dir = tempfile::tempdir().unwrap();
    // --help is read-only even if the full command dispatcher is linked by mistake.
    // Never issue install/start/stop to a service manager on the current host.
    for args in [
        vec!["service", "--help"],
        vec!["config", "--help"],
        vec!["tools", "--help"],
        vec!["probe", "--help"],
        vec!["version", "extra"],
        vec!["start", "extra"],
        vec!["start", "--unknown"],
        vec!["start", "--as-service"],
        vec!["start", "--service-name", "test"],
    ] {
        let out = cli(&args, dir.path());
        assert!(!out.status.success(), "accepted {args:?}");
    }
    for text in [
        "api: {http: '127.0.0.1:0'}",
        "plugins: [{type: cache, args: {dump_interval: -1}}]",
        "plugins: [{type: forward, args: {upstreams: [{addr: 'tls://127.0.0.1:853'}]}}]",
        "plugins: [{type: tcp_server, args: {cert: missing.pem}}]",
        "plugins: [{type: cache, args: {unknown_option: true}}]",
    ] {
        std::fs::write(dir.path().join("invalid.yaml"), text).unwrap();
        let out = cli(&["check", "-c", "invalid.yaml"], dir.path());
        assert!(!out.status.success(), "accepted {text}");
    }
}
