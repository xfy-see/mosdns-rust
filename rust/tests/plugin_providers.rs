//! Go data_provider interfaces, mixed set composition, and live matcher handles.
#![cfg(feature = "full")]
use anyhow::Result;
use futures::{
    future::{BoxFuture, Either},
    FutureExt,
};
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{
        rdata::{A, AAAA, CNAME},
        Name, RData, Record, RecordType,
    },
};
use mosdns_rs::{
    coremain::{Config, Engine, ExecutablePlugin, Plugin, PluginCloser, PluginObject, Registry},
    pkg::matcher::{domain::DomainMatcher, netlist::NetList},
    plugin::{
        executable::Executable,
        matcher::{
            providers::{DomainMatch, DomainMatcherProvider, IPMatcherProvider, IpMatch},
            Matcher,
        },
        query_context::{reply, QueryContext},
    },
};
use std::{
    net::IpAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
};

fn query(name: &str, typ: RecordType) -> Message {
    let mut query = Message::new();
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), typ));
    query
}
fn domains(rules: &[&str]) -> DomainMatcher {
    let mut matcher = DomainMatcher::new();
    for rule in rules {
        matcher.add(rule).unwrap();
    }
    matcher
}
fn ips(rules: &[&str]) -> NetList {
    let mut matcher = NetList::new();
    for rule in rules {
        matcher.add(rule).unwrap();
    }
    matcher
}
struct Dynamic {
    domains: RwLock<DomainMatcher>,
    ips: RwLock<NetList>,
    domain_gets: AtomicUsize,
    domain_calls: AtomicUsize,
    ip_gets: AtomicUsize,
    ip_calls: AtomicUsize,
    closes: AtomicUsize,
}
impl Dynamic {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            domains: RwLock::new(domains(&["full:live.example", "full:target.example"])),
            ips: RwLock::new(ips(&["192.0.2.17", "2001:db8::17"])),
            domain_gets: AtomicUsize::new(0),
            domain_calls: AtomicUsize::new(0),
            ip_gets: AtomicUsize::new(0),
            ip_calls: AtomicUsize::new(0),
            closes: AtomicUsize::new(0),
        })
    }
}
impl DomainMatch for Dynamic {
    fn matches(&self, name: &str) -> bool {
        self.domain_calls.fetch_add(1, Ordering::SeqCst);
        self.domains.read().unwrap().matches(name)
    }
}
impl IpMatch for Dynamic {
    fn matches(&self, ip: IpAddr) -> bool {
        self.ip_calls.fetch_add(1, Ordering::SeqCst);
        self.ips.read().unwrap().contains(ip)
    }
}
impl DomainMatcherProvider for Dynamic {
    fn get_domain_matcher(self: Arc<Self>) -> Arc<dyn DomainMatch> {
        self.domain_gets.fetch_add(1, Ordering::SeqCst);
        self
    }
}
impl IPMatcherProvider for Dynamic {
    fn get_ip_matcher(self: Arc<Self>) -> Arc<dyn IpMatch> {
        self.ip_gets.fetch_add(1, Ordering::SeqCst);
        self
    }
}
impl PluginCloser for Dynamic {
    fn close(&self) -> Result<()> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
impl ExecutablePlugin for Dynamic {
    fn exec<'a>(&'a self, ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut response = reply(&ctx.query, ResponseCode::NoError);
            let name = ctx.query.queries()[0].name().clone();
            response.add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::CNAME(CNAME(Name::from_ascii("target.example.").unwrap())),
            ));
            response.add_answer(Record::from_rdata(
                name.clone(),
                60,
                RData::A(A("192.0.2.17".parse().unwrap())),
            ));
            response.add_answer(Record::from_rdata(
                name,
                60,
                RData::AAAA(AAAA("2001:db8::17".parse().unwrap())),
            ));
            ctx.set_response(Some(response));
            Ok(())
        })
    }
}
fn registry(object: Arc<Dynamic>) -> Registry {
    let mut registry = Registry::new();
    registry
        .register_plugin_type("dynamic", move |_, _| {
            Ok(Plugin::Custom(Arc::new(PluginObject {
                executable: Some(Executable::Custom(object.clone())),
                data: Some(object.clone()),
                closer: Some(object.clone()),
                domain_provider: Some(object.clone()),
                ip_provider: Some(object.clone()),
                ..Default::default()
            })))
        })
        .unwrap();
    registry
}
fn engine(object: Arc<Dynamic>, text: &str) -> Engine {
    Engine::new_with_registry(Config::from_yaml(text).unwrap(), registry(object)).unwrap()
}
async fn code(
    engine: &Engine,
    name: &str,
    typ: RecordType,
    client: &str,
    entry: &str,
) -> ResponseCode {
    engine
        .handle(query(name, typ), client.parse().unwrap(), entry)
        .await
        .unwrap()
        .response_code()
}

#[tokio::test]
async fn live_provider_changes_reach_direct_and_nested_qname_cname_and_ip_matchers() {
    let object = Dynamic::new();
    let engine = engine(object.clone(), "plugins:\n - {tag: dynamic, type: dynamic}\n - {tag: d1, type: domain_set, args: {exps: ['full:static.example'], sets: [dynamic]}}\n - {tag: d2, type: domain_set, args: {sets: [d1]}}\n - {tag: i1, type: ip_set, args: {ips: ['198.51.100.0/24'], sets: [dynamic]}}\n - {tag: i2, type: ip_set, args: {sets: [i1]}}\n - {tag: named_q, type: qname, args: {domain_sets: [d2]}}\n - {tag: named_client, type: client_ip, args: {ip_sets: [i2]}}\n - tag: main\n   type: sequence\n   args:\n    - exec: $dynamic\n    - matches: ['$named_q', 'cname $d2', '$named_client', 'resp_ip $i2']\n      exec: reject 3\n    - exec: reject 5\n - {tag: direct, type: sequence, args: [{matches: 'qname $dynamic', exec: reject 3}, {exec: reject 5}]}\n");
    let gets = (
        object.domain_gets.load(Ordering::SeqCst),
        object.ip_gets.load(Ordering::SeqCst),
    );
    assert_eq!(
        code(
            &engine,
            "live.example.",
            RecordType::A,
            "192.0.2.17",
            "main"
        )
        .await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        code(
            &engine,
            "static.example.",
            RecordType::A,
            "198.51.100.2",
            "main"
        )
        .await,
        ResponseCode::NXDomain
    );
    *object.domains.write().unwrap() = domains(&["full:next.example", "full:target.example"]);
    assert_eq!(
        code(
            &engine,
            "live.example.",
            RecordType::A,
            "192.0.2.17",
            "main"
        )
        .await,
        ResponseCode::Refused
    );
    assert_eq!(
        code(
            &engine,
            "next.example.",
            RecordType::A,
            "192.0.2.17",
            "main"
        )
        .await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        code(
            &engine,
            "next.example.",
            RecordType::A,
            "127.0.0.1",
            "direct"
        )
        .await,
        ResponseCode::NXDomain
    );
    *object.ips.write().unwrap() = ips(&["203.0.113.9"]);
    assert_eq!(
        code(
            &engine,
            "next.example.",
            RecordType::A,
            "192.0.2.17",
            "main"
        )
        .await,
        ResponseCode::Refused
    );
    assert_eq!(
        (
            object.domain_gets.load(Ordering::SeqCst),
            object.ip_gets.load(Ordering::SeqCst)
        ),
        gets,
        "provider getters must not run for every query"
    );
    let same = engine
        .get_plugin("dynamic")
        .unwrap()
        .data()
        .unwrap()
        .downcast::<Dynamic>()
        .unwrap();
    assert!(Arc::ptr_eq(&same, &object));
    engine.shutdown().await.unwrap();
    assert_eq!(object.closes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dynamic_ip_provider_supports_ipv4_ipv6_ptr_and_invalid_client_does_not_call_it() {
    let object = Dynamic::new();
    let engine = engine(object.clone(), "plugins:\n - {tag: dynamic, type: dynamic}\n - {tag: ptr, type: sequence, args: [{matches: 'ptr_ip $dynamic', exec: reject 3}, {exec: reject 5}]}\n - {tag: client, type: sequence, args: [{matches: 'client_ip $dynamic', exec: reject 3}, {exec: reject 5}]}\n - {tag: response, type: sequence, args: [{exec: '$dynamic'}, {matches: 'resp_ip $dynamic', exec: reject 3}, {exec: reject 5}]}\n");
    for name in [
        "17.2.0.192.in-addr.arpa.",
        "7.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
    ] {
        assert_eq!(
            code(&engine, name, RecordType::PTR, "127.0.0.1", "ptr").await,
            ResponseCode::NXDomain
        );
    }
    assert_eq!(
        code(
            &engine,
            "17.2.0.192.in-addr.arpa.",
            RecordType::A,
            "127.0.0.1",
            "ptr"
        )
        .await,
        ResponseCode::Refused
    );
    assert_eq!(
        code(
            &engine,
            "live.example.",
            RecordType::AAAA,
            "2001:db8::17",
            "client"
        )
        .await,
        ResponseCode::NXDomain
    );
    let before = object.ip_calls.load(Ordering::SeqCst);
    let response = engine
        .handle_with_client_meta(
            query("live.example.", RecordType::A),
            None,
            "client",
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(response.response_code(), ResponseCode::Refused);
    assert_eq!(object.ip_calls.load(Ordering::SeqCst), before);
    // Match only the AAAA response after dropping the A address from provider rules.
    *object.ips.write().unwrap() = ips(&["2001:db8::17"]);
    assert_eq!(
        code(
            &engine,
            "live.example.",
            RecordType::AAAA,
            "127.0.0.1",
            "response"
        )
        .await,
        ResponseCode::NXDomain
    );
    engine.shutdown().await.unwrap();
}

struct Snapshot {
    current: RwLock<Arc<DomainMatcher>>,
    gets: AtomicUsize,
}
impl DomainMatcherProvider for Snapshot {
    fn get_domain_matcher(self: Arc<Self>) -> Arc<dyn DomainMatch> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.current.read().unwrap().clone()
    }
}
#[tokio::test]
async fn getter_result_is_captured_at_initialization_instead_of_re_reading_provider() {
    let object = Arc::new(Snapshot {
        current: RwLock::new(Arc::new(domains(&["full:before.example"]))),
        gets: AtomicUsize::new(0),
    });
    let provider = object.clone();
    let mut registry = Registry::new();
    registry
        .register_preset("snapshot", move |_| {
            Ok(Plugin::Custom(Arc::new(PluginObject {
                domain_provider: Some(provider.clone()),
                ..Default::default()
            })))
        })
        .unwrap();
    let engine = Engine::new_with_registry(Config::from_yaml("plugins: [{tag: main, type: sequence, args: [{matches: 'qname $snapshot', exec: reject 3}, {exec: reject 5}]}]").unwrap(), registry).unwrap();
    *object.current.write().unwrap() = Arc::new(domains(&["full:after.example"]));
    assert_eq!(
        code(
            &engine,
            "before.example.",
            RecordType::A,
            "127.0.0.1",
            "main"
        )
        .await,
        ResponseCode::NXDomain
    );
    assert_eq!(
        code(
            &engine,
            "after.example.",
            RecordType::A,
            "127.0.0.1",
            "main"
        )
        .await,
        ResponseCode::Refused
    );
    assert_eq!(object.gets.load(Ordering::SeqCst), 1);
    engine.shutdown().await.unwrap();
}

#[test]
fn wrong_capability_and_missing_provider_fail_initialization() {
    for definition in [
        "{tag: set, type: ip_set, args: {sets: [domain]}}",
        "{tag: main, type: sequence, args: [{matches: 'client_ip $domain', exec: reject}]}",
    ] {
        let mut registry = Registry::new();
        registry
            .register_preset("domain", |_| {
                Ok(Plugin::Custom(Arc::new(PluginObject {
                    domain_provider: Some(Dynamic::new()),
                    ..Default::default()
                })))
            })
            .unwrap();
        let error = Engine::new_with_registry(
            Config::from_yaml(&format!("plugins: [{definition}]")).unwrap(),
            registry,
        )
        .err()
        .unwrap();
        assert!(format!("{error:#}").contains("IP provider"));
    }
    for rule in ["qname $missing", "client_ip $missing"] {
        let error = Engine::new(Config::from_yaml(&format!("plugins: [{{tag: main, type: sequence, args: [{{matches: '{rule}', exec: reject}}]}}]")).unwrap()).err().unwrap();
        assert!(format!("{error:#}").contains("cannot find plugin missing"));
    }
}

#[tokio::test]
async fn static_and_provider_based_builtins_keep_the_synchronous_ready_path() {
    let object = Dynamic::new();
    let engine = engine(object, "plugins:\n - {tag: dynamic, type: dynamic}\n - {tag: static, type: qname, args: {exps: ['full:live.example']}}\n - {tag: live, type: qname, args: {domain_sets: [dynamic]}}\n - {tag: ip, type: client_ip, args: {ip_sets: [dynamic]}}\n");
    for tag in ["static", "live", "ip"] {
        let matcher = engine.get_plugin(tag).unwrap().matcher().unwrap();
        let mut context = QueryContext::new(
            query("live.example.", RecordType::A),
            "192.0.2.17".parse().unwrap(),
        );
        let result = matcher.matches(&mut context);
        assert!(
            matches!(result, Either::Left(_)),
            "{tag} allocated a custom async future"
        );
        assert!(result.now_or_never().unwrap().unwrap());
    }
    let Some(Plugin::Match(Matcher::Qname(_))) = engine.get_plugin("static") else {
        panic!("static matcher left the original enum variant");
    };
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn set_inline_rules_precede_provider_but_matcher_refs_precede_inline_rules() {
    let object = Dynamic::new();
    let engine = engine(object.clone(), "plugins:\n - {tag: dynamic, type: dynamic}\n - {tag: d, type: domain_set, args: {exps: ['full:static.example'], sets: [dynamic]}}\n - {tag: i, type: ip_set, args: {ips: ['198.51.100.0/24'], sets: [dynamic]}}\n - {tag: set, type: sequence, args: [{matches: ['qname $d', 'client_ip $i'], exec: reject 3}, {exec: reject 5}]}\n - {tag: inline, type: sequence, args: [{matches: ['qname $dynamic full:static.example', 'client_ip $dynamic 198.51.100.0/24'], exec: reject 3}, {exec: reject 5}]}\n");
    assert_eq!(
        code(
            &engine,
            "static.example.",
            RecordType::A,
            "198.51.100.1",
            "set"
        )
        .await,
        ResponseCode::NXDomain
    );
    assert_eq!(object.domain_calls.load(Ordering::SeqCst), 0);
    assert_eq!(object.ip_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        code(
            &engine,
            "static.example.",
            RecordType::A,
            "198.51.100.1",
            "inline"
        )
        .await,
        ResponseCode::NXDomain
    );
    assert_eq!(object.domain_calls.load(Ordering::SeqCst), 1);
    assert_eq!(object.ip_calls.load(Ordering::SeqCst), 1);
    engine.shutdown().await.unwrap();
}

struct PanickingGetter {
    closes: AtomicUsize,
}
impl DomainMatcherProvider for PanickingGetter {
    fn get_domain_matcher(self: Arc<Self>) -> Arc<dyn DomainMatch> {
        panic!("domain getter panic");
    }
}
impl IPMatcherProvider for PanickingGetter {
    fn get_ip_matcher(self: Arc<Self>) -> Arc<dyn IpMatch> {
        panic!("IP getter panic");
    }
}
impl PluginCloser for PanickingGetter {
    fn close(&self) -> Result<()> {
        self.closes.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
#[test]
fn getter_panic_becomes_initialization_error_and_releases_its_managed_provider() {
    for rule in ["qname $provider", "resp_ip $provider"] {
        let object = Arc::new(PanickingGetter {
            closes: AtomicUsize::new(0),
        });
        let provider = object.clone();
        let mut registry = Registry::new();
        registry
            .register_preset("provider", move |_| {
                Ok(Plugin::Custom(Arc::new(PluginObject {
                    domain_provider: Some(provider.clone()),
                    ip_provider: Some(provider.clone()),
                    closer: Some(provider.clone()),
                    ..Default::default()
                })))
            })
            .unwrap();
        let config = Config::from_yaml(&format!(
            "plugins: [{{tag: main, type: sequence, args: [{{matches: '{rule}', exec: reject}}]}}]"
        ))
        .unwrap();
        let error = Engine::new_with_registry(config, registry).err().unwrap();
        assert!(format!("{error:#}").contains("getter panic"));
        assert_eq!(object.closes.load(Ordering::SeqCst), 1);
    }
}
