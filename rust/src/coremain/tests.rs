//! Cases adapted from plugin/executable/sequence/config_test.go and sequence_test.go.
use super::{Config, Engine};
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use std::net::{IpAddr, Ipv4Addr};

fn query(name: &str, typ: RecordType, id: u16) -> Message {
    let mut q = Message::new();
    q.set_id(id)
        .set_recursion_desired(true)
        .add_query(Query::query(Name::from_ascii(name).unwrap(), typ));
    q
}
fn engine(yaml: &str) -> Engine {
    Engine::new(Config::from_yaml(yaml).unwrap()).unwrap()
}
async fn answer(e: &Engine, name: &str) -> Message {
    e.handle(
        query(name, RecordType::A, 10),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "main",
    )
    .await
    .unwrap()
}
fn ip(m: &Message) -> IpAddr {
    match m.answers()[0].data().unwrap() {
        RData::A(a) => IpAddr::V4(a.0),
        RData::AAAA(a) => IpAddr::V6(a.0),
        _ => panic!("not IP"),
    }
}

#[tokio::test]
async fn jump_return_end_accept_and_goto_preserve_go_chain_semantics() {
    for (sub, action, want) in [
        (
            "- exec: return\n      - exec: reject",
            "jump sub",
            "192.0.2.1",
        ),
        ("- exec: sleep 0", "jump sub", "192.0.2.1"),
        (
            "- exec: black_hole 192.0.2.2\n      - exec: accept",
            "jump sub",
            "192.0.2.2",
        ),
        (
            "- exec: black_hole 192.0.2.2\n      - exec: return",
            "goto sub",
            "192.0.2.2",
        ),
    ] {
        let e = engine(&format!("plugins:\n  - tag: sub\n    type: sequence\n    args:\n      {sub}\n  - tag: main\n    type: sequence\n    args:\n      - exec: {action}\n      - exec: black_hole 192.0.2.1\n"));
        assert_eq!(ip(&answer(&e, "test.example.").await).to_string(), want);
    }
}

#[tokio::test]
async fn reject_stops_the_entire_jump_chain_and_and_not_matches() {
    let e = engine("plugins:\n  - tag: sub\n    type: sequence\n    args:\n      - matches: ['_true', '! _false']\n        exec: reject 3\n      - exec: black_hole 192.0.2.1\n  - tag: main\n    type: sequence\n    args:\n      - matches: ['_true', '_false']\n        exec: reject 5\n      - exec: jump sub\n      - exec: black_hole 192.0.2.2\n");
    assert_eq!(
        answer(&e, "test.example.").await.response_code(),
        ResponseCode::NXDomain
    );
}

#[tokio::test]
async fn cn_site_and_response_ip_split() {
    let e = engine("plugins:\n  - tag: cn_site\n    type: domain_set\n    args: {exps: ['domain:cn']}\n  - tag: cn_ip\n    type: ip_set\n    args: {ips: ['1.0.1.0/24']}\n  - tag: main\n    type: sequence\n    args:\n      - matches: ['qname $cn_site', 'qtype 1']\n        exec: black_hole 1.0.1.1\n      - matches: ['!has_resp']\n        exec: black_hole 192.0.2.1\n      - matches: ['resp_ip $cn_ip']\n        exec: ttl 99\n");
    let domestic = answer(&e, "www.test.cn.").await;
    assert_eq!(ip(&domestic).to_string(), "1.0.1.1");
    assert_eq!(domestic.answers()[0].ttl(), 99);
    assert_eq!(
        ip(&answer(&e, "www.test.org.").await).to_string(),
        "192.0.2.1"
    );
}

#[tokio::test]
async fn cache_writes_response_after_nested_jump_and_restores_request_id() {
    let e = engine("plugins:\n  - tag: cached\n    type: cache\n    args: {size: 16}\n  - tag: fill\n    type: sequence\n    args:\n      - exec: black_hole 192.0.2.7\n      - exec: ttl 60\n      - exec: return\n  - tag: main\n    type: sequence\n    args:\n      - exec: $cached\n      - matches: ['has_resp']\n        exec: accept\n      - exec: jump fill\n");
    let first = answer(&e, "cache.example.").await;
    assert_eq!(first.answers()[0].ttl(), 60);
    let second = e
        .handle(
            query("cache.example.", RecordType::A, 1234),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "main",
        )
        .await
        .unwrap();
    assert_eq!(second.id(), 1234);
    assert_eq!(ip(&second), ip(&first));
    assert_eq!(e.cache_stats("cached").unwrap().hits, 1);
}

#[tokio::test]
async fn negative_cache_and_mark_qtype_qclass_matchers() {
    let e = engine("plugins:\n  - tag: cached\n    type: cache\n  - tag: main\n    type: sequence\n    args:\n      - exec: $cached\n      - matches: ['has_resp']\n        exec: accept\n      - exec: mark 5 7\n      - matches: ['mark 7', 'qtype 1', 'qclass 1', 'client_ip 127.0.0.0/8']\n        exec: reject 3\n      - exec: reject 5\n");
    assert_eq!(
        answer(&e, "absent.example.").await.response_code(),
        ResponseCode::NXDomain
    );
    assert_eq!(
        answer(&e, "absent.example.").await.response_code(),
        ResponseCode::NXDomain
    );
    assert_eq!(e.cache_stats("cached").unwrap().hits, 1);
}

#[test]
fn unsupported_plugin_and_missing_references_fail_at_startup() {
    for s in [
        "plugins: [{tag: bad, type: made_up}]",
        "plugins: [{tag: main, type: sequence, args: [{exec: '$missing'}]}]",
        "plugins: [{tag: main, type: sequence, args: [{exec: 'made_up'}]}]",
    ] {
        assert!(Engine::new(Config::from_yaml(s).unwrap()).is_err(), "{s}");
    }
}

#[tokio::test]
async fn domain_root_rule_and_full_hosts_negative_family() {
    let e=engine("plugins:\n  - tag: hosts\n    type: hosts\n    args: {entries: ['example.org 192.0.2.1']}\n  - tag: root\n    type: domain_set\n    args: {exps: ['domain:.']}\n  - tag: main\n    type: sequence\n    args:\n      - exec: $hosts\n      - matches: ['has_resp']\n        exec: accept\n      - matches: ['qname $root']\n        exec: black_hole 192.0.2.9\n");
    assert_eq!(
        ip(&answer(&e, "example.org.").await).to_string(),
        "192.0.2.1"
    );
    assert_eq!(
        ip(&answer(&e, "sub.example.org.").await).to_string(),
        "192.0.2.9"
    );
    let q = query("example.org.", RecordType::AAAA, 99);
    let r = e
        .handle(q, IpAddr::V4(Ipv4Addr::LOCALHOST), "main")
        .await
        .unwrap();
    assert!(r.answers().is_empty());
    assert_eq!(r.name_servers()[0].record_type(), RecordType::SOA);
}

#[tokio::test]
async fn arbitrary_redirect_and_cname_wanted_answer() {
    let e=engine("plugins:\n  - tag: arbitrary\n    type: arbitrary\n    args: {rules: ['target.example. 60 IN A 192.0.2.4']}\n  - tag: redirect\n    type: redirect\n    args: {rules: ['alias.example target.example']}\n  - tag: resolve\n    type: sequence\n    args:\n      - exec: $redirect\n      - exec: $arbitrary\n  - tag: main\n    type: sequence\n    args:\n      - exec: $resolve\n      - matches: ['cname full:target.example', 'has_wanted_ans']\n        exec: ttl 30\n");
    let r = answer(&e, "alias.example.").await;
    assert_eq!(r.queries()[0].name().to_ascii(), "alias.example.");
    assert_eq!(r.answers()[0].record_type(), RecordType::CNAME);
    assert_eq!(r.answers()[1].ttl(), 30);
}

#[tokio::test]
async fn fallback_primary_failure_threshold_and_standby() {
    for (primary, secondary, threshold, standby, want) in [
        (
            "- exec: drop_resp",
            "- exec: black_hole 192.0.2.2",
            100,
            false,
            "192.0.2.2",
        ),
        (
            "- exec: sleep 50\n      - exec: black_hole 192.0.2.1",
            "- exec: black_hole 192.0.2.2",
            5,
            false,
            "192.0.2.2",
        ),
        (
            "- exec: sleep 5\n      - exec: black_hole 192.0.2.1",
            "- exec: black_hole 192.0.2.2",
            100,
            true,
            "192.0.2.1",
        ),
    ] {
        let e=engine(&format!("plugins:\n  - tag: primary\n    type: sequence\n    args:\n      {primary}\n  - tag: secondary\n    type: sequence\n    args:\n      {secondary}\n  - tag: fallback\n    type: fallback\n    args: {{primary: primary, secondary: secondary, threshold: {threshold}, always_standby: {standby}}}\n  - tag: main\n    type: sequence\n    args:\n      - exec: $fallback\n      - exec: ttl 17\n"));
        let r = answer(&e, "fallback.example.").await;
        assert_eq!(ip(&r).to_string(), want);
        assert_eq!(r.answers()[0].ttl(), 17);
    }
}

#[tokio::test]
async fn reverse_lookup_saves_ips_and_handles_ptr() {
    let e=engine("plugins:\n  - tag: reverse\n    type: reverse_lookup\n    args: {handle_ptr: true, ttl: 50}\n  - tag: main\n    type: sequence\n    args:\n      - exec: $reverse\n      - exec: black_hole 192.0.2.7\n");
    let r = answer(&e, "reverse.example.").await;
    assert_eq!(r.answers()[0].ttl(), 50);
    let r = e
        .handle(
            query("7.2.0.192.in-addr.arpa.", RecordType::PTR, 20),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "main",
        )
        .await
        .unwrap();
    assert_eq!(r.answers()[0].record_type(), RecordType::PTR);
    assert_eq!(
        e.reverse_lookup("reverse", "192.0.2.7".parse().unwrap())
            .unwrap(),
        "reverse.example."
    );
}

#[tokio::test]
async fn prefer_ipv4_blocks_ipv6_using_parallel_reference_and_cached_knowledge() {
    let e=engine("plugins:\n  - tag: main\n    type: sequence\n    args:\n      - exec: prefer_ipv4\n      - exec: black_hole 192.0.2.7 2001:db8::7\n");
    for id in [30, 31] {
        let r = e
            .handle(
                query("dual.example.", RecordType::AAAA, id),
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                "main",
            )
            .await
            .unwrap();
        assert!(r.answers().is_empty());
        assert_eq!(r.id(), id);
        assert_eq!(r.name_servers()[0].record_type(), RecordType::SOA);
    }
    assert_eq!(
        answer(&e, "dual.example.").await.answers()[0].record_type(),
        RecordType::A
    );
}

#[tokio::test]
async fn metrics_collect_nested_completion_and_metadata_matchers() {
    let e=engine("plugins:\n  - tag: main\n    type: sequence\n    args:\n      - exec: metrics_collector test\n      - matches: ['string_exp url_path eq /dns-query', 'string_exp server_name suffix example.org']\n        exec: black_hole 192.0.2.1\n      - exec: accept\n");
    let r = e
        .handle_with_meta(
            query("meta.example.", RecordType::A, 90),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            "main",
            Some("/dns-query"),
            Some("dns.example.org"),
        )
        .await
        .unwrap();
    assert_eq!(ip(&r).to_string(), "192.0.2.1");
    let text = e.metrics_text();
    assert!(text.contains("query_total{name=\"test\"} 1"));
    assert!(text.contains("thread{name=\"test\"} 0"));
    assert!(text.contains("_count{name=\"test\"} 1"));
}

#[tokio::test]
async fn rate_limiter_is_a_matcher_and_per_client() {
    let e=engine("plugins:\n  - tag: limit\n    type: rate_limiter\n    args: {qps: 0.00001, burst: 1}\n  - tag: main\n    type: sequence\n    args:\n      - matches: ['$limit']\n        exec: black_hole 192.0.2.1\n      - matches: ['!has_resp']\n        exec: reject 5\n");
    assert_eq!(
        answer(&e, "rate.example.").await.response_code(),
        ResponseCode::NoError
    );
    assert_eq!(
        answer(&e, "rate.example.").await.response_code(),
        ResponseCode::Refused
    );
    let r = e
        .handle(
            query("rate.example.", RecordType::A, 55),
            "192.0.2.44".parse().unwrap(),
            "main",
        )
        .await
        .unwrap();
    assert_eq!(r.response_code(), ResponseCode::NoError);
}

#[tokio::test]
async fn scalar_matches_and_set_lists_are_weakly_typed_like_go() {
    let e=engine("plugins:\n  - tag: cn\n    type: domain_set\n    args: {exps: 'domain:cn'}\n  - tag: main\n    type: sequence\n    args:\n      - matches: 'qname $cn'\n        exec: black_hole 1.0.1.1\n      - matches: '!has_resp'\n        exec: reject\n");
    assert_eq!(ip(&answer(&e, "scalar.cn.").await).to_string(), "1.0.1.1");
    assert_eq!(
        answer(&e, "scalar.example.").await.response_code(),
        ResponseCode::Refused
    );
}

#[tokio::test]
async fn quoted_numeric_and_boolean_args_keep_go_weak_types() {
    let e=engine("log: {production: 'false'}\nplugins:\n  - tag: c\n    type: cache\n    args: {size: '32', lazy_cache_ttl: '100'}\n  - tag: primary\n    type: sequence\n    args: [{exec: 'black_hole 192.0.2.1'}]\n  - tag: secondary\n    type: sequence\n    args: [{exec: 'black_hole 192.0.2.2'}]\n  - tag: f\n    type: fallback\n    args: {primary: primary, secondary: secondary, threshold: '500', always_standby: 'true'}\n  - tag: main\n    type: sequence\n    args: [{exec: '$c'}, {exec: '$f'}]\n");
    assert_eq!(
        ip(&answer(&e, "weak.example.").await).to_string(),
        "192.0.2.1"
    );
}

#[tokio::test]
async fn absent_response_is_refused_and_tagged_sequence_accept_only_finishes_its_call() {
    let empty = engine("plugins: [{tag: main, type: sequence, args: [{exec: accept}]}]");
    assert_eq!(
        answer(&empty, "empty.example.").await.response_code(),
        ResponseCode::Refused
    );
    let e=engine("plugins:\n  - tag: sub\n    type: sequence\n    args: [{exec: 'black_hole 192.0.2.1'}, {exec: accept}]\n  - tag: main\n    type: sequence\n    args: [{exec: '$sub'}, {exec: 'black_hole 192.0.2.2'}]\n");
    assert_eq!(
        ip(&answer(&e, "tagged.example.").await).to_string(),
        "192.0.2.2"
    );
}

#[tokio::test]
async fn env_key_value_is_evaluated_at_startup_and_not_treated_as_a_variable_name() {
    const KEY: &str = "MOSDNS_RUST_TEST_EXPECTED_TOKEN_6458445";
    std::env::set_var(KEY, "expected");
    let e=engine(&format!("plugins:\n  - tag: main\n    type: sequence\n    args:\n      - matches: ['env {KEY} expected']\n        exec: black_hole 192.0.2.1\n      - matches: ['!has_resp']\n        exec: reject\n"));
    std::env::remove_var(KEY);
    assert_eq!(
        ip(&answer(&e, "env.example.").await).to_string(),
        "192.0.2.1"
    );
}

#[tokio::test]
async fn concurrent_forward_accepts_a_first_empty_noerror_answer() {
    use crate::plugin::query_context::reply;
    use hickory_proto::rr::{rdata::A, Record};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    let fast = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let slow = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let fast_addr = fast.local_addr().unwrap();
    let slow_addr = slow.local_addr().unwrap();
    let fast_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (n, peer) = fast.recv_from(&mut buf).await.unwrap();
        let q = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(q.extensions().as_ref().unwrap().max_payload(), 1200);
        let r = reply(&q, ResponseCode::NoError);
        fast.send_to(&r.to_vec().unwrap(), peer).await.unwrap();
    });
    let slow_task = tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let (n, peer) = slow.recv_from(&mut buf).await.unwrap();
        let q = Message::from_vec(&buf[..n]).unwrap();
        tokio::time::sleep(Duration::from_millis(25)).await;
        let mut r = reply(&q, ResponseCode::NoError);
        r.add_answer(Record::from_rdata(
            q.queries()[0].name().clone(),
            60,
            RData::A(A("192.0.2.2".parse().unwrap())),
        ));
        let _ = slow.send_to(&r.to_vec().unwrap(), peer).await;
    });
    let e=engine(&format!("plugins:\n  - tag: f\n    type: forward\n    args:\n      concurrent: 2\n      upstreams: [{{tag: empty, addr: 'udp://{fast_addr}'}}, {{tag: full, addr: 'udp://{slow_addr}'}}]\n  - tag: main\n    type: sequence\n    args: [{{exec: '$f'}}]\n"));
    let r = answer(&e, "first-empty.example.").await;
    assert_eq!(r.response_code(), ResponseCode::NoError);
    assert!(r.answers().is_empty());
    fast_task.await.unwrap();
    slow_task.await.unwrap();
}

#[test]
fn includes_are_loaded_first_and_cycles_duplicates_bad_types_fail() {
    let dir = tempfile::tempdir().unwrap();
    let inc = dir.path().join("included.yaml");
    let main = dir.path().join("main.yaml");
    std::fs::write(
        &inc,
        "plugins: [{tag: included, type: domain_set, args: {exps: domain:cn}}]",
    )
    .unwrap();
    std::fs::write(&main,format!("include: '{}'\nplugins: [{{tag: main, type: sequence, args: [{{matches: 'qname $included', exec: 'reject 3'}}]}}]",inc.display())).unwrap();
    let config = Config::load(&main).unwrap();
    assert_eq!(config.plugins[0].tag, "included");
    assert!(Engine::new(config).is_ok());
    for yaml in [
        "plugins: [{tag: x, type: cache}, {tag: x, type: cache}]",
        "plugins: [{tag: x, type: domain_set, args: {sets: x}}]",
        "plugins: [{tag: x, type: cache, args: {siz: 10}}]",
    ] {
        assert!(Engine::new(Config::from_yaml(yaml).unwrap()).is_err());
    }
}

#[tokio::test]
async fn configured_cache_dump_survives_restart_with_request_id_restored() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.dump");
    let config = |answer: &str| {
        format!("plugins:\n  - tag: cache\n    type: cache\n    args: {{size: 32, dump_file: '{}'}}\n  - tag: main\n    type: sequence\n    args:\n      - exec: $cache\n      - matches: ['has_resp']\n        exec: accept\n      - exec: black_hole {answer}\n",path.display())
    };
    let e = engine(&config("192.0.2.1"));
    assert_eq!(
        ip(&answer(&e, "dump.example.").await).to_string(),
        "192.0.2.1"
    );
    e.save_cache_dumps().unwrap();
    drop(e);
    let e = engine(&config("192.0.2.2"));
    let response = e
        .handle(
            query("dump.example.", RecordType::A, 600),
            "127.0.0.1".parse().unwrap(),
            "main",
        )
        .await
        .unwrap();
    assert_eq!(ip(&response).to_string(), "192.0.2.1");
    assert_eq!(response.id(), 600);
    assert_eq!(e.cache_stats("cache").unwrap().hits, 1);
}

#[tokio::test]
async fn hosts_prioritizes_full_and_longest_suffix_before_regex_keyword() {
    let e=engine("plugins:\n  - tag: hosts\n    type: hosts\n    args:\n      entries: ['full:www.sub.example 192.0.2.1', 'domain:sub.example 192.0.2.2', 'domain:example 192.0.2.3', 'regexp:.*example 192.0.2.4', 'keyword:example 192.0.2.5']\n  - tag: main\n    type: sequence\n    args: [{exec: '$hosts'}]\n");
    for (name, want) in [
        ("www.sub.example.", "192.0.2.1"),
        ("foo.sub.example.", "192.0.2.2"),
        ("foo.example.", "192.0.2.3"),
    ] {
        assert_eq!(ip(&answer(&e, name).await).to_string(), want);
    }
}

#[tokio::test]
async fn invalid_unix_client_neither_matches_ip_ranges_nor_consumes_limiter_tokens() {
    let engine = engine("plugins:\n  - {tag: limited, type: rate_limiter, args: {qps: 0.001, burst: 1}}\n  - tag: main\n    type: sequence\n    args:\n      - {matches: 'client_ip 0.0.0.0/0', exec: 'reject 3'}\n      - {matches: '!$limited', exec: 'reject 2'}\n      - {exec: 'reject 0'}\n");
    for id in [81, 82, 83] {
        let response = engine
            .handle_with_client_meta(
                query("unix.example.", RecordType::A, id),
                None,
                "main",
                None,
                None,
            )
            .await
            .unwrap();
        assert_eq!(response.id(), id);
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }
}

#[test]
fn unix_listeners_are_only_accepted_for_stream_protocols() {
    for kind in ["tcp_server", "http_server"] {
        let args = if kind == "tcp_server" {
            "{listen: '@mosdns-regression', entry: main}"
        } else {
            "{listen: 'unix:///tmp/mosdns-regression', entries: [{path: /dns-query, exec: main}]}"
        };
        let config = Config::from_yaml(&format!("plugins:\n  - {{tag: main, type: sequence, args: [{{exec: accept}}]}}\n  - {{type: {kind}, args: {args}}}\n")).unwrap();
        assert!(Engine::new(config).is_ok());
    }
    let config = Config::from_yaml("plugins:\n  - {tag: main, type: sequence, args: [{exec: accept}]}\n  - {type: udp_server, args: {listen: '@invalid-datagram', entry: main}}\n").unwrap();
    assert!(Engine::new(config).is_err());
}
