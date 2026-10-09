// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

//! Independent behavioral checks from review of the Go sequence/cache model.

#![cfg(feature = "full")]
use hickory_proto::{
    op::{Edns, Message, Query, ResponseCode},
    rr::{
        rdata::opt::{ClientSubnet, EdnsCode, EdnsOption},
        Name, RData, RecordType,
    },
};
use mosdns_rs::coremain::{Config, Engine};
use std::time::Duration;

fn engine(yaml: &str) -> Engine {
    Engine::new(Config::from_yaml(yaml).unwrap()).unwrap()
}

fn query(id: u16) -> Message {
    let mut query = Message::new();
    query.set_id(id).add_query(Query::query(
        Name::from_ascii("review.test.").unwrap(),
        RecordType::A,
    ));
    query
}

async fn answer(engine: &Engine, id: u16) -> Message {
    engine
        .handle(query(id), "127.0.0.1".parse().unwrap(), "main")
        .await
        .unwrap()
}

fn ip(response: &Message) -> String {
    match response.answers()[0].data().unwrap() {
        RData::A(ip) => ip.0.to_string(),
        data => panic!("unexpected answer {data:?}"),
    }
}

#[tokio::test]
async fn hosts_keep_go_full_priority_and_longest_subdomain_priority() {
    let e = engine("plugins:\n  - tag: hosts\n    type: hosts\n    args:\n      entries: ['full:www.example.com 192.0.2.1', 'domain:example.com 192.0.2.2', 'domain:a.other.test 192.0.2.3', 'domain:other.test 192.0.2.4']\n  - tag: main\n    type: sequence\n    args:\n      - exec: $hosts\n");
    for (name, expected) in [
        ("www.example.com.", "192.0.2.1"),
        ("b.a.other.test.", "192.0.2.3"),
    ] {
        let mut q = query(1);
        q.queries_mut()[0].set_name(Name::from_ascii(name).unwrap());
        let response = e
            .handle(q, "127.0.0.1".parse().unwrap(), "main")
            .await
            .unwrap();
        assert_eq!(ip(&response), expected, "{name}");
    }
}

#[tokio::test]
async fn redirect_keeps_go_full_priority_over_later_domain_rule() {
    let e = engine("plugins:\n  - tag: redirect\n    type: redirect\n    args:\n      rules: ['full:www.example.com full.test.', 'domain:example.com broad.test.']\n  - tag: main\n    type: sequence\n    args:\n      - exec: $redirect\n      - exec: black_hole 192.0.2.1\n");
    let mut q = query(1);
    q.queries_mut()[0].set_name(Name::from_ascii("www.example.com.").unwrap());
    let response = e
        .handle(q, "127.0.0.1".parse().unwrap(), "main")
        .await
        .unwrap();
    match response.answers()[0].data().unwrap() {
        RData::CNAME(target) => assert_eq!(target.0.to_ascii(), "full.test."),
        data => panic!("unexpected redirect record {data:?}"),
    }
}

#[tokio::test]
async fn equivalent_subdomain_rules_keep_the_last_value_after_normalization() {
    let e = engine("plugins:\n  - tag: hosts\n    type: hosts\n    args:\n      entries: ['domain:İ.example 192.0.2.1', 'domain:i.example 192.0.2.2', 'domain:.other.test 192.0.2.3', 'domain:other.test 192.0.2.4']\n  - tag: main\n    type: sequence\n    args:\n      - exec: $hosts\n");
    for (name, expected) in [
        ("www.i.example.", "192.0.2.2"),
        ("www.other.test.", "192.0.2.4"),
    ] {
        let mut q = query(1);
        q.queries_mut()[0].set_name(Name::from_ascii(name).unwrap());
        let response = e
            .handle(q, "127.0.0.1".parse().unwrap(), "main")
            .await
            .unwrap();
        assert_eq!(ip(&response), expected, "{name}");
    }
}

#[tokio::test]
async fn hosts_empty_type_prefix_keeps_the_go_full_default_matcher() {
    let e = engine("plugins:\n  - tag: hosts\n    type: hosts\n    args:\n      entries: [':example.com 192.0.2.1']\n  - tag: main\n    type: sequence\n    args:\n      - exec: $hosts\n");
    for (name, code) in [
        ("example.com.", ResponseCode::NoError),
        ("www.example.com.", ResponseCode::Refused),
    ] {
        let mut q = query(1);
        q.queries_mut()[0].set_name(Name::from_ascii(name).unwrap());
        let response = e
            .handle(q, "127.0.0.1".parse().unwrap(), "main")
            .await
            .unwrap();
        assert_eq!(response.response_code(), code, "{name}");
    }
}

#[tokio::test]
async fn redirect_normalizes_domain_priority_and_empty_type_defaults_to_full() {
    let e = engine("plugins:\n  - tag: redirect\n    type: redirect\n    args:\n      rules: ['domain:İ.example old.test.', 'domain:i.example latest.test.', 'domain:.other.test old.test.', 'domain:other.test latest.test.', ':exact.test full.test.']\n  - tag: main\n    type: sequence\n    args:\n      - exec: $redirect\n      - exec: black_hole 192.0.2.1\n");
    for (name, expected) in [
        ("www.i.example.", Some("latest.test.")),
        ("www.other.test.", Some("latest.test.")),
        ("exact.test.", Some("full.test.")),
        ("www.exact.test.", None),
    ] {
        let mut q = query(1);
        q.queries_mut()[0].set_name(Name::from_ascii(name).unwrap());
        let response = e
            .handle(q, "127.0.0.1".parse().unwrap(), "main")
            .await
            .unwrap();
        let target = response
            .answers()
            .iter()
            .find_map(|record| match record.data() {
                Some(RData::CNAME(target)) => Some(target.0.to_ascii()),
                _ => None,
            });
        assert_eq!(target.as_deref(), expected, "{name}");
    }
}

#[tokio::test]
async fn empty_black_hole_preserves_an_existing_response_and_is_a_noop() {
    let e = engine("plugins:\n  - tag: main\n    type: sequence\n    args:\n      - exec: black_hole 192.0.2.1\n      - exec: black_hole\n      - exec: accept\n");
    assert_eq!(ip(&answer(&e, 1).await), "192.0.2.1");
    let empty = engine("plugins:\n  - tag: main\n    type: sequence\n    args:\n      - exec: black_hole\n      - exec: black_hole 192.0.2.2\n");
    assert_eq!(ip(&answer(&empty, 2).await), "192.0.2.2");
}

#[tokio::test]
async fn goto_discards_all_jump_back_frames_but_tagged_sequences_return_locally() {
    let e = engine("plugins:\n  - tag: target\n    type: sequence\n    args:\n      - exec: black_hole 192.0.2.3\n      - exec: return\n  - tag: middle\n    type: sequence\n    args:\n      - exec: goto target\n      - exec: black_hole 192.0.2.2\n  - tag: main\n    type: sequence\n    args:\n      - exec: jump middle\n      - exec: black_hole 192.0.2.1\n");
    assert_eq!(ip(&answer(&e, 1).await), "192.0.2.3");
    let local = engine("plugins:\n  - tag: sub\n    type: sequence\n    args:\n      - exec: black_hole 192.0.2.2\n      - exec: accept\n      - exec: reject 3\n  - tag: main\n    type: sequence\n    args:\n      - exec: $sub\n      - exec: black_hole 192.0.2.1\n");
    assert_eq!(ip(&answer(&local, 2).await), "192.0.2.1");
}

#[tokio::test]
async fn hot_cache_does_not_restart_ttl_and_preserves_a_goto_result() {
    let e = engine("plugins:\n  - tag: cached\n    type: cache\n    args: {size: 16}\n  - tag: target\n    type: sequence\n    args:\n      - exec: black_hole 192.0.2.3\n      - exec: ttl 20\n      - exec: return\n  - tag: main\n    type: sequence\n    args:\n      - exec: $cached\n      - matches: has_resp\n        exec: accept\n      - exec: goto target\n      - exec: reject 3\n");
    assert_eq!(answer(&e, 1).await.answers()[0].ttl(), 20);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    for id in 2..5 {
        let response = answer(&e, id).await;
        assert_eq!(response.id(), id);
        assert_eq!(ip(&response), "192.0.2.3");
        assert_eq!(response.answers()[0].ttl(), 19);
    }
    assert_eq!(e.cache_stats("cached").unwrap().hits, 3);
}

#[tokio::test]
async fn lazy_refresh_runs_once_without_seeing_the_installed_cached_response() {
    let e = engine("plugins:\n  - tag: cached\n    type: cache\n    args: {size: 16, lazy_cache_ttl: 60}\n  - tag: main\n    type: sequence\n    args:\n      - exec: $cached\n      - matches: has_resp\n        exec: accept\n      - exec: metrics_collector review_fills\n      - exec: sleep 80\n      - exec: black_hole 192.0.2.4\n      - exec: ttl 1\n");
    assert_eq!(answer(&e, 1).await.answers()[0].ttl(), 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let responses = futures::future::join_all((2..22).map(|id| answer(&e, id))).await;
    assert!(responses
        .iter()
        .all(|response| response.answers()[0].ttl() == 5));
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if answer(&e, 22).await.answers()[0].ttl() == 1 {
                break;
            }
        }
    })
    .await
    .unwrap();
    assert!(e
        .metrics_text()
        .contains("mosdns_metrics_collector_query_total{name=\"review_fills\"} 2\n"));
}

#[tokio::test]
async fn lazy_refresh_tail_timeout_releases_singleflight_and_keeps_the_old_response() {
    let e = engine("plugins:\n  - {tag: cached, type: cache, args: {size: 16, lazy_cache_ttl: 60}}\n  - tag: warm\n    type: sequence\n    args: [{exec: '$cached'}, {exec: 'black_hole 192.0.2.4'}, {exec: 'ttl 1'}]\n  - tag: main\n    type: sequence\n    args:\n      - {exec: '$cached'}\n      - {matches: has_resp, exec: accept}\n      - {exec: 'metrics_collector timed_refresh'}\n      - {exec: 'sleep 6000'}\n      - {exec: 'black_hole 192.0.2.5'}\n");
    e.handle(query(1), "127.0.0.1".parse().unwrap(), "warm")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let response = answer(&e, 2).await;
    assert_eq!(ip(&response), "192.0.2.4");
    assert_eq!(response.answers()[0].ttl(), 5);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !e
            .metrics_text()
            .contains("mosdns_metrics_collector_thread{name=\"timed_refresh\"} 1\n")
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    // The background tail has a five-second deadline, shorter than its sleep.
    // After timeout it must release its refresh key so another request can retry.
    tokio::time::timeout(Duration::from_secs(6), async {
        while !e
            .metrics_text()
            .contains("mosdns_metrics_collector_thread{name=\"timed_refresh\"} 0\n")
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let response = answer(&e, 3).await;
    assert_eq!(ip(&response), "192.0.2.4");
    assert_eq!(response.answers()[0].ttl(), 5);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !e
            .metrics_text()
            .contains("mosdns_metrics_collector_query_total{name=\"timed_refresh\"} 2\n")
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fallback_loser_keeps_running_to_fill_its_own_cache_like_go() {
    let e = engine("plugins:\n  - tag: cached_secondary\n    type: cache\n    args: {size: 16}\n  - tag: primary\n    type: sequence\n    args:\n      - exec: sleep 5\n      - exec: black_hole 192.0.2.1\n  - tag: secondary\n    type: sequence\n    args:\n      - exec: $cached_secondary\n      - exec: sleep 80\n      - exec: black_hole 192.0.2.2\n  - tag: fallback\n    type: fallback\n    args: {primary: primary, secondary: secondary, threshold: 100, always_standby: true}\n  - tag: main\n    type: sequence\n    args:\n      - exec: $fallback\n");
    assert_eq!(ip(&answer(&e, 1).await), "192.0.2.1");
    tokio::time::timeout(Duration::from_secs(2), async {
        while e.cache_stats("cached_secondary").unwrap().len == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn cache_hit_keeps_the_current_clients_do_bit_and_does_not_echo_ecs_options() {
    let e = engine("plugins:\n  - tag: cached\n    type: cache\n    args: {size: 16}\n  - tag: ecs\n    type: ecs_handler\n    args: {forward: true}\n  - tag: main\n    type: sequence\n    args:\n      - exec: $cached\n      - matches: has_resp\n        exec: accept\n      - exec: $ecs\n      - exec: black_hole 192.0.2.1\n");
    for (id, do_bit, subnet) in [(1, true, "192.0.2.0"), (2, false, "198.51.100.0")] {
        let mut q = query(id);
        let mut opt = Edns::new();
        opt.set_dnssec_ok(do_bit).set_max_payload(4096);
        opt.options_mut()
            .insert(EdnsOption::Subnet(ClientSubnet::new(
                subnet.parse().unwrap(),
                24,
                0,
            )));
        q.set_edns(opt);
        let response = e
            .handle(q, "127.0.0.1".parse().unwrap(), "main")
            .await
            .unwrap();
        assert_eq!(response.response_code(), ResponseCode::NoError);
        let opt = response.extensions().as_ref().unwrap();
        assert_eq!(opt.dnssec_ok(), do_bit);
        assert!(opt.options().get(EdnsCode::Subnet).is_none());
    }
    assert_eq!(e.cache_stats("cached").unwrap().hits, 1);
}
