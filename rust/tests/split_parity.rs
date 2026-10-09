// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

#![cfg(feature = "full")]
use hickory_proto::{
    op::{Message, Query},
    rr::{DNSClass, Name, RData, RecordType},
};
use mosdns_rs::coremain::{Config, Engine};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    name: String,
    qname: String,
    qtype: u16,
    #[serde(default)]
    qclass: u16,
    rcode: u16,
    addresses: Vec<String>,
    ttl: u32,
    repeat: u16,
}

#[derive(Deserialize)]
struct Fixture {
    format_version: usize,
    cases: Vec<Case>,
}

#[tokio::test]
async fn shared_go_cn_site_and_ip_split_fixture() {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../tests/fixtures/split_cases.json")).unwrap();
    assert_eq!(fixture.format_version, 1);
    for case in fixture.cases {
        let config = Config::from_yaml(include_str!("../../tests/fixtures/split.yaml")).unwrap();
        let engine = Engine::new(config).unwrap();
        for request in 0..case.repeat {
            let id = 100 + request;
            let mut question = Query::query(
                Name::from_ascii(&case.qname).unwrap(),
                RecordType::from(case.qtype),
            );
            question.set_query_class(DNSClass::from(if case.qclass == 0 {
                1
            } else {
                case.qclass
            }));
            let mut query = Message::new();
            query
                .set_id(id)
                .set_recursion_desired(true)
                .add_query(question);
            let response = engine
                .handle(query, "127.0.0.1".parse().unwrap(), "main")
                .await
                .unwrap();
            assert_eq!(response.id(), id, "{}: ID on request {request}", case.name);
            assert_eq!(
                u16::from(response.response_code()),
                case.rcode,
                "{}: rcode",
                case.name
            );
            let addresses = response
                .answers()
                .iter()
                .map(|answer| {
                    assert!(
                        answer.ttl() <= case.ttl && case.ttl - answer.ttl() <= 1,
                        "{}: TTL {} on request {request}",
                        case.name,
                        answer.ttl()
                    );
                    assert_eq!(
                        answer.name().to_ascii(),
                        case.qname,
                        "{}: answer name",
                        case.name
                    );
                    match answer.data().unwrap() {
                        RData::A(addr) => addr.0.to_string(),
                        RData::AAAA(addr) => addr.0.to_string(),
                        data => panic!("{}: unexpected answer {data:?}", case.name),
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(
                addresses, case.addresses,
                "{}: request {request}",
                case.name
            );
            assert_eq!(
                engine.cache_stats("cached").unwrap().hits,
                u64::from(request),
                "{}: cache hits on request {request}",
                case.name
            );
        }
    }
}
