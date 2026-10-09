// SPDX-License-Identifier: GPL-3.0-or-later
#![cfg(feature = "full")]
use hickory_proto::{
    op::{Message, Query, ResponseCode},
    rr::{Name, RData, RecordType},
};
use mosdns_rs::coremain::{Config, Engine};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    format_version: usize,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    group: String,
    zone: String,
    qname: String,
    ttl: u32,
    answers: Vec<Vec<String>>,
}

fn from_hex(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    hex.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
async fn check_fixture(group: &str) {
    let fixture: Fixture =
        serde_json::from_str(include_str!("../../tests/fixtures/arbitrary_txt.json")).unwrap();
    assert_eq!(fixture.format_version, 1);
    for (index, case) in fixture
        .cases
        .into_iter()
        .enumerate()
        .filter(|(_, case)| case.group == group)
    {
        let value = serde_json::json!({"plugins":[{"tag":"answer","type":"arbitrary","args":{"rules":[case.zone]}},{"tag":"main","type":"sequence","args":[{"exec":"$answer"},{"exec":"accept"}]}]});
        let config = Config::from_yaml(&serde_yaml::to_string(&value).unwrap()).unwrap();
        let engine =
            Engine::new(config).unwrap_or_else(|error| panic!("{} startup: {error:#}", case.name));
        let mut query = Message::new();
        query.set_id(index as u16 + 100).add_query(Query::query(
            Name::from_ascii(&case.qname).unwrap(),
            RecordType::TXT,
        ));
        let response = engine
            .handle(query.clone(), "127.0.0.1".parse().unwrap(), "main")
            .await
            .unwrap();
        engine.shutdown().await.unwrap();
        assert_eq!(
            response.response_code(),
            ResponseCode::NoError,
            "{}",
            case.name
        );
        assert_eq!(response.id(), query.id(), "{}", case.name);
        let wire = response
            .to_vec()
            .unwrap_or_else(|error| panic!("{} wire encoding: {error}", case.name));
        let decoded = Message::from_vec(&wire).unwrap();
        assert_eq!(decoded.answers().len(), case.answers.len(), "{}", case.name);
        for (index, (record, want)) in decoded.answers().iter().zip(case.answers).enumerate() {
            assert_eq!(record.ttl(), case.ttl, "{} answer {index}", case.name);
            let RData::TXT(data) = record.data().unwrap() else {
                panic!("{} not TXT", case.name)
            };
            let got = data
                .txt_data()
                .iter()
                .map(|segment| segment.as_ref().to_vec())
                .collect::<Vec<_>>();
            let want = want.iter().map(|hex| from_hex(hex)).collect::<Vec<_>>();
            assert_eq!(got, want, "{} answer {index}", case.name);
        }
    }
}
#[tokio::test]
async fn shared_txt_escaped_raw_octets() {
    check_fixture("escapes").await
}
#[tokio::test]
async fn shared_txt_character_strings_chunk_at_255_bytes() {
    check_fixture("chunk").await
}
#[tokio::test]
async fn shared_txt_native_utf8_preserves_bytes_including_chunk_boundaries() {
    check_fixture("unicode").await
}
#[tokio::test]
async fn shared_txt_empty_strings_quotes_and_multiline_preserve_order() {
    check_fixture("presentation").await
}
