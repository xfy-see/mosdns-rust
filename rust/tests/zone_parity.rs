// SPDX-License-Identifier: GPL-3.0-or-later
#![cfg(feature = "full")]
use hickory_proto::{
    op::{Message, Query},
    rr::{DNSClass, Name, Record, RecordType},
    serialize::binary::{BinDecodable, BinDecoder, BinEncodable, BinEncoder},
};
use mosdns_rs::{
    coremain::{Config, Engine},
    plugin::executable::arbitrary::parse_zone,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    format_version: u32,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    name: String,
    group: String,
    zone: String,
    error: bool,
    records: Vec<WireRecord>,
}
#[derive(Deserialize)]
struct WireRecord {
    owner_wire: String,
    #[serde(rename = "type")]
    typ: u16,
    class: u16,
    ttl: u32,
    rdata: String,
}
fn fixture() -> Fixture {
    let f: Fixture =
        serde_json::from_str(include_str!("../../tests/fixtures/zone_records.json")).unwrap();
    assert_eq!(f.format_version, 1);
    f
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn encoded(record: &Record) -> (String, String) {
    let mut owner = Vec::new();
    let mut enc = BinEncoder::new(&mut owner);
    enc.set_canonical_names(true);
    record.name().emit(&mut enc).unwrap();
    (hex(&owner), hex(&raw_data(record)))
}
fn emit_name(out: &mut Vec<u8>, name: &Name) {
    for label in name.iter() {
        out.push(label.len() as u8);
        out.extend(label);
    }
    out.push(0);
}
fn raw_data(record: &Record) -> Vec<u8> {
    use hickory_proto::rr::RData;
    let mut data = Vec::new();
    match record.data() {
        Some(RData::NS(value)) => emit_name(&mut data, &value.0),
        Some(RData::CNAME(value)) => emit_name(&mut data, &value.0),
        Some(RData::PTR(value)) => emit_name(&mut data, &value.0),
        Some(RData::MX(value)) => {
            data.extend(value.preference().to_be_bytes());
            emit_name(&mut data, value.exchange());
        }
        Some(RData::SOA(value)) => {
            emit_name(&mut data, value.mname());
            emit_name(&mut data, value.rname());
            data.extend(value.serial().to_be_bytes());
            data.extend(value.refresh().to_be_bytes());
            data.extend(value.retry().to_be_bytes());
            data.extend(value.expire().to_be_bytes());
            data.extend(value.minimum().to_be_bytes());
        }
        Some(RData::SRV(value)) => {
            data.extend(value.priority().to_be_bytes());
            data.extend(value.weight().to_be_bytes());
            data.extend(value.port().to_be_bytes());
            emit_name(&mut data, value.target());
        }
        Some(RData::NAPTR(value)) => {
            data.extend(value.order().to_be_bytes());
            data.extend(value.preference().to_be_bytes());
            for bytes in [value.flags(), value.services(), value.regexp()] {
                data.push(bytes.len() as u8);
                data.extend(bytes);
            }
            emit_name(&mut data, value.replacement());
        }
        Some(value) => value.emit(&mut BinEncoder::new(&mut data)).unwrap(),
        None => {}
    }
    data
}
fn check(case: &Case, records: &[Record]) {
    assert_eq!(
        records.len(),
        case.records.len(),
        "{} record count",
        case.name
    );
    for (index, (record, want)) in records.iter().zip(&case.records).enumerate() {
        let (owner, rdata) = encoded(record);
        assert_eq!(owner, want.owner_wire, "{} record {index} owner", case.name);
        assert_eq!(
            u16::from(record.record_type()),
            want.typ,
            "{} type",
            case.name
        );
        assert_eq!(
            u16::from(record.dns_class()),
            want.class,
            "{} class",
            case.name
        );
        assert_eq!(record.ttl(), want.ttl, "{} TTL", case.name);
        assert_eq!(rdata, want.rdata, "{} record {index} RDATA", case.name);
    }
}
fn group(group: &str) {
    for case in fixture()
        .cases
        .into_iter()
        .filter(|case| case.group == group)
    {
        let result = parse_zone(&case.zone);
        if case.error {
            assert!(result.is_err(), "{} must be rejected", case.name);
        } else {
            check(
                &case,
                &result.unwrap_or_else(|e| panic!("{} parse: {e:#}", case.name)),
            );
        }
    }
}
#[test]
fn shared_zone_all_go_rr_types() {
    group("types");
}
#[test]
fn shared_zone_dnskey_text_is_a_static_zone_record() {
    let case = fixture()
        .cases
        .into_iter()
        .find(|case| case.name == "rr_dnskey")
        .unwrap();
    check(&case, &parse_zone(&case.zone).unwrap());
}
#[test]
fn amtrelay_discovery_bit_retains_the_gateway_on_wire() {
    // Go v1.1.72 omits this name because its encoder switches on the full
    // discovery/type byte. The Rust encoder masks the discovery bit.
    let records = parse_zone("rr.Example. 73 IN AMTRELAY 10 1 3 gateway.Example.").unwrap();
    assert_eq!(
        encoded(&records[0]).1,
        "0a830767617465776179074578616d706c6500"
    );
}
#[test]
fn shared_zone_header_origin_class_owner_order_and_escapes() {
    group("header");
}
#[test]
fn shared_zone_generate_range_modifiers_and_subparser_state() {
    group("generate");
}
#[test]
fn shared_zone_rfc3597_unknown_and_known_wire() {
    group("rfc3597");
}
#[test]
fn shared_zone_rejects_go_invalid_syntax_and_external_include() {
    group("error");
}

#[tokio::test]
async fn shared_zone_arbitrary_answers_preserve_type_class_ttl_and_order() {
    for case in fixture().cases.into_iter().filter(|case| !case.error) {
        let value = serde_json::json!({"plugins":[{"tag":"answer","type":"arbitrary","args":{"rules":[case.zone]}},{"tag":"main","type":"sequence","args":[{"exec":"$answer"},{"exec":"accept"}]}]});
        let engine =
            Engine::new(Config::from_yaml(&serde_yaml::to_string(&value).unwrap()).unwrap())
                .unwrap_or_else(|e| panic!("{} startup: {e:#}", case.name));
        for wanted in &case.records {
            let wire = unhex(&wanted.owner_wire);
            let owner = Name::read(&mut BinDecoder::new(&wire)).unwrap();
            let mut query = Message::new();
            let mut question = Query::query(owner.to_lowercase(), RecordType::from(wanted.typ));
            question.set_query_class(DNSClass::from(wanted.class));
            query.set_id(123).add_query(question);
            let response = engine
                .handle(query, "127.0.0.1".parse().unwrap(), "main")
                .await
                .unwrap();
            assert_eq!(response.id(), 123);
            let expected: Vec<_> = case
                .records
                .iter()
                .filter(|r| {
                    r.owner_wire == wanted.owner_wire
                        && r.typ == wanted.typ
                        && r.class == wanted.class
                })
                .collect();
            assert_eq!(
                response.answers().len(),
                expected.len(),
                "{} answers",
                case.name
            );
            for (record, want) in response.answers().iter().zip(expected) {
                assert_eq!(encoded(record).1, want.rdata, "{} answer", case.name);
                assert_eq!(u16::from(record.record_type()), want.typ);
                assert_eq!(u16::from(record.dns_class()), want.class);
                assert_eq!(record.ttl(), want.ttl);
            }
        }
        engine.shutdown().await.unwrap();
    }
}
