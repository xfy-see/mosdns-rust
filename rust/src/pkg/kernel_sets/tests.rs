use super::*;
use hickory_proto::{
    op::Query,
    rr::{
        rdata::{A, AAAA, SOA},
        Name, RData, Record, RecordType,
    },
};
use std::net::{Ipv4Addr, Ipv6Addr};

fn target() -> nft::Target {
    nft::Target {
        family: nft::TableFamily::Inet,
        table: "mosdns_test".into(),
        set: "ipv4".into(),
    }
}
fn metadata(interval: bool, ipv6: bool) -> nft::Metadata {
    nft::Metadata {
        family: nft::TableFamily::Inet,
        table: "mosdns_test".into(),
        name: "ipv4".into(),
        flags: if interval { 4 } else { 0 },
        key_type: if ipv6 { 8 } else { 7 },
        key_length: if ipv6 { 16 } else { 4 },
        id: None,
        default_timeout: None,
    }
}
fn element(prefix: &str) -> Element {
    prefix.parse::<IpNet>().unwrap().into()
}
fn element_attributes(message: &wire::Message) -> Vec<Vec<(u16, Vec<u8>)>> {
    let root = wire::attributes(&message.payload[4..]).unwrap();
    let list = root.iter().find(|attribute| attribute.kind == 3).unwrap();
    wire::attributes(list.payload)
        .unwrap()
        .iter()
        .map(|element| {
            wire::attributes(element.payload)
                .unwrap()
                .iter()
                .map(|attribute| (attribute.kind, attribute.payload.to_vec()))
                .collect()
        })
        .collect()
}
fn key(attributes: &[(u16, Vec<u8>)]) -> Vec<u8> {
    wire::attributes(&attributes.iter().find(|(kind, _)| *kind == 1).unwrap().1).unwrap()[0]
        .payload
        .to_vec()
}

#[test]
fn attribute_headers_use_native_endian_payloads_use_declared_byte_order_and_padding() {
    let encoded = wire::attribute(5 | wire::NLA_NETWORK_ORDER, &[1, 2, 3]).unwrap();
    assert_eq!(&encoded[..2], &7u16.to_ne_bytes());
    assert_eq!(encoded.len(), 8);
    assert_eq!(encoded[7], 0);
    let parsed = wire::attributes(&encoded).unwrap();
    assert_eq!(parsed[0].kind, 5);
    assert_eq!(parsed[0].flags, wire::NLA_NETWORK_ORDER);
    assert_eq!(parsed[0].payload, [1, 2, 3]);
    for payload in [
        &[0, 0, 0, 0][..],
        &[1, 0, 0, 0][..],
        &[255, 255, 0, 0][..],
        &[4, 0, 0][..],
    ] {
        assert!(wire::attributes(payload).is_err());
    }
    assert!(wire::attribute(1, &vec![0; 65532]).is_err());
}

#[test]
fn name_limits_are_bytes_including_terminating_nul() {
    assert!(wire::string_attribute(1, &"a".repeat(255), 256).is_ok());
    assert!(wire::string_attribute(1, &"a".repeat(256), 256).is_err());
    assert!(wire::string_attribute(1, &"a".repeat(31), 32).is_ok());
    assert!(wire::string_attribute(1, &"a".repeat(32), 32).is_err());
    assert!(wire::string_attribute(1, "bad\0name", 256).is_err());
    assert!(wire::string_attribute(1, "", 256).is_err());
    assert!(wire::nul_string(&[]).is_err());
    assert!(wire::nul_string(b"name").is_err());
}

#[test]
fn message_frames_decode_multiple_aligned_messages_and_reject_corruption() {
    let first = wire::Message {
        kind: 42,
        flags: 1,
        sequence: 13,
        port: 27,
        payload: vec![1, 2, 3],
    };
    let second = wire::Message {
        kind: 43,
        payload: vec![4, 5],
        ..first.clone()
    };
    let mut encoded = first.encode().unwrap();
    encoded.extend(second.encode().unwrap());
    let decoded = wire::messages(&encoded).unwrap();
    assert_eq!(decoded.len(), 2);
    assert_eq!(decoded[0].payload, first.payload);
    assert_eq!(decoded[1].kind, 43);
    let mut corrupt = first.encode().unwrap();
    corrupt[..4].copy_from_slice(&15u32.to_ne_bytes());
    assert!(wire::messages(&corrupt).is_err());
    assert!(wire::messages(&encoded[..encoded.len() - 1]).is_err());
}

#[test]
fn get_nft_set_request_matches_linux_uapi() {
    let request = nft::get_set(&target(), 12, 34).unwrap();
    assert_eq!(request.kind, 0x0a0a);
    assert_eq!(request.flags, 5);
    assert_eq!(request.payload[..4], [1, 0, 0, 0]);
    let attrs = wire::attributes(&request.payload[4..]).unwrap();
    assert_eq!(attrs[0].kind, 1);
    assert_eq!(attrs[0].payload, b"mosdns_test\0");
    assert_eq!(attrs[1].kind, 2);
    assert_eq!(attrs[1].payload, b"ipv4\0");
    let encoded = request.encode().unwrap();
    assert_eq!(&encoded[8..12], &12u32.to_ne_bytes());
    assert_eq!(&encoded[12..16], &34u32.to_ne_bytes());
}

#[test]
fn nft_metadata_parser_validates_identity_key_type_and_flags() {
    let mut message = nft::get_set(&target(), 1, 2).unwrap();
    message.kind = 0x0a09;
    for (kind, value) in [(3, 0x14u32), (4, 7), (5, 4), (10, 17)] {
        message
            .payload
            .extend(wire::attribute(kind, &value.to_be_bytes()).unwrap());
    }
    message
        .payload
        .extend(wire::attribute(11, &45000u64.to_be_bytes()).unwrap());
    let parsed = nft::parse_metadata(&target(), &message).unwrap();
    assert!(parsed.interval());
    assert!(parsed.has_timeout());
    assert_eq!(parsed.id, Some(17));
    assert_eq!(parsed.default_timeout, Some(Duration::from_secs(45)));
    let mut wrong = target();
    wrong.set = "other".into();
    assert!(nft::parse_metadata(&wrong, &message).is_err());
    let mut mutable = metadata(false, false);
    for flag in [1, 2, 8, 0x40, 0x80] {
        mutable.flags = flag;
        assert!(mutable.validate_address_set().is_err());
    }
    mutable.flags = 0;
    mutable.key_type = 3;
    assert!(mutable.validate_address_set().is_err());
    let mut invalid = message.clone();
    invalid.payload[0] = 2;
    assert!(nft::parse_metadata(&target(), &invalid).is_err());
}

#[test]
fn nft_plain_set_ignores_mask_and_preserves_original_ip_like_go() {
    let request =
        nft::add_elements(&metadata(false, false), &[element("192.0.2.123/24")], 1, 2).unwrap();
    let attrs = element_attributes(&request);
    assert_eq!(attrs.len(), 1);
    assert_eq!(key(&attrs[0]), [192, 0, 2, 123]);
    assert_eq!(request.flags, wire::REQUEST | wire::ACK | wire::CREATE);
    assert!(
        nft::add_elements(&metadata(false, false), &[element("2001:db8::1/48")], 1, 2).is_err()
    );
}

#[test]
fn nft_interval_encodes_masked_start_and_exclusive_end_for_both_families() {
    let request =
        nft::add_elements(&metadata(true, false), &[element("192.0.2.123/24")], 1, 2).unwrap();
    let attrs = element_attributes(&request);
    assert_eq!(attrs.len(), 2);
    assert_eq!(key(&attrs[0]), [192, 0, 2, 0]);
    assert_eq!(key(&attrs[1]), [192, 0, 3, 0]);
    assert_eq!(
        attrs[1].iter().find(|(kind, _)| *kind == 3).unwrap().1,
        1u32.to_be_bytes()
    );
    let request = nft::add_elements(
        &metadata(true, true),
        &[element("2001:db8:1234:5678::9/48")],
        1,
        2,
    )
    .unwrap();
    let attrs = element_attributes(&request);
    assert_eq!(
        key(&attrs[0]),
        "2001:db8:1234::".parse::<Ipv6Addr>().unwrap().octets()
    );
    assert_eq!(
        key(&attrs[1]),
        "2001:db8:1235::".parse::<Ipv6Addr>().unwrap().octets()
    );
}

#[test]
fn interval_end_overflow_preserves_the_last_ipv4_or_ipv6_address() {
    for prefix in [
        "255.255.255.255/32",
        "0.0.0.0/0",
        "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
        "::/0",
    ] {
        let prefix = prefix.parse::<IpNet>().unwrap();
        assert_eq!(nft::interval_end(prefix), None);
        let request = nft::add_elements(
            &metadata(true, prefix.addr().is_ipv6()),
            &[prefix.into()],
            1,
            2,
        )
        .unwrap();
        assert_eq!(element_attributes(&request).len(), 1);
    }
    assert_eq!(
        nft::interval_end("192.0.2.1/32".parse().unwrap()),
        Some("192.0.2.2".parse().unwrap())
    );
}

#[test]
fn nft_timeout_is_big_endian_milliseconds_and_never_added_to_end_marker() {
    let element = Element {
        prefix: "192.0.2.9/24".parse().unwrap(),
        timeout: Some(Duration::from_millis(1250)),
    };
    assert!(
        nft::add_elements(&metadata(true, false), std::slice::from_ref(&element), 1, 2).is_err()
    );
    let mut meta = metadata(true, false);
    meta.flags |= 0x10;
    let request = nft::add_elements(&meta, &[element], 1, 2).unwrap();
    let attrs = element_attributes(&request);
    assert_eq!(
        attrs[0].iter().find(|(kind, _)| *kind == 4).unwrap().1,
        1250u64.to_be_bytes()
    );
    assert!(!attrs[1].iter().any(|(kind, _)| *kind == 4));
    let without = nft::add_elements(&meta, &[self::element("192.0.2.9/24")], 1, 2).unwrap();
    assert!(!element_attributes(&without)[0]
        .iter()
        .any(|(kind, _)| *kind == 4));
}

#[test]
fn nft_batch_has_transaction_begin_end_with_correct_subsystem_resource() {
    let add =
        nft::add_elements(&metadata(false, false), &[element("192.0.2.1/32")], 12, 27).unwrap();
    let transaction = nft::batch(add, 11, 13);
    assert_eq!(
        (
            transaction[0].kind,
            transaction[1].kind,
            transaction[2].kind
        ),
        (16, 0x0a0c, 17)
    );
    assert_eq!(transaction[0].payload, [0, 0, 0, 10]);
    assert_eq!(transaction[2].payload, [0, 0, 0, 10]);
    assert_eq!(transaction[1].sequence, 12);
    assert_eq!(transaction[2].port, 27);
}

#[test]
fn ipset_add_preserves_go_protocol_and_cidr_with_network_order_ip_and_timeout() {
    for prefix in ["127.0.0.1/24", "2001:db8::9/48"] {
        let element = Element {
            prefix: prefix.parse().unwrap(),
            timeout: Some(Duration::from_millis(1250)),
        };
        let request = ipset::add_prefix("test", &element, 19, 20).unwrap();
        assert_eq!(request.kind, 0x0609);
        assert_eq!(request.flags, wire::REQUEST | wire::ACK);
        assert_eq!(&request.payload[..4], &[2, 0, 0, 0]);
        let attrs = wire::attributes(&request.payload[4..]).unwrap();
        assert_eq!(attrs[0].payload, [6]);
        let data =
            wire::attributes(attrs.iter().find(|attr| attr.kind == 7).unwrap().payload).unwrap();
        let address = wire::attributes(data[0].payload).unwrap();
        assert_eq!(address[0].flags, wire::NLA_NETWORK_ORDER);
        assert_eq!(
            address[0].kind,
            if element.prefix.addr().is_ipv4() {
                1
            } else {
                2
            }
        );
        assert_eq!(
            data.iter().find(|attr| attr.kind == 3).unwrap().payload,
            [element.prefix.prefix_len()]
        );
        let timeout = data.iter().find(|attr| attr.kind == 6).unwrap();
        assert_eq!(timeout.flags, wire::NLA_NETWORK_ORDER);
        assert_eq!(timeout.payload, 2u32.to_be_bytes());
    }
}

#[test]
fn ack_collection_accepts_data_and_ack_in_either_order_and_ignores_old_sequence() {
    let ack = wire::Message {
        kind: 2,
        flags: 0,
        sequence: 12,
        port: 27,
        payload: 0i32.to_ne_bytes().to_vec(),
    };
    let data = wire::Message {
        kind: 0x0a09,
        payload: vec![1, 0, 0, 0],
        ..ack.clone()
    };
    for replies in [
        vec![ack.clone(), data.clone()],
        vec![data.clone(), ack.clone()],
    ] {
        let mut collector = wire::ReplyCollector::new([12], [12], Some((12, 1)));
        collector
            .push(wire::Message {
                sequence: 11,
                ..ack.clone()
            })
            .unwrap();
        assert!(!collector.complete());
        for reply in replies {
            collector.push(reply).unwrap();
        }
        assert!(collector.complete());
        assert_eq!(collector.data.len(), 1);
    }
}

#[test]
fn ack_errors_include_kernel_errno_and_capped_extended_message() {
    let mut payload = (-1i32).to_ne_bytes().to_vec();
    payload.extend([0u8; 16]);
    payload.extend(wire::string_attribute(1, "operation denied", 256).unwrap());
    let message = wire::Message {
        kind: 2,
        flags: 0x300,
        sequence: 12,
        port: 27,
        payload,
    };
    let mut collector = wire::ReplyCollector::new([12], [12], None);
    let error = collector.push(message).unwrap_err();
    let kernel = error.downcast_ref::<wire::KernelError>().unwrap();
    assert_eq!(kernel.errno, 1);
    assert_eq!(kernel.detail.as_deref(), Some("operation denied"));
    assert!(collector
        .push(wire::Message {
            kind: 2,
            flags: 0,
            sequence: 12,
            port: 27,
            payload: vec![0; 3]
        })
        .is_err());
}

#[test]
fn multipart_dump_waits_for_done_even_after_receiving_data() {
    let data = wire::Message {
        kind: 0x0a0d,
        flags: 2,
        sequence: 12,
        port: 27,
        payload: vec![1, 0, 0, 0],
    };
    let mut collector = wire::ReplyCollector::dump(12, []);
    collector.push(data).unwrap();
    assert!(!collector.complete());
    collector
        .push(wire::Message {
            kind: 3,
            flags: 0,
            sequence: 12,
            port: 27,
            payload: 0i32.to_ne_bytes().to_vec(),
        })
        .unwrap();
    assert!(collector.complete());
    assert_eq!(collector.data.len(), 1);
    let mut interrupted = wire::ReplyCollector::dump(12, []);
    assert!(interrupted
        .push(wire::Message {
            kind: 3,
            flags: 0x10,
            sequence: 12,
            port: 27,
            payload: Vec::new()
        })
        .is_err());
}

#[test]
fn dns_element_policy_keeps_default_or_raises_ttl_to_ip_soa_and_minimum() {
    let name = Name::from_ascii("example.").unwrap();
    let mut response = Message::new();
    response.add_query(Query::query(name.clone(), RecordType::A));
    response.add_answer(Record::from_rdata(
        name.clone(),
        10,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 123))),
    ));
    response.add_answer(Record::from_rdata(
        name.clone(),
        500,
        RData::AAAA(AAAA("2001:db8::123".parse().unwrap())),
    ));
    response.add_name_server(Record::from_rdata(
        name.clone(),
        200,
        RData::SOA(SOA::new(name.clone(), name, 1, 2, 3, 4, 5)),
    ));
    let (v4, v6) = response_elements(&response, 24, 48, TimeoutPolicy::SetDefault).unwrap();
    assert_eq!(
        v4[0].prefix.addr(),
        "192.0.2.123".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(v6[0].prefix.prefix_len(), 48);
    assert_eq!(v4[0].timeout, None);
    let (v4, v6) = response_elements(
        &response,
        24,
        48,
        TimeoutPolicy::DnsTtl {
            minimum: Duration::from_secs(100),
        },
    )
    .unwrap();
    assert_eq!(v4[0].timeout, Some(Duration::from_secs(200)));
    assert_eq!(v6[0].timeout, Some(Duration::from_secs(500)));
    assert!(response_elements(&response, 33, 48, TimeoutPolicy::SetDefault).is_err());
}

#[test]
fn oversized_element_batch_is_rejected_before_a_transaction_can_be_sent() {
    let elements = vec![element("192.0.2.1/32"); 4000];
    assert!(nft::add_elements(&metadata(true, false), &elements, 1, 2).is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn native_operations_are_explicitly_unsupported_on_other_operating_systems() {
    assert!(NftSetHandler::new(target(), Duration::from_secs(1))
        .err()
        .unwrap()
        .to_string()
        .contains("require Linux"));
    assert!(IpSetHandler::new("test".into(), Duration::from_secs(1))
        .err()
        .unwrap()
        .to_string()
        .contains("require Linux"));
}
