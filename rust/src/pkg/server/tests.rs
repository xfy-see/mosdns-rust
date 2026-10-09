use super::*;
use anyhow::anyhow;
use hickory_proto::{
    op::Query,
    rr::{rdata::TXT, Name, RData, Record, RecordType},
};

fn query(id: u16) -> Message {
    let mut message = Message::new();
    message
        .set_id(id)
        .set_recursion_desired(true)
        .add_query(Query::query(
            Name::from_ascii("example.").unwrap(),
            RecordType::TXT,
        ));
    message
}

fn big_response(query: &Message) -> Message {
    let mut response = error_response(query, ResponseCode::NoError);
    for index in 0..8 {
        response.add_answer(Record::from_rdata(
            query.queries()[0].name().clone(),
            60,
            RData::TXT(TXT::new(vec![format!("{index}{}", "x".repeat(200))])),
        ));
    }
    response
}

#[tokio::test]
async fn udp_listener_returns_formerr_servfail_and_negotiated_truncation() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let handler: Handler = Arc::new(|query, _client| {
        Box::pin(async move {
            if query.id() == 9 {
                return Err(anyhow!("mock upstream failure"));
            }
            Ok(big_response(&query))
        })
    });
    let task = tokio::spawn(serve_udp_socket(socket, handler));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(addr).await.unwrap();
    let mut buffer = [0; 65535];
    for (payload, expected) in [
        (vec![0, 17, 0], ResponseCode::FormErr),
        (
            Message::new().set_id(18).to_vec().unwrap(),
            ResponseCode::FormErr,
        ),
        (query(9).to_vec().unwrap(), ResponseCode::ServFail),
    ] {
        client.send(&payload).await.unwrap();
        let length = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let response = Message::from_vec(&buffer[..length]).unwrap();
        assert_eq!(response.response_code(), expected);
        assert_eq!(response.id(), u16::from_be_bytes([payload[0], payload[1]]));
        assert_eq!(response.message_type(), MessageType::Response);
    }
    client.send(&query(20).to_vec().unwrap()).await.unwrap();
    let length = client.recv(&mut buffer).await.unwrap();
    assert!(length <= 512);
    assert!(Message::from_vec(&buffer[..length]).unwrap().truncated());
    let mut edns_query = query(21);
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    edns_query.set_edns(edns);
    client.send(&edns_query.to_vec().unwrap()).await.unwrap();
    let length = client.recv(&mut buffer).await.unwrap();
    let response = Message::from_vec(&buffer[..length]).unwrap();
    assert!(length > 512 && length <= 4096);
    assert!(!response.truncated());
    assert_eq!(response.answers().len(), 8);
    task.abort();
}

#[tokio::test]
async fn tcp_listener_frames_multiple_pipelined_queries_on_one_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler: Handler = Arc::new(|query, _client| {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis((15 - query.id() % 16) as u64)).await;
            Ok(big_response(&query))
        })
    });
    let task = tokio::spawn(serve_tcp_listener(listener, handler));
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let mut combined = Vec::new();
    for id in 0..16 {
        let payload = query(id).to_vec().unwrap();
        combined.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        combined.extend_from_slice(&payload);
    }
    // A fragmented first length header followed by many coalesced frames.
    stream.write_all(&combined[..1]).await.unwrap();
    stream.write_all(&combined[1..]).await.unwrap();
    let mut ids = std::collections::HashSet::new();
    for _ in 0..16 {
        let length = tokio::time::timeout(Duration::from_secs(1), stream.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut payload = vec![0; length as usize];
        stream.read_exact(&mut payload).await.unwrap();
        let response = Message::from_vec(&payload).unwrap();
        assert_eq!(response.answers().len(), 8);
        assert!(!response.truncated());
        assert!(ids.insert(response.id()));
    }
    assert_eq!(ids.len(), 16);
    let payload = query(50).to_vec().unwrap();
    stream.write_u16(payload.len() as u16).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    let length = stream.read_u16().await.unwrap();
    let mut payload = vec![0; length as usize];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(Message::from_vec(&payload).unwrap().id(), 50);
    task.abort();
}

#[tokio::test]
async fn malformed_tcp_query_gets_a_framed_formerr() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler: Handler =
        Arc::new(|_, _| Box::pin(async { panic!("malformed DNS must not reach engine") }));
    let task = tokio::spawn(serve_tcp_listener(listener, handler));
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(&[0, 3, 0, 44, 0]).await.unwrap();
    let length = stream.read_u16().await.unwrap();
    let mut payload = vec![0; length as usize];
    stream.read_exact(&mut payload).await.unwrap();
    let response = Message::from_vec(&payload).unwrap();
    assert_eq!(response.id(), 44);
    assert_eq!(response.response_code(), ResponseCode::FormErr);
    task.abort();
}

#[test]
fn truncated_udp_message_preserves_questions_and_never_splits_rrsets() {
    let request = query(1234);
    let payload = pack_udp(&RequestContext::new(&request), big_response(&request)).unwrap();
    let response = Message::from_vec(&payload).unwrap();
    assert!(response.truncated());
    assert!(response.answers().is_empty());
    assert_eq!(response.queries(), request.queries());
    assert_eq!(response.id(), request.id());
    assert!(payload.len() <= 512);
}

#[tokio::test]
async fn tcp_configured_idle_timeout_closes_a_reused_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handler: Handler = Arc::new(|query, _| {
        Box::pin(async move { Ok(error_response(&query, ResponseCode::NoError)) })
    });
    let task = tokio::spawn(serve_tcp_listener_with_timeout(
        listener,
        handler,
        Duration::from_millis(40),
    ));
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let payload = query(50).to_vec().unwrap();
    stream.write_u16(payload.len() as u16).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    let length = stream.read_u16().await.unwrap();
    let mut payload = vec![0; length as usize];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(Message::from_vec(&payload).unwrap().id(), 50);
    let mut byte = [0];
    let length = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        length, 0,
        "configured idle timeout should close the connection"
    );
    task.abort();
}

#[tokio::test]
async fn response_edns_matches_client_do_without_leaking_to_classic_dns() {
    let handler: Handler = Arc::new(|query, _| {
        Box::pin(async move {
            let mut response = error_response(&query, ResponseCode::NoError);
            let mut edns = Edns::new();
            edns.set_max_payload(65535).set_dnssec_ok(true);
            response.set_edns(edns);
            Ok(response)
        })
    });
    for client_do in [None, Some(false), Some(true)] {
        let mut request = query(1);
        if let Some(client_do) = client_do {
            let mut edns = Edns::new();
            edns.set_max_payload(4096).set_dnssec_ok(client_do);
            request.set_edns(edns);
        }
        let (_, response) = process_wire(
            &request.to_vec().unwrap(),
            Some("127.0.0.1".parse().unwrap()),
            &handler,
        )
        .await
        .unwrap();
        match client_do {
            None => assert!(response.extensions().is_none()),
            Some(client_do) => {
                let edns = response.extensions().as_ref().unwrap();
                assert_eq!(edns.max_payload(), 1200);
                assert_eq!(edns.dnssec_ok(), client_do);
            }
        }
    }
}

#[tokio::test]
async fn handler_receives_original_edns_and_failure_preserves_request_fields() {
    use hickory_proto::{
        op::OpCode,
        rr::rdata::opt::{EdnsCode, EdnsOption},
    };
    let client = "198.51.100.19".parse().unwrap();
    let mut request = query(0x1234);
    request
        .set_op_code(OpCode::Status)
        .set_checking_disabled(true);
    let mut edns = Edns::new();
    edns.set_max_payload(4096).set_dnssec_ok(true);
    edns.options_mut()
        .insert(EdnsOption::Unknown(65001, vec![19; 1024]));
    request.set_edns(edns);
    let original_question = request.queries()[0].clone();
    let handler: Handler = Arc::new(move |mut query, metadata| {
        assert_eq!(metadata, Some(client));
        assert_eq!(query.extensions().as_ref().unwrap().max_payload(), 4096);
        assert_eq!(
            query
                .extensions()
                .as_ref()
                .unwrap()
                .options()
                .get(EdnsCode::Unknown(65001)),
            Some(&EdnsOption::Unknown(65001, vec![19; 1024]))
        );
        query
            .set_id(999)
            .set_recursion_desired(false)
            .set_checking_disabled(false);
        query.queries_mut().clear();
        *query.extensions_mut() = None;
        Box::pin(async { Err(anyhow!("failed after consuming the request")) })
    });
    let (_, response) = process_wire(&request.to_vec().unwrap(), Some(client), &handler)
        .await
        .unwrap();
    assert_eq!(response.id(), 0x1234);
    assert_eq!(response.op_code(), OpCode::Status);
    assert!(response.recursion_desired());
    assert!(response.checking_disabled());
    assert_eq!(response.queries(), &[original_question]);
    assert_eq!(response.response_code(), ResponseCode::ServFail);
    let edns = response.extensions().as_ref().unwrap();
    assert_eq!(edns.max_payload(), 1200);
    assert!(edns.dnssec_ok());
    assert!(edns.options().as_ref().is_empty());
}

#[tokio::test(start_paused = true)]
async fn handler_timeout_keeps_request_id_question_and_edns() {
    let mut request = query(0x4567);
    let mut edns = Edns::new();
    edns.set_max_payload(2048).set_dnssec_ok(true);
    request.set_edns(edns);
    let handler: Handler = Arc::new(|mut query, _| {
        query.set_id(99);
        query.queries_mut().clear();
        *query.extensions_mut() = None;
        Box::pin(std::future::pending())
    });
    let (_, response) = process_query(request.clone(), None, &handler).await;
    assert_eq!(response.id(), request.id());
    assert_eq!(response.queries(), request.queries());
    assert_eq!(response.response_code(), ResponseCode::ServFail);
    assert!(response.extensions().as_ref().unwrap().dnssec_ok());
}

#[tokio::test]
async fn connection_parses_large_small_and_malformed_frames_without_stale_bytes() {
    let (stream, mut client) = tokio::io::duplex(8192);
    let handler: Handler = Arc::new(|query, metadata| {
        assert!(metadata.is_none());
        if query.id() == 102 {
            assert_eq!(query.additionals().len(), 1);
            assert_eq!(
                query.additionals()[0].data(),
                Some(&RData::TXT(TXT::new(vec!["x".repeat(200); 16])))
            );
        }
        Box::pin(async move { Ok(error_response(&query, ResponseCode::NoError)) })
    });
    let server = tokio::spawn(serve_dns_connection(
        stream,
        None,
        handler,
        Arc::new(Semaphore::new(MAX_QUERIES)),
        IDLE_TIMEOUT,
    ));
    let mut large = query(102);
    large.add_additional(Record::from_rdata(
        Name::from_ascii("additional.example.").unwrap(),
        60,
        RData::TXT(TXT::new(vec!["x".repeat(200); 16])),
    ));
    for (payload, id, code) in [
        (large.to_vec().unwrap(), 102, ResponseCode::NoError),
        (query(101).to_vec().unwrap(), 101, ResponseCode::NoError),
        (vec![0, 103, 0], 103, ResponseCode::FormErr),
        (query(104).to_vec().unwrap(), 104, ResponseCode::NoError),
    ] {
        client.write_u16(payload.len() as u16).await.unwrap();
        client.write_all(&payload).await.unwrap();
        let length = tokio::time::timeout(Duration::from_secs(1), client.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut reply = vec![0; length as usize];
        client.read_exact(&mut reply).await.unwrap();
        let response = Message::from_vec(&reply).unwrap();
        assert_eq!(response.id(), id);
        assert_eq!(response.response_code(), code);
    }
    drop(client);
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn pipelined_fast_reply_overtakes_slow_reply_and_close_cancels_work() {
    struct OnDrop(Option<tokio::sync::oneshot::Sender<()>>);
    impl Drop for OnDrop {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _ = sender.send(());
            }
        }
    }
    let (cancelled, cancellation) = tokio::sync::oneshot::channel();
    let cancellation_sender = Arc::new(std::sync::Mutex::new(Some(cancelled)));
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let handler: Handler = Arc::new({
        let entered = entered.clone();
        let release = release.clone();
        move |query, _| {
            let entered = entered.clone();
            let release = release.clone();
            let cancellation_sender = cancellation_sender.clone();
            Box::pin(async move {
                if query.id() == 201 {
                    entered.notify_one();
                    release.notified().await;
                } else if query.id() == 203 {
                    let _guard = OnDrop(cancellation_sender.lock().unwrap().take());
                    entered.notify_one();
                    std::future::pending::<()>().await;
                }
                Ok(error_response(&query, ResponseCode::NoError))
            })
        }
    });
    let limit = Arc::new(Semaphore::new(2));
    let (stream, mut client) = tokio::io::duplex(8192);
    let server = tokio::spawn(serve_dns_connection(
        stream,
        None,
        handler,
        limit.clone(),
        IDLE_TIMEOUT,
    ));
    for id in [201, 202] {
        let payload = query(id).to_vec().unwrap();
        client.write_u16(payload.len() as u16).await.unwrap();
        client.write_all(&payload).await.unwrap();
        if id == 201 {
            entered.notified().await;
        }
    }
    for id in [202, 201] {
        let length = tokio::time::timeout(Duration::from_secs(1), client.read_u16())
            .await
            .unwrap()
            .unwrap();
        let mut reply = vec![0; length as usize];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(Message::from_vec(&reply).unwrap().id(), id);
        if id == 202 {
            release.notify_one();
        }
    }
    let payload = query(203).to_vec().unwrap();
    client.write_u16(payload.len() as u16).await.unwrap();
    client.write_all(&payload).await.unwrap();
    entered.notified().await;
    drop(client);
    server.await.unwrap().unwrap();
    tokio::time::timeout(Duration::from_secs(1), cancellation)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(limit.available_permits(), 2);
}

#[test]
fn stream_frame_compression_stays_relative_to_dns_payload_when_buffer_is_reused() {
    let request = query(0x789a);
    let large = big_response(&request);
    let small = error_response(&request, ResponseCode::NXDomain);
    let mut frame = Vec::new();
    for response in [&large, &small, &large] {
        encode_stream_response(response, &mut frame).unwrap();
        assert_eq!(
            u16::from_be_bytes([frame[0], frame[1]]) as usize,
            frame.len() - 2
        );
        let parsed = Message::from_vec(&frame[2..]).unwrap();
        assert_eq!(parsed.id(), 0x789a);
        assert_eq!(parsed.queries(), request.queries());
        assert_eq!(parsed.response_code(), response.response_code());
        assert_eq!(parsed.answers(), response.answers());
        if !parsed.answers().is_empty() {
            assert!(
                frame[2..].windows(2).any(|bytes| bytes == [0xc0, 12]),
                "answer names should point to the question at DNS offset 12"
            );
        }
    }
}

#[tokio::test]
async fn response_restores_id_and_do_without_overwriting_handler_edns_options() {
    use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
    let mut request = query(88);
    let mut edns = Edns::new();
    edns.set_max_payload(4096).set_dnssec_ok(true);
    edns.options_mut()
        .insert(EdnsOption::Unknown(65001, vec![1; 512]));
    request.set_edns(edns);
    let handler: Handler = Arc::new(|query, _| {
        assert!(query
            .extensions()
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Unknown(65001))
            .is_some());
        Box::pin(async move {
            let mut response = error_response(&query, ResponseCode::NoError);
            response.set_id(99);
            let edns = response.extensions_mut().as_mut().unwrap();
            edns.set_dnssec_ok(false);
            edns.options_mut()
                .insert(EdnsOption::Unknown(65002, vec![2; 512]));
            Ok(response)
        })
    });
    let (_, response) = process_query(request, None, &handler).await;
    assert_eq!(response.id(), 88);
    assert_eq!(response.extensions().as_ref().unwrap().max_payload(), 1200);
    assert!(response.extensions().as_ref().unwrap().dnssec_ok());
    assert_eq!(
        response
            .extensions()
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Unknown(65002)),
        Some(&EdnsOption::Unknown(65002, vec![2; 512]))
    );
    assert!(response
        .extensions()
        .as_ref()
        .unwrap()
        .options()
        .get(EdnsCode::Unknown(65001))
        .is_none());
}

#[tokio::test]
async fn writer_discards_an_unencodable_response_without_poisoning_the_next_frame() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let handler: Handler = Arc::new({
        let entered = entered.clone();
        move |query, _| {
            let entered = entered.clone();
            Box::pin(async move {
                let mut response = error_response(&query, ResponseCode::NoError);
                if query.id() == 301 {
                    response.add_answer(Record::from_rdata(
                        query.queries()[0].name().clone(),
                        60,
                        RData::TXT(TXT::new(vec!["x".repeat(256)])),
                    ));
                    assert!(
                        response.to_vec().is_err(),
                        "TXT character strings are limited to 255 bytes"
                    );
                    entered.notify_one();
                }
                Ok(response)
            })
        }
    });
    let (stream, mut client) = tokio::io::duplex(8192);
    let server = tokio::spawn(serve_dns_connection(
        stream,
        None,
        handler,
        Arc::new(Semaphore::new(MAX_QUERIES)),
        IDLE_TIMEOUT,
    ));
    for id in [301, 302] {
        let payload = query(id).to_vec().unwrap();
        client.write_u16(payload.len() as u16).await.unwrap();
        client.write_all(&payload).await.unwrap();
        if id == 301 {
            entered.notified().await;
        }
    }
    let length = tokio::time::timeout(Duration::from_secs(1), client.read_u16())
        .await
        .unwrap()
        .unwrap();
    let mut reply = vec![0; length as usize];
    client.read_exact(&mut reply).await.unwrap();
    let response = Message::from_vec(&reply).unwrap();
    assert_eq!(response.id(), 302);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.queries(), query(302).queries());
    drop(client);
    server.await.unwrap().unwrap();
}

#[tokio::test]
async fn invalid_question_list_is_preserved_for_formerr_and_truncated_as_a_whole() {
    let mut request = Message::new();
    request
        .set_id(0x6789)
        .set_recursion_desired(true)
        .set_checking_disabled(true);
    for index in 0..80 {
        request.add_query(Query::query(
            Name::from_ascii(format!("question-{index}.many-questions.example.")).unwrap(),
            RecordType::A,
        ));
    }
    let handler: Handler = Arc::new(|_, _| {
        Box::pin(async { panic!("multiple-question requests must not reach the handler") })
    });
    let (context, response) = process_wire(&request.to_vec().unwrap(), None, &handler)
        .await
        .unwrap();
    assert_eq!(response.id(), 0x6789);
    assert_eq!(response.response_code(), ResponseCode::FormErr);
    assert_eq!(response.queries(), request.queries());
    let payload = pack_udp(&context, response).unwrap();
    assert!(payload.len() <= 512);
    let truncated = Message::from_vec(&payload).unwrap();
    assert_eq!(truncated.id(), 0x6789);
    assert_eq!(truncated.response_code(), ResponseCode::FormErr);
    assert!(truncated.truncated());
    assert!(truncated.recursion_desired());
    assert!(truncated.checking_disabled());
    assert!(truncated.queries().is_empty());
}

#[cfg(feature = "full")]
pub(super) fn pem_fixture() -> (tempfile::TempDir, String, String) {
    use base64::Engine as _;
    let temporary = tempfile::tempdir().unwrap();
    let cert = temporary.path().join("cert.pem");
    let key = temporary.path().join("key.pem");
    let cert_data = base64::engine::general_purpose::STANDARD
        .encode(include_bytes!("../upstream/fixtures/localhost-cert.der"));
    let key_data = base64::engine::general_purpose::STANDARD
        .encode(include_bytes!("../upstream/fixtures/localhost-key.der"));
    std::fs::write(
        &cert,
        format!("-----BEGIN CERTIFICATE-----\n{cert_data}\n-----END CERTIFICATE-----\n"),
    )
    .unwrap();
    std::fs::write(
        &key,
        format!("-----BEGIN PRIVATE KEY-----\n{key_data}\n-----END PRIVATE KEY-----\n"),
    )
    .unwrap();
    (
        temporary,
        cert.to_str().unwrap().to_owned(),
        key.to_str().unwrap().to_owned(),
    )
}

#[cfg(feature = "full")]
pub(super) fn test_engine() -> Arc<crate::coremain::Engine> {
    let config = crate::coremain::Config::from_yaml(
        r#"
plugins:
  - tag: main
    type: sequence
    args:
      - matches: ["client_ip 198.51.100.1"]
        exec: reject 3
      - matches: ["string_exp url_path eq /dns-query"]
        exec: reject 0
      - matches: ["string_exp server_name eq dns.test.invalid"]
        exec: reject 0
      - exec: reject 5
"#,
    )
    .unwrap();
    Arc::new(crate::coremain::Engine::new(config).unwrap())
}

#[cfg(feature = "full")]
pub(super) fn trusted_tls_client() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            include_bytes!("../upstream/fixtures/localhost-cert.der").to_vec(),
        ))
        .unwrap();
    Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    )
}

#[tokio::test]
#[cfg(feature = "full")]
async fn http_get_post_path_source_ip_and_request_validation() {
    use base64::Engine as _;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes = http::Routes {
        engine: test_engine(),
        entries: vec![("/dns-query".into(), "main".into())],
        src_ip_header: "x-forwarded-for".into(),
        limit: Arc::new(Semaphore::new(MAX_QUERIES)),
    };
    let task = tokio::spawn(http::serve_http_listener(
        listener,
        routes,
        None,
        Duration::from_secs(2),
    ));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("http://{addr}/dns-query");
    let payload = query(15).to_vec().unwrap();
    let post = client
        .post(&url)
        .header("content-type", "application/dns-message")
        .body(payload.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(post.status(), reqwest::StatusCode::OK);
    let response = Message::from_vec(&post.bytes().await.unwrap()).unwrap();
    assert_eq!(response.id(), 15);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&payload);
    let get = client
        .get(format!("{url}?dns={encoded}"))
        .header("accept", "application/dns-message")
        .header("x-forwarded-for", "198.51.100.1, 192.0.2.1")
        .send()
        .await
        .unwrap();
    assert_eq!(
        Message::from_vec(&get.bytes().await.unwrap())
            .unwrap()
            .response_code(),
        ResponseCode::NXDomain
    );
    for request in [
        client.post(&url).body(payload.clone()),
        client.get(&url).header("accept", "application/dns-message"),
        client
            .get(format!("{url}?dns=%%%"))
            .header("accept", "application/dns-message"),
        client
            .post(&url)
            .header("content-type", "application/dns-message")
            .body(vec![0; 65536]),
        client
            .post(&url)
            .header("content-type", "application/dns-message")
            .header("x-forwarded-for", "garbage")
            .body(payload.clone()),
    ] {
        assert_eq!(
            request.send().await.unwrap().status(),
            reqwest::StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        client
            .get(format!("http://{addr}/missing"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    task.abort();
}

#[tokio::test]
#[cfg(feature = "full")]
async fn https_listener_supports_http2_and_validates_tls_certificates() {
    let (_temporary, cert, key) = pem_fixture();
    let config = tls::load_tls_config(&cert, &key, &[b"h2", b"http/1.1"]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let routes = http::Routes {
        engine: test_engine(),
        entries: vec![("/dns-query".into(), "main".into())],
        src_ip_header: String::new(),
        limit: Arc::new(Semaphore::new(MAX_QUERIES)),
    };
    let task = tokio::spawn(http::serve_http_listener(
        listener,
        routes,
        Some(config),
        Duration::from_secs(2),
    ));
    let url = format!("https://{addr}/dns-query");
    assert!(reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(&url)
        .send()
        .await
        .is_err());
    let client = reqwest::Client::builder()
        .no_proxy()
        .http2_prior_knowledge()
        .add_root_certificate(
            reqwest::Certificate::from_der(include_bytes!(
                "../upstream/fixtures/localhost-cert.der"
            ))
            .unwrap(),
        )
        .build()
        .unwrap();
    let response = client
        .post(&url)
        .header("content-type", "application/dns-message")
        .body(query(22).to_vec().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    assert_eq!(
        Message::from_vec(&response.bytes().await.unwrap())
            .unwrap()
            .id(),
        22
    );
    task.abort();
}

#[tokio::test]
#[cfg(feature = "full")]
async fn tls_dns_listener_passes_sni_to_sequence_matching() {
    let (_temporary, cert, key) = pem_fixture();
    let config = tls::load_tls_config(&cert, &key, &[b"dot"]).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let engine = test_engine();
    let server = tokio::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(stream)
            .await
            .unwrap();
        let name = stream.get_ref().1.server_name().unwrap().to_owned();
        let handler: Handler = Arc::new(move |query, client| {
            let engine = engine.clone();
            let name = name.clone();
            Box::pin(async move {
                engine
                    .handle_with_client_meta(query, client, "main", None, Some(&name))
                    .await
            })
        });
        serve_dns_connection(
            stream,
            Some(peer.ip()),
            handler,
            Arc::new(Semaphore::new(MAX_QUERIES)),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    });
    let tcp = TcpStream::connect(addr).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(trusted_tls_client())
        .connect(
            rustls::pki_types::ServerName::try_from("dns.test.invalid").unwrap(),
            tcp,
        )
        .await
        .unwrap();
    let payload = query(24).to_vec().unwrap();
    tls.write_u16(payload.len() as u16).await.unwrap();
    tls.write_all(&payload).await.unwrap();
    tls.flush().await.unwrap();
    let length = tls.read_u16().await.unwrap();
    let mut payload = vec![0; length as usize];
    tls.read_exact(&mut payload).await.unwrap();
    let response = Message::from_vec(&payload).unwrap();
    assert_eq!(response.id(), 24);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    drop(tls);
    server.await.unwrap();
}

#[tokio::test]
#[cfg(feature = "full")]
async fn quic_listener_obeys_dns_id_zero_and_one_frame_per_stream() {
    let (_temporary, cert, key) = pem_fixture();
    let tls = tls::load_tls_config(&cert, &key, &[b"doq"]).unwrap();
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls.as_ref().clone()).unwrap(),
    ));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let task = tokio::spawn(quic::serve_quic_endpoint(
        endpoint,
        test_engine(),
        "main".into(),
        Duration::from_secs(2),
    ));
    let mut tls = trusted_tls_client().as_ref().clone();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
    ));
    let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    endpoint.set_default_client_config(config);
    let connection = endpoint
        .connect(addr, "dns.test.invalid")
        .unwrap()
        .await
        .unwrap();
    for _ in 0..3 {
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        let payload = query(0).to_vec().unwrap();
        let mut frame = (payload.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&payload);
        send.write_all(&frame).await.unwrap();
        send.finish().unwrap();
        let frame = recv.read_to_end(65537).await.unwrap();
        assert_eq!(
            u16::from_be_bytes([frame[0], frame[1]]) as usize,
            frame.len() - 2
        );
        let response = Message::from_vec(&frame[2..]).unwrap();
        assert_eq!(response.id(), 0);
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }
    let (mut send, mut receive) = connection.open_bi().await.unwrap();
    let payload = query(55).to_vec().unwrap();
    let mut frame = (payload.len() as u16).to_be_bytes().to_vec();
    frame.extend_from_slice(&payload);
    send.write_all(&frame).await.unwrap();
    send.finish().unwrap();
    assert!(
        receive.read_to_end(65537).await.is_err(),
        "nonzero DoQ ID must close the connection"
    );
    task.abort();
}
