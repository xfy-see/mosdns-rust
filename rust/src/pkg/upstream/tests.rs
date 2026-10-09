use super::*;
use hickory_proto::{
    op::Query,
    rr::{rdata::A, Name, RData, Record, RecordType},
};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

fn query(id: u16, name: &str) -> Message {
    let mut message = Message::new();
    message
        .set_id(id)
        .set_recursion_desired(true)
        .add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    message
}

fn answer(query: &Message) -> Message {
    let mut response = query.clone();
    response
        .set_message_type(MessageType::Response)
        .set_recursion_available(true);
    response.add_answer(Record::from_rdata(
        query.queries()[0].name().clone(),
        60,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 1))),
    ));
    response
}

#[tokio::test]
async fn udp_reuses_socket_with_identical_client_ids_and_reordered_responses() {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let sources = Arc::new(Mutex::new(HashSet::<SocketAddr>::new()));
    let server_sources = sources.clone();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        for index in 0..100 {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            server_sources.lock().unwrap().insert(peer);
            let message = Message::from_vec(&buffer[..length]).unwrap();
            let response = answer(&message).to_vec().unwrap();
            let socket = socket.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis((index % 5) as u64)).await;
                socket.send_to(&response, peer).await.unwrap();
            });
        }
    });
    let upstream = Upstream::new(&format!("udp://{addr}"), Duration::from_secs(2)).unwrap();
    let mut queries = tokio::task::JoinSet::new();
    for index in 0..100 {
        let upstream = upstream.clone();
        queries.spawn(async move {
            let request = query(42, &format!("host-{index}.example."));
            let response = upstream.exchange(&request).await.unwrap();
            assert_eq!(response.id(), 42);
            assert_eq!(response.queries(), request.queries());
            assert_eq!(response.answers().len(), 1);
        });
    }
    while let Some(result) = queries.join_next().await {
        result.unwrap();
    }
    server.await.unwrap();
    assert_eq!(
        sources.lock().unwrap().len(),
        1,
        "queries should share one UDP socket"
    );
}

#[tokio::test]
async fn udp_retransmits_a_dropped_first_packet_with_the_same_id_and_socket() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
        // Deterministic packet loss: consume the first datagram without replying.
        let first = buffer[..length].to_vec();
        let sent = tokio::time::Instant::now();
        let (length, retry_peer) =
            tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
                .await
                .expect("UDP query must be retransmitted before its deadline")
                .unwrap();
        assert!(sent.elapsed() >= Duration::from_millis(900));
        assert_eq!(retry_peer, peer);
        assert_eq!(&buffer[..length], first.as_slice());
        let response = answer(&Message::from_vec(&buffer[..length]).unwrap());
        socket
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(1100), socket.recv_from(&mut buffer),)
                .await
                .is_err(),
            "completed UDP query must stop retransmitting"
        );
    });
    let upstream = Upstream::new(&format!("udp://{address}"), Duration::from_secs(3)).unwrap();
    let request = query(65535, "dropped-first.example.");
    let response = upstream.exchange(&request).await.unwrap();
    assert_eq!(response.id(), request.id());
    assert_eq!(response.queries(), request.queries());
    assert_eq!(response.answers().len(), 1);
    server.await.unwrap();
}

#[tokio::test]
async fn tcp_pipeline_reuses_connection_and_handles_fragmented_reordered_frames() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted = connections.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        accepted.fetch_add(1, Ordering::Relaxed);
        let (mut read, mut write) = stream.into_split();
        let mut responses = Vec::new();
        for _ in 0..32 {
            let length = read.read_u16().await.unwrap();
            let mut payload = vec![0; length as usize];
            read.read_exact(&mut payload).await.unwrap();
            responses.push(
                answer(&Message::from_vec(&payload).unwrap())
                    .to_vec()
                    .unwrap(),
            );
        }
        // Respond in reverse query order and deliberately fragment the length
        // prefix and body: socket reads do not correspond to DNS frames.
        for payload in responses.into_iter().rev() {
            let length = (payload.len() as u16).to_be_bytes();
            write.write_all(&length[..1]).await.unwrap();
            write.write_all(&length[1..]).await.unwrap();
            for chunk in payload.chunks(3) {
                write.write_all(chunk).await.unwrap();
            }
        }
        // Keep the connection alive for a later sequential exchange.
        let length = read.read_u16().await.unwrap();
        let mut payload = vec![0; length as usize];
        read.read_exact(&mut payload).await.unwrap();
        let payload = answer(&Message::from_vec(&payload).unwrap())
            .to_vec()
            .unwrap();
        write.write_u16(payload.len() as u16).await.unwrap();
        write.write_all(&payload).await.unwrap();
    });
    let upstream =
        Upstream::new(&format!("tcp+pipeline://{addr}"), Duration::from_secs(2)).unwrap();
    let mut queries = tokio::task::JoinSet::new();
    for index in 0..32 {
        let upstream = upstream.clone();
        queries.spawn(async move {
            let request = query(1, &format!("host-{index}.example."));
            let response = upstream.exchange(&request).await.unwrap();
            assert_eq!(response.id(), 1);
            assert_eq!(response.queries(), request.queries());
        });
    }
    while let Some(result) = queries.join_next().await {
        result.unwrap();
    }
    upstream
        .exchange(&query(8, "later.example."))
        .await
        .unwrap();
    server.await.unwrap();
    assert_eq!(connections.load(Ordering::Relaxed), 1);
}

async fn read_pipeline_query<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Message {
    let length = stream.read_u16().await.unwrap();
    let mut payload = vec![0; length as usize];
    stream.read_exact(&mut payload).await.unwrap();
    Message::from_vec(&payload).unwrap()
}

async fn reply_pipeline_query<S: tokio::io::AsyncWrite + Unpin>(stream: &mut S, query: &Message) {
    let payload = answer(query).to_vec().unwrap();
    stream.write_u16(payload.len() as u16).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();
}

async fn pipeline_close_after_reused_query<
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
>(
    mut stream: S,
) {
    let warmup = read_pipeline_query(&mut stream).await;
    reply_pipeline_query(&mut stream, &warmup).await;
    let reused = read_pipeline_query(&mut stream).await;
    assert_eq!(
        reused.queries()[0].name().to_ascii(),
        "retry-current.example."
    );
    // Close after the reused query is sent, so checking a dead socket before
    // reservation cannot accidentally make this test pass without a retry.
}

#[tokio::test]
#[cfg(feature = "full")]
async fn pipeline_retries_the_current_query_after_reused_tcp_or_tls_eof() {
    for protocol in ["tcp", "tls"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (old, _) = listener.accept().await.unwrap();
            if protocol == "tcp" {
                pipeline_close_after_reused_query(old).await;
            } else {
                let old = tokio_rustls::TlsAcceptor::from(tls_server_config())
                    .accept(old)
                    .await
                    .unwrap();
                pipeline_close_after_reused_query(old).await;
            }
            let (new, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .expect("failed old socket must reconnect for the same query")
                .unwrap();
            if protocol == "tcp" {
                let mut new = new;
                let retried = read_pipeline_query(&mut new).await;
                assert_eq!(
                    retried.queries()[0].name().to_ascii(),
                    "retry-current.example."
                );
                reply_pipeline_query(&mut new, &retried).await;
            } else {
                let mut new = tokio_rustls::TlsAcceptor::from(tls_server_config())
                    .accept(new)
                    .await
                    .unwrap();
                let retried = read_pipeline_query(&mut new).await;
                assert_eq!(
                    retried.queries()[0].name().to_ascii(),
                    "retry-current.example."
                );
                reply_pipeline_query(&mut new, &retried).await;
            }
        });
        let upstream = if protocol == "tcp" {
            Upstream::new(&format!("tcp+pipeline://{address}"), Duration::from_secs(2)).unwrap()
        } else {
            Upstream {
                inner: Arc::new(Inner {
                    backend: Backend::Traditional {
                        transport: Transport::with_tls_config(
                            "127.0.0.1".into(),
                            address.port(),
                            tls_client_config(),
                            true,
                        ),
                        tcp_fallback: None,
                    },
                    timeout: Duration::from_secs(2),
                    events: events::Lifecycle::default(),
                }),
            }
        };
        upstream
            .exchange(&query(1, "warmup.example."))
            .await
            .unwrap();
        let request = query(65535, "retry-current.example.");
        let response = upstream
            .exchange(&request)
            .await
            .expect("reused connection EOF must not fail this query");
        assert_eq!(response.id(), request.id());
        assert_eq!(response.queries(), request.queries());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn pipeline_does_not_retry_a_new_connection_failure() {
    for after_old_failure in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            if after_old_failure {
                let (old, _) = listener.accept().await.unwrap();
                pipeline_close_after_reused_query(old).await;
            }
            let (mut stream, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .unwrap()
                .unwrap();
            read_pipeline_query(&mut stream).await;
            drop(stream);
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "a new connection failure must be returned without another dial"
            );
        });
        let upstream =
            Upstream::new(&format!("tcp+pipeline://{address}"), Duration::from_secs(2)).unwrap();
        if after_old_failure {
            upstream
                .exchange(&query(1, "warmup.example."))
                .await
                .unwrap();
        }
        assert!(upstream
            .exchange(&query(42, "retry-current.example."))
            .await
            .is_err());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn pipeline_does_not_retry_a_dns_validation_error_on_a_live_old_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let warmup = read_pipeline_query(&mut stream).await;
        reply_pipeline_query(&mut stream, &warmup).await;
        let request = read_pipeline_query(&mut stream).await;
        let mut invalid = answer(&request);
        invalid.queries_mut().clear();
        invalid.add_query(Query::query(
            Name::from_ascii("wrong-question.example.").unwrap(),
            RecordType::A,
        ));
        let payload = invalid.to_vec().unwrap();
        stream.write_u16(payload.len() as u16).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        // The next frame must be the caller's next distinct query, not a
        // hidden resend of the invalid response's query.
        let next = read_pipeline_query(&mut stream).await;
        assert_eq!(
            next.queries()[0].name().to_ascii(),
            "after-invalid.example."
        );
        reply_pipeline_query(&mut stream, &next).await;
    });
    let upstream =
        Upstream::new(&format!("tcp+pipeline://{address}"), Duration::from_secs(1)).unwrap();
    upstream
        .exchange(&query(1, "warmup.example."))
        .await
        .unwrap();
    let error = upstream
        .exchange(&query(2, "invalid.example."))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("question mismatch"), "{error:#}");
    upstream
        .exchange(&query(3, "after-invalid.example."))
        .await
        .unwrap();
    server.await.unwrap();
}

#[cfg(feature = "full")]
async fn legacy_dns_stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    mut stream: S,
    first_batch: Arc<tokio::sync::Barrier>,
    wait_for_first_batch: bool,
) {
    let mut first = true;
    while let Ok(length) = stream.read_u16().await {
        let mut payload = vec![0; length as usize];
        stream.read_exact(&mut payload).await.unwrap();
        if first && wait_for_first_batch {
            // Every initial query must occupy a different connection. No
            // response is released until all connections have a query.
            first_batch.wait().await;
        }
        first = false;
        let payload = answer(&Message::from_vec(&payload).unwrap())
            .to_vec()
            .unwrap();
        stream.write_u16(payload.len() as u16).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        stream.flush().await.unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "full")]
async fn tcp_and_tls_without_pipeline_use_parallel_exclusive_connections_then_reuse_them() {
    for protocol in ["tcp", "tls"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let accepted = connections.clone();
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            tokio::pin!(stopped);
            let mut workers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    result = listener.accept() => {
                        let (stream, _) = result.unwrap();
                        let first_batch = accepted.fetch_add(1, Ordering::Relaxed) < 8;
                        let barrier = barrier.clone();
                        workers.spawn(async move {
                            if protocol == "tcp" {
                                legacy_dns_stream(stream, barrier, first_batch).await;
                            } else {
                                let tls = tokio_rustls::TlsAcceptor::from(tls_server_config()).accept(stream).await.unwrap();
                                legacy_dns_stream(tls, barrier, first_batch).await;
                            }
                        });
                    }
                }
            }
            workers.abort_all();
            while workers.join_next().await.is_some() {}
        });
        let upstream = Upstream::new_with_options(
            &format!("{protocol}://{address}"),
            Duration::from_secs(3),
            Options {
                insecure_skip_verify: true,
                enable_pipeline: false,
                ..Default::default()
            },
        )
        .unwrap();
        let responses = futures::future::join_all((0..8).map(|id| {
            let request = query(id, &format!("exclusive-{id}.example."));
            let upstream = &upstream;
            async move { upstream.exchange(&request).await.unwrap() }
        }))
        .await;
        for (id, response) in responses.iter().enumerate() {
            assert_eq!(response.id(), id as u16);
        }
        assert_eq!(connections.load(Ordering::Relaxed), 8);
        for id in 8..12 {
            assert_eq!(
                upstream
                    .exchange(&query(id, "reused.example."))
                    .await
                    .unwrap()
                    .id(),
                id
            );
        }
        assert_eq!(
            connections.load(Ordering::Relaxed),
            8,
            "completed connections must enter the idle pool"
        );
        stop.send(()).unwrap();
        server.await.unwrap();
    }
}

#[tokio::test]
async fn cancelled_or_timed_out_nonpipeline_query_closes_its_exclusive_connection() {
    for cancel in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (received, receive) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let length = first.read_u16().await.unwrap();
            let mut buffer = vec![0; length as usize];
            first.read_exact(&mut buffer).await.unwrap();
            received.send(()).unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), first.read_u8())
                    .await
                    .unwrap()
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::UnexpectedEof
            );
            let (mut second, _) = listener.accept().await.unwrap();
            let length = second.read_u16().await.unwrap();
            let mut buffer = vec![0; length as usize];
            second.read_exact(&mut buffer).await.unwrap();
            let payload = answer(&Message::from_vec(&buffer).unwrap())
                .to_vec()
                .unwrap();
            second.write_u16(payload.len() as u16).await.unwrap();
            second.write_all(&payload).await.unwrap();
        });
        let upstream =
            Upstream::new(&format!("tcp://{address}"), Duration::from_millis(300)).unwrap();
        let client = upstream.clone();
        let first =
            tokio::spawn(async move { client.exchange(&query(1, "cancelled.example.")).await });
        receive.await.unwrap();
        if cancel {
            first.abort();
            assert!(first.await.unwrap_err().is_cancelled());
        } else {
            assert!(first.await.unwrap().is_err());
        }
        assert_eq!(
            upstream
                .exchange(&query(2, "after-cancel.example."))
                .await
                .unwrap()
                .id(),
            2
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn a_failed_reused_connection_retries_with_a_new_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut old, _) = listener.accept().await.unwrap();
        for response in [true, false] {
            let length = old.read_u16().await.unwrap();
            let mut payload = vec![0; length as usize];
            old.read_exact(&mut payload).await.unwrap();
            if response {
                let payload = answer(&Message::from_vec(&payload).unwrap())
                    .to_vec()
                    .unwrap();
                old.write_u16(payload.len() as u16).await.unwrap();
                old.write_all(&payload).await.unwrap();
            }
        }
        // Close only after receiving the second query. This forces failure
        // during reuse, rather than filtering an already-dead idle socket.
        drop(old);
        let (mut new, _) = listener.accept().await.unwrap();
        let length = new.read_u16().await.unwrap();
        let mut payload = vec![0; length as usize];
        new.read_exact(&mut payload).await.unwrap();
        let payload = answer(&Message::from_vec(&payload).unwrap())
            .to_vec()
            .unwrap();
        new.write_u16(payload.len() as u16).await.unwrap();
        new.write_all(&payload).await.unwrap();
    });
    let upstream = Upstream::new(&format!("tcp://{address}"), Duration::from_secs(2)).unwrap();
    upstream
        .exchange(&query(1, "first-reuse.example."))
        .await
        .unwrap();
    assert_eq!(
        upstream
            .exchange(&query(2, "failed-reuse.example."))
            .await
            .unwrap()
            .id(),
        2
    );
    server.await.unwrap();
}

#[tokio::test]
async fn udp_truncation_falls_back_to_tcp_with_original_question() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(addr).await.unwrap();
    let udp_server = tokio::spawn(async move {
        let mut payload = [0; 4096];
        let (length, peer) = udp.recv_from(&mut payload).await.unwrap();
        let mut response = Message::from_vec(&payload[..length]).unwrap();
        response
            .set_message_type(MessageType::Response)
            .set_truncated(true);
        udp.send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let tcp_server = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut payload = vec![0; length as usize];
        stream.read_exact(&mut payload).await.unwrap();
        let request = Message::from_vec(&payload).unwrap();
        assert_eq!(request.queries()[0].name().to_ascii(), "large.example.");
        let payload = answer(&request).to_vec().unwrap();
        stream.write_u16(payload.len() as u16).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });
    let upstream = Upstream::new(&format!("udp://{addr}"), Duration::from_secs(1)).unwrap();
    let response = upstream
        .exchange(&query(65535, "large.example."))
        .await
        .unwrap();
    assert_eq!(response.id(), 65535);
    assert!(!response.truncated());
    assert_eq!(response.answers().len(), 1);
    udp_server.await.unwrap();
    tcp_server.await.unwrap();
}

#[tokio::test]
async fn invalid_udp_response_is_rejected() {
    for malformed in ["wire", "question", "qr", "id"] {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let mut response = answer(&Message::from_vec(&buffer[..length]).unwrap());
            let payload = match malformed {
                "wire" => vec![buffer[0], buffer[1], 0x80],
                "question" => {
                    response.queries_mut()[0] =
                        Query::query(Name::from_ascii("wrong.example.").unwrap(), RecordType::A);
                    response.to_vec().unwrap()
                }
                "qr" => {
                    response.set_message_type(MessageType::Query);
                    response.to_vec().unwrap()
                }
                "id" => {
                    response.set_id(response.id().wrapping_add(1));
                    response.to_vec().unwrap()
                }
                _ => unreachable!(),
            };
            socket.send_to(&payload, peer).await.unwrap();
            // Keep UDP socket open so mismatched-ID test reaches the timeout.
            tokio::time::sleep(Duration::from_millis(150)).await;
        });
        let upstream = Upstream::new(&format!("udp://{addr}"), Duration::from_millis(80)).unwrap();
        assert!(
            upstream.exchange(&query(12, "example.")).await.is_err(),
            "accepted {malformed}"
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn tcp_incomplete_frame_fails_without_hanging() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let length = stream.read_u16().await.unwrap();
        let mut query = vec![0; length as usize];
        stream.read_exact(&mut query).await.unwrap();
        stream.write_u16(100).await.unwrap();
        stream.write_all(&[0; 3]).await.unwrap();
    });
    let upstream = Upstream::new(&format!("tcp://{addr}"), Duration::from_secs(1)).unwrap();
    assert!(upstream.exchange(&query(12, "example.")).await.is_err());
    server.await.unwrap();
}

#[test]
#[cfg(feature = "full")]
fn upstream_address_validation_is_explicit() {
    let timeout = Duration::from_secs(1);
    for address in [
        "127.0.0.1",
        "udp://[::1]:53",
        "tcp+pipeline://127.0.0.1:53",
        "tls://dns.example",
        "https://dns.example/dns-query",
        "quic://127.0.0.1",
        "doq://127.0.0.1",
        "h3://dns.example",
    ] {
        assert!(Upstream::new(address, timeout).is_ok(), "{address}");
    }
    for address in [
        "doq-invalid://127.0.0.1",
        "http://dns.example",
        "udp://127.0.0.1:0",
        "udp://127.0.0.1/path",
    ] {
        assert!(Upstream::new(address, timeout).is_err(), "{address}");
    }
    assert!(Upstream::new("127.0.0.1", Duration::ZERO).is_err());
}

// A disposable certificate/key pair committed only for local mock servers.
// The certificate names 127.0.0.1 and is never used outside tests.
#[cfg(feature = "full")]
const LOCAL_CERT: &[u8] = include_bytes!("fixtures/localhost-cert.der");
#[cfg(feature = "full")]
const LOCAL_KEY: &[u8] = include_bytes!("fixtures/localhost-key.der");

#[cfg(feature = "full")]
fn tls_server_config() -> Arc<rustls::ServerConfig> {
    let certificate = rustls::pki_types::CertificateDer::from(LOCAL_CERT.to_vec());
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(LOCAL_KEY.to_vec());
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key.into())
        .unwrap(),
    )
}

#[cfg(feature = "full")]
fn tls_client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(LOCAL_CERT.to_vec()))
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
async fn dot_uses_verified_tls_and_reuses_a_pipelined_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(tls_server_config())
            .accept(stream)
            .await
            .unwrap();
        let mut replies = Vec::new();
        for _ in 0..10 {
            let length = tls.read_u16().await.unwrap();
            let mut payload = vec![0; length as usize];
            tls.read_exact(&mut payload).await.unwrap();
            replies.push(
                answer(&Message::from_vec(&payload).unwrap())
                    .to_vec()
                    .unwrap(),
            );
        }
        for payload in replies.into_iter().rev() {
            tls.write_u16(payload.len() as u16).await.unwrap();
            tls.write_all(&payload).await.unwrap();
        }
        tls.flush().await.unwrap();
    });
    let transport = Transport::with_tls_config(
        "127.0.0.1".to_owned(),
        addr.port(),
        tls_client_config(),
        true,
    );
    let upstream = Upstream {
        inner: Arc::new(Inner {
            backend: Backend::Traditional {
                transport,
                tcp_fallback: None,
            },
            timeout: Duration::from_secs(2),
            events: events::Lifecycle::default(),
        }),
    };
    let mut tasks = tokio::task::JoinSet::new();
    for index in 0..10 {
        let upstream = upstream.clone();
        tasks.spawn(async move {
            let request = query(99, &format!("tls-{index}.example."));
            let response = upstream.exchange(&request).await.unwrap();
            assert_eq!(response.id(), 99);
            assert_eq!(response.queries(), request.queries());
        });
    }
    while let Some(result) = tasks.join_next().await {
        result.unwrap();
    }
    server.await.unwrap();
}

#[tokio::test]
#[cfg(feature = "full")]
async fn dot_rejects_an_untrusted_certificate() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let result = tokio_rustls::TlsAcceptor::from(tls_server_config())
            .accept(stream)
            .await;
        assert!(result.is_err());
    });
    let upstream = Upstream::new(&format!("tls://{addr}"), Duration::from_secs(2)).unwrap();
    let error = upstream.exchange(&query(12, "example.")).await.unwrap_err();
    assert!(format!("{error:#}").contains("TLS handshake"));
    server.await.unwrap();
}

#[tokio::test]
#[cfg(feature = "full")]
async fn dot_rejects_a_trusted_certificate_with_wrong_name() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        assert!(tokio_rustls::TlsAcceptor::from(tls_server_config())
            .accept(stream)
            .await
            .is_err());
    });
    let transport = Transport::with_tls_config(
        "localhost".to_owned(),
        addr.port(),
        tls_client_config(),
        false,
    );
    let upstream = Upstream {
        inner: Arc::new(Inner {
            backend: Backend::Traditional {
                transport,
                tcp_fallback: None,
            },
            timeout: Duration::from_secs(2),
            events: events::Lifecycle::default(),
        }),
    };
    assert!(format!(
        "{:#}",
        upstream.exchange(&query(12, "example.")).await.unwrap_err()
    )
    .contains("TLS handshake"));
    server.await.unwrap();
}

#[cfg(feature = "full")]
async fn read_http_query<S: tokio::io::AsyncRead + Unpin>(read: &mut S) -> Message {
    read_http_query_and_headers(read).await.0
}

#[cfg(feature = "full")]
async fn read_http_query_and_headers<S: tokio::io::AsyncRead + Unpin>(
    read: &mut S,
) -> (Message, String) {
    read_http_query_and_headers_at_path(read, "/dns-query").await
}

#[cfg(feature = "full")]
async fn read_http_query_and_headers_at_path<S: tokio::io::AsyncRead + Unpin>(
    read: &mut S,
    path: &str,
) -> (Message, String) {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(read.read_u8().await.unwrap());
        assert!(headers.len() < 8192);
    }
    let headers = String::from_utf8(headers).unwrap().to_ascii_lowercase();
    assert!(headers.starts_with(&format!("post {path} http/1.1\r\n")));
    assert!(headers.contains("content-type: application/dns-message\r\n"));
    assert!(headers.contains("accept: application/dns-message\r\n"));
    let length: usize = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .unwrap()
        .parse()
        .unwrap();
    let mut payload = vec![0; length];
    read.read_exact(&mut payload).await.unwrap();
    (Message::from_vec(&payload).unwrap(), headers)
}

#[tokio::test]
#[cfg(feature = "full")]
async fn doh_preserves_a_root_endpoint_path_with_direct_and_custom_dialers() {
    for custom in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(tls_server_config())
                .accept(stream)
                .await
                .unwrap();
            let (request, _) = read_http_query_and_headers_at_path(&mut tls, "/").await;
            let payload = answer(&request).to_vec().unwrap();
            let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", payload.len());
            tls.write_all(headers.as_bytes()).await.unwrap();
            tls.write_all(&payload).await.unwrap();
            tls.flush().await.unwrap();
        });
        let url = if custom {
            "https://192.0.2.1:8443/".to_owned()
        } else {
            format!("https://{address}/")
        };
        let upstream = Upstream::new_with_options(
            &url,
            Duration::from_secs(2),
            Options {
                dial_addr: if custom {
                    address.to_string()
                } else {
                    String::new()
                },
                insecure_skip_verify: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            upstream
                .exchange(&query(31, "root-doh.example."))
                .await
                .unwrap()
                .id(),
            31
        );
        server.await.unwrap();
    }
}

#[cfg(feature = "full")]
fn local_doh_upstream(addr: SocketAddr) -> Upstream {
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_der(LOCAL_CERT).unwrap())
        .build()
        .unwrap();
    Upstream {
        inner: Arc::new(Inner {
            backend: Backend::Https {
                client: Mutex::new(Some(client)),
                url: Url::parse(&format!("https://{addr}/dns-query")).unwrap(),
                host_header: None,
            },
            timeout: Duration::from_secs(2),
            events: events::Lifecycle::default(),
        }),
    }
}

#[tokio::test]
#[cfg(feature = "full")]
async fn doh_posts_rfc8484_messages_and_reuses_https_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(tls_server_config())
            .accept(stream)
            .await
            .unwrap();
        for _ in 0..8 {
            let request = read_http_query(&mut tls).await;
            let payload = answer(&request).to_vec().unwrap();
            let headers = format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", payload.len());
            tls.write_all(headers.as_bytes()).await.unwrap();
            tls.write_all(&payload).await.unwrap();
            tls.flush().await.unwrap();
        }
    });
    let upstream = local_doh_upstream(addr);
    for index in 0..8 {
        let request = query(index, &format!("doh-{index}.example."));
        let response = upstream.exchange(&request).await.unwrap();
        assert_eq!(response.id(), index);
        assert_eq!(response.queries(), request.queries());
    }
    server.await.unwrap();
}

#[tokio::test]
#[cfg(feature = "full")]
async fn doh_rejects_bad_status_mime_oversized_and_mismatched_dns() {
    for mode in ["status", "mime", "oversized", "id"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(tls_server_config())
                .accept(stream)
                .await
                .unwrap();
            let query = read_http_query(&mut tls).await;
            let mut response = answer(&query);
            if mode == "id" {
                response.set_id(query.id().wrapping_add(1));
            }
            let payload = response.to_vec().unwrap();
            let status = if mode == "status" {
                "500 Internal Server Error"
            } else {
                "200 OK"
            };
            let mime = if mode == "mime" {
                "text/html"
            } else {
                "application/dns-message"
            };
            let length = if mode == "oversized" {
                65536
            } else {
                payload.len()
            };
            let headers = format!(
                "HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {length}\r\n\r\n"
            );
            tls.write_all(headers.as_bytes()).await.unwrap();
            tls.write_all(&payload).await.unwrap();
            tls.flush().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;
        });
        let upstream = local_doh_upstream(addr);
        assert!(
            upstream.exchange(&query(12, "example.")).await.is_err(),
            "accepted DoH {mode}"
        );
        server.await.unwrap();
    }
}

#[tokio::test]
#[cfg(feature = "full")]
async fn doq_reuses_connection_and_restores_ids_across_concurrent_streams() {
    let mut tls = tls_server_config().as_ref().clone();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let addr = endpoint.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let mut streams = tokio::task::JoinSet::new();
        for _ in 0..32 {
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            streams.spawn(async move {
                let frame = receive.read_to_end(65537).await.unwrap();
                assert_eq!(
                    u16::from_be_bytes([frame[0], frame[1]]) as usize,
                    frame.len() - 2
                );
                let request = Message::from_vec(&frame[2..]).unwrap();
                assert_eq!(request.id(), 0);
                let payload = answer(&request).to_vec().unwrap();
                let mut frame = (payload.len() as u16).to_be_bytes().to_vec();
                frame.extend_from_slice(&payload);
                send.write_all(&frame).await.unwrap();
                send.finish().unwrap();
                let _ = send.stopped().await;
            });
        }
        while let Some(result) = streams.join_next().await {
            result.unwrap();
        }
    });
    let backend = quic::QuicUpstream::with_tls_config(
        "127.0.0.1".into(),
        addr.port(),
        tls_client_config().as_ref().clone(),
    )
    .unwrap();
    let upstream = Upstream {
        inner: Arc::new(Inner {
            backend: Backend::Quic(backend),
            timeout: Duration::from_secs(2),
            events: events::Lifecycle::default(),
        }),
    };
    let mut queries = tokio::task::JoinSet::new();
    for index in 0..32 {
        let upstream = upstream.clone();
        queries.spawn(async move {
            let request = query(index, &format!("doq-{index}.example."));
            let response = upstream.exchange(&request).await.unwrap();
            assert_eq!(response.id(), index);
            assert_eq!(response.queries(), request.queries());
        });
    }
    while let Some(result) = queries.join_next().await {
        result.unwrap();
    }
    server.await.unwrap();
}

#[tokio::test]
async fn dial_addr_routes_udp_without_resolving_the_original_host() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut payload = [0; 4096];
        let (length, peer) = socket.recv_from(&mut payload).await.unwrap();
        let response = answer(&Message::from_vec(&payload[..length]).unwrap())
            .to_vec()
            .unwrap();
        socket.send_to(&response, peer).await.unwrap();
    });
    let options = Options {
        dial_addr: addr.to_string(),
        ..Options::default()
    };
    let upstream = Upstream::new_with_options(
        "udp://unresolvable.invalid:5353",
        Duration::from_secs(1),
        options,
    )
    .unwrap();
    assert_eq!(
        upstream
            .exchange(&query(14, "example."))
            .await
            .unwrap()
            .id(),
        14
    );
    server.await.unwrap();
}

#[tokio::test]
async fn configured_upstream_idle_timeout_closes_and_reconnects_tcp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for index in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap();
            let mut payload = vec![0; length as usize];
            stream.read_exact(&mut payload).await.unwrap();
            let response = answer(&Message::from_vec(&payload).unwrap())
                .to_vec()
                .unwrap();
            stream.write_u16(response.len() as u16).await.unwrap();
            stream.write_all(&response).await.unwrap();
            if index == 0 {
                let mut byte = [0];
                assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
            }
        }
    });
    let options = Options {
        idle_timeout: Duration::from_millis(30),
        ..Options::default()
    };
    let upstream =
        Upstream::new_with_options(&format!("tcp://{addr}"), Duration::from_secs(1), options)
            .unwrap();
    upstream
        .exchange(&query(1, "first.example."))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(75)).await;
    upstream
        .exchange(&query(2, "second.example."))
        .await
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
#[cfg(feature = "full")]
async fn explicit_tls_skip_verify_and_dial_override_retain_original_sni() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(tls_server_config())
            .accept(stream)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some("dns.test.invalid"));
        let length = tls.read_u16().await.unwrap();
        let mut payload = vec![0; length as usize];
        tls.read_exact(&mut payload).await.unwrap();
        let payload = answer(&Message::from_vec(&payload).unwrap())
            .to_vec()
            .unwrap();
        tls.write_u16(payload.len() as u16).await.unwrap();
        tls.write_all(&payload).await.unwrap();
        tls.flush().await.unwrap();
    });
    let options = Options {
        dial_addr: addr.to_string(),
        insecure_skip_verify: true,
        ..Options::default()
    };
    let upstream = Upstream::new_with_options(
        "tls://dns.test.invalid:853",
        Duration::from_secs(1),
        options,
    )
    .unwrap();
    assert_eq!(
        upstream
            .exchange(&query(16, "example."))
            .await
            .unwrap()
            .id(),
        16
    );
    server.await.unwrap();
}

#[tokio::test]
#[cfg(feature = "full")]
async fn doh_dial_override_retains_original_tls_name_and_http_host_port() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(tls_server_config())
            .accept(stream)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some("dns.test.invalid"));
        let (query, headers) = read_http_query_and_headers(&mut tls).await;
        assert!(headers.contains("host: dns.test.invalid:8443\r\n"));
        let payload = answer(&query).to_vec().unwrap();
        tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",payload.len()).as_bytes()).await.unwrap();
        tls.write_all(&payload).await.unwrap();
        tls.flush().await.unwrap();
    });
    let options = Options {
        dial_addr: addr.to_string(),
        insecure_skip_verify: true,
        ..Options::default()
    };
    let upstream = Upstream::new_with_options(
        "https://dns.test.invalid:8443/dns-query",
        Duration::from_secs(1),
        options,
    )
    .unwrap();
    assert_eq!(
        upstream
            .exchange(&query(17, "example."))
            .await
            .unwrap()
            .id(),
        17
    );
    server.await.unwrap();
}
