//! Upstream observer contracts, using loopback peers and real connection reuse.
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{Name, RecordType},
};
use mosdns_rs::pkg::upstream::{Event, EventObserver, Options, QueryOutcome, Upstream};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

#[cfg(feature = "full")]
fn tls_config(alpn: Option<&str>) -> Arc<rustls::ServerConfig> {
    let cert = rustls::pki_types::CertificateDer::from(
        include_bytes!("../src/pkg/upstream/fixtures/localhost-cert.der").to_vec(),
    );
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
        include_bytes!("../src/pkg/upstream/fixtures/localhost-key.der").to_vec(),
    );
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key.into())
    .unwrap();
    if let Some(alpn) = alpn {
        config.alpn_protocols = vec![alpn.as_bytes().to_vec()];
    }
    Arc::new(config)
}

#[derive(Default)]
struct Observer {
    opened: AtomicUsize,
    closed: AtomicUsize,
    started: AtomicUsize,
    outcomes: Mutex<Vec<QueryOutcome>>,
    active: AtomicUsize,
}
impl EventObserver for Observer {
    fn on_event(&self, event: Event) {
        match event {
            Event::ConnOpen => {
                self.opened.fetch_add(1, Ordering::SeqCst);
            }
            Event::ConnClose => {
                self.closed.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    fn query_started(&self) {
        self.started.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_add(1, Ordering::SeqCst);
    }
    fn query_finished(&self, outcome: QueryOutcome, _elapsed: Duration) {
        self.outcomes.lock().unwrap().push(outcome);
        assert!(self.active.fetch_sub(1, Ordering::SeqCst) > 0);
    }
}
impl Observer {
    fn connections(&self, opened: usize, closed: usize) {
        assert_eq!(self.opened.load(Ordering::SeqCst), opened, "opened");
        assert_eq!(self.closed.load(Ordering::SeqCst), closed, "closed");
    }
    fn queries(&self, expected: &[QueryOutcome]) {
        assert_eq!(
            self.started.load(Ordering::SeqCst),
            expected.len(),
            "started"
        );
        assert_eq!(self.outcomes.lock().unwrap().as_slice(), expected);
        assert_eq!(self.active.load(Ordering::SeqCst), 0);
    }
}
fn query(id: u16) -> Message {
    let mut q = Message::new();
    q.set_id(id).add_query(Query::query(
        Name::from_ascii(format!("events-{id}.example.")).unwrap(),
        RecordType::A,
    ));
    q
}
fn answer(mut q: Message) -> Message {
    q.set_message_type(MessageType::Response);
    q
}
async fn read_query<S: AsyncRead + Unpin>(s: &mut S) -> Message {
    let length = s.read_u16().await.unwrap();
    let mut payload = vec![0; usize::from(length)];
    s.read_exact(&mut payload).await.unwrap();
    Message::from_vec(&payload).unwrap()
}
async fn write_answer<S: AsyncWrite + Unpin>(s: &mut S, q: Message) {
    let payload = answer(q).to_vec().unwrap();
    s.write_u16(payload.len() as u16).await.unwrap();
    s.write_all(&payload).await.unwrap();
    s.flush().await.unwrap();
}
fn options(observer: &Arc<Observer>) -> Options {
    Options {
        event_observer: Some(observer.clone()),
        ..Default::default()
    }
}

#[tokio::test]
async fn clones_share_query_observation_and_one_udp_connection_lifecycle() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let mut payload = [0; 4096];
        for _ in 0..8 {
            let (length, peer) = socket.recv_from(&mut payload).await.unwrap();
            socket
                .send_to(
                    &answer(Message::from_vec(&payload[..length]).unwrap())
                        .to_vec()
                        .unwrap(),
                    peer,
                )
                .await
                .unwrap();
        }
    });
    let observer = Arc::new(Observer::default());
    let upstream = Upstream::new_with_options(
        &format!("udp://{address}"),
        Duration::from_secs(1),
        options(&observer),
    )
    .unwrap();
    let mut queries = tokio::task::JoinSet::new();
    for id in 0..8 {
        let clone = upstream.clone();
        queries.spawn(async move { clone.exchange(&query(id)).await.unwrap() });
    }
    while let Some(q) = queries.join_next().await {
        q.unwrap();
    }
    peer.await.unwrap();
    observer.queries(&[QueryOutcome::Success; 8]);
    observer.connections(1, 0);
    upstream.close().await.unwrap();
    upstream.close().await.unwrap();
    observer.connections(1, 1);
}

#[tokio::test]
async fn tcp_idle_expiry_reports_one_close_while_the_upstream_is_still_owned() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let q = read_query(&mut stream).await;
        write_answer(&mut stream, q).await;
        assert!(stream.read_u8().await.is_err());
    });
    let observer = Arc::new(Observer::default());
    let mut opts = options(&observer);
    opts.idle_timeout = Duration::from_millis(30);
    let upstream = Upstream::new_with_options(
        &format!("tcp+pipeline://{address}"),
        Duration::from_secs(1),
        opts,
    )
    .unwrap();
    upstream.exchange(&query(1)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
    observer.connections(1, 1);
    upstream.close().await.unwrap();
    observer.connections(1, 1);
    observer.queries(&[QueryOutcome::Success]);
}

#[tokio::test]
async fn explicit_close_cancels_active_queries_and_rejects_all_clones_idempotently() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, received) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_query(&mut stream).await;
        sent.send(()).unwrap();
        assert!(stream.read_u8().await.is_err());
    });
    let observer = Arc::new(Observer::default());
    let upstream = Upstream::new_with_options(
        &format!("tcp+pipeline://{address}"),
        Duration::from_secs(30),
        options(&observer),
    )
    .unwrap();
    let clone = upstream.clone();
    let task = tokio::spawn(async move { clone.exchange(&query(1)).await });
    received.await.unwrap();
    upstream.close().await.unwrap();
    // The assertion is bounded even with the intentionally missing red wiring.
    let result = tokio::time::timeout(Duration::from_millis(100), task).await;
    assert!(result.is_ok(), "close must wake an active query");
    assert!(result.unwrap().unwrap().is_err());
    assert!(upstream.clone().exchange(&query(2)).await.is_err());
    upstream.close().await.unwrap();
    peer.await.unwrap();
    observer.connections(1, 1);
    observer.queries(&[QueryOutcome::Error; 2]);
}

#[tokio::test]
async fn timeout_and_cancel_balance_queries_and_close_exclusive_tcp_connections() {
    for cancelled in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sent, received) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            read_query(&mut stream).await;
            sent.send(()).unwrap();
            assert!(stream.read_u8().await.is_err());
        });
        let observer = Arc::new(Observer::default());
        let upstream = Upstream::new_with_options(
            &format!("tcp://{address}"),
            if cancelled {
                Duration::from_secs(30)
            } else {
                Duration::from_millis(30)
            },
            options(&observer),
        )
        .unwrap();
        let clone = upstream.clone();
        let task = tokio::spawn(async move { clone.exchange(&query(1)).await });
        received.await.unwrap();
        if cancelled {
            task.abort();
            assert!(task.await.unwrap_err().is_cancelled());
        } else {
            assert!(task
                .await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("timeout"));
        }
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        observer.connections(1, 1);
        observer.queries(&[if cancelled {
            QueryOutcome::Cancelled
        } else {
            QueryOutcome::Error
        }]);
        upstream.close().await.unwrap();
        observer.connections(1, 1);
    }
}

#[tokio::test]
#[cfg(feature = "full")]
async fn tls_success_reports_one_physical_pair_and_handshake_failure_also_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(tls_config(None))
            .accept(stream)
            .await
            .unwrap();
        for _ in 0..2 {
            let q = read_query(&mut stream).await;
            write_answer(&mut stream, q).await;
        }
        assert!(stream.read_u8().await.is_err());
    });
    let observer = Arc::new(Observer::default());
    let mut opts = options(&observer);
    opts.insecure_skip_verify = true;
    let upstream =
        Upstream::new_with_options(&format!("tls://{address}"), Duration::from_secs(1), opts)
            .unwrap();
    for id in 0..2 {
        upstream.exchange(&query(id)).await.unwrap();
    }
    observer.connections(1, 0); // Go's original double wrapping produces 2.
    upstream.close().await.unwrap();
    peer.await.unwrap();
    observer.connections(1, 1);
    observer.queries(&[QueryOutcome::Success; 2]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        drop(listener.accept().await.unwrap());
    });
    let observer = Arc::new(Observer::default());
    let mut opts = options(&observer);
    opts.insecure_skip_verify = true;
    let upstream =
        Upstream::new_with_options(&format!("tls://{address}"), Duration::from_secs(1), opts)
            .unwrap();
    assert!(upstream.exchange(&query(1)).await.is_err());
    peer.await.unwrap();
    observer.connections(1, 1);
    observer.queries(&[QueryOutcome::Error]);
    upstream.close().await.unwrap();
    observer.connections(1, 1);
}

#[tokio::test]
#[cfg(feature = "full")]
async fn cancelled_lazy_tls_slots_report_each_raw_socket_close_exactly_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (hello, mut hellos) = tokio::sync::mpsc::unbounded_channel();
    let peer = tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let hello = hello.clone();
            clients.spawn(async move {
                assert_eq!(stream.read_u8().await.unwrap(), 0x16);
                hello.send(()).unwrap();
                stream.read_to_end(&mut Vec::new()).await.unwrap();
            });
        }
        while let Some(client) = clients.join_next().await {
            client.unwrap();
        }
    });
    let observer = Arc::new(Observer::default());
    let mut opts = options(&observer);
    opts.insecure_skip_verify = true;
    let upstream = Upstream::new_with_options(
        &format!("tls+pipeline://{address}"),
        Duration::from_secs(30),
        opts,
    )
    .unwrap();
    let mut queries = tokio::task::JoinSet::new();
    for id in 0..65 {
        let clone = upstream.clone();
        queries.spawn(async move { clone.exchange(&query(id)).await });
    }
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(1), hellos.recv())
            .await
            .unwrap()
            .unwrap();
    }
    observer.connections(2, 0);
    queries.abort_all();
    while queries.join_next().await.is_some() {}
    peer.await.unwrap();
    observer.connections(2, 2);
    observer.queries(&[QueryOutcome::Cancelled; 65]);
    upstream.close().await.unwrap();
    observer.connections(2, 2);
}

#[tokio::test]
async fn old_connection_retry_observes_sockets_but_counts_the_query_once() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut old, _) = listener.accept().await.unwrap();
        let q = read_query(&mut old).await;
        write_answer(&mut old, q).await;
        let failed = read_query(&mut old).await;
        drop(old);
        let (mut fresh, _) = listener.accept().await.unwrap();
        let retry = read_query(&mut fresh).await;
        assert_eq!(failed.queries(), retry.queries());
        write_answer(&mut fresh, retry).await;
        assert!(fresh.read_u8().await.is_err());
    });
    let observer = Arc::new(Observer::default());
    let upstream = Upstream::new_with_options(
        &format!("tcp+pipeline://{address}"),
        Duration::from_secs(1),
        options(&observer),
    )
    .unwrap();
    upstream.exchange(&query(1)).await.unwrap();
    upstream.exchange(&query(2)).await.unwrap();
    observer.connections(2, 1);
    observer.queries(&[QueryOutcome::Success; 2]);
    upstream.close().await.unwrap();
    peer.await.unwrap();
    observer.connections(2, 2);
}

#[tokio::test]
async fn udp_tcp_fallback_opens_two_sockets_but_observes_each_query_once() {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind(address).await.unwrap();
    let udp_peer = tokio::spawn(async move {
        let mut payload = [0; 4096];
        for _ in 0..2 {
            let (length, peer) = udp.recv_from(&mut payload).await.unwrap();
            let mut response = answer(Message::from_vec(&payload[..length]).unwrap());
            response.set_truncated(true);
            udp.send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let tcp_peer = tokio::spawn(async move {
        let (mut stream, _) = tcp.accept().await.unwrap();
        for _ in 0..2 {
            let q = read_query(&mut stream).await;
            write_answer(&mut stream, q).await;
        }
        assert!(stream.read_u8().await.is_err());
    });
    let observer = Arc::new(Observer::default());
    let upstream = Upstream::new_with_options(
        &format!("udp://{address}"),
        Duration::from_secs(1),
        options(&observer),
    )
    .unwrap();
    for id in 0..2 {
        assert!(!upstream.exchange(&query(id)).await.unwrap().truncated());
    }
    observer.connections(2, 0);
    observer.queries(&[QueryOutcome::Success; 2]);
    upstream.close().await.unwrap();
    udp_peer.await.unwrap();
    tcp_peer.await.unwrap();
    observer.connections(2, 2);
}

#[tokio::test]
#[cfg(feature = "full")]
async fn observed_doh_http1_and_http2_reuse_one_connection_until_explicit_close() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, service::service_fn, Request, Response};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    for http2 in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let requests = count.clone();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(tls_config(Some(if http2 {
                "h2"
            } else {
                "http/1.1"
            })))
            .accept(stream)
            .await
            .unwrap();
            let service = service_fn(move |request: Request<Incoming>| {
                let requests = requests.clone();
                async move {
                    assert_eq!(request.uri().path(), "/dns-query");
                    let payload = request.into_body().collect().await.unwrap().to_bytes();
                    let reply = answer(Message::from_vec(&payload).unwrap())
                        .to_vec()
                        .unwrap();
                    requests.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    Ok::<_, std::convert::Infallible>(
                        Response::builder()
                            .header("content-type", "application/dns-message")
                            .body(Full::new(Bytes::from(reply)))
                            .unwrap(),
                    )
                }
            });
            if http2 {
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            } else {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            }
        });
        let observer = Arc::new(Observer::default());
        let mut opts = options(&observer);
        opts.insecure_skip_verify = true;
        let upstream = Upstream::new_with_options(
            &format!("https://localhost:{}/dns-query", address.port()),
            Duration::from_secs(1),
            opts,
        )
        .unwrap();
        let mut queries = tokio::task::JoinSet::new();
        for id in 0..16 {
            let clone = upstream.clone();
            queries.spawn(async move { clone.exchange(&query(id)).await.unwrap() });
        }
        while let Some(q) = queries.join_next().await {
            q.unwrap();
        }
        assert_eq!(count.load(Ordering::SeqCst), 16);
        observer.connections(1, 0);
        observer.queries(&[QueryOutcome::Success; 16]);
        upstream.close().await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), peer)
            .await
            .unwrap()
            .unwrap();
        observer.connections(1, 1);
    }
}

#[tokio::test]
async fn failed_dial_and_invalid_query_count_errors_without_connection_events() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let observer = Arc::new(Observer::default());
    let upstream = Upstream::new_with_options(
        &format!("tcp://{address}"),
        Duration::from_secs(1),
        options(&observer),
    )
    .unwrap();
    assert!(upstream.exchange(&query(1)).await.is_err());
    assert!(upstream.exchange(&Message::new()).await.is_err());
    observer.connections(0, 0);
    observer.queries(&[QueryOutcome::Error; 2]);
    upstream.close().await.unwrap();
}

#[tokio::test]
async fn dropping_the_last_upstream_clone_closes_its_idle_tcp_socket() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let q = read_query(&mut stream).await;
        write_answer(&mut stream, q).await;
        assert!(stream.read_u8().await.is_err());
    });
    let observer = Arc::new(Observer::default());
    let upstream = Upstream::new_with_options(
        &format!("tcp://{address}"),
        Duration::from_secs(1),
        options(&observer),
    )
    .unwrap();
    let clone = upstream.clone();
    upstream.exchange(&query(1)).await.unwrap();
    drop(upstream);
    observer.connections(1, 0);
    drop(clone);
    tokio::time::timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
    observer.connections(1, 1);
    observer.queries(&[QueryOutcome::Success]);
}

#[tokio::test]
#[cfg(feature = "full")]
async fn bootstrap_dns_is_not_included_in_parent_upstream_events() {
    use hickory_proto::rr::{rdata::A, RData, Record};
    let bootstrap = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = bootstrap.local_addr().unwrap();
    let bootstrap_peer = tokio::spawn(async move {
        let mut payload = [0; 4096];
        let (length, peer) = bootstrap.recv_from(&mut payload).await.unwrap();
        let mut response = answer(Message::from_vec(&payload[..length]).unwrap());
        response.add_answer(Record::from_rdata(
            response.queries()[0].name().clone(),
            60,
            RData::A(A("127.0.0.1".parse().unwrap())),
        ));
        bootstrap
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let q = read_query(&mut stream).await;
        write_answer(&mut stream, q).await;
        assert!(stream.read_u8().await.is_err());
    });
    let observer = Arc::new(Observer::default());
    let mut opts = options(&observer);
    opts.bootstrap = resolver.to_string();
    let upstream = Upstream::new_with_options(
        &format!("tcp://bootstrap-events.invalid:{}", address.port()),
        Duration::from_secs(1),
        opts,
    )
    .unwrap();
    upstream.exchange(&query(1)).await.unwrap();
    observer.connections(1, 0);
    observer.queries(&[QueryOutcome::Success]);
    upstream.close().await.unwrap();
    bootstrap_peer.await.unwrap();
    peer.await.unwrap();
    observer.connections(1, 1);
}

#[tokio::test]
#[cfg(feature = "full")]
async fn doq_and_http3_observe_queries_without_emitting_go_unsupported_connection_events() {
    use bytes::{Buf, Bytes};
    for http3 in [false, true] {
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(
            (*tls_config(Some(if http3 { "h3" } else { "doq" }))).clone(),
        )
        .unwrap();
        let endpoint = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            "127.0.0.1:0".parse().unwrap(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut requests = tokio::task::JoinSet::new();
            if http3 {
                let mut h3 =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                        .await
                        .unwrap();
                for _ in 0..8 {
                    let resolver = h3.accept().await.unwrap().unwrap();
                    requests.spawn(async move {
                        let (_, mut stream) = resolver.resolve_request().await.unwrap();
                        let mut payload = Vec::new();
                        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
                            let length = chunk.remaining();
                            payload.extend_from_slice(&chunk.copy_to_bytes(length));
                        }
                        let response = answer(Message::from_vec(&payload).unwrap())
                            .to_vec()
                            .unwrap();
                        stream
                            .send_response(
                                hyper::Response::builder()
                                    .header("content-type", "application/dns-message")
                                    .body(())
                                    .unwrap(),
                            )
                            .await
                            .unwrap();
                        stream.send_data(Bytes::from(response)).await.unwrap();
                        stream.finish().await.unwrap();
                    });
                }
                tokio::select! {
                    () = async { while let Some(r) = requests.join_next().await { r.unwrap(); } } => {},
                    _ = h3.accept() => panic!("unexpected extra HTTP/3 request"),
                }
                tokio::select! { _ = stopped => {}, _ = h3.accept() => {} }
            } else {
                for _ in 0..8 {
                    let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                    requests.spawn(async move {
                        let frame = receive.read_to_end(65537).await.unwrap();
                        let q = Message::from_vec(&frame[2..]).unwrap();
                        assert_eq!(q.id(), 0);
                        let response = answer(q).to_vec().unwrap();
                        send.write_all(&(response.len() as u16).to_be_bytes())
                            .await
                            .unwrap();
                        send.write_all(&response).await.unwrap();
                        send.finish().unwrap();
                    });
                }
                while let Some(r) = requests.join_next().await {
                    r.unwrap();
                }
                let _ = stopped.await;
            }
        });
        let observer = Arc::new(Observer::default());
        let mut opts = options(&observer);
        opts.insecure_skip_verify = true;
        let upstream = Upstream::new_with_options(
            &if http3 {
                format!("h3://{address}/dns-query")
            } else {
                format!("quic://{address}")
            },
            Duration::from_secs(2),
            opts,
        )
        .unwrap();
        let mut queries = tokio::task::JoinSet::new();
        for id in 0..8 {
            let clone = upstream.clone();
            queries.spawn(async move { clone.exchange(&query(id)).await.unwrap() });
        }
        while let Some(q) = queries.join_next().await {
            q.unwrap();
        }
        observer.connections(0, 0);
        observer.queries(&[QueryOutcome::Success; 8]);
        stop.send(()).unwrap();
        upstream.close().await.unwrap();
        peer.await.unwrap();
        observer.connections(0, 0);
    }
}

#[tokio::test]
#[cfg(feature = "full")]
async fn cancelled_doh_http1_closes_the_socket_while_http2_keeps_its_shared_connection() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, service::service_fn, Request, Response};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    for http2 in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sent, received) = tokio::sync::oneshot::channel();
        let signal = Arc::new(Mutex::new(Some(sent)));
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let stream = tokio_rustls::TlsAcceptor::from(tls_config(Some(if http2 {
                "h2"
            } else {
                "http/1.1"
            })))
            .accept(stream)
            .await
            .unwrap();
            let service = service_fn(move |request: Request<Incoming>| {
                let signal = signal.clone();
                async move {
                    let payload = request.into_body().collect().await.unwrap().to_bytes();
                    Message::from_vec(&payload).unwrap();
                    signal.lock().unwrap().take().unwrap().send(()).unwrap();
                    std::future::pending::<()>().await;
                    Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::new())))
                }
            });
            if http2 {
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            } else {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            }
        });
        let observer = Arc::new(Observer::default());
        let mut opts = options(&observer);
        opts.insecure_skip_verify = true;
        let upstream = Upstream::new_with_options(
            &format!("https://{address}/dns-query"),
            Duration::from_secs(30),
            opts,
        )
        .unwrap();
        let clone = upstream.clone();
        let task = tokio::spawn(async move { clone.exchange(&query(1)).await });
        received.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        observer.queries(&[QueryOutcome::Cancelled]);
        observer.connections(1, usize::from(!http2));
        upstream.close().await.unwrap();
        observer.connections(1, 1);
        // The test server deliberately never completes its service future.
        peer.abort();
        let _ = peer.await;
    }
}

#[tokio::test]
#[cfg(feature = "full")]
async fn unobserved_reqwest_idle_pool_closes_even_while_the_upstream_is_retained() {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, service::service_fn, Request, Response};
    use hyper_util::rt::TokioIo;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let stream = tokio_rustls::TlsAcceptor::from(tls_config(Some("http/1.1")))
            .accept(stream)
            .await
            .unwrap();
        let service = service_fn(|request: Request<Incoming>| async {
            let payload = request.into_body().collect().await.unwrap().to_bytes();
            let payload = answer(Message::from_vec(&payload).unwrap())
                .to_vec()
                .unwrap();
            Ok::<_, std::convert::Infallible>(
                Response::builder()
                    .header("content-type", "application/dns-message")
                    .body(Full::new(Bytes::from(payload)))
                    .unwrap(),
            )
        });
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });
    let upstream = Upstream::new_with_options(
        &format!("https://{address}/dns-query"),
        Duration::from_secs(1),
        Options {
            insecure_skip_verify: true,
            ..Default::default()
        },
    )
    .unwrap();
    for id in 0..2 {
        upstream.exchange(&query(id)).await.unwrap();
    }
    upstream.close().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), peer)
        .await
        .unwrap()
        .unwrap();
    assert!(upstream.clone().exchange(&query(3)).await.is_err());
    upstream.close().await.unwrap();
}

#[tokio::test]
#[cfg(feature = "full")]
async fn close_waits_for_exclusive_tls_dial_cleanup_before_returning() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (sent, received) = tokio::sync::oneshot::channel();
    let peer = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 0x16);
        sent.send(()).unwrap();
        stream.read_to_end(&mut Vec::new()).await.unwrap();
    });
    let observer = Arc::new(Observer::default());
    let mut opts = options(&observer);
    opts.insecure_skip_verify = true;
    let upstream =
        Upstream::new_with_options(&format!("tls://{address}"), Duration::from_secs(30), opts)
            .unwrap();
    let clone = upstream.clone();
    let task = tokio::spawn(async move { clone.exchange(&query(1)).await });
    received.await.unwrap();
    observer.connections(1, 0);
    upstream.close().await.unwrap();
    // No yield or joining the query task before these assertions: close must
    // finish dial cancellation itself, while this upstream is still retained.
    observer.connections(1, 1);
    observer.queries(&[QueryOutcome::Error]);
    assert!(task.await.unwrap().is_err());
    peer.await.unwrap();
    upstream.close().await.unwrap();
    observer.connections(1, 1);
}
