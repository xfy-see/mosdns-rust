use super::*;
#[cfg(feature = "full")]
use crate::pkg::upstream::{events, Backend, Inner};
use crate::pkg::upstream::{Options, Upstream};
use hickory_proto::{
    op::{MessageType, Query},
    rr::{Name, RecordType},
};
#[cfg(feature = "full")]
use std::{collections::HashSet, net::SocketAddr};
use tokio::net::TcpListener;

fn query(id: u16) -> Message {
    let mut query = Message::new();
    query.set_id(id).add_query(Query::query(
        Name::from_ascii(format!("capacity-{id}.example.")).unwrap(),
        RecordType::A,
    ));
    query
}

async fn read_query<S: AsyncRead + Unpin>(stream: &mut S) -> Message {
    let length = stream.read_u16().await.unwrap();
    let mut payload = vec![0; length as usize];
    stream.read_exact(&mut payload).await.unwrap();
    Message::from_vec(&payload).unwrap()
}

async fn first_session(transport: &Transport) -> Arc<Session> {
    transport.first_session().await
}

#[cfg(feature = "full")]
fn tls_client_config() -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            include_bytes!("../fixtures/localhost-cert.der").to_vec(),
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

#[cfg(feature = "full")]
fn pipeline_upstream(transport: Transport, timeout: Duration) -> Upstream {
    Upstream {
        inner: Arc::new(Inner {
            backend: Backend::Traditional {
                transport,
                tcp_fallback: None,
            },
            timeout,
            events: events::Lifecycle::default(),
        }),
    }
}

#[cfg(feature = "full")]
type CapturedQuery = (SocketAddr, Message, mpsc::UnboundedSender<Vec<u8>>);

#[cfg(feature = "full")]
async fn capacity_peer<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    peer: SocketAddr,
    incoming: mpsc::UnboundedSender<CapturedQuery>,
) {
    let (mut read, mut write) = tokio::io::split(stream);
    let (reply, mut replies) = mpsc::unbounded_channel::<Vec<u8>>();
    let read_loop = async {
        loop {
            let query = read_query(&mut read).await;
            if incoming.send((peer, query, reply.clone())).is_err() {
                return;
            }
        }
    };
    let write_loop = async {
        while let Some(payload) = replies.recv().await {
            write.write_u16(payload.len() as u16).await.unwrap();
            write.write_all(&payload).await.unwrap();
            write.flush().await.unwrap();
        }
    };
    tokio::select! { () = read_loop => {}, () = write_loop => {} }
}

#[tokio::test]
#[cfg(feature = "full")]
async fn tcp_and_tls_pipeline_expand_after_sixty_four_inflight_queries() {
    for protocol in ["tcp", "tls"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (incoming, mut queries) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel();
        let certificate = rustls::pki_types::CertificateDer::from(
            include_bytes!("../fixtures/localhost-cert.der").to_vec(),
        );
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
            include_bytes!("../fixtures/localhost-key.der").to_vec(),
        );
        let tls_server = Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key.into())
            .unwrap(),
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let tls_client = Arc::new(
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        );
        let server = tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            tokio::pin!(stopped);
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => {
                        let (stream, peer) = accepted.unwrap();
                        let incoming = incoming.clone();
                        let tls_server = tls_server.clone();
                        workers.spawn(async move {
                            if protocol == "tcp" {
                                capacity_peer(stream, peer, incoming).await;
                            } else {
                                let stream = tokio_rustls::TlsAcceptor::from(tls_server).accept(stream).await.unwrap();
                                capacity_peer(stream, peer, incoming).await;
                            }
                        });
                    }
                }
            }
            workers.abort_all();
            while workers.join_next().await.is_some() {}
        });
        let upstream = if protocol == "tcp" {
            Upstream::new(&format!("tcp+pipeline://{address}"), Duration::from_secs(3)).unwrap()
        } else {
            Upstream {
                inner: Arc::new(Inner {
                    backend: Backend::Traditional {
                        transport: Transport::with_tls_config(
                            "127.0.0.1".into(),
                            address.port(),
                            tls_client,
                            true,
                        ),
                        tcp_fallback: None,
                    },
                    timeout: Duration::from_secs(3),
                    events: events::Lifecycle::default(),
                }),
            }
        };
        let mut clients = tokio::task::JoinSet::new();
        for id in 0..65 {
            let upstream = upstream.clone();
            clients.spawn(async move { upstream.exchange(&query(id)).await.unwrap() });
        }
        let mut captured = Vec::new();
        for _ in 0..65 {
            captured.push(
                tokio::time::timeout(Duration::from_secs(2), queries.recv())
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        let peers = captured
            .iter()
            .map(|(peer, _, _)| *peer)
            .collect::<HashSet<_>>();
        assert_eq!(
            peers.len(),
            2,
            "65 held queries must occupy two {protocol} connections"
        );
        for peer in &peers {
            assert!(
                captured
                    .iter()
                    .filter(|(source, _, _)| source == peer)
                    .count()
                    <= 64
            );
        }
        for (_, mut response, reply) in captured {
            response.set_message_type(MessageType::Response);
            reply.send(response.to_vec().unwrap()).unwrap();
        }
        while let Some(result) = clients.join_next().await {
            result.unwrap();
        }
        stop.send(()).unwrap();
        server.await.unwrap();
    }
}

#[tokio::test]
async fn udp_pipeline_has_four_thousand_ninety_six_slots_and_expands_when_full() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut sources = Vec::new();
        for _ in 0..2 {
            let mut payload = [0; 4096];
            let (length, peer) = socket.recv_from(&mut payload).await.unwrap();
            let mut response = Message::from_vec(&payload[..length]).unwrap();
            response.set_message_type(MessageType::Response);
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
            sources.push(peer);
        }
        sources
    });
    let transport = Transport::new(Protocol::Udp, "127.0.0.1".into(), address.port());
    transport.exchange(&query(1)).await.unwrap();
    let first = first_session(&transport).await;
    assert_eq!(first.limit.available_permits(), 4096);
    // Occupy the exact public resource limit without sending 4096 packets;
    // the next real query must be sent from another upstream UDP socket.
    let occupied = first.limit.acquire_many(4096).await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), transport.exchange(&query(2)))
        .await
        .unwrap()
        .unwrap();
    let sources = server.await.unwrap();
    assert_ne!(sources[0], sources[1]);
    drop(occupied);
}

#[tokio::test]
async fn waiting_reply_deadline_closes_a_silent_new_connection_after_ten_seconds() {
    for (scheme, reply_timeout) in [
        ("tcp+pipeline", Duration::from_secs(10)),
        ("tcp", Duration::from_secs(6)),
    ] {
        for overall in [Duration::from_secs(30), Duration::from_secs(2)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (received, receive) = oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                read_query(&mut stream).await;
                received.send(()).unwrap();
                let _ = stream.read_u8().await;
            });
            let upstream = Upstream::new_with_options(
                &format!("{scheme}://{address}"),
                overall,
                Options {
                    // A longer idle deadline isolates waiting-reply health from
                    // idle expiry, including for the exclusive reuse transport.
                    idle_timeout: Duration::from_secs(30),
                    ..Default::default()
                },
            )
            .unwrap();
            let client = upstream.clone();
            let task = tokio::spawn(async move { client.exchange(&query(1)).await });
            receive.await.unwrap();
            tokio::time::pause();
            let limit = overall.min(reply_timeout);
            tokio::time::advance(limit - Duration::from_secs(1)).await;
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            assert!(
                !task.is_finished(),
                "connection must not fail before its earliest deadline"
            );
            // Tokio's timer wheel rounds deadlines to milliseconds. Move beyond
            // that rounding boundary, then let the health and query tasks wake.
            tokio::time::advance(Duration::from_secs(1) + Duration::from_millis(1)).await;
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
            assert!(
                task.is_finished(),
                "silent connection must fail by {limit:?}"
            );
            let error = task.await.unwrap().unwrap_err();
            if overall > reply_timeout {
                assert!(
                    error.to_string().contains("waiting reply timeout"),
                    "{error:#}"
                );
            } else {
                assert!(
                    error.to_string().contains("DNS upstream timeout"),
                    "{error:#}"
                );
            }
            tokio::time::resume();
            drop(upstream);
            server.await.unwrap();
        }
    }
}

#[tokio::test]
#[cfg(feature = "full")]
async fn cancelling_all_handshake_waiters_releases_every_lazy_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (hello, mut hellos) = mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        let mut peers = tokio::task::JoinSet::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let hello = hello.clone();
            peers.spawn(async move {
                assert_eq!(stream.read_u8().await.unwrap(), 0x16);
                hello.send(()).unwrap();
                let mut tail = Vec::new();
                stream.read_to_end(&mut tail).await.unwrap();
            });
        }
        while let Some(peer) = peers.join_next().await {
            peer.unwrap();
        }
    });
    let transport = Arc::new(Transport::with_tls_config(
        "localhost".into(),
        address.port(),
        tls_client_config(),
        true,
    ));
    let mut queries = tokio::task::JoinSet::new();
    for id in 0..65 {
        let transport = transport.clone();
        queries.spawn(async move { transport.exchange(&query(id)).await });
    }
    for _ in 0..2 {
        tokio::time::timeout(Duration::from_secs(1), hellos.recv())
            .await
            .unwrap()
            .unwrap();
    }
    assert_eq!(transport.pool.slots.lock().unwrap().len(), 2);
    queries.abort_all();
    while queries.join_next().await.is_some() {}
    assert!(transport.pool.slots.lock().unwrap().is_empty());
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
#[cfg(feature = "full")]
async fn stalled_tls_dial_is_limited_to_five_seconds_with_a_long_overall_timeout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (hello, received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), 0x16);
        hello.send(()).unwrap();
        let mut tail = Vec::new();
        stream.read_to_end(&mut tail).await.unwrap();
    });
    let upstream = pipeline_upstream(
        Transport::with_tls_config(
            "localhost".into(),
            address.port(),
            tls_client_config(),
            true,
        ),
        Duration::from_secs(30),
    );
    let client = upstream.clone();
    let task = tokio::spawn(async move { client.exchange(&query(1)).await });
    received.await.unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(4)).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert!(!task.is_finished());
    tokio::time::advance(Duration::from_secs(1) + Duration::from_millis(1)).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(
        task.is_finished(),
        "lazy TLS dial must fail by five seconds"
    );
    let error = task.await.unwrap().unwrap_err();
    assert!(error.to_string().contains("dial timeout"), "{error:#}");
    tokio::time::resume();
    drop(upstream);
    server.await.unwrap();
}

#[tokio::test]
async fn any_reply_restores_the_idle_deadline_with_another_query_still_pending() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (first, received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut response = read_query(&mut stream).await;
        first.send(()).unwrap();
        read_query(&mut stream).await;
        response.set_message_type(MessageType::Response);
        let payload = response.to_vec().unwrap();
        stream.write_u16(payload.len() as u16).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    });
    let mut transport = Transport::new(Protocol::Tcp, "127.0.0.1".into(), address.port());
    transport.pipeline = true;
    transport.idle_timeout = Duration::from_secs(30);
    let transport = Arc::new(transport);
    let first_client = transport.clone();
    let first = tokio::spawn(async move { first_client.exchange(&query(1)).await });
    received.await.unwrap();
    let second_client = transport.clone();
    let second = tokio::spawn(async move { second_client.exchange(&query(2)).await });
    first.await.unwrap().unwrap();
    let session = first_session(&transport).await;
    assert_eq!(session.pending.lock().unwrap().len(), 1);
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    for _ in 0..4 {
        tokio::task::yield_now().await;
    }
    assert!(session.alive.load(Ordering::Acquire));
    assert!(
        !second.is_finished(),
        "any response proves connection health"
    );
    tokio::time::advance(Duration::from_secs(19) + Duration::from_millis(1)).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(!session.alive.load(Ordering::Acquire));
    second.abort();
    let _ = second.await;
    tokio::time::resume();
    drop(transport);
    server.await.unwrap();
}

#[tokio::test]
async fn pipeline_idle_expiry_removes_the_session_without_another_query() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut response = read_query(&mut stream).await;
        response.set_message_type(MessageType::Response);
        let payload = response.to_vec().unwrap();
        stream.write_u16(payload.len() as u16).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        assert_eq!(
            stream.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    });
    let mut transport = Transport::new(Protocol::Tcp, "127.0.0.1".into(), address.port());
    transport.pipeline = true;
    transport.idle_timeout = Duration::from_millis(30);
    transport.exchange(&query(1)).await.unwrap();
    assert_eq!(transport.pool.slots.lock().unwrap().len(), 1);
    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
    assert!(transport.pool.slots.lock().unwrap().is_empty());
}

#[tokio::test]
async fn udp_retransmission_does_not_replace_an_idle_deadline_restored_by_another_reply() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (first, received) = oneshot::channel();
    let (retry, retried) = oneshot::channel();
    let (stop, stopped) = oneshot::channel();
    let server = tokio::spawn(async move {
        let mut payload = [0; 4096];
        let (length, _) = socket.recv_from(&mut payload).await.unwrap();
        let original = Message::from_vec(&payload[..length]).unwrap();
        first.send(()).unwrap();
        let (length, peer) = socket.recv_from(&mut payload).await.unwrap();
        let mut response = Message::from_vec(&payload[..length]).unwrap();
        assert_ne!(response.queries(), original.queries());
        response.set_message_type(MessageType::Response);
        socket
            .send_to(&response.to_vec().unwrap(), peer)
            .await
            .unwrap();
        let (length, _) = socket.recv_from(&mut payload).await.unwrap();
        let retransmission = Message::from_vec(&payload[..length]).unwrap();
        assert_eq!(retransmission.id(), original.id());
        assert_eq!(retransmission.queries(), original.queries());
        retry.send(()).unwrap();
        // Keep the peer port open while the clock advances, so late UDP
        // resends cannot introduce an unrelated ICMP connection error.
        stopped.await.unwrap();
    });
    let mut transport = Transport::new(Protocol::Udp, "127.0.0.1".into(), address.port());
    transport.idle_timeout = Duration::from_secs(30);
    let transport = Arc::new(transport);
    let client = transport.clone();
    let first = tokio::spawn(async move { client.exchange(&query(1)).await });
    received.await.unwrap();
    transport.exchange(&query(2)).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), retried)
        .await
        .unwrap()
        .unwrap();
    let session = first_session(&transport).await;
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(11)).await;
    for _ in 0..16 {
        tokio::task::yield_now().await;
    }
    assert!(
        session.alive.load(Ordering::Acquire),
        "a UDP resend must preserve the restored 30s idle deadline"
    );
    assert!(!first.is_finished());
    first.abort();
    let _ = first.await;
    tokio::time::resume();
    drop(transport);
    drop(session);
    stop.send(()).unwrap();
    server.await.unwrap();
}
