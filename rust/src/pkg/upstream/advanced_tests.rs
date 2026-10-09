// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

//! End-to-end socket tests for bootstrap, proxying, and platform controls.

use super::*;
use hickory_proto::{
    op::Query,
    rr::{
        rdata::{A, AAAA},
        Name, RData, Record, RecordType,
    },
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

fn query() -> Message {
    let mut q = Message::new();
    q.set_id(123).add_query(Query::query(
        Name::from_ascii("example.test.").unwrap(),
        RecordType::A,
    ));
    q
}
fn answer(q: &Message) -> Message {
    let mut r = q.clone();
    r.set_message_type(MessageType::Response)
        .add_answer(Record::from_rdata(
            q.queries()[0].name().clone(),
            60,
            RData::A(A("192.0.2.1".parse().unwrap())),
        ));
    r
}
fn tls_config() -> Arc<rustls::ServerConfig> {
    let cert = rustls::pki_types::CertificateDer::from(
        include_bytes!("fixtures/localhost-cert.der").to_vec(),
    );
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
        include_bytes!("fixtures/localhost-key.der").to_vec(),
    );
    Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap(),
    )
}
async fn dns_stream<T: AsyncRead + AsyncWrite + Unpin>(stream: &mut T) {
    let length = stream.read_u16().await.unwrap();
    let mut payload = vec![0; usize::from(length)];
    stream.read_exact(&mut payload).await.unwrap();
    let response = answer(&Message::from_vec(&payload).unwrap())
        .to_vec()
        .unwrap();
    stream.write_u16(response.len() as u16).await.unwrap();
    stream.write_all(&response).await.unwrap();
    stream.flush().await.unwrap();
}
async fn http_stream<T: AsyncRead + AsyncWrite + Unpin>(stream: &mut T, authority: &str) {
    let query = read_http_query(stream, authority).await;
    let payload = answer(&query).to_vec().unwrap();
    stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", payload.len()).as_bytes()).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();
}

async fn read_http_query<T: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut T,
    authority: &str,
) -> Message {
    let mut headers = Vec::new();
    while !headers.ends_with(b"\r\n\r\n") {
        headers.push(stream.read_u8().await.unwrap());
        assert!(headers.len() < 8192);
    }
    let headers = String::from_utf8(headers).unwrap().to_ascii_lowercase();
    assert!(headers.starts_with("post /dns-query http/1.1\r\n"));
    assert!(
        headers.contains(&format!("host: {authority}\r\n")),
        "{headers}"
    );
    let length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length: "))
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.unwrap();
    Message::from_vec(&payload).unwrap()
}

async fn bootstrap_stub(
    ip: IpAddr,
    version: i64,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let task = tokio::spawn(async move {
        loop {
            let mut buffer = [0; 4096];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            seen.fetch_add(1, Ordering::Relaxed);
            let mut q = Message::from_vec(&buffer[..length]).unwrap();
            assert_eq!(q.queries()[0].name().to_ascii(), "dns.test.invalid.");
            assert_eq!(
                q.queries()[0].query_type(),
                if version == 6 {
                    RecordType::AAAA
                } else {
                    RecordType::A
                }
            );
            assert_eq!(q.extensions().as_ref().unwrap().max_payload(), 1200);
            q.set_message_type(MessageType::Response);
            q.add_answer(Record::from_rdata(
                q.queries()[0].name().clone(),
                1,
                match ip {
                    IpAddr::V4(ip) => RData::A(A(ip)),
                    IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
                },
            ));
            socket.send_to(&q.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    (address, count, task)
}

#[tokio::test]
async fn bootstrap_singleflight_caches_small_ttl_for_at_least_five_minutes() {
    let (server, count, task) = bootstrap_stub("127.0.0.1".parse().unwrap(), 4).await;
    let bootstrap = bootstrap::Bootstrap::new("dns.test.invalid", 853, server, 0).unwrap();
    let results = futures::future::join_all((0..32).map(|_| bootstrap.resolve())).await;
    assert!(results
        .iter()
        .all(|result| result.as_ref().unwrap() == &"127.0.0.1:853".parse().unwrap()));
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        bootstrap.resolve().await.unwrap(),
        "127.0.0.1:853".parse().unwrap()
    );
    assert_eq!(count.load(Ordering::Relaxed), 1);
    task.abort();
}

#[tokio::test]
async fn bootstrap_ipv4_and_ipv6_route_tls_and_keep_original_sni() {
    for version in [4, 6] {
        let bind = if version == 4 {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        };
        let listener = TcpListener::bind(bind).await.unwrap();
        let address = listener.local_addr().unwrap();
        let (bootstrap, count, stub) = bootstrap_stub(address.ip(), version).await;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(tls_config())
                .accept(stream)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.server_name(), Some("dns.test.invalid"));
            dns_stream(&mut tls).await;
        });
        let options = Options {
            bootstrap: bootstrap.to_string(),
            bootstrap_version: version,
            insecure_skip_verify: true,
            ..Default::default()
        };
        let upstream = Upstream::new_with_options(
            &format!("tls://dns.test.invalid:{}", address.port()),
            Duration::from_secs(2),
            options,
        )
        .unwrap();
        assert_eq!(upstream.exchange(&query()).await.unwrap().id(), 123);
        server.await.unwrap();
        assert_eq!(count.load(Ordering::Relaxed), 1);
        stub.abort();
    }
}

#[tokio::test]
async fn doh_bootstrap_routes_ipv6_and_preserves_http_and_tls_identity() {
    let listener = TcpListener::bind("[::1]:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (bootstrap, _, stub) = bootstrap_stub(address.ip(), 6).await;
    let authority = format!("dns.test.invalid:{}", address.port());
    let host = authority.clone();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(tls_config())
            .accept(stream)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some("dns.test.invalid"));
        http_stream(&mut tls, &host).await;
    });
    let options = Options {
        bootstrap: bootstrap.to_string(),
        bootstrap_version: 6,
        insecure_skip_verify: true,
        ..Default::default()
    };
    let upstream = Upstream::new_with_options(
        &format!("https://{authority}/dns-query"),
        Duration::from_secs(2),
        options,
    )
    .unwrap();
    assert_eq!(upstream.exchange(&query()).await.unwrap().id(), 123);
    server.await.unwrap();
    stub.abort();
}

async fn socks_proxy(
    target: SocketAddr,
    expected_host: &'static str,
    expected_port: u16,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut client, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        client.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        client.write_all(&[5, 0]).await.unwrap();
        let mut header = [0; 4];
        client.read_exact(&mut header).await.unwrap();
        assert_eq!(header, [5, 1, 0, 3]);
        let length = client.read_u8().await.unwrap();
        let mut host = vec![0; usize::from(length)];
        client.read_exact(&mut host).await.unwrap();
        assert_eq!(String::from_utf8(host).unwrap(), expected_host);
        assert_eq!(client.read_u16().await.unwrap(), expected_port);
        let mut remote = tokio::net::TcpStream::connect(target).await.unwrap();
        client
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
            .await
            .unwrap();
        let _ = tokio::io::copy_bidirectional(&mut client, &mut remote).await;
    });
    (proxy, task)
}

#[tokio::test]
async fn socks5_tcp_tls_and_doh_resolve_target_at_proxy_and_keep_tls_identity() {
    for protocol in ["tcp", "tls", "https"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            if protocol == "tcp" {
                dns_stream(&mut stream).await;
            } else {
                let mut tls = tokio_rustls::TlsAcceptor::from(tls_config())
                    .accept(stream)
                    .await
                    .unwrap();
                assert_eq!(tls.get_ref().1.server_name(), Some("dns.test.invalid"));
                if protocol == "tls" {
                    dns_stream(&mut tls).await;
                } else {
                    http_stream(&mut tls, "dns.test.invalid:8443").await;
                }
            }
        });
        let (proxy, relay) = socks_proxy(target, "dns.test.invalid", 8443).await;
        let options = Options {
            socks5: proxy.to_string(),
            insecure_skip_verify: true,
            ..Default::default()
        };
        let upstream = Upstream::new_with_options(
            &format!(
                "{protocol}://dns.test.invalid:8443{}",
                if protocol == "https" {
                    "/dns-query"
                } else {
                    ""
                }
            ),
            Duration::from_secs(2),
            options,
        )
        .unwrap();
        assert_eq!(upstream.exchange(&query()).await.unwrap().id(), 123);
        server.await.unwrap();
        relay.abort();
    }
}

#[tokio::test]
async fn udp_tcp_fallback_ignores_socks5() {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = udp.local_addr().unwrap();
    let tcp = TcpListener::bind(address).await.unwrap();
    let server = tokio::spawn(async move {
        let mut payload = [0; 4096];
        let (n, peer) = udp.recv_from(&mut payload).await.unwrap();
        let mut r = answer(&Message::from_vec(&payload[..n]).unwrap());
        r.set_truncated(true);
        udp.send_to(&r.to_vec().unwrap(), peer).await.unwrap();
        let (mut stream, _) = tcp.accept().await.unwrap();
        dns_stream(&mut stream).await;
    });
    let upstream = Upstream::new_with_options(
        &format!("udp://{address}"),
        Duration::from_secs(2),
        Options {
            socks5: "not-a-valid-proxy-address".into(),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(!upstream.exchange(&query()).await.unwrap().truncated());
    server.await.unwrap();
}

#[test]
fn invalid_bootstrap_and_platform_socket_options_fail_explicitly() {
    for address in ["dns.example:53", "127.0.0.1:0", "[::1]:0"] {
        assert!(Upstream::new_with_options(
            "tls://dns.test.invalid",
            Duration::from_secs(1),
            Options {
                bootstrap: address.into(),
                ..Default::default()
            }
        )
        .is_err());
    }
    assert!(Upstream::new_with_options(
        "tls://dns.test.invalid",
        Duration::from_secs(1),
        Options {
            bootstrap: "127.0.0.1".into(),
            bootstrap_version: 5,
            ..Default::default()
        }
    )
    .is_err());
    #[cfg(not(target_os = "linux"))]
    for options in [
        Options {
            so_mark: 42,
            ..Default::default()
        },
        Options {
            bind_to_device: "lo".into(),
            ..Default::default()
        },
    ] {
        let error =
            match Upstream::new_with_options("udp://127.0.0.1", Duration::from_secs(1), options) {
                Ok(_) => panic!("Linux options accepted"),
                Err(error) => error,
            };
        assert!(error.to_string().contains("only on Linux"));
    }
}

#[tokio::test]
async fn quic_bootstrap_routes_ipv6_and_ignores_socks5() {
    let mut tls = tls_config().as_ref().clone();
    tls.alpn_protocols = vec![b"doq".to_vec()];
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
    ));
    let endpoint = quinn::Endpoint::server(config, "[::1]:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let (bootstrap, count, stub) = bootstrap_stub(address.ip(), 6).await;
    let server = tokio::spawn(async move {
        let connection = endpoint.accept().await.unwrap().await.unwrap();
        let (mut send, mut receive) = connection.accept_bi().await.unwrap();
        let frame = receive.read_to_end(65537).await.unwrap();
        let q = Message::from_vec(&frame[2..]).unwrap();
        assert_eq!(q.id(), 0);
        let response = answer(&q).to_vec().unwrap();
        let mut frame = (response.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(&response);
        send.write_all(&frame).await.unwrap();
        send.finish().unwrap();
        send.stopped().await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
    });
    let options = Options {
        bootstrap: bootstrap.to_string(),
        bootstrap_version: 6,
        socks5: "invalid-proxy-ignored-for-quic".into(),
        insecure_skip_verify: true,
        ..Default::default()
    };
    let upstream = Upstream::new_with_options(
        &format!("quic://dns.test.invalid:{}", address.port()),
        Duration::from_secs(2),
        options,
    )
    .unwrap();
    assert_eq!(upstream.exchange(&query()).await.unwrap().id(), 123);
    server.await.unwrap();
    assert_eq!(count.load(Ordering::Relaxed), 1);
    stub.abort();
}

#[tokio::test]
async fn doh_ip_url_dial_override_keeps_ip_tls_identity_and_original_host() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = tokio_rustls::TlsAcceptor::from(tls_config())
            .accept(stream)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.server_name(), None);
        http_stream(&mut tls, "192.0.2.1:8443").await;
    });
    let upstream = Upstream::new_with_options(
        "https://192.0.2.1:8443/dns-query",
        Duration::from_secs(2),
        Options {
            dial_addr: target.to_string(),
            insecure_skip_verify: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(upstream.exchange(&query()).await.unwrap().id(), 123);
    server.await.unwrap();
}

#[tokio::test]
async fn socks5_doh_http2_queries_are_concurrent_on_one_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(8));
    let server = tokio::spawn(async move {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Full};
        let (stream, _) = listener.accept().await.unwrap();
        let mut config = tls_config().as_ref().clone();
        config.alpn_protocols = vec![b"h2".to_vec()];
        let tls = tokio_rustls::TlsAcceptor::from(Arc::new(config))
            .accept(stream)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.server_name(), Some("dns.test.invalid"));
        let service =
            hyper::service::service_fn(move |request: hyper::Request<hyper::body::Incoming>| {
                let barrier = barrier.clone();
                async move {
                    assert_eq!(
                        request.uri().authority().unwrap().as_str(),
                        "dns.test.invalid:8443"
                    );
                    let body = request.into_body().collect().await.unwrap().to_bytes();
                    barrier.wait().await;
                    let response = answer(&Message::from_vec(&body).unwrap()).to_vec().unwrap();
                    Ok::<_, std::convert::Infallible>(
                        hyper::Response::builder()
                            .header("content-type", "application/dns-message")
                            .body(Full::new(Bytes::from(response)))
                            .unwrap(),
                    )
                }
            });
        hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
            .await
            .unwrap();
    });
    let (proxy, relay) = socks_proxy(target, "dns.test.invalid", 8443).await;
    let upstream = Upstream::new_with_options(
        "https://dns.test.invalid:8443/dns-query",
        Duration::from_secs(2),
        Options {
            socks5: proxy.to_string(),
            insecure_skip_verify: true,
            ..Default::default()
        },
    )
    .unwrap();
    let results = futures::future::join_all((0..8).map(|id| {
        let mut q = query();
        q.set_id(id);
        let upstream = &upstream;
        async move { upstream.exchange(&q).await.unwrap() }
    }))
    .await;
    for (id, response) in results.iter().enumerate() {
        assert_eq!(response.id(), id as u16);
    }
    server.abort();
    relay.abort();
}

#[tokio::test]
async fn forward_inherits_socks5_connection_options() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        dns_stream(&mut stream).await;
    });
    let (proxy, relay) = socks_proxy(target, "dns.test.invalid", 53).await;
    let yaml = format!("plugins:\n  - tag: upstream\n    type: forward\n    args:\n      socks5: {proxy}\n      upstreams: [{{addr: 'tcp://dns.test.invalid'}}]\n  - tag: main\n    type: sequence\n    args:\n      - exec: $upstream\n");
    let engine =
        crate::coremain::Engine::new(crate::coremain::Config::from_yaml(&yaml).unwrap()).unwrap();
    let response = engine
        .handle(query(), "127.0.0.1".parse().unwrap(), "main")
        .await
        .unwrap();
    assert_eq!(response.id(), 123);
    assert_eq!(response.answers().len(), 1);
    server.await.unwrap();
    relay.abort();
}

#[tokio::test]
async fn custom_doh_http1_timeout_and_idle_close_connections_and_reconnect() {
    for timeout in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(tls_config())
                .accept(stream)
                .await
                .unwrap();
            if timeout {
                read_http_query(&mut tls, "192.0.2.1:8443").await;
            } else {
                http_stream(&mut tls, "192.0.2.1:8443").await;
            }
            let mut buffer = [0; 1];
            let closed = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buffer))
                .await
                .unwrap();
            assert!(
                matches!(closed, Ok(0))
                    || closed
                        .as_ref()
                        .is_err_and(|error| error.kind() == std::io::ErrorKind::UnexpectedEof)
            );
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(tls_config())
                .accept(stream)
                .await
                .unwrap();
            http_stream(&mut tls, "192.0.2.1:8443").await;
        });
        let upstream = Upstream::new_with_options(
            "https://192.0.2.1:8443/dns-query",
            Duration::from_millis(200),
            Options {
                dial_addr: target.to_string(),
                insecure_skip_verify: true,
                idle_timeout: Duration::from_millis(30),
                ..Default::default()
            },
        )
        .unwrap();
        let result = upstream.exchange(&query()).await;
        if timeout {
            assert!(format!("{:#}", result.unwrap_err()).contains("DNS upstream timeout"));
        } else {
            assert_eq!(result.unwrap().id(), 123);
            tokio::time::sleep(Duration::from_millis(90)).await;
        }
        assert_eq!(upstream.exchange(&query()).await.unwrap().id(), 123);
        server.await.unwrap();
    }
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires Linux CAP_NET_ADMIN or CAP_NET_RAW"]
fn linux_socket_mark_and_bind_device_are_applied_before_bind() {
    use std::os::fd::AsRawFd;
    let dialer = dialer::Dialer::new(
        "127.0.0.1".into(),
        53,
        &Options {
            so_mark: 42,
            bind_to_device: "lo".into(),
            ..Default::default()
        },
    )
    .unwrap();
    let socket = dialer.bind_udp("127.0.0.1:53".parse().unwrap()).unwrap();
    let mut mark: u32 = 0;
    let mut mark_len = std::mem::size_of::<u32>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&mut mark as *mut u32).cast(),
            &mut mark_len,
        )
    };
    assert_eq!(result, 0);
    assert_eq!(mark, 42);
    let mut device = [0u8; libc::IFNAMSIZ];
    let mut device_len = device.len() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            device.as_mut_ptr().cast(),
            &mut device_len,
        )
    };
    assert_eq!(result, 0);
    assert_eq!(&device[..3], b"lo\0");
}
