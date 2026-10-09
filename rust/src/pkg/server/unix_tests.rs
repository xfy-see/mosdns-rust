use super::*;
use hickory_proto::{
    op::Query,
    rr::{Name, RecordType},
};
use tokio::net::UnixStream;

fn query(id: u16) -> Message {
    let mut query = Message::new();
    query.set_id(id).add_query(Query::query(
        Name::from_ascii("unix.example.").unwrap(),
        RecordType::A,
    ));
    query
}

fn engine() -> Arc<crate::coremain::Engine> {
    let matches = if cfg!(feature = "full") {
        "client_ip 0.0.0.0/0"
    } else {
        "_false"
    };
    Arc::new(
        crate::coremain::Engine::new(
            crate::coremain::Config::from_yaml(&format!(
                r#"
plugins:
  - tag: main
    type: sequence
    args:
      - matches: {matches}
        exec: reject 3
      - exec: reject 0
"#,
            ))
            .unwrap(),
        )
        .unwrap(),
    )
}

async fn exchange<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut S,
    id: u16,
) -> Message {
    let payload = query(id).to_vec().unwrap();
    stream.write_u16(payload.len() as u16).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();
    let length = tokio::time::timeout(Duration::from_secs(1), stream.read_u16())
        .await
        .unwrap()
        .unwrap();
    let mut payload = vec![0; length as usize];
    stream.read_exact(&mut payload).await.unwrap();
    Message::from_vec(&payload).unwrap()
}

#[tokio::test]
async fn unix_dns_keeps_persistent_framing_and_no_ip_client() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("dns.sock");
    let listener = socket::bind_stream(&format!("unix://{}", path.display()))
        .await
        .unwrap();
    let engine = engine();
    let handler: Handler = Arc::new(move |query, client| {
        let engine = engine.clone();
        Box::pin(async move {
            engine
                .handle_with_client_meta(query, client, "main", None, None)
                .await
        })
    });
    let task = tokio::spawn(serve_tcp_listener_with_timeout(
        listener,
        handler,
        Duration::from_secs(1),
    ));
    let mut stream = UnixStream::connect(&path).await.unwrap();
    for id in [17, 18] {
        let response = exchange(&mut stream, id).await;
        assert_eq!(response.id(), id);
        assert_eq!(
            response.response_code(),
            ResponseCode::NoError,
            "Unix must not invent a 0.0.0.0 client"
        );
    }
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(
        !path.exists(),
        "closing listener removes only its owned filesystem socket"
    );
}

#[tokio::test]
async fn unix_binding_does_not_remove_an_existing_file() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("owned.txt");
    std::fs::write(&path, "preserve existing content").unwrap();
    assert!(socket::bind_stream(&format!("unix://{}", path.display()))
        .await
        .is_err());
    assert_eq!(
        std::fs::read_to_string(path).unwrap(),
        "preserve existing content"
    );
}

#[tokio::test]
#[cfg(feature = "full")]
async fn unix_http_uses_header_client_and_cleans_up_socket() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("doh.sock");
    let listener = socket::bind_stream(&format!("unix://{}", path.display()))
        .await
        .unwrap();
    let routes = http::Routes {
        engine: engine(),
        entries: vec![("/dns-query".into(), "main".into())],
        src_ip_header: "x-forwarded-for".into(),
        limit: Arc::new(Semaphore::new(MAX_QUERIES)),
    };
    let task = tokio::spawn(http::serve_http_listener(
        listener,
        routes,
        None,
        Duration::from_secs(1),
    ));
    for (source, expected) in [
        (None, ResponseCode::NoError),
        (Some("198.51.100.1"), ResponseCode::NXDomain),
    ] {
        let mut stream = UnixStream::connect(&path).await.unwrap();
        let payload = query(41).to_vec().unwrap();
        let header = source
            .map(|ip| format!("X-Forwarded-For: {ip}\r\n"))
            .unwrap_or_default();
        let request = format!("POST /dns-query HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n{header}\r\n", payload.len());
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let split = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        assert_eq!(
            Message::from_vec(&response[split + 4..])
                .unwrap()
                .response_code(),
            expected
        );
    }
    task.abort();
    let _ = task.await;
    assert!(!path.exists());
}

#[tokio::test]
#[cfg(feature = "full")]
async fn unix_tls_listener_keeps_sni_and_dns_framing() {
    let (_temporary, cert, key) = tests::pem_fixture();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("dot.sock");
    let listener = socket::bind_stream(&format!("unix://{}", path.display()))
        .await
        .unwrap();
    let config = tls::load_tls_config(&cert, &key, &[b"dot"]).unwrap();
    let task = tokio::spawn(tls::serve_tls_listener(
        listener,
        tests::test_engine(),
        "main".into(),
        config,
        Duration::from_secs(1),
    ));
    let stream = UnixStream::connect(&path).await.unwrap();
    let mut stream = tokio_rustls::TlsConnector::from(tests::trusted_tls_client())
        .connect(
            rustls::pki_types::ServerName::try_from("dns.test.invalid").unwrap(),
            stream,
        )
        .await
        .unwrap();
    let response = exchange(&mut stream, 44).await;
    assert_eq!(response.id(), 44);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    task.abort();
    let _ = task.await;
    assert!(!path.exists());
}

#[tokio::test]
#[cfg(feature = "full")]
async fn unix_https_listener_preserves_tls_and_http_metadata() {
    let (_temporary, cert, key) = tests::pem_fixture();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("https.sock");
    let listener = socket::bind_stream(&format!("unix://{}", path.display()))
        .await
        .unwrap();
    let config = tls::load_tls_config(&cert, &key, &[b"http/1.1"]).unwrap();
    let routes = http::Routes {
        engine: tests::test_engine(),
        entries: vec![("/dns-query".into(), "main".into())],
        src_ip_header: String::new(),
        limit: Arc::new(Semaphore::new(MAX_QUERIES)),
    };
    let task = tokio::spawn(http::serve_http_listener(
        listener,
        routes,
        Some(config),
        Duration::from_secs(1),
    ));
    let stream = UnixStream::connect(&path).await.unwrap();
    let mut stream = tokio_rustls::TlsConnector::from(tests::trusted_tls_client())
        .connect(
            rustls::pki_types::ServerName::try_from("dns.test.invalid").unwrap(),
            stream,
        )
        .await
        .unwrap();
    let payload = query(46).to_vec().unwrap();
    let request = format!("POST /dns-query HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", payload.len());
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(&payload).await.unwrap();
    stream.flush().await.unwrap();
    let mut response = Vec::new();
    // The DNS payload completes before TLS close_notify; inspect Content-Length
    // rather than requiring a clean TLS shutdown from the HTTP connection loop.
    loop {
        let mut buffer = [0; 1024];
        let length = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert!(length > 0);
        response.extend_from_slice(&buffer[..length]);
        if let Some(split) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            let header = String::from_utf8_lossy(&response[..split]);
            let length: usize = header
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .unwrap()
                .parse()
                .unwrap();
            if response.len() >= split + 4 + length {
                assert!(response.starts_with(b"HTTP/1.1 200"));
                let reply = Message::from_vec(&response[split + 4..split + 4 + length]).unwrap();
                assert_eq!(reply.id(), 46);
                assert_eq!(reply.response_code(), ResponseCode::NoError);
                break;
            }
        }
    }
    task.abort();
    let _ = task.await;
    assert!(!path.exists());
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn go_at_name_keeps_the_prefix_in_the_filesystem_path() {
    let name = format!(
        "@mosdns-test-{}-{}.sock",
        std::process::id(),
        rand::random::<u64>()
    );
    let listener = socket::bind_stream(&name).await.unwrap();
    assert!(std::path::Path::new(&name).exists());
    let _client = UnixStream::connect(&name).await.unwrap();
    let (_, peer) = listener.accept().await.unwrap();
    assert!(peer.is_none());
    drop(listener);
    assert!(!std::path::Path::new(&name).exists());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn go_at_name_uses_the_linux_abstract_namespace() {
    use std::os::linux::net::SocketAddrExt;
    let name = format!(
        "mosdns-test-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    );
    let listener = socket::bind_stream(&format!("@{name}")).await.unwrap();
    let address = std::os::unix::net::SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let client = std::os::unix::net::UnixStream::connect_addr(&address).unwrap();
    client.set_nonblocking(true).unwrap();
    let mut client = UnixStream::from_std(client).unwrap();
    let (mut server, peer) = listener.accept().await.unwrap();
    assert!(peer.is_none());
    client.write_all(b"abstract").await.unwrap();
    let mut message = [0; 8];
    server.read_exact(&mut message).await.unwrap();
    assert_eq!(&message, b"abstract");
    assert!(!std::path::Path::new(&format!("@{name}")).exists());
}
