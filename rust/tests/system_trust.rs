// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

//! Each trust case runs in a subprocess: SSL_CERT_FILE/DIR never alter the
//! parent process or the operating system's certificate store.

#![cfg(feature = "full")]
use bytes::{Buf, Bytes};
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{rdata::A, Name, RData, Record, RecordType},
};
use mosdns_rs::pkg::upstream::{Options, Upstream};
use std::{net::SocketAddr, process::Command, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};

const CA: &[u8] = include_bytes!("../src/pkg/upstream/fixtures/system-trust/ca.pem");
const OTHER_CA: &[u8] =
    include_bytes!("../src/pkg/upstream/fixtures/system-trust/untrusted-ca.pem");
const PROTOCOLS: &[&str] = &["dot", "doh", "doh-custom", "doq", "h3", "probe"];

fn run_cases(scenario: &str) {
    let directory = tempfile::tempdir().unwrap();
    let ca_path = directory.path().join("roots.pem");
    let cert_dir = directory.path().join("certs");
    std::fs::create_dir(&cert_dir).unwrap();
    let mut contents = CA.to_vec();
    if scenario == "untrusted" || scenario == "insecure" {
        contents = OTHER_CA.to_vec();
    } else if scenario == "malformed" {
        contents =
            b"-----BEGIN CERTIFICATE-----\n!bad-base64!\n-----END CERTIFICATE-----\n".to_vec();
    } else if scenario == "partial" {
        contents
            .extend_from_slice(b"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n");
    }
    if scenario != "missing" {
        std::fs::write(&ca_path, contents).unwrap();
    }
    if scenario == "directory" || scenario == "directory-only" {
        std::fs::write(cert_dir.join("test-ca.pem"), CA).unwrap();
        std::fs::write(&ca_path, b"").unwrap();
    }
    let extra_dir = directory.path().join("extra-certs");
    let cert_dirs = if scenario == "directory-list" {
        std::fs::create_dir(&extra_dir).unwrap();
        std::fs::write(extra_dir.join("test-ca.pem"), CA).unwrap();
        std::fs::write(&ca_path, b"").unwrap();
        std::env::join_paths([&cert_dir, &extra_dir]).unwrap()
    } else {
        cert_dir.as_os_str().to_owned()
    };
    let mut failures = Vec::new();
    for protocol in PROTOCOLS {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "system_trust_child", "--nocapture"])
            .env("MOSDNS_TRUST_SCENARIO", scenario)
            .env("MOSDNS_TRUST_PROTOCOL", protocol)
            .env("SSL_CERT_FILE", &ca_path)
            .env("SSL_CERT_DIR", &cert_dirs);
        if scenario == "file-only" {
            command.env_remove("SSL_CERT_DIR");
        } else if scenario == "directory-only" {
            command.env_remove("SSL_CERT_FILE");
        }
        let output = command.output().unwrap();
        if !output.status.success() {
            failures.push(format!(
                "{protocol}/{scenario}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn private_ca_file_is_trusted_by_all_tls_transports() {
    run_cases("trusted");
}

#[test]
fn private_ca_directory_is_trusted_by_all_tls_transports() {
    run_cases("directory");
}

#[test]
fn private_ca_directory_list_is_trusted_by_all_tls_transports() {
    run_cases("directory-list");
}

#[test]
fn single_ca_file_override_is_trusted_by_all_tls_transports() {
    run_cases("file-only");
}

#[test]
fn single_ca_directory_override_is_trusted_by_all_tls_transports() {
    run_cases("directory-only");
}

#[test]
fn native_platform_roots_can_build_all_tls_clients() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "system_trust_child", "--nocapture"])
        .env("MOSDNS_TRUST_SCENARIO", "native")
        .env_remove("SSL_CERT_FILE")
        .env_remove("SSL_CERT_DIR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unrelated_ca_rejects_all_tls_transports() {
    run_cases("untrusted");
}

#[test]
fn trusted_ca_still_checks_original_tls_identity() {
    run_cases("wrong-name");
}

#[test]
fn explicit_insecure_bypasses_untrusted_ca() {
    run_cases("insecure");
}

#[test]
fn malformed_ca_fails_closed_and_insecure_can_bypass_it() {
    run_cases("malformed");
}

#[test]
fn missing_ca_fails_closed_and_insecure_can_bypass_it() {
    run_cases("missing");
}

#[test]
fn valid_roots_survive_an_unusable_certificate() {
    run_cases("partial");
}

fn query() -> Message {
    let mut query = Message::new();
    query.set_id(571).add_query(Query::query(
        Name::from_ascii("private-ca.example.").unwrap(),
        RecordType::A,
    ));
    query
}

fn answer(mut query: Message) -> Vec<u8> {
    query.set_message_type(MessageType::Response);
    query.add_answer(Record::from_rdata(
        query.queries()[0].name().clone(),
        60,
        RData::A(A("192.0.2.10".parse().unwrap())),
    ));
    query.to_vec().unwrap()
}

fn server_config(alpn: &[u8]) -> rustls::ServerConfig {
    let cert = rustls::pki_types::CertificateDer::from(
        include_bytes!("../src/pkg/upstream/fixtures/system-trust/server-cert.der").to_vec(),
    );
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
        include_bytes!("../src/pkg/upstream/fixtures/system-trust/server-key.der").to_vec(),
    );
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(vec![cert], key.into())
    .unwrap();
    config.alpn_protocols = vec![alpn.to_vec()];
    config
}

async fn tcp_server(http: bool, queries: usize) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let Ok(mut stream) = tokio_rustls::TlsAcceptor::from(Arc::new(server_config(if http {
            b"http/1.1"
        } else {
            b"dot"
        })))
        .accept(socket)
        .await
        else {
            return;
        };
        for _ in 0..queries {
            let length = if http {
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(stream.read_u8().await.unwrap());
                    assert!(headers.len() < 8192);
                }
                let headers = String::from_utf8(headers).unwrap().to_ascii_lowercase();
                assert!(headers.starts_with("post /dns-query http/1.1\r\n"));
                headers
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length: "))
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
            } else {
                usize::from(stream.read_u16().await.unwrap())
            };
            let mut payload = vec![0; length];
            stream.read_exact(&mut payload).await.unwrap();
            let response = answer(Message::from_vec(&payload).unwrap());
            if http {
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", response.len()).as_bytes()).await.unwrap();
            } else {
                stream.write_u16(response.len() as u16).await.unwrap();
            }
            stream.write_all(&response).await.unwrap();
            stream.flush().await.unwrap();
        }
        std::future::pending::<()>().await;
    });
    (address, task)
}

fn quic_server(http: bool) -> (SocketAddr, JoinHandle<()>) {
    let config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_config(if http {
            b"h3"
        } else {
            b"doq"
        }))
        .unwrap(),
    ));
    let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let address = endpoint.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let Ok(connection) = endpoint.accept().await.unwrap().await else {
            return;
        };
        if http {
            let mut h3 =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
            let (_, mut stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            let mut payload = Vec::new();
            while let Some(mut data) = stream.recv_data().await.unwrap() {
                let length = data.remaining();
                payload.extend_from_slice(&data.copy_to_bytes(length));
            }
            stream
                .send_response(
                    hyper::Response::builder()
                        .header("content-type", "application/dns-message")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            stream
                .send_data(Bytes::from(answer(Message::from_vec(&payload).unwrap())))
                .await
                .unwrap();
            stream.finish().await.unwrap();
            let _ = h3.accept().await;
        } else {
            let (mut send, mut receive) = connection.accept_bi().await.unwrap();
            let frame = receive.read_to_end(65537).await.unwrap();
            let response = answer(Message::from_vec(&frame[2..]).unwrap());
            send.write_all(&(response.len() as u16).to_be_bytes())
                .await
                .unwrap();
            send.write_all(&response).await.unwrap();
            send.finish().unwrap();
            std::future::pending::<()>().await;
        }
    });
    (address, task)
}

#[tokio::test]
async fn system_trust_child() {
    let Ok(scenario) = std::env::var("MOSDNS_TRUST_SCENARIO") else {
        return;
    };
    if scenario == "native" {
        for scheme in ["tls", "https", "doq", "h3"] {
            Upstream::new(
                &format!("{scheme}://dns.test.invalid"),
                Duration::from_secs(3),
            )
            .unwrap();
        }
        Upstream::new_with_options(
            "https://192.0.2.1/dns-query",
            Duration::from_secs(3),
            Options {
                dial_addr: "127.0.0.1:443".to_owned(),
                ..Default::default()
            },
        )
        .unwrap();
        return;
    }
    let protocol = std::env::var("MOSDNS_TRUST_PROTOCOL").unwrap();
    let http = protocol == "doh" || protocol == "doh-custom" || protocol == "h3";
    let (address, server) = if protocol == "doq" || protocol == "h3" {
        quic_server(http)
    } else {
        tcp_server(http, if protocol == "probe" { 3 } else { 1 }).await
    };
    if protocol == "probe" {
        let url = format!(
            "tls://{}:{}",
            if scenario == "wrong-name" {
                "localhost"
            } else {
                "127.0.0.1"
            },
            address.port()
        );
        let response = mosdns_rs::tools::run(&["probe".into(), "conn-reuse".into(), url]).await;
        if matches!(scenario.as_str(), "untrusted" | "wrong-name" | "insecure") {
            // The CLI deliberately has no insecure switch.
            let error = format!("{:#}", response.unwrap_err()).to_ascii_lowercase();
            assert!(error.contains("cert") || error.contains("tls"), "{error}");
        } else if scenario == "missing" || scenario == "malformed" {
            assert!(format!("{:#}", response.unwrap_err()).contains("system TLS trust"));
        } else {
            response.unwrap_or_else(|error| panic!("probe: {error:#}"));
        }
        server.abort();
        return;
    }
    let host = if protocol == "doh-custom" {
        // IP URL + dial override selects the explicit Hyper DoH backend.
        if scenario == "wrong-name" {
            "192.0.2.2"
        } else {
            "192.0.2.1"
        }
    } else if scenario == "wrong-name" {
        "wrong.test.invalid"
    } else {
        "dns.test.invalid"
    };
    let scheme = match protocol.as_str() {
        "dot" => "tls",
        "doh" | "doh-custom" => "https",
        "doq" => "doq",
        _ => "h3",
    };
    let url = format!(
        "{scheme}://{host}:{}/{}",
        address.port(),
        if http { "dns-query" } else { "" }
    );
    let mut options = Options {
        dial_addr: address.to_string(),
        insecure_skip_verify: scenario == "insecure",
        ..Default::default()
    };
    if scenario == "missing" || scenario == "malformed" {
        let error = Upstream::new_with_options(&url, Duration::from_secs(3), options.clone())
            .err()
            .expect("invalid explicit trust path must fail at construction");
        assert!(format!("{error:#}").contains("system TLS trust"));
        options.insecure_skip_verify = true;
    }
    let upstream = Upstream::new_with_options(&url, Duration::from_secs(3), options).unwrap();
    let query = query();
    let response = upstream.exchange(&query).await;
    if scenario == "untrusted" || scenario == "wrong-name" {
        let error = response.expect_err("untrusted certificate or wrong identity must be rejected");
        let error = format!("{error:#}").to_ascii_lowercase();
        assert!(error.contains("cert") || error.contains("tls"), "{error}");
    } else {
        let response = response.unwrap_or_else(|error| panic!("{protocol}: {error:#}"));
        assert_eq!(response.id(), query.id());
        assert_eq!(response.queries(), query.queries());
        assert_eq!(response.answers().len(), 1);
        assert_eq!(
            response.answers()[0].data(),
            Some(&RData::A(A("192.0.2.10".parse().unwrap())))
        );
    }
    server.abort();
}
