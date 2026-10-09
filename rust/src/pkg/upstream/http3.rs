// SPDX-License-Identifier: GPL-3.0-or-later
//! DoH over HTTP/3, retaining URL authority and TLS identity with dial overrides.
use super::dialer::Dialer;
use super::{options, validate_response, Options};
use anyhow::{bail, Context, Result};
use bytes::{Buf, Bytes};
use hickory_proto::op::Message;
use std::{sync::Arc, time::Duration};
use tokio::sync::{Mutex, Semaphore};
use url::Url;

type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

struct Session {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    sender: Sender,
    driver: tokio::task::AbortHandle,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"closed");
        self.driver.abort();
    }
}

pub(super) struct Http3Upstream {
    url: Url,
    host: String,
    dialer: Dialer,
    config: quinn::ClientConfig,
    session: Mutex<Option<Session>>,
    limit: Semaphore,
}
impl Http3Upstream {
    pub(super) async fn close(&self) {
        self.session.lock().await.take();
    }
    pub(super) fn new(url: Url, options: &Options) -> Result<Self> {
        let host = url
            .host_str()
            .context("HTTP/3 URL has no host")?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let mut udp_options = options.clone();
        udp_options.socks5.clear();
        let dialer = Dialer::new(host.clone(), url.port().unwrap_or(443), &udp_options)?;
        let tls = options::tls_client_config(options.insecure_skip_verify, b"h3")?;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls.as_ref().clone())?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(0u8.into())
            .max_idle_timeout(Some(
                if options.idle_timeout.is_zero() {
                    Duration::from_secs(30)
                } else {
                    options.idle_timeout
                }
                .try_into()?,
            ));
        config.transport_config(Arc::new(transport));
        Ok(Self {
            url,
            host,
            dialer,
            config,
            session: Mutex::new(None),
            limit: Semaphore::new(1024),
        })
    }

    async fn sender(&self) -> Result<Sender> {
        let mut session = self.session.lock().await;
        if let Some(s) = session.as_ref() {
            if s.connection.close_reason().is_none() && !s.driver.is_finished() {
                return Ok(s.sender.clone());
            }
        }
        let remote = self.dialer.resolve().await?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            self.dialer.bind_udp(remote)?,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(self.config.clone());
        let connection = endpoint
            .connect(remote, &self.host)?
            .await
            .context("HTTP/3 TLS handshake")?;
        let (mut driver, sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone())).await?;
        let driver = tokio::spawn(async move {
            driver.wait_idle().await;
        })
        .abort_handle();
        *session = Some(Session {
            endpoint,
            connection,
            sender: sender.clone(),
            driver,
        });
        Ok(sender)
    }

    pub(super) async fn exchange(&self, query: &Message) -> Result<Message> {
        let _permit = self.limit.acquire().await?;
        let mut sender = self.sender().await?;
        let payload = query.to_vec()?;
        if payload.len() > 65535 {
            bail!("HTTP/3 DNS query exceeds 65535 bytes");
        }
        let request = hyper::Request::post(self.url.as_str())
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())?;
        let mut stream = sender
            .send_request(request)
            .await
            .context("HTTP/3 request")?;
        stream.send_data(Bytes::from(payload)).await?;
        stream.finish().await?;
        let response = stream.recv_response().await?;
        if !response.status().is_success() {
            bail!("HTTP/3 status {}", response.status());
        }
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim();
        if !content_type.eq_ignore_ascii_case("application/dns-message") {
            bail!("invalid HTTP/3 DoH content-type");
        }
        if response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|v| v > 65535)
        {
            bail!("HTTP/3 DNS response exceeds 65535 bytes");
        }
        let mut payload = Vec::with_capacity(512);
        while let Some(mut chunk) = stream.recv_data().await? {
            if payload.len() + chunk.remaining() > 65535 {
                bail!("HTTP/3 DNS response exceeds 65535 bytes");
            }
            let n = chunk.remaining();
            payload.extend_from_slice(&chunk.copy_to_bytes(n));
        }
        let response = Message::from_vec(&payload).context("invalid HTTP/3 DNS response")?;
        validate_response(query, &response)?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{MessageType, Query},
        rr::{rdata::A, Name, RData, Record, RecordType},
    };

    fn query(id: u16) -> Message {
        let mut q = Message::new();
        q.set_id(id).add_query(Query::query(
            Name::from_ascii(format!("h3-{id}.example.")).unwrap(),
            RecordType::A,
        ));
        q
    }
    fn server() -> quinn::Endpoint {
        let cert = rustls::pki_types::CertificateDer::from(
            include_bytes!("fixtures/localhost-cert.der").to_vec(),
        );
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
            include_bytes!("fixtures/localhost-key.der").to_vec(),
        );
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap(),
        ));
        quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap()
    }

    #[tokio::test]
    async fn http3_reuses_connection_and_preserves_authority_dial_override_and_ids() {
        let endpoint = server();
        let address = endpoint.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let connection = endpoint.accept().await.unwrap().await.unwrap();
            let mut h3 =
                h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                    .await
                    .unwrap();
            let mut requests = tokio::task::JoinSet::new();
            for _ in 0..16 {
                let resolver = h3.accept().await.unwrap().unwrap();
                requests.spawn(async move {
                    let (request, mut stream) = resolver.resolve_request().await.unwrap();
                    assert_eq!(request.method(), hyper::Method::POST);
                    assert_eq!(
                        request.uri().authority().unwrap().as_str(),
                        "dns.example:8443"
                    );
                    assert_eq!(
                        request.uri().path_and_query().unwrap().as_str(),
                        "/custom-dns?key=test"
                    );
                    let mut payload = Vec::new();
                    while let Some(mut data) = stream.recv_data().await.unwrap() {
                        let n = data.remaining();
                        payload.extend_from_slice(&data.copy_to_bytes(n));
                    }
                    let mut response = Message::from_vec(&payload).unwrap();
                    response.set_message_type(MessageType::Response);
                    response.add_answer(Record::from_rdata(
                        response.queries()[0].name().clone(),
                        60,
                        RData::A(A("192.0.2.1".parse().unwrap())),
                    ));
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
                        .send_data(Bytes::from(response.to_vec().unwrap()))
                        .await
                        .unwrap();
                    stream.finish().await.unwrap();
                });
            }
            // Keep polling HTTP/3 control streams until the client has read all responses.
            tokio::select! {
                _ = async { while let Some(result) = requests.join_next().await { result.unwrap(); } } => {},
                _ = h3.accept() => panic!("unexpected extra request"),
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let options = Options {
            dial_addr: address.to_string(),
            insecure_skip_verify: true,
            ..Default::default()
        };
        let upstream = Arc::new(
            Http3Upstream::new(
                Url::parse("https://dns.example:8443/custom-dns?key=test").unwrap(),
                &options,
            )
            .unwrap(),
        );
        let mut requests = tokio::task::JoinSet::new();
        for id in 0..16 {
            let upstream = upstream.clone();
            requests.spawn(async move {
                let q = query(id);
                let r = tokio::time::timeout(Duration::from_secs(3), upstream.exchange(&q))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(r.id(), id);
                assert_eq!(r.queries(), q.queries());
                assert_eq!(r.answers().len(), 1);
            });
        }
        while let Some(result) = requests.join_next().await {
            result.unwrap();
        }
        task.await.unwrap();
    }

    #[tokio::test]
    async fn http3_verifies_certificates_by_default() {
        let endpoint = server();
        let address = endpoint.local_addr().unwrap();
        let task = tokio::spawn(async move {
            assert!(endpoint.accept().await.unwrap().await.is_err());
        });
        let upstream = Http3Upstream::new(
            Url::parse(&format!("https://{address}/dns-query")).unwrap(),
            &Options::default(),
        )
        .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), upstream.exchange(&query(1)))
                .await
                .unwrap()
                .is_err()
        );
        task.await.unwrap();
    }
}
