//! RFC 9250: one DNS length frame per bidirectional QUIC stream, with ID zero.

use super::*;
use tokio::sync::{Mutex, Semaphore};

pub(super) struct QuicUpstream {
    host: String,
    port: u16,
    dialer: dialer::Dialer,
    config: quinn::ClientConfig,
    session: Mutex<Option<Session>>,
    limit: Semaphore,
}

struct Session {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"closed");
    }
}

impl QuicUpstream {
    pub(super) async fn close(&self) {
        self.session.lock().await.take();
    }
    pub(super) fn new(host: String, port: u16, options: &Options) -> Result<Self> {
        let tls = options::tls_client_config(options.insecure_skip_verify, b"doq")?;
        let mut upstream = Self::with_tls_config(host, port, tls.as_ref().clone())?;
        upstream.dialer = dialer::Dialer::new(upstream.host.clone(), upstream.port, options)?;
        let mut transport = quinn::TransportConfig::default();
        let idle = if options.idle_timeout.is_zero() {
            Duration::from_secs(30)
        } else {
            options.idle_timeout
        };
        transport
            .max_concurrent_bidi_streams(0u8.into())
            .max_concurrent_uni_streams(0u8.into())
            .max_idle_timeout(Some(idle.try_into()?));
        upstream.config.transport_config(Arc::new(transport));
        Ok(upstream)
    }

    pub(super) fn with_tls_config(
        host: String,
        port: u16,
        mut tls: rustls::ClientConfig,
    ) -> Result<Self> {
        tls.alpn_protocols = vec![b"doq".to_vec()];
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).context("QUIC TLS config")?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport
            .max_concurrent_bidi_streams(0u8.into())
            .max_concurrent_uni_streams(0u8.into())
            .max_idle_timeout(Some(Duration::from_secs(30).try_into()?));
        config.transport_config(Arc::new(transport));
        Ok(Self {
            dialer: dialer::Dialer::new(host.clone(), port, &Options::default())?,
            host,
            port,
            config,
            session: Mutex::new(None),
            limit: Semaphore::new(1024),
        })
    }

    async fn connection(&self) -> Result<quinn::Connection> {
        let mut session = self.session.lock().await;
        if let Some(session) = session.as_ref() {
            if session.connection.close_reason().is_none() {
                return Ok(session.connection.clone());
            }
        }
        let remote = self.dialer.resolve().await?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            self.dialer.bind_udp(remote)?,
            Arc::new(quinn::TokioRuntime),
        )
        .context("bind QUIC client socket")?;
        endpoint.set_default_client_config(self.config.clone());
        let connection = endpoint
            .connect(remote, &self.host)
            .context("connect QUIC upstream")?
            .await
            .context("QUIC handshake")?;
        *session = Some(Session {
            endpoint,
            connection: connection.clone(),
        });
        Ok(connection)
    }

    pub(super) async fn exchange(&self, query: &Message) -> Result<Message> {
        let _permit = self.limit.acquire().await?;
        let connection = self.connection().await?;
        let mut wire_query = query.clone();
        wire_query.set_id(0);
        let payload = wire_query.to_vec()?;
        if payload.len() > 65535 {
            bail!("QUIC DNS query exceeds 65535 bytes");
        }
        let mut frame = Vec::with_capacity(payload.len() + 2);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(&payload);
        let (mut send, mut receive) = connection.open_bi().await.context("open QUIC DNS stream")?;
        send.write_all(&frame)
            .await
            .context("write QUIC DNS query")?;
        send.finish().context("finish QUIC DNS query")?;
        let frame = receive
            .read_to_end(65537)
            .await
            .context("read QUIC DNS response")?;
        if frame.len() < 14 || u16::from_be_bytes([frame[0], frame[1]]) as usize != frame.len() - 2
        {
            connection.close(2u32.into(), b"invalid DNS length frame");
            bail!("invalid QUIC DNS response frame");
        }
        let mut response = Message::from_vec(&frame[2..]).context("invalid QUIC DNS response")?;
        if let Err(error) = validate_response(&wire_query, &response) {
            connection.close(2u32.into(), b"invalid DNS response");
            return Err(error);
        }
        response.set_id(query.id());
        Ok(response)
    }
}
