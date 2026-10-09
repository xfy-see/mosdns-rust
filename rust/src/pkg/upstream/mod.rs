//! DNS upstreams. Traditional transports share persistent, pipelined connections.

#[cfg(feature = "full")]
mod bootstrap;
mod dialer;
mod events;
#[cfg(feature = "full")]
mod http3;
#[cfg(feature = "full")]
mod https;
mod options;
#[cfg(feature = "full")]
mod quic;
mod transport;
#[cfg(feature = "full")]
mod trust;
pub use events::{Event, EventObserver, QueryOutcome};
#[cfg(feature = "full")]
pub use options::tls_client_config;
pub use options::Options;

use anyhow::{bail, Context, Result};
use hickory_proto::op::{Message, MessageType};
#[cfg(feature = "full")]
use std::sync::Mutex;
use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use transport::{Protocol, Transport};
use url::Url;

#[derive(Clone)]
pub struct Upstream {
    inner: Arc<Inner>,
}

enum Backend {
    #[cfg(feature = "full")]
    Http3(http3::Http3Upstream),
    #[cfg(feature = "full")]
    HttpsCustom(https::HttpsUpstream),
    #[cfg(feature = "full")]
    Quic(quic::QuicUpstream),
    Traditional {
        transport: Transport,
        tcp_fallback: Option<Transport>,
    },
    #[cfg(feature = "full")]
    Https {
        client: Mutex<Option<reqwest::Client>>,
        url: Url,
        host_header: Option<String>,
    },
}

struct Inner {
    backend: Backend,
    timeout: Duration,
    events: events::Lifecycle,
}

/// Address/profile validation is shared by construction and minimal CLI check.
/// It never constructs a transport, reads trust roots, or resolves a hostname.
fn parse_address(addr: &str, options: &mut Options) -> Result<(Url, String)> {
    let address = if let Some(host) = addr.strip_prefix("h3://") {
        options.enable_http3 = true;
        format!("https://{host}")
    } else if addr.contains("://") {
        addr.to_owned()
    } else {
        format!("udp://{addr}")
    };
    let url = Url::parse(&address).context("invalid upstream address")?;
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        bail!("upstream userinfo and fragments are unsupported");
    }
    #[cfg(not(feature = "full"))]
    options::check_profile_options(url.scheme(), options)?;
    let host = url
        .host_str()
        .context("upstream address has no host")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let default_port = match url.scheme() {
        "udp" | "tcp" | "tcp+pipeline" => Some(53),
        #[cfg(feature = "full")]
        "tls" | "tls+pipeline" => Some(853),
        _ => None,
    };
    if let Some(default_port) = default_port {
        if url.port().unwrap_or(default_port) == 0 {
            bail!("upstream port must be nonzero");
        }
        if !matches!(url.path(), "" | "/") || url.query().is_some() {
            bail!("traditional upstream addresses cannot have paths or query parameters");
        }
    }
    #[cfg(not(feature = "full"))]
    {
        let (dial_host, _) =
            options::dial_target(&host, url.port().unwrap_or(53), &options.dial_addr)?;
        if dial_host.parse::<std::net::IpAddr>().is_err() {
            bail!("minimal upstream address must be a numeric IP address");
        }
    }
    Ok((url, host))
}

impl Upstream {
    /// Parse `[protocol://]host[:port][/path]`; the default protocol is UDP.
    pub fn new(addr: &str, timeout: Duration) -> Result<Self> {
        Self::new_with_options(addr, timeout, Options::default())
    }

    /// Check the minimal address/options without a runtime, socket or transport.
    #[cfg(not(feature = "full"))]
    pub fn validate_options(addr: &str, options: &Options) -> Result<()> {
        parse_address(addr, &mut options.clone()).map(|_| ())
    }

    #[allow(unused_mut)] // URL port overrides are only used by full-profile DoH.
    pub fn new_with_options(addr: &str, timeout: Duration, mut options: Options) -> Result<Self> {
        if timeout.is_zero() {
            bail!("upstream timeout must be positive");
        }
        let (mut url, host) = parse_address(addr, &mut options)?;
        let backend = match url.scheme() {
            "udp" | "tcp" | "tcp+pipeline" | "tls" | "tls+pipeline" => {
                let protocol = match url.scheme() {
                    "udp" => Protocol::Udp,
                    "tcp" | "tcp+pipeline" => Protocol::Tcp,
                    #[cfg(feature = "full")]
                    _ => Protocol::Tls,
                    #[cfg(not(feature = "full"))]
                    other => bail!("protocol [{other}] is unavailable in minimal (supports udp/tcp)"),
                };
                let default_port = match protocol {
                    #[cfg(feature = "full")]
                    Protocol::Tls => 853,
                    _ => 53,
                };
                let port = url.port().unwrap_or(default_port);
                // Go's UDP TCP fallback is direct too, never SOCKS5.
                let mut direct_options = options.clone();
                if protocol == Protocol::Udp { direct_options.socks5.clear(); }
                if matches!(url.scheme(), "tcp+pipeline" | "tls+pipeline") {
                    direct_options.enable_pipeline = true;
                }
                let mut fallback_options = direct_options.clone();
                fallback_options.enable_pipeline = false;
                // Go creates a separate TCP reuse transport with its default
                // 10-second idle timeout, independent of the UDP options.
                fallback_options.idle_timeout = Duration::ZERO;
                Backend::Traditional {
                    transport: Transport::new(protocol, host.clone(), port).configure(&direct_options)?,
                    tcp_fallback: (protocol == Protocol::Udp)
                        .then(|| Transport::new(Protocol::Tcp, host, port).configure(&fallback_options)).transpose()?,
                }
            }
            #[cfg(feature = "full")]
            "https" if options.enable_http3 => Backend::Http3(http3::Http3Upstream::new(url, &options)?),
            #[cfg(feature = "full")]
            "https" if !options.socks5.is_empty() || options.so_mark > 0
                || !options.bind_to_device.is_empty()
                || options.event_observer.is_some()
                || (!options.dial_addr.is_empty() && host.parse::<std::net::IpAddr>().is_ok()) => {
                Backend::HttpsCustom(https::HttpsUpstream::new(url, &options)?)
            }
            #[cfg(feature = "full")]
            "https" => {
                let mut tls = (*options::tls_client_config(options.insecure_skip_verify, b"h2")?).clone();
                tls.alpn_protocols.push(b"http/1.1".to_vec());
                let mut client = reqwest::Client::builder()
                    .no_proxy()
                    .timeout(timeout)
                    .pool_idle_timeout(if options.idle_timeout.is_zero() { Duration::from_secs(30) } else { options.idle_timeout })
                    .redirect(reqwest::redirect::Policy::none())
                    .use_preconfigured_tls(tls);
                let mut host_header = None;
                if !options.dial_addr.is_empty() || !options.bootstrap.is_empty() {
                    let original_port = url.port().unwrap_or(443);
                    let (dial_host, dial_port) = options::dial_target(&host, original_port, &options.dial_addr)?;
                    let authority = match url.port() {
                        Some(port) => format!("{}:{port}", url.host_str().unwrap()),
                        None => url.host_str().unwrap().to_owned(),
                    };
                    url.set_port(Some(dial_port)).map_err(|_| anyhow::anyhow!("invalid DoH dial port"))?;
                    host_header = Some(authority);
                    let mut resolver_options = options.clone();
                    resolver_options.dial_addr = dial_host;
                    client = client.dns_resolver(Arc::new(options::DialResolver {
                        dialer: dialer::Dialer::new(host.clone(), dial_port, &resolver_options)?,
                    }));
                }
                let client = client.build().context("build DoH client")?;
                Backend::Https { client: Mutex::new(Some(client)), url, host_header }
            }
            #[cfg(feature = "full")]
            "quic" | "doq" => {
                if !matches!(url.path(), "" | "/") || url.query().is_some() {
                    bail!("QUIC upstream addresses cannot have paths or query parameters");
                }
                let port = url.port().unwrap_or(853);
                if port == 0 { bail!("upstream port must be nonzero"); }
                let mut direct_options = options.clone();
                direct_options.socks5.clear();
                Backend::Quic(quic::QuicUpstream::new(host, port, &direct_options)?)
            }
            #[cfg(feature = "full")]
            other => bail!("unsupported DNS upstream protocol: {other} (supported: udp, tcp, tls, https, quic)"),
            #[cfg(not(feature = "full"))]
            other => bail!("protocol [{other}] is unavailable in minimal (supports udp/tcp)"),
        };
        Ok(Self {
            inner: Arc::new(Inner {
                backend,
                timeout,
                events: events::Lifecycle::new(options.event_observer),
            }),
        })
    }

    pub async fn exchange(&self, query: &Message) -> Result<Message> {
        let active = self.inner.events.enter();
        let mut observed = self
            .inner
            .events
            .observer
            .as_deref()
            .map(events::QueryGuard::start);
        let result = if active.is_some() {
            self.exchange_observed(query).await
        } else {
            Err(anyhow::anyhow!("DNS upstream closed"))
        };
        if let Some(observed) = observed.as_mut() {
            observed.finish(if result.is_ok() {
                QueryOutcome::Success
            } else {
                QueryOutcome::Error
            });
        }
        // Query callbacks and transport cleanup complete before close can
        // proceed with pool draining, including a success racing shutdown.
        drop(active);
        result
    }

    /// Close the shared upstream and reject subsequent queries from any clone.
    pub async fn close(&self) -> Result<()> {
        let _closing = self.inner.events.close_lock.lock().await;
        // Repeating cleanup also completes a close future cancelled midway.
        self.inner.events.closed.store(true, Ordering::Release);
        self.inner.events.closing.notify_waiters();
        self.inner.events.wait_drained().await;
        match &self.inner.backend {
            Backend::Traditional {
                transport,
                tcp_fallback,
            } => {
                transport.close().await;
                if let Some(tcp) = tcp_fallback {
                    tcp.close().await;
                }
            }
            #[cfg(feature = "full")]
            Backend::Https { client, .. } => {
                client.lock().unwrap().take();
            }
            #[cfg(feature = "full")]
            Backend::HttpsCustom(upstream) => upstream.close().await,
            #[cfg(feature = "full")]
            Backend::Quic(upstream) => upstream.close().await,
            #[cfg(feature = "full")]
            Backend::Http3(upstream) => upstream.close().await,
        }
        Ok(())
    }

    async fn exchange_observed(&self, query: &Message) -> Result<Message> {
        let closing = self.inner.events.closing.notified();
        tokio::pin!(closing);
        closing.as_mut().enable();
        if self.inner.events.closed.load(Ordering::Acquire) {
            bail!("DNS upstream closed");
        }
        if query.message_type() != MessageType::Query || query.queries().is_empty() {
            bail!("upstream requires a DNS query with at least one question");
        }
        tokio::select! {
            biased;
            () = &mut closing => Err(anyhow::anyhow!("DNS upstream closed")),
            result = tokio::time::timeout(self.inner.timeout, self.exchange_inner(query)) => result.context("DNS upstream timeout")?,
        }
    }

    async fn exchange_inner(&self, query: &Message) -> Result<Message> {
        match &self.inner.backend {
            #[cfg(feature = "full")]
            Backend::Http3(upstream) => upstream.exchange(query).await,
            #[cfg(feature = "full")]
            Backend::HttpsCustom(upstream) => upstream.exchange(query).await,
            #[cfg(feature = "full")]
            Backend::Quic(upstream) => upstream.exchange(query).await,
            Backend::Traditional {
                transport,
                tcp_fallback,
            } => {
                let response = transport.exchange(query).await?;
                if response.truncated() {
                    if let Some(tcp) = tcp_fallback {
                        return tcp
                            .exchange(query)
                            .await
                            .context("UDP truncated response TCP fallback");
                    }
                }
                Ok(response)
            }
            #[cfg(feature = "full")]
            Backend::Https {
                client,
                url,
                host_header,
            } => {
                let client = client
                    .lock()
                    .unwrap()
                    .as_ref()
                    .cloned()
                    .context("DNS upstream closed")?;
                let payload = query.to_vec().context("encode DNS query")?;
                let mut request = client
                    .post(url.clone())
                    .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
                    .header(reqwest::header::ACCEPT, "application/dns-message")
                    .body(payload);
                if let Some(host) = host_header {
                    request = request.header(reqwest::header::HOST, host);
                }
                let mut response = request
                    .send()
                    .await
                    .context("DoH request")?
                    .error_for_status()
                    .context("DoH HTTP status")?;
                let content_type = response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or("")
                    .split(';')
                    .next()
                    .unwrap_or("")
                    .trim();
                if !content_type.eq_ignore_ascii_case("application/dns-message") {
                    bail!("invalid DoH content-type: {content_type}");
                }
                if response
                    .content_length()
                    .is_some_and(|length| length > 65535)
                {
                    bail!("DoH DNS message exceeds 65535 bytes");
                }
                let mut payload = Vec::with_capacity(512);
                while let Some(chunk) = response.chunk().await.context("read DoH response")? {
                    if payload.len() + chunk.len() > 65535 {
                        bail!("DoH DNS message exceeds 65535 bytes");
                    }
                    payload.extend_from_slice(&chunk);
                }
                let message = Message::from_vec(&payload).context("invalid DoH DNS response")?;
                validate_response(query, &message)?;
                Ok(message)
            }
        }
    }
}

pub(crate) fn validate_response(query: &Message, response: &Message) -> Result<()> {
    if response.id() != query.id() {
        bail!("DNS response ID mismatch");
    }
    if response.message_type() != MessageType::Response {
        bail!("DNS response has QR=0");
    }
    if response.op_code() != query.op_code() {
        bail!("DNS response opcode mismatch");
    }
    if response.queries() != query.queries() {
        bail!("DNS response question mismatch");
    }
    Ok(())
}

#[cfg(all(test, feature = "full"))]
mod advanced_tests;
#[cfg(all(test, not(feature = "full")))]
mod minimal_tests;
#[cfg(test)]
mod tests;
