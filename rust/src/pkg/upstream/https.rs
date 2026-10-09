// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

//! DoH with an explicit dialer, retaining the original TLS and HTTP identity.

use super::{
    dialer::Dialer,
    events::{close_connection, ConnectionGuard, ObservedIo},
    options, validate_response, EventObserver, Options,
};
use anyhow::{bail, Context, Result};
use bytes::Bytes;
use hickory_proto::op::Message;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::{sync::Mutex, task::AbortHandle};
use url::Url;

pub(super) struct HttpsUpstream {
    url: Url,
    host: String,
    authority: String,
    dialer: Dialer,
    tls: Arc<rustls::ClientConfig>,
    idle_timeout: Duration,
    session: Arc<Mutex<Option<Arc<Session>>>>,
    observer: Option<Arc<dyn EventObserver>>,
}

enum Sender {
    Http1(Mutex<hyper::client::conn::http1::SendRequest<Full<Bytes>>>),
    Http2(hyper::client::conn::http2::SendRequest<Full<Bytes>>),
}
struct Session {
    sender: Sender,
    task: AbortHandle,
    last_used: std::sync::Mutex<Instant>,
    closed: AtomicBool,
    event: Option<Arc<ConnectionGuard>>,
}
impl Session {
    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        close_connection(&self.event);
        self.task.abort();
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}

struct Http1RequestGuard {
    session: Arc<Session>,
    completed: bool,
}
impl Drop for Http1RequestGuard {
    fn drop(&mut self) {
        if !self.completed {
            self.session.close();
        }
    }
}

impl HttpsUpstream {
    pub(super) fn new(url: Url, options: &Options) -> Result<Self> {
        let host = url
            .host_str()
            .context("DoH has no hostname")?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let authority = match url.port() {
            Some(port) => format!("{}:{port}", url.host_str().unwrap()),
            None => url.host_str().unwrap().to_owned(),
        };
        let dialer = Dialer::new(host.clone(), url.port().unwrap_or(443), options)?;
        let mut tls = options::tls_client_config(options.insecure_skip_verify, b"h2")?
            .as_ref()
            .clone();
        tls.alpn_protocols.push(b"http/1.1".to_vec());
        Ok(Self {
            url,
            host,
            authority,
            dialer,
            tls: Arc::new(tls),
            idle_timeout: if options.idle_timeout.is_zero() {
                Duration::from_secs(30)
            } else {
                options.idle_timeout
            },
            session: Arc::new(Mutex::new(None)),
            observer: options.event_observer.clone(),
        })
    }

    async fn connect(&self) -> Result<Session> {
        let tcp = self.dialer.tcp().await?;
        let event = ConnectionGuard::open(&self.observer);
        let tcp = ObservedIo::new(tcp, event.clone());
        let name = rustls::pki_types::ServerName::try_from(self.host.clone())
            .context("invalid DoH TLS name")?;
        let tls = tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, tcp)
            .await
            .context("DoH TLS handshake")?;
        let http2 = tls.get_ref().1.alpn_protocol() == Some(b"h2");
        let io = TokioIo::new(tls);
        let (sender, task) = if http2 {
            let (sender, connection) =
                hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                    .max_header_list_size(4096)
                    .handshake(io)
                    .await
                    .context("DoH HTTP/2 handshake")?;
            (
                Sender::Http2(sender),
                tokio::spawn(async move {
                    let _ = connection.await;
                })
                .abort_handle(),
            )
        } else {
            let (sender, connection) = hyper::client::conn::http1::Builder::new()
                .max_buf_size(8192)
                .handshake(io)
                .await
                .context("DoH HTTP/1 handshake")?;
            (
                Sender::Http1(Mutex::new(sender)),
                tokio::spawn(async move {
                    let _ = connection.await;
                })
                .abort_handle(),
            )
        };
        Ok(Session {
            sender,
            task,
            last_used: std::sync::Mutex::new(Instant::now()),
            closed: AtomicBool::new(false),
            event,
        })
    }

    pub(super) async fn close(&self) {
        if let Some(session) = self.session.lock().await.take() {
            session.close();
        }
    }

    pub(super) async fn exchange(&self, query: &Message) -> Result<Message> {
        let payload = query.to_vec()?;
        if payload.len() > 65535 {
            bail!("DoH DNS query exceeds 65535 bytes");
        }
        let session = {
            let mut current = self.session.lock().await;
            if current.as_ref().is_some_and(|s| {
                s.closed.load(Ordering::Acquire)
                    || s.task.is_finished()
                    || (Arc::strong_count(s) == 1
                        && s.last_used.lock().unwrap().elapsed() >= self.idle_timeout)
            }) {
                *current = None;
            }
            if current.is_none() {
                let session = Arc::new(self.connect().await?);
                let weak = Arc::downgrade(&session);
                let pool = Arc::downgrade(&self.session);
                let idle_timeout = self.idle_timeout;
                tokio::spawn(async move {
                    let mut interval =
                        tokio::time::interval(idle_timeout.min(Duration::from_secs(1)));
                    loop {
                        interval.tick().await;
                        let Some(pool) = pool.upgrade() else {
                            return;
                        };
                        let _pool_guard = pool.lock().await;
                        let Some(session) = weak.upgrade() else {
                            return;
                        };
                        if session.closed.load(Ordering::Acquire) || session.task.is_finished() {
                            return;
                        }
                        // The pool and this temporary weak upgrade own two
                        // strong references; an active request owns another.
                        if Arc::strong_count(&session) == 2
                            && session.last_used.lock().unwrap().elapsed() >= idle_timeout
                        {
                            session.close();
                            return;
                        }
                    }
                });
                *current = Some(session);
            }
            current.as_ref().unwrap().clone()
        };
        let uri = if matches!(&session.sender, Sender::Http2(_)) {
            self.url.as_str().to_owned()
        } else {
            let mut path = self.url.path().to_owned();
            if let Some(query) = self.url.query() {
                path.push('?');
                path.push_str(query);
            }
            path
        };
        let request = Request::post(uri)
            .header("host", &self.authority)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(Full::new(Bytes::from(payload)))?;
        let result = match &session.sender {
            Sender::Http1(sender) => {
                // Keep an HTTP/1 request ordered through consumption of its body.
                let mut sender = sender.lock().await;
                let mut guard = Http1RequestGuard {
                    session: session.clone(),
                    completed: false,
                };
                let response = sender.send_request(request).await;
                let response = decode_response(query, response).await;
                guard.completed = true;
                response
            }
            Sender::Http2(sender) => {
                let mut sender = sender.clone();
                let response = sender.send_request(request).await;
                decode_response(query, response).await
            }
        };
        match result {
            Ok(response) => {
                *session.last_used.lock().unwrap() = Instant::now();
                Ok(response)
            }
            Err(error) => {
                let mut current = self.session.lock().await;
                if current.as_ref().is_some_and(|s| Arc::ptr_eq(s, &session)) {
                    *current = None;
                }
                Err(error)
            }
        }
    }
}

async fn decode_response(
    query: &Message,
    response: Result<Response<Incoming>, hyper::Error>,
) -> Result<Message> {
    let payload = read_response(response.context("DoH HTTP request")?).await?;
    let message = Message::from_vec(&payload).context("invalid DoH DNS response")?;
    validate_response(query, &message)?;
    Ok(message)
}

async fn read_response(response: Response<Incoming>) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        bail!("DoH HTTP status {}", response.status());
    }
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim();
    if !content_type.eq_ignore_ascii_case("application/dns-message") {
        bail!("invalid DoH content-type: {content_type}");
    }
    if response
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok())
        .is_some_and(|v| v > 65535)
    {
        bail!("DoH DNS message exceeds 65535 bytes");
    }
    let mut body = response.into_body();
    let mut payload = Vec::with_capacity(512);
    while let Some(frame) = body.frame().await {
        let frame = frame.context("read DoH response")?;
        if let Some(data) = frame.data_ref() {
            if payload.len() + data.len() > 65535 {
                bail!("DoH DNS message exceeds 65535 bytes");
            }
            payload.extend_from_slice(data);
        }
    }
    Ok(payload)
}
