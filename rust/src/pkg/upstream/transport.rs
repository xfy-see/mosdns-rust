//! Reusable DNS connections with a private ID namespace for simultaneous clients.

use super::{
    dialer::Dialer,
    events::{close_connection, ConnectionGuard, ObservedIo},
    validate_response, EventObserver,
};
use anyhow::{anyhow, bail, Context, Result};
use hickory_proto::op::Message;
use std::time::Duration;
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::UdpSocket,
    sync::{mpsc, oneshot, Notify, Semaphore},
    task::AbortHandle,
};

mod pipeline;
#[cfg(test)]
mod pipeline_tests;
mod reuse;

const TCP_PIPELINE_LIMIT: usize = 64;
const UDP_PIPELINE_LIMIT: usize = 4096;

fn per_connection_limit(protocol: Protocol) -> usize {
    if protocol == Protocol::Udp {
        UDP_PIPELINE_LIMIT
    } else {
        TCP_PIPELINE_LIMIT
    }
}

enum PoolCleaner {
    Reuse(std::sync::Weak<reuse::IdlePool>),
    Pipeline(std::sync::Weak<pipeline::ConnectionPool>),
}

impl PoolCleaner {
    fn clean(&self) {
        match self {
            Self::Reuse(pool) => {
                if let Some(pool) = pool.upgrade() {
                    pool.lock()
                        .unwrap()
                        .retain(|session| session.alive.load(Ordering::Acquire));
                }
            }
            Self::Pipeline(pool) => {
                if let Some(pool) = pool.upgrade() {
                    pool.lock()
                        .unwrap()
                        .retain(|slot| slot.alive.load(Ordering::Acquire));
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Protocol {
    Udp,
    Tcp,
    #[cfg(feature = "full")]
    Tls,
}

pub(super) struct Transport {
    protocol: Protocol,
    host: String,
    port: u16,
    dialer: Dialer,
    idle_timeout: Duration,
    pipeline: bool,
    #[cfg(feature = "full")]
    tls_config: Option<Arc<rustls::ClientConfig>>,
    pool: pipeline::PipelinePool,
    reuse: reuse::ReusePool,
    observer: Option<Arc<dyn EventObserver>>,
}

struct Pending {
    generation: u64,
    query: Message,
    reply: oneshot::Sender<Result<Message>>,
}

type PendingMap = Arc<Mutex<HashMap<u16, Pending>>>;

struct Outbound {
    payload: Vec<u8>,
    is_new_query: bool,
}

struct Session {
    next_generation: AtomicU64,
    outbound: mpsc::Sender<Outbound>,
    pending: PendingMap,
    alive: Arc<AtomicBool>,
    limit: Arc<Semaphore>,
    reader: AbortHandle,
    writer: AbortHandle,
    idle_task: AbortHandle,
    event: Option<Arc<ConnectionGuard>>,
}

#[derive(Clone, Copy)]
struct Deadline {
    until: Option<tokio::time::Instant>,
    waiting_reply: bool,
}

struct ReadDeadline {
    state: Mutex<Deadline>,
    changed: Notify,
    idle_timeout: Duration,
    reply_timeout: Duration,
}

impl ReadDeadline {
    fn new(idle_timeout: Duration, reply_timeout: Duration) -> Self {
        Self {
            state: Mutex::new(Deadline {
                until: tokio::time::Instant::now().checked_add(idle_timeout),
                waiting_reply: false,
            }),
            changed: Notify::new(),
            idle_timeout,
            reply_timeout,
        }
    }
    fn sent(&self) {
        let mut state = self.state.lock().unwrap();
        // Retransmits and additional in-flight requests must not indefinitely
        // extend the health deadline when the peer sends no response.
        if !state.waiting_reply {
            *state = Deadline {
                until: tokio::time::Instant::now().checked_add(self.reply_timeout),
                waiting_reply: true,
            };
            self.changed.notify_one();
        }
    }
    fn received(&self) {
        *self.state.lock().unwrap() = Deadline {
            until: tokio::time::Instant::now().checked_add(self.idle_timeout),
            waiting_reply: false,
        };
        self.changed.notify_one();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.close("upstream connection closed");
    }
}

// Removing a timed-out/cancelled query prevents unbounded growth and ID reuse
// while a live query still owns the same ID.
struct Reservation {
    id: u16,
    generation: u64,
    pending: PendingMap,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut pending = self.pending.lock().unwrap();
        if pending
            .get(&self.id)
            .is_some_and(|entry| entry.generation == self.generation)
        {
            pending.remove(&self.id);
        }
    }
}

impl Transport {
    pub(super) fn new(protocol: Protocol, host: String, port: u16) -> Self {
        Self {
            protocol,
            dialer: Dialer::new(host.clone(), port, &super::Options::default())
                .expect("default dial options are valid"),
            host,
            port,
            // Public construction always calls configure(), which builds TLS
            // trust through the shared options path and can report failures.
            #[cfg(feature = "full")]
            tls_config: None,
            idle_timeout: if protocol == Protocol::Udp {
                Duration::from_secs(300)
            } else {
                Duration::from_secs(10)
            },
            pipeline: protocol == Protocol::Udp,
            pool: pipeline::PipelinePool::default(),
            reuse: reuse::ReusePool::default(),
            observer: None,
        }
    }

    pub(super) fn configure(mut self, options: &super::Options) -> Result<Self> {
        self.dialer = Dialer::new(self.host.clone(), self.port, options)?;
        self.observer = options.event_observer.clone();
        self.pipeline = self.protocol == Protocol::Udp || options.enable_pipeline;
        if !options.idle_timeout.is_zero() {
            self.idle_timeout = options.idle_timeout;
        }
        #[cfg(feature = "full")]
        if self.protocol == Protocol::Tls {
            self.tls_config = Some(super::options::tls_client_config(
                options.insecure_skip_verify,
                b"dot",
            )?);
        }
        Ok(self)
    }

    #[cfg(all(test, feature = "full"))]
    pub(super) fn with_tls_config(
        host: String,
        port: u16,
        config: Arc<rustls::ClientConfig>,
        pipeline: bool,
    ) -> Self {
        Self {
            protocol: Protocol::Tls,
            dialer: Dialer::new(host.clone(), port, &super::Options::default())
                .expect("default dial options are valid"),
            host,
            port,
            tls_config: Some(config),
            idle_timeout: Duration::from_secs(10),
            pipeline,
            pool: pipeline::PipelinePool::default(),
            reuse: reuse::ReusePool::default(),
            observer: None,
        }
    }

    #[cfg(test)]
    async fn first_session(&self) -> Arc<Session> {
        let slot = self.pool.slots.lock().unwrap()[0].clone();
        let session = slot.session.lock().await.as_ref().unwrap().clone();
        session
    }

    pub(super) async fn exchange(&self, query: &Message) -> Result<Message> {
        if !self.pipeline {
            return self.reuse.exchange(self, query).await;
        }
        let mut retry = 0;
        loop {
            let lease = self.pool.reserve(self.protocol);
            let response = async {
                let session = lease.session(self).await?;
                self.exchange_reserved(&session, query).await
            }
            .await;
            // Go's PipelineTransport retries a failed old connection twice.
            // The outer Upstream deadline covers every attempt; dropping this
            // future on cancellation also releases its pending reservation.
            // DNS validation errors on a live session are returned directly.
            if response.is_ok()
                || lease.is_new
                || retry >= 2
                || lease.slot.alive.load(Ordering::Acquire)
            {
                return response;
            }
            retry += 1;
        }
    }

    pub(super) async fn close(&self) {
        self.pool.close().await;
        self.reuse.close();
    }

    async fn exchange_on_session(&self, session: &Session, query: &Message) -> Result<Message> {
        let _permit = session
            .limit
            .acquire()
            .await
            .context("upstream connection closed")?;
        self.exchange_reserved(session, query).await
    }

    async fn exchange_reserved(&self, session: &Session, query: &Message) -> Result<Message> {
        if !session.alive.load(Ordering::Acquire) {
            bail!("upstream connection closed");
        }
        let (reply, receiver) = oneshot::channel();
        let mut wire_query = query.clone();
        let reservation = {
            let mut pending = session.pending.lock().unwrap();
            // fail_all marks the session closed before draining this map.
            // Recheck under the same lock so an EOF between the earlier
            // alive check and insertion cannot leave a new waiter behind.
            if !session.alive.load(Ordering::Acquire) {
                bail!("upstream connection closed");
            }
            let id = loop {
                let id = rand::random::<u16>();
                if !pending.contains_key(&id) {
                    break id;
                }
            };
            wire_query.set_id(id);
            let generation = session.next_generation.fetch_add(1, Ordering::Relaxed);
            pending.insert(
                id,
                Pending {
                    generation,
                    query: wire_query.clone(),
                    reply,
                },
            );
            Reservation {
                id,
                generation,
                pending: session.pending.clone(),
            }
        };
        let payload = wire_query.to_vec().context("encode DNS query")?;
        if payload.len() > u16::MAX as usize {
            bail!("DNS message exceeds 65535 bytes");
        }
        let retry_payload = (self.protocol == Protocol::Udp).then(|| payload.clone());
        session
            .outbound
            .send(Outbound {
                payload,
                is_new_query: true,
            })
            .await
            .context("upstream writer closed")?;
        let response = if let Some(payload) = retry_payload {
            let mut receiver = receiver;
            // Go's UDP transport resends once per second using the same query
            // ID and connection. Keep this timer in the query future so reply,
            // timeout and cancellation also stop its retransmissions.
            let period = Duration::from_secs(1);
            let mut retry = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            retry.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    biased;
                    response = &mut receiver => break response,
                    _ = retry.tick() => {
                        session.outbound.send(Outbound {
                            payload: payload.clone(),
                            is_new_query: false,
                        }).await.context("upstream writer closed")?;
                    }
                }
            }
        } else {
            receiver.await
        };
        let mut response = response.context("upstream response channel closed")??;
        response.set_id(query.id());
        drop(reservation);
        Ok(response)
    }
}

trait DnsStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> DnsStream for T {}

impl Session {
    fn close(&self, reason: &str) {
        fail_all(&self.pending, &self.alive, reason);
        close_connection(&self.event);
        self.reader.abort();
        self.writer.abort();
        self.idle_task.abort();
    }

    // Keep dial settings and optional pool/observer hooks explicit in this
    // private constructor shared by reuse and pipeline transports.
    #[allow(clippy::too_many_arguments)]
    async fn connect(
        protocol: Protocol,
        _host: &str,
        dialer: &Dialer,
        #[cfg(feature = "full")] tls_config: Option<Arc<rustls::ClientConfig>>,
        idle_timeout: Duration,
        idle_pool: Option<PoolCleaner>,
        resources: Option<(Arc<Semaphore>, Arc<AtomicBool>)>,
        observer: &Option<Arc<dyn EventObserver>>,
    ) -> Result<Self> {
        let pending: PendingMap = Arc::new(Mutex::new(HashMap::new()));
        let reply_timeout = Duration::from_secs(if resources.is_some() { 10 } else { 6 });
        let (limit, alive) = resources
            .unwrap_or_else(|| (Arc::new(Semaphore::new(1)), Arc::new(AtomicBool::new(true))));
        let health = Arc::new(ReadDeadline::new(idle_timeout, reply_timeout));
        let (outbound, mut incoming) = mpsc::channel::<Outbound>(per_connection_limit(protocol));
        let (reader, writer, event) = if protocol == Protocol::Udp {
            let target = dialer.resolve().await?;
            let socket = UdpSocket::from_std(dialer.bind_udp(target)?)?;
            socket
                .connect(target)
                .await
                .context("connect upstream UDP socket")?;
            let event = ConnectionGuard::open(observer);
            let socket = Arc::new(ObservedIo::new(socket, event.clone()));
            health.received();
            let reader_socket = socket.clone();
            let reader_pending = pending.clone();
            let reader_alive = alive.clone();
            let reader_health = health.clone();
            let reader_event = event.clone();
            let reader = tokio::spawn(async move {
                let mut buffer = vec![0; 65535];
                loop {
                    match reader_socket.recv(&mut buffer).await {
                        Ok(length) => {
                            reader_health.received();
                            dispatch(&reader_pending, &buffer[..length]);
                        }
                        Err(error) => {
                            close_connection(&reader_event);
                            fail_all(
                                &reader_pending,
                                &reader_alive,
                                &format!("UDP read: {error}"),
                            );
                            reader_health.changed.notify_one();
                            return;
                        }
                    }
                }
            });
            let writer_pending = pending.clone();
            let writer_alive = alive.clone();
            let writer_health = health.clone();
            let writer_event = event.clone();
            let writer = tokio::spawn(async move {
                while let Some(Outbound {
                    payload,
                    is_new_query,
                }) = incoming.recv().await
                {
                    // Go resends the same wire query without changing the
                    // waiting-reply deadline. Only a new exchange sets it.
                    if is_new_query {
                        writer_health.sent();
                    }
                    if let Err(error) = socket.send(&payload).await {
                        close_connection(&writer_event);
                        fail_all(
                            &writer_pending,
                            &writer_alive,
                            &format!("UDP write: {error}"),
                        );
                        writer_health.changed.notify_one();
                        return;
                    }
                }
            });
            (reader.abort_handle(), writer.abort_handle(), event)
        } else {
            let tcp = dialer.tcp().await?;
            let event = ConnectionGuard::open(observer);
            let tcp = ObservedIo::new(tcp, event.clone());
            tcp.set_nodelay(true).context("set upstream TCP_NODELAY")?;
            #[cfg(feature = "full")]
            let stream: Box<dyn DnsStream> = if protocol == Protocol::Tls {
                let server_name = rustls::pki_types::ServerName::try_from(_host.to_owned())
                    .context("invalid TLS upstream server name")?;
                let tls =
                    tokio_rustls::TlsConnector::from(tls_config.context("missing TLS config")?)
                        .connect(server_name, tcp)
                        .await
                        .context("TLS handshake")?;
                Box::new(tls)
            } else {
                Box::new(tcp)
            };
            #[cfg(not(feature = "full"))]
            let stream: Box<dyn DnsStream> = Box::new(tcp);
            health.received();
            let (mut read, mut write) = tokio::io::split(stream);
            let reader_pending = pending.clone();
            let reader_alive = alive.clone();
            let reader_health = health.clone();
            let reader_event = event.clone();
            let reader = tokio::spawn(async move {
                loop {
                    let frame = async {
                        let length = read.read_u16().await.context("read DNS TCP length")? as usize;
                        if length < 12 {
                            bail!("DNS TCP frame is shorter than a header");
                        }
                        let mut payload = vec![0; length];
                        read.read_exact(&mut payload)
                            .await
                            .context("read DNS TCP payload")?;
                        Ok::<_, anyhow::Error>(payload)
                    }
                    .await;
                    match frame {
                        Ok(payload) => {
                            reader_health.received();
                            dispatch(&reader_pending, &payload);
                        }
                        Err(error) => {
                            close_connection(&reader_event);
                            fail_all(&reader_pending, &reader_alive, &error.to_string());
                            reader_health.changed.notify_one();
                            return;
                        }
                    }
                }
            });
            let writer_pending = pending.clone();
            let writer_alive = alive.clone();
            let writer_health = health.clone();
            let writer_event = event.clone();
            let writer = tokio::spawn(async move {
                while let Some(Outbound {
                    payload,
                    is_new_query,
                }) = incoming.recv().await
                {
                    if is_new_query {
                        writer_health.sent();
                    }
                    let result = async {
                        let mut frame = Vec::with_capacity(payload.len() + 2);
                        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                        frame.extend_from_slice(&payload);
                        write.write_all(&frame).await?;
                        Ok::<_, std::io::Error>(())
                    }
                    .await;
                    if let Err(error) = result {
                        close_connection(&writer_event);
                        fail_all(
                            &writer_pending,
                            &writer_alive,
                            &format!("TCP write: {error}"),
                        );
                        writer_health.changed.notify_one();
                        return;
                    }
                }
            });
            (reader.abort_handle(), writer.abort_handle(), event)
        };
        let idle_pending = pending.clone();
        let idle_alive = alive.clone();
        let idle_reader = reader.clone();
        let idle_writer = writer.clone();
        let idle_event = event.clone();
        let idle_task = tokio::spawn(async move {
            loop {
                let changed = health.changed.notified();
                let deadline = *health.state.lock().unwrap();
                if !idle_alive.load(Ordering::Acquire)
                    || deadline
                        .until
                        .is_some_and(|until| tokio::time::Instant::now() >= until)
                {
                    let reason = if !idle_alive.load(Ordering::Acquire) {
                        "upstream connection closed"
                    } else if deadline.waiting_reply {
                        "upstream connection waiting reply timeout"
                    } else {
                        "upstream connection idle timeout"
                    };
                    fail_all(&idle_pending, &idle_alive, reason);
                    close_connection(&idle_event);
                    idle_reader.abort();
                    idle_writer.abort();
                    if let Some(pool) = &idle_pool {
                        pool.clean();
                    }
                    return;
                }
                let elapsed = async {
                    if let Some(until) = deadline.until {
                        tokio::time::sleep_until(until).await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                tokio::select! { () = changed => {}, () = elapsed => {} }
            }
        })
        .abort_handle();
        Ok(Self {
            next_generation: AtomicU64::new(0),
            outbound,
            pending,
            alive,
            idle_task,
            limit,
            reader,
            writer,
            event,
        })
    }
}

fn dispatch(pending: &PendingMap, payload: &[u8]) {
    if payload.len() < 2 {
        return;
    }
    let id = u16::from_be_bytes([payload[0], payload[1]]);
    if let Some(request) = pending.lock().unwrap().remove(&id) {
        let response = Message::from_vec(payload)
            .context("invalid upstream DNS message")
            .and_then(|response| {
                validate_response(&request.query, &response)?;
                Ok(response)
            });
        let _ = request.reply.send(response);
    }
}

fn fail_all(pending: &PendingMap, alive: &AtomicBool, reason: &str) {
    alive.store(false, Ordering::Release);
    for (_, request) in pending.lock().unwrap().drain() {
        let _ = request.reply.send(Err(anyhow!("{reason}")));
    }
}

#[cfg(test)]
#[cfg_attr(not(feature = "full"), allow(irrefutable_let_patterns))]
mod tests {
    use super::*;
    use hickory_proto::{
        op::Query,
        rr::{Name, RecordType},
    };
    use std::time::Duration;

    #[test]
    fn pipeline_options_aliases_and_udp_fallback_select_the_go_transport_model() {
        use crate::pkg::upstream::{Backend, Options, Upstream};
        for (scheme, configured, expected) in [
            ("tcp", false, false),
            ("tcp", true, true),
            ("tcp+pipeline", false, true),
            #[cfg(feature = "full")]
            ("tls", false, false),
            #[cfg(feature = "full")]
            ("tls", true, true),
            #[cfg(feature = "full")]
            ("tls+pipeline", false, true),
            ("udp", false, true),
            ("udp", true, true),
        ] {
            let upstream = Upstream::new_with_options(
                &format!("{scheme}://127.0.0.1"),
                Duration::from_secs(1),
                Options {
                    enable_pipeline: configured,
                    ..Default::default()
                },
            )
            .unwrap();
            let Backend::Traditional {
                transport,
                tcp_fallback,
            } = &upstream.inner.backend
            else {
                panic!("expected traditional transport")
            };
            assert_eq!(
                transport.pipeline, expected,
                "{scheme} with enable_pipeline={configured}"
            );
            if scheme == "udp" {
                assert!(
                    !tcp_fallback.as_ref().unwrap().pipeline,
                    "TC fallback must use direct reusable TCP connections"
                );
            }
        }
    }

    #[tokio::test]
    async fn early_reply_is_retained_before_the_query_awaits_its_receiver() {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let mut query = Message::new();
        query.set_id(42).add_query(Query::query(
            Name::from_ascii("early.test.").unwrap(),
            RecordType::A,
        ));
        let (reply, receiver) = oneshot::channel();
        pending.lock().unwrap().insert(
            42,
            Pending {
                generation: 1,
                query: query.clone(),
                reply,
            },
        );
        let mut response = query.clone();
        response.set_message_type(hickory_proto::op::MessageType::Response);
        // No receiver future has been polled when the actual dispatch runs.
        dispatch(&pending, &response.to_vec().unwrap());
        assert!(pending.lock().unwrap().is_empty());
        assert_eq!(
            receiver.await.unwrap().unwrap().to_vec().unwrap(),
            response.to_vec().unwrap()
        );
    }

    #[test]
    fn udp_custom_idle_timeout_does_not_change_tcp_fallback_timeout() {
        use crate::pkg::upstream::{Backend, Options, Upstream};
        let upstream = Upstream::new_with_options(
            "udp://127.0.0.1",
            Duration::from_secs(1),
            Options {
                idle_timeout: Duration::from_millis(30),
                enable_pipeline: true,
                ..Default::default()
            },
        )
        .unwrap();
        let Backend::Traditional {
            transport,
            tcp_fallback,
        } = &upstream.inner.backend
        else {
            panic!("expected traditional transport");
        };
        assert_eq!(transport.idle_timeout, Duration::from_millis(30));
        assert_eq!(
            tcp_fallback.as_ref().unwrap().idle_timeout,
            Duration::from_secs(10),
            "Go's UDP TC fallback uses the TCP default regardless of UDP options"
        );
    }

    #[tokio::test]
    async fn pipeline_retries_an_idle_close_after_a_query_selects_the_old_session() {
        use crate::pkg::upstream::{Backend, Upstream};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (close, closed) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut old, _) = listener.accept().await.unwrap();
            let length = old.read_u16().await.unwrap();
            let mut payload = vec![0; length as usize];
            old.read_exact(&mut payload).await.unwrap();
            let mut reply = Message::from_vec(&payload).unwrap();
            reply.set_message_type(hickory_proto::op::MessageType::Response);
            let payload = reply.to_vec().unwrap();
            old.write_u16(payload.len() as u16).await.unwrap();
            old.write_all(&payload).await.unwrap();
            closed.await.unwrap();
            // Model the peer's idle timer closing while a selected session
            // has a query waiting to finish its lazy session lookup.
            drop(old);
            let (mut new, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
                .await
                .unwrap()
                .unwrap();
            let length = new.read_u16().await.unwrap();
            let mut payload = vec![0; length as usize];
            new.read_exact(&mut payload).await.unwrap();
            let mut reply = Message::from_vec(&payload).unwrap();
            reply.set_message_type(hickory_proto::op::MessageType::Response);
            let payload = reply.to_vec().unwrap();
            new.write_u16(payload.len() as u16).await.unwrap();
            new.write_all(&payload).await.unwrap();
        });
        let upstream =
            Upstream::new(&format!("tcp+pipeline://{address}"), Duration::from_secs(2)).unwrap();
        let mut query = Message::new();
        query.set_id(65535).add_query(Query::query(
            Name::from_ascii("idle-race.example.").unwrap(),
            RecordType::A,
        ));
        upstream.exchange(&query).await.unwrap();
        let Backend::Traditional { transport, .. } = &upstream.inner.backend else {
            unreachable!()
        };
        let old_slot = transport.pool.slots.lock().unwrap()[0].clone();
        let old = transport.first_session().await;
        // Pause after selection, before initialization/lookup finishes. New
        // queries no longer wait for capacity: a full connection expands.
        let selected = old_slot.session.lock().await;
        let retry = upstream.exchange(&query);
        tokio::pin!(retry);
        assert!(futures::poll!(retry.as_mut()).is_pending());
        close.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            while old.alive.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        drop(selected);
        let response = retry
            .await
            .expect("selected old session closing must retry this query");
        assert_eq!(response.id(), query.id());
        assert_eq!(response.queries(), query.queries());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_pipeline_retry_releases_the_fresh_session_and_pending_query() {
        use crate::pkg::upstream::{Backend, Upstream};
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (received, receive) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut old, _) = listener.accept().await.unwrap();
            let length = old.read_u16().await.unwrap();
            let mut payload = vec![0; length as usize];
            old.read_exact(&mut payload).await.unwrap();
            let mut reply = Message::from_vec(&payload).unwrap();
            reply.set_message_type(hickory_proto::op::MessageType::Response);
            let payload = reply.to_vec().unwrap();
            old.write_u16(payload.len() as u16).await.unwrap();
            old.write_all(&payload).await.unwrap();
            let length = old.read_u16().await.unwrap();
            let mut payload = vec![0; length as usize];
            old.read_exact(&mut payload).await.unwrap();
            drop(old);
            let (mut fresh, _) = listener.accept().await.unwrap();
            let length = fresh.read_u16().await.unwrap();
            let mut payload = vec![0; length as usize];
            fresh.read_exact(&mut payload).await.unwrap();
            received.send(()).unwrap();
            // Drop of the last upstream owner must release both split tasks
            // and the socket even after cancellation during a retry.
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), fresh.read_u8())
                    .await
                    .unwrap()
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        });
        let upstream =
            Upstream::new(&format!("tcp+pipeline://{address}"), Duration::from_secs(2)).unwrap();
        let mut query = Message::new();
        query.add_query(Query::query(
            Name::from_ascii("cancel-retry.example.").unwrap(),
            RecordType::A,
        ));
        upstream.exchange(&query).await.unwrap();
        let client = upstream.clone();
        let task = tokio::spawn(async move { client.exchange(&query).await });
        tokio::time::timeout(Duration::from_secs(1), receive)
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        {
            let Backend::Traditional { transport, .. } = &upstream.inner.backend else {
                unreachable!()
            };
            let fresh = transport.first_session().await;
            assert!(fresh.pending.lock().unwrap().is_empty());
            assert_eq!(fresh.limit.available_permits(), TCP_PIPELINE_LIMIT);
        }
        drop(upstream);
        server.await.unwrap();
    }

    #[test]
    fn completed_query_reservation_cannot_remove_a_later_query_reusing_its_id() {
        let pending = Arc::new(Mutex::new(HashMap::new()));
        let old = Reservation {
            id: 42,
            generation: 1,
            pending: pending.clone(),
        };
        let (reply, _receiver) = oneshot::channel();
        pending.lock().unwrap().insert(
            42,
            Pending {
                generation: 2,
                query: Message::new(),
                reply,
            },
        );
        drop(old);
        assert_eq!(pending.lock().unwrap().get(&42).unwrap().generation, 2);
    }

    #[tokio::test]
    async fn cancellation_and_timeout_release_pending_ids_and_concurrency_slots() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let transport = Arc::new(Transport::new(
            Protocol::Udp,
            "127.0.0.1".to_owned(),
            addr.port(),
        ));
        let mut query = Message::new();
        query.add_query(Query::query(
            Name::from_ascii("example.").unwrap(),
            RecordType::A,
        ));
        let (received, receive) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut payload = [0; 4096];
            socket.recv_from(&mut payload).await.unwrap();
            received.send(()).unwrap();
            socket.recv_from(&mut payload).await.unwrap();
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let task_transport = transport.clone();
        let task_query = query.clone();
        let task = tokio::spawn(async move { task_transport.exchange(&task_query).await });
        receive.await.unwrap();
        task.abort();
        let _ = task.await;
        let session = transport.first_session().await;
        assert!(session.pending.lock().unwrap().is_empty());
        assert_eq!(session.limit.available_permits(), UDP_PIPELINE_LIMIT);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), transport.exchange(&query))
                .await
                .is_err()
        );
        assert!(session.pending.lock().unwrap().is_empty());
        assert_eq!(session.limit.available_permits(), UDP_PIPELINE_LIMIT);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_udp_query_stops_its_retry_timer() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let transport = Arc::new(Transport::new(
            Protocol::Udp,
            "127.0.0.1".into(),
            address.port(),
        ));
        let mut query = Message::new();
        query.add_query(Query::query(
            Name::from_ascii("cancel-retry.example.").unwrap(),
            RecordType::A,
        ));
        let sent = transport.clone();
        let task = tokio::spawn(async move { sent.exchange(&query).await });
        let mut buffer = [0; 4096];
        socket.recv_from(&mut buffer).await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(
            tokio::time::timeout(Duration::from_millis(1200), socket.recv_from(&mut buffer))
                .await
                .is_err()
        );
        let session = transport.first_session().await;
        assert!(session.pending.lock().unwrap().is_empty());
        assert_eq!(session.limit.available_permits(), UDP_PIPELINE_LIMIT);
    }
}
