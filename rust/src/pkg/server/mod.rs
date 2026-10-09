//! DNS listeners with bounded concurrency and persistent TCP framing.

#[cfg(feature = "full")]
mod http;
#[cfg(feature = "full")]
mod quic;
mod socket;
#[cfg(feature = "full")]
mod tls;
mod udp;
#[cfg(feature = "full")]
pub use http::serve_http;
#[cfg(feature = "full")]
pub use quic::serve_quic;
#[cfg(feature = "full")]
pub use tls::serve_tls;

use anyhow::{bail, Context, Result};
use hickory_proto::{
    op::{Edns, Header, Message, MessageType, Query, ResponseCode},
    serialize::binary::{BinEncodable, BinEncoder},
};
use std::{future::Future, net::IpAddr, pin::Pin, sync::Arc, time::Duration};
#[cfg(test)]
use tokio::net::{TcpListener, TcpStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::{mpsc, Semaphore},
    task::JoinSet,
};

const MAX_QUERIES: usize = 2048;
const MAX_TCP_CONNECTIONS: usize = 1024;
const TCP_PIPELINE_LIMIT: usize = 64;
const HANDLE_TIMEOUT: Duration = Duration::from_secs(5);
const FIRST_READ_TIMEOUT: Duration = Duration::from_secs(2);
const IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
// Reuse ordinary DNS buffers without retaining jumbo frame allocations on idle connections.
const MAX_REUSED_WIRE_CAPACITY: usize = 8192;

type QueryFuture = Pin<Box<dyn Future<Output = Result<Message>> + Send>>;
type Handler = Arc<dyn Fn(Message, Option<IpAddr>) -> QueryFuture + Send + Sync>;

enum RequestQuestions {
    Single(Query),
    Other(Vec<Query>),
}

/// Reply metadata outlives the request consumed by the handler. A valid request
/// needs only one inline question and EDNS flags, not a cloned message/options.
struct RequestContext {
    header: Header,
    questions: RequestQuestions,
    edns: Option<(u16, bool)>,
}

impl RequestContext {
    fn new(query: &Message) -> Self {
        Self {
            header: *query.header(),
            questions: match query.queries() {
                [question] => RequestQuestions::Single(question.clone()),
                questions => RequestQuestions::Other(questions.to_vec()),
            },
            edns: query
                .extensions()
                .as_ref()
                .map(|edns| (edns.max_payload(), edns.dnssec_ok())),
        }
    }

    fn questions(&self) -> &[Query] {
        match &self.questions {
            RequestQuestions::Single(question) => std::slice::from_ref(question),
            RequestQuestions::Other(questions) => questions,
        }
    }

    fn from_invalid(mut query: Message) -> Self {
        Self {
            header: *query.header(),
            edns: query
                .extensions()
                .as_ref()
                .map(|edns| (edns.max_payload(), edns.dnssec_ok())),
            questions: RequestQuestions::Other(query.take_queries()),
        }
    }

    fn error_response(&self, code: ResponseCode) -> Message {
        let mut response = Message::new();
        response
            .set_id(self.header.id())
            .set_message_type(MessageType::Response)
            .set_op_code(self.header.op_code())
            .set_recursion_desired(self.header.recursion_desired())
            .set_checking_disabled(self.header.checking_disabled())
            .set_recursion_available(true)
            .set_response_code(code);
        response.add_queries(self.questions().iter().cloned());
        if let Some((_, dnssec_ok)) = self.edns {
            let mut response_edns = Edns::new();
            response_edns.set_max_payload(1200).set_dnssec_ok(dnssec_ok);
            response.set_edns(response_edns);
        }
        response
    }
}

pub async fn serve_udp(
    listen: &str,
    engine: Arc<crate::coremain::Engine>,
    entry: String,
) -> Result<()> {
    let socket = socket::bind_udp(listen)
        .await
        .context("bind UDP DNS listener")?;
    let entry: Arc<str> = entry.into();
    let handler: Handler = Arc::new(move |query, client| {
        let engine = engine.clone();
        let entry = entry.clone();
        Box::pin(async move {
            engine
                .handle_with_client_meta(query, client, &entry, None, None)
                .await
        })
    });
    serve_udp_socket(socket, handler).await
}

pub async fn serve_tcp(
    listen: &str,
    engine: Arc<crate::coremain::Engine>,
    entry: String,
) -> Result<()> {
    serve_tcp_with_timeout(listen, engine, entry, IDLE_TIMEOUT).await
}

pub async fn serve_tcp_with_timeout(
    listen: &str,
    engine: Arc<crate::coremain::Engine>,
    entry: String,
    idle_timeout: Duration,
) -> Result<()> {
    let listener = socket::bind_stream(listen)
        .await
        .context("bind TCP DNS listener")?;
    let entry: Arc<str> = entry.into();
    let handler: Handler = Arc::new(move |query, client| {
        let engine = engine.clone();
        let entry = entry.clone();
        Box::pin(async move {
            engine
                .handle_with_client_meta(query, client, &entry, None, None)
                .await
        })
    });
    serve_tcp_listener_with_timeout(listener, handler, idle_timeout).await
}

async fn serve_udp_socket(socket: UdpSocket, handler: Handler) -> Result<()> {
    let socket =
        Arc::new(udp::DatagramSocket::new(socket).context("initialize UDP destination metadata")?);
    let limit = Arc::new(Semaphore::new(MAX_QUERIES));
    let mut tasks = JoinSet::new();
    let mut buffer = vec![0; 65535];
    loop {
        let (length, peer, destination) = socket
            .receive(&mut buffer)
            .await
            .context("receive DNS datagram")?;
        // Avoid allocating a queued task per datagram when the server is overloaded.
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let Some(query) = decode_wire(&buffer[..length]) else {
            continue;
        };
        let socket = socket.clone();
        let handler = handler.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let (request, response) = process_query(query, Some(peer.ip()), &handler).await;
            if let Ok(payload) = pack_udp(&request, response) {
                let _ = socket.send(&payload, peer, destination).await;
            }
        });
        while tasks.try_join_next().is_some() {}
    }
}

#[cfg(test)]
async fn serve_tcp_listener(listener: TcpListener, handler: Handler) -> Result<()> {
    serve_tcp_listener_with_timeout(listener, handler, IDLE_TIMEOUT).await
}

async fn serve_tcp_listener_with_timeout(
    listener: impl Into<socket::StreamListener>,
    handler: Handler,
    idle_timeout: Duration,
) -> Result<()> {
    let listener = listener.into();
    let idle_timeout = if idle_timeout.is_zero() {
        IDLE_TIMEOUT
    } else {
        idle_timeout
    };
    let connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    let queries = Arc::new(Semaphore::new(MAX_QUERIES));
    let mut tasks = JoinSet::new();
    loop {
        let (stream, client) = listener
            .accept()
            .await
            .context("accept DNS TCP connection")?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let handler = handler.clone();
        let queries = queries.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let _ = serve_dns_connection(stream, client, handler, queries, idle_timeout).await;
        });
        while tasks.try_join_next().is_some() {}
    }
}

async fn serve_dns_connection<S>(
    stream: S,
    client: Option<IpAddr>,
    handler: Handler,
    queries: Arc<Semaphore>,
    idle_timeout: Duration,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut read, mut write) = tokio::io::split(stream);
    let (responses, mut outgoing) = mpsc::channel::<Message>(TCP_PIPELINE_LIMIT);
    let mut tasks = JoinSet::new();
    tasks.spawn(async move {
        let mut frame = Vec::with_capacity(512);
        while let Some(response) = outgoing.recv().await {
            if encode_stream_response(&response, &mut frame).is_err() {
                release_large_buffer(&mut frame);
                continue;
            }
            if !matches!(
                tokio::time::timeout(WRITE_TIMEOUT, write.write_all(&frame)).await,
                Ok(Ok(()))
            ) {
                return;
            }
            release_large_buffer(&mut frame);
        }
    });
    let per_connection = Arc::new(Semaphore::new(TCP_PIPELINE_LIMIT));
    let mut buffer = Vec::with_capacity(512);
    let mut first = true;
    loop {
        let timeout = if first {
            FIRST_READ_TIMEOUT.min(idle_timeout)
        } else {
            idle_timeout
        };
        first = false;
        let query = tokio::select! {
            _ = responses.closed() => break,
            payload = tokio::time::timeout(timeout, async {
                let length = read.read_u16().await? as usize;
                if length == 0 { bail!("empty DNS TCP frame"); }
                buffer.resize(length, 0);
                read.read_exact(&mut buffer).await?;
                Ok::<_, anyhow::Error>(decode_wire(&buffer))
            }) => match payload { Ok(Ok(query)) => query, _ => break }
        };
        release_large_buffer(&mut buffer);
        let Some(query) = query else {
            continue;
        };
        let connection_permit = per_connection.clone().acquire_owned().await?;
        let global_permit = queries.clone().acquire_owned().await?;
        let responses = responses.clone();
        let handler = handler.clone();
        tasks.spawn(async move {
            let _connection_permit = connection_permit;
            let _global_permit = global_permit;
            let (_, response) = process_query(query, client, &handler).await;
            let _ = responses.send(response).await;
        });
        while tasks.try_join_next().is_some() {}
    }
    // Dropping the JoinSet cancels requests and closes the owned write half.
    Ok(())
}

fn decode_wire(payload: &[u8]) -> Option<Message> {
    match Message::from_vec(payload) {
        Ok(query) => Some(query),
        Err(_) => {
            if payload.len() < 2 {
                return None;
            }
            let mut query = Message::new();
            query.set_id(u16::from_be_bytes([payload[0], payload[1]]));
            if payload.len() >= 4 {
                query.set_recursion_desired(payload[2] & 1 != 0);
            }
            // An empty question list is rejected before reaching the handler.
            Some(query)
        }
    }
}

#[cfg(test)]
async fn process_wire(
    payload: &[u8],
    client: Option<IpAddr>,
    handler: &Handler,
) -> Option<(RequestContext, Message)> {
    Some(process_query(decode_wire(payload)?, client, handler).await)
}

async fn process_query(
    query: Message,
    client: Option<IpAddr>,
    handler: &Handler,
) -> (RequestContext, Message) {
    if query.message_type() != MessageType::Query
        || query.queries().len() != 1
        || !query.answers().is_empty()
        || !query.name_servers().is_empty()
        || query.additionals().len() + usize::from(query.extensions().is_some()) > 1
    {
        let request = RequestContext::from_invalid(query);
        let response = request.error_response(ResponseCode::FormErr);
        return (request, response);
    }
    let request = RequestContext::new(&query);
    let mut response = match tokio::time::timeout(HANDLE_TIMEOUT, handler(query, client)).await {
        Ok(Ok(mut response)) => {
            response
                .set_id(request.header.id())
                .set_message_type(MessageType::Response)
                .set_recursion_available(true);
            response
        }
        _ => request.error_response(ResponseCode::ServFail),
    };
    match request.edns {
        Some((_, dnssec_ok)) => {
            let edns = response.extensions_mut().get_or_insert_with(Edns::new);
            edns.set_max_payload(1200).set_dnssec_ok(dnssec_ok);
        }
        None => {
            *response.extensions_mut() = None;
        }
    }
    (request, response)
}

#[cfg(test)]
fn error_response(query: &Message, code: ResponseCode) -> Message {
    RequestContext::new(query).error_response(code)
}

fn release_large_buffer(buffer: &mut Vec<u8>) {
    if buffer.capacity() > MAX_REUSED_WIRE_CAPACITY {
        *buffer = Vec::with_capacity(512);
    }
}

fn encode_message(message: &Message, payload: &mut Vec<u8>) -> Result<()> {
    payload.clear();
    message.emit(&mut BinEncoder::new(payload))?;
    Ok(())
}

fn encode_stream_response(response: &Message, frame: &mut Vec<u8>) -> Result<()> {
    // Encode at DNS offset zero so compression pointers remain relative to the
    // message, then add framing in the same allocation.
    encode_message(response, frame)?;
    let length = frame.len();
    if length > u16::MAX as usize {
        bail!("DNS response exceeds stream frame length");
    }
    frame.resize(length + 2, 0);
    frame.copy_within(..length, 2);
    frame[..2].copy_from_slice(&(length as u16).to_be_bytes());
    Ok(())
}

/// Remove whole answer sets when a response exceeds the client's advertised
/// datagram limit. TC allows a client to obtain the complete response over TCP.
fn pack_udp(query: &RequestContext, response: Message) -> Result<Vec<u8>> {
    let maximum = query.edns.map_or(512, |(maximum, _)| maximum.max(512)) as usize;
    let mut payload = Vec::with_capacity(512);
    encode_message(&response, &mut payload).context("encode DNS UDP response")?;
    if payload.len() <= maximum {
        return Ok(payload);
    }
    let mut truncated = query.error_response(response.response_code());
    truncated
        .set_truncated(true)
        .set_authoritative(response.authoritative())
        .set_recursion_available(response.recursion_available());
    encode_message(&truncated, &mut payload)?;
    if payload.len() <= maximum {
        return Ok(payload);
    }
    // An oversized question list can itself exceed the limit; a header and
    // optional EDNS response still conveys truncation without a partial name.
    truncated.queries_mut().clear();
    encode_message(&truncated, &mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests;
#[cfg(all(test, unix))]
mod unix_tests;
