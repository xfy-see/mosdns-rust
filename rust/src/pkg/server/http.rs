use super::*;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, service::service_fn, Method, Request, Response, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::conn::auto::Builder,
};
use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
};

type HttpResponse = Response<Full<Bytes>>;

#[derive(Clone)]
pub(super) struct Routes {
    pub(super) engine: Arc<crate::coremain::Engine>,
    pub(super) entries: Vec<(String, String)>, // (path, entry)
    pub(super) src_ip_header: String,
    pub(super) limit: Arc<Semaphore>,
}

pub async fn serve_http(
    listen: &str,
    engine: Arc<crate::coremain::Engine>,
    mut entries: Vec<(String, String)>,
    src_ip_header: String,
    cert: &str,
    key: &str,
    idle_timeout: Duration,
) -> Result<()> {
    if entries.is_empty() {
        bail!("HTTP server needs at least one path/exec entry");
    }
    entries.sort_by_key(|(path, _)| std::cmp::Reverse(path.len()));
    let tls = if !cert.is_empty() || !key.is_empty() {
        Some(tls::load_tls_config(cert, key, &[b"h2", b"http/1.1"])?)
    } else {
        None
    };
    let routes = Routes {
        engine,
        entries,
        src_ip_header,
        limit: Arc::new(Semaphore::new(MAX_QUERIES)),
    };
    let listener = socket::bind_stream(listen)
        .await
        .context("bind HTTP DNS listener")?;
    serve_http_listener(listener, routes, tls, idle_timeout).await
}

pub(super) async fn serve_http_listener(
    listener: impl Into<socket::StreamListener>,
    routes: Routes,
    tls: Option<Arc<rustls::ServerConfig>>,
    idle_timeout: Duration,
) -> Result<()> {
    let listener = listener.into();
    let connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    let idle_timeout = if idle_timeout.is_zero() {
        Duration::from_secs(30)
    } else {
        idle_timeout
    };
    let mut tasks = JoinSet::new();
    loop {
        let (stream, client) = listener
            .accept()
            .await
            .context("accept HTTP DNS connection")?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let routes = routes.clone();
        let tls = tls.clone();
        tasks.spawn(async move {
            let _permit = permit;
            if let Some(config) = tls {
                if let Ok(Ok(tls)) = tokio::time::timeout(
                    FIRST_READ_TIMEOUT,
                    tokio_rustls::TlsAcceptor::from(config).accept(stream),
                )
                .await
                {
                    let server_name = tls.get_ref().1.server_name().map(str::to_owned);
                    serve_http_connection(tls, client, routes, server_name, idle_timeout).await;
                }
            } else {
                serve_http_connection(stream, client, routes, None, idle_timeout).await;
            }
        });
        while tasks.try_join_next().is_some() {}
    }
}

async fn serve_http_connection<S>(
    stream: S,
    client: Option<IpAddr>,
    routes: Routes,
    server_name: Option<String>,
    idle_timeout: Duration,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let active = Arc::new(AtomicUsize::new(0));
    let last_request = Arc::new(Mutex::new(tokio::time::Instant::now()));
    let request_active = active.clone();
    let request_time = last_request.clone();
    let service = service_fn(move |request| {
        let routes = routes.clone();
        let server_name = server_name.clone();
        let active = request_active.clone();
        let last_request = request_time.clone();
        async move {
            active.fetch_add(1, Ordering::Relaxed);
            let response = handle_http(request, client, &routes, server_name.as_deref()).await;
            *last_request.lock().unwrap() = tokio::time::Instant::now();
            active.fetch_sub(1, Ordering::Relaxed);
            Ok::<_, Infallible>(response)
        }
    });
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(1))
        .max_buf_size(8192);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_concurrent_streams(TCP_PIPELINE_LIMIT as u32)
        .max_frame_size(16384)
        .max_header_list_size(4096);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    let idle = async {
        let mut interval = tokio::time::interval(idle_timeout.min(Duration::from_secs(1)));
        loop {
            interval.tick().await;
            if active.load(Ordering::Relaxed) == 0
                && last_request.lock().unwrap().elapsed() >= idle_timeout
            {
                break;
            }
        }
    };
    tokio::select! { _ = connection => (), _ = idle => () }
}

fn status(status: StatusCode) -> HttpResponse {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = status;
    response
}

async fn handle_http(
    request: Request<Incoming>,
    mut client: Option<IpAddr>,
    routes: &Routes,
    server_name: Option<&str>,
) -> HttpResponse {
    let path = request.uri().path().to_owned();
    let Some((_, entry)) = routes
        .entries
        .iter()
        .find(|(route, _)| route == &path || route.ends_with('/') && path.starts_with(route))
    else {
        return status(StatusCode::NOT_FOUND);
    };
    if !routes.src_ip_header.is_empty() {
        if let Some(header) = request.headers().get(&routes.src_ip_header) {
            let address = header
                .to_str()
                .ok()
                .and_then(|value| value.split(',').next())
                .and_then(|value| value.trim().parse::<IpAddr>().ok());
            match address {
                Some(address) => client = Some(address),
                None => return status(StatusCode::BAD_REQUEST),
            }
        }
    }
    let payload = match *request.method() {
        Method::GET => {
            if request
                .headers()
                .get(hyper::header::ACCEPT)
                .and_then(|value| value.to_str().ok())
                != Some("application/dns-message")
            {
                return status(StatusCode::BAD_REQUEST);
            }
            let encoded =
                url::form_urlencoded::parse(request.uri().query().unwrap_or("").as_bytes())
                    .find(|(name, _)| name == "dns")
                    .map(|(_, value)| value.into_owned());
            let Some(encoded) = encoded else {
                return status(StatusCode::BAD_REQUEST);
            };
            if encoded.len() > 87380 {
                return status(StatusCode::BAD_REQUEST);
            }
            match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded) {
                Ok(payload) if payload.len() <= 65535 => Bytes::from(payload),
                _ => return status(StatusCode::BAD_REQUEST),
            }
        }
        Method::POST => {
            if request
                .headers()
                .get(hyper::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                != Some("application/dns-message")
            {
                return status(StatusCode::BAD_REQUEST);
            }
            match tokio::time::timeout(
                Duration::from_secs(1),
                Limited::new(request.into_body(), 65535).collect(),
            )
            .await
            {
                Ok(Ok(payload)) => payload.to_bytes(),
                _ => return status(StatusCode::BAD_REQUEST),
            }
        }
        _ => return status(StatusCode::BAD_REQUEST),
    };
    let query = match Message::from_vec(&payload) {
        Ok(query) => query,
        Err(_) => return status(StatusCode::BAD_REQUEST),
    };
    let Ok(_permit) = routes.limit.clone().try_acquire_owned() else {
        return status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let engine = routes.engine.clone();
    let entry = entry.clone();
    let path = path.clone();
    let server_name = server_name.map(str::to_owned);
    let handler: Handler = Arc::new(move |query, client| {
        let engine = engine.clone();
        let entry = entry.clone();
        let path = path.clone();
        let server_name = server_name.clone();
        Box::pin(async move {
            engine
                .handle_with_client_meta(query, client, &entry, Some(&path), server_name.as_deref())
                .await
        })
    });
    let (_, response) = process_query(query, client, &handler).await;
    match response.to_vec() {
        Ok(payload) => {
            let mut response = Response::new(Full::new(Bytes::from(payload)));
            response.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("application/dns-message"),
            );
            response
        }
        Err(_) => status(StatusCode::INTERNAL_SERVER_ERROR),
    }
}
