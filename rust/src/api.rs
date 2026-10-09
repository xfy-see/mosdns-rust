// SPDX-License-Identifier: GPL-3.0-or-later
//! The existing metrics and per-plugin cache HTTP API.
use crate::coremain::Engine;
use anyhow::Result;
use bytes::Bytes;
use futures::FutureExt;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, service::service_fn, Method, Request, Response, StatusCode};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use std::{convert::Infallible, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore};

fn response(status: StatusCode, mime: &str, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", mime)
        .body(Full::new(body.into()))
        .unwrap()
}

fn metrics(engine: &Engine) -> String {
    let mut text = crate::pkg::metrics::process_metrics();
    text.push_str(&engine.metrics_text());
    let mut tags = engine.cache_tags();
    tags.sort();
    let mut described_caches = false;
    for tag in tags {
        if let Some(s) = engine.cache_stats(&tag) {
            if !described_caches {
                for (name, kind, help) in [
                    (
                        "cache_query_total",
                        "counter",
                        "The total number of processed queries",
                    ),
                    (
                        "cache_hit_total",
                        "counter",
                        "The total number of queries that hit the cache",
                    ),
                    (
                        "cache_lazy_hit_total",
                        "counter",
                        "The total number of queries that hit the expired cache",
                    ),
                    (
                        "cache_size_current",
                        "gauge",
                        "Current cache size in records",
                    ),
                ] {
                    text.push_str(&format!(
                        "# HELP mosdns_{name} {help}\n# TYPE mosdns_{name} {kind}\n"
                    ));
                }
                described_caches = true;
            }
            let label = tag
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            for (name, value) in [
                ("cache_query_total", s.queries),
                ("cache_hit_total", s.hits),
                ("cache_lazy_hit_total", s.lazy_hits),
                ("cache_size_current", s.len as u64),
            ] {
                text.push_str(&format!("mosdns_{name}{{tag=\"{label}\"}} {value}\n"));
            }
        }
    }
    text
}

async fn handle(
    request: Request<Incoming>,
    engine: Arc<Engine>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let text = |status, s: &str| response(status, "text/plain; charset=utf-8", s.to_owned());
    if let Some((api, relative_path)) = engine.plugin_api(&path) {
        let _work = match engine.api_work() {
            Ok(work) => work,
            Err(_) => {
                return Ok(text(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "engine is shutting down\n",
                ))
            }
        };
        let (parts, body) = request.into_parts();
        let body = match Limited::new(body, 16 * 1024 * 1024).collect().await {
            Ok(body) => body.to_bytes(),
            Err(_) => {
                return Ok(text(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "plugin body exceeds limit or is incomplete\n",
                ))
            }
        };
        // Catch both an immediate handler panic and a panic while polling its future.
        let request = Request::from_parts(parts, body);
        let result =
            std::panic::AssertUnwindSafe(async { api.handle(request, relative_path).await })
                .catch_unwind()
                .await;
        return Ok(match result {
            Ok(Ok(response)) => response.map(Full::new),
            Ok(Err(error)) => text(StatusCode::INTERNAL_SERVER_ERROR, &format!("{error:#}\n")),
            Err(_) => text(StatusCode::INTERNAL_SERVER_ERROR, "plugin API panicked\n"),
        });
    }
    if method == Method::GET && path == "/metrics" {
        return Ok(response(
            StatusCode::OK,
            "text/plain; version=0.0.4",
            metrics(&engine),
        ));
    }
    if method == Method::GET && path == "/health" {
        return Ok(text(StatusCode::OK, "ok\n"));
    }
    if let Some(rest) = path.strip_prefix("/plugins/") {
        if let Some((tag, operation)) = rest.split_once('/') {
            if method == Method::GET
                && operation.is_empty()
                && engine
                    .config()
                    .plugins
                    .iter()
                    .any(|p| p.tag == tag && p.kind == "reverse_lookup")
            {
                let ip = url::form_urlencoded::parse(
                    request.uri().query().unwrap_or_default().as_bytes(),
                )
                .find_map(|(key, value)| (key == "ip").then(|| value.into_owned()));
                let Some(ip) = ip.filter(|ip| !ip.is_empty()) else {
                    return Ok(text(
                        StatusCode::BAD_REQUEST,
                        "no 'ip' query parameter found\n",
                    ));
                };
                let Ok(ip) = ip.parse() else {
                    return Ok(text(StatusCode::BAD_REQUEST, "invalid IP address\n"));
                };
                return Ok(text(
                    StatusCode::OK,
                    &engine.reverse_lookup(tag, ip).unwrap_or_default(),
                ));
            }
            if engine.cache_stats(tag).is_none() {
                return Ok(text(StatusCode::NOT_FOUND, "unknown cache\n"));
            }
            match (method, operation) {
                (Method::GET | Method::POST, "flush") => {
                    engine.flush_cache(tag);
                    return Ok(text(StatusCode::OK, "flushed\n"));
                }
                (Method::GET, "dump") => {
                    return Ok(match engine.cache_dump(tag) {
                        Ok(dump) => response(StatusCode::OK, "application/octet-stream", dump),
                        Err(e) => text(StatusCode::INTERNAL_SERVER_ERROR, &format!("{e}\n")),
                    })
                }
                (Method::POST, "load_dump") => {
                    let data = match Limited::new(request.into_body(), 16 * 1024 * 1024)
                        .collect()
                        .await
                    {
                        Ok(data) => data.to_bytes(),
                        Err(_) => {
                            return Ok(text(
                                StatusCode::PAYLOAD_TOO_LARGE,
                                "dump body exceeds limit or is incomplete\n",
                            ))
                        }
                    };
                    return Ok(match engine.load_cache_dump(tag, &data) {
                        Ok(entries) => text(StatusCode::OK, &format!("loaded {entries}\n")),
                        Err(e) => text(StatusCode::BAD_REQUEST, &format!("invalid dump: {e}\n")),
                    });
                }
                _ => {}
            }
        }
    }
    Ok(text(StatusCode::NOT_FOUND, "not found\n"))
}

pub async fn serve(listen: String, engine: Arc<Engine>) -> Result<()> {
    serve_listener(TcpListener::bind(listen).await?, engine).await
}

pub async fn serve_listener(listener: TcpListener, engine: Arc<Engine>) -> Result<()> {
    let limit = Arc::new(Semaphore::new(64));
    loop {
        let (stream, _) = listener.accept().await?;
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            continue;
        };
        let engine = engine.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(move |request| handle(request, engine.clone()));
            let builder = Builder::new(TokioExecutor::new());
            let _ = tokio::time::timeout(
                Duration::from_secs(30),
                builder.serve_connection(TokioIo::new(stream), service),
            )
            .await;
        });
    }
}

#[cfg(test)]
mod cache_metrics_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coremain::Config;
    use hickory_proto::{
        op::{Message, Query},
        rr::{Name, RecordType},
    };

    #[tokio::test]
    async fn cache_api_metrics_flush_and_go_compatible_dump_roundtrip() {
        let config = Config::from_yaml("plugins:\n  - {tag: cached, type: cache}\n  - tag: main\n    type: sequence\n    args:\n      - {exec: '$cached'}\n      - {matches: has_resp, exec: accept}\n      - {exec: 'black_hole 223.5.5.5'}\n").unwrap();
        let engine = Arc::new(Engine::new(config).unwrap());
        let mut q = Message::new();
        q.add_query(Query::query(
            Name::from_ascii("api.example.").unwrap(),
            RecordType::A,
        ));
        engine
            .handle(q, "127.0.0.1".parse().unwrap(), "main")
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(serve_listener(listener, engine.clone()));
        let client = reqwest::Client::new();
        let metrics = client
            .get(format!("{url}/metrics"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(metrics.contains("mosdns_cache_size_current{tag=\"cached\"} 1"));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        for name in [
            "process_cpu_seconds_total",
            "process_open_fds",
            "process_max_fds",
            "process_resident_memory_bytes",
            "process_virtual_memory_bytes",
        ] {
            let line = metrics
                .lines()
                .find(|line| line.starts_with(&format!("{name} ")))
                .unwrap_or_else(|| panic!("missing default process metric {name}"));
            let value: f64 = line.split_whitespace().nth(1).unwrap().parse().unwrap();
            assert!(value.is_finite() && value >= 0.0, "{line}");
        }
        let dump = client
            .get(format!("{url}/plugins/cached/dump"))
            .send()
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(&dump[..2], &[0x1f, 0x8b]);
        assert!(client
            .get(format!("{url}/plugins/cached/flush"))
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
        assert_eq!(engine.cache_stats("cached").unwrap().len, 0);
        assert!(client
            .post(format!("{url}/plugins/cached/load_dump"))
            .body(dump)
            .send()
            .await
            .unwrap()
            .status()
            .is_success());
        assert_eq!(engine.cache_stats("cached").unwrap().len, 1);
        assert_eq!(
            client
                .post(format!("{url}/plugins/cached/load_dump"))
                .body("invalid")
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            client
                .get(format!("{url}/plugins/absent/flush"))
                .send()
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        task.abort();
    }

    #[tokio::test]
    async fn reverse_api_ip_validation_and_empty_lookup() {
        let config = Config::from_yaml("plugins:\n  - {tag: reverse, type: reverse_lookup}\n  - tag: main\n    type: sequence\n    args:\n      - {exec: '$reverse'}\n      - {exec: 'black_hole 223.5.5.5'}\n").unwrap();
        let engine = Arc::new(Engine::new(config).unwrap());
        let mut q = Message::new();
        q.add_query(Query::query(
            Name::from_ascii("reverse.example.").unwrap(),
            RecordType::A,
        ));
        engine
            .handle(q, "127.0.0.1".parse().unwrap(), "main")
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/plugins/reverse/", listener.local_addr().unwrap());
        let task = tokio::spawn(serve_listener(listener, engine));
        let client = reqwest::Client::new();
        for parameter in ["", "?ip=", "?ip=invalid"] {
            assert_eq!(
                client
                    .get(format!("{url}{parameter}"))
                    .send()
                    .await
                    .unwrap()
                    .status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            client
                .get(format!("{url}?ip=223.5.5.5"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "reverse.example."
        );
        assert_eq!(
            client
                .get(format!("{url}?ip=192.0.2.1"))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            ""
        );
        task.abort();
    }
}
