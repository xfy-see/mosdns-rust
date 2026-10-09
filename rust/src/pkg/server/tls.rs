use super::*;
use std::{fs::File, io::BufReader};

pub(super) fn load_tls_config(
    cert: &str,
    key: &str,
    alpn: &[&[u8]],
) -> Result<Arc<rustls::ServerConfig>> {
    if cert.is_empty() || key.is_empty() {
        bail!("TLS requires both cert and key");
    }
    let mut cert_reader =
        BufReader::new(File::open(cert).with_context(|| format!("open TLS certificate {cert}"))?);
    let certificates = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("read TLS certificate PEM")?;
    if certificates.is_empty() {
        bail!("TLS certificate PEM is empty");
    }
    let mut key_reader =
        BufReader::new(File::open(key).with_context(|| format!("open TLS private key {key}"))?);
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .context("read TLS private key PEM")?
        .context("TLS private key PEM is empty")?;
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("TLS protocol versions")?
    .with_no_client_auth()
    .with_single_cert(certificates, private_key)
    .context("TLS certificate and private key")?;
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

pub async fn serve_tls(
    listen: &str,
    engine: Arc<crate::coremain::Engine>,
    entry: String,
    cert: &str,
    key: &str,
    idle_timeout: Duration,
) -> Result<()> {
    let config = load_tls_config(cert, key, &[b"dot"])?;
    let listener = socket::bind_stream(listen)
        .await
        .context("bind TLS DNS listener")?;
    serve_tls_listener(listener, engine, entry, config, idle_timeout).await
}

pub(super) async fn serve_tls_listener(
    listener: socket::StreamListener,
    engine: Arc<crate::coremain::Engine>,
    entry: String,
    config: Arc<rustls::ServerConfig>,
    idle_timeout: Duration,
) -> Result<()> {
    let connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    let queries = Arc::new(Semaphore::new(MAX_QUERIES));
    let entry: Arc<str> = entry.into();
    let idle_timeout = if idle_timeout.is_zero() {
        IDLE_TIMEOUT
    } else {
        idle_timeout
    };
    let mut tasks = JoinSet::new();
    loop {
        let (stream, client) = listener
            .accept()
            .await
            .context("accept DNS TLS connection")?;
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            continue;
        };
        let config = config.clone();
        let engine = engine.clone();
        let entry = entry.clone();
        let queries = queries.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let tls = match tokio::time::timeout(
                FIRST_READ_TIMEOUT,
                tokio_rustls::TlsAcceptor::from(config).accept(stream),
            )
            .await
            {
                Ok(Ok(tls)) => tls,
                _ => return,
            };
            let server_name = tls.get_ref().1.server_name().map(Arc::<str>::from);
            let handler: Handler = Arc::new(move |query, client| {
                let engine = engine.clone();
                let entry = entry.clone();
                let server_name = server_name.clone();
                Box::pin(async move {
                    engine
                        .handle_with_client_meta(
                            query,
                            client,
                            &entry,
                            None,
                            server_name.as_deref(),
                        )
                        .await
                })
            });
            let _ = serve_dns_connection(tls, client, handler, queries, idle_timeout).await;
        });
        while tasks.try_join_next().is_some() {}
    }
}
