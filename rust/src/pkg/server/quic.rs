use super::*;

pub async fn serve_quic(
    listen: &str,
    engine: Arc<crate::coremain::Engine>,
    entry: String,
    cert: &str,
    key: &str,
    idle_timeout: Duration,
) -> Result<()> {
    let tls = tls::load_tls_config(cert, key, &[b"doq"])?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls.as_ref().clone())
        .context("QUIC TLS server config")?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let idle_timeout = if idle_timeout.is_zero() {
        Duration::from_secs(30)
    } else {
        idle_timeout
    };
    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams((TCP_PIPELINE_LIMIT as u32).into())
        .max_concurrent_uni_streams(0u8.into())
        .max_idle_timeout(Some(idle_timeout.try_into()?))
        .stream_receive_window(65537u32.into())
        .receive_window((4 * 1024 * 1024u32).into());
    config.transport_config(Arc::new(transport));
    let address = tokio::net::lookup_host(listen)
        .await
        .context("resolve QUIC listen address")?
        .next()
        .context("QUIC listen address resolved to no addresses")?;
    let endpoint = quinn::Endpoint::server(config, address).context("bind QUIC DNS listener")?;
    serve_quic_endpoint(endpoint, engine, entry, idle_timeout).await
}

pub(super) async fn serve_quic_endpoint(
    endpoint: quinn::Endpoint,
    engine: Arc<crate::coremain::Engine>,
    entry: String,
    idle_timeout: Duration,
) -> Result<()> {
    let connections = Arc::new(Semaphore::new(MAX_TCP_CONNECTIONS));
    let queries = Arc::new(Semaphore::new(MAX_QUERIES));
    let entry: Arc<str> = entry.into();
    let mut tasks = JoinSet::new();
    while let Some(incoming) = endpoint.accept().await {
        let Ok(permit) = connections.clone().try_acquire_owned() else {
            incoming.refuse();
            continue;
        };
        let engine = engine.clone();
        let entry = entry.clone();
        let queries = queries.clone();
        tasks.spawn(async move {
            let _permit = permit;
            let connection = match tokio::time::timeout(FIRST_READ_TIMEOUT, incoming).await {
                Ok(Ok(connection)) => connection,
                _ => return,
            };
            let server_name = connection
                .handshake_data()
                .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
                .and_then(|data| data.server_name)
                .map(Arc::<str>::from);
            let client = Some(connection.remote_address().ip());
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
            let mut streams = JoinSet::new();
            let mut first = true;
            loop {
                let timeout = if first {
                    FIRST_READ_TIMEOUT.min(idle_timeout)
                } else {
                    idle_timeout
                };
                first = false;
                let (mut send, mut receive) =
                    match tokio::time::timeout(timeout, connection.accept_bi()).await {
                        Ok(Ok(stream)) => stream,
                        _ => break,
                    };
                let permit = match queries.clone().acquire_owned().await {
                    Ok(permit) => permit,
                    Err(_) => break,
                };
                let connection = connection.clone();
                let handler = handler.clone();
                streams.spawn(async move {
                    let _permit = permit;
                    let frame =
                        match tokio::time::timeout(FIRST_READ_TIMEOUT, receive.read_to_end(65537))
                            .await
                        {
                            Ok(Ok(frame)) => frame,
                            _ => {
                                let _ = receive.stop(2u32.into());
                                return;
                            }
                        };
                    if frame.len() < 14
                        || u16::from_be_bytes([frame[0], frame[1]]) as usize != frame.len() - 2
                    {
                        connection.close(2u32.into(), b"invalid DNS length frame");
                        return;
                    }
                    let query = match Message::from_vec(&frame[2..]) {
                        Ok(query) if query.id() == 0 => query,
                        _ => {
                            connection.close(2u32.into(), b"invalid DNS query or ID");
                            return;
                        }
                    };
                    let (_, response) = process_query(query, client, &handler).await;
                    let mut frame = Vec::with_capacity(512);
                    if encode_stream_response(&response, &mut frame).is_err() {
                        return;
                    }
                    if matches!(
                        tokio::time::timeout(WRITE_TIMEOUT, send.write_all(&frame)).await,
                        Ok(Ok(()))
                    ) {
                        let _ = send.finish();
                    }
                });
                while streams.try_join_next().is_some() {}
            }
            connection.close(0u32.into(), b"idle or closed");
        });
        while tasks.try_join_next().is_some() {}
    }
    Ok(())
}
