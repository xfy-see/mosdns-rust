use super::*;
use hickory_proto::op::{MessageType, OpCode};
use std::sync::Arc;
use tokio::net::TcpListener;

const LOCAL_TIMEOUT: Duration = Duration::from_secs(1);

fn response(query: &Message) -> Message {
    let mut reply = query.clone();
    reply.set_message_type(MessageType::Response);
    reply
}

async fn stub<F, Fut>(handler: F) -> (String, tokio::task::JoinHandle<()>)
where
    F: FnOnce(TcpStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = format!("tcp://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        handler(stream).await;
    });
    (address, task)
}

#[test]
fn template_generation_and_roundtrip_conversion_preserve_plugin_structure() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let expected = Format::Yaml.decode(TEMPLATE)?;
    for extension in ["yaml", "yml", "json", "toml"] {
        let generated = directory.path().join(format!("template.{extension}"));
        generate_config(&generated)?;
        assert_eq!(read_config_value(&generated)?, expected);
        let config = crate::coremain::Config::load(&generated)?;
        assert_eq!(config.plugins.len(), 3);
        assert_eq!(config.plugins[0].kind, "forward");
        assert_eq!(config.plugins[1].args["listen"], "127.0.0.1:53");
        for output_extension in ["yaml", "json", "toml"] {
            let converted = directory
                .path()
                .join(format!("{extension}-to.{output_extension}"));
            convert_config(&generated, &converted)?;
            assert_eq!(read_config_value(&converted)?, expected);
        }
    }
    Ok(())
}

#[test]
fn config_tools_never_overwrite_existing_outputs_or_input() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("input.yaml");
    generate_config(&input)?;
    let before = fs::read(&input)?;
    assert!(generate_config(&input).is_err());
    assert!(convert_config(&input, &input).is_err());
    let output = directory.path().join("output.json");
    fs::write(&output, b"preserve these bytes")?;
    assert!(convert_config(&input, &output).is_err());
    assert_eq!(fs::read(&input)?, before);
    assert_eq!(fs::read(&output)?, b"preserve these bytes");
    assert!(fs::read_dir(directory.path())?.all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".tmp")));
    Ok(())
}

#[cfg(unix)]
#[test]
fn output_symlinks_are_preserved_without_writing_the_target() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let target = directory.path().join("target");
    fs::write(&target, b"untouched")?;
    let output = directory.path().join("config.yaml");
    std::os::unix::fs::symlink(&target, &output)?;
    assert!(generate_config(&output).is_err());
    assert!(fs::symlink_metadata(&output)?.file_type().is_symlink());
    assert_eq!(fs::read(&target)?, b"untouched");
    Ok(())
}

#[test]
fn config_format_errors_do_not_create_output_files() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let bad = directory.path().join("bad.yaml");
    fs::write(&bad, "plugins: [")?;
    let output = directory.path().join("result.json");
    assert!(convert_config(&bad, &output).is_err());
    assert!(!output.exists());
    fs::write(&bad, "plugins: null\n")?;
    let toml = directory.path().join("null.toml");
    assert!(convert_config(&bad, &toml).is_err());
    assert!(!toml.exists());
    fs::write(&bad, "- list\n- is-not-a-config\n")?;
    assert!(read_config_value(&bad).is_err());
    assert!(generate_config(&directory.path().join("unknown.ini")).is_err());
    Ok(())
}

#[test]
fn config_no_overwrite_is_atomic_under_concurrent_generation() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("race.json");
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let path = output.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                generate_config(&path)
            })
        })
        .collect();
    let outcomes: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(read_config_value(&output)?, Format::Yaml.decode(TEMPLATE)?);
    Ok(())
}

#[test]
fn regression_toml_datetime_scalars_survive_conversion() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let input = directory.path().join("dates.toml");
    fs::write(
        &input,
        r#"[[plugins]]
type = "arbitrary"
[plugins.args]
dates = [1979-05-27T07:32:00Z, 1979-05-27T07:32:00, 1979-05-27, 07:32:00]
"#,
    )?;
    let expected = [
        "1979-05-27T07:32:00Z",
        "1979-05-27T07:32:00",
        "1979-05-27",
        "07:32:00",
    ];
    let config = crate::coremain::Config::load(&input)?;
    for (actual, expected) in config.plugins[0].args["dates"]
        .as_sequence()
        .unwrap()
        .iter()
        .zip(expected)
    {
        assert_eq!(
            actual.as_str(),
            Some(expected),
            "datetime must remain a scalar"
        );
    }
    for extension in ["yaml", "json", "toml"] {
        let output = directory.path().join(format!("converted.{extension}"));
        convert_config(&input, &output)?;
        let config = crate::coremain::Config::load(&output)?;
        for (actual, expected) in config.plugins[0].args["dates"]
            .as_sequence()
            .unwrap()
            .iter()
            .zip(expected)
        {
            assert_eq!(actual.as_str(), Some(expected));
        }
        assert!(!fs::read_to_string(&output)?.contains("$__toml_private"));
    }
    Ok(())
}

#[test]
fn regression_json_conversion_rejects_non_finite_numbers_without_output() -> Result<()> {
    let directory = tempfile::tempdir()?;
    for (index, (extension, document)) in [
        ("yaml", "nested: [1, .nan]"),
        ("yaml", "nested: {value: .inf}"),
        ("yaml", "nested: {value: -.inf}"),
        ("toml", "nested = [1, nan]"),
        ("toml", "[nested]\nvalue = inf"),
        ("toml", "[nested]\nvalue = -inf"),
    ]
    .into_iter()
    .enumerate()
    {
        let input = directory
            .path()
            .join(format!("special-{index}.{extension}"));
        let output = directory.path().join(format!("result-{index}.json"));
        fs::write(&input, document)?;
        let error = convert_config(&input, &output)
            .err()
            .context("non-finite number was silently converted to JSON null")?;
        assert!(format!("{error:#}").contains("non-finite"));
        assert!(!output.exists());
        assert_eq!(fs::read_to_string(&input)?, document);
    }
    let finite = directory.path().join("finite.yaml");
    let output = directory.path().join("finite.json");
    fs::write(&finite, "nested: [null, 1, 1.5]\n")?;
    convert_config(&finite, &output)?;
    assert_eq!(read_config_value(&finite)?, read_config_value(&output)?);
    assert!(fs::read_dir(directory.path())?.all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".tmp")));
    Ok(())
}

async fn trusted_test_tls_stream<F, Fut>(
    handler: F,
) -> Result<(Stream, tokio::task::JoinHandle<()>)>
where
    F: FnOnce(tokio_rustls::server::TlsStream<TcpStream>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let certificate = rustls::pki_types::CertificateDer::from(
        include_bytes!("pkg/upstream/fixtures/localhost-cert.der").to_vec(),
    );
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(
        include_bytes!("pkg/upstream/fixtures/localhost-key.der").to_vec(),
    );
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![certificate.clone()], key.into())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
    let (address, server) = stub(move |stream| async move {
        handler(acceptor.accept(stream).await.unwrap()).await;
    })
    .await;
    let address = ProbeAddress::parse(&address)?;
    let stream = TcpStream::connect((address.host.as_str(), address.port)).await?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(certificate)?;
    let client = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(address.host)?;
    let stream = tokio_rustls::TlsConnector::from(Arc::new(client))
        .connect(name, stream)
        .await?;
    Ok((Box::new(stream), server))
}

#[tokio::test]
async fn regression_tls_abrupt_idle_close_is_measured_after_a_valid_response() -> Result<()> {
    let (mut stream, server) = trusted_test_tls_stream(|mut stream| async move {
        let query = read_message(&mut stream).await.unwrap();
        write_message(&mut stream, &response(&query)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        // Drop the TCP transport without a TLS close_notify alert.
        drop(stream);
    })
    .await?;
    assert!(matches!(
        idle_timeout(&mut stream, LOCAL_TIMEOUT).await?,
        IdleObservation::Closed(_)
    ));
    server.await?;
    Ok(())
}

#[tokio::test]
async fn regression_tls_abrupt_close_during_a_partial_response_stays_an_error() -> Result<()> {
    let (mut stream, server) = trusted_test_tls_stream(|mut stream| async move {
        let query = read_message(&mut stream).await.unwrap();
        let bytes = response(&query).to_vec().unwrap();
        stream
            .write_all(&(bytes.len() as u16).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&bytes[..10]).await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);
    })
    .await?;
    assert!(idle_timeout(&mut stream, LOCAL_TIMEOUT).await.is_err());
    server.await?;
    Ok(())
}

#[test]
fn probe_address_and_duration_validation_is_explicit() -> Result<()> {
    let address = ProbeAddress::parse("tls://[::1]")?;
    assert_eq!(address.host, "::1");
    assert_eq!(address.port, 853);
    assert!(address.tls);
    assert_eq!(ProbeAddress::parse("tcp://localhost")?.port, 53);
    for address in [
        "127.0.0.1",
        "udp://127.0.0.1",
        "https://localhost",
        "tcp://user@localhost",
        "tls://localhost/path",
        "tcp://localhost?x=1",
        "tcp://localhost#fragment",
        "tcp://localhost:0",
    ] {
        assert!(ProbeAddress::parse(address).is_err(), "accepted {address}");
    }
    assert_eq!(parse_duration("25ms")?, Duration::from_millis(25));
    assert_eq!(parse_duration("1.5m")?, Duration::from_secs(90));
    for duration in ["0s", "-1s", "NaNs", "infs", "5", "1h"] {
        assert!(parse_duration(duration).is_err(), "accepted {duration}");
    }
    Ok(())
}

#[tokio::test]
async fn connection_reuse_requires_three_valid_responses_on_one_connection() -> Result<()> {
    let (address, server) = stub(|mut stream| async move {
        for expected in 0..3 {
            let query = read_message(&mut stream).await.unwrap();
            assert_eq!(query.id(), expected);
            write_message(&mut stream, &response(&query)).await.unwrap();
        }
    })
    .await;
    let mut stream = connect(&address).await?;
    connection_reuse(&mut stream, LOCAL_TIMEOUT).await?;
    server.await?;
    let (address, server) = stub(|mut stream| async move {
        let query = read_message(&mut stream).await.unwrap();
        write_message(&mut stream, &response(&query)).await.unwrap();
    })
    .await;
    let mut stream = connect(&address).await?;
    assert!(connection_reuse(&mut stream, LOCAL_TIMEOUT).await.is_err());
    server.await?;
    Ok(())
}

#[tokio::test]
async fn connection_reuse_rejects_id_question_qr_and_opcode_mismatches() -> Result<()> {
    for mutation in 0..4 {
        let (address, server) = stub(move |mut stream| async move {
            let query = read_message(&mut stream).await.unwrap();
            let mut reply = response(&query);
            match mutation {
                0 => {
                    reply.set_id(query.id().wrapping_add(1));
                }
                1 => {
                    reply.queries_mut()[0].set_name(Name::from_ascii("other.example.").unwrap());
                }
                2 => {
                    reply.set_message_type(MessageType::Query);
                }
                _ => {
                    reply.set_op_code(OpCode::Status);
                }
            }
            write_message(&mut stream, &reply).await.unwrap();
        })
        .await;
        let mut stream = connect(&address).await?;
        assert!(connection_reuse(&mut stream, LOCAL_TIMEOUT).await.is_err());
        server.await?;
    }
    Ok(())
}

#[tokio::test]
async fn pipeline_sends_both_queries_before_reading_and_accepts_reverse_order() -> Result<()> {
    let (address, server) = stub(|mut stream| async move {
        let first = read_message(&mut stream).await.unwrap();
        let second = read_message(&mut stream).await.unwrap();
        assert_eq!(first.id(), 0);
        assert_eq!(second.id(), 1);
        assert_eq!(second.queries()[0].name(), &Name::root());
        write_message(&mut stream, &response(&second))
            .await
            .unwrap();
        write_message(&mut stream, &response(&first)).await.unwrap();
    })
    .await;
    let mut stream = connect(&address).await?;
    let result = pipeline(&mut stream, LOCAL_TIMEOUT).await?;
    assert!(result.out_of_order);
    assert_eq!(
        result
            .responses
            .iter()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>(),
        vec![1, 0]
    );
    server.await?;
    Ok(())
}

#[tokio::test]
async fn pipeline_rejects_unknown_duplicate_and_forged_responses() -> Result<()> {
    for mutation in 0..3 {
        let (address, server) = stub(move |mut stream| async move {
            let first = read_message(&mut stream).await.unwrap();
            let second = read_message(&mut stream).await.unwrap();
            let mut reply = response(&first);
            match mutation {
                0 => {
                    reply.set_id(42);
                }
                1 => (),
                _ => {
                    reply.queries_mut()[0] = second.queries()[0].clone();
                }
            }
            write_message(&mut stream, &reply).await.unwrap();
            if mutation == 1 {
                write_message(&mut stream, &reply).await.unwrap();
            }
        })
        .await;
        let mut stream = connect(&address).await?;
        assert!(pipeline(&mut stream, LOCAL_TIMEOUT).await.is_err());
        server.await?;
    }
    Ok(())
}

#[tokio::test]
async fn idle_timeout_reports_peer_closure_and_an_observation_lower_bound() -> Result<()> {
    let (address, server) = stub(|mut stream| async move {
        let query = read_message(&mut stream).await.unwrap();
        write_message(&mut stream, &response(&query)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
    })
    .await;
    let mut stream = connect(&address).await?;
    assert!(matches!(
        idle_timeout(&mut stream, LOCAL_TIMEOUT).await?,
        IdleObservation::Closed(_)
    ));
    server.await?;
    let (address, server) = stub(|mut stream| async move {
        let query = read_message(&mut stream).await.unwrap();
        write_message(&mut stream, &response(&query)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
    })
    .await;
    let mut stream = connect(&address).await?;
    match idle_timeout(&mut stream, Duration::from_millis(20)).await? {
        IdleObservation::OpenAtLeast(elapsed) => assert!(elapsed >= Duration::from_millis(20)),
        other => panic!("expected bounded open observation, got {other:?}"),
    }
    server.await?;
    Ok(())
}

#[tokio::test]
async fn probe_framing_rejects_short_or_partial_dns_messages() -> Result<()> {
    for bytes in [vec![0, 0], vec![0, 11], vec![0, 20, 0, 1, 2, 3]] {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer.write_all(&bytes).await?;
        drop(writer);
        assert!(read_message(&mut reader).await.is_err());
    }
    Ok(())
}

#[tokio::test]
async fn tls_probe_keeps_certificate_verification_enabled() -> Result<()> {
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(
            include_bytes!("pkg/upstream/fixtures/localhost-cert.der").to_vec(),
        )],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            include_bytes!("pkg/upstream/fixtures/localhost-key.der").to_vec(),
        )),
    )?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let (address, server) = stub(move |stream| async move {
        let _ = acceptor.accept(stream).await;
    })
    .await;
    let address = address.replacen("tcp://", "tls://", 1);
    let error = connect(&address)
        .await
        .err()
        .context("self-signed certificate was accepted")?;
    assert!(format!("{error:#}").contains("certificate"));
    server.await?;
    Ok(())
}

#[tokio::test]
async fn cli_dispatch_keeps_go_hierarchy_and_rejects_unknown_flags() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("cli.toml");
    run(&[
        "tools".into(),
        "config".into(),
        "gen".into(),
        output.to_string_lossy().into_owned(),
    ])
    .await?;
    assert_eq!(crate::coremain::Config::load(&output)?.plugins.len(), 3);
    for args in [
        vec!["config", "conv", "-i", "a.yaml"],
        vec!["config", "conv", "--in=a.yaml", "--out=b.json", "--force"],
        vec!["probe", "unknown", "tcp://127.0.0.1"],
        vec!["probe", "conn-reuse", "tcp://127.0.0.1", "--insecure"],
        vec!["probe", "idle-timeout", "tcp://127.0.0.1", "--timeout=0s"],
    ] {
        assert!(
            run(&args.into_iter().map(str::to_owned).collect::<Vec<_>>())
                .await
                .is_err()
        );
    }
    let input = directory.path().join("cli-in.yaml");
    generate_config(&input)?;
    let converted = directory.path().join("converted.json");
    run(&[
        "config".into(),
        "conv".into(),
        format!("--in={}", input.display()),
        "-o".into(),
        converted.to_string_lossy().into_owned(),
    ])
    .await?;
    assert_eq!(read_config_value(&input)?, read_config_value(&converted)?);
    Ok(())
}
