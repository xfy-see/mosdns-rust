use super::*;

/// Connection options retain mosdns's upstream URL as the TLS/HTTP identity.
#[derive(Clone, Default)]
pub struct Options {
    pub dial_addr: String,
    pub socks5: String,
    pub bootstrap: String,
    pub bootstrap_version: i64,
    pub so_mark: i64,
    pub bind_to_device: String,
    pub idle_timeout: Duration,
    pub enable_pipeline: bool,
    pub enable_http3: bool,
    pub insecure_skip_verify: bool,
    /// Optional shared observer. Observed DoH uses the explicit Hyper driver
    /// so its socket lifecycle can be counted; unobserved DoH retains reqwest.
    pub event_observer: Option<Arc<dyn EventObserver>>,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("dial_addr", &self.dial_addr)
            .field("socks5", &self.socks5)
            .field("bootstrap", &self.bootstrap)
            .field("bootstrap_version", &self.bootstrap_version)
            .field("so_mark", &self.so_mark)
            .field("bind_to_device", &self.bind_to_device)
            .field("idle_timeout", &self.idle_timeout)
            .field("enable_pipeline", &self.enable_pipeline)
            .field("enable_http3", &self.enable_http3)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("event_observer", &self.event_observer.is_some())
            .finish()
    }
}

#[cfg(not(feature = "full"))]
pub(super) fn check_profile_options(scheme: &str, options: &Options) -> Result<()> {
    // Go applies its tcp+pipeline helper before checking the plaintext profile.
    if !matches!(scheme, "udp" | "tcp" | "tcp+pipeline") {
        bail!("protocol [{scheme}] is unavailable in minimal (supports udp/tcp)");
    }
    if options.enable_http3 {
        bail!("enable_http3 is unavailable in minimal");
    }
    if !options.socks5.is_empty() || !options.bootstrap.is_empty() || options.bootstrap_version != 0
    {
        bail!("socks5/bootstrap options require the full profile; minimal uses numeric UDP/TCP upstream addresses");
    }
    if options.insecure_skip_verify {
        bail!("insecure_skip_verify is unavailable in minimal");
    }
    Ok(())
}

pub(super) fn dial_target(host: &str, port: u16, override_address: &str) -> Result<(String, u16)> {
    if override_address.is_empty() {
        return Ok((host.to_owned(), port));
    }
    if let Ok(ip) = override_address.parse::<std::net::IpAddr>() {
        return Ok((ip.to_string(), port));
    }
    let address = Url::parse(&format!("tcp://{override_address}")).context("invalid dial_addr")?;
    if !address.username().is_empty()
        || address.password().is_some()
        || address.query().is_some()
        || address.fragment().is_some()
        || !matches!(address.path(), "" | "/")
    {
        bail!("dial_addr must contain only a host and optional port");
    }
    let host = address
        .host_str()
        .context("dial_addr has no host")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = address.port().unwrap_or(port);
    if port == 0 {
        bail!("dial_addr port must be nonzero");
    }
    Ok((host, port))
}

#[cfg(feature = "full")]
pub(super) struct DialResolver {
    pub dialer: super::dialer::Dialer,
}
#[cfg(feature = "full")]
impl reqwest::dns::Resolve for DialResolver {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let dialer = self.dialer.clone();
        Box::pin(async move {
            let addresses = dialer
                .resolve_addresses()
                .await
                .map_err(std::io::Error::other)?;
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

#[derive(Debug)]
#[cfg(feature = "full")]
struct NoCertificateVerification {
    provider: rustls::crypto::CryptoProvider,
}
#[cfg(feature = "full")]
impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Build a DNS client's TLS configuration with the platform trust store.
/// `SSL_CERT_FILE` and `SSL_CERT_DIR` select explicit PEM trust locations.
/// Explicit insecure mode skips root loading but still verifies TLS signatures.
#[cfg(feature = "full")]
pub fn tls_client_config(insecure: bool, alpn: &[u8]) -> Result<Arc<rustls::ClientConfig>> {
    let roots = if insecure {
        Arc::new(rustls::RootCertStore::empty())
    } else {
        super::trust::system_roots()?
    };
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("TLS protocol versions")?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![alpn.to_vec()];
    if insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification {
                provider: rustls::crypto::ring::default_provider(),
            }));
    }
    Ok(Arc::new(config))
}
