// SPDX-License-Identifier: GPL-3.0-or-later
//! The Go `tools` package registers `probe` and `config` at the CLI root.

use anyhow::{bail, Context, Result};
use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};
use serde_yaml::Value;
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::{timeout, Instant},
};

const HELP: &str = "Usage:
  mosdns probe conn-reuse {tcp|tls}://host[:port]
  mosdns probe pipeline {tcp|tls}://host[:port]
  mosdns probe idle-timeout {tcp|tls}://host[:port] [--timeout 300s]
  mosdns config gen FILE.{yaml|yml|json|toml}
  mosdns config conv -i INPUT -o OUTPUT

TLS probes verify the certificate and server name. Config output must not exist.
The optional tools prefix is also accepted.";

const TEMPLATE: &str = r#"log:
  level: info
plugins:
  - tag: forward_google
    type: forward
    args:
      upstreams:
        - addr: https://8.8.8.8/dns-query
  - tag: udp_server
    type: udp_server
    args:
      entry: forward_google
      listen: "127.0.0.1:53"
  - tag: tcp_server
    type: tcp_server
    args:
      entry: forward_google
      listen: "127.0.0.1:53"
"#;

#[derive(Clone, Copy)]
enum Format {
    Yaml,
    Json,
    Toml,
}
impl Format {
    fn of(path: &Path) -> Result<Self> {
        match path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("yaml" | "yml") => Ok(Self::Yaml),
            Some("json") => Ok(Self::Json),
            Some("toml") => Ok(Self::Toml),
            _ => bail!(
                "unsupported config extension: {}; expected yaml, yml, json, or toml",
                path.display()
            ),
        }
    }
    fn decode(self, text: &str) -> Result<Value> {
        let value = match self {
            Self::Yaml => serde_yaml::from_str(text).context("parse YAML config")?,
            Self::Json => serde_json::from_str(text).context("parse JSON config")?,
            Self::Toml => {
                let value = toml::from_str::<toml::Value>(text).context("parse TOML config")?;
                normalize_toml(value)
            }
        };
        if !matches!(value, Value::Mapping(_)) {
            bail!("config root must be a mapping");
        }
        Ok(value)
    }
    fn encode(self, value: &Value) -> Result<Vec<u8>> {
        let text = match self {
            Self::Yaml => serde_yaml::to_string(value).context("serialize YAML config")?,
            Self::Json => {
                ensure_json_finite(value)?;
                let mut text =
                    serde_json::to_string_pretty(value).context("serialize JSON config")?;
                text.push('\n');
                text
            }
            Self::Toml => toml::to_string_pretty(value).context(
                "serialize TOML config (null values and YAML tags cannot be represented)",
            )?,
        };
        Ok(text.into_bytes())
    }
}

fn normalize_toml(value: toml::Value) -> Value {
    match value {
        toml::Value::String(value) => Value::String(value),
        toml::Value::Integer(value) => Value::Number(value.into()),
        toml::Value::Float(value) => Value::Number(value.into()),
        toml::Value::Boolean(value) => Value::Bool(value),
        // The shared YAML value model has no native datetime type. Retain its
        // textual scalar instead of exposing toml's private serde struct fields.
        toml::Value::Datetime(value) => Value::String(value.to_string()),
        toml::Value::Array(values) => {
            Value::Sequence(values.into_iter().map(normalize_toml).collect())
        }
        toml::Value::Table(values) => Value::Mapping(
            values
                .into_iter()
                .map(|(key, value)| (Value::String(key), normalize_toml(value)))
                .collect(),
        ),
    }
}

fn ensure_json_finite(value: &Value) -> Result<()> {
    match value {
        Value::Number(number) if number.as_f64().is_some_and(|value| !value.is_finite()) => {
            bail!("non-finite numbers (NaN or Infinity) cannot be represented in JSON");
        }
        Value::Sequence(values) => {
            for value in values {
                ensure_json_finite(value)?;
            }
        }
        Value::Mapping(values) => {
            for (key, value) in values {
                ensure_json_finite(key)?;
                ensure_json_finite(value)?;
            }
        }
        Value::Tagged(value) => ensure_json_finite(&value.value)?,
        _ => (),
    }
    Ok(())
}

/// Shared by Config::load and format conversion; includes are left unresolved.
pub fn read_config_value(path: &Path) -> Result<Value> {
    let format = Format::of(path)?;
    let text =
        fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    format
        .decode(&text)
        .with_context(|| format!("config {}", path.display()))
}

struct TemporaryOutput(PathBuf);
impl Drop for TemporaryOutput {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Publish a complete file through a same-directory hard link. Creating the
/// final name is atomic and cannot replace a file or symlink, even in a race.
fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut candidate = None;
    for _ in 0..16 {
        let temporary = parent.join(format!(
            ".mosdns-rs-{}-{:016x}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temporary) {
            Ok(file) => {
                candidate = Some((TemporaryOutput(temporary), file));
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error).with_context(|| format!("create output in {}", parent.display()))
            }
        }
    }
    let (temporary, mut file) = candidate.context("cannot allocate a unique temporary output")?;
    file.write_all(data).context("write config output")?;
    file.sync_all().context("sync config output")?;
    drop(file);
    fs::hard_link(&temporary.0, path).with_context(|| {
        format!(
            "create output {}; refusing to overwrite existing paths",
            path.display()
        )
    })?;
    Ok(())
}

pub fn generate_config(output: &Path) -> Result<()> {
    let format = Format::of(output)?;
    let template = Format::Yaml.decode(TEMPLATE)?;
    write_new(output, &format.encode(&template)?)
}

pub fn convert_config(input: &Path, output: &Path) -> Result<()> {
    let format = Format::of(output)?;
    let value = read_config_value(input)?;
    write_new(output, &format.encode(&value)?)
}

trait ProbeStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProbeStream for T {}
type Stream = Box<dyn ProbeStream>;

struct ProbeAddress {
    host: String,
    port: u16,
    tls: bool,
}
impl ProbeAddress {
    fn parse(address: &str) -> Result<Self> {
        if !address.contains("://") {
            bail!("probe address requires tcp:// or tls://");
        }
        let url = url::Url::parse(address).context("invalid probe address")?;
        let tls = match url.scheme() {
            "tcp" => false,
            "tls" => true,
            other => bail!("unsupported probe protocol {other}; expected tcp or tls"),
        };
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !matches!(url.path(), "" | "/")
        {
            bail!("probe address must contain only a protocol, host, and optional port");
        }
        let host = url
            .host_str()
            .context("probe address has no host")?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = url.port().unwrap_or(if tls { 853 } else { 53 });
        if port == 0 {
            bail!("probe port must be nonzero");
        }
        Ok(Self { host, port, tls })
    }
}

async fn connect(address: &str) -> Result<Stream> {
    let address = ProbeAddress::parse(address)?;
    timeout(Duration::from_secs(5), async move {
        let stream = TcpStream::connect((address.host.as_str(), address.port))
            .await
            .context("connect probe TCP socket")?;
        stream.set_nodelay(true).context("set probe TCP_NODELAY")?;
        if !address.tls {
            return Ok(Box::new(stream) as Stream);
        }
        let config = crate::pkg::upstream::tls_client_config(false, b"dot")?;
        let name = rustls::pki_types::ServerName::try_from(address.host)
            .context("invalid probe TLS server name")?;
        let stream = tokio_rustls::TlsConnector::from(config)
            .connect(name, stream)
            .await
            .context("probe TLS handshake and certificate validation")?;
        Ok(Box::new(stream) as Stream)
    })
    .await
    .context("probe connection timeout")?
}

fn question(domain: &str, kind: RecordType, id: u16) -> Result<Message> {
    let mut query = Message::new();
    query
        .set_id(id)
        .set_recursion_desired(true)
        .add_query(Query::query(Name::from_ascii(domain)?, kind));
    Ok(query)
}

async fn write_message<S: AsyncWrite + Unpin + ?Sized>(
    stream: &mut S,
    message: &Message,
) -> Result<()> {
    let bytes = message.to_vec().context("encode probe DNS message")?;
    let length = u16::try_from(bytes.len()).context("probe DNS message exceeds 65535 bytes")?;
    stream
        .write_all(&length.to_be_bytes())
        .await
        .context("write probe DNS frame length")?;
    stream
        .write_all(&bytes)
        .await
        .context("write probe DNS frame")?;
    stream.flush().await.context("flush probe DNS frame")?;
    Ok(())
}

async fn read_message<S: AsyncRead + Unpin + ?Sized>(stream: &mut S) -> Result<Message> {
    let length = stream
        .read_u16()
        .await
        .context("read probe DNS frame length")? as usize;
    if length < 12 {
        bail!("invalid probe DNS frame length {length}");
    }
    let mut bytes = vec![0; length];
    stream
        .read_exact(&mut bytes)
        .await
        .context("read complete probe DNS frame")?;
    Message::from_vec(&bytes).context("decode probe DNS response")
}

#[derive(Debug)]
enum IdleObservation {
    Closed(Duration),
    OpenAtLeast(Duration),
}

async fn connection_reuse(stream: &mut Stream, limit: Duration) -> Result<()> {
    for id in 0..3 {
        let query = question("www.cloudflare.com.", RecordType::A, id)?;
        let response = timeout(limit, async {
            write_message(stream, &query).await?;
            read_message(stream).await
        })
        .await
        .with_context(|| format!("connection reuse probe #{id} timed out"))?
        .with_context(|| format!("connection reuse probe #{id}"))?;
        crate::pkg::upstream::validate_response(&query, &response)
            .with_context(|| format!("connection reuse probe #{id}"))?;
    }
    Ok(())
}

struct PipelineObservation {
    out_of_order: bool,
    responses: Vec<(u16, Duration)>,
}
async fn pipeline(stream: &mut Stream, limit: Duration) -> Result<PipelineObservation> {
    let label = format!("{:032x}.com.", rand::random::<u128>());
    let queries = [
        question(&label, RecordType::NS, 0)?,
        question(".", RecordType::NS, 1)?,
    ];
    for query in &queries {
        timeout(Duration::from_secs(3), write_message(stream, query))
            .await
            .context("pipeline query write timeout")??;
    }
    let started = Instant::now();
    let mut seen = HashSet::new();
    let mut observation = PipelineObservation {
        out_of_order: false,
        responses: Vec::new(),
    };
    for index in 0..queries.len() {
        let response = timeout(limit, read_message(stream))
            .await
            .context("pipeline response timeout")??;
        let id = response.id();
        let query = queries
            .get(id as usize)
            .context("pipeline response has an unknown ID")?;
        if !seen.insert(id) {
            bail!("duplicate pipeline response ID {id}");
        }
        crate::pkg::upstream::validate_response(query, &response)?;
        observation.out_of_order |= id as usize != index;
        observation.responses.push((id, started.elapsed()));
    }
    Ok(observation)
}

async fn idle_timeout(stream: &mut Stream, limit: Duration) -> Result<IdleObservation> {
    let query = question("www.cloudflare.com.", RecordType::A, rand::random())?;
    let response = timeout(Duration::from_secs(3), async {
        write_message(stream, &query).await?;
        read_message(stream).await
    })
    .await
    .context("idle timeout initial query timed out")??;
    crate::pkg::upstream::validate_response(&query, &response)?;
    let started = Instant::now();
    let mut byte = [0u8; 1];
    match timeout(limit, stream.read(&mut byte)).await {
        Err(_) => Ok(IdleObservation::OpenAtLeast(started.elapsed())),
        Ok(Ok(0)) => Ok(IdleObservation::Closed(started.elapsed())),
        Ok(Err(error))
            if matches!(
                error.kind(),
                std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::UnexpectedEof
            ) =>
        {
            // A complete validated response precedes this observation. rustls
            // reports a TCP close without TLS close_notify as UnexpectedEof.
            // A truncated DNS response still fails in the initial read above.
            Ok(IdleObservation::Closed(started.elapsed()))
        }
        Ok(Err(error)) => Err(error).context("observe probe connection idle closure"),
        Ok(Ok(_)) => bail!("unsolicited bytes received while measuring idle timeout"),
    }
}

fn parse_duration(value: &str) -> Result<Duration> {
    let (number, scale) = if let Some(number) = value.strip_suffix("ms") {
        (number, 0.001)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1.0)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60.0)
    } else {
        bail!("duration requires an ms, s, or m suffix");
    };
    let seconds = number.parse::<f64>().context("invalid duration number")? * scale;
    let duration = Duration::try_from_secs_f64(seconds).context("invalid duration")?;
    if duration.is_zero() {
        bail!("duration must be positive");
    }
    Ok(duration)
}

fn conversion_paths(args: &[String]) -> Result<(&Path, &Path)> {
    let mut input = None;
    let mut output = None;
    let mut index = 0;
    while index < args.len() {
        let (flag, inline) = args[index]
            .split_once('=')
            .map_or((args[index].as_str(), None), |(flag, value)| {
                (flag, Some(value))
            });
        let slot = match flag {
            "-i" | "--in" => &mut input,
            "-o" | "--out" => &mut output,
            other => bail!("unknown config conv argument {other}"),
        };
        if slot.is_some() {
            bail!("duplicate config conv option {flag}");
        }
        let value = match inline {
            Some(value) => value,
            None => {
                index += 1;
                args.get(index)
                    .context("config conv option requires a path")?
                    .as_str()
            }
        };
        if value.is_empty() {
            bail!("config conv path must not be empty");
        }
        *slot = Some(Path::new(value));
        index += 1;
    }
    Ok((
        input.context("config conv requires -i/--in")?,
        output.context("config conv requires -o/--out")?,
    ))
}

/// `args` begins with `probe` or `config`; an optional `tools` prefix is accepted.
pub async fn run(args: &[String]) -> Result<()> {
    let args = if args.first().is_some_and(|value| value == "tools") {
        &args[1..]
    } else {
        args
    };
    if args.is_empty() || args.iter().any(|value| value == "--help" || value == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    match args[0].as_str() {
        "config" => match args.get(1).map(String::as_str) {
            Some("gen") if args.len() == 3 => generate_config(Path::new(&args[2])),
            Some("conv") => {
                let (input, output) = conversion_paths(&args[2..])?;
                convert_config(input, output)
            }
            _ => bail!("expected config gen FILE or config conv -i INPUT -o OUTPUT"),
        },
        "probe" => {
            let operation = args
                .get(1)
                .context("probe requires conn-reuse, pipeline, or idle-timeout")?;
            if !matches!(
                operation.as_str(),
                "conn-reuse" | "pipeline" | "idle-timeout"
            ) {
                bail!("unknown probe command {operation}");
            }
            let address = args
                .get(2)
                .context("probe requires a tcp:// or tls:// address")?;
            let limit = match &args[3..] {
                [] => {
                    if operation == "idle-timeout" {
                        Duration::from_secs(300)
                    } else if operation == "pipeline" {
                        Duration::from_secs(10)
                    } else {
                        Duration::from_secs(3)
                    }
                }
                [flag, value] if operation == "idle-timeout" && flag == "--timeout" => {
                    parse_duration(value)?
                }
                [flag] if operation == "idle-timeout" && flag.starts_with("--timeout=") => {
                    parse_duration(&flag[10..])?
                }
                _ => bail!(
                    "unexpected probe arguments; only idle-timeout accepts --timeout DURATION"
                ),
            };
            let mut stream = connect(address).await?;
            match operation.as_str() {
                "conn-reuse" => {
                    connection_reuse(&mut stream, limit).await?;
                    println!("server {address} supports RFC 1035 connection reuse (3 validated responses on one connection)");
                }
                "pipeline" => {
                    let result = pipeline(&mut stream, limit).await?;
                    for (id, latency) in result.responses {
                        println!("#{id} response received, latency: {} ms", latency.as_millis());
                    }
                    if result.out_of_order {
                        println!("server {address} supports RFC 7766 out-of-order query pipelining");
                    } else {
                        println!("no out-of-order response received; this test does not establish RFC 7766 out-of-order query pipelining");
                    }
                }
                _ => match idle_timeout(&mut stream, limit).await? {
                    IdleObservation::Closed(elapsed) => println!("connection closed by peer after {:.2} seconds idle", elapsed.as_secs_f64()),
                    IdleObservation::OpenAtLeast(elapsed) => println!("connection remained open for at least {:.2} seconds idle; no closure observed", elapsed.as_secs_f64()),
                },
            }
            Ok(())
        }
        other => bail!("unknown tools command {other}; expected probe or config"),
    }
}

#[cfg(test)]
#[path = "tools_tests.rs"]
mod tests;
