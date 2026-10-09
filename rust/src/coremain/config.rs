use anyhow::{bail, Result};
use serde::{Deserialize, Deserializer};
use serde_yaml::Value;
use std::path::Path;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub log: LogConfig,
    #[serde(deserialize_with = "deserialize_strings")]
    pub include: Vec<String>,
    pub plugins: Vec<PluginConfig>,
    pub api: ApiConfig,
}
/// mapstructure's WeaklyTypedInput accepts a scalar as a one-element slice.
pub(crate) fn deserialize_strings<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<Vec<String>, D::Error> {
    let value = Value::deserialize(d)?;
    fn scalar<E: serde::de::Error>(v: Value) -> std::result::Result<String, E> {
        match v {
            Value::String(s) => Ok(s),
            Value::Number(n) => Ok(n.to_string()),
            Value::Bool(b) => Ok(b.to_string()),
            _ => Err(E::custom("expected string scalar")),
        }
    }
    match value {
        Value::Null => Ok(Vec::new()),
        Value::Sequence(v) => v.into_iter().map(scalar).collect(),
        v => Ok(vec![scalar(v)?]),
    }
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    pub level: String,
    pub file: String,
    #[serde(deserialize_with = "deserialize_bool")]
    pub production: bool,
}
pub(crate) fn deserialize_number<'de, D, T>(d: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    use serde::de::Error;
    let s = match Value::deserialize(d)? {
        Value::String(s) => s,
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => if b { "1" } else { "0" }.into(),
        _ => return Err(D::Error::custom("expected number")),
    };
    s.parse().map_err(D::Error::custom)
}
pub(crate) fn deserialize_bool<'de, D: Deserializer<'de>>(
    d: D,
) -> std::result::Result<bool, D::Error> {
    use serde::de::Error;
    match Value::deserialize(d)? {
        Value::Bool(b) => Ok(b),
        Value::Number(n) => Ok(n.as_f64().is_some_and(|n| n != 0.0)),
        Value::String(s) => match s.as_str() {
            "true" | "True" | "TRUE" | "1" => Ok(true),
            "false" | "False" | "FALSE" | "0" => Ok(false),
            _ => Err(D::Error::custom("expected boolean")),
        },
        _ => Err(D::Error::custom("expected boolean")),
    }
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ApiConfig {
    pub http: String,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    #[serde(default)]
    pub tag: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub args: Value,
}
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub kind: String,
    pub listen: String,
    pub entry: String,
    pub idle_timeout: u64,
    pub cert: String,
    pub key: String,
    pub entries: Vec<HttpEntry>,
    pub src_ip_header: String,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpEntry {
    pub exec: String,
    pub path: String,
}
impl Config {
    pub fn from_yaml(s: &str) -> Result<Self> {
        Ok(serde_yaml::from_str(s)?)
    }
    /// Paths retain Go's working-directory semantics (including `-d`).
    pub fn load(path: &Path) -> Result<Self> {
        Self::load_depth(path, 0)
    }
    fn load_depth(path: &Path, depth: usize) -> Result<Self> {
        if depth > 8 {
            bail!("maximum include depth reached");
        }
        let mut cfg: Self = serde_yaml::from_value(read_config_value(path)?)?;
        cfg.validate_profile()?;
        let mut plugins = Vec::new();
        for inc in &cfg.include {
            plugins.extend(Self::load_depth(Path::new(inc), depth + 1)?.plugins);
        }
        plugins.append(&mut cfg.plugins);
        cfg.plugins = plugins;
        cfg.include.clear();
        Ok(cfg)
    }
    pub fn validate_profile(&self) -> Result<()> {
        #[cfg(not(feature = "full"))]
        {
            if !self.api.http.is_empty() {
                bail!("HTTP API is unavailable in the minimal build");
            }
        }
        Ok(())
    }
}

#[cfg(feature = "full")]
fn read_config_value(path: &Path) -> Result<Value> {
    crate::tools::read_config_value(path)
}

#[cfg(not(feature = "full"))]
fn read_config_value(path: &Path) -> Result<Value> {
    use anyhow::Context;
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    let value = match path
        .extension()
        .and_then(|x| x.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("yaml" | "yml") => serde_yaml::from_str(&text)?,
        Some("json") => serde_json::from_str(&text)?,
        _ => bail!(
            "minimal config supports yaml, yml or json: {}",
            path.display()
        ),
    };
    if !matches!(value, Value::Mapping(_)) {
        bail!("config root must be a mapping");
    }
    Ok(value)
}
