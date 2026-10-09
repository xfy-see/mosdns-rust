// SPDX-License-Identifier: GPL-3.0-or-later
//! Per-engine BP services. Factory registration is committed or rolled back as a unit.
use super::LogConfig;
use crate::pkg::metrics::{MetricRegistry, Registerer};
use anyhow::{bail, Result};
#[cfg(feature = "full")]
use bytes::Bytes;
#[cfg(feature = "full")]
use futures::future::BoxFuture;
#[cfg(feature = "full")]
use hyper::{Request, Response};
use serde_json::{Map, Value};
use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

/// Receives the original method, URI, headers and bounded body; relative_path
/// starts with '/', after the /plugins/<tag> mount. The handler owns routing.
#[cfg(feature = "full")]
pub trait PluginApi: Send + Sync {
    fn handle<'a>(
        &'a self,
        request: Request<Bytes>,
        relative_path: String,
    ) -> BoxFuture<'a, Result<Response<Bytes>>>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}
impl LogLevel {
    fn name(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}
/// Named plugin logger sharing the engine's configured destination and lock.
/// Error returns an I/O error; it does not request engine shutdown.
#[derive(Clone)]
pub struct PluginLogger {
    tag: String,
    config: LogConfig,
    sink: Option<Arc<Mutex<File>>>,
}
impl PluginLogger {
    pub fn tag(&self) -> &str {
        &self.tag
    }
    pub fn log(&self, level: LogLevel, message: &str, fields: Map<String, Value>) -> Result<()> {
        if fields
            .keys()
            .any(|key| matches!(key.as_str(), "level" | "msg" | "tag"))
        {
            bail!("level, msg and tag are reserved log fields");
        }
        let threshold = match self.config.level.as_str() {
            "debug" => LogLevel::Debug,
            "" | "info" => LogLevel::Info,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            _ => return Ok(()),
        };
        if level < threshold {
            return Ok(());
        }
        let mut value = fields;
        value.insert("level".into(), level.name().into());
        value.insert("msg".into(), message.into());
        value.insert("tag".into(), self.tag.clone().into());
        let line = if self.config.production {
            Value::Object(value).to_string()
        } else {
            format!(
                "{} [{}] {message}: {}",
                level.name(),
                self.tag,
                Value::Object(value)
            )
        };
        if let Some(sink) = &self.sink {
            writeln!(sink.lock().unwrap(), "{line}")?;
        } else {
            writeln!(std::io::stderr().lock(), "{line}")?;
        }
        Ok(())
    }
    pub fn debug(&self, message: &str, fields: Map<String, Value>) -> Result<()> {
        self.log(LogLevel::Debug, message, fields)
    }
    pub fn info(&self, message: &str, fields: Map<String, Value>) -> Result<()> {
        self.log(LogLevel::Info, message, fields)
    }
    pub fn warn(&self, message: &str, fields: Map<String, Value>) -> Result<()> {
        self.log(LogLevel::Warn, message, fields)
    }
    pub fn error(&self, message: &str, fields: Map<String, Value>) -> Result<()> {
        self.log(LogLevel::Error, message, fields)
    }
}

#[cfg(feature = "full")]
struct Mounted {
    owner: u64,
    api: Arc<dyn PluginApi>,
}
struct HubState {
    #[cfg(feature = "full")]
    apis: Mutex<HashMap<String, Mounted>>,
    metrics: MetricRegistry,
    next_owner: AtomicU64,
    scopes: Mutex<HashMap<u64, (String, Arc<AtomicBool>)>>,
    log_config: LogConfig,
    log_sink: Option<Arc<Mutex<File>>>,
}
#[derive(Clone)]
pub(crate) struct ExtensionHub(Arc<HubState>);
impl ExtensionHub {
    pub fn new(log_config: LogConfig, log_sink: Option<Arc<Mutex<File>>>) -> Result<Self> {
        let metrics = MetricRegistry::new();
        metrics.reserve_names(&[
            "mosdns_cache_query_total",
            "mosdns_cache_hit_total",
            "mosdns_cache_lazy_hit_total",
            "mosdns_cache_size_current",
            "mosdns_metrics_collector_query_total",
            "mosdns_metrics_collector_err_total",
            "mosdns_metrics_collector_thread",
            "mosdns_metrics_collector_response_latency_millisecond",
            "mosdns_metrics_collector_response_latency_millisecond_bucket",
            "mosdns_metrics_collector_response_latency_millisecond_sum",
            "mosdns_metrics_collector_response_latency_millisecond_count",
            "mosdns_forward_query_total",
            "mosdns_forward_err_total",
            "mosdns_forward_thread",
            "mosdns_forward_response_latency_millisecond",
            "mosdns_forward_response_latency_millisecond_bucket",
            "mosdns_forward_response_latency_millisecond_sum",
            "mosdns_forward_response_latency_millisecond_count",
            "mosdns_forward_conn_opened_total",
            "mosdns_forward_conn_closed_total",
        ])?;
        Ok(Self(Arc::new(HubState {
            #[cfg(feature = "full")]
            apis: Mutex::new(HashMap::new()),
            metrics,
            next_owner: AtomicU64::new(1),
            scopes: Mutex::new(HashMap::new()),
            log_config,
            log_sink,
        })))
    }
    pub fn begin(&self, tag: &str) -> RegistrationScope {
        let owner = self.0.next_owner.fetch_add(1, Ordering::Relaxed);
        let active = Arc::new(AtomicBool::new(true));
        self.0
            .scopes
            .lock()
            .unwrap()
            .insert(owner, (tag.into(), active.clone()));
        RegistrationScope {
            hub: self.clone(),
            tag: tag.into(),
            owner,
            active,
            committed: false,
        }
    }
    #[cfg(feature = "full")]
    pub fn api(&self, path: &str) -> Option<(Arc<dyn PluginApi>, String)> {
        self.0
            .apis
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(tag, mounted)| {
                let mount = format!("/plugins/{tag}");
                let rest = path.strip_prefix(&mount)?;
                if !rest.is_empty() && !rest.starts_with('/') {
                    return None;
                }
                Some((
                    mount.len(),
                    mounted.api.clone(),
                    if rest.is_empty() {
                        "/".into()
                    } else {
                        rest.into()
                    },
                ))
            })
            .max_by_key(|(length, _, _)| *length)
            .map(|(_, api, path)| (api, path))
    }
    #[cfg(feature = "full")]
    pub fn metrics_text(&self) -> String {
        self.0.metrics.text()
    }
    pub fn rollback_all(&self) {
        let scopes = std::mem::take(&mut *self.0.scopes.lock().unwrap());
        for (owner, (_, active)) in scopes {
            active.store(false, Ordering::Release);
            self.0.metrics.unregister_owner(owner);
        }
        #[cfg(feature = "full")]
        self.0.apis.lock().unwrap().clear();
    }
    /// Quick setup commits independently, but a later step can invalidate the
    /// enclosing configured plugin. Keep successful dependencies with other tags.
    pub fn rollback_tag(&self, tag: &str) {
        let mut scopes = self.0.scopes.lock().unwrap();
        let owners: Vec<_> = scopes
            .iter()
            .filter_map(|(owner, (owner_tag, _))| (owner_tag == tag).then_some(*owner))
            .collect();
        let removed: Vec<_> = owners
            .into_iter()
            .map(|owner| (owner, scopes.remove(&owner).unwrap().1))
            .collect();
        drop(scopes);
        for (owner, active) in removed {
            active.store(false, Ordering::Release);
            #[cfg(feature = "full")]
            self.0
                .apis
                .lock()
                .unwrap()
                .retain(|_, mounted| mounted.owner != owner);
            self.0.metrics.unregister_owner(owner);
        }
    }
}
pub(crate) struct RegistrationScope {
    hub: ExtensionHub,
    tag: String,
    owner: u64,
    active: Arc<AtomicBool>,
    committed: bool,
}
impl RegistrationScope {
    pub fn commit(&mut self) {
        self.committed = true;
    }
    #[cfg(feature = "full")]
    pub fn register_api(&self, api: Arc<dyn PluginApi>) -> Result<()> {
        let mut apis = self.hub.0.apis.lock().unwrap();
        if !self.active.load(Ordering::Acquire) {
            bail!("API registration scope is no longer active");
        }
        if apis.contains_key(&self.tag) {
            bail!("duplicate API mount for plugin {}", self.tag);
        }
        apis.insert(
            self.tag.clone(),
            Mounted {
                owner: self.owner,
                api,
            },
        );
        Ok(())
    }
    pub fn metrics(&self) -> Registerer {
        self.hub
            .0
            .metrics
            .owned_registerer(self.owner, self.active.clone())
            .with_prefix("mosdns_")
    }
    pub fn logger(&self) -> PluginLogger {
        PluginLogger {
            tag: self.tag.clone(),
            config: self.hub.0.log_config.clone(),
            sink: self.hub.0.log_sink.clone(),
        }
    }
}
impl Drop for RegistrationScope {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        self.active.store(false, Ordering::Release);
        #[cfg(feature = "full")]
        self.hub
            .0
            .apis
            .lock()
            .unwrap()
            .retain(|_, mounted| mounted.owner != self.owner);
        self.hub.0.metrics.unregister_owner(self.owner);
        self.hub.0.scopes.lock().unwrap().remove(&self.owner);
    }
}
