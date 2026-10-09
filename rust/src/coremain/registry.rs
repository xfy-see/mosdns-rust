//! Extension registration without changing the built-in plugin representation.
//!
//! Registries are explicit and local to an Engine construction. Factories run
//! synchronously during startup; query execution and matching may be async.
use super::{engine::Engine, lifecycle::CloseEntry, Plugin};
pub use crate::plugin::matcher::providers::{
    DomainMatch, DomainMatcherProvider, DomainRules, IPMatcherProvider, IpMatch, IpRules,
};
use crate::plugin::{
    executable::Executable, matcher::Matcher, query_context::QueryContext, sequence::ChainWalker,
};
use anyhow::{bail, Result};
use futures::future::BoxFuture;
use serde_yaml::Value;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
pub(crate) type ResourceLedger = Arc<Mutex<ResourceLedgerState>>;
#[derive(Default)]
pub(crate) struct ResourceLedgerState {
    pub owners: HashMap<usize, usize>,
    // Keep rolled-back Arcs alive so a later allocation cannot reuse their identity.
    pub closed: HashMap<usize, Arc<dyn PluginCloser>>,
}

/// Go io.Closer-style cleanup, once per Arc identity within an Engine lifecycle.
/// Normal Engine shutdown runs this on a blocking worker; startup rollback runs
/// it on the synchronous constructor's caller. It must not await async services.
pub trait PluginCloser: Send + Sync {
    fn close(&self) -> Result<()>;
}

/// Explicit capabilities of one custom plugin object. Each field can refer to
/// the same Arc<T>; built-in plugins retain their existing enum representation.
#[derive(Clone, Default)]
pub struct PluginObject {
    pub executable: Option<Executable>,
    pub matcher: Option<Matcher>,
    pub data: Option<crate::plugin::query_context::SharedValue>,
    pub closer: Option<Arc<dyn PluginCloser>>,
    pub domain_provider: Option<Arc<dyn DomainMatcherProvider>>,
    pub ip_provider: Option<Arc<dyn IPMatcherProvider>>,
}

pub(crate) struct PendingService {
    pub tag: String,
    pub future: BoxFuture<'static, Result<()>>,
}
#[derive(Default)]
pub(crate) struct InitResources {
    pub closers: Vec<CloseEntry>,
    pub services: Vec<PendingService>,
}

pub trait ExecutablePlugin: Send + Sync {
    fn exec<'a>(&'a self, ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<()>>;
    /// Like Go QuickConfigurableExec: None uses the original instance.
    fn quick_configure(&self, _args: &str) -> Result<Option<Executable>> {
        Ok(None)
    }
}
pub trait RecursiveExecutablePlugin: Send + Sync {
    /// Returning without calling next stops the chain; errors propagate unchanged.
    fn exec<'a>(&'a self, ctx: &'a mut QueryContext, next: Next<'a>) -> BoxFuture<'a, Result<()>>;
    fn quick_configure(&self, _args: &str) -> Result<Option<Executable>> {
        Ok(None)
    }
}
pub trait MatcherPlugin: Send + Sync {
    fn matches<'a>(&'a self, ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<bool>>;
    /// Like Go QuickConfigurableMatch: None uses the original instance.
    fn quick_configure(&self, _args: &str) -> Result<Option<Matcher>> {
        Ok(None)
    }
}

/// The remainder of a sequence, including its jump-back continuation.
/// Cloning replays the same tail, as copying Go's ChainWalker does.
#[derive(Clone)]
pub struct Next<'a> {
    pub(crate) engine: &'a Engine,
    pub(crate) walker: ChainWalker,
}
impl<'a> Next<'a> {
    pub fn exec(self, ctx: &'a mut QueryContext) -> BoxFuture<'a, Result<()>> {
        match self.engine.walk(self.walker, ctx) {
            futures::future::Either::Left(ready) => Box::pin(ready),
            futures::future::Either::Right(boxed) => boxed,
        }
    }
    pub fn engine(&self) -> &'a Engine {
        self.engine
    }
}

/// Initialization context, corresponding to Go BP/BQ tag and plugin lookup.
/// Dependency lookup initializes a referenced definition on demand and detects cycles.
pub struct BuildContext<'a> {
    tag: &'a str,
    lookup: &'a mut dyn FnMut(&str) -> Result<Plugin>,
    resources: &'a mut InitResources,
    shutdown: tokio::sync::watch::Receiver<bool>,
    ledger: ResourceLedger,
    extensions: super::extensions::RegistrationScope,
}
impl<'a> BuildContext<'a> {
    pub(crate) fn new(
        tag: &'a str,
        lookup: &'a mut dyn FnMut(&str) -> Result<Plugin>,
        resources: &'a mut InitResources,
        shutdown: tokio::sync::watch::Receiver<bool>,
        ledger: ResourceLedger,
        extensions: super::extensions::RegistrationScope,
    ) -> Self {
        Self {
            tag,
            lookup,
            resources,
            shutdown,
            ledger,
            extensions,
        }
    }
    pub fn tag(&self) -> &str {
        self.tag
    }
    /// Mount an HTTP handler at /plugins/<tag>, committed with the factory.
    #[cfg(feature = "full")]
    pub fn register_api(&self, api: Arc<dyn super::extensions::PluginApi>) -> Result<()> {
        self.extensions.register_api(api)
    }
    /// Prometheus registerer wrapped with the Go BP mosdns_ prefix.
    pub fn metrics(&self) -> crate::pkg::metrics::Registerer {
        self.extensions.metrics()
    }
    pub fn logger(&self) -> super::extensions::PluginLogger {
        self.extensions.logger()
    }
    pub(crate) fn commit_extensions(&mut self) {
        self.extensions.commit();
    }
    pub fn get_plugin(&mut self, tag: &str) -> Result<Plugin> {
        (self.lookup)(tag)
    }
    /// Register immediately after acquiring a resource, before any fallible work.
    /// Duplicate registration of the same Arc is idempotent.
    pub fn register_closer(&mut self, closer: Arc<dyn PluginCloser>) -> Result<()> {
        let entry = CloseEntry {
            tag: self.tag.into(),
            closer,
        };
        let mut ledger = self.ledger.lock().unwrap();
        if ledger.closed.contains_key(&entry.identity()) {
            bail!(
                "plugin {} registered a resource already closed during startup rollback",
                self.tag
            );
        }
        *ledger.owners.entry(entry.identity()).or_default() += 1;
        drop(ledger);
        self.resources.closers.push(entry);
        Ok(())
    }
    pub fn shutdown_signal(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown.clone()
    }
    /// Service futures start only after the entire Engine startup succeeds.
    /// They must exit on shutdown_signal; Engine waits for them before close.
    /// A failed/panicking service requests Engine shutdown.
    pub fn attach_service<F>(&mut self, future: F) -> Result<()>
    where
        F: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        tokio::runtime::Handle::try_current()
            .map_err(|_| anyhow::anyhow!("attach_service requires a Tokio runtime"))?;
        self.resources.services.push(PendingService {
            tag: self.tag.into(),
            future: Box::pin(future),
        });
        Ok(())
    }
}

pub type PluginFactory =
    Arc<dyn for<'a> Fn(&mut BuildContext<'a>, &Value) -> Result<Plugin> + Send + Sync>;
pub type PresetFactory = Arc<dyn for<'a> Fn(&mut BuildContext<'a>) -> Result<Plugin> + Send + Sync>;
pub type ExecSetup =
    Arc<dyn for<'a> Fn(&mut BuildContext<'a>, &str) -> Result<Executable> + Send + Sync>;
pub type MatchSetup =
    Arc<dyn for<'a> Fn(&mut BuildContext<'a>, &str) -> Result<Matcher> + Send + Sync>;

// Kept separate: Go configurable plugin types and sequence quick syntax are different registries.
#[cfg(feature = "full")]
const BUILTIN_TYPES: &[&str] = &[
    "domain_set",
    "ip_set",
    "sequence",
    "forward",
    "cache",
    "fallback",
    "hosts",
    "redirect",
    "arbitrary",
    "sleep",
    "ecs_handler",
    "reverse_lookup",
    "rate_limiter",
    "qname",
    "cname",
    "client_ip",
    "resp_ip",
    "ptr_ip",
    "qtype",
    "qclass",
    "rcode",
    "udp_server",
    "tcp_server",
    "quic_server",
    "http_server",
];
#[cfg(feature = "full")]
const BUILTIN_EXECS: &[&str] = &[
    "accept",
    "reject",
    "return",
    "jump",
    "goto",
    "forward",
    "cache",
    "ttl",
    "black_hole",
    "drop_resp",
    "sleep",
    "mark",
    "ecs",
    "forward_edns0opt",
    "prefer_ipv4",
    "prefer_ipv6",
    "metrics_collector",
    "nftset",
    "ipset",
    "query_summary",
    "debug_print",
];
#[cfg(feature = "full")]
const BUILTIN_MATCHERS: &[&str] = &[
    "_true",
    "_false",
    "qname",
    "cname",
    "client_ip",
    "resp_ip",
    "ptr_ip",
    "qtype",
    "qclass",
    "rcode",
    "has_resp",
    "has_wanted_ans",
    "mark",
    "random",
    "env",
    "string_exp",
];

#[cfg(not(feature = "full"))]
const BUILTIN_TYPES: &[&str] = &[
    "domain_set",
    "cache",
    "forward",
    "sequence",
    "udp_server",
    "tcp_server",
];
#[cfg(not(feature = "full"))]
const BUILTIN_EXECS: &[&str] = &[
    "accept", "reject", "return", "jump", "goto", "forward", "cache", "nftset",
];
#[cfg(not(feature = "full"))]
const BUILTIN_MATCHERS: &[&str] = &["_true", "_false", "qname", "has_resp"];

#[derive(Clone, Default)]
pub struct Registry {
    types: HashMap<String, PluginFactory>,
    presets: HashMap<String, PresetFactory>,
    execs: HashMap<String, ExecSetup>,
    matchers: HashMap<String, MatchSetup>,
}
impl Registry {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn register_plugin_type<F>(&mut self, name: &str, factory: F) -> Result<()>
    where
        F: for<'a> Fn(&mut BuildContext<'a>, &Value) -> Result<Plugin> + Send + Sync + 'static,
    {
        check_name(name)?;
        if BUILTIN_TYPES.contains(&name) || self.types.contains_key(name) {
            bail!("duplicate plugin type {name}");
        }
        self.types.insert(name.into(), Arc::new(factory));
        Ok(())
    }
    pub fn register_preset<F>(&mut self, tag: &str, factory: F) -> Result<()>
    where
        F: for<'a> Fn(&mut BuildContext<'a>) -> Result<Plugin> + Send + Sync + 'static,
    {
        check_name(tag)?;
        if (cfg!(feature = "full") && tag == "_sleep_500ms") || self.presets.contains_key(tag) {
            bail!("duplicate preset tag {tag}");
        }
        self.presets.insert(tag.into(), Arc::new(factory));
        Ok(())
    }
    pub fn register_exec<F>(&mut self, name: &str, setup: F) -> Result<()>
    where
        F: for<'a> Fn(&mut BuildContext<'a>, &str) -> Result<Executable> + Send + Sync + 'static,
    {
        check_name(name)?;
        if BUILTIN_EXECS.contains(&name) || self.execs.contains_key(name) {
            bail!("duplicate executable quick setup {name}");
        }
        self.execs.insert(name.into(), Arc::new(setup));
        Ok(())
    }
    pub fn register_matcher<F>(&mut self, name: &str, setup: F) -> Result<()>
    where
        F: for<'a> Fn(&mut BuildContext<'a>, &str) -> Result<Matcher> + Send + Sync + 'static,
    {
        check_name(name)?;
        if BUILTIN_MATCHERS.contains(&name) || self.matchers.contains_key(name) {
            bail!("duplicate matcher quick setup {name}");
        }
        self.matchers.insert(name.into(), Arc::new(setup));
        Ok(())
    }
    /// Only extension registrations can be removed; built-ins remain static.
    pub fn remove_plugin_type(&mut self, name: &str) -> bool {
        self.types.remove(name).is_some()
    }
    pub fn remove_preset(&mut self, tag: &str) -> bool {
        self.presets.remove(tag).is_some()
    }
    pub fn remove_exec(&mut self, name: &str) -> bool {
        self.execs.remove(name).is_some()
    }
    pub fn remove_matcher(&mut self, name: &str) -> bool {
        self.matchers.remove(name).is_some()
    }
    pub fn plugin_types(&self) -> Vec<String> {
        names(BUILTIN_TYPES, self.types.keys())
    }
    pub fn exec_types(&self) -> Vec<String> {
        names(BUILTIN_EXECS, self.execs.keys())
    }
    pub fn matcher_types(&self) -> Vec<String> {
        names(BUILTIN_MATCHERS, self.matchers.keys())
    }
    pub fn preset_tags(&self) -> Vec<String> {
        #[cfg(feature = "full")]
        let builtins = &["_sleep_500ms"][..];
        #[cfg(not(feature = "full"))]
        let builtins = &[];
        names(builtins, self.presets.keys())
    }
    pub fn get_plugin_type(&self, name: &str) -> Option<PluginFactory> {
        self.types.get(name).cloned()
    }
    pub fn get_preset(&self, tag: &str) -> Option<PresetFactory> {
        self.presets.get(tag).cloned()
    }
    pub fn get_exec(&self, name: &str) -> Option<ExecSetup> {
        self.execs.get(name).cloned()
    }
    pub fn get_matcher(&self, name: &str) -> Option<MatchSetup> {
        self.matchers.get(name).cloned()
    }
}
fn check_name(name: &str) -> Result<()> {
    if name.is_empty() {
        bail!("registration name cannot be empty");
    }
    Ok(())
}
fn names<'a>(builtins: &[&str], added: impl Iterator<Item = &'a String>) -> Vec<String> {
    let mut result = builtins
        .iter()
        .map(|s| (*s).to_owned())
        .chain(added.cloned())
        .collect::<Vec<_>>();
    result.sort();
    result
}
