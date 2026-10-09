#[cfg(feature = "full")]
use super::HttpEntry;
use super::{Config, PluginConfig, ServerConfig};
#[cfg(feature = "full")]
use crate::{
    pkg::matcher::netlist::NetList,
    plugin::{
        executable::{
            cache::{map_ttl, CacheStats},
            forward::ForwardMetrics,
            stateful::{
                empty_reply, forward_client_edns, forward_response_edns, EcsHandler, Metrics,
                ReverseLookup, Selector,
            },
            Fallback, HostEntry, RedirectRule,
        },
        matcher::{rate_limiter::RateLimiter, StringOperator, StringSource},
    },
};
use crate::{
    pkg::{matcher::domain::DomainMatcher, upstream::Upstream},
    plugin::{
        executable::{cache::Cache, Executable, Forward},
        matcher::{DomainGroup, IpGroup, Matcher},
        query_context::{reply, QueryContext},
        sequence::{parse_quick, ChainWalker, Rule, RuleArgs},
    },
};
use anyhow::{anyhow, bail, Context, Result};
use futures::{
    future::{Either, Ready},
    FutureExt,
};
use hickory_proto::op::{Message, ResponseCode};
#[cfg(feature = "full")]
use hickory_proto::rr::{
    rdata::{A, AAAA, CNAME, SOA},
    DNSClass, Name, RData, Record, RecordType,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_yaml::Value;
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::IpAddr,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(feature = "full")]
use std::{io::Write, time::Instant};

/// Configured plugin capabilities. Data holds a custom provider shared by dependants.
#[derive(Clone)]
pub enum Plugin {
    Exec(Executable),
    Match(Matcher),
    Domains(DomainGroup),
    Ips(IpGroup),
    Server,
    Data(Arc<dyn std::any::Any + Send + Sync>),
    Custom(Arc<super::registry::PluginObject>),
    DynamicDomains(super::registry::DomainRules),
    DynamicIps(super::registry::IpRules),
}
impl Plugin {
    /// Acquire provider handles once during rule construction, matching Go's getter contract.
    pub fn domain_rules(&self) -> Result<Option<super::registry::DomainRules>> {
        Ok(match self {
            Self::Domains(group) => Some(super::registry::DomainRules::Builtin(group.clone())),
            Self::DynamicDomains(rules) => Some(rules.clone()),
            Self::Custom(object) => match &object.domain_provider {
                Some(provider) => Some(super::registry::DomainRules::Dynamic(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        provider.clone().get_domain_matcher()
                    }))
                    .map_err(|panic| {
                        anyhow!(
                            "domain provider getter panicked: {}",
                            super::lifecycle::panic_message(panic)
                        )
                    })?,
                )),
                None => None,
            },
            _ => None,
        })
    }
    pub fn ip_rules(&self) -> Result<Option<super::registry::IpRules>> {
        Ok(match self {
            Self::Ips(group) => Some(super::registry::IpRules::Builtin(group.clone())),
            Self::DynamicIps(rules) => Some(rules.clone()),
            Self::Custom(object) => match &object.ip_provider {
                Some(provider) => Some(super::registry::IpRules::Dynamic(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        provider.clone().get_ip_matcher()
                    }))
                    .map_err(|panic| {
                        anyhow!(
                            "IP provider getter panicked: {}",
                            super::lifecycle::panic_message(panic)
                        )
                    })?,
                )),
                None => None,
            },
            _ => None,
        })
    }
    pub fn executable(&self) -> Option<Executable> {
        match self {
            Self::Exec(exec) => Some(exec.clone()),
            Self::Custom(object) => object.executable.clone(),
            _ => None,
        }
    }
    pub fn matcher(&self) -> Option<Matcher> {
        match self {
            Self::Match(matcher) => Some(matcher.clone()),
            Self::Custom(object) => object.matcher.clone(),
            _ => None,
        }
    }
    pub fn data(&self) -> Option<crate::plugin::query_context::SharedValue> {
        match self {
            Self::Data(data) => Some(data.clone()),
            Self::Custom(object) => object.data.clone(),
            _ => None,
        }
    }
}
struct State {
    plugins: HashMap<String, Plugin>,
    servers: Vec<ServerConfig>,
    pub config: Config,
    #[cfg(feature = "full")]
    metrics: Vec<Arc<Metrics>>,
    #[cfg(feature = "full")]
    forward_metrics: Arc<ForwardMetrics>,
    upstreams: Vec<Arc<Upstream>>,
    #[cfg(feature = "full")]
    log: Option<Arc<Mutex<fs::File>>>,
    #[cfg(feature = "full")]
    extensions: super::extensions::ExtensionHub,
    #[cfg(feature = "full")]
    cache_dumps: Vec<(Arc<Cache>, String)>,
    caches: Vec<Arc<Cache>>,
    #[cfg(feature = "full")]
    selectors: Vec<Arc<Selector>>,
    #[cfg(feature = "full")]
    reverse_lookups: Vec<Arc<ReverseLookup>>,
    lifecycle: Arc<super::lifecycle::Lifecycle>,
    closers: Vec<super::lifecycle::CloseEntry>,
}
#[derive(Clone)]
pub struct Engine {
    state: Arc<State>,
}
pub(crate) type WalkFuture<'a> =
    Either<Ready<Result<()>>, futures::future::BoxFuture<'a, Result<()>>>;
impl Engine {
    pub fn new(config: Config) -> Result<Self> {
        Self::new_with_registry(config, super::registry::Registry::new())
    }
    pub fn new_with_registry(
        mut config: Config,
        registry: super::registry::Registry,
    ) -> Result<Self> {
        config.validate_profile()?;
        #[cfg(not(feature = "full"))]
        for plugin in &config.plugins {
            if !registry.plugin_types().contains(&plugin.kind) {
                bail!(
                    "plugin type {} is unavailable in the minimal build",
                    plugin.kind
                );
            }
        }
        if !config.include.is_empty() {
            bail!("use Config::load to resolve included configs");
        }
        let mut defs = HashMap::new();
        for (i, p) in config.plugins.iter_mut().enumerate() {
            if p.tag.is_empty() {
                p.tag = format!("__anonymous_{i}");
            }
            if registry.preset_tags().contains(&p.tag) {
                bail!("duplicated plugin tag {} (preset)", p.tag);
            }
            if defs.insert(p.tag.clone(), p.clone()).is_some() {
                bail!("duplicated plugin tag {}", p.tag);
            }
        }
        if !matches!(
            config.log.level.as_str(),
            "" | "debug" | "info" | "warn" | "error" | "dpanic" | "panic" | "fatal"
        ) {
            bail!("invalid log level {}", config.log.level);
        }
        let log = if config.log.file.is_empty() {
            None
        } else {
            Some(Arc::new(Mutex::new(
                fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&config.log.file)?,
            )))
        };
        let mut b = Builder {
            extensions: super::extensions::ExtensionHub::new(config.log.clone(), log.clone())?,
            lifecycle: super::lifecycle::Lifecycle::new(),
            closers: Vec::new(),
            services: Vec::new(),
            resource_ledger: Arc::new(Mutex::new(super::registry::ResourceLedgerState::default())),
            committed_closers: HashMap::new(),
            registry,
            defs,
            plugins: HashMap::new(),
            building: HashSet::new(),
            servers: Vec::new(),
            #[cfg(feature = "full")]
            metrics: Vec::new(),
            #[cfg(feature = "full")]
            forward_metrics: ForwardMetrics::new(),
            upstreams: Vec::new(),
            #[cfg(feature = "full")]
            metric_names: HashSet::new(),
            #[cfg(feature = "full")]
            metric_owners: HashMap::new(),
            #[cfg(feature = "full")]
            cache_dumps: Vec::new(),
            caches: Vec::new(),
            #[cfg(feature = "full")]
            selectors: Vec::new(),
            #[cfg(feature = "full")]
            reverse_lookups: Vec::new(),
        };
        #[cfg(feature = "full")]
        b.plugins.insert(
            "_sleep_500ms".into(),
            Plugin::Exec(Executable::Sleep(Duration::from_millis(500))),
        );
        let initialized = (|| -> Result<()> {
            for tag in b.registry.preset_tags() {
                b.build(&tag)
                    .with_context(|| format!("initialize preset plugin {tag}"))?;
            }
            for p in &config.plugins {
                b.build(&p.tag)
                    .with_context(|| format!("initialize plugin {} ({})", p.tag, p.kind))?;
            }
            Ok(())
        })();
        if let Err(error) = initialized {
            for cache in &b.caches {
                cache.close();
            }
            #[cfg(feature = "full")]
            for selector in &b.selectors {
                selector.close();
            }
            #[cfg(feature = "full")]
            for reverse in &b.reverse_lookups {
                reverse.close();
            }
            b.extensions.rollback_all();
            b.services.clear();
            b.lifecycle.request(Some(format!("{error:#}")));
            let errors = super::lifecycle::close_entries(&b.closers, &HashSet::new());
            return Err(if errors.is_empty() {
                error
            } else {
                anyhow!("{error:#}; {}", errors.join("; "))
            });
        }
        let services = std::mem::take(&mut b.services);
        let engine = Self {
            state: Arc::new(State {
                plugins: b.plugins,
                servers: b.servers,
                config,
                #[cfg(feature = "full")]
                metrics: b.metrics,
                #[cfg(feature = "full")]
                forward_metrics: b.forward_metrics,
                upstreams: b.upstreams,
                #[cfg(feature = "full")]
                log,
                #[cfg(feature = "full")]
                extensions: b.extensions,
                #[cfg(feature = "full")]
                cache_dumps: b.cache_dumps,
                caches: b.caches,
                #[cfg(feature = "full")]
                selectors: b.selectors,
                #[cfg(feature = "full")]
                reverse_lookups: b.reverse_lookups,
                lifecycle: b.lifecycle,
                closers: b.closers,
            }),
        };
        for service in services {
            let lifecycle = engine.state.lifecycle.clone();
            let guard = lifecycle.fork();
            tokio::spawn(async move {
                let _guard = guard;
                let outcome = std::panic::AssertUnwindSafe(service.future)
                    .catch_unwind()
                    .await;
                match outcome {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        lifecycle
                            .service_failed(format!("plugin service {}: {error:#}", service.tag));
                    }
                    Err(panic) => {
                        lifecycle.service_failed(format!(
                            "plugin service {} panicked: {}",
                            service.tag,
                            super::lifecycle::panic_message(panic)
                        ));
                    }
                }
            });
        }
        Ok(engine)
    }
    /// Decode minimal plugin arguments without initializing any plugin resources.
    #[cfg(not(feature = "full"))]
    pub fn check_config(config: &Config) -> Result<()> {
        config.validate_profile()?;
        let types = super::Registry::new().plugin_types();
        for plugin in &config.plugins {
            if !types.contains(&plugin.kind) {
                bail!(
                    "plugin type {} is unavailable in the minimal build",
                    plugin.kind
                );
            }
            match plugin.kind.as_str() {
                "domain_set" => {
                    decode::<SetArgs>(&plugin.args)?;
                }
                "cache" => {
                    let args = decode::<CacheArgs>(&plugin.args)?;
                    if !args.dump_file.is_empty() || args.dump_interval != 0 {
                        bail!("minimal cache does not support dump_file or dump_interval");
                    }
                }
                "forward" => {
                    let args = decode::<ForwardArgs>(&plugin.args)?;
                    for upstream in &args.upstreams {
                        Upstream::validate_options(
                            &upstream.addr,
                            &crate::pkg::upstream::Options {
                                dial_addr: upstream.dial_addr.clone(),
                                socks5: if upstream.socks5.is_empty() {
                                    args.socks5.clone()
                                } else {
                                    upstream.socks5.clone()
                                },
                                bootstrap: if upstream.bootstrap.is_empty() {
                                    args.bootstrap.clone()
                                } else {
                                    upstream.bootstrap.clone()
                                },
                                bootstrap_version: if upstream.bootstrap_version <= 0 {
                                    args.bootstrap_version
                                } else {
                                    upstream.bootstrap_version
                                },
                                enable_http3: upstream.enable_http3,
                                insecure_skip_verify: upstream.insecure_skip_verify,
                                ..Default::default()
                            },
                        )?;
                    }
                }
                "sequence" => {
                    decode::<Vec<RuleArgs>>(&plugin.args)?;
                }
                "udp_server" | "tcp_server" => {
                    let args = decode::<ServerArgs>(&plugin.args)?;
                    if !args.cert.is_empty() || !args.key.is_empty() {
                        bail!("tcp_server cert/key require the full build");
                    }
                }
                _ => unreachable!("profile validated"),
            }
        }
        Ok(())
    }
    pub fn servers(&self) -> &[ServerConfig] {
        &self.state.servers
    }
    pub fn config(&self) -> &Config {
        &self.state.config
    }
    pub fn get_plugin(&self, tag: &str) -> Option<Plugin> {
        self.state.plugins.get(tag).cloned()
    }
    /// Shared by all Engine clones. First error wins, like Go SafeClose.
    pub fn request_shutdown(&self, error: Option<String>) -> bool {
        self.state.lifecycle.request(error)
    }
    pub fn shutdown_signal(&self) -> tokio::sync::watch::Receiver<bool> {
        self.state.lifecycle.signal()
    }
    /// Stops new queries, drains existing queries/background services, saves
    /// configured cache dumps, then closes registered resources exactly once.
    pub async fn shutdown(&self) -> Result<()> {
        self.request_shutdown(None);
        self.wait_closed().await
    }
    /// Wait for a close request. Cancelling this future does not cancel an
    /// already started shutdown coordinator; all clones observe the same result.
    pub async fn wait_closed(&self) -> Result<()> {
        let mut signal = self.shutdown_signal();
        if !*signal.borrow() {
            signal.changed().await?;
        }
        let runtime = tokio::runtime::Handle::try_current()
            .context("Engine shutdown requires a Tokio runtime")?;
        if self.state.lifecycle.start_coordinator() {
            let engine = self.clone();
            runtime.spawn(async move {
                engine.state.lifecycle.drain().await;
                let mut closed_caches = HashSet::new();
                for cache in &engine.state.caches {
                    if closed_caches.insert(Arc::as_ptr(cache) as usize) {
                        cache.close_and_wait().await;
                    }
                }
                #[cfg(feature = "full")]
                let mut closed_selectors = HashSet::new();
                #[cfg(feature = "full")]
                for selector in &engine.state.selectors {
                    if closed_selectors.insert(Arc::as_ptr(selector) as usize) {
                        selector.close_and_wait().await;
                    }
                }
                #[cfg(feature = "full")]
                let mut closed_reverses = HashSet::new();
                #[cfg(feature = "full")]
                for reverse in &engine.state.reverse_lookups {
                    if closed_reverses.insert(Arc::as_ptr(reverse) as usize) {
                        reverse.close_and_wait().await;
                    }
                }
                let mut upstream_errors = Vec::new();
                let mut closed_upstreams = HashSet::new();
                for (index, upstream) in engine.state.upstreams.iter().enumerate() {
                    if closed_upstreams.insert(Arc::as_ptr(upstream) as usize) {
                        if let Err(error) = upstream.close().await {
                            upstream_errors.push(format!("close upstream {index}: {error:#}"));
                        }
                    }
                }
                let closing = engine.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let mut errors = upstream_errors;
                    #[cfg(feature = "full")]
                    if let Err(error) = closing.save_cache_dumps() {
                        errors.push(format!("{error:#}"));
                    }
                    errors.extend(super::lifecycle::close_entries(
                        &closing.state.closers,
                        &HashSet::new(),
                    ));
                    errors
                })
                .await;
                let errors = match result {
                    Ok(errors) => errors,
                    Err(error) => vec![format!("shutdown worker failed: {error}")],
                };
                engine.state.lifecycle.finish(errors);
            });
        }
        self.state.lifecycle.wait_finished().await
    }
    pub fn cache_tags(&self) -> Vec<String> {
        self.state
            .plugins
            .iter()
            .filter_map(|(k, p)| {
                if matches!(p, Plugin::Exec(Executable::Cache(_))) {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect()
    }
    #[cfg(feature = "full")]
    pub fn cache_stats(&self, tag: &str) -> Option<CacheStats> {
        match self.state.plugins.get(tag) {
            Some(Plugin::Exec(Executable::Cache(c))) => Some(c.stats()),
            _ => None,
        }
    }
    pub fn flush_cache(&self, tag: &str) -> bool {
        if let Some(Plugin::Exec(Executable::Cache(c))) = self.state.plugins.get(tag) {
            c.flush();
            true
        } else {
            false
        }
    }
    pub fn metrics_text(&self) -> String {
        #[cfg(feature = "full")]
        {
            let mut text = Metrics::render(self.state.metrics.iter().map(Arc::as_ref));
            text.push_str(&self.state.forward_metrics.text());
            text.push_str(&self.state.extensions.metrics_text());
            text
        }
        #[cfg(not(feature = "full"))]
        String::new()
    }
    #[cfg(feature = "full")]
    pub(crate) fn plugin_api(
        &self,
        path: &str,
    ) -> Option<(Arc<dyn super::extensions::PluginApi>, String)> {
        self.state.extensions.api(path)
    }
    #[cfg(feature = "full")]
    pub(crate) fn api_work(&self) -> Result<super::lifecycle::WorkGuard> {
        self.state.lifecycle.enter()
    }
    #[cfg(feature = "full")]
    pub fn reverse_lookup(&self, tag: &str, ip: IpAddr) -> Option<String> {
        match self.state.plugins.get(tag) {
            Some(Plugin::Exec(Executable::ReverseLookup(r))) => r.lookup(ip).map(|n| n.to_ascii()),
            _ => None,
        }
    }
    #[cfg(feature = "full")]
    pub fn cache_dump(&self, tag: &str) -> Result<Vec<u8>> {
        match self.state.plugins.get(tag) {
            Some(Plugin::Exec(Executable::Cache(c))) => c.dump_bytes(),
            _ => bail!("unknown cache {tag}"),
        }
    }
    #[cfg(feature = "full")]
    pub fn load_cache_dump(&self, tag: &str, data: &[u8]) -> Result<usize> {
        match self.state.plugins.get(tag) {
            Some(Plugin::Exec(Executable::Cache(c))) => c.load_dump_bytes(data),
            _ => bail!("unknown cache {tag}"),
        }
    }
    #[cfg(feature = "full")]
    pub fn save_cache_dumps(&self) -> Result<()> {
        let mut errors = Vec::new();
        for (cache, path) in &self.state.cache_dumps {
            if let Err(error) = cache.save_dump(Path::new(path)) {
                errors.push(format!("save cache dump {path}: {error:#}"));
            }
        }
        if !errors.is_empty() {
            bail!(errors.join("; "));
        }
        Ok(())
    }
    #[cfg(feature = "full")]
    fn log(&self, title: &str, ctx: &QueryContext, error: Option<String>) {
        if !matches!(self.state.config.log.level.as_str(), "" | "debug" | "info") {
            return;
        }
        let value = serde_json::json!({"level":"info","msg":title,"uqid":ctx.id,"qname":ctx.query.queries()[0].name().to_ascii(),"qtype":u16::from(ctx.query.queries()[0].query_type()),"qclass":u16::from(ctx.query.queries()[0].query_class()),"client":if ctx.client_valid {ctx.client.to_string()} else {String::new()},"rcode":ctx.response.as_ref().map(|r|u16::from(r.response_code())),"elapsed_ms":ctx.started.elapsed().as_secs_f64()*1000.0,"error":error});
        let line = if self.state.config.log.production {
            value.to_string()
        } else {
            format!("{title}: {value}")
        };
        if let Some(file) = &self.state.log {
            let _ = writeln!(file.lock().unwrap(), "{line}");
        } else {
            eprintln!("{line}");
        }
    }
    pub async fn handle(&self, query: Message, client: IpAddr, entry: &str) -> Result<Message> {
        self.handle_with_meta(query, client, entry, None, None)
            .await
    }
    pub async fn handle_with_meta(
        &self,
        query: Message,
        client: IpAddr,
        entry: &str,
        url_path: Option<&str>,
        server_name: Option<&str>,
    ) -> Result<Message> {
        self.handle_with_client_meta(query, Some(client), entry, url_path, server_name)
            .await
    }
    pub async fn handle_with_client_meta(
        &self,
        query: Message,
        client: Option<IpAddr>,
        entry: &str,
        url_path: Option<&str>,
        server_name: Option<&str>,
    ) -> Result<Message> {
        let _work = self.state.lifecycle.enter()?;
        if query.queries().len() != 1 {
            bail!("query must have exactly one question");
        }
        let ex = self
            .state
            .plugins
            .get(entry)
            .and_then(Plugin::executable)
            .ok_or_else(|| anyhow!("entry {entry} is not executable"))?;
        let mut ctx = QueryContext::new(
            query,
            client.unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
        );
        ctx.client_valid = client.is_some();
        ctx.server_name = server_name.unwrap_or_default().into();
        ctx.url_path = url_path.unwrap_or_default().into();
        self.standalone(ex, &mut ctx).await?;
        if ctx.response.is_none() {
            ctx.set_response(Some(reply(&ctx.query, ResponseCode::Refused)));
        }
        Ok(ctx.finish().unwrap())
    }
    fn standalone<'a>(&'a self, ex: Executable, ctx: &'a mut QueryContext) -> WalkFuture<'a> {
        if let Executable::Sequence(chain) = ex {
            // The old singleton wrapper entered the configured sequence at
            // depth one. Keep that boundary without allocating its Vec/Arc or
            // a second walker future for every listener query.
            let mut walker = ChainWalker::new(chain);
            walker.depth = 1;
            return self.walk(walker, ctx);
        }
        self.walk(
            ChainWalker::new(Arc::new(vec![Rule {
                matches: Vec::new(),
                exec: ex,
            }])),
            ctx,
        )
    }
    pub(crate) fn walk<'a>(
        &'a self,
        mut w: ChainWalker,
        ctx: &'a mut QueryContext,
    ) -> WalkFuture<'a> {
        // Pure terminal rules need no continuation state. Do not speculate on
        // custom matchers, random/rate-limit checks, logging or any other rule:
        // they still execute once, in order, through the normal walker.
        if w.depth <= 128
            && w.chain.get(w.pos).is_some_and(|rule| {
                matches!(rule.exec, Executable::Accept)
                    && rule.matches.iter().all(|matcher| match matcher {
                        Matcher::Constant(value) => *value,
                        Matcher::HasResp => ctx.response.is_some(),
                        _ => false,
                    })
            })
        {
            return Either::Left(futures::future::ready(Ok(())));
        }
        Either::Right(Box::pin(async move {
            if w.depth > 128 {
                bail!("maximum sequence depth reached");
            }
            while w.pos < w.chain.len() {
                let rule = &w.chain[w.pos];
                let mut matched = true;
                for matcher in &rule.matches {
                    if !matcher.matches(ctx).await? {
                        matched = false;
                        break;
                    }
                }
                if !matched {
                    w.pos += 1;
                    continue;
                }
                // The chain is immutable for the lifetime of this walk. Borrow
                // its executable instead of cloning vectors and Arc handles
                // on every query; only a newly owned walker needs a clone.
                match &rule.exec {
                    Executable::Custom(plugin) => plugin.exec(ctx).await?,
                    Executable::RecursiveCustom(plugin) => {
                        return plugin
                            .exec(
                                ctx,
                                super::registry::Next {
                                    engine: self,
                                    walker: w.next(),
                                },
                            )
                            .await;
                    }
                    Executable::Accept => return Ok(()),
                    Executable::Reject(code) => {
                        ctx.set_response(Some(reply(&ctx.query, (*code).into())));
                        return Ok(());
                    }
                    Executable::Return => {
                        return if let Some(back) = w.jump_back {
                            self.walk(*back, ctx).await
                        } else {
                            Ok(())
                        }
                    }
                    Executable::Jump(chain) => {
                        let mut child = ChainWalker::new(chain.clone());
                        child.depth = w.depth + 1;
                        child.jump_back = Some(Box::new(w.next()));
                        return self.walk(child, ctx).await;
                    }
                    Executable::Goto(chain) => {
                        let mut child = ChainWalker::new(chain.clone());
                        child.depth = w.depth + 1;
                        return self.walk(child, ctx).await;
                    }
                    Executable::Sequence(chain) => {
                        let mut child = ChainWalker::new(chain.clone());
                        child.depth = w.depth + 1;
                        self.walk(child, ctx).await?;
                    }
                    Executable::Cache(cache) => {
                        let next = w.next();
                        let Some(key) = Cache::key(ctx) else {
                            return self.walk(next, ctx).await;
                        };
                        let (cached, lazy) = cache.lookup(&key);
                        if lazy && cache.refreshing.lock().unwrap().insert(key.clone()) {
                            let e = self.clone();
                            let c = cache.clone();
                            let k = key.clone();
                            let mut context = ctx.clone();
                            let tail = next.clone();
                            let work = self.state.lifecycle.fork();
                            tokio::spawn(async move {
                                let _work = work;
                                let _ = tokio::time::timeout(
                                    Duration::from_secs(5),
                                    e.walk(tail, &mut context),
                                )
                                .await;
                                if let Some(r) = context.response {
                                    c.store(k.clone(), &r);
                                }
                                c.refreshing.lock().unwrap().remove(&k);
                            });
                        }
                        let had_cached = cached.is_some();
                        if let Some(mut r) = cached {
                            r.set_id(ctx.query.id());
                            ctx.set_response(Some(r));
                        }
                        let generation = ctx.response_generation;
                        let result = self.walk(next, ctx).await;
                        if !had_cached || ctx.response_generation != generation {
                            if let Some(r) = &ctx.response {
                                cache.store(key, r);
                            }
                        }
                        return result;
                    }
                    Executable::Forward(forward) => ctx.set_response(Some(
                        exchange(forward, &ctx.query, &self.state.lifecycle).await?,
                    )),
                    #[cfg(feature = "full")]
                    Executable::Fallback(fallback) => {
                        let mut primary_ctx = ctx.clone();
                        let secondary_ctx = ctx.clone();
                        let e = self.clone();
                        let primary = fallback.primary.clone();
                        let work = self.state.lifecycle.fork();
                        let mut p = tokio::spawn(async move {
                            let _work = work;
                            tokio::time::timeout(
                                Duration::from_secs(5),
                                e.standalone(primary, &mut primary_ctx),
                            )
                            .await??;
                            primary_ctx
                                .response
                                .ok_or_else(|| anyhow!("primary returned no response"))
                        });
                        let mut secondary = None;
                        if fallback.always_standby {
                            secondary = Some(spawn_secondary(
                                self.clone(),
                                fallback.secondary.clone(),
                                secondary_ctx.clone(),
                            ));
                        }
                        let wait = tokio::time::sleep(fallback.threshold);
                        tokio::pin!(wait);
                        let primary_failed = tokio::select! {
                            r=&mut p=>match r{Ok(Ok(response))=>{ctx.set_response(Some(response));w.pos+=1;continue;},_=>true},
                            _=&mut wait=>false,
                        };
                        let mut s = secondary.unwrap_or_else(|| {
                            spawn_secondary(self.clone(), fallback.secondary.clone(), secondary_ctx)
                        });
                        if primary_failed {
                            ctx.set_response(Some(s.await??));
                        } else {
                            tokio::select! {
                                r=&mut p=>match r{Ok(Ok(response))=>ctx.set_response(Some(response)),_=>ctx.set_response(Some(s.await??))},
                                r=&mut s=>match r{Ok(Ok(response))=>ctx.set_response(Some(response)),_=>ctx.set_response(Some(p.await??))},
                            }
                        }
                    }
                    #[cfg(feature = "full")]
                    Executable::Ttl { fix, min, max } => {
                        let (fix, min, max) = (*fix, *min, *max);
                        if let Some(r) = &mut ctx.response {
                            map_ttl(r, |ttl| {
                                if fix > 0 {
                                    fix
                                } else {
                                    let ttl = if min > 0 { ttl.max(min) } else { ttl };
                                    if max > 0 {
                                        ttl.min(max)
                                    } else {
                                        ttl
                                    }
                                }
                            });
                        }
                    }
                    #[cfg(feature = "full")]
                    Executable::BlackHole(ips) => {
                        if let Some(r) = ip_response(&ctx.query, ips, 300, false) {
                            ctx.set_response(Some(r));
                        }
                    }
                    #[cfg(feature = "full")]
                    Executable::Hosts(hosts) => {
                        if ctx.query.queries()[0].query_class() == DNSClass::IN {
                            let name = ctx.query.queries()[0].name().to_ascii();
                            if let Some(entry) = hosts
                                .iter()
                                .filter(|entry| entry.domain.matches(&name))
                                .max_by_key(|entry| entry.priority)
                            {
                                if let Some(r) = ip_response(&ctx.query, &entry.ips, 10, true) {
                                    ctx.set_response(Some(r));
                                }
                            }
                        }
                    }
                    #[cfg(feature = "full")]
                    Executable::Arbitrary(records) => {
                        let question = &ctx.query.queries()[0];
                        let answer = records
                            .iter()
                            .filter(|r| {
                                r.name() == question.name()
                                    && r.dns_class() == question.query_class()
                                    && r.record_type() == question.query_type()
                            })
                            .cloned()
                            .collect::<Vec<_>>();
                        if !answer.is_empty() {
                            let mut r = reply(&ctx.query, ResponseCode::NoError);
                            r.add_answers(answer);
                            ctx.set_response(Some(r));
                        }
                    }
                    #[cfg(feature = "full")]
                    Executable::Redirect(rules) => {
                        let original = ctx.query.queries()[0].name().clone();
                        if ctx.query.queries()[0].query_class() == DNSClass::IN {
                            if let Some(rule) = rules
                                .iter()
                                .filter(|r| r.domain.matches(&original.to_ascii()))
                                .max_by_key(|r| r.priority)
                            {
                                let target = rule.target.clone();
                                ctx.query.queries_mut()[0].set_name(target.clone());
                                let result = self.walk(w.next(), ctx).await;
                                ctx.query.queries_mut()[0].set_name(original.clone());
                                if let Some(response) = &mut ctx.response {
                                    for q in response.queries_mut() {
                                        if q.name() == &target {
                                            q.set_name(original.clone());
                                        }
                                    }
                                    response.answers_mut().insert(
                                        0,
                                        Record::from_rdata(
                                            original,
                                            1,
                                            RData::CNAME(CNAME(target)),
                                        ),
                                    );
                                }
                                return result;
                            }
                        }
                    }
                    #[cfg(feature = "full")]
                    Executable::DropResponse => ctx.set_response(None),
                    Executable::KernelSets(sets) => {
                        if let Some(response) = &ctx.response {
                            sets.apply(response).await?;
                        }
                    }
                    #[cfg(feature = "full")]
                    Executable::Sleep(d) => tokio::time::sleep(*d).await,
                    #[cfg(feature = "full")]
                    Executable::Mark(marks) => ctx.marks.extend(marks),
                    #[cfg(feature = "full")]
                    Executable::Ecs(handler) => {
                        let forwarded = handler.add(ctx);
                        let result = self.walk(w.next(), ctx).await;
                        if result.is_ok() && forwarded {
                            forward_response_edns(ctx, &[8]);
                        }
                        return result;
                    }
                    #[cfg(feature = "full")]
                    Executable::ForwardEdns(codes) => {
                        forward_client_edns(ctx, codes);
                        let result = self.walk(w.next(), ctx).await;
                        if result.is_ok() {
                            forward_response_edns(ctx, codes);
                        }
                        return result;
                    }
                    #[cfg(feature = "full")]
                    Executable::ReverseLookup(lookup) => {
                        if let Some(r) = lookup.response(&ctx.query) {
                            ctx.set_response(Some(r));
                            return Ok(());
                        }
                        self.walk(w.next(), ctx).await?;
                        lookup.store(ctx);
                        return Ok(());
                    }
                    #[cfg(feature = "full")]
                    Executable::Selector(selector) => {
                        let typ = ctx.query.queries()[0].query_type();
                        if typ != RecordType::A && typ != RecordType::AAAA {
                            return self.walk(w.next(), ctx).await;
                        }
                        let name = ctx.query.queries()[0].name().to_ascii();
                        if typ == selector.prefer {
                            self.walk(w.next(), ctx).await?;
                            if selector.has_answer(&ctx.response) {
                                selector.save(name);
                            }
                            return Ok(());
                        }
                        if selector.known(&name) {
                            ctx.set_response(Some(empty_reply(&ctx.query)));
                            return Ok(());
                        }
                        let mut reference = ctx.clone();
                        reference.query.queries_mut()[0].set_query_type(selector.prefer);
                        let mut original = ctx.clone();
                        let e = self.clone();
                        let tail = w.next();
                        let selected = selector.clone();
                        let ref_name = name.clone();
                        let work = self.state.lifecycle.fork();
                        let mut reference = tokio::spawn(async move {
                            let _work = work;
                            let result = tokio::time::timeout(
                                Duration::from_secs(5),
                                e.walk(tail, &mut reference),
                            )
                            .await;
                            let found = matches!(result, Ok(Ok(())))
                                && selected.has_answer(&reference.response);
                            if found {
                                selected.save(ref_name);
                            }
                            found
                        });
                        let e = self.clone();
                        let tail = w.next();
                        let work = self.state.lifecycle.fork();
                        let mut original = tokio::spawn(async move {
                            let _work = work;
                            let result = tokio::time::timeout(
                                Duration::from_secs(5),
                                e.walk(tail, &mut original),
                            )
                            .await;
                            (original, result)
                        });
                        let result = tokio::select! {
                            found=&mut reference=>{if found.unwrap_or(false){ctx.set_response(Some(empty_reply(&ctx.query)));return Ok(());}original.await?},
                            result=&mut original=>{
                                let result=result?;
                                if tokio::time::timeout(Duration::from_millis(500),&mut reference).await.is_ok_and(|r|r.unwrap_or(false)){ctx.set_response(Some(empty_reply(&ctx.query)));return Ok(());}result
                            }
                        };
                        *ctx = result.0;
                        return result.1?;
                    }
                    #[cfg(feature = "full")]
                    Executable::Metrics(metrics) => {
                        let guard = metrics.begin();
                        let start = Instant::now();
                        let result = self.walk(w.next(), ctx).await;
                        metrics.end(result.is_err(), ctx.response.is_some(), start.elapsed());
                        drop(guard);
                        return result;
                    }
                    #[cfg(feature = "full")]
                    Executable::QuerySummary(title) => {
                        let result = self.walk(w.next(), ctx).await;
                        self.log(title, ctx, result.as_ref().err().map(ToString::to_string));
                        return result;
                    }
                    #[cfg(feature = "full")]
                    Executable::DebugPrint(title) => self.log(title, ctx, None),
                }
                w.pos += 1;
            }
            if let Some(back) = w.jump_back {
                self.walk(*back, ctx).await
            } else {
                Ok(())
            }
        }))
    }
}
#[cfg(feature = "full")]
fn spawn_secondary(
    e: Engine,
    secondary: Executable,
    mut ctx: QueryContext,
) -> tokio::task::JoinHandle<Result<Message>> {
    let work = e.state.lifecycle.fork();
    tokio::spawn(async move {
        let _work = work;
        tokio::time::timeout(Duration::from_secs(5), e.standalone(secondary, &mut ctx)).await??;
        ctx.response
            .ok_or_else(|| anyhow!("secondary returned no response"))
    })
}
async fn exchange(
    f: &Forward,
    q: &Message,
    lifecycle: &Arc<super::lifecycle::Lifecycle>,
) -> Result<Message> {
    let start = rand::random::<usize>() % f.upstreams.len();
    let (sender, mut results) = tokio::sync::mpsc::unbounded_channel();
    for i in 0..f.concurrent {
        let u = f.upstreams[(start + i) % f.upstreams.len()].1.clone();
        let q = q.clone();
        let sender = sender.clone();
        let work = lifecycle.fork();
        // Go gives every upstream an independent Background context with a
        // fixed 5-second deadline. A winner/cancelled caller stops receiving,
        // while losers continue and remain owned by Engine shutdown drain.
        tokio::spawn(async move {
            let _work = work;
            let _ = sender.send(u.exchange(&q).await);
        });
    }
    drop(sender);
    let mut remaining = f.concurrent;
    while let Some(result) = results.recv().await {
        remaining -= 1;
        if let Ok(r) = result {
            if remaining > 0
                && r.response_code() != ResponseCode::NoError
                && r.response_code() != ResponseCode::NXDomain
            {
                continue;
            }
            return Ok(r);
        }
    }
    bail!("all upstream servers failed")
}
#[cfg(feature = "full")]
fn ip_response(q: &Message, ips: &[IpAddr], ttl: u32, negative: bool) -> Option<Message> {
    let question = &q.queries()[0];
    if question.query_type() != RecordType::A && question.query_type() != RecordType::AAAA {
        return None;
    }
    let mut r = reply(q, ResponseCode::NoError);
    for ip in ips {
        let data = match (question.query_type(), ip) {
            (RecordType::A, IpAddr::V4(ip)) => RData::A(A(*ip)),
            (RecordType::AAAA, IpAddr::V6(ip)) => RData::AAAA(AAAA(*ip)),
            _ => continue,
        };
        r.add_answer(Record::from_rdata(question.name().clone(), ttl, data));
    }
    if r.answers().is_empty() {
        if !negative || ips.is_empty() {
            return None;
        }
        r.add_name_server(Record::from_rdata(
            question.name().clone(),
            300,
            RData::SOA(SOA::new(
                Name::from_ascii("fake-ns.mosdns.fake.root.").unwrap(),
                Name::from_ascii("fake-mbox.mosdns.fake.root.").unwrap(),
                2021110400,
                1800,
                900,
                604800,
                86400,
            )),
        ));
    }
    Some(r)
}

struct Builder {
    extensions: super::extensions::ExtensionHub,
    lifecycle: Arc<super::lifecycle::Lifecycle>,
    closers: Vec<super::lifecycle::CloseEntry>,
    services: Vec<super::registry::PendingService>,
    resource_ledger: super::registry::ResourceLedger,
    committed_closers: HashMap<String, Vec<super::lifecycle::CloseEntry>>,
    registry: super::registry::Registry,
    defs: HashMap<String, PluginConfig>,
    plugins: HashMap<String, Plugin>,
    building: HashSet<String>,
    servers: Vec<ServerConfig>,
    #[cfg(feature = "full")]
    metrics: Vec<Arc<Metrics>>,
    #[cfg(feature = "full")]
    forward_metrics: Arc<ForwardMetrics>,
    upstreams: Vec<Arc<Upstream>>,
    #[cfg(feature = "full")]
    metric_names: HashSet<String>,
    #[cfg(feature = "full")]
    metric_owners: HashMap<String, Vec<String>>,
    #[cfg(feature = "full")]
    cache_dumps: Vec<(Arc<Cache>, String)>,
    caches: Vec<Arc<Cache>>,
    #[cfg(feature = "full")]
    selectors: Vec<Arc<Selector>>,
    #[cfg(feature = "full")]
    reverse_lookups: Vec<Arc<ReverseLookup>>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SetArgs {
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    exps: Vec<String>,
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    ips: Vec<String>,
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    sets: Vec<String>,
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    files: Vec<String>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DomainArgs {
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    exps: Vec<String>,
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    domain_sets: Vec<String>,
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    files: Vec<String>,
}
#[cfg(feature = "full")]
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct IpArgs {
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    ips: Vec<String>,
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    ip_sets: Vec<String>,
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    files: Vec<String>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ForwardArgs {
    upstreams: Vec<UpstreamArgs>,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    concurrent: i64,
    socks5: String,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    so_mark: i64,
    bind_to_device: String,
    bootstrap: String,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    bootstrap_version: i64,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct UpstreamArgs {
    tag: String,
    addr: String,
    dial_addr: String,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    idle_timeout: i64,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    max_conns: i64,
    #[serde(deserialize_with = "super::config::deserialize_bool")]
    enable_pipeline: bool,
    #[serde(deserialize_with = "super::config::deserialize_bool")]
    enable_http3: bool,
    #[serde(deserialize_with = "super::config::deserialize_bool")]
    insecure_skip_verify: bool,
    socks5: String,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    so_mark: i64,
    bind_to_device: String,
    bootstrap: String,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    bootstrap_version: i64,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct CacheArgs {
    #[serde(deserialize_with = "super::config::deserialize_number")]
    size: i64,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    lazy_cache_ttl: i64,
    dump_file: String,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    dump_interval: i64,
}
#[cfg(feature = "full")]
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FallbackArgs {
    primary: String,
    secondary: String,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    threshold: i64,
    #[serde(deserialize_with = "super::config::deserialize_bool")]
    always_standby: bool,
}
#[cfg(feature = "full")]
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct HostsArgs {
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    entries: Vec<String>,
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    files: Vec<String>,
}
#[cfg(feature = "full")]
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuleFilesArgs {
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    rules: Vec<String>,
    #[serde(deserialize_with = "super::config::deserialize_strings")]
    files: Vec<String>,
}
#[cfg(feature = "full")]
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SleepArgs {
    #[serde(deserialize_with = "super::config::deserialize_number")]
    duration: u64,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ServerArgs {
    entry: String,
    listen: String,
    cert: String,
    key: String,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    idle_timeout: i64,
}
#[cfg(feature = "full")]
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct HttpServerArgs {
    entries: Vec<HttpEntry>,
    listen: String,
    cert: String,
    key: String,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    idle_timeout: i64,
    src_ip_header: String,
}
#[cfg(feature = "full")]
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct EcsArgs {
    #[serde(deserialize_with = "super::config::deserialize_bool")]
    forward: bool,
    #[serde(deserialize_with = "super::config::deserialize_bool")]
    send: bool,
    preset: String,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    mask4: i64,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    mask6: i64,
}
#[cfg(feature = "full")]
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ReverseLookupArgs {
    #[serde(deserialize_with = "super::config::deserialize_number")]
    size: i64,
    #[serde(deserialize_with = "super::config::deserialize_bool")]
    handle_ptr: bool,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    ttl: i64,
}
#[cfg(feature = "full")]
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RateLimiterArgs {
    #[serde(deserialize_with = "super::config::deserialize_number")]
    qps: f64,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    burst: i64,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    mask4: i64,
    #[serde(deserialize_with = "super::config::deserialize_number")]
    mask6: i64,
}
fn decode<T: DeserializeOwned + Default>(args: &Value) -> Result<T> {
    if args.is_null() {
        Ok(T::default())
    } else {
        Ok(serde_yaml::from_value(args.clone())?)
    }
}
#[cfg(feature = "full")]
fn numbers(s: &str) -> Result<Vec<i64>> {
    s.split_whitespace()
        .map(|s| s.parse().map_err(Into::into))
        .collect()
}
#[cfg(feature = "full")]
fn marks(s: &str) -> Result<Vec<u32>> {
    s.split_whitespace()
        .map(|s| s.parse().map_err(Into::into))
        .collect()
}
#[cfg(feature = "full")]
fn lines_with_files(mut entries: Vec<String>, files: Vec<String>) -> Result<Vec<String>> {
    for path in files {
        entries.extend(
            fs::read_to_string(&path)
                .with_context(|| format!("read {}", path))?
                .lines()
                .map(str::to_owned),
        );
    }
    Ok(entries
        .into_iter()
        .map(|s| s.split('#').next().unwrap_or("").trim().to_owned())
        .filter(|s| !s.is_empty())
        .collect())
}
impl Builder {
    fn rollback_closers(&mut self, entries: &[super::lifecycle::CloseEntry]) -> Vec<String> {
        let protected = {
            let mut ledger = self.resource_ledger.lock().unwrap();
            for entry in entries {
                let count = ledger.owners.get_mut(&entry.identity()).unwrap();
                *count -= 1;
                if *count == 0 {
                    ledger.owners.remove(&entry.identity());
                    ledger.closed.insert(entry.identity(), entry.closer.clone());
                }
            }
            ledger.owners.keys().copied().collect::<HashSet<_>>()
        };
        let identities: HashSet<_> = entries.iter().map(|entry| entry.identity()).collect();
        self.closers.retain(|entry| {
            !identities.contains(&entry.identity()) || protected.contains(&entry.identity())
        });
        super::lifecycle::close_entries(entries, &protected)
    }
    fn add_closer(&mut self, entry: super::lifecycle::CloseEntry) {
        if !self
            .closers
            .iter()
            .any(|existing| existing.identity() == entry.identity())
        {
            self.closers.push(entry);
        }
    }
    fn initialize<T>(
        &mut self,
        tag: &str,
        factory: impl FnOnce(&mut super::registry::BuildContext<'_>) -> Result<T>,
    ) -> Result<T> {
        let mut resources = super::registry::InitResources::default();
        let signal = self.lifecycle.signal();
        let ledger = self.resource_ledger.clone();
        let extensions = self.extensions.begin(tag);
        let outcome = {
            let mut lookup = |dependency: &str| self.build(dependency);
            let mut context = super::registry::BuildContext::new(
                tag,
                &mut lookup,
                &mut resources,
                signal,
                ledger,
                extensions,
            );
            let result =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| factory(&mut context)));
            if matches!(&result, Ok(Ok(_))) {
                context.commit_extensions();
            }
            result
        };
        let result = match outcome {
            Ok(result) => result,
            Err(panic) => Err(anyhow!(
                "plugin factory {tag} panicked: {}",
                super::lifecycle::panic_message(panic)
            )),
        };
        match result {
            Ok(value) => {
                for entry in resources.closers {
                    self.committed_closers
                        .entry(tag.into())
                        .or_default()
                        .push(entry.clone());
                    self.add_closer(entry);
                }
                self.services.extend(resources.services);
                Ok(value)
            }
            Err(error) => {
                resources.services.clear();
                let errors = self.rollback_closers(&resources.closers);
                Err(if errors.is_empty() {
                    error
                } else {
                    anyhow!("{error:#}; {}", errors.join("; "))
                })
            }
        }
    }
    fn initialize_plugin(
        &mut self,
        tag: &str,
        factory: impl FnOnce(&mut super::registry::BuildContext<'_>) -> Result<Plugin>,
    ) -> Result<Plugin> {
        self.initialize(tag, |context| {
            let plugin = factory(context)?;
            if let Plugin::Custom(object) = &plugin {
                if let Some(closer) = &object.closer {
                    context.register_closer(closer.clone())?;
                }
            }
            Ok(plugin)
        })
    }
    fn build(&mut self, tag: &str) -> Result<Plugin> {
        if let Some(p) = self.plugins.get(tag) {
            return Ok(p.clone());
        }
        if !self.building.insert(tag.into()) {
            // This marker belongs to the active outer build; leave it intact.
            bail!("plugin dependency cycle at {tag}");
        }
        let mut result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.build_inner(tag)))
                .unwrap_or_else(|panic| {
                    Err(anyhow!(
                        "plugin build {tag} panicked: {}",
                        super::lifecycle::panic_message(panic)
                    ))
                });
        // Factories may recover from dependency errors. Do not leave a failed
        // lookup marked as building, or a later retry will report a false cycle.
        self.building.remove(tag);
        if let Ok(plugin) = &result {
            self.plugins.insert(tag.into(), plugin.clone());
        } else {
            self.extensions.rollback_tag(tag);
            #[cfg(feature = "full")]
            let names = self.metric_owners.remove(tag).unwrap_or_default();
            #[cfg(feature = "full")]
            for name in &names {
                self.metric_names.remove(name);
            }
            #[cfg(feature = "full")]
            self.metrics.retain(|metric| !names.contains(&metric.name));
            self.services.retain(|service| service.tag != tag);
            let entries = self.committed_closers.remove(tag).unwrap_or_default();
            let errors = self.rollback_closers(&entries);
            if !errors.is_empty() {
                let error = result.err().unwrap();
                result = Err(anyhow!("{error:#}; {}", errors.join("; ")));
            }
        }
        result
    }
    fn build_inner(&mut self, tag: &str) -> Result<Plugin> {
        if let Some(factory) = self.registry.get_preset(tag) {
            return self.initialize_plugin(tag, |context| factory(context));
        }
        let c = self
            .defs
            .get(tag)
            .ok_or_else(|| anyhow!("cannot find plugin {tag}"))?
            .clone();
        let p = match c.kind.as_str() {
            "domain_set" => {
                let a: SetArgs = decode(&c.args)?;
                if !a.ips.is_empty() {
                    bail!("domain_set does not accept ips");
                }
                let mut g = Vec::new();
                let mut m = DomainMatcher::new();
                for exp in a.exps {
                    m.add(&exp)?;
                }
                for path in a.files {
                    if !path.is_empty() {
                        m.load_file(Path::new(&path))?;
                    }
                }
                if !m.is_empty() {
                    g.push(Arc::new(m));
                }
                let mut rules = super::registry::DomainRules::Builtin(g);
                for set in a.sets {
                    let acquired = self
                        .build(&set)?
                        .domain_rules()?
                        .ok_or_else(|| anyhow!("{set} is not a domain provider"))?;
                    rules.append(acquired);
                }
                match rules {
                    super::registry::DomainRules::Builtin(group) => Plugin::Domains(group),
                    dynamic => Plugin::DynamicDomains(dynamic),
                }
            }
            #[cfg(feature = "full")]
            "ip_set" => {
                let a: SetArgs = decode(&c.args)?;
                if !a.exps.is_empty() {
                    bail!("ip_set does not accept exps");
                }
                let mut g = Vec::new();
                let mut m = NetList::new();
                for ip in a.ips {
                    m.add(&ip)?;
                }
                for path in a.files {
                    if !path.is_empty() {
                        m.load_file(Path::new(&path))?;
                    }
                }
                if !m.is_empty() {
                    g.push(Arc::new(m));
                }
                let mut rules = super::registry::IpRules::Builtin(g);
                for set in a.sets {
                    let acquired = self
                        .build(&set)?
                        .ip_rules()?
                        .ok_or_else(|| anyhow!("{set} is not an IP provider"))?;
                    rules.append(acquired);
                }
                match rules {
                    super::registry::IpRules::Builtin(group) => Plugin::Ips(group),
                    dynamic => Plugin::DynamicIps(dynamic),
                }
            }
            "sequence" => {
                let a: Vec<RuleArgs> = decode(&c.args)?;
                let mut sequence = Vec::new();
                for (index, r) in a.into_iter().enumerate() {
                    let matches = r
                        .matches
                        .iter()
                        .map(|m| self.matcher(m, tag))
                        .collect::<Result<Vec<_>>>()
                        .with_context(|| format!("rule {index} matcher"))?;
                    let exec = self
                        .executable(&r.exec, tag)
                        .with_context(|| format!("rule {index} exec {}", r.exec))?;
                    sequence.push(Rule { matches, exec });
                }
                Plugin::Exec(Executable::Sequence(Arc::new(sequence)))
            }
            "forward" => Plugin::Exec(Executable::Forward(Arc::new(
                self.forward(decode(&c.args)?, tag)?,
            ))),
            "cache" => {
                let a: CacheArgs = decode(&c.args)?;
                #[cfg(not(feature = "full"))]
                if !a.dump_file.is_empty() || a.dump_interval != 0 {
                    bail!("minimal cache does not support dump_file or dump_interval");
                }
                let cache = Arc::new(Cache::new(
                    a.size.max(0) as usize,
                    a.lazy_cache_ttl.max(0) as u64,
                ));
                self.caches.push(cache.clone());
                #[cfg(feature = "full")]
                if !a.dump_file.is_empty() {
                    if let Err(err) = cache.load_dump(Path::new(&a.dump_file)) {
                        eprintln!("cache {} load dump: {err:#}", c.tag);
                    }
                    self.cache_dumps.push((cache.clone(), a.dump_file.clone()));
                    if tokio::runtime::Handle::try_current().is_ok() {
                        let weak = Arc::downgrade(&cache);
                        let path = a.dump_file;
                        let mut shutdown = self.lifecycle.signal();
                        let interval = Duration::from_secs(if a.dump_interval <= 0 {
                            600
                        } else {
                            a.dump_interval as u64
                        });
                        self.services.push(super::registry::PendingService {
                            tag: c.tag.clone(),
                            future: Box::pin(async move {
                                loop {
                                    if *shutdown.borrow() {
                                        return Ok(());
                                    }
                                    tokio::select! {
                                        _ = shutdown.changed() => return Ok(()),
                                        _ = tokio::time::sleep(interval) => {}
                                    }
                                    let Some(cache) = weak.upgrade() else {
                                        return Ok(());
                                    };
                                    let output = path.clone();
                                    match tokio::task::spawn_blocking(move || {
                                        cache.save_dump(Path::new(&output))
                                    })
                                    .await
                                    {
                                        Ok(Ok(_)) => {}
                                        Ok(Err(err)) => eprintln!("cache dump {path}: {err:#}"),
                                        Err(err) => eprintln!("cache dump worker {path}: {err}"),
                                    }
                                }
                            }),
                        });
                    }
                }
                Plugin::Exec(Executable::Cache(cache))
            }
            #[cfg(feature = "full")]
            "fallback" => {
                let a: FallbackArgs = decode(&c.args)?;
                let primary = self.tag_exec(&a.primary, "")?;
                let secondary = self.tag_exec(&a.secondary, "")?;
                Plugin::Exec(Executable::Fallback(Arc::new(Fallback {
                    primary,
                    secondary,
                    threshold: Duration::from_millis(if a.threshold <= 0 {
                        500
                    } else {
                        a.threshold as u64
                    }),
                    always_standby: a.always_standby,
                })))
            }
            #[cfg(feature = "full")]
            "hosts" => {
                let a: HostsArgs = decode(&c.args)?;
                let mut entries = Vec::new();
                for line in lines_with_files(a.entries, a.files)? {
                    let mut words = line.split_whitespace();
                    let pattern = words.next().unwrap();
                    let mut domain = DomainMatcher::new();
                    domain.add(&full_default(pattern))?;
                    let ips = words
                        .map(|s| s.parse().map_err(Into::into))
                        .collect::<Result<Vec<_>>>()?;
                    entries.push(HostEntry {
                        domain,
                        ips,
                        priority: rule_priority(&full_default(pattern)),
                    });
                }
                Plugin::Exec(Executable::Hosts(Arc::new(entries)))
            }
            #[cfg(feature = "full")]
            "redirect" => {
                let a: RuleFilesArgs = decode(&c.args)?;
                let mut entries = Vec::new();
                for line in lines_with_files(a.rules, a.files)? {
                    let words = line.split_whitespace().collect::<Vec<_>>();
                    if words.len() != 2 {
                        bail!("redirect rule must have two fields");
                    }
                    let mut domain = DomainMatcher::new();
                    domain.add(&full_default(words[0]))?;
                    entries.push(RedirectRule {
                        domain,
                        target: Name::from_ascii(words[1])?,
                        priority: rule_priority(&full_default(words[0])),
                    });
                }
                Plugin::Exec(Executable::Redirect(Arc::new(entries)))
            }
            #[cfg(feature = "full")]
            "arbitrary" => {
                let a: RuleFilesArgs = decode(&c.args)?;
                let mut records = Vec::new();
                // Parse full zone text, preserving $ORIGIN and multiline records.
                for text in a.rules.into_iter().chain(
                    a.files
                        .into_iter()
                        .map(fs::read_to_string)
                        .collect::<std::io::Result<Vec<_>>>()?,
                ) {
                    records.extend(crate::plugin::executable::arbitrary::parse_zone(&text)?);
                }
                Plugin::Exec(Executable::Arbitrary(Arc::new(records)))
            }
            #[cfg(feature = "full")]
            "sleep" => {
                let a: SleepArgs = decode(&c.args)?;
                Plugin::Exec(Executable::Sleep(Duration::from_millis(a.duration)))
            }
            #[cfg(feature = "full")]
            "ecs_handler" => {
                let a: EcsArgs = decode(&c.args)?;
                Plugin::Exec(Executable::Ecs(Arc::new(self.ecs(a)?)))
            }
            #[cfg(feature = "full")]
            "reverse_lookup" => {
                let a: ReverseLookupArgs = decode(&c.args)?;
                let reverse = Arc::new(ReverseLookup::new(
                    if a.size <= 0 { 65536 } else { a.size as usize },
                    a.handle_ptr,
                    if a.ttl <= 0 {
                        7200
                    } else {
                        u32::try_from(a.ttl)?
                    },
                ));
                self.reverse_lookups.push(reverse.clone());
                Plugin::Exec(Executable::ReverseLookup(reverse))
            }
            #[cfg(feature = "full")]
            "rate_limiter" => {
                let a: RateLimiterArgs = decode(&c.args)?;
                if !(0..=32).contains(&a.mask4)
                    || !(0..=128).contains(&a.mask6)
                    || !a.qps.is_finite()
                {
                    bail!("invalid rate_limiter args");
                }
                Plugin::Match(Matcher::RateLimiter(Arc::new(RateLimiter::new(
                    if a.qps <= 0.0 { 20.0 } else { a.qps },
                    if a.burst <= 0 {
                        40
                    } else {
                        u32::try_from(a.burst)?
                    },
                    if a.mask4 == 0 { 32 } else { a.mask4 as u8 },
                    if a.mask6 == 0 { 48 } else { a.mask6 as u8 },
                ))))
            }
            #[cfg(feature = "full")]
            "qname" | "cname" => {
                let a: DomainArgs = decode(&c.args)?;
                let g = self.domains(a)?;
                Plugin::Match(if c.kind == "qname" {
                    Matcher::qname(g)
                } else {
                    Matcher::cname(g)
                })
            }
            #[cfg(feature = "full")]
            "client_ip" | "resp_ip" | "ptr_ip" => {
                let a: IpArgs = decode(&c.args)?;
                let g = self.ips(a)?;
                Plugin::Match(match c.kind.as_str() {
                    "client_ip" => Matcher::client_ip(g),
                    "resp_ip" => Matcher::resp_ip(g),
                    _ => Matcher::ptr_ip(g),
                })
            }
            #[cfg(feature = "full")]
            "qtype" | "qclass" | "rcode" => {
                let v: Vec<i64> = decode(&c.args)?;
                Plugin::Match(match c.kind.as_str() {
                    "qtype" => Matcher::Qtype(v),
                    "qclass" => Matcher::Qclass(v),
                    _ => Matcher::Rcode(v),
                })
            }
            "udp_server" | "tcp_server" | "quic_server"
                if c.kind != "quic_server" || cfg!(feature = "full") =>
            {
                let a: ServerArgs = decode(&c.args)?;
                self.tag_exec(&a.entry, "")?;
                #[cfg(not(feature = "full"))]
                if !a.cert.is_empty() || !a.key.is_empty() {
                    bail!("tcp_server cert/key require the full build");
                }
                if a.cert.is_empty() != a.key.is_empty() {
                    bail!("TLS server requires both cert and key");
                }
                if c.kind == "quic_server" && a.cert.is_empty() {
                    bail!("quic server requires a TLS certificate");
                }
                for path in [&a.cert, &a.key] {
                    if !path.is_empty() {
                        fs::metadata(path)
                            .with_context(|| format!("TLS credential file {path}"))?;
                    }
                }
                if c.kind == "udp_server" && a.idle_timeout != 0 {
                    bail!("udp_server does not accept idle_timeout");
                }
                if c.kind == "udp_server" && !a.cert.is_empty() {
                    bail!("udp_server does not support TLS certificates");
                }
                let listen = if a.listen.is_empty() {
                    "127.0.0.1:53".into()
                } else {
                    a.listen
                };
                if (listen.starts_with('@') || listen.starts_with("unix://"))
                    && c.kind != "tcp_server"
                {
                    bail!("{} requires an IP listener address", c.kind);
                }
                let idle_timeout = if a.idle_timeout <= 0 {
                    if c.kind == "quic_server" {
                        30
                    } else {
                        10
                    }
                } else {
                    a.idle_timeout as u64
                };
                self.servers.push(ServerConfig {
                    kind: c.kind,
                    listen,
                    entry: a.entry,
                    idle_timeout,
                    cert: a.cert,
                    key: a.key,
                    entries: Vec::new(),
                    src_ip_header: String::new(),
                });
                Plugin::Server
            }
            #[cfg(feature = "full")]
            "http_server" => {
                let a: HttpServerArgs = decode(&c.args)?;
                if a.listen.is_empty() {
                    bail!("http_server requires listen");
                }
                if a.cert.is_empty() != a.key.is_empty() {
                    bail!("http_server TLS requires cert and key");
                }
                let mut paths = HashSet::new();
                for entry in &a.entries {
                    self.tag_exec(&entry.exec, "")?;
                    if !entry.path.starts_with('/') || !paths.insert(entry.path.clone()) {
                        bail!("invalid or duplicate HTTP entry path {}", entry.path);
                    }
                }
                for path in [&a.cert, &a.key] {
                    if !path.is_empty() {
                        fs::metadata(path)
                            .with_context(|| format!("TLS credential file {path}"))?;
                    }
                }
                self.servers.push(ServerConfig {
                    kind: c.kind,
                    listen: a.listen,
                    entry: String::new(),
                    idle_timeout: if a.idle_timeout <= 0 {
                        30
                    } else {
                        a.idle_timeout as u64
                    },
                    cert: a.cert,
                    key: a.key,
                    entries: a.entries,
                    src_ip_header: a.src_ip_header,
                });
                Plugin::Server
            }
            other => {
                let factory = self.registry.get_plugin_type(other).ok_or_else(|| {
                    anyhow!("unsupported plugin type {other}; refusing to silently ignore it")
                })?;
                self.initialize_plugin(tag, |context| factory(context, &c.args))?
            }
        };
        Ok(p)
    }
    fn domains(&mut self, a: DomainArgs) -> Result<super::registry::DomainRules> {
        let mut rules = super::registry::DomainRules::default();
        for tag in a.domain_sets {
            let acquired = self
                .build(&tag)?
                .domain_rules()?
                .ok_or_else(|| anyhow!("{tag} is not a domain provider"))?;
            rules.append(acquired);
        }
        let mut matcher = DomainMatcher::new();
        for exp in a.exps {
            matcher.add(&exp)?;
        }
        for path in a.files {
            matcher.load_file(Path::new(&path))?;
        }
        if !matcher.is_empty() {
            rules.append(super::registry::DomainRules::Builtin(vec![Arc::new(
                matcher,
            )]));
        }
        Ok(rules)
    }
    #[cfg(feature = "full")]
    fn ips(&mut self, a: IpArgs) -> Result<super::registry::IpRules> {
        let mut rules = super::registry::IpRules::default();
        for tag in a.ip_sets {
            let acquired = self
                .build(&tag)?
                .ip_rules()?
                .ok_or_else(|| anyhow!("{tag} is not an IP provider"))?;
            rules.append(acquired);
        }
        let mut matcher = NetList::new();
        for ip in a.ips {
            matcher.add(&ip)?;
        }
        for path in a.files {
            matcher.load_file(Path::new(&path))?;
        }
        if !matcher.is_empty() {
            rules.append(super::registry::IpRules::Builtin(vec![Arc::new(matcher)]));
        }
        Ok(rules)
    }
    fn matcher(&mut self, s: &str, owner: &str) -> Result<Matcher> {
        let c = parse_quick(s, true)?;
        #[cfg(not(feature = "full"))]
        if !c.tagged && !self.registry.matcher_types().contains(&c.name) {
            bail!("matcher {} is unavailable in the minimal build", c.name);
        }
        let m = if c.tagged {
            match self.build(&c.name)?.matcher() {
                Some(Matcher::Custom(m)) => {
                    m.quick_configure(&c.args)?.unwrap_or(Matcher::Custom(m))
                }
                Some(m) => m,
                _ => bail!("{} is not a matcher", c.name),
            }
        } else {
            match c.name.as_str() {
                "_true" => Matcher::Constant(true),
                "_false" => Matcher::Constant(false),
                "qname" | "cname" if c.name == "qname" || cfg!(feature = "full") => {
                    let mut a = DomainArgs::default();
                    for v in c.args.split_whitespace() {
                        if let Some(s) = v.strip_prefix('$') {
                            a.domain_sets.push(s.into());
                        } else if let Some(s) = v.strip_prefix('&') {
                            a.files.push(s.into());
                        } else {
                            a.exps.push(v.into());
                        }
                    }
                    let d = self.domains(a)?;
                    #[cfg(feature = "full")]
                    if c.name == "qname" {
                        Matcher::qname(d)
                    } else {
                        Matcher::cname(d)
                    }
                    #[cfg(not(feature = "full"))]
                    Matcher::qname(d)
                }
                #[cfg(feature = "full")]
                "client_ip" | "resp_ip" | "ptr_ip" => {
                    let mut a = IpArgs::default();
                    for v in c.args.split_whitespace() {
                        if let Some(s) = v.strip_prefix('$') {
                            a.ip_sets.push(s.into());
                        } else if let Some(s) = v.strip_prefix('&') {
                            a.files.push(s.into());
                        } else {
                            a.ips.push(v.into());
                        }
                    }
                    let d = self.ips(a)?;
                    match c.name.as_str() {
                        "client_ip" => Matcher::client_ip(d),
                        "resp_ip" => Matcher::resp_ip(d),
                        _ => Matcher::ptr_ip(d),
                    }
                }
                #[cfg(feature = "full")]
                "qtype" => Matcher::Qtype(numbers(&c.args)?),
                #[cfg(feature = "full")]
                "qclass" => Matcher::Qclass(numbers(&c.args)?),
                #[cfg(feature = "full")]
                "rcode" => Matcher::Rcode(numbers(&c.args)?),
                "has_resp" => Matcher::HasResp,
                #[cfg(feature = "full")]
                "has_wanted_ans" => Matcher::HasWantedAnswer,
                #[cfg(feature = "full")]
                "mark" => Matcher::Mark(marks(&c.args)?),
                #[cfg(feature = "full")]
                "random" => {
                    let p: f64 = c.args.parse()?;
                    if !p.is_finite() {
                        bail!("invalid probability");
                    }
                    Matcher::Random(p)
                }
                #[cfg(feature = "full")]
                "env" => {
                    let v = c.args.split_whitespace().collect::<Vec<_>>();
                    if !(1..=2).contains(&v.len()) {
                        bail!("env expects key [value]");
                    }
                    Matcher::Constant(
                        std::env::var(v[0])
                            .ok()
                            .is_some_and(|s| v.len() == 1 || s == v[1]),
                    )
                }
                #[cfg(feature = "full")]
                "string_exp" => {
                    let v = c.args.split_whitespace().collect::<Vec<_>>();
                    if v.len() < 2 {
                        bail!("string_exp expects source operator arguments");
                    }
                    let src = if let Some(s) = v[0].strip_prefix('$') {
                        StringSource::Env(s.into())
                    } else {
                        match v[0] {
                            "server_name" => StringSource::ServerName,
                            "url_path" => StringSource::UrlPath,
                            _ => bail!("invalid string_exp source"),
                        }
                    };
                    let args = v[2..].iter().map(|s| s.to_string()).collect::<Vec<_>>();
                    let op = match v[1] {
                        "zl" => StringOperator::Empty,
                        "eq" => StringOperator::Eq(args),
                        "prefix" => StringOperator::Prefix(args),
                        "suffix" => StringOperator::Suffix(args),
                        "contains" => StringOperator::Contains(args),
                        "regexp" => StringOperator::Regex(
                            args.iter()
                                .map(|s| regex::Regex::new(s))
                                .collect::<Result<Vec<_>, _>>()?,
                        ),
                        _ => bail!("invalid string_exp operator"),
                    };
                    Matcher::StringExp(src, op)
                }
                other => {
                    let setup = self
                        .registry
                        .get_matcher(other)
                        .ok_or_else(|| anyhow!("unsupported matcher {other}"))?;
                    self.initialize(owner, |context| setup(context, &c.args))?
                }
            }
        };
        Ok(if c.reverse {
            Matcher::Reverse(Box::new(m))
        } else {
            m
        })
    }
    fn tag_exec(&mut self, tag: &str, args: &str) -> Result<Executable> {
        let executable = self
            .build(tag)?
            .executable()
            .ok_or_else(|| anyhow!("{tag} is not executable"))?;
        match executable {
            Executable::Forward(f) if !args.is_empty() => {
                let mut upstreams = Vec::new();
                for tag in args.split_whitespace() {
                    upstreams.push(
                        f.upstreams
                            .iter()
                            .find(|(t, _)| t == tag)
                            .ok_or_else(|| anyhow!("cannot find upstream tag {tag}"))?
                            .clone(),
                    );
                }
                Ok(Executable::Forward(Arc::new(Forward {
                    upstreams,
                    concurrent: f.concurrent,
                })))
            }
            Executable::Custom(plugin) => Ok(plugin
                .quick_configure(args)?
                .unwrap_or(Executable::Custom(plugin))),
            Executable::RecursiveCustom(plugin) => Ok(plugin
                .quick_configure(args)?
                .unwrap_or(Executable::RecursiveCustom(plugin))),
            e => Ok(e),
        }
    }
    fn executable(&mut self, s: &str, owner: &str) -> Result<Executable> {
        let c = parse_quick(s, false)?;
        #[cfg(not(feature = "full"))]
        if !c.tagged && !self.registry.exec_types().contains(&c.name) {
            bail!("executable {} is unavailable in the minimal build", c.name);
        }
        if c.tagged {
            return self.tag_exec(&c.name, &c.args);
        }
        Ok(match c.name.as_str() {
            "accept" => Executable::Accept,
            "reject" => {
                let n = if c.args.is_empty() {
                    5
                } else {
                    c.args.parse::<u16>()?
                };
                if n > 4095 {
                    bail!("invalid reject rcode");
                }
                Executable::Reject(n)
            }
            "return" => Executable::Return,
            "jump" | "goto" => {
                let e = self.tag_exec(&c.args, "")?;
                let Executable::Sequence(seq) = e else {
                    bail!("{} target is not a sequence", c.name)
                };
                if c.name == "jump" {
                    Executable::Jump(seq)
                } else {
                    Executable::Goto(seq)
                }
            }
            "forward" => {
                let a = ForwardArgs {
                    upstreams: c
                        .args
                        .split_whitespace()
                        .map(|s| UpstreamArgs {
                            addr: s.into(),
                            ..Default::default()
                        })
                        .collect(),
                    concurrent: 3,
                    ..Default::default()
                };
                Executable::Forward(Arc::new(self.forward(a, owner)?))
            }
            "cache" => {
                let cache = Arc::new(Cache::new(
                    if c.args.is_empty() {
                        1024
                    } else {
                        c.args.parse::<usize>()?
                    },
                    0,
                ));
                self.caches.push(cache.clone());
                Executable::Cache(cache)
            }
            #[cfg(feature = "full")]
            "ttl" => {
                let (fix, min, max) = if let Some((lo, hi)) = c.args.split_once('-') {
                    (0, lo.parse()?, hi.parse()?)
                } else {
                    (c.args.parse()?, 0, 0)
                };
                Executable::Ttl { fix, min, max }
            }
            #[cfg(feature = "full")]
            "black_hole" => Executable::BlackHole(
                c.args
                    .split_whitespace()
                    .map(|s| s.parse().map_err(Into::into))
                    .collect::<Result<Vec<_>>>()?,
            ),
            #[cfg(feature = "full")]
            "drop_resp" => Executable::DropResponse,
            #[cfg(feature = "full")]
            "sleep" => {
                Executable::Sleep(Duration::from_millis(c.args.parse::<i64>()?.max(0) as u64))
            }
            #[cfg(feature = "full")]
            "mark" => Executable::Mark(marks(&c.args)?),
            #[cfg(feature = "full")]
            "ecs" => {
                let preset = c
                    .args
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_string();
                Executable::Ecs(Arc::new(self.ecs(EcsArgs {
                    preset,
                    ..Default::default()
                })?))
            }
            #[cfg(feature = "full")]
            "forward_edns0opt" => Executable::ForwardEdns(
                c.args
                    .split_whitespace()
                    .map(|s| s.parse().map_err(Into::into))
                    .collect::<Result<Vec<_>>>()?,
            ),
            #[cfg(feature = "full")]
            "prefer_ipv4" | "prefer_ipv6" => {
                let selector = Arc::new(Selector::new(if c.name == "prefer_ipv4" {
                    RecordType::A
                } else {
                    RecordType::AAAA
                }));
                self.selectors.push(selector.clone());
                Executable::Selector(selector)
            }
            #[cfg(feature = "full")]
            "metrics_collector" => {
                if c.args.is_empty() {
                    bail!("collector must have a name");
                }
                if !self.metric_names.insert(c.args.clone()) {
                    bail!("duplicate metrics collector name {}", c.args);
                }
                self.metric_owners
                    .entry(owner.into())
                    .or_default()
                    .push(c.args.clone());
                let m = Arc::new(Metrics::new(c.args));
                self.metrics.push(m.clone());
                Executable::Metrics(m)
            }
            "nftset" | "ipset" if c.name == "nftset" || cfg!(feature = "full") => {
                Executable::KernelSets(Arc::new(
                    crate::plugin::executable::kernel_sets::KernelSets::parse(&c.name, &c.args)?,
                ))
            }
            #[cfg(feature = "full")]
            "query_summary" => Executable::QuerySummary(if c.args.is_empty() {
                "query summary".into()
            } else {
                c.args
            }),
            #[cfg(feature = "full")]
            "debug_print" => Executable::DebugPrint(if c.args.is_empty() {
                "debug print".into()
            } else {
                c.args
            }),
            other => {
                let setup = self
                    .registry
                    .get_exec(other)
                    .ok_or_else(|| anyhow!("unsupported executable {other}"))?;
                self.initialize(owner, |context| setup(context, &c.args))?
            }
        })
    }
    fn forward(&mut self, a: ForwardArgs, owner: &str) -> Result<Forward> {
        #[cfg(not(feature = "full"))]
        let _ = owner;
        if a.upstreams.is_empty() {
            bail!("no upstream configured");
        }
        let mut upstreams = Vec::new();
        let mut tags = HashSet::new();
        #[cfg(feature = "full")]
        let metrics = self.forward_metrics.begin();
        for u in a.upstreams {
            if u.idle_timeout < 0 {
                bail!("invalid upstream idle_timeout");
            }
            let _ = u.max_conns;
            if !u.tag.is_empty() && !tags.insert(u.tag.clone()) {
                bail!("duplicate upstream tag {}", u.tag);
            }
            #[cfg(feature = "full")]
            let observer = if u.tag.is_empty() {
                None
            } else {
                Some(metrics.observer(owner, &u.tag)?)
            };
            upstreams.push((
                u.tag,
                Arc::new(Upstream::new_with_options(
                    &u.addr,
                    Duration::from_secs(5),
                    crate::pkg::upstream::Options {
                        #[cfg(feature = "full")]
                        event_observer: observer,
                        #[cfg(not(feature = "full"))]
                        event_observer: None,
                        dial_addr: u.dial_addr,
                        socks5: if u.socks5.is_empty() {
                            a.socks5.clone()
                        } else {
                            u.socks5
                        },
                        so_mark: if u.so_mark <= 0 { a.so_mark } else { u.so_mark },
                        bind_to_device: if u.bind_to_device.is_empty() {
                            a.bind_to_device.clone()
                        } else {
                            u.bind_to_device
                        },
                        bootstrap: if u.bootstrap.is_empty() {
                            a.bootstrap.clone()
                        } else {
                            u.bootstrap
                        },
                        bootstrap_version: if u.bootstrap_version <= 0 {
                            a.bootstrap_version
                        } else {
                            u.bootstrap_version
                        },
                        idle_timeout: Duration::from_secs(u.idle_timeout as u64),
                        enable_pipeline: u.enable_pipeline,
                        enable_http3: u.enable_http3,
                        insecure_skip_verify: u.insecure_skip_verify,
                    },
                )?),
            ));
        }
        #[cfg(feature = "full")]
        metrics.commit();
        self.upstreams
            .extend(upstreams.iter().map(|(_, upstream)| upstream.clone()));
        Ok(Forward {
            upstreams,
            concurrent: a.concurrent.clamp(1, 3) as usize,
        })
    }
    #[cfg(feature = "full")]
    fn ecs(&self, a: EcsArgs) -> Result<EcsHandler> {
        if !(0..=32).contains(&a.mask4) || !(0..=128).contains(&a.mask6) {
            bail!("invalid ECS mask");
        }
        let preset = if a.preset.is_empty() {
            None
        } else {
            Some(a.preset.parse::<IpAddr>()?)
        };
        Ok(EcsHandler {
            forward: a.forward,
            send: a.send,
            preset,
            mask4: if a.mask4 == 0 { 24 } else { a.mask4 as u8 },
            mask6: if a.mask6 == 0 { 48 } else { a.mask6 as u8 },
        })
    }
}
#[cfg(feature = "full")]
fn full_default(pattern: &str) -> String {
    match pattern.split_once(':') {
        Some(("", value)) => format!("full:{value}"),
        Some(_) => pattern.to_owned(),
        None => format!("full:{pattern}"),
    }
}
#[cfg(feature = "full")]
fn rule_priority(pattern: &str) -> (u8, usize) {
    let (kind, value) = pattern.split_once(':').unwrap();
    match kind {
        "full" => (4, 0),
        "domain" => {
            // Match NormalizeDomain followed by ReverseDomainScanner: each
            // trims one trailing dot, and the scanner skips a leading empty
            // label. Count labels so equivalent spellings keep insertion order.
            let value = value.strip_suffix('.').unwrap_or(value);
            let mut remaining = value.strip_suffix('.').unwrap_or(value);
            let mut depth = 0;
            while !remaining.is_empty() {
                depth += 1;
                remaining = remaining.rsplit_once('.').map_or("", |(left, _)| left);
            }
            (3, depth)
        }
        "regexp" => (2, 0),
        "keyword" => (1, 0),
        _ => (0, 0),
    }
}
