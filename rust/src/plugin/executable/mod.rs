#[cfg(feature = "full")]
pub mod arbitrary;
pub mod cache;
pub mod forward;
pub mod kernel_sets;
#[cfg(feature = "full")]
pub mod stateful;
#[cfg(feature = "full")]
use crate::pkg::matcher::domain::DomainMatcher;
use crate::{pkg::upstream::Upstream, plugin::sequence::Sequence};
#[cfg(feature = "full")]
use hickory_proto::rr::{Name, Record};
use std::sync::Arc;
#[cfg(feature = "full")]
use std::{net::IpAddr, time::Duration};

#[derive(Clone)]
pub enum Executable {
    Custom(Arc<dyn crate::coremain::registry::ExecutablePlugin>),
    RecursiveCustom(Arc<dyn crate::coremain::registry::RecursiveExecutablePlugin>),
    Accept,
    Reject(u16),
    Return,
    Jump(Arc<Sequence>),
    Goto(Arc<Sequence>),
    Sequence(Arc<Sequence>),
    Forward(Arc<Forward>),
    Cache(Arc<cache::Cache>),
    #[cfg(feature = "full")]
    Fallback(Arc<Fallback>),
    #[cfg(feature = "full")]
    Ttl {
        fix: u32,
        min: u32,
        max: u32,
    },
    #[cfg(feature = "full")]
    BlackHole(Vec<IpAddr>),
    #[cfg(feature = "full")]
    Hosts(Arc<Vec<HostEntry>>),
    #[cfg(feature = "full")]
    Arbitrary(Arc<Vec<Record>>),
    #[cfg(feature = "full")]
    Redirect(Arc<Vec<RedirectRule>>),
    #[cfg(feature = "full")]
    DropResponse,
    #[cfg(feature = "full")]
    Sleep(Duration),
    #[cfg(feature = "full")]
    Mark(Vec<u32>),
    #[cfg(feature = "full")]
    Ecs(Arc<stateful::EcsHandler>),
    #[cfg(feature = "full")]
    ForwardEdns(Vec<u16>),
    #[cfg(feature = "full")]
    Selector(Arc<stateful::Selector>),
    #[cfg(feature = "full")]
    ReverseLookup(Arc<stateful::ReverseLookup>),
    #[cfg(feature = "full")]
    Metrics(Arc<stateful::Metrics>),
    #[cfg(feature = "full")]
    QuerySummary(String),
    #[cfg(feature = "full")]
    DebugPrint(String),
    KernelSets(Arc<kernel_sets::KernelSets>),
}
pub struct Forward {
    pub upstreams: Vec<(String, Arc<Upstream>)>,
    pub concurrent: usize,
}
#[cfg(feature = "full")]
pub struct Fallback {
    pub primary: Executable,
    pub secondary: Executable,
    pub threshold: Duration,
    pub always_standby: bool,
}
#[cfg(feature = "full")]
pub struct HostEntry {
    pub domain: DomainMatcher,
    pub ips: Vec<IpAddr>,
    pub priority: (u8, usize),
}
#[cfg(feature = "full")]
pub struct RedirectRule {
    pub domain: DomainMatcher,
    pub target: Name,
    pub priority: (u8, usize),
}
