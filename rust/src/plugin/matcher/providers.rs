//! Synchronous equivalents of Go data_provider getter and matcher interfaces.
//! Getters acquire a long-lived matcher at initialization. The matcher can keep
//! mutable rules internally; replacing the provider's handle does not retarget
//! an already built rule. Only dynamic configurations use trait dispatch.
use super::{DomainGroup, IpGroup};
use crate::pkg::matcher::{domain::DomainMatcher, netlist::NetList};
use std::{net::IpAddr, sync::Arc};

pub trait DomainMatch: Send + Sync {
    fn matches(&self, name: &str) -> bool;
}
pub trait IpMatch: Send + Sync {
    fn matches(&self, address: IpAddr) -> bool;
}
/// Arc receiver permits a provider and matcher to be the same shared object.
pub trait DomainMatcherProvider: Send + Sync {
    fn get_domain_matcher(self: Arc<Self>) -> Arc<dyn DomainMatch>;
}
pub trait IPMatcherProvider: Send + Sync {
    fn get_ip_matcher(self: Arc<Self>) -> Arc<dyn IpMatch>;
}
impl DomainMatch for DomainMatcher {
    fn matches(&self, name: &str) -> bool {
        DomainMatcher::matches(self, name)
    }
}
impl IpMatch for NetList {
    fn matches(&self, address: IpAddr) -> bool {
        self.contains(address)
    }
}

#[derive(Clone)]
pub enum DomainRules {
    Builtin(DomainGroup),
    Dynamic(Arc<dyn DomainMatch>),
    Group(Vec<DomainRules>),
}
impl Default for DomainRules {
    fn default() -> Self {
        Self::Builtin(Vec::new())
    }
}
impl DomainRules {
    pub fn matches(&self, name: &str) -> bool {
        match self {
            Self::Builtin(group) => group.iter().any(|matcher| matcher.matches(name)),
            Self::Dynamic(matcher) => matcher.matches(name),
            Self::Group(group) => group.iter().any(|matcher| matcher.matches(name)),
        }
    }
    /// Preserve Go OR order; flatten composed groups during initialization.
    pub fn append(&mut self, other: Self) {
        if let (Self::Builtin(group), Self::Builtin(extra)) = (&mut *self, &other) {
            group.extend(extra.iter().cloned());
            return;
        }
        if matches!(self, Self::Builtin(group) if group.is_empty()) {
            *self = other;
            return;
        }
        if matches!(&other, Self::Builtin(group) if group.is_empty()) {
            return;
        }
        let original = std::mem::take(self);
        let mut group = match original {
            Self::Group(group) => group,
            rule => vec![rule],
        };
        match other {
            Self::Group(extra) => group.extend(extra),
            rule => group.push(rule),
        }
        *self = Self::Group(group);
    }
}

#[derive(Clone)]
pub enum IpRules {
    Builtin(IpGroup),
    Dynamic(Arc<dyn IpMatch>),
    Group(Vec<IpRules>),
}
impl Default for IpRules {
    fn default() -> Self {
        Self::Builtin(Vec::new())
    }
}
impl IpRules {
    pub fn matches(&self, address: IpAddr) -> bool {
        match self {
            Self::Builtin(group) => group.iter().any(|matcher| matcher.contains(address)),
            Self::Dynamic(matcher) => matcher.matches(address),
            Self::Group(group) => group.iter().any(|matcher| matcher.matches(address)),
        }
    }
    pub fn append(&mut self, other: Self) {
        if let (Self::Builtin(group), Self::Builtin(extra)) = (&mut *self, &other) {
            group.extend(extra.iter().cloned());
            return;
        }
        if matches!(self, Self::Builtin(group) if group.is_empty()) {
            *self = other;
            return;
        }
        if matches!(&other, Self::Builtin(group) if group.is_empty()) {
            return;
        }
        let original = std::mem::take(self);
        let mut group = match original {
            Self::Group(group) => group,
            rule => vec![rule],
        };
        match other {
            Self::Group(extra) => group.extend(extra),
            rule => group.push(rule),
        }
        *self = Self::Group(group);
    }
}
