use crate::pkg::matcher::{domain::DomainMatcher, netlist::NetList};
use crate::plugin::query_context::QueryContext;
#[cfg(feature = "full")]
use hickory_proto::rr::{RData, RecordType};
#[cfg(feature = "full")]
use regex::Regex;
#[cfg(feature = "full")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
pub mod providers;
#[cfg(feature = "full")]
pub mod rate_limiter;
use providers::DomainRules;
#[cfg(feature = "full")]
use providers::IpRules;

pub type DomainGroup = Vec<Arc<DomainMatcher>>;
pub type IpGroup = Vec<Arc<NetList>>;
#[derive(Clone)]
pub enum Matcher {
    Custom(Arc<dyn crate::coremain::registry::MatcherPlugin>),
    Constant(bool),
    Reverse(Box<Matcher>),
    Qname(DomainGroup),
    #[cfg(feature = "full")]
    Cname(DomainGroup),
    #[cfg(feature = "full")]
    ClientIp(IpGroup),
    #[cfg(feature = "full")]
    RespIp(IpGroup),
    #[cfg(feature = "full")]
    PtrIp(IpGroup),
    QnameProvider(DomainRules),
    #[cfg(feature = "full")]
    CnameProvider(DomainRules),
    #[cfg(feature = "full")]
    ClientIpProvider(IpRules),
    #[cfg(feature = "full")]
    RespIpProvider(IpRules),
    #[cfg(feature = "full")]
    PtrIpProvider(IpRules),
    #[cfg(feature = "full")]
    Qtype(Vec<i64>),
    #[cfg(feature = "full")]
    Qclass(Vec<i64>),
    #[cfg(feature = "full")]
    Rcode(Vec<i64>),
    HasResp,
    #[cfg(feature = "full")]
    HasWantedAnswer,
    #[cfg(feature = "full")]
    Mark(Vec<u32>),
    #[cfg(feature = "full")]
    Random(f64),
    #[cfg(feature = "full")]
    StringExp(StringSource, StringOperator),
    #[cfg(feature = "full")]
    RateLimiter(Arc<rate_limiter::RateLimiter>),
}
#[cfg(feature = "full")]
#[derive(Clone)]
pub enum StringSource {
    Env(String),
    ServerName,
    UrlPath,
}
#[cfg(feature = "full")]
#[derive(Clone)]
pub enum StringOperator {
    Empty,
    Eq(Vec<String>),
    Prefix(Vec<String>),
    Suffix(Vec<String>),
    Contains(Vec<String>),
    Regex(Vec<Regex>),
}
impl Matcher {
    pub fn qname(rules: DomainRules) -> Self {
        match rules {
            DomainRules::Builtin(group) => Self::Qname(group),
            dynamic => Self::QnameProvider(dynamic),
        }
    }
    #[cfg(feature = "full")]
    pub fn cname(rules: DomainRules) -> Self {
        match rules {
            DomainRules::Builtin(group) => Self::Cname(group),
            dynamic => Self::CnameProvider(dynamic),
        }
    }
    #[cfg(feature = "full")]
    pub fn client_ip(rules: IpRules) -> Self {
        match rules {
            IpRules::Builtin(group) => Self::ClientIp(group),
            dynamic => Self::ClientIpProvider(dynamic),
        }
    }
    #[cfg(feature = "full")]
    pub fn resp_ip(rules: IpRules) -> Self {
        match rules {
            IpRules::Builtin(group) => Self::RespIp(group),
            dynamic => Self::RespIpProvider(dynamic),
        }
    }
    #[cfg(feature = "full")]
    pub fn ptr_ip(rules: IpRules) -> Self {
        match rules {
            IpRules::Builtin(group) => Self::PtrIp(group),
            dynamic => Self::PtrIpProvider(dynamic),
        }
    }
    pub fn matches<'a>(
        &'a self,
        ctx: &'a mut QueryContext,
    ) -> futures::future::Either<
        futures::future::Ready<anyhow::Result<bool>>,
        futures::future::BoxFuture<'a, anyhow::Result<bool>>,
    > {
        // Built-ins, including their negations, retain a synchronous allocation-free path.
        if let Some(value) = self.builtin_matches(ctx) {
            return futures::future::Either::Left(futures::future::ready(Ok(value)));
        }
        futures::future::Either::Right(Box::pin(async move {
            match self {
                Self::Custom(m) => m.matches(ctx).await,
                Self::Reverse(m) => Ok(!m.matches(ctx).await?),
                _ => unreachable!("built-ins were evaluated above"),
            }
        }))
    }
    fn builtin_matches(&self, ctx: &QueryContext) -> Option<bool> {
        let q = &ctx.query.queries()[0];
        Some(match self {
            Self::Constant(v) => *v,
            Self::Custom(_) => return None,
            Self::Reverse(m) => return m.builtin_matches(ctx).map(|value| !value),
            Self::Qname(g) => g.iter().any(|m| m.matches(&q.name().to_ascii())),
            Self::QnameProvider(rules) => rules.matches(&q.name().to_ascii()),
            #[cfg(feature = "full")]
            Self::CnameProvider(rules) => ctx.response.as_ref().is_some_and(|response| {
                response.answers().iter().any(|record| match record.data() {
                    Some(RData::CNAME(name)) => rules.matches(&name.0.to_ascii()),
                    _ => false,
                })
            }),
            #[cfg(feature = "full")]
            Self::ClientIpProvider(rules) => ctx.client_valid && rules.matches(ctx.client),
            #[cfg(feature = "full")]
            Self::RespIpProvider(rules) => ctx.response.as_ref().is_some_and(|response| {
                response.answers().iter().any(|record| match record.data() {
                    Some(RData::A(address)) => rules.matches(IpAddr::V4(address.0)),
                    Some(RData::AAAA(address)) => rules.matches(IpAddr::V6(address.0)),
                    _ => false,
                })
            }),
            #[cfg(feature = "full")]
            Self::PtrIpProvider(rules) => {
                q.query_type() == RecordType::PTR
                    && parse_ptr(&q.name().to_ascii()).is_some_and(|address| rules.matches(address))
            }
            #[cfg(feature = "full")]
            Self::Cname(g) => ctx.response.as_ref().is_some_and(|r| {
                r.answers().iter().any(|rr| match rr.data() {
                    Some(RData::CNAME(n)) => g.iter().any(|m| m.matches(&n.0.to_ascii())),
                    _ => false,
                })
            }),
            #[cfg(feature = "full")]
            Self::ClientIp(g) => ctx.client_valid && g.iter().any(|m| m.contains(ctx.client)),
            #[cfg(feature = "full")]
            Self::RespIp(g) => ctx.response.as_ref().is_some_and(|r| {
                r.answers().iter().any(|rr| {
                    let ip = match rr.data() {
                        Some(RData::A(a)) => Some(IpAddr::V4(a.0)),
                        Some(RData::AAAA(a)) => Some(IpAddr::V6(a.0)),
                        _ => None,
                    };
                    ip.is_some_and(|ip| g.iter().any(|m| m.contains(ip)))
                })
            }),
            #[cfg(feature = "full")]
            Self::PtrIp(g) => {
                q.query_type() == RecordType::PTR
                    && parse_ptr(&q.name().to_ascii())
                        .is_some_and(|ip| g.iter().any(|m| m.contains(ip)))
            }
            #[cfg(feature = "full")]
            Self::Qtype(v) => v.contains(&i64::from(u16::from(q.query_type()))),
            #[cfg(feature = "full")]
            Self::Qclass(v) => v.contains(&i64::from(u16::from(q.query_class()))),
            #[cfg(feature = "full")]
            Self::Rcode(v) => ctx
                .response
                .as_ref()
                .is_some_and(|r| v.contains(&i64::from(u16::from(r.response_code())))),
            Self::HasResp => ctx.response.is_some(),
            #[cfg(feature = "full")]
            Self::HasWantedAnswer => ctx.response.as_ref().is_some_and(|r| {
                r.answers().iter().any(|rr| {
                    rr.record_type() == q.query_type() && rr.dns_class() == q.query_class()
                })
            }),
            #[cfg(feature = "full")]
            Self::Mark(v) => v.iter().any(|m| ctx.marks.contains(m)),
            #[cfg(feature = "full")]
            Self::Random(p) => rand::random::<f64>() < *p,
            #[cfg(feature = "full")]
            Self::RateLimiter(l) => !ctx.client_valid || l.allow(ctx.client),
            #[cfg(feature = "full")]
            Self::StringExp(src, op) => {
                let value = match src {
                    StringSource::Env(k) => std::env::var(k).unwrap_or_default(),
                    StringSource::ServerName => ctx.server_name.clone(),
                    StringSource::UrlPath => ctx.url_path.clone(),
                };
                match op {
                    StringOperator::Empty => value.is_empty(),
                    StringOperator::Eq(v) => v.contains(&value),
                    StringOperator::Prefix(v) => v.iter().any(|s| value.starts_with(s)),
                    StringOperator::Suffix(v) => v.iter().any(|s| value.ends_with(s)),
                    StringOperator::Contains(v) => v.iter().any(|s| value.contains(s)),
                    StringOperator::Regex(v) => v.iter().any(|r| r.is_match(&value)),
                }
            }
        })
    }
}
#[cfg(feature = "full")]
pub fn parse_ptr(s: &str) -> Option<IpAddr> {
    let name = s.trim_end_matches('.').to_ascii_lowercase();
    if let Some(s) = name.strip_suffix(".in-addr.arpa") {
        let parts = s
            .rsplit('.')
            .filter(|s| !s.is_empty())
            .take(4)
            .collect::<Vec<_>>();
        if parts.len() != 4 {
            return None;
        }
        let o = parts
            .into_iter()
            .map(str::parse::<u8>)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        return Some(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3])));
    }
    if let Some(s) = name.strip_suffix(".ip6.arpa") {
        let parts = s
            .rsplit('.')
            .filter(|s| !s.is_empty())
            .take(32)
            .collect::<Vec<_>>();
        if parts.len() != 32 || parts.iter().any(|s| s.len() != 1) {
            return None;
        }
        let hex = parts.into_iter().collect::<String>();
        return Some(IpAddr::V6(Ipv6Addr::from(
            u128::from_str_radix(&hex, 16).ok()?,
        )));
    }
    None
}
#[cfg(all(test, feature = "full"))]
mod tests {
    use super::*;
    #[test]
    fn parses_original_ptr_cases_with_ignored_prefixes() {
        for s in ["4.4.8.8.in-addr.arpa.", "prefix.4.4.8.8.in-addr.arpa."] {
            assert_eq!(parse_ptr(s), Some("8.8.4.4".parse().unwrap()));
        }
        for s in [
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
            "prefix.b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ] {
            assert_eq!(parse_ptr(s), Some("2001:db8::567:89ab".parse().unwrap()));
        }
        for s in [
            "123114123.in-addr.arpa.",
            "4.8.8.in-addr.arpa.",
            "0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
        ] {
            assert_eq!(parse_ptr(s), None);
        }
    }
}
