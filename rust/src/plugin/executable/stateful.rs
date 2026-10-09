use crate::pkg::{
    cache::{Cache as Backend, Opts},
    concurrent_map::Hashable,
};
use crate::plugin::{
    matcher::parse_ptr,
    query_context::{reply, QueryContext},
};
use hickory_proto::{
    op::{Message, ResponseCode},
    rr::{
        rdata::{
            opt::{ClientSubnet, EdnsCode, EdnsOption},
            PTR, SOA,
        },
        RData, Record, RecordType,
    },
};
use std::{
    hash::BuildHasher,
    net::IpAddr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, OnceLock,
    },
    time::{Duration, Instant},
};

pub struct EcsHandler {
    pub forward: bool,
    pub send: bool,
    pub preset: Option<IpAddr>,
    pub mask4: u8,
    pub mask6: u8,
}
impl EcsHandler {
    pub fn add(&self, ctx: &mut QueryContext) -> bool {
        if ctx.query.queries()[0].query_class() != hickory_proto::rr::DNSClass::IN
            || ctx
                .query
                .extensions()
                .as_ref()
                .unwrap()
                .options()
                .get(EdnsCode::Subnet)
                .is_some()
        {
            return false;
        }
        if self.forward {
            if let Some(option) = ctx
                .client_edns
                .as_ref()
                .and_then(|e| e.options().get(EdnsCode::Subnet))
                .cloned()
            {
                ctx.query
                    .extensions_mut()
                    .as_mut()
                    .unwrap()
                    .options_mut()
                    .insert(option);
                return true;
            }
        }
        let ip = self.preset.or(if self.send && ctx.client_valid {
            Some(ctx.client)
        } else {
            None
        });
        if let Some(ip) = ip {
            let ip = unmap(ip);
            let mask = if ip.is_ipv4() { self.mask4 } else { self.mask6 };
            ctx.query
                .extensions_mut()
                .as_mut()
                .unwrap()
                .options_mut()
                .insert(EdnsOption::Subnet(ClientSubnet::new(ip, mask, 0)));
        }
        false
    }
}
pub fn forward_client_edns(ctx: &mut QueryContext, codes: &[u16]) {
    if let Some(client) = &ctx.client_edns {
        for (code, value) in client.options().as_ref() {
            if codes.contains(&u16::from(*code)) {
                ctx.query
                    .extensions_mut()
                    .as_mut()
                    .unwrap()
                    .options_mut()
                    .insert(value.clone());
            }
        }
    }
}
pub fn forward_response_edns(ctx: &mut QueryContext, codes: &[u16]) {
    if let (Some(upstream), Some(response)) = (&ctx.upstream_edns, &mut ctx.response_edns) {
        for (code, value) in upstream.options().as_ref() {
            if codes.contains(&u16::from(*code)) {
                response.options_mut().insert(value.clone());
            }
        }
    }
}
#[derive(Clone, Hash, PartialEq, Eq)]
struct DomainKey(String);
impl Hashable for DomainKey {
    fn sum(&self) -> u64 {
        static HASHER: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
        HASHER
            .get_or_init(std::collections::hash_map::RandomState::new)
            .hash_one(self)
    }
}
#[derive(Clone, Hash, PartialEq, Eq)]
struct AddressKey(IpAddr);
impl Hashable for AddressKey {
    fn sum(&self) -> u64 {
        static HASHER: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
        HASHER
            .get_or_init(std::collections::hash_map::RandomState::new)
            .hash_one(self)
    }
}
pub struct Selector {
    pub prefer: RecordType,
    known: Arc<Backend<DomainKey, bool>>,
}
impl Selector {
    pub fn new(prefer: RecordType) -> Self {
        Self {
            prefer,
            known: Backend::new(Opts {
                size: 65536,
                cleaner_interval: Duration::from_secs(60),
            }),
        }
    }
    pub fn known(&self, name: &str) -> bool {
        self.known
            .get(&DomainKey(name.to_owned()))
            .is_some_and(|(known, _)| known)
    }
    pub fn save(&self, name: String) {
        self.known.store(
            DomainKey(name),
            true,
            Instant::now() + Duration::from_secs(3600),
        );
    }
    pub fn close(&self) {
        self.known.close();
    }
    pub async fn close_and_wait(&self) {
        self.known.close_and_wait().await;
    }
    pub fn has_answer(&self, r: &Option<Message>) -> bool {
        r.as_ref()
            .is_some_and(|r| r.answers().iter().any(|r| r.record_type() == self.prefer))
    }
}
pub fn empty_reply(q: &Message) -> Message {
    let mut r = reply(q, ResponseCode::NoError);
    r.add_name_server(Record::from_rdata(
        hickory_proto::rr::Name::root(),
        300,
        RData::SOA(SOA::new(
            hickory_proto::rr::Name::from_ascii("fake-ns.mosdns.fake.root.").unwrap(),
            hickory_proto::rr::Name::from_ascii("fake-mbox.mosdns.fake.root.").unwrap(),
            2021110400,
            1800,
            900,
            604800,
            86400,
        )),
    ));
    r
}
pub struct ReverseLookup {
    pub handle_ptr: bool,
    pub ttl: u32,
    entries: Arc<Backend<AddressKey, hickory_proto::rr::Name>>,
}
impl ReverseLookup {
    pub fn new(size: usize, handle_ptr: bool, ttl: u32) -> Self {
        Self {
            handle_ptr,
            ttl,
            entries: Backend::new(Opts {
                size: if size == 0 { 65536 } else { size },
                ..Opts::default()
            }),
        }
    }
    pub fn lookup(&self, ip: IpAddr) -> Option<hickory_proto::rr::Name> {
        let ip = unmap(ip);
        self.entries.get(&AddressKey(ip)).map(|(name, _)| name)
    }
    pub fn close(&self) {
        self.entries.close();
    }
    pub async fn close_and_wait(&self) {
        self.entries.close_and_wait().await;
    }
    pub fn response(&self, q: &Message) -> Option<Message> {
        let question = q.queries().first()?;
        if !self.handle_ptr || question.query_type() != RecordType::PTR {
            return None;
        }
        let target = self.lookup(parse_ptr(&question.name().to_ascii())?)?;
        let mut r = reply(q, ResponseCode::NoError);
        let mut rr = Record::from_rdata(question.name().clone(), 5, RData::PTR(PTR(target)));
        rr.set_dns_class(question.query_class());
        r.add_answer(rr);
        Some(r)
    }
    pub fn store(&self, ctx: &mut QueryContext) {
        let question_name =
            (ctx.query.queries().len() == 1).then(|| ctx.query.queries()[0].name().clone());
        if let Some(r) = &mut ctx.response {
            for rr in r.answers_mut() {
                let ip = match rr.data() {
                    Some(RData::A(a)) => IpAddr::V4(a.0),
                    Some(RData::AAAA(a)) => IpAddr::V6(a.0),
                    _ => continue,
                };
                if rr.ttl() > self.ttl {
                    rr.set_ttl(self.ttl);
                }
                self.entries.store(
                    AddressKey(unmap(ip)),
                    question_name.clone().unwrap_or_else(|| rr.name().clone()),
                    Instant::now() + Duration::from_secs(u64::from(self.ttl)),
                );
            }
        }
    }
}
pub fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}
pub struct Metrics {
    pub name: String,
    queries: AtomicU64,
    errors: AtomicU64,
    active: AtomicU64,
    latency_sum_ms: AtomicU64,
    latency_count: AtomicU64,
    buckets: [AtomicU64; 11],
}
const BUCKETS: [u64; 11] = [1, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000];
pub struct MetricsGuard<'a> {
    collector: &'a Metrics,
}
impl Drop for MetricsGuard<'_> {
    fn drop(&mut self) {
        self.collector.active.fetch_sub(1, Ordering::Relaxed);
    }
}
impl Metrics {
    pub fn new(name: String) -> Self {
        Self {
            name,
            queries: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            active: AtomicU64::new(0),
            latency_sum_ms: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
            buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }
    pub fn begin(&self) -> MetricsGuard<'_> {
        self.queries.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::Relaxed);
        MetricsGuard { collector: self }
    }
    pub fn end(&self, failed: bool, has_response: bool, duration: Duration) {
        if failed {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        if has_response {
            self.latency_sum_ms.fetch_add(
                duration.as_millis().min(u128::from(u64::MAX)) as u64,
                Ordering::Relaxed,
            );
            self.latency_count.fetch_add(1, Ordering::Relaxed);
            for (i, limit) in BUCKETS.iter().enumerate() {
                if duration.as_millis() <= u128::from(*limit) {
                    self.buckets[i].fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    pub fn text(&self) -> String {
        Self::render(std::iter::once(self))
    }
    /// Render shared family descriptors once, even with multiple named collectors.
    pub fn render<'a>(collectors: impl IntoIterator<Item = &'a Self>) -> String {
        let mut collectors = collectors.into_iter().peekable();
        if collectors.peek().is_none() {
            return String::new();
        }
        let mut text = String::new();
        for (name, kind, help) in [
            (
                "query_total",
                "counter",
                "The total number of queries pass through",
            ),
            ("err_total", "counter", "The total number of queries failed"),
            (
                "thread",
                "gauge",
                "The number of threads that are currently being processed",
            ),
            (
                "response_latency_millisecond",
                "histogram",
                "The response latency in millisecond",
            ),
        ] {
            text.push_str(&format!(
                "# HELP mosdns_metrics_collector_{name} {help}\n# TYPE mosdns_metrics_collector_{name} {kind}\n"
            ));
        }
        for collector in collectors {
            text.push_str(&collector.samples());
        }
        text
    }
    fn samples(&self) -> String {
        let name = self
            .name
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n");
        let mut s=format!("mosdns_metrics_collector_query_total{{name=\"{name}\"}} {}\nmosdns_metrics_collector_err_total{{name=\"{name}\"}} {}\nmosdns_metrics_collector_thread{{name=\"{name}\"}} {}\n",self.queries.load(Ordering::Relaxed),self.errors.load(Ordering::Relaxed),self.active.load(Ordering::Relaxed));
        for (i, limit) in BUCKETS.iter().enumerate() {
            s+=&format!("mosdns_metrics_collector_response_latency_millisecond_bucket{{name=\"{name}\",le=\"{limit}\"}} {}\n",self.buckets[i].load(Ordering::Relaxed));
        }
        s+=&format!("mosdns_metrics_collector_response_latency_millisecond_bucket{{name=\"{name}\",le=\"+Inf\"}} {}\nmosdns_metrics_collector_response_latency_millisecond_sum{{name=\"{name}\"}} {}\nmosdns_metrics_collector_response_latency_millisecond_count{{name=\"{name}\"}} {}\n",self.latency_count.load(Ordering::Relaxed),self.latency_sum_ms.load(Ordering::Relaxed),self.latency_count.load(Ordering::Relaxed));
        s
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{Edns, Query},
        rr::{Name, RecordType},
    };
    fn context() -> QueryContext {
        let mut q = Message::new();
        q.add_query(Query::query(
            Name::from_ascii("ecs.example.").unwrap(),
            RecordType::A,
        ));
        QueryContext::new(q, "192.0.2.129".parse().unwrap())
    }
    #[test]
    fn reverse_lookup_uses_sharded_capacity_and_normalizes_mapped_addresses() {
        let lookup = ReverseLookup::new(1, true, 10);
        let mut ctx = context();
        let mut response = reply(&ctx.query, ResponseCode::NoError);
        for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3"] {
            response.add_answer(Record::from_rdata(
                ctx.query.queries()[0].name().clone(),
                300,
                RData::A(hickory_proto::rr::rdata::A(ip.parse().unwrap())),
            ));
        }
        ctx.set_response(Some(response));
        lookup.store(&mut ctx);
        assert!(ctx
            .response
            .unwrap()
            .answers()
            .iter()
            .all(|rr| rr.ttl() == 10));
        for ip in ["192.0.2.1", "192.0.2.2", "192.0.2.3", "::ffff:192.0.2.1"] {
            assert_eq!(
                lookup.lookup(ip.parse().unwrap()).unwrap().to_ascii(),
                "ecs.example."
            );
        }
        lookup.entries.gc(Instant::now() + Duration::from_secs(11));
        assert!(lookup.lookup("192.0.2.1".parse().unwrap()).is_none());
    }
    #[test]
    fn public_reverse_lookup_handles_empty_and_multi_question_messages() {
        let lookup = ReverseLookup::new(1, true, 10);
        assert!(lookup.response(&Message::new()).is_none());
        for count in [0, 2] {
            let mut query = Message::new();
            for index in 0..count {
                query.add_query(Query::query(
                    Name::from_ascii(format!("question-{index}.test.")).unwrap(),
                    RecordType::A,
                ));
            }
            let mut ctx = QueryContext::new(query, "127.0.0.1".parse().unwrap());
            let mut response = reply(&ctx.query, ResponseCode::NoError);
            response.add_answer(Record::from_rdata(
                Name::from_ascii("rr-owner.test.").unwrap(),
                30,
                RData::A(hickory_proto::rr::rdata::A("192.0.2.10".parse().unwrap())),
            ));
            ctx.set_response(Some(response));
            lookup.store(&mut ctx);
            assert_eq!(
                lookup
                    .lookup("192.0.2.10".parse().unwrap())
                    .unwrap()
                    .to_ascii(),
                "rr-owner.test."
            );
        }
    }
    #[tokio::test]
    async fn closed_selector_and_reverse_lookup_keep_explicit_operations_available() {
        let selector = Selector::new(RecordType::AAAA);
        selector.save("closed-selector.test.".into());
        assert!(selector.known("closed-selector.test."));
        selector
            .known
            .gc(Instant::now() + Duration::from_secs(3601));
        assert!(!selector.known("closed-selector.test."));
        selector.close_and_wait().await;
        selector.save("closed-selector.test.".into());
        assert!(selector.known("closed-selector.test."));
        let lookup = ReverseLookup::new(1, true, 10);
        lookup.close_and_wait().await;
        let mut ctx = context();
        let mut response = reply(&ctx.query, ResponseCode::NoError);
        response.add_answer(Record::from_rdata(
            ctx.query.queries()[0].name().clone(),
            30,
            RData::A(hickory_proto::rr::rdata::A("192.0.2.1".parse().unwrap())),
        ));
        ctx.set_response(Some(response));
        lookup.store(&mut ctx);
        assert!(lookup.lookup("192.0.2.1".parse().unwrap()).is_some());
    }
    #[test]
    fn invalid_unix_client_does_not_generate_ecs_without_a_preset() {
        let mut ctx = context();
        ctx.client_valid = false;
        let mut handler = EcsHandler {
            forward: false,
            send: true,
            preset: None,
            mask4: 24,
            mask6: 48,
        };
        assert!(!handler.add(&mut ctx));
        assert!(ctx
            .query
            .extensions()
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Subnet)
            .is_none());
        handler.preset = Some("198.51.100.1".parse().unwrap());
        assert!(!handler.add(&mut ctx));
        assert!(ctx
            .query
            .extensions()
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Subnet)
            .is_some());
    }
    #[test]
    fn ecs_preset_masks_and_never_replaces_an_existing_option() {
        let mut ctx = context();
        let e = EcsHandler {
            forward: false,
            send: true,
            preset: None,
            mask4: 24,
            mask6: 48,
        };
        assert!(!e.add(&mut ctx));
        let existing = ctx
            .query
            .extensions()
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Subnet)
            .unwrap()
            .clone();
        assert!(!e.add(&mut ctx));
        assert_eq!(
            ctx.query
                .extensions()
                .as_ref()
                .unwrap()
                .options()
                .get(EdnsCode::Subnet)
                .unwrap(),
            &existing
        );
        let wire = ctx.query.to_vec().unwrap();
        let decoded = Message::from_vec(&wire).unwrap();
        assert_eq!(
            decoded
                .extensions()
                .as_ref()
                .unwrap()
                .options()
                .get(EdnsCode::Subnet)
                .unwrap(),
            &EdnsOption::Subnet(ClientSubnet::new("192.0.2.0".parse().unwrap(), 24, 0))
        );
    }
    #[test]
    fn edns_options_forward_only_selected_codes_in_both_directions() {
        let mut ctx = context();
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(65001, vec![1]));
        edns.options_mut()
            .insert(EdnsOption::Unknown(65002, vec![2]));
        ctx.client_edns = Some(edns.clone());
        ctx.response_edns = Some(Edns::new());
        forward_client_edns(&mut ctx, &[65001]);
        assert!(ctx
            .query
            .extensions()
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Unknown(65001))
            .is_some());
        assert!(ctx
            .query
            .extensions()
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Unknown(65002))
            .is_none());
        let mut r = reply(&ctx.query, ResponseCode::NoError);
        r.set_edns(edns);
        ctx.set_response(Some(r));
        forward_response_edns(&mut ctx, &[65002]);
        let r = ctx.finish().unwrap();
        assert!(r
            .extensions()
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Unknown(65001))
            .is_none());
        assert!(r
            .extensions()
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Unknown(65002))
            .is_some());
    }
}
