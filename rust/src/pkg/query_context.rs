use hickory_proto::op::{Edns, Message, MessageType, ResponseCode};
use std::{
    any::Any,
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_KEY: AtomicU32 = AtomicU32::new(0);

/// Register a unique KV key during plugin initialization, matching Go RegKey.
/// Panics on overflow rather than reusing a previously issued key.
pub fn reg_key() -> u32 {
    allocate_key(&NEXT_KEY)
}
fn allocate_key(counter: &AtomicU32) -> u32 {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.checked_add(1).expect("key id overflowed");
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(value) => current = value,
        }
    }
}
pub type SharedValue = Arc<dyn Any + Send + Sync>;

#[derive(Clone)]
pub struct QueryContext {
    pub id: u64,
    pub started: Instant,
    pub query: Message,
    pub client: IpAddr,
    /// Unix sockets have no IP peer; retain this separately from the placeholder.
    pub client_valid: bool,
    pub response: Option<Message>,
    pub marks: HashSet<u32>,
    pub response_generation: u64,
    pub client_edns: Option<Edns>,
    pub upstream_edns: Option<Edns>,
    pub response_edns: Option<Edns>,
    pub server_name: String,
    pub url_path: String,
    /// A copied context owns its map but shares stored values, like Go CopyTo.
    kv: Option<HashMap<u32, SharedValue>>,
}
impl QueryContext {
    pub fn new(mut query: Message, client: IpAddr) -> Self {
        // The incoming message is owned. Move its OPT into client metadata;
        // cloning it only to replace the original duplicated option buffers.
        let client_edns = query.extensions_mut().take();
        let response_edns = client_edns.as_ref().map(|c| {
            let mut e = Edns::new();
            e.set_max_payload(1200).set_dnssec_ok(c.dnssec_ok());
            e
        });
        let mut outbound = Edns::new();
        outbound.set_max_payload(1200);
        *query.extensions_mut() = Some(outbound);
        Self {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            started: Instant::now(),
            query,
            client,
            client_valid: true,
            response: None,
            marks: HashSet::new(),
            response_generation: 0,
            client_edns,
            upstream_edns: None,
            response_edns,
            server_name: String::new(),
            url_path: String::new(),
            kv: None,
        }
    }
    pub fn set_response(&mut self, mut response: Option<Message>) {
        self.upstream_edns = response.as_mut().and_then(|r| r.extensions_mut().take());
        self.response = response;
        self.response_generation += 1;
    }
    /// The key must come from reg_key. Values shared by cloned contexts must be
    /// Send + Sync; use a Mutex/atomic for shared mutable plugin state.
    pub fn store_value<T: Any + Send + Sync>(&mut self, key: u32, value: T) {
        self.store_shared_value(key, Arc::new(value));
    }
    pub fn store_shared_value(&mut self, key: u32, value: SharedValue) {
        self.kv.get_or_insert_with(HashMap::new).insert(key, value);
    }
    pub fn get_value(&self, key: u32) -> Option<&SharedValue> {
        self.kv.as_ref()?.get(&key)
    }
    pub fn get_value_as<T: Any>(&self, key: u32) -> Option<&T> {
        self.get_value(key)?.downcast_ref()
    }
    pub fn delete_value(&mut self, key: u32) {
        if let Some(values) = &mut self.kv {
            values.remove(&key);
        }
    }
    pub fn finish(&mut self) -> Option<Message> {
        self.response.take().map(|mut r| {
            r.set_id(self.query.id());
            *r.extensions_mut() = self.response_edns.clone();
            r
        })
    }
}
pub fn reply(query: &Message, code: ResponseCode) -> Message {
    let mut r = Message::new();
    r.set_id(query.id())
        .set_message_type(MessageType::Response)
        .set_op_code(query.op_code())
        .set_recursion_desired(query.recursion_desired())
        .set_checking_disabled(query.checking_disabled())
        .set_response_code(code);
    r.add_queries(query.queries().iter().cloned());
    r
}
#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::Query,
        rr::{
            rdata::opt::{EdnsCode, EdnsOption},
            Name, RecordType,
        },
    };
    #[test]
    fn key_overflow_panics_without_reusing_keys() {
        let counter = AtomicU32::new(u32::MAX - 1);
        assert_eq!(allocate_key(&counter), u32::MAX);
        assert!(std::panic::catch_unwind(|| allocate_key(&counter)).is_err());
        assert_eq!(counter.load(Ordering::Relaxed), u32::MAX);
    }
    #[test]
    fn concurrent_registration_issues_unique_nonzero_keys() {
        let keys = std::thread::scope(|scope| {
            let workers = (0..8)
                .map(|_| scope.spawn(|| (0..128).map(|_| reg_key()).collect::<Vec<_>>()))
                .collect::<Vec<_>>();
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap())
                .collect::<HashSet<_>>()
        });
        assert_eq!(keys.len(), 8 * 128);
        assert!(!keys.contains(&0));
    }
    #[test]
    fn context_resets_upstream_opt_and_keeps_client_response_do() {
        let mut q = Message::new();
        q.set_id(400).add_query(Query::query(
            Name::from_ascii("edns.example.").unwrap(),
            RecordType::A,
        ));
        let mut opt = Edns::new();
        opt.set_max_payload(4096).set_dnssec_ok(true);
        opt.options_mut()
            .insert(EdnsOption::Unknown(65001, vec![1, 2, 3]));
        q.set_edns(opt);
        let mut ctx = QueryContext::new(q, "127.0.0.1".parse().unwrap());
        assert_eq!(ctx.query.extensions().as_ref().unwrap().max_payload(), 1200);
        assert!(!ctx.query.extensions().as_ref().unwrap().dnssec_ok());
        assert!(ctx
            .query
            .extensions()
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Unknown(65001))
            .is_none());
        let mut r = reply(&ctx.query, ResponseCode::NoError);
        let mut opt = Edns::new();
        opt.options_mut()
            .insert(EdnsOption::Unknown(65002, vec![4]));
        r.set_edns(opt);
        ctx.set_response(Some(r));
        assert!(ctx.response.as_ref().unwrap().extensions().is_none());
        assert!(ctx
            .upstream_edns
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Unknown(65002))
            .is_some());
        let response = ctx.finish().unwrap();
        assert_eq!(response.id(), 400);
        assert!(response.extensions().as_ref().unwrap().dnssec_ok());
        assert_eq!(response.extensions().as_ref().unwrap().max_payload(), 1200);
        assert!(response
            .extensions()
            .as_ref()
            .unwrap()
            .options()
            .get(EdnsCode::Unknown(65002))
            .is_none());
    }
}
