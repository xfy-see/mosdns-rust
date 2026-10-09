use crate::pkg::{
    cache::{Cache as Backend, Opts},
    concurrent_map::Hashable,
};
use crate::plugin::query_context::QueryContext;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::RecordType,
};
#[cfg(feature = "full")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::{
    collections::HashSet,
    hash::BuildHasher,
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub(crate) struct Key {
    name: String,
    typ: u16,
    class: u16,
    ad: bool,
    cd: bool,
    do_bit: bool,
}
impl Hashable for Key {
    fn sum(&self) -> u64 {
        static HASHER: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
        HASHER
            .get_or_init(std::collections::hash_map::RandomState::new)
            .hash_one(self)
    }
}
#[derive(Clone)]
struct Item {
    response: Message,
    stored: Instant,
    #[cfg(feature = "full")]
    age_offset: Duration,
    message_ttl: Duration,
    cache_ttl: Duration,
}
pub struct Cache {
    entries: Arc<Backend<Key, Arc<Item>>>,
    pub lazy_ttl: u64,
    pub(crate) refreshing: Mutex<HashSet<Key>>,
    #[cfg(feature = "full")]
    queries: AtomicU64,
    #[cfg(feature = "full")]
    hits: AtomicU64,
    #[cfg(feature = "full")]
    lazy_hits: AtomicU64,
}
#[cfg(feature = "full")]
#[derive(Debug, Clone, Copy)]
pub struct CacheStats {
    pub queries: u64,
    pub hits: u64,
    pub lazy_hits: u64,
    pub len: usize,
}
impl Cache {
    /// Current entries, without constructing or updating a metrics collector.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
    pub fn new(size: usize, lazy_ttl: u64) -> Self {
        Self {
            entries: Backend::new(Opts {
                size,
                ..Opts::default()
            }),
            lazy_ttl,
            refreshing: Mutex::new(HashSet::new()),
            #[cfg(feature = "full")]
            queries: AtomicU64::new(0),
            #[cfg(feature = "full")]
            hits: AtomicU64::new(0),
            #[cfg(feature = "full")]
            lazy_hits: AtomicU64::new(0),
        }
    }
    pub(crate) fn key(ctx: &QueryContext) -> Option<Key> {
        let q = &ctx.query;
        if q.message_type() != MessageType::Query
            || q.op_code() != OpCode::Query
            || q.queries().len() != 1
        {
            return None;
        }
        let question = &q.queries()[0];
        Some(Key {
            name: question.name().to_ascii(),
            typ: question.query_type().into(),
            class: question.query_class().into(),
            ad: q.authentic_data(),
            cd: q.checking_disabled(),
            do_bit: q.extensions().as_ref().is_some_and(|e| e.dnssec_ok()),
        })
    }
    pub(crate) fn lookup(&self, key: &Key) -> (Option<Message>, bool) {
        #[cfg(feature = "full")]
        self.queries.fetch_add(1, Ordering::Relaxed);
        let Some((item, _)) = self.entries.get(key) else {
            return (None, false);
        };
        let age = item.stored.elapsed();
        #[cfg(feature = "full")]
        let age = age.saturating_add(item.age_offset);
        if age >= item.cache_ttl {
            self.entries
                .del_if(key, |current| Arc::ptr_eq(current, &item));
            return (None, false);
        }
        let lazy = age >= item.message_ttl;
        if lazy && self.lazy_ttl == 0 {
            return (None, false);
        }
        let mut response = item.response.clone();
        map_ttl(&mut response, |ttl| {
            if lazy {
                5
            } else {
                ttl.saturating_sub(age.as_secs().min(u64::from(u32::MAX)) as u32)
                    .max(1)
            }
        });
        #[cfg(feature = "full")]
        self.hits.fetch_add(1, Ordering::Relaxed);
        #[cfg(feature = "full")]
        if lazy {
            self.lazy_hits.fetch_add(1, Ordering::Relaxed);
        }
        (Some(response), lazy)
    }
    pub(crate) fn store(&self, key: Key, r: &Message) {
        if r.truncated() {
            return;
        }
        let min_ttl = r
            .answers()
            .iter()
            .chain(r.name_servers())
            .chain(r.additionals())
            .filter(|r| r.record_type() != RecordType::OPT)
            .map(|r| r.ttl())
            .min()
            .unwrap_or(0);
        let message_ttl = match r.response_code() {
            ResponseCode::NXDomain => 30,
            ResponseCode::ServFail => 5,
            ResponseCode::NoError => {
                if r.answers().is_empty() {
                    u64::from(min_ttl.min(300))
                } else {
                    u64::from(min_ttl)
                }
            }
            _ => 0,
        };
        let cache_ttl = if r.response_code() == ResponseCode::NoError
            && !r.answers().is_empty()
            && self.lazy_ttl > 0
        {
            self.lazy_ttl
        } else {
            message_ttl
        };
        if message_ttl == 0 || cache_ttl == 0 {
            return;
        }
        let mut response = r.clone();
        *response.extensions_mut() = None;
        let stored = Instant::now();
        let Some(expiration) = stored.checked_add(Duration::from_secs(cache_ttl)) else {
            return;
        };
        self.entries.store(
            key,
            Arc::new(Item {
                response,
                stored,
                #[cfg(feature = "full")]
                age_offset: Duration::ZERO,
                message_ttl: Duration::from_secs(message_ttl),
                cache_ttl: Duration::from_secs(cache_ttl),
            }),
            expiration,
        );
    }
    #[cfg(feature = "full")]
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            queries: self.queries.load(Ordering::Relaxed),
            hits: self.hits.load(Ordering::Relaxed),
            lazy_hits: self.lazy_hits.load(Ordering::Relaxed),
            len: self.entries.len(),
        }
    }
    pub fn flush(&self) {
        self.entries.flush();
    }
    pub fn close(&self) {
        self.entries.close();
    }
    pub async fn close_and_wait(&self) {
        self.entries.close_and_wait().await;
    }
    #[cfg(test)]
    fn update_for_test(&self, key: &Key, f: impl FnOnce(&mut Item)) {
        self.entries
            .update_for_test(key.clone(), |value| f(Arc::make_mut(value)));
    }
}
pub fn map_ttl(r: &mut Message, f: impl Fn(u32) -> u32) {
    for section in 0..3 {
        let records = match section {
            0 => r.answers_mut(),
            1 => r.name_servers_mut(),
            _ => r.additionals_mut(),
        };
        for rr in records {
            if rr.record_type() != RecordType::OPT {
                rr.set_ttl(f(rr.ttl()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::query_context::reply;
    use hickory_proto::{
        op::Query,
        rr::{rdata::A, Name, RData, Record},
    };

    fn context_and_answer(ttl: u32, code: ResponseCode) -> (QueryContext, Message) {
        let mut query = Message::new();
        query.add_query(Query::query(
            Name::from_ascii("cache-aging.test.").unwrap(),
            RecordType::A,
        ));
        let context = QueryContext::new(query, "127.0.0.1".parse().unwrap());
        let mut response = reply(&context.query, code);
        if code == ResponseCode::NoError {
            response.add_answer(Record::from_rdata(
                Name::from_ascii("cache-aging.test.").unwrap(),
                ttl,
                RData::A(A("192.0.2.1".parse().unwrap())),
            ));
        }
        (context, response)
    }

    #[test]
    fn positive_cache_ages_ttl_and_expires_at_the_original_deadline() {
        let cache = Cache::new(8, 0);
        let (context, response) = context_and_answer(20, ResponseCode::NoError);
        let key = Cache::key(&context).unwrap();
        cache.store(key.clone(), &response);
        cache.update_for_test(&key, |item| {
            item.stored = Instant::now() - Duration::from_secs(10)
        });
        let (response, lazy) = cache.lookup(&key);
        assert!(!lazy);
        assert_eq!(response.unwrap().answers()[0].ttl(), 10);
        cache.update_for_test(&key, |item| {
            item.stored = Instant::now() - Duration::from_secs(20)
        });
        assert!(cache.lookup(&key).0.is_none());
        assert_eq!(cache.entries.len(), 0);
    }

    #[test]
    fn small_capacity_keeps_go_unlimited_shard_boundary() {
        let cache = Cache::new(1, 0);
        let (context, response) = context_and_answer(20, ResponseCode::NoError);
        let original = Cache::key(&context).unwrap();
        for index in 0..3 {
            let mut key = original.clone();
            key.name = format!("capacity-{index}.test.");
            cache.store(key, &response);
        }
        assert_eq!(
            cache.entries.len(),
            3,
            "Go size/64 is zero: no capacity eviction"
        );
    }
    #[test]
    fn unrepresentable_cache_lifetime_is_not_stored() {
        let cache = Cache::new(1, u64::MAX);
        let (context, response) = context_and_answer(20, ResponseCode::NoError);
        cache.store(Cache::key(&context).unwrap(), &response);
        assert_eq!(cache.entries.len(), 0);
    }

    #[test]
    fn lazy_cache_returns_ttl_five_after_message_expiry() {
        let cache = Cache::new(8, 100);
        let (context, response) = context_and_answer(20, ResponseCode::NoError);
        let key = Cache::key(&context).unwrap();
        cache.store(key.clone(), &response);
        cache.update_for_test(&key, |item| {
            item.stored = Instant::now() - Duration::from_secs(25)
        });
        let (response, lazy) = cache.lookup(&key);
        assert!(lazy);
        assert_eq!(response.unwrap().answers()[0].ttl(), 5);
        #[cfg(feature = "full")]
        assert_eq!(cache.stats().lazy_hits, 1);
        cache.update_for_test(&key, |item| {
            item.stored = Instant::now() - Duration::from_secs(100)
        });
        assert!(cache.lookup(&key).0.is_none());
    }

    #[test]
    fn negative_expirations_and_non_cacheable_responses_match_go() {
        for (code, seconds) in [(ResponseCode::NXDomain, 30), (ResponseCode::ServFail, 5)] {
            let cache = Cache::new(8, 100);
            let (context, response) = context_and_answer(20, code);
            let key = Cache::key(&context).unwrap();
            cache.store(key.clone(), &response);
            assert!(cache.lookup(&key).0.is_some());
            cache.update_for_test(&key, |item| {
                item.stored = Instant::now() - Duration::from_secs(seconds)
            });
            assert!(cache.lookup(&key).0.is_none());
        }
        for (ttl, code, truncated) in [
            (0, ResponseCode::NoError, false),
            (20, ResponseCode::Refused, false),
            (20, ResponseCode::NoError, true),
        ] {
            let cache = Cache::new(8, 0);
            let (context, mut response) = context_and_answer(ttl, code);
            response.set_truncated(truncated);
            cache.store(Cache::key(&context).unwrap(), &response);
            assert_eq!(cache.entries.len(), 0);
        }
    }
}
// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(feature = "full")]
mod dump;
