// SPDX-License-Identifier: GPL-3.0-or-later
//! Expiring cache above the original sharded map. Values are cloned after
//! releasing the shard lock; use Arc values for pointer semantics like Go.
use super::concurrent_map::{Hashable, Map, Update};
use std::{
    convert::Infallible,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;

pub struct Opts {
    pub size: usize,
    pub cleaner_interval: Duration,
}
impl Default for Opts {
    fn default() -> Self {
        Self {
            size: 1024,
            cleaner_interval: Duration::from_secs(10),
        }
    }
}
struct Entry<V> {
    value: V,
    expiration: Instant,
}
#[derive(Default)]
struct CleanerState {
    started: bool,
    stopped: bool,
}
#[derive(Default)]
struct CleanerControl {
    closed: AtomicBool,
    started: AtomicBool,
    state: Mutex<CleanerState>,
    close_notify: Notify,
    changed: Notify,
}
struct CleanerGuard(Arc<CleanerControl>);
impl Drop for CleanerGuard {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.stopped = true;
        state.started = false;
        self.0.started.store(false, Ordering::Release);
        self.0.changed.notify_waiters();
    }
}
pub struct Cache<K, V> {
    map: Map<K, Arc<Entry<V>>>,
    interval: Duration,
    cleaner: Arc<CleanerControl>,
}
impl<K: Hashable + Send + Sync + 'static, V: Clone + Send + Sync + 'static> Cache<K, V> {
    pub fn new(opts: Opts) -> Arc<Self> {
        let cache = Arc::new(Self {
            map: Map::new_cache(if opts.size == 0 { 1024 } else { opts.size }),
            interval: if opts.cleaner_interval.is_zero() {
                Duration::from_secs(10)
            } else {
                opts.cleaner_interval
            },
            cleaner: Arc::new(CleanerControl::default()),
        });
        cache.start_cleaner();
        cache
    }
    fn start_cleaner(self: &Arc<Self>) {
        if self.cleaner.started.load(Ordering::Acquire)
            || self.cleaner.closed.load(Ordering::Acquire)
        {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let mut state = self.cleaner.state.lock().unwrap();
        if state.started || self.cleaner.closed.load(Ordering::Acquire) {
            return;
        }
        state.started = true;
        state.stopped = false;
        self.cleaner.started.store(true, Ordering::Release);
        let cache = Arc::downgrade(self);
        let control = self.cleaner.clone();
        let interval = self.interval;
        // Guard exists before spawning, so abort/runtime destruction also
        // wakes close waiters. The task holds no strong Cache during sleep.
        let guard = CleanerGuard(control.clone());
        handle.spawn(async move {
            let _guard = guard;
            let mut ticker =
                tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let closed = control.close_notify.notified();
                tokio::pin!(closed);
                closed.as_mut().enable();
                if control.closed.load(Ordering::Acquire) {
                    break;
                }
                tokio::select! {
                    _ = closed => break,
                    _ = ticker.tick() => {
                        let Some(cache) = cache.upgrade() else { break; };
                        cache.gc(Instant::now());
                    }
                }
            }
        });
    }
    pub fn get(self: &Arc<Self>, key: &K) -> Option<(V, Instant)> {
        self.start_cleaner();
        let entry = self.map.get(key)?;
        if entry.expiration <= Instant::now() {
            // Avoid deleting a replacement stored after this reader's load.
            self.map.test_and_set(key.clone(), |current| {
                if current.is_some_and(|current| Arc::ptr_eq(current, &entry)) {
                    Update::Delete
                } else {
                    Update::Keep
                }
            });
            return None;
        }
        Some((entry.value.clone(), entry.expiration))
    }
    pub fn store(self: &Arc<Self>, key: K, value: V, expiration: Instant) {
        self.start_cleaner();
        if expiration < Instant::now() {
            return;
        }
        self.map.set(key, Arc::new(Entry { value, expiration }));
    }
    pub fn range<E>(&self, mut f: impl FnMut(&K, &V, Instant) -> Result<(), E>) -> Result<(), E> {
        self.map
            .range(|key, entry| f(key, &entry.value, entry.expiration))
    }
    pub fn gc(&self, now: Instant) {
        let _: Result<(), Infallible> = self.map.range_do(|_, entry| {
            Ok(if entry.expiration < now {
                Update::Delete
            } else {
                Update::Keep
            })
        });
    }
    pub fn len(&self) -> usize {
        self.map.len()
    }
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
    pub fn flush(&self) {
        self.map.flush();
    }
    pub fn del(&self, key: &K) {
        self.map.del(key);
    }
    pub fn del_if(&self, key: &K, predicate: impl FnOnce(&V) -> bool) {
        self.map.test_and_set(key.clone(), |current| {
            if current.is_some_and(|entry| predicate(&entry.value)) {
                Update::Delete
            } else {
                Update::Keep
            }
        });
    }
    /// Closing stops only the automatic cleaner, matching Go's public API.
    pub fn close(&self) {
        let _state = self.cleaner.state.lock().unwrap();
        self.cleaner.closed.store(true, Ordering::Release);
        self.cleaner.close_notify.notify_waiters();
    }
    pub async fn close_and_wait(&self) {
        self.close();
        loop {
            let changed = self.cleaner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            {
                let state = self.cleaner.state.lock().unwrap();
                if !state.started || state.stopped {
                    return;
                }
            }
            changed.await;
        }
    }
    #[cfg(test)]
    pub(crate) fn update_for_test(&self, key: K, f: impl FnOnce(&mut V)) {
        self.map.test_and_set(key, |entry| {
            let entry = entry.unwrap();
            let mut value = entry.value.clone();
            f(&mut value);
            Update::Set(Arc::new(Entry {
                value,
                expiration: entry.expiration,
            }))
        });
    }
}
impl<K, V> Drop for Cache<K, V> {
    fn drop(&mut self) {
        self.cleaner.closed.store(true, Ordering::Release);
        self.cleaner.close_notify.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[derive(Clone, Copy, Eq, Hash, PartialEq)]
    struct Key(u64);
    impl Hashable for Key {
        fn sum(&self) -> u64 {
            self.0
        }
    }
    #[derive(Deserialize)]
    struct Fixture {
        expired_store_ms: i64,
        live_store_ms: u64,
    }
    #[test]
    fn shared_go_expiration_fixture_and_close_contract() {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../../../tests/fixtures/cache_backend.json"))
                .unwrap();
        let cache = Cache::new(Opts {
            size: 64,
            ..Opts::default()
        });
        let now = Instant::now();
        cache.store(
            Key(0),
            7,
            now - Duration::from_millis(fixture.expired_store_ms.unsigned_abs()),
        );
        assert!(cache.is_empty());
        cache.store(
            Key(0),
            9,
            now + Duration::from_millis(fixture.live_store_ms),
        );
        assert_eq!(cache.get(&Key(0)).unwrap().0, 9);
        cache.gc(now + Duration::from_millis(fixture.live_store_ms + 1));
        assert!(cache.is_empty());
        cache.close();
        cache.close();
        cache.store(Key(1), 11, now + Duration::from_secs(60));
        assert_eq!(cache.get(&Key(1)).unwrap().0, 11);
    }
    #[tokio::test(start_paused = true)]
    async fn cleaner_expires_untouched_entries_and_closes_without_waiting_for_tick() {
        let cache = Cache::new(Opts {
            size: 64,
            cleaner_interval: Duration::from_secs(10),
        });
        cache.store(Key(0), 7, Instant::now() + Duration::from_secs(60));
        // std Instant is the cache's monotonic clock; GC can be tested with
        // an explicit instant while Tokio's timer test verifies wake/close.
        cache.gc(Instant::now() + Duration::from_secs(61));
        assert!(cache.is_empty());
        tokio::time::timeout(Duration::from_millis(1), cache.close_and_wait())
            .await
            .unwrap();
        assert!(cache.cleaner.state.lock().unwrap().stopped);
    }
    #[tokio::test]
    async fn cleaner_starts_after_synchronous_construction_and_drop_wakes_it() {
        let cache = std::thread::spawn(|| Cache::<Key, i32>::new(Opts::default()))
            .join()
            .unwrap();
        assert!(!cache.cleaner.state.lock().unwrap().started);
        cache.store(Key(0), 1, Instant::now() + Duration::from_secs(60));
        assert!(cache.cleaner.state.lock().unwrap().started);
        let control = cache.cleaner.clone();
        let weak = Arc::downgrade(&cache);
        drop(cache);
        assert!(weak.upgrade().is_none());
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let changed = control.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if control.state.lock().unwrap().stopped {
                    break;
                }
                changed.await;
            }
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn cancelled_and_concurrent_close_waiters_still_finish() {
        let cache = Cache::<Key, i32>::new(Opts::default());
        let cancelled = tokio::spawn({
            let cache = cache.clone();
            async move { cache.close_and_wait().await }
        });
        cancelled.abort();
        let a = cache.close_and_wait();
        let b = cache.close_and_wait();
        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(a, b);
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn automatic_cleaner_removes_expired_entries_without_a_lookup() {
        let cache = Cache::new(Opts {
            size: 64,
            cleaner_interval: Duration::from_millis(10),
        });
        cache.store(Key(0), 7, Instant::now() + Duration::from_millis(15));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !cache.is_empty() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        cache.close_and_wait().await;
    }

    #[test]
    fn stale_reader_cannot_delete_a_replacement() {
        let cache = Cache::new(Opts::default());
        let old = Arc::new(7);
        cache.store(
            Key(0),
            old.clone(),
            Instant::now() + Duration::from_secs(60),
        );
        cache.store(
            Key(0),
            Arc::new(9),
            Instant::now() + Duration::from_secs(60),
        );
        cache.del_if(&Key(0), |current| Arc::ptr_eq(current, &old));
        assert_eq!(*cache.get(&Key(0)).unwrap().0, 9);
    }
}
