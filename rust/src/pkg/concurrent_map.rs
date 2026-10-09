// SPDX-License-Identifier: GPL-3.0-or-later
//! The original 64-shard map, including its per-shard capacity semantics.
use std::{collections::HashMap, hash::Hash, sync::RwLock};

pub const MAP_SHARD_SIZE: usize = 64;
pub trait Hashable: Eq + Hash + Clone {
    fn sum(&self) -> u64;
}
pub enum Update<V> {
    Keep,
    Set(V),
    Delete,
}
struct Shard<K, V> {
    entries: RwLock<HashMap<K, V>>,
    max: usize,
}
pub struct Map<K, V> {
    shards: [Shard<K, V>; MAP_SHARD_SIZE],
}
impl<K: Hashable, V> Default for Map<K, V> {
    fn default() -> Self {
        Self::new()
    }
}
impl<K: Hashable, V> Map<K, V> {
    pub fn new() -> Self {
        Self::new_cache(0)
    }
    /// A zero quotient is unlimited, including positive sizes below 64.
    pub fn new_cache(size: usize) -> Self {
        Self {
            shards: std::array::from_fn(|_| Shard {
                entries: RwLock::new(HashMap::new()),
                max: size / MAP_SHARD_SIZE,
            }),
        }
    }
    fn shard(&self, key: &K) -> &Shard<K, V> {
        &self.shards[(key.sum() % MAP_SHARD_SIZE as u64) as usize]
    }
    pub fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        self.shard(key).entries.read().unwrap().get(key).cloned()
    }
    pub fn set(&self, key: K, value: V) {
        let shard = self.shard(&key);
        let mut entries = shard.entries.write().unwrap();
        // Go checks capacity before assignment, including overwrites. Which
        // old entry is removed remains unspecified, as with Go map iteration.
        while shard.max > 0 && entries.len() >= shard.max {
            let victim = entries.keys().next().unwrap().clone();
            entries.remove(&victim);
        }
        entries.insert(key, value);
    }
    pub fn del(&self, key: &K) {
        self.shard(key).entries.write().unwrap().remove(key);
    }
    /// Like Go TestAndSet, this atomic operation does not enforce capacity.
    pub fn test_and_set(&self, key: K, f: impl FnOnce(Option<&V>) -> Update<V>) {
        let mut entries = self.shard(&key).entries.write().unwrap();
        match f(entries.get(&key)) {
            Update::Keep => {}
            Update::Set(value) => {
                entries.insert(key, value);
            }
            Update::Delete => {
                entries.remove(&key);
            }
        }
    }
    /// Callback runs under each shard's write lock; do not reenter this map.
    pub fn range_do<E>(&self, mut f: impl FnMut(&K, &V) -> Result<Update<V>, E>) -> Result<(), E> {
        for shard in &self.shards {
            let mut failure = None;
            shard.entries.write().unwrap().retain(|key, value| {
                if failure.is_some() {
                    return true;
                }
                match f(key, value) {
                    Ok(Update::Keep) => true,
                    Ok(Update::Set(next)) => {
                        *value = next;
                        true
                    }
                    Ok(Update::Delete) => false,
                    Err(error) => {
                        failure = Some(error);
                        true
                    }
                }
            });
            if let Some(error) = failure {
                return Err(error);
            }
        }
        Ok(())
    }
    /// Callback runs under each shard's read lock; do not mutate this map.
    pub fn range<E>(&self, mut f: impl FnMut(&K, &V) -> Result<(), E>) -> Result<(), E> {
        for shard in &self.shards {
            for (key, value) in shard.entries.read().unwrap().iter() {
                f(key, value)?;
            }
        }
        Ok(())
    }
    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.entries.read().unwrap().len())
            .sum()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn flush(&self) {
        // Go's Flush uses RLock for mutation. Rust uses the exclusive lock.
        for shard in &self.shards {
            shard.entries.write().unwrap().clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::sync::Arc;
    #[derive(Clone, Copy, Eq, Hash, PartialEq)]
    struct Key(u64);
    impl Hashable for Key {
        fn sum(&self) -> u64 {
            self.0
        }
    }
    #[derive(Deserialize)]
    struct Fixture {
        shards: usize,
        capacity_cases: Vec<Case>,
        collision_keys: Vec<u64>,
    }
    #[derive(Deserialize)]
    struct Case {
        size: usize,
        inserted: usize,
        expected: usize,
    }
    #[test]
    fn shared_go_capacity_fixture() {
        let fixture: Fixture =
            serde_json::from_str(include_str!("../../../tests/fixtures/cache_backend.json"))
                .unwrap();
        assert_eq!(fixture.shards, MAP_SHARD_SIZE);
        for case in fixture.capacity_cases {
            let map = Map::new_cache(case.size);
            for i in 0..case.inserted {
                map.set(Key(i as u64), i);
            }
            assert_eq!(map.len(), case.expected, "size {}", case.size);
            map.flush();
            assert!(map.is_empty());
        }
        let map = Map::new_cache(64);
        for (value, key) in fixture.collision_keys.into_iter().enumerate() {
            map.set(Key(key), value);
            assert_eq!(map.len(), 1);
            assert_eq!(map.get(&Key(key)), Some(value));
        }
        map.test_and_set(Key(0), |_| Update::Set(9));
        assert_eq!(map.len(), 2);
        assert_eq!(map.get(&Key(0)), Some(9));
    }
    #[test]
    fn range_updates_deletes_and_stops_on_error() {
        let map = Map::new();
        for i in 0..128 {
            map.set(Key(i), i);
        }
        map.range_do::<()>(|key, value| {
            Ok(if key.0 % 2 == 0 {
                Update::Set(value + 1)
            } else {
                Update::Delete
            })
        })
        .unwrap();
        assert_eq!(map.len(), 64);
        assert_eq!(map.get(&Key(0)), Some(1));
        let mut calls = 0;
        assert_eq!(
            map.range_do(|_, _| {
                calls += 1;
                Err::<Update<u64>, _>("stop")
            }),
            Err("stop")
        );
        assert_eq!(calls, 1);
    }
    #[test]
    fn concurrent_read_write_range_and_flush_remain_safe() {
        let map = Arc::new(Map::<Key, usize>::new_cache(1024));
        std::thread::scope(|scope| {
            for worker in 0..16 {
                let map = map.clone();
                scope.spawn(move || {
                    for i in 0..512 {
                        let key = Key((i + worker * 64) as u64);
                        map.set(key, i);
                        let _ = map.get(&key);
                        if i % 31 == 0 {
                            map.flush();
                        }
                        if i % 7 == 0 {
                            map.range_do::<()>(|_, _| Ok(Update::Keep)).unwrap();
                        }
                    }
                });
            }
        });
        assert!(map.len() <= 1024);
    }
}
