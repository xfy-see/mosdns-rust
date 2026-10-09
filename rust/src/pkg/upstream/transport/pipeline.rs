//! Reserve each query before dialing, as Go's lazy pipeline connections do.

use super::{per_connection_limit, PoolCleaner, Protocol, Session, Transport};
use anyhow::{anyhow, bail, Result};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, Weak,
};
use std::time::Duration;
use tokio::sync::{Mutex as AsyncMutex, OwnedSemaphorePermit, Semaphore};

pub(super) type ConnectionPool = Mutex<Vec<Arc<Slot>>>;

pub(super) struct Slot {
    pub(super) alive: Arc<AtomicBool>,
    pub(super) limit: Arc<Semaphore>,
    pub(super) session: AsyncMutex<Option<Arc<Session>>>,
    connected: AtomicBool,
    capacity: usize,
}

#[derive(Default)]
pub(super) struct PipelinePool {
    pub(super) slots: Arc<ConnectionPool>,
}

impl PipelinePool {
    pub(super) async fn close(&self) {
        let slots = std::mem::take(&mut *self.slots.lock().unwrap());
        for slot in slots {
            slot.alive.store(false, Ordering::Release);
            if let Some(session) = slot.session.lock().await.as_ref() {
                session.close("DNS upstream closed");
            }
        }
    }
    pub(super) fn reserve(&self, protocol: Protocol) -> Lease {
        let mut slots = self.slots.lock().unwrap();
        slots.retain(|slot| slot.alive.load(Ordering::Acquire));
        for slot in slots.iter() {
            if let Ok(permit) = slot.limit.clone().try_acquire_owned() {
                return Lease {
                    slot: slot.clone(),
                    is_new: false,
                    permit: Some(permit),
                    pool: Arc::downgrade(&self.slots),
                };
            }
        }
        let capacity = per_connection_limit(protocol);
        let slot = Arc::new(Slot {
            alive: Arc::new(AtomicBool::new(true)),
            limit: Arc::new(Semaphore::new(capacity)),
            session: AsyncMutex::new(None),
            connected: AtomicBool::new(false),
            capacity,
        });
        let permit = slot
            .limit
            .clone()
            .try_acquire_owned()
            .expect("new connection has query slots");
        slots.push(slot.clone());
        Lease {
            slot,
            is_new: true,
            permit: Some(permit),
            pool: Arc::downgrade(&self.slots),
        }
    }
}

pub(super) struct Lease {
    pub(super) slot: Arc<Slot>,
    pub(super) is_new: bool,
    permit: Option<OwnedSemaphorePermit>,
    pool: Weak<ConnectionPool>,
}

impl Lease {
    pub(super) async fn session(&self, transport: &Transport) -> Result<Arc<Session>> {
        let mut stored = self.slot.session.lock().await;
        if !self.slot.alive.load(Ordering::Acquire) {
            bail!("upstream connection closed");
        }
        if let Some(session) = stored.as_ref() {
            return Ok(session.clone());
        }
        let connected = tokio::time::timeout(
            Duration::from_secs(5),
            Session::connect(
                transport.protocol,
                &transport.host,
                &transport.dialer,
                #[cfg(feature = "full")]
                transport.tls_config.clone(),
                transport.idle_timeout,
                Some(PoolCleaner::Pipeline(self.pool.clone())),
                Some((self.slot.limit.clone(), self.slot.alive.clone())),
                &transport.observer,
            ),
        )
        .await
        .unwrap_or_else(|_| Err(anyhow!("upstream connection dial timeout")));
        match connected {
            Ok(session) => {
                let session = Arc::new(session);
                *stored = Some(session.clone());
                self.slot.connected.store(true, Ordering::Release);
                Ok(session)
            }
            Err(error) => {
                self.slot.alive.store(false, Ordering::Release);
                Err(error)
            }
        }
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        // Reserve and prune use the same lock. If the last dialing waiter is
        // cancelled, the uninitialized slot must not accumulate in the pool.
        if let Some(pool) = self.pool.upgrade() {
            let mut slots = pool.lock().unwrap();
            self.permit.take();
            if !self.slot.connected.load(Ordering::Acquire)
                && self.slot.limit.available_permits() == self.slot.capacity
            {
                self.slot.alive.store(false, Ordering::Release);
            }
            slots.retain(|slot| slot.alive.load(Ordering::Acquire));
        }
    }
}
