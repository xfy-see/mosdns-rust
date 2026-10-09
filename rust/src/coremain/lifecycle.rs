//! Explicit Engine-wide shutdown; Drop only releases Rust ownership.
use super::registry::PluginCloser;
use anyhow::{anyhow, Result};
use std::{
    any::Any,
    collections::HashSet,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Arc, Mutex},
};
use tokio::sync::{watch, Notify};

#[derive(Clone)]
pub(crate) struct CloseEntry {
    pub tag: String,
    pub closer: Arc<dyn PluginCloser>,
}
impl CloseEntry {
    pub fn identity(&self) -> usize {
        Arc::as_ptr(&self.closer) as *const () as usize
    }
}

pub(crate) fn panic_message(value: Box<dyn Any + Send>) -> String {
    if let Some(message) = value.downcast_ref::<&str>() {
        (*message).to_owned()
    } else if let Some(message) = value.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic".into()
    }
}
/// No async cleanup in Drop. Startup invokes this explicitly on its caller;
/// normal shutdown invokes it on a blocking worker after all tracked work exits.
pub(crate) fn close_entries(entries: &[CloseEntry], protected: &HashSet<usize>) -> Vec<String> {
    let mut seen = protected.clone();
    let mut errors = Vec::new();
    for entry in entries.iter().rev() {
        if !seen.insert(entry.identity()) {
            continue;
        }
        match catch_unwind(AssertUnwindSafe(|| entry.closer.close())) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => errors.push(format!("close plugin {}: {error:#}", entry.tag)),
            Err(panic) => errors.push(format!(
                "close plugin {} panicked: {}",
                entry.tag,
                panic_message(panic)
            )),
        }
    }
    errors
}

#[derive(Default)]
struct Status {
    closing: bool,
    coordinator_started: bool,
    active: usize,
    cause: Option<String>,
    cleanup_errors: Vec<String>,
    completed: Option<std::result::Result<(), String>>,
}
pub(crate) struct Lifecycle {
    status: Mutex<Status>,
    signal: watch::Sender<bool>,
    changed: Notify,
}
impl Lifecycle {
    pub fn new() -> Arc<Self> {
        let (signal, _) = watch::channel(false);
        Arc::new(Self {
            status: Mutex::new(Status::default()),
            signal,
            changed: Notify::new(),
        })
    }
    pub fn signal(&self) -> watch::Receiver<bool> {
        self.signal.subscribe()
    }
    pub fn request(&self, error: Option<String>) -> bool {
        let mut status = self.status.lock().unwrap();
        if status.closing {
            return false;
        }
        status.closing = true;
        status.cause = error;
        self.signal.send_replace(true);
        true
    }
    pub fn service_failed(&self, error: String) {
        let mut status = self.status.lock().unwrap();
        if status.closing {
            // Preserve the first close cause; a service failure during drain is
            // still a cleanup failure, even if normal shutdown won the race.
            status.cleanup_errors.push(error);
        } else {
            status.closing = true;
            status.cause = Some(error);
            self.signal.send_replace(true);
        }
    }
    pub fn enter(self: &Arc<Self>) -> Result<WorkGuard> {
        let mut status = self.status.lock().unwrap();
        if status.closing {
            return Err(anyhow!("engine is shutting down"));
        }
        status.active += 1;
        Ok(WorkGuard(self.clone()))
    }
    /// Called only by an already tracked query, or while startup schedules services.
    /// Active parents may fork after the close signal: draining still owns them.
    pub fn fork(self: &Arc<Self>) -> WorkGuard {
        let mut status = self.status.lock().unwrap();
        assert!(
            status.completed.is_none(),
            "work attached after Engine shutdown"
        );
        status.active += 1;
        WorkGuard(self.clone())
    }
    pub fn start_coordinator(&self) -> bool {
        let mut status = self.status.lock().unwrap();
        if status.coordinator_started {
            return false;
        }
        status.coordinator_started = true;
        true
    }
    pub async fn drain(&self) {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.status.lock().unwrap().active == 0 {
                return;
            }
            changed.await;
        }
    }
    pub fn finish(&self, mut errors: Vec<String>) {
        let mut status = self.status.lock().unwrap();
        errors.append(&mut status.cleanup_errors);
        if let Some(cause) = &status.cause {
            errors.insert(0, cause.clone());
        }
        status.completed = Some(if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        });
        drop(status);
        self.changed.notify_waiters();
    }
    pub async fn wait_finished(&self) -> Result<()> {
        loop {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(result) = self.status.lock().unwrap().completed.clone() {
                return result.map_err(anyhow::Error::msg);
            }
            changed.await;
        }
    }
}
pub(crate) struct WorkGuard(Arc<Lifecycle>);
impl Drop for WorkGuard {
    fn drop(&mut self) {
        let mut status = self.0.status.lock().unwrap();
        status.active -= 1;
        let idle = status.active == 0;
        drop(status);
        if idle {
            self.0.changed.notify_waiters();
        }
    }
}
