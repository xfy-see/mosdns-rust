//! Optional upstream observation, shared by all clones of the upstream.

use std::{
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, Notify},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    ConnOpen,
    ConnClose,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryOutcome {
    Success,
    Error,
    Cancelled,
}

/// Callbacks run synchronously and may run concurrently on different workers.
/// Implementations should keep them short and must synchronize shared state.
/// UDP, TCP, TLS and DoH report one pair per physical connection, including
/// sockets whose TLS negotiation fails. TLS deliberately avoids Go's duplicate
/// raw/TLS wrapper events. DoQ and HTTP/3 emit no connection events, as in Go.
/// Query callbacks count each outer exchange once; internal retries, fallback
/// and bootstrap do not create additional query observations. Dropping an
/// unfinished exchange reports `Cancelled`; a deadline failure reports `Error`.
pub trait EventObserver: Send + Sync {
    fn on_event(&self, event: Event);
    fn query_started(&self) {}
    fn query_finished(&self, _outcome: QueryOutcome, _elapsed: Duration) {}
}

#[derive(Default)]
pub(super) struct Lifecycle {
    pub(super) observer: Option<Arc<dyn EventObserver>>,
    pub(super) closed: AtomicBool,
    pub(super) closing: Notify,
    pub(super) close_lock: Mutex<()>,
    active: AtomicUsize,
    drained: Notify,
}

pub(super) struct ActiveQuery<'a>(&'a Lifecycle);
impl Lifecycle {
    pub(super) fn new(observer: Option<Arc<dyn EventObserver>>) -> Self {
        Self {
            observer,
            ..Self::default()
        }
    }
    pub(super) fn enter(&self) -> Option<ActiveQuery<'_>> {
        if self.closed.load(Ordering::Acquire) {
            return None;
        }
        self.active.fetch_add(1, Ordering::AcqRel);
        let active = ActiveQuery(self);
        // A close can race the first closed check. No backend operation may
        // start after the shared close flag has been published.
        if self.closed.load(Ordering::Acquire) {
            None
        } else {
            Some(active)
        }
    }
    pub(super) async fn wait_drained(&self) {
        loop {
            let drained = self.drained.notified();
            tokio::pin!(drained);
            drained.as_mut().enable();
            if self.active.load(Ordering::Acquire) == 0 {
                return;
            }
            drained.await;
        }
    }
}
impl Drop for ActiveQuery<'_> {
    fn drop(&mut self) {
        if self.0.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.drained.notify_waiters();
        }
    }
}

pub(super) struct QueryGuard<'a> {
    observer: &'a dyn EventObserver,
    start: Instant,
    completed: bool,
}
impl<'a> QueryGuard<'a> {
    pub(super) fn start(observer: &'a dyn EventObserver) -> Self {
        observer.query_started();
        Self {
            observer,
            start: Instant::now(),
            completed: false,
        }
    }
    pub(super) fn finish(&mut self, outcome: QueryOutcome) {
        self.completed = true;
        self.observer.query_finished(outcome, self.start.elapsed());
    }
}
impl Drop for QueryGuard<'_> {
    fn drop(&mut self) {
        if !self.completed {
            self.observer
                .query_finished(QueryOutcome::Cancelled, self.start.elapsed());
        }
    }
}

pub(super) struct ConnectionGuard {
    observer: Arc<dyn EventObserver>,
    closed: AtomicBool,
}
impl ConnectionGuard {
    pub(super) fn open(observer: &Option<Arc<dyn EventObserver>>) -> Option<Arc<Self>> {
        observer.as_ref().map(|observer| {
            observer.on_event(Event::ConnOpen);
            Arc::new(Self {
                observer: observer.clone(),
                closed: AtomicBool::new(false),
            })
        })
    }
    pub(super) fn close(&self) {
        if !self.closed.swap(true, Ordering::AcqRel) {
            self.observer.on_event(Event::ConnClose);
        }
    }
}
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.close();
    }
}
pub(super) fn close_connection(event: &Option<Arc<ConnectionGuard>>) {
    if let Some(event) = event {
        event.close();
    }
}

/// Reports physical socket closure even during TLS negotiation or driver EOF.
pub(super) struct ObservedIo<S> {
    inner: S,
    event: Option<Arc<ConnectionGuard>>,
}
impl<S> ObservedIo<S> {
    pub(super) fn new(inner: S, event: Option<Arc<ConnectionGuard>>) -> Self {
        Self { inner, event }
    }
}
impl<S> std::ops::Deref for ObservedIo<S> {
    type Target = S;
    fn deref(&self) -> &S {
        &self.inner
    }
}
impl<S> Drop for ObservedIo<S> {
    fn drop(&mut self) {
        close_connection(&self.event);
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for ObservedIo<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedIo<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Observer {
        opened: AtomicUsize,
        closed: AtomicUsize,
    }
    impl EventObserver for Observer {
        fn on_event(&self, event: Event) {
            match event {
                Event::ConnOpen => self.opened.fetch_add(1, Ordering::SeqCst),
                Event::ConnClose => self.closed.fetch_add(1, Ordering::SeqCst),
            };
        }
    }
    #[test]
    fn socket_driver_and_transport_close_races_emit_a_single_close() {
        assert!(ConnectionGuard::open(&None).is_none());
        let observer = Arc::new(Observer::default());
        let event =
            ConnectionGuard::open(&Some(observer.clone() as Arc<dyn EventObserver>)).unwrap();
        std::thread::scope(|scope| {
            for _ in 0..32 {
                let event = event.clone();
                scope.spawn(move || event.close());
            }
        });
        drop(event);
        assert_eq!(observer.opened.load(Ordering::SeqCst), 1);
        assert_eq!(observer.closed.load(Ordering::SeqCst), 1);
    }
}
