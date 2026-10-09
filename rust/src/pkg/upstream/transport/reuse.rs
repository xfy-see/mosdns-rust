// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

//! The Go reuse transport model: one in-flight query per reusable TCP socket.

use super::{Message, Mutex, Ordering, PoolCleaner, Result, Session, Transport};
use std::sync::Arc;

pub(super) type IdlePool = Mutex<Vec<Arc<Session>>>;

#[derive(Default)]
pub(super) struct ReusePool {
    idle: Arc<IdlePool>,
}

impl ReusePool {
    pub(super) fn close(&self) {
        let idle = std::mem::take(&mut *self.idle.lock().unwrap());
        for session in idle {
            session.close("DNS upstream closed");
        }
    }
    pub(super) async fn exchange(&self, transport: &Transport, query: &Message) -> Result<Message> {
        let mut retry = 0;
        loop {
            let session = {
                let mut idle = self.idle.lock().unwrap();
                idle.retain(|session| session.alive.load(Ordering::Acquire));
                idle.pop()
            };
            let is_new = session.is_none();
            let session = match session {
                Some(session) => session,
                None => Arc::new(
                    Session::connect(
                        transport.protocol,
                        &transport.host,
                        &transport.dialer,
                        #[cfg(feature = "full")]
                        transport.tls_config.clone(),
                        transport.idle_timeout,
                        Some(PoolCleaner::Reuse(Arc::downgrade(&self.idle))),
                        None,
                        &transport.observer,
                    )
                    .await?,
                ),
            };
            // The session is removed from the pool throughout this await.
            // Cancellation/error drops its only owner and closes the socket;
            // a later query must never consume this query's delayed response.
            let response = transport.exchange_on_session(&session, query).await;
            if response.is_ok() {
                if session.alive.load(Ordering::Acquire) {
                    self.idle.lock().unwrap().push(session);
                }
                return response;
            }
            drop(session);
            // Match reuse.go's bounded retries only for old pooled sockets.
            // A new connection's failure is returned immediately.
            if is_new || retry > 2 {
                return response;
            }
            retry += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkg::upstream::{transport::Protocol, Options};
    use hickory_proto::{
        op::{MessageType, Query},
        rr::{Name, RecordType},
    };
    use std::time::Duration;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[tokio::test]
    async fn idle_timeout_removes_dead_sessions_from_the_pool_without_another_query() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = stream.read_u16().await.unwrap();
            let mut payload = vec![0; length as usize];
            stream.read_exact(&mut payload).await.unwrap();
            let mut reply = Message::from_vec(&payload).unwrap();
            reply.set_message_type(MessageType::Response);
            let payload = reply.to_vec().unwrap();
            stream.write_u16(payload.len() as u16).await.unwrap();
            stream.write_all(&payload).await.unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), stream.read_u8())
                    .await
                    .unwrap()
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::UnexpectedEof
            );
        });
        let transport = Transport::new(Protocol::Tcp, "127.0.0.1".into(), address.port())
            .configure(&Options {
                idle_timeout: Duration::from_millis(30),
                ..Default::default()
            })
            .unwrap();
        let mut query = Message::new();
        query.add_query(Query::query(
            Name::from_ascii("pool-idle.example.").unwrap(),
            RecordType::A,
        ));
        transport.exchange(&query).await.unwrap();
        assert_eq!(transport.reuse.idle.lock().unwrap().len(), 1);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !transport.reuse.idle.lock().unwrap().is_empty() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn repeated_old_connection_failures_have_a_bounded_retry_budget() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = failures.clone();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            for _ in 0..5 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let observed = observed.clone();
                workers.spawn(async move {
                    let length = stream.read_u16().await.unwrap();
                    let mut payload = vec![0; length as usize];
                    stream.read_exact(&mut payload).await.unwrap();
                    observed.fetch_add(1, Ordering::Relaxed);
                    // Fail only after the reused connection has a query.
                });
            }
            // One pooled socket is deliberately never queried: the retry
            // budget must stop before consuming every available connection.
            for _ in 0..4 {
                workers.join_next().await.unwrap().unwrap();
            }
            stopped.await.unwrap();
            workers.abort_all();
        });
        let transport = Transport::new(Protocol::Tcp, "127.0.0.1".into(), address.port());
        for _ in 0..5 {
            let session = Session::connect(
                Protocol::Tcp,
                &transport.host,
                &transport.dialer,
                #[cfg(feature = "full")]
                None,
                Duration::from_secs(10),
                Some(PoolCleaner::Reuse(Arc::downgrade(&transport.reuse.idle))),
                None,
                &transport.observer,
            )
            .await
            .unwrap();
            transport.reuse.idle.lock().unwrap().push(Arc::new(session));
        }
        let mut query = Message::new();
        query.add_query(Query::query(
            Name::from_ascii("bounded-retry.example.").unwrap(),
            RecordType::A,
        ));
        assert!(
            tokio::time::timeout(Duration::from_secs(1), transport.exchange(&query))
                .await
                .unwrap()
                .is_err()
        );
        // Go reuse.go starts retry=0 and tests retry<=maxRetry (2), so a
        // chain of failing old sockets permits four total attempts.
        assert_eq!(failures.load(Ordering::Relaxed), 4);
        assert_eq!(transport.reuse.idle.lock().unwrap().len(), 1);
        stop.send(()).unwrap();
        server.await.unwrap();
    }
}
