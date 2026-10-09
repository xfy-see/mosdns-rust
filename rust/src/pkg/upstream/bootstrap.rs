// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

//! IP-only DNS bootstrap, with single-flight updates and stale address reuse.

use super::validate_response;
use anyhow::{bail, Context, Result};
use hickory_proto::{
    op::{Edns, Message, Query},
    rr::{Name, RData, RecordType},
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::Notify};

pub(super) fn parse_server(address: &str) -> Result<SocketAddr> {
    let server = if let Ok(ip) = address.parse::<IpAddr>() {
        SocketAddr::new(ip, 53)
    } else if let Some(ip) = address.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        SocketAddr::new(ip.parse().context("bootstrap must be an IP address")?, 53)
    } else {
        address
            .parse()
            .context("bootstrap must be an IP address with optional port")?
    };
    if server.port() == 0 {
        bail!("bootstrap port must be nonzero");
    }
    Ok(server)
}

pub(super) struct Bootstrap {
    name: Name,
    port: u16,
    server: SocketAddr,
    record_type: RecordType,
    state: Mutex<State>,
    updating: AtomicBool,
    changed: Notify,
}

struct State {
    address: Option<SocketAddr>,
    next_update: Instant,
    error: Option<String>,
}

impl Bootstrap {
    pub(super) fn new(
        host: &str,
        port: u16,
        server: SocketAddr,
        version: i64,
    ) -> Result<Arc<Self>> {
        let record_type = match version {
            0 | 4 => RecordType::A,
            6 => RecordType::AAAA,
            other => bail!("invalid bootstrap version {other}"),
        };
        Ok(Arc::new(Self {
            name: Name::from_utf8(host).context("invalid bootstrap hostname")?,
            port,
            server,
            record_type,
            state: Mutex::new(State {
                address: None,
                next_update: Instant::now(),
                error: None,
            }),
            updating: AtomicBool::new(false),
            changed: Notify::new(),
        }))
    }

    pub(super) async fn resolve(self: &Arc<Self>) -> Result<SocketAddr> {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.state.lock().unwrap();
                if state.next_update <= Instant::now()
                    && !self.updating.swap(true, Ordering::AcqRel)
                {
                    state.error = None;
                    let bootstrap = self.clone();
                    tokio::spawn(async move {
                        let result =
                            tokio::time::timeout(Duration::from_secs(5), bootstrap.query()).await;
                        let result = result
                            .context("bootstrap query timeout")
                            .and_then(|result| result);
                        let mut state = bootstrap.state.lock().unwrap();
                        match result {
                            Ok((ip, ttl)) => {
                                state.address = Some(SocketAddr::new(ip, bootstrap.port));
                                state.next_update =
                                    Instant::now() + Duration::from_secs(u64::from(ttl).max(300));
                                state.error = None;
                            }
                            Err(error) => {
                                state.next_update = Instant::now() + Duration::from_secs(2);
                                state.error = Some(format!("{error:#}"));
                            }
                        }
                        bootstrap.updating.store(false, Ordering::Release);
                        drop(state);
                        bootstrap.changed.notify_waiters();
                    });
                }
                if let Some(address) = state.address {
                    return Ok(address);
                }
                if let Some(error) = &state.error {
                    bail!("bootstrap failed: {error}");
                }
            }
            notified.await;
        }
    }

    async fn query(&self) -> Result<(IpAddr, u32)> {
        let mut query = Message::new();
        query
            .set_id(rand::random())
            .set_recursion_desired(true)
            .add_query(Query::query(self.name.clone(), self.record_type))
            .set_edns(Edns::new().set_max_payload(1200).clone());
        // Bootstrap itself deliberately uses plain DNS and the default route,
        // matching Go; upstream socket/proxy settings apply to the final dial.
        let bind = if self.server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)
            .await
            .context("bind bootstrap socket")?;
        socket
            .connect(self.server)
            .await
            .context("connect bootstrap DNS")?;
        let payload = query.to_vec()?;
        let mut retry = tokio::time::interval(Duration::from_secs(1));
        let mut buffer = [0; 65535];
        loop {
            tokio::select! {
                _ = retry.tick() => { socket.send(&payload).await.context("send bootstrap query")?; }
                length = socket.recv(&mut buffer) => {
                    let response = Message::from_vec(&buffer[..length.context("read bootstrap response")?])?;
                    validate_response(&query, &response)?;
                    for record in response.answers() {
                        let ip = match record.data() {
                            Some(RData::A(ip)) => IpAddr::V4(ip.0),
                            Some(RData::AAAA(ip)) => IpAddr::V6(ip.0),
                            _ => continue,
                        };
                        return Ok((ip, record.ttl()));
                    }
                    bail!("bootstrap response has no IP address");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{
        op::{MessageType, ResponseCode},
        rr::{rdata::A, Record},
    };
    use tokio::sync::oneshot;

    fn response(query: &[u8], ip: Option<&str>) -> Vec<u8> {
        let mut message = Message::from_vec(query).unwrap();
        message.set_message_type(MessageType::Response);
        if let Some(ip) = ip {
            message.add_answer(Record::from_rdata(
                message.queries()[0].name().clone(),
                1,
                RData::A(A(ip.parse().unwrap())),
            ));
        } else {
            message.set_response_code(ResponseCode::NXDomain);
        }
        message.to_vec().unwrap()
    }

    async fn finish_update(bootstrap: &Bootstrap) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while bootstrap.updating.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn cancelling_the_first_waiter_keeps_the_shared_lookup_alive() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bootstrap =
            Bootstrap::new("bootstrap.example.", 853, socket.local_addr().unwrap(), 4).unwrap();
        let (received, receive) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let reply = response(&buffer[..length], Some("192.0.2.1"));
            received.send(()).unwrap();
            released.await.unwrap();
            socket.send_to(&reply, peer).await.unwrap();
        });
        let first = bootstrap.clone();
        let first = tokio::spawn(async move { first.resolve().await });
        receive.await.unwrap();
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert!(bootstrap.updating.load(Ordering::Acquire));
        release.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), bootstrap.resolve())
                .await
                .unwrap()
                .unwrap(),
            "192.0.2.1:853".parse().unwrap()
        );
        assert!(!bootstrap.updating.load(Ordering::Acquire));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn failed_initial_lookup_backs_off_then_recovers() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bootstrap =
            Bootstrap::new("bootstrap.example.", 853, socket.local_addr().unwrap(), 4).unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            for ip in [None, Some("192.0.2.2")] {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                socket
                    .send_to(&response(&buffer[..length], ip), peer)
                    .await
                    .unwrap();
            }
        });
        assert!(bootstrap
            .resolve()
            .await
            .unwrap_err()
            .to_string()
            .contains("no IP address"));
        {
            let state = bootstrap.state.lock().unwrap();
            assert!(state.address.is_none());
            assert!(state.next_update > Instant::now());
        }
        // During the two-second backoff, another call returns the recorded
        // failure and must not start an extra DNS query.
        assert!(bootstrap.resolve().await.is_err());
        assert!(!bootstrap.updating.load(Ordering::Acquire));
        bootstrap.state.lock().unwrap().next_update = Instant::now();
        assert_eq!(
            bootstrap.resolve().await.unwrap(),
            "192.0.2.2:853".parse().unwrap()
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn failed_refresh_retains_stale_address_and_a_later_refresh_replaces_it() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bootstrap =
            Bootstrap::new("bootstrap.example.", 853, socket.local_addr().unwrap(), 4).unwrap();
        let server = tokio::spawn(async move {
            let mut buffer = [0; 4096];
            for ip in [Some("192.0.2.1"), None, Some("192.0.2.2")] {
                let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
                socket
                    .send_to(&response(&buffer[..length], ip), peer)
                    .await
                    .unwrap();
            }
        });
        let old = "192.0.2.1:853".parse().unwrap();
        assert_eq!(bootstrap.resolve().await.unwrap(), old);
        bootstrap.state.lock().unwrap().next_update = Instant::now();
        assert_eq!(bootstrap.resolve().await.unwrap(), old);
        finish_update(&bootstrap).await;
        assert!(bootstrap.state.lock().unwrap().error.is_some());
        assert_eq!(bootstrap.resolve().await.unwrap(), old);
        bootstrap.state.lock().unwrap().next_update = Instant::now();
        assert_eq!(bootstrap.resolve().await.unwrap(), old);
        finish_update(&bootstrap).await;
        assert_eq!(
            bootstrap.resolve().await.unwrap(),
            "192.0.2.2:853".parse().unwrap()
        );
        server.await.unwrap();
    }
}
