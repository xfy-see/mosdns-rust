//! Native NETLINK_NETFILTER socket; no command line tools are involved.

use super::wire;
use anyhow::{bail, Result};
use std::time::Duration;

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use anyhow::Context;
    use std::{
        io, mem,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
        time::Instant,
    };

    pub struct Connection {
        descriptor: OwnedFd,
        pub port: u32,
        sequence: u32,
        timeout: Duration,
    }
    impl Connection {
        pub fn open(timeout: Duration) -> Result<Self> {
            if timeout.is_zero() {
                bail!("netlink request timeout must be positive");
            }
            // SAFETY: socket returns an owned descriptor; OwnedFd closes every
            // success/error path after ownership has been transferred.
            let raw = unsafe {
                libc::socket(
                    libc::AF_NETLINK,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    libc::NETLINK_NETFILTER,
                )
            };
            if raw < 0 {
                return Err(io::Error::last_os_error()).context("open NETLINK_NETFILTER socket");
            }
            let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
            let mut address: libc::sockaddr_nl = unsafe { mem::zeroed() };
            address.nl_family = libc::AF_NETLINK as u16;
            let length = mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t;
            // SAFETY: address is initialized and both pointer/length describe it.
            if unsafe { libc::bind(raw, (&address as *const libc::sockaddr_nl).cast(), length) } < 0
            {
                return Err(io::Error::last_os_error()).context("bind NETLINK_NETFILTER socket");
            }
            let mut length = length;
            if unsafe {
                libc::getsockname(
                    raw,
                    (&mut address as *mut libc::sockaddr_nl).cast(),
                    &mut length,
                )
            } < 0
            {
                return Err(io::Error::last_os_error()).context("get netlink port ID");
            }
            if length as usize != mem::size_of::<libc::sockaddr_nl>() {
                bail!("invalid netlink socket address length");
            }
            // Extended errors improve diagnostics but older kernels may reject
            // the option. They do not affect protocol correctness.
            let enabled: libc::c_int = 1;
            unsafe {
                libc::setsockopt(
                    raw,
                    libc::SOL_NETLINK,
                    libc::NETLINK_EXT_ACK,
                    (&enabled as *const libc::c_int).cast(),
                    mem::size_of_val(&enabled) as libc::socklen_t,
                );
            }
            Ok(Self {
                descriptor,
                port: address.nl_pid,
                sequence: rand::random(),
                timeout,
            })
        }
        pub fn next_sequence(&mut self) -> u32 {
            self.sequence = self.sequence.wrapping_add(1);
            if self.sequence == 0 {
                self.sequence = 1;
            }
            self.sequence
        }
        fn ready(&self, event: libc::c_short, deadline: Instant) -> Result<()> {
            loop {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .context("netlink request timeout")?;
                let milliseconds = remaining
                    .as_millis()
                    .saturating_add(1)
                    .min(i32::MAX as u128) as i32;
                let mut descriptor = libc::pollfd {
                    fd: self.descriptor.as_raw_fd(),
                    events: event,
                    revents: 0,
                };
                let result = unsafe { libc::poll(&mut descriptor, 1, milliseconds) };
                if result < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error).context("poll netlink socket");
                }
                if result == 0 {
                    bail!("netlink request timeout");
                }
                if descriptor.revents & (libc::POLLHUP | libc::POLLNVAL | libc::POLLERR) != 0 {
                    bail!("netlink socket polling error");
                }
                if descriptor.revents & event != 0 {
                    return Ok(());
                }
            }
        }
        pub fn exchange(
            &mut self,
            requests: &[wire::Message],
            acks: &[u32],
            data: Option<(u32, usize)>,
        ) -> Result<Vec<wire::Message>> {
            let deadline = Instant::now()
                .checked_add(self.timeout)
                .context("netlink timeout overflow")?;
            let mut outbound = Vec::new();
            for message in requests {
                if message.port != self.port {
                    bail!("netlink request port differs from socket port");
                }
                outbound.extend(message.encode()?);
            }
            // Reject a giant single datagram before mutating kernel state.
            if outbound.len() > 65536 {
                bail!("netlink transaction exceeds 64 KiB; split the element batch");
            }
            let mut kernel: libc::sockaddr_nl = unsafe { mem::zeroed() };
            kernel.nl_family = libc::AF_NETLINK as u16;
            loop {
                self.ready(libc::POLLOUT, deadline)?;
                let sent = unsafe {
                    libc::sendto(
                        self.descriptor.as_raw_fd(),
                        outbound.as_ptr().cast(),
                        outbound.len(),
                        0,
                        (&kernel as *const libc::sockaddr_nl).cast(),
                        mem::size_of_val(&kernel) as libc::socklen_t,
                    )
                };
                if sent < 0 {
                    let error = io::Error::last_os_error();
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) {
                        continue;
                    }
                    return Err(error).context("send netfilter netlink transaction");
                }
                if sent as usize != outbound.len() {
                    bail!("partial netlink datagram write");
                }
                break;
            }
            let mut collector = if requests.len() == 1 && requests[0].flags & 0x300 == 0x300 {
                wire::ReplyCollector::dump(requests[0].sequence, acks.iter().copied())
            } else {
                wire::ReplyCollector::new(
                    requests.iter().map(|request| request.sequence),
                    acks.iter().copied(),
                    data,
                )
            };
            let mut payload = vec![0u8; 65536];
            while !collector.complete() {
                self.ready(libc::POLLIN, deadline)?;
                let mut source: libc::sockaddr_nl = unsafe { mem::zeroed() };
                let mut source_length = mem::size_of_val(&source) as libc::socklen_t;
                let received = unsafe {
                    libc::recvfrom(
                        self.descriptor.as_raw_fd(),
                        payload.as_mut_ptr().cast(),
                        payload.len(),
                        libc::MSG_TRUNC,
                        (&mut source as *mut libc::sockaddr_nl).cast(),
                        &mut source_length,
                    )
                };
                if received < 0 {
                    let error = io::Error::last_os_error();
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) {
                        continue;
                    }
                    return Err(error).context("receive netfilter netlink reply");
                }
                if source_length as usize != mem::size_of_val(&source)
                    || source.nl_family != libc::AF_NETLINK as u16
                    || source.nl_pid != 0
                {
                    continue;
                }
                if received as usize > payload.len() {
                    bail!("truncated netlink response datagram");
                }
                if received == 0 {
                    bail!("empty netlink response datagram");
                }
                for message in wire::messages(&payload[..received as usize])? {
                    let sequence = message.sequence;
                    collector.push(message).with_context(|| {
                        let kind = requests
                            .iter()
                            .find(|request| request.sequence == sequence)
                            .map_or(0, |request| request.kind);
                        format!(
                            "netfilter request subsystem={} operation={} sequence={sequence}",
                            kind >> 8,
                            kind & 0xff
                        )
                    })?;
                }
            }
            Ok(collector.data)
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::*;
    pub struct Connection {
        pub port: u32,
    }
    impl Connection {
        pub fn open(_timeout: Duration) -> Result<Self> {
            bail!("kernel nftset/ipset operations require Linux NETLINK_NETFILTER");
        }
        pub fn next_sequence(&mut self) -> u32 {
            0
        }
        pub fn exchange(
            &mut self,
            _requests: &[wire::Message],
            _acks: &[u32],
            _data: Option<(u32, usize)>,
        ) -> Result<Vec<wire::Message>> {
            bail!("kernel nftset/ipset operations require Linux NETLINK_NETFILTER");
        }
    }
}
pub use platform::Connection;
