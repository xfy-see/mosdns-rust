//! Linux wildcard listeners must answer from the address queried by the client.
//! Other platforms retain Go's ordinary recvfrom/sendto behavior.
use std::{io, net::SocketAddr};
use tokio::net::UdpSocket;

#[derive(Clone, Copy)]
pub(super) struct Destination {
    #[cfg(target_os = "linux")]
    ip: std::net::IpAddr,
    #[cfg(target_os = "linux")]
    interface: u32,
}

pub(super) struct DatagramSocket {
    socket: UdpSocket,
    #[cfg(target_os = "linux")]
    packet_info: bool,
}
impl DatagramSocket {
    pub(super) fn new(socket: UdpSocket) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            let local = socket.local_addr()?;
            let packet_info = local.ip().is_unspecified();
            if packet_info {
                linux::enable_packet_info(&socket, local.is_ipv6())?;
            }
            Ok(Self {
                socket,
                packet_info,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(Self { socket })
        }
    }
    pub(super) async fn receive(
        &self,
        buffer: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<Destination>)> {
        #[cfg(target_os = "linux")]
        if self.packet_info {
            return self
                .socket
                .async_io(tokio::io::Interest::READABLE, || {
                    linux::receive(&self.socket, buffer)
                })
                .await;
        }
        let (length, peer) = self.socket.recv_from(buffer).await?;
        Ok((length, peer, None))
    }
    pub(super) async fn send(
        &self,
        payload: &[u8],
        peer: SocketAddr,
        destination: Option<Destination>,
    ) -> io::Result<usize> {
        #[cfg(target_os = "linux")]
        if let Some(destination) = destination {
            return self
                .socket
                .async_io(tokio::io::Interest::WRITABLE, || {
                    linux::send(&self.socket, payload, peer, destination)
                })
                .await;
        }
        #[cfg(not(target_os = "linux"))]
        let _ = destination;
        self.socket.send_to(payload, peer).await
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        mem::{size_of, zeroed},
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        os::fd::AsRawFd,
        ptr,
    };

    pub(super) fn enable_packet_info(socket: &UdpSocket, ipv6: bool) -> io::Result<()> {
        let enabled: libc::c_int = 1;
        let (level, option) = if ipv6 {
            (libc::IPPROTO_IPV6, libc::IPV6_RECVPKTINFO)
        } else {
            (libc::IPPROTO_IP, libc::IP_PKTINFO)
        };
        // SAFETY: enabled points to one initialized int of the supplied length.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                ptr::from_ref(&enabled).cast(),
                size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result == -1 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    #[allow(clippy::unnecessary_cast)] // musl uses u32 lengths, glibc uses usize.
    pub(super) fn receive(
        socket: &UdpSocket,
        buffer: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, Option<Destination>)> {
        // usize guarantees alignment for cmsghdr and all supported packet-info structs.
        let mut control = [0usize; 32];
        let mut vector = libc::iovec {
            iov_base: buffer.as_mut_ptr().cast(),
            iov_len: buffer.len(),
        };
        // SAFETY: try_init supplies initialized sockaddr storage and its capacity;
        // recvmsg writes at most the named buffer/control capacities.
        let ((length, destination), peer) = unsafe {
            socket2::SockAddr::try_init(|address, length| {
                let mut message: libc::msghdr = zeroed();
                message.msg_name = address.cast();
                message.msg_namelen = *length;
                message.msg_iov = &mut vector;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                message.msg_controllen = size_of_val(&control) as _;
                let received = libc::recvmsg(socket.as_raw_fd(), &mut message, 0);
                if received < 0 {
                    return Err(io::Error::last_os_error());
                }
                *length = message.msg_namelen;
                let destination = destination(&message)?;
                Ok((received as usize, destination))
            })
        }?;
        let peer = peer.as_socket().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "UDP peer is not an IP socket")
        })?;
        Ok((length, peer, destination))
    }

    #[allow(clippy::unnecessary_cast)] // musl uses u32 lengths, glibc uses usize.
    unsafe fn destination(message: &libc::msghdr) -> io::Result<Option<Destination>> {
        if message.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDP packet-info control message truncated",
            ));
        }
        let mut header = libc::CMSG_FIRSTHDR(message);
        while !header.is_null() {
            let remaining = (message.msg_control as usize + message.msg_controllen as usize)
                .saturating_sub(header as usize);
            if ((*header).cmsg_len as usize) < libc::CMSG_LEN(0) as usize
                || (*header).cmsg_len as usize > remaining
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid UDP control message length",
                ));
            }
            let data = libc::CMSG_DATA(header);
            if (*header).cmsg_level == libc::IPPROTO_IP
                && (*header).cmsg_type == libc::IP_PKTINFO
                && (*header).cmsg_len as usize
                    >= libc::CMSG_LEN(size_of::<libc::in_pktinfo>() as u32) as usize
            {
                let info = ptr::read_unaligned(data.cast::<libc::in_pktinfo>());
                return Ok(Some(Destination {
                    ip: IpAddr::V4(Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes())),
                    interface: info.ipi_ifindex as u32,
                }));
            }
            if (*header).cmsg_level == libc::IPPROTO_IPV6
                && (*header).cmsg_type == libc::IPV6_PKTINFO
                && (*header).cmsg_len as usize
                    >= libc::CMSG_LEN(size_of::<libc::in6_pktinfo>() as u32) as usize
            {
                let info = ptr::read_unaligned(data.cast::<libc::in6_pktinfo>());
                return Ok(Some(Destination {
                    ip: IpAddr::V6(Ipv6Addr::from(info.ipi6_addr.s6_addr)),
                    interface: info.ipi6_ifindex,
                }));
            }
            header = libc::CMSG_NXTHDR(message, header);
        }
        Ok(None)
    }

    #[allow(clippy::unnecessary_cast)] // musl uses u32 lengths, glibc uses usize.
    pub(super) fn send(
        socket: &UdpSocket,
        payload: &[u8],
        peer: SocketAddr,
        destination: Destination,
    ) -> io::Result<usize> {
        let address = socket2::SockAddr::from(peer);
        let mut vector = libc::iovec {
            iov_base: payload.as_ptr().cast_mut().cast(),
            iov_len: payload.len(),
        };
        let mut control = [0usize; 8];
        // SAFETY: pointers reference live address, payload, vector and aligned
        // ancillary storage for the duration of the synchronous sendmsg syscall.
        unsafe {
            let mut message: libc::msghdr = zeroed();
            message.msg_name = address.as_ptr().cast_mut().cast();
            message.msg_namelen = address.len();
            message.msg_iov = &mut vector;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            let (level, kind, length) = match destination.ip {
                IpAddr::V4(_) => (
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    size_of::<libc::in_pktinfo>(),
                ),
                IpAddr::V6(_) => (
                    libc::IPPROTO_IPV6,
                    libc::IPV6_PKTINFO,
                    size_of::<libc::in6_pktinfo>(),
                ),
            };
            message.msg_controllen = libc::CMSG_SPACE(length as u32) as _;
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = level;
            (*header).cmsg_type = kind;
            (*header).cmsg_len = libc::CMSG_LEN(length as u32) as _;
            match destination.ip {
                IpAddr::V4(ip) => {
                    let mut info: libc::in_pktinfo = zeroed();
                    info.ipi_ifindex = destination.interface as libc::c_int;
                    info.ipi_spec_dst.s_addr = u32::from_ne_bytes(ip.octets());
                    ptr::write_unaligned(libc::CMSG_DATA(header).cast(), info);
                }
                IpAddr::V6(ip) => {
                    let info = libc::in6_pktinfo {
                        ipi6_addr: libc::in6_addr {
                            s6_addr: ip.octets(),
                        },
                        ipi6_ifindex: destination.interface,
                    };
                    ptr::write_unaligned(libc::CMSG_DATA(header).cast(), info);
                }
            }
            let written = libc::sendmsg(socket.as_raw_fd(), &message, 0);
            if written < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(written as usize)
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::pkg::server::{error_response, serve_udp_socket, Handler};
    use hickory_proto::{
        op::{Message, Query, ResponseCode},
        rr::{Name, RecordType},
    };
    use std::{net::IpAddr, sync::Arc, time::Duration};

    async fn verify(local: &str, target: IpAddr) {
        let socket = UdpSocket::bind(local).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let handler: Handler = Arc::new(|query, _| {
            Box::pin(async move { Ok(error_response(&query, ResponseCode::NoError)) })
        });
        let task = tokio::spawn(serve_udp_socket(socket, handler));
        let client = UdpSocket::bind(if target.is_ipv4() {
            "127.0.0.1:0"
        } else {
            "[::1]:0"
        })
        .await
        .unwrap();
        let mut query = Message::new();
        query.set_id(811).add_query(Query::query(
            Name::from_ascii("source.example.").unwrap(),
            RecordType::A,
        ));
        client
            .send_to(&query.to_vec().unwrap(), SocketAddr::new(target, port))
            .await
            .unwrap();
        let mut buffer = [0; 512];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(1), client.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(
            source,
            SocketAddr::new(target, port),
            "response source must match queried local destination"
        );
        assert_eq!(Message::from_vec(&buffer[..length]).unwrap().id(), 811);
        task.abort();
    }
    #[tokio::test]
    async fn ipv4_wildcard_preserves_nondefault_loopback_source() {
        verify("0.0.0.0:0", "127.0.0.2".parse().unwrap()).await;
    }
    #[tokio::test]
    async fn ipv6_wildcard_preserves_ipv6_source() {
        verify("[::]:0", "::1".parse().unwrap()).await;
    }
    #[tokio::test]
    async fn dual_stack_wildcard_preserves_ipv4_mapped_source() {
        verify("[::]:0", "127.0.0.2".parse().unwrap()).await;
    }
}
