// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

//! Shared network dialer: proxy-side DNS, optional bootstrap, and Linux sockets.

#[cfg(feature = "full")]
use super::bootstrap::{self, Bootstrap};
use super::{options::dial_target, Options};
use anyhow::{bail, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
#[cfg(feature = "full")]
use std::sync::Arc;
#[cfg(feature = "full")]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream};

#[derive(Clone)]
pub(super) struct Dialer {
    host: String,
    port: u16,
    #[cfg(feature = "full")]
    proxy: Option<(String, u16)>,
    #[cfg(feature = "full")]
    bootstrap: Option<Arc<Bootstrap>>,
    mark: i64,
    device: String,
}

impl Dialer {
    pub(super) fn new(host: String, port: u16, options: &Options) -> Result<Self> {
        let (host, port) = dial_target(&host, port, &options.dial_addr)?;
        if options.so_mark > u32::MAX.into() {
            bail!("SO_MARK exceeds 32 bits");
        }
        if options.bind_to_device.contains('\0') {
            bail!("bind_to_device contains NUL");
        }
        #[cfg(not(target_os = "linux"))]
        if options.so_mark > 0 || !options.bind_to_device.is_empty() {
            bail!("SO_MARK and SO_BINDTODEVICE are supported only on Linux");
        }
        #[cfg(feature = "full")]
        let server = if options.bootstrap.is_empty() {
            None
        } else {
            Some(bootstrap::parse_server(&options.bootstrap)?)
        };
        #[cfg(feature = "full")]
        let bootstrap = if host.parse::<IpAddr>().is_err() {
            server
                .map(|server| Bootstrap::new(&host, port, server, options.bootstrap_version))
                .transpose()?
        } else {
            None
        };
        #[cfg(feature = "full")]
        let proxy = if options.socks5.is_empty() {
            None
        } else {
            let (proxy_host, proxy_port) = options
                .socks5
                .rsplit_once(':')
                .context("socks5 requires a host and port")?;
            let proxy_host = proxy_host.trim_start_matches('[').trim_end_matches(']');
            let proxy_port = proxy_port.parse::<u16>().context("invalid socks5 port")?;
            if proxy_host.is_empty() || proxy_port == 0 {
                bail!("invalid socks5 address");
            }
            Some((proxy_host.to_owned(), proxy_port))
        };
        Ok(Self {
            host,
            port,
            #[cfg(feature = "full")]
            proxy,
            #[cfg(feature = "full")]
            bootstrap,
            mark: options.so_mark,
            device: options.bind_to_device.clone(),
        })
    }

    pub(super) async fn resolve(&self) -> Result<SocketAddr> {
        self.resolve_addresses()
            .await?
            .into_iter()
            .next()
            .context("upstream resolved to no addresses")
    }

    pub(super) async fn resolve_addresses(&self) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = self.host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, self.port)]);
        }
        #[cfg(feature = "full")]
        {
            if let Some(bootstrap) = &self.bootstrap {
                return Ok(vec![bootstrap.resolve().await?]);
            }
            let addresses = tokio::net::lookup_host((self.host.as_str(), self.port))
                .await
                .context("resolve upstream")?
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                bail!("upstream resolved to no addresses");
            }
            Ok(addresses)
        }
        #[cfg(not(feature = "full"))]
        bail!("minimal upstream address must be a numeric IP address")
    }

    fn control(&self, socket: &Socket) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            if self.mark > 0 {
                socket.set_mark(self.mark as u32).context("set SO_MARK")?;
            }
            if !self.device.is_empty() {
                socket
                    .bind_device(Some(self.device.as_bytes()))
                    .context("set SO_BINDTODEVICE")?;
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (socket, self.mark, &self.device);
        }
        Ok(())
    }

    async fn tcp_to(&self, remote: SocketAddr) -> Result<TcpStream> {
        let socket = Socket::new(
            Domain::for_address(remote),
            Type::STREAM,
            Some(Protocol::TCP),
        )?;
        self.control(&socket)?;
        socket.set_nonblocking(true)?;
        let socket = TcpSocket::from_std_stream(socket.into());
        let stream = socket
            .connect(remote)
            .await
            .context("connect TCP upstream")?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    #[cfg(not(feature = "full"))]
    pub(super) async fn tcp(&self) -> Result<TcpStream> {
        self.tcp_to_addresses(self.resolve_addresses().await?).await
    }

    #[cfg(feature = "full")]
    pub(super) async fn tcp(&self) -> Result<TcpStream> {
        let Some((host, port)) = &self.proxy else {
            return self.tcp_to_addresses(self.resolve_addresses().await?).await;
        };
        let proxy = tokio::net::lookup_host((host.as_str(), *port))
            .await
            .context("resolve SOCKS5 proxy")?
            .collect::<Vec<_>>();
        let mut stream = self
            .tcp_to_addresses(proxy)
            .await
            .context("connect SOCKS5 proxy")?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut greeting = [0; 2];
        stream.read_exact(&mut greeting).await?;
        if greeting != [5, 0] {
            bail!("SOCKS5 proxy rejected unauthenticated method");
        }
        let mut connect = vec![5, 1, 0];
        match self.host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => {
                connect.push(1);
                connect.extend_from_slice(&ip.octets());
            }
            Ok(IpAddr::V6(ip)) => {
                connect.push(4);
                connect.extend_from_slice(&ip.octets());
            }
            Err(_) => {
                let length =
                    u8::try_from(self.host.len()).context("SOCKS5 hostname exceeds 255 bytes")?;
                connect.extend_from_slice(&[3, length]);
                connect.extend_from_slice(self.host.as_bytes());
            }
        }
        connect.extend_from_slice(&self.port.to_be_bytes());
        stream.write_all(&connect).await?;
        let mut reply = [0; 4];
        stream.read_exact(&mut reply).await?;
        if reply[0] != 5 || reply[2] != 0 {
            bail!("invalid SOCKS5 response");
        }
        if reply[1] != 0 {
            bail!("SOCKS5 connect failed with status {}", reply[1]);
        }
        let length = match reply[3] {
            1 => 4,
            4 => 16,
            3 => usize::from(stream.read_u8().await?),
            other => bail!("invalid SOCKS5 address type {other}"),
        };
        let mut bound = vec![0; length + 2];
        stream.read_exact(&mut bound).await?;
        Ok(stream)
    }

    async fn tcp_to_addresses(&self, addresses: Vec<SocketAddr>) -> Result<TcpStream> {
        let mut last_error = None;
        for address in addresses {
            match self.tcp_to(address).await {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = Some(error),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("upstream resolved to no addresses")))
    }

    /// UDP/QUIC ignore SOCKS5, as in Go. Socket controls precede the first bind.
    pub(super) fn bind_udp(&self, remote: SocketAddr) -> Result<std::net::UdpSocket> {
        let socket = Socket::new(
            Domain::for_address(remote),
            Type::DGRAM,
            Some(Protocol::UDP),
        )?;
        self.control(&socket)?;
        let bind: SocketAddr = if remote.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        }
        .parse()?;
        socket
            .bind(&bind.into())
            .context("bind upstream UDP socket")?;
        socket.set_nonblocking(true)?;
        Ok(socket.into())
    }
}
