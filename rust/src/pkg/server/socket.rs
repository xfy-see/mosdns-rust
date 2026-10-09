//! Match Go's listener options before bind so accepted sockets inherit them.

use anyhow::{Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::IpAddr,
    pin::Pin,
    task::{Context as TaskContext, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, UdpSocket};

const RECEIVE_BUFFER: usize = 64 * 1024;

async fn bind_socket(listen: &str, kind: Type, protocol: Protocol) -> Result<Socket> {
    let addresses = tokio::net::lookup_host(listen)
        .await
        .context("resolve DNS listen address")?;
    let mut last_error = None;
    for address in addresses {
        let socket = Socket::new(Domain::for_address(address), kind, Some(protocol))
            .context("create DNS listener socket")?;
        #[cfg(unix)]
        socket
            .set_reuse_port(true)
            .context("set listener SO_REUSEPORT")?;
        socket
            .set_recv_buffer_size(RECEIVE_BUFFER)
            .context("set listener SO_RCVBUF")?;
        socket
            .set_nonblocking(true)
            .context("set listener nonblocking")?;
        match socket.bind(&address.into()) {
            Ok(()) => return Ok(socket),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("DNS listen address resolved to no addresses")))
}

pub(super) async fn bind_udp(listen: &str) -> Result<UdpSocket> {
    let socket = bind_socket(listen, Type::DGRAM, Protocol::UDP).await?;
    UdpSocket::from_std(socket.into()).context("create Tokio UDP listener")
}

pub(super) async fn bind_tcp(listen: &str) -> Result<TcpListener> {
    let socket = bind_socket(listen, Type::STREAM, Protocol::TCP).await?;
    socket.listen(1024).context("listen on DNS TCP socket")?;
    TcpListener::from_std(socket.into()).context("create Tokio TCP listener")
}

pub(super) fn is_unix(listen: &str) -> bool {
    listen.starts_with('@') || listen.starts_with("unix://")
}

pub(super) enum StreamSocket {
    Tcp(tokio::net::TcpStream),
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
}

impl AsyncRead for StreamSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_read(cx, buffer),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}
impl AsyncWrite for StreamSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_write(cx, buffer),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_write(cx, buffer),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            #[cfg(unix)]
            Self::Unix(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

enum ListenerSocket {
    Tcp(TcpListener),
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
}
pub(super) struct StreamListener {
    socket: ListenerSocket,
    #[cfg(unix)]
    _path: Option<UnixPath>,
}
impl From<TcpListener> for StreamListener {
    fn from(listener: TcpListener) -> Self {
        Self {
            socket: ListenerSocket::Tcp(listener),
            #[cfg(unix)]
            _path: None,
        }
    }
}
impl StreamListener {
    pub(super) async fn accept(&self) -> io::Result<(StreamSocket, Option<IpAddr>)> {
        match &self.socket {
            ListenerSocket::Tcp(listener) => {
                let (stream, peer) = listener.accept().await?;
                stream.set_nodelay(true)?;
                Ok((StreamSocket::Tcp(stream), Some(peer.ip())))
            }
            #[cfg(unix)]
            ListenerSocket::Unix(listener) => {
                let (stream, _) = listener.accept().await?;
                Ok((StreamSocket::Unix(stream), None))
            }
        }
    }
}

#[cfg(unix)]
struct UnixPath {
    path: std::path::PathBuf,
    device: u64,
    inode: u64,
}
#[cfg(unix)]
impl Drop for UnixPath {
    fn drop(&mut self) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        // A replacement path belongs to somebody else. Never unlink it.
        if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(super) async fn bind_stream(listen: &str) -> Result<StreamListener> {
    if !is_unix(listen) {
        return Ok(bind_tcp(listen).await?.into());
    }
    #[cfg(not(unix))]
    anyhow::bail!("Unix DNS listeners are unavailable on this platform");
    #[cfg(unix)]
    {
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
        let path = if let Some(path) = listen.strip_prefix("unix://") {
            if path.is_empty() {
                anyhow::bail!("empty Unix socket path");
            }
            std::path::PathBuf::from(path)
        } else {
            #[cfg(target_os = "linux")]
            {
                std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
                    &[&[0], &listen.as_bytes()[1..]].concat(),
                ))
            }
            #[cfg(not(target_os = "linux"))]
            {
                std::path::PathBuf::from(listen)
            }
        };
        let address = socket2::SockAddr::unix(&path).context("Unix listener address")?;
        let socket =
            Socket::new(Domain::UNIX, Type::STREAM, None).context("create Unix listener")?;
        socket.set_recv_buffer_size(RECEIVE_BUFFER)?;
        socket.set_nonblocking(true)?;
        socket.bind(&address).context("bind Unix listener")?;
        let cleanup = if path.as_os_str().as_bytes().first() != Some(&0) {
            let metadata = std::fs::symlink_metadata(&path)?;
            Some(UnixPath {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        } else {
            None
        };
        socket.listen(1024).context("listen on Unix socket")?;
        let listener = tokio::net::UnixListener::from_std(socket.into())
            .context("create Tokio Unix listener")?;
        Ok(StreamListener {
            socket: ListenerSocket::Unix(listener),
            _path: cleanup,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn listener_receive_buffer_matches_the_go_requested_size() {
        let udp = bind_udp("127.0.0.1:0").await.unwrap();
        let buffer = socket2::SockRef::from(&udp).recv_buffer_size().unwrap();
        // Linux reports twice the requested amount for bookkeeping; macOS
        // reports the requested amount. Both implementations request 64 KiB.
        assert!(buffer >= RECEIVE_BUFFER);
        let tcp = bind_tcp("127.0.0.1:0").await.unwrap();
        assert!(socket2::SockRef::from(&tcp).recv_buffer_size().unwrap() >= RECEIVE_BUFFER);
    }
}
