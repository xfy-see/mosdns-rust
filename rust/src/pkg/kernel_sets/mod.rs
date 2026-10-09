//! Native Linux nftset/ipset operations on existing sets only.
//!
//! None as an element timeout retains mosdns Go semantics: the set's configured
//! default is used. Explicit DNS TTL mode is opt-in and never shortens an IP RR
//! or authority SOA lifetime. Runtime mutations require CAP_NET_ADMIN.

pub mod ipset;
mod native;
pub mod nft;
pub mod wire;
/// Low-level native socket for callers that supply Linux UAPI messages, used by
/// isolated integration fixtures. Higher-level handlers only add existing sets.
pub use native::Connection as NetfilterSocket;

use anyhow::{bail, Context, Result};
use hickory_proto::{op::Message, rr::RData};
use ipnet::IpNet;
use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Element {
    pub prefix: IpNet,
    pub timeout: Option<Duration>,
}
impl From<IpNet> for Element {
    fn from(prefix: IpNet) -> Self {
        Self {
            prefix,
            timeout: None,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum TimeoutPolicy {
    SetDefault,
    DnsTtl { minimum: Duration },
}

pub fn response_elements(
    response: &Message,
    mask4: u8,
    mask6: u8,
    policy: TimeoutPolicy,
) -> Result<(Vec<Element>, Vec<Element>)> {
    if mask4 > 32 || mask6 > 128 {
        bail!("invalid IPv4/IPv6 set mask");
    }
    let soa_ttl = response
        .name_servers()
        .iter()
        .filter(|record| matches!(record.data(), Some(RData::SOA(_))))
        .map(|record| Duration::from_secs(record.ttl() as u64))
        .max()
        .unwrap_or_default();
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for record in response.answers() {
        let (address, mask, target) = match record.data() {
            Some(RData::A(address)) => (std::net::IpAddr::V4(address.0), mask4, &mut ipv4),
            Some(RData::AAAA(address)) => (std::net::IpAddr::V6(address.0), mask6, &mut ipv6),
            _ => continue,
        };
        let timeout = match policy {
            TimeoutPolicy::SetDefault => None,
            TimeoutPolicy::DnsTtl { minimum } => Some(
                minimum
                    .max(soa_ttl)
                    .max(Duration::from_secs(record.ttl() as u64))
                    .max(Duration::from_secs(1)),
            ),
        };
        target.push(Element {
            prefix: IpNet::new(address, mask)?,
            timeout,
        });
    }
    Ok((ipv4, ipv6))
}

fn supported() -> Result<()> {
    if !cfg!(target_os = "linux") {
        bail!("kernel nftset/ipset operations require Linux NETLINK_NETFILTER");
    }
    Ok(())
}

struct NftState {
    socket: Option<native::Connection>,
    metadata: Option<nft::Metadata>,
    updated: Option<Instant>,
    closed: bool,
}

#[derive(Clone)]
pub struct NftSetHandler {
    target: nft::Target,
    timeout: Duration,
    state: Arc<Mutex<NftState>>,
}
impl NftSetHandler {
    pub fn new(target: nft::Target, timeout: Duration) -> Result<Self> {
        target.validate()?;
        supported()?;
        if timeout.is_zero() {
            bail!("netlink timeout must be positive");
        }
        Ok(Self {
            target,
            timeout,
            state: Arc::new(Mutex::new(NftState {
                socket: None,
                metadata: None,
                updated: None,
                closed: false,
            })),
        })
    }
    fn lock(&self) -> Result<MutexGuard<'_, NftState>> {
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("nftset handler lock poisoned"))
    }
    fn metadata_locked(&self, state: &mut NftState) -> Result<nft::Metadata> {
        if state.closed {
            bail!("closed nftset handler");
        }
        if state
            .updated
            .is_some_and(|updated| updated.elapsed() < Duration::from_secs(1))
        {
            if let Some(metadata) = &state.metadata {
                return Ok(metadata.clone());
            }
        }
        if state.socket.is_none() {
            state.socket = Some(native::Connection::open(self.timeout)?);
        }
        let socket = state.socket.as_mut().unwrap();
        let sequence = socket.next_sequence();
        let request = nft::get_set(&self.target, sequence, socket.port)?;
        let replies = socket.exchange(&[request], &[sequence], Some((sequence, 1)))?;
        if replies.len() != 1 {
            bail!(
                "expected one nftset metadata response, got {}",
                replies.len()
            );
        }
        let metadata = nft::parse_metadata(&self.target, &replies[0])?;
        state.metadata = Some(metadata.clone());
        state.updated = Some(Instant::now());
        Ok(metadata)
    }
    pub fn metadata(&self) -> Result<nft::Metadata> {
        let mut state = self.lock()?;
        match self.metadata_locked(&mut state) {
            Ok(metadata) => Ok(metadata),
            Err(error) => {
                state.socket = None;
                state.metadata = None;
                state.updated = None;
                Err(error)
            }
        }
    }
    pub fn add_elements(&self, elements: &[Element]) -> Result<()> {
        let mut state = self.lock()?;
        if state.closed {
            bail!("closed nftset handler");
        }
        if elements.is_empty() {
            return Ok(());
        }
        let result = (|| {
            let metadata = self.metadata_locked(&mut state)?;
            let socket = state.socket.as_mut().unwrap();
            let begin = socket.next_sequence();
            let sequence = socket.next_sequence();
            let end = socket.next_sequence();
            let request = nft::add_elements(&metadata, elements, sequence, socket.port)?;
            socket.exchange(&nft::batch(request, begin, end), &[sequence], None)?;
            Ok(())
        })();
        if result.is_err() {
            state.socket = None;
            state.metadata = None;
            state.updated = None;
        }
        result
    }
    pub async fn add_prefixes(&self, prefixes: Vec<IpNet>) -> Result<()> {
        let handler = self.clone();
        tokio::task::spawn_blocking(move || {
            handler.add_elements(&prefixes.into_iter().map(Element::from).collect::<Vec<_>>())
        })
        .await
        .context("nftset blocking task failed")?
    }
    pub async fn add_elements_async(&self, elements: Vec<Element>) -> Result<()> {
        let handler = self.clone();
        tokio::task::spawn_blocking(move || handler.add_elements(&elements))
            .await
            .context("nftset blocking task failed")?
    }
    pub fn close(&self) -> Result<()> {
        let mut state = self.lock()?;
        state.closed = true;
        state.socket = None;
        state.metadata = None;
        state.updated = None;
        Ok(())
    }
}

struct IpSetState {
    socket: Option<native::Connection>,
    closed: bool,
}
#[derive(Clone)]
pub struct IpSetHandler {
    set: String,
    timeout: Duration,
    state: Arc<Mutex<IpSetState>>,
}
impl IpSetHandler {
    pub fn new(set: String, timeout: Duration) -> Result<Self> {
        wire::string_attribute(2, &set, 32)?;
        supported()?;
        if timeout.is_zero() {
            bail!("netlink timeout must be positive");
        }
        Ok(Self {
            set,
            timeout,
            state: Arc::new(Mutex::new(IpSetState {
                socket: None,
                closed: false,
            })),
        })
    }
    pub fn add_elements(&self, elements: &[Element]) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("ipset handler lock poisoned"))?;
        if state.closed {
            bail!("closed ipset handler");
        }
        if elements.is_empty() {
            return Ok(());
        }
        // Validate every element before the first write. Kernel failures after
        // earlier ACKs can still leave a partial batch, matching Go's per-RR add.
        for element in elements {
            ipset::add_prefix(&self.set, element, 1, 0)?;
        }
        if state.socket.is_none() {
            state.socket = Some(native::Connection::open(self.timeout)?);
        }
        for (index, element) in elements.iter().enumerate() {
            let socket = state.socket.as_mut().unwrap();
            let sequence = socket.next_sequence();
            let request = ipset::add_prefix(&self.set, element, sequence, socket.port)?;
            if let Err(error) = socket.exchange(&[request], &[sequence], None) {
                state.socket = None;
                return Err(error)
                .with_context(||format!("ipset batch failed at element {index}; earlier elements may have been added"));
            }
        }
        Ok(())
    }
    pub async fn add_prefixes(&self, prefixes: Vec<IpNet>) -> Result<()> {
        let handler = self.clone();
        tokio::task::spawn_blocking(move || {
            handler.add_elements(&prefixes.into_iter().map(Element::from).collect::<Vec<_>>())
        })
        .await
        .context("ipset blocking task failed")?
    }
    pub async fn add_elements_async(&self, elements: Vec<Element>) -> Result<()> {
        let handler = self.clone();
        tokio::task::spawn_blocking(move || handler.add_elements(&elements))
            .await
            .context("ipset blocking task failed")?
    }
    pub fn close(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("ipset handler lock poisoned"))?;
        state.closed = true;
        state.socket = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
