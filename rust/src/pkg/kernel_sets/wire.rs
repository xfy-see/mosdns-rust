//! Linux UAPI encoding, independent of the host operating system.

use anyhow::{bail, Context, Result};
use std::collections::HashSet;

pub const NLA_NESTED: u16 = 0x8000;
pub const NLA_NETWORK_ORDER: u16 = 0x4000;
pub const REQUEST: u16 = 1;
pub const ACK: u16 = 4;
pub const CREATE: u16 = 0x400;
pub const NFT_SUBSYSTEM: u16 = 10;
pub const IPSET_SUBSYSTEM: u16 = 6;

pub const fn align(length: usize) -> usize {
    (length + 3) & !3
}

pub fn attribute(kind: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let length = payload
        .len()
        .checked_add(4)
        .context("attribute length overflow")?;
    if length > u16::MAX as usize {
        bail!("netlink attribute exceeds 65535 bytes");
    }
    let mut result = Vec::with_capacity(align(length));
    result.extend_from_slice(&(length as u16).to_ne_bytes());
    result.extend_from_slice(&kind.to_ne_bytes());
    result.extend_from_slice(payload);
    result.resize(align(length), 0);
    Ok(result)
}

pub fn string_attribute(kind: u16, value: &str, limit: usize) -> Result<Vec<u8>> {
    if value.is_empty() || value.as_bytes().contains(&0) || value.len() >= limit {
        bail!(
            "invalid set/table name: requires 1..{} bytes without NUL",
            limit - 1
        );
    }
    let mut payload = value.as_bytes().to_vec();
    payload.push(0);
    attribute(kind, &payload)
}

#[derive(Clone, Copy, Debug)]
pub struct Attribute<'a> {
    pub kind: u16,
    pub flags: u16,
    pub payload: &'a [u8],
}

pub fn attributes(mut payload: &[u8]) -> Result<Vec<Attribute<'_>>> {
    let mut result = Vec::new();
    while !payload.is_empty() {
        if payload.len() < 4 {
            bail!("truncated netlink attribute header");
        }
        let length = u16::from_ne_bytes(payload[..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(payload[2..4].try_into().unwrap());
        if length < 4 || length > payload.len() || align(length) > payload.len() {
            bail!("invalid netlink attribute length {length}");
        }
        result.push(Attribute {
            kind: kind & 0x3fff,
            flags: kind & 0xc000,
            payload: &payload[4..length],
        });
        payload = &payload[align(length)..];
    }
    Ok(result)
}

pub fn be_u32(payload: &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(payload.try_into().map_err(|_| {
        anyhow::anyhow!("invalid netlink u32 length")
    })?))
}
pub fn be_u64(payload: &[u8]) -> Result<u64> {
    Ok(u64::from_be_bytes(payload.try_into().map_err(|_| {
        anyhow::anyhow!("invalid netlink u64 length")
    })?))
}
pub fn nul_string(payload: &[u8]) -> Result<&str> {
    if payload.last() != Some(&0) || payload[..payload.len() - 1].contains(&0) {
        bail!("invalid netlink NUL string");
    }
    std::str::from_utf8(&payload[..payload.len() - 1]).context("invalid UTF-8 netlink name")
}

#[derive(Clone, Debug)]
pub struct Message {
    pub kind: u16,
    pub flags: u16,
    pub sequence: u32,
    pub port: u32,
    pub payload: Vec<u8>,
}

impl Message {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let length = self
            .payload
            .len()
            .checked_add(16)
            .context("netlink message length overflow")?;
        let length_u32 = u32::try_from(length).context("netlink message exceeds u32 length")?;
        let mut result = Vec::with_capacity(align(length));
        result.extend_from_slice(&length_u32.to_ne_bytes());
        result.extend_from_slice(&self.kind.to_ne_bytes());
        result.extend_from_slice(&self.flags.to_ne_bytes());
        result.extend_from_slice(&self.sequence.to_ne_bytes());
        result.extend_from_slice(&self.port.to_ne_bytes());
        result.extend_from_slice(&self.payload);
        result.resize(align(length), 0);
        Ok(result)
    }
}

pub fn messages(mut payload: &[u8]) -> Result<Vec<Message>> {
    let mut result = Vec::new();
    while !payload.is_empty() {
        if payload.len() < 16 {
            bail!("truncated netlink message header");
        }
        let length = u32::from_ne_bytes(payload[..4].try_into().unwrap()) as usize;
        if length < 16 || length > payload.len() || align(length) > payload.len() {
            bail!("invalid netlink message length {length}");
        }
        result.push(Message {
            kind: u16::from_ne_bytes(payload[4..6].try_into().unwrap()),
            flags: u16::from_ne_bytes(payload[6..8].try_into().unwrap()),
            sequence: u32::from_ne_bytes(payload[8..12].try_into().unwrap()),
            port: u32::from_ne_bytes(payload[12..16].try_into().unwrap()),
            payload: payload[16..length].to_vec(),
        });
        payload = &payload[align(length)..];
    }
    Ok(result)
}

#[derive(Debug)]
pub struct KernelError {
    pub errno: i32,
    pub detail: Option<String>,
}
impl std::fmt::Display for KernelError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "netfilter netlink error {}: {}",
            self.errno,
            std::io::Error::from_raw_os_error(self.errno)
        )?;
        if let Some(detail) = &self.detail {
            write!(formatter, " ({detail})")?;
        }
        Ok(())
    }
}
impl std::error::Error for KernelError {}

/// ACKs can precede data, arrive in the same datagram, or arrive separately.
/// A sequence from a previous timed-out request cannot complete this request.
pub struct ReplyCollector {
    sequences: HashSet<u32>,
    acks: HashSet<u32>,
    data_sequence: Option<u32>,
    data_count: usize,
    pub data: Vec<Message>,
    dump_sequence: Option<u32>,
    dump_done: bool,
}
impl ReplyCollector {
    pub fn new(
        sequences: impl IntoIterator<Item = u32>,
        acks: impl IntoIterator<Item = u32>,
        data: Option<(u32, usize)>,
    ) -> Self {
        Self {
            sequences: sequences.into_iter().collect(),
            acks: acks.into_iter().collect(),
            data_sequence: data.map(|value| value.0),
            data_count: data.map_or(0, |value| value.1),
            data: Vec::new(),
            dump_sequence: None,
            dump_done: false,
        }
    }
    pub fn dump(sequence: u32, acks: impl IntoIterator<Item = u32>) -> Self {
        let mut collector = Self::new([sequence], acks, Some((sequence, 0)));
        collector.dump_sequence = Some(sequence);
        collector
    }
    pub fn push(&mut self, message: Message) -> Result<()> {
        if !self.sequences.contains(&message.sequence) {
            return Ok(());
        }
        if message.flags & 0x10 != 0 {
            bail!("interrupted netlink dump; metadata is inconsistent");
        }
        match message.kind {
            2 => {
                if message.payload.len() < 4 {
                    bail!("truncated netlink ACK");
                }
                let code = i32::from_ne_bytes(message.payload[..4].try_into().unwrap());
                if code > 0 || code == i32::MIN {
                    bail!("invalid netlink error code {code}");
                }
                if code < 0 {
                    let mut detail = None;
                    if message.flags & 0x200 != 0 && message.payload.len() >= 20 {
                        let original_length =
                            u32::from_ne_bytes(message.payload[4..8].try_into().unwrap()) as usize;
                        let offset = if message.flags & 0x100 != 0 {
                            20
                        } else {
                            4 + align(original_length)
                        };
                        if offset <= message.payload.len() {
                            detail =
                                attributes(&message.payload[offset..])
                                    .ok()
                                    .and_then(|attrs| {
                                        attrs.into_iter().find(|attr| attr.kind == 1).and_then(
                                            |attr| nul_string(attr.payload).ok().map(str::to_owned),
                                        )
                                    });
                        }
                    }
                    return Err(KernelError {
                        errno: -code,
                        detail,
                    }
                    .into());
                }
                self.acks.remove(&message.sequence);
            }
            4 => bail!("netlink receive overrun"),
            3 => {
                if message.payload.len() >= 4 {
                    let code = i32::from_ne_bytes(message.payload[..4].try_into().unwrap());
                    if code != 0 {
                        bail!("netlink dump completed with error {code}");
                    }
                }
                if self.dump_sequence == Some(message.sequence) {
                    self.dump_done = true;
                }
            }
            kind if kind >= 16 && self.data_sequence == Some(message.sequence) => {
                self.data.push(message)
            }
            _ => (),
        }
        Ok(())
    }
    pub fn complete(&self) -> bool {
        self.acks.is_empty()
            && self.data.len() >= self.data_count
            && (self.dump_sequence.is_none() || self.dump_done)
    }
}

pub fn nfgen(family: u8, resource: u16) -> Vec<u8> {
    let mut payload = vec![family, 0];
    payload.extend_from_slice(&resource.to_be_bytes());
    payload
}
