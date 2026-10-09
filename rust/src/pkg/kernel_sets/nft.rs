use super::{wire, Element};
use anyhow::{bail, Context, Result};
use std::{net::IpAddr, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TableFamily {
    Inet = 1,
    Ipv4 = 2,
    Ipv6 = 10,
}
impl std::str::FromStr for TableFamily {
    type Err = anyhow::Error;
    fn from_str(value: &str) -> Result<Self> {
        match value {
            "inet" => Ok(Self::Inet),
            "ip" => Ok(Self::Ipv4),
            "ip6" => Ok(Self::Ipv6),
            _ => bail!("unsupported nftables table family {value}"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Target {
    pub family: TableFamily,
    pub table: String,
    pub set: String,
}
impl Target {
    pub fn validate(&self) -> Result<()> {
        wire::string_attribute(1, &self.table, 256)?;
        wire::string_attribute(2, &self.set, 256)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub family: TableFamily,
    pub table: String,
    pub name: String,
    pub flags: u32,
    pub key_type: u32,
    pub key_length: u32,
    pub id: Option<u32>,
    pub default_timeout: Option<Duration>,
}
impl Metadata {
    pub fn interval(&self) -> bool {
        self.flags & 4 != 0
    }
    pub fn has_timeout(&self) -> bool {
        self.flags & 0x10 != 0
    }
    pub fn validate_address_set(&self) -> Result<()> {
        if self.flags & (1 | 2 | 8 | 0x40 | 0x80) != 0 {
            bail!("nftset must be a mutable, named IP set, not a map/object/concatenation");
        }
        if !matches!((self.key_type, self.key_length), (7, 4) | (8, 16)) {
            bail!("nftset key type/length is not ipv4_addr or ipv6_addr");
        }
        Ok(())
    }
}

pub fn get_set(target: &Target, sequence: u32, port: u32) -> Result<wire::Message> {
    target.validate()?;
    let mut payload = wire::nfgen(target.family as u8, 0);
    payload.extend(wire::string_attribute(1, &target.table, 256)?);
    payload.extend(wire::string_attribute(2, &target.set, 256)?);
    Ok(wire::Message {
        kind: (wire::NFT_SUBSYSTEM << 8) | 10,
        flags: wire::REQUEST | wire::ACK,
        sequence,
        port,
        payload,
    })
}

pub fn parse_metadata(target: &Target, message: &wire::Message) -> Result<Metadata> {
    if message.kind != (wire::NFT_SUBSYSTEM << 8) | 9
        || message.payload.len() < 4
        || message.payload[0] != target.family as u8
        || message.payload[1] != 0
    {
        bail!("unexpected nftset metadata message");
    }
    let mut flags = None;
    let mut key_type = None;
    let mut key_length = None;
    let mut table = None;
    let mut name = None;
    let mut id = None;
    let mut timeout = None;
    for attr in wire::attributes(&message.payload[4..])? {
        match attr.kind {
            1 => table = Some(wire::nul_string(attr.payload)?.to_owned()),
            2 => name = Some(wire::nul_string(attr.payload)?.to_owned()),
            3 => flags = Some(wire::be_u32(attr.payload)?),
            4 => key_type = Some(wire::be_u32(attr.payload)?),
            5 => key_length = Some(wire::be_u32(attr.payload)?),
            10 => id = Some(wire::be_u32(attr.payload)?),
            11 => timeout = Some(Duration::from_millis(wire::be_u64(attr.payload)?)),
            _ => (),
        }
    }
    let table = table.context("nftset metadata omitted table name")?;
    let name = name.context("nftset metadata omitted set name")?;
    if table != target.table || name != target.set {
        bail!("nftset metadata target mismatch");
    }
    let metadata = Metadata {
        family: target.family,
        table,
        name,
        flags: flags.context("nftset metadata omitted flags")?,
        key_type: key_type.context("nftset metadata omitted key type")?,
        key_length: key_length.context("nftset metadata omitted key length")?,
        id,
        default_timeout: timeout,
    };
    metadata.validate_address_set()?;
    Ok(metadata)
}

fn address_bytes(address: IpAddr) -> Vec<u8> {
    match address {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

/// Closed-open interval endpoints match mosdns's Go nftset handler. An interval
/// ending at the largest address has no representable end+1 marker.
pub fn interval_end(prefix: ipnet::IpNet) -> Option<IpAddr> {
    match prefix {
        ipnet::IpNet::V4(prefix) => u32::from(prefix.broadcast())
            .checked_add(1)
            .map(|ip| IpAddr::V4(ip.into())),
        ipnet::IpNet::V6(prefix) => {
            let host_bits = 128 - prefix.prefix_len();
            let mask = if host_bits == 128 {
                u128::MAX
            } else {
                (1u128 << host_bits) - 1
            };
            (u128::from(prefix.network()) | mask)
                .checked_add(1)
                .map(|ip| IpAddr::V6(ip.into()))
        }
    }
}

fn encoded_element(key: &[u8], end: bool, timeout: Option<Duration>) -> Result<Vec<u8>> {
    let mut result = wire::attribute(1 | wire::NLA_NESTED, &wire::attribute(1, key)?)?;
    if end {
        result.extend(wire::attribute(3, &1u32.to_be_bytes())?);
    }
    // Linux forbids TIMEOUT on INTERVAL_END markers: only the range start owns it.
    if !end {
        if let Some(timeout) = timeout {
            let millis = timeout
                .as_millis()
                .checked_add(u128::from(timeout.subsec_nanos() % 1_000_000 != 0))
                .context("nftset timeout overflow")?;
            let millis =
                u64::try_from(millis).context("nftset timeout exceeds u64 milliseconds")?;
            result.extend(wire::attribute(4, &millis.to_be_bytes())?);
        }
    }
    Ok(result)
}

pub fn add_elements(
    metadata: &Metadata,
    elements: &[Element],
    sequence: u32,
    port: u32,
) -> Result<wire::Message> {
    metadata.validate_address_set()?;
    if elements.is_empty() {
        bail!("nftset element batch is empty");
    }
    let mut encoded = Vec::new();
    let mut index = 0u16;
    for element in elements {
        let key = address_bytes(if metadata.interval() {
            element.prefix.network()
        } else {
            element.prefix.addr()
        });
        if key.len() != metadata.key_length as usize {
            bail!("IP family differs from nftset key family");
        }
        if element.timeout.is_some() && !metadata.has_timeout() {
            bail!("explicit element TTL requires nftset timeout flag");
        }
        index = index.checked_add(1).context("too many nftset elements")?;
        encoded.extend(wire::attribute(
            index | wire::NLA_NESTED,
            &encoded_element(&key, false, element.timeout)?,
        )?);
        if metadata.interval() {
            if let Some(end) = interval_end(element.prefix) {
                index = index.checked_add(1).context("too many nftset elements")?;
                encoded.extend(wire::attribute(
                    index | wire::NLA_NESTED,
                    &encoded_element(&address_bytes(end), true, None)?,
                )?);
            }
        }
        if index >= 0x4000 {
            bail!("nftset element count exceeds netlink attribute type range");
        }
    }
    let mut payload = wire::nfgen(metadata.family as u8, 0);
    payload.extend(wire::string_attribute(1, &metadata.table, 256)?);
    payload.extend(wire::string_attribute(2, &metadata.name, 256)?);
    payload.extend(wire::attribute(3 | wire::NLA_NESTED, &encoded)?);
    Ok(wire::Message {
        kind: (wire::NFT_SUBSYSTEM << 8) | 12,
        flags: wire::REQUEST | wire::ACK | wire::CREATE,
        sequence,
        port,
        payload,
    })
}

pub fn batch(message: wire::Message, begin_sequence: u32, end_sequence: u32) -> [wire::Message; 3] {
    let port = message.port;
    [
        wire::Message {
            kind: 16,
            flags: wire::REQUEST,
            sequence: begin_sequence,
            port,
            payload: wire::nfgen(0, wire::NFT_SUBSYSTEM),
        },
        message,
        wire::Message {
            kind: 17,
            flags: wire::REQUEST,
            sequence: end_sequence,
            port,
            payload: wire::nfgen(0, wire::NFT_SUBSYSTEM),
        },
    ]
}
