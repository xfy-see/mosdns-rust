//! Privileged integration tests. All mutations are confined to new objects
//! named mosdns_rs_test_*. No chains, rules, or hooks are ever created.
#![cfg(target_os = "linux")]

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
#[cfg(feature = "full")]
use mosdns_rs::pkg::kernel_sets::IpSetHandler;
use mosdns_rs::pkg::kernel_sets::{nft, wire, Element, NetfilterSocket, NftSetHandler};
use std::{
    net::IpAddr,
    sync::atomic::{AtomicU32, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

static SERIAL: AtomicU32 = AtomicU32::new(0);
const IO_TIMEOUT: Duration = Duration::from_secs(3);

fn fixture_name(label: &str) -> String {
    let serial = SERIAL.fetch_add(1, Ordering::Relaxed);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let name = format!(
        "mosdns_rs_test_{label}_{:x}",
        nonce ^ std::process::id() ^ serial
    );
    assert!(name.starts_with("mosdns_rs_test_") && name.len() < 32);
    name
}

fn nft_transaction(
    socket: &mut NetfilterSocket,
    operation: u16,
    attributes: Vec<u8>,
    create: bool,
) -> Result<()> {
    let begin = socket.next_sequence();
    let sequence = socket.next_sequence();
    let end = socket.next_sequence();
    let mut payload = wire::nfgen(nft::TableFamily::Inet as u8, 0);
    payload.extend(attributes);
    let request = wire::Message {
        kind: (wire::NFT_SUBSYSTEM << 8) | operation,
        flags: wire::REQUEST | wire::ACK | if create { wire::CREATE | 0x200 } else { 0 },
        sequence,
        port: socket.port,
        payload,
    };
    socket.exchange(&nft::batch(request, begin, end), &[sequence], None)?;
    Ok(())
}

struct NftFixture {
    socket: NetfilterSocket,
    table: String,
    owned: bool,
}
impl NftFixture {
    fn new() -> Result<Self> {
        let mut socket = NetfilterSocket::open(IO_TIMEOUT)?;
        let table = fixture_name("nft");
        // EXCL prevents adopting, flushing, or deleting a pre-existing table.
        nft_transaction(
            &mut socket,
            0,
            wire::string_attribute(1, &table, 256)?,
            true,
        )?;
        Ok(Self {
            socket,
            table,
            owned: true,
        })
    }
    fn create_set(
        &mut self,
        name: &str,
        ipv6: bool,
        interval: bool,
        timeout: Option<Duration>,
    ) -> Result<nft::Target> {
        let mut attributes = wire::string_attribute(1, &self.table, 256)?;
        attributes.extend(wire::string_attribute(2, name, 256)?);
        let flags = u32::from(interval) * 4 + u32::from(timeout.is_some()) * 16;
        for (kind, value) in [
            (3, flags),
            (4, if ipv6 { 8 } else { 7 }),
            (5, if ipv6 { 16 } else { 4 }),
            // The kernel requires a transaction-local ID for every new set.
            (10, 1),
        ] {
            attributes.extend(wire::attribute(kind, &value.to_be_bytes())?);
        }
        if let Some(timeout) = timeout {
            attributes.extend(wire::attribute(
                11,
                &(timeout.as_millis() as u64).to_be_bytes(),
            )?);
        }
        nft_transaction(&mut self.socket, 9, attributes, true)?;
        Ok(nft::Target {
            family: nft::TableFamily::Inet,
            table: self.table.clone(),
            set: name.into(),
        })
    }
    fn elements(&mut self, target: &nft::Target) -> Result<Vec<NftElement>> {
        let sequence = self.socket.next_sequence();
        let mut payload = wire::nfgen(target.family as u8, 0);
        payload.extend(wire::string_attribute(1, &target.table, 256)?);
        payload.extend(wire::string_attribute(2, &target.set, 256)?);
        let request = wire::Message {
            kind: (wire::NFT_SUBSYSTEM << 8) | 13,
            flags: wire::REQUEST | 0x300,
            sequence,
            port: self.socket.port,
            payload,
        };
        let replies = self.socket.exchange(&[request], &[], None)?;
        let mut result = Vec::new();
        for reply in replies {
            if reply.payload.len() < 4 {
                bail!("short nftset element dump");
            }
            for list in wire::attributes(&reply.payload[4..])?
                .iter()
                .filter(|attribute| attribute.kind == 3)
            {
                for element in wire::attributes(list.payload)? {
                    let mut key = None;
                    let mut flags = 0;
                    let mut timeout = None;
                    let mut expiration = None;
                    for attribute in wire::attributes(element.payload)? {
                        match attribute.kind {
                            1 => {
                                key = Some(
                                    wire::attributes(attribute.payload)?
                                        .into_iter()
                                        .find(|attribute| attribute.kind == 1)
                                        .context("nftset element omitted its key")?
                                        .payload
                                        .to_vec(),
                                )
                            }
                            3 => flags = wire::be_u32(attribute.payload)?,
                            4 => {
                                timeout =
                                    Some(Duration::from_millis(wire::be_u64(attribute.payload)?))
                            }
                            5 => {
                                expiration =
                                    Some(Duration::from_millis(wire::be_u64(attribute.payload)?))
                            }
                            _ => (),
                        }
                    }
                    result.push(NftElement {
                        key: key.context("nftset element has no key")?,
                        end: flags & 1 != 0,
                        timeout,
                        expiration,
                    });
                }
            }
        }
        Ok(result)
    }
    fn cleanup(&mut self) -> Result<()> {
        if self.owned {
            nft_transaction(
                &mut self.socket,
                2,
                wire::string_attribute(1, &self.table, 256)?,
                false,
            )?;
            self.owned = false;
        }
        Ok(())
    }
}
impl Drop for NftFixture {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("cleanup of isolated table {} failed: {error:#}", self.table);
        }
    }
}
struct NftElement {
    key: Vec<u8>,
    end: bool,
    timeout: Option<Duration>,
    expiration: Option<Duration>,
}

fn address_bytes(address: &str) -> Vec<u8> {
    match address.parse::<IpAddr>().unwrap() {
        IpAddr::V4(ip) => ip.octets().to_vec(),
        IpAddr::V6(ip) => ip.octets().to_vec(),
    }
}

#[test]
#[ignore = "requires Linux root/CAP_NET_ADMIN and creates isolated nftables fixtures"]
fn native_nftset_membership_interval_families_and_set_default_timeout() -> Result<()> {
    let mut fixture = NftFixture::new()?;
    let plain = fixture.create_set("plain4", false, false, Some(Duration::from_secs(60)))?;
    let ranges4 = fixture.create_set("ranges4", false, true, None)?;
    let ranges6 = fixture.create_set("ranges6", true, true, None)?;
    let plain_handler = NftSetHandler::new(plain.clone(), IO_TIMEOUT)?;
    let metadata = plain_handler.metadata()?;
    assert!(metadata.has_timeout());
    assert_eq!(metadata.default_timeout, Some(Duration::from_secs(60)));
    plain_handler.add_elements(&["192.0.2.123/24".parse::<IpNet>()?.into()])?;
    let elements = fixture.elements(&plain)?;
    assert_eq!(elements.len(), 1);
    assert_eq!(elements[0].key, address_bytes("192.0.2.123"));
    assert!(!elements[0].end);
    assert_eq!(
        elements[0].timeout.or(metadata.default_timeout),
        Some(Duration::from_secs(60))
    );
    assert!(elements[0]
        .expiration
        .is_some_and(|value| value > Duration::ZERO && value <= Duration::from_secs(60)));
    for (target, prefix, start, end) in [
        (&ranges4, "198.51.100.9/24", "198.51.100.0", "198.51.101.0"),
        (
            &ranges6,
            "2001:db8:abcd:1234::9/48",
            "2001:db8:abcd::",
            "2001:db8:abce::",
        ),
    ] {
        let handler = NftSetHandler::new(target.clone(), IO_TIMEOUT)?;
        assert!(handler.metadata()?.interval());
        handler.add_elements(&[prefix.parse::<IpNet>()?.into()])?;
        let elements = fixture.elements(target)?;
        assert_eq!(elements.len(), 2);
        assert!(elements
            .iter()
            .any(|element| element.key == address_bytes(start) && !element.end));
        assert!(elements
            .iter()
            .any(|element| element.key == address_bytes(end) && element.end));
        handler.close()?;
    }
    plain_handler.close()?;
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires Linux root/CAP_NET_ADMIN and creates an isolated nftables timeout set"]
fn native_nftset_explicit_timeout_is_read_back_without_timing_out_end_marker() -> Result<()> {
    let mut fixture = NftFixture::new()?;
    let target = fixture.create_set("timeout4", false, true, Some(Duration::from_secs(60)))?;
    let handler = NftSetHandler::new(target.clone(), IO_TIMEOUT)?;
    handler.add_elements(&[Element {
        prefix: "203.0.113.7/24".parse()?,
        timeout: Some(Duration::from_millis(3500)),
    }])?;
    let elements = fixture.elements(&target)?;
    assert_eq!(elements.len(), 2);
    let start = elements.iter().find(|element| !element.end).unwrap();
    assert_eq!(start.timeout, Some(Duration::from_millis(3500)));
    assert!(start
        .expiration
        .is_some_and(|value| value > Duration::ZERO && value <= Duration::from_millis(3500)));
    let end = elements.iter().find(|element| element.end).unwrap();
    // Some kernels include a zero timeout when dumping an interval-end marker.
    assert_eq!(end.timeout.unwrap_or_default(), Duration::ZERO);
    handler.close()?;
    fixture.cleanup()?;
    Ok(())
}

#[cfg(feature = "full")]
fn ipset_command(
    socket: &mut NetfilterSocket,
    operation: u16,
    mut attributes: Vec<u8>,
    exclusive: bool,
) -> Result<()> {
    let sequence = socket.next_sequence();
    let mut payload = wire::nfgen(2, 0);
    payload.extend(wire::attribute(1, &[6])?);
    payload.append(&mut attributes);
    let request = wire::Message {
        kind: (wire::IPSET_SUBSYSTEM << 8) | operation,
        flags: wire::REQUEST | wire::ACK | if exclusive { 0x200 } else { 0 },
        sequence,
        port: socket.port,
        payload,
    };
    socket
        .exchange(&[request], &[sequence], None)
        .with_context(|| format!("ipset fixture operation={operation} exclusive={exclusive}"))?;
    Ok(())
}

#[test]
#[ignore = "requires Linux root/CAP_NET_ADMIN; reads IPSET protocol without creating any objects"]
#[cfg(feature = "full")]
fn native_ipset_protocol_only_reports_subsystem_availability() -> Result<()> {
    let mut socket = NetfilterSocket::open(IO_TIMEOUT)?;
    let sequence = socket.next_sequence();
    let mut payload = wire::nfgen(2, 0);
    payload.extend(wire::attribute(1, &[6])?);
    let request = wire::Message {
        kind: (wire::IPSET_SUBSYSTEM << 8) | 1,
        flags: wire::REQUEST | wire::ACK,
        sequence,
        port: socket.port,
        payload,
    };
    let replies = socket
        .exchange(&[request], &[sequence], Some((sequence, 1)))
        .context("IPSET_CMD_PROTOCOL operation=1 protocol-only query; no sets were created")?;
    assert_eq!(replies.len(), 1);
    let reply = &replies[0];
    assert_eq!(reply.kind, (wire::IPSET_SUBSYSTEM << 8) | 1);
    if reply.payload.len() < 4 {
        bail!("short IPSET protocol response");
    }
    let attributes = wire::attributes(&reply.payload[4..])?;
    let protocol = attributes
        .iter()
        .find(|attribute| attribute.kind == 1)
        .context("IPSET protocol response omitted its version")?;
    assert_eq!(protocol.payload.len(), 1);
    assert!(
        protocol.payload[0] >= 6,
        "kernel IPSET protocol does not support version 6"
    );
    if let Some(minimum) = attributes.iter().find(|attribute| attribute.kind == 10) {
        assert_eq!(minimum.payload.len(), 1);
        assert!(
            minimum.payload[0] <= 6,
            "kernel IPSET minimum protocol exceeds version 6"
        );
    }
    Ok(())
}

#[cfg(feature = "full")]
struct IpSetFixture {
    socket: NetfilterSocket,
    sets: Vec<String>,
}
#[cfg(feature = "full")]
struct IpSetElement {
    address: Vec<u8>,
    cidr: u8,
    timeout: Option<u32>,
}
#[cfg(feature = "full")]
impl IpSetFixture {
    fn new() -> Result<Self> {
        Ok(Self {
            socket: NetfilterSocket::open(IO_TIMEOUT)?,
            sets: Vec::new(),
        })
    }
    fn create(&mut self, ipv6: bool) -> Result<String> {
        let name = fixture_name(if ipv6 { "i6" } else { "i4" });
        let mut attributes = wire::string_attribute(2, &name, 32)?;
        attributes.extend(wire::string_attribute(3, "hash:net", 32)?);
        attributes.extend(wire::attribute(4, &[1])?);
        attributes.extend(wire::attribute(5, &[if ipv6 { 10 } else { 2 }])?);
        let data = wire::attribute(6 | wire::NLA_NETWORK_ORDER, &60u32.to_be_bytes())?;
        attributes.extend(wire::attribute(7 | wire::NLA_NESTED, &data)?);
        ipset_command(&mut self.socket, 2, attributes, true)?;
        self.sets.push(name.clone());
        Ok(name)
    }
    fn elements(&mut self, name: &str) -> Result<Vec<IpSetElement>> {
        let sequence = self.socket.next_sequence();
        let mut payload = wire::nfgen(2, 0);
        payload.extend(wire::attribute(1, &[6])?);
        payload.extend(wire::string_attribute(2, name, 32)?);
        let request = wire::Message {
            kind: (wire::IPSET_SUBSYSTEM << 8) | 7,
            flags: wire::REQUEST | 0x300,
            sequence,
            port: self.socket.port,
            payload,
        };
        let replies = self.socket.exchange(&[request], &[], None)?;
        let mut entries = Vec::new();
        for reply in replies {
            if reply.payload.len() < 4 {
                bail!("short ipset element dump");
            }
            for list in wire::attributes(&reply.payload[4..])?
                .iter()
                .filter(|attribute| attribute.kind == 8)
            {
                for element in wire::attributes(list.payload)? {
                    let mut address = None;
                    let mut cidr = None;
                    let mut timeout = None;
                    for attribute in wire::attributes(element.payload)? {
                        match attribute.kind {
                            1 => {
                                address = Some(
                                    wire::attributes(attribute.payload)?
                                        .into_iter()
                                        .find(|attribute| matches!(attribute.kind, 1 | 2))
                                        .context("ipset element omitted address")?
                                        .payload
                                        .to_vec(),
                                )
                            }
                            3 if attribute.payload.len() == 1 => cidr = Some(attribute.payload[0]),
                            6 => timeout = Some(wire::be_u32(attribute.payload)?),
                            _ => (),
                        }
                    }
                    entries.push(IpSetElement {
                        address: address.context("ipset element has no IP")?,
                        cidr: cidr.context("ipset element has no CIDR")?,
                        timeout,
                    });
                }
            }
        }
        Ok(entries)
    }
    fn cleanup(&mut self) -> Result<()> {
        while let Some(name) = self.sets.last().cloned() {
            ipset_command(
                &mut self.socket,
                3,
                wire::string_attribute(2, &name, 32)?,
                true,
            )?;
            self.sets.pop();
        }
        Ok(())
    }
}
#[cfg(feature = "full")]
impl Drop for IpSetFixture {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!(
                "cleanup of isolated ipsets {:?} failed: {error:#}",
                self.sets
            );
        }
    }
}

#[test]
#[ignore = "requires Linux root/CAP_NET_ADMIN and the hash:net ipset kernel module"]
#[cfg(feature = "full")]
fn native_ipset_v4_v6_prefix_deduplication_and_default_timeout() -> Result<()> {
    let mut fixture = IpSetFixture::new()?;
    for (ipv6, first, second, network, mask) in [
        (false, "192.0.2.1/24", "192.0.2.2/24", "192.0.2.0", 24),
        (
            true,
            "2001:db8:abcd::1/48",
            "2001:db8:abcd::2/48",
            "2001:db8:abcd::",
            48,
        ),
    ] {
        let name = fixture.create(ipv6)?;
        let handler = IpSetHandler::new(name.clone(), IO_TIMEOUT)?;
        handler.add_elements(&[
            first.parse::<IpNet>()?.into(),
            second.parse::<IpNet>()?.into(),
        ])?;
        let entries = fixture.elements(&name)?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].address, address_bytes(network));
        assert_eq!(entries[0].cidr, mask);
        assert!(entries[0]
            .timeout
            .is_some_and(|timeout| timeout > 0 && timeout <= 60));
        handler.close()?;
    }
    fixture.cleanup()?;
    Ok(())
}

#[test]
#[ignore = "requires Linux root/CAP_NET_ADMIN; verifies ipset's seconds rounding with readback"]
#[cfg(feature = "full")]
fn native_ipset_explicit_timeout_rounds_up_to_seconds() -> Result<()> {
    let mut fixture = IpSetFixture::new()?;
    let name = fixture.create(false)?;
    let handler = IpSetHandler::new(name.clone(), IO_TIMEOUT)?;
    handler.add_elements(&[Element {
        prefix: "203.0.113.7/32".parse()?,
        timeout: Some(Duration::from_millis(5500)),
    }])?;
    let entries = fixture.elements(&name)?;
    assert_eq!(entries.len(), 1);
    assert!(entries[0]
        .timeout
        .is_some_and(|timeout| timeout > 0 && timeout <= 6));
    handler.close()?;
    fixture.cleanup()?;
    Ok(())
}
