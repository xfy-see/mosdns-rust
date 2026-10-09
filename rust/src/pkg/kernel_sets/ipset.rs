use super::{wire, Element};
use anyhow::{Context, Result};
use std::net::IpAddr;

/// Existing sets only. Protocol 6 preserves compatibility with the Go ipset
/// dependency; omitted EXCL allows duplicate additions to the same prefix.
pub fn add_prefix(set: &str, element: &Element, sequence: u32, port: u32) -> Result<wire::Message> {
    let mut payload = wire::nfgen(2, 0);
    payload.extend(wire::attribute(1, &[6])?);
    payload.extend(wire::string_attribute(2, set, 32)?);
    let (kind, address) = match element.prefix.addr() {
        IpAddr::V4(ip) => (1, ip.octets().to_vec()),
        IpAddr::V6(ip) => (2, ip.octets().to_vec()),
    };
    let mut data = wire::attribute(
        1 | wire::NLA_NESTED,
        &wire::attribute(kind | wire::NLA_NETWORK_ORDER, &address)?,
    )?;
    data.extend(wire::attribute(3, &[element.prefix.prefix_len()])?);
    if let Some(timeout) = element.timeout {
        // Round upward: subsecond TTL must not become zero/permanent or expire
        // before the DNS RR it protects.
        let seconds = timeout
            .as_secs()
            .checked_add(u64::from(timeout.subsec_nanos() != 0))
            .context("ipset timeout overflow")?;
        let seconds = u32::try_from(seconds).context("ipset timeout exceeds u32 seconds")?;
        data.extend(wire::attribute(
            6 | wire::NLA_NETWORK_ORDER,
            &seconds.to_be_bytes(),
        )?);
    }
    data.extend(wire::attribute(
        9 | wire::NLA_NETWORK_ORDER,
        &0u32.to_be_bytes(),
    )?);
    payload.extend(wire::attribute(7 | wire::NLA_NESTED, &data)?);
    Ok(wire::Message {
        kind: (wire::IPSET_SUBSYSTEM << 8) | 9,
        flags: wire::REQUEST | wire::ACK,
        sequence,
        port,
        payload,
    })
}
