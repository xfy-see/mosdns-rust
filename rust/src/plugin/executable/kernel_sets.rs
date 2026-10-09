// SPDX-License-Identifier: GPL-3.0-or-later
//! Sequence quick syntax for native Linux IP sets. Targets must already exist.
#[cfg(feature = "full")]
use crate::pkg::kernel_sets::IpSetHandler;
use crate::pkg::kernel_sets::{nft::Target, response_elements, NftSetHandler, TimeoutPolicy};
use anyhow::{bail, Context, Result};
use hickory_proto::op::Message;
use std::time::Duration;

enum Handler {
    #[cfg(feature = "full")]
    Ip(IpSetHandler),
    Nft(NftSetHandler),
}
pub struct KernelSets {
    ipv4: Option<Handler>,
    ipv6: Option<Handler>,
    mask4: u8,
    mask6: u8,
}
impl KernelSets {
    pub fn parse(kind: &str, arguments: &str) -> Result<Self> {
        if !cfg!(target_os = "linux") {
            bail!("{kind} requires Linux");
        }
        let fields = arguments.split_whitespace().collect::<Vec<_>>();
        if fields.len() > 2 {
            bail!("{kind} expects no more than two set specifications");
        }
        let mut result = Self {
            ipv4: None,
            ipv6: None,
            mask4: 24,
            mask6: if kind == "nftset" { 48 } else { 32 },
        };
        for field in fields {
            let pieces = field.split(',').collect::<Vec<_>>();
            let (ipv6, mask, handler) = match kind {
                #[cfg(feature = "full")]
                "ipset" => {
                    if pieces.len() != 3 {
                        bail!("ipset expects set_name,inet|inet6,mask");
                    }
                    let ipv6 = match pieces[1] {
                        "inet" => false,
                        "inet6" => true,
                        _ => bail!("invalid ipset family"),
                    };
                    let mask = parse_mask(pieces[2], ipv6, if ipv6 { 32 } else { 24 })?;
                    (
                        ipv6,
                        mask,
                        Handler::Ip(IpSetHandler::new(
                            pieces[0].to_owned(),
                            Duration::from_secs(1),
                        )?),
                    )
                }
                "nftset" => {
                    if pieces.len() != 5 {
                        bail!("nftset expects table_family,table_name,set_name,ipv4_addr|ipv6_addr,mask");
                    }
                    let ipv6 = match pieces[3] {
                        "ipv4_addr" => false,
                        "ipv6_addr" => true,
                        _ => bail!("invalid nftset address type"),
                    };
                    let mask = parse_mask(pieces[4], ipv6, if ipv6 { 48 } else { 24 })?;
                    let target = Target {
                        family: pieces[0].parse()?,
                        table: pieces[1].to_owned(),
                        set: pieces[2].to_owned(),
                    };
                    (
                        ipv6,
                        mask,
                        Handler::Nft(NftSetHandler::new(target, Duration::from_secs(1))?),
                    )
                }
                _ => bail!("invalid kernel set plugin {kind}"),
            };
            if ipv6 {
                result.ipv6 = Some(handler);
                result.mask6 = mask;
            } else {
                result.ipv4 = Some(handler);
                result.mask4 = mask;
            }
        }
        Ok(result)
    }
    pub async fn apply(&self, response: &Message) -> Result<()> {
        let (ipv4, ipv6) =
            response_elements(response, self.mask4, self.mask6, TimeoutPolicy::SetDefault)?;
        for (handler, elements) in [(&self.ipv4, ipv4), (&self.ipv6, ipv6)] {
            if elements.is_empty() {
                continue;
            }
            match handler {
                #[cfg(feature = "full")]
                Some(Handler::Ip(handler)) => handler.add_elements_async(elements).await?,
                Some(Handler::Nft(handler)) => handler.add_elements_async(elements).await?,
                None => (),
            }
        }
        Ok(())
    }
}
fn parse_mask(value: &str, ipv6: bool, default: u8) -> Result<u8> {
    let mask: i64 = value.parse().context("invalid set mask")?;
    if mask <= 0 {
        return Ok(default);
    }
    if mask > if ipv6 { 128 } else { 32 } {
        bail!("set mask exceeds IP address width");
    }
    Ok(mask as u8)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn masks_retain_go_defaults_and_validate_address_width() {
        assert_eq!(parse_mask("0", false, 24).unwrap(), 24);
        assert_eq!(parse_mask("-1", true, 48).unwrap(), 48);
        assert_eq!(parse_mask("128", true, 48).unwrap(), 128);
        assert!(parse_mask("33", false, 24).is_err());
        assert!(parse_mask("invalid", true, 48).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn quick_syntax_is_validated_without_writing_to_kernel() {
        assert!(KernelSets::parse(
            "nftset",
            "inet,example,cn4,ipv4_addr,24 inet,example,cn6,ipv6_addr,48"
        )
        .is_ok());
        #[cfg(feature = "full")]
        assert!(KernelSets::parse("ipset", "cn4,inet,24 cn6,inet6,32").is_ok());
        #[cfg(not(feature = "full"))]
        assert!(KernelSets::parse("ipset", "cn4,inet,24 cn6,inet6,32").is_err());
        for (kind, args) in [
            ("nftset", "bad,table,set,ipv4_addr,24"),
            ("nftset", "inet,t,s,ipv4_addr,33"),
            ("ipset", "cn,bad,24"),
            ("ipset", "a,inet,24 b,inet6,64 c,inet,32"),
        ] {
            assert!(KernelSets::parse(kind, args).is_err());
        }
    }
}
