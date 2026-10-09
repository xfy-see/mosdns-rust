// SPDX-License-Identifier: GPL-3.0-or-later
//! Wire encoders for Go's master-file RR types. Opaque RDATA contains no pointers.
use super::zone::{name_wire, octets, time, Token};
use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hickory_proto::rr::Name;
use std::{
    collections::BTreeMap,
    net::{Ipv4Addr, Ipv6Addr},
};

pub(super) fn record_type(text: &str) -> Option<u16> {
    let upper = text.to_ascii_uppercase();
    if let Some(number) = upper.strip_prefix("TYPE") {
        return number.parse().ok();
    }
    match upper.as_str() {
        "A" => Some(1),
        "NS" => Some(2),
        "MD" => Some(3),
        "MF" => Some(4),
        "CNAME" => Some(5),
        "SOA" => Some(6),
        "MB" => Some(7),
        "MG" => Some(8),
        "MR" => Some(9),
        "NULL" => Some(10),
        "PTR" => Some(12),
        "HINFO" => Some(13),
        "MINFO" => Some(14),
        "MX" => Some(15),
        "TXT" => Some(16),
        "RP" => Some(17),
        "AFSDB" => Some(18),
        "X25" => Some(19),
        "ISDN" => Some(20),
        "RT" => Some(21),
        "NSAP-PTR" => Some(23),
        "SIG" => Some(24),
        "KEY" => Some(25),
        "PX" => Some(26),
        "GPOS" => Some(27),
        "AAAA" => Some(28),
        "LOC" => Some(29),
        "NXT" => Some(30),
        "EID" => Some(31),
        "NIMLOC" => Some(32),
        "SRV" => Some(33),
        "ATMA" => Some(34),
        "NAPTR" => Some(35),
        "KX" => Some(36),
        "CERT" => Some(37),
        "DNAME" => Some(39),
        "OPT" => Some(41),
        "APL" => Some(42),
        "DS" => Some(43),
        "SSHFP" => Some(44),
        "IPSECKEY" => Some(45),
        "RRSIG" => Some(46),
        "NSEC" => Some(47),
        "DNSKEY" => Some(48),
        "DHCID" => Some(49),
        "NSEC3" => Some(50),
        "NSEC3PARAM" => Some(51),
        "TLSA" => Some(52),
        "SMIMEA" => Some(53),
        "HIP" => Some(55),
        "NINFO" => Some(56),
        "RKEY" => Some(57),
        "TALINK" => Some(58),
        "CDS" => Some(59),
        "CDNSKEY" => Some(60),
        "OPENPGPKEY" => Some(61),
        "CSYNC" => Some(62),
        "ZONEMD" => Some(63),
        "SVCB" => Some(64),
        "HTTPS" => Some(65),
        "SPF" => Some(99),
        "UINFO" => Some(100),
        "UID" => Some(101),
        "GID" => Some(102),
        "UNSPEC" => Some(103),
        "NID" => Some(104),
        "L32" => Some(105),
        "L64" => Some(106),
        "LP" => Some(107),
        "EUI48" => Some(108),
        "EUI64" => Some(109),
        "NXNAME" => Some(128),
        "TKEY" => Some(249),
        "TSIG" => Some(250),
        "IXFR" => Some(251),
        "AXFR" => Some(252),
        "MAILB" => Some(253),
        "MAILA" => Some(254),
        "ANY" => Some(255),
        "URI" => Some(256),
        "CAA" => Some(257),
        "AVC" => Some(258),
        "AMTRELAY" => Some(260),
        "RESINFO" => Some(261),
        "TA" => Some(32768),
        "DLV" => Some(32769),
        _ => None,
    }
}
fn go_record_type(typ: u16) -> bool {
    matches!(typ,1..=10|12..=21|23..=33|35..=37|39|41..=53|55..=65|99..=102|104..=109|128|249..=258|260|261|32768|32769)
}
fn empty_rdata(typ: u16) -> Vec<u8> {
    // Go returns the zero-valued RR struct for an omitted RDATA. Its encoder
    // still writes fixed scalar/string fields; empty domain fields emit nothing.
    let length = match typ {
        6 => 20,
        13 | 15 | 18 | 20 | 21 | 36 | 107 | 44 | 260 | 64 | 65 => 2,
        19 => 1,
        24 | 46 => 18,
        25 | 48 | 57 | 60 | 43 | 59 | 32768 | 32769 | 101 | 102 | 55 | 256 => 4,
        27 | 45 | 52 | 53 => 3,
        29 | 249 | 250 => 16,
        33 | 62 | 63 | 50 | 108 => 6,
        35 => 7,
        37 | 51 => 5,
        104 | 106 => 10,
        105 => 2,
        109 => 8,
        257 => 2,
        _ => 0,
    };
    vec![0; length]
}
fn svc_param(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut output = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\\' {
            output.push(bytes[i]);
            i += 1;
            continue;
        }
        i += 1;
        let byte = *bytes
            .get(i)
            .ok_or_else(|| anyhow!("unfinished SVCB parameter escape"))?;
        if byte.is_ascii_digit() {
            let digits = bytes
                .get(i..i + 3)
                .ok_or_else(|| anyhow!("incomplete SVCB octet"))?;
            if !digits.iter().all(u8::is_ascii_digit) {
                bail!("invalid SVCB octet");
            }
            let value = number(std::str::from_utf8(digits)?, 8)? as u8;
            output.push(value);
            i += 3;
        } else {
            output.push(byte);
            i += 1;
        }
    }
    Ok(output)
}
fn field(tokens: &[Token], index: usize) -> Result<&str> {
    tokens
        .get(index)
        .map(|token| token.raw.as_str())
        .ok_or_else(|| anyhow!("missing RDATA field {index}"))
}
/// Go decodes generic RDATA into its known RR struct before packing it again.
/// Fixed fields ending exactly at EOF retain their zero value; partial fields fail.
fn generic(typ: u16, data: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Ok(if go_record_type(typ) {
            empty_rdata(typ)
        } else {
            Vec::new()
        });
    }
    if !go_record_type(typ) {
        return Ok(data.to_vec());
    }
    struct Wire<'a> {
        data: &'a [u8],
        at: usize,
        out: Vec<u8>,
    }
    impl Wire<'_> {
        fn scalar(&mut self, size: usize) -> Result<u64> {
            if self.at == self.data.len() {
                self.out.resize(self.out.len() + size, 0);
                return Ok(0);
            }
            let bytes = self
                .data
                .get(self.at..self.at + size)
                .ok_or_else(|| anyhow!("short RFC3597 scalar field"))?;
            self.at += size;
            self.out.extend(bytes);
            Ok(bytes
                .iter()
                .fold(0, |value, byte| value << 8 | u64::from(*byte)))
        }
        fn blob(&mut self, size: usize) -> Result<()> {
            if self.at == self.data.len() {
                return Ok(());
            }
            let bytes = self
                .data
                .get(self.at..self.at + size)
                .ok_or_else(|| anyhow!("short RFC3597 variable field"))?;
            self.at += size;
            self.out.extend(bytes);
            Ok(())
        }
        fn name(&mut self) -> Result<()> {
            use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};
            if self.at == self.data.len() {
                return Ok(());
            }
            let mut decoder = BinDecoder::new(self.data);
            decoder.read_slice(self.at)?;
            let name = Name::read(&mut decoder)?;
            self.at = decoder.index();
            for label in name.iter() {
                self.out.push(label.len() as u8);
                self.out.extend(label);
            }
            self.out.push(0);
            Ok(())
        }
        fn character(&mut self) -> Result<()> {
            let len = self.scalar(1)? as usize;
            if self.data.len() - self.at < len {
                bail!("short RFC3597 character string");
            }
            self.blob(len)
        }
        fn rest(&mut self) {
            self.out.extend(&self.data[self.at..]);
            self.at = self.data.len();
        }
        fn bitmap(&mut self) -> Result<()> {
            let mut previous = None;
            while self.at < self.data.len() {
                let header = self
                    .data
                    .get(self.at..self.at + 2)
                    .ok_or_else(|| anyhow!("short RFC3597 bitmap header"))?;
                let window = header[0];
                let len = usize::from(header[1]);
                self.at += 2;
                if len == 0 || len > 32 || previous.is_some_and(|n| window <= n) {
                    bail!("invalid RFC3597 type bitmap");
                }
                previous = Some(window);
                let bytes = self
                    .data
                    .get(self.at..self.at + len)
                    .ok_or_else(|| anyhow!("short RFC3597 bitmap"))?;
                self.at += len;
                if let Some(last) = bytes.iter().rposition(|byte| *byte != 0) {
                    self.out.extend([window, (last + 1) as u8]);
                    self.out.extend(&bytes[..=last]);
                }
            }
            Ok(())
        }
        fn gateway(&mut self, typ: u8) -> Result<()> {
            match typ {
                0 => Ok(()),
                1 => self.blob(4),
                2 => self.blob(16),
                3 => self.name(),
                _ => bail!("invalid generic gateway type"),
            }
        }
        fn pairs(&mut self) -> Result<()> {
            while self.at < self.data.len() {
                if self.data.len() - self.at < 4 {
                    bail!("short generic option header");
                }
                self.scalar(2)?;
                let length = self.scalar(2)? as usize;
                if self.data.len() - self.at < length {
                    bail!("short generic option value");
                }
                self.blob(length)?;
            }
            Ok(())
        }
        fn svc_pairs(&mut self) -> Result<()> {
            let mut previous = None;
            while self.at < self.data.len() {
                if self.data.len() - self.at < 4 {
                    bail!("short SVCB wire header");
                }
                let key = self.scalar(2)? as u16;
                let length = self.scalar(2)? as usize;
                if key == 65535 || previous.is_some_and(|old| key <= old) {
                    bail!("unordered or reserved SVCB key");
                }
                previous = Some(key);
                let bytes = self
                    .data
                    .get(self.at..self.at + length)
                    .ok_or_else(|| anyhow!("short SVCB wire value"))?;
                match key {
                    0 if !length.is_multiple_of(2) => bail!("odd mandatory SVCB value"),
                    1 => {
                        let mut index = 0;
                        while index < length {
                            let n = usize::from(bytes[index]);
                            index += 1 + n;
                            if index > length {
                                bail!("short SVCB ALPN");
                            }
                        }
                    }
                    2 | 8 if length != 0 => bail!("nonempty flag SVCB value"),
                    3 if length != 2 => bail!("short SVCB port"),
                    4 if length == 0 || !length.is_multiple_of(4) => bail!("short SVCB IPv4 hint"),
                    6 => {
                        if length == 0 || !length.is_multiple_of(16) {
                            bail!("short SVCB IPv6 hint");
                        }
                        for address in bytes.as_chunks::<16>().0 {
                            if Ipv6Addr::from(*address).to_ipv4_mapped().is_some() {
                                bail!("mapped IPv6 hint");
                            }
                        }
                    }
                    _ => {}
                }
                if key == 0 {
                    let mut keys = bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                        .collect::<Vec<_>>();
                    keys.sort_unstable();
                    for key in keys {
                        self.out.extend(key.to_be_bytes());
                    }
                    self.at += length;
                } else {
                    self.blob(length)?;
                }
            }
            Ok(())
        }
    }
    let mut w = Wire {
        data,
        at: 0,
        out: Vec::new(),
    };
    match typ {
        1 => w.blob(4)?,
        28 => w.blob(16)?,
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 23 | 39 => w.name()?,
        14 | 17 | 58 => {
            w.name()?;
            w.name()?;
        }
        15 | 18 | 21 | 36 | 107 => {
            w.scalar(2)?;
            w.name()?;
        }
        26 => {
            w.scalar(2)?;
            w.name()?;
            w.name()?;
        }
        6 => {
            w.name()?;
            w.name()?;
            for _ in 0..5 {
                w.scalar(4)?;
            }
        }
        13 | 20 => {
            w.character()?;
            w.character()?;
        }
        19 | 100 => w.character()?,
        16 | 56 | 99 | 258 | 261 => {
            while w.at < data.len() {
                w.character()?;
            }
        }
        27 => {
            for _ in 0..3 {
                w.character()?;
            }
        }
        29 => {
            for _ in 0..4 {
                w.scalar(1)?;
            }
            for _ in 0..3 {
                w.scalar(4)?;
            }
        }
        33 => {
            for _ in 0..3 {
                w.scalar(2)?;
            }
            w.name()?;
        }
        35 => {
            w.scalar(2)?;
            w.scalar(2)?;
            for _ in 0..3 {
                w.character()?;
            }
            w.name()?;
        }
        24 | 46 => {
            w.scalar(2)?;
            w.scalar(1)?;
            w.scalar(1)?;
            for _ in 0..3 {
                w.scalar(4)?;
            }
            w.scalar(2)?;
            w.name()?;
            w.rest();
        }
        25 | 48 | 57 | 60 | 43 | 59 | 32768 | 32769 => {
            w.scalar(2)?;
            w.scalar(1)?;
            w.scalar(1)?;
            w.rest();
        }
        37 => {
            w.scalar(2)?;
            w.scalar(2)?;
            w.scalar(1)?;
            w.rest();
        }
        44 => {
            w.scalar(1)?;
            w.scalar(1)?;
            w.rest();
        }
        52 | 53 => {
            for _ in 0..3 {
                w.scalar(1)?;
            }
            w.rest();
        }
        30 | 47 => {
            w.name()?;
            w.bitmap()?;
        }
        62 => {
            w.scalar(4)?;
            w.scalar(2)?;
            w.bitmap()?;
        }
        63 => {
            w.scalar(4)?;
            w.scalar(1)?;
            w.scalar(1)?;
            w.rest();
        }
        50 | 51 => {
            w.scalar(1)?;
            w.scalar(1)?;
            w.scalar(2)?;
            let salt = w.scalar(1)? as usize;
            w.blob(salt)?;
            if typ == 50 {
                let hash = w.scalar(1)? as usize;
                w.blob(hash)?;
                w.bitmap()?;
            }
        }
        55 => {
            let hit = w.scalar(1)? as usize;
            w.scalar(1)?;
            let key = w.scalar(2)? as usize;
            w.blob(hit)?;
            w.blob(key)?;
            while w.at < data.len() {
                w.name()?;
            }
        }
        45 => {
            w.scalar(1)?;
            let gateway = w.scalar(1)? as u8;
            w.scalar(1)?;
            w.gateway(gateway)?;
            w.rest();
        }
        260 => {
            w.scalar(1)?;
            let gateway = w.scalar(1)? as u8;
            w.gateway(gateway & 0x7f)?;
        }
        101 | 102 => {
            w.scalar(4)?;
        }
        104 | 106 => {
            w.scalar(2)?;
            w.scalar(8)?;
        }
        105 => {
            w.scalar(2)?;
            w.blob(4)?;
        }
        108 => {
            w.scalar(6)?;
        }
        109 => {
            w.scalar(8)?;
        }
        64 | 65 => {
            w.scalar(2)?;
            w.name()?;
            w.svc_pairs()?;
        }
        249 => {
            w.name()?;
            w.scalar(4)?;
            w.scalar(4)?;
            w.scalar(2)?;
            w.scalar(2)?;
            let key = w.scalar(2)? as usize;
            w.blob(key)?;
            let other = w.scalar(2)? as usize;
            w.blob(other)?;
        }
        250 => {
            w.name()?;
            w.scalar(6)?;
            w.scalar(2)?;
            let mac = w.scalar(2)? as usize;
            w.blob(mac)?;
            w.scalar(2)?;
            w.scalar(2)?;
            let other = w.scalar(2)? as usize;
            w.blob(other)?;
        }
        256 => {
            w.scalar(2)?;
            w.scalar(2)?;
            w.rest();
        }
        257 => {
            w.scalar(1)?;
            w.character()?;
            w.rest();
        }
        41 => w.pairs()?,
        42 => {
            while w.at < data.len() {
                w.scalar(2)?;
                w.scalar(1)?;
                let length = w.scalar(1)? as usize & 0x7f;
                w.blob(length)?;
            }
        }
        255 => {}
        _ => w.rest(),
    }
    if w.out.len() > 65535 {
        bail!("expanded generic RDATA exceeds 65535 octets");
    }
    Ok(w.out)
}
fn count(tokens: &[Token], expected: usize) -> Result<()> {
    if tokens.len() != expected {
        bail!("expected {expected} RDATA fields, got {}", tokens.len());
    }
    Ok(())
}
fn number(text: &str, bits: u8) -> Result<u64> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid unsigned RDATA number {text}");
    }
    let number = text.parse::<u64>()?;
    if bits < 64 && number >= (1u64 << bits) {
        bail!("RDATA number {text} overflows {bits} bits");
    }
    Ok(number)
}
fn u8_at(tokens: &[Token], index: usize) -> Result<u8> {
    Ok(number(field(tokens, index)?, 8)? as u8)
}
fn u16_at(tokens: &[Token], index: usize) -> Result<u16> {
    Ok(number(field(tokens, index)?, 16)? as u16)
}
fn u32_at(tokens: &[Token], index: usize) -> Result<u32> {
    Ok(number(field(tokens, index)?, 32)? as u32)
}
fn join(tokens: &[Token]) -> String {
    tokens
        .iter()
        .map(|token| token.raw.as_str())
        .collect::<String>()
}
fn hex(text: &str) -> Result<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        bail!("odd hex RDATA length");
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect()
}
fn b64(tokens: &[Token]) -> Result<Vec<u8>> {
    Ok(STANDARD.decode(join(tokens))?)
}
fn character(output: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    output.push(
        u8::try_from(bytes.len()).map_err(|_| anyhow!("character string exceeds 255 bytes"))?,
    );
    output.extend(bytes);
    Ok(())
}
fn strings(tokens: &[Token]) -> Result<Vec<Vec<u8>>> {
    let mut result = Vec::new();
    for token in tokens {
        let bytes = octets(&token.raw)?;
        if bytes.is_empty() {
            result.push(Vec::new());
        } else {
            result.extend(bytes.chunks(255).map(<[u8]>::to_vec));
        }
    }
    Ok(result)
}
fn algorithm(text: &str) -> Result<u8> {
    Ok(match text {
        "RSAMD5" => 1,
        "DH" => 2,
        "DSA" => 3,
        "RSASHA1" => 5,
        "DSA-NSEC3-SHA1" => 6,
        "RSASHA1-NSEC3-SHA1" => 7,
        "RSASHA256" => 8,
        "RSASHA512" => 10,
        "ECC-GOST" => 12,
        "ECDSAP256SHA256" => 13,
        "ECDSAP384SHA384" => 14,
        "ED25519" => 15,
        "ED448" => 16,
        "INDIRECT" => 252,
        "PRIVATEDNS" => 253,
        "PRIVATEOID" => 254,
        _ => number(text, 8)? as u8,
    })
}
pub(super) fn parse(typ: u16, tokens: &[Token], origin: Option<&Name>) -> Result<Vec<u8>> {
    if tokens.is_empty() {
        if !go_record_type(typ) {
            bail!("unknown type {typ} requires RFC3597 RDATA");
        }
        return Ok(empty_rdata(typ));
    }
    if tokens[0].raw == "\\#" {
        let length = usize::from(u16_at(tokens, 1)?);
        let data = hex(&join(&tokens[2..]))?;
        if data.len() != length {
            bail!("RFC3597 RDATA length mismatch");
        }
        return generic(typ, &data);
    }
    if !matches!(
        typ,
        13 | 16 | 20 | 35 | 56 | 64 | 65 | 99 | 100 | 256 | 257 | 258 | 261
    ) && tokens.iter().any(|token| token.quoted)
    {
        bail!("quoted field is not valid for type {typ}");
    }
    let mut out = Vec::new();
    match typ {
        1 => {
            count(tokens, 1)?;
            out.extend(field(tokens, 0)?.parse::<Ipv4Addr>()?.octets());
        }
        28 => {
            count(tokens, 1)?;
            out.extend(field(tokens, 0)?.parse::<Ipv6Addr>()?.octets());
        }
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 23 | 39 => {
            count(tokens, 1)?;
            out.extend(name_wire(field(tokens, 0)?, origin)?);
        }
        14 | 17 | 58 => {
            count(tokens, 2)?;
            for token in tokens {
                out.extend(name_wire(&token.raw, origin)?);
            }
        }
        15 | 18 | 21 | 36 | 107 => {
            count(tokens, 2)?;
            out.extend(u16_at(tokens, 0)?.to_be_bytes());
            out.extend(name_wire(field(tokens, 1)?, origin)?);
        }
        26 => {
            count(tokens, 3)?;
            out.extend(u16_at(tokens, 0)?.to_be_bytes());
            out.extend(name_wire(field(tokens, 1)?, origin)?);
            out.extend(name_wire(field(tokens, 2)?, origin)?);
        }
        6 => {
            count(tokens, 7)?;
            out.extend(name_wire(field(tokens, 0)?, origin)?);
            out.extend(name_wire(field(tokens, 1)?, origin)?);
            out.extend(u32_at(tokens, 2)?.to_be_bytes());
            for token in &tokens[3..] {
                out.extend(time(&token.raw)?.to_be_bytes());
            }
        }
        16 | 56 | 99 | 258 | 261 => {
            for bytes in strings(tokens)? {
                character(&mut out, &bytes)?;
            }
        }
        100 => {
            if let Some(first) = strings(tokens)?.first() {
                character(&mut out, first)?;
            }
        }
        13 | 20 => {
            let mut parts = strings(tokens)?;
            if parts.len() == 1 {
                let raw_parts = tokens[0].raw.split_whitespace().collect::<Vec<_>>();
                if raw_parts.len() > 1 {
                    parts = raw_parts.into_iter().map(octets).collect::<Result<_>>()?;
                } else {
                    parts.push(Vec::new());
                }
            }
            if parts.is_empty() {
                parts = vec![Vec::new(), Vec::new()];
            }
            character(&mut out, &parts[0])?;
            let rest = parts[1..].join(&b' ');
            character(&mut out, &rest)?;
        }
        19 => {
            count(tokens, 1)?;
            character(&mut out, &octets(field(tokens, 0)?)?)?;
        }
        27 => {
            count(tokens, 3)?;
            for token in tokens {
                token.raw.parse::<f64>()?;
                character(&mut out, token.raw.as_bytes())?;
            }
        }
        33 => {
            count(tokens, 4)?;
            for i in 0..3 {
                out.extend(u16_at(tokens, i)?.to_be_bytes());
            }
            out.extend(name_wire(field(tokens, 3)?, origin)?);
        }
        35 => {
            count(tokens, 6)?;
            out.extend(u16_at(tokens, 0)?.to_be_bytes());
            out.extend(u16_at(tokens, 1)?.to_be_bytes());
            if tokens[..2].iter().chain(&tokens[5..]).any(|t| t.quoted)
                || tokens[2..5].iter().any(|t| !t.quoted)
            {
                bail!("NAPTR requires three quoted strings");
            }
            for token in &tokens[2..5] {
                character(&mut out, &octets(&token.raw)?)?;
            }
            out.extend(name_wire(field(tokens, 5)?, origin)?);
        }
        256 => {
            out.extend(u16_at(tokens, 0)?.to_be_bytes());
            out.extend(u16_at(tokens, 1)?.to_be_bytes());
            let values = strings(&tokens[2..])?;
            if values.len() != 1 {
                bail!("URI requires one target character string");
            }
            out.extend(&values[0]);
        }
        257 => {
            out.push(u8_at(tokens, 0)?);
            character(&mut out, &octets(field(tokens, 1)?)?)?;
            let values = strings(&tokens[2..])?;
            if values.len() != 1 {
                bail!("CAA requires one value character string");
            }
            out.extend(&values[0]);
        }
        24 | 46 => {
            if tokens.len() < 8 {
                bail!("RRSIG requires eight header fields");
            }
            out.extend(
                record_type(field(tokens, 0)?)
                    .ok_or_else(|| anyhow!("bad signature type covered"))?
                    .to_be_bytes(),
            );
            out.push(algorithm(field(tokens, 1)?)?);
            out.push(u8_at(tokens, 2)?);
            out.extend(u32_at(tokens, 3)?.to_be_bytes());
            out.extend(signature_time(field(tokens, 4)?)?.to_be_bytes());
            out.extend(signature_time(field(tokens, 5)?)?.to_be_bytes());
            out.extend(u16_at(tokens, 6)?.to_be_bytes());
            out.extend(name_wire(field(tokens, 7)?, origin)?);
            out.extend(b64(&tokens[8..])?);
        }
        25 | 48 | 57 | 60 => {
            out.extend(u16_at(tokens, 0)?.to_be_bytes());
            out.push(u8_at(tokens, 1)?);
            out.push(u8_at(tokens, 2)?);
            out.extend(b64(&tokens[3..])?);
        }
        43 | 59 | 32768 | 32769 => {
            out.extend(u16_at(tokens, 0)?.to_be_bytes());
            out.push(algorithm(&field(tokens, 1)?.to_ascii_uppercase())?);
            out.push(u8_at(tokens, 2)?);
            out.extend(hex(&join(&tokens[3..]))?);
        }
        44 => {
            out.push(u8_at(tokens, 0)?);
            out.push(u8_at(tokens, 1)?);
            out.extend(hex(&join(&tokens[2..]))?);
        }
        52 | 53 => {
            for i in 0..3 {
                out.push(u8_at(tokens, i)?);
            }
            out.extend(hex(&join(&tokens[3..]))?);
        }
        37 => {
            let cert = match field(tokens, 0)? {
                "PKIX" => 1,
                "SPKI" => 2,
                "PGP" => 3,
                "IPIX" => 4,
                "ISPKI" => 5,
                "IPGP" => 6,
                "ACPKIX" => 7,
                "IACPKIX" => 8,
                "URI" => 253,
                "OID" => 254,
                text => number(text, 16)? as u16,
            };
            out.extend(cert.to_be_bytes());
            out.extend(u16_at(tokens, 1)?.to_be_bytes());
            out.push(algorithm(field(tokens, 2)?)?);
            out.extend(b64(&tokens[3..])?);
        }
        49 | 61 => out.extend(b64(tokens)?),
        63 => {
            out.extend(u32_at(tokens, 0)?.to_be_bytes());
            out.push(u8_at(tokens, 1)?);
            out.push(u8_at(tokens, 2)?);
            out.extend(hex(&join(&tokens[3..]))?);
        }
        30 | 47 => {
            out.extend(name_wire(field(tokens, 0)?, origin)?);
            out.extend(bitmap(&tokens[1..])?);
        }
        62 => {
            out.extend(u32_at(tokens, 0)?.to_be_bytes());
            out.extend(u16_at(tokens, 1)?.to_be_bytes());
            out.extend(bitmap(&tokens[2..])?);
        }
        50 | 51 => {
            out.push(u8_at(tokens, 0)?);
            out.push(u8_at(tokens, 1)?);
            out.extend(u16_at(tokens, 2)?.to_be_bytes());
            let salt = if field(tokens, 3)? == "-" {
                Vec::new()
            } else {
                hex(field(tokens, 3)?)?
            };
            out.push(u8::try_from(salt.len())?);
            out.extend(salt);
            if typ == 50 {
                let hash = base32hex(field(tokens, 4)?)?;
                out.push(20);
                out.extend(hash);
                out.extend(bitmap(&tokens[5..])?);
            } else {
                count(tokens, 4)?;
            }
        }
        31 | 32 => out.extend(hex(&join(tokens))?),
        101 | 102 => {
            count(tokens, 1)?;
            out.extend(u32_at(tokens, 0)?.to_be_bytes());
        }
        104 | 106 => {
            count(tokens, 2)?;
            out.extend(u16_at(tokens, 0)?.to_be_bytes());
            let text = field(tokens, 1)?;
            let parts = text.split(':').collect::<Vec<_>>();
            if parts.len() != 4 || parts.iter().any(|part| part.len() != 4) {
                bail!("invalid ILNP node/locator ID");
            }
            out.extend(hex(&parts.join(""))?);
        }
        105 => {
            count(tokens, 2)?;
            out.extend(u16_at(tokens, 0)?.to_be_bytes());
            out.extend(field(tokens, 1)?.parse::<Ipv4Addr>()?.octets());
        }
        108 | 109 => {
            count(tokens, 1)?;
            let parts = field(tokens, 0)?.split('-').collect::<Vec<_>>();
            if parts.len() != if typ == 108 { 6 } else { 8 } || parts.iter().any(|p| p.len() != 2) {
                bail!("invalid EUI address");
            }
            out.extend(hex(&parts.join(""))?);
        }
        55 => {
            let hit = hex(field(tokens, 1)?)?;
            let key = STANDARD.decode(field(tokens, 2)?)?;
            out.push(u8::try_from(hit.len())?);
            out.push(u8_at(tokens, 0)?);
            out.extend(u16::try_from(key.len())?.to_be_bytes());
            out.extend(hit);
            out.extend(key);
            for token in &tokens[3..] {
                out.extend(name_wire(&token.raw, origin)?);
            }
        }
        45 => {
            out.push(u8_at(tokens, 0)?);
            let gateway_type = u8_at(tokens, 1)?;
            out.push(gateway_type);
            out.push(u8_at(tokens, 2)?);
            out.extend(gateway(gateway_type, field(tokens, 3)?, origin)?);
            out.extend(b64(&tokens[4..])?);
        }
        260 => {
            count(tokens, 4)?;
            let discovery = u8_at(tokens, 1)?;
            if discovery > 1 {
                bail!("bad AMTRELAY discovery bit");
            }
            let typ = u8_at(tokens, 2)? | discovery << 7;
            out.push(u8_at(tokens, 0)?);
            out.push(typ);
            out.extend(gateway(typ & 0x7f, field(tokens, 3)?, origin)?);
        }
        29 => out = loc(tokens)?,
        42 => out = apl(tokens)?,
        64 | 65 => out = svcb(tokens, origin)?,
        249 => {
            count(tokens, 5)?;
            out.extend(name_wire(field(tokens, 0)?, None)?);
            out.extend([0u8; 12]);
            let key = hex(field(tokens, 2)?)?;
            let other = hex(field(tokens, 4)?)?;
            out.extend(u16::from(u8_at(tokens, 1)?).to_be_bytes());
            out.extend(key);
            out.extend(u16::from(u8_at(tokens, 3)?).to_be_bytes());
            out.extend(other);
        }
        _ => bail!("type {typ} requires RFC3597 generic RDATA"),
    }
    if out.len() > 65535 {
        bail!("RDATA exceeds 65535 octets");
    }
    Ok(out)
}
fn bitmap(tokens: &[Token]) -> Result<Vec<u8>> {
    let mut windows = BTreeMap::<u8, Vec<u8>>::new();
    for token in tokens {
        let typ =
            record_type(&token.raw).ok_or_else(|| anyhow!("unknown bitmap type {}", token.raw))?;
        let window = (typ / 256) as u8;
        let octet = usize::from((typ % 256) / 8);
        let bits = windows.entry(window).or_default();
        bits.resize(bits.len().max(octet + 1), 0);
        bits[octet] |= 1 << (7 - typ % 8);
    }
    let mut result = Vec::new();
    for (window, bits) in windows {
        result.extend([window, u8::try_from(bits.len())?]);
        result.extend(bits);
    }
    Ok(result)
}
fn base32hex(text: &str) -> Result<Vec<u8>> {
    let mut result = Vec::new();
    let mut bits = 0u32;
    let mut count = 0u8;
    for byte in text.bytes().take_while(|byte| *byte != b'=') {
        let value = match byte.to_ascii_uppercase() {
            b'0'..=b'9' => byte - b'0',
            b'A'..=b'V' => byte.to_ascii_uppercase() - b'A' + 10,
            _ => bail!("invalid base32hex"),
        };
        bits = bits << 5 | u32::from(value);
        count += 5;
        if count >= 8 {
            count -= 8;
            result.push((bits >> count) as u8);
            bits &= (1 << count) - 1;
        }
    }
    if bits != 0 {
        bail!("nonzero base32hex padding");
    }
    Ok(result)
}
fn signature_time(text: &str) -> Result<u32> {
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("invalid signature time");
    }
    if text.len() != 14 {
        return Ok(number(text, 32)? as u32);
    }
    let year = text[0..4].parse::<i64>()?;
    let month = text[4..6].parse::<i64>()?;
    let day = text[6..8].parse::<i64>()?;
    let hour = text[8..10].parse::<i64>()?;
    let minute = text[10..12].parse::<i64>()?;
    let second = text[12..14].parse::<i64>()?;
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day < 1
        || day > months[(month - 1) as usize]
        || hour > 23
        || minute > 59
        || second > 59
    {
        bail!("invalid signature date");
    }
    let y = year - i64::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * m + 2) / 5 + day - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    Ok((days * 86400 + hour * 3600 + minute * 60 + second) as u32)
}
fn loc(tokens: &[Token]) -> Result<Vec<u8>> {
    fn coordinate(
        tokens: &[Token],
        at: &mut usize,
        maximum: u64,
        positive: &str,
        negative: &str,
    ) -> Result<u32> {
        let degrees = number(field(tokens, *at)?, 32)?;
        *at += 1;
        if degrees > maximum {
            bail!("LOC degrees outside range");
        }
        let mut angle = degrees * 3_600_000;
        let mut direction = field(tokens, *at)?.to_ascii_uppercase();
        *at += 1;
        if direction != positive && direction != negative {
            let minutes = number(&direction, 32)?;
            if minutes > 59 {
                bail!("LOC minutes outside range");
            }
            let seconds = field(tokens, *at)?.parse::<f64>()?;
            *at += 1;
            if !seconds.is_finite() || !(0.0..60.0).contains(&seconds) {
                bail!("LOC seconds outside range");
            }
            angle += minutes * 60_000 + (seconds * 1000.0) as u64;
            direction = field(tokens, *at)?.to_ascii_uppercase();
            *at += 1;
        }
        if angle > maximum * 3_600_000 {
            bail!("LOC coordinate exceeds range");
        }
        let angle = u32::try_from(angle)?;
        match direction.as_str() {
            d if d == positive => Ok((1u32 << 31) + angle),
            d if d == negative => Ok((1u32 << 31) - angle),
            _ => bail!("invalid LOC direction"),
        }
    }
    fn precision(text: &str) -> Result<u8> {
        let text = text.strip_suffix(['m', 'M']).unwrap_or(text);
        let (meters, fraction) = text.split_once('.').unwrap_or((text, ""));
        if text.is_empty() || (text.contains('.') && fraction.is_empty()) {
            bail!("empty LOC precision");
        }
        if fraction.len() > 2
            || (!meters.is_empty() && !meters.bytes().all(|b| b.is_ascii_digit()))
            || !fraction.bytes().all(|b| b.is_ascii_digit())
        {
            bail!("invalid LOC precision");
        }
        let meters = if meters.is_empty() {
            0
        } else {
            number(meters, 64)?
        };
        if meters > 90_000_000 || (meters == 90_000_000 && fraction.bytes().any(|b| b != b'0')) {
            bail!("LOC precision exceeds limit");
        }
        let centimeters = meters * 100
            + if fraction.is_empty() {
                0
            } else {
                number(fraction, 8)? * if fraction.len() == 1 { 10 } else { 1 }
            };
        let mut mantissa = centimeters;
        let mut exponent = 0u8;
        while mantissa > 9 {
            mantissa /= 10;
            exponent += 1;
        }
        Ok((mantissa as u8) << 4 | exponent)
    }
    let mut at = 0;
    let latitude = coordinate(tokens, &mut at, 90, "N", "S")?;
    let longitude = coordinate(tokens, &mut at, 180, "E", "W")?;
    let altitude = field(tokens, at)?;
    let altitude = altitude
        .strip_suffix(['m', 'M'])
        .unwrap_or(altitude)
        .parse::<f64>()?;
    at += 1;
    if !altitude.is_finite() {
        bail!("invalid LOC altitude");
    }
    let altitude = (altitude * 100.0 + 10_000_000.0 + 0.5) as u32;
    let mut dimensions = [0x12, 0x16, 0x13];
    for (dimension, token) in dimensions.iter_mut().zip(&tokens[at..]) {
        *dimension = precision(&token.raw)?;
    }
    let mut out = vec![0, dimensions[0], dimensions[1], dimensions[2]];
    out.extend(latitude.to_be_bytes());
    out.extend(longitude.to_be_bytes());
    out.extend(altitude.to_be_bytes());
    Ok(out)
}
fn apl(tokens: &[Token]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for token in tokens {
        let (negative, text) = token
            .raw
            .strip_prefix('!')
            .map(|s| (true, s))
            .unwrap_or((false, token.raw.as_str()));
        let (family, cidr) = text
            .split_once(':')
            .ok_or_else(|| anyhow!("APL family delimiter missing"))?;
        let family = number(family, 16)? as u16;
        let network = cidr.parse::<ipnet::IpNet>()?;
        if network.addr() != network.network() {
            bail!("APL address has host bits");
        }
        let bytes = match (family, network) {
            (1, ipnet::IpNet::V4(network)) => network.addr().octets().to_vec(),
            (2, ipnet::IpNet::V6(network)) => network.addr().octets().to_vec(),
            _ => bail!("APL address family mismatch"),
        };
        let prefix = network.prefix_len();
        let mut length = bytes.len();
        while length > 0 && bytes[length - 1] == 0 {
            length -= 1;
        }
        out.extend(family.to_be_bytes());
        out.push(prefix);
        out.push(length as u8 | if negative { 128 } else { 0 });
        out.extend(&bytes[..length]);
    }
    Ok(out)
}
fn svcb_key(text: &str) -> Result<u16> {
    Ok(match text {
        "mandatory" => 0,
        "alpn" => 1,
        "no-default-alpn" => 2,
        "port" => 3,
        "ipv4hint" => 4,
        "ech" => 5,
        "ipv6hint" => 6,
        "dohpath" => 7,
        "ohttp" => 8,
        _ => {
            let suffix = text
                .strip_prefix("key")
                .ok_or_else(|| anyhow!("unknown SVCB key"))?;
            let key = number(suffix, 16)? as u16;
            if suffix.starts_with('0') || key <= 8 || key == 65535 {
                bail!("reserved SVCB key");
            }
            key
        }
    })
}
fn svcb(tokens: &[Token], origin: Option<&Name>) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend(u16_at(tokens, 0)?.to_be_bytes());
    out.extend(name_wire(field(tokens, 1)?, origin)?);
    let mut pairs = BTreeMap::new();
    for token in &tokens[2..] {
        if token.adjacent || token.rendered.starts_with('"') {
            bail!("bad SVCB quotation or missing whitespace");
        }
        let (key, text) = token
            .raw
            .split_once('=')
            .unwrap_or((token.raw.as_str(), ""));
        let key = svcb_key(key)?;
        let mut value = Vec::new();
        match key {
            0 => {
                if !text.is_empty() {
                    let mut keys = text
                        .strip_suffix(',')
                        .unwrap_or(text)
                        .split(',')
                        .map(svcb_key)
                        .collect::<Result<Vec<_>>>()?;
                    keys.sort_unstable();
                    for key in keys {
                        value.extend(key.to_be_bytes());
                    }
                }
            }
            1 => {
                let bytes = octets(text)?;
                let mut index = 0;
                let mut protocol = Vec::new();
                while index < bytes.len() {
                    let byte = bytes[index];
                    index += 1;
                    match byte {
                        b',' => {
                            if protocol.is_empty() {
                                bail!("empty SVCB ALPN");
                            }
                            character(&mut value, &protocol)?;
                            protocol.clear();
                        }
                        b'\\' => {
                            let escaped = *bytes
                                .get(index)
                                .ok_or_else(|| anyhow!("unfinished SVCB ALPN escape"))?;
                            index += 1;
                            if escaped != b'\\' && escaped != b',' {
                                bail!("bad SVCB ALPN escape");
                            }
                            protocol.push(escaped);
                        }
                        _ => protocol.push(byte),
                    }
                }
                if !bytes.is_empty() {
                    if protocol.is_empty() {
                        bail!("empty final SVCB ALPN");
                    }
                    character(&mut value, &protocol)?;
                }
            }
            2 | 8 => {
                if !text.is_empty() {
                    bail!("SVCB key does not take a value");
                }
            }
            3 => value.extend((number(text, 16)? as u16).to_be_bytes()),
            4 => {
                if text.is_empty() {
                    bail!("empty IPv4 hint");
                }
                for address in text.strip_suffix(',').unwrap_or(text).split(',') {
                    value.extend(address.parse::<Ipv4Addr>()?.octets());
                }
            }
            5 => value.extend(STANDARD.decode(text)?),
            6 => {
                if text.is_empty() {
                    bail!("empty IPv6 hint");
                }
                for address in text.strip_suffix(',').unwrap_or(text).split(',') {
                    let address = address.parse::<Ipv6Addr>()?;
                    if address.to_ipv4_mapped().is_some() {
                        bail!("IPv4-mapped IPv6 hint");
                    }
                    value.extend(address.octets());
                }
            }
            _ => value = svc_param(text)?,
        }
        if pairs.insert(key, value).is_some() {
            bail!("repeated SVCB key");
        }
    }
    for (key, value) in pairs {
        out.extend(key.to_be_bytes());
        out.extend(u16::try_from(value.len())?.to_be_bytes());
        out.extend(value);
    }
    Ok(out)
}
fn gateway(typ: u8, text: &str, origin: Option<&Name>) -> Result<Vec<u8>> {
    Ok(match typ {
        0 if text == "." => Vec::new(),
        1 => text.parse::<Ipv4Addr>()?.octets().to_vec(),
        2 => text.parse::<Ipv6Addr>()?.octets().to_vec(),
        3 => name_wire(text, origin)?,
        _ => bail!("invalid IPSECKEY/AMTRELAY gateway"),
    })
}
