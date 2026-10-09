// SPDX-License-Identifier: GPL-3.0-or-later
//! The master-file state follows miekg/dns v1.1.72's ZoneParser.
use super::{generate, rdata};
use anyhow::{anyhow, bail, Context, Result};
use hickory_proto::{
    rr::{rdata::NULL, RData, RecordType},
    rr::{DNSClass, Name, Record},
    serialize::binary::{BinDecoder, Restrict},
};

#[derive(Clone, Default)]
pub(super) struct Token {
    pub raw: String,
    pub rendered: String,
    pub quoted: bool,
    pub adjacent: bool,
}
pub(super) struct Line {
    pub tokens: Vec<Token>,
    pub blank: bool,
}

pub fn parse_zone(text: &str) -> Result<Vec<Record>> {
    parse(text, None, true)
}
pub(super) fn parse(
    text: &str,
    mut origin: Option<Name>,
    generate_allowed: bool,
) -> Result<Vec<Record>> {
    let mut previous = None;
    let mut ttl = 3600;
    let mut directive_ttl = false;
    let mut records = Vec::new();
    for (line_index, line) in tokenize(text)?.into_iter().enumerate() {
        let tokens = &line.tokens;
        if tokens[0].raw.starts_with('$') {
            match tokens[0].raw.to_ascii_uppercase().as_str() {
                "$ORIGIN" if tokens.len() == 2 => {
                    origin = Some(name(&tokens[1].raw, origin.as_ref())?)
                }
                "$TTL" if tokens.len() == 2 => {
                    ttl = time(&tokens[1].raw)?;
                    directive_ttl = true;
                }
                "$GENERATE" if generate_allowed => {
                    let expanded = generate::expand(tokens)?;
                    // Go creates a separate parser with default TTL 3600. Its
                    // previous owner and TTL do not overwrite the parent state.
                    records.extend(parse(&expanded, origin.clone(), false)?);
                }
                "$INCLUDE" => bail!("$INCLUDE directive not allowed"),
                "$GENERATE" => bail!("nested $GENERATE directive not allowed"),
                other => bail!("unsupported or malformed zone directive {other}"),
            }
            continue;
        }
        let mut index = 0;
        let owner = if line.blank {
            previous
                .clone()
                .ok_or_else(|| anyhow!("zone record omits its initial owner"))?
        } else {
            if tokens[0].quoted {
                bail!("quoted zone owner");
            }
            index += 1;
            name(&tokens[0].raw, origin.as_ref())?
        };
        previous = Some(owner.clone());
        let mut class = 1;
        let mut record_ttl = ttl;
        let mut had_class = false;
        let mut had_ttl = false;
        let typ = loop {
            let token = tokens
                .get(index)
                .ok_or_else(|| anyhow!("zone record lacks type"))?;
            if token.quoted {
                bail!("quoted zone record header");
            }
            index += 1;
            if let Some(typ) = rdata::record_type(&token.raw) {
                break typ;
            }
            if let Some(parsed) = class_number(&token.raw) {
                if had_class {
                    bail!("duplicate zone class");
                }
                class = parsed;
                had_class = true;
            } else {
                if had_ttl {
                    bail!("unknown RR type or duplicate TTL: {}", token.raw);
                }
                record_ttl = time(&token.raw)?;
                had_ttl = true;
                if !directive_ttl {
                    ttl = record_ttl;
                }
            }
        };
        let bytes = rdata::parse(typ, &tokens[index..], origin.as_ref())
            .with_context(|| format!("zone record {} type {typ}", line_index + 1))?;
        let code = RecordType::from(typ);
        // Retain typed data where execution inspects it; unsupported record
        // types use opaque octets with the original numeric type. Never compress
        // domain names inside opaque RDATA.
        let omitted = tokens[index..].is_empty()
            || (tokens[index].raw == "\\#" && tokens.get(index + 1).is_some_and(|t| t.raw == "0"));
        let data = if matches!(typ, 1 | 2 | 5 | 6 | 12 | 15 | 16 | 28 | 33 | 35)
            && !bytes.is_empty()
            && !omitted
        {
            match RData::read(
                &mut BinDecoder::new(&bytes),
                code,
                Restrict::new(u16::try_from(bytes.len())?),
            ) {
                Ok(data) => data,
                Err(_) if tokens[index].raw == "\\#" => RData::Unknown {
                    code,
                    rdata: NULL::with(bytes),
                },
                Err(error) => return Err(error.into()),
            }
        } else {
            RData::Unknown {
                code,
                rdata: if bytes.is_empty() {
                    NULL::new()
                } else {
                    NULL::with(bytes)
                },
            }
        };
        let mut record = Record::from_rdata(owner, record_ttl, data);
        record.set_dns_class(DNSClass::from(class));
        records.push(record);
    }
    Ok(records)
}
fn class_number(text: &str) -> Option<u16> {
    let text = text.to_ascii_uppercase();
    match text.as_str() {
        "IN" => Some(1),
        "CS" => Some(2),
        "CH" => Some(3),
        "HS" => Some(4),
        "NONE" => Some(254),
        "ANY" => Some(255),
        _ => text.strip_prefix("CLASS").and_then(|s| s.parse().ok()),
    }
}
pub(super) fn time(text: &str) -> Result<u32> {
    if text.is_empty() {
        bail!("empty TTL");
    }
    let mut value = 0u64;
    let mut total = 0u64;
    for byte in text.bytes() {
        if byte.is_ascii_digit() {
            value = value
                .checked_mul(10)
                .and_then(|n| n.checked_add(u64::from(byte - b'0')))
                .ok_or_else(|| anyhow!("TTL overflow"))?;
        } else {
            let factor = match byte.to_ascii_lowercase() {
                b's' => 1,
                b'm' => 60,
                b'h' => 3600,
                b'd' => 86400,
                b'w' => 604800,
                _ => bail!("invalid TTL {text}"),
            };
            total = total
                .checked_add(
                    value
                        .checked_mul(factor)
                        .ok_or_else(|| anyhow!("TTL overflow"))?,
                )
                .ok_or_else(|| anyhow!("TTL overflow"))?;
            value = 0;
        }
    }
    Ok(u32::try_from(
        total
            .checked_add(value)
            .ok_or_else(|| anyhow!("TTL overflow"))?,
    )?)
}
pub(super) fn escape(bytes: &[u8], index: &mut usize) -> Result<u8> {
    *index += 1;
    let first = *bytes
        .get(*index)
        .ok_or_else(|| anyhow!("trailing zone escape"))?;
    if let Some(digits) = bytes
        .get(*index..*index + 3)
        .filter(|d| d.iter().all(u8::is_ascii_digit))
    {
        let value = u16::from(digits[0] - b'0') * 100
            + u16::from(digits[1] - b'0') * 10
            + u16::from(digits[2] - b'0');
        *index += 3;
        Ok(value as u8)
    } else {
        *index += 1;
        Ok(first)
    }
}
pub(super) fn octets(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    let mut result = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            result.push(escape(bytes, &mut index)?);
        } else {
            result.push(bytes[index]);
            index += 1;
        }
    }
    Ok(result)
}
pub(super) fn name(text: &str, origin: Option<&Name>) -> Result<Name> {
    if text == "@" {
        return origin
            .cloned()
            .ok_or_else(|| anyhow!("@ requires an origin"));
    }
    if text == "." {
        return Ok(Name::root());
    }
    if text.is_empty() {
        bail!("empty domain name");
    }
    let bytes = text.as_bytes();
    let mut labels = Vec::new();
    let mut label = Vec::new();
    let mut index = 0;
    let mut absolute = false;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => label.push(escape(bytes, &mut index)?),
            b'.' => {
                if label.is_empty() {
                    bail!("empty domain label");
                }
                labels.push(std::mem::take(&mut label));
                index += 1;
                absolute = index == bytes.len();
            }
            byte => {
                label.push(byte);
                index += 1;
            }
        }
    }
    if !label.is_empty() {
        labels.push(label);
    }
    if !absolute {
        let origin = origin.ok_or_else(|| anyhow!("relative domain {text} requires an origin"))?;
        labels.extend(origin.iter().map(<[u8]>::to_vec));
    }
    Ok(Name::from_labels(labels)?)
}
pub(super) fn name_wire(text: &str, origin: Option<&Name>) -> Result<Vec<u8>> {
    let name = name(text, origin)?;
    let mut bytes = Vec::new();
    for label in name.iter() {
        bytes.push(u8::try_from(label.len())?);
        bytes.extend(label);
    }
    bytes.push(0);
    Ok(bytes)
}
fn tokenize(text: &str) -> Result<Vec<Line>> {
    let bytes = text.as_bytes();
    let mut lines = Vec::new();
    let mut tokens = Vec::new();
    let mut token = Token::default();
    let mut raw = Vec::new();
    let mut rendered = Vec::new();
    let mut active = false;
    let mut quoted = false;
    let mut nesting = 0usize;
    let mut separated = true;
    let mut beginning = true;
    let mut blank = false;
    let mut index = 0;
    let flush = |tokens: &mut Vec<Token>,
                 token: &mut Token,
                 raw: &mut Vec<u8>,
                 rendered: &mut Vec<u8>,
                 active: &mut bool|
     -> Result<()> {
        if *active {
            token.raw = String::from_utf8(std::mem::take(raw))?;
            token.rendered = String::from_utf8(std::mem::take(rendered))?;
            tokens.push(std::mem::take(token));
            *active = false;
        }
        Ok(())
    };
    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;
        if beginning {
            blank = matches!(byte, b' ' | b'\t');
            beginning = false;
        }
        if byte == b'\\' {
            let next = *bytes
                .get(index)
                .ok_or_else(|| anyhow!("trailing zone escape"))?;
            if !active {
                token.adjacent = !separated;
            }
            raw.extend([byte, next]);
            rendered.extend([byte, next]);
            index += 1;
            active = true;
            separated = false;
            continue;
        }
        if byte == b'"' {
            if !quoted && active && !raw.contains(&b'=') {
                flush(
                    &mut tokens,
                    &mut token,
                    &mut raw,
                    &mut rendered,
                    &mut active,
                )?;
            }
            if !active {
                token.adjacent = !separated;
            }
            quoted = !quoted;
            token.quoted = true;
            rendered.push(byte);
            active = true;
            separated = false;
            if !quoted {
                flush(
                    &mut tokens,
                    &mut token,
                    &mut raw,
                    &mut rendered,
                    &mut active,
                )?;
            }
            continue;
        }
        if quoted {
            raw.push(byte);
            rendered.push(byte);
            continue;
        }
        match byte {
            b';' => {
                flush(
                    &mut tokens,
                    &mut token,
                    &mut raw,
                    &mut rendered,
                    &mut active,
                )?;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
            }
            b'(' | b')' => {
                flush(
                    &mut tokens,
                    &mut token,
                    &mut raw,
                    &mut rendered,
                    &mut active,
                )?;
                if byte == b'(' {
                    nesting += 1;
                } else {
                    nesting = nesting
                        .checked_sub(1)
                        .ok_or_else(|| anyhow!("unmatched zone parenthesis"))?;
                }
                separated = true;
            }
            b' ' | b'\t' | b'\r' | b'\n' => {
                flush(
                    &mut tokens,
                    &mut token,
                    &mut raw,
                    &mut rendered,
                    &mut active,
                )?;
                separated = true;
                if byte == b'\n' && nesting == 0 {
                    if !tokens.is_empty() {
                        lines.push(Line {
                            tokens: std::mem::take(&mut tokens),
                            blank,
                        });
                    }
                    beginning = true;
                }
            }
            _ => {
                if !active {
                    token.adjacent = !separated;
                }
                raw.push(byte);
                rendered.push(byte);
                active = true;
                separated = false;
            }
        }
    }
    if quoted || nesting != 0 {
        bail!("unterminated zone quote or parenthesis");
    }
    flush(
        &mut tokens,
        &mut token,
        &mut raw,
        &mut rendered,
        &mut active,
    )?;
    if !tokens.is_empty() {
        lines.push(Line { tokens, blank });
    }
    Ok(lines)
}
