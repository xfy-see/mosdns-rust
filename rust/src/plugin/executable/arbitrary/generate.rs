// SPDX-License-Identifier: GPL-3.0-or-later
//! BIND-style expansion with the narrower bases accepted by miekg/dns v1.1.72.
use super::zone::Token;
use anyhow::{anyhow, bail, Result};

pub(super) fn expand(tokens: &[Token]) -> Result<String> {
    if tokens.len() < 3 {
        bail!("$GENERATE requires range and template");
    }
    let range = tokens[1].raw.as_str();
    let (range, step) = match range.split_once('/') {
        Some((range, step)) => (range, step.parse::<i64>()?),
        None => (range, 1),
    };
    if step <= 0 {
        bail!("bad $GENERATE step");
    }
    let (start, end) = range
        .split_once('-')
        .ok_or_else(|| anyhow!("bad $GENERATE range"))?;
    let start = start.parse::<i64>()?;
    let end = end.parse::<i64>()?;
    if start < 0 || end < start || (end - start) / step > 65535 {
        bail!("bad $GENERATE range");
    }
    let template = tokens[2..]
        .iter()
        .map(|token| token.rendered.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    let mut output = String::new();
    let mut current = start;
    loop {
        output.push_str(&substitute(&template, current, start, end)?);
        output.push('\n');
        let Some(next) = current.checked_add(step).filter(|next| *next <= end) else {
            break;
        };
        current = next;
    }
    Ok(output)
}
fn substitute(template: &str, current: i64, start: i64, end: i64) -> Result<String> {
    let bytes = template.as_bytes();
    let mut output = Vec::new();
    let mut index = 0;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        index += 1;
        match byte {
            b'\\' if escaped => {
                escaped = false;
                output.push(byte);
            }
            b'\\' => escaped = true,
            b'$' if escaped => {
                escaped = false;
                output.push(byte);
            }
            b'$' => {
                if bytes.get(index) == Some(&b'$') {
                    index += 1;
                    output.push(b'$');
                    continue;
                }
                let mut offset = 0;
                let mut width = 0;
                let mut base = "d";
                if bytes.get(index) == Some(&b'{') {
                    let stop = bytes[index + 1..]
                        .iter()
                        .position(|byte| *byte == b'}')
                        .ok_or_else(|| anyhow!("bad $GENERATE modifier"))?
                        + index
                        + 1;
                    let fields = std::str::from_utf8(&bytes[index + 1..stop])?
                        .split(',')
                        .collect::<Vec<_>>();
                    if fields.len() > 3 {
                        bail!("bad $GENERATE modifier");
                    }
                    offset = fields[0].parse::<i64>()?;
                    if fields.len() > 1 {
                        width = usize::from(fields[1].parse::<u8>()?);
                    }
                    if fields.len() > 2 {
                        base = fields[2];
                    }
                    if start.checked_add(offset).is_none_or(|n| n < 0)
                        || end
                            .checked_add(offset)
                            .is_none_or(|n| n > i64::from(i32::MAX))
                    {
                        bail!("bad $GENERATE offset");
                    }
                    index = stop + 1;
                }
                let value = current
                    .checked_add(offset)
                    .ok_or_else(|| anyhow!("$GENERATE overflow"))?;
                let formatted = match base {
                    "d" => format!("{value:0width$}"),
                    "o" => format!("{value:0width$o}"),
                    "x" => format!("{value:0width$x}"),
                    "X" => format!("{value:0width$X}"),
                    _ => bail!("bad $GENERATE base"),
                };
                output.extend(formatted.as_bytes());
            }
            _ if escaped => escaped = false, // Go drops an escaped non-$, non-\ byte.
            _ => output.push(byte),
        }
    }
    Ok(String::from_utf8(output)?)
}
