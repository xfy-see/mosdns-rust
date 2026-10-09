// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

//! A sorted, merged CIDR list with binary-search lookup, matching the Go List.

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Clone, Copy, Debug)]
struct Prefix {
    network: u128,
    bits: u8,
}

fn address_as_ipv6(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(addr) => u128::from(addr.to_ipv6_mapped()),
        IpAddr::V6(addr) => u128::from(addr),
    }
}

fn mask(bits: u8) -> u128 {
    if bits == 0 {
        0
    } else {
        u128::MAX << (128 - bits)
    }
}

impl Prefix {
    fn parse(rule: &str) -> Result<Self> {
        let (address, bits) = if rule.contains('/') {
            match rule.parse::<IpNet>().context("invalid IP prefix")? {
                IpNet::V4(prefix) => (IpAddr::V4(prefix.addr()), prefix.prefix_len() + 96),
                IpNet::V6(prefix) => (IpAddr::V6(prefix.addr()), prefix.prefix_len()),
            }
        } else {
            let address = if let Some((address, zone)) = rule.split_once('%') {
                let address = address
                    .parse::<IpAddr>()
                    .context("invalid scoped IP address")?;
                if zone.is_empty() || !address.is_ipv6() {
                    bail!("invalid IPv6 zone");
                }
                address
            } else {
                rule.parse::<IpAddr>().context("invalid IP address")?
            };
            (address, 128)
        };
        Ok(Self {
            network: address_as_ipv6(address) & mask(bits),
            bits,
        })
    }

    fn contains(self, address: u128) -> bool {
        address & mask(self.bits) == self.network
    }
}

#[derive(Default, Debug)]
pub struct NetList {
    entries: Vec<Prefix>,
    sorted: OnceLock<Vec<Prefix>>,
}

impl NetList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, rule: &str) -> Result<()> {
        let prefix = Prefix::parse(rule)?;
        self.entries.push(prefix);
        self.sorted.take();
        Ok(())
    }

    // Sort lazily once after loading; adding a large file remains O(n), while
    // queries use the same O(log n) binary search as the Go implementation.
    fn sorted_entries(&self) -> &[Prefix] {
        self.sorted.get_or_init(|| {
            let mut entries = self.entries.clone();
            entries.sort_unstable_by_key(|prefix| (prefix.network, prefix.bits));
            let mut merged: Vec<Prefix> = Vec::with_capacity(entries.len());
            for prefix in entries {
                if merged
                    .last()
                    .is_some_and(|last| last.contains(prefix.network))
                {
                    continue;
                }
                merged.push(prefix);
            }
            merged
        })
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        let address = address_as_ipv6(address);
        let entries = self.sorted_entries();
        let index = entries.partition_point(|prefix| prefix.network <= address);
        index > 0 && entries[index - 1].contains(address)
    }

    pub fn len(&self) -> usize {
        self.sorted_entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn load_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        let file = File::open(path).with_context(|| format!("open {}", path.display()))?;
        self.load_reader(BufReader::new(file))
            .with_context(|| format!("load {}", path.display()))
    }

    pub fn load_reader<R: BufRead>(&mut self, reader: R) -> Result<()> {
        for (offset, line) in reader.lines().enumerate() {
            let line_number = offset + 1;
            let line = line.with_context(|| format!("read line {line_number}"))?;
            let rule = line.trim();
            let rule = rule.split_once('#').map_or(rule, |(rule, _)| rule);
            // Go's loader strips ASCII-space columns, but not embedded tabs.
            let rule = rule.split_once(' ').map_or(rule, |(rule, _)| rule);
            if rule.is_empty() {
                continue;
            }
            self.add(rule)
                .with_context(|| format!("invalid data at line #{line_number}:"))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::io::Cursor;

    #[derive(Deserialize)]
    struct Query {
        ip: String,
        matches: bool,
    }

    #[derive(Deserialize)]
    struct Case {
        name: String,
        #[serde(default)]
        rules: Vec<String>,
        #[serde(default)]
        invalid_rules: Vec<String>,
        expected_len: usize,
        queries: Vec<Query>,
        #[serde(default)]
        text: String,
        #[serde(default)]
        error_line: usize,
    }

    #[derive(Deserialize)]
    struct Fixture {
        format_version: usize,
        cases: Vec<Case>,
        load_cases: Vec<Case>,
    }

    fn check(list: &NetList, case: &Case) {
        assert_eq!(list.len(), case.expected_len, "{}: length", case.name);
        for query in &case.queries {
            assert_eq!(
                list.contains(query.ip.parse().unwrap()),
                query.matches,
                "{}: {:?}",
                case.name,
                query.ip
            );
        }
    }

    #[test]
    fn shared_go_netlist_fixture() {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/matcher_netlist.json"
        ))
        .unwrap();
        assert_eq!(fixture.format_version, 1);
        for case in fixture.cases {
            let mut list = NetList::new();
            for rule in &case.rules {
                list.add(rule)
                    .unwrap_or_else(|error| panic!("{}: {error}", case.name));
            }
            for rule in &case.invalid_rules {
                assert!(list.add(rule).is_err(), "{}: {rule:?}", case.name);
            }
            check(&list, &case);
        }
        for case in fixture.load_cases {
            let mut list = NetList::new();
            let result = list.load_reader(Cursor::new(&case.text));
            if case.error_line == 0 {
                result.unwrap_or_else(|error| panic!("{}: {error}", case.name));
            } else {
                let error = result.expect_err(&case.name);
                assert!(error
                    .to_string()
                    .contains(&format!("line #{}:", case.error_line)));
            }
            check(&list, &case);
        }
    }

    #[test]
    fn adding_after_a_query_invalidates_the_sorted_index() {
        let mut list = NetList::new();
        list.add("192.0.2.0/24").unwrap();
        assert!(list.contains("192.0.2.1".parse().unwrap()));
        assert!(!list.contains("198.51.100.1".parse().unwrap()));
        list.add("198.51.100.0/24").unwrap();
        assert!(list.contains("198.51.100.1".parse().unwrap()));
        assert_eq!(list.len(), 2);
        assert!(list.add("invalid").is_err());
        assert_eq!(list.len(), 2);
    }
}
