// Copyright (C) 2020-2022, IrineSistiana
// SPDX-License-Identifier: GPL-3.0-or-later

//! Domain rules mirror `pkg/matcher/domain`: a reverse-label trie, exact names,
//! regular expressions, and keywords. Unprefixed rules use the domain matcher.

use anyhow::{bail, Context, Result};
use regex::{Regex, RegexBuilder};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

#[derive(Default, Debug)]
struct LabelNode {
    children: HashMap<String, LabelNode>,
    has_value: bool,
}

impl LabelNode {
    fn add(&mut self, domain: &str) {
        let mut remaining = domain;
        let mut node = self;
        while !remaining.is_empty() {
            let (left, label) = remaining.rsplit_once('.').unwrap_or(("", remaining));
            node = node.children.entry(label.to_owned()).or_default();
            remaining = left;
        }
        node.has_value = true;
    }

    fn matches(&self, domain: &str) -> bool {
        let mut node = self;
        if node.has_value {
            return true;
        }
        let mut remaining = domain;
        while !remaining.is_empty() {
            let (left, label) = remaining.rsplit_once('.').unwrap_or(("", remaining));
            match node.children.get(label) {
                Some(child) if child.has_value => return true,
                Some(child) => node = child,
                None => return false,
            }
            remaining = left;
        }
        false
    }

    // Preserve the Go labelNode.len behavior: a root rule is not counted.
    fn len(&self) -> usize {
        self.children
            .values()
            .map(|child| usize::from(child.has_value) + child.len())
            .sum()
    }
}

fn normalize_domain(domain: &str) -> Cow<'_, str> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_ascii() {
        return if domain.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Cow::Owned(domain.to_ascii_lowercase())
        } else {
            Cow::Borrowed(domain)
        };
    }
    // Go strings.ToLower uses simple Unicode mappings: no expansion of dotted
    // I and no context-sensitive final sigma conversion.
    Cow::Owned(
        domain
            .chars()
            .map(|ch| ch.to_lowercase().next().unwrap())
            .collect(),
    )
}

fn compile_go_regexp(pattern: &str) -> Result<Regex> {
    let mut translated = String::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    let mut class_first = false;
    let mut class_negated = false;
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            if in_class {
                match ch {
                    '[' if chars.peek() == Some(&':') => {
                        // POSIX classes contain an internal closing bracket.
                        translated.push('[');
                        for ch in chars.by_ref() {
                            translated.push(ch);
                            if ch == ']' {
                                break;
                            }
                        }
                    }
                    '[' => translated.push_str(r"\["),
                    ']' if class_first => translated.push_str(r"\]"),
                    ']' => {
                        in_class = false;
                        translated.push(']');
                    }
                    '^' if class_first && !class_negated => {
                        translated.push('^');
                        class_negated = true;
                        continue;
                    }
                    '&' | '~' => {
                        // Go treats these as literals; Rust defines class-set
                        // operations for doubled ampersands and tildes.
                        translated.push('\\');
                        translated.push(ch);
                    }
                    '-' if class_first || chars.peek() == Some(&']') => translated.push_str(r"\-"),
                    _ => translated.push(ch),
                }
                class_first = false;
                continue;
            }
            if ch == '[' {
                in_class = true;
                class_first = true;
                class_negated = false;
            } else if ch == '(' && chars.peek() == Some(&'?') {
                chars.next();
                let mut extension = String::new();
                for ch in chars.by_ref() {
                    extension.push(ch);
                    if ch == '<' || ch == ':' || ch == ')' {
                        break;
                    }
                }
                if extension == "P<" || extension == "<" {
                    let mut name = String::new();
                    let mut closed = false;
                    for ch in chars.by_ref() {
                        if ch == '>' {
                            closed = true;
                            break;
                        }
                        name.push(ch);
                    }
                    if !closed
                        || name.is_empty()
                        || !name
                            .bytes()
                            .all(|ch| ch.is_ascii_alphanumeric() || ch == b'_')
                    {
                        bail!("invalid regexp named capture");
                    }
                    // Captures are not observed by a matcher. Discarding their
                    // names also supports Go's duplicate and digit-first names.
                    translated.push_str("(?:");
                } else {
                    let flags = extension.trim_end_matches([':', ')']);
                    if !flags
                        .chars()
                        .all(|ch| matches!(ch, 'i' | 'm' | 's' | 'U' | '-'))
                    {
                        bail!("unsupported Go regexp group extension (?{extension}");
                    }
                    translated.push_str("(?");
                    translated.push_str(&extension);
                }
                continue;
            } else if ch == '{' {
                let suffix = chars.clone().collect::<String>();
                let repeat = suffix.split_once('}').map(|(count, _)| count);
                let counts = repeat.map(|count| count.split(',').collect::<Vec<_>>());
                let valid = counts.as_ref().is_some_and(|counts| {
                    counts.len() <= 2
                        && !counts[0].is_empty()
                        && counts.iter().enumerate().all(|(index, value)| {
                            (index == 1 && value.is_empty())
                                || (!value.is_empty()
                                    && value.bytes().all(|ch| ch.is_ascii_digit())
                                    && !(value.len() > 1 && value.starts_with('0')))
                        })
                });
                if !valid {
                    // An incomplete or otherwise non-quantifier brace is a
                    // literal in Go, whereas Rust's parser rejects some forms.
                    translated.push_str(r"\{");
                    continue;
                }
                if counts
                    .unwrap()
                    .iter()
                    .filter(|s| !s.is_empty())
                    .any(|s| s.parse::<usize>().map_or(true, |n| n > 1000))
                {
                    bail!("invalid regexp repeat count exceeds 1000");
                }
            }
            translated.push(ch);
            continue;
        }
        let Some(escaped) = chars.next() else {
            translated.push('\\');
            break;
        };
        // Go Perl classes are ASCII even when the expression also uses Unicode
        // properties. Keep Unicode enabled for literals and explicit properties.
        match escaped {
            'd' => translated.push_str("[0-9]"),
            'D' => translated.push_str("[^0-9]"),
            'w' => translated.push_str("[0-9A-Za-z_]"),
            'W' => translated.push_str("[^0-9A-Za-z_]"),
            's' => translated.push_str(r"[\t\n\f\r ]"),
            'S' => translated.push_str(r"[^\t\n\f\r ]"),
            'b' | 'B' => {
                if in_class {
                    bail!("invalid regexp escape in character class");
                }
                translated.push_str("(?-u:\\");
                translated.push(escaped);
                translated.push(')');
            }
            'Q' => {
                if in_class {
                    bail!("invalid regexp quote in character class");
                }
                let mut literal = String::new();
                while let Some(ch) = chars.next() {
                    if ch == '\\' && chars.peek() == Some(&'E') {
                        chars.next();
                        break;
                    }
                    literal.push(ch);
                }
                translated.push_str(&regex::escape(&literal));
            }
            '1'..='7' if !chars.peek().is_some_and(|ch| matches!(ch, '0'..='7')) => {
                bail!("invalid regexp octal escape");
            }
            'p' | 'P' | 'x' => {
                translated.push('\\');
                translated.push(escaped);
                if chars.peek() == Some(&'{') {
                    for ch in chars.by_ref() {
                        translated.push(ch);
                        if ch == '}' {
                            break;
                        }
                    }
                }
            }
            ch if ch.is_ascii_alphabetic()
                && !matches!(
                    ch,
                    'a' | 'f' | 't' | 'n' | 'r' | 'v' | 'x' | 'p' | 'P' | 'A' | 'z'
                ) =>
            {
                bail!("invalid regexp escape \\{ch}");
            }
            _ => {
                translated.push('\\');
                translated.push(escaped);
            }
        }
        if in_class {
            class_first = false;
        }
    }
    RegexBuilder::new(&translated)
        .octal(true)
        .build()
        .context("invalid regexp rule")
}

#[derive(Default, Debug)]
pub struct DomainMatcher {
    full: HashSet<String>,
    domain: LabelNode,
    regex: HashMap<String, Regex>,
    keyword: HashSet<String>,
}

impl DomainMatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, rule: &str) -> Result<()> {
        let (typ, pattern) = rule.split_once(':').unwrap_or(("", rule));
        match typ {
            "" | "domain" => {
                let normalized = normalize_domain(pattern);
                // The Go scanner trims one more trailing dot after normalization.
                let domain = normalized.strip_suffix('.').unwrap_or(&normalized);
                self.domain.add(domain);
            }
            "full" => {
                self.full.insert(normalize_domain(pattern).into_owned());
            }
            "keyword" => {
                self.keyword.insert(normalize_domain(pattern).into_owned());
            }
            "regexp" => {
                if !self.regex.contains_key(pattern) {
                    let regex = compile_go_regexp(pattern)?;
                    self.regex.insert(pattern.to_owned(), regex);
                }
            }
            _ => bail!("unsupported match type [{typ}]"),
        }
        Ok(())
    }

    pub fn matches(&self, domain: &str) -> bool {
        let normalized = normalize_domain(domain);
        let scanned = normalized.strip_suffix('.').unwrap_or(&normalized);
        self.full.contains(normalized.as_ref())
            || self.domain.matches(scanned)
            || self.regex.values().any(|regex| regex.is_match(&normalized))
            || self
                .keyword
                .iter()
                .any(|keyword| normalized.contains(keyword))
    }

    pub fn len(&self) -> usize {
        self.full.len() + self.domain.len() + self.regex.len() + self.keyword.len()
    }

    pub fn is_empty(&self) -> bool {
        self.full.is_empty()
            && !self.domain.has_value
            && self.domain.children.is_empty()
            && self.regex.is_empty()
            && self.keyword.is_empty()
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
            let rule = line
                .split_once('#')
                .map_or(line.as_str(), |(rule, _)| rule)
                .trim();
            if rule.is_empty() {
                continue;
            }
            if rule.chars().any(char::is_whitespace) {
                bail!("line {line_number}: rule string has more than one section");
            }
            self.add(rule)
                .with_context(|| format!("line {line_number}: invalid rule"))?;
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
        domain: String,
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

    fn check(matcher: &DomainMatcher, case: &Case) {
        assert_eq!(matcher.len(), case.expected_len, "{}: length", case.name);
        for query in &case.queries {
            assert_eq!(
                matcher.matches(&query.domain),
                query.matches,
                "{}: {:?}",
                case.name,
                query.domain
            );
        }
    }

    #[test]
    fn shared_go_domain_fixture() {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/matcher_domain.json"
        ))
        .unwrap();
        assert_eq!(fixture.format_version, 1);
        for case in fixture.cases {
            let mut matcher = DomainMatcher::new();
            for rule in &case.rules {
                matcher
                    .add(rule)
                    .unwrap_or_else(|error| panic!("{}: {error}", case.name));
            }
            for rule in &case.invalid_rules {
                assert!(matcher.add(rule).is_err(), "{}: {rule:?}", case.name);
            }
            check(&matcher, &case);
        }
        for case in fixture.load_cases {
            let mut matcher = DomainMatcher::new();
            let result = matcher.load_reader(Cursor::new(&case.text));
            if case.error_line == 0 {
                result.unwrap_or_else(|error| panic!("{}: {error}", case.name));
            } else {
                let error = result.expect_err(&case.name);
                assert!(error
                    .to_string()
                    .contains(&format!("line {}:", case.error_line)));
            }
            check(&matcher, &case);
        }
    }
}
