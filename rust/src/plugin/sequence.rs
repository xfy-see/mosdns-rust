use super::{executable::Executable, matcher::Matcher};
use anyhow::Result;
use serde::Deserialize;
use std::sync::Arc;

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuleArgs {
    #[serde(deserialize_with = "crate::coremain::config::deserialize_strings")]
    pub matches: Vec<String>,
    pub exec: String,
}
pub struct Rule {
    pub matches: Vec<Matcher>,
    pub exec: Executable,
}
pub type Sequence = Vec<Rule>;
#[derive(Clone)]
pub(crate) struct ChainWalker {
    pub chain: Arc<Sequence>,
    pub pos: usize,
    pub jump_back: Option<Box<ChainWalker>>,
    pub depth: usize,
}
impl ChainWalker {
    pub fn new(chain: Arc<Sequence>) -> Self {
        Self {
            chain,
            pos: 0,
            jump_back: None,
            depth: 0,
        }
    }
    pub fn next(&self) -> Self {
        Self {
            chain: self.chain.clone(),
            pos: self.pos + 1,
            jump_back: self.jump_back.clone(),
            depth: self.depth,
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
pub struct QuickConfig {
    pub name: String,
    pub args: String,
    pub tagged: bool,
    pub reverse: bool,
}
pub fn parse_quick(s: &str, matcher: bool) -> Result<QuickConfig> {
    let mut s = s.trim();
    let reverse = matcher && s.starts_with('!');
    if reverse {
        s = s[1..].trim();
    }
    let (name, args) = s.split_once(' ').unwrap_or((s, ""));
    let tagged = name.starts_with('$');
    Ok(QuickConfig {
        name: if tagged {
            name[1..].to_owned()
        } else {
            name.to_owned()
        },
        args: args.trim().to_owned(),
        tagged,
        reverse,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_original_go_config_cases() {
        assert_eq!(
            parse_quick(" $t1   a 1  ", false).unwrap(),
            QuickConfig {
                name: "t1".into(),
                args: "a 1".into(),
                tagged: true,
                reverse: false
            }
        );
        assert_eq!(
            parse_quick(" typ   a 1  ", false).unwrap(),
            QuickConfig {
                name: "typ".into(),
                args: "a 1".into(),
                tagged: false,
                reverse: false
            }
        );
        assert_eq!(
            parse_quick(" ! typ  a 1 ", true).unwrap(),
            QuickConfig {
                name: "typ".into(),
                args: "a 1".into(),
                tagged: false,
                reverse: true
            }
        );
    }
}
