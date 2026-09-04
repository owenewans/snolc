use std::fs;
use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;
use serde::Deserialize;

use crate::error::{Error, Result};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Direct,
    Proxy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "match", rename_all = "lowercase", deny_unknown_fields)]
pub enum Rule {
    Domain { value: String, action: Action },
    Ip { value: IpNet, action: Action },
    Any { action: Action },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn load(path: &Path) -> Result<Self> {
        let source = fs::read_to_string(path)?;
        let mut rules: Self =
            yaml_serde::from_str(&source).map_err(|error| Error::Routing(error.to_string()))?;
        rules.normalize_and_validate()?;
        Ok(rules)
    }

    pub fn normalize_and_validate(&mut self) -> Result<()> {
        if self.rules.is_empty() {
            return Err(Error::Routing("routing rules cannot be empty".to_owned()));
        }
        let last = self.rules.len() - 1;
        for (index, rule) in self.rules.iter_mut().enumerate() {
            match rule {
                Rule::Domain { value, .. } => {
                    *value = normalize_domain(value)?;
                }
                Rule::Any { .. } if index != last => {
                    return Err(Error::Routing("any rule must be last".to_owned()));
                }
                _ => {}
            }
        }
        if !matches!(self.rules.last(), Some(Rule::Any { .. })) {
            return Err(Error::Routing(
                "routing requires a final any rule".to_owned(),
            ));
        }
        Ok(())
    }

    pub fn decide(&self, domain: Option<&str>, ip: Option<IpAddr>) -> Result<Action> {
        let domain = domain.map(normalize_domain).transpose()?;
        for rule in &self.rules {
            match rule {
                Rule::Domain { value, action }
                    if domain
                        .as_deref()
                        .is_some_and(|domain| domain_matches(domain, value)) =>
                {
                    return Ok(*action);
                }
                Rule::Ip { value, action } if ip.is_some_and(|ip| value.contains(&ip)) => {
                    return Ok(*action);
                }
                Rule::Any { action } => return Ok(*action),
                _ => {}
            }
        }
        Err(Error::Routing("no routing rule matched".to_owned()))
    }
}

fn normalize_domain(value: &str) -> Result<String> {
    let value = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    if value.is_empty() || value.len() > 253 {
        return Err(Error::Routing("invalid domain rule".to_owned()));
    }
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(Error::Routing("invalid domain rule".to_owned()));
        }
    }
    Ok(value)
}

fn domain_matches(domain: &str, rule: &str) -> bool {
    domain == rule
        || domain
            .strip_suffix(rule)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules() -> RuleSet {
        let mut rules = RuleSet {
            rules: vec![
                Rule::Domain {
                    value: "Example.RU.".to_owned(),
                    action: Action::Direct,
                },
                Rule::Ip {
                    value: "10.0.0.0/8".parse().unwrap(),
                    action: Action::Direct,
                },
                Rule::Any {
                    action: Action::Proxy,
                },
            ],
        };
        rules.normalize_and_validate().unwrap();
        rules
    }

    #[test]
    fn first_matching_rule_wins() {
        let rules = rules();
        assert_eq!(
            rules
                .decide(Some("a.example.ru"), Some("8.8.8.8".parse().unwrap()))
                .unwrap(),
            Action::Direct
        );
        assert_eq!(
            rules
                .decide(None, Some("10.2.3.4".parse().unwrap()))
                .unwrap(),
            Action::Direct
        );
        assert_eq!(
            rules
                .decide(Some("notexample.ru"), Some("8.8.8.8".parse().unwrap()))
                .unwrap(),
            Action::Proxy
        );
    }

    #[test]
    fn rejects_unreachable_rules_after_any() {
        let mut rules = RuleSet {
            rules: vec![
                Rule::Any {
                    action: Action::Proxy,
                },
                Rule::Ip {
                    value: "127.0.0.0/8".parse().unwrap(),
                    action: Action::Direct,
                },
            ],
        };
        assert!(rules.normalize_and_validate().is_err());
    }

    #[test]
    fn final_action_must_be_explicit() {
        let mut rules = RuleSet {
            rules: vec![Rule::Ip {
                value: "127.0.0.0/8".parse().unwrap(),
                action: Action::Direct,
            }],
        };
        assert!(rules.normalize_and_validate().is_err());
    }

    /// `snolc-geoconv`'s output (see `src/bin/geoconv.rs`) is a sequence of
    /// rule fragments meant to be pasted under an existing `rules:` key,
    /// plus a final `any` rule the converter deliberately leaves out. This
    /// checks that assembling them exactly that way -- indenting the
    /// converter's own output under `rules:`, no other edits -- produces a
    /// file this module accepts.
    #[test]
    fn geoconv_output_format_loads_after_the_documented_assembly_step() {
        let converter_output = "\
- match: domain
  value: example.com
  action: direct
- match: ip
  value: 10.0.0.0/8
  action: direct
";
        let mut source = "rules:\n".to_owned();
        for line in converter_output.lines() {
            source.push_str("  ");
            source.push_str(line);
            source.push('\n');
        }
        source.push_str("  - match: any\n    action: proxy\n");

        let mut rules: RuleSet =
            yaml_serde::from_str(&source).expect("geoconv output must parse as a RuleSet");
        rules.normalize_and_validate().unwrap();
        assert_eq!(
            rules.decide(Some("www.example.com"), None).unwrap(),
            Action::Direct
        );
        assert_eq!(
            rules
                .decide(None, Some("10.1.2.3".parse().unwrap()))
                .unwrap(),
            Action::Direct
        );
        assert_eq!(
            rules
                .decide(Some("other.example"), Some("8.8.8.8".parse().unwrap()))
                .unwrap(),
            Action::Proxy
        );
    }
}
