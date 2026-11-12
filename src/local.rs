//! Local mode: suritui runs on the router itself. Everything that needs root
//! goes through `sudo -n` with fixed arguments; nothing is built from free text.

use crate::alert::category;
use crate::rules::RuleIndex;
use crate::source::{map_output, validate, AlertSource, Loaded, Range, SourceError};
use std::collections::HashSet;
use std::process::Command;

pub const DISABLE_CONF: &str = "/usr/local/etc/suricata/disable.conf";

/// The privileged helper; local mode never runs anything else through sudo.
pub const HELPER: &str = "/usr/local/sbin/suritui-admin";

pub struct LocalSource;

impl AlertSource for LocalSource {
    fn load(&self, r: Range) -> Result<Loaded, SourceError> {
        let r = validate(r)?;
        let mut args = vec!["-n".to_string(), HELPER.to_string(), "alerts".to_string()];
        match r {
            Range::Today => args.push("live".to_string()),
            Range::Day(k) => args.extend(["day".to_string(), k.to_string()]),
        }
        let out = Command::new("sudo")
            .args(&args)
            .output()
            .map_err(|e| SourceError::Ssh(format!("cannot run sudo: {e}")))?;
        map_output(out.status.code(), &out.stdout, &out.stderr)
    }
}

/// Run `sudo -n <args>` and return stdout, or one line of error text.
fn sudo_output(args: &[&str]) -> Result<Vec<u8>, String> {
    let out = Command::new("sudo")
        .arg("-n")
        .args(args)
        .output()
        .map_err(|e| format!("cannot run sudo: {e}"))?;
    if out.status.success() {
        return Ok(out.stdout);
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(err
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("{} failed", args.first().copied().unwrap_or("command"))))
}

/// The rules Suricata actually loads, as merged by suricata-update.
pub fn load_rule_index() -> Result<RuleIndex, String> {
    let bytes = sudo_output(&[HELPER, "rules"])?;
    Ok(RuleIndex::from_text(&String::from_utf8_lossy(&bytes)))
}

/// What `disable.conf` says; used only to explain why a rule is disabled.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DisableConf {
    pub sids: HashSet<u64>,
    pub groups: usize,
    pub patterns: usize,
}

pub fn parse_disable_conf(text: &str) -> DisableConf {
    let mut d = DisableConf::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("group:") {
            d.groups += 1;
        } else if line.starts_with("re:") {
            d.patterns += 1;
        } else {
            // "2012345", "1:2012345" (gid:sid), optionally followed by a comment
            let first = line.split_whitespace().next().unwrap_or("");
            let sid = first.rsplit(':').next().unwrap_or("");
            if let Ok(n) = sid.parse::<u64>() {
                d.sids.insert(n);
            }
        }
    }
    d
}

pub fn load_disable_conf() -> DisableConf {
    std::fs::read_to_string(DISABLE_CONF)
        .map(|t| parse_disable_conf(&t))
        .unwrap_or_default()
}

/// Why a rule is in the state it is in.
pub fn origin(enabled: bool, sid: u64, d: &DisableConf) -> &'static str {
    if enabled {
        "enabled"
    } else if d.sids.contains(&sid) {
        "disabled by sid in disable.conf"
    } else if d.groups > 0 || d.patterns > 0 {
        "disabled by a group or pattern in disable.conf, or off in the source"
    } else {
        "disabled in the rule source"
    }
}

/// One row of the rules browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    pub sid: u64,
    pub enabled: bool,
    pub category: String,
    pub msg: String,
}

/// `msg:"...";` value of a rule line.
pub fn rule_msg(text: &str) -> Option<String> {
    let start = text.find("msg:")? + 4;
    let rest = text[start..].trim_start().strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            '"' => return Some(out),
            c => out.push(c),
        }
    }
    None
}

/// All rules sorted by sid, for the browser.
pub fn catalog(idx: &RuleIndex) -> Vec<CatalogEntry> {
    let mut v: Vec<CatalogEntry> = idx
        .iter()
        .map(|r| {
            let msg = rule_msg(&r.text).unwrap_or_default();
            CatalogEntry {
                sid: r.sid,
                enabled: r.enabled,
                category: category(&msg).label(),
                msg,
            }
        })
        .collect();
    v.sort_by_key(|e| e.sid);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_disable_conf_forms() {
        let d = parse_disable_conf(
            "# c\n\ngroup:emerging-info.rules\nre:badword\n2012345\n1:2099999\nnot-a-sid\n",
        );
        assert_eq!(d.groups, 1);
        assert_eq!(d.patterns, 1);
        assert!(d.sids.contains(&2012345) && d.sids.contains(&2099999));
        assert_eq!(d.sids.len(), 2);
    }

    #[test]
    fn disable_conf_lines_with_trailing_comments_count() {
        // the exact form suritui-admin writes
        let d = parse_disable_conf("2002979  # suritui 2026-11-12\n1:2000001   # old\n");
        assert!(d.sids.contains(&2002979) && d.sids.contains(&2000001));
        assert_eq!(d.sids.len(), 2);
    }

    #[test]
    fn origin_wording() {
        let mut d = DisableConf::default();
        assert_eq!(origin(true, 1, &d), "enabled");
        assert_eq!(origin(false, 1, &d), "disabled in the rule source");
        d.sids.insert(1);
        assert_eq!(origin(false, 1, &d), "disabled by sid in disable.conf");
        d.groups = 1;
        assert!(origin(false, 2, &d).contains("group or pattern"));
    }

    #[test]
    fn msg_is_extracted_with_escapes() {
        let t = r#"alert tcp any any -> any any (msg:"ET SCAN a \"b\" c"; sid:1; rev:1;)"#;
        assert_eq!(rule_msg(t).as_deref(), Some("ET SCAN a \"b\" c"));
        assert_eq!(rule_msg("alert tcp any any -> any any (sid:1;)"), None);
    }

    #[test]
    fn catalog_sorted_with_state_and_category() {
        let text = "\
alert tcp any any -> any any (msg:\"ET SCAN b\"; sid:20; rev:1;)
# alert tcp any any -> any any (msg:\"ET MALWARE a\"; sid:10; rev:2;)
alert tcp any any -> any any (msg:\"SURICATA STREAM x\"; sid:30; rev:1;)
";
        let c = catalog(&RuleIndex::from_text(text));
        let sids: Vec<_> = c.iter().map(|e| e.sid).collect();
        assert_eq!(sids, [10, 20, 30]);
        assert!(!c[0].enabled && c[1].enabled);
        assert_eq!(c[0].category, "MALWARE");
        assert_eq!(c[2].category, "SURICATA (decoder)");
    }
}
