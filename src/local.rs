//! Local mode: suritui runs on the router itself. Everything that needs root
//! goes through `sudo -n` with fixed arguments; nothing is built from free text.

use crate::alert::category;
use crate::rules::RuleIndex;
use crate::source::{map_output, validate, AlertSource, Loaded, Range, SourceError};
use std::collections::HashSet;
use std::process::Command;

pub const DISABLE_CONF: &str = "/usr/local/etc/suricata/disable.conf";
pub const ENABLE_CONF: &str = "/usr/local/etc/suricata/enable.conf";
pub const THRESHOLD_CONF: &str = "/usr/local/etc/suricata/threshold.config";
pub const SURICATA_YAML: &str = "/usr/local/etc/suricata/suricata.yaml";

/// The privileged helper; local mode never runs anything else through sudo.
pub const HELPER: &str = "/usr/local/sbin/suritui-admin";

pub struct LocalSource;

impl AlertSource for LocalSource {
    fn load(&self, r: Range) -> Result<Loaded, SourceError> {
        let r = validate(r)?;
        let mut args = vec!["-n".to_string(), HELPER.to_string(), "alerts".to_string()];
        args.extend(r.remote_args());
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
    Err(crate::source::last_error_line(&err)
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
    /// Sids listed in enable.conf (they override a group or the rule source).
    pub enabled_sids: HashSet<u64>,
    pub groups: usize,
    pub patterns: usize,
    /// disable.conf exists but cannot be read, so the lists above are unknown.
    pub unreadable: bool,
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
        } else if let Some(n) = crate::admin::line_sid(line) {
            // The same reading of a sid line as the helper's, so the screen and the helper agree.
            d.sids.insert(n);
        }
    }
    d
}

/// Plain sid lines of an enable.conf.
pub fn parse_enable_conf(text: &str) -> HashSet<u64> {
    parse_disable_conf(text).sids
}

/// A missing file is an empty list; a file that cannot be read is not.
fn read_conf(path: &str) -> Result<String, std::io::Error> {
    match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        other => other,
    }
}

pub fn load_disable_conf() -> DisableConf {
    let mut d = DisableConf::default();
    match read_conf(DISABLE_CONF) {
        Ok(t) => d = parse_disable_conf(&t),
        Err(_) => d.unreadable = true,
    }
    match read_conf(ENABLE_CONF) {
        Ok(t) => d.enabled_sids = parse_enable_conf(&t),
        Err(_) => d.unreadable = true,
    }
    d
}

/// The entries of threshold.config; Err when it exists but cannot be read.
pub fn load_thresholds() -> Result<Vec<crate::threshold::ThresholdEntry>, String> {
    read_conf(THRESHOLD_CONF)
        .map(|t| crate::threshold::parse_entries(&t))
        .map_err(|e| format!("Cannot read {THRESHOLD_CONF}: {e}"))
}

/// Why a rule is in the state it is in.
pub fn origin(enabled: bool, sid: u64, d: &DisableConf) -> &'static str {
    if enabled {
        if d.enabled_sids.contains(&sid) {
            "enabled by sid in enable.conf"
        } else {
            "enabled"
        }
    } else if d.sids.contains(&sid) {
        "disabled by sid in disable.conf"
    } else if d.unreadable {
        "disabled (disable.conf or enable.conf cannot be read, so the reason is unknown)"
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
        d.enabled_sids.insert(1);
        assert_eq!(origin(true, 1, &d), "enabled by sid in enable.conf");
        d.enabled_sids.clear();
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

    #[test]
    fn disable_conf_reads_sid_lines_like_the_helper() {
        let d = parse_disable_conf("2012345\n1:2012346 # x\n+2012347\n0\n00000000002012348\ngroup:x\nre:y\n# 5\n");
        let mut sids: Vec<u64> = d.sids.iter().copied().collect();
        sids.sort();
        assert_eq!(sids, vec![2012345, 2012346]);
        assert_eq!((d.groups, d.patterns), (1, 1));
    }

    #[test]
    fn an_unreadable_conf_is_not_reported_as_a_rule_source_choice() {
        let d = DisableConf { unreadable: true, ..Default::default() };
        assert!(origin(false, 1, &d).contains("cannot be read"));
        assert_eq!(origin(false, 1, &DisableConf::default()), "disabled in the rule source");
    }
}
