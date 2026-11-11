//! Local rule index: maps a sid to its rule text and rev. Read-only.

use std::collections::HashMap;
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub sid: u64,
    pub rev: u32,
    pub text: String,
}

#[derive(Debug)]
pub enum RulesError {
    NotInstalled,
    Io(String),
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RulesError::NotInstalled => write!(f, "rules are not installed"),
            RulesError::Io(e) => write!(f, "rules I/O error: {e}"),
        }
    }
}

impl std::error::Error for RulesError {}

#[derive(Debug, Default)]
pub struct RuleIndex {
    rules: HashMap<u64, Rule>,
}

const ACTIONS: [&str; 7] = [
    "alert",
    "drop",
    "reject",
    "rejectsrc",
    "rejectdst",
    "rejectboth",
    "pass",
];

/// Find the last `key : digits` option (tolerating spaces) in `line`.
fn last_number(line: &str, key: &str) -> Option<u64> {
    let bytes = line.as_bytes();
    let mut found = None;
    for (pos, _) in line.match_indices(key) {
        if pos > 0 && (bytes[pos - 1].is_ascii_alphanumeric() || bytes[pos - 1] == b'_') {
            continue;
        }
        let rest = line[pos + key.len()..].trim_start();
        let Some(rest) = rest.strip_prefix(':') else {
            continue;
        };
        let rest = rest.trim_start();
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = digits.parse::<u64>() {
            found = Some(n);
        }
    }
    found
}

fn parse_line(line: &str) -> Option<Rule> {
    let text = line.trim();
    let body = text.trim_start_matches('#').trim_start();
    let action = body.split_whitespace().next()?;
    if !ACTIONS.contains(&action) || !body.contains('(') {
        return None;
    }
    let sid = last_number(body, "sid")?;
    let rev = last_number(body, "rev")
        .and_then(|r| u32::try_from(r).ok())
        .unwrap_or(0);
    Some(Rule {
        sid,
        rev,
        text: text.to_string(),
    })
}

impl RuleIndex {
    pub fn from_text(text: &str) -> RuleIndex {
        let mut idx = RuleIndex::default();
        idx.add_text(text);
        idx
    }

    fn add_text(&mut self, text: &str) {
        for rule in text.lines().filter_map(parse_line) {
            match self.rules.get(&rule.sid) {
                Some(old) if old.rev >= rule.rev => {}
                _ => {
                    self.rules.insert(rule.sid, rule);
                }
            }
        }
    }

    pub fn from_dir(dir: &Path) -> Result<RuleIndex, RulesError> {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(RulesError::NotInstalled)
            }
            Err(e) => return Err(RulesError::Io(e.to_string())),
        };
        let mut files = Vec::new();
        for entry in entries {
            let path = entry.map_err(|e| RulesError::Io(e.to_string()))?.path();
            if path.extension().is_some_and(|x| x == "rules") && path.is_file() {
                files.push(path);
            }
        }
        if files.is_empty() {
            return Err(RulesError::NotInstalled);
        }
        files.sort();
        let mut idx = RuleIndex::default();
        for f in files {
            let bytes = std::fs::read(&f).map_err(|e| RulesError::Io(e.to_string()))?;
            idx.add_text(&String::from_utf8_lossy(&bytes));
        }
        Ok(idx)
    }

    pub fn lookup(&self, sid: u64) -> Option<&Rule> {
        self.rules.get(&sid)
    }
}

pub fn rev_warning(alert_rev: Option<u32>, rule: &Rule) -> Option<String> {
    let a = alert_rev?;
    (a != rule.rev).then(|| format!("rule text is rev {}, alert was rev {a}", rule.rev))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir()
                .join(format!("suritui-rules-test-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn indexes_sid_and_rev() {
        let line = r#"alert dns any any -> any any (msg:"x"; sid:1000001; rev:3;)"#;
        let idx = RuleIndex::from_text(line);
        let r = idx.lookup(1000001).unwrap();
        assert_eq!(r.rev, 3);
        assert_eq!(r.text, line);
    }

    #[test]
    fn tolerates_spacing() {
        let idx = RuleIndex::from_text(
            r#"alert dns any any -> any any (msg:"x"; sid: 1000002 ; rev : 4 ;)"#,
        );
        assert_eq!(idx.lookup(1000002).unwrap().rev, 4);
    }

    #[test]
    fn commented_rules_are_indexed() {
        let line = r#"# alert dns any any -> any any (msg:"x"; sid:1000003; rev:1;)"#;
        let idx = RuleIndex::from_text(line);
        let r = idx.lookup(1000003).unwrap();
        assert!(r.text.starts_with("# alert"));
    }

    #[test]
    fn plain_comments_and_junk_are_ignored() {
        let idx = RuleIndex::from_text("# note about sid:5; rev:1;\n\nnot a rule sid:6;\n");
        assert!(idx.lookup(5).is_none());
        assert!(idx.lookup(6).is_none());
    }

    #[test]
    fn missing_rev_is_zero() {
        let idx = RuleIndex::from_text(r#"alert ip any any -> any any (msg:"x"; sid:7;)"#);
        assert_eq!(idx.lookup(7).unwrap().rev, 0);
    }

    #[test]
    fn duplicate_sid_keeps_highest_rev() {
        let text = "alert ip any any -> any any (msg:\"a\"; sid:9; rev:2;)\n\
                    alert ip any any -> any any (msg:\"b\"; sid:9; rev:5;)\n\
                    alert ip any any -> any any (msg:\"c\"; sid:9; rev:1;)\n";
        let idx = RuleIndex::from_text(text);
        let r = idx.lookup(9).unwrap();
        assert_eq!(r.rev, 5);
        assert!(r.text.contains("\"b\""));
    }

    #[test]
    fn non_utf8_bytes_do_not_panic() {
        let d = TempDir::new("utf8");
        let mut bytes = b"alert ip any any -> any any (msg:\"caf".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe]);
        bytes.extend_from_slice(b"\"; sid:11; rev:1;)\n");
        std::fs::write(d.0.join("a.rules"), bytes).unwrap();
        let idx = RuleIndex::from_dir(&d.0).unwrap();
        assert_eq!(idx.lookup(11).unwrap().rev, 1);
    }

    #[test]
    fn from_dir_reads_only_rules_files() {
        let d = TempDir::new("only");
        std::fs::write(
            d.0.join("a.rules"),
            "alert ip any any -> any any (sid:20; rev:1;)\n",
        )
        .unwrap();
        std::fs::write(
            d.0.join("b.txt"),
            "alert ip any any -> any any (sid:21; rev:1;)\n",
        )
        .unwrap();
        let idx = RuleIndex::from_dir(&d.0).unwrap();
        assert!(idx.lookup(20).is_some());
        assert!(idx.lookup(21).is_none());
    }

    #[test]
    fn from_dir_missing_is_not_installed() {
        let d = TempDir::new("missing");
        let r = RuleIndex::from_dir(&d.0.join("nope"));
        assert!(matches!(r, Err(RulesError::NotInstalled)));
    }

    #[test]
    fn from_dir_without_rules_files_is_not_installed() {
        let d = TempDir::new("empty");
        let r = RuleIndex::from_dir(&d.0);
        assert!(matches!(r, Err(RulesError::NotInstalled)));
    }

    #[test]
    fn rev_warning_cases() {
        let rule = Rule {
            sid: 1,
            rev: 3,
            text: String::new(),
        };
        assert_eq!(rev_warning(Some(3), &rule), None);
        assert_eq!(
            rev_warning(Some(2), &rule).as_deref(),
            Some("rule text is rev 3, alert was rev 2")
        );
        assert_eq!(rev_warning(None, &rule), None);
    }
}
