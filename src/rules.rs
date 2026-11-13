//! Local rule index: maps a sid to its rule text and rev. Read-only.

use crate::config::Config;
use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub sid: u64,
    pub rev: u32,
    /// False when the rule is commented out (disabled) in the rules file.
    pub enabled: bool,
    pub text: String,
}

#[derive(Debug)]
pub enum RulesError {
    NotInstalled,
    Io(String),
    Download(String),
    Archive(String),
    NotARulesDir(String),
}

impl fmt::Display for RulesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RulesError::NotInstalled => write!(f, "rules are not installed"),
            RulesError::Io(e) => write!(f, "rules I/O error: {e}"),
            RulesError::Download(e) => write!(f, "rules download failed: {e}"),
            RulesError::Archive(e) => write!(f, "rules archive rejected: {e}"),
            RulesError::NotARulesDir(e) => write!(f, "{e}"),
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

pub(crate) fn parse_line(line: &str) -> Option<Rule> {
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
        enabled: !text.starts_with('#'),
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
                // Higher rev wins; on an equal rev an active rule wins over a
                // commented-out (disabled) copy of the same sid.
                Some(old)
                    if old.rev > rule.rev
                        || (old.rev == rule.rev && (old.enabled || !rule.enabled)) => {}
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

    /// Every rule, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.values()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

pub fn rev_warning(alert_rev: Option<u32>, rule: &Rule) -> Option<String> {
    let a = alert_rev?;
    (a != rule.rev).then(|| format!("rule text is rev {}, alert was rev {a}", rule.rev))
}

/// Cap on the decompressed tar stream of the rules tarball (512 MB).
pub const MAX_UNPACKED_BYTES: u64 = 512 * 1024 * 1024;

/// Cap on the compressed download (128 MB; the real tarball is a few MB).
const MAX_DOWNLOAD_BYTES: u64 = 128 * 1024 * 1024;

pub fn rules_url(et_version: &str) -> String {
    format!("https://rules.emergingthreats.net/open/suricata-{et_version}/emerging.rules.tar.gz")
}

fn io_err(e: impl fmt::Display) -> RulesError {
    RulesError::Io(e.to_string())
}

/// Unpack `.rules` files from a gzip tarball and replace `dir` with them.
/// Returns the number of rules files installed. Nothing is touched unless the
/// whole archive reads cleanly and holds at least one `.rules` file.
pub fn install_from_tarball<R: Read>(r: R, dir: &Path) -> Result<usize, RulesError> {
    install_with_cap(r, dir, MAX_UNPACKED_BYTES)
}

fn install_with_cap<R: Read>(r: R, dir: &Path, cap: u64) -> Result<usize, RulesError> {
    let name = dir
        .file_name()
        .ok_or_else(|| RulesError::Io("rules directory has no name".into()))?
        .to_string_lossy()
        .into_owned();
    let parent = match dir.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    check_target(dir)?;
    std::fs::create_dir_all(&parent).map_err(io_err)?;
    let pid = std::process::id();
    let tmp = parent.join(format!(".{name}.new-{pid}"));
    let old = parent.join(format!(".{name}.old-{pid}"));
    let _ = std::fs::remove_dir_all(&tmp);
    let _ = std::fs::remove_dir_all(&old);
    std::fs::create_dir(&tmp).map_err(io_err)?;
    let result = unpack_into(r, &tmp, cap).and_then(|n| swap_dirs(&tmp, dir, &old).map(|()| n));
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
    }
    result
}

/// Refuse to replace a directory that holds anything but `*.rules` regular
/// files: a mistaken `rules_dir` (e.g. a home directory) must never be deleted.
fn check_target(dir: &Path) -> Result<(), RulesError> {
    let refuse = |why: &str| {
        RulesError::NotARulesDir(format!(
            "refusing to replace {}: {why}; check `rules_dir` in the config",
            dir.display()
        ))
    };
    let meta = match std::fs::symlink_metadata(dir) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(io_err(e)),
    };
    if !meta.is_dir() {
        return Err(refuse("it is not a plain directory"));
    }
    for entry in std::fs::read_dir(dir).map_err(io_err)? {
        let entry = entry.map_err(io_err)?;
        let is_file = entry.file_type().map_err(io_err)?.is_file();
        let is_rules = entry.file_name().to_string_lossy().ends_with(".rules");
        if !(is_file && is_rules) {
            return Err(refuse(&format!(
                "it contains {:?}, which is not a regular .rules file",
                entry.file_name()
            )));
        }
    }
    Ok(())
}

/// Read the whole archive; write only regular `*.rules` entries, by file name.
fn unpack_into<R: Read>(r: R, tmp: &Path, cap: u64) -> Result<usize, RulesError> {
    let gz = flate2::read::GzDecoder::new(r);
    // Everything read from the decompressor counts against the cap, including
    // entries we skip and trailing bytes, so a decompression bomb is bounded.
    let mut budget = gz.take(cap.saturating_add(1));
    let mut written: u64 = 0;
    let mut files = std::collections::HashSet::new();
    {
        let mut archive = tar::Archive::new(&mut budget);
        for entry in archive
            .entries()
            .map_err(|e| RulesError::Archive(e.to_string()))?
        {
            let mut entry = entry.map_err(|e| RulesError::Archive(e.to_string()))?;
            if !entry.header().entry_type().is_file() {
                continue;
            }
            let path = entry
                .path()
                .map_err(|e| RulesError::Archive(e.to_string()))?
                .into_owned();
            let Some(fname) = path.file_name().and_then(|f| f.to_str()) else {
                continue;
            };
            if !fname.ends_with(".rules") || fname == ".rules" {
                continue;
            }
            let mut out = std::fs::File::create(tmp.join(fname)).map_err(io_err)?;
            written += std::io::copy(&mut entry, &mut out)
                .map_err(|e| RulesError::Archive(e.to_string()))?;
            if written > cap {
                return Err(RulesError::Archive(format!(
                    "unpacked size exceeds {cap} bytes"
                )));
            }
            files.insert(fname.to_string());
        }
    }
    // Drain to the end of the gzip stream so truncation or a bad checksum is
    // detected even when the tar end marker came early.
    std::io::copy(&mut budget, &mut std::io::sink())
        .map_err(|e| RulesError::Archive(e.to_string()))?;
    if budget.limit() == 0 {
        return Err(RulesError::Archive(format!(
            "unpacked size exceeds {cap} bytes"
        )));
    }
    if files.is_empty() {
        return Err(RulesError::Archive("no .rules files in archive".into()));
    }
    Ok(files.len())
}

/// Put `new` in place of `dir`, keeping the old directory until the move worked.
fn swap_dirs(new: &Path, dir: &Path, old: &Path) -> Result<(), RulesError> {
    let had_old = dir.exists();
    if had_old {
        std::fs::rename(dir, old).map_err(io_err)?;
    }
    if let Err(e) = std::fs::rename(new, dir) {
        if had_old {
            if let Err(e2) = std::fs::rename(old, dir) {
                return Err(RulesError::Io(format!(
                    "{e}; restoring the old rules also failed ({e2}); \
                     the old rules are now in {}",
                    old.display()
                )));
            }
        }
        return Err(io_err(e));
    }
    if had_old {
        let _ = std::fs::remove_dir_all(old);
    }
    Ok(())
}

/// HTTP agent. Without an override the default URL is https and redirects are
/// restricted to https too (no plaintext downgrade); an override keeps its scheme.
fn download_agent(url_override: Option<&str>) -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(url_override.is_none())
        .max_redirects(3)
        .timeout_global(Some(std::time::Duration::from_secs(300)))
        .build()
        .into()
}

/// Download the ET Open rules tarball and install it into `cfg.rules_dir`.
pub fn update_rules(cfg: &Config, url_override: Option<&str>) -> Result<usize, RulesError> {
    let url = url_override
        .map(str::to_string)
        .unwrap_or_else(|| rules_url(&cfg.et_version));
    check_target(&cfg.rules_dir)?;
    let agent = download_agent(url_override);
    let resp = agent
        .get(&url)
        .call()
        .map_err(|e| RulesError::Download(e.to_string()))?;
    let reader = resp
        .into_body()
        .into_with_config()
        .limit(MAX_DOWNLOAD_BYTES)
        .reader();
    install_from_tarball(reader, &cfg.rules_dir)
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
            enabled: true,
            text: String::new(),
        };
        assert_eq!(rev_warning(Some(3), &rule), None);
        assert_eq!(
            rev_warning(Some(2), &rule).as_deref(),
            Some("rule text is rev 3, alert was rev 2")
        );
        assert_eq!(rev_warning(None, &rule), None);
    }

    // ---- update-rules ----

    fn raw_entry(
        b: &mut tar::Builder<Vec<u8>>,
        name: &str,
        kind: tar::EntryType,
        data: &[u8],
        link: Option<&str>,
    ) {
        let mut h = tar::Header::new_gnu();
        h.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        h.set_entry_type(kind);
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        if let Some(l) = link {
            h.set_link_name(l).unwrap();
        }
        h.set_cksum();
        b.append(&h, data).unwrap();
    }

    fn tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut b = tar::Builder::new(Vec::new());
        for (n, d) in entries {
            raw_entry(&mut b, n, tar::EntryType::Regular, d, None);
        }
        let raw = b.into_inner().unwrap();
        gz(&raw)
    }

    fn gz(raw: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(raw).unwrap();
        e.finish().unwrap()
    }

    const RULE_A: &[u8] = b"alert dns any any -> any any (msg:\"a\"; sid:9000001; rev:1;)\n";
    const RULE_B: &[u8] = b"alert dns any any -> any any (msg:\"b\"; sid:9000002; rev:1;)\n";

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn url_uses_version() {
        assert_eq!(
            rules_url("8.0.0"),
            "https://rules.emergingthreats.net/open/suricata-8.0.0/emerging.rules.tar.gz"
        );
        assert!(rules_url("7.0.3").contains("suricata-7.0.3/"));
    }

    #[test]
    fn installs_only_rules_files() {
        let t = TempDir::new("inst");
        let dir = t.0.join("rules");
        let tgz = tarball(&[
            ("rules/a.rules", RULE_A),
            ("rules/b.rules", RULE_B),
            ("rules/classification.config", b"config"),
        ]);
        assert_eq!(install_from_tarball(&tgz[..], &dir).unwrap(), 2);
        assert_eq!(names(&dir), ["a.rules", "b.rules"]);
        assert_eq!(names(&t.0), ["rules"], "no temp leftovers");
        assert!(RuleIndex::from_dir(&dir).unwrap().lookup(9000002).is_some());
    }

    #[test]
    fn rejects_path_traversal() {
        let t = TempDir::new("trav");
        let dir = t.0.join("data/rules");
        let tgz = tarball(&[
            ("../evil.rules", RULE_A),
            ("../../evil2.rules", RULE_A),
            ("/abs.rules", RULE_A),
            ("good.rules", RULE_B),
        ]);
        let n = install_from_tarball(&tgz[..], &dir);
        assert!(!t.0.join("evil.rules").exists());
        assert!(!t.0.join("data/evil.rules").exists());
        assert!(!t.0.join("evil2.rules").exists());
        assert!(!Path::new("/abs.rules").exists());
        // Entries are flattened to their file name inside dir.
        assert!(n.is_ok());
        assert!(names(&dir).iter().all(|n| n.ends_with(".rules")));
        assert_eq!(names(&t.0), ["data"]);
        assert_eq!(names(&t.0.join("data")), ["rules"]);
    }

    #[test]
    fn failed_install_keeps_existing_rules() {
        let t = TempDir::new("fail");
        let dir = t.0.join("rules");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("old.rules"), RULE_A).unwrap();
        assert!(install_from_tarball(&b"this is not gzip at all"[..], &dir).is_err());
        assert_eq!(names(&dir), ["old.rules"]);
        assert_eq!(names(&t.0), ["rules"], "temp dir cleaned up");
    }

    #[test]
    fn truncated_download_keeps_existing_rules() {
        let t = TempDir::new("trunc");
        let dir = t.0.join("rules");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("old.rules"), RULE_A).unwrap();
        let tgz = tarball(&[("rules/a.rules", RULE_B)]);
        let cut = &tgz[..tgz.len() - 6];
        assert!(install_from_tarball(cut, &dir).is_err());
        assert_eq!(names(&dir), ["old.rules"]);
        assert_eq!(names(&t.0), ["rules"]);
    }

    #[test]
    fn success_replaces_old_set() {
        let t = TempDir::new("swap");
        let dir = t.0.join("rules");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("old.rules"), RULE_A).unwrap();
        let tgz = tarball(&[("rules/new.rules", RULE_B)]);
        assert_eq!(install_from_tarball(&tgz[..], &dir).unwrap(), 1);
        assert_eq!(names(&dir), ["new.rules"]);
        assert_eq!(names(&t.0), ["rules"]);
    }

    #[test]
    fn zero_rules_is_an_error_and_keeps_existing() {
        let t = TempDir::new("zero");
        let dir = t.0.join("rules");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("old.rules"), RULE_A).unwrap();
        let tgz = tarball(&[("rules/classification.config", b"x")]);
        assert!(install_from_tarball(&tgz[..], &dir).is_err());
        assert_eq!(names(&dir), ["old.rules"]);
        assert_eq!(names(&t.0), ["rules"]);
    }

    #[test]
    fn links_and_dirs_are_never_followed() {
        let t = TempDir::new("links");
        let dir = t.0.join("rules");
        let mut b = tar::Builder::new(Vec::new());
        raw_entry(
            &mut b,
            "sym.rules",
            tar::EntryType::Symlink,
            b"",
            Some("/etc/passwd"),
        );
        raw_entry(
            &mut b,
            "hard.rules",
            tar::EntryType::Link,
            b"",
            Some("x.rules"),
        );
        raw_entry(&mut b, "adir.rules", tar::EntryType::Directory, b"", None);
        raw_entry(&mut b, "ok.rules", tar::EntryType::Regular, RULE_A, None);
        let tgz = gz(&b.into_inner().unwrap());
        assert_eq!(install_from_tarball(&tgz[..], &dir).unwrap(), 1);
        assert_eq!(names(&dir), ["ok.rules"]);
    }

    #[test]
    fn oversized_archive_is_refused_and_keeps_existing() {
        let t = TempDir::new("cap");
        let dir = t.0.join("rules");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("old.rules"), RULE_A).unwrap();
        let big = vec![b'x'; 5000];
        let tgz = tarball(&[("a.rules", &big), ("b.rules", &big)]);
        assert!(install_with_cap(&tgz[..], &dir, 8000).is_err());
        assert_eq!(names(&dir), ["old.rules"]);
        assert_eq!(names(&t.0), ["rules"]);
        assert_eq!(install_with_cap(&tgz[..], &dir, 20_000).unwrap(), 2);
    }

    #[test]
    fn update_rules_reports_download_failure_and_keeps_rules() {
        let t = TempDir::new("net");
        let dir = t.0.join("rules");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("old.rules"), RULE_A).unwrap();
        let cfg = Config {
            router: "192.0.2.1".into(),
            user: "u".into(),
            labels: Default::default(),
            rules_dir: dir.clone(),
            et_version: "8.0.0".into(),
            local: false,
        };
        // Port 1 on loopback: nothing listens there, no network is touched.
        let e = update_rules(&cfg, Some("http://127.0.0.1:1/x.tar.gz")).unwrap_err();
        assert!(matches!(e, RulesError::Download(_)), "{e}");
        assert_eq!(names(&dir), ["old.rules"]);
    }

    #[test]
    fn dir_with_foreign_file_is_refused_untouched() {
        let t = TempDir::new("foreign");
        let dir = t.0.join("home");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("old.rules"), RULE_A).unwrap();
        std::fs::write(dir.join("notes.txt"), b"precious").unwrap();
        let tgz = tarball(&[("a.rules", RULE_B)]);
        let e = install_from_tarball(&tgz[..], &dir).unwrap_err();
        assert!(matches!(e, RulesError::NotARulesDir(_)), "{e}");
        assert!(e.to_string().contains("rules_dir"));
        assert_eq!(names(&dir), ["notes.txt", "old.rules"]);
        assert_eq!(names(&t.0), ["home"]);
    }

    #[test]
    fn dir_with_subdirectory_is_refused() {
        let t = TempDir::new("subdir");
        let dir = t.0.join("rules");
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let tgz = tarball(&[("a.rules", RULE_B)]);
        assert!(matches!(
            install_from_tarball(&tgz[..], &dir),
            Err(RulesError::NotARulesDir(_))
        ));
        assert_eq!(names(&dir), ["sub"]);
    }

    #[test]
    fn dir_with_rules_symlink_is_refused() {
        let t = TempDir::new("symlink");
        let dir = t.0.join("rules");
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink("/nonexistent", dir.join("l.rules")).unwrap();
        let tgz = tarball(&[("a.rules", RULE_B)]);
        assert!(matches!(
            install_from_tarball(&tgz[..], &dir),
            Err(RulesError::NotARulesDir(_))
        ));
    }

    #[test]
    fn empty_and_missing_dirs_are_accepted() {
        let t = TempDir::new("emptydir");
        let tgz = tarball(&[("a.rules", RULE_B)]);
        let empty = t.0.join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        assert_eq!(install_from_tarball(&tgz[..], &empty).unwrap(), 1);
        let missing = t.0.join("a/b/missing");
        assert_eq!(install_from_tarball(&tgz[..], &missing).unwrap(), 1);
        assert_eq!(names(&missing), ["a.rules"]);
    }

    #[test]
    fn default_agent_is_https_only_with_few_redirects() {
        let a = download_agent(None);
        assert!(a.config().https_only());
        assert_eq!(a.config().max_redirects(), 3);
        assert!(!download_agent(Some("http://127.0.0.1:1/x"))
            .config()
            .https_only());
    }

    #[test]
    fn equal_rev_prefers_the_active_copy_whatever_the_order() {
        let off = "# alert ip any any -> any any (msg:\"off\"; sid:30; rev:2;)\n";
        let on = "alert ip any any -> any any (msg:\"on\"; sid:30; rev:2;)\n";
        for text in [format!("{off}{on}"), format!("{on}{off}")] {
            let r = RuleIndex::from_text(&text);
            assert!(r.lookup(30).unwrap().enabled, "{text}");
        }
        // a higher rev still beats an active older one
        let newer_off = "# alert ip any any -> any any (msg:\"n\"; sid:30; rev:3;)\n";
        let r = RuleIndex::from_text(&format!("{on}{newer_off}"));
        assert_eq!(r.lookup(30).unwrap().rev, 3);
    }
}
