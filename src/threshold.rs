//! Suppress entries in threshold.config: "ignore this rule when it comes from /
//! goes to this host". Created from an alert, removable again, and only ever
//! written in the one exact form below so they can be recognised later.
//!
//!   suppress gen_id 1, sig_id N, track by_src|by_dst, ip ADDR[/PREFIX]

use crate::admin::{
    commit_swaps, io, log_line, now, plain_file, prune_backups, rule_map, say, Lock, Paths, Report, Runner, Swap,
};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;

/// More entries than this means something is wrong (or someone is scripting).
pub const MAX_ENTRIES: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Track {
    BySrc,
    ByDst,
}

impl Track {
    pub fn word(self) -> &'static str {
        match self {
            Track::BySrc => "by_src",
            Track::ByDst => "by_dst",
        }
    }

    pub fn parse(s: &str) -> Option<Track> {
        match s {
            "by_src" => Some(Track::BySrc),
            "by_dst" => Some(Track::ByDst),
            _ => None,
        }
    }
}

/// A single address or an address/prefix, normalised. Nothing else is accepted.
pub fn parse_ip_spec(s: &str) -> Option<String> {
    let (addr, prefix) = match s.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (s, None),
    };
    if addr.is_empty() || !addr.bytes().all(|b| b.is_ascii_hexdigit() || b == b'.' || b == b':') {
        return None;
    }
    let ip: IpAddr = addr.parse().ok()?;
    match prefix {
        None => Some(ip.to_string()),
        Some(p) => {
            if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let n: u8 = p.parse().ok()?;
            let max = if ip.is_ipv4() { 32 } else { 128 };
            (n <= max).then(|| format!("{ip}/{n}"))
        }
    }
}

pub fn suppress_line(sid: u64, track: Track, ip: &str) -> String {
    format!("suppress gen_id 1, sig_id {sid}, track {}, ip {ip}", track.word())
}

/// The (sid, track, ip) of a line in exactly the form this program writes.
pub fn parse_entry(line: &str) -> Option<(u64, Track, String)> {
    let parts: Vec<&str> = line.trim().split(',').map(str::trim).collect();
    if parts.len() != 4 || parts[0] != "suppress gen_id 1" {
        return None;
    }
    let sid = crate::admin::parse_sid(parts[1].strip_prefix("sig_id ")?.trim())?;
    let track = Track::parse(parts[2].strip_prefix("track ")?.trim())?;
    let ip = parse_ip_spec(parts[3].strip_prefix("ip ")?.trim())?;
    Some((sid, track, ip))
}

/// One non-comment line of threshold.config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThresholdEntry {
    pub line: String,
    /// Set when this program can remove it again.
    pub removable: Option<(u64, Track, String)>,
}

pub fn parse_entries(text: &str) -> Vec<ThresholdEntry> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| ThresholdEntry { line: l.to_string(), removable: parse_entry(l) })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    NoChange(String),
    Write(String),
}

/// New text of threshold.config. Pure: no I/O.
pub fn plan_suppress(text: &str, add: bool, sid: u64, track: Track, ip: &str, date: &str) -> Result<Plan, String> {
    let want = (sid, track, ip.to_string());
    let exists = text.lines().any(|l| parse_entry(l).as_ref() == Some(&want));
    if add {
        if exists {
            return Ok(Plan::NoChange(format!("sid {sid} is already suppressed for {} {ip}", track.word())));
        }
        if parse_entries(text).len() >= MAX_ENTRIES {
            return Err(format!("threshold.config already has {MAX_ENTRIES} entries; refusing to add more"));
        }
        let mut out = text.to_string();
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("# suritui {date}\n{}\n", suppress_line(sid, track, ip)));
        Ok(Plan::Write(out))
    } else {
        if !exists {
            return Ok(Plan::NoChange(format!("no such suppress entry for sid {sid} ({} {ip})", track.word())));
        }
        let lines: Vec<&str> = text.lines().collect();
        let mut out = String::new();
        for (i, l) in lines.iter().enumerate() {
            let is_target = parse_entry(l).as_ref() == Some(&want);
            let next_is_target = lines.get(i + 1).is_some_and(|n| parse_entry(n).as_ref() == Some(&want));
            if is_target || (next_is_target && l.trim_start().starts_with("# suritui ")) {
                continue;
            }
            out.push_str(l);
            out.push('\n');
        }
        Ok(Plan::Write(out))
    }
}

/// Add or remove one suppress entry, checked by Suricata itself before install.
pub fn apply_suppress(
    paths: &Paths,
    runner: &dyn Runner,
    add: bool,
    sid: u64,
    track: Track,
    ip: &str,
) -> Result<Report, String> {
    let mut rep = Report::default();
    let ip = parse_ip_spec(ip).ok_or("not a valid address")?;
    if paths.require_root {
        let id = runner.run("/usr/bin/id", &["-u"])?;
        if id.stdout.trim() != "0" {
            return Err("suritui-admin must run as root (through sudo)".into());
        }
    }
    let _lock = Lock::take(&paths.lock, runner)?;
    for p in ["suricata-update", "suricata-update-reload"] {
        if runner.run("/bin/pgrep", &["-f", p]).map(|o| o.code == Some(0)).unwrap_or(false) {
            return Err("a rule update is running right now; try again after it finishes".into());
        }
    }
    let live = fs::read_to_string(&paths.rules).map_err(|e| io("cannot read the live rules", e))?;
    if !rule_map(&live).contains_key(&sid) {
        return Err(format!("sid {sid} is not in the live rules"));
    }
    drop(live);
    let exists = paths.threshold_conf.exists() || fs::symlink_metadata(&paths.threshold_conf).is_ok();
    let meta = if exists { plain_file(&paths.threshold_conf)? } else { plain_file(&paths.disable_conf)? };
    let old = if exists {
        fs::read_to_string(&paths.threshold_conf).map_err(|e| io("cannot read threshold.config", e))?
    } else {
        String::new()
    };
    let new = match plan_suppress(&old, add, sid, track, &ip, &crate::admin::ymd(now()))? {
        Plan::NoChange(msg) => {
            say(&mut rep, format!("{msg}; nothing changed"));
            return Ok(rep);
        }
        Plan::Write(t) => t,
    };

    // Let Suricata itself check the candidate before anything goes live.
    let _ = fs::remove_dir_all(&paths.build_dir);
    fs::create_dir_all(&paths.build_dir).map_err(|e| io("cannot create the build directory", e))?;
    let cand = paths.build_dir.join("threshold.config");
    let check = fs::write(&cand, &new).map_err(|e| io("cannot write the candidate", e)).and_then(|_| {
        let set = format!("threshold-file={}", cand.display());
        let yaml = paths.suricata_yaml.to_string_lossy().into_owned();
        runner.run("/usr/bin/timeout", &["120", &paths.suricata_bin, "-T", "-c", &yaml, "--set", &set])
    });
    let _ = fs::remove_dir_all(&paths.build_dir);
    let o = check?;
    if o.code != Some(0) {
        let why: Vec<&str> = o.stdout.lines().chain(o.stderr.lines()).filter(|l| l.contains("hreshold") || l.contains("rror")).take(2).collect();
        return Err(format!("Suricata rejected the new threshold.config: {}", why.join(" | ")));
    }

    let stamp = format!("{}-{}", crate::admin::ymd(now()), now());
    let backup = paths.backup_root.join(&stamp);
    fs::create_dir_all(&backup).map_err(|e| io("cannot create the backup directory", e))?;
    let _ = fs::set_permissions(&paths.backup_root, fs::Permissions::from_mode(0o700));
    if exists {
        fs::copy(&paths.threshold_conf, backup.join("threshold.config")).map_err(|e| io("backup of threshold.config", e))?;
    }
    say(&mut rep, format!("backup: {}", backup.display()));
    let swaps = [Swap {
        path: paths.threshold_conf.clone(),
        new: Some(&new),
        old: exists.then_some(old.as_str()),
        meta: &meta,
    }];
    let what = format!("{} sid {sid} {} {ip}", if add { "suppress" } else { "unsuppress" }, track.word());
    commit_swaps(paths, runner, &swaps, &backup, &what)?;
    prune_backups(&paths.backup_root);
    log_line(paths, runner, &format!("{what} (backup {stamp})"));
    say(
        &mut rep,
        if add {
            format!("sid {sid} is now suppressed for {} {ip}; Suricata reloaded", track.word())
        } else {
            format!("the suppress entry for sid {sid} ({} {ip}) is removed; Suricata reloaded", track.word())
        },
    );
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::Out;
    use std::cell::RefCell;
    use std::path::PathBuf;

    const A: &str = "alert tcp any any -> any any (msg:\"ET SCAN a\"; sid:100; rev:1;)";

    #[test]
    fn ip_specs() {
        for (inp, want) in [
            ("192.0.2.5", Some("192.0.2.5")),
            ("192.0.2.0/24", Some("192.0.2.0/24")),
            ("2001:db8::1", Some("2001:db8::1")),
            ("2001:DB8::0:1/64", Some("2001:db8::1/64")),
            ("", None),
            ("192.0.2.5/33", None),
            ("192.0.2.5/", None),
            ("192.0.2.5/-1", None),
            ("192.0.2.5, any", None),
            ("any", None),
            ("$HOME_NET", None),
            ("[192.0.2.5]", None),
            ("192.0.2.5 ", None),
            ("999.1.1.1", None),
        ] {
            assert_eq!(parse_ip_spec(inp).as_deref(), want, "{inp:?}");
        }
    }

    #[test]
    fn entries_round_trip_through_the_exact_form() {
        let l = suppress_line(2002979, Track::ByDst, "192.0.2.9");
        assert_eq!(parse_entry(&l), Some((2002979, Track::ByDst, "192.0.2.9".to_string())));
        assert_eq!(parse_entry("suppress gen_id 1,sig_id 5 ,track by_src,ip 10.0.0.1"), Some((5, Track::BySrc, "10.0.0.1".into())));
        for bad in ["suppress gen_id 1, sig_id 5", "threshold gen_id 1, sig_id 5, type limit", "suppress gen_id 0, sig_id 5, track by_src, ip 10.0.0.1", "suppress gen_id 1, sig_id 5, track by_src, ip 10.0.0.1, extra"] {
            assert_eq!(parse_entry(bad), None, "{bad}");
        }
    }

    #[test]
    fn entries_list_marks_which_can_be_removed() {
        let t = "# c\n\nsuppress gen_id 1, sig_id 7, track by_src, ip 10.0.0.1\nthreshold gen_id 1, sig_id 8, type limit, track by_src, count 1, seconds 60\n";
        let e = parse_entries(t);
        assert_eq!(e.len(), 2);
        assert!(e[0].removable.is_some() && e[1].removable.is_none());
    }

    #[test]
    fn add_and_remove_are_exact_inverses() {
        let base = "# default\n# comment\n";
        let Plan::Write(a) = plan_suppress(base, true, 7, Track::BySrc, "10.0.0.1", "D").unwrap() else { panic!() };
        assert_eq!(a, "# default\n# comment\n# suritui D\nsuppress gen_id 1, sig_id 7, track by_src, ip 10.0.0.1\n");
        assert!(matches!(plan_suppress(&a, true, 7, Track::BySrc, "10.0.0.1", "D"), Ok(Plan::NoChange(_))));
        let Plan::Write(b) = plan_suppress(&a, false, 7, Track::BySrc, "10.0.0.1", "D").unwrap() else { panic!() };
        assert_eq!(b, base);
        assert!(matches!(plan_suppress(&b, false, 7, Track::BySrc, "10.0.0.1", "D"), Ok(Plan::NoChange(_))));
        // a different track or address is a different entry
        let Plan::Write(c) = plan_suppress(&a, true, 7, Track::ByDst, "10.0.0.1", "D").unwrap() else { panic!() };
        assert_eq!(parse_entries(&c).len(), 2);
    }

    #[test]
    fn removal_keeps_hand_written_lines_and_comments() {
        let t = "# mine\nthreshold gen_id 1, sig_id 8, type limit, track by_src, count 1, seconds 60\n# suritui D\nsuppress gen_id 1, sig_id 7, track by_src, ip 10.0.0.1\n";
        let Plan::Write(b) = plan_suppress(t, false, 7, Track::BySrc, "10.0.0.1", "D").unwrap() else { panic!() };
        assert_eq!(b, "# mine\nthreshold gen_id 1, sig_id 8, type limit, track by_src, count 1, seconds 60\n");
    }

    #[test]
    fn the_entry_limit_holds() {
        let mut t = String::new();
        for i in 0..MAX_ENTRIES {
            t.push_str(&format!("suppress gen_id 1, sig_id {}, track by_src, ip 10.0.0.1\n", i + 1));
        }
        assert!(plan_suppress(&t, true, 999, Track::BySrc, "10.0.0.2", "D").is_err());
    }

    // ---- orchestration ----

    struct Fake {
        calls: RefCell<Vec<String>>,
        t_ok: bool,
        reloads: RefCell<Vec<bool>>,
        alive: bool,
        seen_candidate: RefCell<Vec<String>>,
        reloaded: std::cell::Cell<u32>,
    }

    fn out(code: i32, stdout: &str) -> Result<Out, String> {
        Ok(Out { code: Some(code), stdout: stdout.into(), stderr: String::new() })
    }

    impl Runner for Fake {
        fn run(&self, prog: &str, args: &[&str]) -> Result<Out, String> {
            self.calls.borrow_mut().push(format!("{prog} {}", args.join(" ")));
            match prog {
                "/usr/bin/id" => out(0, "0\n"),
                "/bin/pgrep" if args[0] == "-f" => out(1, ""),
                "/bin/pgrep" => out(if self.alive { 0 } else { 1 }, ""),
                "/bin/ps" => out(1, ""),
                "/usr/bin/timeout" => {
                    let i = args.iter().position(|a| *a == "--set").unwrap();
                    let path = args[i + 1].strip_prefix("threshold-file=").unwrap();
                    self.seen_candidate.borrow_mut().push(fs::read_to_string(path).unwrap());
                    if self.t_ok { out(0, "ok") } else { out(1, "E: threshold-config: parse error, string , track by_src, ip x") }
                }
                "sc" => match args[1] {
                    "ruleset-reload-time" => out(0, &format!("{{\"message\":[{{\"id\":0,\"last_reload\":\"T{}\"}}],\"return\":\"OK\"}}", self.reloaded.get())),
                    "ruleset-stats" => out(0, "{\"message\":[{\"id\":0,\"rules_loaded\":1,\"rules_failed\":0,\"rules_skipped\":0}],\"return\":\"OK\"}"),
                    _ => {
                        let ok = self.reloads.borrow_mut().pop().unwrap_or(true);
                        if ok {
                            self.reloaded.set(self.reloaded.get() + 1);
                        }
                        out(if ok { 0 } else { 1 }, if ok { "{\"return\":\"OK\"}" } else { "{\"return\":\"NOK\"}" })
                    }
                },
                "/usr/bin/logger" => out(0, ""),
                other => panic!("unexpected program {other}"),
            }
        }
    }

    fn fake() -> Fake {
        Fake { calls: RefCell::new(vec![]), t_ok: true, reloads: RefCell::new(vec![true]), alive: true, seen_candidate: RefCell::new(vec![]), reloaded: std::cell::Cell::new(0) }
    }

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn setup(tag: &str, thr: Option<&str>) -> (Tmp, Paths) {
        let d = std::env::temp_dir().join(format!("suritui-thr-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let p = Paths {
            disable_conf: d.join("disable.conf"),
            enable_conf: d.join("enable.conf"),
            threshold_conf: d.join("threshold.config"),
            suricata_yaml: d.join("suricata.yaml"),
            suricata_bin: "sur".into(),
            rules: d.join("suricata.rules"),
            build_dir: d.join("build"),
            backup_root: d.join("backups"),
            cache_dir: d.join("cache"),
            update_log: d.join("update.log"),
            suricata_log: d.join("suricata.log"),
            eve_dir: d.join("eve"),
            lock: d.join("lock"),
            log: d.join("log"),
            suricata_update: "su".into(),
            suricatasc: "sc".into(),
            require_root: false,
            reload_wait_secs: 0,
        };
        fs::write(&p.rules, A.to_string() + "\n").unwrap();
        fs::write(&p.disable_conf, "5\n").unwrap();
        if let Some(t) = thr {
            fs::write(&p.threshold_conf, t).unwrap();
        }
        (Tmp(d), p)
    }

    #[test]
    fn suppress_validates_installs_and_reloads() {
        let (_t, p) = setup("add", Some("# default\n"));
        let f = fake();
        let rep = apply_suppress(&p, &f, true, 100, Track::BySrc, "192.0.2.5").unwrap();
        assert!(rep.lines.iter().any(|l| l.contains("now suppressed for by_src 192.0.2.5")), "{rep:?}");
        let now_text = fs::read_to_string(&p.threshold_conf).unwrap();
        assert!(now_text.ends_with("suppress gen_id 1, sig_id 100, track by_src, ip 192.0.2.5\n"), "{now_text}");
        assert_eq!(f.seen_candidate.borrow()[0], now_text, "Suricata checked exactly what was installed");
        assert!(f.calls.borrow().join("\n").contains("ruleset-reload-nonblocking"));
        let b = fs::read_dir(&p.backup_root).unwrap().next().unwrap().unwrap().path();
        assert_eq!(fs::read_to_string(b.join("threshold.config")).unwrap(), "# default\n");
        assert!(!p.build_dir.exists() && !p.lock.exists());
    }

    #[test]
    fn suppress_then_unsuppress_restores_the_file() {
        let (_t, p) = setup("rt", Some("# default\n"));
        apply_suppress(&p, &fake(), true, 100, Track::ByDst, "10.0.0.9").unwrap();
        apply_suppress(&p, &fake(), false, 100, Track::ByDst, "10.0.0.9").unwrap();
        assert_eq!(fs::read_to_string(&p.threshold_conf).unwrap(), "# default\n");
    }

    #[test]
    fn a_missing_threshold_file_is_created_and_removed_again() {
        let (_t, p) = setup("missing", None);
        apply_suppress(&p, &fake(), true, 100, Track::BySrc, "10.0.0.9").unwrap();
        assert!(p.threshold_conf.exists());
        apply_suppress(&p, &fake(), false, 100, Track::BySrc, "10.0.0.9").unwrap();
        assert_eq!(fs::read_to_string(&p.threshold_conf).unwrap().trim(), "");
    }

    #[test]
    fn suricata_rejecting_the_candidate_changes_nothing() {
        let (_t, p) = setup("rej", Some("# default\n"));
        let mut f = fake();
        f.t_ok = false;
        let e = apply_suppress(&p, &f, true, 100, Track::BySrc, "10.0.0.9").unwrap_err();
        assert!(e.contains("rejected"), "{e}");
        assert_eq!(fs::read_to_string(&p.threshold_conf).unwrap(), "# default\n");
        assert!(!p.backup_root.exists() && !p.build_dir.exists());
        assert!(!f.calls.borrow().join("\n").contains("ruleset-reload"));
    }

    #[test]
    fn failed_reload_restores_the_file() {
        let (_t, p) = setup("rf", Some("# default\n"));
        let f = fake();
        *f.reloads.borrow_mut() = vec![true, false];
        let e = apply_suppress(&p, &f, true, 100, Track::BySrc, "10.0.0.9").unwrap_err();
        assert!(e.contains("previous rules are back"), "{e}");
        assert_eq!(fs::read_to_string(&p.threshold_conf).unwrap(), "# default\n");
    }

    #[test]
    fn bad_input_and_unknown_sid_are_refused_early() {
        let (_t, p) = setup("bad", Some("# default\n"));
        let f = fake();
        assert!(apply_suppress(&p, &f, true, 100, Track::BySrc, "any").is_err());
        assert!(apply_suppress(&p, &f, true, 100, Track::BySrc, "10.0.0.1, 10.0.0.2").is_err());
        assert!(apply_suppress(&p, &f, true, 999, Track::BySrc, "10.0.0.1").unwrap_err().contains("not in the live rules"));
        assert!(!f.calls.borrow().join("\n").contains("timeout"), "Suricata is not even asked");
        assert_eq!(fs::read_to_string(&p.threshold_conf).unwrap(), "# default\n");
    }

    #[test]
    fn duplicates_are_no_ops() {
        let (_t, p) = setup("dup", Some("suppress gen_id 1, sig_id 100, track by_src, ip 10.0.0.1\n"));
        let f = fake();
        let rep = apply_suppress(&p, &f, true, 100, Track::BySrc, "10.0.0.1").unwrap();
        assert!(rep.lines[0].contains("already suppressed"));
        assert!(!p.backup_root.exists());
    }
}
