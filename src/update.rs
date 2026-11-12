//! `suritui-admin info` and `suritui-admin update`: the health/status text for
//! the Updates screen, and a checked "update the rules now".

use crate::admin::{
    commit_swaps, io, log_line, now, plain_file, prune_backups, rule_map, say, suricata_running, Lock, Out, Paths,
    Report, Runner, Swap, REBUILD_TIMEOUT_SECS,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// An update that would leave fewer than this share of the current rules is
/// treated as a broken download and refused.
pub const MIN_KEPT_PERCENT: usize = 70;

/// `YYYY-MM-DD HH:MM UTC`.
pub fn stamp(secs: u64) -> String {
    let (h, m) = ((secs % 86400) / 3600, (secs % 3600) / 60);
    format!("{} {h:02}:{m:02} UTC", crate::admin::ymd(secs))
}

/// `5 min`, `3 h`, `2 days`.
pub fn age(secs: u64) -> String {
    match secs {
        0..=89 => format!("{secs} s"),
        90..=5399 => format!("{} min", secs / 60),
        5400..=172_799 => format!("{} h", secs / 3600),
        _ => format!("{} days", secs / 86400),
    }
}

fn mtime(path: &Path) -> Option<u64> {
    let m = fs::metadata(path).ok()?;
    m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs())
}

/// The `message` of a suricatasc reply, if it says OK.
fn sc_message(runner: &dyn Runner, sc: &str, cmd: &str) -> Option<serde_json::Value> {
    let o = runner.run(sc, &["-c", cmd]).ok()?;
    let v: serde_json::Value = serde_json::from_str(o.stdout.trim()).ok()?;
    if v.get("return")?.as_str()? == "OK" {
        v.get("message").cloned()
    } else {
        None
    }
}

use crate::model::group;

fn duration(secs: u64) -> String {
    let (d, h, m) = (secs / 86400, (secs % 86400) / 3600, (secs % 3600) / 60);
    if d > 0 {
        format!("{d} d {h} h")
    } else if h > 0 {
        format!("{h} h {m} min")
    } else {
        format!("{m} min")
    }
}

/// Last lines of the update log that say what happened (never the whole log).
fn update_log_summary(path: &Path) -> Vec<String> {
    let Ok(m) = fs::symlink_metadata(path) else { return vec![] };
    if !m.file_type().is_file() {
        return vec![];
    }
    let Ok(text) = fs::read_to_string(path) else { return vec![] };
    let keep = |l: &str| {
        ["===", "Loaded", "Enabled", "Disabled", "Writing", "reload", "FAILED", "Error", "error"]
            .iter()
            .any(|k| l.contains(k))
    };
    let lines: Vec<&str> = text.lines().filter(|l| keep(l)).collect();
    let from = lines.len().saturating_sub(8);
    lines[from..].iter().map(|l| l.trim().to_string()).collect()
}

/// The text of the Updates screen. Read-only; every part is best effort.
pub fn info(paths: &Paths, runner: &dyn Runner) -> Report {
    let mut r = Report::default();
    let sc = paths.suricatasc.as_str();
    let up = suricata_running(runner);
    let mut line = format!("Suricata: {}", if up { "running" } else { "NOT RUNNING" });
    if let Some(v) = sc_message(runner, sc, "version").and_then(|v| v.as_str().map(str::to_string)) {
        line.push_str(&format!(", version {v}"));
    }
    if let Some(secs) = sc_message(runner, sc, "uptime").and_then(|v| v.as_u64()) {
        line.push_str(&format!(", up {}", duration(secs)));
    }
    say(&mut r, line);
    match sc_message(runner, sc, "ruleset-stats").and_then(|v| v.get(0).cloned()) {
        Some(st) => {
            let g = |k: &str| st.get(k).and_then(|x| x.as_u64()).unwrap_or(0) as usize;
            say(
                &mut r,
                format!(
                    "Loaded in memory: {} rules (failed {}, skipped {})",
                    group(g("rules_loaded")),
                    g("rules_failed"),
                    g("rules_skipped")
                ),
            );
        }
        None => say(&mut r, "Loaded in memory: unknown (Suricata did not answer)"),
    }
    match fs::read_to_string(&paths.rules) {
        Ok(t) => {
            let m = rule_map(&t);
            let off = m.values().filter(|(e, _)| !*e).count();
            let when = mtime(&paths.rules)
                .map(|s| format!(", written {} ({} ago)", stamp(s), age(now().saturating_sub(s))))
                .unwrap_or_default();
            say(&mut r, format!("Rules file: {} rules, {} disabled{when}", group(m.len()), group(off)));
        }
        Err(e) => say(&mut r, format!("Rules file: cannot read ({e})")),
    }
    let newest = fs::read_dir(&paths.cache_dir).ok().and_then(|rd| {
        rd.filter_map(|e| e.ok())
            .filter_map(|e| mtime(&e.path()).map(|t| (t, e.file_name().to_string_lossy().into_owned())))
            .max()
    });
    match newest {
        Some((t, name)) => say(&mut r, format!("Rule download: {name}, fetched {} ({} ago)", stamp(t), age(now().saturating_sub(t)))),
        None => say(&mut r, "Rule download: none cached"),
    }
    let count = |p: &Path| {
        fs::read_to_string(p)
            .map(|t| t.lines().filter(|l| crate::admin::line_sid(l).is_some()).count())
            .unwrap_or(0)
    };
    say(
        &mut r,
        format!(
            "Your changes: {} sids in disable.conf, {} in enable.conf",
            count(&paths.disable_conf),
            count(&paths.enable_conf)
        ),
    );
    let cron = runner
        .run("/usr/bin/crontab", &["-l", "-u", "root"])
        .ok()
        .filter(|o| o.code == Some(0))
        .map(|o| o.stdout.lines().filter(|l| !l.trim_start().starts_with('#') && l.contains("suricata")).map(str::to_string).collect::<Vec<_>>())
        .unwrap_or_default();
    if cron.is_empty() {
        say(&mut r, "Daily update: no root cron entry mentions suricata");
    } else {
        for c in cron {
            say(&mut r, format!("Daily update (root cron): {c}"));
        }
    }
    let busy = ["suricata-update", "suricata-update-reload"].iter().any(|p| {
        runner.run("/bin/pgrep", &["-f", p]).map(|o| o.code == Some(0)).unwrap_or(false)
    });
    say(&mut r, format!("Update running now: {}", if busy { "yes" } else { "no" }));
    if let Ok(o) = runner.run("/bin/ps", &["-axo", "command"]) {
        if let Some(cmd) = o.stdout.lines().map(str::trim).find(|l| l.starts_with("/usr/local/bin/suricata ") && l.contains(" -c ")) {
            say(&mut r, format!("Started as: {cmd}"));
        }
    }
    let log = update_log_summary(&paths.update_log);
    if !log.is_empty() {
        say(&mut r, "");
        say(&mut r, "Last update log:");
        for l in log {
            say(&mut r, format!("  {l}"));
        }
    }
    r
}

fn run_update_build(paths: &Paths, runner: &dyn Runner) -> Result<String, String> {
    let _ = fs::remove_dir_all(&paths.build_dir);
    fs::create_dir_all(&paths.build_dir).map_err(|e| io("cannot create the build directory", e))?;
    let dir = paths.build_dir.to_string_lossy().into_owned();
    let o: Out = runner.run(
        "/usr/bin/timeout",
        &[REBUILD_TIMEOUT_SECS, "/usr/bin/nice", "-n", "15", &paths.suricata_update, "--no-reload", "-o", &dir],
    )?;
    if o.code != Some(0) {
        let tail: Vec<&str> = o.stdout.lines().chain(o.stderr.lines()).rev().take(3).collect();
        return Err(format!("the update failed (exit {:?}): {}", o.code, tail.join(" | ")));
    }
    fs::read_to_string(paths.build_dir.join("suricata.rules")).map_err(|e| io("the update produced no rules file", e))
}

/// Download and install the newest rules, like the daily job, but checked.
pub fn apply_update(paths: &Paths, runner: &dyn Runner) -> Result<Report, String> {
    let mut rep = Report::default();
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
    let rules_meta = plain_file(&paths.rules)?;
    let live_rules = fs::read_to_string(&paths.rules).map_err(|e| io("cannot read the live rules", e))?;
    let class_path = paths.rules.with_file_name("classification.config");
    let live_class = match plain_file(&class_path) {
        Ok(m) => Some((m, fs::read_to_string(&class_path).map_err(|e| io("cannot read classification.config", e))?)),
        Err(_) => None,
    };

    let cleanup = || {
        let _ = fs::remove_dir_all(&paths.build_dir);
    };
    let cand_rules = match run_update_build(paths, runner) {
        Ok(t) => t,
        Err(e) => {
            cleanup();
            return Err(e);
        }
    };
    let cand_class = fs::read_to_string(paths.build_dir.join("classification.config")).ok();
    cleanup();

    let (l, c) = (rule_map(&live_rules), rule_map(&cand_rules));
    if c.is_empty() || c.len() * 100 < l.len() * MIN_KEPT_PERCENT {
        return Err(format!(
            "the update has {} rules but {} are loaded now; that looks like a broken download, so nothing was changed",
            group(c.len()),
            group(l.len())
        ));
    }
    let added = c.keys().filter(|k| !l.contains_key(k)).count();
    let removed = l.keys().filter(|k| !c.contains_key(k)).count();
    let changed = l.iter().filter(|(k, (le, lb))| c.get(k).is_some_and(|(ce, cb)| ce != le || cb != lb)).count();
    let class_changed = match (&live_class, &cand_class) {
        (Some((_, old)), Some(new)) => old != new,
        (None, Some(_)) => true,
        _ => false,
    };
    if added == 0 && removed == 0 && changed == 0 && !class_changed {
        say(&mut rep, "the rules are already up to date; nothing changed");
        return Ok(rep);
    }

    let stamp_s = format!("{}-{}", crate::admin::ymd(now()), now());
    let backup = paths.backup_root.join(&stamp_s);
    fs::create_dir_all(&backup).map_err(|e| io("cannot create the backup directory", e))?;
    let _ = fs::set_permissions(&paths.backup_root, fs::Permissions::from_mode(0o700));
    fs::copy(&paths.rules, backup.join("suricata.rules")).map_err(|e| io("backup of the rules", e))?;
    for f in [&paths.disable_conf, &paths.enable_conf, &class_path] {
        if f.is_file() {
            let _ = fs::copy(f, backup.join(f.file_name().unwrap_or_default()));
        }
    }
    say(&mut rep, format!("backup: {}", backup.display()));

    let class_meta = live_class.as_ref().map(|(m, _)| m).unwrap_or(&rules_meta);
    let swaps = [
        Swap { path: paths.rules.clone(), new: Some(&cand_rules), old: Some(&live_rules), meta: &rules_meta },
        Swap {
            path: class_path.clone(),
            new: cand_class.as_deref().or(live_class.as_ref().map(|(_, t)| t.as_str())),
            old: live_class.as_ref().map(|(_, t)| t.as_str()),
            meta: class_meta,
        },
    ];
    commit_swaps(paths, runner, &swaps, &backup, "rule update")?;
    prune_backups(&paths.backup_root);
    log_line(paths, runner, &format!("update: +{added} -{removed} ~{changed} rules (backup {stamp_s})"));
    say(
        &mut rep,
        format!("rules updated: {added} added, {removed} removed, {changed} changed; Suricata reloaded"),
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
    const B: &str = "alert tcp any any -> any any (msg:\"ET INFO b\"; sid:200; rev:1;)";
    const B2: &str = "alert tcp any any -> any any (msg:\"ET INFO b\"; sid:200; rev:2;)";
    const C: &str = "alert tcp any any -> any any (msg:\"ET INFO c\"; sid:300; rev:1;)";

    fn rules(parts: &[&str]) -> String {
        parts.join("\n") + "\n"
    }

    struct Fake {
        calls: RefCell<Vec<String>>,
        update_running: bool,
        alive: bool,
        build_rules: String,
        build_class: Option<String>,
        reloads: RefCell<Vec<bool>>,
    }

    fn out(code: i32, stdout: &str) -> Result<Out, String> {
        Ok(Out { code: Some(code), stdout: stdout.into(), stderr: String::new() })
    }

    impl Runner for Fake {
        fn run(&self, prog: &str, args: &[&str]) -> Result<Out, String> {
            self.calls.borrow_mut().push(format!("{prog} {}", args.join(" ")));
            match prog {
                "/usr/bin/id" => out(0, "0\n"),
                "/bin/pgrep" if args[0] == "-f" => out(if self.update_running { 0 } else { 1 }, ""),
                "/bin/pgrep" => out(if self.alive { 0 } else { 1 }, "4242\n"),
                "/bin/ps" => out(1, ""),
                "/usr/bin/timeout" => {
                    let dir = args[args.iter().position(|a| *a == "-o").unwrap() + 1];
                    fs::write(Path::new(dir).join("suricata.rules"), &self.build_rules).unwrap();
                    if let Some(c) = &self.build_class {
                        fs::write(Path::new(dir).join("classification.config"), c).unwrap();
                    }
                    out(0, "")
                }
                "/usr/bin/crontab" => out(0, "# c\n23 4 * * * /usr/local/sbin/suricata-update-reload.sh\n17 3 * * * /usr/local/sbin/other.sh\n"),
                "/usr/bin/logger" => out(0, ""),
                "sc" => match args[1] {
                    "version" => out(0, "{\"message\":\"8.0.7 RELEASE\",\"return\":\"OK\"}"),
                    "uptime" => out(0, "{\"message\":3700,\"return\":\"OK\"}"),
                    "ruleset-stats" => out(0, "{\"message\":[{\"id\":0,\"rules_loaded\":28780,\"rules_failed\":2,\"rules_skipped\":0}],\"return\":\"OK\"}"),
                    _ => {
                        let ok = self.reloads.borrow_mut().pop().unwrap_or(true);
                        out(if ok { 0 } else { 1 }, if ok { "{\"message\":\"done\",\"return\":\"OK\"}" } else { "{\"return\":\"NOK\"}" })
                    }
                },
                other => panic!("unexpected program {other}"),
            }
        }
    }

    fn fake(build: String) -> Fake {
        Fake {
            calls: RefCell::new(vec![]),
            update_running: false,
            alive: true,
            build_rules: build,
            build_class: None,
            reloads: RefCell::new(vec![true]),
        }
    }

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn setup(tag: &str, live: &str) -> (Tmp, Paths) {
        let d = std::env::temp_dir().join(format!("suritui-update-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("cache")).unwrap();
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
        };
        fs::write(&p.rules, live).unwrap();
        fs::write(&p.disable_conf, "5\n").unwrap();
        fs::write(d.join("classification.config"), "old-class\n").unwrap();
        (Tmp(d), p)
    }

    #[test]
    fn info_summarizes_health_rules_cache_cron_and_log() {
        let (_t, p) = setup("info", &rules(&[A, B]));
        fs::write(p.cache_dir.join("emerging.rules.tar.gz"), "x").unwrap();
        fs::write(
            &p.update_log,
            "=== Wed\n  Loaded 69367 rules.\n  noise line\n  Writing rules to x: total: 1\n  reload: {\"return\":\"OK\"}\n",
        )
        .unwrap();
        let s = info(&p, &fake(String::new())).lines.join("\n");
        assert!(s.contains("Suricata: running, version 8.0.7 RELEASE, up 1 h 1 min"), "{s}");
        assert!(s.contains("Loaded in memory: 28,780 rules (failed 2, skipped 0)"), "{s}");
        assert!(s.contains("Rules file: 2 rules, 0 disabled, written"), "{s}");
        assert!(s.contains("Rule download: emerging.rules.tar.gz, fetched"), "{s}");
        assert!(s.contains("1 sids in disable.conf, 0 in enable.conf"), "{s}");
        assert!(s.contains("suricata-update-reload.sh") && !s.contains("other.sh"), "{s}");
        assert!(s.contains("Update running now: no") && s.contains("Last update log:"), "{s}");
        assert!(s.contains("Loaded 69367 rules.") && !s.contains("noise line"), "{s}");
    }

    #[test]
    fn info_survives_missing_everything() {
        let (_t, mut p) = setup("info-empty", "");
        p.rules = p.rules.with_file_name("nope");
        p.cache_dir = p.cache_dir.with_file_name("nocache");
        let mut f = fake(String::new());
        f.alive = false;
        let s = info(&p, &f).lines.join("\n");
        assert!(s.contains("NOT RUNNING") && s.contains("cannot read") && s.contains("none cached"), "{s}");
    }

    #[test]
    fn time_helpers() {
        assert_eq!(stamp(0), "1970-01-01 00:00 UTC");
        assert_eq!(age(30), "30 s");
        assert_eq!(age(3600), "60 min");
        assert_eq!(age(7200), "2 h");
        assert_eq!(age(3 * 86400), "3 days");
        assert_eq!(group(1234567), "1,234,567");
    }

    #[test]
    fn update_installs_reloads_and_counts() {
        let live = rules(&[A, B]);
        let (t, p) = setup("upd", &live);
        let mut f = fake(rules(&[A, B2, C]));
        f.build_class = Some("new-class\n".into());
        let rep = apply_update(&p, &f).unwrap();
        let s = rep.lines.join("\n");
        assert!(s.contains("1 added, 0 removed, 1 changed"), "{s}");
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), rules(&[A, B2, C]));
        assert_eq!(fs::read_to_string(t.0.join("classification.config")).unwrap(), "new-class\n");
        assert_eq!(fs::read_to_string(&p.disable_conf).unwrap(), "5\n");
        let b = fs::read_dir(&p.backup_root).unwrap().next().unwrap().unwrap().path();
        assert_eq!(fs::read_to_string(b.join("suricata.rules")).unwrap(), live);
        assert_eq!(fs::read_to_string(b.join("classification.config")).unwrap(), "old-class\n");
        let calls = f.calls.borrow().join("\n");
        assert!(calls.contains("--no-reload") && !calls.contains("--offline"), "{calls}");
        assert!(calls.contains("ruleset-reload-nonblocking"));
        assert!(!p.build_dir.exists() && !p.lock.exists());
        assert!(fs::read_to_string(&p.log).unwrap().contains("update: +1 -0 ~1"));
    }

    #[test]
    fn up_to_date_changes_nothing() {
        let live = rules(&[A, B]);
        let (t, p) = setup("noop", &live);
        let mut f = fake(live.clone());
        f.build_class = Some("old-class\n".into());
        let rep = apply_update(&p, &f).unwrap();
        assert!(rep.lines[0].contains("already up to date"));
        assert!(!p.backup_root.exists());
        assert!(!f.calls.borrow().join("\n").contains("ruleset-reload"));
        assert_eq!(fs::read_to_string(t.0.join("classification.config")).unwrap(), "old-class\n");
    }

    #[test]
    fn a_broken_download_is_refused() {
        let live: String = rules(&[A, B, C]);
        let (_t, p) = setup("broken", &live);
        for bad in [String::new(), rules(&[A])] {
            let e = apply_update(&p, &fake(bad)).unwrap_err();
            assert!(e.contains("broken download"), "{e}");
            assert_eq!(fs::read_to_string(&p.rules).unwrap(), live);
        }
        assert!(!p.backup_root.exists());
    }

    #[test]
    fn failed_reload_restores_the_rules_and_classification() {
        let live = rules(&[A, B]);
        let (t, p) = setup("upd-fail", &live);
        let mut f = fake(rules(&[A, B, C]));
        f.build_class = Some("new-class\n".into());
        *f.reloads.borrow_mut() = vec![true, false];
        let e = apply_update(&p, &f).unwrap_err();
        assert!(e.contains("previous rules are back and reloaded"), "{e}");
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), live);
        assert_eq!(fs::read_to_string(t.0.join("classification.config")).unwrap(), "old-class\n");
    }

    #[test]
    fn refuses_while_another_update_runs() {
        let (_t, p) = setup("busy", &rules(&[A]));
        let mut f = fake(String::new());
        f.update_running = true;
        assert!(apply_update(&p, &f).unwrap_err().contains("update is running"));
    }
}
