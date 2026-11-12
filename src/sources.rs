//! Rule sources for the helper: list them, switch a free one on or off, and
//! install the result with the same checked update as the `update` verb.
//!
//! `suricata-update` uses ONLY the sources that were enabled explicitly; with
//! none it falls back to et/open. So the first explicit source also enables
//! et/open, or the router would lose the rules it has now.

use crate::admin::{log_line, say, Out, Paths, Report, Runner};
use crate::browser::{parse_sources, Source};
use crate::update::{begin, update_locked};

const DEFAULT_SOURCE: &str = "et/open";

/// A source name from the index: letters, digits and `/ _ . -` only.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('/')
        && !s.contains("..")
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
}

fn su(paths: &Paths, runner: &dyn Runner, args: &[&str]) -> Result<Out, String> {
    runner.run(&paths.suricata_update, args)
}

fn text(o: &Out) -> String {
    o.stdout.clone()
}

fn must(paths: &Paths, runner: &dyn Runner, args: &[&str]) -> Result<Out, String> {
    let o = su(paths, runner, args)?;
    if o.code != Some(0) {
        let tail: Vec<&str> = o.stderr.lines().chain(o.stdout.lines()).rev().take(2).collect();
        return Err(format!("suricata-update {} failed: {}", args.join(" "), tail.join(" | ")));
    }
    Ok(o)
}

/// What the Sources screen shows: the enabled sources, a marker line, then
/// the whole index. Both texts are `suricata-update`'s own output.
pub fn list(paths: &Paths, runner: &dyn Runner) -> Result<Report, String> {
    let en = must(paths, runner, &["list-enabled-sources"])?;
    let all = must(paths, runner, &["list-sources"])?;
    let mut rep = Report::default();
    rep.lines.extend(text(&en).lines().map(str::to_string));
    say(&mut rep, SEPARATOR);
    rep.lines.extend(text(&all).lines().map(str::to_string));
    Ok(rep)
}

/// Splits the two parts of the `sources` output.
pub const SEPARATOR: &str = "=====index=====";

fn index(paths: &Paths, runner: &dyn Runner) -> Result<(Vec<Source>, Vec<Source>), String> {
    let en = must(paths, runner, &["list-enabled-sources"])?;
    let all = must(paths, runner, &["list-sources"])?;
    Ok((parse_sources(&text(&en)), parse_sources(&text(&all))))
}

/// Switch a free source on (`enable`) or off, then install the new rule set.
/// Anything that goes wrong puts the sources back as they were.
pub fn change(paths: &Paths, runner: &dyn Runner, enable: bool, name: &str) -> Result<Report, String> {
    if !valid_name(name) {
        return Err("not a valid source name".into());
    }
    let _lock = begin(paths, runner)?;
    let (enabled, all) = index(paths, runner)?;
    let known = all.iter().find(|s| s.name == name);
    let is_on = enabled.iter().any(|s| s.name == name);
    let mut undo: Vec<(&str, String)> = Vec::new();
    let mut rep = Report::default();
    if enable {
        let Some(src) = known else {
            return Err(format!("{name} is not in the source index"));
        };
        if src.needs_key {
            return Err(format!("{name} needs a key or subscription; it cannot be switched on here"));
        }
        if is_on {
            return Err(format!("{name} is already enabled"));
        }
        if enabled.is_empty() && name != DEFAULT_SOURCE {
            must(paths, runner, &["enable-source", DEFAULT_SOURCE])?;
            undo.push(("remove-source", DEFAULT_SOURCE.to_string()));
            say(&mut rep, format!("{DEFAULT_SOURCE} is now listed explicitly, so it stays in use"));
        }
        if let Err(e) = must(paths, runner, &["enable-source", name]) {
            roll_back(paths, runner, &undo);
            return Err(e);
        }
        undo.push(("remove-source", name.to_string()));
    } else {
        if !is_on {
            return Err(format!("{name} is not enabled"));
        }
        if enabled.len() <= 1 {
            return Err("at least one source must stay enabled".into());
        }
        must(paths, runner, &["disable-source", name])?;
        undo.push(("enable-source", name.to_string()));
    }
    match update_locked(paths, runner) {
        Ok(r) => {
            rep.lines.extend(r.lines);
            log_line(paths, runner, &format!("source {} {name}", if enable { "enabled" } else { "disabled" }));
            Ok(rep)
        }
        Err(e) => {
            roll_back(paths, runner, &undo);
            Err(format!("{e}; the source change was undone"))
        }
    }
}

fn roll_back(paths: &Paths, runner: &dyn Runner, undo: &[(&str, String)]) {
    for (cmd, name) in undo.iter().rev() {
        let _ = su(paths, runner, &[cmd, name]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::fs;
    use std::path::{Path, PathBuf};

    const A: &str = "alert tcp any any -> any any (msg:\"ET SCAN a\"; sid:100; rev:1;)";
    const B: &str = "alert tcp any any -> any any (msg:\"ET INFO b\"; sid:200; rev:1;)";
    const C: &str = "alert tcp any any -> any any (msg:\"X c\"; sid:300; rev:1;)";

    const INDEX: &str = "Name: et/open\n  Summary: ET\n  License: MIT\n\
        Name: abuse.ch/urlhaus\n  Summary: URLhaus\n  License: CC0-1.0\n\
        Name: et/pro\n  Summary: Pro\n  License: Commercial\n  Parameters: secret-code\n";

    struct Fake {
        calls: RefCell<Vec<String>>,
        enabled: RefCell<Vec<String>>,
        build: String,
        reloaded: Cell<u32>,
    }

    fn out(code: i32, stdout: &str) -> Result<Out, String> {
        Ok(Out { code: Some(code), stdout: stdout.into(), stderr: String::new() })
    }

    impl Runner for Fake {
        fn run(&self, prog: &str, args: &[&str]) -> Result<Out, String> {
            self.calls.borrow_mut().push(format!("{prog} {}", args.join(" ")));
            match (prog, args) {
                ("/usr/bin/id", _) => out(0, "0\n"),
                ("/bin/pgrep", ["-f", ..]) => out(1, ""),
                ("/bin/pgrep", _) => out(0, "4242\n"),
                ("/bin/ps", _) => out(1, ""),
                ("/usr/bin/logger", _) => out(0, ""),
                ("su", ["list-sources"]) => out(0, INDEX),
                ("su", ["list-enabled-sources"]) => {
                    let e: String = self.enabled.borrow().iter().map(|n| format!("Name: {n}\n")).collect();
                    out(0, &e)
                }
                ("su", ["enable-source", n]) => {
                    self.enabled.borrow_mut().push(n.to_string());
                    out(0, "")
                }
                ("su", ["disable-source" | "remove-source", n]) => {
                    self.enabled.borrow_mut().retain(|x| x != n);
                    out(0, "")
                }
                ("/usr/bin/timeout", _) => {
                    let dir = args[args.iter().position(|a| *a == "-o").unwrap() + 1];
                    fs::write(Path::new(dir).join("suricata.rules"), &self.build).unwrap();
                    out(0, "")
                }
                ("sc", ["-c", "ruleset-reload-time"]) | ("sc", [_, "ruleset-reload-time"]) => out(
                    0,
                    &format!("{{\"message\":[{{\"id\":0,\"last_reload\":\"T{}\"}}],\"return\":\"OK\"}}", self.reloaded.get()),
                ),
                ("sc", [_, "ruleset-stats"]) => {
                    out(0, "{\"message\":[{\"id\":0,\"rules_loaded\":9,\"rules_failed\":0,\"rules_skipped\":0}],\"return\":\"OK\"}")
                }
                ("sc", _) => {
                    self.reloaded.set(self.reloaded.get() + 1);
                    out(0, "{\"message\":\"done\",\"return\":\"OK\"}")
                }
                other => panic!("unexpected {other:?}"),
            }
        }
    }

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn setup(tag: &str, enabled: &[&str], build: &str) -> (Tmp, Paths, Fake) {
        let d = std::env::temp_dir().join(format!("suritui-src-{}-{tag}", std::process::id()));
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
        fs::write(&p.rules, format!("{A}\n{B}\n")).unwrap();
        let f = Fake {
            calls: RefCell::new(vec![]),
            enabled: RefCell::new(enabled.iter().map(|s| s.to_string()).collect()),
            build: build.to_string(),
            reloaded: Cell::new(0),
        };
        (Tmp(d), p, f)
    }

    #[test]
    fn names_are_checked() {
        assert!(valid_name("et/open"));
        assert!(valid_name("abuse.ch/sslbl-ja3"));
        for bad in ["", "/etc", "a..b", "a b", "a;b", "a\nb", "$(x)", &"a".repeat(65)] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn list_has_both_parts() {
        let (_t, p, f) = setup("list", &["et/open"], "");
        let l = list(&p, &f).unwrap().lines;
        let at = l.iter().position(|x| x == SEPARATOR).unwrap();
        assert_eq!(parse_sources(&l[..at].join("\n")).len(), 1);
        assert_eq!(parse_sources(&l[at + 1..].join("\n")).len(), 3);
    }

    #[test]
    fn first_source_keeps_et_open() {
        let (_t, p, f) = setup("first", &[], &format!("{A}\n{B}\n{C}\n"));
        let r = change(&p, &f, true, "abuse.ch/urlhaus").unwrap().lines.join("\n");
        assert_eq!(*f.enabled.borrow(), vec!["et/open", "abuse.ch/urlhaus"]);
        assert!(r.contains("et/open is now listed explicitly") && r.contains("1 added"), "{r}");
        assert!(fs::read_to_string(&p.rules).unwrap().contains("sid:300"));
    }

    #[test]
    fn a_failed_update_undoes_the_source() {
        // The candidate is empty: the update refuses it.
        let (_t, p, f) = setup("undo", &[], "");
        let e = change(&p, &f, true, "abuse.ch/urlhaus").unwrap_err();
        assert!(e.contains("undone"), "{e}");
        assert!(f.enabled.borrow().is_empty());
        assert!(fs::read_to_string(&p.rules).unwrap().contains("sid:200"));
    }

    #[test]
    fn disable_keeps_at_least_one_and_undoes_on_failure() {
        let (_t, p, f) = setup("dis", &["et/open"], "");
        assert!(change(&p, &f, false, "et/open").unwrap_err().contains("at least one"));
        let (_t2, p2, f2) = setup("dis2", &["et/open", "abuse.ch/urlhaus"], "");
        assert!(change(&p2, &f2, false, "abuse.ch/urlhaus").is_err());
        assert_eq!(*f2.enabled.borrow(), vec!["et/open", "abuse.ch/urlhaus"]);
        let (_t3, p3, f3) = setup("dis3", &["et/open", "abuse.ch/urlhaus"], &format!("{A}\n"));
        // one rule of two is 50%, under the 70% guard: refused and undone
        assert!(change(&p3, &f3, false, "abuse.ch/urlhaus").is_err());
    }

    #[test]
    fn refuses_keyed_unknown_and_repeated() {
        let (_t, p, f) = setup("ref", &["et/open"], "");
        assert!(change(&p, &f, true, "et/pro").unwrap_err().contains("key"));
        assert!(change(&p, &f, true, "nope/x").unwrap_err().contains("not in the source index"));
        assert!(change(&p, &f, true, "et/open").unwrap_err().contains("already"));
        assert!(change(&p, &f, false, "abuse.ch/urlhaus").unwrap_err().contains("not enabled"));
        assert!(change(&p, &f, true, "a b").is_err());
        assert!(f.calls.borrow().iter().all(|c| !c.contains("enable-source") && !c.contains("disable-source")));
    }
}
