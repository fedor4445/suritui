//! Rule sources for the helper: list them, switch one on or off, store a key,
//! and install the result with the same checked update as the `update` verb.
//!
//! `suricata-update` uses ONLY the sources that were enabled explicitly; with
//! none it falls back to et/open. So the first explicit source also enables
//! et/open, or the router would lose the rules it has now.
//!
//! Keys live in the source files (`params:` or the `url:` of a custom source).
//! `suricata-update` writes those files readable by everyone, so the helper
//! writes them itself, mode 600, and refuses to work unless the directories
//! above them belong to root (Suricata's user must not be able to swap them).
//! Every message that leaves the helper is scrubbed of the stored keys.

use crate::admin::{log_line, say, Out, Paths, Report, Runner};
use crate::browser::{enabled_sources, parse_enabled, parse_sources, Source};
use crate::update::{begin, update_locked};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const DEFAULT_SOURCE: &str = "et/open";

/// A source name from the index: letters, digits and `/ _ . -` only.
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('/')
        && !s.starts_with('-') // never read as an option by suricata-update
        && !s.contains("..")
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"/_.-".contains(&b))
}

/// A key as the vendors issue them: letters, digits, `-` and `_`.
pub fn valid_key(s: &str) -> bool {
    (8..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}

fn file_name(name: &str) -> String {
    format!("{}.yaml", name.replace('/', "-"))
}

fn su(paths: &Paths, runner: &dyn Runner, args: &[&str]) -> Result<Out, String> {
    runner.run(&paths.suricata_update, args)
}

fn must(paths: &Paths, runner: &dyn Runner, args: &[&str]) -> Result<Out, String> {
    let o = su(paths, runner, args)?;
    if o.code != Some(0) {
        let tail: Vec<&str> = o.stderr.lines().chain(o.stdout.lines()).rev().take(2).collect();
        return Err(redact(paths, &format!("suricata-update {} failed: {}", args.join(" "), tail.join(" | "))));
    }
    Ok(o)
}

// ------------------------------------------------------------ the secrets

/// The key values stored in the sources directory.
pub fn secrets(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dir) else { return out };
    for e in rd.flatten() {
        let Ok(text) = crate::admin::read_regular(e.path()) else { continue };
        let mut in_params = false;
        for line in text.lines() {
            if let Some(url) = line.strip_prefix("url:") {
                if let Some(i) = url.find("oinkcode=") {
                    let v: String = url[i + 9..].chars().take_while(|c| !"&\" ".contains(*c)).collect();
                    out.push(v);
                }
                in_params = false;
            } else if line.starts_with("params:") {
                in_params = true;
            } else if in_params && line.starts_with(' ') {
                if let Some((_, v)) = line.split_once(':') {
                    out.push(v.trim().trim_matches('"').to_string());
                }
            } else {
                in_params = false;
            }
        }
    }
    out.retain(|v| v.len() >= 6);
    out
}

pub fn redact_with(text: &str, secrets: &[String]) -> String {
    let mut t = text.to_string();
    for s in secrets {
        t = t.replace(s.as_str(), "***");
    }
    t
}

/// Hide every stored key in `text`.
pub fn redact(paths: &Paths, text: &str) -> String {
    redact_with(text, &secrets(&paths.sources_dir))
}

// ------------------------------------------------------- the directories

/// The sources directory and the two above it must be real directories that
/// nobody but root can change; otherwise Suricata's user could swap one for a
/// symlink and make the root helper write a key (or an arbitrary file) elsewhere.
fn check_dirs(paths: &Paths) -> Result<(), String> {
    let upd = paths.sources_dir.parent().ok_or("bad sources path")?;
    let data = upd.parent().ok_or("bad sources path")?;
    let mut bad = Vec::new();
    for d in [data, upd, paths.sources_dir.as_path()] {
        let m = match fs::symlink_metadata(d) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && d == paths.sources_dir => {
                fs::create_dir(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
                fs::set_permissions(d, fs::Permissions::from_mode(0o755)).map_err(|e| format!("chmod: {e}"))?;
                continue;
            }
            Err(e) => return Err(format!("cannot stat {}: {e}", d.display())),
        };
        if !m.file_type().is_dir() {
            return Err(format!("{} is not a plain directory; refusing", d.display()));
        }
        if (paths.require_root && m.uid() != 0) || m.mode() & 0o022 != 0 {
            bad.push(d.display().to_string());
        }
    }
    if bad.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} can be changed by Suricata's user, so rule keys and source files are not safe there. \
             Run once as root: chown root:wheel {} (the rules directory stays Suricata's)",
            bad.join(" and "),
            bad.join(" ")
        ))
    }
}

struct Saved {
    name: String,
    data: Vec<u8>,
    mode: u32,
    uid: u32,
    gid: u32,
}

fn snapshot(dir: &Path) -> Result<Vec<Saved>, String> {
    let mut v = Vec::new();
    for e in fs::read_dir(dir).map_err(|e| format!("cannot read the sources directory: {e}"))?.flatten() {
        let Ok(m) = fs::symlink_metadata(e.path()) else { continue };
        if !m.file_type().is_file() {
            continue;
        }
        let data = crate::admin::read_regular_bytes(e.path()).map_err(|e| format!("cannot read a source file: {e}"))?;
        v.push(Saved { name: e.file_name().to_string_lossy().into_owned(), data, mode: m.mode() & 0o7777, uid: m.uid(), gid: m.gid() });
    }
    Ok(v)
}

fn restore(dir: &Path, saved: &[Saved]) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if fs::symlink_metadata(e.path()).map(|m| m.file_type().is_file()).unwrap_or(false) {
                let _ = fs::remove_file(e.path());
            }
        }
    }
    for s in saved {
        let _ = write_new(&dir.join(&s.name), &s.data, s.mode, s.uid, s.gid);
    }
}

/// Create a file that did not exist (or replace it) without following links.
fn write_new(path: &Path, data: &[u8], mode: u32, uid: u32, gid: u32) -> Result<(), String> {
    let mut name = path.as_os_str().to_os_string();
    name.push(".suritui-new");
    let stage = PathBuf::from(name);
    let _ = fs::remove_file(&stage);
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&stage)
        .map_err(|e| format!("create the source file: {e}"))?;
    let r = (|| -> Result<(), String> {
        f.write_all(data).map_err(|e| format!("write: {e}"))?;
        std::os::unix::fs::fchown(&f, Some(uid), Some(gid)).map_err(|e| format!("chown: {e}"))?;
        f.set_permissions(fs::Permissions::from_mode(mode)).map_err(|e| format!("chmod: {e}"))?;
        f.sync_all().map_err(|e| format!("sync: {e}"))
    })();
    if let Err(e) = r {
        let _ = fs::remove_file(&stage);
        return Err(e);
    }
    fs::rename(&stage, path).map_err(|e| {
        let _ = fs::remove_file(&stage);
        format!("rename into place: {e}")
    })
}

// ----------------------------------------------------------------- listing

/// What the Sources screen shows: the enabled sources, a marker line, then
/// the whole index. Both texts are `suricata-update`'s own output.
pub fn list(paths: &Paths, runner: &dyn Runner, refresh: bool) -> Result<Report, String> {
    if refresh {
        // The index that ships with suricata-update goes stale (some sources
        // disappear); this fetches the current one.
        must(paths, runner, &["update-sources"])?;
    }
    let en = must(paths, runner, &["list-enabled-sources"])?;
    let all = must(paths, runner, &["list-sources"])?;
    let mut rep = Report::default();
    rep.lines.extend(en.stdout.lines().map(str::to_string));
    say(&mut rep, SEPARATOR);
    rep.lines.extend(all.stdout.lines().map(str::to_string));
    Ok(rep)
}

/// Splits the two parts of the `sources` output.
pub const SEPARATOR: &str = "=====index=====";

fn index(paths: &Paths, runner: &dyn Runner) -> Result<(Vec<Source>, Vec<Source>), String> {
    let en = must(paths, runner, &["list-enabled-sources"])?;
    let all = must(paths, runner, &["list-sources"])?;
    let all = parse_sources(&all.stdout);
    Ok((enabled_sources(parse_enabled(&en.stdout), &all), all))
}

// ---------------------------------------------------------------- changing

/// Run `edit`, then install the new rule set. Anything that goes wrong puts
/// the sources directory back exactly as it was.
fn transact(
    paths: &Paths,
    runner: &dyn Runner,
    what: &str,
    mut rep: Report,
    edit: impl FnOnce(&mut Report) -> Result<(), String>,
) -> Result<Report, String> {
    let saved = snapshot(&paths.sources_dir)?;
    let undo = |e: String| {
        restore(&paths.sources_dir, &saved);
        Err(format!("{e}; the source change was undone"))
    };
    if let Err(e) = edit(&mut rep) {
        return undo(redact(paths, &e));
    }
    match update_locked(paths, runner, true) {
        Ok(r) => {
            if r.lines.iter().any(|l| l.contains("already up to date")) {
                say(&mut rep, "note: the new set contains no new rules");
            }
            rep.lines.extend(r.lines);
            log_line(paths, runner, what);
            Ok(rep)
        }
        Err(e) => undo(redact(paths, &e)),
    }
}

/// Switch a source on (`enable`) or off. Free sources only; keys go through `set_key`.
pub fn change(paths: &Paths, runner: &dyn Runner, enable: bool, name: &str) -> Result<Report, String> {
    if !valid_name(name) {
        return Err("not a valid source name".into());
    }
    let _lock = begin(paths, runner)?;
    check_dirs(paths)?;
    let (enabled, all) = index(paths, runner)?;
    let is_on = enabled.iter().any(|s| s.name == name);
    let rep = Report::default();
    if enable {
        let Some(src) = all.iter().find(|s| s.name == name) else {
            return Err(format!("{name} is not in the source index"));
        };
        if src.needs_key {
            return Err(format!("{name} needs a key or subscription; use the key entry instead"));
        }
        if is_on {
            return Err(format!("{name} is already enabled"));
        }
        let first = enabled.is_empty() && name != DEFAULT_SOURCE;
        transact(paths, runner, &format!("source enabled {name}"), rep, |rep| {
            if first {
                must(paths, runner, &["enable-source", DEFAULT_SOURCE])?;
                say(rep, format!("{DEFAULT_SOURCE} is now listed explicitly, so it stays in use"));
            }
            must(paths, runner, &["enable-source", name])?;
            Ok(())
        })
    } else {
        if !is_on {
            return Err(format!("{name} is not enabled"));
        }
        if name == DEFAULT_SOURCE && enabled.len() <= 1 {
            return Err("et/open is the only source; at least one must stay".into());
        }
        transact(paths, runner, &format!("source disabled {name}"), rep, |_| remove_source_file(paths, name))
    }
}

fn remove_source_file(paths: &Paths, name: &str) -> Result<(), String> {
    let f = paths.sources_dir.join(file_name(name));
    let m = fs::symlink_metadata(&f).map_err(|_| format!("no source file for {name}"))?;
    if !m.file_type().is_file() {
        return Err(format!("the source file for {name} is not a plain file"));
    }
    let text = crate::admin::read_regular(&f).map_err(|e| format!("cannot read the source file: {e}"))?;
    if !text.lines().any(|l| l.trim() == format!("source: {name}")) {
        return Err(format!("the source file for {name} does not say it is {name}; refusing to remove it"));
    }
    fs::remove_file(&f).map_err(|e| format!("cannot remove the source file: {e}"))
}

/// Store a key for a source that needs one, switch it on and install.
pub fn set_key(paths: &Paths, runner: &dyn Runner, name: &str, key: &str) -> Result<Report, String> {
    if !valid_key(key) {
        return Err("the key must be 8 to 128 letters, digits, - or _".into());
    }
    if !valid_name(name) {
        return Err("not a valid source name".into());
    }
    let _lock = begin(paths, runner)?;
    check_dirs(paths)?;
    let (enabled, all) = index(paths, runner)?;
    let Some(src) = all.iter().find(|s| s.name == name) else {
        return Err(format!("{name} is not in the source index"));
    };
    if src.params != ["secret-code"] {
        return Err(format!("{name} needs something other than a plain access code; set it up by hand"));
    }
    let content = format!("params:\n  secret-code: {key}\nsource: {name}\n");
    let replaced = src.replaces.clone();
    let first = enabled.is_empty() && replaced.as_deref() != Some(DEFAULT_SOURCE);
    let file = paths.sources_dir.join(file_name(name));
    let (uid, gid) = {
        let m = fs::symlink_metadata(&paths.sources_dir).map_err(|e| format!("stat: {e}"))?;
        (m.uid(), m.gid())
    };
    transact(paths, runner, &format!("source key set for {name}"), Report::default(), |rep| {
        if first {
            must(paths, runner, &["enable-source", DEFAULT_SOURCE])?;
            say(rep, format!("{DEFAULT_SOURCE} is now listed explicitly, so it stays in use"));
        }
        if let Some(r) = &replaced {
            // suricata-update does the same when a source replaces another.
            let _ = fs::remove_file(paths.sources_dir.join(file_name(r)));
            say(rep, format!("{name} replaces {r}, so {r} is switched off"));
        }
        if fs::symlink_metadata(&file).map(|m| !m.file_type().is_file()).unwrap_or(false) {
            return Err("the source file is not a plain file".into());
        }
        write_new(&file, content.as_bytes(), 0o600, uid, gid)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    const A: &str = "alert tcp any any -> any any (msg:\"ET SCAN a\"; sid:100; rev:1;)";
    const B: &str = "alert tcp any any -> any any (msg:\"ET INFO b\"; sid:200; rev:1;)";
    const C: &str = "alert tcp any any -> any any (msg:\"X c\"; sid:300; rev:1;)";

    const INDEX: &str = "Name: et/open\n  Summary: ET\n  License: MIT\n\
        Name: abuse.ch/urlhaus\n  Summary: URLhaus\n  License: CC0-1.0\n\
        Name: et/pro\n  Summary: Pro\n  License: Commercial\n  Replaces: et/open\n  Parameters: secret-code\n\
        Name: odd/two\n  License: Commercial\n  Parameters: user, secret-code\n";

    const KEY: &str = "SECRETKEY1234567";

    struct Fake {
        dir: PathBuf,
        calls: RefCell<Vec<String>>,
        build: String,
        reloaded: Cell<u32>,
        fetch_error: Cell<bool>,
    }

    fn out(code: i32, stdout: &str) -> Result<Out, String> {
        Ok(Out { code: Some(code), stdout: stdout.into(), stderr: String::new() })
    }

    impl Fake {
        fn names(&self) -> Vec<String> {
            let mut v: Vec<String> = fs::read_dir(&self.dir)
                .unwrap()
                .flatten()
                .filter_map(|e| fs::read_to_string(e.path()).ok())
                .filter_map(|t| t.lines().find_map(|l| l.strip_prefix("source: ").map(str::to_string)))
                .collect();
            v.sort();
            v
        }
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
                ("su", ["update-sources"]) => out(0, ""),
                ("su", ["list-enabled-sources"]) => {
                    let e: String = self.names().iter().map(|n| format!("  - {n}\n")).collect();
                    out(0, &format!("12/11/2026 -- 05:51:15 - <Info> -- Using data-directory /x\nEnabled sources:\n{e}"))
                }
                ("su", ["enable-source", n]) => {
                    fs::write(self.dir.join(file_name(n)), format!("source: {n}\n")).unwrap();
                    out(0, "")
                }
                ("/usr/bin/timeout", _) => {
                    let dir = args[args.iter().position(|a| *a == "-o").unwrap() + 1];
                    fs::write(Path::new(dir).join("suricata.rules"), &self.build).unwrap();
                    if self.fetch_error.get() {
                        // A vendor that puts the key in the download path.
                        let leaked = fs::read_to_string(self.dir.join("et-pro.yaml")).unwrap_or_default();
                        let url = match leaked.lines().find_map(|l| l.trim().strip_prefix("secret-code: ")) {
                            Some(key) => format!("https://rules.example/{key}/r.tar.gz?oinkcode={key}"),
                            None => "https://x.example/r.tar.gz".to_string(),
                        };
                        return out(0, &format!("12/11/2026 -- 05:52:07 - <Error> -- Failed to fetch {url}: HTTP Error 410: Gone\n"));
                    }
                    out(0, "")
                }
                ("sc", [_, "ruleset-reload-time"]) => out(
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

    /// `enabled` source files are created first; the sources directory sits at
    /// <tmp>/lib/update/sources like the real one.
    fn setup(tag: &str, enabled: &[&str], build: &str) -> (Tmp, Paths, Fake) {
        let d = std::env::temp_dir().join(format!("suritui-src-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let sources = d.join("lib/update/sources");
        fs::create_dir_all(&sources).unwrap();
        for n in enabled {
            fs::write(sources.join(file_name(n)), format!("source: {n}\n")).unwrap();
        }
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
            sources_dir: sources.clone(),
            require_root: false,
            reload_wait_secs: 0,
        };
        fs::write(&p.rules, format!("{A}\n{B}\n")).unwrap();
        let f = Fake { dir: sources, calls: RefCell::new(vec![]), build: build.to_string(), reloaded: Cell::new(0), fetch_error: Cell::new(false) };
        (Tmp(d), p, f)
    }

    fn three() -> String {
        format!("{A}\n{B}\n{C}\n")
    }

    #[test]
    fn names_and_keys_are_checked() {
        assert!(valid_name("et/open") && valid_name("abuse.ch/sslbl-ja3"));
        for bad in ["", "/etc", "-x", "--help", "-oFoo", "a..b", "a b", "a;b", "a\nb", "$(x)", &"a".repeat(65)] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert!(valid_key("0123456789abcdef0123456789abcdef01234567") && valid_key("ab_cd-ef12"));
        for bad in ["short", "has space1234", "new\nline1234", "q?x=1&y=2zz", "", &"a".repeat(129)] {
            assert!(!valid_key(bad), "{bad:?}");
        }
    }

    #[test]
    fn list_has_both_parts_and_no_snort_entry() {
        let (_t, p, f) = setup("list", &["et/open"], "");
        let l = list(&p, &f, false).unwrap().lines;
        let at = l.iter().position(|x| x == SEPARATOR).unwrap();
        assert_eq!(parse_enabled(&l[..at].join("\n")), vec!["et/open"]);
        let all = parse_sources(&l[at + 1..].join("\n"));
        assert!(all.iter().any(|s| s.name == "et/pro" && s.params == ["secret-code"]));
        assert!(!all.iter().any(|s| s.name.contains("snort")));
    }

    #[test]
    fn refresh_fetches_the_index_first() {
        let (_t, p, f) = setup("refresh", &["et/open"], "");
        list(&p, &f, true).unwrap();
        let c = f.calls.borrow();
        let u = c.iter().position(|x| x == "su update-sources").unwrap();
        assert!(c[u + 1].contains("list-enabled-sources"));
    }

    #[test]
    fn first_source_keeps_et_open() {
        let (_t, p, f) = setup("first", &[], &three());
        let r = change(&p, &f, true, "abuse.ch/urlhaus").unwrap().lines.join("\n");
        assert_eq!(f.names(), vec!["abuse.ch/urlhaus", "et/open"]);
        assert!(r.contains("et/open is now listed explicitly") && r.contains("1 added"), "{r}");
        assert!(fs::read_to_string(&p.rules).unwrap().contains("sid:300"));
    }

    #[test]
    fn a_failed_update_undoes_the_source() {
        let (_t, p, f) = setup("undo", &[], "");
        let e = change(&p, &f, true, "abuse.ch/urlhaus").unwrap_err();
        assert!(e.contains("undone"), "{e}");
        assert!(f.names().is_empty());
        assert!(fs::read_to_string(&p.rules).unwrap().contains("sid:200"));
    }

    #[test]
    fn a_source_that_cannot_be_downloaded_is_refused() {
        let (_t, p, f) = setup("fetch", &["et/open"], &three());
        f.fetch_error.set(true);
        let e = change(&p, &f, true, "abuse.ch/urlhaus").unwrap_err();
        assert!(e.contains("Failed to fetch https://x.example/r.tar.gz: HTTP Error 410: Gone"), "{e}");
        assert!(e.contains("nothing was installed") && e.contains("undone"), "{e}");
        assert_eq!(f.names(), vec!["et/open"]);
        assert!(!fs::read_to_string(&p.rules).unwrap().contains("sid:300"));
    }

    #[test]
    fn disable_removes_the_file_and_undoes_on_failure() {
        let (_t, p, f) = setup("dis", &["et/open"], "");
        assert!(change(&p, &f, false, "et/open").unwrap_err().contains("at least one"));
        let (_t2, p2, f2) = setup("dis2", &["et/open", "abuse.ch/urlhaus"], "");
        assert!(change(&p2, &f2, false, "abuse.ch/urlhaus").is_err());
        assert_eq!(f2.names(), vec!["abuse.ch/urlhaus", "et/open"]);
        let (_t3, p3, f3) = setup("dis3", &["et/open", "abuse.ch/urlhaus"], &three());
        let r = change(&p3, &f3, false, "abuse.ch/urlhaus").unwrap().lines.join("\n");
        assert_eq!(f3.names(), vec!["et/open"], "{r}");
    }

    #[test]
    fn refuses_keyed_unknown_and_repeated() {
        let (_t, p, f) = setup("ref", &["et/open"], "");
        assert!(change(&p, &f, true, "et/pro").unwrap_err().contains("key"));
        assert!(change(&p, &f, true, "nope/x").unwrap_err().contains("not in the source index"));
        assert!(change(&p, &f, true, "et/open").unwrap_err().contains("already"));
        assert!(change(&p, &f, false, "abuse.ch/urlhaus").unwrap_err().contains("not enabled"));
        assert!(change(&p, &f, true, "a b").is_err());
        assert!(f.calls.borrow().iter().all(|c| !c.contains("enable-source")));
    }

    #[test]
    fn a_pro_key_is_stored_private_and_replaces_et_open() {
        let (_t, p, f) = setup("pro", &["et/open"], &three());
        let r = set_key(&p, &f, "et/pro", KEY).unwrap().lines.join("\n");
        assert!(r.contains("et/pro replaces et/open"), "{r}");
        assert!(!r.contains(KEY));
        let file = p.sources_dir.join("et-pro.yaml");
        assert_eq!(fs::read_to_string(&file).unwrap(), format!("params:\n  secret-code: {KEY}\nsource: et/pro\n"));
        assert_eq!(fs::metadata(&file).unwrap().mode() & 0o777, 0o600);
        assert_eq!(f.names(), vec!["et/pro"]);
        assert!(!p.sources_dir.join("et-open.yaml").exists());
    }

    #[test]
    fn a_wrong_key_changes_nothing_and_never_shows_in_the_error() {
        // The failed download message can contain the whole URL, key included.
        let (_t, p, f) = setup("wrong", &["et/open"], &three());
        f.fetch_error.set(true);
        let e = set_key(&p, &f, "et/pro", KEY).unwrap_err();
        assert!(e.contains("Failed to fetch") && e.contains("oinkcode=***"), "{e}");
        assert!(!e.contains(KEY), "{e}");
        assert_eq!(f.names(), vec!["et/open"]);
        assert!(!p.sources_dir.join("et-pro.yaml").exists());
        // The helper's own log line never has the key either.
        assert!(!f.calls.borrow().iter().any(|c| c.contains(KEY)));
    }

    #[test]
    fn key_requests_are_checked() {
        let (_t, p, f) = setup("badkey", &["et/open"], &three());
        assert!(set_key(&p, &f, "et/pro", "short").is_err());
        assert!(set_key(&p, &f, "snort-registered", KEY).is_err());
        assert!(set_key(&p, &f, "../x", KEY).is_err());
        assert!(set_key(&p, &f, "odd/two", KEY).unwrap_err().contains("by hand"));
        assert!(set_key(&p, &f, "abuse.ch/urlhaus", KEY).unwrap_err().contains("by hand"));
        assert!(f.calls.borrow().iter().all(|c| !c.contains("enable-source")));
    }

    #[test]
    fn a_swapped_directory_is_refused() {
        let (_t, p, f) = setup("link", &["et/open"], &three());
        let elsewhere = p.sources_dir.with_file_name("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        fs::remove_dir_all(&p.sources_dir).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &p.sources_dir).unwrap();
        assert!(change(&p, &f, true, "abuse.ch/urlhaus").unwrap_err().contains("not a plain directory"));
        assert!(set_key(&p, &f, "et/pro", KEY).is_err());
        assert!(fs::read_dir(&elsewhere).unwrap().next().is_none());
    }

    #[test]
    fn secrets_are_found_and_hidden() {
        let (_t, p, _f) = setup("sec", &[], "");
        fs::write(p.sources_dir.join("a.yaml"), "params:\n  secret-code: ABCDEF123456\nsource: x\n").unwrap();
        fs::write(p.sources_dir.join("b.yaml"), "source: y\nurl: https://h/p.tgz?oinkcode=ZZZZ99998888&z=1\n").unwrap();
        let s = secrets(&p.sources_dir);
        assert!(s.contains(&"ABCDEF123456".to_string()) && s.contains(&"ZZZZ99998888".to_string()), "{s:?}");
        assert_eq!(redact(&p, "x ABCDEF123456 y ZZZZ99998888"), "x *** y ***");
    }
}
