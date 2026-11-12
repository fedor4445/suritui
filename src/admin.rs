//! The privileged rule-change logic behind `suritui-admin`.
//!
//! Everything that could hurt the router lives here, small and testable: the
//! input is one verb and one sid, every other value is a fixed path, and a
//! change only goes live after the rebuilt rules have been checked against the
//! live ones. IDS (pcap) only: nothing here touches drop/reject rules.

use crate::rules::parse_line;
use std::collections::HashMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

/// More flips than this besides the target means something is off.
pub const MAX_EXTRA_FLIPS: usize = 25;
/// Backups kept (newest first).
pub const KEEP_BACKUPS: usize = 5;
/// A rebuild that takes longer than this is killed (the daily one takes ~2 minutes).
pub const REBUILD_TIMEOUT_SECS: &str = "900";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Disable,
    Enable,
}

impl Verb {
    pub fn word(self) -> &'static str {
        match self {
            Verb::Disable => "disable",
            Verb::Enable => "enable",
        }
    }

    fn wants_enabled(self) -> bool {
        self == Verb::Enable
    }
}

/// A sid is 1 to 10 plain digits, not zero. Nothing else is accepted.
pub fn parse_sid(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok().filter(|n| *n > 0)
}

/// The sid a disable.conf line names (`2012345` or `1:2012345`), if it is a
/// plain sid line. Comments, groups and patterns give None.
pub(crate) fn line_sid(line: &str) -> Option<u64> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') || t.starts_with("group:") || t.starts_with("re:") {
        return None;
    }
    let first = t.split_whitespace().next()?;
    parse_sid(first.rsplit(':').next()?)
}

fn lists(text: &str, sid: u64) -> bool {
    text.lines().any(|l| line_sid(l) == Some(sid))
}

/// The text with every plain line naming `sid` removed.
fn without_sid(text: &str, sid: u64) -> String {
    let mut out = String::new();
    for line in text.lines().filter(|l| line_sid(l) != Some(sid)) {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The text with a line for `sid` appended.
fn with_sid(text: &str, sid: u64, date: &str) -> String {
    let mut out = text.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(&format!("{sid}  # suritui {date}\n"));
    out
}

/// New full texts for disable.conf and enable.conf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub disable: String,
    pub enable: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// The files already say it.
    NoChange(String),
    /// Candidates to try in order; the first whose rebuild flips the rule wins.
    Try(Vec<Candidate>),
}

/// Decide which edits to try. Pure: no I/O. The aim is the smallest edit, so
/// that disable followed by enable (or the reverse) restores the files exactly:
///   disable: add the sid to disable.conf, or take it back out of enable.conf;
///   enable:  take the sid out of disable.conf, or add it to enable.conf when a
///            group or the source keeps it off.
pub fn plan_change(dc: &str, ec: &str, verb: Verb, sid: u64, date: &str) -> Plan {
    let (d, e) = (lists(dc, sid), lists(ec, sid));
    let cand = |disable: String, enable: String| Candidate { disable, enable };
    match verb {
        Verb::Disable => {
            if e {
                let mut v = vec![cand(dc.to_string(), without_sid(ec, sid))];
                if !d {
                    // It was on by default as well: list it in disable.conf too.
                    v.push(cand(with_sid(dc, sid, date), without_sid(ec, sid)));
                }
                Plan::Try(v)
            } else if d {
                Plan::NoChange(format!("sid {sid} is already listed in disable.conf"))
            } else {
                Plan::Try(vec![cand(with_sid(dc, sid, date), ec.to_string())])
            }
        }
        Verb::Enable => {
            if d {
                let mut v = vec![cand(without_sid(dc, sid), ec.to_string())];
                if !e {
                    // A group keeps it off as well: enable.conf overrides that.
                    v.push(cand(without_sid(dc, sid), with_sid(ec, sid, date)));
                }
                Plan::Try(v)
            } else if e {
                Plan::NoChange(format!("sid {sid} is already listed in enable.conf"))
            } else {
                Plan::Try(vec![cand(dc.to_string(), with_sid(ec, sid, date))])
            }
        }
    }
}

pub(crate) fn rule_map(text: &str) -> HashMap<u64, (bool, String)> {
    let mut m = HashMap::new();
    for line in text.lines() {
        if let Some(r) = parse_line(line) {
            let body = r.text.trim_start_matches('#').trim_start().to_string();
            m.insert(r.sid, (r.enabled, body));
        }
    }
    m
}

#[derive(Debug, PartialEq, Eq)]
pub enum DiffError {
    /// The rebuild left the target in its old state: the next candidate may do it.
    TargetUnchanged(String),
    Other(String),
}

impl std::fmt::Display for DiffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiffError::TargetUnchanged(m) | DiffError::Other(m) => write!(f, "{m}"),
        }
    }
}

/// Compare the live rules with the rebuilt candidate. Ok(other sids whose state
/// also flipped, sorted) when the only differences are the target's state and a
/// few flowbit dependents; Err(reason) for anything else.
pub fn check_rule_diff(live: &str, cand: &str, sid: u64, verb: Verb) -> Result<Vec<u64>, DiffError> {
    let other = |m: String| DiffError::Other(m);
    let (l, c) = (rule_map(live), rule_map(cand));
    if l.is_empty() {
        return Err(other("the live rules file has no rules; refusing to continue".into()));
    }
    let added = c.keys().filter(|k| !l.contains_key(k)).count();
    let removed = l.keys().filter(|k| !c.contains_key(k)).count();
    if added > 0 || removed > 0 {
        return Err(other(format!(
            "the rebuilt rules add {added} and remove {removed} rules; the cache is not what produced the live \
             rules. Run the daily update first"
        )));
    }
    let mut flips = Vec::new();
    let mut text_changed = 0;
    for (k, (le, lb)) in &l {
        let (ce, cb) = &c[k];
        if lb != cb {
            text_changed += 1;
        }
        if le != ce {
            flips.push(*k);
        }
    }
    if text_changed > 0 {
        return Err(other(format!(
            "{text_changed} rules changed text; the cache is not what produced the live rules. Run the daily update first"
        )));
    }
    let Some((live_state, _)) = l.get(&sid) else {
        return Err(other(format!("sid {sid} is not in the live rules")));
    };
    let want = verb.wants_enabled();
    let cand_state = c[&sid].0;
    if cand_state != want {
        return Err(DiffError::TargetUnchanged(format!(
            "after the rebuild sid {sid} is still {} (a rule that other enabled rules depend on through flowbits \
             cannot be turned off, and a rule switched off by a group needs enable.conf)",
            if cand_state { "enabled" } else { "disabled" }
        )));
    }
    if *live_state == want && flips.contains(&sid) {
        return Err(other("internal inconsistency in the diff".into()));
    }
    let mut extra: Vec<u64> = flips.into_iter().filter(|k| *k != sid).collect();
    extra.sort_unstable();
    if extra.len() > MAX_EXTRA_FLIPS {
        return Err(other(format!(
            "{} other rules would change state (limit {MAX_EXTRA_FLIPS}); refusing",
            extra.len()
        )));
    }
    Ok(extra)
}

/// `YYYY-MM-DD` of a unix time (UTC), without a date library.
pub fn ymd(secs: u64) -> String {
    let z = (secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

// ------------------------------------------------------------ running things

pub struct Out {
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Runs the few external programs. Fixed program paths and arguments only.
pub trait Runner {
    fn run(&self, prog: &str, args: &[&str]) -> Result<Out, String>;
}

pub struct SystemRunner;

impl Runner for SystemRunner {
    fn run(&self, prog: &str, args: &[&str]) -> Result<Out, String> {
        let out = Command::new(prog)
            .args(args)
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin")
            .env("LANG", "C")
            .output()
            .map_err(|e| format!("cannot run {prog}: {e}"))?;
        Ok(Out {
            code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        })
    }
}

/// Every path and program the helper touches. Production values are constants;
/// tests build their own under a temp dir.
#[derive(Debug, Clone)]
pub struct Paths {
    pub disable_conf: PathBuf,
    pub enable_conf: PathBuf,
    pub threshold_conf: PathBuf,
    pub suricata_yaml: PathBuf,
    pub suricata_bin: String,
    pub rules: PathBuf,
    pub build_dir: PathBuf,
    pub backup_root: PathBuf,
    pub cache_dir: PathBuf,
    pub update_log: PathBuf,
    pub suricata_log: PathBuf,
    pub eve_dir: PathBuf,
    pub lock: PathBuf,
    pub log: PathBuf,
    pub suricata_update: String,
    pub suricatasc: String,
    /// suricata-update's sources directory (holds the keys).
    pub sources_dir: PathBuf,
    pub require_root: bool,
    /// How long to wait for a started reload to finish.
    pub reload_wait_secs: u64,
}

impl Paths {
    pub fn production() -> Paths {
        Paths {
            disable_conf: "/usr/local/etc/suricata/disable.conf".into(),
            enable_conf: "/usr/local/etc/suricata/enable.conf".into(),
            threshold_conf: "/usr/local/etc/suricata/threshold.config".into(),
            suricata_yaml: "/usr/local/etc/suricata/suricata.yaml".into(),
            suricata_bin: "/usr/local/bin/suricata".into(),
            rules: "/var/lib/suricata/rules/suricata.rules".into(),
            // Root-only parents: the suricata user must never be able to plant
            // a symlink that the root helper would write through.
            build_dir: "/var/db/suritui-build".into(),
            backup_root: "/var/backups/suritui".into(),
            cache_dir: "/var/lib/suricata/update/cache".into(),
            update_log: "/var/log/suricata/update.log".into(),
            suricata_log: "/var/log/suricata/suricata.log".into(),
            eve_dir: "/var/log/suricata".into(),
            lock: "/var/run/suritui-admin.lock".into(),
            log: "/var/log/suritui-admin.log".into(),
            suricata_update: "/usr/local/bin/suricata-update".into(),
            suricatasc: "/usr/local/bin/suricatasc".into(),
            sources_dir: "/var/lib/suricata/update/sources".into(),
            require_root: true,
            reload_wait_secs: 180,
        }
    }
}

pub(crate) fn io(what: &str, e: std::io::Error) -> String {
    format!("{what}: {e}")
}

pub(crate) struct Lock(PathBuf);

impl Lock {
    pub(crate) fn take(path: &Path, runner: &dyn Runner) -> Result<Lock, String> {
        for attempt in 0..2 {
            match fs::OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut f) => {
                    use std::io::Write;
                    let _ = writeln!(f, "{}", std::process::id());
                    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
                    return Ok(Lock(path.to_path_buf()));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && attempt == 0 => {
                    let pid = fs::read_to_string(path).unwrap_or_default();
                    let pid = pid.trim();
                    let alive = parse_sid(pid).is_some_and(|p| {
                        runner
                            .run("/bin/ps", &["-p", &p.to_string()])
                            .map(|o| o.code == Some(0))
                            .unwrap_or(true)
                    });
                    if alive {
                        return Err("another suritui-admin run is active".into());
                    }
                    let _ = fs::remove_file(path); // stale: its owner is gone
                }
                Err(e) => return Err(io("cannot take the lock", e)),
            }
        }
        Err("cannot take the lock".into())
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Write `data` to `path` the safe way for a directory another user can write
/// to: a fresh staging file created with O_EXCL (never through a symlink), owner
/// and mode set on the open file, then an atomic rename over `path`.
pub(crate) fn put(path: &Path, data: &[u8], like: &fs::Metadata) -> Result<(), String> {
    use std::io::Write;
    let mut name = path.as_os_str().to_os_string();
    name.push(".suritui-new");
    let stage = PathBuf::from(name);
    match fs::remove_file(&stage) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(io("clear the staging file", e)),
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode_0600()
        .open(&stage)
        .map_err(|e| io("create the staging file", e))?;
    let r = (|| -> Result<(), String> {
        f.write_all(data).map_err(|e| io("write", e))?;
        std::os::unix::fs::fchown(&f, Some(like.uid()), Some(like.gid())).map_err(|e| io("chown", e))?;
        f.set_permissions(fs::Permissions::from_mode(like.mode() & 0o7777)).map_err(|e| io("chmod", e))?;
        f.sync_all().map_err(|e| io("sync", e))
    })();
    if let Err(e) = r {
        let _ = fs::remove_file(&stage);
        return Err(e);
    }
    fs::rename(&stage, path).map_err(|e| {
        let _ = fs::remove_file(&stage);
        io("rename into place", e)
    })
}

/// A live file must be a plain file, not a symlink or anything else.
pub(crate) fn plain_file(path: &Path) -> Result<fs::Metadata, String> {
    let m = fs::symlink_metadata(path).map_err(|e| io(&format!("cannot stat {}", path.display()), e))?;
    if !m.file_type().is_file() {
        return Err(format!("{} is not a regular file; refusing", path.display()));
    }
    Ok(m)
}

trait Mode600 {
    fn mode_0600(&mut self) -> &mut Self;
}

impl Mode600 for fs::OpenOptions {
    fn mode_0600(&mut self) -> &mut Self {
        std::os::unix::fs::OpenOptionsExt::mode(self, 0o600)
    }
}

pub(crate) fn prune_backups(root: &Path) {
    let Ok(rd) = fs::read_dir(root) else { return };
    let mut dirs: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.is_dir()).collect();
    dirs.sort();
    while dirs.len() > KEEP_BACKUPS {
        let _ = fs::remove_dir_all(dirs.remove(0));
    }
}

/// What a finished change tells the user.
#[derive(Debug, Default)]
pub struct Report {
    pub lines: Vec<String>,
}

pub(crate) fn say(r: &mut Report, s: impl Into<String>) {
    r.lines.push(s.into());
}

pub(crate) fn log_line(paths: &Paths, runner: &dyn Runner, msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(&paths.log) {
        let _ = writeln!(f, "{} {msg}", ymd(now()));
    }
    let _ = runner.run("/usr/bin/logger", &["-t", "suritui-admin", msg]);
}

pub(crate) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub(crate) fn suricata_running(runner: &dyn Runner) -> bool {
    runner
        .run("/bin/pgrep", &["-x", "suricata"])
        .map(|o| o.code == Some(0))
        .unwrap_or(false)
}

/// `last_reload` of the running ruleset: it changes when a reload has finished.
fn last_reload(paths: &Paths, runner: &dyn Runner) -> Option<String> {
    let o = runner.run(&paths.suricatasc, &["-c", "ruleset-reload-time"]).ok()?;
    let v: serde_json::Value = serde_json::from_str(o.stdout.trim()).ok()?;
    v.get("message")?.get(0)?.get("last_reload")?.as_str().map(str::to_string)
}

fn failed_rules(paths: &Paths, runner: &dyn Runner) -> Option<u64> {
    let o = runner.run(&paths.suricatasc, &["-c", "ruleset-stats"]).ok()?;
    let v: serde_json::Value = serde_json::from_str(o.stdout.trim()).ok()?;
    v.get("message")?.get(0)?.get("rules_failed")?.as_u64()
}

/// Ask Suricata for a live reload and wait until it has really finished (the
/// request itself is answered at once). Fails if Suricata does not accept it,
/// does not finish in time, or cannot load some of the rules.
pub(crate) fn reload(paths: &Paths, runner: &dyn Runner) -> Result<(), String> {
    let before = last_reload(paths, runner);
    let failed_before = failed_rules(paths, runner);
    let o = runner.run(&paths.suricatasc, &["-c", "ruleset-reload-nonblocking"])?;
    let ok_reply = o.stdout.contains("\"return\": \"OK\"") || o.stdout.contains("\"return\":\"OK\"");
    if !(o.code == Some(0) && ok_reply) {
        let why = [o.stdout.trim(), o.stderr.trim()]
            .iter()
            .filter(|t| !t.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" ");
        return Err(format!(
            "reload was not accepted ({})",
            if why.is_empty() { "no answer from Suricata: is it running?" } else { &why }
        ));
    }
    // Without a timestamp to compare there is nothing to wait for; the caller's
    // health check still runs.
    let Some(before) = before else { return Ok(()) };
    let start = std::time::Instant::now();
    loop {
        if last_reload(paths, runner).is_some_and(|now| now != before) {
            break;
        }
        if start.elapsed() >= std::time::Duration::from_secs(paths.reload_wait_secs) {
            return Err(format!(
                "Suricata accepted the reload but did not finish it within {} seconds",
                paths.reload_wait_secs
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if let (Some(fb), Some(fa)) = (failed_before, failed_rules(paths, runner)) {
        if fa > fb {
            return Err(format!("Suricata could not load {} rules of the new set", fa - fb));
        }
    }
    Ok(())
}

/// One file to replace: what it should hold afterwards and what it held before
/// (`None` = absent). Texts are borrowed so the 46 MB rules file is not copied.
pub(crate) struct Swap<'a> {
    pub path: PathBuf,
    pub new: Option<&'a str>,
    pub old: Option<&'a str>,
    pub meta: &'a fs::Metadata,
}

fn put_or_remove(path: &Path, text: Option<&str>, meta: &fs::Metadata) -> Result<(), String> {
    match text {
        Some(t) => put(path, t.as_bytes(), meta),
        None => match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(io("remove", e)),
        },
    }
}

/// Install every changed file in order, reload Suricata live and check that it
/// is still running. On any failure all files go back and Suricata reloads again.
pub(crate) fn commit_swaps(
    paths: &Paths,
    runner: &dyn Runner,
    swaps: &[Swap],
    backup: &Path,
    what: &str,
) -> Result<(), String> {
    let restore = || -> Result<(), String> {
        let mut result = Ok(());
        for sw in swaps.iter().rev().filter(|sw| sw.new != sw.old) {
            let r = put_or_remove(&sw.path, sw.old, sw.meta);
            if result.is_ok() {
                result = r;
            }
        }
        result
    };
    for sw in swaps.iter().filter(|sw| sw.new != sw.old) {
        if let Err(e) = put_or_remove(&sw.path, sw.new, sw.meta) {
            let _ = restore();
            return Err(format!("{e} (previous files restored)"));
        }
    }
    let reloaded = reload(paths, runner);
    let healthy = reloaded.is_ok() && {
        std::thread::sleep(std::time::Duration::from_secs(if paths.require_root { 3 } else { 0 }));
        suricata_running(runner)
    };
    if healthy {
        return Ok(());
    }
    let restored = restore();
    let again = reload(paths, runner);
    let tail = match (&restored, &again) {
        (Ok(()), Ok(())) => " and reloaded".to_string(),
        (Ok(()), Err(_)) => {
            ". The files are restored, but Suricata did not accept a reload: check that it is running".to_string()
        }
        (Err(e), _) => format!(". Restoring the files failed ({e}): the backup is in {}", backup.display()),
    };
    log_line(paths, runner, &format!("FAILED {what}: restored the previous rules"));
    Err(format!(
        "Suricata did not take the new rules ({}); the previous rules are back{tail}",
        reloaded.err().unwrap_or_else(|| "it stopped running".into()),
    ))
}

/// Build the rules for one candidate into the scratch directory and return them.
fn rebuild(paths: &Paths, runner: &dyn Runner, cand: &Candidate) -> Result<String, String> {
    let _ = fs::remove_dir_all(&paths.build_dir);
    fs::create_dir_all(&paths.build_dir).map_err(|e| io("cannot create the build directory", e))?;
    let cand_dc = paths.build_dir.join("disable.conf");
    let cand_ec = paths.build_dir.join("enable.conf");
    fs::write(&cand_dc, &cand.disable).map_err(|e| io("cannot write the candidate", e))?;
    // Always passed explicitly so a stale live enable.conf cannot leak into the build.
    let ec_text = if cand.enable.trim().is_empty() { "# none\n" } else { cand.enable.as_str() };
    fs::write(&cand_ec, ec_text).map_err(|e| io("cannot write the candidate", e))?;
    let build_dir = paths.build_dir.to_string_lossy().into_owned();
    let (dc_s, ec_s) = (cand_dc.to_string_lossy().into_owned(), cand_ec.to_string_lossy().into_owned());
    let o = runner.run(
        "/usr/bin/timeout",
        &[
            REBUILD_TIMEOUT_SECS, "/usr/bin/nice", "-n", "15", &paths.suricata_update, "--offline", "--no-reload",
            "--disable-conf", &dc_s, "--enable-conf", &ec_s, "-o", &build_dir,
        ],
    )?;
    if o.code != Some(0) {
        let tail: Vec<&str> = o.stdout.lines().chain(o.stderr.lines()).rev().take(3).collect();
        return Err(format!("the rebuild failed (exit {:?}): {}", o.code, tail.join(" | ")));
    }
    fs::read_to_string(paths.build_dir.join("suricata.rules")).map_err(|e| io("the rebuild produced no rules file", e))
}

/// Disable or enable one rule. Nothing changes unless every check passes; if the
/// reload fails the previous files are put back and reloaded again.
pub fn apply(paths: &Paths, runner: &dyn Runner, verb: Verb, sid: u64) -> Result<Report, String> {
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
    let dc_meta = plain_file(&paths.disable_conf)?;
    let ec_exists = paths.enable_conf.exists() || fs::symlink_metadata(&paths.enable_conf).is_ok();
    let ec_meta = if ec_exists { plain_file(&paths.enable_conf)? } else { dc_meta.clone() };
    let live_rules = fs::read_to_string(&paths.rules).map_err(|e| io("cannot read the live rules", e))?;
    if !rule_map(&live_rules).contains_key(&sid) {
        return Err(format!("sid {sid} is not in the live rules"));
    }
    let dc_text = fs::read_to_string(&paths.disable_conf).map_err(|e| io("cannot read disable.conf", e))?;
    let ec_text = if ec_exists {
        fs::read_to_string(&paths.enable_conf).map_err(|e| io("cannot read enable.conf", e))?
    } else {
        String::new()
    };
    let candidates = match plan_change(&dc_text, &ec_text, verb, sid, &ymd(now())) {
        Plan::NoChange(msg) => {
            say(&mut rep, format!("{msg}; nothing changed"));
            return Ok(rep);
        }
        Plan::Try(c) => c,
    };

    // 2./3. rebuild each candidate into a scratch directory (never the live one)
    // and check it against the live rules; the first that really flips the rule wins.
    let cleanup = |p: &Paths| {
        let _ = fs::remove_dir_all(&p.build_dir);
    };
    let mut chosen: Option<(Candidate, String, Vec<u64>)> = None;
    let mut last_err = String::from("no candidate worked");
    for cand in &candidates {
        let cand_rules = match rebuild(paths, runner, cand) {
            Ok(t) => t,
            Err(e) => {
                cleanup(paths);
                return Err(e);
            }
        };
        match check_rule_diff(&live_rules, &cand_rules, sid, verb) {
            Ok(extra) => {
                chosen = Some((cand.clone(), cand_rules, extra));
                break;
            }
            Err(DiffError::TargetUnchanged(m)) => last_err = m,
            Err(DiffError::Other(m)) => {
                cleanup(paths);
                return Err(m);
            }
        }
    }
    cleanup(paths);
    let Some((cand, cand_rules, extra)) = chosen else {
        return Err(last_err);
    };

    // Back up now that every check has passed (refused attempts leave nothing behind).
    let stamp = format!("{}-{}", ymd(now()), now());
    let backup = paths.backup_root.join(&stamp);
    fs::create_dir_all(&backup).map_err(|e| io("cannot create the backup directory", e))?;
    let _ = fs::set_permissions(&paths.backup_root, fs::Permissions::from_mode(0o700));
    fs::copy(&paths.disable_conf, backup.join("disable.conf")).map_err(|e| io("backup of disable.conf", e))?;
    if ec_exists {
        fs::copy(&paths.enable_conf, backup.join("enable.conf")).map_err(|e| io("backup of enable.conf", e))?;
    }
    fs::copy(&paths.rules, backup.join("suricata.rules")).map_err(|e| io("backup of the rules", e))?;
    say(&mut rep, format!("backup: {}", backup.display()));

    // 4./5. install the new files and reload; everything is undone from the
    // originals held in memory if any step fails.
    let new_ec = (!cand.enable.trim().is_empty()).then_some(cand.enable.as_str());
    let old_ec = ec_exists.then_some(ec_text.as_str());
    let swaps = [
        Swap { path: paths.disable_conf.clone(), new: Some(&cand.disable), old: Some(&dc_text), meta: &dc_meta },
        Swap { path: paths.enable_conf.clone(), new: new_ec, old: old_ec, meta: &ec_meta },
        Swap { path: paths.rules.clone(), new: Some(&cand_rules), old: Some(&live_rules), meta: &rules_meta },
    ];
    commit_swaps(paths, runner, &swaps, &backup, &format!("{} sid {sid}", verb.word()))?;
    prune_backups(&paths.backup_root);
    log_line(paths, runner, &format!("{} sid {sid} (backup {stamp})", verb.word()));
    say(&mut rep, format!("sid {sid} {}d; Suricata reloaded", verb.word()));
    if !extra.is_empty() {
        let list: Vec<String> = extra.iter().map(u64::to_string).collect();
        say(&mut rep, format!("also changed (flowbit dependencies): {}", list.join(" ")));
    }
    Ok(rep)
}

/// Why a read verb failed. `NoSuchDay` maps to exit code 3 for the TUI.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    NoSuchDay,
    Other(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReadError::NoSuchDay => write!(f, "no alert log for that day"),
            ReadError::Other(m) => write!(f, "{m}"),
        }
    }
}

fn open_plain(path: &Path) -> Result<fs::File, ReadError> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => {}
        Ok(_) => return Err(ReadError::Other(format!("{} is not a regular file; refusing", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ReadError::NoSuchDay),
        Err(e) => return Err(ReadError::Other(io("cannot stat the log", e))),
    }
    fs::File::open(path).map_err(|e| ReadError::Other(io("cannot open", e)))
}

const ALERT_MARK: &[u8] = b"\"event_type\":\"alert\"";

fn has_alert_mark(line: &[u8]) -> bool {
    line.windows(ALERT_MARK.len()).any(|w| w == ALERT_MARK)
}

fn copy_alert_lines<R: std::io::Read, W: std::io::Write>(r: R, w: &mut W) -> Result<(), ReadError> {
    use std::io::BufRead;
    let mut r = std::io::BufReader::new(r);
    let mut line = Vec::new();
    loop {
        line.clear();
        let n = r.read_until(b'\n', &mut line).map_err(|e| ReadError::Other(io("read", e)))?;
        if n == 0 {
            return Ok(());
        }
        if has_alert_mark(&line) {
            if !line.ends_with(b"\n") {
                line.push(b'\n');
            }
            w.write_all(&line).map_err(|e| ReadError::Other(io("write", e)))?;
        }
    }
}

/// `alerts live` / `alerts day K`: print the alert events (raw JSON lines).
pub fn read_alerts<W: std::io::Write>(paths: &Paths, r: crate::source::Range, w: &mut W) -> Result<(), ReadError> {
    use crate::source::{validate, Range};
    let r = validate(r).map_err(|_| ReadError::NoSuchDay)?;
    match r {
        Range::Today => copy_alert_lines(open_plain(&paths.eve_dir.join("eve.json"))?, w),
        Range::Day(k) => {
            let f = open_plain(&paths.eve_dir.join(format!("eve.json.{k}.gz")))?;
            copy_alert_lines(flate2::read::MultiGzDecoder::new(f), w)
        }
    }
}

/// How much of the end of a log is shown.
pub const LOG_TAIL_BYTES: u64 = 96 * 1024;
pub const LOG_TAIL_LINES: usize = 400;

/// Which log `suritui-admin log NAME` may print.
pub fn log_path<'a>(paths: &'a Paths, name: &str) -> Option<&'a Path> {
    match name {
        "suricata" => Some(&paths.suricata_log),
        "update" => Some(&paths.update_log),
        "admin" => Some(&paths.log),
        _ => None,
    }
}

/// `log NAME`: the last lines of one of three fixed logs.
pub fn read_log<W: std::io::Write>(paths: &Paths, name: &str, w: &mut W) -> Result<(), ReadError> {
    use std::io::{Read, Seek, SeekFrom};
    let path = log_path(paths, name).ok_or_else(|| ReadError::Other("unknown log (suricata | update | admin)".into()))?;
    let mut f = open_plain(path)?;
    let len = f.metadata().map_err(|e| ReadError::Other(io("stat", e)))?.len();
    let from = len.saturating_sub(LOG_TAIL_BYTES);
    f.seek(SeekFrom::Start(from)).map_err(|e| ReadError::Other(io("seek", e)))?;
    let mut buf = Vec::new();
    f.take(LOG_TAIL_BYTES).read_to_end(&mut buf).map_err(|e| ReadError::Other(io("read", e)))?;
    let mut text = String::from_utf8_lossy(&buf).into_owned();
    if from > 0 {
        // The first line is probably cut in half.
        if let Some(i) = text.find('\n') {
            text.drain(..=i);
        }
    }
    // A failed download is logged with its whole URL; hide any stored key in it.
    let text = crate::sources::redact(paths, &text);
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(LOG_TAIL_LINES);
    for l in &lines[start..] {
        writeln!(w, "{l}").map_err(|e| ReadError::Other(io("write", e)))?;
    }
    Ok(())
}

/// `rules`: print the live rules file, so the TUI can show what is loaded.
pub fn read_rules<W: std::io::Write>(paths: &Paths, w: &mut W) -> Result<(), ReadError> {
    let mut f = open_plain(&paths.rules)?;
    std::io::copy(&mut f, w).map_err(|e| ReadError::Other(io("read the rules", e)))?;
    Ok(())
}

/// Read-only summary for `status`.
pub fn status(paths: &Paths, runner: &dyn Runner) -> Report {
    let mut rep = Report::default();
    say(&mut rep, format!("suricata running: {}", if suricata_running(runner) { "yes" } else { "no" }));
    match fs::read_to_string(&paths.rules) {
        Ok(t) => {
            let m = rule_map(&t);
            let off = m.values().filter(|(e, _)| !*e).count();
            say(&mut rep, format!("rules: {} loaded file, {} disabled", m.len(), off));
        }
        Err(e) => say(&mut rep, format!("rules: cannot read ({e})")),
    }
    let n = fs::read_to_string(&paths.disable_conf)
        .map(|t| t.lines().filter(|l| line_sid(l).is_some()).count())
        .unwrap_or(0);
    say(&mut rep, format!("disable.conf: {n} sids"));
    let e = fs::read_to_string(&paths.enable_conf)
        .map(|t| t.lines().filter(|l| line_sid(l).is_some()).count())
        .unwrap_or(0);
    say(&mut rep, format!("enable.conf: {e} sids"));
    let update = runner
        .run("/bin/pgrep", &["-f", "suricata-update"])
        .map(|o| o.code == Some(0))
        .unwrap_or(false);
    say(&mut rep, format!("update running: {}", if update { "yes" } else { "no" }));
    rep
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const R_ON: &str = "alert tcp any any -> any any (msg:\"ET SCAN a\"; sid:100; rev:1;)";
    const R_OFF: &str = "# alert tcp any any -> any any (msg:\"ET SCAN a\"; sid:100; rev:1;)";
    const R2: &str = "alert tcp any any -> any any (msg:\"ET INFO b\"; sid:200; rev:1;)";
    const R2_OFF: &str = "# alert tcp any any -> any any (msg:\"ET INFO b\"; sid:200; rev:1;)";

    fn rules(parts: &[&str]) -> String {
        parts.join("\n") + "\n"
    }

    #[test]
    fn sid_validation() {
        assert_eq!(parse_sid("2012345"), Some(2012345));
        for bad in ["", "0", "-1", "+5", " 5", "5 ", "1e3", "12345678901", "5;ls", "../x", "0x10", "١٢"] {
            assert_eq!(parse_sid(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn dates() {
        assert_eq!(ymd(0), "1970-01-01");
        assert_eq!(ymd(1_700_000_000), "2023-11-14");
        assert_eq!(ymd(951_782_400), "2000-02-29");
    }

    fn c(dc: &str, ec: &str) -> Candidate {
        Candidate { disable: dc.to_string(), enable: ec.to_string() }
    }

    #[test]
    fn disable_adds_to_disable_conf_and_is_idempotent() {
        let t = "# c\ngroup:x.rules\n5\n";
        let Plan::Try(v) = plan_change(t, "", Verb::Disable, 9, "2026-01-02") else { panic!() };
        assert_eq!(v, vec![c("# c\ngroup:x.rules\n5\n9  # suritui 2026-01-02\n", "")]);
        assert!(matches!(plan_change(t, "", Verb::Disable, 5, "d"), Plan::NoChange(_)));
        let Plan::Try(v) = plan_change("5", "", Verb::Disable, 9, "d") else { panic!() };
        assert!(v[0].disable.starts_with("5\n9"));
    }

    #[test]
    fn enable_removes_only_that_sid_from_disable_conf_first() {
        let t = "# keep\n7\n1:9  # suritui d\n9x\ngroup:g.rules\n";
        let Plan::Try(v) = plan_change(t, "", Verb::Enable, 9, "D") else { panic!() };
        assert_eq!(v[0], c("# keep\n7\n9x\ngroup:g.rules\n", ""));
        // second candidate: a group keeps it off, so enable.conf is added too
        assert_eq!(v[1], c("# keep\n7\n9x\ngroup:g.rules\n", "9  # suritui D\n"));
        assert_eq!(v.len(), 2);
    }

    #[test]
    fn enable_of_a_group_disabled_rule_goes_to_enable_conf() {
        let Plan::Try(v) = plan_change("group:g.rules\n", "", Verb::Enable, 11, "D") else { panic!() };
        assert_eq!(v, vec![c("group:g.rules\n", "11  # suritui D\n")]);
        assert!(matches!(plan_change("", "11\n", Verb::Enable, 11, "D"), Plan::NoChange(_)));
    }

    #[test]
    fn disable_undoes_an_enable_conf_entry_exactly() {
        let ec = "11  # suritui D\n";
        let Plan::Try(v) = plan_change("group:g.rules\n", ec, Verb::Disable, 11, "D") else { panic!() };
        assert_eq!(v[0], c("group:g.rules\n", ""));
        // fallback when the rule is also on by default: list it in disable.conf too
        assert_eq!(v[1], c("group:g.rules\n11  # suritui D\n", ""));
    }

    #[test]
    fn round_trips_restore_the_texts() {
        let dc = "# c\ngroup:g.rules\n";
        // disable then enable
        let Plan::Try(a) = plan_change(dc, "", Verb::Disable, 9, "D") else { panic!() };
        let Plan::Try(b) = plan_change(&a[0].disable, &a[0].enable, Verb::Enable, 9, "D") else { panic!() };
        assert_eq!(b[0], c(dc, ""));
        // enable (via enable.conf) then disable
        let Plan::Try(a) = plan_change(dc, "", Verb::Enable, 9, "D") else { panic!() };
        let Plan::Try(b) = plan_change(&a[0].disable, &a[0].enable, Verb::Disable, 9, "D") else { panic!() };
        assert_eq!(b[0], c(dc, ""));
    }

    #[test]
    fn diff_accepts_the_one_expected_flip() {
        let live = rules(&[R_ON, R2]);
        let cand = rules(&[R_OFF, R2]);
        assert_eq!(check_rule_diff(&live, &cand, 100, Verb::Disable), Ok(vec![]));
    }

    #[test]
    fn diff_lists_flowbit_dependents_on_enable() {
        let live = rules(&[R_OFF, R2_OFF]);
        let cand = rules(&[R_ON, R2]);
        assert_eq!(check_rule_diff(&live, &cand, 100, Verb::Enable), Ok(vec![200]));
    }

    #[test]
    fn diff_refuses_surprises() {
        let live = rules(&[R_ON, R2]);
        // target did not flip (flowbit keeps it enabled)
        let e = check_rule_diff(&live, &live, 100, Verb::Disable).unwrap_err();
        assert!(matches!(e, DiffError::TargetUnchanged(_)));
        let e = e.to_string();
        assert!(e.contains("still enabled"), "{e}");
        // a rule was removed
        let e = check_rule_diff(&live, &rules(&[R_OFF]), 100, Verb::Disable).unwrap_err().to_string();
        assert!(e.contains("remove 1"), "{e}");
        // a rule changed text
        let changed = rules(&[R_OFF, &R2.replace("rev:1", "rev:2")]);
        let e = check_rule_diff(&live, &changed, 100, Verb::Disable).unwrap_err().to_string();
        assert!(e.contains("changed text"), "{e}");
        // unknown sid
        assert!(check_rule_diff(&live, &live, 999, Verb::Disable).is_err());
        // empty live file
        assert!(check_rule_diff("", "", 100, Verb::Disable).is_err());
    }

    #[test]
    fn diff_caps_the_number_of_other_flips() {
        let mk = |on: bool| {
            let mut v = vec![if on { R_ON.to_string() } else { R_OFF.to_string() }];
            for i in 0..(MAX_EXTRA_FLIPS + 1) {
                let body = format!("alert tcp any any -> any any (msg:\"ET X {i}\"; sid:{}; rev:1;)", 1000 + i);
                v.push(if on { body } else { format!("# {body}") });
            }
            v.join("\n") + "\n"
        };
        let e = check_rule_diff(&mk(false), &mk(true), 100, Verb::Enable).unwrap_err().to_string();
        assert!(e.contains("limit"), "{e}");
    }

    // ---- orchestration with a fake runner and a temp dir ----

    enum Rebuild {
        Rules(String),
        /// One result per rebuild, in order.
        Seq(RefCell<Vec<String>>),
        Fail,
    }

    struct Fake {
        calls: RefCell<Vec<String>>,
        root: bool,
        update_running: bool,
        alive: bool,
        rebuild: Rebuild,
        reloads: RefCell<Vec<bool>>,
        /// enable.conf texts the rebuilds were given.
        seen_enable: RefCell<Vec<String>>,
        /// Reloads Suricata has accepted (drives `ruleset-reload-time`).
        reloaded: std::cell::Cell<u32>,
        /// The reload never finishes.
        stuck: bool,
        /// `rules_failed` after a reload.
        failed_after: u64,
        /// Polls that still show the old timestamp after a reload was accepted.
        slow_polls: std::cell::Cell<u32>,
    }

    impl Fake {
        fn ok(cand_rules: String) -> Fake {
            Fake {
                calls: RefCell::new(vec![]),
                root: true,
                update_running: false,
                alive: true,
                rebuild: Rebuild::Rules(cand_rules),
                reloads: RefCell::new(vec![true]),
                seen_enable: RefCell::new(vec![]),
                reloaded: std::cell::Cell::new(0),
                stuck: false,
                failed_after: 0,
                slow_polls: std::cell::Cell::new(0),
            }
        }
    }

    fn out(code: i32, stdout: &str) -> Result<Out, String> {
        Ok(Out { code: Some(code), stdout: stdout.into(), stderr: String::new() })
    }

    impl Runner for Fake {
        fn run(&self, prog: &str, args: &[&str]) -> Result<Out, String> {
            self.calls.borrow_mut().push(format!("{prog} {}", args.join(" ")));
            match prog {
                "/usr/bin/id" => out(0, if self.root { "0\n" } else { "1000\n" }),
                "/bin/pgrep" if args[0] == "-f" => out(if self.update_running { 0 } else { 1 }, ""),
                "/bin/pgrep" => out(if self.alive { 0 } else { 1 }, ""),
                "/bin/ps" => out(1, ""),
                "/usr/bin/timeout" => {
                    let dir = args[args.iter().position(|a| *a == "-o").unwrap() + 1];
                    if let Some(i) = args.iter().position(|a| *a == "--enable-conf") {
                        self.seen_enable.borrow_mut().push(fs::read_to_string(args[i + 1]).unwrap());
                    }
                    match &self.rebuild {
                        Rebuild::Rules(t) => {
                            fs::write(Path::new(dir).join("suricata.rules"), t).unwrap();
                            out(0, "")
                        }
                        Rebuild::Seq(q) => {
                            let t = q.borrow_mut().remove(0);
                            fs::write(Path::new(dir).join("suricata.rules"), t).unwrap();
                            out(0, "")
                        }
                        Rebuild::Fail => out(1, "boom"),
                    }
                }
                "sc" => match args[1] {
                    "ruleset-reload-time" => {
                        let mut n = self.reloaded.get();
                        if n > 0 && self.slow_polls.get() > 0 {
                            self.slow_polls.set(self.slow_polls.get() - 1);
                            n -= 1; // still the old timestamp
                        }
                        out(
                            0,
                            &format!(
                                "{{\"message\":[{{\"id\":0,\"last_reload\":\"T{}\"}}],\"return\":\"OK\"}}",
                                if self.stuck { 0 } else { n }
                            ),
                        )
                    }
                    "ruleset-stats" => out(
                        0,
                        &format!(
                            "{{\"message\":[{{\"id\":0,\"rules_loaded\":1,\"rules_failed\":{},\"rules_skipped\":0}}],\"return\":\"OK\"}}",
                            if self.reloaded.get() > 0 { self.failed_after } else { 0 }
                        ),
                    ),
                    _ => {
                        let ok = self.reloads.borrow_mut().pop().unwrap_or(true);
                        if ok {
                            self.reloaded.set(self.reloaded.get() + 1);
                        }
                        out(if ok { 0 } else { 1 }, if ok { "{\"message\": \"done\", \"return\": \"OK\"}" } else { "{\"return\": \"NOK\"}" })
                    }
                },
                "/usr/bin/logger" => out(0, ""),
                other => panic!("unexpected program {other}"),
            }
        }
    }

    struct Tmp(PathBuf);
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn setup(tag: &str, live: &str, dc: &str) -> (Tmp, Paths) {
        let d = std::env::temp_dir().join(format!("suritui-admin-{}-{tag}", std::process::id()));
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
            sources_dir: d.join("sources"),
            require_root: false,
            reload_wait_secs: 0,
        };
        fs::write(&p.rules, live).unwrap();
        fs::write(&p.disable_conf, dc).unwrap();
        (Tmp(d), p)
    }

    fn calls(f: &Fake) -> String {
        f.calls.borrow().join("\n")
    }

    #[test]
    fn apply_installs_reloads_and_backs_up() {
        let live = rules(&[R_ON, R2]);
        let (_t, p) = setup("ok", &live, "5\n");
        let f = Fake::ok(rules(&[R_OFF, R2]));
        let rep = apply(&p, &f, Verb::Disable, 100).unwrap();
        assert!(rep.lines.iter().any(|l| l.contains("sid 100 disabled")), "{rep:?}");
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), rules(&[R_OFF, R2]));
        assert!(fs::read_to_string(&p.disable_conf).unwrap().contains("100  # suritui"));
        assert!(!p.build_dir.exists() && !p.lock.exists());
        let b: Vec<_> = fs::read_dir(&p.backup_root).unwrap().collect();
        assert_eq!(b.len(), 1);
        let bdir = b[0].as_ref().unwrap().path();
        assert_eq!(fs::read_to_string(bdir.join("suricata.rules")).unwrap(), live);
        assert_eq!(fs::read_to_string(bdir.join("disable.conf")).unwrap(), "5\n");
        let c = calls(&f);
        assert!(c.contains("--offline") && c.contains("--no-reload") && c.contains("ruleset-reload-nonblocking"), "{c}");
        assert!(fs::read_to_string(&p.log).unwrap().contains("disable sid 100"));
    }

    #[test]
    fn failed_reload_restores_both_files() {
        let live = rules(&[R_ON, R2]);
        let (_t, p) = setup("reload", &live, "5\n");
        let f = Fake::ok(rules(&[R_OFF, R2]));
        *f.reloads.borrow_mut() = vec![true, false]; // popped from the back: first call fails
        let e = apply(&p, &f, Verb::Disable, 100).unwrap_err();
        assert!(e.contains("previous rules are back and reloaded"), "{e}");
        assert!(e.contains("reload was not accepted"), "{e}");
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), live);
        assert_eq!(fs::read_to_string(&p.disable_conf).unwrap(), "5\n");
    }

    #[test]
    fn dead_suricata_after_reload_restores() {
        let live = rules(&[R_ON]);
        let (_t, p) = setup("dead", &live, "5\n");
        let mut f = Fake::ok(rules(&[R_OFF]));
        f.alive = false;
        let e = apply(&p, &f, Verb::Disable, 100).unwrap_err();
        assert!(e.contains("stopped running"), "{e}");
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), live);
        assert_eq!(fs::read_to_string(&p.disable_conf).unwrap(), "5\n");
    }

    #[test]
    fn failed_rebuild_changes_nothing() {
        let live = rules(&[R_ON]);
        let (_t, p) = setup("fail", &live, "5\n");
        let mut f = Fake::ok(String::new());
        f.rebuild = Rebuild::Fail;
        let e = apply(&p, &f, Verb::Disable, 100).unwrap_err();
        assert!(e.contains("rebuild failed"), "{e}");
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), live);
        assert_eq!(fs::read_to_string(&p.disable_conf).unwrap(), "5\n");
        assert!(!p.build_dir.exists() && !p.lock.exists());
        assert!(!calls(&f).contains("ruleset-reload"));
    }

    #[test]
    fn surprising_rebuild_is_refused_before_install() {
        let live = rules(&[R_ON, R2]);
        let (_t, p) = setup("surprise", &live, "5\n");
        let f = Fake::ok(rules(&[R_OFF])); // lost a rule
        assert!(apply(&p, &f, Verb::Disable, 100).is_err());
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), live);
        assert_eq!(fs::read_to_string(&p.disable_conf).unwrap(), "5\n");
        assert!(!calls(&f).contains("ruleset-reload"));
    }

    #[test]
    fn already_listed_is_a_no_op_without_a_rebuild() {
        let (_t, p) = setup("noop", &rules(&[R_OFF]), "100\n");
        let f = Fake::ok(String::new());
        let rep = apply(&p, &f, Verb::Disable, 100).unwrap();
        assert!(rep.lines[0].contains("nothing changed"));
        assert!(!calls(&f).contains("timeout"));
        assert!(!p.backup_root.exists());
    }

    #[test]
    fn refuses_unknown_sid_update_in_progress_and_non_root() {
        let live = rules(&[R_ON]);
        let (_t, p) = setup("refuse", &live, "5\n");
        let f = Fake::ok(String::new());
        assert!(apply(&p, &f, Verb::Disable, 999).unwrap_err().contains("not in the live rules"));
        let mut f = Fake::ok(String::new());
        f.update_running = true;
        assert!(apply(&p, &f, Verb::Disable, 100).unwrap_err().contains("update is running"));
        let mut f = Fake::ok(String::new());
        f.root = false;
        let mut p2 = p.clone();
        p2.require_root = true;
        assert!(apply(&p2, &f, Verb::Disable, 100).unwrap_err().contains("must run as root"));
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), live);
        assert!(!calls(&f).contains("timeout"));
    }

    #[test]
    fn a_stale_lock_is_replaced_and_a_live_one_blocks() {
        let live = rules(&[R_ON]);
        let (_t, p) = setup("lock", &live, "5\n");
        fs::write(&p.lock, "4242\n").unwrap();
        // fake `ps` says the pid is dead -> stale lock is taken over
        let f = Fake::ok(rules(&[R_OFF]));
        assert!(apply(&p, &f, Verb::Disable, 100).is_ok());
    }

    #[test]
    fn old_backups_are_pruned() {
        let (_t, p) = setup("prune", &rules(&[R_ON]), "5\n");
        fs::create_dir_all(&p.backup_root).unwrap();
        for i in 0..(KEEP_BACKUPS + 3) {
            fs::create_dir_all(p.backup_root.join(format!("2020-01-01-{i:03}"))).unwrap();
        }
        prune_backups(&p.backup_root);
        assert_eq!(fs::read_dir(&p.backup_root).unwrap().count(), KEEP_BACKUPS);
        assert!(!p.backup_root.join("2020-01-01-000").exists());
    }

    #[test]
    fn status_reports_counts() {
        let (_t, p) = setup("status", &rules(&[R_ON, R2_OFF]), "5\n# c\n7\n");
        let f = Fake::ok(String::new());
        let s = status(&p, &f).lines.join("\n");
        assert!(s.contains("suricata running: yes") && s.contains("2 loaded file, 1 disabled"), "{s}");
        assert!(s.contains("disable.conf: 2 sids") && s.contains("enable.conf: 0 sids"), "{s}");
    }

    #[test]
    fn symlinked_live_files_are_refused() {
        let live = rules(&[R_ON]);
        let (t, p) = setup("symlink", &live, "5\n");
        let real = t.0.join("real.rules");
        fs::rename(&p.rules, &real).unwrap();
        std::os::unix::fs::symlink(&real, &p.rules).unwrap();
        let f = Fake::ok(rules(&[R_OFF]));
        assert!(apply(&p, &f, Verb::Disable, 100).unwrap_err().contains("not a regular file"));
        assert_eq!(fs::read_to_string(&real).unwrap(), live);
    }

    #[test]
    fn a_planted_staging_symlink_is_not_written_through() {
        let live = rules(&[R_ON]);
        let (t, p) = setup("plant", &live, "5\n");
        let victim = t.0.join("victim");
        fs::write(&victim, "precious").unwrap();
        std::os::unix::fs::symlink(&victim, t.0.join("suricata.rules.suritui-new")).unwrap();
        std::os::unix::fs::symlink(&victim, t.0.join("disable.conf.suritui-new")).unwrap();
        let f = Fake::ok(rules(&[R_OFF]));
        apply(&p, &f, Verb::Disable, 100).unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "precious");
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), rules(&[R_OFF]));
    }

    #[test]
    fn installed_files_keep_mode_of_the_live_ones() {
        let (_t, p) = setup("mode", &rules(&[R_ON]), "5\n");
        fs::set_permissions(&p.rules, fs::Permissions::from_mode(0o640)).unwrap();
        let f = Fake::ok(rules(&[R_OFF]));
        apply(&p, &f, Verb::Disable, 100).unwrap();
        assert_eq!(fs::metadata(&p.rules).unwrap().mode() & 0o777, 0o640);
    }

    #[test]
    fn refused_attempts_leave_no_backup() {
        let live = rules(&[R_ON, R2]);
        let (_t, p) = setup("nobackup", &live, "5\n");
        let f = Fake::ok(rules(&[R_ON, R2])); // target never flips: refused
        assert!(apply(&p, &f, Verb::Disable, 100).is_err());
        assert!(!p.backup_root.exists(), "a refused attempt must not leave backups");
    }

    #[test]
    fn restore_failure_names_the_backup() {
        let live = rules(&[R_ON]);
        let (_t, p) = setup("dead2", &live, "5\n");
        let mut f = Fake::ok(rules(&[R_OFF]));
        f.alive = false;
        *f.reloads.borrow_mut() = vec![false, true]; // 2nd reload (popped first... ) fails after restore
        let e = apply(&p, &f, Verb::Disable, 100).unwrap_err();
        assert!(e.contains("previous rules are back"), "{e}");
    }

    // ---- read verbs ----

    fn gz(text: &str) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(text.as_bytes()).unwrap();
        e.finish().unwrap()
    }

    const EVE: &str = "{\"event_type\":\"flow\",\"x\":1}\n{\"timestamp\":\"t\",\"event_type\":\"alert\",\"a\":1}\n{\"event_type\":\"dns\"}\n{\"event_type\":\"alert\",\"b\":2}";

    #[test]
    fn alerts_live_prints_only_alert_lines() {
        let (_t, p) = setup("eve-live", "", "");
        fs::create_dir_all(&p.eve_dir).unwrap();
        fs::write(p.eve_dir.join("eve.json"), EVE).unwrap();
        let mut out = Vec::new();
        read_alerts(&p, crate::source::Range::Today, &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.lines().count(), 2, "{s}");
        assert!(s.lines().all(|l| l.contains("\"event_type\":\"alert\"")));
        assert!(s.ends_with('\n'));
    }

    #[test]
    fn alerts_day_reads_gzip_and_reports_missing_days() {
        let (_t, p) = setup("eve-day", "", "");
        fs::create_dir_all(&p.eve_dir).unwrap();
        fs::write(p.eve_dir.join("eve.json.3.gz"), gz(EVE)).unwrap();
        let mut out = Vec::new();
        read_alerts(&p, crate::source::Range::Day(3), &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap().lines().count(), 2);
        let e = read_alerts(&p, crate::source::Range::Day(4), &mut Vec::new()).unwrap_err();
        assert_eq!(e, ReadError::NoSuchDay);
        let e = read_alerts(&p, crate::source::Range::Day(14), &mut Vec::new()).unwrap_err();
        assert_eq!(e, ReadError::NoSuchDay);
    }

    #[test]
    fn read_verbs_refuse_symlinked_logs_and_print_the_rules() {
        let (t, p) = setup("eve-link", &rules(&[R_ON]), "");
        fs::create_dir_all(&p.eve_dir).unwrap();
        let secret = t.0.join("secret");
        fs::write(&secret, EVE).unwrap();
        std::os::unix::fs::symlink(&secret, p.eve_dir.join("eve.json")).unwrap();
        let e = read_alerts(&p, crate::source::Range::Today, &mut Vec::new()).unwrap_err();
        assert!(matches!(e, ReadError::Other(m) if m.contains("not a regular file")));
        let mut out = Vec::new();
        read_rules(&p, &mut out).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), rules(&[R_ON]));
    }

    // ---- enable.conf ----

    #[test]
    fn enabling_a_group_disabled_rule_creates_enable_conf() {
        let live = rules(&[R_OFF, R2]);
        let (_t, p) = setup("ec-new", &live, "group:g.rules\n");
        let f = Fake::ok(rules(&[R_ON, R2]));
        let rep = apply(&p, &f, Verb::Enable, 100).unwrap();
        assert!(rep.lines.iter().any(|l| l.contains("sid 100 enabled")), "{rep:?}");
        assert!(fs::read_to_string(&p.enable_conf).unwrap().starts_with("100  # suritui"));
        assert_eq!(fs::read_to_string(&p.disable_conf).unwrap(), "group:g.rules\n");
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), rules(&[R_ON, R2]));
        assert!(f.seen_enable.borrow()[0].contains("100  # suritui"), "the rebuild must be given the candidate");
        assert_eq!(fs::metadata(&p.enable_conf).unwrap().mode() & 0o777, fs::metadata(&p.disable_conf).unwrap().mode() & 0o777);
    }

    #[test]
    fn disabling_it_again_removes_enable_conf_and_restores_everything() {
        let live = rules(&[R_OFF, R2]);
        let (_t, p) = setup("ec-roundtrip", &live, "group:g.rules\n");
        apply(&p, &Fake::ok(rules(&[R_ON, R2])), Verb::Enable, 100).unwrap();
        assert!(p.enable_conf.exists());
        apply(&p, &Fake::ok(rules(&[R_OFF, R2])), Verb::Disable, 100).unwrap();
        assert!(!p.enable_conf.exists(), "an empty enable.conf is removed");
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), live);
        assert_eq!(fs::read_to_string(&p.disable_conf).unwrap(), "group:g.rules\n");
    }

    #[test]
    fn second_candidate_is_tried_when_a_group_also_keeps_it_off() {
        // sid 100 is listed in disable.conf AND its group is disabled
        let live = rules(&[R_OFF, R2]);
        let (_t, p) = setup("ec-two", &live, "group:g.rules\n100\n");
        let mut f = Fake::ok(String::new());
        f.rebuild = Rebuild::Seq(RefCell::new(vec![rules(&[R_OFF, R2]), rules(&[R_ON, R2])]));
        apply(&p, &f, Verb::Enable, 100).unwrap();
        assert_eq!(fs::read_to_string(&p.disable_conf).unwrap(), "group:g.rules\n");
        assert!(fs::read_to_string(&p.enable_conf).unwrap().contains("100"));
        assert_eq!(f.seen_enable.borrow().len(), 2);
    }

    #[test]
    fn failed_reload_removes_a_newly_created_enable_conf() {
        let live = rules(&[R_OFF]);
        let (_t, p) = setup("ec-fail", &live, "group:g.rules\n");
        let f = Fake::ok(rules(&[R_ON]));
        *f.reloads.borrow_mut() = vec![true, false];
        assert!(apply(&p, &f, Verb::Enable, 100).is_err());
        assert!(!p.enable_conf.exists());
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), live);
        assert_eq!(fs::read_to_string(&p.disable_conf).unwrap(), "group:g.rules\n");
    }

    #[test]
    fn enable_conf_is_backed_up_when_it_exists() {
        let (_t, p) = setup("ec-backup", &rules(&[R_ON]), "5\n");
        fs::write(&p.enable_conf, "77\n").unwrap();
        apply(&p, &Fake::ok(rules(&[R_OFF])), Verb::Disable, 100).unwrap();
        let b = fs::read_dir(&p.backup_root).unwrap().next().unwrap().unwrap().path();
        assert_eq!(fs::read_to_string(b.join("enable.conf")).unwrap(), "77\n");
        assert_eq!(fs::read_to_string(&p.enable_conf).unwrap(), "77\n");
    }

    #[test]
    fn logs_show_only_the_tail_of_three_fixed_files() {
        let (_t, p) = setup("logs", "", "");
        let mut text = String::new();
        for i in 0..1000 {
            text.push_str(&format!("line {i}\n"));
        }
        fs::write(&p.suricata_log, &text).unwrap();
        let mut out = Vec::new();
        read_log(&p, "suricata", &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.lines().count(), LOG_TAIL_LINES);
        assert!(s.ends_with("line 999\n") && s.starts_with("line 600\n"), "{}", &s[..30]);
        assert!(read_log(&p, "../etc/passwd", &mut Vec::new()).is_err());
        assert_eq!(read_log(&p, "update", &mut Vec::new()).unwrap_err(), ReadError::NoSuchDay);
    }

    #[test]
    fn a_huge_log_is_read_from_the_end_without_a_cut_first_line() {
        let (_t, p) = setup("biglog", "", "");
        let mut text = String::new();
        for i in 0..40_000 {
            text.push_str(&format!("a fairly long log line number {i}\n"));
        }
        fs::write(&p.log, &text).unwrap();
        let mut out = Vec::new();
        read_log(&p, "admin", &mut out).unwrap();
        let s = String::from_utf8(out).unwrap();
        assert!(s.lines().next().unwrap().starts_with("a fairly long log line number "), "first line must be whole");
        assert!(s.ends_with("number 39999\n"));
    }

    #[test]
    fn symlinked_logs_are_refused() {
        let (t, p) = setup("loglink", "", "");
        fs::write(t.0.join("secret"), "x\n").unwrap();
        std::os::unix::fs::symlink(t.0.join("secret"), &p.suricata_log).unwrap();
        assert!(matches!(read_log(&p, "suricata", &mut Vec::new()), Err(ReadError::Other(m)) if m.contains("not a regular file")));
    }

    // ---- the reload is waited for ----

    #[test]
    fn the_change_is_only_reported_after_the_reload_finished() {
        let live = rules(&[R_ON, R2]);
        let (_t, mut p) = setup("slowreload", &live, "5\n");
        p.reload_wait_secs = 10;
        let f = Fake::ok(rules(&[R_OFF, R2]));
        f.slow_polls.set(3); // the old timestamp is shown for three more polls
        let start = std::time::Instant::now();
        let rep = apply(&p, &f, Verb::Disable, 100).unwrap();
        assert!(rep.lines.iter().any(|l| l.contains("sid 100 disabled")), "{rep:?}");
        assert_eq!(f.slow_polls.get(), 0, "all slow polls were waited out");
        assert!(start.elapsed() >= std::time::Duration::from_millis(1000), "it really waited");
        let polls = f.calls.borrow().iter().filter(|c| c.contains("ruleset-reload-time")).count();
        assert!(polls >= 4, "{polls}");
    }

    #[test]
    fn a_reload_that_never_finishes_is_undone() {
        let live = rules(&[R_ON, R2]);
        let (_t, p) = setup("stuck", &live, "5\n"); // reload_wait_secs = 0
        let mut f = Fake::ok(rules(&[R_OFF, R2]));
        f.stuck = true;
        let e = apply(&p, &f, Verb::Disable, 100).unwrap_err();
        assert!(e.contains("did not finish"), "{e}");
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), live);
        assert_eq!(fs::read_to_string(&p.disable_conf).unwrap(), "5\n");
    }

    #[test]
    fn rules_that_fail_to_load_after_the_reload_undo_the_change() {
        let live = rules(&[R_ON, R2]);
        let (_t, p) = setup("failedrules", &live, "5\n");
        let mut f = Fake::ok(rules(&[R_OFF, R2]));
        f.failed_after = 3;
        let e = apply(&p, &f, Verb::Disable, 100).unwrap_err();
        assert!(e.contains("could not load 3 rules"), "{e}");
        assert_eq!(fs::read_to_string(&p.rules).unwrap(), live);
        assert_eq!(fs::read_to_string(&p.disable_conf).unwrap(), "5\n");
    }
}
