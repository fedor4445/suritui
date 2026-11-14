//! Changing a rule from the TUI: the confirm step, the background job and the
//! outcome. The privileged work is done by `suritui-admin` through `sudo -n`;
//! this module only builds that one fixed command line.

use crate::admin::Verb;
use crate::threshold::{ThresholdEntry, Track};
use crate::local::{self, DisableConf};
use crate::rules::RuleIndex;
use std::process::Command;
use std::sync::mpsc::Receiver;
use std::time::Instant;

pub use crate::local::HELPER;

/// A key being passed to the helper. Never printed: Debug hides it.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(***)")
    }
}

/// What can be started from the TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Rule(Verb, u64),
    /// Add (`add`) or remove a suppress entry for one host.
    Suppress { add: bool, sid: u64, track: Track, ip: String },
    /// Download and install the newest rules now.
    Update,
    /// Switch a free rule source on or off, then install the new rule set.
    Source { enable: bool, name: String },
    /// Store a key for a source that needs one and switch it on.
    SourceKey { name: String, key: Secret },
    /// Fetch the current source index from the internet (no confirm step: it changes no rules).
    RefreshSources,
}

/// What the user is being asked to confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub action: Action,
    pub msg: String,
    /// One sentence on which file is edited.
    pub how: String,
    /// The screen to go back to on Esc.
    pub from: crate::model::Mode,
}

/// Does the privileged work. The real one runs the helper; tests use a fake.
pub trait Admin: Send + Sync {
    fn available(&self) -> bool;
    /// Run the change; Ok(lines to show) or Err(one message).
    fn change(&self, verb: Verb, sid: u64) -> Result<Vec<String>, String>;
    /// Download and install the newest rules.
    fn update(&self) -> Result<Vec<String>, String> {
        Err("updating is not available here".to_string())
    }
    /// The source lists (see `sources::list`).
    fn sources(&self, _refresh: bool) -> Result<Vec<String>, String> {
        Err("rule sources are not available here".to_string())
    }
    /// Switch a source on or off.
    fn source(&self, _enable: bool, _name: &str) -> Result<Vec<String>, String> {
        Err("changing sources is not available here".to_string())
    }
    /// Store a key and switch the source on.
    fn source_key(&self, _name: &str, _key: &str) -> Result<Vec<String>, String> {
        Err("keys are not available here".to_string())
    }
    /// The text of the Updates screen.
    fn info(&self) -> Result<Vec<String>, String> {
        Err("no status is available here".to_string())
    }
    /// Add or remove a suppress entry.
    fn suppress(&self, _add: bool, _sid: u64, _track: Track, _ip: &str) -> Result<Vec<String>, String> {
        Err("suppressing is not available here".to_string())
    }
    /// The entries of threshold.config.
    fn thresholds(&self) -> Result<Vec<ThresholdEntry>, String> {
        Ok(Vec::new())
    }
    /// Lines of the read-only Settings screen.
    fn settings(&self) -> Vec<String> {
        Vec::new()
    }
    /// The tail of one log (`suricata`, `update` or `admin`).
    fn log(&self, _name: &str) -> Result<Vec<String>, String> {
        Err("logs are not available here".to_string())
    }
    fn run(&self, a: &Action) -> Result<Vec<String>, String> {
        match a {
            Action::Rule(v, sid) => self.change(*v, *sid),
            Action::Update => self.update(),
            Action::Source { enable, name } => self.source(*enable, name),
            Action::SourceKey { name, key } => self.source_key(name, &key.0),
            Action::Suppress { add, sid, track, ip } => self.suppress(*add, *sid, *track, ip),
            Action::RefreshSources => {
                self.sources(true)?;
                Ok(vec!["The source list was refreshed from the internet.".to_string()])
            }
        }
    }
    /// Read the rules again after a change.
    fn reload(&self) -> Result<(RuleIndex, DisableConf), String>;
}

/// `sudo -n <helper> <args>`; Ok(stdout lines) or Err(one line of stderr).
fn run_helper(args: &[&str]) -> Result<Vec<String>, String> {
    run_helper_with(args, None)
}

/// Like `run_helper`; `stdin` goes to the helper's standard input (a key must
/// never be an argument: `ps` shows those).
fn run_helper_with(args: &[&str], stdin: Option<&str>) -> Result<Vec<String>, String> {
    use std::io::Write;
    use std::process::Stdio;
    let mut child = Command::new("sudo")
        .arg("-n")
        .arg(HELPER)
        .args(args)
        .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run sudo: {e}"))?;
    if let (Some(text), Some(mut pipe)) = (stdin, child.stdin.take()) {
        let _ = writeln!(pipe, "{text}");
    }
    let out = child.wait_with_output().map_err(|e| format!("cannot run sudo: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.success() {
        return Ok(stdout.lines().map(str::to_string).collect());
    }
    Err(crate::source::last_error_line(&stderr)
        .unwrap_or_else(|| "the helper failed without a message".to_string()))
}

pub struct LocalAdmin;

impl Admin for LocalAdmin {
    fn available(&self) -> bool {
        std::path::Path::new(HELPER).is_file()
    }

    fn change(&self, verb: Verb, sid: u64) -> Result<Vec<String>, String> {
        run_helper(&[verb.word(), &sid.to_string()])
    }

    fn update(&self) -> Result<Vec<String>, String> {
        run_helper(&["update"])
    }

    fn info(&self) -> Result<Vec<String>, String> {
        run_helper(&["info"])
    }

    fn sources(&self, refresh: bool) -> Result<Vec<String>, String> {
        if refresh {
            run_helper(&["sources", "refresh"])
        } else {
            run_helper(&["sources"])
        }
    }

    fn source(&self, enable: bool, name: &str) -> Result<Vec<String>, String> {
        run_helper(&["source", if enable { "enable" } else { "disable" }, name])
    }

    fn source_key(&self, name: &str, key: &str) -> Result<Vec<String>, String> {
        run_helper_with(&["source", "key", name], Some(key))
    }

    fn suppress(&self, add: bool, sid: u64, track: Track, ip: &str) -> Result<Vec<String>, String> {
        run_helper(&[if add { "suppress" } else { "unsuppress" }, &sid.to_string(), track.word(), ip])
    }

    fn settings(&self) -> Vec<String> {
        match std::fs::read_to_string(crate::local::SURICATA_YAML) {
            Ok(t) => crate::settings::summarize(crate::local::SURICATA_YAML, &t),
            Err(e) => vec![format!("Cannot read {}: {e}", crate::local::SURICATA_YAML)],
        }
    }

    fn log(&self, name: &str) -> Result<Vec<String>, String> {
        run_helper(&["log", name])
    }

    fn thresholds(&self) -> Result<Vec<ThresholdEntry>, String> {
        local::load_thresholds()
    }

    fn reload(&self) -> Result<(RuleIndex, DisableConf), String> {
        Ok((local::load_rule_index()?, local::load_disable_conf()))
    }
}

/// The result of a finished job.
pub struct Outcome {
    pub ok: bool,
    pub lines: Vec<String>,
    pub fresh: Option<(RuleIndex, DisableConf)>,
    /// The source lists, when the job was a refresh of them.
    pub sources: Option<Vec<String>>,
}

pub struct Job {
    pub rx: Receiver<Outcome>,
    pub started: Instant,
    pub action: Action,
}
