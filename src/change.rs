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

/// What can be started from the TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Rule(Verb, u64),
    /// Add (`add`) or remove a suppress entry for one host.
    Suppress { add: bool, sid: u64, track: Track, ip: String },
    /// Download and install the newest rules now.
    Update,
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
    /// The text of the Updates screen.
    fn info(&self) -> Result<Vec<String>, String> {
        Err("no status is available here".to_string())
    }
    /// Add or remove a suppress entry.
    fn suppress(&self, _add: bool, _sid: u64, _track: Track, _ip: &str) -> Result<Vec<String>, String> {
        Err("suppressing is not available here".to_string())
    }
    /// The entries of threshold.config.
    fn thresholds(&self) -> Vec<ThresholdEntry> {
        Vec::new()
    }
    fn run(&self, a: &Action) -> Result<Vec<String>, String> {
        match a {
            Action::Rule(v, sid) => self.change(*v, *sid),
            Action::Update => self.update(),
            Action::Suppress { add, sid, track, ip } => self.suppress(*add, *sid, *track, ip),
        }
    }
    /// Read the rules again after a change.
    fn reload(&self) -> Result<(RuleIndex, DisableConf), String>;
}

/// `sudo -n <helper> <args>`; Ok(stdout lines) or Err(one line of stderr).
fn run_helper(args: &[&str]) -> Result<Vec<String>, String> {
    let out = Command::new("sudo")
        .arg("-n")
        .arg(HELPER)
        .args(args)
        .output()
        .map_err(|e| format!("cannot run sudo: {e}"))?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.success() {
        return Ok(stdout.lines().map(str::to_string).collect());
    }
    let msg = stderr
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("the helper failed without a message");
    Err(msg.trim_start_matches("suritui-admin: ").to_string())
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

    fn suppress(&self, add: bool, sid: u64, track: Track, ip: &str) -> Result<Vec<String>, String> {
        run_helper(&[if add { "suppress" } else { "unsuppress" }, &sid.to_string(), track.word(), ip])
    }

    fn thresholds(&self) -> Vec<ThresholdEntry> {
        std::fs::read_to_string(crate::local::THRESHOLD_CONF)
            .map(|t| crate::threshold::parse_entries(&t))
            .unwrap_or_default()
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
}

pub struct Job {
    pub rx: Receiver<Outcome>,
    pub started: Instant,
    pub action: Action,
}
