//! Changing a rule from the TUI: the confirm step, the background job and the
//! outcome. The privileged work is done by `suritui-admin` through `sudo -n`;
//! this module only builds that one fixed command line.

use crate::admin::Verb;
use crate::local::{self, DisableConf};
use crate::rules::RuleIndex;
use std::process::Command;
use std::sync::mpsc::Receiver;
use std::time::Instant;

pub use crate::local::HELPER;

/// What the user is being asked to confirm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub verb: Verb,
    pub sid: u64,
    pub msg: String,
}

/// Does the privileged work. The real one runs the helper; tests use a fake.
pub trait Admin: Send + Sync {
    fn available(&self) -> bool;
    /// Run the change; Ok(lines to show) or Err(one message).
    fn change(&self, verb: Verb, sid: u64) -> Result<Vec<String>, String>;
    /// Read the rules again after a change.
    fn reload(&self) -> Result<(RuleIndex, DisableConf), String>;
}

pub struct LocalAdmin;

impl Admin for LocalAdmin {
    fn available(&self) -> bool {
        std::path::Path::new(HELPER).is_file()
    }

    fn change(&self, verb: Verb, sid: u64) -> Result<Vec<String>, String> {
        let out = Command::new("sudo")
            .args(["-n", HELPER, verb.word(), &sid.to_string()])
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
    pub verb: Verb,
    pub sid: u64,
}
