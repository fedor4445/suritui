//! Alert source: reads the router's alert log over ssh (read-only).

use crate::alert::{parse_line, Alert};
use crate::config::Config;
use std::process::Command;

const MAX_DAY: u8 = 13;

/// Which day of alerts to load. Day(k) is k days back, 0..=13 (see `Range::day`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Range {
    Today,
    Day(u8),
}

impl Range {
    /// `Day(k)` for k in 0..=13 (k = 0 is `day 0`); None above 13.
    pub fn day(k: u8) -> Option<Range> {
        if k <= MAX_DAY {
            Some(Range::Day(k))
        } else {
            None
        }
    }

    pub fn remote_args(&self) -> Vec<String> {
        match self {
            Range::Today => vec!["live".to_string()],
            // Never emit a day above MAX_DAY, even if the pub variant was built directly.
            Range::Day(k) => vec!["day".to_string(), (*k).min(MAX_DAY).to_string()],
        }
    }
}

#[derive(Debug, Default)]
pub struct Loaded {
    pub alerts: Vec<Alert>,
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SourceError {
    NoSuchDay,
    Ssh(String),
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::NoSuchDay => write!(f, "no alert log for that day"),
            SourceError::Ssh(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for SourceError {}

pub trait AlertSource {
    fn load(&self, r: Range) -> Result<Loaded, SourceError>;
}

/// Parse remote output; non-empty lines that are not alerts are counted as skipped.
pub fn parse_output(out: &str) -> Loaded {
    let mut loaded = Loaded::default();
    for line in out.lines() {
        if line.trim().is_empty() {
            continue;
        }
        match parse_line(line) {
            Some(a) => loaded.alerts.push(a),
            None => loaded.skipped += 1,
        }
    }
    loaded
}

/// Map a finished ssh run to a result. Output is decoded lossily (never panics).
pub fn map_output(
    status_code: Option<i32>,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Loaded, SourceError> {
    match status_code {
        Some(0) => Ok(parse_output(&String::from_utf8_lossy(stdout))),
        Some(3) => Err(SourceError::NoSuchDay),
        code => Err(SourceError::Ssh(ssh_failure_text(code, stderr))),
    }
}

/// One line of error text for a failed ssh run.
fn ssh_failure_text(code: Option<i32>, stderr: &[u8]) -> String {
    let err = String::from_utf8_lossy(stderr);
    if err.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
        return "router host key CHANGED, ssh refused; check known_hosts".to_string();
    }
    match err.lines().rev().map(str::trim).find(|l| !l.is_empty()) {
        Some(line) => line.to_string(),
        None => match code {
            Some(c) => format!("ssh failed (exit {c})"),
            None => "ssh failed (killed by signal)".to_string(),
        },
    }
}

/// Reject out-of-range days before any ssh process is started.
pub fn validate(r: Range) -> Result<Range, SourceError> {
    match r {
        Range::Day(k) if k > MAX_DAY => Err(SourceError::NoSuchDay),
        ok => Ok(ok),
    }
}

pub struct SshSource {
    target: String,
}

impl SshSource {
    pub fn new(cfg: &Config) -> SshSource {
        SshSource {
            target: format!("{}@{}", cfg.user, cfg.router),
        }
    }

    pub fn ssh_args(&self, r: Range) -> Vec<String> {
        let mut args: Vec<String> = [
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=3",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        args.push(self.target.clone());
        args.extend(r.remote_args());
        args
    }
}

impl AlertSource for SshSource {
    fn load(&self, r: Range) -> Result<Loaded, SourceError> {
        let r = validate(r)?;
        let out = Command::new("ssh")
            .args(self.ssh_args(r))
            .output()
            .map_err(|e| SourceError::Ssh(format!("cannot run ssh: {e}")))?;
        map_output(out.status.code(), &out.stdout, &out.stderr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn cfg() -> Config {
        Config {
            router: "198.51.100.1".into(),
            user: "alertview".into(),
            labels: HashMap::new(),
            rules_dir: PathBuf::new(),
            et_version: "8.0.0".into(),
            local: false,
        }
    }

    const ALERT: &str = r#"{"timestamp":"2026-01-01T00:00:00.000000+0000","event_type":"alert","src_ip":"192.0.2.1","dest_ip":"198.51.100.2","proto":"TCP","alert":{"signature_id":2000001,"signature":"ET TEST x","category":"Misc","severity":3,"action":"allowed"}}"#;

    #[test]
    fn remote_args_today_and_day() {
        assert_eq!(Range::Today.remote_args(), vec!["live"]);
        assert_eq!(Range::day(5).unwrap().remote_args(), vec!["day", "5"]);
        assert_eq!(Range::day(13).unwrap().remote_args(), vec!["day", "13"]);
    }

    #[test]
    fn day_above_13_rejected() {
        assert_eq!(Range::day(14), None);
        assert_eq!(Range::day(255), None);
    }

    #[test]
    fn validate_rejects_day_above_13_before_ssh() {
        assert_eq!(validate(Range::Day(14)), Err(SourceError::NoSuchDay));
        assert_eq!(validate(Range::Day(200)), Err(SourceError::NoSuchDay));
        assert_eq!(validate(Range::Day(13)), Ok(Range::Day(13)));
        assert_eq!(validate(Range::Day(0)), Ok(Range::Day(0)));
        assert_eq!(validate(Range::Today), Ok(Range::Today));
        // load() calls validate first, so this returns without spawning ssh.
        let s = SshSource::new(&cfg());
        assert_eq!(s.load(Range::Day(200)).unwrap_err(), SourceError::NoSuchDay);
    }

    #[test]
    fn remote_args_never_above_13() {
        for k in 0..=255u8 {
            let a = Range::Day(k).remote_args();
            assert!(a[1].parse::<u8>().unwrap() <= 13);
            assert!(
                SshSource::new(&cfg())
                    .ssh_args(Range::Day(k))
                    .last()
                    .unwrap()
                    .parse::<u8>()
                    .unwrap()
                    <= 13
            );
        }
    }

    #[test]
    fn ssh_args_exact() {
        let s = SshSource::new(&cfg());
        assert_eq!(
            s.ssh_args(Range::Today),
            vec![
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=10",
                "-o",
                "ServerAliveCountMax=3",
                "alertview@198.51.100.1",
                "live"
            ]
        );
        assert_eq!(
            s.ssh_args(Range::Day(2))[10..],
            ["alertview@198.51.100.1", "day", "2"]
        );
    }

    #[test]
    fn parse_output_counts_skipped() {
        let out = format!("{ALERT}\nnot json\n{{\"event_type\":\"dns\"}}\n{ALERT}\n");
        let l = parse_output(&out);
        assert_eq!(l.alerts.len(), 2);
        assert_eq!(l.skipped, 2);
    }

    #[test]
    fn parse_output_ignores_blank_lines() {
        let l = parse_output(&format!("\n  \n{ALERT}\n\n"));
        assert_eq!(l.alerts.len(), 1);
        assert_eq!(l.skipped, 0);
    }

    #[test]
    fn exit_code_3_maps_to_no_such_day() {
        assert_eq!(
            map_output(Some(3), b"", b"").unwrap_err(),
            SourceError::NoSuchDay
        );
    }

    #[test]
    fn other_nonzero_maps_to_ssh_error_with_stderr() {
        let e = map_output(Some(255), b"", b"Host key verification failed.\n").unwrap_err();
        assert_eq!(e, SourceError::Ssh("Host key verification failed.".into()));
        assert_eq!(e.to_string(), "Host key verification failed.");
        assert!(matches!(
            map_output(None, b"", b"killed"),
            Err(SourceError::Ssh(_))
        ));
    }

    #[test]
    fn blank_stderr_failure_names_the_exit_code() {
        let e = map_output(Some(255), b"", b"").unwrap_err();
        assert_eq!(e, SourceError::Ssh("ssh failed (exit 255)".into()));
        let e = map_output(Some(1), b"", b" \n\n").unwrap_err();
        assert_eq!(e, SourceError::Ssh("ssh failed (exit 1)".into()));
        let e = map_output(None, b"", b"").unwrap_err();
        assert_eq!(e, SourceError::Ssh("ssh failed (killed by signal)".into()));
    }

    #[test]
    fn host_key_change_is_reported_as_such() {
        let stderr = b"@@@@@@@@\n@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\n@@@@@@@@\nHost key verification failed.\n";
        let e = map_output(Some(255), b"", stderr).unwrap_err();
        assert_eq!(
            e,
            SourceError::Ssh("router host key CHANGED, ssh refused; check known_hosts".into())
        );
    }

    #[test]
    fn multi_line_stderr_uses_last_non_empty_line() {
        let e = map_output(
            Some(255),
            b"",
            b"Warning: something\nPermission denied (publickey).\n\n",
        )
        .unwrap_err();
        assert_eq!(e, SourceError::Ssh("Permission denied (publickey).".into()));
    }

    #[test]
    fn non_utf8_output_does_not_panic() {
        let mut bytes = ALERT.as_bytes().to_vec();
        bytes.extend_from_slice(b"\n\xff\xfe\n");
        let l = map_output(Some(0), &bytes, b"").unwrap();
        assert_eq!(l.alerts.len(), 1);
        assert_eq!(l.skipped, 1);
    }
}
