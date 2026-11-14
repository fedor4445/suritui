//! suritui-admin: the only privileged piece of suritui. Run through sudo.
//!
//!   suritui-admin status
//!   suritui-admin info
//!   suritui-admin update
//!   suritui-admin suppress|unsuppress SID by_src|by_dst IP
//!   suritui-admin rules
//!   suritui-admin log suricata | update | admin
//!   suritui-admin alerts live | day K
//!   suritui-admin sources [refresh]
//!   suritui-admin source enable|disable NAME
//!   suritui-admin source key NAME          (the key on stdin, never on the command line)
//!   suritui-admin disable SID
//!   suritui-admin enable SID
//!
//! Nothing else is accepted: no options, no paths, no free text.

use std::io::Write;
use std::process::ExitCode;
use suritui::admin::{apply, parse_sid, read_alerts, read_log, read_rules, status, Paths, ReadError, SystemRunner, Verb};
use suritui::threshold::{apply_suppress, Track};
use suritui::update::{apply_update, info};
use suritui::source::Range;

/// The reader closed the pipe (for example `| head`): not an error, stop quietly.
/// Anything else that stops stdout is a real failure.
fn print_failed(e: &std::io::Error) -> ExitCode {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        ExitCode::SUCCESS
    } else {
        eprintln!("suritui-admin: cannot write output: {e}");
        ExitCode::from(1)
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: suritui-admin status | info | log suricata|update|admin | update | suppress|unsuppress SID by_src|by_dst IP | rules | sources [refresh] | source enable|disable NAME | source key NAME | alerts live | alerts day K | disable SID | enable SID");
    ExitCode::from(2)
}

/// One line from stdin: the key. Never taken from the arguments, where `ps` shows it.
fn read_key() -> Result<String, String> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin().take(300).read_to_string(&mut buf).map_err(|e| format!("cannot read the key: {e}"))?;
    Ok(buf.trim_end_matches(['\n', '\r']).to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = Paths::production();
    let runner = SystemRunner;
    let words: Vec<&str> = args.iter().map(String::as_str).collect();
    // The read verbs stream to stdout and use their own exit codes
    // (3 = no log for that day), so they are handled before the change verbs.
    let read = match words.as_slice() {
        ["rules"] => Some(read_rules(&paths, &mut std::io::stdout().lock())),
        ["log", name] => Some(match read_log(&paths, name, &mut std::io::stdout().lock()) {
            // A log that has not been written yet is not an error for the screen.
            Err(ReadError::NoSuchDay) => {
                match writeln!(std::io::stdout(), "(this log file does not exist yet)") {
                    Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(ReadError::Other(e.to_string())),
                    _ => Ok(()),
                }
            }
            other => other,
        }),
        ["alerts", "live"] => Some(read_alerts(&paths, Range::Today, &mut std::io::stdout().lock())),
        ["alerts", "day", k] if k.len() <= 2 && k.bytes().all(|b| b.is_ascii_digit()) => {
            let k: u8 = k.parse().unwrap_or(255);
            Some(read_alerts(&paths, Range::Day(k), &mut std::io::stdout().lock()))
        }
        _ => None,
    };
    if let Some(r) = read {
        return match r {
            Ok(()) => ExitCode::SUCCESS,
            Err(ReadError::NoSuchDay) => ExitCode::from(3),
            Err(ReadError::OutputClosed) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("suritui-admin: {e}");
                ExitCode::from(1)
            }
        };
    }
    // From here on the verb changes live files. If ssh or sudo goes away halfway
    // (hangup, Ctrl-C, terminate), the change must still run to its end so the
    // reload, the health check and any restore happen; the lock goes with it.
    // SIGKILL cannot be caught, but then nothing has been left half-written:
    // every file is replaced atomically.
    for sig in [libc::SIGHUP, libc::SIGINT, libc::SIGTERM, libc::SIGQUIT] {
        // SAFETY: setting a signal to "ignore" has no handler code to run.
        unsafe {
            libc::signal(sig, libc::SIG_IGN);
        }
    }
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["status"] => Ok(status(&paths, &runner)),
        ["info"] => Ok(info(&paths, &runner)),
        ["update"] => apply_update(&paths, &runner),
        ["sources"] => suritui::sources::list(&paths, &runner, false),
        ["sources", "refresh"] => suritui::sources::list(&paths, &runner, true),
        ["source", verb @ ("enable" | "disable"), name] => {
            suritui::sources::change(&paths, &runner, *verb == "enable", name)
        }
        ["source", "key", name] => match read_key() {
            Ok(k) => suritui::sources::set_key(&paths, &runner, name, &k),
            Err(e) => Err(e),
        },
        [verb @ ("suppress" | "unsuppress"), sid, track, ip] => {
            let (Some(sid), Some(track)) = (parse_sid(sid), Track::parse(track)) else {
                eprintln!("suritui-admin: not a valid sid or track (by_src | by_dst)");
                return ExitCode::from(2);
            };
            apply_suppress(&paths, &runner, *verb == "suppress", sid, track, ip)
        }
        [verb @ ("disable" | "enable"), sid] => {
            let Some(sid) = parse_sid(sid) else {
                eprintln!("suritui-admin: not a valid sid");
                return ExitCode::from(2);
            };
            let verb = if *verb == "disable" { Verb::Disable } else { Verb::Enable };
            apply(&paths, &runner, verb, sid)
        }
        _ => return usage(),
    };
    match result {
        Ok(rep) => {
            // Printing comes after the work is done, so a reader that went away
            // (`| head`) must not turn a finished change into a panic.
            let mut out = std::io::stdout().lock();
            let text = suritui::sources::redact(&paths, &rep.lines.join("\n"));
            for l in text.lines() {
                if let Err(e) = writeln!(out, "{l}") {
                    return print_failed(&e);
                }
            }
            match out.flush() {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => print_failed(&e),
            }
        }
        Err(e) => {
            eprintln!("suritui-admin: {}", suritui::sources::redact(&paths, &e));
            ExitCode::from(1)
        }
    }
}
