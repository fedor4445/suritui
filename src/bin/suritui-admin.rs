//! suritui-admin: the only privileged piece of suritui. Run through sudo.
//!
//!   suritui-admin status
//!   suritui-admin disable SID
//!   suritui-admin enable SID
//!
//! Nothing else is accepted: no options, no paths, no free text.

use std::process::ExitCode;
use suritui::admin::{apply, parse_sid, status, Paths, SystemRunner, Verb};

fn usage() -> ExitCode {
    eprintln!("usage: suritui-admin status | disable SID | enable SID");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = Paths::production();
    let runner = SystemRunner;
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["status"] => Ok(status(&paths, &runner)),
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
            for l in rep.lines {
                println!("{l}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("suritui-admin: {e}");
            ExitCode::from(1)
        }
    }
}
