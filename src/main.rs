//! suritui: a read-only Suricata alert viewer.

use clap::{Args, Parser, Subcommand};
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use ratatui::crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use suritui::config::{Config, ConfigError, Overrides};
use suritui::model::App;
use suritui::rules::{self, RuleIndex, RulesError};
use suritui::local::{self, LocalSource};
use suritui::source::{AlertSource, SshSource};
use suritui::{input, ui};

#[derive(Parser, Debug)]
#[command(
    name = "suritui",
    version,
    about = "Read-only Suricata alert viewer (alerts are read over ssh)"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    #[command(flatten)]
    common: Common,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Download the ET Open rules into the rules directory (the only network use besides ssh)
    UpdateRules {
        #[command(flatten)]
        common: Common,
        /// Test hook: download from this URL instead of the default.
        #[arg(long, hide = true)]
        rules_url: Option<String>,
    },
}

#[derive(Args, Debug, Clone, Default)]
struct Common {
    /// Config file (default: ~/.config/suritui/config.toml)
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,
    /// Router host to read alerts from
    #[arg(long, global = true, value_name = "HOST")]
    router: Option<String>,
    /// ssh user on the router
    #[arg(long, global = true, value_name = "NAME")]
    user: Option<String>,
    /// Run on the router itself: read logs and rules directly (uses sudo)
    #[arg(long, global = true)]
    local: bool,
    /// Directory holding the local copy of the rules
    #[arg(long, global = true, value_name = "DIR")]
    rules_dir: Option<PathBuf>,
}

fn overrides(c: &Common) -> Overrides {
    Overrides {
        router: c.router.clone(),
        user: c.user.clone(),
        rules_dir: c.rules_dir.clone(),
        config_path: c.config.clone(),
        local: c.local,
    }
}

/// The config file path in effect, for error messages.
fn config_path(c: &Common, home: &Path) -> PathBuf {
    c.config
        .clone()
        .unwrap_or_else(|| home.join(".config/suritui/config.toml"))
}

fn config_error_message(e: &ConfigError, path: &Path) -> String {
    match e {
        ConfigError::MissingRouter => format!(
            "suritui: no router address. Set `router = \"HOST\"` in {} or pass --router HOST.",
            path.display()
        ),
        other => format!("suritui: {other}"),
    }
}

fn exit_code(ok: bool) -> ExitCode {
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

/// `update-rules` needs no router: fall back to a placeholder when none is set.
fn load_config(c: &Common, home: &Path, need_router: bool) -> Result<Config, String> {
    let mut o = overrides(c);
    if !need_router && o.router.is_none() {
        // Only the rules directory and ET version matter here; try the real
        // config first, and use a placeholder router if it has none.
        match Config::load(&o, home) {
            Ok(cfg) => return Ok(cfg),
            Err(ConfigError::MissingRouter) => o.router = Some("unused".to_string()),
            Err(e) => return Err(config_error_message(&e, &config_path(c, home))),
        }
    }
    Config::load(&o, home).map_err(|e| config_error_message(&e, &config_path(c, home)))
}

fn restore_terminal() {
    let _ = disable_raw_mode();
    let _ = execute!(std::io::stdout(), LeaveAlternateScreen);
    let _ = execute!(std::io::stdout(), ratatui::crossterm::cursor::Show);
}

fn run_tui(cfg: Config) -> std::io::Result<()> {
    let (rules, source): (Option<RuleIndex>, Box<dyn AlertSource>) = if cfg.local {
        // The rules Suricata really loads, from every enabled source.
        let rules = match local::load_rule_index() {
            Ok(i) => Some(i),
            Err(e) => {
                eprintln!("suritui: warning: cannot read the loaded rules: {e}");
                None
            }
        };
        (rules, Box::new(LocalSource))
    } else {
        let rules = match RuleIndex::from_dir(&cfg.rules_dir) {
            Ok(i) => Some(i),
            Err(RulesError::NotInstalled) => None,
            Err(e) => {
                eprintln!("suritui: warning: {e}");
                None
            }
        };
        (rules, Box::new(SshSource::new(&cfg)))
    };
    let local = cfg.local;
    let mut app = App::new(cfg, source, rules);
    if local {
        app.set_admin(std::sync::Arc::new(suritui::change::LocalAdmin));
    }

    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore_terminal();
        prev(info);
    }));

    enable_raw_mode()?;
    let result = (|| {
        execute!(std::io::stdout(), EnterAlternateScreen)?;
        let mut term = Terminal::new(CrosstermBackend::new(std::io::stdout()))?;
        loop {
            term.draw(|f| ui::draw(f, &app))?;
            if app.job.is_some() {
                // A change is running: wake up often to show progress and
                // pick up the result.
                app.poll_job();
                if !event::poll(std::time::Duration::from_millis(250))? {
                    continue;
                }
            }
            match event::read()? {
                // Only presses: holding a key must not repeat actions such as refresh.
                Event::Key(k)
                    if k.kind == KeyEventKind::Press && input::handle_key(&mut app, k) =>
                {
                    return Ok(());
                }
                _ => {} // resize and everything else: loop redraws
            }
        }
    })();
    restore_terminal();
    result
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        eprintln!("suritui: the HOME environment variable is not set");
        return ExitCode::from(1);
    };
    match cli.command {
        Some(Command::UpdateRules { common, rules_url }) => {
            let cfg = match load_config(&common, &home, false) {
                Ok(c) => c,
                Err(m) => {
                    eprintln!("{m}");
                    return ExitCode::from(1);
                }
            };
            match rules::update_rules(&cfg, rules_url.as_deref()) {
                Ok(n) => {
                    println!("installed {n} rule files into {}", cfg.rules_dir.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("suritui: {e}");
                    ExitCode::from(1)
                }
            }
        }
        None => {
            let cfg = match load_config(&cli.common, &home, true) {
                Ok(c) => c,
                Err(m) => {
                    eprintln!("{m}");
                    return ExitCode::from(1);
                }
            };
            let r = run_tui(cfg);
            if let Err(e) = &r {
                eprintln!("suritui: terminal error: {e}");
            }
            exit_code(r.is_ok())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overrides_map_all_flags() {
        let cli = Cli::try_parse_from([
            "suritui",
            "--config",
            "/c.toml",
            "--router",
            "r",
            "--user",
            "u",
            "--rules-dir",
            "/d",
            "--local",
        ])
        .unwrap();
        let o = overrides(&cli.common);
        assert!(o.local);
        assert_eq!(o.router.as_deref(), Some("r"));
        assert_eq!(o.user.as_deref(), Some("u"));
        assert_eq!(o.rules_dir, Some(PathBuf::from("/d")));
        assert_eq!(o.config_path, Some(PathBuf::from("/c.toml")));
    }

    #[test]
    fn update_rules_accepts_flags_after_subcommand() {
        let cli = Cli::try_parse_from(["suritui", "update-rules", "--rules-dir", "/d"]).unwrap();
        match cli.command {
            Some(Command::UpdateRules { common, rules_url }) => {
                assert_eq!(common.rules_dir, Some(PathBuf::from("/d")));
                assert!(rules_url.is_none());
            }
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn missing_router_message_names_path_and_flag() {
        let m = config_error_message(&ConfigError::MissingRouter, Path::new("/h/c.toml"));
        assert!(m.contains("/h/c.toml") && m.contains("--router"));
    }

    #[test]
    fn exit_codes() {
        assert_eq!(exit_code(true), ExitCode::SUCCESS);
        assert_eq!(exit_code(false), ExitCode::from(1));
    }
}
