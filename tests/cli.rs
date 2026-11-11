use std::path::PathBuf;
use std::process::{Command, Output};

fn temp_home(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("suritui-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(home: &PathBuf, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_suritui"))
        .args(args)
        .env("HOME", home)
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_DATA_HOME")
        .output()
        .unwrap()
}

#[test]
fn help_mentions_update_rules() {
    let home = temp_home("help");
    let out = run(&home, &["--help"]);
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("update-rules"), "{text}");
    assert!(!text.contains("rules-url"), "hidden flag leaked: {text}");
}

#[test]
fn missing_router_prints_clear_error_and_exits_nonzero() {
    let home = temp_home("norouter");
    let out = run(&home, &[]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--router"), "{err}");
    assert!(err.contains("config.toml"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    assert!(out.stdout.is_empty());
}

#[test]
fn update_rules_without_router_not_required() {
    let home = temp_home("update");
    let rules = home.join("rules");
    let out = run(
        &home,
        &[
            "update-rules",
            "--rules-dir",
            rules.to_str().unwrap(),
            "--rules-url",
            "http://127.0.0.1:1/",
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("--router"), "{err}");
    assert!(!err.contains("panicked"), "{err}");
    assert!(err.contains("download"), "{err}");
}
