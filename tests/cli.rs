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

#[test]
fn print_sudoers_prints_a_checked_file_or_refuses() {
    let home = temp_home("sudoers");
    let ok = run(&home, &["print-sudoers", "alice"]);
    assert!(ok.status.success());
    let t = String::from_utf8_lossy(&ok.stdout);
    assert!(t.contains("alice ALL=(root) NOPASSWD: SURITUI") && t.contains("suritui-admin source key *"), "{t}");
    let bad = run(&home, &["print-sudoers", "root"]);
    assert!(!bad.status.success() && bad.stdout.is_empty());
}

// ---- contrib/freebsd/uninstall.sh (run against a DESTDIR tree, never the real system) ----

fn script(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contrib/freebsd").join(name)
}

fn put(root: &std::path::Path, rel: &str, text: &str) -> PathBuf {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, text).unwrap();
    p
}

fn uninstall(dest: &std::path::Path, args: &[&str]) -> Output {
    Command::new("sh").arg(script("uninstall.sh")).args(args).env("DESTDIR", dest).output().unwrap()
}

/// A fake router tree: suritui installed, plus files that must survive.
fn fake_router(tag: &str) -> PathBuf {
    let d = temp_home(tag);
    put(&d, "usr/local/bin/suritui", "program");
    put(&d, "usr/local/sbin/suritui-admin", "helper");
    put(&d, "usr/local/etc/sudoers.d/suritui", "admin ALL=(root) NOPASSWD: /usr/local/sbin/suritui-admin info\n");
    put(&d, "usr/local/bin/suritui.prev", "old program");
    put(&d, "usr/local/sbin/suritui-admin.prev", "old helper");
    put(&d, "usr/local/etc/suricata/disable.conf", "2012345\n");
    put(&d, "usr/local/etc/suricata/threshold.config", "suppress gen_id 1, sig_id 2\n");
    put(&d, "usr/local/etc/sudoers.d/other", "someone else's entry\n");
    put(&d, "home/admin/.config/suritui/config.toml", "router = \"x\"\n");
    d
}

#[test]
fn uninstall_removes_only_the_programs_and_the_sudoers_file() {
    let d = fake_router("un-basic");
    let out = uninstall(&d, &[]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    for gone in ["usr/local/bin/suritui", "usr/local/sbin/suritui-admin", "usr/local/etc/sudoers.d/suritui"] {
        assert!(!d.join(gone).exists(), "{gone} should be gone");
    }
    for kept in [
        "usr/local/bin/suritui.prev",
        "usr/local/sbin/suritui-admin.prev",
        "usr/local/etc/suricata/disable.conf",
        "usr/local/etc/suricata/threshold.config",
        "usr/local/etc/sudoers.d/other",
        "home/admin/.config/suritui/config.toml",
    ] {
        assert!(d.join(kept).exists(), "{kept} must be left alone");
    }
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Left alone on purpose"), "{text}");
    assert!(!d.join("usr/local/etc/sudoers.d/suritui.uninstall-rollback").exists());
}

#[test]
fn and_prev_also_removes_the_older_copies() {
    let d = fake_router("un-prev");
    let out = uninstall(&d, &["--and-prev"]);
    assert!(out.status.success());
    assert!(!d.join("usr/local/bin/suritui.prev").exists());
    assert!(!d.join("usr/local/sbin/suritui-admin.prev").exists());
    assert!(d.join("usr/local/etc/suricata/disable.conf").exists());
}

#[test]
fn uninstalling_twice_or_when_nothing_is_installed_is_harmless() {
    let d = temp_home("un-twice");
    let out = uninstall(&d, &[]);
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("not installed"), "{}", String::from_utf8_lossy(&out.stdout));
    let d = fake_router("un-twice2");
    assert!(uninstall(&d, &[]).status.success());
    assert!(uninstall(&d, &[]).status.success());
}

#[test]
fn a_half_installed_tree_is_cleaned_up_too() {
    let d = temp_home("un-half");
    put(&d, "usr/local/sbin/suritui-admin", "helper only");
    let out = uninstall(&d, &[]);
    assert!(out.status.success());
    assert!(!d.join("usr/local/sbin/suritui-admin").exists());
}

#[test]
fn an_unknown_argument_is_refused_and_removes_nothing() {
    let d = fake_router("un-bad");
    let out = uninstall(&d, &["--everything"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(d.join("usr/local/bin/suritui").exists());
}

#[test]
fn the_shell_scripts_parse() {
    for name in ["install.sh", "uninstall.sh"] {
        let out = Command::new("sh").arg("-n").arg(script(name)).output().unwrap();
        assert!(out.status.success(), "{name}: {}", String::from_utf8_lossy(&out.stderr));
    }
}
