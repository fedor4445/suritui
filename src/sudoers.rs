//! The sudoers drop-in for local mode, printed by `suritui print-sudoers USER`.
//! It lists exactly the helper commands the TUI runs, nothing else.

use crate::local::HELPER;

/// Every helper command the TUI may run through `sudo -n`. `*` and `[0-9]`
/// are sudoers patterns; the helper validates its own arguments again.
const COMMANDS: &[&str] = &[
    "info",
    "update",
    "rules",
    "sources",
    "sources refresh",
    "source enable *",
    "source disable *",
    "source key *",
    "log suricata",
    "log update",
    "log admin",
    "alerts live",
    "alerts day [0-9]",
    "alerts day 1[0-3]",
    "disable [0-9]*",
    "enable [0-9]*",
    "suppress [0-9]* by_src *",
    "suppress [0-9]* by_dst *",
    "unsuppress [0-9]* by_src *",
    "unsuppress [0-9]* by_dst *",
];

/// A unix account name: letters, digits, `_`, `-`, `.`; starts with a letter or `_`.
pub fn valid_user(u: &str) -> bool {
    let b = u.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && (b[0].is_ascii_alphabetic() || b[0] == b'_')
        && b.iter().all(|c| c.is_ascii_alphanumeric() || b"_-.".contains(c))
        && u != "root"
        // sudoers reads `ALL` and any all-capitals word as a keyword or a
        // User_Alias, so such a name could grant the helper to more than one account.
        && !(b[0].is_ascii_uppercase() && b.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_'))
}

/// The whole file for `user`.
pub fn render(user: &str) -> Result<String, String> {
    if !valid_user(user) {
        return Err("not a usable account name (letters, digits, _ - .; not root)".to_string());
    }
    let mut s = String::from(
        "# suritui: the only privileges the TUI user has. Everything goes through the\n\
         # root-owned helper, which validates its own arguments.\n\
         Cmnd_Alias SURITUI = ",
    );
    for (i, c) in COMMANDS.iter().enumerate() {
        if i > 0 {
            s.push_str(", \\\n                     ");
        }
        s.push_str(&format!("{HELPER} {c}"));
    }
    s.push_str(&format!("\n{user} ALL=(root) NOPASSWD: SURITUI\n"));
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_file_names_only_the_helper_and_one_user() {
        let t = render("alice").unwrap();
        assert!(t.ends_with("alice ALL=(root) NOPASSWD: SURITUI\n"));
        for l in t.lines().filter(|l| l.contains("suritui-admin")) {
            let l = l.trim_start_matches("Cmnd_Alias SURITUI = ").trim_start();
            assert!(l.starts_with("/usr/local/sbin/suritui-admin "), "{l}");
        }
        assert_eq!(t.matches("suritui-admin").count(), COMMANDS.len());
        assert!(!t.contains("ALL=(ALL)"));
    }

    #[test]
    fn odd_account_names_are_refused() {
        for bad in ["", "root", "a b", "a;b", "-x", "a\nb", "a:b", &"a".repeat(33), "x,y", "ALL", "ADMINS", "A_1"] {
            assert!(render(bad).is_err(), "{bad:?}");
        }
        assert!(render("_svc-1.x").is_ok());
    }

    #[test]
    fn only_commands_the_tui_runs_are_granted() {
        // `status` is a helper verb, but no TUI screen calls it.
        assert!(!COMMANDS.iter().any(|c| c.starts_with("status")));
    }

    #[test]
    fn every_command_is_one_the_helper_knows() {
        // The helper's verbs, by first word: a command here that the helper does
        // not accept would be a dead sudo rule.
        let known = ["status", "info", "update", "rules", "sources", "source", "log", "alerts", "disable", "enable", "suppress", "unsuppress"];
        for c in COMMANDS {
            assert!(known.contains(&c.split(' ').next().unwrap()), "{c}");
        }
    }
}
