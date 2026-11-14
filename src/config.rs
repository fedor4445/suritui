//! Configuration: `~/.config/suritui/config.toml` plus command-line overrides.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

const DEFAULT_USER: &str = "alertview";
const DEFAULT_ET_VERSION: &str = "8.0.0";

#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    pub router: String,
    pub user: String,
    pub labels: HashMap<String, String>,
    pub rules_dir: PathBuf,
    pub et_version: String,
    /// Running on the router itself: read the logs and rules directly (via sudo).
    pub local: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub local: bool,
    pub router: Option<String>,
    pub user: Option<String>,
    pub rules_dir: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    MissingRouter,
    Parse(String),
    /// A router host or ssh user that is not safe to hand to ssh.
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingRouter => {
                write!(
                    f,
                    "no router address: set `router` in the config file or pass --router"
                )
            }
            ConfigError::Parse(m) => write!(f, "cannot read config: {m}"),
            ConfigError::Invalid(m) => write!(f, "invalid setting: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    router: Option<String>,
    user: Option<String>,
    rules_dir: Option<PathBuf>,
    et_version: Option<String>,
    #[serde(default)]
    local: bool,
    #[serde(default)]
    labels: HashMap<String, String>,
}

impl Config {
    pub fn load(o: &Overrides, home: &Path) -> Result<Config, ConfigError> {
        let path = o
            .config_path
            .clone()
            .unwrap_or_else(|| home.join(".config/suritui/config.toml"));
        let file = match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str::<FileConfig>(&text)
                .map_err(|e| ConfigError::Parse(e.to_string()))?,
            // A file named with --config must exist; only the default one is optional.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && o.config_path.is_some() => {
                return Err(ConfigError::Parse(format!(
                    "{}: no such file (named with --config)",
                    path.display()
                )))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileConfig::default(),
            Err(e) => return Err(ConfigError::Parse(format!("{}: {e}", path.display()))),
        };
        let local = o.local || file.local;
        let router = o
            .router
            .clone()
            .or(file.router)
            .filter(|r| !r.trim().is_empty());
        let router = match (router, local) {
            (Some(r), _) => r,
            (None, true) => String::new(),
            (None, false) => return Err(ConfigError::MissingRouter),
        };
        let user = o
            .user
            .clone()
            .or(file.user)
            .unwrap_or_else(|| DEFAULT_USER.to_string());
        if !local {
            check_host(&router)?;
            check_user(&user)?;
        }
        let et_version = file.et_version.unwrap_or_else(|| DEFAULT_ET_VERSION.to_string());
        check_et_version(&et_version)?;
        Ok(Config {
            local,
            router,
            user,
            labels: file.labels,
            rules_dir: expand_home(
                o.rules_dir
                    .clone()
                    .or(file.rules_dir)
                    .unwrap_or_else(|| home.join(".local/share/suritui/rules")),
                home,
            ),
            et_version,
        })
    }

    /// The mapped label for an interface, or the raw name if unmapped.
    pub fn label(&self, iface: &str) -> String {
        self.labels
            .get(iface)
            .cloned()
            .unwrap_or_else(|| iface.to_string())
    }
}

/// `~` and `~/...` at the start of a path mean the home directory.
fn expand_home(p: PathBuf, home: &Path) -> PathBuf {
    if p == Path::new("~") {
        home.to_path_buf()
    } else if let Ok(rest) = p.strip_prefix("~") {
        home.join(rest)
    } else {
        p
    }
}

/// A host name or address that is safe to pass to ssh: letters, digits and
/// `. - _ :` only, not starting with `-` (ssh would read it as an option).
fn check_host(h: &str) -> Result<(), ConfigError> {
    let ok = !h.is_empty()
        && h.len() <= 253
        && !h.starts_with('-')
        && h.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
    if ok {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!(
            "router {h:?}: use a host name or IP address (letters, digits, . - _ :)"
        )))
    }
}

/// A unix account name that is safe to pass to ssh.
/// The ET Open rules version goes into a download URL path: digits and dots
/// only, so a config value can never add path segments, a query or a fragment.
fn check_et_version(v: &str) -> Result<(), ConfigError> {
    let ok = !v.is_empty()
        && v.len() <= 16
        && v.starts_with(|c: char| c.is_ascii_digit())
        && v.chars().all(|c| c.is_ascii_digit() || c == '.');
    if ok {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!("et_version {v:?} must be digits and dots, like 8.0.0")))
    }
}

fn check_user(u: &str) -> Result<(), ConfigError> {
    let ok = !u.is_empty()
        && u.len() <= 64
        && !u.starts_with('-')
        && u.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    if ok {
        Ok(())
    } else {
        Err(ConfigError::Invalid(format!(
            "user {u:?}: use letters, digits, . - _ (not starting with -)"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempHome(PathBuf);
    impl TempHome {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("suritui-test-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            TempHome(p)
        }
        fn write_config(&self, text: &str) {
            let d = self.0.join(".config/suritui");
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join("config.toml"), text).unwrap();
        }
    }
    impl Drop for TempHome {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const SAMPLE: &str = "router = \"198.51.100.1\"\n[labels]\neth0 = \"WAN\"\n";

    #[test]
    fn loads_toml_and_defaults() {
        let h = TempHome::new("defaults");
        h.write_config(SAMPLE);
        let c = Config::load(&Overrides::default(), &h.0).unwrap();
        assert_eq!(c.router, "198.51.100.1");
        assert_eq!(c.user, "alertview");
        assert_eq!(c.et_version, "8.0.0");
        assert_eq!(c.rules_dir, h.0.join(".local/share/suritui/rules"));
        assert_eq!(c.label("eth0"), "WAN");
    }

    #[test]
    fn flag_overrides_file() {
        let h = TempHome::new("flags");
        h.write_config(SAMPLE);
        let o = Overrides {
            router: Some("203.0.113.7".into()),
            user: Some("viewer".into()),
            rules_dir: Some(PathBuf::from("/x/rules")),
            config_path: None,
            local: false,
        };
        let c = Config::load(&o, &h.0).unwrap();
        assert_eq!(c.router, "203.0.113.7");
        assert_eq!(c.user, "viewer");
        assert_eq!(c.rules_dir, PathBuf::from("/x/rules"));
    }

    #[test]
    fn missing_router_is_error() {
        let h = TempHome::new("missing");
        let r = Config::load(&Overrides::default(), &h.0);
        assert_eq!(r, Err(ConfigError::MissingRouter));
    }

    #[test]
    fn flag_router_works_without_file() {
        let h = TempHome::new("nofile");
        let o = Overrides {
            router: Some("192.0.2.1".into()),
            ..Default::default()
        };
        assert_eq!(Config::load(&o, &h.0).unwrap().router, "192.0.2.1");
    }

    #[test]
    fn label_falls_back_to_raw_name() {
        let h = TempHome::new("label");
        h.write_config(SAMPLE);
        let c = Config::load(&Overrides::default(), &h.0).unwrap();
        assert_eq!(c.label("eth9"), "eth9");
    }

    #[test]
    fn bad_toml_is_parse_error() {
        let h = TempHome::new("bad");
        h.write_config("router = = nope");
        assert!(matches!(
            Config::load(&Overrides::default(), &h.0),
            Err(ConfigError::Parse(_))
        ));
    }

    #[test]
    fn local_mode_needs_no_router() {
        let h = TempHome::new("local-flag");
        let o = Overrides {
            local: true,
            ..Default::default()
        };
        let c = Config::load(&o, &h.0).unwrap();
        assert!(c.local);
        assert_eq!(c.router, "");
    }

    #[test]
    fn local_mode_from_the_config_file() {
        let h = TempHome::new("local-file");
        h.write_config("local = true\n");
        let c = Config::load(&Overrides::default(), &h.0).unwrap();
        assert!(c.local);
    }

    #[test]
    fn remote_mode_still_needs_a_router() {
        let h = TempHome::new("remote-missing");
        let e = Config::load(&Overrides::default(), &h.0).unwrap_err();
        assert_eq!(e, ConfigError::MissingRouter);
    }

    #[test]
    fn explicit_config_must_exist_default_may_not() {
        let h = TempHome::new("explicit");
        let o = Overrides {
            router: Some("192.0.2.1".into()),
            config_path: Some(h.0.join("nope.toml")),
            ..Default::default()
        };
        let e = Config::load(&o, &h.0).unwrap_err();
        assert!(matches!(&e, ConfigError::Parse(m) if m.contains("nope.toml")));
        let o = Overrides {
            router: Some("192.0.2.1".into()),
            ..Default::default()
        };
        assert!(Config::load(&o, &h.0).is_ok());
    }

    #[test]
    fn unknown_config_key_is_an_error() {
        let h = TempHome::new("unknown");
        h.write_config("router = \"192.0.2.1\"\nrouterr = \"x\"\n");
        let e = Config::load(&Overrides::default(), &h.0).unwrap_err();
        assert!(matches!(&e, ConfigError::Parse(m) if m.contains("routerr")));
    }

    #[test]
    fn tilde_in_rules_dir_is_expanded() {
        let h = TempHome::new("tilde");
        h.write_config("router = \"192.0.2.1\"\nrules_dir = \"~/r\"\n");
        let c = Config::load(&Overrides::default(), &h.0).unwrap();
        assert_eq!(c.rules_dir, h.0.join("r"));
        assert_eq!(expand_home(PathBuf::from("~"), &h.0), h.0);
        assert_eq!(
            expand_home(PathBuf::from("~other/x"), &h.0),
            PathBuf::from("~other/x")
        );
        assert_eq!(expand_home(PathBuf::from("/a/~"), &h.0), PathBuf::from("/a/~"));
    }

    #[test]
    fn et_version_is_digits_and_dots_only() {
        for (v, ok) in [("8.0.0", true), ("5.0", true), ("8.0.0/../x", false), ("8?x=1", false), ("", false), (".8", false), ("8.0.0#f", false)] {
            let h = TempHome::new("etver");
            h.write_config(&format!("router = \"198.51.100.1\"\net_version = \"{v}\"\n"));
            assert_eq!(Config::load(&Overrides::default(), &h.0).is_ok(), ok, "{v:?}");
        }
    }

    #[test]
    fn hostile_router_or_user_is_refused() {
        let h = TempHome::new("hostile");
        for bad in ["-oProxyCommand=x", "a b", "a;b", "", "h@x", "a\nb", "-"] {
            let o = Overrides {
                router: Some(bad.into()),
                ..Default::default()
            };
            // an empty router is "missing", everything else "invalid"
            assert!(Config::load(&o, &h.0).is_err(), "router {bad:?}");
        }
        for bad in ["-oProxyCommand=x", "a b", "a@b", "", "a/b", "x\ty"] {
            let o = Overrides {
                router: Some("192.0.2.1".into()),
                user: Some(bad.into()),
                ..Default::default()
            };
            assert!(
                matches!(Config::load(&o, &h.0), Err(ConfigError::Invalid(_))),
                "user {bad:?}"
            );
        }
        for good in ["192.0.2.1", "router.example.org", "fe80::1", "my_host-2"] {
            let o = Overrides {
                router: Some(good.into()),
                ..Default::default()
            };
            assert!(Config::load(&o, &h.0).is_ok(), "router {good:?}");
        }
    }

    #[test]
    fn local_mode_skips_ssh_checks() {
        let h = TempHome::new("local-skip");
        let o = Overrides {
            local: true,
            user: Some("a b".into()),
            ..Default::default()
        };
        assert!(Config::load(&o, &h.0).is_ok());
    }
}
