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
}

#[derive(Debug, Clone, Default)]
pub struct Overrides {
    pub router: Option<String>,
    pub user: Option<String>,
    pub rules_dir: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ConfigError {
    MissingRouter,
    Parse(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingRouter => {
                write!(f, "no router address: set `router` in the config file or pass --router")
            }
            ConfigError::Parse(m) => write!(f, "cannot read config: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    router: Option<String>,
    user: Option<String>,
    rules_dir: Option<PathBuf>,
    et_version: Option<String>,
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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileConfig::default(),
            Err(e) => return Err(ConfigError::Parse(format!("{}: {e}", path.display()))),
        };
        let router = o
            .router
            .clone()
            .or(file.router)
            .filter(|r| !r.trim().is_empty())
            .ok_or(ConfigError::MissingRouter)?;
        Ok(Config {
            router,
            user: o
                .user
                .clone()
                .or(file.user)
                .unwrap_or_else(|| DEFAULT_USER.to_string()),
            labels: file.labels,
            rules_dir: o
                .rules_dir
                .clone()
                .or(file.rules_dir)
                .unwrap_or_else(|| home.join(".local/share/suritui/rules")),
            et_version: file.et_version.unwrap_or_else(|| DEFAULT_ET_VERSION.to_string()),
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
        let o = Overrides { router: Some("192.0.2.1".into()), ..Default::default() };
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
}
