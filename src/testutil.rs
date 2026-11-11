//! Shared test helpers: a fake `AlertSource` and an `App` builder.

use crate::alert::Alert;
use crate::config::Config;
use crate::model::App;
use crate::rules::RuleIndex;
use crate::source::{AlertSource, Loaded, Range, SourceError};
use std::collections::HashMap;
use std::path::PathBuf;

pub fn alert(ts: &str, sig: &str, action: &str, et: Option<&str>) -> Alert {
    Alert {
        ts: ts.to_string(),
        iface: "if0".to_string(),
        src: "192.0.2.1:1".to_string(),
        dst: "198.51.100.2:2".to_string(),
        proto: "TCP".to_string(),
        action: action.to_string(),
        signature: sig.to_string(),
        sid: Some(2000001),
        rev: Some(2),
        severity: Some(2),
        et_severity: et.map(str::to_string),
        confidence: None,
        mitre: None,
        context: None,
        category: None,
        attack_target: None,
        affected_product: None,
        mitre_tactic: None,
        created_at: None,
        updated_at: None,
        app_proto: None,
        raw: r#"{"event_type":"alert"}"#.to_string(),
    }
}

struct Fake(HashMap<Range, Vec<Alert>>);

impl AlertSource for Fake {
    fn load(&self, r: Range) -> Result<Loaded, SourceError> {
        match self.0.get(&r) {
            Some(v) => Ok(Loaded {
                alerts: v.clone(),
                skipped: 0,
            }),
            None if r == Range::Today => Ok(Loaded::default()),
            None => Err(SourceError::NoSuchDay),
        }
    }
}

pub fn app_with(days: Vec<(Range, Vec<Alert>)>, rules: Option<RuleIndex>) -> App {
    let cfg = Config {
        router: "router.example".to_string(),
        user: "viewer".to_string(),
        labels: HashMap::from([("if0".to_string(), "wan".to_string())]),
        rules_dir: PathBuf::from("/nonexistent"),
        et_version: "7".to_string(),
    };
    App::new(cfg, Box::new(Fake(days.into_iter().collect())), rules)
}

pub fn app(today: Vec<Alert>) -> App {
    app_with(vec![(Range::Today, today)], None)
}
