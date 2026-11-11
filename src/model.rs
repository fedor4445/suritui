//! Application model: state and transitions, no I/O beyond the `AlertSource`.

use crate::alert::{category, is_informational, Alert};
use crate::config::Config;
use crate::rules::{rev_warning, RuleIndex};
use crate::source::{AlertSource, Loaded, Range, SourceError};
use std::collections::HashMap;

const MAX_DAY: u8 = 13;
const ALL: &str = "All";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    List,
    Detail,
    Rule,
    Raw,
    Help,
}

#[derive(Debug, PartialEq)]
pub enum RuleView {
    NotInstalled,
    NotFound(u64),
    Found {
        text: String,
        warning: Option<String>,
    },
    NoSid,
}

pub struct App {
    cfg: Config,
    source: Box<dyn AlertSource>,
    rules: Option<RuleIndex>,
    cache: HashMap<Range, Loaded>,
    pub mode: Mode,
    pub range: Range,
    pub hide_informational: bool,
    pub status: String,
    category: String,
    selected: usize,
}

fn newest_first(mut l: Loaded) -> Loaded {
    l.alerts.sort_by(|a, b| b.ts.cmp(&a.ts));
    l
}

fn day_index(r: Range) -> i32 {
    match r {
        Range::Today => 0,
        Range::Day(k) => k as i32 + 1,
    }
}

impl App {
    pub fn new(cfg: Config, source: Box<dyn AlertSource>, rules: Option<RuleIndex>) -> App {
        let mut app = App {
            cfg,
            source,
            rules,
            cache: HashMap::new(),
            mode: Mode::List,
            range: Range::Today,
            hide_informational: false,
            status: String::new(),
            category: ALL.to_string(),
            selected: 0,
        };
        app.fetch(Range::Today);
        app
    }

    pub fn label(&self, iface: &str) -> String {
        self.cfg.label(iface)
    }

    /// Load `r` into the cache (replacing any entry). On failure the status
    /// shows why and the cache is untouched. Returns whether it succeeded.
    fn fetch(&mut self, r: Range) -> bool {
        match self.source.load(r) {
            Ok(l) => {
                self.cache.insert(r, newest_first(l));
                self.status.clear();
                true
            }
            Err(SourceError::NoSuchDay) => {
                self.status = "no log for that day".to_string();
                false
            }
            Err(SourceError::Ssh(m)) => {
                self.status = m;
                false
            }
        }
    }

    /// Alerts of the current day that pass the informational toggle.
    fn day_alerts(&self) -> impl Iterator<Item = &Alert> {
        let hide = self.hide_informational;
        self.cache
            .get(&self.range)
            .into_iter()
            .flat_map(|l| l.alerts.iter())
            .filter(move |a| !(hide && is_informational(a)))
    }

    pub fn categories(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        let mut total = 0;
        for a in self.day_alerts() {
            total += 1;
            *counts.entry(category(&a.signature).label()).or_default() += 1;
        }
        let decoder = crate::alert::Category::Decoder.label();
        let other = crate::alert::Category::Other.label();
        let mut et: Vec<(String, usize)> = counts
            .iter()
            .filter(|(k, _)| **k != decoder && **k != other)
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        et.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let mut out = vec![(ALL.to_string(), total)];
        out.extend(et);
        for tail in [decoder, other] {
            if let Some(n) = counts.get(&tail) {
                out.push((tail, *n));
            }
        }
        out
    }

    pub fn visible(&self) -> Vec<&Alert> {
        let all = self.category == ALL;
        self.day_alerts()
            .filter(|a| all || category(&a.signature).label() == self.category)
            .collect()
    }

    /// Alerts hidden by the informational toggle, in the selected category
    /// (same scope as `visible()`).
    pub fn hidden_count(&self) -> usize {
        if !self.hide_informational {
            return 0;
        }
        let all = self.category == ALL;
        self.cache
            .get(&self.range)
            .map(|l| {
                l.alerts
                    .iter()
                    .filter(|a| is_informational(a))
                    .filter(|a| all || category(&a.signature).label() == self.category)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Keep the category by label (fall back to All) and clamp the selection.
    fn normalize(&mut self) {
        if !self.categories().iter().any(|(l, _)| *l == self.category) {
            self.category = ALL.to_string();
        }
        let len = self.visible().len();
        self.selected = if len == 0 {
            0
        } else {
            self.selected.min(len - 1)
        };
        if len == 0 && matches!(self.mode, Mode::Detail | Mode::Rule | Mode::Raw) {
            self.mode = Mode::List;
        }
    }

    pub fn toggle_informational(&mut self) {
        self.hide_informational = !self.hide_informational;
        // The list changed: leave any detail/rule/raw/help view (Help included,
        // so the user is never stranded in Help after a list change).
        self.mode = Mode::List;
        self.normalize();
    }

    fn step_category(&mut self, delta: isize) {
        let cats = self.categories();
        let pos = cats
            .iter()
            .position(|(l, _)| *l == self.category)
            .unwrap_or(0) as isize;
        let n = cats.len() as isize;
        self.category = cats[(pos + delta).rem_euclid(n) as usize].0.clone();
        self.selected = 0;
        self.mode = Mode::List;
        self.normalize();
    }

    pub fn next_category(&mut self) {
        self.step_category(1);
    }

    pub fn prev_category(&mut self) {
        self.step_category(-1);
    }

    pub fn move_selection(&mut self, delta: i32) {
        let len = self.visible().len();
        if len == 0 {
            self.selected = 0;
            return;
        }
        let s = (self.selected as i64 + delta as i64).clamp(0, len as i64 - 1);
        self.selected = s as usize;
    }

    /// Positive delta = older. Never goes below Today or above Day(13).
    pub fn change_day(&mut self, delta: i32) {
        let target = (day_index(self.range).saturating_add(delta)).clamp(0, MAX_DAY as i32 + 1);
        let r = if target == 0 {
            Range::Today
        } else {
            Range::Day((target - 1) as u8)
        };
        if r == self.range {
            return;
        }
        // Today is live and never served from the cache; only Day(k) is cached.
        if (r == Range::Today || !self.cache.contains_key(&r)) && !self.fetch(r) {
            return;
        }
        self.status.clear();
        self.range = r;
        self.selected = 0;
        self.mode = Mode::List;
        self.normalize();
    }

    pub fn refresh(&mut self) {
        let r = self.range;
        self.fetch(r);
        self.mode = Mode::List;
        self.normalize();
    }

    pub fn selected(&self) -> Option<&Alert> {
        self.visible().get(self.selected).copied()
    }

    /// Label of the selected sidebar category ("All" when none).
    pub fn category(&self) -> &str {
        &self.category
    }

    pub fn selected_index(&self) -> usize {
        self.selected
    }

    pub fn rule_view(&self) -> RuleView {
        let Some(idx) = &self.rules else {
            return RuleView::NotInstalled;
        };
        let Some(a) = self.selected() else {
            return RuleView::NoSid;
        };
        let Some(sid) = a.sid else {
            return RuleView::NoSid;
        };
        match idx.lookup(sid) {
            None => RuleView::NotFound(sid),
            Some(rule) => RuleView::Found {
                text: rule.text.clone(),
                warning: rev_warning(a.rev, rule),
            },
        }
    }

    pub fn status_line(&self) -> String {
        if !self.status.is_empty() {
            return self.status.clone();
        }
        let shown = self.visible().len();
        let hidden = self.hidden_count();
        let mut s = if shown == 0 && hidden == 0 {
            "0 alerts in this range".to_string()
        } else if hidden > 0 {
            format!(
                "{} shown, {} hidden (informational)",
                group(shown),
                group(hidden)
            )
        } else {
            format!("{} shown", group(shown))
        };
        let skipped = self.cache.get(&self.range).map_or(0, |l| l.skipped);
        if skipped > 0 {
            s.push_str(&format!(", {skipped} lines skipped"));
        }
        s
    }
}

/// Thousands separator: 5277 -> "5,277".
fn group(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleIndex;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::rc::Rc;

    fn alert(ts: &str, sig: &str, sid: Option<u64>, info: bool) -> Alert {
        Alert {
            ts: ts.to_string(),
            iface: "if0".to_string(),
            src: "192.0.2.1:1".to_string(),
            dst: "198.51.100.2:2".to_string(),
            proto: "TCP".to_string(),
            action: "allowed".to_string(),
            signature: sig.to_string(),
            sid,
            rev: Some(2),
            severity: Some(2),
            et_severity: info.then(|| "Informational".to_string()),
            confidence: None,
            mitre: None,
            context: None,
            raw: "{}".to_string(),
        }
    }

    type Canned = HashMap<Range, Result<Vec<Alert>, SourceError>>;

    struct Fake {
        data: Rc<RefCell<Canned>>,
        calls: Rc<RefCell<Vec<Range>>>,
        skipped: usize,
    }

    impl AlertSource for Fake {
        fn load(&self, r: Range) -> Result<Loaded, SourceError> {
            self.calls.borrow_mut().push(r);
            match self.data.borrow().get(&r) {
                Some(Ok(v)) => Ok(Loaded {
                    alerts: v.clone(),
                    skipped: self.skipped,
                }),
                Some(Err(e)) => Err(e.clone()),
                None => Ok(Loaded::default()),
            }
        }
    }

    fn cfg() -> Config {
        Config {
            router: "router.example".to_string(),
            user: "viewer".to_string(),
            labels: HashMap::from([("if0".to_string(), "wan".to_string())]),
            rules_dir: PathBuf::from("/nonexistent"),
            et_version: "7".to_string(),
        }
    }

    struct H {
        app: App,
        data: Rc<RefCell<Canned>>,
        calls: Rc<RefCell<Vec<Range>>>,
    }

    fn harness(today: Vec<Alert>, skipped: usize, rules: Option<RuleIndex>) -> H {
        let data: Rc<RefCell<Canned>> = Rc::default();
        data.borrow_mut().insert(Range::Today, Ok(today));
        let calls: Rc<RefCell<Vec<Range>>> = Rc::default();
        let src = Fake {
            data: data.clone(),
            calls: calls.clone(),
            skipped,
        };
        H {
            app: App::new(cfg(), Box::new(src), rules),
            data,
            calls,
        }
    }

    fn sample() -> Vec<Alert> {
        vec![
            alert("2026-01-01T00:00:01", "ET SCAN a", Some(1), false),
            alert("2026-01-01T00:00:03", "ET SCAN b", Some(2), true),
            alert("2026-01-01T00:00:02", "ET INFO c", Some(3), true),
            alert("2026-01-01T00:00:04", "SURICATA d", Some(4), false),
            alert("2026-01-01T00:00:05", "weird", Some(5), false),
            alert("2026-01-01T00:00:06", "ET DROP e", Some(6), false),
        ]
    }

    #[test]
    fn default_shows_everything() {
        let h = harness(sample(), 0, None);
        assert!(!h.app.hide_informational);
        assert_eq!(h.app.visible().len(), 6);
        assert_eq!(h.app.hidden_count(), 0);
        assert_eq!(h.app.visible()[0].ts, "2026-01-01T00:00:06");
        assert_eq!(h.app.label("if0"), "wan");
    }

    #[test]
    fn toggle_hides_informational_and_status_says_how_many() {
        let mut h = harness(sample(), 0, None);
        h.app.toggle_informational();
        assert_eq!(h.app.visible().len(), 4);
        assert_eq!(h.app.hidden_count(), 2);
        assert_eq!(h.app.status_line(), "4 shown, 2 hidden (informational)");
        h.app.toggle_informational();
        assert_eq!(h.app.visible().len(), 6);
    }

    #[test]
    fn categories_ordering_and_counts() {
        let h = harness(sample(), 0, None);
        let c = h.app.categories();
        assert_eq!(
            c,
            vec![
                ("All".to_string(), 6),
                ("SCAN".to_string(), 2),
                ("DROP".to_string(), 1),
                ("INFO".to_string(), 1),
                ("SURICATA (decoder)".to_string(), 1),
                ("Other".to_string(), 1),
            ]
        );
    }

    #[test]
    fn categories_follow_toggle() {
        let mut h = harness(sample(), 0, None);
        h.app.toggle_informational();
        let c = h.app.categories();
        assert_eq!(c[0], ("All".to_string(), 4));
        assert_eq!(c[1], ("DROP".to_string(), 1));
        assert!(!c.iter().any(|(l, _)| l == "INFO"));
    }

    #[test]
    fn empty_list_is_valid_state_and_selection_is_zero() {
        let mut h = harness(vec![], 0, None);
        assert!(h.app.selected().is_none());
        assert_eq!(h.app.selected_index(), 0);
        h.app.move_selection(5);
        h.app.next_category();
        assert_eq!(h.app.selected_index(), 0);
        assert!(h.app.selected().is_none());
        assert_eq!(h.app.status_line(), "0 alerts in this range");
    }

    #[test]
    fn selection_clamped_after_toggle() {
        let mut h = harness(sample(), 0, None);
        h.app.move_selection(100);
        assert_eq!(h.app.selected_index(), 5);
        h.app.toggle_informational();
        assert_eq!(h.app.selected_index(), 3);
        assert!(h.app.selected().is_some());
    }

    #[test]
    fn selection_clamped_after_category_change() {
        let mut h = harness(sample(), 0, None);
        h.app.move_selection(100);
        h.app.next_category(); // SCAN, 2 rows
        assert!(h.app.selected_index() < 2);
        assert!(h.app.selected().is_some());
        h.app.prev_category();
        h.app.prev_category(); // wraps to Other
        assert_eq!(h.app.visible().len(), 1);
        assert_eq!(h.app.selected_index(), 0);
    }

    #[test]
    fn category_vanishing_falls_back_to_all() {
        let mut h = harness(sample(), 0, None);
        h.app.next_category();
        h.app.next_category();
        h.app.next_category(); // INFO
        assert_eq!(h.app.visible().len(), 1);
        h.app.toggle_informational(); // INFO only has informational alerts
        assert_eq!(h.app.visible().len(), 4);
    }

    #[test]
    fn selection_clamped_after_refresh() {
        let mut h = harness(sample(), 0, None);
        h.app.move_selection(100);
        h.data
            .borrow_mut()
            .insert(Range::Today, Ok(vec![alert("t", "ET X y", None, false)]));
        h.app.refresh();
        assert_eq!(h.app.selected_index(), 0);
        h.data.borrow_mut().insert(Range::Today, Ok(vec![]));
        h.app.refresh();
        assert!(h.app.selected().is_none());
        assert_eq!(h.app.selected_index(), 0);
    }

    #[test]
    fn day_change_loads_and_caches() {
        let mut h = harness(sample(), 0, None);
        h.data
            .borrow_mut()
            .insert(Range::Day(0), Ok(vec![alert("t", "ET X y", None, false)]));
        h.app.move_selection(3);
        h.app.change_day(1);
        assert_eq!(h.app.range, Range::Day(0));
        assert_eq!(h.app.visible().len(), 1);
        assert_eq!(h.app.selected_index(), 0);
        h.app.change_day(-1);
        assert_eq!(h.app.range, Range::Today);
        h.app.change_day(1);
        let n = h
            .calls
            .borrow()
            .iter()
            .filter(|r| **r == Range::Day(0))
            .count();
        assert_eq!(n, 1);
    }

    #[test]
    fn today_is_reloaded_on_return_but_day_is_cached() {
        let mut h = harness(sample(), 0, None);
        h.app.change_day(1);
        h.app.change_day(-1);
        h.app.change_day(1);
        h.app.change_day(-1);
        let n = |h: &H, r| h.calls.borrow().iter().filter(|c| **c == r).count();
        assert_eq!(n(&h, Range::Day(0)), 1);
        assert_eq!(n(&h, Range::Today), 3); // initial + two returns
        h.data
            .borrow_mut()
            .insert(Range::Today, Ok(vec![alert("t", "ET X y", None, false)]));
        h.app.change_day(1);
        h.app.change_day(-1);
        assert_eq!(h.app.visible().len(), 1);
        // failed reload keeps old data, stays on Day(0), shows error
        h.data
            .borrow_mut()
            .insert(Range::Today, Err(SourceError::Ssh("down".into())));
        h.app.change_day(1);
        h.app.change_day(-1);
        assert_eq!(h.app.range, Range::Day(0));
        assert_eq!(h.app.status_line(), "down");
    }

    #[test]
    fn mode_returns_to_list_after_list_changing_actions() {
        for action in 0..5 {
            let mut h = harness(sample(), 0, None);
            h.data
                .borrow_mut()
                .insert(Range::Day(0), Ok(vec![alert("t", "ET X y", None, false)]));
            h.app.mode = Mode::Detail;
            match action {
                0 => h.app.toggle_informational(),
                1 => h.app.next_category(),
                2 => h.app.prev_category(),
                3 => h.app.change_day(1),
                _ => h.app.refresh(),
            }
            assert_eq!(h.app.mode, Mode::List, "action {action}");
        }
        let mut h = harness(sample(), 0, None);
        h.app.mode = Mode::Help;
        h.app.refresh();
        assert_eq!(h.app.mode, Mode::List);
    }

    #[test]
    fn mode_demoted_when_list_becomes_empty() {
        for m in [Mode::Detail, Mode::Rule, Mode::Raw] {
            let mut h = harness(sample(), 0, None);
            h.app.mode = m;
            h.data.borrow_mut().insert(Range::Today, Ok(vec![]));
            h.app.refresh();
            assert_eq!(h.app.mode, Mode::List);
        }
    }

    #[test]
    fn status_forms_when_toggle_hides_everything() {
        let mut h = harness(
            vec![
                alert("1", "ET INFO a", None, true),
                alert("2", "ET INFO b", None, true),
            ],
            0,
            None,
        );
        h.app.toggle_informational();
        assert_eq!(h.app.status_line(), "0 shown, 2 hidden (informational)");
        let mut e = harness(vec![], 0, None);
        e.app.toggle_informational();
        assert_eq!(e.app.status_line(), "0 alerts in this range");
        let mut c = harness(sample(), 0, None);
        c.app.toggle_informational();
        c.app.next_category(); // DROP first (ties alphabetical): scope check below
        c.app.next_category(); // SCAN: 1 shown, 1 hidden in this category
        assert_eq!(c.app.status_line(), "1 shown, 1 hidden (informational)");
    }

    #[test]
    fn day_never_below_today_or_above_13() {
        let mut h = harness(sample(), 0, None);
        h.app.change_day(-1);
        assert_eq!(h.app.range, Range::Today);
        h.app.change_day(100);
        assert_eq!(h.app.range, Range::Day(13));
        h.app.change_day(1);
        assert_eq!(h.app.range, Range::Day(13));
    }

    #[test]
    fn no_such_day_sets_status_and_keeps_data() {
        let mut h = harness(sample(), 0, None);
        h.data
            .borrow_mut()
            .insert(Range::Day(0), Err(SourceError::NoSuchDay));
        h.app.change_day(1);
        assert_eq!(h.app.range, Range::Today);
        assert_eq!(h.app.status_line(), "no log for that day");
        assert_eq!(h.app.visible().len(), 6);
    }

    #[test]
    fn ssh_error_sets_status_and_keeps_data() {
        let mut h = harness(sample(), 0, None);
        h.data.borrow_mut().insert(
            Range::Today,
            Err(SourceError::Ssh("connection refused".into())),
        );
        h.app.refresh();
        assert_eq!(h.app.status_line(), "connection refused");
        assert_eq!(h.app.visible().len(), 6);
        h.data
            .borrow_mut()
            .insert(Range::Day(0), Err(SourceError::Ssh("timed out".into())));
        h.app.change_day(1);
        assert_eq!(h.app.range, Range::Today);
        assert_eq!(h.app.status_line(), "timed out");
    }

    #[test]
    fn refresh_reloads_current_range() {
        let mut h = harness(sample(), 0, None);
        h.data
            .borrow_mut()
            .insert(Range::Today, Ok(vec![alert("t", "ET X y", None, false)]));
        h.app.refresh();
        assert_eq!(h.app.visible().len(), 1);
        assert_eq!(h.calls.borrow().len(), 2);
    }

    #[test]
    fn skipped_lines_show_in_status() {
        let h = harness(sample(), 3, None);
        assert_eq!(h.app.status_line(), "6 shown, 3 lines skipped");
    }

    #[test]
    fn hidden_count_is_grouped() {
        let many: Vec<Alert> = (0..5277)
            .map(|i| alert(&format!("{i:05}"), "ET INFO x", None, true))
            .chain([alert("z", "ET SCAN y", None, false)])
            .collect();
        let mut h = harness(many, 0, None);
        h.app.toggle_informational();
        assert_eq!(h.app.status_line(), "1 shown, 5,277 hidden (informational)");
    }

    #[test]
    fn rule_view_variants() {
        let idx = RuleIndex::from_text("alert tcp any any -> any any (msg:\"x\"; sid:1; rev:5;)\n");
        let mut h = harness(
            vec![
                alert("3", "ET A a", Some(1), false),
                alert("2", "ET A b", Some(99), false),
                alert("1", "ET A c", None, false),
            ],
            0,
            Some(idx),
        );
        match h.app.rule_view() {
            RuleView::Found { text, warning } => {
                assert!(text.contains("sid:1"));
                assert_eq!(
                    warning.as_deref(),
                    Some("rule text is rev 5, alert was rev 2")
                );
            }
            other => panic!("{other:?}"),
        }
        h.app.move_selection(1);
        assert_eq!(h.app.rule_view(), RuleView::NotFound(99));
        h.app.move_selection(1);
        assert_eq!(h.app.rule_view(), RuleView::NoSid);
        let h2 = harness(sample(), 0, None);
        assert_eq!(h2.app.rule_view(), RuleView::NotInstalled);
    }
}
