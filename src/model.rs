//! Application model: state and transitions. I/O is limited to the
//! `AlertSource`, the local rule files and `suricata-update` (read-only).

use crate::alert::{category, is_informational, Alert};
use crate::browser::{self, RulesBrowser, SourcesView};
use crate::admin::Verb;
use crate::change::{Action, Admin, Job, Outcome, Pending};
use crate::threshold::{ThresholdEntry, Track};
use crate::config::Config;
use crate::local::{self, DisableConf};
use crate::rules::{rev_warning, RuleIndex};
use crate::source::{AlertSource, Loaded, Range, SourceError};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::Arc;

const MAX_DAY: u8 = 13;
const ALL: &str = "All";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    List,
    Detail,
    Rule,
    Raw,
    Help,
    /// The Rules browser (every loaded rule with its state).
    Rules,
    /// One rule from the browser.
    RuleInfo,
    /// Rule sources.
    Sources,
    /// Typing the key of a source.
    KeyEntry,
    /// Asking before a rule is disabled or enabled.
    Confirm,
    /// The helper is working.
    Working,
    /// Suricata health and rule updates.
    Updates,
    /// Suppress entries (threshold.config).
    Thresholds,
    /// Read-only summary of suricata.yaml.
    Settings,
    /// Tail of the Suricata, update and helper logs.
    Logs,
    /// The helper has finished.
    Done,
}

impl Mode {
    /// Screens that scroll (all drawn with `scroll_screen` in ui.rs).
    pub fn scrolls(self) -> bool {
        matches!(
            self,
            Mode::Detail
                | Mode::Rule
                | Mode::Raw
                | Mode::Help
                | Mode::RuleInfo
                | Mode::Confirm
                | Mode::Done
                | Mode::Updates
                | Mode::Settings
                | Mode::Logs
        )
    }
}

/// The form for the key of a source. Its values are never printed (Debug hides them).
#[derive(Clone)]
pub struct KeyEntry {
    pub name: String,
    pub summary: String,
    /// (label, value, masked)
    pub fields: Vec<(String, String, bool)>,
    pub idx: usize,
}

impl std::fmt::Debug for KeyEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeyEntry({})", self.name)
    }
}

/// What the last draw learned about the scrolling screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ViewFacts {
    mode: Mode,
    /// Wrapped content lines (title excluded).
    content: usize,
    /// Rows available for content.
    viewport: usize,
}

/// Scroll offset together with the (mode, selection) it belongs to; it only
/// counts while both still match, so any change of either reads as the top.
#[derive(Debug, Clone, Copy)]
struct Scroll {
    mode: Mode,
    selected: usize,
    top: usize,
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
    pub browser: Option<RulesBrowser>,
    pub sources: Option<SourcesView>,
    pub src_sel: usize,
    pub key_entry: Option<KeyEntry>,
    admin: Option<Arc<dyn Admin>>,
    pub pending: Option<Pending>,
    pub job: Option<Job>,
    pub outcome: Option<(bool, Vec<String>)>,
    pub updates: Option<Vec<String>>,
    pub thresholds: Vec<ThresholdEntry>,
    pub thr_sel: usize,
    pub settings: Option<Vec<String>>,
    pub logs: Vec<String>,
    pub log_idx: usize,
    after_done: Mode,
    cache: HashMap<Range, Loaded>,
    pub mode: Mode,
    pub range: Range,
    pub hide_informational: bool,
    pub status: String,
    category: String,
    selected: usize,
    scroll: Scroll,
    /// The one piece of interior mutability: `ui::draw` only gets `&App`, but
    /// the key handler needs the real content/viewport heights of the last
    /// frame to clamp scrolling.
    view: Cell<Option<ViewFacts>>,
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
            browser: None,
            sources: None,
            src_sel: 0,
            key_entry: None,
            admin: None,
            pending: None,
            job: None,
            outcome: None,
            updates: None,
            thresholds: Vec::new(),
            thr_sel: 0,
            settings: None,
            logs: Vec::new(),
            log_idx: 0,
            after_done: Mode::Rules,
            cache: HashMap::new(),
            mode: Mode::List,
            range: Range::Today,
            hide_informational: false,
            status: String::new(),
            category: ALL.to_string(),
            selected: 0,
            scroll: Scroll {
                mode: Mode::List,
                selected: 0,
                top: 0,
            },
            view: Cell::new(None),
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
            self.set_mode(Mode::List);
        }
    }

    /// Open the Rules browser, building the catalog on first use.
    pub fn open_rules(&mut self) {
        if self.browser.is_none() {
            let Some(idx) = &self.rules else {
                self.status = "no rules are loaded here".to_string();
                return;
            };
            let disable = if self.cfg.local {
                local::load_disable_conf()
            } else {
                DisableConf::default()
            };
            self.browser = Some(RulesBrowser::new(local::catalog(idx), disable));
        }
        self.status.clear();
        self.set_mode(Mode::Rules);
    }

    /// Open the Sources screen (router only: it asks the helper).
    pub fn open_sources(&mut self) {
        if self.admin.is_none() {
            self.status = "rule sources are only available on the router (use --local)".to_string();
            return;
        }
        if self.sources.is_none() {
            self.load_sources(false);
        }
        self.status.clear();
        self.set_mode(Mode::Sources);
    }

    /// `R` on the Sources screen: fetch the current source index from the internet.
    pub fn reload_sources(&mut self) {
        self.load_sources(true);
        if self.sources.as_ref().is_some_and(|v| v.error.is_none()) {
            self.status = "source list refreshed from the internet".to_string();
        }
    }

    pub fn load_sources(&mut self, refresh: bool) {
        let view = match self.admin.as_ref().map(|a| a.sources(refresh)) {
            Some(Ok(lines)) => browser::sources_from_lines(&lines),
            Some(Err(e)) => SourcesView { error: Some(e), ..Default::default() },
            None => SourcesView {
                error: Some("the helper suritui-admin is not available here".to_string()),
                ..Default::default()
            },
        };
        let n = view.enabled.len() + view.free.len();
        self.src_sel = self.src_sel.min(n.saturating_sub(1));
        self.sources = Some(view);
    }

    /// The sources that can be picked: enabled ones first, then free ones.
    pub fn source_items(&self) -> Vec<(&browser::Source, bool)> {
        match &self.sources {
            Some(v) if v.error.is_none() => v
                .enabled
                .iter()
                .map(|s| (s, true))
                .chain(v.free.iter().map(|s| (s, false)))
                .chain(v.keyed.iter().map(|s| (s, false)))
                .collect(),
            _ => Vec::new(),
        }
    }

    pub fn key_char(&mut self, c: char) {
        let Some(e) = &mut self.key_entry else { return };
        let (label, val, masked) = &mut e.fields[e.idx];
        let ok = if *masked || label.starts_with("Snapshot") { c.is_ascii_alphanumeric() || c == '-' || c == '_' } else { false };
        if ok && val.len() < 128 {
            val.push(c);
        }
    }

    pub fn key_backspace(&mut self) {
        if let Some(e) = &mut self.key_entry {
            e.fields[e.idx].1.pop();
        }
    }

    pub fn key_next(&mut self) {
        if let Some(e) = &mut self.key_entry {
            e.idx = (e.idx + 1) % e.fields.len();
        }
    }

    pub fn key_cancel(&mut self) {
        self.key_entry = None;
        self.status.clear();
        self.set_mode(Mode::Sources);
    }

    /// Enter in the key form: check what was typed and ask for the final yes.
    pub fn key_submit(&mut self) {
        let Some(e) = &self.key_entry else { return };
        if e.idx + 1 < e.fields.len() {
            return self.key_next();
        }
        let (snapshot, key) = match e.fields.as_slice() {
            [(_, snap, _), (_, key, _)] => (Some(snap.clone()), key.clone()),
            [(_, key, _)] => (None, key.clone()),
            _ => return,
        };
        if let Some(s) = &snapshot {
            if !(3..=6).contains(&s.len()) || !s.bytes().all(|b| b.is_ascii_digit()) {
                self.status = "the snapshot number is 3 to 6 digits".to_string();
                return;
            }
        }
        if !crate::sources::valid_key(&key) {
            self.status = "the code must be 8 to 128 letters, digits, - or _".to_string();
            return;
        }
        let Some(e) = self.key_entry.take() else { return };
        let snort = e.name == crate::sources::SNORT;
        let mut how = "stores the code in a file only root can read, downloads this source's rules together with the \
                       others and installs them (about 2 minutes); if the download or the check fails, everything is \
                       put back and the code is forgotten"
            .to_string();
        if snort {
            how.push_str(". Snort rules are written for Snort: Suricata skips or rejects some of them");
        }
        self.status.clear();
        self.pending = Some(Pending {
            action: Action::SourceKey { name: e.name.clone(), snapshot, key: crate::change::Secret(key) },
            msg: format!("Store the code for {} and switch it on: {}", e.name, e.summary),
            how,
            from: Mode::Sources,
        });
        self.set_mode(Mode::Confirm);
    }

    pub fn move_source(&mut self, delta: i32) {
        let n = self.source_items().len();
        self.src_sel = if n == 0 { 0 } else { (self.src_sel as i64 + delta as i64).clamp(0, n as i64 - 1) as usize };
    }

    /// `e` / `d` on the Sources screen: ask first.
    pub fn request_source_change(&mut self, enable: bool) {
        let Some(admin) = &self.admin else { return };
        if !admin.available() {
            self.status = "the helper suritui-admin is not installed here".to_string();
            return;
        }
        let items = self.source_items();
        let Some((src, on)) = items.get(self.src_sel).map(|(s, on)| ((*s).clone(), *on)) else { return };
        if enable == on {
            self.status = if on {
                "this source is already enabled (d switches it off)".to_string()
            } else {
                "this source is not enabled (e switches it on)".to_string()
            };
            return;
        }
        if enable && src.needs_key {
            let snort = src.name == crate::sources::SNORT;
            if !snort && src.params != ["secret-code"] {
                self.status = "this source needs more than a plain access code; set it up by hand".to_string();
                return;
            }
            let mut fields = Vec::new();
            if snort {
                fields.push(("Snapshot number (for example 29200; see snort.org/downloads)".to_string(), String::new(), false));
            }
            fields.push((if snort { "Oinkcode" } else { "Access code" }.to_string(), String::new(), true));
            self.status.clear();
            self.key_entry = Some(KeyEntry { name: src.name.clone(), summary: src.summary.clone(), fields, idx: 0 });
            self.set_mode(Mode::KeyEntry);
            return;
        }
        let first = enable && self.sources.as_ref().is_some_and(|v| v.enabled.is_empty()) && src.name != "et/open";
        let how = if enable {
            let mut h = "downloads the rules of this source together with the others and installs them \
                         (about 2 minutes); if anything fails the source is switched off again"
                .to_string();
            if first {
                h.push_str("; et/open is listed explicitly too, so it stays in use");
            }
            h
        } else {
            "switches the source off and installs the rule set without it (about 2 minutes); if anything fails \
             the source is switched on again"
                .to_string()
        };
        self.status.clear();
        self.pending = Some(Pending {
            action: Action::Source { enable, name: src.name.clone() },
            msg: format!("{} the source {}: {}", if enable { "Switch on" } else { "Switch off" }, src.name, src.summary),
            how,
            from: self.mode,
        });
        self.set_mode(Mode::Confirm);
    }

    /// Text of the rule picked in the browser.
    pub fn browser_rule(&self) -> Option<&crate::rules::Rule> {
        let sid = self.browser.as_ref()?.selected()?.sid;
        self.rules.as_ref()?.lookup(sid)
    }

    /// Enable rule changes (local mode only).
    pub fn set_admin(&mut self, a: Arc<dyn Admin>) {
        self.admin = Some(a);
    }

    pub fn can_change(&self) -> bool {
        self.admin.as_ref().is_some_and(|a| a.available())
    }

    /// Build the rules catalog on first use. False when no rules are loaded.
    fn ensure_browser(&mut self) -> bool {
        if self.browser.is_none() {
            let Some(idx) = &self.rules else { return false };
            let disable = if self.cfg.local { local::load_disable_conf() } else { DisableConf::default() };
            self.browser = Some(RulesBrowser::new(local::catalog(idx), disable));
        }
        true
    }

    /// `d` / `e` on the Rules list or the rule screen: the highlighted rule.
    pub fn request_change(&mut self, want: Verb) {
        let sid = self.browser.as_ref().and_then(|b| b.selected()).map(|e| e.sid);
        if let Some(sid) = sid {
            self.request_change_sid(sid, want);
        }
    }

    /// `d` on an alert screen: the rule behind the alert.
    pub fn request_change_for_alert(&mut self, want: Verb) {
        let Some(sid) = self.selected().and_then(|a| a.sid) else {
            self.status = "this alert has no rule id".to_string();
            return;
        };
        if !self.ensure_browser() {
            self.status = "no rules are loaded here".to_string();
            return;
        }
        self.request_change_sid(sid, want);
    }

    /// Ask first, change nothing yet.
    fn request_change_sid(&mut self, sid: u64, want: Verb) {
        let Some(admin) = &self.admin else {
            self.status = "changing rules works only on the router (--local)".to_string();
            return;
        };
        if !admin.available() {
            self.status = "the helper suritui-admin is not installed here".to_string();
            return;
        }
        let Some(b) = &self.browser else { return };
        let Some(e) = b.entry(sid) else {
            self.status = format!("sid {sid} is not in the loaded rules");
            return;
        };
        let verb = if e.enabled { Verb::Disable } else { Verb::Enable };
        if verb != want {
            self.status = format!("this rule is already {}d", want.word());
            return;
        }
        let (in_d, in_e) = (b.disable.sids.contains(&sid), b.disable.enabled_sids.contains(&sid));
        let how = match (verb, in_d, in_e) {
            (Verb::Disable, _, false) => "adds the sid to disable.conf".to_string(),
            (Verb::Disable, _, true) => {
                "removes the sid from enable.conf (and lists it in disable.conf if it is still on)".to_string()
            }
            (Verb::Enable, true, _) => {
                "removes the sid from disable.conf (and lists it in enable.conf if a group keeps it off)".to_string()
            }
            (Verb::Enable, false, _) => {
                "adds the sid to enable.conf, which overrides the group or source that switches it off".to_string()
            }
        };
        self.status.clear();
        self.pending = Some(Pending {
            action: Action::Rule(verb, sid),
            msg: e.msg.clone(),
            how,
            from: self.mode,
        });
        self.set_mode(Mode::Confirm);
    }

    pub fn cancel_change(&mut self) {
        let back = self.pending.take().map_or(Mode::RuleInfo, |p| p.from);
        self.set_mode(back);
    }

    /// The confirming second keystroke: start the helper in the background.
    pub fn confirm_change(&mut self) {
        let (Some(p), Some(admin)) = (self.pending.take(), self.admin.clone()) else {
            return;
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let action = p.action;
        // Back to where the change started: the alert list for an alert's rule.
        self.after_done = match (&action, p.from) {
            (Action::Update, _) => Mode::Updates,
            (Action::Source { .. } | Action::SourceKey { .. }, _) => Mode::Sources,
            (Action::Suppress { .. }, Mode::Thresholds) => Mode::Thresholds,
            (_, Mode::Detail | Mode::Rule) => Mode::List,
            _ => Mode::Rules,
        };
        let job_action = action.clone();
        std::thread::spawn(move || {
            let out = match admin.run(&action) {
                Ok(lines) => match admin.reload() {
                    Ok(fresh) => Outcome { ok: true, lines, fresh: Some(fresh) },
                    Err(e) => {
                        let mut lines = lines;
                        lines.push(format!("(could not re-read the rules: {e})"));
                        Outcome { ok: true, lines, fresh: None }
                    }
                },
                Err(e) => Outcome { ok: false, lines: vec![e], fresh: None },
            };
            let _ = tx.send(out);
        });
        self.job = Some(Job {
            rx,
            started: std::time::Instant::now(),
            action: job_action,
        });
        self.set_mode(Mode::Working);
    }

    /// Called by the main loop; picks up a finished job.
    pub fn poll_job(&mut self) {
        let Some(job) = &self.job else { return };
        let done = match job.rx.try_recv() {
            Ok(o) => Some(o),
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(Outcome {
                ok: false,
                lines: vec!["the change stopped unexpectedly; check the rules and Suricata".to_string()],
                fresh: None,
            }),
        };
        let Some(o) = done else { return };
        self.job = None;
        if let Some((idx, disable)) = o.fresh {
            let entries = local::catalog(&idx);
            self.rules = Some(idx);
            match &mut self.browser {
                Some(b) => b.replace_entries(entries, disable),
                None => self.browser = Some(RulesBrowser::new(entries, disable)),
            }
        }
        self.outcome = Some((o.ok, o.lines));
        self.set_mode(Mode::Done);
    }

    pub fn dismiss_outcome(&mut self) {
        self.outcome = None;
        if self.after_done == Mode::Updates {
            self.load_updates();
        }
        if self.after_done == Mode::Sources {
            self.load_sources(false);
        }
        if self.after_done == Mode::Thresholds {
            self.load_thresholds();
        }
        self.set_mode(self.after_done);
    }

    /// Open the Updates screen (router only: it asks the helper).
    pub fn open_updates(&mut self) {
        if self.admin.is_none() {
            self.status = "updates and status are only available on the router (use --local)".to_string();
            return;
        }
        if self.updates.is_none() {
            self.load_updates();
        }
        self.status.clear();
        self.set_mode(Mode::Updates);
    }

    pub fn load_updates(&mut self) {
        let Some(admin) = &self.admin else { return };
        self.updates = Some(admin.info().unwrap_or_else(|e| vec![format!("Could not read the status: {e}")]));
    }

    /// Open the read-only Settings screen (router only).
    pub fn open_settings(&mut self) {
        let Some(admin) = &self.admin else {
            self.status = "settings are only available on the router (use --local)".to_string();
            return;
        };
        self.settings = Some(admin.settings());
        self.status.clear();
        self.set_mode(Mode::Settings);
    }

    pub fn reload_settings(&mut self) {
        if let Some(a) = &self.admin {
            self.settings = Some(a.settings());
        }
    }

    pub const LOG_NAMES: [&'static str; 3] = ["suricata", "update", "admin"];

    pub fn log_name(&self) -> &'static str {
        Self::LOG_NAMES[self.log_idx % Self::LOG_NAMES.len()]
    }

    /// Open the log viewer, positioned at the end of the log.
    pub fn open_logs(&mut self) {
        if self.admin.is_none() {
            self.status = "logs are only available on the router (use --local)".to_string();
            return;
        }
        self.status.clear();
        self.load_logs();
        self.set_mode(Mode::Logs);
        self.scroll.top = usize::MAX; // clamped to the end when drawn
    }

    pub fn next_log(&mut self) {
        self.log_idx = (self.log_idx + 1) % Self::LOG_NAMES.len();
        self.load_logs();
        self.set_mode(Mode::Logs);
        self.scroll.top = usize::MAX;
    }

    pub fn load_logs(&mut self) {
        let name = self.log_name();
        let Some(a) = &self.admin else { return };
        self.logs = match a.log(name) {
            Ok(l) if l.is_empty() => vec![format!("The {name} log is empty.")],
            Ok(l) => l,
            Err(e) => vec![format!("Cannot read the {name} log: {e}")],
        };
    }

    /// Open the suppress list (router only).
    pub fn open_thresholds(&mut self) {
        if self.admin.is_none() {
            self.status = "suppress entries are only available on the router (use --local)".to_string();
            return;
        }
        self.load_thresholds();
        self.status.clear();
        self.set_mode(Mode::Thresholds);
    }

    pub fn load_thresholds(&mut self) {
        if let Some(a) = &self.admin {
            self.thresholds = a.thresholds();
        }
        self.thr_sel = self.thr_sel.min(self.thresholds.len().saturating_sub(1));
    }

    pub fn move_threshold(&mut self, delta: i32) {
        let n = self.thresholds.len();
        if n == 0 {
            self.thr_sel = 0;
            return;
        }
        self.thr_sel = (self.thr_sel as i64 + delta as i64).clamp(0, n as i64 - 1) as usize;
    }

    /// `s` / `S` on an alert: silence its rule for the alert's source / destination.
    pub fn request_suppress_for_alert(&mut self, track: Track) {
        let Some(a) = self.selected() else { return };
        let Some(sid) = a.sid else {
            self.status = "this alert has no rule id".to_string();
            return;
        };
        let key = if track == Track::BySrc { "src_ip" } else { "dest_ip" };
        let host = serde_json::from_str::<serde_json::Value>(&a.raw)
            .ok()
            .and_then(|v| v.get(key).and_then(|x| x.as_str().map(str::to_string)));
        let Some(host) = host.and_then(|h| crate::threshold::parse_ip_spec(&h)) else {
            self.status = "this alert has no usable address".to_string();
            return;
        };
        let msg = a.signature.clone();
        let Some(admin) = &self.admin else {
            self.status = "suppressing works only on the router (--local)".to_string();
            return;
        };
        if !admin.available() {
            self.status = "the helper suritui-admin is not installed here".to_string();
            return;
        }
        let who = if track == Track::BySrc { "source" } else { "destination" };
        self.status.clear();
        self.pending = Some(Pending {
            action: Action::Suppress { add: true, sid, track, ip: host.clone() },
            msg,
            how: format!(
                "adds a suppress entry to threshold.config: alerts of this rule are ignored when the {who} is {host}; \
                 the rule stays active for every other host"
            ),
            from: self.mode,
        });
        self.set_mode(Mode::Confirm);
    }

    /// `x` on the suppress list: remove the highlighted entry (only ours).
    pub fn request_unsuppress(&mut self) {
        let Some(e) = self.thresholds.get(self.thr_sel) else { return };
        let Some((sid, track, ip)) = e.removable.clone() else {
            self.status = "this entry was not made by suritui; edit threshold.config by hand".to_string();
            return;
        };
        self.status.clear();
        self.pending = Some(Pending {
            action: Action::Suppress { add: false, sid, track, ip: ip.clone() },
            msg: e.line.clone(),
            how: "removes the suppress entry from threshold.config, so the rule alerts for this host again"
                .to_string(),
            from: self.mode,
        });
        self.set_mode(Mode::Confirm);
    }

    /// `U` on the Updates screen: ask first.
    pub fn request_update(&mut self) {
        let Some(admin) = &self.admin else { return };
        if !admin.available() {
            self.status = "the helper suritui-admin is not installed here".to_string();
            return;
        }
        self.status.clear();
        self.pending = Some(Pending {
            action: Action::Update,
            msg: "Download the newest rules and install them now".to_string(),
            how: "downloads the newest ET Open rules (the same download as the daily update), keeps your \
                  disable.conf and enable.conf choices"
                .to_string(),
            from: self.mode,
        });
        self.set_mode(Mode::Confirm);
    }

    pub fn is_local(&self) -> bool {
        self.cfg.local
    }

    /// Change screen; the scroll position goes back to the top.
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
        self.scroll = Scroll {
            mode,
            selected: self.selected,
            top: 0,
        };
    }

    /// (content, viewport) of the last draw, if it was for the current screen.
    pub fn last_view(&self) -> Option<(usize, usize)> {
        self.view
            .get()
            .filter(|v| v.mode == self.mode)
            .map(|v| (v.content, v.viewport))
    }

    /// Called by `ui::draw` for a scrolling screen.
    pub fn record_view(&self, content: usize, viewport: usize) {
        self.view.set(Some(ViewFacts {
            mode: self.mode,
            content,
            viewport,
        }));
    }

    /// First visible content line for a screen of `content` lines in
    /// `viewport` rows, clamped so a resize never leaves it out of range.
    pub fn scroll_top(&self, content: usize, viewport: usize) -> usize {
        let max = content.saturating_sub(viewport);
        self.raw_top().min(max)
    }

    fn raw_top(&self) -> usize {
        let s = self.scroll;
        if s.mode == self.mode && s.selected == self.selected {
            s.top
        } else {
            0
        }
    }

    fn move_scroll(&mut self, f: impl FnOnce(usize, usize, usize) -> usize) {
        if !self.mode.scrolls() {
            return;
        }
        // Facts from another screen (no draw since the switch) count as none.
        let Some(v) = self.view.get().filter(|v| v.mode == self.mode) else {
            return;
        };
        let cur = self.scroll_top(v.content, v.viewport);
        let max = v.content.saturating_sub(v.viewport);
        let top = f(cur, max, v.viewport).min(max);
        self.scroll = Scroll {
            mode: self.mode,
            selected: self.selected,
            top,
        };
    }

    pub fn scroll_lines(&mut self, delta: i32) {
        self.move_scroll(|cur, _, _| (cur as i64 + delta as i64).max(0) as usize);
    }

    /// `dir` is 1 (down) or -1 (up); a page is the viewport minus one row.
    pub fn scroll_page(&mut self, dir: i32) {
        self.move_scroll(|cur, _, vh| {
            let page = vh.saturating_sub(1).max(1) as i64;
            (cur as i64 + dir as i64 * page).max(0) as usize
        });
    }

    pub fn scroll_to_top(&mut self) {
        self.move_scroll(|_, _, _| 0);
    }

    pub fn scroll_to_bottom(&mut self) {
        self.move_scroll(|_, max, _| max);
    }

    pub fn toggle_informational(&mut self) {
        self.hide_informational = !self.hide_informational;
        self.status.clear();
        // The list changed: leave any detail/rule/raw/help view (Help included,
        // so the user is never stranded in Help after a list change).
        self.set_mode(Mode::List);
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
        self.status.clear();
        self.selected = 0;
        self.set_mode(Mode::List);
        self.normalize();
    }

    pub fn next_category(&mut self) {
        self.step_category(1);
    }

    pub fn prev_category(&mut self) {
        self.step_category(-1);
    }

    pub fn move_selection(&mut self, delta: i32) {
        self.status.clear();
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
        let mut error = String::new();
        if (r == Range::Today || !self.cache.contains_key(&r)) && !self.fetch(r) {
            // A failed Today reload still lets the user return to the cached
            // Today (if any); the error stays visible. Other days stay put.
            if r == Range::Today && self.cache.contains_key(&r) {
                error = std::mem::take(&mut self.status);
            } else {
                return;
            }
        }
        self.status = error;
        self.range = r;
        self.selected = 0;
        self.set_mode(Mode::List);
        self.normalize();
    }

    pub fn refresh(&mut self) {
        let r = self.range;
        self.fetch(r);
        self.set_mode(Mode::List);
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
        if let (Mode::Rules | Mode::RuleInfo | Mode::Confirm | Mode::Working | Mode::Done, Some(b)) =
            (self.mode, &self.browser)
        {
            let mut s = format!(
                "{} rules, {} disabled",
                group(b.total()),
                group(b.disabled_total())
            );
            if !self.status.is_empty() {
                s.push_str(" | ");
                s.push_str(&self.status);
            }
            return s;
        }
        if matches!(self.mode, Mode::Sources | Mode::KeyEntry) {
            let base = if self.mode == Mode::Sources { "rule sources" } else { "source code" };
            return if self.status.is_empty() { base.to_string() } else { format!("{base} | {}", self.status) };
        }
        if matches!(self.mode, Mode::Confirm | Mode::Working | Mode::Done) {
            return self.status.clone();
        }
        if self.mode == Mode::Updates {
            return "updates and status".to_string();
        }
        if self.mode == Mode::Thresholds {
            return format!("{} entries", self.thresholds.len());
        }
        if self.mode == Mode::Settings {
            return "settings".to_string();
        }
        if self.mode == Mode::Logs {
            return format!("{} log, {} lines", self.log_name(), self.logs.len());
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
        if !self.status.is_empty() {
            s.push_str(" | ");
            s.push_str(&self.status);
        }
        s
    }
}

/// Thousands separator: 5277 -> "5,277".
pub(crate) fn group(n: usize) -> String {
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
            category: None,
            attack_target: None,
            affected_product: None,
            mitre_tactic: None,
            created_at: None,
            updated_at: None,
            app_proto: None,
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
            local: false,
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
        // failed Today reload falls back to the cached Today and shows the error
        h.data
            .borrow_mut()
            .insert(Range::Today, Err(SourceError::Ssh("down".into())));
        h.app.change_day(1);
        h.app.change_day(-1);
        assert_eq!(h.app.range, Range::Today);
        assert_eq!(h.app.visible().len(), 1);
        assert_eq!(h.app.status_line(), "1 shown | down");
    }

    #[test]
    fn failed_today_reload_without_cache_stays_put() {
        let mut h = harness(sample(), 0, None);
        h.app.change_day(1);
        h.app.cache.remove(&Range::Today);
        h.data
            .borrow_mut()
            .insert(Range::Today, Err(SourceError::Ssh("down".into())));
        h.app.change_day(-1);
        assert_eq!(h.app.range, Range::Day(0));
        assert!(h.app.status_line().ends_with("| down"));
    }

    fn failing_today(h: &mut H) {
        h.data
            .borrow_mut()
            .insert(Range::Today, Err(SourceError::Ssh("down".into())));
        h.app.refresh();
        assert!(h.app.status_line().ends_with(" | down"));
    }

    #[test]
    fn status_line_keeps_counts_with_error() {
        let mut h = harness(sample(), 3, None);
        h.app.status = "boom".into();
        assert_eq!(h.app.status_line(), "6 shown, 3 lines skipped | boom");
        h.app.toggle_informational();
        h.app.status = "boom".into();
        assert_eq!(
            h.app.status_line(),
            "4 shown, 2 hidden (informational), 3 lines skipped | boom"
        );
        let mut e = harness(vec![], 0, None);
        e.app.status = "boom".into();
        assert_eq!(e.app.status_line(), "0 alerts in this range | boom");
    }

    #[test]
    fn failed_refresh_sets_error_and_keeps_counts() {
        let mut h = harness(sample(), 0, None);
        failing_today(&mut h);
        assert_eq!(h.app.status_line(), "6 shown | down");
    }

    #[test]
    fn error_clears_on_toggle() {
        let mut h = harness(sample(), 0, None);
        failing_today(&mut h);
        h.app.toggle_informational();
        assert_eq!(h.app.status_line(), "4 shown, 2 hidden (informational)");
    }

    #[test]
    fn error_clears_on_category_change() {
        let mut h = harness(sample(), 0, None);
        failing_today(&mut h);
        h.app.next_category();
        assert!(!h.app.status_line().contains('|'));
        failing_today(&mut h);
        h.app.prev_category();
        assert!(!h.app.status_line().contains('|'));
    }

    #[test]
    fn error_clears_on_selection_move() {
        let mut h = harness(sample(), 0, None);
        failing_today(&mut h);
        h.app.move_selection(1);
        assert_eq!(h.app.status_line(), "6 shown");
    }

    #[test]
    fn error_clears_on_successful_day_change_and_refresh() {
        let mut h = harness(sample(), 0, None);
        failing_today(&mut h);
        h.app.change_day(1);
        assert_eq!(h.app.range, Range::Day(0));
        assert!(!h.app.status_line().contains('|'));
        h.data
            .borrow_mut()
            .insert(Range::Day(0), Err(SourceError::Ssh("x".into())));
        h.app.refresh();
        assert!(h.app.status_line().ends_with("| x"));
        h.data.borrow_mut().insert(Range::Day(0), Ok(vec![]));
        h.app.refresh();
        assert_eq!(h.app.status_line(), "0 alerts in this range");
    }

    #[test]
    fn move_selection_extremes_do_not_overflow() {
        let mut h = harness(sample(), 0, None);
        h.app.move_selection(i32::MAX);
        assert_eq!(h.app.selected_index(), 5);
        h.app.move_selection(i32::MIN);
        assert_eq!(h.app.selected_index(), 0);
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
        assert_eq!(h.app.status_line(), "6 shown | no log for that day");
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
        assert_eq!(h.app.status_line(), "6 shown | connection refused");
        assert_eq!(h.app.visible().len(), 6);
        h.data
            .borrow_mut()
            .insert(Range::Day(0), Err(SourceError::Ssh("timed out".into())));
        h.app.change_day(1);
        assert_eq!(h.app.range, Range::Today);
        assert_eq!(h.app.status_line(), "6 shown | timed out");
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
