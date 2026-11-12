//! State of the Rules browser and the Sources screen (pure logic, no drawing).

use crate::local::{CatalogEntry, DisableConf};
use std::collections::HashMap;
use std::process::Command;

pub const ALL: &str = "All";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFilter {
    All,
    Disabled,
    Enabled,
}

impl StateFilter {
    pub fn next(self) -> StateFilter {
        match self {
            StateFilter::All => StateFilter::Disabled,
            StateFilter::Disabled => StateFilter::Enabled,
            StateFilter::Enabled => StateFilter::All,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            StateFilter::All => "all rules",
            StateFilter::Disabled => "disabled only",
            StateFilter::Enabled => "enabled only",
        }
    }

    fn matches(self, enabled: bool) -> bool {
        match self {
            StateFilter::All => true,
            StateFilter::Disabled => !enabled,
            StateFilter::Enabled => enabled,
        }
    }
}

pub struct RulesBrowser {
    entries: Vec<CatalogEntry>,
    pub disable: DisableConf,
    category: String,
    pub filter: StateFilter,
    query: String,
    /// True while the user is typing a search.
    pub editing: bool,
    selected: usize,
}

impl RulesBrowser {
    pub fn new(entries: Vec<CatalogEntry>, disable: DisableConf) -> RulesBrowser {
        RulesBrowser {
            entries,
            disable,
            category: ALL.to_string(),
            filter: StateFilter::All,
            query: String::new(),
            editing: false,
            selected: 0,
        }
    }

    /// Swap in freshly read rules but keep the user's category, filter and search.
    pub fn replace_entries(&mut self, entries: Vec<CatalogEntry>, disable: DisableConf) {
        self.entries = entries;
        self.disable = disable;
        // Like `settle`, but the selection stays where it was (clamped on read).
        if !self.categories().iter().any(|(c, _)| *c == self.category) {
            self.category = ALL.to_string();
            self.selected = 0;
        }
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    pub fn category(&self) -> &str {
        &self.category
    }

    pub fn total(&self) -> usize {
        self.entries.len()
    }

    pub fn disabled_total(&self) -> usize {
        self.entries.iter().filter(|e| !e.enabled).count()
    }

    fn matches_query(&self, e: &CatalogEntry) -> bool {
        if self.query.is_empty() {
            return true;
        }
        let q = self.query.to_lowercase();
        e.msg.to_lowercase().contains(&q) || e.sid.to_string().contains(&q)
    }

    /// Entries passing the state filter and the search, before the category.
    fn pre_filtered(&self) -> impl Iterator<Item = &CatalogEntry> {
        self.entries
            .iter()
            .filter(|e| self.filter.matches(e.enabled) && self.matches_query(e))
    }

    /// `All` first, then categories by count (largest first), then name.
    pub fn categories(&self) -> Vec<(String, usize)> {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        let mut total = 0;
        for e in self.pre_filtered() {
            total += 1;
            *counts.entry(e.category.as_str()).or_default() += 1;
        }
        let mut rest: Vec<(String, usize)> =
            counts.into_iter().map(|(k, v)| (k.to_string(), v)).collect();
        rest.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let mut out = vec![(ALL.to_string(), total)];
        out.extend(rest);
        out
    }

    pub fn visible(&self) -> Vec<&CatalogEntry> {
        self.pre_filtered()
            .filter(|e| self.category == ALL || e.category == self.category)
            .collect()
    }

    pub fn selected_index(&self) -> usize {
        let n = self.visible().len();
        self.selected.min(n.saturating_sub(1))
    }

    pub fn selected(&self) -> Option<&CatalogEntry> {
        let v = self.visible();
        v.get(self.selected_index()).copied()
    }

    pub fn move_selection(&mut self, delta: i32) {
        let n = self.visible().len();
        if n == 0 {
            self.selected = 0;
            return;
        }
        let cur = self.selected_index() as i64;
        let next = (cur + delta as i64).clamp(0, n as i64 - 1);
        self.selected = next as usize;
    }

    fn step_category(&mut self, dir: i32) {
        let cats = self.categories();
        let cur = cats.iter().position(|(c, _)| *c == self.category).unwrap_or(0) as i32;
        let n = cats.len() as i32;
        self.category = cats[(cur + dir).rem_euclid(n) as usize].0.clone();
        self.selected = 0;
    }

    pub fn next_category(&mut self) {
        self.step_category(1);
    }

    pub fn prev_category(&mut self) {
        self.step_category(-1);
    }

    /// After the filter or search changes, the chosen category may be empty;
    /// fall back to All so the list never silently shows nothing.
    fn settle(&mut self) {
        if !self.categories().iter().any(|(c, _)| *c == self.category) {
            self.category = ALL.to_string();
        }
        self.selected = 0;
    }

    pub fn cycle_filter(&mut self) {
        self.filter = self.filter.next();
        self.settle();
    }

    pub fn start_search(&mut self) {
        self.editing = true;
    }

    pub fn type_char(&mut self, c: char) {
        if !c.is_control() && self.query.chars().count() < 80 {
            self.query.push(c);
            self.settle();
        }
    }

    pub fn backspace(&mut self) {
        self.query.pop();
        self.settle();
    }

    /// Enter: keep the search and go back to browsing.
    pub fn finish_search(&mut self) {
        self.editing = false;
    }

    /// Esc while typing, or `c`: drop the search.
    pub fn clear_search(&mut self) {
        self.query.clear();
        self.editing = false;
        self.settle();
    }
}

// ---------------------------------------------------------------- sources

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Source {
    pub name: String,
    pub summary: String,
    pub license: String,
    pub needs_key: bool,
    pub replaces: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourcesView {
    /// Sources set up with `suricata-update enable-source`.
    pub enabled: Vec<Source>,
    /// Free sources from the index that are not enabled.
    pub free: Vec<Source>,
    /// Sources that need a subscription or key.
    pub keyed: Vec<Source>,
    pub error: Option<String>,
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                for d in chars.by_ref() {
                    if d.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Parse the `Name:` blocks of `suricata-update list-sources`.
pub fn parse_sources(text: &str) -> Vec<Source> {
    let mut out: Vec<Source> = Vec::new();
    let mut params = false;
    for line in strip_ansi(text).lines() {
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let v = v.trim().to_string();
        match k.trim() {
            "Name" => {
                params = false;
                out.push(Source {
                    name: v,
                    ..Default::default()
                });
            }
            key => {
                let Some(s) = out.last_mut() else { continue };
                match key {
                    "Summary" => s.summary = v,
                    "License" => {
                        s.needs_key |= v.eq_ignore_ascii_case("commercial");
                        s.license = v;
                    }
                    "Replaces" => s.replaces = Some(v),
                    "Parameters" => params = true,
                    "Subscription" => s.needs_key = true,
                    _ => {}
                }
                if params {
                    s.needs_key = true;
                }
            }
        }
    }
    out
}

/// Split the index into free and key-needing sources, minus the enabled ones.
pub fn build_sources(enabled: Vec<Source>, all: Vec<Source>) -> SourcesView {
    let names: Vec<&str> = enabled.iter().map(|s| s.name.as_str()).collect();
    let (mut free, mut keyed) = (Vec::new(), Vec::new());
    for s in all.into_iter().filter(|s| !names.contains(&s.name.as_str())) {
        if s.needs_key {
            keyed.push(s)
        } else {
            free.push(s)
        }
    }
    SourcesView {
        enabled,
        free,
        keyed,
        error: None,
    }
}

fn run_update(arg: &str) -> Result<String, String> {
    let out = Command::new("suricata-update")
        .arg(arg)
        .output()
        .map_err(|e| format!("cannot run suricata-update: {e}"))?;
    if !out.status.success() {
        return Err(format!("suricata-update {arg} failed"));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Read the source index and the enabled sources (read-only).
pub fn load_sources() -> SourcesView {
    match (run_update("list-enabled-sources"), run_update("list-sources")) {
        (Ok(en), Ok(all)) => build_sources(parse_sources(&en), parse_sources(&all)),
        (Err(e), _) | (_, Err(e)) => SourcesView {
            error: Some(e),
            ..Default::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(sid: u64, enabled: bool, cat: &str, msg: &str) -> CatalogEntry {
        CatalogEntry {
            sid,
            enabled,
            category: cat.to_string(),
            msg: msg.to_string(),
        }
    }

    fn browser() -> RulesBrowser {
        RulesBrowser::new(
            vec![
                e(1, true, "SCAN", "ET SCAN nmap"),
                e(2, false, "SCAN", "ET SCAN masscan"),
                e(3, true, "MALWARE", "ET MALWARE bot"),
                e(4, false, "INFO", "ET INFO thing"),
                e(5, true, "SCAN", "ET SCAN other"),
            ],
            DisableConf::default(),
        )
    }

    #[test]
    fn categories_by_count_then_name() {
        let b = browser();
        let c = b.categories();
        assert_eq!(c[0], ("All".to_string(), 5));
        assert_eq!(c[1], ("SCAN".to_string(), 3));
        assert_eq!(c[2], ("INFO".to_string(), 1));
        assert_eq!(c[3], ("MALWARE".to_string(), 1));
    }

    #[test]
    fn state_filter_cycles_and_filters() {
        let mut b = browser();
        b.cycle_filter();
        assert_eq!(b.filter, StateFilter::Disabled);
        let sids: Vec<_> = b.visible().iter().map(|e| e.sid).collect();
        assert_eq!(sids, [2, 4]);
        b.cycle_filter();
        assert_eq!(b.visible().len(), 3);
        b.cycle_filter();
        assert_eq!(b.visible().len(), 5);
    }

    #[test]
    fn search_matches_message_and_sid_case_insensitively() {
        let mut b = browser();
        b.start_search();
        for c in "NMAP".chars() {
            b.type_char(c);
        }
        assert_eq!(b.visible().len(), 1);
        b.clear_search();
        b.type_char('4');
        assert_eq!(b.visible()[0].sid, 4);
        assert!(!b.editing);
    }

    #[test]
    fn category_falls_back_to_all_when_it_empties() {
        let mut b = browser();
        b.next_category(); // SCAN
        assert_eq!(b.category(), "SCAN");
        b.start_search();
        for c in "malware".chars() {
            b.type_char(c);
        }
        assert_eq!(b.category(), ALL);
        assert_eq!(b.visible().len(), 1);
    }

    #[test]
    fn selection_is_clamped_and_resets() {
        let mut b = browser();
        b.move_selection(100);
        assert_eq!(b.selected_index(), 4);
        b.move_selection(-100);
        assert_eq!(b.selected_index(), 0);
        b.move_selection(2);
        b.next_category();
        assert_eq!(b.selected_index(), 0);
    }

    #[test]
    fn empty_result_is_valid() {
        let mut b = browser();
        b.type_char('z');
        assert!(b.selected().is_none());
        b.move_selection(5);
        assert_eq!(b.selected_index(), 0);
    }

    #[test]
    fn typed_control_characters_are_ignored() {
        let mut b = browser();
        b.type_char('\u{1b}');
        b.type_char('\n');
        assert_eq!(b.query(), "");
    }

    const INDEX: &str = "\x1b[1;36mName\x1b[0m: \x1b[1;35met/open\x1b[0m
  Vendor: Proofpoint
  Summary: Emerging Threats Open Ruleset
  License: MIT
Name: et/pro
  Summary: ET Pro
  License: Commercial
  Replaces: et/open
  Parameters: secret-code
  Subscription: https://example.invalid/
Name: abuse.ch/urlhaus
  Summary: URLhaus
  License: CC0-1.0
";

    #[test]
    fn parses_sources_with_ansi_and_keys() {
        let v = parse_sources(INDEX);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].name, "et/open");
        assert_eq!(v[0].summary, "Emerging Threats Open Ruleset");
        assert!(!v[0].needs_key);
        assert!(v[1].needs_key);
        assert_eq!(v[1].replaces.as_deref(), Some("et/open"));
        assert!(!v[2].needs_key);
    }

    #[test]
    fn builds_free_and_keyed_lists_without_enabled() {
        let all = parse_sources(INDEX);
        let enabled = vec![all[2].clone()];
        let v = build_sources(enabled, all);
        assert_eq!(v.enabled.len(), 1);
        assert_eq!(v.free.iter().map(|s| s.name.as_str()).collect::<Vec<_>>(), ["et/open"]);
        assert_eq!(v.keyed.len(), 1);
    }
}
