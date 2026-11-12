//! Rendering: sidebar, list, detail, rule, raw and help screens.

use crate::alert::Alert;
use crate::change::Action;
use crate::model::{group, App, Mode, RuleView};
use crate::source::Range;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

const SIDEBAR_MAX: u16 = 26;
const RULE_NOTE_1: &str = "Rule text is the hub's copy of ET Open.";
const RULE_NOTE_2: &str = "Whether the router has this rule enabled or disabled is not known here.";

fn header_style() -> Style {
    Style::default()
        .fg(Color::Blue)
        .add_modifier(Modifier::BOLD)
}

/// Truncate to `w` chars (never splitting a char) and pad with spaces.
/// Replace control characters (C0, DEL, C1) and bidi overrides/isolates with
/// `?`. All text that did not originate in this program passes through here
/// (via `fit`, `field`, `plain`) before it becomes a span.
fn clean(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_control() || matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}') {
                '?'
            } else {
                c
            }
        })
        .collect()
}

/// A line of untrusted text.
fn plain(s: &str) -> Line<'static> {
    Line::from(clean(s))
}

fn fit(s: &str, w: usize) -> String {
    let mut out: String = clean(s).chars().take(w).collect();
    let n = out.chars().count();
    out.extend(std::iter::repeat_n(' ', w - n));
    out
}

fn day_label(r: Range) -> String {
    match r {
        Range::Today => "Today".to_string(),
        Range::Day(0) => "Yesterday".to_string(),
        Range::Day(k) => format!("{} days ago", k as u32 + 1),
    }
}

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    if area.width == 0 || area.height == 0 {
        return;
    }
    let [body, status] = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).areas(area);
    match app.mode {
        Mode::List => {
            let sw = (body.width / 3).min(SIDEBAR_MAX);
            let [side, list] =
                Layout::horizontal([Constraint::Length(sw), Constraint::Min(0)]).areas(body);
            draw_sidebar(f, app, side);
            draw_list(f, app, list);
        }
        Mode::Detail => draw_detail(f, app, body),
        Mode::Rule => draw_rule(f, app, body),
        Mode::Raw => draw_raw(f, app, body),
        Mode::Help => draw_help(f, app, body),
        Mode::Rules => {
            let sw = (body.width / 3).min(SIDEBAR_MAX);
            let [side, list] =
                Layout::horizontal([Constraint::Length(sw), Constraint::Min(0)]).areas(body);
            draw_rules_sidebar(f, app, side);
            draw_rules_list(f, app, list);
        }
        Mode::RuleInfo => draw_rule_info(f, app, body),
        Mode::Sources => draw_sources(f, app, body),
        Mode::Updates => draw_updates(f, app, body),
        Mode::Thresholds => draw_thresholds(f, app, body),
        Mode::Settings => draw_settings(f, app, body),
        Mode::Logs => draw_logs(f, app, body),
        Mode::Confirm => draw_confirm(f, app, body),
        Mode::KeyEntry => draw_key_entry(f, app, body),
        Mode::Working => draw_working(f, app, body),
        Mode::Done => draw_done(f, app, body),
    }
    let hint = match app.mode {
        Mode::List => "  ? help  2 rules  3 sources  4 updates  5 suppress  6 settings  7 logs",
        Mode::Detail if app.can_change() => "  Esc back   r rule   w raw   d disable rule   s silence src   S silence dest",
        Mode::Detail => "  Esc back   r rule text   w raw JSON",
        Mode::Rule if app.can_change() => "  Esc back   d disable rule   s silence src   S silence dest",
        Mode::Rules if app.browser.as_ref().is_some_and(|b| b.editing) => {
            "  typing a search: Enter keeps it, Esc drops it"
        }
        Mode::Rules if app.can_change() => "  / search   s state   d disable   e enable   Enter rule   1 alerts",
        Mode::Rules => "  / search   s state   c clear   Enter rule   1 alerts   3 sources",
        Mode::Sources => "  j k move   e switch on   d switch off   R refresh list   1 alerts   2 rules   Esc back",
        Mode::Updates if app.can_change() => "  U update now   R reload   1 alerts   2 rules   3 sources",
        Mode::Updates => "  R reload   1 alerts   2 rules   3 sources",
        Mode::Thresholds => "  x remove   R reload   1 alerts   2 rules   4 updates",
        Mode::Settings => "  R reload   1 alerts   2 rules   4 updates   7 logs",
        Mode::Logs => "  Tab next log   R reload   G end   1 alerts   6 settings",
        Mode::Confirm => "  y confirm   Esc cancel",
        Mode::KeyEntry => "  type the code   Tab next field   Enter continue   Esc cancel",
        Mode::Working => "  working: do not close this window",
        Mode::Done => "  Enter continue",
        Mode::RuleInfo if app.can_change() => match app.browser.as_ref().and_then(|b| b.selected()) {
            Some(e) if e.enabled => "  Esc back   d disable this rule",
            Some(_) => "  Esc back   e enable this rule",
            None => "  Esc back",
        },
        _ => "  Esc back",
    };
    let left = Paragraph::new(Line::from(vec![
        Span::raw(clean(&app.status_line())),
        Span::styled(hint, Style::default().add_modifier(Modifier::DIM)),
    ]));
    // The scroll indicator has priority over the status text on narrow
    // terminals; it is right-aligned and never wider than the row.
    match scroll_indicator(app) {
        Some(ind) => {
            let iw = (ind.chars().count() as u16).min(status.width);
            let [l, r] =
                Layout::horizontal([Constraint::Min(0), Constraint::Length(iw)]).areas(status);
            f.render_widget(left, l);
            f.render_widget(Paragraph::new(ind), r);
        }
        None => f.render_widget(left, status),
    }
}

/// `lines 5-22 of 41` when the current screen scrolls and does not fit.
fn scroll_indicator(app: &App) -> Option<String> {
    let (content, vh) = app.last_view()?;
    if vh == 0 || content <= vh {
        return None;
    }
    let top = app.scroll_top(content, vh);
    Some(format!(
        "lines {}-{} of {}",
        top + 1,
        (top + vh).min(content),
        content
    ))
}

fn draw_sidebar(f: &mut Frame, app: &App, area: Rect) {
    // Keep the last column blank as a gap before the list.
    let w = (area.width as usize).saturating_sub(1);
    let head = Line::from(Span::styled(fit("Categories", w), header_style()));
    let cats = app.categories();
    let h = (area.height as usize).saturating_sub(1);
    // The header stays pinned; the category rows scroll so the current one
    // is always visible.
    let sel = cats
        .iter()
        .position(|(label, _)| *label == app.category())
        .unwrap_or(0);
    let offset = if h == 0 || sel < h { 0 } else { sel + 1 - h };
    let mut lines = vec![head];
    for (label, n) in cats.iter().skip(offset).take(h) {
        let count = n.to_string();
        let lw = w.saturating_sub(count.chars().count() + 1);
        let text = format!("{} {}", fit(label, lw), count);
        let style = if *label == app.category() {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(fit(&text, w), style)));
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn row_style(a: &Alert) -> Style {
    match a.et_severity.as_deref() {
        Some("Critical") | Some("Major") => Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
        Some("Informational") => Style::default().add_modifier(Modifier::DIM),
        Some(_) => Style::default(),
        None if a.severity == Some(3) => Style::default().add_modifier(Modifier::DIM),
        None => Style::default(),
    }
}

fn time_of(ts: &str) -> String {
    // "2026-11-10T10:11:12.000000+0000" -> "10:11:12"
    ts.split('T')
        .nth(1)
        .map(|t| t.chars().take(8).collect())
        .unwrap_or_else(|| ts.chars().take(8).collect())
}

fn row_line(app: &App, a: &Alert, width: usize, selected: bool) -> Line<'static> {
    let base = if selected {
        row_style(a).add_modifier(Modifier::REVERSED)
    } else {
        row_style(a)
    };
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut left = width;
    let mut push = |text: String, style: Style, spans: &mut Vec<Span<'static>>| {
        let cell: String = clean(&text).chars().take(left).collect();
        left -= cell.chars().count();
        spans.push(Span::styled(cell, style));
    };
    let action_blocked = a.action != "allowed" && a.action != "-";
    // Fixed columns first; the signature takes whatever is left, so it is
    // the first thing to shrink on narrow terminals.
    push(format!("{} ", fit(&time_of(&a.ts), 8)), base, &mut spans);
    push(
        format!("{} ", fit(&app.label(&a.iface), 8)),
        base,
        &mut spans,
    );
    push(format!("{} ", fit(&a.src, 21)), base, &mut spans);
    push(format!("{} ", fit(&a.dst, 21)), base, &mut spans);
    if action_blocked {
        let red = base.fg(Color::Red);
        push(format!("{} ", fit(&a.action, 8)), red, &mut spans);
    }
    push(a.signature.clone(), base, &mut spans);
    Line::from(spans)
}

fn draw_list(f: &mut Frame, app: &App, area: Rect) {
    let w = area.width as usize;
    let rows = app.visible();
    let head = format!(
        "{}  {}  {} alerts",
        day_label(app.range),
        app.category(),
        rows.len()
    );
    let mut lines = vec![Line::from(Span::styled(fit(&head, w), header_style()))];
    let h = (area.height as usize).saturating_sub(1);
    if rows.is_empty() {
        let msg = if app.hidden_count() > 0 {
            "No alerts to show: the rest are informational; press i to show them."
        } else {
            "No alerts in this range."
        };
        lines.push(Line::from(msg));
    } else {
        let sel = app.selected_index();
        let offset = if h == 0 || sel < h { 0 } else { sel + 1 - h };
        for (i, a) in rows.iter().enumerate().skip(offset).take(h) {
            lines.push(row_line(app, a, w, i == sel));
        }
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn field(name: &str, value: &str) -> Line<'static> {
    field_styled(name, value, Style::default())
}

fn field_styled(name: &str, value: &str, style: Style) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{name:<14}"),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::styled(clean(value), style),
    ])
}

/// Hard-wrap a line at `w` characters (the program counts characters, not
/// display cells, everywhere), keeping span styles. An empty line stays one
/// row, so the result is exactly the rows the screen will show.
fn wrap_line(line: Line<'static>, w: usize) -> Vec<Line<'static>> {
    let w = w.max(1);
    let mut rows: Vec<Vec<Span<'static>>> = vec![Vec::new()];
    let mut used = 0;
    for span in line.spans {
        let mut buf = String::new();
        for c in span.content.chars() {
            if used == w {
                if !buf.is_empty() {
                    rows.last_mut()
                        .unwrap()
                        .push(Span::styled(std::mem::take(&mut buf), span.style));
                }
                rows.push(Vec::new());
                used = 0;
            }
            buf.push(c);
            used += 1;
        }
        if !buf.is_empty() {
            rows.last_mut().unwrap().push(Span::styled(buf, span.style));
        }
    }
    rows.into_iter().map(Line::from).collect()
}

/// A screen with a pinned title and scrollable, hard-wrapped content. Records
/// the wrapped content height and viewport for the key handler; the offset is
/// clamped here too, so a resize cannot leave it out of range.
fn scroll_screen(f: &mut Frame, app: &App, area: Rect, title: &str, lines: Vec<Line<'static>>) {
    let rows: Vec<Line<'static>> = lines
        .into_iter()
        .flat_map(|l| wrap_line(l, area.width as usize))
        .collect();
    let vh = (area.height as usize).saturating_sub(1);
    app.record_view(rows.len(), vh);
    let top = app.scroll_top(rows.len(), vh);
    let [head, body] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(title.to_string(), header_style()))),
        head,
    );
    f.render_widget(
        Paragraph::new(rows.into_iter().skip(top).take(vh).collect::<Vec<_>>()),
        body,
    );
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some(a) = app.selected() else {
        return scroll_screen(
            f,
            app,
            area,
            "Alert",
            vec![Line::from("No alert selected.")],
        );
    };
    let opt = |v: Option<String>| v.unwrap_or_else(|| "-".to_string());
    let lines = vec![
        field("Signature", &a.signature),
        field("Time", &a.ts),
        field(
            "Interface",
            &format!("{} ({})", app.label(&a.iface), a.iface),
        ),
        field("Source", &a.src),
        field("Destination", &a.dst),
        field("Protocol", &a.proto),
        field_styled(
            "Action",
            &a.action,
            if a.action == "allowed" || a.action == "-" {
                Style::default()
            } else {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            },
        ),
        field(
            "SID / rev",
            &format!(
                "{} / {}",
                opt(a.sid.map(|s| s.to_string())),
                opt(a.rev.map(|r| r.to_string()))
            ),
        ),
        field("Severity", &opt(a.severity.map(|s| s.to_string()))),
        field("ET severity", &opt(a.et_severity.clone())),
        field("Confidence", &opt(a.confidence.clone())),
        field("MITRE", &opt(a.mitre.clone())),
        field("MITRE tactic", &opt(a.mitre_tactic.clone())),
        field("Context", &opt(a.context.clone())),
        field("Category", &opt(a.category.clone())),
        field("Target", &opt(a.attack_target.clone())),
        field("Product", &opt(a.affected_product.clone())),
        field("App proto", &opt(a.app_proto.clone())),
        field("Created", &opt(a.created_at.clone())),
        field("Updated", &opt(a.updated_at.clone())),
    ];
    scroll_screen(f, app, area, "Alert", lines);
}

fn draw_rule(f: &mut Frame, app: &App, area: Rect) {
    let mut lines: Vec<Line<'static>> = Vec::new();
    match app.rule_view() {
        RuleView::Found { text, warning } => {
            if let Some(w) = warning {
                lines.push(Line::from(Span::styled(
                    clean(&w),
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::default());
            }
            lines.push(plain(&text));
        }
        RuleView::NotInstalled => lines.push(Line::from(
            "The ET Open rules are not installed here. Run `suritui update-rules` to fetch them.",
        )),
        RuleView::NotFound(sid) => lines.push(Line::from(format!(
            "sid {sid} was not found in the local ET copy. It may be a local rule or removed upstream."
        ))),
        RuleView::NoSid => lines.push(Line::from("This alert carries no sid.")),
    }
    lines.push(Line::default());
    lines.push(Line::from(RULE_NOTE_1));
    lines.push(Line::from(RULE_NOTE_2));
    scroll_screen(f, app, area, "Rule", lines);
}

fn draw_raw(f: &mut Frame, app: &App, area: Rect) {
    let text = app
        .selected()
        .map(|a| {
            serde_json::from_str::<serde_json::Value>(&a.raw)
                .ok()
                .and_then(|v| serde_json::to_string_pretty(&v).ok())
                .unwrap_or_else(|| a.raw.clone())
        })
        .unwrap_or_default();
    let lines = text.lines().map(plain).collect();
    scroll_screen(f, app, area, "Raw JSON", lines);
}

/// Category rows with the current one kept in view (header pinned).
fn category_rows(
    cats: &[(String, usize)],
    current: &str,
    w: usize,
    h: usize,
    title: &str,
) -> Vec<Line<'static>> {
    let sel = cats.iter().position(|(c, _)| c == current).unwrap_or(0);
    let offset = if h == 0 || sel < h { 0 } else { sel + 1 - h };
    let mut lines = vec![Line::from(Span::styled(fit(title, w), header_style()))];
    for (label, n) in cats.iter().skip(offset).take(h) {
        let count = n.to_string();
        let lw = w.saturating_sub(count.chars().count() + 1);
        let text = format!("{} {}", fit(label, lw), count);
        let style = if label == current {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default()
        };
        lines.push(Line::from(Span::styled(fit(&text, w), style)));
    }
    lines
}

fn draw_rules_sidebar(f: &mut Frame, app: &App, area: Rect) {
    let Some(b) = &app.browser else { return };
    let w = (area.width as usize).saturating_sub(1);
    let h = (area.height as usize).saturating_sub(1);
    let lines = category_rows(&b.categories(), b.category(), w, h, "Categories");
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_rules_list(f: &mut Frame, app: &App, area: Rect) {
    let Some(b) = &app.browser else { return };
    let w = area.width as usize;
    let rows = b.visible();
    let mut head = format!(
        "Rules  {}  {} of {}  [{}]",
        b.category(),
        group(rows.len()),
        group(b.total()),
        b.filter.label()
    );
    if b.editing {
        head.push_str(&format!("  search: {}_", b.query()));
    } else if !b.query().is_empty() {
        head.push_str(&format!("  search: {}", b.query()));
    }
    let mut lines = vec![Line::from(Span::styled(fit(&head, w), header_style()))];
    let h = (area.height as usize).saturating_sub(1);
    if rows.is_empty() {
        lines.push(Line::from("No rules match."));
    } else {
        let sel = b.selected_index();
        let offset = if h == 0 || sel < h { 0 } else { sel + 1 - h };
        for (i, e) in rows.iter().enumerate().skip(offset).take(h) {
            let base = if i == sel {
                Style::default().add_modifier(Modifier::REVERSED)
            } else if e.enabled {
                Style::default()
            } else {
                Style::default().add_modifier(Modifier::DIM)
            };
            let state = if e.enabled { "on " } else { "OFF" };
            let state_style = if e.enabled {
                base
            } else {
                base.fg(Color::Red)
            };
            let mut left = w;
            let mut spans = Vec::new();
            for (text, style) in [
                (format!("{:<9} ", e.sid), base),
                (format!("{state} "), state_style),
                (e.msg.clone(), base),
            ] {
                let cell: String = clean(&text).chars().take(left).collect();
                left -= cell.chars().count();
                spans.push(Span::styled(cell, style));
            }
            lines.push(Line::from(spans));
        }
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_rule_info(f: &mut Frame, app: &App, area: Rect) {
    let (Some(b), Some(rule)) = (&app.browser, app.browser_rule()) else {
        return scroll_screen(f, app, area, "Rule", vec![Line::from("No rule selected.")]);
    };
    let Some(e) = b.selected() else {
        return scroll_screen(f, app, area, "Rule", vec![Line::from("No rule selected.")]);
    };
    let state_style = if e.enabled {
        Style::default().add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    };
    let mut lines = vec![
        field("SID / rev", &format!("{} / {}", e.sid, rule.rev)),
        field("Category", &e.category),
        field_styled(
            "State",
            if e.enabled { "enabled" } else { "DISABLED" },
            state_style,
        ),
        field("Why", crate::local::origin(e.enabled, e.sid, &b.disable)),
        Line::default(),
        plain(&rule.text),
    ];
    lines.push(Line::default());
    lines.push(Line::from(if app.can_change() {
        "This is the rule as Suricata loaded it."
    } else {
        "This is the rule as Suricata loaded it. Rules can be changed only on the router (suritui --local)."
    }));
    scroll_screen(f, app, area, "Rule", lines);
}

fn draw_confirm(f: &mut Frame, app: &App, area: Rect) {
    let Some(p) = &app.pending else {
        return scroll_screen(f, app, area, "Confirm", vec![Line::from("Nothing to confirm.")]);
    };
    let title = match &p.action {
        Action::Rule(crate::admin::Verb::Disable, sid) => format!("Disable rule {sid}?"),
        Action::Rule(crate::admin::Verb::Enable, sid) => format!("Enable rule {sid}?"),
        Action::Update => "Update the rules now?".to_string(),
        Action::SourceKey { name, .. } => format!("Store the code and switch on {name}?"),
        Action::Source { enable: true, name } => format!("Switch on the source {name}?"),
        Action::Source { enable: false, name } => format!("Switch off the source {name}?"),
        Action::Suppress { add: true, sid, track, ip } => format!(
            "Silence rule {sid} for {} {ip}?",
            if *track == crate::threshold::Track::BySrc { "source" } else { "destination" }
        ),
        Action::Suppress { add: false, sid, .. } => format!("Remove the suppress entry for rule {sid}?"),
    };
    let lines = vec![
        Line::from(Span::styled(title, Style::default().add_modifier(Modifier::BOLD))),
        plain(&p.msg),
        Line::default(),
        Line::from(match &p.action {
            Action::Suppress { .. } => format!("This {}; Suricata checks the new file and reloads it live.", p.how),
            Action::Source { .. } | Action::SourceKey { .. } => format!("This {}.", p.how),
            _ => format!("This {}, rebuilds the rules and reloads Suricata live.", p.how),
        }),
        Line::from(match &p.action {
            Action::Suppress { .. } => "It takes a few seconds.".to_string(),
            _ => "The rebuild can take a couple of minutes. Suricata keeps watching with the old rules until the reload.".to_string(),
        }),
        Line::from("A backup is made first. If the check or the reload fails, the previous files are put back."),
        Line::default(),
        Line::from(Span::styled(
            "Press y to confirm, Esc to cancel.",
            Style::default().add_modifier(Modifier::BOLD),
        )),
    ];
    scroll_screen(f, app, area, "Confirm change", lines);
}

fn draw_thresholds(f: &mut Frame, app: &App, area: Rect) {
    let w = area.width as usize;
    let h = (area.height as usize).saturating_sub(1);
    let mut lines = vec![Line::from(Span::styled(
        fit(&format!("Suppress and threshold entries  {} in threshold.config", app.thresholds.len()), w),
        header_style(),
    ))];
    if app.thresholds.is_empty() {
        lines.push(Line::from("No entries. Open an alert and press s (source) or S (destination) to silence its rule for one host."));
    } else {
        let sel = app.thr_sel.min(app.thresholds.len() - 1);
        let offset = if h == 0 || sel < h { 0 } else { sel + 1 - h };
        for (i, e) in app.thresholds.iter().enumerate().skip(offset).take(h) {
            let mut text = e.line.clone();
            if e.removable.is_none() {
                text.push_str("   (edit by hand)");
            }
            let style = if i == sel {
                Style::default().add_modifier(Modifier::REVERSED)
            } else if e.removable.is_none() {
                Style::default().add_modifier(Modifier::DIM)
            } else {
                Style::default()
            };
            lines.push(Line::from(Span::styled(fit(&text, w), style)));
        }
    }
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_settings(f: &mut Frame, app: &App, area: Rect) {
    let lines: Vec<Line<'static>> = match &app.settings {
        Some(l) => l.iter().map(|t| plain(t)).collect(),
        None => vec![Line::from("Not loaded.")],
    };
    scroll_screen(f, app, area, "Settings (suricata.yaml, read-only)", lines);
}

fn draw_logs(f: &mut Frame, app: &App, area: Rect) {
    let lines: Vec<Line<'static>> = app.logs.iter().map(|t| plain(t)).collect();
    let title = format!(
        "Log: {} ({} of {}, newest at the bottom)   Tab: next log",
        app.log_name(),
        app.log_idx % App::LOG_NAMES.len() + 1,
        App::LOG_NAMES.len()
    );
    scroll_screen(f, app, area, &title, lines);
}

fn draw_updates(f: &mut Frame, app: &App, area: Rect) {
    let lines: Vec<Line<'static>> = match &app.updates {
        Some(l) => l.iter().map(|t| plain(t)).collect(),
        None => vec![Line::from("Not loaded.")],
    };
    scroll_screen(f, app, area, "Updates and status", lines);
}

fn draw_working(f: &mut Frame, app: &App, area: Rect) {
    let (what, secs) = match &app.job {
        Some(j) => (
            match &j.action {
                Action::Rule(v, sid) => format!("{} rule {sid}", v.word()),
                Action::Update => "updating the rules".to_string(),
                Action::SourceKey { name, .. } => format!("storing the code for {name} and installing its rules"),
                Action::Source { enable, name } => {
                    format!("{} the source {name}", if *enable { "switching on" } else { "switching off" })
                }
                Action::Suppress { add: true, sid, .. } => format!("silencing rule {sid}"),
                Action::Suppress { add: false, sid, .. } => format!("removing the suppress entry of rule {sid}"),
            },
            j.started.elapsed().as_secs(),
        ),
        None => ("change".to_string(), 0),
    };
    let lines = vec![
        Line::from(format!("Working: {what} ... {secs}s")),
        Line::default(),
        Line::from("Rebuilding the rules and reloading Suricata. Please wait and do not close this window."),
    ];
    scroll_screen(f, app, area, "Working", lines);
}

fn draw_done(f: &mut Frame, app: &App, area: Rect) {
    let (ok, text) = match &app.outcome {
        Some((ok, l)) => (*ok, l.clone()),
        None => (true, vec![]),
    };
    let mut lines = vec![if ok {
        Line::from(Span::styled("Done", Style::default().add_modifier(Modifier::BOLD)))
    } else {
        Line::from(Span::styled(
            "Failed",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        ))
    }];
    lines.extend(text.iter().map(|l| plain(l)));
    lines.push(Line::default());
    lines.push(Line::from("Press Enter to continue."));
    scroll_screen(f, app, area, if ok { "Change finished" } else { "Change failed" }, lines);
}

fn source_text(s: &crate::browser::Source) -> String {
    let mut text = format!("{:<28} {:<12} {}", s.name, s.license, s.summary);
    if let Some(r) = &s.replaces {
        text.push_str(&format!(" (replaces {r})"));
    }
    text
}

fn draw_sources(f: &mut Frame, app: &App, area: Rect) {
    let w = area.width as usize;
    let h = (area.height as usize).saturating_sub(1);
    let Some(v) = &app.sources else {
        return f.render_widget(Paragraph::new("Not loaded."), area);
    };
    if let Some(e) = &v.error {
        return f.render_widget(Paragraph::new(format!("Could not read the sources: {e}")), area);
    }
    let sel = app.src_sel.min((v.enabled.len() + v.free.len() + v.keyed.len()).saturating_sub(1));
    // (line, is the selected row)
    let mut rows: Vec<(Line<'static>, bool)> = Vec::new();
    let head = |t: String| (Line::from(Span::styled(fit(&t, w), header_style())), false);
    let item = |s: &crate::browser::Source, idx: usize| {
        let style = if idx == sel { Style::default().add_modifier(Modifier::REVERSED) } else { Style::default() };
        (Line::from(Span::styled(fit(&source_text(s), w), style)), idx == sel)
    };
    rows.push(head("Enabled".to_string()));
    if v.enabled.is_empty() {
        rows.push((Line::from("None set up explicitly: suricata-update falls back to et/open."), false));
    }
    for (i, s) in v.enabled.iter().enumerate() {
        rows.push(item(s, i));
    }
    rows.push((Line::default(), false));
    rows.push(head(format!("Free sources available ({})   e switches the highlighted one on", v.free.len())));
    for (i, s) in v.free.iter().enumerate() {
        rows.push(item(s, v.enabled.len() + i));
    }
    rows.push((Line::default(), false));
    rows.push(head(format!("Need a key or subscription ({})   e asks for the code", v.keyed.len())));
    for (i, s) in v.keyed.iter().enumerate() {
        rows.push(item(s, v.enabled.len() + v.free.len() + i));
    }
    rows.push((Line::default(), false));
    rows.push((Line::from("R fetches the current source list from the internet."), false));
    let at = rows.iter().position(|(_, s)| *s).unwrap_or(0);
    let top = if h == 0 || at < h { 0 } else { at + 1 - h };
    let mut lines = vec![Line::from(Span::styled(fit("Rule sources", w), header_style()))];
    lines.extend(rows.into_iter().skip(top).take(h).map(|(l, _)| l));
    f.render_widget(Paragraph::new(lines), area);
}

fn draw_key_entry(f: &mut Frame, app: &App, area: Rect) {
    let Some(e) = &app.key_entry else {
        return f.render_widget(Paragraph::new("Nothing to enter."), area);
    };
    let mut lines = vec![
        Line::from(Span::styled(format!("Code for {}", e.name), Style::default().add_modifier(Modifier::BOLD))),
        plain(&e.summary),
        Line::default(),
    ];
    for (i, (label, value, masked)) in e.fields.iter().enumerate() {
        let shown = if *masked { "*".repeat(value.chars().count()) } else { value.clone() };
        let cursor = if i == e.idx { "_" } else { "" };
        lines.push(Line::from(Span::styled(label.clone(), header_style())));
        lines.push(Line::from(format!("  {shown}{cursor}")));
        lines.push(Line::default());
    }
    lines.push(Line::from("The code is shown as stars, is sent to the helper through a pipe (never on a command line)"));
    lines.push(Line::from("and is kept only in a file that root can read. Nothing is stored until you confirm."));
    scroll_screen(f, app, area, "Source code", lines);
}

fn draw_help(f: &mut Frame, app: &App, area: Rect) {
    let keys = [
        ("Tab / Shift-Tab", "next / previous category"),
        ("j k, Down Up", "move in the list"),
        ("g G, Home End", "first / last row"),
        ("PgUp PgDn", "move 20 rows"),
        ("j k, PgUp PgDn, g G", "scroll (detail, rule, raw, help)"),
        ("Enter", "alert detail"),
        ("Esc", "back to the list"),
        ("i", "show / hide informational alerts"),
        ("[ ]", "older / newer day"),
        ("r", "rule text (from detail)"),
        ("w", "raw JSON (from detail)"),
        ("R", "refresh"),
        ("2 / 3 / 4 / 1", "rules / sources / updates / alerts"),
        ("U", "updates screen: update the rules now (router)"),
        ("s / S", "alert screens: silence the rule for this source / destination"),
        ("5, x", "suppress list; x removes the highlighted entry"),
        ("6 / 7", "settings (read-only) / logs (Tab: next log)"),
        ("d / e", "disable / enable a rule: rules list, rule screen; d on an alert (router)"),
        ("3, j k, e / d", "sources: move, switch on (e; asks for a code if needed) / off (d); R refreshes the list"),
        ("y", "confirm a change (Esc cancels)"),
        ("/ s c", "rules: search / state filter / clear"),
        ("?", "this help"),
        ("q, Ctrl-C", "quit"),
    ];
    let lines = keys
        .iter()
        .map(|(k, d)| field_wide(k, d))
        .collect::<Vec<_>>();
    scroll_screen(f, app, area, "Help", lines);
}

fn field_wide(k: &str, d: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{k:<21}"),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::raw(d.to_string()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Mode, RuleView};
    use crate::testutil::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn render(app: &App, w: u16, h: u16) -> Vec<String> {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        let buf = t.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
            })
            .collect()
    }
    fn screen(app: &App, w: u16, h: u16) -> String {
        render(app, w, h).join("\n")
    }

    fn sample() -> App {
        app(vec![
            alert(
                "2026-11-10T10:11:12.000000+0000",
                "ET SCAN Probe",
                "allowed",
                None,
            ),
            alert(
                "2026-11-10T09:00:00.000000+0000",
                "ET DNS Query",
                "blocked",
                None,
            ),
            alert(
                "2026-11-10T08:00:00.000000+0000",
                "ET DNS Other",
                "allowed",
                Some("Informational"),
            ),
        ])
    }

    #[test]
    fn sidebar_lists_all_first_with_counts() {
        let a = sample();
        let rows = render(&a, 100, 20);
        let left: Vec<String> = rows.iter().map(|r| r.chars().take(26).collect()).collect();
        let all = left.iter().position(|r| r.contains("All")).expect("All");
        let scan = left.iter().position(|r| r.contains("SCAN")).expect("SCAN");
        assert!(all < scan);
        assert!(left[all].contains('3'));
        assert!(left.iter().any(|r| r.contains("DNS") && r.contains('2')));
    }

    #[test]
    fn sidebar_count_is_separated_from_list_column() {
        let alerts: Vec<Alert> = (0..1000)
            .map(|i| {
                alert(
                    &format!("2026-11-10T10:{:02}:12.000000+0000", i % 60),
                    "ET SCAN Probe",
                    "allowed",
                    None,
                )
            })
            .collect();
        let a = app(alerts);
        let rows = render(&a, 100, 20);
        let all: Vec<char> = rows
            .iter()
            .find(|r| r.starts_with("All"))
            .unwrap()
            .chars()
            .collect();
        let end = all
            .iter()
            .take(26)
            .rposition(|c| c.is_ascii_digit())
            .unwrap();
        assert!(all[..26].iter().collect::<String>().contains("1000"));
        assert_eq!(all[25], ' ');
        assert!(end < 25);
    }

    #[test]
    fn list_shows_columns_for_row() {
        let a = sample();
        let s = screen(&a, 120, 20);
        assert!(s.contains("10:11:12"));
        assert!(s.contains("wan"));
        assert!(s.contains("192.0.2.1:1"));
        assert!(s.contains("198.51.100.2:2"));
        assert!(s.contains("ET SCAN Probe"));
    }

    #[test]
    fn blocked_action_is_shown_allowed_is_not() {
        let a = sample();
        let rows = render(&a, 120, 20);
        let row = |sig: &str| rows.iter().find(|r| r.contains(sig)).expect(sig).clone();
        assert!(row("ET DNS Query").contains("blocked"));
        assert!(!row("ET SCAN Probe").contains("allowed"));
        assert!(!row("ET DNS Other").contains("allowed"));
    }

    #[test]
    fn empty_state_message_is_explicit() {
        let a = app(vec![]);
        let s = screen(&a, 100, 12);
        assert!(s.contains("No alerts"));
        assert!(s.contains("0 alerts in this range"));
    }

    #[test]
    fn empty_state_when_all_hidden_mentions_toggle() {
        let mut a = app(vec![alert(
            "2026-11-10T10:00:00.000000+0000",
            "ET X y",
            "allowed",
            Some("Informational"),
        )]);
        a.toggle_informational();
        let s = screen(&a, 100, 12);
        assert!(s.contains("informational"));
        assert!(s.contains("press i"));
    }

    #[test]
    fn detail_shows_key_fields_and_raw_hint() {
        let mut a = sample();
        a.mode = Mode::Detail;
        let s = screen(&a, 100, 30);
        assert!(s.contains("ET SCAN Probe"));
        assert!(s.contains("2000001"));
        assert!(s.contains("192.0.2.1:1"));
        assert!(s.contains("w raw JSON"));
    }

    fn cells(app: &App, w: u16, h: u16) -> Vec<Vec<(String, Style)>> {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        let buf = t.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| (buf[(x, y)].symbol().to_string(), buf[(x, y)].style()))
                    .collect()
            })
            .collect()
    }

    /// Style of the first cell of `needle` on the row that contains `row_key`.
    fn style_of(app: &App, row_key: &str, needle: &str) -> Style {
        let grid = cells(app, 120, 30);
        for row in grid {
            let line: String = row.iter().map(|(c, _)| c.as_str()).collect();
            if line.contains(row_key) {
                let at = line.find(needle).expect(needle);
                let col = line[..at].chars().count();
                return row[col].1;
            }
        }
        panic!("row {row_key} not found");
    }

    #[test]
    fn detail_action_not_allowed_is_bold_red() {
        let mut a = sample();
        a.move_selection(1); // the "blocked" alert
        a.mode = Mode::Detail;
        let st = style_of(&a, "Action", "blocked");
        assert_eq!(st.fg, Some(Color::Red));
        assert!(st.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn detail_action_allowed_is_plain() {
        let mut a = sample();
        a.mode = Mode::Detail;
        let st = style_of(&a, "Action", "allowed");
        assert_ne!(st.fg, Some(Color::Red));
    }

    #[test]
    fn detail_shows_extra_fields_when_present() {
        let mut al = alert(
            "2026-11-10T10:11:12.000000+0000",
            "ET SCAN Probe",
            "allowed",
            None,
        );
        al.category = Some("Attempted Recon".into());
        al.attack_target = Some("Server_Endpoint".into());
        al.affected_product = Some("Linux".into());
        al.mitre_tactic = Some("Discovery".into());
        al.created_at = Some("2020_01_02".into());
        al.updated_at = Some("2021_03_04".into());
        al.app_proto = Some("http".into());
        let mut a = app(vec![al]);
        a.mode = Mode::Detail;
        let rows = render(&a, 100, 30);
        let has = |label: &str, val: &str| {
            assert!(
                rows.iter().any(|r| r.contains(label) && r.contains(val)),
                "{label} {val}"
            )
        };
        has("Category", "Attempted Recon");
        has("Target", "Server_Endpoint");
        has("Product", "Linux");
        has("MITRE tactic", "Discovery");
        has("Created", "2020_01_02");
        has("Updated", "2021_03_04");
        has("App proto", "http");
    }

    #[test]
    fn detail_extra_fields_missing_show_dash() {
        let mut a = sample();
        a.mode = Mode::Detail;
        let rows = render(&a, 100, 30);
        for label in [
            "Category",
            "Target",
            "Product",
            "MITRE tactic",
            "Created",
            "Updated",
            "App proto",
        ] {
            let r = rows.iter().find(|r| r.contains(label)).expect(label);
            assert!(r.trim_end().ends_with(" -"), "{label}: {r:?}");
        }
    }

    #[test]
    fn extra_detail_values_are_cleaned() {
        let mut al = alert("2026-11-10T10:11:12.000000+0000", "ET X y", "allowed", None);
        al.category = Some(format!("C{HOSTILE}"));
        al.attack_target = Some(format!("T{HOSTILE}"));
        al.affected_product = Some(format!("P{HOSTILE}"));
        al.mitre_tactic = Some(format!("M{HOSTILE}"));
        al.created_at = Some(format!("D{HOSTILE}"));
        al.updated_at = Some(format!("U{HOSTILE}"));
        al.app_proto = Some(format!("A{HOSTILE}"));
        let mut a = app(vec![al]);
        a.mode = Mode::Detail;
        assert_clean(&screen(&a, 120, 30));
    }

    #[test]
    fn missing_action_dash_is_not_red_in_list() {
        let a = app(vec![alert(
            "2026-11-10T10:11:12.000000+0000",
            "ET DASH Row",
            "-",
            None,
        )]);
        let grid = cells(&a, 120, 10);
        let row = grid
            .iter()
            .find(|r| {
                r.iter()
                    .map(|(c, _)| c.as_str())
                    .collect::<String>()
                    .contains("ET DASH Row")
            })
            .unwrap();
        assert!(row.iter().all(|(_, st)| st.fg != Some(Color::Red)));
        let text: String = row.iter().map(|(c, _)| c.as_str()).collect();
        assert!(!text.contains(" - "));
    }

    #[test]
    fn status_line_shows_counts_and_error() {
        let mut a = sample();
        a.status = "ssh down".into();
        let s = screen(&a, 120, 10);
        assert!(s.contains("3 shown | ssh down"));
    }

    #[test]
    fn help_lists_paging_keys() {
        let mut a = sample();
        a.mode = Mode::Help;
        let s = screen(&a, 100, 24);
        assert!(s.contains("g G, Home End"));
        assert!(s.contains("PgUp PgDn"));
    }

    #[test]
    fn raw_screen_shows_json() {
        let mut a = sample();
        a.mode = Mode::Raw;
        assert!(screen(&a, 100, 20).contains("event_type"));
    }

    #[test]
    fn rule_screen_shows_note_about_router_state() {
        let mut a = sample();
        a.mode = Mode::Rule;
        assert_eq!(a.rule_view(), RuleView::NotInstalled);
        let s = screen(&a, 100, 20);
        assert!(
            s.contains("Whether the router has this rule enabled or disabled is not known here.")
        );
    }

    #[test]
    fn rule_screen_shows_run_update_rules_hint_when_not_installed() {
        let mut a = sample();
        a.mode = Mode::Rule;
        assert!(screen(&a, 100, 20).contains("suritui update-rules"));
    }

    #[test]
    fn help_screen_lists_keys() {
        let mut a = sample();
        a.mode = Mode::Help;
        let s = screen(&a, 100, 30);
        assert!(s.contains("Tab") && s.contains("quit"));
    }

    #[test]
    fn narrow_terminal_does_not_panic() {
        let modes = [Mode::List, Mode::Detail, Mode::Rule, Mode::Raw, Mode::Help];
        for (w, h) in [(40, 10), (20, 5), (20, 1), (1, 1), (0, 0), (5, 2), (200, 3)] {
            for m in modes {
                let mut a = sample();
                a.mode = m;
                render(&a, w, h);
            }
            render(&app(vec![]), w, h);
        }
    }

    #[test]
    fn status_line_always_visible() {
        let a = sample();
        assert!(screen(&a, 40, 6).contains("shown"));
    }

    const HOSTILE: &str = "\x1b[31m\x07\u{9b}\u{202e}";

    fn assert_clean(s: &str) {
        for c in ['\x1b', '\x07', '\u{9b}', '\u{202e}'] {
            assert!(!s.contains(c), "leaked {:?}", c);
        }
        assert!(s.contains('?'));
    }

    fn hostile_app() -> App {
        let mut al = alert(
            "2026-11-10T10:11:12.000000+0000",
            &format!("SIG{HOSTILE}end"),
            "allowed",
            None,
        );
        al.src = format!("S{HOSTILE}");
        al.context = Some(format!("C{HOSTILE}"));
        al.raw = format!("raw{HOSTILE}notjson");
        app_with(
            vec![(crate::source::Range::Today, vec![al])],
            Some(crate::rules::RuleIndex::from_text(&format!(
                "alert tcp any any -> any any (msg:\"x{HOSTILE}\"; sid:2000001; rev:5;)\n"
            ))),
        )
    }

    #[test]
    fn hostile_text_never_reaches_list_detail_raw_rule() {
        for m in [Mode::List, Mode::Detail, Mode::Raw, Mode::Rule] {
            let mut a = hostile_app();
            a.mode = m;
            assert_clean(&screen(&a, 120, 24));
        }
    }

    #[test]
    fn hostile_status_is_cleaned() {
        let mut a = sample();
        a.status = format!("ssh: bad{HOSTILE}");
        let out = screen(&a, 120, 10);
        assert_clean(&out);
        assert!(out.contains("bad?[31m"));
    }

    #[test]
    fn normal_text_is_unchanged() {
        let s = screen(&sample(), 120, 20);
        assert!(s.contains("ET SCAN Probe") && !s.contains('?') || s.contains("? help"));
        assert_eq!(clean("ET SCAN Probe é 日本"), "ET SCAN Probe é 日本");
    }

    // ---- scrolling ----

    use crate::input::handle_key;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    fn press(a: &mut App, c: KeyCode) {
        handle_key(a, KeyEvent::new(c, KeyModifiers::NONE));
    }
    fn key(a: &mut App, ch: char) {
        press(a, KeyCode::Char(ch));
    }

    /// One alert whose raw JSON pretty-prints to 42 lines (40 keys).
    fn long_app() -> App {
        let mut al = alert(
            "2026-11-10T10:11:12.000000+0000",
            "ET SCAN Probe",
            "allowed",
            None,
        );
        let body: Vec<String> = (0..40)
            .map(|i| format!("\"key{i:02}\":\"val{i:02}\""))
            .collect();
        al.raw = format!("{{{}}}", body.join(","));
        app(vec![al])
    }

    fn mode_app(m: Mode) -> App {
        let mut a = long_app();
        a.set_mode(m);
        a
    }

    /// First content row (below the title) of a w x h render.
    fn first_line(a: &App, w: u16, h: u16) -> String {
        render(a, w, h)[1].trim_end().to_string()
    }
    fn footer(a: &App, w: u16, h: u16) -> String {
        render(a, w, h)[h as usize - 1].trim_end().to_string()
    }

    #[test]
    fn raw_scrolls_with_j_k_and_arrows() {
        let mut a = mode_app(Mode::Raw);
        let top = first_line(&a, 60, 10);
        assert_eq!(top, "{");
        key(&mut a, 'j');
        assert_eq!(first_line(&a, 60, 10), "  \"key00\": \"val00\",");
        press(&mut a, KeyCode::Down);
        assert_eq!(first_line(&a, 60, 10), "  \"key01\": \"val01\",");
        key(&mut a, 'k');
        press(&mut a, KeyCode::Up);
        assert_eq!(first_line(&a, 60, 10), top);
    }

    #[test]
    fn detail_scrolls_and_pages() {
        let mut a = mode_app(Mode::Detail);
        assert!(first_line(&a, 60, 10).starts_with("Signature"));
        key(&mut a, 'j');
        assert!(first_line(&a, 60, 10).starts_with("Time"));
        key(&mut a, 'k');
        assert!(first_line(&a, 60, 10).starts_with("Signature"));
        // viewport = 10 - 1 status - 1 title = 8 rows; page = 7
        press(&mut a, KeyCode::PageDown);
        assert!(
            first_line(&a, 60, 10).starts_with("SID / rev"),
            "{}",
            first_line(&a, 60, 10)
        );
        press(&mut a, KeyCode::PageUp);
        assert!(first_line(&a, 60, 10).starts_with("Signature"));
    }

    #[test]
    fn raw_pages_g_and_big_g() {
        let mut a = mode_app(Mode::Raw);
        render(&a, 60, 10);
        key(&mut a, 'G');
        assert_eq!(first_line(&a, 60, 10), "  \"key33\": \"val33\",");
        assert!(render(&a, 60, 10)[8].starts_with("}"));
        key(&mut a, 'g');
        assert_eq!(first_line(&a, 60, 10), "{");
        press(&mut a, KeyCode::End);
        assert!(render(&a, 60, 10)[8].starts_with("}"));
        press(&mut a, KeyCode::Home);
        assert_eq!(first_line(&a, 60, 10), "{");
        press(&mut a, KeyCode::PageDown);
        assert_eq!(first_line(&a, 60, 10), "  \"key06\": \"val06\",");
        press(&mut a, KeyCode::PageUp);
        assert_eq!(first_line(&a, 60, 10), "{");
    }

    #[test]
    fn scrolling_is_clamped_at_both_ends() {
        let mut a = mode_app(Mode::Raw);
        render(&a, 60, 10);
        key(&mut a, 'k');
        assert_eq!(first_line(&a, 60, 10), "{");
        key(&mut a, 'G');
        let bottom = first_line(&a, 60, 10);
        key(&mut a, 'j');
        press(&mut a, KeyCode::PageDown);
        assert_eq!(first_line(&a, 60, 10), bottom);
        // no hidden overshoot: one k moves exactly one line up
        key(&mut a, 'k');
        assert_eq!(first_line(&a, 60, 10), "  \"key32\": \"val32\",");
        // same for the top after a page up
        key(&mut a, 'g');
        press(&mut a, KeyCode::PageUp);
        key(&mut a, 'j');
        assert_eq!(first_line(&a, 60, 10), "  \"key00\": \"val00\",");
    }

    #[test]
    fn scroll_resets_on_mode_change() {
        let mut a = mode_app(Mode::Detail);
        render(&a, 60, 10);
        key(&mut a, 'G');
        render(&a, 60, 10);
        key(&mut a, 'w');
        assert_eq!(a.mode, Mode::Raw);
        assert_eq!(first_line(&a, 60, 10), "{");
        key(&mut a, 'G');
        render(&a, 60, 10);
        press(&mut a, KeyCode::Esc);
        press(&mut a, KeyCode::Enter);
        assert!(first_line(&a, 60, 10).starts_with("Signature"));
        key(&mut a, 'G');
        render(&a, 60, 10);
        press(&mut a, KeyCode::Esc);
        press(&mut a, KeyCode::Enter);
        key(&mut a, 'w');
        assert_eq!(first_line(&a, 60, 10), "{");
    }

    #[test]
    fn scroll_resets_when_alert_changes() {
        let mut a = app(vec![
            alert(
                "2026-11-10T10:00:00.000000+0000",
                "ET A one",
                "allowed",
                None,
            ),
            alert(
                "2026-11-10T09:00:00.000000+0000",
                "ET B two",
                "allowed",
                None,
            ),
        ]);
        a.set_mode(Mode::Detail);
        render(&a, 60, 8);
        key(&mut a, 'G');
        assert!(!first_line(&a, 60, 8).starts_with("Signature"));
        // the selection moves under the screen (model-level change)
        a.move_selection(1);
        assert!(first_line(&a, 60, 8).starts_with("Signature"));
    }

    #[test]
    fn scroll_resets_when_model_demotes_mode() {
        let mut a = mode_app(Mode::Raw);
        render(&a, 60, 10);
        key(&mut a, 'G');
        a.refresh();
        assert_eq!(a.mode, Mode::List);
        press(&mut a, KeyCode::Enter);
        key(&mut a, 'w');
        assert_eq!(first_line(&a, 60, 10), "{");
    }

    #[test]
    fn content_that_fits_does_not_scroll_and_has_no_indicator() {
        let mut a = mode_app(Mode::Detail);
        let before = render(&a, 80, 40);
        for c in [
            KeyCode::Char('j'),
            KeyCode::PageDown,
            KeyCode::Char('G'),
            KeyCode::End,
        ] {
            press(&mut a, c);
            assert_eq!(render(&a, 80, 40), before);
        }
        assert!(!footer(&a, 80, 40).contains("lines"));
        assert!(footer(&a, 80, 40).contains("w raw JSON"));
    }

    #[test]
    fn indicator_shows_visible_range() {
        let mut a = mode_app(Mode::Raw);
        // 42 content lines, 8 rows
        assert!(
            footer(&a, 100, 10).contains("lines 1-8 of 42"),
            "{}",
            footer(&a, 100, 10)
        );
        key(&mut a, 'j');
        assert!(footer(&a, 100, 10).contains("lines 2-9 of 42"));
        key(&mut a, 'G');
        assert!(footer(&a, 100, 10).contains("lines 35-42 of 42"));
        let d = mode_app(Mode::Detail);
        let f = footer(&d, 100, 10);
        assert!(f.contains("lines 1-8 of 20"), "{f}");
        assert!(f.contains("Esc back") && f.contains("r rule text") && f.contains("w raw JSON"));
    }

    #[test]
    fn footer_fits_narrow_terminals() {
        let a = mode_app(Mode::Detail);
        for w in [1u16, 5, 12, 20, 40] {
            let f = footer(&a, w, 6);
            assert!(f.chars().count() <= w as usize);
        }
        assert!(footer(&a, 20, 6).contains("lines 1-4 of"));
    }

    #[test]
    fn resize_keeps_offset_valid() {
        let mut a = mode_app(Mode::Raw);
        render(&a, 100, 30);
        key(&mut a, 'G');
        let big = render(&a, 100, 30);
        assert!(big[28].starts_with("}"));
        // offset 14 is still valid in 8 rows
        assert!(footer(&a, 100, 10).contains("lines 15-22 of 42"));
        key(&mut a, 'G');
        assert!(render(&a, 100, 10)[8].starts_with("}"));
        // back to a tall screen: the offset is clamped to the new maximum
        let big = render(&a, 100, 30);
        assert!(big[28].starts_with("}"), "{big:?}");
        let tall = render(&a, 100, 50);
        assert_eq!(tall[1].trim_end(), "{");
        assert!(!tall[49].contains("lines"));
        // after the clamp, k moves exactly one line from the clamped offset
        render(&a, 100, 30);
        key(&mut a, 'G');
        render(&a, 100, 50);
        key(&mut a, 'k');
        assert_eq!(first_line(&a, 100, 50), "{");
    }

    #[test]
    fn long_wrapped_line_counts_as_many_lines() {
        let mut al = alert("2026-11-10T10:11:12.000000+0000", "ET X y", "allowed", None);
        al.raw = format!("{{\"a\":\"{}\"}}", "z".repeat(200));
        let mut a = app(vec![al]);
        a.set_mode(Mode::Raw);
        // 3 JSON lines, the middle one wraps at width 20 into 11 rows
        let f = footer(&a, 20, 8);
        assert!(f.contains("of 13"), "{f}");
        key(&mut a, 'G');
        let rows = render(&a, 20, 8);
        assert!(rows[6].starts_with("}"), "{rows:?}");
        assert!(rows[5].contains('z'));
    }

    #[test]
    fn list_keys_do_not_leak_into_scrolled_modes() {
        for m in [Mode::Detail, Mode::Raw] {
            let mut a = mode_app(m);
            render(&a, 60, 10);
            for c in [
                KeyCode::Tab,
                KeyCode::Char('i'),
                KeyCode::Char('['),
                KeyCode::Char(']'),
                KeyCode::Char('R'),
                KeyCode::Char('?'),
            ] {
                press(&mut a, c);
                assert_eq!(a.mode, m);
                assert_eq!(first_line(&a, 60, 10).trim_end(), first_line(&a, 60, 10));
            }
            assert!(!a.hide_informational);
        }
    }

    #[test]
    fn rule_and_help_scroll_and_clamp() {
        for m in [Mode::Rule, Mode::Help] {
            let mut a = mode_app(m);
            let top = first_line(&a, 30, 6);
            assert!(footer(&a, 30, 6).contains("lines 1-4 of"), "{m:?}");
            key(&mut a, 'j');
            assert_ne!(first_line(&a, 30, 6), top, "{m:?}");
            key(&mut a, 'G');
            let end = footer(&a, 30, 6);
            press(&mut a, KeyCode::PageDown);
            assert_eq!(footer(&a, 30, 6), end, "{m:?} clamps at the end");
            key(&mut a, 'g');
            assert_eq!(first_line(&a, 30, 6), top, "{m:?}");
            assert_eq!(a.mode, m);
        }
    }

    #[test]
    fn sidebar_keeps_the_current_category_visible() {
        let als: Vec<_> = (0..12)
            .map(|i| {
                alert(
                    "2026-11-10T10:11:12.000000+0000",
                    &format!("ET CAT{i:02} Probe"),
                    "allowed",
                    None,
                )
            })
            .collect();
        let mut a = app(als);
        for _ in 0..8 {
            press(&mut a, KeyCode::Tab);
        }
        let sel = a.category().to_string();
        let r = render(&a, 90, 6);
        assert!(r.iter().any(|l| l.contains(&sel)), "{sel} not visible");
        assert!(r[0].contains("Categories"));
    }

    #[test]
    fn scrolled_screens_do_not_panic_when_tiny() {
        for m in [Mode::Detail, Mode::Raw] {
            for (w, h) in [
                (40, 10),
                (20, 5),
                (20, 1),
                (1, 1),
                (0, 0),
                (5, 2),
                (200, 3),
                (20, 2),
                (3, 40),
            ] {
                let mut a = mode_app(m);
                render(&a, 100, 30);
                for c in [
                    KeyCode::Char('G'),
                    KeyCode::PageDown,
                    KeyCode::Char('j'),
                    KeyCode::PageUp,
                    KeyCode::Char('k'),
                ] {
                    press(&mut a, c);
                    render(&a, w, h);
                }
            }
        }
    }

    #[test]
    fn scrolled_text_is_still_cleaned() {
        let mut a = hostile_app();
        a.set_mode(Mode::Raw);
        render(&a, 20, 4);
        key(&mut a, 'G');
        assert_clean(&screen(&a, 20, 4));
    }

    #[test]
    fn help_mentions_scroll_keys() {
        let mut a = sample();
        a.mode = Mode::Help;
        assert!(screen(&a, 100, 24).contains("scroll (detail, rule, raw, help)"));
    }

    // ---- rules browser ----

    const RULES: &str = "\
alert tcp any any -> any any (msg:\"ET SCAN nmap probe\"; sid:2000001; rev:3;)
# alert tcp any any -> any any (msg:\"ET MALWARE bot beacon\"; sid:2000002; rev:1;)
alert tcp any any -> any any (msg:\"ET INFO plain thing\"; sid:2000003; rev:1;)
";

    fn rules_app() -> App {
        let mut a = app_with(
            vec![(Range::Today, vec![])],
            Some(crate::rules::RuleIndex::from_text(RULES)),
        );
        key(&mut a, '2');
        a
    }

    #[test]
    fn two_opens_the_rules_browser_with_states() {
        let a = rules_app();
        assert_eq!(a.mode, Mode::Rules);
        let s = screen(&a, 100, 12);
        assert!(s.contains("Rules  All  3 of 3"), "{s}");
        assert!(s.contains("2000002") && s.contains("OFF"), "{s}");
        assert!(s.contains("3 rules, 1 disabled"), "{s}");
    }

    #[test]
    fn two_without_rules_stays_put_and_says_why() {
        let mut a = app(vec![]);
        key(&mut a, '2');
        assert_eq!(a.mode, Mode::List);
        assert!(a.status.contains("no rules"));
    }

    #[test]
    fn typing_q_in_a_search_does_not_quit() {
        let mut a = rules_app();
        key(&mut a, '/');
        assert!(!crate::input::handle_key(
            &mut a,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)
        ));
        key(&mut a, 'x');
        assert_eq!(a.browser.as_ref().unwrap().query(), "qx");
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.browser.as_ref().unwrap().query(), "");
        assert_eq!(a.mode, Mode::Rules);
        // and q quits again once not searching
        assert!(crate::input::handle_key(
            &mut a,
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE)
        ));
    }

    #[test]
    fn search_and_state_filter_narrow_the_list() {
        let mut a = rules_app();
        key(&mut a, 's'); // disabled only
        let s = screen(&a, 100, 12);
        assert!(s.contains("[disabled only]") && s.contains("2000002"), "{s}");
        assert!(!s.contains("2000001"), "{s}");
        key(&mut a, 's');
        key(&mut a, 's'); // back to all
        key(&mut a, '/');
        for c in "nmap".chars() {
            key(&mut a, c);
        }
        press(&mut a, KeyCode::Enter);
        let s = screen(&a, 100, 12);
        assert!(s.contains("1 of 3") && s.contains("search: nmap"), "{s}");
    }

    #[test]
    fn enter_shows_the_rule_and_esc_returns_to_the_browser() {
        let mut a = rules_app();
        key(&mut a, 's'); // disabled only -> the malware rule
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::RuleInfo);
        let s = screen(&a, 100, 14);
        assert!(s.contains("DISABLED") && s.contains("bot beacon"), "{s}");
        assert!(s.contains("disabled in the rule source"), "{s}");
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, Mode::Rules);
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, Mode::List);
    }

    #[test]
    fn sources_need_local_mode() {
        let mut a = app(vec![]);
        key(&mut a, '3');
        assert_eq!(a.mode, Mode::List);
        assert!(a.status.contains("--local"));
    }

    #[test]
    fn sources_screen_renders_the_three_blocks() {
        let mut a = app(vec![]);
        a.sources = Some(crate::browser::build_sources(
            vec![],
            crate::browser::parse_sources(
                "Name: et/open\n  Summary: ET Open\n  License: MIT\nName: et/pro\n  License: Commercial\n  Parameters: secret-code\n",
            ),
        ));
        a.set_mode(Mode::Sources);
        let s = screen(&a, 100, 16);
        assert!(s.contains("falls back to et/open"), "{s}");
        assert!(s.contains("Free sources available (1)"), "{s}");
        assert!(s.contains("Need a key or subscription (1)"), "{s}");
    }

    #[test]
    fn new_screens_do_not_panic_when_tiny() {
        let mut a = rules_app();
        for (w, h) in [(1, 1), (5, 2), (20, 3)] {
            render(&a, w, h);
        }
        press(&mut a, KeyCode::Enter);
        for (w, h) in [(1, 1), (5, 2), (20, 3)] {
            render(&a, w, h);
        }
    }

    #[test]
    fn hint_changes_while_typing_a_search() {
        let mut a = rules_app();
        assert!(footer(&a, 100, 8).contains("/ search"));
        key(&mut a, '/');
        assert!(footer(&a, 100, 8).contains("Enter keeps it"));
    }

    // ---- changing rules (fake helper) ----

    use crate::admin::Verb;
    use crate::change::Admin;
    use crate::local::DisableConf;
    use crate::rules::RuleIndex;
    use std::sync::Arc;
    use std::time::Duration;

    struct FakeAdmin {
        available: bool,
        result: Result<Vec<String>, String>,
        delay_ms: u64,
        after: String,
        disable_sids: Vec<u64>,
    }

    impl Admin for FakeAdmin {
        fn available(&self) -> bool {
            self.available
        }
        fn change(&self, _v: Verb, _sid: u64) -> Result<Vec<String>, String> {
            std::thread::sleep(Duration::from_millis(self.delay_ms));
            self.result.clone()
        }
        fn reload(&self) -> Result<(RuleIndex, DisableConf), String> {
            let mut d = DisableConf::default();
            d.sids.extend(self.disable_sids.iter().copied());
            Ok((RuleIndex::from_text(&self.after), d))
        }
    }

    fn fake(result: Result<Vec<String>, String>, after: &str) -> Arc<FakeAdmin> {
        Arc::new(FakeAdmin {
            available: true,
            result,
            delay_ms: 0,
            after: after.to_string(),
            disable_sids: vec![2000001],
        })
    }

    /// Rules browser with the first rule (sid 2000001, enabled) opened.
    fn change_app(admin: Arc<FakeAdmin>) -> App {
        let mut a = rules_app();
        // the browser's disable.conf lists sid 2000002 only
        a.browser.as_mut().unwrap().disable.sids.insert(2000002);
        a.set_admin(admin);
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::RuleInfo);
        a
    }

    fn wait_done(a: &mut App) {
        for _ in 0..200 {
            a.poll_job();
            if a.job.is_none() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("job did not finish");
    }

    const AFTER_DISABLED: &str = "\
# alert tcp any any -> any any (msg:\"ET SCAN nmap probe\"; sid:2000001; rev:3;)
# alert tcp any any -> any any (msg:\"ET MALWARE bot beacon\"; sid:2000002; rev:1;)
alert tcp any any -> any any (msg:\"ET INFO plain thing\"; sid:2000003; rev:1;)
";

    #[test]
    fn d_asks_first_and_esc_cancels_without_a_job() {
        let mut a = change_app(fake(Ok(vec![]), AFTER_DISABLED));
        assert!(footer(&a, 100, 12).contains("d disable this rule"));
        key(&mut a, 'd');
        assert_eq!(a.mode, Mode::Confirm);
        let s = screen(&a, 100, 14);
        assert!(s.contains("Disable rule 2000001?") && s.contains("Press y to confirm"), "{s}");
        assert!(a.job.is_none());
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, Mode::RuleInfo);
        assert!(a.job.is_none() && a.pending.is_none());
    }

    #[test]
    fn nothing_but_y_starts_the_change() {
        let mut a = change_app(fake(Ok(vec![]), AFTER_DISABLED));
        key(&mut a, 'd');
        for c in ['d', 'e', 'x', ' '] {
            key(&mut a, c);
        }
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::Confirm);
        assert!(a.job.is_none());
    }

    #[test]
    fn confirmed_change_runs_refreshes_and_reports() {
        let mut a = change_app(fake(
            Ok(vec!["sid 2000001 disabled; Suricata reloaded".to_string()]),
            AFTER_DISABLED,
        ));
        key(&mut a, 'd');
        key(&mut a, 'y');
        assert_eq!(a.mode, Mode::Working);
        wait_done(&mut a);
        assert_eq!(a.mode, Mode::Done);
        let s = screen(&a, 100, 12);
        assert!(s.contains("Done") && s.contains("sid 2000001 disabled"), "{s}");
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::Rules);
        // the browser now shows the new state
        let b = a.browser.as_ref().unwrap();
        assert!(b.visible().iter().all(|e| !e.enabled || e.sid == 2000003));
        assert!(screen(&a, 100, 12).contains("3 rules, 2 disabled"));
    }

    #[test]
    fn failed_change_is_shown_and_state_is_kept() {
        let mut a = change_app(fake(Err("the rebuild failed (exit 1): boom".into()), AFTER_DISABLED));
        key(&mut a, 'd');
        key(&mut a, 'y');
        wait_done(&mut a);
        let s = screen(&a, 100, 12);
        assert!(s.contains("Failed") && s.contains("boom"), "{s}");
        press(&mut a, KeyCode::Enter);
        assert!(screen(&a, 100, 12).contains("3 rules, 1 disabled"));
    }

    #[test]
    fn keys_are_ignored_while_the_helper_works() {
        let mut a = change_app(Arc::new(FakeAdmin {
            available: true,
            result: Ok(vec![]),
            delay_ms: 300,
            after: AFTER_DISABLED.to_string(),
            disable_sids: vec![],
        }));
        key(&mut a, 'd');
        key(&mut a, 'y');
        assert_eq!(a.mode, Mode::Working);
        for c in ['q', 'y', 'n', 'j'] {
            assert!(!crate::input::handle_key(
                &mut a,
                KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE)
            ));
        }
        assert!(!crate::input::handle_key(
            &mut a,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
        ));
        assert_eq!(a.mode, Mode::Working);
        assert!(screen(&a, 100, 8).contains("do not close"));
        wait_done(&mut a);
        assert_eq!(a.mode, Mode::Done);
    }

    #[test]
    fn enable_explains_which_file_changes() {
        let mut a = change_app(fake(Ok(vec![]), AFTER_DISABLED));
        press(&mut a, KeyCode::Esc);
        key(&mut a, 's'); // disabled only -> sid 2000002, listed in disable.conf by the fixture
        press(&mut a, KeyCode::Enter);
        key(&mut a, 'e');
        assert_eq!(a.mode, Mode::Confirm);
        let s = screen(&a, 120, 12);
        assert!(s.contains("Enable rule 2000002?") && s.contains("removes the sid from disable.conf"), "{s}");
        press(&mut a, KeyCode::Esc);
        // a rule a group keeps off: not in disable.conf by sid -> enable.conf
        a.browser.as_mut().unwrap().disable.sids.clear();
        key(&mut a, 'e');
        assert_eq!(a.mode, Mode::Confirm, "{}", a.status);
        let s = screen(&a, 120, 12);
        assert!(s.contains("adds the sid to enable.conf"), "{s}");
    }

    #[test]
    fn wrong_direction_and_missing_helper_are_explained() {
        let mut a = change_app(fake(Ok(vec![]), AFTER_DISABLED));
        key(&mut a, 'e'); // rule is enabled already
        assert!(a.status.contains("already enabled"), "{}", a.status);
        let mut a = rules_app();
        press(&mut a, KeyCode::Enter);
        key(&mut a, 'd'); // remote mode: no helper object
        assert!(a.status.contains("only on the router"), "{}", a.status);
        let mut a = change_app(Arc::new(FakeAdmin {
            available: false,
            result: Ok(vec![]),
            delay_ms: 0,
            after: String::new(),
            disable_sids: vec![],
        }));
        key(&mut a, 'd');
        assert!(a.status.contains("not installed"), "{}", a.status);
        assert!(!footer(&a, 100, 12).contains("d disable"));
    }

    #[test]
    fn help_lists_the_change_keys() {
        let mut a = sample();
        a.mode = Mode::Help;
        let s = screen(&a, 100, 40);
        assert!(s.contains("disable / enable") && s.contains("confirm a change"), "{s}");
    }

    #[test]
    fn change_screens_do_not_show_alert_counts() {
        let mut a = change_app(fake(Ok(vec![]), AFTER_DISABLED));
        key(&mut a, 'd');
        let f = footer(&a, 100, 14);
        assert!(f.contains("3 rules") && !f.contains("alerts in this range"), "{f}");
        assert!(!screen(&change_app(fake(Ok(vec![]), AFTER_DISABLED)), 100, 12).contains("not built yet"));
    }

    #[test]
    fn enable_works_for_the_exact_line_the_helper_writes() {
        // browser disable.conf as parsed from the helper's own line
        let mut a = rules_app();
        a.browser.as_mut().unwrap().disable = crate::local::parse_disable_conf("2000002  # suritui 2026-11-12\n");
        a.set_admin(fake(Ok(vec![]), AFTER_DISABLED));
        key(&mut a, 's');
        press(&mut a, KeyCode::Enter);
        key(&mut a, 'e');
        assert_eq!(a.mode, Mode::Confirm, "{}", a.status);
    }

    // ---- d / e from other screens ----

    #[test]
    fn d_and_e_work_from_the_rules_list() {
        let mut a = rules_app();
        a.browser.as_mut().unwrap().disable.sids.insert(2000002);
        a.set_admin(fake(Ok(vec![]), AFTER_DISABLED));
        assert!(footer(&a, 100, 12).contains("d disable   e enable"));
        key(&mut a, 'd'); // highlighted row is sid 2000001, enabled
        assert_eq!(a.mode, Mode::Confirm);
        assert!(screen(&a, 120, 12).contains("Disable rule 2000001?"));
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, Mode::Rules, "Esc goes back where it started");
        key(&mut a, 'e'); // already enabled
        assert_eq!(a.mode, Mode::Rules);
        assert!(a.status.contains("already enabled"), "{}", a.status);
        key(&mut a, 'j'); // sid 2000002, disabled
        key(&mut a, 'e');
        assert_eq!(a.mode, Mode::Confirm);
        assert!(screen(&a, 120, 12).contains("Enable rule 2000002?"));
    }

    #[test]
    fn d_on_an_alert_disables_its_rule_and_returns_to_the_alerts() {
        let mut a = app_with(
            vec![(
                Range::Today,
                vec![alert("2026-11-10T10:11:12.000000+0000", "ET SCAN nmap probe", "allowed", None)],
            )],
            Some(crate::rules::RuleIndex::from_text(RULES)),
        );
        a.set_admin(fake(Ok(vec!["done".into()]), AFTER_DISABLED));
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::Detail);
        assert!(footer(&a, 120, 12).contains("d disable rule"));
        key(&mut a, 'd');
        assert_eq!(a.mode, Mode::Confirm);
        assert!(screen(&a, 120, 12).contains("Disable rule 2000001?"));
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, Mode::Detail);
        key(&mut a, 'r'); // the alert's rule view
        key(&mut a, 'd');
        assert_eq!(a.mode, Mode::Confirm);
        key(&mut a, 'y');
        wait_done(&mut a);
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::List, "back to the alerts");
    }

    #[test]
    fn d_on_an_alert_without_rules_or_helper_explains() {
        let mut a = app(vec![alert("2026-11-10T10:11:12.000000+0000", "ET SCAN x", "allowed", None)]);
        press(&mut a, KeyCode::Enter);
        key(&mut a, 'd');
        assert_eq!(a.mode, Mode::Detail);
        assert!(a.status.contains("no rules"), "{}", a.status);
    }

    // ---- Sources: switching free sources ----

    struct FakeSrc {
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl Admin for FakeSrc {
        fn available(&self) -> bool {
            true
        }
        fn change(&self, _v: Verb, _sid: u64) -> Result<Vec<String>, String> {
            Ok(vec![])
        }
        fn sources(&self, _refresh: bool) -> Result<Vec<String>, String> {
            Ok("Enabled sources:\n  - et/open\n=====index=====\nName: et/open\n  Summary: ET Open\n  License: MIT\nName: abuse.ch/urlhaus\n  Summary: URLhaus rules\n  License: CC0-1.0\nName: et/pro\n  License: Commercial\n  Parameters: secret-code\nName: snort-registered\n  Summary: Snort registered rules\n  License: Registered\n  Parameters: oinkcode\nName: odd/two\n  License: Commercial\n  Parameters: user, secret-code\n"
                .lines()
                .map(str::to_string)
                .collect())
        }
        fn source(&self, enable: bool, name: &str) -> Result<Vec<String>, String> {
            self.calls.lock().unwrap().push(format!("{enable} {name}"));
            Ok(vec!["rules updated".to_string()])
        }
        fn source_key(&self, name: &str, snapshot: Option<&str>, key: &str) -> Result<Vec<String>, String> {
            self.calls.lock().unwrap().push(format!("key {name} {snapshot:?} {key}"));
            Ok(vec!["rules updated".to_string()])
        }
        fn reload(&self) -> Result<(RuleIndex, DisableConf), String> {
            Ok((RuleIndex::from_text(RULES), DisableConf::default()))
        }
    }

    #[test]
    fn a_free_source_is_switched_on_after_a_confirm() {
        let mut a = rules_app();
        let fake = Arc::new(FakeSrc { calls: Default::default() });
        a.set_admin(fake.clone());
        press(&mut a, KeyCode::Esc);
        key(&mut a, '3');
        assert_eq!(a.mode, Mode::Sources);
        let s = screen(&a, 110, 20);
        assert!(s.contains("Free sources available (1)") && s.contains("Need a key or subscription (3)"), "{s}");
        // et/open (enabled) is highlighted first: e says it is already on, d asks.
        key(&mut a, 'e');
        assert_eq!(a.mode, Mode::Sources);
        assert!(a.status.contains("already enabled"), "{}", a.status);
        assert!(screen(&a, 110, 20).contains("rule sources | this source is already enabled"));
        key(&mut a, 'j');
        key(&mut a, 'e');
        assert_eq!(a.mode, Mode::Confirm);
        let s = screen(&a, 110, 20);
        assert!(s.contains("Switch on the source abuse.ch/urlhaus?"), "{s}");
        key(&mut a, 'y');
        for _ in 0..200 {
            a.poll_job();
            if a.mode == Mode::Done {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(a.mode, Mode::Done);
        assert_eq!(*fake.calls.lock().unwrap(), vec!["true abuse.ch/urlhaus".to_string()]);
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::Sources);
    }

    fn type_text(a: &mut App, t: &str) {
        for c in t.chars() {
            key(a, c);
        }
    }

    #[test]
    fn a_key_is_typed_masked_confirmed_and_sent_without_being_shown() {
        let mut a = rules_app();
        let fake = Arc::new(FakeSrc { calls: Default::default() });
        a.set_admin(fake.clone());
        press(&mut a, KeyCode::Esc);
        key(&mut a, '3');
        // enabled: et/open; free: urlhaus-less list has none but et/open is enabled; keyed: et/pro, snort, odd/two
        let items: Vec<String> = a.source_items().iter().map(|(s, _)| s.name.clone()).collect();
        let pro = items.iter().position(|n| n == "et/pro").unwrap();
        for _ in 0..pro {
            key(&mut a, 'j');
        }
        key(&mut a, 'e');
        assert_eq!(a.mode, Mode::KeyEntry);
        type_text(&mut a, "bad");
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::KeyEntry);
        assert!(a.status.contains("8 to 128"), "{}", a.status);
        type_text(&mut a, "SECRETKEY123");
        let s = screen(&a, 100, 16);
        assert!(s.contains("Code for et/pro") && s.contains("***************"), "{s}");
        assert!(!s.contains("SECRETKEY"), "{s}");
        assert!(!format!("{:?}", a.key_entry).contains("SECRET"));
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::Confirm);
        let s = screen(&a, 110, 20);
        assert!(s.contains("Store the code and switch on et/pro?") && !s.contains("SECRETKEY"), "{s}");
        assert!(!format!("{:?}", a.pending).contains("SECRET"));
        key(&mut a, 'y');
        for _ in 0..200 {
            a.poll_job();
            if a.mode == Mode::Done {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(a.mode, Mode::Done);
        assert_eq!(*fake.calls.lock().unwrap(), vec!["key et/pro None badSECRETKEY123".to_string()]);
        assert!(a.key_entry.is_none());
    }

    #[test]
    fn snort_asks_for_the_snapshot_first_and_odd_sources_are_refused() {
        let mut a = rules_app();
        a.set_admin(Arc::new(FakeSrc { calls: Default::default() }));
        press(&mut a, KeyCode::Esc);
        key(&mut a, '3');
        let items: Vec<String> = a.source_items().iter().map(|(s, _)| s.name.clone()).collect();
        let snort = items.iter().position(|n| n == "snort-registered").unwrap();
        for _ in 0..snort {
            key(&mut a, 'j');
        }
        key(&mut a, 'e');
        assert_eq!(a.mode, Mode::KeyEntry);
        type_text(&mut a, "29200");
        press(&mut a, KeyCode::Enter); // next field
        type_text(&mut a, "0123456789abcdef");
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, Mode::Sources);
        assert!(a.key_entry.is_none());
        let odd = items.iter().position(|n| n == "odd/two").unwrap();
        for _ in snort..odd {
            key(&mut a, 'j');
        }
        key(&mut a, 'e');
        assert_eq!(a.mode, Mode::Sources);
        assert!(a.status.contains("by hand"), "{}", a.status);
    }

    // ---- Updates screen ----

    struct FakeUpd {
        info_calls: std::sync::atomic::AtomicUsize,
        update_result: Result<Vec<String>, String>,
    }

    impl Admin for FakeUpd {
        fn available(&self) -> bool {
            true
        }
        fn change(&self, _v: Verb, _sid: u64) -> Result<Vec<String>, String> {
            Ok(vec![])
        }
        fn update(&self) -> Result<Vec<String>, String> {
            self.update_result.clone()
        }
        fn info(&self) -> Result<Vec<String>, String> {
            let n = self.info_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            Ok(vec![format!("Suricata: running (reading {n})"), "Update running now: no".to_string()])
        }
        fn reload(&self) -> Result<(RuleIndex, DisableConf), String> {
            Ok((RuleIndex::from_text(RULES), DisableConf::default()))
        }
    }

    fn upd_app(result: Result<Vec<String>, String>) -> App {
        let mut a = rules_app();
        a.set_admin(Arc::new(FakeUpd {
            info_calls: std::sync::atomic::AtomicUsize::new(0),
            update_result: result,
        }));
        press(&mut a, KeyCode::Esc); // back to the alerts list
        a
    }

    #[test]
    fn four_opens_updates_and_needs_local_mode() {
        let mut a = app(vec![]);
        key(&mut a, '4');
        assert_eq!(a.mode, Mode::List);
        assert!(a.status.contains("--local"), "{}", a.status);
        let mut a = upd_app(Ok(vec![]));
        key(&mut a, '4');
        assert_eq!(a.mode, Mode::Updates);
        let s = screen(&a, 100, 10);
        assert!(s.contains("Updates and status") && s.contains("Suricata: running (reading 1)"), "{s}");
        assert!(footer(&a, 100, 10).contains("U update now"));
        key(&mut a, 'R');
        assert!(screen(&a, 100, 10).contains("reading 2"));
        key(&mut a, '2');
        assert_eq!(a.mode, Mode::Rules);
        key(&mut a, '4');
        assert_eq!(a.mode, Mode::Updates);
        key(&mut a, '1');
        assert_eq!(a.mode, Mode::List);
    }

    #[test]
    fn u_asks_then_updates_and_comes_back_with_fresh_status() {
        let mut a = upd_app(Ok(vec!["rules updated: 3 added, 1 removed, 2 changed; Suricata reloaded".into()]));
        key(&mut a, '4');
        key(&mut a, 'U');
        assert_eq!(a.mode, Mode::Confirm);
        let s = screen(&a, 120, 14);
        assert!(s.contains("Update the rules now?") && s.contains("Press y to confirm"), "{s}");
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, Mode::Updates, "Esc goes back to the Updates screen");
        key(&mut a, 'U');
        key(&mut a, 'y');
        assert_eq!(a.mode, Mode::Working);
        assert!(screen(&a, 100, 8).contains("updating the rules"));
        wait_done(&mut a);
        assert!(screen(&a, 100, 10).contains("3 added, 1 removed"));
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::Updates);
        assert!(screen(&a, 100, 10).contains("reading 2"), "the status is read again after an update");
    }

    #[test]
    fn a_failed_update_is_reported() {
        let mut a = upd_app(Err("the update has 5 rules but 69,367 are loaded now".into()));
        key(&mut a, '4');
        key(&mut a, 'U');
        key(&mut a, 'y');
        wait_done(&mut a);
        let s = screen(&a, 100, 10);
        assert!(s.contains("Failed") && s.contains("5 rules"), "{s}");
    }

    #[test]
    fn help_lists_the_updates_keys() {
        let mut a = sample();
        a.mode = Mode::Help;
        let s = screen(&a, 100, 40);
        assert!(s.contains("updates") && s.contains("update the rules now"), "{s}");
    }

    // ---- suppress entries ----

    use crate::threshold::{parse_entries, ThresholdEntry, Track};

    struct FakeThr {
        entries: std::sync::Mutex<Vec<ThresholdEntry>>,
        calls: std::sync::Mutex<Vec<String>>,
    }

    impl Admin for FakeThr {
        fn available(&self) -> bool {
            true
        }
        fn change(&self, _v: Verb, _sid: u64) -> Result<Vec<String>, String> {
            Ok(vec![])
        }
        fn suppress(&self, add: bool, sid: u64, track: Track, ip: &str) -> Result<Vec<String>, String> {
            self.calls.lock().unwrap().push(format!("{add} {sid} {} {ip}", track.word()));
            let line = crate::threshold::suppress_line(sid, track, ip);
            let mut e = self.entries.lock().unwrap();
            if add {
                e.extend(parse_entries(&line));
            } else {
                e.retain(|x| x.line != line);
            }
            Ok(vec![format!("done {add}")])
        }
        fn thresholds(&self) -> Vec<ThresholdEntry> {
            self.entries.lock().unwrap().clone()
        }
        fn reload(&self) -> Result<(RuleIndex, DisableConf), String> {
            Ok((RuleIndex::from_text(RULES), DisableConf::default()))
        }
    }

    fn thr_app(entries: &str) -> (App, Arc<FakeThr>) {
        let mut al = alert("2026-11-10T10:11:12.000000+0000", "ET SCAN nmap probe", "allowed", None);
        al.raw = r#"{"event_type":"alert","src_ip":"192.0.2.5","dest_ip":"198.51.100.7"}"#.to_string();
        let mut a = app_with(
            vec![(Range::Today, vec![al])],
            Some(crate::rules::RuleIndex::from_text(RULES)),
        );
        let f = Arc::new(FakeThr {
            entries: std::sync::Mutex::new(parse_entries(entries)),
            calls: std::sync::Mutex::new(vec![]),
        });
        a.set_admin(f.clone());
        (a, f)
    }

    #[test]
    fn s_on_an_alert_silences_the_rule_for_its_source() {
        let (mut a, f) = thr_app("");
        press(&mut a, KeyCode::Enter);
        assert!(footer(&a, 140, 12).contains("s silence src"));
        key(&mut a, 's');
        assert_eq!(a.mode, Mode::Confirm);
        let s = screen(&a, 140, 14);
        assert!(s.contains("Silence rule 2000001 for source 192.0.2.5?") && s.contains("stays active for"), "{s}");
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, Mode::Detail);
        key(&mut a, 'S');
        assert!(screen(&a, 140, 14).contains("for destination 198.51.100.7?"));
        key(&mut a, 'y');
        wait_done(&mut a);
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::List);
        assert_eq!(f.calls.lock().unwrap().as_slice(), ["true 2000001 by_dst 198.51.100.7"]);
    }

    #[test]
    fn alerts_without_an_address_or_helper_explain_themselves() {
        let (mut a, _f) = thr_app("");
        a.set_mode(Mode::List);
        // an alert whose raw JSON has no addresses
        let mut b = app_with(
            vec![(Range::Today, vec![alert("2026-11-10T10:11:12.000000+0000", "ET SCAN x", "allowed", None)])],
            Some(crate::rules::RuleIndex::from_text(RULES)),
        );
        b.set_admin(Arc::new(FakeThr { entries: Default::default(), calls: Default::default() }));
        press(&mut b, KeyCode::Enter);
        key(&mut b, 's');
        assert_eq!(b.mode, Mode::Detail);
        assert!(b.status.contains("no usable address"), "{}", b.status);
        let mut c = app(vec![alert("2026-11-10T10:11:12.000000+0000", "ET SCAN x", "allowed", None)]);
        press(&mut c, KeyCode::Enter);
        key(&mut c, 's');
        assert_eq!(c.mode, Mode::Detail);
    }

    #[test]
    fn the_suppress_list_shows_entries_and_removes_only_ours() {
        let (mut a, f) = thr_app(
            "suppress gen_id 1, sig_id 2000001, track by_src, ip 192.0.2.5\nthreshold gen_id 1, sig_id 8, type limit, track by_src, count 1, seconds 60\n",
        );
        key(&mut a, '5');
        assert_eq!(a.mode, Mode::Thresholds);
        let s = screen(&a, 120, 10);
        assert!(s.contains("2 in threshold.config") && s.contains("sig_id 2000001") && s.contains("(edit by hand)"), "{s}");
        key(&mut a, 'j');
        key(&mut a, 'x'); // the hand-written threshold line
        assert_eq!(a.mode, Mode::Thresholds);
        assert!(a.status.contains("by hand"), "{}", a.status);
        key(&mut a, 'k');
        key(&mut a, 'x');
        assert_eq!(a.mode, Mode::Confirm);
        assert!(screen(&a, 140, 12).contains("Remove the suppress entry for rule 2000001?"));
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, Mode::Thresholds);
        key(&mut a, 'x');
        key(&mut a, 'y');
        wait_done(&mut a);
        press(&mut a, KeyCode::Enter);
        assert_eq!(a.mode, Mode::Thresholds, "back on the list, which is read again");
        assert!(!screen(&a, 120, 10).contains("sig_id 2000001"));
        assert_eq!(f.calls.lock().unwrap().as_slice(), ["false 2000001 by_src 192.0.2.5"]);
    }

    #[test]
    fn five_needs_local_mode_and_empty_list_explains() {
        let mut a = app(vec![]);
        key(&mut a, '5');
        assert_eq!(a.mode, Mode::List);
        assert!(a.status.contains("--local"), "{}", a.status);
        let (mut a, _f) = thr_app("");
        key(&mut a, '5');
        assert!(screen(&a, 140, 8).contains("No entries"));
        key(&mut a, '1');
        assert_eq!(a.mode, Mode::List);
    }

    #[test]
    fn help_lists_the_suppress_keys() {
        let mut a = sample();
        a.mode = Mode::Help;
        let s = screen(&a, 110, 44);
        assert!(s.contains("silence the rule") && s.contains("suppress list"), "{s}");
    }

    // ---- settings and logs ----

    struct FakeLogs {
        bodies: Vec<(&'static str, Result<Vec<String>, String>)>,
    }

    impl Admin for FakeLogs {
        fn available(&self) -> bool {
            true
        }
        fn change(&self, _v: Verb, _sid: u64) -> Result<Vec<String>, String> {
            Ok(vec![])
        }
        fn settings(&self) -> Vec<String> {
            vec!["Config file: /x/suricata.yaml   (read-only: edit it by hand)".into(), "  HOME_NET      [10.0.0.0/8]".into()]
        }
        fn log(&self, name: &str) -> Result<Vec<String>, String> {
            self.bodies.iter().find(|(n, _)| *n == name).map(|(_, r)| r.clone()).unwrap()
        }
        fn reload(&self) -> Result<(RuleIndex, DisableConf), String> {
            Ok((RuleIndex::from_text(RULES), DisableConf::default()))
        }
    }

    fn logs_app() -> App {
        let long: Vec<String> = (0..100).map(|i| format!("suricata log line {i}")).collect();
        let mut a = app(vec![]);
        a.set_admin(Arc::new(FakeLogs {
            bodies: vec![("suricata", Ok(long)), ("update", Ok(vec![])), ("admin", Err("permission denied".into()))],
        }));
        a
    }

    #[test]
    fn six_shows_the_read_only_settings() {
        let mut a = logs_app();
        key(&mut a, '6');
        assert_eq!(a.mode, Mode::Settings);
        let s = screen(&a, 100, 8);
        assert!(s.contains("Settings (suricata.yaml, read-only)") && s.contains("HOME_NET      [10.0.0.0/8]"), "{s}");
        key(&mut a, '1');
        assert_eq!(a.mode, Mode::List);
        let mut b = app(vec![]);
        key(&mut b, '6');
        assert_eq!(b.mode, Mode::List);
        assert!(b.status.contains("--local"), "{}", b.status);
    }

    #[test]
    fn seven_opens_the_log_at_its_end_and_tab_cycles() {
        let mut a = logs_app();
        key(&mut a, '7');
        assert_eq!(a.mode, Mode::Logs);
        let s = screen(&a, 100, 8);
        assert!(s.contains("Log: suricata (1 of 3") && s.contains("suricata log line 99"), "{s}");
        assert!(!s.contains("suricata log line 0\n"), "{s}");
        assert!(footer(&a, 100, 8).contains("lines"), "scroll indicator shows the position");
        key(&mut a, 'g');
        assert!(screen(&a, 100, 8).contains("suricata log line 0"));
        press(&mut a, KeyCode::Tab);
        assert!(screen(&a, 100, 8).contains("Log: update (2 of 3") && screen(&a, 100, 8).contains("The update log is empty."));
        press(&mut a, KeyCode::Tab);
        assert!(screen(&a, 100, 8).contains("Cannot read the admin log: permission denied"));
        press(&mut a, KeyCode::Tab);
        assert!(screen(&a, 100, 8).contains("Log: suricata (1 of 3"));
        key(&mut a, '6');
        assert_eq!(a.mode, Mode::Settings);
        key(&mut a, '7');
        assert_eq!(a.mode, Mode::Logs);
        press(&mut a, KeyCode::Esc);
        assert_eq!(a.mode, Mode::List);
    }

    #[test]
    fn log_text_is_cleaned_of_terminal_escapes() {
        let mut a = app(vec![]);
        a.set_admin(Arc::new(FakeLogs {
            bodies: vec![
                ("suricata", Ok(vec!["evil \u{1b}[31mred\u{1b}[0m text".to_string()])),
                ("update", Ok(vec![])),
                ("admin", Ok(vec![])),
            ],
        }));
        key(&mut a, '7');
        let s = screen(&a, 100, 6);
        assert!(!s.contains('\u{1b}'), "{s:?}");
    }

    #[test]
    fn help_lists_settings_and_logs() {
        let mut a = sample();
        a.mode = Mode::Help;
        let s = screen(&a, 110, 50);
        assert!(s.contains("settings (read-only) / logs"), "{s}");
    }
}
