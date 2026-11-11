//! Rendering: sidebar, list, detail, rule, raw and help screens.

use crate::alert::Alert;
use crate::model::{App, Mode, RuleView};
use crate::source::Range;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};
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
        Mode::Help => draw_help(f, body),
    }
    let hint = if app.mode == Mode::List {
        "  ? help"
    } else {
        "  Esc back"
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::raw(clean(&app.status_line())),
            Span::styled(hint, Style::default().add_modifier(Modifier::DIM)),
        ])),
        status,
    );
}

fn draw_sidebar(f: &mut Frame, app: &App, area: Rect) {
    let w = area.width as usize;
    let mut lines = vec![Line::from(Span::styled(
        fit("Categories", w),
        header_style(),
    ))];
    for (label, n) in app.categories() {
        let count = n.to_string();
        let lw = w.saturating_sub(count.chars().count() + 1);
        let text = format!("{} {}", fit(&label, lw), count);
        let style = if label == app.category() {
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

fn screen(f: &mut Frame, area: Rect, title: &str, mut lines: Vec<Line<'static>>) {
    lines.insert(
        0,
        Line::from(Span::styled(title.to_string(), header_style())),
    );
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn draw_detail(f: &mut Frame, app: &App, area: Rect) {
    let Some(a) = app.selected() else {
        return screen(f, area, "Alert", vec![Line::from("No alert selected.")]);
    };
    let opt = |v: Option<String>| v.unwrap_or_else(|| "-".to_string());
    let mut lines = vec![
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
    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        "Esc back   r rule text   w raw JSON",
        Style::default().add_modifier(Modifier::DIM),
    )));
    screen(f, area, "Alert", lines);
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
    screen(f, area, "Rule", lines);
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
    screen(f, area, "Raw JSON", lines);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let keys = [
        ("Tab / Shift-Tab", "next / previous category"),
        ("j k, Down Up", "move in the list"),
        ("g G, Home End", "first / last row"),
        ("PgUp PgDn", "move 20 rows"),
        ("Enter", "alert detail"),
        ("Esc", "back to the list"),
        ("i", "show / hide informational alerts"),
        ("[ ]", "older / newer day"),
        ("r", "rule text (from detail)"),
        ("w", "raw JSON (from detail)"),
        ("R", "refresh"),
        ("?", "this help"),
        ("q, Ctrl-C", "quit"),
    ];
    let lines = keys
        .iter()
        .map(|(k, d)| field_wide(k, d))
        .collect::<Vec<_>>();
    screen(f, area, "Help", lines);
}

fn field_wide(k: &str, d: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!("{k:<18}"),
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
        let s = screen(&a, 100, 24);
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
}
