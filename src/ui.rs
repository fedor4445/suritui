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
fn fit(s: &str, w: usize) -> String {
    let mut out: String = s.chars().take(w).collect();
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
            Span::raw(app.status_line()),
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
        let cell: String = text.chars().take(left).collect();
        left -= cell.chars().count();
        spans.push(Span::styled(cell, style));
    };
    let action_blocked = a.action != "allowed";
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
    Line::from(vec![
        Span::styled(
            format!("{name:<12}"),
            Style::default().add_modifier(Modifier::DIM),
        ),
        Span::raw(value.to_string()),
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
        field("Action", &a.action),
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
        field("Context", &opt(a.context.clone())),
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
                    w,
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::default());
            }
            lines.push(Line::from(text));
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
    let lines = text.lines().map(|l| Line::from(l.to_string())).collect();
    screen(f, area, "Raw JSON", lines);
}

fn draw_help(f: &mut Frame, area: Rect) {
    let keys = [
        ("Tab / Shift-Tab", "next / previous category"),
        ("j k, Down Up", "move in the list"),
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
        let s = screen(&a, 120, 20);
        assert!(s.contains("blocked"));
        assert!(!s.contains("allowed"));
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
        let s = screen(&a, 100, 20);
        assert!(s.contains("ET SCAN Probe"));
        assert!(s.contains("2000001"));
        assert!(s.contains("192.0.2.1:1"));
        assert!(s.contains("w raw JSON"));
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
}
