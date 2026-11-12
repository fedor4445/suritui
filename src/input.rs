//! Key handling: maps key events onto model transitions.

use crate::admin::Verb;
use crate::threshold::Track;
use crate::model::{App, Mode};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// Returns true when the program should quit.
///
/// Keys that do not apply in the current mode do nothing. Everything that
/// would change the underlying list (category, day, selection, toggle,
/// refresh) works only in the list view, so a detail/rule/raw/help screen
/// never shows data that has shifted under it.
pub fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    if key.kind == KeyEventKind::Release {
        return false;
    }
    // While the helper works nothing is accepted: quitting now would leave
    // a half-finished change behind.
    if app.mode == Mode::Working {
        return false;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return key.code == KeyCode::Char('c');
    }
    if key.modifiers.contains(KeyModifiers::ALT) {
        return false;
    }
    if app.mode == Mode::Rules && app.browser.as_ref().is_some_and(|b| b.editing) {
        search_key(app, key.code);
        return false;
    }
    if app.mode == Mode::KeyEntry {
        match key.code {
            KeyCode::Char(c) => app.key_char(c),
            KeyCode::Backspace => app.key_backspace(),
            KeyCode::Tab | KeyCode::Down => app.key_next(),
            KeyCode::Enter => app.key_submit(),
            KeyCode::Esc => app.key_cancel(),
            _ => {}
        }
        return false;
    }
    if key.code == KeyCode::Char('q') {
        return true;
    }
    match (app.mode, key.code) {
        (Mode::List, KeyCode::Tab) => app.next_category(),
        (Mode::List, KeyCode::BackTab) => app.prev_category(),
        (Mode::List, KeyCode::Char('j') | KeyCode::Down) => app.move_selection(1),
        (Mode::List, KeyCode::Char('k') | KeyCode::Up) => app.move_selection(-1),
        (Mode::List, KeyCode::Char('g') | KeyCode::Home) => app.move_selection(i32::MIN),
        (Mode::List, KeyCode::Char('G') | KeyCode::End) => app.move_selection(i32::MAX),
        (Mode::List, KeyCode::PageUp) => app.move_selection(-20),
        (Mode::List, KeyCode::PageDown) => app.move_selection(20),
        (Mode::List, KeyCode::Enter) => {
            if app.selected().is_some() {
                app.set_mode(Mode::Detail);
            }
        }
        (Mode::List, KeyCode::Char('i')) => app.toggle_informational(),
        (Mode::List, KeyCode::Char('[')) => app.change_day(1),
        (Mode::List, KeyCode::Char(']')) => app.change_day(-1),
        (Mode::List, KeyCode::Char('R')) => app.refresh(),
        (Mode::List, KeyCode::Char('?')) => app.set_mode(Mode::Help),
        (Mode::List, KeyCode::Char('2')) => app.open_rules(),
        (Mode::List, KeyCode::Char('3')) => app.open_sources(),
        (Mode::List | Mode::Rules | Mode::Sources | Mode::Updates | Mode::Settings | Mode::Logs, KeyCode::Char('4')) => {
            app.open_updates()
        }
        (Mode::List | Mode::Rules | Mode::Sources | Mode::Updates | Mode::Thresholds | Mode::Settings | Mode::Logs, KeyCode::Char('6')) => {
            app.open_settings()
        }
        (Mode::List | Mode::Rules | Mode::Sources | Mode::Updates | Mode::Thresholds | Mode::Settings | Mode::Logs, KeyCode::Char('7')) => {
            app.open_logs()
        }
        (Mode::Settings | Mode::Logs, KeyCode::Char('1')) => app.set_mode(Mode::List),
        (Mode::Settings | Mode::Logs, KeyCode::Char('2')) => app.open_rules(),
        (Mode::Settings, KeyCode::Char('R')) => app.reload_settings(),
        (Mode::Logs, KeyCode::Char('R')) => {
            app.load_logs();
            app.scroll_to_bottom();
        }
        (Mode::Logs, KeyCode::Tab) => app.next_log(),
        (Mode::List | Mode::Rules | Mode::Sources | Mode::Updates | Mode::Settings | Mode::Logs, KeyCode::Char('5')) => app.open_thresholds(),
        (Mode::Thresholds, KeyCode::Char('1')) => app.set_mode(Mode::List),
        (Mode::Thresholds, KeyCode::Char('2')) => app.open_rules(),
        (Mode::Thresholds, KeyCode::Char('4')) => app.open_updates(),
        (Mode::Thresholds, KeyCode::Char('j') | KeyCode::Down) => app.move_threshold(1),
        (Mode::Thresholds, KeyCode::Char('k') | KeyCode::Up) => app.move_threshold(-1),
        (Mode::Thresholds, KeyCode::Char('x')) => app.request_unsuppress(),
        (Mode::Thresholds, KeyCode::Char('R')) => app.load_thresholds(),
        (Mode::Detail | Mode::Rule, KeyCode::Char('s')) => app.request_suppress_for_alert(Track::BySrc),
        (Mode::Detail | Mode::Rule, KeyCode::Char('S')) => app.request_suppress_for_alert(Track::ByDst),
        (Mode::Updates, KeyCode::Char('1')) => app.set_mode(Mode::List),
        (Mode::Updates, KeyCode::Char('2')) => app.open_rules(),
        (Mode::Updates, KeyCode::Char('3')) => app.open_sources(),
        (Mode::Updates, KeyCode::Char('R')) => app.load_updates(),
        (Mode::Updates, KeyCode::Char('U')) => app.request_update(),
        (Mode::Rules | Mode::Sources, KeyCode::Char('1')) => app.set_mode(Mode::List),
        (Mode::Rules, KeyCode::Char('3')) => app.open_sources(),
        (Mode::Sources, KeyCode::Char('2')) => app.open_rules(),
        (Mode::Sources, KeyCode::Char('R')) => app.reload_sources(),
        (Mode::Sources, KeyCode::Char('j') | KeyCode::Down) => app.move_source(1),
        (Mode::Sources, KeyCode::Char('k') | KeyCode::Up) => app.move_source(-1),
        (Mode::Sources, KeyCode::Char('g') | KeyCode::Home) => app.move_source(i32::MIN),
        (Mode::Sources, KeyCode::Char('G') | KeyCode::End) => app.move_source(i32::MAX),
        (Mode::Sources, KeyCode::Char('e')) => app.request_source_change(true),
        (Mode::Sources, KeyCode::Char('d')) => app.request_source_change(false),
        (Mode::Rules, code) => rules_key(app, code),
        (Mode::Detail | Mode::Rule, KeyCode::Char('d')) => app.request_change_for_alert(Verb::Disable),
        (Mode::RuleInfo, KeyCode::Char('d')) => app.request_change(Verb::Disable),
        (Mode::RuleInfo, KeyCode::Char('e')) => app.request_change(Verb::Enable),
        (Mode::Confirm, KeyCode::Char('y')) => app.confirm_change(),
        (Mode::Confirm, KeyCode::Esc | KeyCode::Char('n')) => app.cancel_change(),
        (Mode::Done, KeyCode::Enter | KeyCode::Esc) => app.dismiss_outcome(),
        (m, KeyCode::Char('j') | KeyCode::Down) if m.scrolls() => app.scroll_lines(1),
        (m, KeyCode::Char('k') | KeyCode::Up) if m.scrolls() => app.scroll_lines(-1),
        (m, KeyCode::PageDown) if m.scrolls() => app.scroll_page(1),
        (m, KeyCode::PageUp) if m.scrolls() => app.scroll_page(-1),
        (m, KeyCode::Char('g') | KeyCode::Home) if m.scrolls() => app.scroll_to_top(),
        (m, KeyCode::Char('G') | KeyCode::End) if m.scrolls() => app.scroll_to_bottom(),
        (Mode::Detail, KeyCode::Char('r')) => app.set_mode(Mode::Rule),
        (Mode::Detail, KeyCode::Char('w')) => app.set_mode(Mode::Raw),
        (Mode::Detail | Mode::Rule | Mode::Raw | Mode::Help | Mode::Sources | Mode::Updates | Mode::Thresholds | Mode::Settings | Mode::Logs, KeyCode::Esc) => {
            app.set_mode(Mode::List)
        }
        (Mode::RuleInfo, KeyCode::Esc) => app.set_mode(Mode::Rules),
        _ => {}
    }
    false
}

/// Keys of the Rules browser (not while typing a search).
fn rules_key(app: &mut App, code: KeyCode) {
    if code == KeyCode::Enter {
        if app.browser.as_ref().is_some_and(|b| b.selected().is_some()) {
            app.set_mode(Mode::RuleInfo);
        }
        return;
    }
    if code == KeyCode::Esc {
        app.set_mode(Mode::List);
        return;
    }
    if code == KeyCode::Char('d') {
        return app.request_change(Verb::Disable);
    }
    if code == KeyCode::Char('e') {
        return app.request_change(Verb::Enable);
    }
    let Some(b) = app.browser.as_mut() else { return };
    match code {
        KeyCode::Tab => b.next_category(),
        KeyCode::BackTab => b.prev_category(),
        KeyCode::Char('j') | KeyCode::Down => b.move_selection(1),
        KeyCode::Char('k') | KeyCode::Up => b.move_selection(-1),
        KeyCode::Char('g') | KeyCode::Home => b.move_selection(i32::MIN),
        KeyCode::Char('G') | KeyCode::End => b.move_selection(i32::MAX),
        KeyCode::PageUp => b.move_selection(-20),
        KeyCode::PageDown => b.move_selection(20),
        KeyCode::Char('/') => b.start_search(),
        KeyCode::Char('s') => b.cycle_filter(),
        KeyCode::Char('c') => b.clear_search(),
        _ => {}
    }
}

/// Keys while a search is being typed: everything is text except these.
fn search_key(app: &mut App, code: KeyCode) {
    let Some(b) = app.browser.as_mut() else { return };
    match code {
        KeyCode::Esc => b.clear_search(),
        KeyCode::Enter => b.finish_search(),
        KeyCode::Backspace => b.backspace(),
        KeyCode::Char(c) => b.type_char(c),
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Mode;
    use crate::source::Range;
    use crate::testutil::*;
    use ratatui::crossterm::event::{KeyCode, KeyModifiers};

    fn k(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }
    fn ch(c: char) -> KeyEvent {
        k(KeyCode::Char(c))
    }

    fn two_cats() -> App {
        app(vec![
            alert(
                "2026-11-10T10:00:00.000000+0000",
                "ET SCAN a",
                "allowed",
                None,
            ),
            alert(
                "2026-11-10T09:00:00.000000+0000",
                "ET DNS b",
                "allowed",
                Some("Informational"),
            ),
            alert(
                "2026-11-10T08:00:00.000000+0000",
                "ET DNS c",
                "allowed",
                None,
            ),
        ])
    }

    #[test]
    fn keys_drive_model() {
        let mut a = two_cats();
        let n0 = a.categories().len();
        assert!(n0 >= 3);
        assert!(!handle_key(&mut a, k(KeyCode::Tab)));
        assert_ne!(a.visible().len(), 3);
        handle_key(&mut a, k(KeyCode::BackTab));
        assert_eq!(a.visible().len(), 3);
        handle_key(&mut a, ch('i'));
        assert!(a.hide_informational);
        assert_eq!(a.visible().len(), 2);
        handle_key(&mut a, ch('j'));
        assert_eq!(a.selected_index(), 1);
        handle_key(&mut a, ch('k'));
        assert_eq!(a.selected_index(), 0);
        handle_key(&mut a, k(KeyCode::Enter));
        assert_eq!(a.mode, Mode::Detail);
        handle_key(&mut a, k(KeyCode::Esc));
        assert_eq!(a.mode, Mode::List);
        handle_key(&mut a, ch('?'));
        assert_eq!(a.mode, Mode::Help);
        handle_key(&mut a, k(KeyCode::Esc));
        assert_eq!(a.mode, Mode::List);
        assert!(handle_key(&mut a, ch('q')));
        assert!(handle_key(
            &mut a,
            KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
        ));
    }

    #[test]
    fn bracket_keys_change_day() {
        let mut a = app_with(
            vec![
                (
                    Range::Today,
                    vec![alert(
                        "2026-11-10T10:00:00.000000+0000",
                        "ET A x",
                        "allowed",
                        None,
                    )],
                ),
                (Range::Day(0), vec![]),
                (Range::Day(1), vec![]),
            ],
            None,
        );
        handle_key(&mut a, ch('['));
        assert_eq!(a.range, Range::Day(0));
        handle_key(&mut a, ch('['));
        assert_eq!(a.range, Range::Day(1));
        handle_key(&mut a, ch(']'));
        assert_eq!(a.range, Range::Day(0));
    }

    #[test]
    fn keys_that_do_not_apply_do_nothing() {
        let mut a = two_cats();
        // Enter on a list works, r/w from List do nothing.
        handle_key(&mut a, ch('r'));
        handle_key(&mut a, ch('w'));
        assert_eq!(a.mode, Mode::List);
        handle_key(&mut a, k(KeyCode::Enter));
        assert_eq!(a.mode, Mode::Detail);
        let (idx, range, vis) = (a.selected_index(), a.range, a.visible().len());
        for key in [
            k(KeyCode::Tab),
            k(KeyCode::BackTab),
            ch('j'),
            ch('k'),
            k(KeyCode::Down),
            k(KeyCode::Up),
            ch('i'),
            ch('['),
            ch(']'),
            ch('R'),
            ch('?'),
            k(KeyCode::Enter),
        ] {
            assert!(!handle_key(&mut a, key));
            assert_eq!(a.mode, Mode::Detail);
            assert_eq!(a.selected_index(), idx);
            assert_eq!(a.range, range);
            assert_eq!(a.visible().len(), vis);
            assert!(!a.hide_informational);
        }
        handle_key(&mut a, ch('r'));
        assert_eq!(a.mode, Mode::Rule);
        handle_key(&mut a, ch('w'));
        assert_eq!(a.mode, Mode::Rule);
        handle_key(&mut a, k(KeyCode::Esc));
        handle_key(&mut a, k(KeyCode::Enter));
        handle_key(&mut a, ch('w'));
        assert_eq!(a.mode, Mode::Raw);
        handle_key(&mut a, k(KeyCode::Esc));
        assert_eq!(a.mode, Mode::List);
    }

    fn many(n: usize) -> App {
        app((0..n)
            .map(|i| {
                alert(
                    &format!("2026-11-10T10:{:02}:00.000000+0000", 59 - (i % 60)),
                    &format!("ET SCAN r{i}"),
                    "allowed",
                    None,
                )
            })
            .collect())
    }

    #[test]
    fn paging_keys_jump_in_list() {
        let mut a = many(50);
        handle_key(&mut a, ch('G'));
        assert_eq!(a.selected_index(), 49);
        handle_key(&mut a, ch('g'));
        assert_eq!(a.selected_index(), 0);
        handle_key(&mut a, k(KeyCode::End));
        assert_eq!(a.selected_index(), 49);
        handle_key(&mut a, k(KeyCode::Home));
        assert_eq!(a.selected_index(), 0);
        handle_key(&mut a, k(KeyCode::PageDown));
        assert_eq!(a.selected_index(), 20);
        handle_key(&mut a, k(KeyCode::PageDown));
        handle_key(&mut a, k(KeyCode::PageDown));
        assert_eq!(a.selected_index(), 49);
        handle_key(&mut a, k(KeyCode::PageUp));
        assert_eq!(a.selected_index(), 29);
        handle_key(&mut a, k(KeyCode::PageUp));
        handle_key(&mut a, k(KeyCode::PageUp));
        assert_eq!(a.selected_index(), 0);
    }

    #[test]
    fn paging_keys_on_empty_list_and_outside_list_do_nothing() {
        let mut e = app(vec![]);
        for key in [ch('g'), ch('G'), k(KeyCode::Home), k(KeyCode::End)] {
            handle_key(&mut e, key);
            assert_eq!(e.selected_index(), 0);
        }
        let mut a = many(50);
        handle_key(&mut a, k(KeyCode::Enter));
        for key in [
            ch('G'),
            k(KeyCode::End),
            k(KeyCode::PageDown),
            k(KeyCode::PageUp),
        ] {
            handle_key(&mut a, key);
            assert_eq!(a.selected_index(), 0);
        }
    }

    #[test]
    fn enter_on_empty_list_does_nothing() {
        let mut a = app(vec![]);
        handle_key(&mut a, k(KeyCode::Enter));
        assert_eq!(a.mode, Mode::List);
        handle_key(&mut a, k(KeyCode::Tab));
        handle_key(&mut a, ch('j'));
    }

    #[test]
    fn release_events_and_modified_keys_are_ignored() {
        let mut a = two_cats();
        let mut ev = ch('i');
        ev.kind = ratatui::crossterm::event::KeyEventKind::Release;
        handle_key(&mut a, ev);
        assert!(!a.hide_informational);
        handle_key(
            &mut a,
            KeyEvent::new(KeyCode::Char('i'), KeyModifiers::CONTROL),
        );
        assert!(!a.hide_informational);
    }
}
