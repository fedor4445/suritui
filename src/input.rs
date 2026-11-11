//! Key handling: maps key events onto model transitions.

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
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        return key.code == KeyCode::Char('c');
    }
    if key.modifiers.contains(KeyModifiers::ALT) {
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
        (m, KeyCode::Char('j') | KeyCode::Down) if m.scrolls() => app.scroll_lines(1),
        (m, KeyCode::Char('k') | KeyCode::Up) if m.scrolls() => app.scroll_lines(-1),
        (m, KeyCode::PageDown) if m.scrolls() => app.scroll_page(1),
        (m, KeyCode::PageUp) if m.scrolls() => app.scroll_page(-1),
        (m, KeyCode::Char('g') | KeyCode::Home) if m.scrolls() => app.scroll_to_top(),
        (m, KeyCode::Char('G') | KeyCode::End) if m.scrolls() => app.scroll_to_bottom(),
        (Mode::Detail, KeyCode::Char('r')) => app.set_mode(Mode::Rule),
        (Mode::Detail, KeyCode::Char('w')) => app.set_mode(Mode::Raw),
        (Mode::Detail | Mode::Rule | Mode::Raw | Mode::Help, KeyCode::Esc) => {
            app.set_mode(Mode::List)
        }
        _ => {}
    }
    false
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
