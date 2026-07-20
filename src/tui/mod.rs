//! Interactive terminal dashboard — the default output on a TTY.
//!
//! Hosts stream in live from the worker pool: the left pane lists every host
//! with a verdict symbol and grade, the right pane shows the selected host's
//! detail (expiry lifetime gauge, grade breakdown, warnings). Piped stdout or
//! an explicit `-o`/config `output` bypasses this entirely (see
//! `use_dashboard` in `main.rs`), so scripts keep the classic formatters.
//!
//! While the dashboard owns the terminal, tracing output is discarded via the
//! `TUI_ACTIVE` flag so log lines cannot corrupt the alternate screen.
//! `ratatui::init` installs a panic hook that restores the terminal, so even a
//! crash leaves the shell usable.

mod state;
mod view;

use std::sync::mpsc::{Receiver, TryRecvError};
use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

use crate::HostOutcome;
use state::{App, Screen};

/// How long to wait for input before checking the result channel again.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Runs the dashboard until the user quits, collecting outcomes as they
/// stream in over `rx`.
///
/// Returns the outcomes in input order; hosts still pending when the user
/// quits remain `None` (the caller treats those as "not checked", not as
/// failures).
pub fn run(
    labels: &[String],
    rx: Receiver<(usize, HostOutcome)>,
) -> std::io::Result<Vec<Option<HostOutcome>>> {
    let mut terminal = ratatui::init();
    let mut app = App::new(labels);
    let mut channel_open = true;
    let mut dirty = true;

    // Run the loop inside a closure so that an I/O error propagated by `?`
    // still falls through to `ratatui::restore()` below — otherwise an early
    // return would leave the terminal in raw mode / the alternate screen.
    let result = (|| {
        loop {
            // Drain any results that arrived since the last frame.
            while channel_open {
                match rx.try_recv() {
                    Ok((index, outcome)) => {
                        app.record(index, outcome);
                        dirty = true;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => channel_open = false,
                }
            }

            if dirty {
                terminal.draw(|frame| view::draw(frame, &app))?;
                dirty = false;
            }

            if !event::poll(POLL_INTERVAL)? {
                continue;
            }
            match event::read()? {
                // Accept `Repeat` as well as `Press` so held keys scroll smoothly.
                Event::Key(key)
                    if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat =>
                {
                    // The last scroll offset that still shows a full page (loose
                    // clamp: at least one line remains visible).
                    let scroll_max = {
                        let page = terminal.size().map(|s| s.height as usize).unwrap_or(24);
                        view::detail_line_count(&app).saturating_sub(page.saturating_sub(3))
                    };
                    dirty = true;
                    // If we are in export prompting mode, handle text input first.
                    if app.export_prompt.is_some() {
                        match key.code {
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                break;
                            }
                            KeyCode::Esc => app.cancel_export(),
                            // Only a successful write closes the overlay; a
                            // failure leaves the typed path in place to edit.
                            KeyCode::Enter => app.commit_export(),
                            KeyCode::Backspace => app.export_input_pop(),
                            KeyCode::Char(c) => app.export_input_push(c),
                            _ => {}
                        }
                        dirty = true;
                        continue;
                    }

                    // Clear any flash message on keypress. Remember that we did:
                    // the fallthrough arm below cancels the redraw for unhandled
                    // keys, which would otherwise leave the cleared message on
                    // screen until the next key that does redraw.
                    let had_flash = app.flash.is_some();
                    if had_flash {
                        app.clear_flash();
                    }

                    match (app.screen, key.code) {
                        // Quit from anywhere; Esc only quits from the fleet view.
                        (_, KeyCode::Char('c'))
                            if key.modifiers.contains(KeyModifiers::CONTROL) =>
                        {
                            break
                        }
                        (_, KeyCode::Char('q')) | (Screen::Fleet, KeyCode::Esc) => break,

                        // Start export prompt from anywhere
                        (_, KeyCode::Char('e')) => {
                            app.begin_export();
                            dirty = true;
                        }

                        // Fleet: move selection, open the explorer.
                        (Screen::Fleet, KeyCode::Char('j') | KeyCode::Down) => app.select_next(),
                        (Screen::Fleet, KeyCode::Char('k') | KeyCode::Up) => app.select_prev(),
                        (Screen::Fleet, KeyCode::Char('g') | KeyCode::Home) => app.select_first(),
                        (Screen::Fleet, KeyCode::Char('G') | KeyCode::End) => app.select_last(),
                        (Screen::Fleet, KeyCode::Enter) => app.open_detail(),

                        // Explorer: scroll, page, and go back.
                        (Screen::Detail, KeyCode::Char('j') | KeyCode::Down) => {
                            app.scroll_down(1, scroll_max)
                        }
                        (Screen::Detail, KeyCode::Char('k') | KeyCode::Up) => app.scroll_up(1),
                        (Screen::Detail, KeyCode::PageDown | KeyCode::Char(' ')) => {
                            app.scroll_down(10, scroll_max)
                        }
                        (Screen::Detail, KeyCode::PageUp) => app.scroll_up(10),
                        (Screen::Detail, KeyCode::Char('g') | KeyCode::Home) => {
                            app.detail_scroll = 0
                        }
                        (Screen::Detail, KeyCode::Char('G') | KeyCode::End) => {
                            app.detail_scroll = scroll_max
                        }
                        (Screen::Detail, KeyCode::Esc | KeyCode::Enter | KeyCode::Backspace) => {
                            app.close_detail()
                        }
                        _ => dirty = had_flash,
                    }
                }
                Event::Resize(_, _) => dirty = true,
                _ => {}
            }
        }
        Ok(app.into_outcomes())
    })();

    ratatui::restore();
    result
}
