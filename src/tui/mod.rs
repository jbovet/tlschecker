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
use state::App;

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
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Char('q') | KeyCode::Esc => break,
                KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                KeyCode::Char('j') | KeyCode::Down => {
                    app.select_next();
                    dirty = true;
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    app.select_prev();
                    dirty = true;
                }
                KeyCode::Char('g') | KeyCode::Home => {
                    app.select_first();
                    dirty = true;
                }
                KeyCode::Char('G') | KeyCode::End => {
                    app.select_last();
                    dirty = true;
                }
                _ => {}
            },
            Event::Resize(_, _) => dirty = true,
            _ => {}
        }
    }

    ratatui::restore();
    Ok(app.into_outcomes())
}
