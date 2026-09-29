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

use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::time::Duration;

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

use crate::HostOutcome;
use state::{App, OnDemand, OnDemandJob, OnDemandResult, Screen};

/// How long to wait for input before checking the result channel again.
const POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Whether a keypress handled by the export overlay should end the session.
#[derive(Debug, PartialEq, Eq)]
enum PromptKey {
    Handled,
    Quit,
}

/// Applies one keypress to the open export overlay.
///
/// Split out of the event loop so it is testable without a terminal: the
/// modifier handling here is easy to get wrong and impossible to exercise
/// through `run`.
fn handle_export_key(app: &mut App, key: event::KeyEvent) -> PromptKey {
    // Chords are matched before the catch-all `Char(c)` arm, which would
    // otherwise insert their letter into the filename — `Ctrl+D` appending a
    // literal `d`. SHIFT is deliberately not a chord modifier: it is how
    // capitals arrive.
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let chord = key
        .modifiers
        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);

    match key.code {
        KeyCode::Char('c') if ctrl => return PromptKey::Quit,
        KeyCode::Char('u') if ctrl => app.export_input_clear(),
        KeyCode::Char('w') if ctrl => app.export_input_delete_word(),
        KeyCode::Esc => app.cancel_export(),
        // Only a successful write closes the overlay; a failure leaves the
        // typed path in place to edit.
        KeyCode::Enter => app.commit_export(),
        KeyCode::Backspace => app.export_input_pop(),
        KeyCode::Char(c) if !chord => app.export_input_push(c),
        _ => {}
    }
    PromptKey::Handled
}

/// Runs an on-demand check on its own thread and sends back the result.
///
/// The thread is named like the check workers, so a panic in it is handled
/// the same way: the dashboard's hook leaves the terminal alone, and the
/// panic becomes an `Unknown` result instead of a host stuck "checking…".
fn spawn_on_demand(job: OnDemandJob, tx: Sender<(usize, OnDemandResult)>) {
    let (index, kind) = (job.index(), job.kind());
    let fail_tx = tx.clone();
    let spawned = std::thread::Builder::new()
        .name(crate::WORKER_THREAD_NAME.to_string())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job.run()))
                .unwrap_or_else(|payload| {
                    OnDemandJob::failed(index, kind, crate::panic_message(payload.as_ref()))
                });
            // A closed receiver means the dashboard is gone; nothing to do.
            let _ = tx.send(result);
        });
    if let Err(err) = spawned {
        let _ = fail_tx.send(OnDemandJob::failed(index, kind, &err.to_string()));
    }
}

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
    // Worker panics are caught and rendered as failed rows (`spawn_checks`),
    // but the hook runs before unwinding: ratatui's would tear the terminal
    // down while the dashboard keeps drawing. Only a panic elsewhere is fatal.
    let ratatui_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if !crate::is_worker_thread() {
            ratatui_hook(info);
        }
    }));
    let mut app = App::new(labels);
    let mut channel_open = true;
    // Results of checks started from the dashboard (`r` / `c`).
    let (check_tx, check_rx) = std::sync::mpsc::channel::<(usize, OnDemandResult)>();
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

            while let Ok((index, result)) = check_rx.try_recv() {
                app.finish_check(index, result);
                dirty = true;
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
                    // While the overlay is open it captures all input, so this
                    // runs before the per-`Screen` dispatch below.
                    if app.export_prompt.is_some() {
                        if handle_export_key(&mut app, key) == PromptKey::Quit {
                            break;
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

                        // Run a check the command line did not ask for (or
                        // retry an Unknown one) for the selected host.
                        (_, KeyCode::Char('r')) => {
                            if let Some(job) = app.begin_check(OnDemand::Revocation) {
                                spawn_on_demand(job, check_tx.clone());
                            }
                        }
                        (_, KeyCode::Char('c')) => {
                            if let Some(job) = app.begin_check(OnDemand::Ct) {
                                spawn_on_demand(job, check_tx.clone());
                            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::make_test_tls;
    use ratatui::crossterm::event::KeyEvent;

    fn app_with_prompt() -> App {
        let mut app = App::new(&["example.com".to_string()]);
        app.record(0, HostOutcome::Checked(Box::new(make_test_tls())));
        app.begin_export();
        app
    }

    fn press(app: &mut App, code: KeyCode, modifiers: KeyModifiers) -> PromptKey {
        handle_export_key(app, KeyEvent::new(code, modifiers))
    }

    fn path(app: &App) -> String {
        app.export_prompt.as_ref().unwrap().path.clone()
    }

    #[test]
    fn test_prompt_ignores_modifier_chords() {
        let mut app = app_with_prompt();
        let before = path(&app);

        // Ctrl/Alt chords must not fall through to the text-insert arm.
        for code in ['d', 'a', 'e', 'k', 'n'] {
            press(&mut app, KeyCode::Char(code), KeyModifiers::CONTROL);
            press(&mut app, KeyCode::Char(code), KeyModifiers::ALT);
        }
        assert_eq!(path(&app), before, "chords must not type into the path");
        assert!(
            app.export_prompt.is_some(),
            "and must not close the overlay"
        );
    }

    #[test]
    fn test_prompt_accepts_plain_and_shifted_characters() {
        let mut app = app_with_prompt();
        app.export_input_clear();

        press(&mut app, KeyCode::Char('a'), KeyModifiers::NONE);
        // Capitals arrive with SHIFT set, which must still be typed.
        press(&mut app, KeyCode::Char('B'), KeyModifiers::SHIFT);
        press(&mut app, KeyCode::Char('.'), KeyModifiers::NONE);
        assert_eq!(path(&app), "aB.");

        press(&mut app, KeyCode::Backspace, KeyModifiers::NONE);
        assert_eq!(path(&app), "aB");
    }

    #[test]
    fn test_on_demand_revocation_runs_off_thread_and_reports_back() {
        use openssl::x509::{X509Builder, X509NameBuilder};
        use openssl::{asn1::Asn1Time, hash::MessageDigest, pkey::PKey, rsa::Rsa};

        // A self-signed cert without OCSP/CRL endpoints: the check completes
        // offline, with the reason it could not reach a verdict.
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "offline.example").unwrap();
        let name = name.build();
        let mut b = X509Builder::new().unwrap();
        b.set_version(2).unwrap();
        b.set_subject_name(&name).unwrap();
        b.set_issuer_name(&name).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        b.set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        let pem = String::from_utf8(b.build().to_pem().unwrap()).unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        spawn_on_demand(OnDemandJob::Revocation { index: 7, pem }, tx);
        let (index, result) = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("the worker reports back");

        assert_eq!(index, 7);
        assert!(matches!(
            result,
            OnDemandResult::Revocation(tlschecker::RevocationStatus::Unknown, Some(ref d))
                if d == "OCSP: certificate lists no OCSP responder; \
                         CRL: certificate lists no CRL distribution point"
        ));
    }

    #[test]
    fn test_prompt_control_keys() {
        let mut app = app_with_prompt();

        // Ctrl+C quits from inside the overlay.
        assert_eq!(
            press(&mut app, KeyCode::Char('c'), KeyModifiers::CONTROL),
            PromptKey::Quit
        );

        // Ctrl+U clears, Ctrl+W drops a segment.
        let mut app = app_with_prompt();
        app.export_input_clear();
        for c in "out/a.pem".chars() {
            press(&mut app, KeyCode::Char(c), KeyModifiers::NONE);
        }
        press(&mut app, KeyCode::Char('w'), KeyModifiers::CONTROL);
        assert_eq!(path(&app), "out/");
        press(&mut app, KeyCode::Char('u'), KeyModifiers::CONTROL);
        assert_eq!(path(&app), "");

        // Esc cancels without writing.
        press(&mut app, KeyCode::Esc, KeyModifiers::NONE);
        assert!(app.export_prompt.is_none());
    }
}
