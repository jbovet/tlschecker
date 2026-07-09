//! Pure rendering for the dashboard: `draw` paints an [`App`] onto a frame.
//!
//! Every function here takes `&App` and draws into a `Frame`, with no I/O or
//! state mutation, so the whole view is testable with `TestBackend`.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Gauge, LineGauge, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use tlschecker::TLS;

use super::state::{verdict, App, Verdict};
use crate::{warning_label, HostOutcome};

const DIM: Style = Style::new().fg(Color::DarkGray);

fn verdict_color(verdict: Verdict) -> Color {
    match verdict {
        Verdict::Healthy => Color::Green,
        Verdict::Warning => Color::Yellow,
        Verdict::Critical => Color::Red,
    }
}

fn verdict_symbol(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Healthy => "✓",
        Verdict::Warning => "⚠",
        Verdict::Critical => "✗",
    }
}

/// Renders the whole dashboard.
pub fn draw(frame: &mut Frame, app: &App) {
    let [header, main, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    draw_header(frame, app, header);

    let [left, right] =
        Layout::horizontal([Constraint::Length(36), Constraint::Min(40)]).areas(main);
    draw_host_list(frame, app, left);
    draw_detail(frame, app, right);

    frame.render_widget(
        Line::from(" j/k move · g/G first/last · q quit").style(DIM),
        footer,
    );
}

/// Header: progress gauge while checks are running, plain title when done.
fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let done = app.done();
    let total = app.total();
    if done < total {
        let gauge = Gauge::default()
            .ratio(done as f64 / total.max(1) as f64)
            .label(format!("tlschecker — {}/{} checked", done, total))
            .gauge_style(Style::new().fg(Color::Cyan).bg(Color::Black));
        frame.render_widget(gauge, area);
    } else {
        frame.render_widget(
            Line::from(format!(" tlschecker — {} hosts checked", total))
                .style(Style::new().add_modifier(Modifier::BOLD)),
            area,
        );
    }
}

/// One list row: state symbol + label + grade letter.
fn host_row(app: &App, index: usize) -> Line<'_> {
    let label = app.labels[index].as_str();
    match &app.slots[index] {
        None => Line::from(vec![
            Span::styled("⋯ ", DIM),
            Span::styled(label, DIM),
        ]),
        Some(HostOutcome::Failed { kind, .. }) => Line::from(vec![
            Span::styled("✗ ", Style::new().fg(Color::Red)),
            Span::raw(label),
            Span::styled(format!("  ({})", kind), Style::new().fg(Color::Red)),
        ]),
        Some(HostOutcome::Checked(tls)) => {
            let v = verdict(tls);
            let color = verdict_color(v);
            let grade = tls
                .grade
                .as_ref()
                .map(|g| format!("  {}", g.grade))
                .unwrap_or_default();
            Line::from(vec![
                Span::styled(format!("{} ", verdict_symbol(v)), Style::new().fg(color)),
                Span::raw(label),
                Span::styled(grade, Style::new().fg(color).add_modifier(Modifier::BOLD)),
            ])
        }
    }
}

fn draw_host_list(frame: &mut Frame, app: &App, area: Rect) {
    let [list_area, tally_area] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(6)]).areas(area);

    let items: Vec<ListItem> = (0..app.total()).map(|i| ListItem::new(host_row(app, i))).collect();
    let list = List::new(items)
        .block(Block::bordered().title(" Hosts "))
        .highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    let mut list_state = ListState::default().with_selected(Some(app.selected));
    frame.render_stateful_widget(list, list_area, &mut list_state);

    let tally = app.tally();
    let mut lines = vec![
        Line::from(vec![
            Span::styled("  ✓ ", Style::new().fg(Color::Green)),
            Span::raw(format!("{} healthy", tally.healthy)),
        ]),
        Line::from(vec![
            Span::styled("  ⚠ ", Style::new().fg(Color::Yellow)),
            Span::raw(format!("{} warning", tally.warning)),
        ]),
        Line::from(vec![
            Span::styled("  ✗ ", Style::new().fg(Color::Red)),
            Span::raw(format!(
                "{} critical · {} failed",
                tally.critical, tally.failed
            )),
        ]),
    ];
    if tally.pending > 0 {
        lines.push(Line::from(Span::styled(
            format!("  ⋯ {} pending", tally.pending),
            DIM,
        )));
    }
    frame.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" Tally ")),
        tally_area,
    );
}

/// Right pane: detail for the selected host.
fn draw_detail(frame: &mut Frame, app: &App, area: Rect) {
    let label = app.labels.get(app.selected).cloned().unwrap_or_default();
    match app.slots.get(app.selected).and_then(|s| s.as_ref()) {
        None => {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled("⋯ checking…", DIM)))
                    .block(Block::bordered().title(format!(" {} ", label))),
                area,
            );
        }
        Some(HostOutcome::Failed { kind, detail }) => {
            let lines = vec![
                Line::from(Span::styled(
                    format!("✗ Could not check ({})", kind),
                    Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
                )),
                Line::default(),
                Line::from(detail.as_str()),
            ];
            frame.render_widget(
                Paragraph::new(lines)
                    .wrap(Wrap { trim: true })
                    .block(Block::bordered().title(format!(" {} ", label))),
                area,
            );
        }
        Some(HostOutcome::Checked(tls)) => draw_checked_detail(frame, tls, &label, area),
    }
}

/// Human-friendly "time until expiry" for the detail pane.
fn expiry_text(tls: &TLS) -> String {
    let days = tls.certificate.validity_days;
    if days < 0 {
        format!("expired {}d ago · {}", -days, tls.certificate.valid_to)
    } else if days == 0 {
        let hours = tls.certificate.validity_hours.max(0);
        format!("expires in {}h · {}", hours, tls.certificate.valid_to)
    } else {
        format!("expires in {}d · {}", days, tls.certificate.valid_to)
    }
}

/// Fraction of the certificate's lifetime already consumed (0.0–1.0).
fn lifetime_consumed(tls: &TLS) -> f64 {
    let from = tls.certificate.valid_from_unix;
    let to = tls.certificate.valid_to_unix;
    if to <= from {
        return 1.0; // unknown or degenerate; render as fully consumed
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    ((now - from) as f64 / (to - from) as f64).clamp(0.0, 1.0)
}

fn draw_checked_detail(frame: &mut Frame, tls: &TLS, label: &str, area: Rect) {
    let v = verdict(tls);
    let color = verdict_color(v);
    let cert = &tls.certificate;

    let block = Block::bordered().title(format!(" {} ", label)).title(
        Line::from(format!(" {} {:?} ", verdict_symbol(v), v)).style(
            Style::new().fg(color).add_modifier(Modifier::BOLD),
        )
        .right_aligned(),
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let grade_rows = tls
        .grade
        .as_ref()
        .map(|g| g.categories.len() as u16 + 1)
        .unwrap_or(0);
    let [info_area, gauge_area, grade_area, warn_area] = Layout::vertical([
        Constraint::Length(5),
        Constraint::Length(1),
        Constraint::Length(grade_rows),
        Constraint::Min(0),
    ])
    .areas(inner);

    // Basic facts.
    let info = vec![
        Line::from(vec![
            Span::styled("Protocol  ", DIM),
            Span::raw(format!("{} · {}", tls.cipher.version, tls.cipher.name)),
        ]),
        Line::from(vec![
            Span::styled("Issuer    ", DIM),
            Span::raw(format!(
                "{} ({})",
                cert.issued.organization, cert.issued.common_name
            )),
        ]),
        Line::from(vec![
            Span::styled("Key       ", DIM),
            Span::raw(format!(
                "{} {}-bit · {}",
                cert.cert_key_algorithm, cert.cert_key_bits, cert.cert_alg
            )),
        ]),
        Line::from(vec![
            Span::styled("Revocation", DIM),
            Span::raw(format!(" {:?}", cert.revocation_status)),
        ]),
        Line::from(vec![
            Span::styled("SHA-256   ", DIM),
            Span::raw(cert.cert_sha256.clone()),
        ]),
    ];
    frame.render_widget(Paragraph::new(info), info_area);

    // Lifetime gauge: how much of notBefore→notAfter has elapsed.
    let gauge = LineGauge::default()
        .ratio(lifetime_consumed(tls))
        .label(expiry_text(tls))
        .filled_style(Style::new().fg(color))
        .unfilled_style(DIM);
    frame.render_widget(gauge, gauge_area);

    // Grade breakdown, one mini-gauge per category.
    if let Some(grade) = &tls.grade {
        let mut constraints = vec![Constraint::Length(1); grade.categories.len() + 1];
        constraints[0] = Constraint::Length(1);
        let rows = Layout::vertical(constraints).split(grade_area);
        frame.render_widget(
            Line::from(format!("Grade {} ({}/100)", grade.grade, grade.score)).style(
                Style::new().fg(color).add_modifier(Modifier::BOLD),
            ),
            rows[0],
        );
        for (i, cat) in grade.categories.iter().enumerate() {
            let cat_gauge = LineGauge::default()
                .ratio(f64::from(cat.score) / 100.0)
                .label(format!("{:<22} {:>3}", cat.category, cat.score))
                .filled_style(Style::new().fg(score_color(cat.score)))
                .unfilled_style(DIM);
            frame.render_widget(cat_gauge, rows[i + 1]);
        }
    }

    // Warnings.
    if !cert.security_warnings.is_empty() {
        let mut lines = vec![Line::from(Span::styled(
            "Warnings",
            Style::new()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ))];
        for warning in &cert.security_warnings {
            let (kind, msg) = warning_label(warning);
            lines.push(Line::from(vec![
                Span::styled(format!("⚠ {}: ", kind), Style::new().fg(Color::Yellow)),
                Span::raw(msg.to_string()),
            ]));
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), warn_area);
    }
}

fn score_color(score: u8) -> Color {
    match score {
        80..=100 => Color::Green,
        50..=79 => Color::Yellow,
        _ => Color::Red,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::make_test_tls;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    /// Renders the app into a test buffer and returns its text content.
    fn render(app: &App) -> String {
        let backend = TestBackend::new(110, 32);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        buffer.content().iter().map(|cell| cell.symbol()).collect()
    }

    fn app_with(outcomes: Vec<(usize, HostOutcome)>, labels: &[&str]) -> App {
        let labels: Vec<String> = labels.iter().map(|s| s.to_string()).collect();
        let mut app = App::new(&labels);
        for (index, outcome) in outcomes {
            app.record(index, outcome);
        }
        app
    }

    #[test]
    fn test_draw_pending_and_progress() {
        let app = app_with(vec![], &["example.com", "other.example"]);
        let content = render(&app);
        assert!(content.contains("0/2 checked"));
        assert!(content.contains("example.com"));
        assert!(content.contains("checking"));
        assert!(content.contains("2 pending"));
    }

    #[test]
    fn test_draw_checked_host_shows_grade_and_facts() {
        let mut tls = make_test_tls();
        tls.grade = Some(tlschecker::grading::TLSGrade {
            grade: "A+".to_string(),
            score: 97,
            categories: vec![tlschecker::grading::CategoryScore {
                category: "Protocol Version".to_string(),
                score: 100,
                reason: "TLS 1.3".to_string(),
            }],
        });
        let app = app_with(
            vec![(0, HostOutcome::Checked(Box::new(tls)))],
            &["test.example.com"],
        );
        let content = render(&app);
        assert!(content.contains("1 hosts checked"));
        assert!(content.contains("test.example.com"));
        assert!(content.contains("Grade A+ (97/100)"));
        assert!(content.contains("Protocol Version"));
        assert!(content.contains("TLSv1.3"));
        assert!(content.contains("1 healthy"));
        assert!(content.contains("Healthy"));
    }

    #[test]
    fn test_draw_failed_host() {
        let app = app_with(
            vec![(
                0,
                HostOutcome::Failed {
                    kind: "DNS",
                    detail: "no such host".to_string(),
                },
            )],
            &["nope.invalid"],
        );
        let content = render(&app);
        assert!(content.contains("nope.invalid"));
        assert!(content.contains("(DNS)"));
        assert!(content.contains("Could not check (DNS)"));
        assert!(content.contains("no such host"));
        assert!(content.contains("1 failed"));
    }

    #[test]
    fn test_draw_warning_host_shows_warnings() {
        let mut tls = make_test_tls();
        tls.certificate
            .security_warnings
            .push(tlschecker::SecurityWarning::HostnameMismatch(
                "not valid for host".to_string(),
            ));
        let app = app_with(
            vec![(0, HostOutcome::Checked(Box::new(tls)))],
            &["wrong.example"],
        );
        let content = render(&app);
        assert!(content.contains("HOSTNAME MISMATCH"));
        assert!(content.contains("1 warning"));
    }
}
