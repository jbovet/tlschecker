//! Pure rendering for the dashboard: `draw` paints an [`App`] onto a frame.
//!
//! Every function here takes `&App` and draws into a `Frame`, with no I/O or
//! state mutation, so the whole view is testable with `TestBackend`.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Clear, Gauge, LineGauge, List, ListItem, ListState, Paragraph, Wrap,
};
use ratatui::Frame;

use tlschecker::TLS;

use super::state::{verdict, App, Screen, Verdict};
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
    match app.screen {
        Screen::Fleet => draw_fleet(frame, app),
        Screen::Detail => draw_explorer(frame, app),
    }

    if let Some(prompt) = &app.export_prompt {
        draw_export_prompt(frame, prompt);
    }
}

/// Fleet overview: host list + compact detail pane.
fn draw_fleet(frame: &mut Frame, app: &App) {
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

    draw_footer(
        frame,
        app,
        " j/k move · ⏎ explore · e export · g/G first/last · q quit",
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
        None => Line::from(vec![Span::styled("⋯ ", DIM), Span::styled(label, DIM)]),
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

    let items: Vec<ListItem> = (0..app.total())
        .map(|i| ListItem::new(host_row(app, i)))
        .collect();
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
    // `from == 0` is the fallback `asn1_time_to_unix` returns on a parse
    // failure; `to <= from` covers `to == 0` and any inverted/degenerate range.
    if from == 0 || to <= from {
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
        Line::from(format!(" {} {:?} ", verdict_symbol(v), v))
            .style(Style::new().fg(color).add_modifier(Modifier::BOLD))
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
        Constraint::Length(6),
        Constraint::Length(1),
        Constraint::Length(grade_rows),
        Constraint::Min(0),
    ])
    .areas(inner);

    // Trust is always computed; show it red when the chain doesn't verify.
    let (trust_text, trust_style) = match &cert.trust {
        tlschecker::TrustStatus::Trusted => ("trusted".to_string(), Style::new().fg(Color::Green)),
        tlschecker::TrustStatus::Untrusted { reason } => (
            format!("untrusted · {}", reason),
            Style::new().fg(Color::Red),
        ),
        tlschecker::TrustStatus::Unknown => ("unknown".to_string(), DIM),
    };

    // Basic facts.
    let info = vec![
        Line::from(vec![
            Span::styled("Protocol  ", DIM),
            Span::raw(match &tls.cipher.alpn {
                Some(alpn) => format!("{} · {} · {}", tls.cipher.version, tls.cipher.name, alpn),
                None => format!("{} · {}", tls.cipher.version, tls.cipher.name),
            }),
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
            Span::styled("Trust     ", DIM),
            Span::styled(trust_text, trust_style),
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
            Line::from(format!("Grade {} ({}/100)", grade.grade, grade.score))
                .style(Style::new().fg(color).add_modifier(Modifier::BOLD)),
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
            Style::new().fg(Color::Yellow).add_modifier(Modifier::BOLD),
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

/// Section heading for the explorer.
fn section(title: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("── {} ", title),
        Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    ))
}

/// Key/value line for the explorer ("None" values are dimmed).
fn kv(key: &str, value: impl Into<String>) -> Line<'static> {
    let value = value.into();
    let value_style = if value == "None" || value.is_empty() {
        DIM
    } else {
        Style::new()
    };
    Line::from(vec![
        Span::styled(format!("  {:<22}", key), DIM),
        Span::styled(value, value_style),
    ])
}

/// Builds the full certificate report shown by the explorer.
///
/// Pure content: rendering applies the scroll offset, so this is also the
/// source of truth for the maximum scroll position (`detail_line_count`).
fn detail_lines(app: &App) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    match app.slots.get(app.selected).and_then(|s| s.as_ref()) {
        None => lines.push(Line::from(Span::styled("⋯ checking…", DIM))),
        Some(HostOutcome::Failed { kind, detail }) => {
            lines.push(Line::from(Span::styled(
                format!("✗ Could not check ({})", kind),
                Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::default());
            lines.push(Line::from(detail.clone()));
        }
        Some(HostOutcome::Checked(tls)) => {
            let cert = &tls.certificate;
            let v = verdict(tls);
            let color = verdict_color(v);

            let mut headline = vec![Span::styled(
                format!("{} {:?}", verdict_symbol(v), v),
                Style::new().fg(color).add_modifier(Modifier::BOLD),
            )];
            if let Some(grade) = &tls.grade {
                headline.push(Span::styled(
                    format!("  ·  Grade {} ({}/100)", grade.grade, grade.score),
                    Style::new().fg(color).add_modifier(Modifier::BOLD),
                ));
            }
            lines.push(Line::from(headline));

            lines.push(section("Subject"));
            lines.push(kv("Common Name", cert.subject.common_name.clone()));
            lines.push(kv("Organization", cert.subject.organization.clone()));
            lines.push(kv("Org. Unit", cert.subject.organization_unit.clone()));
            lines.push(kv("Locality", cert.subject.locality.clone()));
            lines.push(kv("State/Province", cert.subject.state_or_province.clone()));
            lines.push(kv("Country", cert.subject.country_or_region.clone()));

            lines.push(section("Issuer"));
            lines.push(kv("Common Name", cert.issued.common_name.clone()));
            lines.push(kv("Organization", cert.issued.organization.clone()));
            lines.push(kv("Country", cert.issued.country_or_region.clone()));

            lines.push(section("Validity"));
            lines.push(kv("Not Before", cert.valid_from.clone()));
            lines.push(kv("Not After", cert.valid_to.clone()));
            lines.push(kv(
                "Remaining",
                if cert.is_expired {
                    format!("expired {}d ago", -cert.validity_days)
                } else {
                    format!("{}d ({}h)", cert.validity_days, cert.validity_hours)
                },
            ));
            lines.push(kv(
                "Self-signed",
                if cert.is_self_signed { "yes" } else { "no" },
            ));
            lines.push(kv("Revocation", format!("{:?}", cert.revocation_status)));
            lines.push(kv(
                "Trust",
                match &cert.trust {
                    tlschecker::TrustStatus::Trusted => "trusted".to_string(),
                    tlschecker::TrustStatus::Untrusted { reason } => {
                        format!("untrusted · {}", reason)
                    }
                    tlschecker::TrustStatus::Unknown => "unknown".to_string(),
                },
            ));
            if let Some(ct) = &tls.ct {
                lines.push(kv(
                    "CT (crt.sh)",
                    match ct {
                        tlschecker::ct::CtStatus::Logged { crtsh_url, .. } => {
                            format!("logged · {}", crtsh_url)
                        }
                        tlschecker::ct::CtStatus::NotLogged => "not logged".to_string(),
                        tlschecker::ct::CtStatus::Unknown => "unknown".to_string(),
                    },
                ));
            }

            lines.push(section("Certificate"));
            lines.push(kv("Serial Number", cert.cert_sn.clone()));
            lines.push(kv("Version", cert.cert_ver.clone()));
            lines.push(kv("Signature Alg.", cert.cert_alg.clone()));
            lines.push(kv(
                "Public Key",
                format!("{} {}-bit", cert.cert_key_algorithm, cert.cert_key_bits),
            ));
            lines.push(kv("SHA-256", cert.cert_sha256.clone()));
            lines.push(kv("SHA-1", cert.cert_sha1.clone()));
            if let Some(skid) = &cert.subject_key_id {
                lines.push(kv("Subject Key ID", skid.clone()));
            }
            if let Some(akid) = &cert.authority_key_id {
                lines.push(kv("Authority Key ID", akid.clone()));
            }
            if let Some(level) = &cert.validation_level {
                lines.push(kv("Validation Level", level.clone()));
            }
            if !cert.key_usage.is_empty() {
                lines.push(kv("Key Usage", cert.key_usage.join(", ")));
            }
            if !cert.ext_key_usage.is_empty() {
                lines.push(kv("Ext Key Usage", cert.ext_key_usage.join(", ")));
            }
            lines.push(kv(
                "Basic Constraints",
                match cert.path_len {
                    Some(n) => format!("CA:{}, pathlen:{}", cert.is_ca, n),
                    None => format!("CA:{}", cert.is_ca),
                },
            ));

            lines.push(section("Connection"));
            lines.push(kv("Protocol", tls.cipher.version.clone()));
            lines.push(kv(
                "Cipher Suite",
                format!("{} ({}-bit)", tls.cipher.name, tls.cipher.bits),
            ));
            if let Some(alpn) = &tls.cipher.alpn {
                lines.push(kv("ALPN", alpn.clone()));
            }

            lines.push(section(&format!(
                "Subject Alternative Names ({})",
                cert.sans.len()
            )));
            for san in &cert.sans {
                lines.push(kv("DNS", san.clone()));
            }

            if !cert.scts.is_empty() {
                lines.push(section(&format!("Embedded SCTs ({})", cert.scts.len())));
                for sct in &cert.scts {
                    lines.push(kv("Log", format!("{} at {}", sct.log_id, sct.timestamp)));
                }
            }

            if let Some(chain) = &cert.chain {
                lines.push(section(&format!("Certificate Chain ({})", chain.len())));
                for (i, link) in chain.iter().enumerate() {
                    lines.push(Line::from(Span::styled(
                        format!("  #{} {}", i + 1, link.subject),
                        Style::new().add_modifier(Modifier::BOLD),
                    )));
                    lines.push(kv("  Issuer", link.issuer.clone()));
                    lines.push(kv(
                        "  Valid",
                        format!("{} → {}", link.valid_from, link.valid_to),
                    ));
                    lines.push(kv("  Signature", link.signature_algorithm.clone()));
                }
            }

            if let Some(grade) = &tls.grade {
                lines.push(section("Grade Breakdown"));
                for cat in &grade.categories {
                    lines.push(Line::from(vec![
                        Span::styled(format!("  {:<22}", cat.category), DIM),
                        Span::styled(
                            format!("{:>3}  ", cat.score),
                            Style::new().fg(score_color(cat.score)),
                        ),
                        Span::raw(cat.reason.clone()),
                    ]));
                }
            }

            if let Some(scan) = &tls.scan {
                lines.push(section("Protocol & Cipher Scan"));
                for proto in &scan.protocols {
                    if proto.supported {
                        lines.push(kv(proto.version.label(), "supported"));
                        for cipher in &proto.ciphers {
                            lines.push(Line::from(Span::raw(format!("      · {}", cipher))));
                        }
                    } else {
                        lines.push(kv(proto.version.label(), "not supported".to_string()));
                    }
                }
            }

            if !cert.security_warnings.is_empty() {
                lines.push(section(&format!(
                    "Warnings ({})",
                    cert.security_warnings.len()
                )));
                for warning in &cert.security_warnings {
                    let (kind, msg) = warning_label(warning);
                    lines.push(Line::from(vec![
                        Span::styled(format!("  ⚠ {}: ", kind), Style::new().fg(Color::Yellow)),
                        Span::raw(msg.to_string()),
                    ]));
                }
            }
        }
    }
    lines
}

/// Number of lines in the explorer's content — the scroll clamp bound.
pub fn detail_line_count(app: &App) -> usize {
    detail_lines(app).len()
}

/// Full-screen certificate explorer for the selected host.
fn draw_explorer(frame: &mut Frame, app: &App) {
    let [main, footer] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(1)]).areas(frame.area());

    let label = app.labels.get(app.selected).cloned().unwrap_or_default();
    let lines = detail_lines(app);
    let total = lines.len();
    let visible = main.height.saturating_sub(2) as usize; // minus borders
    let position = if total > visible {
        format!(
            " {}–{}/{} ",
            app.detail_scroll + 1,
            (app.detail_scroll + visible).min(total),
            total
        )
    } else {
        String::new()
    };

    let block = Block::bordered()
        .title(format!(" {} — certificate ", label))
        .title(Line::from(position).style(DIM).right_aligned());
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.detail_scroll as u16, 0))
            .block(block),
        main,
    );

    draw_footer(
        frame,
        app,
        " j/k scroll · g/G top/bottom · e export · esc back · q quit",
        footer,
    );
}

fn draw_footer(frame: &mut Frame, app: &App, base: &'static str, area: Rect) {
    if let Some(msg) = &app.flash_message {
        let color = if msg.starts_with("Failed") {
            Color::Red
        } else {
            Color::Green
        };
        frame.render_widget(
            Line::from(format!(" {} ", msg))
                .style(Style::new().fg(color).add_modifier(Modifier::BOLD)),
            area,
        );
    } else {
        frame.render_widget(Line::from(base).style(DIM), area);
    }
}

fn centered_rect(width: u16, height: u16, r: Rect) -> Rect {
    let popup_layout = Layout::vertical([
        Constraint::Length(r.height.saturating_sub(height) / 2),
        Constraint::Length(height),
        Constraint::Min(0),
    ])
    .split(r);

    Layout::horizontal([
        Constraint::Length(r.width.saturating_sub(width) / 2),
        Constraint::Length(width),
        Constraint::Min(0),
    ])
    .split(popup_layout[1])[1]
}

fn draw_export_prompt(frame: &mut Frame, prompt: &str) {
    let area = centered_rect(60, 3, frame.area());
    frame.render_widget(Clear, area);
    let block = Block::bordered()
        .title(" Export Certificate ")
        .border_style(Style::new().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let text = Line::from(vec![
        Span::raw(" Path: "),
        Span::styled(prompt, Style::new().fg(Color::Yellow)),
        Span::styled("█", Style::new().fg(Color::Cyan)),
    ]);
    frame.render_widget(Paragraph::new(text), inner);
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

    /// Renders the app into a test buffer of the given size and returns its
    /// text content.
    fn render_sized(app: &App, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        buffer.content().iter().map(|cell| cell.symbol()).collect()
    }

    /// Renders the app at the default test size.
    fn render(app: &App) -> String {
        render_sized(app, 110, 32)
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
    fn test_draw_untrusted_host_shows_trust_fact() {
        let mut tls = make_test_tls();
        tls.certificate.trust = tlschecker::TrustStatus::Untrusted {
            reason: "self-signed certificate".to_string(),
        };
        // TLS::from appends this alongside setting the trust field; mirror that
        // so the fleet verdict reflects it too.
        tls.certificate
            .security_warnings
            .push(tlschecker::SecurityWarning::Untrusted(
                "Certificate chain is not trusted: self-signed certificate".to_string(),
            ));
        let app = app_with(
            vec![(0, HostOutcome::Checked(Box::new(tls)))],
            &["test.example.com"],
        );
        let content = render(&app);
        assert!(content.contains("Trust"));
        assert!(content.contains("untrusted"));
        // A trust failure downgrades the fleet verdict out of Healthy.
        assert!(content.contains("1 warning"));
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
    fn test_explorer_shows_full_certificate_report() {
        let mut tls = make_test_tls();
        tls.scan = Some(tlschecker::probe::TlsScan {
            protocols: vec![tlschecker::probe::ProtocolSupport {
                version: tlschecker::probe::ProtoVersion::Tls1_3,
                supported: true,
                ciphers: vec!["TLS_AES_256_GCM_SHA384".to_string()],
            }],
        });
        let mut app = app_with(
            vec![(0, HostOutcome::Checked(Box::new(tls)))],
            &["test.example.com"],
        );
        app.open_detail();

        // Tall enough to show the whole report without scrolling.
        let content = render_sized(&app, 110, 70);
        // Sections
        for heading in [
            "Subject",
            "Issuer",
            "Validity",
            "Certificate",
            "Connection",
            "Subject Alternative Names (2)",
            "Certificate Chain (1)",
            "Protocol & Cipher Scan",
        ] {
            assert!(content.contains(heading), "missing section {heading:?}");
        }
        // Facts from make_test_tls
        assert!(content.contains("San Francisco")); // subject locality
        assert!(content.contains("1234567890")); // serial number
        assert!(content.contains("www.example.com")); // SAN entry
        assert!(content.contains("Test CA Root")); // chain issuer
        assert!(content.contains("esc back")); // explorer footer
    }

    #[test]
    fn test_explorer_scroll_moves_content() {
        let mut app = app_with(
            vec![(0, HostOutcome::Checked(Box::new(make_test_tls())))],
            &["test.example.com"],
        );
        app.open_detail();
        let top = render(&app);
        assert!(top.contains("Common Name"));

        let max = detail_line_count(&app).saturating_sub(1);
        app.scroll_down(1000, max); // clamped to the last line
        let bottom = render(&app);
        assert!(!bottom.contains("Common Name"), "top content still visible");
    }

    #[test]
    fn test_explorer_failed_host() {
        let mut app = app_with(
            vec![(
                0,
                HostOutcome::Failed {
                    kind: "DNS",
                    detail: "no such host".to_string(),
                },
            )],
            &["nope.invalid"],
        );
        app.open_detail();
        let content = render(&app);
        assert!(content.contains("Could not check (DNS)"));
        assert!(content.contains("no such host"));
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
