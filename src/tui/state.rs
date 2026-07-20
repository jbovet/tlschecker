//! Dashboard application state: the host list, selection, and the verdict
//! logic that colors it.

use std::io::{ErrorKind, Write};

use tlschecker::{RevocationStatus, TLS};

use crate::HostOutcome;

/// Overall health verdict for a checked host.
///
/// Unlike the classic summary's Status column (which only reflected the
/// expiry window), this verdict accounts for every signal the check produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Healthy,
    Warning,
    Critical,
}

/// Computes the verdict for a completed check.
///
/// - Expired, revoked, or expiring within 15 days → `Critical`
/// - Self-signed, any security warning, or expiring within 30 days → `Warning`
/// - Otherwise → `Healthy`
///
/// The day thresholds match the classic summary table's Status column.
pub fn verdict(tls: &TLS) -> Verdict {
    let cert = &tls.certificate;
    if cert.is_expired
        || matches!(cert.revocation_status, RevocationStatus::Revoked(_))
        || cert.validity_days <= 15
    {
        Verdict::Critical
    } else if cert.is_self_signed || !cert.security_warnings.is_empty() || cert.validity_days <= 30
    {
        Verdict::Warning
    } else {
        Verdict::Healthy
    }
}

/// Builds the filename the export prompt is prefilled with.
///
/// Host labels are whatever the user typed on the command line, which
/// `parse_host_port` accepts in three shapes — `host`, `host:port`, and
/// `https://host:port` — so the label is parsed down to the bare hostname
/// first. Using it raw would produce `https://example.com.pem` (a path under a
/// nonexistent `https:` directory) or `example.com:443.pem` (illegal on
/// Windows). Whatever survives parsing is then reduced to characters that are
/// safe in a filename, which also flattens IPv6 colons and wildcard SAN names.
fn default_export_filename(label: &str) -> String {
    let host = crate::parse_host_port(label)
        .map(|hp| hp.host)
        .unwrap_or_else(|_| label.to_string());

    // `parse_host_port` keeps the brackets on an IPv6 literal when it resolves
    // through `Url::parse` (it only strips them on its fallback path).
    let host = host.trim_start_matches('[').trim_end_matches(']');

    let stem: String = host
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect();

    // A stem of only separators (or nothing at all) would yield a dotfile or a
    // bare ".pem"; fall back to a neutral name instead.
    if stem.chars().all(|c| matches!(c, '.' | '-' | '_')) {
        "certificate.pem".to_string()
    } else {
        format!("{}.pem", stem)
    }
}

/// Which screen the dashboard is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// The fleet overview: host list + compact detail pane.
    Fleet,
    /// Full-screen certificate explorer for the selected host.
    Detail,
}

/// Live dashboard state: one slot per host (input order), plus the selection.
pub struct App {
    /// Host labels exactly as the user supplied them.
    pub labels: Vec<String>,
    /// Check outcomes as they stream in; `None` while still pending.
    pub slots: Vec<Option<HostOutcome>>,
    /// Index of the currently selected host row.
    pub selected: usize,
    /// Current screen.
    pub screen: Screen,
    /// Scroll offset (in lines) of the full-screen detail explorer.
    pub detail_scroll: usize,
    /// Optional state for the export prompt overlay. When `Some`, the user is typing a filename.
    pub export_prompt: Option<String>,
    /// Optional flash message to display success or error (e.g. "Exported to example.pem").
    pub flash_message: Option<String>,
}

/// Tally of hosts per state, shown under the host list.
#[derive(Default)]
pub struct Tally {
    pub healthy: usize,
    pub warning: usize,
    pub critical: usize,
    pub failed: usize,
    pub pending: usize,
}

impl App {
    pub fn new(labels: &[String]) -> Self {
        App {
            labels: labels.to_vec(),
            slots: labels.iter().map(|_| None).collect(),
            selected: 0,
            screen: Screen::Fleet,
            detail_scroll: 0,
            export_prompt: None,
            flash_message: None,
        }
    }

    /// Opens the full-screen certificate explorer for the selected host.
    pub fn open_detail(&mut self) {
        self.screen = Screen::Detail;
        self.detail_scroll = 0;
    }

    /// Returns from the explorer to the fleet view.
    pub fn close_detail(&mut self) {
        self.screen = Screen::Fleet;
        self.detail_scroll = 0;
    }

    /// Opens the export prompt for the selected host, prefilled with a
    /// filename derived from its address.
    pub fn begin_export(&mut self) {
        if let Some(Some(HostOutcome::Checked(_))) = self.slots.get(self.selected) {
            let label = self.labels.get(self.selected).cloned().unwrap_or_default();
            self.export_prompt = Some(default_export_filename(&label));
        }
    }

    /// Writes the selected host's PEM chain to the typed path and reports the
    /// result in the flash line.
    ///
    /// The file is created with `create_new`, so an existing file is reported
    /// rather than overwritten: the prompt is prefilled, which makes `e`⏎ two
    /// keystrokes away from clobbering whatever is already there.
    pub fn commit_export(&mut self) {
        let Some(path) = self.export_prompt.take() else {
            return;
        };
        let Some(Some(HostOutcome::Checked(tls))) = self.slots.get(self.selected) else {
            return;
        };

        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| file.write_all(tls.certificate.pem.as_bytes()));

        self.flash_message = Some(match written {
            Ok(()) => format!("Exported to {}", path),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                format!("Failed to export: {} already exists", path)
            }
            Err(e) => format!("Failed to export: {}", e),
        });
    }

    pub fn clear_flash(&mut self) {
        self.flash_message = None;
    }

    /// Scrolls the explorer down, clamped to `max` (the last valid offset).
    pub fn scroll_down(&mut self, lines: usize, max: usize) {
        self.detail_scroll = (self.detail_scroll + lines).min(max);
    }

    /// Scrolls the explorer up.
    pub fn scroll_up(&mut self, lines: usize) {
        self.detail_scroll = self.detail_scroll.saturating_sub(lines);
    }

    /// Records a completed check for the host at `index`.
    pub fn record(&mut self, index: usize, outcome: HostOutcome) {
        if let Some(slot) = self.slots.get_mut(index) {
            *slot = Some(outcome);
        }
    }

    /// Number of hosts that have finished (successfully or not).
    pub fn done(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    pub fn total(&self) -> usize {
        self.slots.len()
    }

    pub fn tally(&self) -> Tally {
        let mut tally = Tally::default();
        for slot in &self.slots {
            match slot {
                None => tally.pending += 1,
                Some(HostOutcome::Failed { .. }) => tally.failed += 1,
                Some(HostOutcome::Checked(tls)) => match verdict(tls) {
                    Verdict::Healthy => tally.healthy += 1,
                    Verdict::Warning => tally.warning += 1,
                    Verdict::Critical => tally.critical += 1,
                },
            }
        }
        tally
    }

    pub fn select_next(&mut self) {
        if self.selected + 1 < self.slots.len() {
            self.selected += 1;
        }
    }

    pub fn select_prev(&mut self) {
        self.selected = self.selected.saturating_sub(1);
    }

    pub fn select_first(&mut self) {
        self.selected = 0;
    }

    pub fn select_last(&mut self) {
        self.selected = self.slots.len().saturating_sub(1);
    }

    /// Consumes the app, returning the collected outcomes in input order.
    pub fn into_outcomes(self) -> Vec<Option<HostOutcome>> {
        self.slots
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::make_test_tls;

    #[test]
    fn test_default_export_filename_strips_scheme_and_port() {
        // All three address shapes `parse_host_port` accepts must collapse to
        // the same plain, writable filename.
        assert_eq!(default_export_filename("example.com"), "example.com.pem");
        assert_eq!(
            default_export_filename("example.com:443"),
            "example.com.pem"
        );
        assert_eq!(
            default_export_filename("https://example.com:8443"),
            "example.com.pem"
        );
    }

    #[test]
    fn test_default_export_filename_sanitizes_unsafe_chars() {
        // IPv6 colons and wildcards would be illegal or awkward in a filename.
        assert_eq!(default_export_filename("[::1]:443"), "__1.pem");
        assert_eq!(default_export_filename("*.example.com"), "_.example.com.pem");
        assert_eq!(default_export_filename(""), "certificate.pem");
    }

    #[test]
    fn test_commit_export_writes_pem_and_refuses_overwrite() {
        let dir = std::env::temp_dir().join("tlschecker_export_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.pem");

        let mut tls = make_test_tls();
        tls.certificate.pem = "-----BEGIN CERTIFICATE-----\n".to_string();
        let mut app = App::new(&["example.com".to_string()]);
        app.record(0, HostOutcome::Checked(Box::new(tls)));

        app.export_prompt = Some(path.to_string_lossy().into_owned());
        app.commit_export();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "-----BEGIN CERTIFICATE-----\n"
        );
        assert!(app.flash_message.as_ref().unwrap().starts_with("Exported to"));

        // A second export to the same path must report, not clobber.
        app.export_prompt = Some(path.to_string_lossy().into_owned());
        app.commit_export();
        assert!(app.flash_message.unwrap().contains("already exists"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_verdict_healthy() {
        let tls = make_test_tls(); // 365 days left, no warnings
        assert_eq!(verdict(&tls), Verdict::Healthy);
    }

    #[test]
    fn test_verdict_expired_is_critical() {
        let mut tls = make_test_tls();
        tls.certificate.is_expired = true;
        assert_eq!(verdict(&tls), Verdict::Critical);
    }

    #[test]
    fn test_verdict_revoked_is_critical() {
        let mut tls = make_test_tls();
        tls.certificate.revocation_status = RevocationStatus::Revoked("test".to_string());
        assert_eq!(verdict(&tls), Verdict::Critical);
    }

    #[test]
    fn test_verdict_expiring_soon() {
        let mut tls = make_test_tls();
        tls.certificate.validity_days = 10;
        assert_eq!(verdict(&tls), Verdict::Critical);
        tls.certificate.validity_days = 25;
        assert_eq!(verdict(&tls), Verdict::Warning);
        tls.certificate.validity_days = 31;
        assert_eq!(verdict(&tls), Verdict::Healthy);
    }

    #[test]
    fn test_verdict_warning_on_security_warning() {
        let mut tls = make_test_tls();
        tls.certificate
            .security_warnings
            .push(tlschecker::SecurityWarning::HostnameMismatch(
                "not valid".to_string(),
            ));
        assert_eq!(verdict(&tls), Verdict::Warning);
    }

    #[test]
    fn test_verdict_warning_on_self_signed() {
        let mut tls = make_test_tls();
        tls.certificate.is_self_signed = true;
        assert_eq!(verdict(&tls), Verdict::Warning);
    }

    #[test]
    fn test_tally_and_record() {
        let labels = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let mut app = App::new(&labels);
        assert_eq!(app.done(), 0);
        assert_eq!(app.tally().pending, 3);

        app.record(0, crate::HostOutcome::Checked(Box::new(make_test_tls())));
        app.record(
            2,
            crate::HostOutcome::Failed {
                kind: "DNS",
                detail: "no such host".to_string(),
            },
        );
        let tally = app.tally();
        assert_eq!(app.done(), 2);
        assert_eq!(tally.healthy, 1);
        assert_eq!(tally.failed, 1);
        assert_eq!(tally.pending, 1);
    }

    #[test]
    fn test_selection_bounds() {
        let labels = vec!["a".to_string(), "b".to_string()];
        let mut app = App::new(&labels);
        app.select_prev();
        assert_eq!(app.selected, 0);
        app.select_next();
        app.select_next(); // clamped at last row
        assert_eq!(app.selected, 1);
        app.select_first();
        assert_eq!(app.selected, 0);
        app.select_last();
        assert_eq!(app.selected, 1);
    }
}
