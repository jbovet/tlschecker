//! Dashboard application state: the host list, selection, and the verdict
//! logic that colors it.

use std::collections::HashSet;
use std::io::{ErrorKind, Write};

use tlschecker::ct::CtStatus;
use tlschecker::{RevocationStatus, TLSError, TLS};

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

/// A check the user asked for that ran but could not reach a verdict.
#[derive(Debug, PartialEq, Eq)]
pub struct Unverified<'a> {
    /// Which check ("Revocation" or "CT").
    pub check: &'static str,
    /// Why it could not complete, when the check recorded a reason.
    pub reason: Option<&'a str>,
}

/// The requested checks that came back `Unknown` for this host.
///
/// Deliberately separate from [`verdict`]: an unreachable OCSP responder or a
/// crt.sh outage says nothing bad about the certificate, so it must not turn a
/// fleet Warning. But it must not read as a pass either — the user asked for
/// the check — so the dashboard marks it on its own.
pub fn unverified_checks(tls: &TLS) -> Vec<Unverified<'_>> {
    let mut out = Vec::new();
    if tls.certificate.revocation_status == RevocationStatus::Unknown {
        out.push(Unverified {
            check: "Revocation",
            reason: tls.certificate.revocation_detail.as_deref(),
        });
    }
    if tls.ct == Some(tlschecker::ct::CtStatus::Unknown) {
        out.push(Unverified {
            check: "CT",
            reason: tls.ct_detail.as_deref(),
        });
    }
    out
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
    /// Export overlay state. When `Some`, the user is typing a filename and the
    /// overlay captures all input.
    pub export_prompt: Option<ExportPrompt>,
    /// Transient footer message reporting the last export attempt, replacing
    /// the key hints until the next keypress.
    pub flash: Option<Flash>,
    /// On-demand checks in flight, by host index.
    pub running: HashSet<(usize, OnDemand)>,
}

/// A check the dashboard can run on demand for the selected host — the ones
/// that are opt-in on the command line because they cost network round trips.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OnDemand {
    Revocation,
    Ct,
}

impl OnDemand {
    fn name(self) -> &'static str {
        match self {
            OnDemand::Revocation => "Revocation",
            OnDemand::Ct => "CT",
        }
    }
}

/// An on-demand check ready to run, carrying only what it needs so it can
/// run on a worker thread while the dashboard keeps drawing.
#[derive(Debug, PartialEq, Eq)]
pub enum OnDemandJob {
    /// Revocation for the chain the check kept — no new TLS connection.
    Revocation { index: usize, pem: String },
    /// crt.sh lookup by the leaf's SHA-256 fingerprint.
    Ct { index: usize, sha256: String },
}

/// The outcome of an [`OnDemandJob`], applied with [`App::finish_check`].
#[derive(Debug)]
pub enum OnDemandResult {
    Revocation(RevocationStatus, Option<String>),
    Ct(Result<CtStatus, TLSError>),
}

impl OnDemandJob {
    /// Runs the check. Blocking (OCSP/CRL/crt.sh requests): call it off the
    /// UI thread.
    pub fn run(self) -> (usize, OnDemandResult) {
        match self {
            OnDemandJob::Revocation { index, pem } => {
                let (status, detail) = tlschecker::check_revocation_from_pem(&pem);
                (index, OnDemandResult::Revocation(status, detail))
            }
            OnDemandJob::Ct { index, sha256 } => (
                index,
                OnDemandResult::Ct(tlschecker::ct::check_ct_status(&sha256)),
            ),
        }
    }

    /// The result to record if [`run`](Self::run) panicked, so the host
    /// doesn't stay "checking…" forever.
    pub fn failed(index: usize, kind: OnDemand, reason: &str) -> (usize, OnDemandResult) {
        let reason = format!("internal error while checking: {reason}");
        match kind {
            OnDemand::Revocation => (
                index,
                OnDemandResult::Revocation(RevocationStatus::Unknown, Some(reason)),
            ),
            OnDemand::Ct => (index, OnDemandResult::Ct(Err(TLSError::Unknown(reason)))),
        }
    }

    pub fn kind(&self) -> OnDemand {
        match self {
            OnDemandJob::Revocation { .. } => OnDemand::Revocation,
            OnDemandJob::Ct { .. } => OnDemand::Ct,
        }
    }

    pub fn index(&self) -> usize {
        match self {
            OnDemandJob::Revocation { index, .. } | OnDemandJob::Ct { index, .. } => *index,
        }
    }
}

/// The export overlay: the path being typed, plus why the last attempt failed.
///
/// The error lives here rather than in [`Flash`] so it renders inside the
/// popup the user is looking at, and so editing the path can clear it — a
/// footer message naming a path the input box no longer holds is worse than
/// no message.
pub struct ExportPrompt {
    pub path: String,
    pub error: Option<String>,
}

impl ExportPrompt {
    fn new(path: String) -> Self {
        ExportPrompt { path, error: None }
    }
}

/// Whether a [`Flash`] reports success or failure, which drives its color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlashKind {
    Success,
    Error,
}

/// A transient footer message (e.g. "Exported to example.com.pem").
///
/// The kind is carried explicitly rather than inferred from the text, so
/// rewording a message cannot silently flip an error from red to green.
pub struct Flash {
    pub text: String,
    pub kind: FlashKind,
}

impl Flash {
    fn success(text: impl Into<String>) -> Self {
        Flash {
            text: text.into(),
            kind: FlashKind::Success,
        }
    }

    fn error(text: impl Into<String>) -> Self {
        Flash {
            text: text.into(),
            kind: FlashKind::Error,
        }
    }
}

/// Tally of hosts per state, shown under the host list.
#[derive(Default)]
pub struct Tally {
    pub healthy: usize,
    pub warning: usize,
    pub critical: usize,
    pub failed: usize,
    pub pending: usize,
    /// Checked hosts with at least one requested check left unverified
    /// (counted independently of their verdict).
    pub unverified: usize,
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
            flash: None,
            running: HashSet::new(),
        }
    }

    /// Starts an on-demand check of the selected host, returning the job to
    /// run off the UI thread — or `None`, with a flash saying why, when there
    /// is nothing to check or the same check is already running.
    pub fn begin_check(&mut self, kind: OnDemand) -> Option<OnDemandJob> {
        let index = self.selected;
        let tls = match self.slots.get(index) {
            Some(Some(HostOutcome::Checked(tls))) => tls,
            Some(Some(HostOutcome::Failed { .. })) => {
                self.flash = Some(Flash::error("Nothing to check: host check failed"));
                return None;
            }
            _ => {
                self.flash = Some(Flash::error("Nothing to check: check still running"));
                return None;
            }
        };
        if self.running.contains(&(index, kind)) {
            self.flash = Some(Flash::error(format!(
                "{} check already running",
                kind.name()
            )));
            return None;
        }
        let job = match kind {
            // Results loaded without a live connection have no chain to check.
            OnDemand::Revocation if tls.certificate.pem.is_empty() => {
                self.flash = Some(Flash::error(
                    "No certificate chain kept for this host: cannot check revocation",
                ));
                return None;
            }
            OnDemand::Revocation => OnDemandJob::Revocation {
                index,
                pem: tls.certificate.pem.clone(),
            },
            OnDemand::Ct => OnDemandJob::Ct {
                index,
                sha256: tls.certificate.cert_sha256.clone(),
            },
        };
        self.running.insert((index, kind));
        Some(job)
    }

    /// Applies a finished on-demand check to its host.
    pub fn finish_check(&mut self, index: usize, result: OnDemandResult) {
        let kind = match result {
            OnDemandResult::Revocation(..) => OnDemand::Revocation,
            OnDemandResult::Ct(_) => OnDemand::Ct,
        };
        self.running.remove(&(index, kind));
        if let Some(Some(HostOutcome::Checked(tls))) = self.slots.get_mut(index) {
            match result {
                OnDemandResult::Revocation(status, detail) => tls.apply_revocation(status, detail),
                OnDemandResult::Ct(lookup) => tls.apply_ct_lookup(lookup),
            }
            let label = self.labels.get(index).map(String::as_str).unwrap_or("");
            self.flash = Some(Flash::success(format!(
                "{} check finished for {}",
                kind.name(),
                label
            )));
        }
    }

    /// Whether `kind` is running for host `index`.
    pub fn is_running(&self, index: usize, kind: OnDemand) -> bool {
        self.running.contains(&(index, kind))
    }

    /// The on-demand checks worth offering for the selected host: those it
    /// has no definitive answer for yet (never run, or `Unknown`) and that
    /// are not already running.
    pub fn check_hints(&self) -> Vec<OnDemand> {
        let Some(Some(HostOutcome::Checked(tls))) = self.slots.get(self.selected) else {
            return Vec::new();
        };
        let mut hints = Vec::new();
        if matches!(
            tls.certificate.revocation_status,
            RevocationStatus::NotChecked | RevocationStatus::Unknown
        ) && !tls.certificate.pem.is_empty()
            && !self.is_running(self.selected, OnDemand::Revocation)
        {
            hints.push(OnDemand::Revocation);
        }
        if matches!(tls.ct, None | Some(CtStatus::Unknown))
            && !self.is_running(self.selected, OnDemand::Ct)
        {
            hints.push(OnDemand::Ct);
        }
        hints
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
    ///
    /// Only a completed check has a chain to write, so a pending or failed
    /// host reports why in the flash line rather than leaving `e` looking like
    /// a dead key.
    pub fn begin_export(&mut self) {
        match self.slots.get(self.selected) {
            Some(Some(HostOutcome::Checked(_))) => {
                let label = self.labels.get(self.selected).cloned().unwrap_or_default();
                self.export_prompt = Some(ExportPrompt::new(default_export_filename(&label)));
            }
            Some(Some(HostOutcome::Failed { .. })) => {
                self.flash = Some(Flash::error("Nothing to export: host check failed"));
            }
            _ => {
                self.flash = Some(Flash::error("Nothing to export: check still running"));
            }
        }
    }

    /// Appends a typed character to the export path.
    pub fn export_input_push(&mut self, c: char) {
        if let Some(prompt) = &mut self.export_prompt {
            prompt.path.push(c);
            // The error described the path as it was; editing invalidates it.
            prompt.error = None;
        }
    }

    /// Deletes the last character of the export path.
    pub fn export_input_pop(&mut self) {
        if let Some(prompt) = &mut self.export_prompt {
            prompt.path.pop();
            prompt.error = None;
        }
    }

    /// Clears the export path (readline `Ctrl+U`).
    pub fn export_input_clear(&mut self) {
        if let Some(prompt) = &mut self.export_prompt {
            prompt.path.clear();
            prompt.error = None;
        }
    }

    /// Deletes the trailing path segment (readline `Ctrl+W`).
    ///
    /// Breaks on `/` as well as whitespace, so it removes one directory
    /// component at a time rather than the whole path.
    pub fn export_input_delete_word(&mut self) {
        if let Some(prompt) = &mut self.export_prompt {
            let is_boundary = |c: char| c == '/' || c.is_whitespace();
            // Drop any trailing boundary first, so a path ending in `/` loses
            // the segment before it rather than just the separator.
            while prompt.path.ends_with(is_boundary) {
                prompt.path.pop();
            }
            while !prompt.path.is_empty() && !prompt.path.ends_with(is_boundary) {
                prompt.path.pop();
            }
            prompt.error = None;
        }
    }

    /// Closes the export prompt without writing anything.
    pub fn cancel_export(&mut self) {
        self.export_prompt = None;
    }

    /// Writes the selected host's PEM chain to the typed path.
    ///
    /// The file is created with `create_new`, so an existing file is reported
    /// rather than overwritten: the prompt is prefilled, which makes `e`⏎ two
    /// keystrokes away from clobbering whatever is already there.
    ///
    /// A write failure is recoverable — most often the name is simply taken —
    /// so the prompt stays open with the reason attached and the typed path
    /// intact, and only a successful write closes it. `Esc` still cancels.
    pub fn commit_export(&mut self) {
        let Some(prompt) = &self.export_prompt else {
            return;
        };
        let path = prompt.path.clone();

        let Some(Some(HostOutcome::Checked(tls))) = self.slots.get(self.selected) else {
            // Unreachable while `begin_export` guards on `Checked`, but closing
            // the overlay with no explanation would repeat the silent no-op
            // this screen already had once.
            self.export_prompt = None;
            self.flash = Some(Flash::error("Nothing to export: no certificate"));
            return;
        };

        let written = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .and_then(|mut file| file.write_all(tls.certificate.pem.as_bytes()));

        match written {
            Ok(()) => {
                self.export_prompt = None;
                self.flash = Some(Flash::success(format!("Exported to {}", path)));
            }
            Err(e) => {
                let reason = if e.kind() == ErrorKind::AlreadyExists {
                    "file already exists".to_string()
                } else {
                    e.to_string()
                };
                if let Some(prompt) = &mut self.export_prompt {
                    prompt.error = Some(reason);
                }
            }
        }
    }

    pub fn clear_flash(&mut self) {
        self.flash = None;
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
                Some(HostOutcome::Checked(tls)) => {
                    match verdict(tls) {
                        Verdict::Healthy => tally.healthy += 1,
                        Verdict::Warning => tally.warning += 1,
                        Verdict::Critical => tally.critical += 1,
                    }
                    if !unverified_checks(tls).is_empty() {
                        tally.unverified += 1;
                    }
                }
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
        assert_eq!(
            default_export_filename("*.example.com"),
            "_.example.com.pem"
        );
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

        app.export_prompt = Some(ExportPrompt::new(path.to_string_lossy().into_owned()));
        app.commit_export();
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "-----BEGIN CERTIFICATE-----\n"
        );
        // Success closes the overlay and reports in the footer.
        assert!(app.export_prompt.is_none());
        let flash = app.flash.as_ref().unwrap();
        assert_eq!(flash.kind, FlashKind::Success);
        assert!(flash.text.starts_with("Exported to"));

        // A second export to the same path must report, not clobber.
        app.export_prompt = Some(ExportPrompt::new(path.to_string_lossy().into_owned()));
        app.commit_export();
        let prompt = app.export_prompt.as_ref().expect("stays open to retry");
        assert_eq!(prompt.error.as_deref(), Some("file already exists"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_failed_export_keeps_prompt_open_for_retry() {
        let dir = std::env::temp_dir().join("tlschecker_export_retry_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let taken = dir.join("taken.pem");
        std::fs::write(&taken, "occupied").unwrap();

        let mut tls = make_test_tls();
        tls.certificate.pem = "PEM".to_string();
        let mut app = App::new(&["example.com".to_string()]);
        app.record(0, HostOutcome::Checked(Box::new(tls)));

        // Collide with the existing file.
        app.export_prompt = Some(ExportPrompt::new(taken.to_string_lossy().into_owned()));
        app.commit_export();
        let prompt = app.export_prompt.as_ref().expect("prompt survives failure");
        assert_eq!(prompt.error.as_deref(), Some("file already exists"));
        // The typed path is preserved, not discarded.
        assert_eq!(prompt.path, taken.to_string_lossy());
        assert!(
            app.flash.is_none(),
            "error belongs to the prompt, not the footer"
        );
        assert_eq!(std::fs::read_to_string(&taken).unwrap(), "occupied");

        // Editing the path clears the now-stale error.
        app.export_input_push('2');
        assert!(app.export_prompt.as_ref().unwrap().error.is_none());
        app.export_input_pop();
        assert!(app.export_prompt.as_ref().unwrap().error.is_none());

        // Retrying with a free name succeeds and closes the overlay.
        app.export_input_pop(); // "…taken.pe"
        app.export_input_push('x'); // "…taken.pex"
        app.commit_export();
        assert!(app.export_prompt.is_none());
        assert_eq!(app.flash.as_ref().unwrap().kind, FlashKind::Success);
        assert_eq!(
            std::fs::read_to_string(dir.join("taken.pex")).unwrap(),
            "PEM"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_export_input_line_editing() {
        let mut app = App::new(&["example.com".to_string()]);
        app.record(0, HostOutcome::Checked(Box::new(make_test_tls())));

        // Ctrl+W removes one path segment at a time, not the whole path.
        app.export_prompt = Some(ExportPrompt::new("out/certs/example.com.pem".to_string()));
        app.export_input_delete_word();
        assert_eq!(app.export_prompt.as_ref().unwrap().path, "out/certs/");
        app.export_input_delete_word();
        assert_eq!(app.export_prompt.as_ref().unwrap().path, "out/");
        app.export_input_delete_word();
        assert_eq!(app.export_prompt.as_ref().unwrap().path, "");
        // Emptied is a fixed point, not a panic.
        app.export_input_delete_word();
        assert_eq!(app.export_prompt.as_ref().unwrap().path, "");

        // Ctrl+U clears outright, and both clear a stale error.
        app.export_prompt = Some(ExportPrompt {
            path: "a/b.pem".to_string(),
            error: Some("file already exists".to_string()),
        });
        app.export_input_clear();
        let prompt = app.export_prompt.as_ref().unwrap();
        assert_eq!(prompt.path, "");
        assert!(prompt.error.is_none());
    }

    #[test]
    fn test_cancel_export_discards_the_prompt() {
        let mut app = App::new(&["example.com".to_string()]);
        app.record(0, HostOutcome::Checked(Box::new(make_test_tls())));
        app.begin_export();
        assert!(app.export_prompt.is_some());
        app.cancel_export();
        assert!(app.export_prompt.is_none());
        assert!(app.flash.is_none());
    }

    #[test]
    fn test_begin_export_reports_unexportable_hosts() {
        let labels = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let mut app = App::new(&labels);
        app.record(0, HostOutcome::Checked(Box::new(make_test_tls())));
        app.record(
            1,
            HostOutcome::Failed {
                kind: "DNS",
                detail: "no such host".to_string(),
            },
        );
        // Slot 2 is left pending.

        // A checked host opens the prompt and says nothing.
        app.selected = 0;
        app.begin_export();
        assert_eq!(
            app.export_prompt.as_ref().map(|p| p.path.as_str()),
            Some("a.pem")
        );
        assert!(app.flash.is_none());

        // A failed host explains itself instead of doing nothing.
        app.export_prompt = None;
        app.selected = 1;
        app.begin_export();
        assert!(app.export_prompt.is_none());
        let flash = app.flash.as_ref().unwrap();
        assert_eq!(flash.kind, FlashKind::Error);
        assert!(flash.text.contains("check failed"));

        // So does a host that has not finished yet.
        app.selected = 2;
        app.begin_export();
        assert!(app.export_prompt.is_none());
        assert!(app.flash.as_ref().unwrap().text.contains("still running"));
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
    fn test_unverified_checks_do_not_change_verdict() {
        let mut tls = make_test_tls();
        tls.certificate.revocation_status = RevocationStatus::Unknown;
        tls.certificate.revocation_detail = Some("OCSP: timeout".to_string());
        tls.apply_ct(tlschecker::ct::CtStatus::Unknown);

        assert_eq!(
            unverified_checks(&tls),
            vec![
                Unverified {
                    check: "Revocation",
                    reason: Some("OCSP: timeout"),
                },
                Unverified {
                    check: "CT",
                    reason: None,
                },
            ]
        );
        // An outage says nothing bad about the certificate itself.
        assert_eq!(verdict(&tls), Verdict::Healthy);

        let mut app = App::new(&["a".to_string(), "b".to_string()]);
        app.record(0, HostOutcome::Checked(Box::new(tls)));
        app.record(1, HostOutcome::Checked(Box::new(make_test_tls())));
        let tally = app.tally();
        assert_eq!((tally.healthy, tally.unverified), (2, 1));
    }

    #[test]
    fn test_not_checked_is_not_unverified() {
        // Checks the user did not request are not "unverified".
        let tls = make_test_tls(); // revocation NotChecked, ct None
        assert!(unverified_checks(&tls).is_empty());
    }

    fn app_with_checked(tls: TLS) -> App {
        let mut app = App::new(&["host.example".to_string()]);
        app.record(0, HostOutcome::Checked(Box::new(tls)));
        app
    }

    #[test]
    fn test_begin_check_builds_jobs_and_refuses_duplicates() {
        let tls = make_test_tls();
        let (pem, sha256) = (
            tls.certificate.pem.clone(),
            tls.certificate.cert_sha256.clone(),
        );
        let mut app = app_with_checked(tls);

        assert_eq!(
            app.begin_check(OnDemand::Revocation),
            Some(OnDemandJob::Revocation { index: 0, pem })
        );
        assert_eq!(
            app.begin_check(OnDemand::Ct),
            Some(OnDemandJob::Ct { index: 0, sha256 })
        );
        assert!(app.is_running(0, OnDemand::Revocation));

        // Pressing the key again while it runs must not start a second one.
        assert_eq!(app.begin_check(OnDemand::Revocation), None);
        assert!(app.flash.as_ref().unwrap().text.contains("already running"));
    }

    #[test]
    fn test_begin_check_needs_a_checked_host_with_a_chain() {
        let mut app = App::new(&["pending.example".to_string(), "failed.example".to_string()]);
        app.record(
            1,
            HostOutcome::Failed {
                kind: "DNS",
                detail: "no such host".to_string(),
            },
        );
        assert_eq!(app.begin_check(OnDemand::Ct), None); // index 0 still pending
        app.select_next();
        assert_eq!(app.begin_check(OnDemand::Ct), None);
        assert!(app
            .flash
            .as_ref()
            .unwrap()
            .text
            .contains("host check failed"));

        let mut no_chain = make_test_tls();
        no_chain.certificate.pem.clear();
        let mut app = app_with_checked(no_chain);
        assert_eq!(app.begin_check(OnDemand::Revocation), None);
        assert!(app
            .flash
            .as_ref()
            .unwrap()
            .text
            .contains("No certificate chain"));
        assert!(app.running.is_empty());
    }

    #[test]
    fn test_finish_check_updates_host_verdict_and_grade() {
        let mut tls = make_test_tls();
        tls.grade = Some(tlschecker::grading::calculate_grade(
            &tlschecker::grading::GradingInput {
                protocol_version: "TLSv1.3".into(),
                cipher_name: "TLS_AES_256_GCM_SHA384".into(),
                cipher_bits: 256,
                cert_key_bits: 2048,
                cert_key_algorithm: "RSA".into(),
                is_expired: false,
                is_self_signed: false,
                has_incomplete_chain: false,
                has_weak_signature: false,
                has_hostname_mismatch: false,
                has_invalid_chain_signature: false,
                supports_obsolete_protocol: false,
                accepts_weak_cipher: false,
                is_revoked: false,
                is_untrusted: false,
            },
        ));
        let mut app = app_with_checked(tls);
        app.begin_check(OnDemand::Revocation).unwrap();

        app.finish_check(
            0,
            OnDemandResult::Revocation(RevocationStatus::Revoked("Revoked via CRL".into()), None),
        );

        assert!(!app.is_running(0, OnDemand::Revocation));
        let Some(Some(HostOutcome::Checked(tls))) = app.slots.first() else {
            panic!("host should still be checked")
        };
        assert_eq!(verdict(tls), Verdict::Critical);
        assert_eq!(tls.grade.as_ref().unwrap().grade, "F");
        assert_eq!(
            app.flash.as_ref().unwrap().text,
            "Revocation check finished for host.example"
        );
    }

    #[test]
    fn test_finish_ct_check_keeps_the_failure_reason() {
        let mut app = app_with_checked(make_test_tls());
        app.begin_check(OnDemand::Ct).unwrap();
        app.finish_check(
            0,
            OnDemandResult::Ct(Err(TLSError::Unknown("CT lookup returned HTTP 502".into()))),
        );
        let Some(Some(HostOutcome::Checked(tls))) = app.slots.first() else {
            panic!("host should still be checked")
        };
        assert_eq!(tls.ct, Some(CtStatus::Unknown));
        assert_eq!(
            tls.ct_detail.as_deref(),
            Some("CT lookup returned HTTP 502")
        );
    }

    #[test]
    fn test_check_hints_offer_only_undecided_checks() {
        // Neither check requested on the command line: both offered.
        let mut app = app_with_checked(make_test_tls());
        assert_eq!(app.check_hints(), vec![OnDemand::Revocation, OnDemand::Ct]);

        // Running: not offered again.
        app.begin_check(OnDemand::Ct).unwrap();
        assert_eq!(app.check_hints(), vec![OnDemand::Revocation]);

        // Definitive answers: nothing left to offer...
        let mut done = make_test_tls();
        done.certificate.revocation_status = RevocationStatus::Good;
        done.apply_ct(CtStatus::NotLogged);
        assert!(app_with_checked(done).check_hints().is_empty());

        // ...but Unknown can be retried.
        let mut unknown = make_test_tls();
        unknown.certificate.revocation_status = RevocationStatus::Unknown;
        unknown.apply_ct(CtStatus::Unknown);
        assert_eq!(
            app_with_checked(unknown).check_hints(),
            vec![OnDemand::Revocation, OnDemand::Ct]
        );
    }

    #[test]
    fn test_failed_job_result_is_unknown_with_reason() {
        let (index, result) = OnDemandJob::failed(3, OnDemand::Revocation, "boom");
        assert_eq!(index, 3);
        assert!(matches!(
            result,
            OnDemandResult::Revocation(RevocationStatus::Unknown, Some(ref r))
                if r == "internal error while checking: boom"
        ));
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
