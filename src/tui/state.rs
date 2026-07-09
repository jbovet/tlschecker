//! Dashboard application state: the host list, selection, and the verdict
//! logic that colors it.

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
    } else if cert.is_self_signed
        || !cert.security_warnings.is_empty()
        || cert.validity_days <= 30
    {
        Verdict::Warning
    } else {
        Verdict::Healthy
    }
}

/// Live dashboard state: one slot per host (input order), plus the selection.
pub struct App {
    /// Host labels exactly as the user supplied them.
    pub labels: Vec<String>,
    /// Check outcomes as they stream in; `None` while still pending.
    pub slots: Vec<Option<HostOutcome>>,
    /// Index of the currently selected host row.
    pub selected: usize,
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
        }
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
