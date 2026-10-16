//! Exit status: the fixed codes tlschecker returns, and the stderr lines that
//! explain them.
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | ok |
//! | 1 | certificate problem: a checked host's status is at or above `--fail-on` |
//! | 2 | usage or configuration error; nothing was checked |
//! | 3 | host(s) could not be checked |
//! | 4 | internal error after the run started |
//!
//! Precedence is 2 > 4 > 1 > 3 > 0: a usage error happens before any check
//! runs, an internal error aborts the run, and a definitive certificate
//! failure (1) is never hidden behind a flaky-network code (3). The two
//! controls are independent: `--fail-on` decides only exit 1 and
//! `--allow-unreachable` only exit 3.
//!
//! Everything here is pure, so `main` only logs what these functions return
//! (through `tracing`, on stderr — stdout stays clean for `| jq`).

use serde::{Deserialize, Serialize};
use tlschecker::verdict::Verdict;

use crate::HostReport;

/// Status level that fails the run with exit code 1 (`--fail-on` /
/// `fail_on`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FailOn {
    /// Fail when any checked host is Critical.
    #[default]
    Critical,
    /// Fail when any checked host is Warning or Critical.
    Warning,
    /// Never exit 1; report only. Hosts that could not be checked still exit 3.
    Never,
}

impl FailOn {
    /// The lowest verdict that fails the run, or `None` for [`FailOn::Never`].
    pub fn threshold(self) -> Option<Verdict> {
        match self {
            FailOn::Critical => Some(Verdict::Critical),
            FailOn::Warning => Some(Verdict::Warning),
            FailOn::Never => None,
        }
    }

    /// The flag/config spelling: `"critical"`, `"warning"` or `"never"`.
    pub fn as_str(self) -> &'static str {
        match self {
            FailOn::Critical => "critical",
            FailOn::Warning => "warning",
            FailOn::Never => "never",
        }
    }
}

/// The process exit status. The numeric values are a public contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum RunStatus {
    /// Every host was checked and none reached the `--fail-on` level.
    Ok = 0,
    /// A checked host's status is at or above `--fail-on`.
    CertificateProblem = 1,
    /// Usage or configuration error; nothing was checked.
    Usage = 2,
    /// A host could not be checked.
    Unchecked = 3,
    /// The run failed after it started (e.g. a dashboard terminal error).
    Internal = 4,
}

impl From<RunStatus> for std::process::ExitCode {
    fn from(status: RunStatus) -> Self {
        std::process::ExitCode::from(status as u8)
    }
}

/// The user's exit-status controls for one run.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Gate {
    /// `--fail-on` / `fail_on`: decides exit 1.
    pub fail_on: FailOn,
    /// `--allow-unreachable`: tolerate unreachable hosts (exit 3) as long as
    /// at least one host was checked.
    pub allow_unreachable: bool,
}

/// How the hosts of one run ended up.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct RunTally {
    /// Checked hosts per verdict.
    pub healthy: usize,
    pub warning: usize,
    pub critical: usize,
    /// Hosts that could not be checked: DNS, connection, handshake,
    /// certificate retrieval, or a caught worker panic.
    pub unreachable: usize,
    /// Host addresses that could not even be parsed — a host-list typo.
    pub invalid: usize,
    /// Hosts still running when the dashboard was quit. Never an error.
    pub pending: usize,
    /// Checked hosts whose trust could not be verified (no system CA bundle).
    pub trust_unknown: usize,
}

impl RunTally {
    /// Hosts that were checked, whatever their verdict.
    pub fn checked(&self) -> usize {
        self.healthy + self.warning + self.critical
    }

    /// The worst verdict among checked hosts, or `None` when none was checked.
    pub fn worst(&self) -> Option<Verdict> {
        if self.critical > 0 {
            Some(Verdict::Critical)
        } else if self.warning > 0 {
            Some(Verdict::Warning)
        } else if self.healthy > 0 {
            Some(Verdict::Healthy)
        } else {
            None
        }
    }

    /// Every host of the run.
    fn total(&self) -> usize {
        self.checked() + self.unreachable + self.invalid + self.pending
    }
}

/// The exit status of a run that checked its hosts.
///
/// 1 beats 3, `--fail-on never` does not suppress 3, and a run where hosts
/// were attempted but none could be checked never exits 0 — not even with
/// `--allow-unreachable`. Invalid addresses are never forgiven.
pub(crate) fn exit_status(t: &RunTally, gate: Gate) -> RunStatus {
    if let Some(threshold) = gate.fail_on.threshold() {
        if t.worst().is_some_and(|worst| worst >= threshold) {
            return RunStatus::CertificateProblem;
        }
    }
    let forgiven = gate.allow_unreachable && t.checked() > 0;
    if t.invalid > 0 || (t.unreachable > 0 && !forgiven) {
        return RunStatus::Unchecked;
    }
    RunStatus::Ok
}

/// Lines explaining a non-zero exit status, for `main` to log with `error!`.
/// Empty for [`RunStatus::Ok`].
///
/// For exit 1 there is one line per finding that caused it, then always a
/// final summary line naming the counts, the code, and how to change it.
pub(crate) fn explain(
    reports: &[HostReport],
    t: &RunTally,
    gate: Gate,
    status: RunStatus,
) -> Vec<String> {
    if status == RunStatus::Ok {
        return Vec::new();
    }

    let mut lines = Vec::new();
    if status == RunStatus::CertificateProblem {
        if let Some(threshold) = gate.fail_on.threshold() {
            for report in reports {
                for finding in &report.status.findings {
                    if !finding.allowed && finding.severity.verdict() >= threshold {
                        lines.push(format!(
                            "{}: {} - {}: {}",
                            report.label,
                            report.status.verdict.label(),
                            finding.code.label(),
                            finding.message
                        ));
                    }
                }
            }
        }
    }

    let reason = match status {
        RunStatus::CertificateProblem => format!(
            "certificate problem at --fail-on {}; report only: --fail-on never; \
             accept one finding: --allow <finding>",
            gate.fail_on.as_str()
        ),
        RunStatus::Unchecked if t.invalid > 0 => "invalid host address; fix the host list".into(),
        RunStatus::Unchecked if t.checked() == 0 => "no host could be checked".into(),
        RunStatus::Unchecked => {
            "host(s) could not be checked; tolerate unreachable hosts: --allow-unreachable".into()
        }
        RunStatus::Usage => "usage or configuration error".into(),
        RunStatus::Internal => "internal error".into(),
        RunStatus::Ok => "ok".into(),
    };
    let not_finished = if t.pending > 0 {
        format!(", {} not finished", t.pending)
    } else {
        String::new()
    };
    lines.push(format!(
        "{} host(s): {} critical, {} warning, {} healthy, {} not checked{} -> exit {} ({})",
        t.total(),
        t.critical,
        t.warning,
        t.healthy,
        t.unreachable + t.invalid,
        not_finished,
        status as u8,
        reason
    ));
    lines
}

/// Notes about what a run tolerated or could not verify, for `main` to log
/// with `warn!`.
pub(crate) fn notes(t: &RunTally, gate: Gate, status: RunStatus) -> Vec<String> {
    let mut lines = Vec::new();
    if status == RunStatus::Ok && gate.allow_unreachable && t.unreachable > 0 {
        lines.push(format!(
            "{} host(s) could not be checked (ignored: --allow-unreachable)",
            t.unreachable
        ));
    }
    if t.trust_unknown > 0 {
        lines.push(format!(
            "trust not verified for {} host(s): no system CA bundle was found, \
             so untrusted chains are not reported",
            t.trust_unknown
        ));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlschecker::verdict::{Assessment, Finding, FindingCode, Severity};

    fn gate(fail_on: FailOn, allow_unreachable: bool) -> Gate {
        Gate {
            fail_on,
            allow_unreachable,
        }
    }

    /// A tally whose worst verdict is `worst`, with `checked` checked hosts.
    fn tally(
        worst: Option<Verdict>,
        checked: usize,
        unreachable: usize,
        invalid: usize,
    ) -> RunTally {
        let mut t = RunTally {
            unreachable,
            invalid,
            ..RunTally::default()
        };
        if checked > 0 {
            match worst.unwrap_or(Verdict::Healthy) {
                Verdict::Healthy => t.healthy = checked,
                Verdict::Warning => t.warning = checked,
                Verdict::Critical => t.critical = checked,
            }
        }
        t
    }

    /// The reference model: `exit_status` must agree with it on every input.
    fn expected(
        worst: Option<Verdict>,
        fail_on: FailOn,
        checked: usize,
        unreachable: usize,
        allow: bool,
        invalid: usize,
    ) -> RunStatus {
        let failing = matches!(
            (worst, fail_on),
            (Some(Verdict::Critical), FailOn::Critical | FailOn::Warning)
                | (Some(Verdict::Warning), FailOn::Warning)
        );
        if failing {
            RunStatus::CertificateProblem
        } else if invalid > 0 || (unreachable > 0 && !(allow && checked > 0)) {
            RunStatus::Unchecked
        } else {
            RunStatus::Ok
        }
    }

    // 20
    #[test]
    fn test_exit_status_table() {
        let worsts = [
            None,
            Some(Verdict::Healthy),
            Some(Verdict::Warning),
            Some(Verdict::Critical),
        ];
        for worst in worsts {
            for fail_on in [FailOn::Critical, FailOn::Warning, FailOn::Never] {
                for unreachable in [0, 1] {
                    for allow in [false, true] {
                        for checked in [0, 1] {
                            for invalid in [0, 1] {
                                // A worst verdict needs a checked host.
                                let worst = if checked == 0 { None } else { worst };
                                let t = tally(worst, checked, unreachable, invalid);
                                assert_eq!(
                                    exit_status(&t, gate(fail_on, allow)),
                                    expected(worst, fail_on, checked, unreachable, allow, invalid),
                                    "{t:?} {fail_on:?} allow_unreachable={allow}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn test_exit_status_named_rows() {
        let critical = Some(Verdict::Critical);
        let warning = Some(Verdict::Warning);
        let default = gate(FailOn::Critical, false);
        let allow = gate(FailOn::Critical, true);
        let never = gate(FailOn::Never, false);

        // Critical + unreachable: 1 beats 3.
        assert_eq!(
            exit_status(&tally(critical, 1, 1, 0), default),
            RunStatus::CertificateProblem
        );
        // Warning only: 0 by default, 1 with --fail-on warning.
        assert_eq!(
            exit_status(&tally(warning, 1, 0, 0), default),
            RunStatus::Ok
        );
        assert_eq!(
            exit_status(&tally(warning, 1, 0, 0), gate(FailOn::Warning, false)),
            RunStatus::CertificateProblem
        );
        // Unreachable only.
        assert_eq!(
            exit_status(&tally(None, 0, 1, 0), default),
            RunStatus::Unchecked
        );
        // Unreachable + allow + 1 checked.
        assert_eq!(
            exit_status(&tally(Some(Verdict::Healthy), 1, 1, 0), allow),
            RunStatus::Ok
        );
        // Unreachable + allow + 0 checked: never exit 0 with nothing checked.
        assert_eq!(
            exit_status(&tally(None, 0, 1, 0), allow),
            RunStatus::Unchecked
        );
        // Invalid + allow + checked: invalid addresses are never forgiven.
        assert_eq!(
            exit_status(&tally(Some(Verdict::Healthy), 1, 0, 1), allow),
            RunStatus::Unchecked
        );
        // --fail-on never does not suppress 3...
        assert_eq!(
            exit_status(&tally(critical, 1, 1, 0), never),
            RunStatus::Unchecked
        );
        // ...but does suppress 1.
        assert_eq!(exit_status(&tally(critical, 1, 0, 0), never), RunStatus::Ok);
        // Only pending hosts (dashboard quit early): not an error.
        let pending = RunTally {
            pending: 3,
            ..RunTally::default()
        };
        assert_eq!(exit_status(&pending, default), RunStatus::Ok);
    }

    // 21
    #[test]
    fn test_numeric_contract() {
        assert_eq!(RunStatus::Ok as u8, 0);
        assert_eq!(RunStatus::CertificateProblem as u8, 1);
        assert_eq!(RunStatus::Usage as u8, 2);
        assert_eq!(RunStatus::Unchecked as u8, 3);
        assert_eq!(RunStatus::Internal as u8, 4);

        assert_eq!(FailOn::default(), FailOn::Critical);
        assert_eq!(FailOn::Critical.threshold(), Some(Verdict::Critical));
        assert_eq!(FailOn::Warning.threshold(), Some(Verdict::Warning));
        assert_eq!(FailOn::Never.threshold(), None);
        for f in [FailOn::Critical, FailOn::Warning, FailOn::Never] {
            assert_eq!(
                serde_json::to_value(f).unwrap(),
                serde_json::json!(f.as_str())
            );
            assert_eq!(
                serde_json::from_value::<FailOn>(serde_json::json!(f.as_str())).unwrap(),
                f
            );
        }
    }

    #[test]
    fn test_tally_worst_and_checked() {
        assert_eq!(RunTally::default().worst(), None);
        let t = RunTally {
            healthy: 2,
            warning: 1,
            unreachable: 4,
            pending: 1,
            ..RunTally::default()
        };
        assert_eq!(t.worst(), Some(Verdict::Warning));
        assert_eq!(t.checked(), 3);
        assert_eq!(t.total(), 8);
    }

    fn mismatch_report() -> HostReport {
        HostReport {
            index: 0,
            label: "wrong.example".to_string(),
            port: 443,
            tls: crate::tests::make_test_tls(),
            status: Assessment {
                verdict: Verdict::Critical,
                findings: vec![
                    Finding {
                        code: FindingCode::HostnameMismatch,
                        severity: Severity::Critical,
                        allowed: false,
                        message: "not valid for 'wrong.example'".to_string(),
                    },
                    Finding {
                        code: FindingCode::SelfSigned,
                        severity: Severity::Warning,
                        allowed: false,
                        message: "Certificate is self-signed".to_string(),
                    },
                ],
            },
        }
    }

    // 22
    #[test]
    fn test_explain_certificate_problem() {
        let t = RunTally {
            critical: 1,
            unreachable: 1,
            ..RunTally::default()
        };
        let g = gate(FailOn::Critical, false);
        let lines = explain(&[mismatch_report()], &t, g, RunStatus::CertificateProblem);
        assert_eq!(
            lines,
            vec![
                "wrong.example: Critical - HOSTNAME MISMATCH: not valid for 'wrong.example'"
                    .to_string(),
                "2 host(s): 1 critical, 0 warning, 0 healthy, 1 not checked -> exit 1 \
                 (certificate problem at --fail-on critical; report only: --fail-on never; \
                 accept one finding: --allow <finding>)"
                    .to_string(),
            ]
        );

        // With --fail-on warning the Warning finding is named too.
        let lines = explain(
            &[mismatch_report()],
            &t,
            gate(FailOn::Warning, false),
            RunStatus::CertificateProblem,
        );
        assert!(lines[1].contains("SELF-SIGNED"));
        assert!(lines.last().unwrap().contains("--fail-on warning"));
    }

    #[test]
    fn test_explain_unchecked() {
        let g = gate(FailOn::Critical, false);
        let some = RunTally {
            healthy: 1,
            unreachable: 1,
            pending: 2,
            ..RunTally::default()
        };
        let lines = explain(&[], &some, g, RunStatus::Unchecked);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].starts_with(
            "4 host(s): 0 critical, 0 warning, 1 healthy, 1 not checked, 2 not finished -> exit 3"
        ));
        assert!(lines[0].contains("--allow-unreachable"));

        let none = RunTally {
            unreachable: 2,
            ..RunTally::default()
        };
        let lines = explain(&[], &none, g, RunStatus::Unchecked);
        assert!(lines[0].contains("no host could be checked"));

        let invalid = RunTally {
            healthy: 1,
            invalid: 1,
            ..RunTally::default()
        };
        let lines = explain(
            &[],
            &invalid,
            gate(FailOn::Critical, true),
            RunStatus::Unchecked,
        );
        assert!(lines[0].contains("invalid host address; fix the host list"));
    }

    #[test]
    fn test_explain_and_notes_are_silent_when_ok() {
        let t = RunTally {
            healthy: 2,
            ..RunTally::default()
        };
        let g = gate(FailOn::Critical, false);
        assert!(explain(&[], &t, g, RunStatus::Ok).is_empty());
        assert!(notes(&t, g, RunStatus::Ok).is_empty());
    }

    #[test]
    fn test_notes() {
        let t = RunTally {
            healthy: 1,
            unreachable: 2,
            trust_unknown: 1,
            ..RunTally::default()
        };
        let g = gate(FailOn::Critical, true);
        let lines = notes(&t, g, exit_status(&t, g));
        assert_eq!(
            lines,
            vec![
                "2 host(s) could not be checked (ignored: --allow-unreachable)".to_string(),
                "trust not verified for 1 host(s): no system CA bundle was found, so \
                 untrusted chains are not reported"
                    .to_string(),
            ]
        );
    }
}
