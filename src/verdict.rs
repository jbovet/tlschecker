//! One status for every frontend.
//!
//! [`assess`] turns a checked host ([`TLS`]) plus the run's [`VerdictPolicy`]
//! into an [`Assessment`]: a [`Verdict`] (`Healthy` / `Warning` / `Critical`)
//! and the [`Finding`]s behind it. The CLI summary, text and JSON output, the
//! dashboard, the Prometheus `tlschecker_verdict` gauge and the process exit
//! code all read this one function, so they cannot disagree about a host.
//!
//! The assessment is a pure function of its inputs, computed on demand and
//! never stored on [`TLS`]: it cannot go stale after
//! [`TLS::apply_scan`], [`TLS::apply_revocation`] or [`TLS::apply_ct`].
//!
//! # Severities
//!
//! - **Critical** — every validating client rejects the certificate now or
//!   very soon, whatever trust store it uses: expired, revoked, not valid for
//!   the checked name, or inside the critical expiry window.
//! - **Warning** — the outcome depends on the client or its trust store, or
//!   security is weakened: self-signed, untrusted chain (private CAs are
//!   legitimate), chain defects, weak algorithms, issuance problems, or inside
//!   the warning expiry window.
//! - **Info** — informational only. The one Info finding is `not-in-ct`, since
//!   private certificates are routinely absent from public CT logs.
//!
//! | Source | Code | Severity | Label | Allowable |
//! |---|---|---|---|---|
//! | `certificate.is_expired` | `expired` | Critical | `EXPIRED` | no |
//! | `RevocationStatus::Revoked` | `revoked` | Critical | `REVOKED` | no |
//! | critical expiry window | `expires-soon` | Critical | `EXPIRES SOON` | no |
//! | warning expiry window | `expires-soon` | Warning | `EXPIRES SOON` | no |
//! | `HostnameMismatch` | `hostname-mismatch` | Critical | `HOSTNAME MISMATCH` | yes |
//! | `certificate.is_self_signed` | `self-signed` | Warning | `SELF-SIGNED` | yes |
//! | `Untrusted` | `untrusted` | Warning | `UNTRUSTED` | yes |
//! | `InvalidChainSignature` | `invalid-chain-signature` | Warning | `INVALID CHAIN SIGNATURE` | yes |
//! | `IncompleteChain` | `incomplete-chain` | Warning | `INCOMPLETE CHAIN` | yes |
//! | `InvalidChainOrder` | `invalid-chain-order` | Warning | `INVALID CHAIN ORDER` | yes |
//! | `WeakSignatureAlgorithm` | `weak-signature` | Warning | `WEAK ALGORITHM` | yes |
//! | `ExpiringIntermediate` | `expiring-intermediate` | Warning | `EXPIRING INTERMEDIATE` | yes |
//! | `WeakProtocol` | `weak-protocol` | Warning | `WEAK PROTOCOL` | yes |
//! | `WeakCipher` | `weak-cipher` | Warning | `WEAK CIPHER` | yes |
//! | `CertificateMisissuance` | `misissuance` | Warning | `MISISSUANCE` | yes |
//! | `NotInCertificateTransparency` | `not-in-ct` | Info | `NOT IN CT LOG` | yes |
//!
//! # Expiry windows
//!
//! Comparisons are "fewer than N" everywhere. For certificates with a lifetime
//! of 90 days or more the windows are fixed: Critical below
//! [`DEFAULT_CRITICAL_DAYS`] days left, Warning below [`DEFAULT_WARNING_DAYS`].
//! Shorter-lived certificates scale with their lifetime — Critical in its last
//! sixth, Warning in its last third — so a 6-day certificate is Critical below
//! 24 hours left and Warning below 48. An explicit
//! [`VerdictPolicy::min_validity_days`] (`--min-validity`) replaces the
//! critical window with `days < N` (0 disables it, leaving only expiry
//! Critical); the warning window always applies.
//!
//! # Never a finding
//!
//! These say nothing bad about the certificate and never produce a finding,
//! at any severity: revocation `Unknown` / `NotChecked`, CT `Unknown` or not
//! requested, trust `Unknown` (no system CA bundle), and the grade — `tls.grade`
//! is never read here.
//!
//! # Semver policy
//!
//! Raising a severity, or adding a Critical finding, is a breaking change.
//! Lowering a severity, or adding a Warning or Info finding, is a minor change.
//!
//! # Example
//!
//! ```no_run
//! use tlschecker::verdict::{Verdict, VerdictPolicy};
//! use tlschecker::TLS;
//!
//! let tls = TLS::from("example.com", None, false, false)?;
//! let assessment = tls.assess(&VerdictPolicy::default());
//! if assessment.verdict == Verdict::Critical {
//!     for finding in &assessment.findings {
//!         println!("{}: {}", finding.code.label(), finding.message);
//!     }
//! }
//! # Ok::<(), tlschecker::TLSError>(())
//! ```

use std::cmp::Reverse;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::{CertificateInfo, RevocationStatus, SecurityWarning, TLS};

/// Overall status of a checked host, ordered `Healthy < Warning < Critical`.
///
/// Deliberately exhaustive: frontends map every verdict to a color or exit
/// code, and a new level would have to be handled by each of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No finding at Warning or above (Info findings may be present).
    Healthy,
    /// At least one Warning finding; no Critical one.
    Warning,
    /// At least one Critical finding.
    Critical,
}

impl Verdict {
    /// Display text: `"Healthy"`, `"Warning"` or `"Critical"`.
    ///
    /// The only source of this text, so the summary table, text output and
    /// dashboard cannot spell a status differently.
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Healthy => "Healthy",
            Verdict::Warning => "Warning",
            Verdict::Critical => "Critical",
        }
    }
}

/// How serious a single [`Finding`] is, ordered `Info < Warning < Critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational: reported, never affects the verdict.
    Info,
    /// Makes the host at least `Warning`.
    Warning,
    /// Makes the host `Critical`.
    Critical,
}

impl Severity {
    /// The verdict this severity raises a host to (`Info` → `Healthy`).
    pub fn verdict(self) -> Verdict {
        match self {
            Severity::Info => Verdict::Healthy,
            Severity::Warning => Verdict::Warning,
            Severity::Critical => Verdict::Critical,
        }
    }

    /// Lowercase display text: `"info"`, `"warning"` or `"critical"`.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

/// Stable identifier of a finding.
///
/// [`FindingCode::as_str`] is its serialized (JSON) form and the value
/// `--allow` accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum FindingCode {
    /// The certificate has expired.
    Expired,
    /// The certificate was reported revoked (OCSP or CRL).
    Revoked,
    /// The certificate is inside an expiry window (see the module docs).
    ExpiresSoon,
    /// The certificate is not valid for the checked name.
    HostnameMismatch,
    /// The certificate is self-signed.
    SelfSigned,
    /// The chain does not build to a trusted system root.
    Untrusted,
    /// A chain link is not validly signed by its issuer.
    InvalidChainSignature,
    /// The issuer is missing from the presented chain.
    IncompleteChain,
    /// The presented chain is not in issuer order.
    InvalidChainOrder,
    /// A SHA-1 / MD5 signature in the leaf or chain.
    WeakSignature,
    /// An intermediate has expired or expires soon.
    ExpiringIntermediate,
    /// An obsolete protocol version: negotiated, or supported (`--scan`).
    WeakProtocol,
    /// A weak cipher suite: negotiated, or accepted (`--scan`).
    WeakCipher,
    /// The leaf deviates from issuance best practice.
    Misissuance,
    /// The leaf was not found in public Certificate Transparency logs.
    NotInCt,
}

impl FindingCode {
    /// Every code, in declaration order.
    pub const ALL: &'static [FindingCode] = &[
        FindingCode::Expired,
        FindingCode::Revoked,
        FindingCode::ExpiresSoon,
        FindingCode::HostnameMismatch,
        FindingCode::SelfSigned,
        FindingCode::Untrusted,
        FindingCode::InvalidChainSignature,
        FindingCode::IncompleteChain,
        FindingCode::InvalidChainOrder,
        FindingCode::WeakSignature,
        FindingCode::ExpiringIntermediate,
        FindingCode::WeakProtocol,
        FindingCode::WeakCipher,
        FindingCode::Misissuance,
        FindingCode::NotInCt,
    ];

    /// Kebab-case identifier, identical to the serde form and to the value
    /// `--allow` accepts (e.g. `"hostname-mismatch"`).
    pub fn as_str(self) -> &'static str {
        match self {
            FindingCode::Expired => "expired",
            FindingCode::Revoked => "revoked",
            FindingCode::ExpiresSoon => "expires-soon",
            FindingCode::HostnameMismatch => "hostname-mismatch",
            FindingCode::SelfSigned => "self-signed",
            FindingCode::Untrusted => "untrusted",
            FindingCode::InvalidChainSignature => "invalid-chain-signature",
            FindingCode::IncompleteChain => "incomplete-chain",
            FindingCode::InvalidChainOrder => "invalid-chain-order",
            FindingCode::WeakSignature => "weak-signature",
            FindingCode::ExpiringIntermediate => "expiring-intermediate",
            FindingCode::WeakProtocol => "weak-protocol",
            FindingCode::WeakCipher => "weak-cipher",
            FindingCode::Misissuance => "misissuance",
            FindingCode::NotInCt => "not-in-ct",
        }
    }

    /// Uppercase display label (e.g. `"HOSTNAME MISMATCH"`), the single source
    /// for every frontend.
    pub fn label(self) -> &'static str {
        match self {
            FindingCode::Expired => "EXPIRED",
            FindingCode::Revoked => "REVOKED",
            FindingCode::ExpiresSoon => "EXPIRES SOON",
            FindingCode::HostnameMismatch => "HOSTNAME MISMATCH",
            FindingCode::SelfSigned => "SELF-SIGNED",
            FindingCode::Untrusted => "UNTRUSTED",
            FindingCode::InvalidChainSignature => "INVALID CHAIN SIGNATURE",
            FindingCode::IncompleteChain => "INCOMPLETE CHAIN",
            FindingCode::InvalidChainOrder => "INVALID CHAIN ORDER",
            FindingCode::WeakSignature => "WEAK ALGORITHM",
            FindingCode::ExpiringIntermediate => "EXPIRING INTERMEDIATE",
            FindingCode::WeakProtocol => "WEAK PROTOCOL",
            FindingCode::WeakCipher => "WEAK CIPHER",
            FindingCode::Misissuance => "MISISSUANCE",
            FindingCode::NotInCt => "NOT IN CT LOG",
        }
    }

    /// Whether [`VerdictPolicy::allow`] may accept this finding.
    ///
    /// False only for `expired`, `revoked` and `expires-soon`: those are about
    /// the certificate's lifetime, and accepting them would hide exactly the
    /// failures a checker exists to catch. `--fail-on never` reports them
    /// without failing, and `--min-validity` tunes the expiry window.
    pub fn is_allowable(self) -> bool {
        !matches!(
            self,
            FindingCode::Expired | FindingCode::Revoked | FindingCode::ExpiresSoon
        )
    }
}

impl FromStr for FindingCode {
    type Err = String;

    /// Parses an [`FindingCode::as_str`] identifier, ignoring case.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let wanted = s.trim().to_ascii_lowercase();
        FindingCode::ALL
            .iter()
            .copied()
            .find(|code| code.as_str() == wanted)
            .ok_or_else(|| {
                let valid: Vec<&str> = FindingCode::ALL.iter().map(|c| c.as_str()).collect();
                format!(
                    "unknown finding '{}' (valid findings: {})",
                    s,
                    valid.join(", ")
                )
            })
    }
}

impl fmt::Display for FindingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One reason behind a host's [`Verdict`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// What was found.
    pub code: FindingCode,
    /// How serious it is. An allowed finding keeps its original severity.
    pub severity: Severity,
    /// Accepted via [`VerdictPolicy::allow`]: still reported, but it no
    /// longer affects the verdict.
    pub allowed: bool,
    /// Human-readable detail.
    pub message: String,
}

/// The status of one host: its verdict and every finding behind it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assessment {
    /// The highest severity among findings that are not allowed (`Healthy`
    /// when there are none).
    pub verdict: Verdict,
    /// Not-allowed findings first, highest severity first; allowed findings
    /// last. Construction order (expiry, revocation, self-signed, then the
    /// security warnings in their own order) is kept within each group.
    pub findings: Vec<Finding>,
}

/// Run-level settings that shape an [`Assessment`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerdictPolicy {
    /// Explicit `--min-validity` / `min_validity`: certificates with fewer
    /// than this many days left are Critical. `None` uses the default
    /// (lifetime-scaled) critical window.
    pub min_validity_days: Option<u32>,
    /// Findings accepted by the user (`--allow`). Codes that are not
    /// [allowable](FindingCode::is_allowable) are ignored.
    pub allow: Vec<FindingCode>,
}

/// Default critical expiry window, in days, for certificates whose lifetime
/// is 90 days or more.
pub const DEFAULT_CRITICAL_DAYS: i64 = 15;

/// Default warning expiry window, in days, for certificates whose lifetime is
/// 90 days or more.
pub const DEFAULT_WARNING_DAYS: i64 = 30;

/// Maps a [`SecurityWarning`] to its finding code and severity.
///
/// Exhaustive with no catch-all arm on purpose: a new warning variant does not
/// compile until it is given a severity here.
pub fn classify(w: &SecurityWarning) -> (FindingCode, Severity) {
    match w {
        SecurityWarning::HostnameMismatch(_) => (FindingCode::HostnameMismatch, Severity::Critical),
        SecurityWarning::Untrusted(_) => (FindingCode::Untrusted, Severity::Warning),
        SecurityWarning::InvalidChainSignature(_) => {
            (FindingCode::InvalidChainSignature, Severity::Warning)
        }
        SecurityWarning::IncompleteChain(_) => (FindingCode::IncompleteChain, Severity::Warning),
        SecurityWarning::InvalidChainOrder(_) => {
            (FindingCode::InvalidChainOrder, Severity::Warning)
        }
        SecurityWarning::WeakSignatureAlgorithm(_) => {
            (FindingCode::WeakSignature, Severity::Warning)
        }
        SecurityWarning::ExpiringIntermediate(_) => {
            (FindingCode::ExpiringIntermediate, Severity::Warning)
        }
        SecurityWarning::WeakProtocol(_) => (FindingCode::WeakProtocol, Severity::Warning),
        SecurityWarning::WeakCipher(_) => (FindingCode::WeakCipher, Severity::Warning),
        SecurityWarning::CertificateMisissuance(_) => (FindingCode::Misissuance, Severity::Warning),
        SecurityWarning::NotInCertificateTransparency(_) => (FindingCode::NotInCt, Severity::Info),
    }
}

impl SecurityWarning {
    /// This warning's finding code (see [`classify`]).
    pub fn code(&self) -> FindingCode {
        classify(self).0
    }
}

/// An expiry window: fewer than this many days, or hours, left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Window {
    Days(i64),
    Hours(i64),
}

/// The certificate's total lifetime in whole hours (rounded to the nearest
/// hour, so a Let's Encrypt `90 days - 1 s` span is exactly 2160), or `None`
/// when the validity timestamps are unknown or inverted.
fn lifetime_hours(c: &CertificateInfo) -> Option<i64> {
    (c.valid_from_unix > 0 && c.valid_to_unix > c.valid_from_unix)
        .then(|| (c.valid_to_unix - c.valid_from_unix).saturating_add(1800) / 3600)
}

/// The default window: `days`, or the last `1/fraction` of the lifetime when
/// that is shorter. There is no step at 90 days: a 90-day lifetime's sixth is
/// exactly 15 days and its third exactly 30.
fn default_window(days: i64, fraction: i64, lifetime: Option<i64>) -> Window {
    match lifetime {
        Some(l) if l / fraction < days * 24 => Window::Hours(l / fraction),
        _ => Window::Days(days),
    }
}

/// Whether the certificate has fewer than the window's days/hours left.
fn within(c: &CertificateInfo, w: Window) -> bool {
    match w {
        Window::Days(n) => i64::from(c.validity_days) < n,
        Window::Hours(h) => i64::from(c.validity_hours) < h,
    }
}

/// Describes why a certificate is inside `window`. `share` names the fraction
/// of the lifetime an hours window covers ("sixth" / "third"); `explicit` is
/// the user's own `--min-validity`, named as such.
fn window_message(
    c: &CertificateInfo,
    window: Window,
    share: &str,
    lifetime: Option<i64>,
    explicit: bool,
) -> String {
    match window {
        Window::Days(n) if explicit => {
            format!("{} days left (below --min-validity {})", c.validity_days, n)
        }
        Window::Days(n) => format!("{} days left (below {} days)", c.validity_days, n),
        Window::Hours(h) => format!(
            "{} hours left (below {} hours, the last {} of its {}-hour lifetime)",
            c.validity_hours,
            h,
            share,
            lifetime.unwrap_or(0)
        ),
    }
}

/// The (at most one) expiry finding: expired, else the critical window, else
/// the warning window.
fn expiry_finding(
    c: &CertificateInfo,
    min_validity_days: Option<u32>,
) -> Option<(FindingCode, Severity, String)> {
    if c.is_expired {
        return Some((
            FindingCode::Expired,
            Severity::Critical,
            format!("Certificate expired on {}", c.valid_to),
        ));
    }

    let lifetime = lifetime_hours(c);
    let critical = match min_validity_days {
        Some(n) => Window::Days(i64::from(n)),
        None => default_window(DEFAULT_CRITICAL_DAYS, 6, lifetime),
    };
    let warning = default_window(DEFAULT_WARNING_DAYS, 3, lifetime);

    if within(c, critical) {
        Some((
            FindingCode::ExpiresSoon,
            Severity::Critical,
            window_message(c, critical, "sixth", lifetime, min_validity_days.is_some()),
        ))
    } else if within(c, warning) {
        Some((
            FindingCode::ExpiresSoon,
            Severity::Warning,
            window_message(c, warning, "third", lifetime, false),
        ))
    } else {
        None
    }
}

/// Assesses a checked host under `policy`.
///
/// Pure and cheap: call it whenever a status is needed rather than caching
/// the result, so it always reflects the host's current data (on-demand
/// revocation or CT results included).
pub fn assess(tls: &TLS, policy: &VerdictPolicy) -> Assessment {
    let cert = &tls.certificate;
    let mut findings = Vec::new();
    let mut push = |code: FindingCode, severity: Severity, message: String| {
        findings.push(Finding {
            code,
            severity,
            allowed: policy.allow.contains(&code) && code.is_allowable(),
            message,
        });
    };

    if let Some((code, severity, message)) = expiry_finding(cert, policy.min_validity_days) {
        push(code, severity, message);
    }
    if let RevocationStatus::Revoked(reason) = &cert.revocation_status {
        push(
            FindingCode::Revoked,
            Severity::Critical,
            format!("Certificate is revoked: {}", reason),
        );
    }
    if cert.is_self_signed {
        push(
            FindingCode::SelfSigned,
            Severity::Warning,
            "Certificate is self-signed".to_string(),
        );
    }
    for warning in &cert.security_warnings {
        let (code, severity) = classify(warning);
        push(code, severity, warning.message().to_string());
    }

    // Stable: construction order survives within each (allowed, severity) group.
    findings.sort_by_key(|f| (f.allowed, Reverse(f.severity)));

    let verdict = findings
        .iter()
        .filter(|f| !f.allowed)
        .map(|f| f.severity.verdict())
        .max()
        .unwrap_or(Verdict::Healthy);

    Assessment { verdict, findings }
}

impl TLS {
    /// Assesses this host under `policy`; shorthand for [`assess`].
    pub fn assess(&self, policy: &VerdictPolicy) -> Assessment {
        assess(self, policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::CtStatus;
    use crate::grading;
    use crate::probe::{ProtoVersion, ProtocolSupport, TlsScan};
    use crate::tests::make_test_tls;
    use crate::TrustStatus;

    fn verdict_of(tls: &TLS) -> Verdict {
        tls.assess(&VerdictPolicy::default()).verdict
    }

    fn codes(a: &Assessment) -> Vec<FindingCode> {
        a.findings.iter().map(|f| f.code).collect()
    }

    fn with_warning(w: SecurityWarning) -> TLS {
        let mut tls = make_test_tls();
        tls.certificate.security_warnings.push(w);
        tls
    }

    fn mismatch() -> SecurityWarning {
        SecurityWarning::HostnameMismatch("Certificate is not valid for 'x'".to_string())
    }

    // 1
    #[test]
    fn test_baseline_is_healthy_without_findings() {
        let tls = make_test_tls(); // 365 days left, 730-day lifetime, trust Unknown
        let a = tls.assess(&VerdictPolicy::default());
        assert_eq!(a.verdict, Verdict::Healthy);
        assert!(a.findings.is_empty());
    }

    // 2
    #[test]
    fn test_expired_is_critical_with_one_expiry_finding() {
        let mut tls = make_test_tls();
        tls.certificate.is_expired = true;
        tls.certificate.validity_days = -3;
        tls.certificate.validity_hours = -72;
        let a = tls.assess(&VerdictPolicy::default());
        assert_eq!(a.verdict, Verdict::Critical);
        assert_eq!(codes(&a), vec![FindingCode::Expired]);
        assert_eq!(
            a.findings[0].message,
            "Certificate expired on Dec 31 23:59:59 2026 GMT"
        );
    }

    // 3
    #[test]
    fn test_revoked_is_critical() {
        let mut tls = make_test_tls();
        tls.certificate.revocation_status = RevocationStatus::Revoked("via CRL".to_string());
        let a = tls.assess(&VerdictPolicy::default());
        assert_eq!(a.verdict, Verdict::Critical);
        assert_eq!(codes(&a), vec![FindingCode::Revoked]);
        assert_eq!(a.findings[0].message, "Certificate is revoked: via CRL");
    }

    // 4
    #[test]
    fn test_unknowns_never_count() {
        let mut unknown_revocation = make_test_tls();
        unknown_revocation.certificate.revocation_status = RevocationStatus::Unknown;
        let mut not_checked = make_test_tls();
        not_checked.certificate.revocation_status = RevocationStatus::NotChecked;
        let mut ct_unknown = make_test_tls();
        ct_unknown.apply_ct(CtStatus::Unknown);
        let mut trust_unknown = make_test_tls();
        trust_unknown.certificate.trust = TrustStatus::Unknown;

        for tls in [unknown_revocation, not_checked, ct_unknown, trust_unknown] {
            let a = tls.assess(&VerdictPolicy::default());
            assert_eq!(a.verdict, Verdict::Healthy);
            assert!(
                a.findings.is_empty(),
                "unexpected findings {:?}",
                a.findings
            );
        }
    }

    // 5
    #[test]
    fn test_not_in_ct_is_info_and_healthy() {
        let mut tls = make_test_tls();
        tls.apply_ct(CtStatus::NotLogged);
        let a = tls.assess(&VerdictPolicy::default());
        assert_eq!(a.verdict, Verdict::Healthy);
        assert_eq!(codes(&a), vec![FindingCode::NotInCt]);
        assert_eq!(a.findings[0].severity, Severity::Info);
    }

    // 6
    #[test]
    fn test_hostname_mismatch_is_critical() {
        assert_eq!(verdict_of(&with_warning(mismatch())), Verdict::Critical);
    }

    // 7
    #[test]
    fn test_warning_level_findings() {
        let mut untrusted = with_warning(SecurityWarning::Untrusted(
            "Certificate chain is not trusted: self-signed certificate".to_string(),
        ));
        untrusted.certificate.trust = TrustStatus::Untrusted {
            reason: "self-signed certificate".to_string(),
        };
        let invalid_sig = with_warning(SecurityWarning::InvalidChainSignature("x".to_string()));
        let mut self_signed = make_test_tls();
        self_signed.certificate.is_self_signed = true;
        let misissuance = with_warning(SecurityWarning::CertificateMisissuance("x".to_string()));

        for tls in [untrusted, invalid_sig, self_signed, misissuance] {
            assert_eq!(verdict_of(&tls), Verdict::Warning);
        }
    }

    // Moved from the dashboard, which used to own its own verdict rules.
    #[test]
    fn test_verdict_warning_on_security_warning() {
        let tls = with_warning(SecurityWarning::IncompleteChain("missing".to_string()));
        assert_eq!(verdict_of(&tls), Verdict::Warning);
    }

    #[test]
    fn test_verdict_expiring_soon() {
        let mut tls = make_test_tls();
        tls.certificate.validity_days = 10;
        assert_eq!(verdict_of(&tls), Verdict::Critical);
        tls.certificate.validity_days = 25;
        assert_eq!(verdict_of(&tls), Verdict::Warning);
        tls.certificate.validity_days = 31;
        assert_eq!(verdict_of(&tls), Verdict::Healthy);
    }

    // 8
    #[test]
    fn test_issue_205_repro_shape() {
        let mut tls = make_test_tls();
        tls.certificate.is_self_signed = true;
        tls.certificate.trust = TrustStatus::Untrusted {
            reason: "self-signed certificate".to_string(),
        };
        tls.certificate.security_warnings = vec![
            SecurityWarning::Untrusted("not trusted".to_string()),
            SecurityWarning::CertificateMisissuance("serial".to_string()),
            mismatch(),
        ];
        let a = tls.assess(&VerdictPolicy::default());
        assert_eq!(a.verdict, Verdict::Critical);
        assert_eq!(a.findings[0].code, FindingCode::HostnameMismatch);
    }

    // 9
    #[test]
    fn test_classify_table() {
        let s = || "m".to_string();
        let table = [
            (
                SecurityWarning::WeakSignatureAlgorithm(s()),
                FindingCode::WeakSignature,
                Severity::Warning,
            ),
            (
                SecurityWarning::IncompleteChain(s()),
                FindingCode::IncompleteChain,
                Severity::Warning,
            ),
            (
                SecurityWarning::InvalidChainOrder(s()),
                FindingCode::InvalidChainOrder,
                Severity::Warning,
            ),
            (
                SecurityWarning::HostnameMismatch(s()),
                FindingCode::HostnameMismatch,
                Severity::Critical,
            ),
            (
                SecurityWarning::ExpiringIntermediate(s()),
                FindingCode::ExpiringIntermediate,
                Severity::Warning,
            ),
            (
                SecurityWarning::WeakProtocol(s()),
                FindingCode::WeakProtocol,
                Severity::Warning,
            ),
            (
                SecurityWarning::WeakCipher(s()),
                FindingCode::WeakCipher,
                Severity::Warning,
            ),
            (
                SecurityWarning::NotInCertificateTransparency(s()),
                FindingCode::NotInCt,
                Severity::Info,
            ),
            (
                SecurityWarning::Untrusted(s()),
                FindingCode::Untrusted,
                Severity::Warning,
            ),
            (
                SecurityWarning::CertificateMisissuance(s()),
                FindingCode::Misissuance,
                Severity::Warning,
            ),
            (
                SecurityWarning::InvalidChainSignature(s()),
                FindingCode::InvalidChainSignature,
                Severity::Warning,
            ),
        ];
        for (warning, code, severity) in table {
            assert_eq!(classify(&warning), (code, severity), "{warning:?}");
            assert_eq!(warning.code(), code);
            assert_eq!(warning.message(), "m");
        }
    }

    // 10
    #[test]
    fn test_allow_accepts_a_finding_but_keeps_reporting_it() {
        let tls = with_warning(mismatch());
        let policy = VerdictPolicy {
            allow: vec![FindingCode::HostnameMismatch],
            ..VerdictPolicy::default()
        };
        let a = tls.assess(&policy);
        assert_eq!(a.verdict, Verdict::Healthy);
        let finding = a.findings.last().unwrap();
        assert_eq!(finding.code, FindingCode::HostnameMismatch);
        assert!(finding.allowed);
        assert_eq!(finding.severity, Severity::Critical);

        // With another finding present, the allowed one sorts last.
        let mut tls = with_warning(mismatch());
        tls.certificate.is_self_signed = true;
        let a = tls.assess(&policy);
        assert_eq!(a.verdict, Verdict::Warning);
        assert_eq!(
            codes(&a),
            vec![FindingCode::SelfSigned, FindingCode::HostnameMismatch]
        );
        assert!(!a.findings[0].allowed);
        assert!(a.findings[1].allowed);
    }

    #[test]
    fn test_allow_cannot_accept_lifetime_findings() {
        let policy = VerdictPolicy {
            allow: vec![
                FindingCode::Expired,
                FindingCode::Revoked,
                FindingCode::ExpiresSoon,
            ],
            ..VerdictPolicy::default()
        };
        let mut expired = make_test_tls();
        expired.certificate.is_expired = true;
        let a = expired.assess(&policy);
        assert_eq!(a.verdict, Verdict::Critical);
        assert!(!a.findings[0].allowed);

        let mut revoked = make_test_tls();
        revoked.certificate.revocation_status = RevocationStatus::Revoked("r".to_string());
        assert_eq!(revoked.assess(&policy).verdict, Verdict::Critical);

        let mut soon = make_test_tls();
        soon.certificate.validity_days = 3;
        assert_eq!(soon.assess(&policy).verdict, Verdict::Critical);
    }

    fn days_left(days: i32, policy: &VerdictPolicy) -> Assessment {
        let mut tls = make_test_tls();
        tls.certificate.validity_days = days;
        tls.certificate.validity_hours = days.saturating_mul(24);
        tls.assess(policy)
    }

    // 11
    #[test]
    fn test_default_day_windows() {
        let policy = VerdictPolicy::default();
        for (days, expected) in [
            (14, Verdict::Critical),
            (15, Verdict::Warning),
            (29, Verdict::Warning),
            (30, Verdict::Healthy),
        ] {
            assert_eq!(days_left(days, &policy).verdict, expected, "{days} days");
        }
        let a = days_left(14, &policy);
        assert_eq!(a.findings[0].code, FindingCode::ExpiresSoon);
        assert_eq!(a.findings[0].message, "14 days left (below 15 days)");
        assert_eq!(
            days_left(20, &policy).findings[0].message,
            "20 days left (below 30 days)"
        );
    }

    // 12
    #[test]
    fn test_explicit_min_validity() {
        let policy = |n: u32| VerdictPolicy {
            min_validity_days: Some(n),
            ..VerdictPolicy::default()
        };
        for (n, days, expected) in [
            (30, 29, Verdict::Critical),
            (30, 30, Verdict::Healthy),
            (7, 10, Verdict::Warning),
            (7, 6, Verdict::Critical),
            (0, 0, Verdict::Warning),
            (45, 40, Verdict::Critical),
        ] {
            assert_eq!(
                days_left(days, &policy(n)).verdict,
                expected,
                "--min-validity {n} with {days} days left"
            );
        }
        assert_eq!(
            days_left(29, &policy(30)).findings[0].message,
            "29 days left (below --min-validity 30)"
        );

        let mut expired = make_test_tls();
        expired.certificate.is_expired = true;
        expired.certificate.validity_days = -1;
        assert_eq!(expired.assess(&policy(0)).verdict, Verdict::Critical);

        // Extreme values must not overflow.
        assert_eq!(
            days_left(i32::MAX, &policy(u32::MAX)).verdict,
            Verdict::Critical
        );
    }

    /// A certificate with `lifetime_secs` of total validity and `hours` left.
    fn lifetime(lifetime_secs: i64, hours: i32) -> TLS {
        let mut tls = make_test_tls();
        let from = 1_700_000_000;
        tls.certificate.valid_from_unix = from;
        tls.certificate.valid_to_unix = from + lifetime_secs;
        tls.certificate.validity_hours = hours;
        tls.certificate.validity_days = hours / 24;
        tls
    }

    const HOUR: i64 = 3600;
    const DAY: i64 = 24 * HOUR;

    // 13
    #[test]
    fn test_lifetime_scaled_windows() {
        for (span, hours, expected) in [
            (6 * DAY, 72, Verdict::Healthy),
            (6 * DAY, 47, Verdict::Warning),
            (6 * DAY, 23, Verdict::Critical),
            (DAY, 9, Verdict::Healthy),
            (DAY, 7, Verdict::Warning),
            (DAY, 3, Verdict::Critical),
            (47 * DAY, 480, Verdict::Healthy),
            (47 * DAY, 360, Verdict::Warning),
            (47 * DAY, 180, Verdict::Critical),
        ] {
            assert_eq!(
                verdict_of(&lifetime(span, hours)),
                expected,
                "{}h lifetime, {hours}h left",
                span / HOUR
            );
        }
        assert_eq!(
            lifetime(6 * DAY, 23)
                .assess(&VerdictPolicy::default())
                .findings[0]
                .message,
            "23 hours left (below 24 hours, the last sixth of its 144-hour lifetime)"
        );
        assert_eq!(
            lifetime(6 * DAY, 47)
                .assess(&VerdictPolicy::default())
                .findings[0]
                .message,
            "47 hours left (below 48 hours, the last third of its 144-hour lifetime)"
        );
    }

    #[test]
    fn test_lets_encrypt_lifetime_uses_day_windows() {
        // 90 days minus one second: rounds to exactly 2160 hours, whose sixth
        // and third are the fixed 15 / 30 days.
        let le = |days: i32| {
            let mut tls = lifetime(7_775_999, days * 24);
            tls.certificate.validity_days = days;
            verdict_of(&tls)
        };
        assert_eq!(le(14), Verdict::Critical);
        assert_eq!(le(15), Verdict::Warning);
        assert_eq!(le(30), Verdict::Healthy);
    }

    #[test]
    fn test_unknown_lifetime_uses_fixed_windows() {
        let mut tls = lifetime(DAY, 7); // would be Warning if scaled
        tls.certificate.valid_from_unix = 0;
        tls.certificate.validity_days = 20;
        assert_eq!(verdict_of(&tls), Verdict::Warning);
        tls.certificate.validity_days = 40;
        assert_eq!(verdict_of(&tls), Verdict::Healthy);
    }

    #[test]
    fn test_min_validity_zero_keeps_scaled_warning_window() {
        let tls = lifetime(6 * DAY, 23);
        let a = tls.assess(&VerdictPolicy {
            min_validity_days: Some(0),
            ..VerdictPolicy::default()
        });
        assert_eq!(a.verdict, Verdict::Warning);
    }

    // 14
    #[test]
    fn test_grade_cap_implies_at_least_warning() {
        fn negotiated(version: &str, cipher: &str) -> TLS {
            let mut tls = make_test_tls();
            tls.cipher.version = version.to_string();
            tls.cipher.name = cipher.to_string();
            tls
        }
        fn scan(version: ProtoVersion, ciphers: &[&str]) -> TlsScan {
            TlsScan {
                protocols: vec![ProtocolSupport {
                    version,
                    tested: true,
                    supported: true,
                    ciphers: ciphers.iter().map(|c| c.to_string()).collect(),
                }],
            }
        }

        let mut self_signed = make_test_tls();
        self_signed.certificate.is_self_signed = true;
        let mut untrusted = with_warning(SecurityWarning::Untrusted("x".to_string()));
        untrusted.certificate.trust = TrustStatus::Untrusted {
            reason: "x".to_string(),
        };
        let mismatch = with_warning(mismatch());
        let invalid_sig = with_warning(SecurityWarning::InvalidChainSignature("x".to_string()));

        let mut fixtures: Vec<(&str, TLS, Option<TlsScan>)> = vec![
            ("self-signed", self_signed, None),
            ("untrusted", untrusted, None),
            ("mismatch", mismatch, None),
            ("invalid chain signature", invalid_sig, None),
            (
                "scan: obsolete protocol",
                make_test_tls(),
                Some(scan(ProtoVersion::Tls1_0, &["ECDHE-RSA-AES128-SHA"])),
            ),
            (
                "scan: weak cipher",
                make_test_tls(),
                Some(scan(ProtoVersion::Tls1_2, &["RC4-SHA"])),
            ),
            (
                "negotiated: TLS 1.0",
                negotiated("TLSv1", "ECDHE-RSA-AES128-SHA"),
                None,
            ),
            ("negotiated: SSLv3", negotiated("SSLv3", "AES128-SHA"), None),
            (
                "negotiated: weak cipher",
                negotiated("TLSv1.2", "RC4-SHA"),
                None,
            ),
        ];

        for (name, tls, scan) in &mut fixtures {
            // What `TLS::from` adds for the negotiated connection.
            let mut negotiated = crate::analyze_negotiated(&tls.cipher);
            tls.certificate.security_warnings.append(&mut negotiated);
            if let Some(scan) = scan {
                // What `apply_scan` adds.
                tls.certificate
                    .security_warnings
                    .append(&mut crate::analyze_scan(scan));
            }
            let grade = grading::calculate_grade(&crate::build_grading_input(
                &tls.cipher,
                &tls.certificate,
                scan.as_ref(),
            ));
            assert!(grade.score <= 69, "{name} should cap the grade");
            assert!(
                verdict_of(tls) >= Verdict::Warning,
                "{name}: grade {} ({}) but verdict {:?}",
                grade.grade,
                grade.score,
                verdict_of(tls)
            );
        }

        // The grade is never read.
        let mut graded = make_test_tls();
        let ungraded = verdict_of(&graded);
        graded.grade = Some(grading::TLSGrade {
            grade: "F".to_string(),
            score: 0,
            categories: vec![],
        });
        assert_eq!(verdict_of(&graded), ungraded);
    }

    // 15
    #[test]
    fn test_findings_order_by_severity_then_construction() {
        let mut tls = make_test_tls();
        tls.certificate.validity_days = 20; // expires-soon, Warning
        tls.certificate.is_self_signed = true; // Warning
        tls.certificate.security_warnings = vec![
            SecurityWarning::NotInCertificateTransparency("ct".to_string()), // Info
            SecurityWarning::IncompleteChain("chain".to_string()),           // Warning
            mismatch(),                                                      // Critical
            SecurityWarning::Untrusted("untrusted".to_string()),             // Warning, allowed
        ];
        let a = tls.assess(&VerdictPolicy {
            allow: vec![FindingCode::Untrusted],
            ..VerdictPolicy::default()
        });
        assert_eq!(
            codes(&a),
            vec![
                FindingCode::HostnameMismatch,
                FindingCode::ExpiresSoon,
                FindingCode::SelfSigned,
                FindingCode::IncompleteChain,
                FindingCode::NotInCt,
                FindingCode::Untrusted,
            ]
        );
    }

    // 16
    #[test]
    fn test_serde_forms() {
        assert_eq!(
            serde_json::to_value(Verdict::Critical).unwrap(),
            serde_json::json!("critical")
        );
        assert_eq!(
            serde_json::to_value(FindingCode::HostnameMismatch).unwrap(),
            serde_json::json!("hostname-mismatch")
        );
        for code in FindingCode::ALL {
            assert_eq!(
                serde_json::to_value(code).unwrap(),
                serde_json::json!(code.as_str())
            );
        }

        let a = with_warning(SecurityWarning::HostnameMismatch("nope".to_string()))
            .assess(&VerdictPolicy::default());
        assert_eq!(
            serde_json::to_value(&a).unwrap(),
            serde_json::json!({
                "verdict": "critical",
                "findings": [{
                    "code": "hostname-mismatch",
                    "severity": "critical",
                    "allowed": false,
                    "message": "nope"
                }]
            })
        );
        let back: Assessment = serde_json::from_value(serde_json::to_value(&a).unwrap()).unwrap();
        assert_eq!(back, a);
    }

    // 17
    #[test]
    fn test_finding_code_strings() {
        assert_eq!(FindingCode::ALL.len(), 15);
        for code in FindingCode::ALL {
            assert_eq!(code.as_str().parse::<FindingCode>(), Ok(*code));
            assert_eq!(
                code.as_str().to_ascii_uppercase().parse::<FindingCode>(),
                Ok(*code)
            );
            assert_eq!(code.to_string(), code.as_str());
            assert_eq!(
                code.is_allowable(),
                !matches!(
                    code,
                    FindingCode::Expired | FindingCode::Revoked | FindingCode::ExpiresSoon
                )
            );
        }
        let err = "bogus".parse::<FindingCode>().unwrap_err();
        assert!(err.contains("bogus"));
        for code in FindingCode::ALL {
            assert!(err.contains(code.as_str()), "{err} should list {code}");
        }
    }

    #[test]
    fn test_labels() {
        assert_eq!(Verdict::Healthy.label(), "Healthy");
        assert_eq!(Verdict::Warning.label(), "Warning");
        assert_eq!(Verdict::Critical.label(), "Critical");
        assert_eq!(Severity::Info.label(), "info");
        assert_eq!(Severity::Critical.verdict(), Verdict::Critical);
        assert_eq!(Severity::Info.verdict(), Verdict::Healthy);
        assert_eq!(FindingCode::WeakSignature.label(), "WEAK ALGORITHM");
        assert_eq!(FindingCode::NotInCt.label(), "NOT IN CT LOG");
    }

    // 18
    #[test]
    fn test_assessment_is_not_cached() {
        let mut tls = make_test_tls();
        assert_eq!(verdict_of(&tls), Verdict::Healthy);
        tls.apply_revocation(RevocationStatus::Revoked("via OCSP".to_string()), None);
        assert_eq!(verdict_of(&tls), Verdict::Critical);
    }
}
