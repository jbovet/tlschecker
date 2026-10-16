//! The versioned JSON output (`-o json`), schema version [`SCHEMA_VERSION`].
//!
//! JSON is the integration surface for scripts, so it is a contract: it is
//! built from dedicated output types here instead of serializing the
//! library's structs, and internal refactors cannot silently reshape it.
//! From schema version 1 on, changes are **additive only** (new keys); a
//! rename, removal or type change bumps `schema_version`.
//!
//! Shape:
//!
//! ```text
//! { "schema_version": 1,
//!   "results": [ { "input", "target", "host", "port", "outcome",
//!                  "error", "status", "connection", "certificate",
//!                  "grade", "scan", "ct" }, ... ] }
//! ```
//!
//! - Every key is always present; a value that does not apply is `null`
//!   (never the string `"None"`).
//! - `results` keeps the input order and includes hosts that could not be
//!   checked (`"outcome": "error"` with an `error` object and `null`
//!   `status`/`connection`/`certificate`).
//! - Timestamps are RFC 3339 UTC strings, with the Unix seconds alongside.

use serde::Serialize;
use tlschecker::ct::CtStatus;
use tlschecker::verdict::{FindingCode, Severity, Verdict};
use tlschecker::{rfc3339_from_unix, Chain, RevocationStatus, TrustStatus, TLS};

use crate::{display_target, parse_host_port, HostFailure, HostReport};

/// Version of the JSON schema produced by [`render`].
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// Renders a run as pretty-printed JSON: checked hosts and failures merged
/// back into input order.
pub(crate) fn render(reports: &[HostReport], failures: &[HostFailure]) -> String {
    let mut results: Vec<(usize, Entry)> = reports
        .iter()
        .map(|r| (r.index, Entry::checked(r)))
        .chain(failures.iter().map(|f| (f.index, Entry::failed(f))))
        .collect();
    results.sort_by_key(|(index, _)| *index);
    let output = Output {
        schema_version: SCHEMA_VERSION,
        results: results.into_iter().map(|(_, entry)| entry).collect(),
    };
    serde_json::to_string_pretty(&output).expect("JSON output is always serializable")
}

/// The library fills missing name attributes with the literal `"None"`;
/// the schema reports them as `null`.
fn opt(value: &str) -> Option<String> {
    (value != "None" && !value.is_empty()).then(|| value.to_string())
}

/// A Unix timestamp the library could not compute is stored as `0`.
fn unix(secs: i64) -> Option<i64> {
    (secs != 0).then_some(secs)
}

fn rfc3339(secs: i64) -> Option<String> {
    unix(secs).map(rfc3339_from_unix)
}

#[derive(Serialize)]
struct Output {
    schema_version: u32,
    results: Vec<Entry>,
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "lowercase")]
enum Outcome {
    Checked,
    Error,
}

#[derive(Serialize)]
struct Entry {
    /// The host exactly as given on the command line or in the config file.
    input: String,
    /// How the other outputs name the host: `host`, or `host:port` off 443.
    /// `null` when the input is not a valid address.
    target: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    outcome: Outcome,
    error: Option<ErrorInfo>,
    status: Option<Status>,
    connection: Option<Connection>,
    certificate: Option<Certificate>,
    grade: Option<Grade>,
    scan: Option<Scan>,
    ct: Option<Ct>,
}

impl Entry {
    fn checked(report: &HostReport) -> Self {
        let tls = &report.tls;
        Entry {
            input: report.label.clone(),
            target: Some(report.target()),
            host: Some(tls.certificate.hostname.clone()),
            port: Some(report.port),
            outcome: Outcome::Checked,
            error: None,
            status: Some(Status::from(report)),
            connection: Some(Connection::from(tls)),
            certificate: Some(Certificate::from(tls)),
            grade: tls.grade.as_ref().map(Grade::from),
            scan: tls.scan.as_ref().map(Scan::from),
            ct: tls
                .ct
                .as_ref()
                .map(|ct| Ct::new(ct, tls.ct_detail.as_deref())),
        }
    }

    fn failed(failure: &HostFailure) -> Self {
        // An invalid address has no host or port; any other failure parsed.
        let parsed = parse_host_port(&failure.label).ok();
        let port = parsed
            .as_ref()
            .map(|hp| hp.port.unwrap_or(crate::DEFAULT_TLS_PORT));
        Entry {
            input: failure.label.clone(),
            target: parsed
                .as_ref()
                .zip(port)
                .map(|(hp, p)| display_target(&hp.host, p)),
            host: parsed.map(|hp| hp.host),
            port,
            outcome: Outcome::Error,
            error: Some(ErrorInfo {
                kind: failure.kind.to_ascii_lowercase(),
                message: failure.detail.clone(),
            }),
            status: None,
            connection: None,
            certificate: None,
            grade: None,
            scan: None,
            ct: None,
        }
    }
}

#[derive(Serialize)]
struct ErrorInfo {
    /// `dns`, `connection`, `handshake`, `certificate`, `invalid`, `internal`
    /// or `error`.
    kind: String,
    message: String,
}

#[derive(Serialize)]
struct Status {
    verdict: Verdict,
    findings: Vec<FindingOut>,
}

#[derive(Serialize)]
struct FindingOut {
    code: FindingCode,
    severity: Severity,
    allowed: bool,
    message: String,
}

impl From<&HostReport> for Status {
    fn from(report: &HostReport) -> Self {
        Status {
            verdict: report.status.verdict,
            findings: report
                .status
                .findings
                .iter()
                .map(|f| FindingOut {
                    code: f.code,
                    severity: f.severity,
                    allowed: f.allowed,
                    message: f.message.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct Connection {
    /// Negotiated protocol as OpenSSL names it, e.g. `TLSv1.3`.
    protocol: String,
    cipher: String,
    cipher_bits: i32,
    alpn: Option<String>,
}

impl From<&TLS> for Connection {
    fn from(tls: &TLS) -> Self {
        Connection {
            protocol: tls.cipher.version.clone(),
            cipher: tls.cipher.name.clone(),
            cipher_bits: tls.cipher.bits,
            alpn: tls.cipher.alpn.clone(),
        }
    }
}

#[derive(Serialize)]
struct Certificate {
    subject: Subject,
    issuer: Issuer,
    not_before: Option<String>,
    not_after: Option<String>,
    not_before_unix: Option<i64>,
    not_after_unix: Option<i64>,
    /// Whole days left (negative once expired).
    days_remaining: i32,
    /// Whole hours left (negative once expired).
    hours_remaining: i32,
    expired: bool,
    /// Colon-separated uppercase hex.
    serial: String,
    /// X.509 version number, e.g. `3` (the encoded value plus one).
    version: Option<u8>,
    signature_algorithm: String,
    key: Key,
    fingerprints: Fingerprints,
    sans: Vec<String>,
    self_signed: bool,
    is_ca: bool,
    path_len: Option<u32>,
    validation_level: Option<String>,
    subject_key_id: Option<String>,
    authority_key_id: Option<String>,
    key_usage: Vec<String>,
    extended_key_usage: Vec<String>,
    trust: Trust,
    revocation: Revocation,
    urls: Urls,
    scts: Vec<SctOut>,
    /// Every certificate the server presented, leaf first.
    chain: Vec<ChainCert>,
}

impl From<&TLS> for Certificate {
    fn from(tls: &TLS) -> Self {
        let c = &tls.certificate;
        Certificate {
            subject: Subject {
                common_name: opt(&c.subject.common_name),
                organization: opt(&c.subject.organization),
                organizational_unit: opt(&c.subject.organization_unit),
                locality: opt(&c.subject.locality),
                state_or_province: opt(&c.subject.state_or_province),
                country: opt(&c.subject.country_or_region),
            },
            issuer: Issuer {
                common_name: opt(&c.issued.common_name),
                organization: opt(&c.issued.organization),
                country: opt(&c.issued.country_or_region),
            },
            not_before: rfc3339(c.valid_from_unix),
            not_after: rfc3339(c.valid_to_unix),
            not_before_unix: unix(c.valid_from_unix),
            not_after_unix: unix(c.valid_to_unix),
            days_remaining: c.validity_days,
            hours_remaining: c.validity_hours,
            expired: c.is_expired,
            serial: c.cert_sn.clone(),
            version: c.cert_ver.parse::<u8>().ok().and_then(|v| v.checked_add(1)),
            signature_algorithm: c.cert_alg.clone(),
            key: Key {
                algorithm: c.cert_key_algorithm.clone(),
                bits: c.cert_key_bits,
            },
            fingerprints: Fingerprints {
                sha256: c.cert_sha256.clone(),
                sha1: c.cert_sha1.clone(),
            },
            sans: c.sans.clone(),
            self_signed: c.is_self_signed,
            is_ca: c.is_ca,
            path_len: c.path_len,
            validation_level: c.validation_level.clone(),
            subject_key_id: c.subject_key_id.clone(),
            authority_key_id: c.authority_key_id.clone(),
            key_usage: c.key_usage.clone(),
            extended_key_usage: c.ext_key_usage.clone(),
            trust: Trust::from(&c.trust),
            revocation: Revocation::new(&c.revocation_status, c.revocation_detail.as_deref()),
            urls: Urls {
                ocsp: c.ocsp_urls.clone(),
                ca_issuers: c.ca_issuer_urls.clone(),
                crl: c.crl_urls.clone(),
            },
            scts: c
                .scts
                .iter()
                .map(|s| SctOut {
                    version: s.version,
                    log_id: s.log_id.clone(),
                    timestamp: s.timestamp.clone(),
                    timestamp_ms: s.timestamp_ms,
                })
                .collect(),
            chain: c
                .chain
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(ChainCert::from)
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct Subject {
    common_name: Option<String>,
    organization: Option<String>,
    organizational_unit: Option<String>,
    locality: Option<String>,
    state_or_province: Option<String>,
    country: Option<String>,
}

#[derive(Serialize)]
struct Issuer {
    common_name: Option<String>,
    organization: Option<String>,
    country: Option<String>,
}

#[derive(Serialize)]
struct Key {
    algorithm: String,
    bits: u32,
}

#[derive(Serialize)]
struct Fingerprints {
    sha256: String,
    sha1: String,
}

#[derive(Serialize)]
struct Trust {
    /// `trusted`, `untrusted` or `unknown` (no system trust store).
    status: &'static str,
    /// OpenSSL's verification error when `untrusted`.
    reason: Option<String>,
}

impl From<&TrustStatus> for Trust {
    fn from(trust: &TrustStatus) -> Self {
        match trust {
            TrustStatus::Trusted => Trust {
                status: "trusted",
                reason: None,
            },
            TrustStatus::Untrusted { reason } => Trust {
                status: "untrusted",
                reason: Some(reason.clone()),
            },
            TrustStatus::Unknown => Trust {
                status: "unknown",
                reason: None,
            },
        }
    }
}

#[derive(Serialize)]
struct Revocation {
    /// `good`, `revoked`, `unknown` or `not_checked`.
    status: &'static str,
    /// The revocation reason when `revoked`.
    reason: Option<String>,
    /// Why each OCSP responder / CRL distribution point failed when `unknown`.
    detail: Option<String>,
}

impl Revocation {
    fn new(status: &RevocationStatus, detail: Option<&str>) -> Self {
        let (status, reason) = match status {
            RevocationStatus::Good => ("good", None),
            RevocationStatus::Revoked(reason) => ("revoked", Some(reason.clone())),
            RevocationStatus::Unknown => ("unknown", None),
            RevocationStatus::NotChecked => ("not_checked", None),
        };
        Revocation {
            status,
            reason,
            detail: detail.map(str::to_string),
        }
    }
}

#[derive(Serialize)]
struct Urls {
    ocsp: Vec<String>,
    ca_issuers: Vec<String>,
    crl: Vec<String>,
}

#[derive(Serialize)]
struct SctOut {
    version: u8,
    /// Lowercase hex SHA-256 of the log's public key.
    log_id: String,
    timestamp: String,
    timestamp_ms: u64,
}

#[derive(Serialize)]
struct ChainCert {
    subject: Option<String>,
    issuer: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    not_before_unix: Option<i64>,
    not_after_unix: Option<i64>,
    signature_algorithm: String,
}

impl From<&Chain> for ChainCert {
    fn from(c: &Chain) -> Self {
        ChainCert {
            subject: opt(&c.subject),
            issuer: opt(&c.issuer),
            not_before: rfc3339(c.valid_from_unix),
            not_after: rfc3339(c.valid_to_unix),
            not_before_unix: unix(c.valid_from_unix),
            not_after_unix: unix(c.valid_to_unix),
            signature_algorithm: c.signature_algorithm.clone(),
        }
    }
}

#[derive(Serialize)]
struct Grade {
    grade: String,
    score: u8,
    categories: Vec<GradeCategory>,
}

#[derive(Serialize)]
struct GradeCategory {
    category: String,
    score: u8,
    reason: String,
}

impl From<&tlschecker::grading::TLSGrade> for Grade {
    fn from(g: &tlschecker::grading::TLSGrade) -> Self {
        Grade {
            grade: g.grade.clone(),
            score: g.score,
            categories: g
                .categories
                .iter()
                .map(|c| GradeCategory {
                    category: c.category.clone(),
                    score: c.score,
                    reason: c.reason.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct Scan {
    protocols: Vec<ScanProtocol>,
}

#[derive(Serialize)]
struct ScanProtocol {
    /// e.g. `TLSv1.2`.
    version: &'static str,
    /// `false` when the linked OpenSSL cannot offer this version at all, so
    /// `supported: false` says nothing about the server.
    tested: bool,
    supported: bool,
    ciphers: Vec<String>,
}

impl From<&tlschecker::probe::TlsScan> for Scan {
    fn from(scan: &tlschecker::probe::TlsScan) -> Self {
        Scan {
            protocols: scan
                .protocols
                .iter()
                .map(|p| ScanProtocol {
                    version: p.version.label(),
                    tested: p.tested,
                    supported: p.supported,
                    ciphers: p.ciphers.clone(),
                })
                .collect(),
        }
    }
}

#[derive(Serialize)]
struct Ct {
    /// `logged`, `not_logged` or `unknown`.
    status: &'static str,
    crtsh_id: Option<u64>,
    crtsh_url: Option<String>,
    /// Why the lookup could not reach a verdict when `unknown`.
    detail: Option<String>,
}

impl Ct {
    fn new(ct: &CtStatus, detail: Option<&str>) -> Self {
        let (status, crtsh_id, crtsh_url) = match ct {
            CtStatus::Logged {
                crtsh_id,
                crtsh_url,
            } => ("logged", Some(*crtsh_id), Some(crtsh_url.clone())),
            CtStatus::NotLogged => ("not_logged", None, None),
            CtStatus::Unknown => ("unknown", None, None),
        };
        Ct {
            status,
            crtsh_id,
            crtsh_url,
            detail: detail.map(str::to_string),
        }
    }
}
