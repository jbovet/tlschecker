//! Core TLS/SSL certificate validation library.
//!
//! This module provides functionality for:
//! - Establishing TLS connections to remote hosts
//! - Extracting and parsing X.509 certificates
//! - Validating certificate expiration dates
//! - Checking certificate revocation status via OCSP and CRL
//! - Detecting self-signed certificates
//! - Extracting certificate chain information
//!
//! # Example
//!
//! ```no_run
//! use tlschecker::TLS;
//!
//! // Check a certificate without revocation checking
//! let result = TLS::from("example.com", None, false, false)?;
//! println!("Certificate expires in {} days", result.certificate.validity_days);
//!
//! // Check with revocation checking and grading enabled
//! let result = TLS::from("example.com", Some(443), true, true)?;
//! if let Some(grade) = &result.grade {
//!     println!("TLS Grade: {} (Score: {}/100)", grade.grade, grade.score);
//! }
//! # Ok::<(), tlschecker::TLSError>(())
//! ```

pub mod certext;
pub mod ct;
mod der;
pub mod grading;
pub mod probe;
pub mod sct;

use std::collections::HashMap;
use std::fmt::Debug;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::ocsp::OcspCertStatus;
use openssl::ssl::HandshakeError;
use openssl::x509::{CrlStatus, ReasonCode, X509Crl, X509NameEntries, X509Ref, X509};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{info, instrument, warn};

/// Default timeout for TLS connection attempts (30 seconds).
///
/// Used by [`TLS::from`]; callers that need a different budget go through
/// [`TLS::from_with_timeout`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Revocation Status
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum RevocationStatus {
    /// Certificate is valid and not revoked
    Good,
    /// Certificate has been revoked, with the reason for revocation if available
    Revoked(String),
    /// OCSP responder is unavailable or status cannot be determined
    Unknown,
    /// Revocation status checking was not performed
    NotChecked,
}

impl Default for RevocationStatus {
    /// Returns `NotChecked` as the default revocation status.
    fn default() -> Self {
        RevocationStatus::NotChecked
    }
}

/// Whether the presented certificate chain builds to a trusted system root.
///
/// This is the authoritative trust verdict computed *after* inspection (the
/// handshake itself runs with verification disabled so broken certs can still
/// be examined), mirroring the tri-state shape of [`RevocationStatus`].
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum TrustStatus {
    /// The chain verified against the system trust store.
    Trusted,
    /// The chain did not verify; `reason` is OpenSSL's verification error
    /// (e.g. "unable to get local issuer certificate", "certificate has expired").
    Untrusted { reason: String },
    /// Trust could not be determined — no system trust store was available or
    /// the store could not be built. Never treated as a problem (no warning,
    /// no grade cap), consistent with the degrade-rather-than-panic ethos.
    Unknown,
}

impl Default for TrustStatus {
    /// Returns `Unknown` as the default trust status.
    fn default() -> Self {
        TrustStatus::Unknown
    }
}

/// Security warnings identified during certificate analysis.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum SecurityWarning {
    /// Certificate uses a weak signature algorithm (e.g., SHA1, MD5)
    WeakSignatureAlgorithm(String),
    /// Certificate chain is incomplete or has missing intermediates
    IncompleteChain(String),
    /// Certificate chain ordering is incorrect
    InvalidChainOrder(String),
    /// The certificate is not valid for the hostname that was checked
    /// (none of the Subject Alternative Names or the Common Name match)
    HostnameMismatch(String),
    /// An intermediate certificate in the chain has expired or is expiring soon
    ExpiringIntermediate(String),
    /// The server supports an obsolete or deprecated TLS protocol version
    /// (discovered via `--scan`)
    WeakProtocol(String),
    /// The server accepts a weak cipher suite (discovered via `--scan`)
    WeakCipher(String),
    /// The presented certificate was not found in any public Certificate
    /// Transparency log (discovered via `--ct-check`)
    NotInCertificateTransparency(String),
    /// The certificate chain did not build to a trusted system root
    Untrusted(String),
    /// The certificate deviates from issuance best practice (e.g. CA:TRUE on a
    /// leaf, missing serverAuth EKU, over-long validity). Informational — it
    /// does not affect the grade.
    CertificateMisissuance(String),
    /// A link in the presented chain is not cryptographically signed by the
    /// certificate that follows it. Informational — it does not affect the grade.
    InvalidChainSignature(String),
}

/// Represents a certificate in the certificate chain.
///
/// Contains basic information about an intermediate or root certificate
/// in the TLS certificate chain.
#[derive(Serialize, Deserialize, Clone)]
pub struct Chain {
    /// Subject common name of the certificate
    pub subject: String,
    /// Issuer common name of the certificate
    pub issuer: String,
    /// Certificate validity start date
    pub valid_from: String,
    /// Certificate expiration date
    pub valid_to: String,
    /// Signature algorithm used by the certificate
    pub signature_algorithm: String,
}

/// Complete TLS connection information including cipher and certificate details.
///
/// This is the main result type returned when checking a TLS certificate.
#[derive(Serialize, Deserialize, Clone)]
pub struct TLS {
    /// TLS cipher suite information
    pub cipher: Cipher,
    /// Detailed certificate information
    pub certificate: CertificateInfo,
    /// TLS configuration grade (populated when --grade is enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grade: Option<grading::TLSGrade>,
    /// Protocol/cipher enumeration results (populated when --scan is enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scan: Option<probe::TlsScan>,
    /// Certificate Transparency lookup result (populated when --ct-check is enabled)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ct: Option<ct::CtStatus>,
    /// Why `ct` is `Unknown`: crt.sh could not be queried, answered with
    /// something unrecognized, or has no record of a certificate that carries
    /// embedded SCTs. `None` for a definitive status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ct_detail: Option<String>,
}

/// TLS cipher suite information.
///
/// Contains details about the negotiated cipher and protocol version
/// used for the TLS connection.
#[derive(Serialize, Deserialize, Clone)]
pub struct Cipher {
    /// Name of the cipher suite (e.g., "ECDHE-RSA-AES128-GCM-SHA256")
    pub name: String,
    /// Negotiated TLS protocol version, as OpenSSL names it: "TLSv1.3",
    /// "TLSv1.2", "TLSv1.1", "TLSv1" (TLS 1.0) or "SSLv3".
    ///
    /// This is the connection's version, not the cipher suite's: a suite such
    /// as `ECDHE-RSA-AES128-SHA` dates from TLS 1.0 but is routinely
    /// negotiated over TLS 1.2.
    pub version: String,
    /// Cipher suite key length in bits
    pub bits: i32,
    /// Application-layer protocol negotiated via ALPN (e.g. "h2", "http/1.1"),
    /// or `None` if the server did not select one.
    #[serde(default)]
    pub alpn: Option<String>,
}

/// Comprehensive X.509 certificate information.
///
/// Contains all extracted metadata from a TLS certificate including
/// validity dates, subject/issuer information, revocation status,
/// and the certificate chain.
#[derive(Serialize, Deserialize, Clone)]
pub struct CertificateInfo {
    /// The hostname that was checked
    pub hostname: String,
    /// Certificate subject (owner) information
    pub subject: Subject,
    /// Certificate issuer (CA) information
    pub issued: Issuer,
    /// Certificate validity start date (ISO 8601 format)
    pub valid_from: String,
    /// Certificate expiration date (ISO 8601 format)
    pub valid_to: String,
    /// Certificate validity start as a Unix timestamp (seconds; 0 if it could
    /// not be computed)
    #[serde(default)]
    pub valid_from_unix: i64,
    /// Certificate expiration as a Unix timestamp (seconds; 0 if it could not
    /// be computed)
    #[serde(default)]
    pub valid_to_unix: i64,
    /// Number of days until certificate expires (negative if expired)
    pub validity_days: i32,
    /// Number of hours until certificate expires (negative if expired)
    pub validity_hours: i32,
    /// Whether the certificate has expired
    pub is_expired: bool,
    /// Certificate serial number as colon-separated uppercase hex (the form
    /// CAs, browsers, and `openssl x509 -text` all use)
    pub cert_sn: String,
    /// Certificate version (typically "2" for v3 certificates)
    pub cert_ver: String,
    /// Certificate signature algorithm
    pub cert_alg: String,
    /// Subject Alternative Names (SANs) - DNS names the certificate is valid for
    pub sans: Vec<String>,
    /// Complete certificate chain (intermediate and root certificates)
    pub chain: Option<Vec<Chain>>,
    /// Certificate revocation status (if checked)
    pub revocation_status: RevocationStatus,
    /// Why `revocation_status` is `Unknown` when a check was attempted — each
    /// OCSP responder's and CRL distribution point's failure — or `None` when
    /// the status is definitive or revocation was not checked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_detail: Option<String>,
    /// Whether the chain builds to a trusted system root (always computed;
    /// `Unknown` when no trust store is available)
    #[serde(default)]
    pub trust: TrustStatus,
    /// Whether this is a self-signed certificate
    pub is_self_signed: bool,
    /// Security warnings identified during analysis
    pub security_warnings: Vec<SecurityWarning>,
    /// Public key size in bits
    pub cert_key_bits: u32,
    /// Public key algorithm (e.g., "RSA", "EC")
    pub cert_key_algorithm: String,
    /// SHA-256 fingerprint of the DER-encoded certificate (colon-separated hex)
    pub cert_sha256: String,
    /// SHA-1 fingerprint of the DER-encoded certificate (colon-separated hex)
    pub cert_sha1: String,
    /// Subject Key Identifier (colon-hex), if the extension is present
    #[serde(default)]
    pub subject_key_id: Option<String>,
    /// Authority Key Identifier (colon-hex), if the extension is present
    #[serde(default)]
    pub authority_key_id: Option<String>,
    /// CA/Browser-Forum validation level ("EV"/"OV"/"DV"/"IV") from the
    /// Certificate Policies extension, or `None` if no CABF policy OID is present
    #[serde(default)]
    pub validation_level: Option<String>,
    /// Key Usage flag names present (e.g. `digitalSignature`)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_usage: Vec<String>,
    /// Extended Key Usage purpose names / OIDs (e.g. `serverAuth`)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ext_key_usage: Vec<String>,
    /// Whether Basic Constraints asserts `CA:TRUE`
    #[serde(default)]
    pub is_ca: bool,
    /// Basic Constraints path-length constraint, if present
    #[serde(default)]
    pub path_len: Option<u32>,
    /// OCSP responder URLs from the Authority Information Access extension
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ocsp_urls: Vec<String>,
    /// CA Issuers URLs (where the issuer certificate can be fetched) from the
    /// Authority Information Access extension
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ca_issuer_urls: Vec<String>,
    /// CRL distribution point URLs from the CRL Distribution Points extension
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub crl_urls: Vec<String>,
    /// Signed Certificate Timestamps embedded in the leaf (offline proof the
    /// certificate was submitted to CT logs). Empty when none are present.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scts: Vec<sct::Sct>,
    /// PEM encoding of the presented certificate chain (leaf first).
    ///
    /// Populated for `--export-pem`. Not serialized: it is bulky and only
    /// meaningful when explicitly exported, so it is skipped in JSON output.
    #[serde(skip)]
    pub pem: String,
}

/// Certificate issuer (Certificate Authority) information.
///
/// Identifies the organization that issued and signed the certificate.
#[derive(Serialize, Deserialize, Clone)]
pub struct Issuer {
    /// Country or region code (e.g., "US", "UK")
    pub country_or_region: String,
    /// Organization name (e.g., "Let's Encrypt")
    pub organization: String,
    /// Common name of the issuer
    pub common_name: String,
}

/// Certificate subject (owner) information.
///
/// Identifies the entity to whom the certificate was issued.
#[derive(Serialize, Deserialize, Clone)]
pub struct Subject {
    /// Country or region code
    pub country_or_region: String,
    /// State or province name
    pub state_or_province: String,
    /// City or locality name
    pub locality: String,
    /// Organizational unit (department, division)
    pub organization_unit: String,
    /// Organization name
    pub organization: String,
    /// Common name (typically the primary domain name)
    pub common_name: String,
}

/// Finds the issuer certificate in a certificate chain.
///
/// Given a certificate and a chain of certificates, this function searches for the
/// certificate that issued (signed) the given certificate by comparing the certificate's
/// issuer name with each chain certificate's subject name.
///
/// # Arguments
///
/// * `cert` - The certificate whose issuer to find
/// * `chain` - The certificate chain to search within
///
/// # Returns
///
/// * `Some(&X509)` - Reference to the issuer certificate if found
/// * `None` - If no matching issuer is found in the chain
///
/// # Example
///
/// ```no_run
/// # use openssl::x509::X509;
/// # use tlschecker::find_issuer_cert;
/// # fn example(cert: &X509, chain: &[X509]) {
/// if let Some(issuer) = find_issuer_cert(cert, chain) {
///     println!("Found issuer: {:?}", issuer.subject_name());
/// }
/// # }
/// ```
pub fn find_issuer_cert<'a>(cert: &X509Ref, chain: &'a [X509]) -> Option<&'a X509> {
    // Prefer the RFC 5280 key-identifier match: the cert's Authority Key
    // Identifier should equal the issuer's Subject Key Identifier. This is
    // unambiguous even when multiple certs share a subject name (e.g. a CA
    // cross-signed by two roots). Only when AKI/SKI are absent or don't match
    // do we fall back to the DN comparison below, so this can only add matches,
    // never remove the ones the name check already found.
    if let Some(akid) = cert.authority_key_id() {
        let by_key_id = chain.iter().find(|c| {
            c.subject_key_id()
                .is_some_and(|skid| skid.as_slice() == akid.as_slice())
        });
        if by_key_id.is_some() {
            return by_key_id;
        }
    }

    // Fall back to matching the certificate's issuer DN against a candidate's
    // subject DN.
    let cert_issuer = cert.issuer_name();
    chain.iter().find(|c| {
        cert_issuer
            .try_cmp(c.subject_name())
            .is_ok_and(|ordering| ordering == std::cmp::Ordering::Equal)
    })
}

/// Analyzes a certificate chain for security issues.
///
/// Checks for:
/// - Weak signature algorithms (SHA1, MD5)
/// - Chain completeness
/// - Chain ordering
///
/// # Arguments
///
/// * `cert` - The end-entity certificate
/// * `chain` - The complete certificate chain
///
/// # Returns
///
/// A vector of `SecurityWarning` items describing any issues found.
pub fn analyze_certificate_chain(cert: &X509, chain: &[X509]) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();

    // Check for weak signature algorithms in the end-entity certificate
    let sig_alg = cert.signature_algorithm().object().to_string();
    if is_weak_algorithm(&sig_alg) {
        warnings.push(SecurityWarning::WeakSignatureAlgorithm(format!(
            "Certificate uses weak signature algorithm: {}",
            sig_alg
        )));
    }

    // Check for weak algorithms in the chain
    for chain_cert in chain.iter() {
        let chain_sig_alg = chain_cert.signature_algorithm().object().to_string();
        if is_weak_algorithm(&chain_sig_alg) {
            let subject = chain_cert
                .subject_name()
                .entries_by_nid(Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().to_string().ok())
                .unwrap_or_else(|| "Unknown".to_string());
            warnings.push(SecurityWarning::WeakSignatureAlgorithm(format!(
                "Chain certificate '{}' uses weak signature algorithm: {}",
                subject, chain_sig_alg
            )));
        }
    }

    // Check chain completeness - verify each cert's issuer is in the chain
    if !chain.is_empty() {
        let issuer = find_issuer_cert(cert, chain);
        if issuer.is_none() && !is_self_signed_certificate(cert) {
            warnings.push(SecurityWarning::IncompleteChain(
                "Certificate issuer not found in chain".to_string(),
            ));
        }
    }

    // Check chain ordering - each cert (except the last) should be directly
    // followed by its issuer, as required when a server presents a chain.
    if !is_chain_well_ordered(chain) {
        warnings.push(SecurityWarning::InvalidChainOrder(
            "Certificate chain is not in issuer order (each certificate should be \
             followed by the certificate that issued it)"
                .to_string(),
        ));
    }

    // Check for intermediate certificates that have expired or are expiring soon.
    // The leaf is reported separately via `is_expired`, and self-signed roots are
    // skipped (clients ship their own trusted roots, so a presented root's expiry
    // is not actionable).
    let leaf_der = cert.to_der().ok();
    for chain_cert in chain.iter() {
        // Skip the leaf itself (its expiry is reported separately via
        // `is_expired`). Compare as `Option`s so that if serialization fails the
        // matching `None == None` still skips the leaf rather than analysing it
        // a second time.
        let chain_der = chain_cert.to_der().ok();
        if chain_der == leaf_der {
            continue;
        }
        if is_self_signed_certificate(chain_cert) {
            continue; // skip roots
        }
        let subject = chain_cert
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .and_then(|e| e.data().to_string().ok())
            .unwrap_or_else(|| "Unknown".to_string());

        if has_expired(chain_cert.not_after()) {
            warnings.push(SecurityWarning::ExpiringIntermediate(format!(
                "Intermediate certificate '{}' has expired ({})",
                subject,
                chain_cert.not_after()
            )));
        } else {
            let days_left = get_validity_days(chain_cert.not_after());
            if days_left < CHAIN_EXPIRY_WARNING_DAYS {
                warnings.push(SecurityWarning::ExpiringIntermediate(format!(
                    "Intermediate certificate '{}' expires in {} days ({})",
                    subject,
                    days_left,
                    chain_cert.not_after()
                )));
            }
        }
    }

    // Cryptographically verify that each certificate is actually signed by its
    // issuer. The issuer is located by *identity* (`find_issuer_cert`), not by
    // chain position, so a merely mis-ordered chain — already reported above —
    // does not produce spurious signature failures. Self-signed roots are
    // skipped (nothing to prove), and a certificate whose issuer isn't present
    // is left to the incomplete-chain check rather than flagged here. Only a
    // real forgery — the named issuer is present but the signature does not
    // validate against its key — warns.
    for chain_cert in chain.iter() {
        if is_self_signed_certificate(chain_cert) {
            continue;
        }
        let Some(issuer) = find_issuer_cert(chain_cert, chain) else {
            continue;
        };
        let Ok(issuer_key) = issuer.public_key() else {
            continue;
        };
        if matches!(chain_cert.verify(&issuer_key), Ok(false)) {
            let subject = chain_cert
                .subject_name()
                .entries_by_nid(Nid::COMMONNAME)
                .next()
                .and_then(|e| e.data().to_string().ok())
                .unwrap_or_else(|| "Unknown".to_string());
            warnings.push(SecurityWarning::InvalidChainSignature(format!(
                "Certificate '{}' is not validly signed by its issuer '{}'",
                subject,
                issuer
                    .subject_name()
                    .entries_by_nid(Nid::COMMONNAME)
                    .next()
                    .and_then(|e| e.data().to_string().ok())
                    .unwrap_or_else(|| "Unknown".to_string())
            )));
        }
    }

    warnings
}

/// Number of days before an intermediate certificate's expiry at which a
/// warning is raised.
const CHAIN_EXPIRY_WARNING_DAYS: i32 = 30;

/// Checks whether a presented certificate chain is in correct issuer order.
///
/// A well-ordered chain has each certificate directly followed by the
/// certificate that issued it (i.e. `chain[i].issuer == chain[i+1].subject`).
/// A chain with fewer than two certificates is trivially considered ordered.
///
/// This only validates ordering of the certificates that are present; a missing
/// issuer is reported separately as an incomplete chain.
fn is_chain_well_ordered(chain: &[X509]) -> bool {
    for pair in chain.windows(2) {
        let issuer_name = pair[0].issuer_name();
        let next_subject = pair[1].subject_name();
        let in_order = issuer_name
            .try_cmp(next_subject)
            .is_ok_and(|ordering| ordering == std::cmp::Ordering::Equal);
        if !in_order {
            return false;
        }
    }
    true
}

/// Validates that `leaf` builds to a trusted root using the OS trust store.
///
/// This is the authoritative trust check a browser performs, computed *after*
/// the inspecting handshake (which runs with verification disabled). `chain`
/// supplies the presented intermediates used to build the path; the trust
/// anchors come solely from the system store.
///
/// Returns [`TrustStatus::Unknown`] — never an error — when the system trust
/// store cannot be located or built, so hosts on a machine without a CA bundle
/// are not mislabelled untrusted.
pub fn validate_trust(leaf: &X509, chain: &[X509]) -> TrustStatus {
    match system_trust_store() {
        Some(store) => validate_trust_with_store(store, leaf, chain),
        // No CA bundle could be located/parsed — can't judge trust, so degrade
        // to `Unknown` rather than mislabelling every host `Untrusted`.
        None => TrustStatus::Unknown,
    }
}

/// Lazily builds (once) an `X509Store` from the OS CA bundle, shared across all
/// checks (`X509Store` is `Send + Sync`; concurrent read-only verification is
/// the intended OpenSSL usage). Returns `None` when no bundle can be located or
/// parsed.
///
/// We load a bundle **file** explicitly rather than relying on
/// `X509StoreBuilder::set_default_paths()`: `openssl` is vendored (its
/// compiled-in defaults don't exist on macOS) and `openssl-probe` 0.2 has no
/// macOS-specific paths — it points `SSL_CERT_DIR` at an empty `/etc/ssl/certs`,
/// which `set_default_paths` accepts as a valid-but-empty store, turning every
/// host into a false `Untrusted`. Loading a real bundle makes the store's
/// emptiness observable (we only proceed if ≥1 cert parsed) and fixes macOS.
fn system_trust_store() -> Option<&'static openssl::x509::store::X509Store> {
    use openssl::x509::store::X509StoreBuilder;
    static STORE: std::sync::OnceLock<Option<openssl::x509::store::X509Store>> =
        std::sync::OnceLock::new();
    STORE
        .get_or_init(|| {
            // Configure SSL_CERT_FILE/DIR too, so reqwest's OpenSSL (used for
            // OCSP/CRL/CT fetches) also finds the system roots.
            // SAFETY: runs exactly once via `OnceLock`, at first trust check,
            // before the store is built; it only sets the vars if unset.
            unsafe {
                openssl_probe::try_init_openssl_env_vars();
            }
            let mut builder = X509StoreBuilder::new().ok()?;
            let mut added = false;
            for path in trust_bundle_candidates() {
                let Ok(pem) = std::fs::read(&path) else {
                    continue;
                };
                let Ok(certs) = X509::stack_from_pem(&pem) else {
                    continue;
                };
                for cert in certs {
                    if builder.add_cert(cert).is_ok() {
                        added = true;
                    }
                }
                if added {
                    break; // first usable bundle wins
                }
            }
            added.then(|| builder.build())
        })
        .as_ref()
}

/// Candidate CA-bundle file paths, most-specific first: an explicit
/// `SSL_CERT_FILE`, whatever `openssl-probe` located, then the well-known
/// bundles for macOS and the common Linux distros.
fn trust_bundle_candidates() -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Some(f) = std::env::var_os("SSL_CERT_FILE") {
        paths.push(std::path::PathBuf::from(f));
    }
    if let Some(f) = openssl_probe::probe().cert_file {
        paths.push(f);
    }
    for p in [
        "/etc/ssl/cert.pem",                  // macOS, Alpine, OpenBSD
        "/etc/ssl/certs/ca-certificates.crt", // Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL/Fedora
        "/etc/pki/tls/cert.pem",              // RHEL variant
    ] {
        paths.push(std::path::PathBuf::from(p));
    }
    paths
}

/// Verifies `leaf` against an explicit trust `store`, using `chain` as the
/// untrusted intermediates for path building.
///
/// Split out from [`validate_trust`] so it can be unit-tested with a synthetic
/// root instead of the OS trust store. A build/verify error that is *not* a
/// certificate rejection degrades to [`TrustStatus::Unknown`].
fn validate_trust_with_store(
    store: &openssl::x509::store::X509Store,
    leaf: &X509,
    chain: &[X509],
) -> TrustStatus {
    use openssl::x509::X509StoreContext;

    // Untrusted intermediates: everything the server presented except the leaf.
    // Passing the leaf again is harmless, but skip it to keep the stack minimal.
    let mut intermediates = match openssl::stack::Stack::<X509>::new() {
        Ok(s) => s,
        Err(_) => return TrustStatus::Unknown,
    };
    for cert in chain.iter().skip(1) {
        let _ = intermediates.push(cert.to_owned());
    }

    let mut ctx = match X509StoreContext::new() {
        Ok(c) => c,
        Err(_) => return TrustStatus::Unknown,
    };

    // Read the verdict — and, on failure, the reason — inside the closure while
    // the store context is live (`error()` reflects the last `verify_cert`).
    let result = ctx.init(store, leaf, &intermediates, |c| match c.verify_cert() {
        Ok(true) => Ok(TrustStatus::Trusted),
        Ok(false) => Ok(TrustStatus::Untrusted {
            reason: c.error().error_string().to_string(),
        }),
        Err(e) => Err(e),
    });

    // An internal error (not a verdict) degrades to Unknown — never Untrusted.
    result.unwrap_or(TrustStatus::Unknown)
}

/// Determines whether `cert` is valid for `hostname`.
///
/// Matching follows the usual TLS rules: the Subject Alternative Name (SAN)
/// DNS entries are checked first, and only if the certificate has no DNS SANs
/// does it fall back to the Subject Common Name. Wildcard names such as
/// `*.example.com` match exactly one label (`a.example.com` but not
/// `a.b.example.com` or the bare `example.com`). Matching is case-insensitive.
///
/// # Arguments
///
/// * `hostname` - The hostname that was connected to
/// * `cert` - The end-entity certificate presented by the server
///
/// # Returns
///
/// `true` if the certificate is valid for the hostname, `false` otherwise.
pub fn cert_matches_hostname(hostname: &str, cert: &X509) -> bool {
    // Certificates carry DNS names in ASCII A-label form; convert an IDN
    // input (e.g. "bücher.example") before comparing.
    let hostname = to_ascii_hostname(hostname.trim_end_matches('.')).to_ascii_lowercase();
    if hostname.is_empty() {
        return false;
    }

    // An IP-address target must be matched against iPAddress SANs (RFC 6125),
    // not DNS names. Compare the raw address bytes so that different textual
    // forms (e.g. compressed vs. expanded IPv6) still match.
    if let Ok(ip) = hostname.parse::<std::net::IpAddr>() {
        let want: Vec<u8> = match ip {
            std::net::IpAddr::V4(v4) => v4.octets().to_vec(),
            std::net::IpAddr::V6(v6) => v6.octets().to_vec(),
        };
        let mut had_ip_san = false;
        if let Some(general_names) = cert.subject_alt_names() {
            for general_name in general_names {
                if let Some(actual) = general_name.ipaddress() {
                    had_ip_san = true;
                    if actual == want.as_slice() {
                        return true;
                    }
                }
            }
        }
        // Fall back to a textual Common Name match only when the certificate
        // carries no iPAddress SANs (common for self-signed/internal certs).
        if !had_ip_san {
            let cn = from_entries(cert.subject_name().entries_by_nid(Nid::COMMONNAME));
            if cn != "None" && cn.trim_end_matches('.').to_ascii_lowercase() == hostname {
                return true;
            }
        }
        return false;
    }

    // DNS-name target: prefer SAN DNS entries.
    let mut had_dns_san = false;
    if let Some(general_names) = cert.subject_alt_names() {
        for general_name in general_names {
            if let Some(dns) = general_name.dnsname() {
                had_dns_san = true;
                if matches_dns_name(dns, &hostname) {
                    return true;
                }
            }
        }
    }

    // Fall back to the Common Name only when there are no DNS SANs, mirroring
    // modern client behaviour (SANs, when present, are authoritative).
    if !had_dns_san {
        let cn = from_entries(cert.subject_name().entries_by_nid(Nid::COMMONNAME));
        if cn != "None" && matches_dns_name(&cn, &hostname) {
            return true;
        }
    }

    false
}

/// Strips the brackets that wrap an IPv6 literal host (`"[::1]"` -> `"::1"`).
///
/// Hostnames and IPv4 literals are returned unchanged. Brackets are only
/// removed when both the leading `[` and trailing `]` are present.
pub(crate) fn unbracket_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host)
}

/// Converts an internationalized (IDN) hostname to its ASCII A-label
/// (punycode) form, e.g. `bücher.example` -> `xn--bcher-kva.example`.
///
/// Certificates carry SAN entries in A-label form, and DNS resolution likewise
/// expects ASCII, so user-supplied unicode hostnames are converted before
/// matching or resolving. Already-ASCII input is returned unchanged, and a
/// failed conversion falls back to the original string (which will then fail
/// resolution/matching with the user's own spelling in the message).
pub(crate) fn to_ascii_hostname(host: &str) -> String {
    if host.is_ascii() {
        return host.to_string();
    }
    idna::domain_to_ascii(host).unwrap_or_else(|_| host.to_string())
}

/// Matches a single certificate DNS name (which may be a wildcard) against a
/// lower-cased hostname.
fn matches_dns_name(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();

    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard matches exactly one left-most label.
        if suffix.is_empty() {
            return false;
        }
        match hostname.split_once('.') {
            Some((label, rest)) => !label.is_empty() && rest == suffix,
            None => false,
        }
    } else {
        pattern == hostname
    }
}

/// Checks if a signature algorithm is considered weak.
///
/// # Arguments
///
/// * `algorithm` - The signature algorithm OID string
///
/// # Returns
///
/// `true` if the algorithm is weak, `false` otherwise.
fn is_weak_algorithm(algorithm: &str) -> bool {
    // Check for SHA1 and MD5 based algorithms
    algorithm.contains("sha1") || algorithm.contains("SHA1") ||
    algorithm.contains("md5") || algorithm.contains("MD5") ||
    algorithm.contains("1.2.840.113549.1.1.5") ||  // sha1WithRSAEncryption
    algorithm.contains("1.2.840.113549.1.1.4") ||  // md5WithRSAEncryption
    algorithm.contains("1.2.840.10040.4.3") // dsaWithSHA1
}

/// Checks whether a cipher suite name denotes a weak cipher.
///
/// Flags RC4, (3)DES, NULL, EXPORT, MD5, and anonymous (ADH/AECDH) suites.
fn is_weak_cipher(name: &str) -> bool {
    let n = name.to_ascii_uppercase();
    n.contains("RC4")
        || n.contains("DES") // matches both DES and 3DES ("DES-CBC3-...")
        || n.contains("NULL")
        || n.contains("MD5")
        || n.contains("EXP") // EXPORT-grade
        || n.contains("ADH")
        || n.contains("AECDH")
        || n.contains("ANON")
}

/// Returns true if the scan shows support for an obsolete protocol that should
/// cap the grade (SSLv3 or TLS 1.0).
fn scan_supports_obsolete_protocol(scan: &probe::TlsScan) -> bool {
    use probe::ProtoVersion;
    scan.protocols
        .iter()
        .any(|p| p.supported && matches!(p.version, ProtoVersion::Ssl3 | ProtoVersion::Tls1_0))
}

/// Returns true if the scan shows the server accepting any weak cipher.
fn scan_accepts_weak_cipher(scan: &probe::TlsScan) -> bool {
    scan.protocols
        .iter()
        .any(|p| p.supported && p.ciphers.iter().any(|c| is_weak_cipher(c)))
}

/// Derives security warnings from protocol/cipher enumeration results.
///
/// Produces a [`SecurityWarning::WeakProtocol`] for each supported obsolete
/// (SSLv3) or deprecated (TLS 1.0 / TLS 1.1) protocol version, and a single
/// [`SecurityWarning::WeakCipher`] per distinct weak cipher the server accepts.
///
/// # Arguments
///
/// * `scan` - The protocol/cipher enumeration result
///
/// # Returns
///
/// A vector of `SecurityWarning` items describing weaknesses found.
pub fn analyze_scan(scan: &probe::TlsScan) -> Vec<SecurityWarning> {
    let mut warnings = Vec::new();

    for proto in scan.protocols.iter().filter(|p| p.supported) {
        match proto.version {
            probe::ProtoVersion::Ssl3 => warnings.push(SecurityWarning::WeakProtocol(format!(
                "Server supports obsolete protocol {} (known to be insecure)",
                proto.version
            ))),
            probe::ProtoVersion::Tls1_0 | probe::ProtoVersion::Tls1_1 => {
                warnings.push(SecurityWarning::WeakProtocol(format!(
                    "Server supports deprecated protocol {}",
                    proto.version
                )))
            }
            _ => {}
        }
    }

    // Collect distinct weak ciphers across all supported versions to avoid
    // emitting the same cipher once per protocol.
    let mut weak_ciphers: Vec<String> = Vec::new();
    for proto in scan.protocols.iter().filter(|p| p.supported) {
        for cipher in &proto.ciphers {
            if is_weak_cipher(cipher) && !weak_ciphers.contains(cipher) {
                weak_ciphers.push(cipher.clone());
            }
        }
    }
    for cipher in weak_ciphers {
        warnings.push(SecurityWarning::WeakCipher(format!(
            "Server accepts weak cipher {}",
            cipher
        )));
    }

    warnings
}

/// Builds the grading input from a connection's cipher and certificate info,
/// plus optional protocol/cipher scan results.
///
/// Trust-related flags are derived from the certificate's accumulated security
/// warnings; scan-derived flags (obsolete protocol / weak cipher) are taken
/// from `scan` when present. Centralising this lets both the initial grade in
/// [`TLS::from`] and the recomputed grade in [`TLS::apply_scan`] stay in sync.
fn build_grading_input(
    cipher: &Cipher,
    certificate: &CertificateInfo,
    scan: Option<&probe::TlsScan>,
) -> grading::GradingInput {
    let has = |pred: fn(&SecurityWarning) -> bool| certificate.security_warnings.iter().any(pred);
    grading::GradingInput {
        protocol_version: cipher.version.clone(),
        cipher_name: cipher.name.clone(),
        cipher_bits: cipher.bits,
        cert_key_bits: certificate.cert_key_bits,
        cert_key_algorithm: certificate.cert_key_algorithm.clone(),
        is_expired: certificate.is_expired,
        is_self_signed: certificate.is_self_signed,
        has_incomplete_chain: has(|w| matches!(w, SecurityWarning::IncompleteChain(_))),
        has_weak_signature: has(|w| matches!(w, SecurityWarning::WeakSignatureAlgorithm(_))),
        has_hostname_mismatch: has(|w| matches!(w, SecurityWarning::HostnameMismatch(_))),
        has_invalid_chain_signature: has(|w| {
            matches!(w, SecurityWarning::InvalidChainSignature(_))
        }),
        supports_obsolete_protocol: scan.map(scan_supports_obsolete_protocol).unwrap_or(false),
        // Penalise a weak cipher even without `--scan`: the negotiated cipher
        // name alone (e.g. RC4/3DES/NULL) is enough to cap the grade. The scan,
        // when present, additionally surfaces weak ciphers the server merely
        // *accepts* beyond the one negotiated here.
        accepts_weak_cipher: is_weak_cipher(&cipher.name)
            || scan.map(scan_accepts_weak_cipher).unwrap_or(false),
        is_revoked: matches!(certificate.revocation_status, RevocationStatus::Revoked(_)),
        is_untrusted: matches!(certificate.trust, TrustStatus::Untrusted { .. }),
    }
}

/// Check OCSP status
/// This function checks the OCSP status of a given certificate against a chain of certificates.
/// It returns a RevocationStatus indicating whether the certificate is good, revoked, or unknown.
/// It uses the OCSP responder URLs from the certificate to perform the check.
/// If the issuer certificate is not found in the chain, it returns Unknown.
/// If the OCSP responder is unavailable or the response is not successful, it returns Unknown.
/// If the OCSP response indicates that the certificate is revoked, it returns Revoked with the reason.
/// If the OCSP response indicates that the certificate is good, it returns Good.
/// If the OCSP response is not valid, it returns Unknown.
#[instrument(skip(cert, chain))]
pub fn check_ocsp_status(cert: &X509, chain: &[X509]) -> Result<RevocationStatus, TLSError> {
    Ok(ocsp_revocation(cert, chain).unwrap_or(RevocationStatus::Unknown))
}

/// Combined revocation checking function that tries both OCSP and CRL
#[instrument(skip(cert, chain))]
pub fn check_revocation_status(cert: &X509, chain: &[X509]) -> Result<RevocationStatus, TLSError> {
    Ok(revocation_status_with_detail(cert, chain).0)
}

#[instrument(skip(cert, chain))]
pub fn check_crl_status(cert: &X509, chain: &[X509]) -> Result<RevocationStatus, TLSError> {
    Ok(crl_revocation(cert, chain).unwrap_or(RevocationStatus::Unknown))
}

/// Checks revocation for a chain given as PEM, leaf first — the form
/// [`CertificateInfo::pem`] keeps — without opening a new TLS connection.
///
/// This is how a result inspected without `check_revocation` can be checked
/// later (the dashboard does it on demand). Returns the status and, when it
/// is `Unknown`, why — as stored in [`CertificateInfo::revocation_detail`].
pub fn check_revocation_from_pem(pem: &str) -> (RevocationStatus, Option<String>) {
    match X509::stack_from_pem(pem.as_bytes()) {
        Ok(chain) if !chain.is_empty() => revocation_status_with_detail(&chain[0], &chain),
        _ => (
            RevocationStatus::Unknown,
            Some("no certificate chain was kept for this result".to_string()),
        ),
    }
}

/// OCSP first (typically more up to date), then CRL when OCSP is
/// inconclusive. Returns the status and, when it is `Unknown`, why both
/// mechanisms failed — e.g. `OCSP: http://ocsp.example: request failed: …;
/// CRL: certificate lists no CRL distribution point`.
fn revocation_status_with_detail(
    cert: &X509,
    chain: &[X509],
) -> (RevocationStatus, Option<String>) {
    match ocsp_revocation(cert, chain) {
        Ok(status) => (status, None),
        Err(ocsp) => match crl_revocation(cert, chain) {
            Ok(status) => (status, None),
            Err(crl) => (
                RevocationStatus::Unknown,
                Some(format!("OCSP: {ocsp}; CRL: {crl}")),
            ),
        },
    }
}

/// Queries the certificate's OCSP responders in turn.
///
/// `Ok` is a definitive `Good` or `Revoked`. `Err` is why no responder gave
/// one — including a responder answering "unknown" — with each responder's
/// failure prefixed by its URL.
fn ocsp_revocation(cert: &X509, chain: &[X509]) -> Result<RevocationStatus, String> {
    use openssl::hash::MessageDigest;
    use openssl::ocsp::{OcspCertId, OcspRequest};

    let issuer = find_issuer_cert(cert, chain)
        .ok_or_else(|| "issuer certificate is not in the presented chain".to_string())?;
    let responders = match cert.ocsp_responders() {
        Ok(responders) if !responders.is_empty() => responders,
        _ => return Err("certificate lists no OCSP responder".to_string()),
    };
    let request = OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer)
        .and_then(|id| {
            let mut request = OcspRequest::new()?;
            request.add_id(id)?;
            request.to_der()
        })
        .map_err(|e| format!("could not build the OCSP request: {e}"))?;

    let mut failures = Vec::new();
    for responder in responders.iter() {
        let Ok(url) = std::str::from_utf8(responder.as_ref()) else {
            failures.push("responder URL is not valid UTF-8".to_string());
            continue;
        };
        match query_ocsp_responder(url, &request, cert, issuer, chain) {
            Ok(status) => return Ok(status),
            Err(reason) => failures.push(format!("{url}: {reason}")),
        }
    }
    Err(failures.join("; "))
}

/// Asks one OCSP responder about `cert`. `Ok` is a definitive `Good` or
/// `Revoked`; `Err` is why this responder's answer could not be used.
fn query_ocsp_responder(
    url: &str,
    request: &[u8],
    cert: &X509,
    issuer: &X509,
    chain: &[X509],
) -> Result<RevocationStatus, String> {
    use openssl::hash::MessageDigest;
    use openssl::ocsp::{OcspCertId, OcspFlag, OcspResponse, OcspResponseStatus};

    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .and_then(|client| {
            client
                .post(url)
                .header("Content-Type", "application/ocsp-request")
                .body(request.to_vec())
                .send()
        })
        .map_err(|e| format!("request failed: {}", error_chain(&e.without_url())))?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let body = read_body_limited(response, MAX_OCSP_RESPONSE_BYTES)?;

    let ocsp_response = OcspResponse::from_der(&body)
        .map_err(|_| "response is not a valid OCSP response".to_string())?;
    if ocsp_response.status() != OcspResponseStatus::SUCCESSFUL {
        return Err(format!(
            "responder answered {}",
            ocsp_response_status_name(ocsp_response.status())
        ));
    }
    let basic = ocsp_response
        .basic()
        .map_err(|_| "response carries no basic OCSP response".to_string())?;

    // Verify the OCSP response signature before trusting any status it
    // reports. Per RFC 6960 an unsigned or improperly signed response
    // must not be relied upon: doing so would let an on-path attacker forge
    // a "good" response and mask a revoked certificate. If verification
    // fails we skip this responder and ultimately fall back to CRL checking
    // (returning `Unknown`) rather than trusting a potentially forged status.
    //
    // The `certs` stack supplies *untrusted* intermediates used only to
    // build the path from the response's signer to the trusted issuer in
    // `store`. Many CAs use a delegated OCSP responder whose certificate is
    // issued by the CA: without the chain intermediates available, that
    // path can't be built and a perfectly valid response would fail to
    // verify (degrading to `Unknown`). Trust is still anchored solely by
    // `store` (the issuer), so providing these does not weaken the check.
    let internal = |e: ErrorStack| format!("could not verify the response: {e}");
    let mut store = openssl::x509::store::X509StoreBuilder::new().map_err(internal)?;
    store.add_cert(issuer.to_owned()).map_err(internal)?;
    let store = store.build();
    let mut certs = openssl::stack::Stack::<X509>::new().map_err(internal)?;
    for c in chain {
        let _ = certs.push(c.to_owned());
    }
    if basic.verify(&certs, &store, OcspFlag::empty()).is_err() {
        warn!("OCSP response signature verification failed; ignoring response from {url}");
        return Err("response signature verification failed".to_string());
    }

    let cert_id = OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer).map_err(internal)?;
    let status = basic
        .find_status(&cert_id)
        .ok_or_else(|| "response has no status for this certificate".to_string())?;
    if status.check_validity(300, None).is_err() {
        return Err("response is outside its validity window".to_string());
    }
    match status.status {
        OcspCertStatus::GOOD => Ok(RevocationStatus::Good),
        OcspCertStatus::REVOKED => Ok(RevocationStatus::Revoked(match status.revocation_time {
            Some(time) => format!("Revoked at {}", time),
            None => "Unknown reason".to_string(),
        })),
        _ => Err("responder does not know this certificate".to_string()),
    }
}

/// RFC 6960 name of a non-successful OCSP response status.
fn ocsp_response_status_name(status: openssl::ocsp::OcspResponseStatus) -> String {
    match status.as_raw() {
        1 => "malformedRequest".to_string(),
        2 => "internalError".to_string(),
        3 => "tryLater".to_string(),
        5 => "sigRequired".to_string(),
        6 => "unauthorized".to_string(),
        other => format!("status {other}"),
    }
}

/// Checks the certificate's CRL distribution points in turn.
///
/// `Ok` is a definitive `Good` or `Revoked`. `Err` is why no CRL gave one,
/// with each distribution point's failure prefixed by its URL.
fn crl_revocation(cert: &X509, chain: &[X509]) -> Result<RevocationStatus, String> {
    let issuer = find_issuer_cert(cert, chain)
        .ok_or_else(|| "issuer certificate is not in the presented chain".to_string())?;
    // Same helper the reported `crl_urls` come from, so what we display is
    // what we fetch.
    let urls = crl_urls(cert);
    if urls.is_empty() {
        return Err("certificate lists no CRL distribution point".to_string());
    }

    let mut failures = Vec::new();
    for url in &urls {
        match crl_status_from(url, cert, issuer) {
            Ok(status) => return Ok(status),
            Err(reason) => failures.push(format!("{url}: {reason}")),
        }
    }
    Err(failures.join("; "))
}

/// Looks `cert` up in the CRL at `url` (downloaded once and shared — see
/// [`cached_crl`]). `Ok` is a definitive `Good` or `Revoked`; `Err` is why
/// this CRL could not be used.
fn crl_status_from(url: &str, cert: &X509, issuer: &X509) -> Result<RevocationStatus, String> {
    let crl = cached_crl(url)?;

    // Signature and freshness are checked on every use, not once per
    // download: the cache is keyed by URL, and each certificate brings its
    // own issuer to verify against.
    if !is_crl_signed_by(&crl, issuer) {
        warn!("CRL from {url} is not signed by the certificate's issuer; ignoring it");
        return Err("CRL is not signed by the certificate's issuer".to_string());
    }
    // Reject stale CRLs: a correctly-signed but expired CRL (nextUpdate in
    // the past) may predate a revocation, so trusting it could mask a
    // revoked certificate — e.g. an on-path attacker replaying an old CRL.
    if !is_crl_fresh(&crl, url) {
        return Err("CRL is stale (nextUpdate is in the past)".to_string());
    }

    match crl.get_by_cert(cert) {
        CrlStatus::Revoked(revoked) => Ok(RevocationStatus::Revoked(
            match revoked.extension::<ReasonCode>() {
                Ok(Some(_)) => "Revoked via CRL".to_string(),
                _ => "Revoked via CRL (no reason specified)".to_string(),
            },
        )),
        // Not listed, or removed from the CRL after a temporary hold.
        CrlStatus::NotRevoked | CrlStatus::RemoveFromCrl(_) => Ok(RevocationStatus::Good),
    }
}

/// Largest CRL accepted. Real ones run from tens of KB to tens of MB; the URL
/// comes from the certificate under inspection, so without a bound a hostile
/// or broken distribution point could exhaust memory.
const MAX_CRL_BYTES: u64 = 32 * 1024 * 1024;

/// Largest OCSP response accepted (real ones are a few KB).
const MAX_OCSP_RESPONSE_BYTES: u64 = 256 * 1024;

/// How long a downloaded CRL is reused. Freshness is still checked on every
/// use ([`is_crl_fresh`]); this only bounds how long a long-running process
/// holds one.
const CRL_CACHE_TTL: Duration = Duration::from_secs(3600);

/// How long a failed download is remembered, so hosts sharing a dead or hung
/// distribution point don't each wait out the 10s timeout — short, so a
/// transient failure doesn't stick.
const CRL_FAILURE_TTL: Duration = Duration::from_secs(60);

/// Downloaded CRLs kept at most, by count and by total size. A parsed CRL
/// takes several times its encoded size in memory, and a fleet on a CA that
/// shards its CRLs (Let's Encrypt, Google) touches many distinct ones.
const CRL_CACHE_MAX_ENTRIES: usize = 16;
const CRL_CACHE_MAX_BYTES: usize = 16 * 1024 * 1024;

/// One URL's download: the parsed CRL shared by every check that needs it,
/// or why it could not be fetched.
struct CachedCrl {
    crl: Result<Arc<X509Crl>, String>,
    /// Encoded size, counted against [`CRL_CACHE_MAX_BYTES`].
    size: usize,
    fetched: Instant,
}

impl CachedCrl {
    fn expired(&self) -> bool {
        let ttl = if self.crl.is_ok() {
            CRL_CACHE_TTL
        } else {
            CRL_FAILURE_TTL
        };
        self.fetched.elapsed() > ttl
    }
}

struct CrlCacheEntry {
    /// Filled once by whichever check asks first; the others block on it.
    cell: Arc<OnceLock<CachedCrl>>,
    last_used: Instant,
}

/// Downloaded CRLs by URL, shared across threads.
///
/// Hosts issued by the same CA name the same distribution point; without
/// this, each re-downloaded and re-parsed it — every concurrent worker at
/// once. A caller that finds a download in progress waits for it rather than
/// starting its own. The map lock is only held to find the entry, never
/// during the download.
struct CrlCache {
    entries: Mutex<HashMap<String, CrlCacheEntry>>,
    max_entries: usize,
    max_bytes: usize,
}

impl CrlCache {
    fn new(max_entries: usize, max_bytes: usize) -> Self {
        CrlCache {
            entries: Mutex::default(),
            max_entries,
            max_bytes,
        }
    }

    /// The CRL at `url`, from the cache or — at most once per TTL, however
    /// many threads ask — from `fetch`.
    fn get(
        &self,
        url: &str,
        fetch: impl FnOnce(&str) -> Result<(X509Crl, usize), String>,
    ) -> Result<Arc<X509Crl>, String> {
        let cell = {
            let mut entries = self
                .entries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if entries
                .get(url)
                .and_then(|entry| entry.cell.get())
                .is_some_and(CachedCrl::expired)
            {
                entries.remove(url);
            }
            let now = Instant::now();
            let entry = entries
                .entry(url.to_string())
                .or_insert_with(|| CrlCacheEntry {
                    cell: Arc::default(),
                    last_used: now,
                });
            entry.last_used = now;
            let cell = Arc::clone(&entry.cell);
            self.evict(&mut entries, url);
            cell
        };
        cell.get_or_init(|| {
            let (crl, size) = match fetch(url) {
                Ok((crl, size)) => (Ok(Arc::new(crl)), size),
                Err(reason) => (Err(reason), 0),
            };
            CachedCrl {
                crl,
                size,
                fetched: Instant::now(),
            }
        })
        .crl
        .clone()
    }

    /// Drops least-recently-used finished downloads until the cache is within
    /// its bounds. Downloads in progress, and `keep` (the one just
    /// requested), are never evicted; a check already holding an evicted CRL
    /// keeps its own reference.
    fn evict(&self, entries: &mut HashMap<String, CrlCacheEntry>, keep: &str) {
        loop {
            let finished = || {
                entries
                    .iter()
                    .filter_map(|(url, entry)| entry.cell.get().map(|c| (url, entry, c)))
            };
            let count = finished().count();
            let bytes: usize = finished().map(|(_, _, c)| c.size).sum();
            if count <= self.max_entries && bytes <= self.max_bytes {
                return;
            }
            let Some(oldest) = finished()
                .filter(|(url, _, _)| url.as_str() != keep)
                .min_by_key(|(_, entry, _)| entry.last_used)
                .map(|(url, _, _)| url.clone())
            else {
                return;
            };
            entries.remove(&oldest);
        }
    }
}

/// The CRL at `url`, through the process-wide [`CrlCache`].
fn cached_crl(url: &str) -> Result<Arc<X509Crl>, String> {
    static CACHE: OnceLock<CrlCache> = OnceLock::new();
    CACHE
        .get_or_init(|| CrlCache::new(CRL_CACHE_MAX_ENTRIES, CRL_CACHE_MAX_BYTES))
        .get(url, |url| fetch_crl(url, MAX_CRL_BYTES))
}

/// Downloads and parses one CRL (at most `limit` bytes), returning it with
/// its encoded size.
fn fetch_crl(url: &str, limit: u64) -> Result<(X509Crl, usize), String> {
    let response = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .and_then(|client| client.get(url).send())
        .map_err(|e| format!("request failed: {}", error_chain(&e.without_url())))?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let body = read_body_limited(response, limit)?;

    // DER is what RFC 5280 distribution points serve; accept PEM too.
    let crl = X509Crl::from_der(&body)
        .or_else(|_| X509Crl::from_pem(&body))
        .map_err(|_| "response is not a CRL".to_string())?;
    Ok((crl, body.len()))
}

/// Reads a response body, failing once it exceeds `limit` bytes — checked
/// against Content-Length up front, and enforced while reading since that
/// header can be absent or wrong.
fn read_body_limited(response: reqwest::blocking::Response, limit: u64) -> Result<Vec<u8>, String> {
    use std::io::Read;

    let too_large = || format!("response exceeds the {} limit", format_bytes(limit));
    if response.content_length().is_some_and(|len| len > limit) {
        return Err(too_large());
    }
    let mut body = Vec::new();
    response
        .take(limit + 1)
        .read_to_end(&mut body)
        .map_err(|e| format!("could not read the response: {}", error_chain(&e)))?;
    if body.len() as u64 > limit {
        return Err(too_large());
    }
    Ok(body)
}

/// `32 MiB` / `256 KiB` / `100 bytes`, for limit messages.
fn format_bytes(n: u64) -> String {
    match n {
        n if n >= 1024 * 1024 && n % (1024 * 1024) == 0 => format!("{} MiB", n / (1024 * 1024)),
        n if n >= 1024 && n % 1024 == 0 => format!("{} KiB", n / 1024),
        n => format!("{n} bytes"),
    }
}

/// Renders an error followed by its `source()` chain (`a: b: c`).
///
/// reqwest's top-level message ("error sending request") leaves out the
/// cause — timed out, connection refused, DNS failure — which is the part
/// that tells a user what went wrong.
pub(crate) fn error_chain(err: &dyn std::error::Error) -> String {
    let mut out = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !out.contains(&cause_text) {
            out.push_str(": ");
            out.push_str(&cause_text);
        }
        source = cause.source();
    }
    out
}

/// Checks whether `crl` carries a valid signature from `issuer`'s key.
///
/// Only `Ok(true)` counts: `X509Crl::verify` reports a signature that does not
/// match as `Ok(false)` and reserves `Err` for malformed input, so treating
/// "not an error" as success would accept a CRL signed by any key. An issuer
/// whose public key cannot be extracted fails the check rather than panicking.
fn is_crl_signed_by(crl: &X509Crl, issuer: &X509) -> bool {
    issuer
        .public_key()
        .is_ok_and(|key| matches!(crl.verify(&key), Ok(true)))
}

/// Checks whether a CRL is still fresh enough to be trusted.
///
/// Returns `false` when `nextUpdate` lies in the past — a correctly-signed but
/// stale CRL may predate a revocation and must not be relied upon. `nextUpdate`
/// is optional per RFC 5280; when absent the CRL is accepted (returns `true`)
/// but a warning is logged, since freshness cannot be established. `source` is
/// only used to make the log messages actionable.
fn is_crl_fresh(crl: &X509Crl, source: &str) -> bool {
    match crl.next_update() {
        Some(next_update) => {
            if has_expired(next_update) {
                warn!(
                    "CRL from {} is stale (nextUpdate {} is in the past); ignoring it",
                    source, next_update
                );
                false
            } else {
                true
            }
        }
        None => {
            warn!(
                "CRL from {} carries no nextUpdate; accepting it but freshness cannot be verified",
                source
            );
            true
        }
    }
}

/// Resolves `host:port` and returns every address DNS reports, in resolution
/// order.
///
/// Resolution is done through the `(host, port)` tuple rather than a
/// `"{host}:{port}"` string so IPv6 literals (e.g. `::1`) work without bracket
/// syntax.
fn resolve_addrs(host: &str, port: u16) -> Result<Vec<SocketAddr>, TLSError> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(TLSError::DNS(format!(
            "No addresses resolved for '{}'",
            host
        )));
    }
    Ok(addrs)
}

/// Connects to the first address in `addrs` that accepts, within a total
/// `timeout` budget shared across all attempts.
///
/// A hostname commonly resolves to several addresses — an A and a AAAA record,
/// or a pool of load-balanced servers. Trying only the first makes a check fail
/// whenever that single address is unreachable even though the host is happily
/// serving on another, which is exactly what happens on an IPv4-only network
/// whose resolver still returns the AAAA record first.
///
/// The `timeout` is the budget for the *whole* connect phase, not per address:
/// that keeps the worst case bounded at the value the caller asked for no
/// matter how many addresses DNS returns, which matters because each check
/// occupies a worker thread. This costs nothing in the case that motivates
/// trying several addresses — an unroutable address family or a refused
/// connection fails immediately rather than burning the budget — while a
/// genuinely blackholed first address will still consume it.
///
/// Returns the last connection error when every address fails, so the reported
/// reason describes an actual attempt rather than a synthesized message.
fn connect_first_available(addrs: &[SocketAddr], timeout: Duration) -> Result<TcpStream, TLSError> {
    let deadline = Instant::now() + timeout;
    let mut last_err: Option<std::io::Error> = None;

    for addr in addrs {
        // `connect_timeout` rejects a zero duration, and no budget left means
        // there is nothing useful to do anyway.
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(addr, remaining) {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                if addrs.len() > 1 {
                    warn!(
                        "Connection to {} failed: {}; trying next address",
                        addr, err
                    );
                }
                last_err = Some(err);
            }
        }
    }

    Err(match last_err {
        Some(err) => TLSError::Connection(err),
        // Only reachable when the budget was already spent before the first
        // attempt, so no attempt ever produced an error.
        None => TLSError::Connection(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "connection timed out before any address could be tried",
        )),
    })
}

impl TLS {
    /// Establishes a TLS connection and inspects the presented certificate,
    /// using the default 30-second connection budget.
    ///
    /// See [`TLS::from_with_timeout`] for the full description; this is that
    /// function with [`DEFAULT_TIMEOUT`].
    pub fn from(
        host: &str,
        port: Option<u16>,
        check_revocation: bool,
        calculate_grade: bool,
    ) -> Result<TLS, TLSError> {
        TLS::from_with_timeout(
            host,
            port,
            check_revocation,
            calculate_grade,
            DEFAULT_TIMEOUT,
        )
    }

    /// Establishes a TLS connection and inspects the presented certificate,
    /// bounding the connect phase by `timeout`.
    ///
    /// `timeout` is the budget for connecting (shared across every address the
    /// hostname resolves to — see [`connect_first_available`]) and is also
    /// applied as the socket read timeout, so a server that accepts the TCP
    /// connection but never completes the handshake cannot block indefinitely.
    ///
    /// A server that rejects the handshake at the protocol level (e.g. it only
    /// speaks TLS 1.0, which OpenSSL's default security level refuses) is
    /// retried once with legacy protocols enabled, on a new connection with
    /// its own `timeout` — so it is inspected and graded rather than reported
    /// as a failure. The negotiated `cipher.version` shows the outcome.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::time::Duration;
    /// use tlschecker::TLS;
    ///
    /// let result = TLS::from_with_timeout(
    ///     "example.com",
    ///     None,
    ///     false,
    ///     false,
    ///     Duration::from_secs(5),
    /// )?;
    /// println!("Expires in {} days", result.certificate.validity_days);
    /// # Ok::<(), tlschecker::TLSError>(())
    /// ```
    #[instrument]
    pub fn from_with_timeout(
        host: &str,
        port: Option<u16>,
        check_revocation: bool,
        calculate_grade: bool,
        timeout: Duration,
    ) -> Result<TLS, TLSError> {
        use openssl::nid::Nid;

        // Trim any whitespace, and strip brackets that wrap IPv6 literals
        // (e.g. "[::1]" -> "::1") so address resolution and hostname matching
        // both operate on a bare address. Internationalized hostnames are
        // converted to their ASCII A-label (punycode) form, which is what both
        // DNS and certificate SAN entries use.
        let host = to_ascii_hostname(unbracket_host(host.trim()));
        let host = host.as_str();

        // Validate hostname is not empty
        if host.is_empty() {
            return Err(TLSError::Validation("Hostname cannot be empty".to_string()));
        }

        // Use the provided port or default to 443
        let port = port.unwrap_or(443);
        // Try every resolved address rather than only the first, so a host that
        // is up on one of its addresses is not reported as unreachable.
        let addrs = resolve_addrs(host, port)?;
        let stream = match inspecting_handshake(host, &addrs, timeout, false) {
            Err(err) if is_protocol_rejection(&err) => {
                info!("{host}: handshake rejected with default settings; retrying with legacy protocols enabled");
                // If the legacy attempt fails too, the original error is the
                // one that describes a normal client's experience.
                inspecting_handshake(host, &addrs, timeout, true).map_err(|_| err)?
            }
            other => other?,
        };

        // `Ssl` object associated with this stream
        let ssl = stream.ssl();

        let cipher = Cipher {
            name: ssl
                .current_cipher()
                .map(|c| c.name().to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
            // The connection's protocol — not `SslCipherRef::version`, which is
            // the oldest version the suite exists in.
            version: ssl.version_str().to_string(),
            bits: ssl.current_cipher().map(|c| c.bits().secret).unwrap_or(0),
            // The negotiated ALPN protocol, if any (e.g. "h2", "http/1.1").
            alpn: ssl
                .selected_alpn_protocol()
                .map(|p| String::from_utf8_lossy(p).into_owned()),
        };

        // Get the peer certificate chain
        let peer_cert_chain = ssl
            .peer_cert_chain()
            .ok_or_else(|| TLSError::Certificate("Peer certificate chain not found".to_string()))?;

        // Create the Chain objects for return data
        let chain_info = peer_cert_chain
            .iter()
            .map(|chain| Chain {
                subject: from_entries(chain.subject_name().entries_by_nid(Nid::COMMONNAME)),
                valid_to: chain.not_after().to_string(),
                valid_from: chain.not_before().to_string(),
                issuer: from_entries(chain.issuer_name().entries_by_nid(Nid::COMMONNAME)),
                signature_algorithm: chain.signature_algorithm().object().to_string(),
            })
            .collect::<Vec<Chain>>();

        let x509_ref = ssl
            .peer_certificate()
            .ok_or_else(|| TLSError::Certificate("Certificate not found".to_string()))?;

        // Check revocation status if requested
        let (revocation_status, revocation_detail) = if check_revocation {
            // Extract all certificates in the chain to X509 objects
            let cert_chain: Vec<openssl::x509::X509> =
                peer_cert_chain.iter().map(|cert| cert.to_owned()).collect();
            revocation_status_with_detail(&x509_ref, &cert_chain)
        } else {
            (RevocationStatus::NotChecked, None)
        };
        if let Some(detail) = &revocation_detail {
            warn!("Revocation status of {host} could not be determined: {detail}");
        }

        let mut data = get_certificate_info(&x509_ref);
        data.revocation_status = revocation_status;
        data.revocation_detail = revocation_detail;

        // Analyze certificate chain for security issues
        let cert_chain: Vec<openssl::x509::X509> =
            peer_cert_chain.iter().map(|cert| cert.to_owned()).collect();
        let mut security_warnings = analyze_certificate_chain(&x509_ref, &cert_chain);

        // Check that the certificate is actually valid for the host we connected to.
        if !cert_matches_hostname(host, &x509_ref) {
            security_warnings.push(SecurityWarning::HostnameMismatch(format!(
                "Certificate is not valid for '{}' (no matching Subject Alternative Name or Common Name)",
                host
            )));
        }

        // Authoritative trust: does the presented chain build to a system root?
        // Offline and always computed. Only a definitive `Untrusted` adds a
        // warning; `Unknown` (no trust store) is silent so it can't false-flag.
        let trust = validate_trust(&x509_ref, &cert_chain);
        if let TrustStatus::Untrusted { reason } = &trust {
            security_warnings.push(SecurityWarning::Untrusted(format!(
                "Certificate chain is not trusted: {}",
                reason
            )));
        }

        // Misissuance checks on the leaf (informational — no grade impact).
        if data.is_ca {
            security_warnings.push(SecurityWarning::CertificateMisissuance(
                "Leaf certificate asserts CA:TRUE in Basic Constraints".to_string(),
            ));
        }
        if !data.ext_key_usage.is_empty()
            && !data
                .ext_key_usage
                .iter()
                .any(|p| p == "serverAuth" || p == "anyExtendedKeyUsage")
        {
            security_warnings.push(SecurityWarning::CertificateMisissuance(
                "Leaf Extended Key Usage does not include serverAuth".to_string(),
            ));
        }
        if !data.key_usage.is_empty()
            && !data
                .key_usage
                .iter()
                .any(|k| k == "digitalSignature" || k == "keyEncipherment")
        {
            security_warnings.push(SecurityWarning::CertificateMisissuance(
                "Leaf Key Usage lacks digitalSignature and keyEncipherment".to_string(),
            ));
        }

        // CA/Browser-Forum baseline sanity (informational). Serial numbers must
        // carry >= 64 bits of entropy; a low bit-count signals a predictable
        // serial. Zero is a parse failure, not a real serial, so it's ignored.
        if let Ok(bits) = x509_ref.serial_number().to_bn().map(|bn| bn.num_bits()) {
            if bits > 0 && bits < 64 {
                security_warnings.push(SecurityWarning::CertificateMisissuance(format!(
                    "Serial number has only {} bits of entropy (CA/B Forum requires >= 64)",
                    bits
                )));
            }
        }
        // Publicly-trusted leaf validity must not exceed 398 days.
        if data.valid_from_unix != 0 && data.valid_to_unix != 0 {
            let span_days = (data.valid_to_unix - data.valid_from_unix) / 86_400;
            if span_days > 398 {
                security_warnings.push(SecurityWarning::CertificateMisissuance(format!(
                    "Validity period is {} days (CA/B Forum limits leaf certs to 398)",
                    span_days
                )));
            }
        }

        // Concatenate the presented chain (leaf first) as PEM for `--export-pem`.
        let pem = cert_chain
            .iter()
            .filter_map(|c| c.to_pem().ok())
            .filter_map(|der| String::from_utf8(der).ok())
            .collect::<String>();

        // Extract public key information
        let public_key = x509_ref
            .public_key()
            .map_err(|e| TLSError::Certificate(e.to_string()))?;
        let cert_key_bits = public_key.bits();
        let cert_key_algorithm = match public_key.id() {
            openssl::pkey::Id::RSA => "RSA".to_string(),
            openssl::pkey::Id::EC => "EC".to_string(),
            openssl::pkey::Id::DSA => "DSA".to_string(),
            openssl::pkey::Id::DH => "DH".to_string(),
            openssl::pkey::Id::ED25519 => "ED25519".to_string(),
            openssl::pkey::Id::ED448 => "ED448".to_string(),
            _ => "Unknown".to_string(),
        };

        let certificate = CertificateInfo {
            hostname: host.to_string(),
            subject: data.subject,
            issued: data.issued,
            valid_from: data.valid_from,
            valid_to: data.valid_to,
            valid_from_unix: data.valid_from_unix,
            valid_to_unix: data.valid_to_unix,
            validity_days: data.validity_days,
            validity_hours: data.validity_hours,
            is_expired: data.is_expired,
            cert_sn: data.cert_sn,
            cert_ver: data.cert_ver,
            cert_alg: data.cert_alg,
            sans: data.sans,
            chain: Some(chain_info),
            revocation_status: data.revocation_status,
            revocation_detail: data.revocation_detail,
            trust,
            is_self_signed: data.is_self_signed,
            security_warnings,
            cert_key_bits,
            cert_key_algorithm,
            cert_sha256: data.cert_sha256,
            cert_sha1: data.cert_sha1,
            subject_key_id: data.subject_key_id,
            authority_key_id: data.authority_key_id,
            validation_level: data.validation_level,
            key_usage: data.key_usage,
            ext_key_usage: data.ext_key_usage,
            is_ca: data.is_ca,
            path_len: data.path_len,
            ocsp_urls: data.ocsp_urls,
            ca_issuer_urls: data.ca_issuer_urls,
            crl_urls: data.crl_urls,
            scts: data.scts,
            pem,
        };

        // Calculate TLS grade if requested. Scan-derived signals are folded in
        // later by `apply_scan` when `--scan` is enabled.
        let grade = if calculate_grade {
            Some(grading::calculate_grade(&build_grading_input(
                &cipher,
                &certificate,
                None,
            )))
        } else {
            None
        };

        Ok(TLS {
            cipher,
            certificate,
            grade,
            scan: None,
            ct: None,
            ct_detail: None,
        })
    }

    /// Incorporates protocol/cipher scan results into this result.
    ///
    /// Appends any [`SecurityWarning`]s derived from the scan (weak protocols /
    /// ciphers) and, when a grade was already computed, recomputes it so the
    /// grade reflects the server's full protocol and cipher posture rather than
    /// just the single negotiated connection. Finally stores the scan itself.
    pub fn apply_scan(&mut self, scan: probe::TlsScan) {
        self.certificate
            .security_warnings
            .append(&mut analyze_scan(&scan));
        if self.grade.is_some() {
            let input = build_grading_input(&self.cipher, &self.certificate, Some(&scan));
            self.grade = Some(grading::calculate_grade(&input));
        }
        self.scan = Some(scan);
    }

    /// Incorporates a Certificate Transparency lookup into this result.
    ///
    /// Only a *definitive* [`ct::CtStatus::NotLogged`] appends a
    /// [`SecurityWarning::NotInCertificateTransparency`] (a publicly-trusted
    /// certificate that is not logged will be rejected by modern browsers). A
    /// [`ct::CtStatus::Unknown`] ("could not check") deliberately produces **no**
    /// warning — an outage must not be reported as a problem. The
    /// [`ct::CtStatus`] is then stored for output.
    ///
    /// A `NotLogged` for a certificate that carries embedded SCTs is recorded
    /// as `Unknown` instead: crt.sh is one aggregator, not the logs, and it
    /// misses certificates the logs themselves prove they include (seen with
    /// google.com and letsencrypt.org leaves). The SCTs show the certificate
    /// was submitted, so crt.sh's miss cannot be read as absence.
    ///
    /// CT inclusion is informational and does **not** cap the grade: many
    /// legitimately private/internal certificates are intentionally absent
    /// from public CT logs, so callers — not the grade — decide what that
    /// means for a given host.
    pub fn apply_ct(&mut self, ct: ct::CtStatus) {
        self.apply_ct_with_reason(ct, None);
    }

    /// Records a revocation result obtained after the initial check (e.g.
    /// [`check_revocation_from_pem`], on demand) and recomputes the grade,
    /// which a revoked certificate caps at F.
    pub fn apply_revocation(&mut self, status: RevocationStatus, detail: Option<String>) {
        self.certificate.revocation_status = status;
        self.certificate.revocation_detail = detail;
        if self.grade.is_some() {
            let input = build_grading_input(&self.cipher, &self.certificate, self.scan.as_ref());
            self.grade = Some(grading::calculate_grade(&input));
        }
    }

    /// Incorporates the outcome of [`ct::check_ct_status`].
    ///
    /// A definitive answer goes through [`TLS::apply_ct`]. An `Err` ("could
    /// not check") is recorded as [`ct::CtStatus::Unknown`] — never
    /// `NotLogged` — with the reason kept in [`TLS::ct_detail`] and logged.
    pub fn apply_ct_lookup(&mut self, lookup: Result<ct::CtStatus, TLSError>) {
        match lookup {
            Ok(status) => self.apply_ct(status),
            Err(err) => {
                // The `ct` module reports these as Unknown/Certificate with a
                // self-describing message; skip the variant's generic prefix.
                let reason = match err {
                    TLSError::Unknown(msg) | TLSError::Certificate(msg) => msg,
                    other => other.to_string(),
                };
                self.apply_ct_with_reason(ct::CtStatus::Unknown, Some(reason));
            }
        }
    }

    /// Records a CT status and, for an `Unknown` one, [`TLS::ct_detail`]:
    /// `reason` (why crt.sh could not answer), then the certificate's embedded
    /// SCTs as offline evidence it was submitted — which still holds when
    /// crt.sh is down, and is why a crt.sh miss is not read as absence.
    fn apply_ct_with_reason(&mut self, ct: ct::CtStatus, reason: Option<String>) {
        let scts = self.certificate.scts.len();
        let (ct, reason) = match ct {
            ct::CtStatus::NotLogged if scts > 0 => (
                ct::CtStatus::Unknown,
                Some("crt.sh has no record of this certificate".to_string()),
            ),
            other => (other, reason),
        };
        self.ct_detail = None;
        if matches!(ct, ct::CtStatus::Unknown) {
            let evidence = (scts > 0).then(|| {
                format!("the certificate carries {scts} embedded SCT(s), so it was submitted to CT logs")
            });
            self.ct_detail = match (reason, evidence) {
                (Some(reason), Some(evidence)) => Some(format!("{reason}; {evidence}")),
                (reason, evidence) => reason.or(evidence),
            };
            if let Some(detail) = &self.ct_detail {
                warn!(
                    "CT status of {} is unknown: {detail}",
                    self.certificate.hostname
                );
            }
        }
        if matches!(ct, ct::CtStatus::NotLogged) {
            self.certificate
                .security_warnings
                .push(SecurityWarning::NotInCertificateTransparency(
                    "Certificate was not found in any public Certificate Transparency log"
                        .to_string(),
                ));
        }
        self.ct = Some(ct);
    }
}

/// Connects to `addrs` and completes the inspecting handshake with `host`.
///
/// Peer verification is disabled on purpose (see [`TLS::from_with_timeout`]).
/// With `legacy`, OpenSSL's security level is lowered to 0 so protocol
/// versions and parameters the default level refuses (TLS 1.0/1.1, SHA-1
/// signatures, small keys) can still be negotiated — only used to retry a
/// server that rejected the default handshake.
fn inspecting_handshake(
    host: &str,
    addrs: &[SocketAddr],
    timeout: Duration,
    legacy: bool,
) -> Result<openssl::ssl::SslStream<TcpStream>, TLSError> {
    use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};

    let mut context = SslContext::builder(SslMethod::tls())?;
    context.set_verify(SslVerifyMode::empty());
    if legacy {
        context.set_security_level(0);
    }
    // Advertise HTTP/2 and HTTP/1.1 via ALPN so we can report what the
    // server negotiates. Wire format: each protocol is a length-prefixed
    // byte string. Best-effort — a server that ignores ALPN just yields
    // `None`, and a failure to set it must not abort the diagnostic.
    let _ = context.set_alpn_protos(b"\x02h2\x08http/1.1");
    let context = context.build();

    let mut connector = Ssl::new(&context)?;
    connector.set_hostname(host)?;

    let tcp_stream = connect_first_available(addrs, timeout)?;
    tcp_stream.set_read_timeout(Some(timeout))?;
    Ok(connector.connect(tcp_stream)?)
}

/// Whether a handshake failed because the server rejected it at the TLS
/// protocol level (an alert, or no common version/cipher) — the case a legacy
/// retry can fix. Timeouts and socket errors carry an I/O error and are not
/// retried: a second attempt would only cost another `timeout`.
fn is_protocol_rejection(err: &TLSError) -> bool {
    matches!(
        err,
        TLSError::Handshake(HandshakeError::Failure(mid)) if mid.error().io_error().is_none()
    )
}

/// Extracts the first entry from X.509 name entries and converts it to a string.
///
/// # Arguments
///
/// * `entries` - Iterator over X.509 name entries
///
/// # Returns
///
/// The first entry as a UTF-8 string, or "None" if no entries exist.
fn from_entries(mut entries: X509NameEntries) -> String {
    match entries.next() {
        None => "None".to_string(),
        // A certificate under inspection may carry non-UTF-8 name entries;
        // degrade to a lossy conversion instead of panicking on it.
        Some(x509_name_ref) => match x509_name_ref.data().to_string() {
            Ok(s) => s,
            Err(_) => String::from_utf8_lossy(x509_name_ref.data().as_slice()).into_owned(),
        },
    }
}

/// Extracts subject information from an X.509 certificate.
///
/// Parses the certificate's subject distinguished name (DN) and extracts
/// all relevant fields into a structured `Subject` object.
///
/// # Arguments
///
/// * `cert_ref` - Reference to the X.509 certificate
///
/// # Returns
///
/// A `Subject` struct containing country, state, locality, organization unit,
/// organization, and common name fields.
fn get_subject(cert_ref: &X509) -> Subject {
    let subject = cert_ref.subject_name();

    let country_or_region = from_entries(subject.entries_by_nid(Nid::COUNTRYNAME));
    let state_or_province = from_entries(subject.entries_by_nid(Nid::STATEORPROVINCENAME));
    let locality = from_entries(subject.entries_by_nid(Nid::LOCALITYNAME));
    let organization_unit = from_entries(subject.entries_by_nid(Nid::ORGANIZATIONALUNITNAME));
    let common_name = from_entries(subject.entries_by_nid(Nid::COMMONNAME));
    let organization = from_entries(subject.entries_by_nid(Nid::ORGANIZATIONNAME));

    Subject {
        country_or_region,
        state_or_province,
        locality,
        organization_unit,
        organization,
        common_name,
    }
}

/// Extracts issuer information from an X.509 certificate.
///
/// Parses the certificate's issuer distinguished name (DN) to identify
/// the Certificate Authority that issued the certificate.
///
/// # Arguments
///
/// * `cert_ref` - Reference to the X.509 certificate
///
/// # Returns
///
/// An `Issuer` struct containing the CA's country, organization, and common name.
fn get_issuer(cert_ref: &X509) -> Issuer {
    let issuer = cert_ref.issuer_name();

    let common_name = from_entries(issuer.entries_by_nid(Nid::COMMONNAME));
    let organization = from_entries(issuer.entries_by_nid(Nid::ORGANIZATIONNAME));
    let country_or_region = from_entries(issuer.entries_by_nid(Nid::COUNTRYNAME));

    Issuer {
        country_or_region,
        organization,
        common_name,
    }
}

/// Extracts comprehensive information from an X.509 certificate.
///
/// This is an internal helper function that parses all certificate metadata
/// including subject, issuer, validity dates, serial number, and SANs.
///
/// # Arguments
///
/// * `cert_ref` - Reference to the X.509 certificate
///
/// # Returns
///
/// A `CertificateInfo` struct with all extracted certificate metadata.
/// The hostname field is set to "None" and should be populated by the caller.
fn get_certificate_info(cert_ref: &X509) -> CertificateInfo {
    let mut sans = Vec::new();
    if let Some(general_names) = cert_ref.subject_alt_names() {
        for general_name in general_names {
            // Only DNS-name SANs are relevant here; other types (IP address,
            // email, URI, ...) are skipped rather than panicking.
            if let Some(dns) = general_name.dnsname() {
                sans.push(dns.to_string());
            }
        }
    }
    let usage = certext::usage(cert_ref);
    CertificateInfo {
        hostname: "None".to_string(),
        subject: get_subject(cert_ref),
        issued: get_issuer(cert_ref),
        valid_from: cert_ref.not_before().to_string(),
        valid_to: cert_ref.not_after().to_string(),
        valid_from_unix: asn1_time_to_unix(cert_ref.not_before()),
        valid_to_unix: asn1_time_to_unix(cert_ref.not_after()),
        validity_days: get_validity_days(cert_ref.not_after()),
        validity_hours: get_validity_in_hours(cert_ref.not_after()),
        is_expired: has_expired(cert_ref.not_after()),
        cert_sn: serial_hex(cert_ref),
        cert_ver: cert_ref.version().to_string(),
        cert_alg: cert_ref.signature_algorithm().object().to_string(),
        sans,
        chain: None,
        revocation_status: RevocationStatus::NotChecked,
        revocation_detail: None,
        trust: TrustStatus::Unknown,
        is_self_signed: is_self_signed_certificate(cert_ref),
        security_warnings: Vec::new(),
        cert_key_bits: 0,
        cert_key_algorithm: String::new(),
        cert_sha256: fingerprint(cert_ref, openssl::hash::MessageDigest::sha256()),
        cert_sha1: fingerprint(cert_ref, openssl::hash::MessageDigest::sha1()),
        subject_key_id: cert_ref
            .subject_key_id()
            .map(|id| bytes_to_hex_colon(id.as_slice())),
        authority_key_id: cert_ref
            .authority_key_id()
            .map(|id| bytes_to_hex_colon(id.as_slice())),
        validation_level: certext::validation_level(cert_ref),
        key_usage: usage.key_usage,
        ext_key_usage: usage.ext_key_usage,
        is_ca: usage.is_ca,
        path_len: cert_ref.pathlen(),
        ocsp_urls: cert_ref
            .ocsp_responders()
            .map(|responders| {
                responders
                    .iter()
                    .filter_map(|r| std::str::from_utf8(r.as_ref()).ok())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default(),
        ca_issuer_urls: certext::ca_issuer_urls(cert_ref),
        crl_urls: crl_urls(cert_ref),
        scts: sct::embedded_scts(cert_ref),
        pem: String::new(),
    }
}

/// Computes a certificate fingerprint as colon-separated uppercase hex.
///
/// This is the standard fingerprint representation shown by browsers and
/// `openssl x509 -fingerprint` (e.g., `AB:CD:EF:...`). Returns an empty
/// string if the digest cannot be computed.
fn fingerprint(cert_ref: &X509, digest: openssl::hash::MessageDigest) -> String {
    match cert_ref.digest(digest) {
        Ok(bytes) => bytes_to_hex_colon(&bytes),
        Err(_) => String::new(),
    }
}

/// Formats a certificate's serial number as colon-separated uppercase hex.
///
/// Serial numbers are conventionally displayed in hex (`F4:4A:01:...`) rather
/// than as the decimal value of the ASN.1 INTEGER, so this matches what a CA
/// portal, a browser's certificate viewer, or `openssl x509 -text` will show.
/// A serial of zero renders as `00`. Negative serials — malformed per RFC 5280
/// §4.1.2.2, but this is a diagnostic tool that surfaces non-conformant certs
/// rather than normalizing them — are prefixed with `-`, since `BigNum::to_vec`
/// returns only the magnitude bytes.
fn serial_hex(cert_ref: &X509) -> String {
    match cert_ref.serial_number().to_bn() {
        Ok(bn) => {
            let bytes = bn.to_vec();
            if bytes.is_empty() {
                "00".to_string()
            } else {
                let hex = bytes_to_hex_colon(&bytes);
                if bn.is_negative() {
                    format!("-{}", hex)
                } else {
                    hex
                }
            }
        }
        Err(_) => "Unknown".to_string(),
    }
}

/// Collects every URI carried in the certificate's CRL Distribution Points
/// extension, across all distribution points.
///
/// Returns an empty vector when the extension is absent or carries no URI-form
/// names — consistent with the best-effort handling used elsewhere in
/// certificate parsing. Duplicate URIs are collapsed so revocation checks don't
/// fetch the same CRL twice; the list is tiny, so the linear `contains` scan is
/// cheaper than a set.
fn crl_urls(cert_ref: &X509) -> Vec<String> {
    let mut urls = Vec::new();
    let Some(dps) = cert_ref.crl_distribution_points() else {
        return urls;
    };
    for dp in dps.iter() {
        let Some(fullname) = dp.distpoint().and_then(|dp_nm| dp_nm.fullname()) else {
            continue;
        };
        for name in fullname.iter() {
            if let Some(uri) = name.uri() {
                let uri = uri.to_string();
                if !urls.contains(&uri) {
                    urls.push(uri);
                }
            }
        }
    }
    urls
}

/// Formats bytes as colon-separated uppercase hex (e.g. `AB:CD:EF`), the
/// conventional rendering for fingerprints and key identifiers.
fn bytes_to_hex_colon(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Converts an ASN.1 time to a Unix timestamp (seconds since the epoch).
///
/// Returns 0 when the conversion cannot be performed, consistent with the
/// degrade-rather-than-panic handling elsewhere in certificate parsing.
fn asn1_time_to_unix(t: &Asn1TimeRef) -> i64 {
    let epoch = match Asn1Time::from_unix(0) {
        Ok(epoch) => epoch,
        Err(_) => return 0,
    };
    match epoch.diff(t) {
        Ok(diff) => i64::from(diff.days) * 86_400 + i64::from(diff.secs),
        Err(_) => {
            warn!("Failed to convert certificate timestamp");
            0
        }
    }
}

/// Computes the time remaining until certificate expiration.
///
/// Returns the openssl `TimeDiff` (days + leftover seconds, both negative when
/// already expired), or `None` if the current time or the diff cannot be
/// computed — callers degrade to zero rather than panicking.
fn validity_diff(not_after: &Asn1TimeRef) -> Option<openssl::asn1::TimeDiff> {
    let now = Asn1Time::days_from_now(0).ok()?;
    match now.diff(not_after) {
        Ok(diff) => Some(diff),
        Err(_) => {
            warn!("Failed to compute certificate validity period");
            None
        }
    }
}

/// Calculates the number of hours until certificate expiration.
///
/// Unlike `days * 24`, this includes the sub-day remainder, so a certificate
/// expiring in 10 hours reports 10 rather than 0.
///
/// # Arguments
///
/// * `not_after` - Certificate expiration timestamp
///
/// # Returns
///
/// Number of hours until expiration (negative if already expired).
fn get_validity_in_hours(not_after: &Asn1TimeRef) -> i32 {
    validity_diff(not_after)
        .map(|diff| diff.days * 24 + diff.secs / 3600)
        .unwrap_or(0)
}

/// Calculates the number of days until certificate expiration.
///
/// # Arguments
///
/// * `not_after` - Certificate expiration timestamp
///
/// # Returns
///
/// Number of days until expiration (negative if already expired).
fn get_validity_days(not_after: &Asn1TimeRef) -> i32 {
    validity_diff(not_after).map(|diff| diff.days).unwrap_or(0)
}

/// Checks whether a certificate has expired.
///
/// # Arguments
///
/// * `not_after` - Certificate expiration timestamp
///
/// # Returns
///
/// `true` if the certificate has expired, `false` otherwise.
fn has_expired(not_after: &Asn1TimeRef) -> bool {
    not_after < Asn1Time::days_from_now(0).unwrap()
}

/// Error type for TLS certificate validation failures.
#[derive(Error, Debug)]
pub enum TLSError {
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("DNS resolution error: {0}")]
    DNS(String),
    #[error("Connection error: {0}")]
    Connection(#[from] std::io::Error),
    #[error("OpenSSL error: {0}")]
    OpenSSL(#[from] ErrorStack),
    #[error("TLS Handshake error: {0}")]
    Handshake(#[from] HandshakeError<std::net::TcpStream>),
    #[error("Certificate error: {0}")]
    Certificate(String),
    #[error("Unknown error: {0}")]
    Unknown(String),
}

/// Determines whether a certificate is self-signed.
///
/// A certificate is considered self-signed if it meets both criteria:
/// 1. The subject and issuer distinguished names are identical
/// 2. The certificate's signature can be verified using its own public key
///
/// Self-signed certificates are commonly used in testing environments or for
/// internal services, but are not suitable for production use on the public internet.
///
/// # Arguments
///
/// * `cert` - The certificate to check
///
/// # Returns
///
/// `true` if the certificate is self-signed, `false` otherwise.
///
/// # Example
///
/// ```no_run
/// use openssl::x509::X509;
/// use tlschecker::is_self_signed_certificate;
///
/// # fn example(cert: &X509) {
/// if is_self_signed_certificate(cert) {
///     println!("Warning: This is a self-signed certificate");
/// }
/// # }
/// ```
pub fn is_self_signed_certificate(cert: &X509) -> bool {
    let subject = cert.subject_name();
    let issuer = cert.issuer_name();

    // A certificate is considered self-signed if the issuer and subject are the same,
    // and the certificate's signature can be verified with its own public key.
    // `verify` returns `Ok(false)` for a signature that does not match, so
    // only `Ok(true)` proves the certificate signed itself.
    subject.try_cmp(issuer).is_ok_and(|o| o.is_eq())
        && cert
            .public_key()
            .is_ok_and(|pkey| matches!(cert.verify(&pkey), Ok(true)))
}

#[cfg(test)]
mod tests {
    use crate::grading;
    use crate::probe::ProtoVersion;
    use crate::{
        connect_first_available, resolve_addrs, CertificateInfo, Chain, Cipher, Issuer,
        RevocationStatus, SecurityWarning, Subject, TLSError, TrustStatus, TLS,
    };
    use std::net::{SocketAddr, TcpListener};
    use std::time::Duration;

    /// Binds a loopback listener and returns it with its address. The listener
    /// is never accepted from; the kernel backlog is enough for a connect to
    /// succeed, which is all these tests need.
    fn live_addr() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        (listener, addr)
    }

    /// Returns a loopback address with nothing listening on it, by binding a
    /// port and immediately releasing it. Connecting there is refused
    /// immediately rather than timing out, which is the fast-failure case
    /// multi-address connect relies on.
    fn dead_addr() -> SocketAddr {
        let (listener, addr) = live_addr();
        drop(listener);
        addr
    }

    /// Starts an in-process loopback TLS server accepting protocol versions
    /// `min..=max` (security level 0, so legacy versions are really offered)
    /// with the given OpenSSL `cipher_list`, and returns its port. It serves
    /// handshakes sequentially until the test process exits — enough for a
    /// check or a scan, without depending on any external host.
    fn spawn_tls_server(
        min: openssl::ssl::SslVersion,
        max: openssl::ssl::SslVersion,
        cipher_list: &str,
    ) -> u16 {
        use openssl::ssl::{Ssl, SslContext, SslMethod};

        let (cert, key) = make_test_x509("localhost");
        let mut ctx = SslContext::builder(SslMethod::tls_server()).unwrap();
        ctx.set_security_level(0);
        ctx.set_min_proto_version(Some(min)).unwrap();
        ctx.set_max_proto_version(Some(max)).unwrap();
        ctx.set_cipher_list(cipher_list).unwrap();
        ctx.set_certificate(&cert).unwrap();
        ctx.set_private_key(&key).unwrap();
        let ctx = ctx.build();

        let (listener, addr) = live_addr();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
                if let Ok(ssl) = Ssl::new(&ctx) {
                    // Failures are expected: the scan offers versions and
                    // ciphers the server rejects, and connect_first_available
                    // opens a plain TCP connection first.
                    let _ = ssl.accept(stream);
                }
            }
        });
        addr.port()
    }

    #[test]
    fn test_reports_negotiated_protocol_not_cipher_minimum_version() {
        // ECDHE-RSA-AES128-SHA dates from TLS 1.0, so the cipher's own version
        // is "TLSv1.0" even though TLS 1.2 is what was negotiated.
        use openssl::ssl::SslVersion;
        let port = spawn_tls_server(
            SslVersion::TLS1_2,
            SslVersion::TLS1_2,
            "ECDHE-RSA-AES128-SHA",
        );

        let tls =
            TLS::from_with_timeout("127.0.0.1", Some(port), false, true, Duration::from_secs(5))
                .expect("loopback TLS 1.2 handshake");

        assert_eq!(tls.cipher.name, "ECDHE-RSA-AES128-SHA");
        assert_eq!(tls.cipher.version, "TLSv1.2");
        let protocol = &tls.grade.unwrap().categories[0];
        assert_eq!(protocol.category, "Protocol Version");
        assert_eq!(protocol.score, 80, "graded as TLS 1.2: {}", protocol.reason);
    }

    #[test]
    fn test_tls10_only_server_is_inspected() {
        // A diagnostic tool must report a legacy-only server, not fail on it.
        use openssl::ssl::SslVersion;
        let port = spawn_tls_server(SslVersion::TLS1, SslVersion::TLS1, "DEFAULT");

        let tls =
            TLS::from_with_timeout("127.0.0.1", Some(port), false, true, Duration::from_secs(5))
                .expect("a TLS 1.0-only server should still be inspected");

        assert_eq!(tls.cipher.version, "TLSv1");
        let grade = tls.grade.unwrap();
        assert!(
            grade.score <= 54,
            "TLS 1.0 caps the grade at D, got {}",
            grade.score
        );
    }

    #[test]
    fn test_scan_detects_tls10_and_tls11() {
        use openssl::ssl::SslVersion;
        let port = spawn_tls_server(SslVersion::TLS1, SslVersion::TLS1_3, "DEFAULT");

        let scan =
            crate::probe::scan_tls_with_timeout("127.0.0.1", Some(port), Duration::from_secs(5))
                .expect("loopback scan");
        let supported = |v: ProtoVersion| {
            scan.protocols
                .iter()
                .find(|p| p.version == v)
                .is_some_and(|p| p.supported)
        };

        for v in [
            ProtoVersion::Tls1_0,
            ProtoVersion::Tls1_1,
            ProtoVersion::Tls1_2,
            ProtoVersion::Tls1_3,
        ] {
            assert!(
                supported(v),
                "{v} is accepted by the server but was not detected"
            );
        }
        let sslv3 = scan
            .protocols
            .iter()
            .find(|p| p.version == ProtoVersion::Ssl3)
            .unwrap();
        assert!(
            !sslv3.tested,
            "SSLv3 is compiled out, so it cannot be probed"
        );
        let tls10 = scan
            .protocols
            .iter()
            .find(|p| p.version == ProtoVersion::Tls1_0)
            .unwrap();
        assert!(
            tls10.ciphers.iter().any(|c| c == "ECDHE-RSA-AES128-SHA"),
            "TLS 1.0 ciphers should be enumerated: {:?}",
            tls10.ciphers
        );
    }

    #[test]
    fn test_resolve_addrs_returns_loopback() {
        let addrs = resolve_addrs("127.0.0.1", 443).expect("loopback resolves");
        assert_eq!(addrs, vec!["127.0.0.1:443".parse::<SocketAddr>().unwrap()]);
    }

    /// Network test: `to_socket_addrs` calls the system resolver, so this is
    /// gated like the other network tests. It is not merely slow — a resolver
    /// that hijacks NXDOMAIN (ISP "search assist", captive portals, corporate
    /// wildcard DNS) answers `.invalid` with a real address and fails the
    /// assertion, which would make `cargo test` red because of the tester's
    /// network rather than the code.
    #[test]
    #[ignore]
    fn test_resolve_addrs_unresolvable_host_errors() {
        // `.invalid` is reserved by RFC 2606 and must never resolve.
        let err = resolve_addrs("nonexistent.invalid", 443);
        assert!(err.is_err(), "reserved .invalid TLD must not resolve");
    }

    #[test]
    fn test_connect_uses_first_reachable_address() {
        let (_listener, live) = live_addr();
        let dead = dead_addr();

        // The reachable address is deliberately last: taking only the first
        // resolved address (the old behaviour) would fail here.
        let stream = connect_first_available(&[dead, live], Duration::from_secs(5))
            .expect("should fall through to the reachable address");
        assert_eq!(stream.peer_addr().unwrap(), live);
    }

    #[test]
    fn test_connect_prefers_earlier_address_when_reachable() {
        let (_first, first_addr) = live_addr();
        let (_second, second_addr) = live_addr();

        let stream = connect_first_available(&[first_addr, second_addr], Duration::from_secs(5))
            .expect("first address is reachable");
        assert_eq!(
            stream.peer_addr().unwrap(),
            first_addr,
            "resolution order must be preserved"
        );
    }

    #[test]
    fn test_connect_all_addresses_fail_reports_connection_error() {
        let addrs = [dead_addr(), dead_addr()];
        let err = connect_first_available(&addrs, Duration::from_secs(5))
            .expect_err("no address is reachable");
        assert!(
            matches!(err, TLSError::Connection(_)),
            "expected a connection error, got {err:?}"
        );
    }

    #[test]
    fn test_connect_with_no_addresses_errors() {
        let err = connect_first_available(&[], Duration::from_secs(5))
            .expect_err("nothing to connect to");
        assert!(matches!(err, TLSError::Connection(_)));
    }

    /// Creates a synthetic TLS struct for offline testing.
    /// No network connection needed — all fields are populated with realistic data.
    fn make_test_tls() -> TLS {
        TLS {
            cipher: Cipher {
                name: "TLS_AES_256_GCM_SHA384".to_string(),
                version: "TLSv1.3".to_string(),
                bits: 256,
                alpn: Some("h2".to_string()),
            },
            certificate: CertificateInfo {
                hostname: "test.example.com".to_string(),
                subject: Subject {
                    country_or_region: "US".to_string(),
                    state_or_province: "California".to_string(),
                    locality: "San Francisco".to_string(),
                    organization_unit: "Engineering".to_string(),
                    organization: "Example Inc".to_string(),
                    common_name: "test.example.com".to_string(),
                },
                issued: Issuer {
                    country_or_region: "US".to_string(),
                    organization: "Test CA".to_string(),
                    common_name: "Test CA Root".to_string(),
                },
                valid_from: "Jan  1 00:00:00 2025 GMT".to_string(),
                valid_to: "Dec 31 23:59:59 2026 GMT".to_string(),
                valid_from_unix: 1_735_689_600,
                valid_to_unix: 1_798_761_599,
                validity_days: 365,
                validity_hours: 8760,
                is_expired: false,
                cert_sn: "1234567890".to_string(),
                cert_ver: "2".to_string(),
                cert_alg: "sha256WithRSAEncryption".to_string(),
                sans: vec![
                    "test.example.com".to_string(),
                    "www.example.com".to_string(),
                ],
                chain: Some(vec![Chain {
                    subject: "test.example.com".to_string(),
                    issuer: "Test CA Root".to_string(),
                    valid_from: "Jan  1 00:00:00 2025 GMT".to_string(),
                    valid_to: "Dec 31 23:59:59 2026 GMT".to_string(),
                    signature_algorithm: "sha256WithRSAEncryption".to_string(),
                }]),
                revocation_status: RevocationStatus::NotChecked,
                revocation_detail: None,
                trust: TrustStatus::Unknown,
                is_self_signed: false,
                security_warnings: vec![],
                cert_key_bits: 2048,
                cert_key_algorithm: "RSA".to_string(),
                cert_sha256: "AB:CD".to_string(),
                cert_sha1: "12:34".to_string(),
                subject_key_id: Some("AA:BB".to_string()),
                authority_key_id: Some("CC:DD".to_string()),
                validation_level: Some("DV".to_string()),
                key_usage: vec!["digitalSignature".to_string()],
                ext_key_usage: vec!["serverAuth".to_string()],
                is_ca: false,
                path_len: None,
                ocsp_urls: vec![],
                ca_issuer_urls: vec![],
                crl_urls: vec![],
                scts: Vec::new(),
                pem: String::new(),
            },
            grade: None,
            scan: None,
            ct: None,
            ct_detail: None,
        }
    }

    /// Creates a synthetic TLS struct with a grade for offline testing.
    fn make_test_tls_with_grade() -> TLS {
        let mut tls = make_test_tls();
        let input = grading::GradingInput {
            protocol_version: tls.cipher.version.clone(),
            cipher_name: tls.cipher.name.clone(),
            cipher_bits: tls.cipher.bits,
            cert_key_bits: tls.certificate.cert_key_bits,
            cert_key_algorithm: tls.certificate.cert_key_algorithm.clone(),
            is_expired: tls.certificate.is_expired,
            is_self_signed: tls.certificate.is_self_signed,
            has_incomplete_chain: false,
            has_weak_signature: false,
            has_hostname_mismatch: false,
            has_invalid_chain_signature: false,
            supports_obsolete_protocol: false,
            accepts_weak_cipher: false,
            is_revoked: false,
            is_untrusted: false,
        };
        tls.grade = Some(grading::calculate_grade(&input));
        tls
    }

    // ── Integration tests (network-dependent, run with: cargo test -- --ignored) ──

    #[test]
    #[ignore] // requires network: connects to google.com
    fn test_check_tls_for_valid_host() {
        let host = "google.com";
        // Check without revocation checking
        let tls_result = TLS::from(host, None, true, false).unwrap();

        assert!(!tls_result.certificate.is_expired);
        assert_eq!(tls_result.certificate.hostname, host);
        assert_eq!(
            tls_result.certificate.revocation_status,
            RevocationStatus::Good
        );
    }

    #[test]
    #[ignore] // requires network: connects to google.com
    fn test_alpn_negotiated_with_google() {
        let tls_result = TLS::from("google.com", None, false, false).unwrap();
        // google.com supports HTTP/2, so ALPN should select "h2". Tolerate
        // "http/1.1" in case of an intermediary, but it must be populated.
        let alpn = tls_result.cipher.alpn.expect("ALPN should be negotiated");
        assert!(
            alpn == "h2" || alpn == "http/1.1",
            "unexpected ALPN protocol: {alpn}"
        );
    }

    #[test]
    #[ignore] // requires network + a system trust store: connects to google.com
    fn test_trust_valid_host_is_trusted() {
        let tls_result = TLS::from("google.com", None, false, false).unwrap();
        // On a machine with a CA bundle this is Trusted; tolerate Unknown so the
        // test doesn't fail in a bare container without system roots.
        assert!(
            matches!(
                tls_result.certificate.trust,
                TrustStatus::Trusted | TrustStatus::Unknown
            ),
            "expected Trusted/Unknown, got {:?}",
            tls_result.certificate.trust
        );
    }

    #[test]
    #[ignore] // requires network: connects to untrusted-root.badssl.com
    fn test_trust_untrusted_host_reports_untrusted() {
        let tls_result = TLS::from("untrusted-root.badssl.com", None, false, false).unwrap();
        // Tolerate Unknown (no system roots) but never claim Trusted.
        assert!(
            !matches!(tls_result.certificate.trust, TrustStatus::Trusted),
            "an untrusted-root host must not be reported Trusted, got {:?}",
            tls_result.certificate.trust
        );
    }

    #[test]
    #[ignore] // requires network: connects to google.com
    fn test_check_tls_with_revocation() {
        // This test depends on external services, so we'll just check that it runs
        // without error and returns a valid status (not specifically which status)
        let host = "google.com";
        let tls_result = TLS::from(host, None, true, false).unwrap();

        // Good/Unknown are both acceptable (external OCSP responders can be
        // unreliable) and Revoked would be surprising but is tolerated; only
        // NotChecked is wrong, since checking was requested.
        assert!(
            !matches!(
                tls_result.certificate.revocation_status,
                RevocationStatus::NotChecked
            ),
            "Revocation status should not be NotChecked when enabled"
        );
    }

    #[test]
    #[ignore] // requires network: connects to expired.badssl.com
    fn test_check_tls_expired_host() {
        let host = "expired.badssl.com";
        let tls_result = TLS::from(host, None, false, false).unwrap();

        assert!(tls_result.certificate.is_expired);
        assert!(tls_result.certificate.validity_days < 0);
        assert_eq!(tls_result.certificate.hostname, host);
    }

    #[test]
    #[ignore] // requires network: connects to revoked.badssl.com
    fn test_check_revoked_host() {
        // NOTE: This test may be flaky due to external service dependencies
        // Test that the revoked.badssl.com host returns a revoked status
        // If the OCSP responder is unavailable, this might return Unknown instead
        let host = "revoked.badssl.com";

        match TLS::from(host, None, true, false) {
            Ok(tls_result) => {
                // The badssl.com site should either show as revoked or unknown
                // depending on whether the OCSP responder is working
                match tls_result.certificate.revocation_status {
                    RevocationStatus::Revoked(_) => {
                        // This is the expected result
                    }
                    RevocationStatus::Unknown => {
                        // This is acceptable if the OCSP responder is unavailable
                        println!("Warning: revoked.badssl.com showed as Unknown, not Revoked. OCSP responder may be unavailable.");
                    }
                    status => {
                        // Any other status would be unexpected
                        panic!(
                            "Expected Revoked or Unknown status for revoked.badssl.com, got {:?}",
                            status
                        );
                    }
                }
            }
            Err(err) => {
                // It's okay if the connection fails (certificate rejected)
                assert!(
                    matches!(err, TLSError::Certificate(_)),
                    "Expected certificate error, got: {:?}",
                    err
                );
            }
        }
    }

    #[test]
    fn test_empty_hostname() {
        let host = "";
        let result = TLS::from(host, None, false, false).err().unwrap();
        assert!(matches!(result, TLSError::Validation(msg) if msg == "Hostname cannot be empty"));
    }

    #[test]
    fn test_whitespace_hostname() {
        let host = "  ";
        let result = TLS::from(host, None, false, false).err().unwrap();
        assert!(matches!(result, TLSError::Validation(msg) if msg == "Hostname cannot be empty"));
    }

    #[test]
    #[ignore] // requires network: connects to google.com
    fn test_combined_revocation_checking() {
        // This test checks that the combined revocation checking function works correctly
        // It depends on external services, so we'll just test that it doesn't error out
        // rather than checking specific result values

        let host = "google.com";
        match TLS::from(host, None, true, false) {
            Ok(tls_result) => {
                // Just check that we get a valid status type
                match tls_result.certificate.revocation_status {
                    RevocationStatus::Good | RevocationStatus::Unknown => {
                        // Either is acceptable since external services might be unreliable
                    }
                    RevocationStatus::Revoked(_) => {
                        // This would be unexpected for google.com - log it
                        println!("Unexpected RevocationStatus::Revoked for google.com");
                    }
                    RevocationStatus::NotChecked => {
                        // This should not happen since we requested checking
                        panic!("Revocation status should not be NotChecked when enabled");
                    }
                }
            }
            Err(e) => {
                // Connection error - this is unexpected but could happen
                println!("Connection error to google.com: {}", e);
            }
        }
    }

    #[test]
    #[ignore] // requires network: connects to digicert.com
    fn test_crl_distribution_point_parsing() {
        // Try to connect to a site that definitely has CRL distribution points
        // We'll use digicert.com as they're a major CA and likely have proper CRLs
        let host = "digicert.com";
        match TLS::from(host, None, true, false) {
            Ok(tls_result) => {
                // The test passes if we get any valid status
                match tls_result.certificate.revocation_status {
                    RevocationStatus::Good
                    | RevocationStatus::Unknown
                    | RevocationStatus::Revoked(_) => {
                        // Any of these is acceptable
                    }
                    RevocationStatus::NotChecked => {
                        // This should not happen since we requested checking
                        panic!("Revocation status should not be NotChecked when enabled");
                    }
                }
            }
            Err(e) => {
                // Connection error - this is unexpected but could happen
                println!("Connection error to digicert.com: {}", e);
            }
        }
    }

    #[test]
    #[ignore] // requires network: connects to revoked.badssl.com
    fn test_revoked_cert_detection() {
        // Try to test with a known revoked certificate
        // badssl.com provides a revoked certificate test site
        let host = "revoked.badssl.com";

        match TLS::from(host, None, true, false) {
            Ok(tls_result) => {
                // The certificate should either be detected as revoked or unknown
                // depending on whether the revocation checking services are available
                match tls_result.certificate.revocation_status {
                    RevocationStatus::Revoked(_) => {
                        // This is the expected result
                    }
                    RevocationStatus::Unknown => {
                        // This is acceptable if the revocation services are unavailable
                        println!("Warning: revoked.badssl.com showed as Unknown, not Revoked");
                    }
                    status => {
                        // Any other status would be unexpected
                        panic!(
                            "Expected Revoked or Unknown status for revoked.badssl.com, got {:?}",
                            status
                        );
                    }
                }
            }
            Err(err) => {
                // It's okay if the connection fails (certificate rejected)
                assert!(
                    matches!(err, TLSError::Certificate(_)),
                    "Expected certificate error, got: {:?}",
                    err
                );
            }
        }
    }

    // ── Grading flag tests (offline) ──────────────────────────────────

    #[test]
    fn test_tls_with_grading_has_grade() {
        let tls_result = make_test_tls_with_grade();
        assert!(tls_result.grade.is_some());
        let grade = tls_result.grade.unwrap();
        assert!(
            ["A+", "A", "B"].contains(&grade.grade.as_str()),
            "Expected A+, A, or B, got {}",
            grade.grade
        );
        assert!(grade.score >= 70);
        assert_eq!(grade.categories.len(), 5);
    }

    #[test]
    fn test_tls_without_grading_has_no_grade() {
        let tls_result = make_test_tls();
        assert!(tls_result.grade.is_none());
    }

    // ── Cipher / key info tests (offline) ─────────────────────────────

    #[test]
    fn test_cipher_bits_populated() {
        let tls_result = make_test_tls();
        assert!(
            tls_result.cipher.bits > 0,
            "Expected cipher bits > 0, got {}",
            tls_result.cipher.bits
        );
    }

    #[test]
    fn test_cert_key_info_populated() {
        let tls_result = make_test_tls();
        assert!(
            tls_result.certificate.cert_key_bits > 0,
            "Expected cert_key_bits > 0, got {}",
            tls_result.certificate.cert_key_bits
        );
        assert!(
            !tls_result.certificate.cert_key_algorithm.is_empty(),
            "Expected non-empty cert_key_algorithm"
        );
    }

    // ── is_weak_algorithm tests ──────────────────────────────────────

    #[test]
    fn test_is_weak_algorithm_sha1() {
        assert!(super::is_weak_algorithm("sha1WithRSAEncryption"));
        assert!(super::is_weak_algorithm("SHA1withECDSA"));
    }

    #[test]
    fn test_is_weak_algorithm_md5() {
        assert!(super::is_weak_algorithm("md5WithRSAEncryption"));
        assert!(super::is_weak_algorithm("MD5withRSA"));
    }

    #[test]
    fn test_is_weak_algorithm_oids() {
        // sha1WithRSAEncryption OID
        assert!(super::is_weak_algorithm("1.2.840.113549.1.1.5"));
        // md5WithRSAEncryption OID
        assert!(super::is_weak_algorithm("1.2.840.113549.1.1.4"));
        // dsaWithSHA1 OID
        assert!(super::is_weak_algorithm("1.2.840.10040.4.3"));
    }

    #[test]
    fn test_is_not_weak_algorithm() {
        assert!(!super::is_weak_algorithm("sha256WithRSAEncryption"));
        assert!(!super::is_weak_algorithm("sha384WithRSAEncryption"));
        assert!(!super::is_weak_algorithm("sha512WithRSAEncryption"));
        assert!(!super::is_weak_algorithm("ecdsa-with-SHA256"));
        assert!(!super::is_weak_algorithm("ecdsa-with-SHA384"));
    }

    // ── find_issuer_cert tests ───────────────────────────────────────

    #[test]
    #[ignore] // requires network: connects to google.com
    fn test_find_issuer_cert_in_real_chain() {
        // Use a real certificate chain from google.com
        let host = "google.com";
        let tls_result = TLS::from(host, None, false, false).unwrap();
        let chain = tls_result.certificate.chain.as_ref().unwrap();
        assert!(
            chain.len() >= 2,
            "Expected at least 2 certs in chain, got {}",
            chain.len()
        );
    }

    #[test]
    fn test_find_issuer_cert_prefers_key_id_over_name() {
        use openssl::x509::extension::{
            AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier,
        };

        // A real CA carrying a Subject Key Identifier.
        let (ca_key, ca_cert) = {
            let rsa = Rsa::generate(2048).unwrap();
            let key = PKey::from_rsa(rsa).unwrap();
            let mut name = X509NameBuilder::new().unwrap();
            name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "Shared CA Name")
                .unwrap();
            let name = name.build();
            let mut b = X509Builder::new().unwrap();
            b.set_version(2).unwrap();
            let mut serial = BigNum::new().unwrap();
            serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
            b.set_serial_number(&serial.to_asn1_integer().unwrap())
                .unwrap();
            b.set_subject_name(&name).unwrap();
            b.set_issuer_name(&name).unwrap();
            b.set_pubkey(&key).unwrap();
            b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            b.set_not_after(&Asn1Time::days_from_now(3650).unwrap())
                .unwrap();
            b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
                .unwrap();
            let ctx = b.x509v3_context(None, None);
            let skid = SubjectKeyIdentifier::new().build(&ctx).unwrap();
            b.append_extension(skid).unwrap();
            b.sign(&key, MessageDigest::sha256()).unwrap();
            (key, b.build())
        };

        // A leaf whose Authority Key Identifier points at that CA's SKI.
        let leaf = {
            let rsa = Rsa::generate(2048).unwrap();
            let key = PKey::from_rsa(rsa).unwrap();
            let mut name = X509NameBuilder::new().unwrap();
            name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "leaf.example.com")
                .unwrap();
            let name = name.build();
            let mut b = X509Builder::new().unwrap();
            b.set_version(2).unwrap();
            let mut serial = BigNum::new().unwrap();
            serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
            b.set_serial_number(&serial.to_asn1_integer().unwrap())
                .unwrap();
            b.set_subject_name(&name).unwrap();
            b.set_issuer_name(ca_cert.subject_name()).unwrap();
            b.set_pubkey(&key).unwrap();
            b.set_not_before(&Asn1Time::days_from_now(0).unwrap())
                .unwrap();
            b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
                .unwrap();
            let ctx = b.x509v3_context(Some(&ca_cert), None);
            let akid = AuthorityKeyIdentifier::new()
                .keyid(true)
                .build(&ctx)
                .unwrap();
            b.append_extension(akid).unwrap();
            b.sign(&ca_key, MessageDigest::sha256()).unwrap();
            b.build()
        };

        // A decoy sharing the CA's subject *name* but a different key (hence a
        // different/absent SKI). Placed first so a name-only match would pick it.
        let (decoy, _) = make_test_x509("Shared CA Name");

        let chain = [decoy.clone(), ca_cert.clone()];
        let found = super::find_issuer_cert(&leaf, &chain).expect("issuer should be found");
        // AKI→SKI must select the real CA, not the same-named decoy.
        assert_eq!(
            found.digest(MessageDigest::sha256()).unwrap().to_vec(),
            ca_cert.digest(MessageDigest::sha256()).unwrap().to_vec(),
            "find_issuer_cert should prefer the key-id match over the name match"
        );
    }

    // ── analyze_certificate_chain tests ──────────────────────────────

    #[test]
    #[ignore] // requires network: connects to google.com
    fn test_analyze_chain_valid_cert_no_warnings() {
        let host = "google.com";
        let tls_result = TLS::from(host, None, false, false).unwrap();
        // google.com should have no security warnings
        assert!(
            tls_result.certificate.security_warnings.is_empty(),
            "Expected no security warnings for google.com, got {:?}",
            tls_result.certificate.security_warnings
        );
    }

    // ── TLS struct serialization tests (offline) ────────────────────

    #[test]
    fn test_tls_json_serialization() {
        let tls_result = make_test_tls();
        let json = serde_json::to_string(&tls_result).unwrap();
        assert!(json.contains("test.example.com"));
        assert!(json.contains("cipher"));
        assert!(json.contains("\"bits\":256"));
        assert!(json.contains("cert_key_bits"));
        assert!(json.contains("cert_key_algorithm"));
        // grade should not appear when None (skip_serializing_if)
        assert!(!json.contains("grade"));
    }

    #[test]
    fn test_tls_json_serialization_with_grade() {
        let tls_result = make_test_tls_with_grade();
        let json = serde_json::to_string(&tls_result).unwrap();
        assert!(json.contains("grade"));
        assert!(json.contains("score"));
        assert!(json.contains("categories"));
    }

    #[test]
    fn test_tls_json_deserialization_roundtrip() {
        let tls_result = make_test_tls();
        let json = serde_json::to_string(&tls_result).unwrap();
        let deserialized: TLS = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.certificate.hostname, "test.example.com");
        assert_eq!(deserialized.cipher.name, tls_result.cipher.name);
        assert_eq!(deserialized.cipher.bits, tls_result.cipher.bits);
        assert_eq!(
            deserialized.certificate.cert_key_bits,
            tls_result.certificate.cert_key_bits
        );
    }

    // ── RevocationStatus default ─────────────────────────────────────

    #[test]
    fn test_revocation_status_default() {
        let status = RevocationStatus::default();
        assert_eq!(status, RevocationStatus::NotChecked);
    }

    // ── TLSError variants ────────────────────────────────────────────

    #[test]
    fn test_tls_error_display() {
        let err = TLSError::Validation("empty host".to_string());
        assert_eq!(format!("{}", err), "Validation error: empty host");

        let err = TLSError::DNS("not found".to_string());
        assert_eq!(format!("{}", err), "DNS resolution error: not found");

        let err = TLSError::Certificate("bad cert".to_string());
        assert_eq!(format!("{}", err), "Certificate error: bad cert");

        let err = TLSError::Unknown("something".to_string());
        assert_eq!(format!("{}", err), "Unknown error: something");

        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let err = TLSError::Connection(io_err);
        assert!(format!("{}", err).contains("refused"));
    }

    // ── Certificate info via TLS::from ───────────────────────────────

    #[test]
    #[ignore] // requires network: connects to google.com
    fn test_valid_cert_has_sans() {
        let host = "google.com";
        let tls_result = TLS::from(host, None, false, false).unwrap();
        assert!(
            !tls_result.certificate.sans.is_empty(),
            "Expected SANs for google.com"
        );
    }

    #[test]
    #[ignore] // requires network: connects to google.com
    fn test_valid_cert_has_chain() {
        let host = "google.com";
        let tls_result = TLS::from(host, None, false, false).unwrap();
        let chain = tls_result.certificate.chain.as_ref().unwrap();
        assert!(!chain.is_empty(), "Expected non-empty chain for google.com");
        // Each chain cert should have non-empty fields
        for c in chain {
            assert!(!c.subject.is_empty());
            assert!(!c.issuer.is_empty());
            assert!(!c.signature_algorithm.is_empty());
        }
    }

    #[test]
    #[ignore] // requires network: connects to google.com
    fn test_valid_cert_has_issuer_info() {
        let host = "google.com";
        let tls_result = TLS::from(host, None, false, false).unwrap();
        assert!(
            tls_result.certificate.issued.organization != "None",
            "Expected issuer organization for google.com"
        );
    }

    #[test]
    #[ignore] // requires network: connects to google.com
    fn test_valid_cert_not_expired() {
        let host = "google.com";
        let tls_result = TLS::from(host, None, false, false).unwrap();
        assert!(!tls_result.certificate.is_expired);
        assert!(tls_result.certificate.validity_days > 0);
        assert!(tls_result.certificate.validity_hours > 0);
        // Hours include the sub-day remainder, so they fall between the whole
        // days and the next full day.
        let days = tls_result.certificate.validity_days;
        let hours = tls_result.certificate.validity_hours;
        assert!(hours >= days * 24 && hours < (days + 1) * 24);
    }

    #[test]
    #[ignore] // requires network: connects to expired.badssl.com
    fn test_expired_cert_has_negative_days() {
        let host = "expired.badssl.com";
        let tls_result = TLS::from(host, None, false, false).unwrap();
        assert!(tls_result.certificate.is_expired);
        assert!(tls_result.certificate.validity_days < 0);
        assert!(tls_result.certificate.validity_hours < 0);
    }

    // ── In-memory X509 helpers and chain analysis tests (offline) ────

    use openssl::asn1::Asn1Time;
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509NameBuilder, X509};

    /// Creates a self-signed X509 certificate with the given CN.
    fn make_test_x509(common_name: &str) -> (X509, PKey<Private>) {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, common_name)
            .unwrap();
        let name = name.build();

        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        (builder.build(), pkey)
    }

    /// Builds a self-signed cert with a caller-chosen serial number, so serial
    /// formatting can be asserted against a known value.
    fn make_test_x509_with_serial(serial_hex_str: &str) -> X509 {
        let pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "serial.example.com")
            .unwrap();
        let name = name.build();

        let serial = BigNum::from_hex_str(serial_hex_str).unwrap();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    /// Wraps URIs into a DER `CRLDistributionPoints` value:
    /// `SEQUENCE OF DistributionPoint { [0] { [0] { [6] IA5String } } }`.
    /// Only short (<128 byte) elements are emitted, which every test URL is.
    fn crl_dp_der(urls: &[&str]) -> Vec<u8> {
        let mut dps = Vec::new();
        for url in urls {
            let name = [&[0x86, url.len() as u8], url.as_bytes()].concat();
            let full_name = [&[0xA0, name.len() as u8], name.as_slice()].concat();
            let dpn = [&[0xA0, full_name.len() as u8], full_name.as_slice()].concat();
            dps.extend([0x30, dpn.len() as u8]);
            dps.extend(dpn);
        }
        [&[0x30, dps.len() as u8], dps.as_slice()].concat()
    }

    /// Builds a self-signed cert carrying a CRL Distribution Points extension
    /// for the given URLs (none when `urls` is empty).
    fn make_test_x509_with_crl_dps(urls: &[&str]) -> X509 {
        use openssl::asn1::{Asn1Object, Asn1OctetString};
        use openssl::x509::X509Extension;

        let pkey = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "crl.example.com")
            .unwrap();
        let name = name.build();

        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        if !urls.is_empty() {
            let obj = Asn1Object::from_str("2.5.29.31").unwrap(); // cRLDistributionPoints
            let value = Asn1OctetString::new_from_bytes(&crl_dp_der(urls)).unwrap();
            builder
                .append_extension(X509Extension::new_from_der(&obj, false, &value).unwrap())
                .unwrap();
        }
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    #[test]
    fn test_serial_hex_uses_colon_separated_uppercase_hex() {
        // The serial carried by the *.tools.walmartdigital.cl leaf.
        let cert = make_test_x509_with_serial("F44A01829C08CF4D13D188A939D27103");
        assert_eq!(
            super::serial_hex(&cert),
            "F4:4A:01:82:9C:08:CF:4D:13:D1:88:A9:39:D2:71:03"
        );
    }

    #[test]
    fn test_serial_hex_short_and_zero_serials() {
        assert_eq!(super::serial_hex(&make_test_x509_with_serial("01")), "01");
        // A zero serial has no magnitude bytes; it must still render as a byte.
        assert_eq!(super::serial_hex(&make_test_x509_with_serial("00")), "00");
    }

    #[test]
    fn test_serial_hex_negative_serial_keeps_sign() {
        // Non-conformant per RFC 5280, but the tool inspects rather than
        // normalizes: the magnitude must not read as a positive serial.
        let cert = make_test_x509_with_serial("-1A2B");
        assert_eq!(super::serial_hex(&cert), "-1A:2B");
    }

    #[test]
    fn test_crl_urls_collects_every_distribution_point() {
        let cert = make_test_x509_with_crl_dps(&[
            "http://c.pki.example/we1/a.crl",
            "http://c.pki.example/we1/b.crl",
        ]);
        assert_eq!(
            super::crl_urls(&cert),
            vec![
                "http://c.pki.example/we1/a.crl".to_string(),
                "http://c.pki.example/we1/b.crl".to_string()
            ]
        );
    }

    #[test]
    fn test_crl_urls_absent_extension() {
        assert!(super::crl_urls(&make_test_x509_with_crl_dps(&[])).is_empty());
    }

    #[test]
    fn test_crl_urls_deduplicates_repeated_uris() {
        let cert = make_test_x509_with_crl_dps(&[
            "http://c.pki.example/we1/a.crl",
            "http://c.pki.example/we1/a.crl",
        ]);
        assert_eq!(
            super::crl_urls(&cert),
            vec!["http://c.pki.example/we1/a.crl".to_string()]
        );
    }

    #[test]
    fn test_certificate_info_carries_revocation_urls() {
        let cert = make_test_x509_with_crl_dps(&["http://c.pki.example/we1/a.crl"]);
        let info = super::get_certificate_info(&cert);
        assert_eq!(info.crl_urls, vec!["http://c.pki.example/we1/a.crl"]);
        // No AIA on this synthetic cert, so both AIA-derived lists stay empty.
        assert!(info.ocsp_urls.is_empty());
        assert!(info.ca_issuer_urls.is_empty());
    }

    /// Builds a signed CRL whose `nextUpdate` is `next_update_offset_secs`
    /// from now (negative = already stale). The builder requires an AKID,
    /// a CRL number, and at least one revoked entry, so those are included.
    fn make_test_crl(next_update_offset_secs: i64) -> openssl::x509::X509Crl {
        let (issuer_cert, issuer_key) = make_test_x509("Test CA");
        make_test_crl_signed_by(next_update_offset_secs, &issuer_cert, &issuer_key)
    }

    /// Like [`make_test_crl`], but naming `issuer_cert` as the CRL issuer and
    /// signing with `signing_key` — which need not be `issuer_cert`'s key, so
    /// a forged CRL can be built.
    fn make_test_crl_signed_by(
        next_update_offset_secs: i64,
        issuer_cert: &X509,
        signing_key: &PKey<Private>,
    ) -> openssl::x509::X509Crl {
        use openssl::x509::extension::AuthorityKeyIdentifier;
        use openssl::x509::{CrlNumber, X509CrlBuilder, X509RevokedBuilder};

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;

        let mut revoked = X509RevokedBuilder::new().unwrap();
        revoked
            .set_serial_number(&BigNum::from_u32(1024).unwrap().to_asn1_integer().unwrap())
            .unwrap();
        revoked
            .set_revocation_date(&Asn1Time::from_unix(now - 86_400).unwrap())
            .unwrap();

        let dummy = X509Builder::new().unwrap();
        let ctx = dummy.x509v3_context(Some(issuer_cert.as_ref()), None);
        let aki = AuthorityKeyIdentifier::new()
            .issuer(true)
            .build(&ctx)
            .unwrap();
        let crl_number = CrlNumber::new(BigNum::from_u32(1).unwrap())
            .unwrap()
            .build()
            .unwrap();

        let mut builder = X509CrlBuilder::new().unwrap();
        builder.set_issuer_name(issuer_cert.subject_name()).unwrap();
        builder
            .set_last_update(&Asn1Time::from_unix(now - 7 * 86_400).unwrap())
            .unwrap();
        builder
            .set_next_update(&Asn1Time::from_unix(now + next_update_offset_secs).unwrap())
            .unwrap();
        builder.append_extension(aki).unwrap();
        builder.append_extension(crl_number).unwrap();
        builder.add_revoked(revoked.build()).unwrap();
        builder.sign(signing_key, MessageDigest::sha256()).unwrap();
        builder.build().unwrap()
    }

    #[test]
    fn test_crl_signed_by_issuer_is_accepted() {
        let (issuer_cert, issuer_key) = make_test_x509("Test CA");
        let crl = make_test_crl_signed_by(7 * 86_400, &issuer_cert, &issuer_key);
        assert!(crate::is_crl_signed_by(&crl, &issuer_cert));
    }

    #[test]
    fn test_crl_with_foreign_signature_is_rejected() {
        // Names the real issuer but is signed by an unrelated key — what an
        // on-path attacker serving a forged CRL over HTTP would produce.
        // `X509Crl::verify` reports a bad signature as `Ok(false)`, not `Err`.
        let (issuer_cert, _) = make_test_x509("Test CA");
        let (_, attacker_key) = make_test_x509("Attacker");
        let crl = make_test_crl_signed_by(7 * 86_400, &issuer_cert, &attacker_key);
        assert!(!crate::is_crl_signed_by(&crl, &issuer_cert));
    }

    #[test]
    fn test_stale_crl_is_rejected() {
        // nextUpdate a day in the past -> stale, must not be trusted.
        let crl = make_test_crl(-86_400);
        assert!(!crate::is_crl_fresh(&crl, "test"));
    }

    #[test]
    fn test_fresh_crl_is_accepted() {
        // nextUpdate a week in the future -> fresh.
        let crl = make_test_crl(7 * 86_400);
        assert!(crate::is_crl_fresh(&crl, "test"));
    }

    #[test]
    fn test_unix_validity_timestamps() {
        // make_test_x509 issues a cert valid from now for 365 days.
        let (cert, _) = make_test_x509("unix.example.com");
        let info = crate::get_certificate_info(&cert);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        assert!(
            (info.valid_from_unix - now).abs() < 300,
            "valid_from_unix should be ~now, got {}",
            info.valid_from_unix
        );
        let lifetime = info.valid_to_unix - info.valid_from_unix;
        assert_eq!(lifetime, 365 * 86_400);
    }

    #[test]
    fn test_validity_hours_includes_subday_remainder() {
        // A certificate expiring in ~10 hours must report 0 days but ~10
        // hours (regression: hours used to be computed as days * 24).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let not_after = Asn1Time::from_unix(now + 10 * 3600).unwrap();

        assert_eq!(crate::get_validity_days(&not_after), 0);
        let hours = crate::get_validity_in_hours(&not_after);
        assert!(
            (9..=10).contains(&hours),
            "expected ~10 hours remaining, got {}",
            hours
        );
    }

    /// Creates a certificate signed by an issuer (not self-signed).
    fn make_test_x509_signed_by(
        common_name: &str,
        issuer_cert: &X509,
        issuer_key: &PKey<Private>,
    ) -> X509 {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut subject_name = X509NameBuilder::new().unwrap();
        subject_name
            .append_entry_by_nid(openssl::nid::Nid::COMMONNAME, common_name)
            .unwrap();
        let subject_name = subject_name.build();

        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&subject_name).unwrap();
        builder.set_issuer_name(issuer_cert.subject_name()).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        // Sign with issuer's key
        builder.sign(issuer_key, MessageDigest::sha256()).unwrap();

        builder.build()
    }

    /// Creates a self-signed CA root: like `make_test_x509` but with
    /// `basicConstraints: CA:TRUE` + `keyCertSign`, which OpenSSL's
    /// `verify_cert` requires of a trust anchor / signer.
    fn make_test_ca(common_name: &str) -> (X509, PKey<Private>) {
        use openssl::x509::extension::{BasicConstraints, KeyUsage};

        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, common_name)
            .unwrap();
        let name = name.build();

        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(3650).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();

        (builder.build(), pkey)
    }

    /// Builds an `X509Store` trusting exactly the given roots.
    fn make_store(roots: &[&X509]) -> openssl::x509::store::X509Store {
        let mut builder = openssl::x509::store::X509StoreBuilder::new().unwrap();
        for root in roots {
            builder.add_cert((*root).clone()).unwrap();
        }
        builder.build()
    }

    #[test]
    fn test_validate_trust_trusted_when_root_in_store() {
        let (ca, ca_key) = make_test_ca("Test Trust Root");
        let leaf = make_test_x509_signed_by("leaf.example.com", &ca, &ca_key);
        let store = make_store(&[&ca]);

        // The presented chain is [leaf, ca]; the store trusts the root.
        let status = super::validate_trust_with_store(&store, &leaf, &[leaf.clone(), ca.clone()]);
        assert_eq!(status, TrustStatus::Trusted);
    }

    #[test]
    fn test_validate_trust_untrusted_when_root_absent() {
        let (ca, ca_key) = make_test_ca("Test Trust Root");
        let leaf = make_test_x509_signed_by("leaf.example.com", &ca, &ca_key);
        // Store trusts an unrelated root, so the leaf cannot build a path.
        let (other, _) = make_test_ca("Unrelated Root");
        let store = make_store(&[&other]);

        let status = super::validate_trust_with_store(&store, &leaf, std::slice::from_ref(&leaf));
        match status {
            TrustStatus::Untrusted { reason } => {
                assert!(
                    reason.contains("unable to get local issuer"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected Untrusted, got {other:?}"),
        }
    }

    /// Creates a certificate signed with a weak algorithm (SHA1).
    fn make_test_x509_weak_sig(
        common_name: &str,
        issuer_cert: &X509,
        issuer_key: &PKey<Private>,
    ) -> X509 {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut subject_name = X509NameBuilder::new().unwrap();
        subject_name
            .append_entry_by_nid(openssl::nid::Nid::COMMONNAME, common_name)
            .unwrap();
        let subject_name = subject_name.build();

        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&subject_name).unwrap();
        builder.set_issuer_name(issuer_cert.subject_name()).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        // Sign with SHA1 (weak)
        builder.sign(issuer_key, MessageDigest::sha1()).unwrap();

        builder.build()
    }

    #[test]
    fn test_find_issuer_cert_synthetic() {
        let (issuer_cert, issuer_key) = make_test_x509("Test CA");
        let leaf_cert = make_test_x509_signed_by("leaf.example.com", &issuer_cert, &issuer_key);

        let chain = vec![issuer_cert.clone()];
        let result = super::find_issuer_cert(&leaf_cert, &chain);
        assert!(result.is_some(), "Expected to find issuer cert in chain");
    }

    #[test]
    fn test_find_issuer_cert_not_found() {
        let (issuer_cert, issuer_key) = make_test_x509("Test CA");
        let leaf_cert = make_test_x509_signed_by("leaf.example.com", &issuer_cert, &issuer_key);

        // Chain contains an unrelated cert, not the actual issuer
        let (unrelated_cert, _) = make_test_x509("Unrelated CA");
        let chain = vec![unrelated_cert];
        let result = super::find_issuer_cert(&leaf_cert, &chain);
        assert!(
            result.is_none(),
            "Expected issuer not found in unrelated chain"
        );
    }

    #[test]
    fn test_is_self_signed_synthetic() {
        let (self_signed_cert, _) = make_test_x509("Self Signed Cert");
        assert!(
            super::is_self_signed_certificate(&self_signed_cert),
            "Certificate created by make_test_x509 should be self-signed"
        );
    }

    /// Builds a *self-issued* cert (subject == issuer) whose signature was
    /// made by a key other than the one it carries — it looks like a root by
    /// name but its signature does not verify against its own key. Also
    /// returns the private half of the key it carries, so it can still issue
    /// validly-signed children.
    fn make_test_x509_forged_self_issued(common_name: &str) -> (X509, PKey<Private>) {
        let (template, key) = make_test_x509(common_name);
        let (_, other_key) = make_test_x509("Other Key");

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_serial_number(template.serial_number()).unwrap();
        builder.set_subject_name(template.subject_name()).unwrap();
        builder.set_issuer_name(template.subject_name()).unwrap();
        builder.set_pubkey(&template.public_key().unwrap()).unwrap();
        builder.set_not_before(template.not_before()).unwrap();
        builder.set_not_after(template.not_after()).unwrap();
        builder.sign(&other_key, MessageDigest::sha256()).unwrap();
        (builder.build(), key)
    }

    #[test]
    fn test_self_issued_with_bad_signature_is_not_self_signed() {
        let (forged, _) = make_test_x509_forged_self_issued("Forged Root");
        assert!(
            !super::is_self_signed_certificate(&forged),
            "a self-issued cert whose signature does not verify is not self-signed"
        );
    }

    #[test]
    fn test_analyze_chain_flags_forged_self_issued_cert() {
        // A forged "root" used to be skipped as self-signed, so its bad
        // signature was never reported. The leaf is validly signed by the
        // root's key, so the only broken link is the root itself.
        let (forged, root_key) = make_test_x509_forged_self_issued("Forged Root");
        let leaf = make_test_x509_signed_by("leaf.example.com", &forged, &root_key);
        let warnings = super::analyze_certificate_chain(&leaf, &[leaf.clone(), forged]);
        assert!(
            warnings.iter().any(|w| matches!(
                w,
                super::SecurityWarning::InvalidChainSignature(msg)
                    if msg.starts_with("Certificate 'Forged Root'")
            )),
            "expected an InvalidChainSignature warning for the forged root, got {:?}",
            warnings
        );
    }

    #[test]
    fn test_is_not_self_signed_synthetic() {
        let (ca_cert, ca_key) = make_test_x509("Test CA");
        let leaf_cert = make_test_x509_signed_by("leaf.example.com", &ca_cert, &ca_key);
        assert!(
            !super::is_self_signed_certificate(&leaf_cert),
            "CA-signed certificate should not be self-signed"
        );
    }

    #[test]
    fn test_analyze_chain_clean() {
        let (ca_cert, ca_key) = make_test_x509("Clean CA");
        let leaf_cert = make_test_x509_signed_by("leaf.example.com", &ca_cert, &ca_key);

        let chain = vec![ca_cert];
        let warnings = super::analyze_certificate_chain(&leaf_cert, &chain);
        assert!(
            warnings.is_empty(),
            "Clean chain should have no warnings, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_analyze_chain_signature_verification() {
        let (ca, ca_key) = make_test_x509("Real CA");
        // An impostor CA sharing the *same subject name* but a different key.
        let (_, impostor_key) = make_test_x509("Real CA");

        // Correct chain: leaf genuinely signed by `ca` → no signature warning.
        let good_leaf = make_test_x509_signed_by("leaf.example.com", &ca, &ca_key);
        let good = super::analyze_certificate_chain(&good_leaf, &[good_leaf.clone(), ca.clone()]);
        assert!(
            !good
                .iter()
                .any(|w| matches!(w, SecurityWarning::InvalidChainSignature(_))),
            "validly signed chain should not warn, got: {:?}",
            good
        );

        // Forged chain: the leaf names `ca` as its issuer (so the issuer *is*
        // found in the chain) but was signed by the impostor's key, so the
        // signature does not validate against `ca`'s key.
        let forged_leaf = make_test_x509_signed_by("leaf.example.com", &ca, &impostor_key);
        let bad =
            super::analyze_certificate_chain(&forged_leaf, &[forged_leaf.clone(), ca.clone()]);
        assert!(
            bad.iter()
                .any(|w| matches!(w, SecurityWarning::InvalidChainSignature(_))),
            "a cryptographically invalid signature should warn, got: {:?}",
            bad
        );
    }

    #[test]
    fn test_analyze_chain_misordered_valid_signatures_no_false_positive() {
        // A valid chain presented out of issuer order must NOT be reported as
        // having invalid signatures — only as mis-ordered.
        let (root, root_key) = make_test_x509("Root");
        let intermediate = make_test_x509_signed_by("Intermediate", &root, &root_key);
        // Note: our synthetic intermediate is signed by the root's key, and the
        // leaf below is signed by the root too (make_test_x509_signed_by signs
        // with the passed key); presenting them out of order still yields valid
        // signatures against each cert's real issuer.
        let leaf = make_test_x509_signed_by("leaf.example.com", &root, &root_key);
        // Deliberately mis-ordered: [leaf, root, intermediate].
        let chain = [leaf.clone(), root.clone(), intermediate.clone()];
        let warnings = super::analyze_certificate_chain(&leaf, &chain);
        assert!(
            !warnings
                .iter()
                .any(|w| matches!(w, SecurityWarning::InvalidChainSignature(_))),
            "mis-ordered but validly-signed chain must not warn about signatures, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_analyze_chain_weak_signature() {
        let (ca_cert, ca_key) = make_test_x509("Weak Sig CA");
        let weak_leaf = make_test_x509_weak_sig("weak.example.com", &ca_cert, &ca_key);

        let chain = vec![ca_cert];
        let warnings = super::analyze_certificate_chain(&weak_leaf, &chain);
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, super::SecurityWarning::WeakSignatureAlgorithm(_))),
            "Expected WeakSignatureAlgorithm warning for SHA1-signed cert, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_analyze_chain_incomplete() {
        let (ca_cert, ca_key) = make_test_x509("Real CA");
        let leaf_cert = make_test_x509_signed_by("leaf.example.com", &ca_cert, &ca_key);

        // Chain does NOT contain the issuer — it has an unrelated cert
        let (unrelated_cert, _) = make_test_x509("Unrelated CA");
        let chain = vec![unrelated_cert];
        let warnings = super::analyze_certificate_chain(&leaf_cert, &chain);
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, super::SecurityWarning::IncompleteChain(_))),
            "Expected IncompleteChain warning when issuer missing from chain, got: {:?}",
            warnings
        );
    }

    /// Creates a self-signed cert with the given Subject Alternative Names.
    fn make_test_x509_with_sans(common_name: &str, dns_names: &[&str]) -> X509 {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, common_name)
            .unwrap();
        let name = name.build();

        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        if !dns_names.is_empty() {
            let mut san = openssl::x509::extension::SubjectAlternativeName::new();
            for d in dns_names {
                san.dns(d);
            }
            let ext = san.build(&builder.x509v3_context(None, None)).unwrap();
            builder.append_extension(ext).unwrap();
        }
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    /// Creates a cert signed by an issuer that expires in `days` days.
    fn make_test_x509_signed_by_expiring(
        common_name: &str,
        issuer_cert: &X509,
        issuer_key: &PKey<Private>,
        days: u32,
    ) -> X509 {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut subject_name = X509NameBuilder::new().unwrap();
        subject_name
            .append_entry_by_nid(openssl::nid::Nid::COMMONNAME, common_name)
            .unwrap();
        let subject_name = subject_name.build();

        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&subject_name).unwrap();
        builder.set_issuer_name(issuer_cert.subject_name()).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(days).unwrap())
            .unwrap();
        builder.sign(issuer_key, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    // ── Feature 1: hostname / SAN matching ───────────────────────────

    #[test]
    fn test_matches_dns_name_exact_and_case_insensitive() {
        assert!(super::matches_dns_name("example.com", "example.com"));
        assert!(super::matches_dns_name("EXAMPLE.com", "example.com"));
        assert!(super::matches_dns_name("example.com.", "example.com"));
        assert!(!super::matches_dns_name("example.com", "other.com"));
    }

    #[test]
    fn test_matches_dns_name_wildcard() {
        assert!(super::matches_dns_name("*.example.com", "a.example.com"));
        assert!(super::matches_dns_name("*.example.com", "www.example.com"));
        // Wildcard matches exactly one label.
        assert!(!super::matches_dns_name("*.example.com", "example.com"));
        assert!(!super::matches_dns_name("*.example.com", "a.b.example.com"));
        assert!(!super::matches_dns_name("*.example.com", "a.example.org"));
        // Bare wildcard is not valid.
        assert!(!super::matches_dns_name("*.", "a."));
    }

    #[test]
    fn test_cert_matches_hostname_san() {
        let cert = make_test_x509_with_sans("example.com", &["example.com", "*.example.com"]);
        assert!(super::cert_matches_hostname("example.com", &cert));
        assert!(super::cert_matches_hostname("www.example.com", &cert));
        assert!(!super::cert_matches_hostname("example.org", &cert));
    }

    #[test]
    fn test_cert_matches_hostname_cn_fallback() {
        // No SANs -> falls back to CN.
        let (cert, _) = make_test_x509("fallback.example.com");
        assert!(super::cert_matches_hostname("fallback.example.com", &cert));
        assert!(!super::cert_matches_hostname("other.example.com", &cert));
    }

    #[test]
    fn test_cert_matches_hostname_san_ignores_cn() {
        // When SANs are present, CN is not consulted.
        let cert = make_test_x509_with_sans("cn.example.com", &["san.example.com"]);
        assert!(super::cert_matches_hostname("san.example.com", &cert));
        assert!(!super::cert_matches_hostname("cn.example.com", &cert));
    }

    #[test]
    fn test_cert_matches_hostname_idn() {
        // Certificates carry SANs in A-label (punycode) form; a unicode input
        // hostname must be converted before matching.
        let cert = make_test_x509_with_sans(
            "xn--bcher-kva.example",
            &["xn--bcher-kva.example", "*.xn--bcher-kva.example"],
        );
        assert!(super::cert_matches_hostname("bücher.example", &cert));
        assert!(super::cert_matches_hostname("www.bücher.example", &cert));
        assert!(!super::cert_matches_hostname("bücherei.example", &cert));
        // The A-label form itself still matches, of course.
        assert!(super::cert_matches_hostname("xn--bcher-kva.example", &cert));
    }

    #[test]
    fn test_to_ascii_hostname() {
        assert_eq!(
            super::to_ascii_hostname("bücher.example"),
            "xn--bcher-kva.example"
        );
        // ASCII input passes through unchanged.
        assert_eq!(super::to_ascii_hostname("example.com"), "example.com");
    }

    /// Creates a self-signed cert with the given iPAddress SANs (plus optional
    /// DNS SANs) so IP-address matching can be tested.
    fn make_test_x509_with_ip_sans(common_name: &str, ips: &[&str], dns: &[&str]) -> X509 {
        let rsa = Rsa::generate(2048).unwrap();
        let pkey = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, common_name)
            .unwrap();
        let name = name.build();

        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&pkey).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        let mut san = openssl::x509::extension::SubjectAlternativeName::new();
        for d in dns {
            san.dns(d);
        }
        for ip in ips {
            san.ip(ip);
        }
        let ext = san.build(&builder.x509v3_context(None, None)).unwrap();
        builder.append_extension(ext).unwrap();
        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    #[test]
    fn test_unbracket_host() {
        assert_eq!(super::unbracket_host("[::1]"), "::1");
        assert_eq!(
            super::unbracket_host("[2606:4700:4700::1111]"),
            "2606:4700:4700::1111"
        );
        assert_eq!(super::unbracket_host("example.com"), "example.com");
        assert_eq!(super::unbracket_host("1.1.1.1"), "1.1.1.1");
        // Unbalanced brackets are left untouched.
        assert_eq!(super::unbracket_host("[::1"), "[::1");
    }

    #[test]
    fn test_cert_matches_hostname_ip_san() {
        // A cert valid for 127.0.0.1 (and example.com) must match the IP target.
        let cert = make_test_x509_with_ip_sans("server", &["127.0.0.1"], &["example.com"]);
        assert!(super::cert_matches_hostname("127.0.0.1", &cert));
        // ... but not a different IP.
        assert!(!super::cert_matches_hostname("10.0.0.1", &cert));
        // The DNS SAN still works for its name.
        assert!(super::cert_matches_hostname("example.com", &cert));
    }

    #[test]
    fn test_cert_matches_hostname_ip_v6_san() {
        let cert = make_test_x509_with_ip_sans("server", &["::1"], &[]);
        // Different textual forms of the same address must match (byte compare).
        assert!(super::cert_matches_hostname("::1", &cert));
        assert!(super::cert_matches_hostname("0:0:0:0:0:0:0:1", &cert));
        assert!(!super::cert_matches_hostname("::2", &cert));
    }

    #[test]
    fn test_ip_target_dns_only_cert_is_mismatch() {
        // An IP target against a DNS-only cert is correctly a mismatch (RFC 6125:
        // IPs are not matched against DNS names).
        let cert = make_test_x509_with_sans("example.com", &["example.com"]);
        assert!(!super::cert_matches_hostname("127.0.0.1", &cert));
    }

    #[test]
    fn test_ip_target_cn_fallback_when_no_ip_san() {
        // Self-signed/internal certs sometimes put the IP only in the CN.
        let (cert, _) = make_test_x509("10.0.0.5");
        assert!(super::cert_matches_hostname("10.0.0.5", &cert));
        assert!(!super::cert_matches_hostname("10.0.0.6", &cert));
    }

    #[test]
    fn test_hostname_mismatch_emitted_via_from_is_not_possible_offline() {
        // The HostnameMismatch warning is produced inside TLS::from, which needs
        // a live connection; here we just assert the matching primitive behaves.
        let cert = make_test_x509_with_sans("example.com", &["example.com"]);
        assert!(!super::cert_matches_hostname("evil.com", &cert));
    }

    // ── Feature 2: chain ordering ────────────────────────────────────

    #[test]
    fn test_chain_well_ordered() {
        let (ca_cert, ca_key) = make_test_x509("Order CA");
        let leaf = make_test_x509_signed_by("leaf.example.com", &ca_cert, &ca_key);
        // Correct order: leaf then its issuer.
        let ordered = vec![leaf.clone(), ca_cert.clone()];
        assert!(super::is_chain_well_ordered(&ordered));
        // Single-element and empty chains are trivially ordered.
        assert!(super::is_chain_well_ordered(std::slice::from_ref(&leaf)));
        assert!(super::is_chain_well_ordered(&[]));
    }

    #[test]
    fn test_chain_misordered_detected() {
        let (ca_cert, ca_key) = make_test_x509("Order CA");
        let leaf = make_test_x509_signed_by("leaf.example.com", &ca_cert, &ca_key);
        // Wrong order: CA before the leaf it issued.
        let misordered = vec![ca_cert.clone(), leaf.clone()];
        assert!(!super::is_chain_well_ordered(&misordered));

        let warnings = super::analyze_certificate_chain(&leaf, &misordered);
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, super::SecurityWarning::InvalidChainOrder(_))),
            "Expected InvalidChainOrder warning, got: {:?}",
            warnings
        );
    }

    // ── Feature 3: intermediate expiry ───────────────────────────────

    #[test]
    fn test_expiring_intermediate_detected() {
        let (root_cert, root_key) = make_test_x509("Expiry Root");
        // Intermediate signed by root, expiring in 10 days (< 30 day threshold).
        let intermediate =
            make_test_x509_signed_by_expiring("Intermediate CA", &root_cert, &root_key, 10);
        let leaf = make_test_x509_signed_by("leaf.example.com", &intermediate, &root_key);

        let chain = vec![leaf.clone(), intermediate.clone()];
        let warnings = super::analyze_certificate_chain(&leaf, &chain);
        assert!(
            warnings
                .iter()
                .any(|w| matches!(w, super::SecurityWarning::ExpiringIntermediate(_))),
            "Expected ExpiringIntermediate warning, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_expiring_leaf_not_reported_as_intermediate() {
        // The leaf is part of the presented chain; even when it is expiring it
        // must NOT be reported as an ExpiringIntermediate (its expiry is surfaced
        // separately via is_expired).
        let (ca_cert, ca_key) = make_test_x509("Dedup CA");
        let leaf = make_test_x509_signed_by_expiring("leaf.example.com", &ca_cert, &ca_key, 10);

        let chain = vec![leaf.clone(), ca_cert.clone()];
        let warnings = super::analyze_certificate_chain(&leaf, &chain);
        assert!(
            !warnings
                .iter()
                .any(|w| matches!(w, super::SecurityWarning::ExpiringIntermediate(_))),
            "Leaf should not be reported as an expiring intermediate, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_healthy_intermediate_no_expiry_warning() {
        let (root_cert, root_key) = make_test_x509("Healthy Root");
        // Intermediate valid for a year — no expiry warning expected.
        let intermediate =
            make_test_x509_signed_by_expiring("Healthy Intermediate", &root_cert, &root_key, 365);
        let leaf = make_test_x509_signed_by("leaf.example.com", &intermediate, &root_key);

        let chain = vec![leaf.clone(), intermediate.clone()];
        let warnings = super::analyze_certificate_chain(&leaf, &chain);
        assert!(
            !warnings
                .iter()
                .any(|w| matches!(w, super::SecurityWarning::ExpiringIntermediate(_))),
            "Did not expect ExpiringIntermediate warning, got: {:?}",
            warnings
        );
    }

    // ── Feature 7: fingerprints ──────────────────────────────────────

    #[test]
    fn test_fingerprint_format() {
        let (cert, _) = make_test_x509("fp.example.com");
        let sha256 = super::fingerprint(&cert, MessageDigest::sha256());
        // 32 bytes -> 32 hex pairs joined by 31 colons = 95 chars.
        assert_eq!(sha256.len(), 95, "sha256 fingerprint: {}", sha256);
        assert!(sha256.split(':').all(|p| p.len() == 2));
        assert!(sha256.chars().all(|c| c.is_ascii_hexdigit() || c == ':'));
        // Uppercase hex.
        assert_eq!(sha256, sha256.to_uppercase());

        let sha1 = super::fingerprint(&cert, MessageDigest::sha1());
        // 20 bytes -> 20 pairs + 19 colons = 59 chars.
        assert_eq!(sha1.len(), 59, "sha1 fingerprint: {}", sha1);
    }

    #[test]
    fn test_get_certificate_info_populates_fingerprints() {
        let (cert, _) = make_test_x509("info.example.com");
        let info = super::get_certificate_info(&cert);
        assert!(!info.cert_sha256.is_empty());
        assert!(!info.cert_sha1.is_empty());
        assert_ne!(info.cert_sha256, info.cert_sha1);
    }

    // ── Feature 1 (scan → findings/grade): scan analysis ─────────────

    fn proto(
        version: crate::probe::ProtoVersion,
        supported: bool,
        ciphers: &[&str],
    ) -> crate::probe::ProtocolSupport {
        crate::probe::ProtocolSupport {
            version,
            tested: true,
            supported,
            ciphers: ciphers.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_is_weak_cipher() {
        assert!(super::is_weak_cipher("RC4-SHA"));
        assert!(super::is_weak_cipher("RC4-MD5"));
        assert!(super::is_weak_cipher("DES-CBC3-SHA")); // 3DES
        assert!(super::is_weak_cipher("DES-CBC-SHA")); // single DES
        assert!(super::is_weak_cipher("ADH-AES128-SHA")); // anonymous
        assert!(super::is_weak_cipher("EXP-RC2-CBC-MD5")); // export
        assert!(super::is_weak_cipher("NULL-SHA"));

        assert!(!super::is_weak_cipher("ECDHE-RSA-AES256-GCM-SHA384"));
        assert!(!super::is_weak_cipher("AES128-GCM-SHA256"));
        assert!(!super::is_weak_cipher("TLS_AES_256_GCM_SHA384"));
    }

    #[test]
    fn test_analyze_scan_flags_weaknesses() {
        let scan = crate::probe::TlsScan {
            protocols: vec![
                proto(ProtoVersion::Ssl3, true, &[]),
                proto(ProtoVersion::Tls1_0, false, &[]),
                proto(ProtoVersion::Tls1_1, true, &["ECDHE-RSA-AES128-SHA"]),
                proto(
                    ProtoVersion::Tls1_2,
                    true,
                    &["ECDHE-RSA-AES256-GCM-SHA384", "RC4-SHA", "DES-CBC3-SHA"],
                ),
                proto(ProtoVersion::Tls1_3, true, &["TLS_AES_256_GCM_SHA384"]),
            ],
        };
        let warnings = super::analyze_scan(&scan);

        // Obsolete + deprecated protocols flagged (SSLv3, TLSv1.1); supported
        // modern versions not flagged; unsupported TLSv1.0 not flagged.
        let protos: Vec<&String> = warnings
            .iter()
            .filter_map(|w| match w {
                super::SecurityWarning::WeakProtocol(m) => Some(m),
                _ => None,
            })
            .collect();
        assert!(protos.iter().any(|m| m.contains("SSLv3")));
        assert!(protos.iter().any(|m| m.contains("TLSv1.1")));
        assert!(!protos.iter().any(|m| m.contains("TLSv1.0"))); // not supported
        assert!(!protos.iter().any(|m| m.contains("TLSv1.2")));
        assert!(!protos.iter().any(|m| m.contains("TLSv1.3")));

        // Weak ciphers flagged once each; strong ones not flagged.
        let ciphers: Vec<&String> = warnings
            .iter()
            .filter_map(|w| match w {
                super::SecurityWarning::WeakCipher(m) => Some(m),
                _ => None,
            })
            .collect();
        assert_eq!(
            ciphers.len(),
            2,
            "expected RC4-SHA and DES-CBC3-SHA, got {:?}",
            ciphers
        );
        assert!(ciphers.iter().any(|m| m.contains("RC4-SHA")));
        assert!(ciphers.iter().any(|m| m.contains("DES-CBC3-SHA")));
    }

    #[test]
    fn test_analyze_scan_clean_server_no_warnings() {
        let scan = crate::probe::TlsScan {
            protocols: vec![
                proto(ProtoVersion::Ssl3, false, &[]),
                proto(ProtoVersion::Tls1_0, false, &[]),
                proto(ProtoVersion::Tls1_1, false, &[]),
                proto(ProtoVersion::Tls1_2, true, &["ECDHE-RSA-AES256-GCM-SHA384"]),
                proto(ProtoVersion::Tls1_3, true, &["TLS_AES_256_GCM_SHA384"]),
            ],
        };
        assert!(super::analyze_scan(&scan).is_empty());
    }

    #[test]
    fn test_apply_scan_downgrades_grade_and_appends_warnings() {
        let mut tls = make_test_tls_with_grade();
        // Sanity: starts as a strong grade.
        assert!(tls.grade.as_ref().unwrap().score > 50);

        let scan = crate::probe::TlsScan {
            protocols: vec![
                proto(ProtoVersion::Ssl3, true, &[]), // obsolete -> cap at C (69)
                proto(ProtoVersion::Tls1_2, true, &["ECDHE-RSA-AES256-GCM-SHA384"]),
            ],
        };
        tls.apply_scan(scan);

        assert!(tls.scan.is_some());
        assert!(
            tls.certificate
                .security_warnings
                .iter()
                .any(|w| matches!(w, SecurityWarning::WeakProtocol(_))),
            "expected a WeakProtocol warning after apply_scan"
        );
        assert!(
            tls.grade.as_ref().unwrap().score <= 69,
            "expected grade capped at C (69), got {}",
            tls.grade.as_ref().unwrap().score
        );
    }

    #[test]
    fn test_apply_scan_weak_cipher_caps_grade() {
        let mut tls = make_test_tls_with_grade();
        let scan = crate::probe::TlsScan {
            protocols: vec![proto(
                ProtoVersion::Tls1_2,
                true,
                &["ECDHE-RSA-AES256-GCM-SHA384", "RC4-SHA"],
            )],
        };
        tls.apply_scan(scan);
        assert!(
            tls.grade.as_ref().unwrap().score <= 69,
            "weak cipher should cap grade at C (69), got {}",
            tls.grade.as_ref().unwrap().score
        );
        assert!(tls
            .certificate
            .security_warnings
            .iter()
            .any(|w| matches!(w, SecurityWarning::WeakCipher(_))));
    }

    #[test]
    fn test_build_grading_input_flags_negotiated_weak_cipher_without_scan() {
        // Finding 2: the negotiated cipher name alone must set accepts_weak_cipher
        // (no scan), so a server negotiating RC4 can't slip through with a high
        // grade when `--scan` is not used.
        let mut tls = make_test_tls();
        tls.cipher.name = "RC4-SHA".to_string();
        tls.cipher.version = "TLSv1.2".to_string();
        tls.cipher.bits = 128;

        let input = crate::build_grading_input(&tls.cipher, &tls.certificate, None);
        assert!(
            input.accepts_weak_cipher,
            "negotiated RC4 should flag accepts_weak_cipher even without a scan"
        );

        let grade = grading::calculate_grade(&input);
        assert!(
            grade.score <= 69,
            "negotiated weak cipher should cap the grade at C (69), got {}",
            grade.score
        );

        // A strong negotiated cipher must NOT trip the flag.
        let strong = crate::build_grading_input(&make_test_tls().cipher, &tls.certificate, None);
        assert!(!strong.accepts_weak_cipher);
    }

    #[test]
    fn test_invalid_chain_signature_caps_grade_without_trust_store() {
        // Without a trust store the trust verdict is `Unknown`, so the chain
        // analysis is the only thing that saw the forged signature — it must
        // still keep the grade from reading as healthy.
        let mut tls = make_test_tls();
        tls.certificate.trust = TrustStatus::Unknown;
        tls.certificate
            .security_warnings
            .push(SecurityWarning::InvalidChainSignature(
                "Certificate 'test.example.com' is not validly signed by its issuer 'Test CA Root'"
                    .to_string(),
            ));

        let grade = grading::calculate_grade(&crate::build_grading_input(
            &tls.cipher,
            &tls.certificate,
            None,
        ));
        assert!(
            grade.score <= 69,
            "an invalid chain signature should cap the grade at C (69), got {} ({})",
            grade.score,
            grade.grade
        );
    }

    #[test]
    fn test_apply_ct_not_logged_with_embedded_scts_is_unknown() {
        // crt.sh is one aggregator, not the logs: it has answered "Certificate
        // not found" for google.com and letsencrypt.org leaves whose SCTs are
        // valid and whose precertificates the logs prove they include.
        let mut tls = make_test_tls();
        tls.certificate.scts = vec![crate::sct::Sct {
            version: 0,
            log_id: "ab".repeat(32),
            timestamp_ms: 1_789_071_715_432,
            timestamp: "2026-09-10T20:21:55Z".to_string(),
        }];

        tls.apply_ct(crate::ct::CtStatus::NotLogged);

        assert_eq!(tls.ct, Some(crate::ct::CtStatus::Unknown));
        assert!(tls
            .ct_detail
            .as_deref()
            .is_some_and(|d| d.contains("1 embedded SCT")));
        assert!(!tls
            .certificate
            .security_warnings
            .iter()
            .any(|w| matches!(w, SecurityWarning::NotInCertificateTransparency(_))));
    }

    // ── CRL cache and download limits ─────────────────────────────────

    /// Minimal loopback HTTP/1.1 server answering every request with
    /// `status` and `body` after `delay`, counting requests. Each connection
    /// gets its own thread, so concurrent clients really overlap.
    fn spawn_http_server(
        status: u16,
        body: Vec<u8>,
        send_length: bool,
        delay: Duration,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let (counter, body) = (Arc::clone(&hits), Arc::new(body));
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let (counter, body) = (Arc::clone(&counter), Arc::clone(&body));
                std::thread::spawn(move || {
                    let mut request = Vec::new();
                    let mut buf = [0u8; 4096];
                    while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                        match stream.read(&mut buf) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => request.extend_from_slice(&buf[..n]),
                        }
                    }
                    counter.fetch_add(1, Ordering::SeqCst);
                    std::thread::sleep(delay);
                    let length = if send_length {
                        format!("Content-Length: {}\r\n", body.len())
                    } else {
                        String::new()
                    };
                    let head = format!("HTTP/1.1 {status} X\r\n{length}Connection: close\r\n\r\n");
                    let _ = stream.write_all(head.as_bytes());
                    let _ = stream.write_all(&body);
                });
            }
        });
        (base, hits)
    }

    /// A CA-issued leaf whose CRL Distribution Point is `url`.
    fn make_test_leaf_with_crl_dp(ca_cert: &X509, ca_key: &PKey<Private>, url: &str) -> X509 {
        use openssl::asn1::{Asn1Object, Asn1OctetString};
        use openssl::x509::X509Extension;

        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "crl-leaf.example")
            .unwrap();
        let name = name.build();
        let mut serial = BigNum::new().unwrap();
        serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder
            .set_serial_number(&serial.to_asn1_integer().unwrap())
            .unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        let obj = Asn1Object::from_str("2.5.29.31").unwrap();
        let value = Asn1OctetString::new_from_bytes(&crl_dp_der(&[url])).unwrap();
        builder
            .append_extension(X509Extension::new_from_der(&obj, false, &value).unwrap())
            .unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();
        builder.build()
    }

    /// DER of a fresh CRL from a throwaway CA, for fake downloads.
    fn test_crl_der() -> Vec<u8> {
        make_test_crl(7 * 86_400).to_der().unwrap()
    }

    #[test]
    fn test_crl_cache_downloads_once_for_concurrent_callers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = crate::CrlCache::new(16, 16 << 20);
        let der = test_crl_der();
        let downloads = AtomicUsize::new(0);

        std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    s.spawn(|| {
                        cache.get("http://ca.example/shared.crl", |_| {
                            downloads.fetch_add(1, Ordering::SeqCst);
                            // Slow enough that every caller arrives mid-download.
                            std::thread::sleep(Duration::from_millis(150));
                            Ok((openssl::x509::X509Crl::from_der(&der).unwrap(), der.len()))
                        })
                    })
                })
                .collect();
            for handle in handles {
                assert!(handle.join().unwrap().is_ok());
            }
        });
        assert_eq!(downloads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_crl_cache_reuses_downloads_and_remembers_failures() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let cache = crate::CrlCache::new(16, 16 << 20);
        let der = test_crl_der();
        let downloads = AtomicUsize::new(0);
        let ok = |_: &str| {
            downloads.fetch_add(1, Ordering::SeqCst);
            Ok((openssl::x509::X509Crl::from_der(&der).unwrap(), der.len()))
        };
        let failing = |_: &str| {
            downloads.fetch_add(1, Ordering::SeqCst);
            Err("request failed: operation timed out".to_string())
        };

        assert!(cache.get("http://ok.example/a.crl", ok).is_ok());
        assert!(cache.get("http://ok.example/a.crl", ok).is_ok());
        assert_eq!(downloads.load(Ordering::SeqCst), 1);

        // A hung distribution point costs its timeout once, not once per host.
        for _ in 0..2 {
            assert_eq!(
                cache
                    .get("http://dead.example/a.crl", failing)
                    .err()
                    .as_deref(),
                Some("request failed: operation timed out")
            );
        }
        assert_eq!(downloads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_crl_cache_evicts_least_recently_used() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let der = test_crl_der();
        let downloads = AtomicUsize::new(0);
        let fetch = |_: &str| {
            downloads.fetch_add(1, Ordering::SeqCst);
            Ok((openssl::x509::X509Crl::from_der(&der).unwrap(), der.len()))
        };
        let count = || downloads.load(Ordering::SeqCst);

        // By count: room for two.
        let cache = crate::CrlCache::new(2, usize::MAX);
        cache.get("a", fetch).unwrap();
        cache.get("b", fetch).unwrap();
        cache.get("a", fetch).unwrap(); // hit; `a` is now the most recent
        cache.get("c", fetch).unwrap(); // over the bound once `c` is in
        assert_eq!(count(), 3);
        cache.get("a", fetch).unwrap(); // still cached — `b` was the oldest
        assert_eq!(count(), 3);
        cache.get("b", fetch).unwrap(); // evicted, so downloaded again
        assert_eq!(count(), 4);

        // By size: room for one CRL's bytes.
        downloads.store(0, Ordering::SeqCst);
        let cache = crate::CrlCache::new(16, der.len());
        cache.get("x", fetch).unwrap();
        cache.get("y", fetch).unwrap();
        cache.get("y", fetch).unwrap(); // evicts `x` to fit
        cache.get("x", fetch).unwrap();
        assert_eq!(count(), 3);
    }

    #[test]
    fn test_fetch_crl_rejects_oversized_bodies() {
        for send_length in [true, false] {
            let (base, hits) = spawn_http_server(200, vec![0u8; 4096], send_length, Duration::ZERO);
            let err = crate::fetch_crl(&format!("{base}/big.crl"), 1024).err();
            assert_eq!(
                err.as_deref(),
                Some("response exceeds the 1 KiB limit"),
                "Content-Length sent: {send_length}"
            );
            assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn test_hosts_sharing_a_crl_download_it_once() {
        // End to end through the revocation check and the process-wide cache:
        // eight concurrent checks of certificates from one CA, one download.
        let (ca_cert, ca_key) = make_test_x509("Shared CRL CA");
        let crl = make_test_crl_signed_by(7 * 86_400, &ca_cert, &ca_key);
        let (base, hits) =
            spawn_http_server(200, crl.to_der().unwrap(), true, Duration::from_millis(150));
        let url = format!("{base}/shared.crl");
        let leaves: Vec<X509> = (0..8)
            .map(|_| make_test_leaf_with_crl_dp(&ca_cert, &ca_key, &url))
            .collect();

        std::thread::scope(|s| {
            let handles: Vec<_> = leaves
                .iter()
                .map(|leaf| {
                    let chain = vec![leaf.clone(), ca_cert.clone()];
                    s.spawn(move || crate::crl_revocation(leaf, &chain))
                })
                .collect();
            for handle in handles {
                assert_eq!(handle.join().unwrap(), Ok(RevocationStatus::Good));
            }
        });
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn test_revocation_detail_when_issuer_missing() {
        let (ca_cert, ca_key) = make_test_x509("Detail CA");
        let leaf = make_test_x509_signed_by("leaf.example.com", &ca_cert, &ca_key);

        let (status, detail) =
            crate::revocation_status_with_detail(&leaf, std::slice::from_ref(&leaf));

        assert_eq!(status, RevocationStatus::Unknown);
        assert_eq!(
            detail.as_deref(),
            Some(
                "OCSP: issuer certificate is not in the presented chain; \
                 CRL: issuer certificate is not in the presented chain"
            )
        );
    }

    #[test]
    fn test_revocation_detail_when_certificate_lists_no_endpoints() {
        let (ca_cert, ca_key) = make_test_x509("Detail CA");
        let leaf = make_test_x509_signed_by("leaf.example.com", &ca_cert, &ca_key);

        let (status, detail) =
            crate::revocation_status_with_detail(&leaf, &[leaf.clone(), ca_cert]);

        assert_eq!(status, RevocationStatus::Unknown);
        assert_eq!(
            detail.as_deref(),
            Some(
                "OCSP: certificate lists no OCSP responder; \
                 CRL: certificate lists no CRL distribution point"
            )
        );
    }

    #[test]
    fn test_revocation_detail_names_unreachable_crl_and_cause() {
        // Loopback with nothing listening: refused immediately, no network.
        let url = format!("http://{}/ca.crl", dead_addr());
        let cert = make_test_x509_with_crl_dps(&[url.as_str()]);

        let (status, detail) =
            crate::revocation_status_with_detail(&cert, std::slice::from_ref(&cert));

        assert_eq!(status, RevocationStatus::Unknown);
        let detail = detail.expect("an Unknown status carries its reason");
        assert!(
            detail.contains(&format!("CRL: {url}: request failed")),
            "{detail}"
        );
        // The cause from reqwest's source chain, not just "error sending request".
        assert!(detail.to_lowercase().contains("refused"), "{detail}");
    }

    #[test]
    fn test_definitive_revocation_has_no_detail() {
        let tls = make_test_tls();
        assert!(tls.certificate.revocation_detail.is_none());
    }

    #[test]
    fn test_apply_ct_lookup_error_is_unknown_with_reason() {
        let mut tls = make_test_tls();
        tls.apply_ct_lookup(Err(TLSError::Unknown(
            "CT lookup returned HTTP 502 Bad Gateway".to_string(),
        )));

        assert_eq!(tls.ct, Some(crate::ct::CtStatus::Unknown));
        assert_eq!(
            tls.ct_detail.as_deref(),
            Some("CT lookup returned HTTP 502 Bad Gateway")
        );
        assert!(tls.certificate.security_warnings.is_empty());
    }

    #[test]
    fn test_ct_detail_carries_embedded_sct_evidence() {
        let sct = crate::sct::Sct {
            version: 0,
            log_id: "ab".repeat(32),
            timestamp_ms: 0,
            timestamp: "2026-09-10T20:21:55Z".to_string(),
        };
        let evidence = "the certificate carries 1 embedded SCT(s), so it was submitted to CT logs";

        // crt.sh could not be queried: its reason, then the offline evidence.
        let mut failed = make_test_tls();
        failed.certificate.scts = vec![sct.clone()];
        failed.apply_ct_lookup(Err(TLSError::Unknown("timeout".to_string())));
        assert_eq!(failed.ct_detail, Some(format!("timeout; {evidence}")));

        // crt.sh has no record: why that was not read as absence.
        let mut unlisted = make_test_tls();
        unlisted.certificate.scts = vec![sct];
        unlisted.apply_ct(crate::ct::CtStatus::NotLogged);
        assert_eq!(
            unlisted.ct_detail,
            Some(format!(
                "crt.sh has no record of this certificate; {evidence}"
            ))
        );

        // No SCTs: nothing to add.
        let mut plain = make_test_tls();
        plain.apply_ct_lookup(Err(TLSError::Unknown("timeout".to_string())));
        assert_eq!(plain.ct_detail.as_deref(), Some("timeout"));
    }

    #[test]
    fn test_check_revocation_from_pem_uses_the_kept_chain() {
        let (ca_cert, ca_key) = make_test_x509("Kept CA");
        let leaf = make_test_x509_signed_by("leaf.example.com", &ca_cert, &ca_key);
        let pem = [leaf.to_pem().unwrap(), ca_cert.to_pem().unwrap()].concat();

        let (status, detail) = crate::check_revocation_from_pem(&String::from_utf8(pem).unwrap());

        // The issuer came from the PEM: the failures are about endpoints, not
        // a missing issuer.
        assert_eq!(status, RevocationStatus::Unknown);
        assert_eq!(
            detail.as_deref(),
            Some(
                "OCSP: certificate lists no OCSP responder; \
                 CRL: certificate lists no CRL distribution point"
            )
        );
    }

    #[test]
    fn test_check_revocation_from_pem_without_chain() {
        let (status, detail) = crate::check_revocation_from_pem("");
        assert_eq!(status, RevocationStatus::Unknown);
        assert_eq!(
            detail.as_deref(),
            Some("no certificate chain was kept for this result")
        );
    }

    #[test]
    fn test_apply_revocation_recomputes_grade() {
        let mut tls = make_test_tls();
        tls.grade = Some(grading::calculate_grade(&crate::build_grading_input(
            &tls.cipher,
            &tls.certificate,
            None,
        )));
        assert!(tls.grade.as_ref().unwrap().score > 0);

        tls.apply_revocation(
            RevocationStatus::Revoked("Revoked via CRL".to_string()),
            None,
        );

        assert_eq!(tls.grade.as_ref().unwrap().grade, "F");
        assert_eq!(
            tls.certificate.revocation_status,
            RevocationStatus::Revoked("Revoked via CRL".to_string())
        );
    }

    #[test]
    fn test_apply_ct_definitive_clears_detail() {
        let mut tls = make_test_tls();
        tls.apply_ct_lookup(Err(TLSError::Unknown("timeout".to_string())));
        tls.apply_ct(crate::ct::CtStatus::Logged {
            crtsh_id: 1,
            crtsh_url: "https://crt.sh/?id=1".to_string(),
        });
        assert!(tls.ct_detail.is_none());
    }

    #[test]
    fn test_apply_ct_not_logged_without_scts_warns() {
        // No embedded SCTs and absent from crt.sh: absence is plausible.
        let mut tls = make_test_tls(); // scts empty
        tls.apply_ct(crate::ct::CtStatus::NotLogged);

        assert_eq!(tls.ct, Some(crate::ct::CtStatus::NotLogged));
        assert!(tls
            .certificate
            .security_warnings
            .iter()
            .any(|w| matches!(w, SecurityWarning::NotInCertificateTransparency(_))));
    }

    #[test]
    fn test_apply_scan_leaves_grade_none_when_not_graded() {
        let mut tls = make_test_tls(); // grade: None
        let scan = crate::probe::TlsScan {
            protocols: vec![proto(ProtoVersion::Ssl3, true, &[])],
        };
        tls.apply_scan(scan);
        assert!(tls.grade.is_none(), "apply_scan must not invent a grade");
        assert!(tls.scan.is_some());
        assert!(tls
            .certificate
            .security_warnings
            .iter()
            .any(|w| matches!(w, SecurityWarning::WeakProtocol(_))));
    }
}
