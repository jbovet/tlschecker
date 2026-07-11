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

pub mod ct;
pub mod grading;
pub mod probe;
pub mod sct;

use std::fmt::Debug;
use std::time::Duration;

use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::error::ErrorStack;
use openssl::nid::Nid;
use openssl::ocsp::OcspCertStatus;
use openssl::ssl::HandshakeError;
use openssl::x509::{CrlStatus, ReasonCode, X509Crl, X509NameEntries, X509Ref, X509};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{instrument, warn};

/// Default timeout for TLS connection attempts (30 seconds).
static TIMEOUT: Duration = Duration::from_secs(30);

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
}

/// TLS cipher suite information.
///
/// Contains details about the negotiated cipher and protocol version
/// used for the TLS connection.
#[derive(Serialize, Deserialize, Clone)]
pub struct Cipher {
    /// Name of the cipher suite (e.g., "ECDHE-RSA-AES128-GCM-SHA256")
    pub name: String,
    /// TLS protocol version (e.g., "TLSv1.3", "TLSv1.2")
    pub version: String,
    /// Cipher suite key length in bits
    pub bits: i32,
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
    /// Certificate serial number
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
    let cert_issuer = cert.issuer_name();

    for potential_issuer in chain {
        // Get the subject name of the potential issuer
        let potential_subject = potential_issuer.subject_name();

        // Compare the issuer name of our certificate with the subject name of the potential issuer
        if cert_issuer
            .try_cmp(potential_subject)
            .is_ok_and(|ordering| ordering == std::cmp::Ordering::Equal)
        {
            return Some(potential_issuer);
        }
    }
    None
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
        supports_obsolete_protocol: scan.map(scan_supports_obsolete_protocol).unwrap_or(false),
        // Penalise a weak cipher even without `--scan`: the negotiated cipher
        // name alone (e.g. RC4/3DES/NULL) is enough to cap the grade. The scan,
        // when present, additionally surfaces weak ciphers the server merely
        // *accepts* beyond the one negotiated here.
        accepts_weak_cipher: is_weak_cipher(&cipher.name)
            || scan.map(scan_accepts_weak_cipher).unwrap_or(false),
        is_revoked: matches!(certificate.revocation_status, RevocationStatus::Revoked(_)),
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
    use openssl::hash::MessageDigest;
    use openssl::ocsp::OcspCertId;

    // First, find the issuer certificate in the chain
    let issuer = match find_issuer_cert(cert, chain) {
        Some(issuer) => issuer,
        None => return Ok(RevocationStatus::Unknown), // Can't verify without issuer
    };

    // Get OCSP responder URLs from certificate
    let ocsp_responders = match cert.ocsp_responders() {
        Ok(responders) if !responders.is_empty() => responders,
        Ok(_) => return Ok(RevocationStatus::Unknown), // No OCSP responders found
        Err(_) => return Ok(RevocationStatus::Unknown), // Error getting responders
    };

    // Create the OCSP request
    let ocsp_cert_id = match OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer) {
        Ok(id) => id,
        Err(_) => return Ok(RevocationStatus::Unknown), // Couldn't create cert ID
    };

    let mut ocsp_req = match openssl::ocsp::OcspRequest::new() {
        Ok(req) => req,
        Err(_) => return Ok(RevocationStatus::Unknown), // Couldn't create request
    };

    if ocsp_req.add_id(ocsp_cert_id).is_err() {
        return Ok(RevocationStatus::Unknown); // Couldn't add ID to request
    }

    let req_bytes = match ocsp_req.to_der() {
        Ok(bytes) => bytes,
        Err(_) => return Ok(RevocationStatus::Unknown), // Couldn't encode request
    };

    // Try each responder URL
    for responder in ocsp_responders.iter() {
        let responder_url = match std::str::from_utf8(responder.as_ref()) {
            Ok(url) => url,
            Err(_) => continue,
        };

        // Make HTTP POST request to OCSP responder
        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(_) => continue,
        };

        let response = match client
            .post(responder_url)
            .header("Content-Type", "application/ocsp-request")
            .body(req_bytes.clone())
            .send()
        {
            Ok(resp) => resp,
            Err(_) => continue, // Try next responder if this one fails
        };

        if !response.status().is_success() {
            continue;
        }

        let resp_bytes = match response.bytes() {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => continue,
        };

        // Parse OCSP response
        let ocsp_response = match openssl::ocsp::OcspResponse::from_der(&resp_bytes) {
            Ok(resp) => resp,
            Err(_) => continue,
        };

        if ocsp_response.status() != openssl::ocsp::OcspResponseStatus::SUCCESSFUL {
            continue;
        }

        let basic_resp = match ocsp_response.basic() {
            Ok(resp) => resp,
            Err(_) => continue,
        };

        // Verify the OCSP response - need to build a store with the issuer
        let mut store_builder = match openssl::x509::store::X509StoreBuilder::new() {
            Ok(builder) => builder,
            Err(_) => continue,
        };

        if store_builder.add_cert(issuer.to_owned()).is_err() {
            continue;
        }

        let store = store_builder.build();

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
        let mut certs = match openssl::stack::Stack::<X509>::new() {
            Ok(certs) => certs,
            Err(_) => continue,
        };
        for c in chain {
            let _ = certs.push(c.to_owned());
        }
        if basic_resp
            .verify(&certs, &store, openssl::ocsp::OcspFlag::empty())
            .is_err()
        {
            warn!("OCSP response signature verification failed; ignoring response from {responder_url}");
            continue;
        }

        // Check status
        // Create a new cert_id for each check since find_status consumes it
        let check_cert_id = match OcspCertId::from_cert(MessageDigest::sha1(), cert, issuer) {
            Ok(id) => id,
            Err(_) => continue,
        };

        match basic_resp.find_status(&check_cert_id) {
            Some(status) => {
                // Check validity of the OCSP response
                if status.check_validity(300, None).is_err() {
                    continue;
                }

                match status.status {
                    OcspCertStatus::GOOD => return Ok(RevocationStatus::Good),
                    OcspCertStatus::REVOKED => {
                        let reason = if let Some(reason) = status.revocation_time {
                            format!("Revoked at {}", reason)
                        } else {
                            "Unknown reason".to_string()
                        };
                        return Ok(RevocationStatus::Revoked(reason));
                    }
                    OcspCertStatus::UNKNOWN => return Ok(RevocationStatus::Unknown),
                    _ => return Ok(RevocationStatus::Unknown),
                }
            }
            None => continue,
        }
    }

    // If we tried all responders and none worked, return Unknown
    Ok(RevocationStatus::Unknown)
}

/// Combined revocation checking function that tries both OCSP and CRL
#[instrument(skip(cert, chain))]
pub fn check_revocation_status(cert: &X509, chain: &[X509]) -> Result<RevocationStatus, TLSError> {
    // First try OCSP checking as it's typically more up-to-date
    match check_ocsp_status(cert, chain) {
        Ok(RevocationStatus::Good) => Ok(RevocationStatus::Good),
        Ok(revoked @ RevocationStatus::Revoked(_)) => Ok(revoked),
        _ => {
            // Fallback to CRL checking if OCSP was inconclusive
            check_crl_status(cert, chain)
        }
    }
}

#[instrument(skip(cert, chain))]
pub fn check_crl_status(cert: &X509, chain: &[X509]) -> Result<RevocationStatus, TLSError> {
    use openssl::x509::store::X509StoreBuilder;

    // Find the issuer certificate in the chain
    let issuer = match find_issuer_cert(cert, chain) {
        Some(issuer) => issuer,
        None => return Ok(RevocationStatus::Unknown), // Can't verify without issuer
    };

    // Get CRL distribution points from the certificate
    let crl_dps = match cert.crl_distribution_points() {
        Some(dps) if !dps.is_empty() => dps,
        _ => return Ok(RevocationStatus::Unknown), // No CRL distribution points found
    };

    // Create a store for verification
    let mut store_builder = match X509StoreBuilder::new() {
        Ok(builder) => builder,
        Err(_) => return Ok(RevocationStatus::Unknown),
    };

    // Add the issuer certificate to the store
    if store_builder.add_cert(issuer.to_owned()).is_err() {
        return Ok(RevocationStatus::Unknown);
    }

    // Try each CRL distribution point
    for dp in crl_dps.iter() {
        // Extract the CRL URL
        let uri = match dp.distpoint().and_then(|dp_nm| dp_nm.fullname()) {
            Some(fullname) => {
                let mut uri = None;
                for name in fullname.iter() {
                    if let Some(url) = name.uri() {
                        uri = Some(url);
                        break;
                    }
                }
                uri
            }
            None => None,
        };

        let crl_url = match uri {
            Some(url) => url,
            None => continue, // No URI found, try next DP
        };

        // Download the CRL
        let client = match reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(_) => continue,
        };

        let response = match client.get(crl_url).send() {
            Ok(resp) => resp,
            Err(_) => continue,
        };

        if !response.status().is_success() {
            continue;
        }

        let crl_data = match response.bytes() {
            Ok(bytes) => bytes.to_vec(),
            Err(_) => continue,
        };

        // Try parsing as DER first, then as PEM
        let crl = match X509Crl::from_der(&crl_data) {
            Ok(crl) => crl,
            Err(_) => {
                // Try PEM format if DER parsing failed
                match X509Crl::from_pem(&crl_data) {
                    Ok(crl) => crl,
                    Err(_) => continue,
                }
            }
        };

        // Verify the CRL signature. An issuer whose public key cannot be
        // extracted is treated like a failed verification: skip this CRL
        // (degrading to `Unknown`) rather than panicking.
        let issuer_key = match issuer.public_key() {
            Ok(key) => key,
            Err(_) => continue,
        };
        if crl.verify(&issuer_key).is_err() {
            continue; // CRL signature verification failed
        }

        // Reject stale CRLs: a correctly-signed but expired CRL (nextUpdate in
        // the past) may predate a revocation, so trusting it could mask a
        // revoked certificate — e.g. an on-path attacker replaying an old CRL.
        // Skipping degrades to `Unknown`, mirroring the OCSP
        // verification-failure handling.
        if !is_crl_fresh(&crl, crl_url) {
            continue;
        }

        // Check if the certificate is in the CRL
        match crl.get_by_cert(cert) {
            CrlStatus::Revoked(revoked) => {
                // Certificate is revoked
                // Try to get the revocation reason if available
                let reason = match revoked.extension::<ReasonCode>() {
                    Ok(Some(_)) => "Revoked via CRL".to_string(),
                    _ => "Revoked via CRL (no reason specified)".to_string(),
                };

                return Ok(RevocationStatus::Revoked(reason));
            }
            CrlStatus::NotRevoked => {
                // Certificate is not in the CRL, so it's good according to this CRL
                return Ok(RevocationStatus::Good);
            }
            CrlStatus::RemoveFromCrl(_) => {
                // This is rare but could happen if a certificate was temporarily suspended
                // and then reinstated
                return Ok(RevocationStatus::Good);
            }
        }
    }

    // If we've tried all CRLs and none worked or none contained information about this certificate
    Ok(RevocationStatus::Unknown)
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

impl TLS {
    #[instrument]
    pub fn from(
        host: &str,
        port: Option<u16>,
        check_revocation: bool,
        calculate_grade: bool,
    ) -> Result<TLS, TLSError> {
        use openssl::nid::Nid;
        use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
        use std::net::{TcpStream, ToSocketAddrs};

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

        let mut context = SslContext::builder(SslMethod::tls())?;
        context.set_verify(SslVerifyMode::empty());
        let context_builder = context.build();

        let mut connector = Ssl::new(&context_builder)?;
        connector.set_hostname(host)?;

        // Use the provided port or default to 443
        let port = port.unwrap_or(443);
        // Resolve via the (host, port) tuple rather than "{host}:{port}" so IPv6
        // literals (e.g. "::1") work without bracket syntax.
        let socket_addr = (host, port)
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| TLSError::DNS("Failed parse remote hostname".to_string()))?;

        let tcp_stream = TcpStream::connect_timeout(&socket_addr, TIMEOUT)?;

        tcp_stream.set_read_timeout(Some(TIMEOUT))?;
        let stream = connector.connect(tcp_stream)?;

        // `Ssl` object associated with this stream
        let ssl = stream.ssl();

        let cipher = Cipher {
            name: ssl
                .current_cipher()
                .map(|c| c.name().to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
            version: ssl
                .current_cipher()
                .map(|c| c.version().to_string())
                .unwrap_or_else(|| "Unknown".to_string()),
            bits: ssl.current_cipher().map(|c| c.bits().secret).unwrap_or(0),
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
        let revocation_status = if check_revocation {
            // Extract all certificates in the chain to X509 objects
            let cert_chain: Vec<openssl::x509::X509> =
                peer_cert_chain.iter().map(|cert| cert.to_owned()).collect();

            match check_revocation_status(&x509_ref, &cert_chain) {
                Ok(status) => status,
                Err(_) => RevocationStatus::Unknown,
            }
        } else {
            RevocationStatus::NotChecked
        };

        let mut data = get_certificate_info(&x509_ref);
        data.revocation_status = revocation_status;

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
            is_self_signed: data.is_self_signed,
            security_warnings,
            cert_key_bits,
            cert_key_algorithm,
            cert_sha256: data.cert_sha256,
            cert_sha1: data.cert_sha1,
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
    /// CT inclusion is informational and does **not** cap the grade: many
    /// legitimately private/internal certificates are intentionally absent
    /// from public CT logs, so callers — not the grade — decide what that
    /// means for a given host.
    pub fn apply_ct(&mut self, ct: ct::CtStatus) {
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
        cert_sn: cert_ref
            .serial_number()
            .to_bn()
            .map(|bn| bn.to_string())
            .unwrap_or_else(|_| "Unknown".to_string()),
        cert_ver: cert_ref.version().to_string(),
        cert_alg: cert_ref.signature_algorithm().object().to_string(),
        sans,
        chain: None,
        revocation_status: RevocationStatus::NotChecked,
        is_self_signed: is_self_signed_certificate(cert_ref),
        security_warnings: Vec::new(),
        cert_key_bits: 0,
        cert_key_algorithm: String::new(),
        cert_sha256: fingerprint(cert_ref, openssl::hash::MessageDigest::sha256()),
        cert_sha1: fingerprint(cert_ref, openssl::hash::MessageDigest::sha1()),
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
        Ok(bytes) => bytes
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":"),
        Err(_) => String::new(),
    }
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
    subject.try_cmp(issuer).is_ok_and(|o| o.is_eq())
        && cert
            .public_key()
            .is_ok_and(|pkey| cert.verify(&pkey).is_ok())
}

#[cfg(test)]
mod tests {
    use crate::grading;
    use crate::probe::ProtoVersion;
    use crate::{
        CertificateInfo, Chain, Cipher, Issuer, RevocationStatus, SecurityWarning, Subject,
        TLSError, TLS,
    };

    /// Creates a synthetic TLS struct for offline testing.
    /// No network connection needed — all fields are populated with realistic data.
    fn make_test_tls() -> TLS {
        TLS {
            cipher: Cipher {
                name: "TLS_AES_256_GCM_SHA384".to_string(),
                version: "TLSv1.3".to_string(),
                bits: 256,
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
                is_self_signed: false,
                security_warnings: vec![],
                cert_key_bits: 2048,
                cert_key_algorithm: "RSA".to_string(),
                cert_sha256: "AB:CD".to_string(),
                cert_sha1: "12:34".to_string(),
                scts: Vec::new(),
                pem: String::new(),
            },
            grade: None,
            scan: None,
            ct: None,
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
            supports_obsolete_protocol: false,
            accepts_weak_cipher: false,
            is_revoked: false,
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
                        assert!(true);
                    }
                    RevocationStatus::Unknown => {
                        // This is acceptable if the OCSP responder is unavailable
                        println!("Warning: revoked.badssl.com showed as Unknown, not Revoked. OCSP responder may be unavailable.");
                        assert!(true);
                    }
                    status => {
                        // Any other status would be unexpected
                        assert!(
                            false,
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
                        assert!(true);
                    }
                    RevocationStatus::Revoked(_) => {
                        // This would be unexpected for google.com - log it
                        println!("Unexpected RevocationStatus::Revoked for google.com");
                        assert!(true);
                    }
                    RevocationStatus::NotChecked => {
                        // This should not happen since we requested checking
                        assert!(
                            false,
                            "Revocation status should not be NotChecked when enabled"
                        );
                    }
                }
            }
            Err(e) => {
                // Connection error - this is unexpected but could happen
                println!("Connection error to google.com: {}", e);
                assert!(true);
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
                        assert!(true);
                    }
                    RevocationStatus::NotChecked => {
                        // This should not happen since we requested checking
                        assert!(
                            false,
                            "Revocation status should not be NotChecked when enabled"
                        );
                    }
                }
            }
            Err(e) => {
                // Connection error - this is unexpected but could happen
                println!("Connection error to digicert.com: {}", e);
                assert!(true);
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
                        assert!(true);
                    }
                    RevocationStatus::Unknown => {
                        // This is acceptable if the revocation services are unavailable
                        println!("Warning: revoked.badssl.com showed as Unknown, not Revoked");
                        assert!(true);
                    }
                    status => {
                        // Any other status would be unexpected
                        assert!(
                            false,
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

    /// Builds a signed CRL whose `nextUpdate` is `next_update_offset_secs`
    /// from now (negative = already stale). The builder requires an AKID,
    /// a CRL number, and at least one revoked entry, so those are included.
    fn make_test_crl(next_update_offset_secs: i64) -> openssl::x509::X509Crl {
        use openssl::x509::extension::AuthorityKeyIdentifier;
        use openssl::x509::{CrlNumber, X509CrlBuilder, X509RevokedBuilder};

        let (issuer_cert, issuer_key) = make_test_x509("Test CA");
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
        builder.sign(&issuer_key, MessageDigest::sha256()).unwrap();
        builder.build().unwrap()
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
        assert!(super::is_chain_well_ordered(&[leaf.clone()]));
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
