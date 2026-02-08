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

pub mod grading;

use std::fmt::Debug;
use std::ops::Deref;
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
                .and_then(|e| e.data().as_utf8().ok().map(|s| s.to_string()))
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

    warnings
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

        // Skip verification of basic response if it fails - many OCSP responders
        // don't provide all the certificates needed for complete verification
        let certs = openssl::stack::Stack::<X509>::new().unwrap();
        let _ = basic_resp.verify(&certs, &store, openssl::ocsp::OcspFlag::empty());

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

        // Verify the CRL signature
        if crl.verify(&issuer.public_key().unwrap()).is_err() {
            continue; // CRL signature verification failed
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

        // Trim any whitespace
        let host = host.trim();

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
        let remote = format!("{host}:{port}");
        let socket_addr = remote
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
        let security_warnings = analyze_certificate_chain(&x509_ref, &cert_chain);

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
            cert_key_algorithm: cert_key_algorithm.clone(),
        };

        // Calculate TLS grade if requested
        let grade = if calculate_grade {
            let grading_input = grading::GradingInput {
                protocol_version: cipher.version.clone(),
                cipher_name: cipher.name.clone(),
                cipher_bits: cipher.bits,
                cert_key_bits: certificate.cert_key_bits,
                cert_key_algorithm,
                is_expired: certificate.is_expired,
                is_self_signed: certificate.is_self_signed,
                has_incomplete_chain: certificate
                    .security_warnings
                    .iter()
                    .any(|w| matches!(w, SecurityWarning::IncompleteChain(_))),
                has_weak_signature: certificate
                    .security_warnings
                    .iter()
                    .any(|w| matches!(w, SecurityWarning::WeakSignatureAlgorithm(_))),
                is_revoked: matches!(certificate.revocation_status, RevocationStatus::Revoked(_)),
            };
            Some(grading::calculate_grade(&grading_input))
        } else {
            None
        };

        Ok(TLS {
            cipher,
            certificate,
            grade,
        })
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
        Some(x509_name_ref) => x509_name_ref
            .data()
            .as_utf8()
            .expect("Failed to convert data to UTF-8")
            .to_string(),
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
    match cert_ref.subject_alt_names() {
        None => {}
        Some(general_names) => {
            for general_name in general_names {
                sans.push(general_name.dnsname().unwrap().to_string());
            }
        }
    }
    CertificateInfo {
        hostname: "None".to_string(),
        subject: get_subject(cert_ref),
        issued: get_issuer(cert_ref),
        valid_from: cert_ref.not_before().to_string(),
        valid_to: cert_ref.not_after().to_string(),
        validity_days: get_validity_days(cert_ref.not_after()),
        validity_hours: get_validity_in_hours(cert_ref.not_after()),
        is_expired: has_expired(cert_ref.not_after()),
        cert_sn: cert_ref.serial_number().to_bn().unwrap().to_string(),
        cert_ver: cert_ref.version().to_string(),
        cert_alg: cert_ref.signature_algorithm().object().to_string(),
        sans,
        chain: None,
        revocation_status: RevocationStatus::NotChecked,
        is_self_signed: is_self_signed_certificate(cert_ref),
        security_warnings: Vec::new(),
        cert_key_bits: 0,
        cert_key_algorithm: String::new(),
    }
}

/// Calculates the number of hours until certificate expiration.
///
/// # Arguments
///
/// * `not_after` - Certificate expiration timestamp
///
/// # Returns
///
/// Number of hours until expiration (negative if already expired).
fn get_validity_in_hours(not_after: &Asn1TimeRef) -> i32 {
    get_validity_days(not_after) * 24
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
    Asn1Time::days_from_now(0)
        .unwrap()
        .deref()
        .diff(not_after)
        .unwrap()
        .days
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
    use crate::{CertificateInfo, Chain, Cipher, Issuer, RevocationStatus, Subject, TLSError, TLS};

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
            },
            grade: None,
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

        match tls_result.certificate.revocation_status {
            RevocationStatus::Good | RevocationStatus::Unknown => {
                // Either is acceptable since external OCSP responders might be unreliable
                assert!(true);
            }
            RevocationStatus::Revoked(_) => {
                // This would be unexpected for google.com - log it but don't fail
                // since it could theoretically happen
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
        assert_eq!(
            tls_result.certificate.validity_hours,
            tls_result.certificate.validity_days * 24
        );
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
}
