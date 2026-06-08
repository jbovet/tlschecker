//! Certificate Transparency (CT) log lookup via [crt.sh](https://crt.sh).
//!
//! Modern browsers require publicly-trusted certificates to be logged in
//! [Certificate Transparency](https://certificate.transparency.dev/) logs.
//! Looking a certificate up in CT serves two purposes:
//!
//! - **Inclusion check** — confirm the presented leaf is actually logged
//!   (a publicly-trusted cert that is *not* logged will be rejected by Chrome,
//!   Safari, and others).
//! - **Mis-issuance visibility** — the same logs are what defenders monitor to
//!   spot unexpected certificates issued for a domain. The returned crt.sh URL
//!   is the pivot point for that investigation.
//!
//! ## How the lookup works
//!
//! We query crt.sh by the leaf's **SHA-256 fingerprint** (`crt.sh/?q=<sha256>`),
//! which is an exact, per-certificate lookup. This answers "is *this* exact
//! certificate logged?" — unlike a domain query, it cannot produce false
//! negatives from crt.sh's result-set limits on high-volume domains. crt.sh
//! does not emit JSON for fingerprint queries, so the HTML response is matched
//! for the two stable, mutually-exclusive outcomes it returns: a `crt.sh ID`
//! link (found) or `Certificate not found` (absent).
//!
//! ## Three-state result
//!
//! [`CtStatus`] is deliberately tri-state — [`Logged`](CtStatus::Logged),
//! [`NotLogged`](CtStatus::NotLogged), and
//! [`Unknown`](CtStatus::Unknown) — mirroring
//! [`RevocationStatus`](crate::RevocationStatus). A network failure or an
//! unrecognized crt.sh response must surface as `Unknown` ("could not check")
//! and never be collapsed into `NotLogged`, so an outage can't masquerade as a
//! mis-issuance signal. [`check_ct_status`] returns the two *definitive*
//! outcomes as `Ok` and "could not check" as `Err` (so the reason can be logged
//! as a diagnostic); callers map that `Err` to [`CtStatus::Unknown`].
//!
//! The lookup is opt-in (`--ct-check`): it performs a network request to crt.sh
//! and is therefore both slow and dependent on an external service.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::TLSError;

/// Timeout for the crt.sh HTTP request. crt.sh can be slow under load, so this
/// is more generous than the OCSP/CRL timeouts.
const CRT_SH_TIMEOUT: Duration = Duration::from_secs(25);

/// Result of a Certificate Transparency lookup for a single certificate.
///
/// Tri-state, like [`RevocationStatus`](crate::RevocationStatus): a "could not
/// check" outcome ([`Unknown`](CtStatus::Unknown)) is kept distinct from a
/// definitive "not logged" ([`NotLogged`](CtStatus::NotLogged)) so a crt.sh
/// outage is never mistaken for a missing-from-CT certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CtStatus {
    /// The certificate was found in crt.sh's view of the public CT logs.
    Logged {
        /// crt.sh's internal identifier for the certificate (stable handle for
        /// its detail page).
        crtsh_id: u64,
        /// Direct link to the certificate on crt.sh — the starting point for
        /// inspecting which logs carry it and investigating mis-issuance.
        crtsh_url: String,
    },
    /// The certificate was definitively not found in public CT logs.
    NotLogged,
    /// The CT status could not be determined (crt.sh unreachable, rate-limited,
    /// or an unrecognized response).
    Unknown,
}

impl CtStatus {
    /// Whether the certificate was confirmed present in CT logs.
    pub fn is_logged(&self) -> bool {
        matches!(self, CtStatus::Logged { .. })
    }
}

/// Looks the presented leaf up in public CT logs by its SHA-256 fingerprint.
///
/// `cert_sha256` is the colon-separated hex fingerprint as produced by
/// [`CertificateInfo::cert_sha256`](crate::CertificateInfo::cert_sha256); the
/// colons are stripped before querying.
///
/// Returns a *definitive* [`CtStatus::Logged`] or [`CtStatus::NotLogged`] on
/// success. Network/HTTP failures, or an unrecognized response, return a
/// [`TLSError`] (the "could not check" case) so the caller can log the reason
/// and record [`CtStatus::Unknown`] — a "could not check" outcome must never be
/// reported as `NotLogged`.
///
/// # Example
///
/// ```no_run
/// use tlschecker::ct::{check_ct_status, CtStatus};
///
/// match check_ct_status("AB:CD:...:EF") {
///     Ok(CtStatus::NotLogged) => println!("not present in any public CT log"),
///     Ok(status) => println!("logged: {}", status.is_logged()),
///     Err(_) => println!("could not determine CT status"),
/// }
/// ```
pub fn check_ct_status(cert_sha256: &str) -> Result<CtStatus, TLSError> {
    let fingerprint = cert_sha256.replace(':', "");
    if fingerprint.is_empty() {
        return Err(TLSError::Certificate(
            "Empty certificate fingerprint for CT lookup".to_string(),
        ));
    }

    let url = format!("https://crt.sh/?q={fingerprint}");

    let client = reqwest::blocking::Client::builder()
        .timeout(CRT_SH_TIMEOUT)
        .build()
        .map_err(|e| TLSError::Unknown(format!("Failed to build CT HTTP client: {e}")))?;

    let response = client
        .get(&url)
        .send()
        .map_err(|e| TLSError::Unknown(format!("CT lookup request failed: {e}")))?;

    if !response.status().is_success() {
        return Err(TLSError::Unknown(format!(
            "CT lookup returned HTTP {}",
            response.status()
        )));
    }

    let body = response
        .text()
        .map_err(|e| TLSError::Unknown(format!("Failed to read CT response: {e}")))?;

    parse_ct_html(&body)
}

/// Parses a crt.sh certificate-page HTML response into a definitive [`CtStatus`].
///
/// Kept separate from the HTTP fetch so the matching logic can be tested
/// offline. crt.sh returns exactly one of two stable signals for a fingerprint
/// query: the literal text `Certificate not found` (absent), or a `?id=<n>`
/// detail link (found). Anything else returns an `Err` (the "could not check"
/// case) rather than silently assuming absence — `Ok` is only ever the
/// definitive [`Logged`](CtStatus::Logged) or [`NotLogged`](CtStatus::NotLogged).
pub(crate) fn parse_ct_html(body: &str) -> Result<CtStatus, TLSError> {
    if body.contains("Certificate not found") {
        return Ok(CtStatus::NotLogged);
    }

    if let Some(id) = extract_crtsh_id(body) {
        return Ok(CtStatus::Logged {
            crtsh_id: id,
            crtsh_url: format!("https://crt.sh/?id={id}"),
        });
    }

    Err(TLSError::Unknown(
        "Unrecognized CT lookup response from crt.sh".to_string(),
    ))
}

/// Extracts the first crt.sh certificate id from a `?id=<digits>` link.
fn extract_crtsh_id(body: &str) -> Option<u64> {
    let marker = "?id=";
    let start = body.find(marker)? + marker.len();
    let digits: String = body[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_not_found() {
        let body = "<HTML><BODY>Certificate not found</BODY></HTML>";
        assert_eq!(parse_ct_html(body).unwrap(), CtStatus::NotLogged);
    }

    #[test]
    fn test_parse_found_extracts_id() {
        let body = r#"<TH>crt.sh ID</TH><TD><A href="?id=16725692066">16725692066</A></TD>"#;
        let status = parse_ct_html(body).unwrap();
        assert!(status.is_logged());
        assert_eq!(
            status,
            CtStatus::Logged {
                crtsh_id: 16725692066,
                crtsh_url: "https://crt.sh/?id=16725692066".to_string(),
            }
        );
    }

    #[test]
    fn test_parse_unrecognized_is_error() {
        // Neither signal present -> "could not check" (Err), never NotLogged.
        // The caller maps this Err to CtStatus::Unknown.
        assert!(parse_ct_html("<html>unexpected</html>").is_err());
    }

    #[test]
    fn test_extract_id_none_when_absent() {
        assert!(extract_crtsh_id("no link here").is_none());
    }

    /// Network test: confirms a well-known, publicly-trusted host's leaf is
    /// present in CT logs. Tolerant of crt.sh flakiness / rate limiting.
    #[test]
    #[ignore]
    fn test_check_ct_status_live() {
        let tls = crate::TLS::from("google.com", None, false, false).unwrap();
        // crt.sh may be unreachable / 5xx / rate-limited; only assert when the
        // lookup actually succeeds so the test isn't flaky on CI.
        if let Ok(status) = check_ct_status(&tls.certificate.cert_sha256) {
            assert!(status.is_logged(), "google.com leaf should be in CT logs");
        }
    }
}
