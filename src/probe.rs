//! TLS protocol version and cipher suite enumeration.
//!
//! Where [`crate::TLS::from`] reports only the *negotiated* protocol and cipher
//! from a single handshake, this module actively probes a server to discover
//! **every** protocol version and cipher suite it will accept. It does this by
//! attempting a series of handshakes, each restricted to a single protocol
//! version and (for cipher enumeration) a single cipher.
//!
//! This is opt-in (`--scan`) because it opens many short-lived connections and
//! is therefore slower than a normal certificate check.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tracing::instrument;

use crate::TLSError;

/// A TLS/SSL protocol version probed by the scanner.
///
/// Carrying a typed value (rather than a display string) lets the analysis in
/// `lib.rs` match on variants instead of re-parsing strings, so [`label`]
/// remains the single source of truth for the version's textual form — used for
/// both display and (de)serialization.
///
/// [`label`]: ProtoVersion::label
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoVersion {
    Ssl3,
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

impl ProtoVersion {
    /// All probed versions, oldest first.
    const ALL: [ProtoVersion; 5] = [
        ProtoVersion::Ssl3,
        ProtoVersion::Tls1_0,
        ProtoVersion::Tls1_1,
        ProtoVersion::Tls1_2,
        ProtoVersion::Tls1_3,
    ];

    /// The canonical display/serialized label (e.g. `"TLSv1.2"`).
    pub fn label(self) -> &'static str {
        match self {
            ProtoVersion::Ssl3 => "SSLv3",
            ProtoVersion::Tls1_0 => "TLSv1.0",
            ProtoVersion::Tls1_1 => "TLSv1.1",
            ProtoVersion::Tls1_2 => "TLSv1.2",
            ProtoVersion::Tls1_3 => "TLSv1.3",
        }
    }
}

impl std::fmt::Display for ProtoVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

// Serialize/Deserialize via the label so the JSON form stays "TLSv1.2" etc. and
// `label()` remains the only place version strings are defined.
impl Serialize for ProtoVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.label())
    }
}

impl<'de> Deserialize<'de> for ProtoVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        ProtoVersion::ALL
            .iter()
            .copied()
            .find(|v| v.label() == s.as_str())
            .ok_or_else(|| serde::de::Error::custom(format!("unknown TLS version label: {s}")))
    }
}

/// Per-handshake timeout while probing. Kept short since a scan performs many
/// connection attempts.
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// Candidate cipher suites for TLS 1.2 and below, including a few deliberately
/// weak suites (3DES, RC4) so the scan surfaces them when a server still
/// accepts them. Unknown names are silently skipped by OpenSSL.
const LEGACY_CIPHERS: &[&str] = &[
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-SHA",
    "ECDHE-RSA-AES128-SHA",
    "ECDHE-ECDSA-AES256-SHA",
    "ECDHE-RSA-AES256-SHA",
    "AES128-GCM-SHA256",
    "AES256-GCM-SHA384",
    "AES128-SHA256",
    "AES256-SHA256",
    "AES128-SHA",
    "AES256-SHA",
    "DES-CBC3-SHA", // weak: 3DES
    "RC4-SHA",      // weak: RC4
    "RC4-MD5",      // weak: RC4
];

/// TLS 1.3 cipher suites (configured separately from legacy ciphers in OpenSSL).
const TLS13_CIPHERS: &[&str] = &[
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
];

/// Protocol versions probed, from oldest/weakest to newest. Pairs the OpenSSL
/// version constant used for the handshake with our typed [`ProtoVersion`].
const VERSIONS: &[(SslVersion, ProtoVersion)] = &[
    (SslVersion::SSL3, ProtoVersion::Ssl3),
    (SslVersion::TLS1, ProtoVersion::Tls1_0),
    (SslVersion::TLS1_1, ProtoVersion::Tls1_1),
    (SslVersion::TLS1_2, ProtoVersion::Tls1_2),
    (SslVersion::TLS1_3, ProtoVersion::Tls1_3),
];

/// Result of probing which protocol versions and ciphers a server supports.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TlsScan {
    /// One entry per probed protocol version (oldest first).
    pub protocols: Vec<ProtocolSupport>,
}

/// Support information for a single TLS protocol version.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ProtocolSupport {
    /// The probed protocol version (serializes/displays as e.g. "TLSv1.2").
    pub version: ProtoVersion,
    /// Whether the server accepted a handshake at this version.
    pub supported: bool,
    /// Cipher suites the server accepted at this version (negotiated names).
    pub ciphers: Vec<String>,
}

/// Attempts a single handshake restricted to one protocol version (and
/// optionally one cipher / TLS 1.3 ciphersuite).
///
/// Returns the negotiated cipher name on success, or `None` if the version /
/// cipher could not be set or the handshake failed for any reason.
fn try_handshake(
    host: &str,
    port: u16,
    version: SslVersion,
    cipher_list: Option<&str>,
    ciphersuites: Option<&str>,
) -> Option<String> {
    let mut ctx = SslContext::builder(SslMethod::tls()).ok()?;
    ctx.set_verify(SslVerifyMode::empty());
    // Pin to exactly one protocol version. If the linked OpenSSL refuses the
    // version (e.g. SSLv3 disabled at build time), this returns Err -> None,
    // which we treat as "not supported".
    ctx.set_min_proto_version(Some(version)).ok()?;
    ctx.set_max_proto_version(Some(version)).ok()?;
    if let Some(list) = cipher_list {
        ctx.set_cipher_list(list).ok()?;
    }
    if let Some(suites) = ciphersuites {
        ctx.set_ciphersuites(suites).ok()?;
    }
    let ctx = ctx.build();

    let mut ssl = Ssl::new(&ctx).ok()?;
    ssl.set_hostname(host).ok()?;

    // Use the (host, port) tuple rather than "{host}:{port}" so IPv6 literals
    // (e.g. "::1") resolve correctly without needing bracket syntax.
    let addr = (host, port).to_socket_addrs().ok()?.next()?;
    let tcp = TcpStream::connect_timeout(&addr, PROBE_TIMEOUT).ok()?;
    tcp.set_read_timeout(Some(PROBE_TIMEOUT)).ok()?;
    tcp.set_write_timeout(Some(PROBE_TIMEOUT)).ok()?;

    let stream = ssl.connect(tcp).ok()?;
    stream.ssl().current_cipher().map(|c| c.name().to_string())
}

/// Probes a server for supported TLS protocol versions and cipher suites.
///
/// For each protocol version a handshake is attempted; if it succeeds, the
/// individual candidate ciphers are then probed to enumerate what the server
/// accepts at that version.
///
/// # Arguments
///
/// * `host` - Hostname to probe
/// * `port` - Port to probe (defaults to 443 when `None`)
///
/// # Returns
///
/// A [`TlsScan`] describing per-version support, or [`TLSError::Validation`]
/// if the hostname is empty.
#[instrument]
pub fn scan_tls(host: &str, port: Option<u16>) -> Result<TlsScan, TLSError> {
    // Strip IPv6 brackets so "[::1]" resolves like the bare "::1".
    let host = crate::unbracket_host(host.trim());
    if host.is_empty() {
        return Err(TLSError::Validation("Hostname cannot be empty".to_string()));
    }
    let port = port.unwrap_or(443);

    let mut protocols = Vec::with_capacity(VERSIONS.len());
    for &(ssl_version, version) in VERSIONS {
        // Is this version accepted at all (with a default cipher selection)?
        let supported = try_handshake(host, port, ssl_version, None, None).is_some();

        let mut ciphers = Vec::new();
        if supported {
            if ssl_version == SslVersion::TLS1_3 {
                for suite in TLS13_CIPHERS {
                    if let Some(name) = try_handshake(host, port, ssl_version, None, Some(suite)) {
                        if !ciphers.contains(&name) {
                            ciphers.push(name);
                        }
                    }
                }
            } else {
                for cipher in LEGACY_CIPHERS {
                    if let Some(name) = try_handshake(host, port, ssl_version, Some(cipher), None) {
                        if !ciphers.contains(&name) {
                            ciphers.push(name);
                        }
                    }
                }
            }
        }

        protocols.push(ProtocolSupport {
            version,
            supported,
            ciphers,
        });
    }

    Ok(TlsScan { protocols })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_empty_hostname_errors() {
        let result = scan_tls("", None);
        assert!(matches!(result, Err(TLSError::Validation(_))));
    }

    #[test]
    #[ignore] // requires network: connects to google.com
    fn test_scan_google_supports_modern_tls() {
        let scan = scan_tls("google.com", None).unwrap();
        // Modern servers must support TLS 1.2 and 1.3 ...
        let tls12 = scan
            .protocols
            .iter()
            .find(|p| p.version == ProtoVersion::Tls1_2)
            .unwrap();
        let tls13 = scan
            .protocols
            .iter()
            .find(|p| p.version == ProtoVersion::Tls1_3)
            .unwrap();
        assert!(tls12.supported, "expected TLS 1.2 support");
        assert!(tls13.supported, "expected TLS 1.3 support");
        assert!(
            !tls12.ciphers.is_empty(),
            "expected enumerated TLS 1.2 ciphers"
        );
        assert!(
            !tls13.ciphers.is_empty(),
            "expected enumerated TLS 1.3 ciphers"
        );
        // ... and must NOT support SSLv3.
        let sslv3 = scan
            .protocols
            .iter()
            .find(|p| p.version == ProtoVersion::Ssl3)
            .unwrap();
        assert!(!sslv3.supported, "SSLv3 should not be supported");
    }
}
