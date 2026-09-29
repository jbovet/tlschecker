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
//!
//! Probes run at OpenSSL security level 0. The default level (2 in OpenSSL
//! 3.2+) refuses TLS 1.0/1.1 outright, so without this a scan could never
//! detect the legacy versions it exists to find — and the result would depend
//! on whatever `openssl.cnf` the host happens to have. A version the linked
//! OpenSSL cannot offer at all (SSLv3, compiled out of the vendored build) is
//! reported as untested rather than unsupported.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use openssl::ssl::{HandshakeError, Ssl, SslContext, SslMethod, SslVerifyMode, SslVersion};
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

/// Upper bound on the per-handshake timeout while probing. Kept short since a
/// scan performs many connection attempts: honouring a long connect timeout for
/// each of them would make a scan of an unresponsive host take minutes.
///
/// A caller-supplied timeout narrows this (see [`scan_tls_with_timeout`]) but
/// never raises it.
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
    /// Whether this version could be probed at all. `false` means the linked
    /// OpenSSL cannot offer it (SSLv3 is compiled out of the vendored build),
    /// so `supported: false` says nothing about the server.
    #[serde(default = "tested_by_default")]
    pub tested: bool,
    /// Whether the server accepted a handshake at this version.
    pub supported: bool,
    /// Cipher suites the server accepted at this version (negotiated names).
    pub ciphers: Vec<String>,
}

/// JSON written before `tested` existed only ever held probed versions.
fn tested_by_default() -> bool {
    true
}

/// Builds a client context pinned to exactly one protocol version (and
/// optionally one cipher / TLS 1.3 ciphersuite), at security level 0 so legacy
/// versions and suites can actually be offered (see the module docs).
///
/// Returns `None` if the linked OpenSSL rejects the version or cipher.
fn probe_context(
    version: SslVersion,
    cipher_list: Option<&str>,
    ciphersuites: Option<&str>,
) -> Option<SslContext> {
    let mut ctx = SslContext::builder(SslMethod::tls()).ok()?;
    ctx.set_verify(SslVerifyMode::empty());
    ctx.set_security_level(0);
    ctx.set_min_proto_version(Some(version)).ok()?;
    ctx.set_max_proto_version(Some(version)).ok()?;
    if let Some(list) = cipher_list {
        ctx.set_cipher_list(list).ok()?;
    }
    if let Some(suites) = ciphersuites {
        ctx.set_ciphersuites(suites).ok()?;
    }
    Some(ctx.build())
}

/// A stream that accepts every write and has nothing to read, so a client
/// handshake over it stops right after sending its ClientHello.
struct OfflineStream;

impl Read for OfflineStream {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::WouldBlock.into())
    }
}

impl Write for OfflineStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Whether the linked OpenSSL can offer `version` at all, checked offline.
///
/// Setting the version on a context succeeds even when it is compiled out
/// (as SSLv3 is in the vendored build); the failure only shows once a
/// ClientHello is built ("no protocols available"). Starting a handshake over
/// [`OfflineStream`] exposes that without touching the network: a ClientHello
/// that was sent leaves the handshake waiting to read (`WouldBlock`).
fn can_offer(version: SslVersion) -> bool {
    probe_context(version, None, None)
        .and_then(|ctx| Ssl::new(&ctx).ok())
        .is_some_and(|ssl| {
            matches!(
                ssl.connect(OfflineStream),
                Err(HandshakeError::WouldBlock(_))
            )
        })
}

/// Attempts a single handshake restricted to one protocol version (and
/// optionally one cipher / TLS 1.3 ciphersuite).
///
/// Returns the negotiated cipher name on success, or `None` if the version /
/// cipher could not be set or the handshake failed for any reason.
fn try_handshake(
    host: &str,
    addr: std::net::SocketAddr,
    version: SslVersion,
    cipher_list: Option<&str>,
    ciphersuites: Option<&str>,
    timeout: Duration,
) -> Option<String> {
    let ctx = probe_context(version, cipher_list, ciphersuites)?;
    let mut ssl = Ssl::new(&ctx).ok()?;
    ssl.set_hostname(host).ok()?;

    let tcp = TcpStream::connect_timeout(&addr, timeout).ok()?;
    tcp.set_read_timeout(Some(timeout)).ok()?;
    tcp.set_write_timeout(Some(timeout)).ok()?;

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
/// A [`TlsScan`] describing per-version support, [`TLSError::Validation`] if
/// the hostname is empty, or a connection/DNS error when the host does not
/// resolve.
pub fn scan_tls(host: &str, port: Option<u16>) -> Result<TlsScan, TLSError> {
    scan_tls_with_timeout(host, port, PROBE_TIMEOUT)
}

/// [`scan_tls`] with a caller-supplied per-handshake timeout.
///
/// The timeout is capped at [`PROBE_TIMEOUT`]: a scan issues on the order of a
/// hundred handshakes, so a long connect budget that is reasonable for a single
/// check would make a scan of a black-holed host take minutes. Lowering the
/// timeout below the cap does take effect, which is how `--timeout` speeds up
/// scans of hosts known to be fast.
#[instrument]
pub fn scan_tls_with_timeout(
    host: &str,
    port: Option<u16>,
    timeout: Duration,
) -> Result<TlsScan, TLSError> {
    // Strip IPv6 brackets so "[::1]" resolves like the bare "::1", and
    // convert IDN hostnames to their ASCII form for resolution.
    let host = crate::to_ascii_hostname(crate::unbracket_host(host.trim()));
    let host = host.as_str();
    if host.is_empty() {
        return Err(TLSError::Validation("Hostname cannot be empty".to_string()));
    }
    let port = port.unwrap_or(443);
    let timeout = timeout.min(PROBE_TIMEOUT);

    // Resolve and pick a reachable address once up front, then pin it: a scan
    // performs on the order of a hundred handshake attempts, and re-resolving
    // per attempt would both hammer the resolver and risk probing different IPs
    // of a multi-address host, making per-version results incoherent. Picking
    // the address by actually connecting (rather than taking the first DNS
    // answer) means a host whose first address is unreachable still gets
    // scanned on the address that works.
    let addrs = crate::resolve_addrs(host, port)?;
    let addr = crate::connect_first_available(&addrs, timeout)?.peer_addr()?;

    let mut protocols = Vec::with_capacity(VERSIONS.len());
    for &(ssl_version, version) in VERSIONS {
        // A version this build cannot offer is untested, not unsupported, and
        // costs no connection.
        let tested = can_offer(ssl_version);
        // Is this version accepted at all (with a default cipher selection)?
        let supported =
            tested && try_handshake(host, addr, ssl_version, None, None, timeout).is_some();

        let mut ciphers = Vec::new();
        if supported {
            if ssl_version == SslVersion::TLS1_3 {
                for suite in TLS13_CIPHERS {
                    if let Some(name) =
                        try_handshake(host, addr, ssl_version, None, Some(suite), timeout)
                    {
                        if !ciphers.contains(&name) {
                            ciphers.push(name);
                        }
                    }
                }
            } else {
                for cipher in LEGACY_CIPHERS {
                    if let Some(name) =
                        try_handshake(host, addr, ssl_version, Some(cipher), None, timeout)
                    {
                        if !ciphers.contains(&name) {
                            ciphers.push(name);
                        }
                    }
                }
            }
        }

        protocols.push(ProtocolSupport {
            version,
            tested,
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
    fn test_can_offer_legacy_tls_versions() {
        // Security level 0 is what makes TLS 1.0/1.1 offerable at all; at the
        // default level OpenSSL refuses to build a ClientHello for them.
        for version in [
            SslVersion::TLS1,
            SslVersion::TLS1_1,
            SslVersion::TLS1_2,
            SslVersion::TLS1_3,
        ] {
            assert!(can_offer(version), "{version:?} should be offerable");
        }
    }

    #[test]
    fn test_can_offer_rejects_compiled_out_sslv3() {
        // The vendored OpenSSL is built with `no-ssl3` (openssl-src's `ssl3`
        // feature is off), so SSLv3 must be reported untested rather than
        // probed and reported unsupported.
        assert!(!can_offer(SslVersion::SSL3));
    }

    #[test]
    fn test_protocol_support_without_tested_deserializes_as_tested() {
        let json = r#"{"version":"TLSv1.2","supported":true,"ciphers":[]}"#;
        let p: ProtocolSupport = serde_json::from_str(json).unwrap();
        assert!(p.tested);
    }

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
