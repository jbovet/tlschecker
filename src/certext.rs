//! Offline extraction of X.509 extensions the `openssl` crate has no getter for.
//!
//! The crate exposes `pathlen()`, `subject_key_id()`, etc., but not Key Usage,
//! Extended Key Usage, or the Certificate Policies OIDs. Those are parsed here
//! by walking the certificate DER with the shared [`crate::der`] primitives,
//! the same structural approach as [`crate::sct`]. Everything is **best-effort
//! and never panics** — malformed or absent structures yield `None`/empty.

use openssl::x509::X509Ref;

use crate::der::{find_extension_value, read_tlv};

// Extension OIDs, as their DER value bytes (without the `06 len` TLV header).
/// Certificate Policies — `2.5.29.32`.
const CERT_POLICIES_OID: [u8; 3] = [0x55, 0x1d, 0x20];
/// Key Usage — `2.5.29.15`.
const KEY_USAGE_OID: [u8; 3] = [0x55, 0x1d, 0x0f];
/// Extended Key Usage — `2.5.29.37`.
const EXT_KEY_USAGE_OID: [u8; 3] = [0x55, 0x1d, 0x25];
/// Basic Constraints — `2.5.29.19`.
const BASIC_CONSTRAINTS_OID: [u8; 3] = [0x55, 0x1d, 0x13];
/// Authority Information Access — `1.3.6.1.5.5.7.1.1`.
const AIA_OID: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01];

/// `1.3.6.1.5.5.7.48.2` — id-ad-caIssuers, the AIA access method whose
/// location points at the issuer's certificate. (The sibling id-ad-ocsp is not
/// parsed here: `openssl` exposes `ocsp_responders()` for it, and reading the
/// OCSP URLs from the same accessor the revocation check uses keeps the
/// displayed responders and the queried ones from drifting apart.)
const AD_CA_ISSUERS: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02];

/// GeneralName `uniformResourceIdentifier [6] IMPLICIT IA5String`.
const GENERAL_NAME_URI: u8 = 0x86;

/// X.509 Key Usage bit names, MSB-first (bit 0 = `digitalSignature`).
const KEY_USAGE_NAMES: [&str; 9] = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
];

/// Well-known Extended Key Usage purpose OIDs → name. The `1.3.6.1.5.5.7.3.*`
/// entries differ only in the trailing byte; `anyExtendedKeyUsage` is the
/// distinct `2.5.29.37.0`.
const EKU_PURPOSES: [(&[u8], &str); 7] = [
    (&[0x55, 0x1d, 0x25, 0x00], "anyExtendedKeyUsage"),
    (
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01],
        "serverAuth",
    ),
    (
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02],
        "clientAuth",
    ),
    (
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03],
        "codeSigning",
    ),
    (
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x04],
        "emailProtection",
    ),
    (
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x08],
        "timeStamping",
    ),
    (
        &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x09],
        "OCSPSigning",
    ),
];

// CA/Browser-Forum reserved policy OIDs (DER value bytes of the arc
// `2.23.140.1.*`). These are issuer-independent, so matching them is a reliable
// way to read a publicly-trusted certificate's validation level.
/// `2.23.140.1.1` — Extended Validation.
const CABF_EV: [u8; 5] = [0x67, 0x81, 0x0c, 0x01, 0x01];
/// `2.23.140.1.2.1` — Domain Validated.
const CABF_DV: [u8; 6] = [0x67, 0x81, 0x0c, 0x01, 0x02, 0x01];
/// `2.23.140.1.2.2` — Organization Validated.
const CABF_OV: [u8; 6] = [0x67, 0x81, 0x0c, 0x01, 0x02, 0x02];
/// `2.23.140.1.2.3` — Individual Validated.
const CABF_IV: [u8; 6] = [0x67, 0x81, 0x0c, 0x01, 0x02, 0x03];

/// Returns the CA/Browser-Forum validation level ("EV"/"OV"/"DV"/"IV") declared
/// in the certificate's Certificate Policies extension, or `None` when no
/// recognized CABF policy OID is present (common for private/internal certs).
pub(crate) fn validation_level(cert: &X509Ref) -> Option<String> {
    let der = cert.to_der().ok()?;
    let policies = find_extension_value(&der, &CERT_POLICIES_OID)?;

    // certificatePolicies ::= SEQUENCE OF PolicyInformation
    let (tag, seq, _) = read_tlv(policies)?;
    if tag != 0x30 {
        return None;
    }

    // Scan each PolicyInformation ::= SEQUENCE { policyIdentifier OID, ... }.
    let mut rest = seq;
    while let Some((tag, info, next)) = read_tlv(rest) {
        rest = next;
        if tag == 0x30 {
            if let Some((oid_tag, oid, _)) = read_tlv(info) {
                if oid_tag == 0x06 {
                    let level = if oid == CABF_EV {
                        Some("EV")
                    } else if oid == CABF_OV {
                        Some("OV")
                    } else if oid == CABF_DV {
                        Some("DV")
                    } else if oid == CABF_IV {
                        Some("IV")
                    } else {
                        None
                    };
                    if let Some(level) = level {
                        return Some(level.to_string());
                    }
                }
            }
        }
        if rest.is_empty() {
            break;
        }
    }
    None
}

/// Returns the CA Issuers URLs from the certificate's Authority Information
/// Access extension — where the issuing CA publishes its own certificate.
///
/// Empty when the extension is absent, carries no caIssuers access description,
/// or the location is not a URI-form `GeneralName`. Duplicate URIs are
/// collapsed; the list is tiny, so the linear `contains` scan is cheaper than a
/// set.
pub(crate) fn ca_issuer_urls(cert: &X509Ref) -> Vec<String> {
    let mut urls = Vec::new();
    let Ok(der) = cert.to_der() else {
        return urls;
    };
    let Some(aia) = find_extension_value(&der, &AIA_OID) else {
        return urls;
    };

    // AuthorityInfoAccessSyntax ::= SEQUENCE OF AccessDescription
    let Some((tag, seq, _)) = read_tlv(aia) else {
        return urls;
    };
    if tag != 0x30 {
        return urls;
    }

    // AccessDescription ::= SEQUENCE { accessMethod OID, accessLocation GeneralName }
    let mut rest = seq;
    while let Some((tag, desc, next)) = read_tlv(rest) {
        rest = next;
        if tag == 0x30 {
            if let Some((oid_tag, oid, after_oid)) = read_tlv(desc) {
                if oid_tag == 0x06 && oid == AD_CA_ISSUERS {
                    if let Some((name_tag, location, _)) = read_tlv(after_oid) {
                        if name_tag == GENERAL_NAME_URI {
                            if let Ok(url) = std::str::from_utf8(location) {
                                let url = url.to_string();
                                if !urls.contains(&url) {
                                    urls.push(url);
                                }
                            }
                        }
                    }
                }
            }
        }
        if rest.is_empty() {
            break;
        }
    }
    urls
}

/// Basic-Constraints and Key-Usage / Extended-Key-Usage facts read from a
/// certificate's extensions. All best-effort — absent extensions yield the
/// empty/false defaults.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Usage {
    /// Key Usage flag names present (e.g. `digitalSignature`).
    pub key_usage: Vec<String>,
    /// Extended Key Usage purpose names / OIDs (e.g. `serverAuth`).
    pub ext_key_usage: Vec<String>,
    /// Whether Basic Constraints asserts `CA:TRUE`.
    pub is_ca: bool,
}

/// Reads Key Usage, Extended Key Usage, and the Basic-Constraints CA flag.
pub(crate) fn usage(cert: &X509Ref) -> Usage {
    let der = match cert.to_der() {
        Ok(d) => d,
        Err(_) => return Usage::default(),
    };
    let mut out = Usage::default();

    // Key Usage: extnValue is a BIT STRING (`03 <unused> <bytes...>`).
    if let Some(ku) = find_extension_value(&der, &KEY_USAGE_OID) {
        if let Some((0x03, bits, _)) = read_tlv(ku) {
            // bits[0] is the count of unused trailing bits; the flags follow,
            // MSB-first across the value bytes.
            let value = &bits[1..];
            for (i, name) in KEY_USAGE_NAMES.iter().enumerate() {
                let byte = i / 8;
                let mask = 0x80u8 >> (i % 8);
                if value.get(byte).is_some_and(|b| b & mask != 0) {
                    out.key_usage.push((*name).to_string());
                }
            }
        }
    }

    // Extended Key Usage: extnValue is a SEQUENCE OF OID.
    if let Some(eku) = find_extension_value(&der, &EXT_KEY_USAGE_OID) {
        if let Some((0x30, seq, _)) = read_tlv(eku) {
            let mut rest = seq;
            while let Some((tag, oid, next)) = read_tlv(rest) {
                rest = next;
                if tag == 0x06 {
                    let name = EKU_PURPOSES
                        .iter()
                        .find(|(bytes, _)| *bytes == oid)
                        .map(|(_, n)| (*n).to_string())
                        .unwrap_or_else(|| oid_to_string(oid));
                    out.ext_key_usage.push(name);
                }
                if rest.is_empty() {
                    break;
                }
            }
        }
    }

    // Basic Constraints: extnValue is SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }.
    if let Some(bc) = find_extension_value(&der, &BASIC_CONSTRAINTS_OID) {
        if let Some((0x30, seq, _)) = read_tlv(bc) {
            if let Some((0x01, val, _)) = read_tlv(seq) {
                out.is_ca = val == [0xff];
            }
        }
    }

    out
}

/// Renders DER OID value bytes as a dotted-decimal string (e.g. `1.3.6.1.5.5.7.3.10`).
/// Best-effort — a malformed encoding yields `"?"`.
fn oid_to_string(oid: &[u8]) -> String {
    if oid.is_empty() {
        return "?".to_string();
    }
    // First byte encodes the first two arcs: X*40 + Y (X capped at 2).
    let first = oid[0];
    let (x, y) = if first < 80 {
        (first / 40, first % 40)
    } else {
        (2, first - 80)
    };
    let mut arcs = vec![x.to_string(), y.to_string()];
    let mut value: u64 = 0;
    for &b in &oid[1..] {
        value = (value << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            arcs.push(value.to_string());
            value = 0;
        }
    }
    arcs.join(".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::asn1::{Asn1Object, Asn1OctetString, Asn1Time};
    use openssl::bn::{BigNum, MsbOption};
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use openssl::x509::{X509Builder, X509Extension, X509NameBuilder};

    /// Wraps `(accessMethod OID, URI)` pairs into a DER `AuthorityInfoAccess`
    /// value: `SEQUENCE OF AccessDescription { OID, [6] IA5String }`.
    /// Only short (<128 byte) elements are emitted, which every test URL is.
    fn aia_der(entries: &[(&[u8], &str)]) -> Vec<u8> {
        let mut descriptions = Vec::new();
        for (oid, uri) in entries {
            let oid_tlv = [&[0x06, oid.len() as u8], *oid].concat();
            let uri_tlv = [&[GENERAL_NAME_URI, uri.len() as u8], uri.as_bytes()].concat();
            let body = [oid_tlv, uri_tlv].concat();
            descriptions.extend([0x30, body.len() as u8]);
            descriptions.extend(body);
        }
        [&[0x30, descriptions.len() as u8], descriptions.as_slice()].concat()
    }

    /// Builds a self-signed cert carrying the given DER extension value under
    /// `oid_str`, or none when `der` is empty.
    fn cert_with_extension(oid_str: &str, der: &[u8]) -> openssl::x509::X509 {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "aia.example.com")
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
        b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        if !der.is_empty() {
            let obj = Asn1Object::from_str(oid_str).unwrap();
            let value = Asn1OctetString::new_from_bytes(der).unwrap();
            b.append_extension(X509Extension::new_from_der(&obj, false, &value).unwrap())
                .unwrap();
        }
        b.sign(&key, MessageDigest::sha256()).unwrap();
        b.build()
    }

    /// `1.3.6.1.5.5.7.48.1` — id-ad-ocsp, used to prove the caIssuers reader
    /// filters on access method rather than returning every AIA location.
    const AD_OCSP: [u8; 8] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01];

    #[test]
    fn test_ca_issuer_urls_reads_ca_issuers_only() {
        let der = aia_der(&[
            (&AD_OCSP, "http://o.pki.example/we1"),
            (&AD_CA_ISSUERS, "http://i.pki.example/we1.crt"),
        ]);
        let cert = cert_with_extension("1.3.6.1.5.5.7.1.1", &der);
        assert_eq!(
            ca_issuer_urls(&cert),
            vec!["http://i.pki.example/we1.crt".to_string()]
        );
    }

    #[test]
    fn test_ca_issuer_urls_multiple_entries() {
        let der = aia_der(&[
            (&AD_CA_ISSUERS, "http://a.example/ca.crt"),
            (&AD_CA_ISSUERS, "http://b.example/ca.crt"),
        ]);
        let cert = cert_with_extension("1.3.6.1.5.5.7.1.1", &der);
        assert_eq!(
            ca_issuer_urls(&cert),
            vec![
                "http://a.example/ca.crt".to_string(),
                "http://b.example/ca.crt".to_string()
            ]
        );
    }

    #[test]
    fn test_ca_issuer_urls_deduplicates_repeated_uris() {
        let der = aia_der(&[
            (&AD_CA_ISSUERS, "http://a.example/ca.crt"),
            (&AD_CA_ISSUERS, "http://a.example/ca.crt"),
        ]);
        let cert = cert_with_extension("1.3.6.1.5.5.7.1.1", &der);
        assert_eq!(
            ca_issuer_urls(&cert),
            vec!["http://a.example/ca.crt".to_string()]
        );
    }

    #[test]
    fn test_ca_issuer_urls_absent_or_ocsp_only() {
        // No AIA extension at all.
        assert!(ca_issuer_urls(&cert_with_extension("1.3.6.1.5.5.7.1.1", &[])).is_empty());
        // AIA present, but carrying only an OCSP responder.
        let der = aia_der(&[(&AD_OCSP, "http://o.pki.example/we1")]);
        assert!(ca_issuer_urls(&cert_with_extension("1.3.6.1.5.5.7.1.1", &der)).is_empty());
    }

    /// Wraps one policy OID (value bytes) into a DER `certificatePolicies`
    /// value: `SEQUENCE OF PolicyInformation { SEQUENCE { policyIdentifier } }`.
    fn policies_der(oid: &[u8]) -> Vec<u8> {
        let oid_tlv = [&[0x06, oid.len() as u8], oid].concat();
        let policy_info = [&[0x30, oid_tlv.len() as u8], oid_tlv.as_slice()].concat();
        [&[0x30, policy_info.len() as u8], policy_info.as_slice()].concat()
    }

    /// Builds a self-signed cert carrying a certificatePolicies extension for
    /// the given OID value bytes, or none when `oid` is empty.
    fn cert_with_policy(oid: &[u8]) -> openssl::x509::X509 {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "policy.example.com")
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
        b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        if !oid.is_empty() {
            let obj = Asn1Object::from_str("2.5.29.32").unwrap(); // certificatePolicies
            let value = Asn1OctetString::new_from_bytes(&policies_der(oid)).unwrap();
            let ext = X509Extension::new_from_der(&obj, false, &value).unwrap();
            b.append_extension(ext).unwrap();
        }
        b.sign(&key, MessageDigest::sha256()).unwrap();
        b.build()
    }

    #[test]
    fn test_validation_level_dv_ov_ev() {
        assert_eq!(
            validation_level(&cert_with_policy(&CABF_DV)).as_deref(),
            Some("DV")
        );
        assert_eq!(
            validation_level(&cert_with_policy(&CABF_OV)).as_deref(),
            Some("OV")
        );
        assert_eq!(
            validation_level(&cert_with_policy(&CABF_EV)).as_deref(),
            Some("EV")
        );
        assert_eq!(
            validation_level(&cert_with_policy(&CABF_IV)).as_deref(),
            Some("IV")
        );
    }

    #[test]
    fn test_validation_level_absent_or_unknown() {
        // No policies extension at all.
        assert_eq!(validation_level(&cert_with_policy(&[])), None);
        // A non-CABF policy OID (1.3.6.1.4.1.99999) is not classified.
        assert_eq!(
            validation_level(&cert_with_policy(&[
                0x2b, 0x06, 0x01, 0x04, 0x01, 0x86, 0x8d, 0x1f
            ])),
            None
        );
    }

    /// Builds a leaf carrying typed KeyUsage / ExtendedKeyUsage extensions.
    fn cert_with_usage() -> openssl::x509::X509 {
        use openssl::x509::extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage};
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "usage.example.com")
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
        b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        b.append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .key_encipherment()
                .build()
                .unwrap(),
        )
        .unwrap();
        b.append_extension(ExtendedKeyUsage::new().server_auth().build().unwrap())
            .unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        b.build()
    }

    #[test]
    fn test_usage_key_and_ext_key_usage() {
        let u = usage(&cert_with_usage());
        assert!(u.key_usage.contains(&"digitalSignature".to_string()));
        assert!(u.key_usage.contains(&"keyEncipherment".to_string()));
        assert!(u.ext_key_usage.contains(&"serverAuth".to_string()));
        assert!(!u.is_ca, "a leaf must not assert CA:TRUE");
    }

    #[test]
    fn test_usage_ca_flag() {
        use openssl::x509::extension::BasicConstraints;
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, "ca.example.com")
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
        b.set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        assert!(usage(&b.build()).is_ca);
    }

    #[test]
    fn test_oid_to_string() {
        // 1.3.6.1.5.5.7.3.10 (a serverAuth-adjacent EKU) round-trips.
        assert_eq!(
            oid_to_string(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x0a]),
            "1.3.6.1.5.5.7.3.10"
        );
    }
}
