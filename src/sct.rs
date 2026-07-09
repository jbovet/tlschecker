//! Offline parsing of embedded Signed Certificate Timestamps (SCTs).
//!
//! When a CA logs a certificate to [Certificate Transparency](https://certificate.transparency.dev/),
//! each log returns a [Signed Certificate Timestamp](https://datatracker.ietf.org/doc/html/rfc6962#section-3.2)
//! — a signed promise to include the certificate. These SCTs are commonly
//! **embedded in the leaf certificate itself**, in the X.509 extension with OID
//! `1.3.6.1.4.1.11129.2.4.2` (RFC 6962 §3.3). Their presence is offline proof
//! that the certificate was submitted to CT logs.
//!
//! This complements the network [`crate::ct`] lookup: `ct` confirms *inclusion*
//! against crt.sh, while embedded SCTs are *submission* evidence that needs no
//! network at all — so they remain available even when crt.sh is unreachable.
//!
//! The parsing is deliberately dependency-free: the `openssl` crate exposes no
//! generic extension accessor, so we walk the certificate DER
//! ([`X509Ref::to_der`]) to locate the extension and then decode the
//! TLS-serialized SCT list by hand. It is **best-effort and never fails the
//! caller** — any malformed or absent structure yields an empty list.

use openssl::x509::X509Ref;
use serde::{Deserialize, Serialize};

/// The value octets of OID `1.3.6.1.4.1.11129.2.4.2` (without the `06 0A` TLV
/// header), i.e. the `extnID` of the embedded-SCT-list extension.
const SCT_LIST_OID: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02];

/// A single embedded Signed Certificate Timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Sct {
    /// SCT version byte (`0` for RFC 6962 v1).
    pub version: u8,
    /// CT log identifier: SHA-256 of the log's public key, as lowercase hex.
    pub log_id: String,
    /// Timestamp in milliseconds since the Unix epoch (as carried in the SCT).
    pub timestamp_ms: u64,
    /// Human-readable UTC timestamp (ISO 8601, e.g. `2024-01-05T12:00:00Z`).
    pub timestamp: String,
}

/// Extracts the embedded SCTs from a certificate.
///
/// Returns the list of [`Sct`]s carried in the leaf's SCT-list extension, or an
/// empty vector if the extension is absent or cannot be parsed. This performs
/// **no network access** and never errors — it is purely an offline read of the
/// certificate's own bytes.
///
/// # Example
///
/// ```no_run
/// use tlschecker::sct::embedded_scts;
/// # fn example(cert: &openssl::x509::X509Ref) {
/// let scts = embedded_scts(cert);
/// if !scts.is_empty() {
///     println!("{} embedded SCT(s) — certificate was submitted to CT logs", scts.len());
/// }
/// # }
/// ```
pub fn embedded_scts(cert: &X509Ref) -> Vec<Sct> {
    let der = match cert.to_der() {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    match find_extension_value(&der, &SCT_LIST_OID) {
        Some(extn_value) => parse_scts_from_extension(extn_value),
        None => Vec::new(),
    }
}

/// Reads one DER TLV from the front of `buf`.
///
/// Returns `(tag, content, rest)` where `content` is the value bytes and `rest`
/// is whatever follows the element. Only definite-length encodings are
/// supported (which is all DER permits). Returns `None` on a truncated or
/// over-long length.
fn read_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    if buf.len() < 2 {
        return None;
    }
    let tag = buf[0];
    let first = buf[1];
    let (len, header) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        // Reject indefinite form (n == 0) and absurd lengths.
        if n == 0 || n > 4 || buf.len() < 2 + n {
            return None;
        }
        let mut l = 0usize;
        for &b in &buf[2..2 + n] {
            l = (l << 8) | b as usize;
        }
        (l, 2 + n)
    };
    let end = header.checked_add(len)?;
    if buf.len() < end {
        return None;
    }
    Some((tag, &buf[header..end], &buf[end..]))
}

/// Walks a certificate's DER to return the `extnValue` octets of the extension
/// whose `extnID` matches `oid` (the OID value bytes, without TLV header).
///
/// Performs a real structural descent (Certificate → tbsCertificate → the `[3]`
/// extensions wrapper → each Extension), rather than scanning for the OID
/// pattern, so an OID-shaped byte run elsewhere in the certificate cannot be
/// mistaken for the extension.
fn find_extension_value<'a>(der: &'a [u8], oid: &[u8]) -> Option<&'a [u8]> {
    // Certificate ::= SEQUENCE { tbsCertificate, ... }
    let (tag, cert_body, _) = read_tlv(der)?;
    if tag != 0x30 {
        return None;
    }
    // tbsCertificate is the first element, itself a SEQUENCE.
    let (tag, tbs, _) = read_tlv(cert_body)?;
    if tag != 0x30 {
        return None;
    }

    // extensions are wrapped in EXPLICIT context tag [3] (0xA3). Scan the tbs
    // children for it.
    let mut rest = tbs;
    let extensions_explicit = loop {
        let (tag, content, next) = read_tlv(rest)?;
        if tag == 0xA3 {
            break content;
        }
        rest = next;
        if rest.is_empty() {
            return None;
        }
    };

    // Inside [3] is the Extensions SEQUENCE.
    let (tag, extensions, _) = read_tlv(extensions_explicit)?;
    if tag != 0x30 {
        return None;
    }

    // Iterate Extension ::= SEQUENCE { extnID OID, critical BOOL OPTIONAL,
    // extnValue OCTET STRING }.
    let mut rest = extensions;
    while let Some((tag, ext, next)) = read_tlv(rest) {
        rest = next;
        if tag != 0x30 {
            if rest.is_empty() {
                break;
            }
            continue;
        }
        let (oid_tag, oid_val, after_oid) = match read_tlv(ext) {
            Some(t) => t,
            None => continue,
        };
        if oid_tag != 0x06 || oid_val != oid {
            if rest.is_empty() {
                break;
            }
            continue;
        }
        // Matched extnID. The extnValue OCTET STRING may be preceded by an
        // optional `critical` BOOLEAN.
        let (next_tag, next_val, after) = read_tlv(after_oid)?;
        if next_tag == 0x04 {
            return Some(next_val);
        }
        if next_tag == 0x01 {
            let (octet_tag, octet_val, _) = read_tlv(after)?;
            if octet_tag == 0x04 {
                return Some(octet_val);
            }
        }
        return None;
    }
    None
}

/// Parses the SCT list out of the extension's `extnValue`.
///
/// Per RFC 6962 §3.3 the `extnValue` octets are a DER `OCTET STRING` whose
/// content is the TLS-serialized `SignedCertificateTimestampList`.
fn parse_scts_from_extension(extn_value: &[u8]) -> Vec<Sct> {
    // Unwrap the inner DER OCTET STRING.
    let tls_list = match read_tlv(extn_value) {
        Some((0x04, content, _)) => content,
        _ => return Vec::new(),
    };
    parse_sct_list(tls_list)
}

/// Parses a TLS-serialized `SignedCertificateTimestampList`.
///
/// Layout: a 2-byte total length, then a sequence of `[2-byte length][SCT]`
/// entries. Truncated trailing data stops iteration rather than discarding the
/// SCTs already parsed.
fn parse_sct_list(buf: &[u8]) -> Vec<Sct> {
    let mut scts = Vec::new();
    if buf.len() < 2 {
        return scts;
    }
    let total = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    let mut body = &buf[2..];
    if body.len() > total {
        body = &body[..total];
    }
    while body.len() >= 2 {
        let sct_len = u16::from_be_bytes([body[0], body[1]]) as usize;
        let rest = &body[2..];
        if rest.len() < sct_len {
            break;
        }
        if let Some(sct) = parse_one_sct(&rest[..sct_len]) {
            scts.push(sct);
        }
        body = &rest[sct_len..];
    }
    scts
}

/// Parses one serialized SCT: `version(1) || log_id(32) || timestamp(8) || …`.
///
/// Only the fixed leading fields are needed; the trailing extensions and
/// signature are intentionally ignored.
fn parse_one_sct(b: &[u8]) -> Option<Sct> {
    const FIXED: usize = 1 + 32 + 8;
    if b.len() < FIXED {
        return None;
    }
    let version = b[0];
    let log_id = b[1..33].iter().map(|x| format!("{:02x}", x)).collect();
    let timestamp_ms = u64::from_be_bytes(b[33..41].try_into().ok()?);
    Some(Sct {
        version,
        log_id,
        timestamp_ms,
        timestamp: format_timestamp_ms(timestamp_ms),
    })
}

/// Formats milliseconds-since-epoch as an ISO 8601 UTC string, without pulling
/// in a date/time dependency.
fn format_timestamp_ms(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Converts days-since-1970-01-01 to a `(year, month, day)` civil date.
///
/// Howard Hinnant's `civil_from_days` algorithm (proleptic Gregorian calendar).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timestamp_ms() {
        assert_eq!(format_timestamp_ms(0), "1970-01-01T00:00:00Z");
        // 1234567890 s since epoch.
        assert_eq!(
            format_timestamp_ms(1_234_567_890_000),
            "2009-02-13T23:31:30Z"
        );
        // A leap-year date.
        assert_eq!(
            format_timestamp_ms(1_582_934_400_000),
            "2020-02-29T00:00:00Z"
        );
    }

    #[test]
    fn test_read_tlv_short_and_long_form() {
        // Short form: tag 0x04, len 3.
        let (tag, content, rest) = read_tlv(&[0x04, 0x03, 1, 2, 3, 9]).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(content, &[1, 2, 3]);
        assert_eq!(rest, &[9]);
        // Long form: len encoded in one following byte (0x81 0x02).
        let (_, content, _) = read_tlv(&[0x30, 0x81, 0x02, 0xaa, 0xbb]).unwrap();
        assert_eq!(content, &[0xaa, 0xbb]);
        // Truncated.
        assert!(read_tlv(&[0x04, 0x05, 1, 2]).is_none());
    }

    /// Builds a TLS `SignedCertificateTimestampList` with two SCTs and verifies
    /// parsing (count, version, log id, timestamp).
    #[test]
    fn test_parse_sct_list() {
        fn one_sct(log_byte: u8, ts_ms: u64) -> Vec<u8> {
            let mut s = vec![0x00]; // version v1
            s.extend(std::iter::repeat_n(log_byte, 32)); // log id
            s.extend_from_slice(&ts_ms.to_be_bytes()); // timestamp
            s.extend_from_slice(&[0x00, 0x00]); // empty extensions
            s.extend_from_slice(&[0x04, 0x03, 0x00, 0x01, 0xab]); // dummy signature
            s
        }
        let a = one_sct(0x11, 1_234_567_890_000);
        let b = one_sct(0x22, 1_582_934_400_000);

        let mut list = Vec::new();
        for sct in [&a, &b] {
            list.extend_from_slice(&(sct.len() as u16).to_be_bytes());
            list.extend_from_slice(sct);
        }
        let mut tls = (list.len() as u16).to_be_bytes().to_vec();
        tls.extend_from_slice(&list);

        let parsed = parse_sct_list(&tls);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].version, 0);
        assert_eq!(parsed[0].log_id, "11".repeat(32));
        assert_eq!(parsed[0].timestamp, "2009-02-13T23:31:30Z");
        assert_eq!(parsed[1].log_id, "22".repeat(32));
        assert_eq!(parsed[1].timestamp, "2020-02-29T00:00:00Z");
    }

    #[test]
    fn test_parse_scts_from_extension_unwraps_octet_string() {
        // extnValue is a DER OCTET STRING wrapping the TLS list.
        let mut s = vec![0x00];
        s.extend(std::iter::repeat_n(0x33, 32));
        s.extend_from_slice(&1_234_567_890_000u64.to_be_bytes());
        s.extend_from_slice(&[0x00, 0x00, 0x04, 0x03, 0x00, 0x01, 0xab]);

        let mut list = (s.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&s);
        let mut tls = (list.len() as u16).to_be_bytes().to_vec();
        tls.extend_from_slice(&list);

        // Wrap as DER OCTET STRING (short-form length is fine here).
        let mut extn_value = vec![0x04, tls.len() as u8];
        extn_value.extend_from_slice(&tls);

        let parsed = parse_scts_from_extension(&extn_value);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].log_id, "33".repeat(32));
    }

    #[test]
    fn test_malformed_inputs_yield_empty() {
        assert!(parse_sct_list(&[]).is_empty());
        assert!(parse_sct_list(&[0x00]).is_empty());
        assert!(parse_scts_from_extension(&[0x30, 0x00]).is_empty()); // not an OCTET STRING
        assert!(parse_one_sct(&[0x00, 0x01]).is_none()); // too short
    }

    /// Network test: a publicly-trusted leaf should carry embedded SCTs.
    #[test]
    #[ignore]
    fn test_embedded_scts_live() {
        let tls = crate::TLS::from("google.com", None, false, false).unwrap();
        assert!(
            !tls.certificate.scts.is_empty(),
            "google.com leaf should carry embedded SCTs"
        );
        for sct in &tls.certificate.scts {
            assert_eq!(sct.log_id.len(), 64); // 32 bytes hex
        }
    }
}
