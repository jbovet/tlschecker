//! Minimal, dependency-free DER reading shared across certificate parsers.
//!
//! The `openssl` crate exposes no generic X.509 extension accessor, so several
//! features ([`crate::sct`], [`crate::certext`]) walk the certificate DER by
//! hand. This module holds the two primitives they share: a single-TLV reader
//! and a structural extension locator. Both are **best-effort and never panic**
//! — malformed or truncated input yields `None`, never a failure for the caller.

/// Reads one DER TLV from the front of `buf`.
///
/// Returns `(tag, content, rest)` where `content` is the value bytes and `rest`
/// is whatever follows the element. Only definite-length encodings are
/// supported (which is all DER permits). Returns `None` on a truncated or
/// over-long length.
pub(crate) fn read_tlv(buf: &[u8]) -> Option<(u8, &[u8], &[u8])> {
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
/// mistaken for the extension. The returned slice is the *content* of the
/// `extnValue` OCTET STRING (the optional `critical` BOOLEAN is skipped), i.e.
/// the DER of the extension proper — ready to hand back to [`read_tlv`].
pub(crate) fn find_extension_value<'a>(der: &'a [u8], oid: &[u8]) -> Option<&'a [u8]> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_tlv_short_and_long_form() {
        // Short form: tag 0x04, len 3.
        let (tag, content, rest) = read_tlv(&[0x04, 0x03, 1, 2, 3, 9]).unwrap();
        assert_eq!(tag, 0x04);
        assert_eq!(content, &[1, 2, 3]);
        assert_eq!(rest, &[9]);

        // Long form: 0x81 0x02 => length 2.
        let (_, content, _) = read_tlv(&[0x30, 0x81, 0x02, 0xaa, 0xbb]).unwrap();
        assert_eq!(content, &[0xaa, 0xbb]);

        // Truncated content is rejected.
        assert!(read_tlv(&[0x04, 0x05, 1, 2]).is_none());
    }
}
