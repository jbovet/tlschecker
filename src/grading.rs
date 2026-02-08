//! TLS Configuration Grading Module
//!
//! Evaluates TLS connection quality across multiple dimensions and produces
//! a composite letter grade (A+ through F). Scoring is deterministic and
//! based on protocol version, cipher strength, key exchange, certificate
//! key size, and certificate trust chain status.

use serde::{Deserialize, Serialize};

/// Individual category score on a 0-100 scale.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct CategoryScore {
    /// Human-readable name of the category
    pub category: String,
    /// Score from 0 (worst) to 100 (best)
    pub score: u8,
    /// Short explanation of why this score was assigned
    pub reason: String,
}

/// Complete TLS configuration grade for a single host.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct TLSGrade {
    /// Final letter grade: A+, A, B, C, D, or F
    pub grade: String,
    /// Composite numeric score (0-100)
    pub score: u8,
    /// Individual category breakdowns
    pub categories: Vec<CategoryScore>,
}

/// Raw data needed for grading, collected during TLS connection.
/// This struct is transient and not serialized.
pub struct GradingInput {
    pub protocol_version: String,
    pub cipher_name: String,
    pub cipher_bits: i32,
    pub cert_key_bits: u32,
    pub cert_key_algorithm: String,
    pub is_expired: bool,
    pub is_self_signed: bool,
    pub has_incomplete_chain: bool,
    pub has_weak_signature: bool,
    pub is_revoked: bool,
}

/// Score the TLS protocol version.
///
/// TLS 1.3 is the strongest, SSLv3 and below are critically insecure.
fn score_protocol(version: &str) -> (u8, String) {
    if version.contains("TLSv1.3") {
        (100, "TLS 1.3 - Excellent".into())
    } else if version.contains("TLSv1.2") {
        (80, "TLS 1.2 - Good".into())
    } else if version.contains("TLSv1.1") {
        (40, "TLS 1.1 - Deprecated".into())
    } else if version.contains("TLSv1") {
        (20, "TLS 1.0 - Insecure".into())
    } else if version.contains("SSLv3") {
        (0, "SSL 3.0 - Critical vulnerability".into())
    } else {
        (0, format!("Unknown protocol: {}", version))
    }
}

/// Score the cipher suite bit strength.
fn score_cipher_bits(bits: i32) -> (u8, String) {
    match bits {
        b if b >= 256 => (100, format!("{}-bit - Excellent", b)),
        b if b >= 128 => (80, format!("{}-bit - Good", b)),
        b if b >= 112 => (50, format!("{}-bit - Acceptable", b)),
        b if b > 0 => (20, format!("{}-bit - Weak", b)),
        _ => (0, "Unknown cipher strength".into()),
    }
}

/// Score the key exchange mechanism.
///
/// Forward secrecy (ECDHE/DHE) is strongly preferred.
/// TLS 1.3 ciphers (prefixed with `TLS_`) always use ephemeral key exchange.
fn score_key_exchange(cipher_name: &str) -> (u8, String) {
    if cipher_name.contains("ECDHE") || cipher_name.starts_with("TLS_") {
        (100, "ECDHE - Forward secrecy".into())
    } else if cipher_name.contains("DHE") {
        (80, "DHE - Forward secrecy".into())
    } else if cipher_name.contains("ECDH") {
        (50, "ECDH - No forward secrecy".into())
    } else if cipher_name.contains("RSA") {
        (30, "RSA key exchange - No forward secrecy".into())
    } else {
        (20, format!("Unknown key exchange in: {}", cipher_name))
    }
}

/// Score the certificate public key size.
///
/// EC keys use different thresholds than RSA/DSA since they achieve
/// equivalent security at much smaller key sizes.
fn score_cert_key_size(bits: u32, algorithm: &str) -> (u8, String) {
    let is_ec = algorithm.contains("EC")
        || algorithm.contains("ec")
        || algorithm == "ED25519"
        || algorithm == "ED448";

    if is_ec {
        match bits {
            b if b >= 384 => (100, format!("EC {}-bit - Excellent", b)),
            b if b >= 256 => (90, format!("EC {}-bit - Good", b)),
            b if b >= 224 => (60, format!("EC {}-bit - Acceptable", b)),
            _ => (30, format!("EC {}-bit - Weak", bits)),
        }
    } else {
        match bits {
            b if b >= 4096 => (100, format!("RSA {}-bit - Excellent", b)),
            b if b >= 2048 => (80, format!("RSA {}-bit - Good", b)),
            b if b >= 1024 => (40, format!("RSA {}-bit - Weak", b)),
            _ => (10, format!("RSA {}-bit - Critical", bits)),
        }
    }
}

/// Score the certificate trust chain status.
///
/// Expired or revoked certificates immediately get a score of 0.
fn score_certificate_trust(input: &GradingInput) -> (u8, String) {
    let mut score: u8 = 100;
    let mut reasons = Vec::new();

    if input.is_expired {
        score = 0;
        reasons.push("Certificate expired");
    }
    if input.is_revoked {
        score = 0;
        reasons.push("Certificate revoked");
    }
    if input.is_self_signed {
        score = score.min(20);
        reasons.push("Self-signed certificate");
    }
    if input.has_weak_signature {
        score = score.min(30);
        reasons.push("Weak signature algorithm");
    }
    if input.has_incomplete_chain {
        score = score.min(50);
        reasons.push("Incomplete certificate chain");
    }

    let reason = if reasons.is_empty() {
        "Certificate trust chain valid".to_string()
    } else {
        reasons.join("; ")
    };
    (score, reason)
}

/// Convert a numeric score (0-100) to a letter grade.
fn score_to_letter(score: u8) -> String {
    match score {
        95..=100 => "A+".into(),
        85..=94 => "A".into(),
        70..=84 => "B".into(),
        55..=69 => "C".into(),
        40..=54 => "D".into(),
        _ => "F".into(),
    }
}

/// Calculate the composite TLS configuration grade.
///
/// Uses a weighted average of five category scores with hard caps
/// for critical security issues.
///
/// **Weights:** Protocol 30% | Cipher 25% | Key Exchange 15% | Key Size 15% | Trust 15%
///
/// **Hard caps:**
/// - Expired or Revoked cert: score forced to 0 (F)
/// - SSLv3 or TLS 1.0: score capped at 35 (D max)
/// - Self-signed cert: score capped at 50 (C max)
pub fn calculate_grade(input: &GradingInput) -> TLSGrade {
    let (protocol_score, protocol_reason) = score_protocol(&input.protocol_version);
    let (cipher_score, cipher_reason) = score_cipher_bits(input.cipher_bits);
    let (kex_score, kex_reason) = score_key_exchange(&input.cipher_name);
    let (key_size_score, key_size_reason) =
        score_cert_key_size(input.cert_key_bits, &input.cert_key_algorithm);
    let (trust_score, trust_reason) = score_certificate_trust(input);

    let categories = vec![
        CategoryScore {
            category: "Protocol Version".into(),
            score: protocol_score,
            reason: protocol_reason,
        },
        CategoryScore {
            category: "Cipher Strength".into(),
            score: cipher_score,
            reason: cipher_reason,
        },
        CategoryScore {
            category: "Key Exchange".into(),
            score: kex_score,
            reason: kex_reason,
        },
        CategoryScore {
            category: "Certificate Key Size".into(),
            score: key_size_score,
            reason: key_size_reason,
        },
        CategoryScore {
            category: "Certificate Trust".into(),
            score: trust_score,
            reason: trust_reason,
        },
    ];

    let weighted_sum: u32 = (protocol_score as u32) * 30
        + (cipher_score as u32) * 25
        + (kex_score as u32) * 15
        + (key_size_score as u32) * 15
        + (trust_score as u32) * 15;
    let mut composite: u8 = (weighted_sum / 100).min(100) as u8;

    // Hard caps: certain conditions force a maximum grade
    if input.is_expired || input.is_revoked {
        composite = 0;
    }
    if protocol_score <= 20 {
        composite = composite.min(35);
    }
    if input.is_self_signed {
        composite = composite.min(50);
    }

    let grade = score_to_letter(composite);

    TLSGrade {
        grade,
        score: composite,
        categories,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_input(overrides: impl FnOnce(&mut GradingInput)) -> GradingInput {
        let mut input = GradingInput {
            protocol_version: "TLSv1.3".into(),
            cipher_name: "TLS_AES_256_GCM_SHA384".into(),
            cipher_bits: 256,
            cert_key_bits: 2048,
            cert_key_algorithm: "RSA".into(),
            is_expired: false,
            is_self_signed: false,
            has_incomplete_chain: false,
            has_weak_signature: false,
            is_revoked: false,
        };
        overrides(&mut input);
        input
    }

    #[test]
    fn test_perfect_config_gets_a_plus() {
        let input = make_input(|i| {
            i.cert_key_bits = 4096;
        });
        let grade = calculate_grade(&input);
        assert_eq!(grade.grade, "A+");
        assert!(grade.score >= 95);
    }

    #[test]
    fn test_good_config_gets_a() {
        let input = make_input(|_| {});
        let grade = calculate_grade(&input);
        assert!(
            grade.grade == "A+" || grade.grade == "A",
            "Expected A+ or A, got {}",
            grade.grade
        );
        assert!(grade.score >= 85);
    }

    #[test]
    fn test_expired_cert_gets_f() {
        let input = make_input(|i| i.is_expired = true);
        let grade = calculate_grade(&input);
        assert_eq!(grade.grade, "F");
        assert_eq!(grade.score, 0);
    }

    #[test]
    fn test_revoked_cert_gets_f() {
        let input = make_input(|i| i.is_revoked = true);
        let grade = calculate_grade(&input);
        assert_eq!(grade.grade, "F");
        assert_eq!(grade.score, 0);
    }

    #[test]
    fn test_self_signed_capped_at_c() {
        let input = make_input(|i| i.is_self_signed = true);
        let grade = calculate_grade(&input);
        assert!(grade.score <= 50);
        assert!(
            ["C", "D", "F"].contains(&grade.grade.as_str()),
            "Expected C, D, or F for self-signed, got {}",
            grade.grade
        );
    }

    #[test]
    fn test_tls12_with_good_cipher() {
        let input = make_input(|i| {
            i.protocol_version = "TLSv1.2".into();
            i.cipher_name = "ECDHE-RSA-AES256-GCM-SHA384".into();
            i.cipher_bits = 256;
        });
        let grade = calculate_grade(&input);
        assert!(
            ["A+", "A", "B"].contains(&grade.grade.as_str()),
            "Expected A+, A, or B for TLS 1.2 + good cipher, got {}",
            grade.grade
        );
    }

    #[test]
    fn test_weak_cipher_lowers_score() {
        let input = make_input(|i| {
            i.cipher_bits = 64;
            i.cipher_name = "DES-CBC3-SHA".into();
        });
        let grade = calculate_grade(&input);
        assert!(
            grade.score < 70,
            "Expected score < 70 for weak cipher, got {}",
            grade.score
        );
    }

    #[test]
    fn test_tls10_capped_at_d() {
        let input = make_input(|i| {
            i.protocol_version = "TLSv1".into();
        });
        let grade = calculate_grade(&input);
        assert!(
            grade.score <= 35,
            "Expected score <= 35 for TLS 1.0, got {}",
            grade.score
        );
        assert!(
            ["D", "F"].contains(&grade.grade.as_str()),
            "Expected D or F for TLS 1.0, got {}",
            grade.grade
        );
    }

    #[test]
    fn test_score_protocol_versions() {
        assert_eq!(score_protocol("TLSv1.3").0, 100);
        assert_eq!(score_protocol("TLSv1.2").0, 80);
        assert_eq!(score_protocol("TLSv1.1").0, 40);
        assert_eq!(score_protocol("TLSv1").0, 20);
        assert_eq!(score_protocol("SSLv3").0, 0);
    }

    #[test]
    fn test_score_to_letter_boundaries() {
        assert_eq!(score_to_letter(100), "A+");
        assert_eq!(score_to_letter(95), "A+");
        assert_eq!(score_to_letter(94), "A");
        assert_eq!(score_to_letter(85), "A");
        assert_eq!(score_to_letter(84), "B");
        assert_eq!(score_to_letter(70), "B");
        assert_eq!(score_to_letter(69), "C");
        assert_eq!(score_to_letter(55), "C");
        assert_eq!(score_to_letter(54), "D");
        assert_eq!(score_to_letter(40), "D");
        assert_eq!(score_to_letter(39), "F");
        assert_eq!(score_to_letter(0), "F");
    }

    #[test]
    fn test_ec_key_scoring() {
        let (score, _) = score_cert_key_size(256, "EC");
        assert_eq!(score, 90);
        let (score, _) = score_cert_key_size(384, "EC");
        assert_eq!(score, 100);
    }

    #[test]
    fn test_rsa_key_scoring() {
        let (score, _) = score_cert_key_size(4096, "RSA");
        assert_eq!(score, 100);
        let (score, _) = score_cert_key_size(2048, "RSA");
        assert_eq!(score, 80);
        let (score, _) = score_cert_key_size(1024, "RSA");
        assert_eq!(score, 40);
    }

    #[test]
    fn test_categories_count() {
        let input = make_input(|_| {});
        let grade = calculate_grade(&input);
        assert_eq!(grade.categories.len(), 5);
    }

    #[test]
    fn test_grade_is_deterministic() {
        let input1 = make_input(|_| {});
        let input2 = make_input(|_| {});
        assert_eq!(calculate_grade(&input1), calculate_grade(&input2));
    }

    #[test]
    fn test_incomplete_chain_lowers_trust() {
        let input = make_input(|i| i.has_incomplete_chain = true);
        let grade = calculate_grade(&input);
        let trust = grade
            .categories
            .iter()
            .find(|c| c.category == "Certificate Trust")
            .unwrap();
        assert!(
            trust.score <= 50,
            "Expected trust score <= 50 for incomplete chain, got {}",
            trust.score
        );
    }

    #[test]
    fn test_weak_signature_lowers_trust() {
        let input = make_input(|i| i.has_weak_signature = true);
        let grade = calculate_grade(&input);
        let trust = grade
            .categories
            .iter()
            .find(|c| c.category == "Certificate Trust")
            .unwrap();
        assert!(
            trust.score <= 30,
            "Expected trust score <= 30 for weak signature, got {}",
            trust.score
        );
    }

    #[test]
    fn test_key_exchange_scoring() {
        assert_eq!(score_key_exchange("ECDHE-RSA-AES256-GCM-SHA384").0, 100);
        assert_eq!(score_key_exchange("TLS_AES_256_GCM_SHA384").0, 100);
        assert_eq!(score_key_exchange("DHE-RSA-AES256-GCM-SHA384").0, 80);
        assert_eq!(score_key_exchange("AES256-GCM-SHA384").0, 20); // unknown
    }
}
