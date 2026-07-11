//! Prometheus metrics integration for TLSChecker.
//!
//! This module provides functionality to export TLS certificate metrics to
//! a Prometheus Push Gateway for monitoring and alerting.
//!
//! # Exported Metrics
//!
//! - `tlschecker_days_before_expired` - Days until certificate expiration (gauge)
//! - `tlschecker_hours_before_expired` - Hours until certificate expiration (gauge)
//! - `tlschecker_revocation_status` - Certificate revocation status (gauge)
//! - `tlschecker_grade_score` - TLS configuration grade score, only when grading ran (gauge)
//! - `tlschecker_below_min_validity` - Whether certificate is below minimum validity threshold (gauge)
//!
//! # Metric Labels
//!
//! Each metric includes the following labels:
//! - `instance`, `job` - Standard Prometheus identifiers
//! - `host` - Target hostname
//! - `cipher` - TLS cipher suite name
//! - `cipher_protocol_version` - TLS protocol version
//! - `issuer` - Certificate issuer organization
//! - `expired` - Boolean expiration status
//! - `revoked` - Boolean revocation status
//!
//! # Revocation Status Values
//!
//! The `tlschecker_revocation_status` metric uses the following values:
//! - `0.0` - Not checked
//! - `1.0` - Good (not revoked)
//! - `2.0` - Unknown (couldn't determine)
//! - `3.0` - Revoked

use prometheus::proto::MetricFamily;
use prometheus::{labels, Gauge, Registry};

use tlschecker::RevocationStatus;
use tlschecker::TLS;

/// Builds the metric families for a single host's check result.
///
/// Each host gets a **fresh registry** so values never leak between hosts:
/// with shared global gauges, a host without a grade would push the previous
/// host's `tlschecker_grade_score` under its own labels. The grade gauge is
/// only registered when grading was actually performed for this host.
fn host_metric_families(tls: &TLS, min_validity: i32) -> Vec<MetricFamily> {
    let registry = Registry::new();

    let register_gauge = |name: &str, help: &str, value: f64| {
        match Gauge::new(name, help) {
            Ok(gauge) => {
                gauge.set(value);
                if let Err(e) = registry.register(Box::new(gauge)) {
                    eprintln!("Failed to register metric {}: {}", name, e);
                }
            }
            Err(e) => eprintln!("Failed to create metric {}: {}", name, e),
        };
    };

    register_gauge(
        "tlschecker_days_before_expired",
        "days before expiration",
        f64::from(tls.certificate.validity_days),
    );
    register_gauge(
        "tlschecker_hours_before_expired",
        "hours before expiration",
        f64::from(tls.certificate.validity_hours),
    );

    // 0 = Not checked, 1 = Good, 2 = Unknown, 3 = Revoked
    let revocation_value = match tls.certificate.revocation_status {
        RevocationStatus::NotChecked => 0.0,
        RevocationStatus::Good => 1.0,
        RevocationStatus::Unknown => 2.0,
        RevocationStatus::Revoked(_) => 3.0,
    };
    register_gauge(
        "tlschecker_revocation_status",
        "certificate revocation status",
        revocation_value,
    );

    // Only exported when grading was performed for this host.
    if let Some(ref grade) = tls.grade {
        register_gauge(
            "tlschecker_grade_score",
            "TLS configuration grade score (0-100)",
            f64::from(grade.score),
        );
    }

    let below_min_validity = min_validity > 0
        && !tls.certificate.is_expired
        && tls.certificate.validity_days < min_validity;
    register_gauge(
        "tlschecker_below_min_validity",
        "1 if certificate validity is below the configured minimum threshold, 0 otherwise",
        if below_min_validity { 1.0 } else { 0.0 },
    );

    registry.gather()
}

/// Pushes TLS certificate metrics to a Prometheus Push Gateway.
///
/// This function exports certificate metrics for each checked host to a Prometheus
/// Push Gateway, making the data available for monitoring, alerting, and visualization.
///
/// # Arguments
///
/// * `results` - Vector of TLS certificate check results
/// * `prometheus_address` - URL of the Prometheus Push Gateway (e.g., "http://localhost:9091")
/// * `min_validity` - Minimum validity threshold in days (0 = disabled)
///
/// # Metrics Exported
///
/// For each certificate:
/// - Days and hours until expiration
/// - Revocation status (0-3, see module documentation)
/// - Grade score (only when grading was performed)
/// - Associated labels (host, cipher, issuer, etc.)
///
/// # Error Handling
///
/// If pushing metrics fails (network error, gateway unavailable, etc.),
/// an error message is printed to stderr but the function doesn't panic.
///
/// # Example
///
/// ```no_run
/// # use tlschecker::TLS;
/// # use tlschecker::metrics::prom::prometheus_metrics;
/// # fn example(results: Vec<TLS>) {
/// prometheus_metrics(results, "http://localhost:9091".to_string(), 30);
/// # }
/// ```
pub fn prometheus_metrics(results: Vec<TLS>, prometheus_address: String, min_validity: i32) {
    for tls in results.iter() {
        let metric_families = host_metric_families(tls, min_validity);
        let below_min_validity = min_validity > 0
            && !tls.certificate.is_expired
            && tls.certificate.validity_days < min_validity;

        let prometheus_client = prometheus::push_metrics(
            "tlschecker",
            labels! {
                "instance".to_owned() => "tlschecker".to_owned(),
                "job".to_owned() => "tlschecker".to_owned(),
                "host".to_owned() =>  tls.certificate.hostname.to_owned(),
                "cipher".to_owned() => tls.cipher.name.to_owned(),
                "cipher_protocol_version".to_owned() => tls.cipher.version.to_owned(),
                "issuer".to_owned() => tls.certificate.issued.organization.to_owned(),
                "expired".to_owned() => tls.certificate.is_expired.to_string(),
                "revoked".to_owned() => (matches!(tls.certificate.revocation_status, RevocationStatus::Revoked(_))).to_string(),
                "grade".to_owned() => tls.grade.as_ref().map_or("N/A".to_string(), |g| g.grade.clone()),
                "below_min_validity".to_owned() => below_min_validity.to_string(),
            },
            &format!("{}/metrics/job", prometheus_address),
            metric_families,
            None,
        );

        if let Err(e) = prometheus_client {
            eprintln!("\nFailed to push metrics to prometheus: {}", e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlschecker::{CertificateInfo, Cipher, Issuer, Subject};

    fn make_test_tls() -> TLS {
        TLS {
            cipher: Cipher {
                name: "TLS_AES_256_GCM_SHA384".to_string(),
                version: "TLSv1.3".to_string(),
                bits: 256,
                alpn: None,
            },
            certificate: CertificateInfo {
                hostname: "test.example.com".to_string(),
                subject: Subject {
                    country_or_region: "US".to_string(),
                    state_or_province: "None".to_string(),
                    locality: "None".to_string(),
                    organization_unit: "None".to_string(),
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
                validity_days: 100,
                validity_hours: 2400,
                is_expired: false,
                cert_sn: "1".to_string(),
                cert_ver: "2".to_string(),
                cert_alg: "sha256WithRSAEncryption".to_string(),
                sans: vec![],
                chain: None,
                revocation_status: RevocationStatus::NotChecked,
                trust: tlschecker::TrustStatus::Unknown,
                is_self_signed: false,
                security_warnings: vec![],
                cert_key_bits: 2048,
                cert_key_algorithm: "RSA".to_string(),
                cert_sha256: String::new(),
                cert_sha1: String::new(),
                subject_key_id: None,
                authority_key_id: None,
                validation_level: None,
                key_usage: vec![],
                ext_key_usage: vec![],
                is_ca: false,
                path_len: None,
                scts: Vec::new(),
                pem: String::new(),
            },
            grade: None,
            scan: None,
            ct: None,
        }
    }

    fn family_names(families: &[MetricFamily]) -> Vec<&str> {
        families.iter().map(|f| f.name()).collect()
    }

    #[test]
    fn test_no_grade_gauge_without_grade() {
        // Regression: with shared global gauges, a grade-less host pushed the
        // previous host's grade score under its own labels.
        let tls = make_test_tls();
        let families = host_metric_families(&tls, 0);
        let names = family_names(&families);
        assert!(!names.contains(&"tlschecker_grade_score"));
        assert!(names.contains(&"tlschecker_days_before_expired"));
        assert!(names.contains(&"tlschecker_revocation_status"));
    }

    #[test]
    fn test_grade_gauge_present_with_grade() {
        let mut tls = make_test_tls();
        tls.grade = Some(tlschecker::grading::TLSGrade {
            grade: "A".to_string(),
            score: 90,
            categories: vec![],
        });
        let families = host_metric_families(&tls, 0);
        let names = family_names(&families);
        assert!(names.contains(&"tlschecker_grade_score"));

        let grade_family = families
            .iter()
            .find(|f| f.name() == "tlschecker_grade_score")
            .unwrap();
        let value = grade_family.get_metric()[0].get_gauge().value();
        assert_eq!(value, 90.0);
    }

    #[test]
    fn test_below_min_validity_gauge() {
        let tls = make_test_tls(); // 100 days left
        let get_value = |min_validity: i32| {
            host_metric_families(&tls, min_validity)
                .iter()
                .find(|f| f.name() == "tlschecker_below_min_validity")
                .unwrap()
                .get_metric()[0]
                .get_gauge()
                .value()
        };
        assert_eq!(get_value(0), 0.0); // disabled
        assert_eq!(get_value(30), 0.0); // above threshold
        assert_eq!(get_value(365), 1.0); // below threshold
    }
}
