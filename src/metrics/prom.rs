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
//! - `tlschecker_verdict` - Host status: 0 healthy, 1 warning, 2 critical — the same
//!   `tlschecker::verdict::assess` result the CLI status and exit code use (gauge)
//! - `tlschecker_below_min_validity` - Whether certificate is below the explicit
//!   `--min-validity` threshold; always 0 when `--min-validity` is unset (gauge)
//!
//! - `tlschecker_certificate_info` - Descriptive info metric (constant `1`), carrying
//!   the cipher/issuer/grade labels (the standard Prometheus "info metric" pattern)
//!
//! # Metric Labels
//!
//! Every metric carries the push **grouping key** — `job` and `instance` (the target:
//! `host`, or `host:port` when the port is not 443) — and nothing else. Only these
//! stable identity labels belong in the grouping key: a `PUT` to the push gateway
//! replaces series under the exact grouping key, so putting volatile labels (grade,
//! expired, cipher, …) there would orphan the previous run's series every time one of
//! those values changed. Descriptive, changeable labels live on
//! `tlschecker_certificate_info` instead:
//! - `cipher` - TLS cipher suite name
//! - `cipher_protocol_version` - TLS protocol version
//! - `issuer` - Certificate issuer organization
//! - `grade` - TLS configuration grade letter (`N/A` when grading did not run)
//!
//! # Revocation Status Values
//!
//! The `tlschecker_revocation_status` metric uses the following values:
//! - `0.0` - Not checked
//! - `1.0` - Good (not revoked)
//! - `2.0` - Unknown (couldn't determine)
//! - `3.0` - Revoked

use prometheus::proto::MetricFamily;
use prometheus::{labels, Gauge, Opts, Registry};
use tracing::warn;

use tlschecker::verdict::Verdict;
use tlschecker::RevocationStatus;
use tlschecker::TLS;

use crate::HostReport;

/// Returns whether a host's certificate is below the configured minimum validity.
///
/// Explicit-only: `min_validity <= 0` (including `--min-validity` unset) disables the
/// check, independent of the default expiry windows behind `tlschecker_verdict`; expired certificates are excluded (they are
/// already reported via the expiry metrics), so this specifically flags "valid but
/// running out".
fn is_below_min_validity(tls: &TLS, min_validity: i32) -> bool {
    min_validity > 0 && !tls.certificate.is_expired && tls.certificate.validity_days < min_validity
}

/// Builds the metric families for a single host's check result.
///
/// Each host gets a **fresh registry** so values never leak between hosts:
/// with shared global gauges, a host without a grade would push the previous
/// host's `tlschecker_grade_score` under its own labels. The grade gauge is
/// only registered when grading was actually performed for this host.
///
/// `verdict` is the host's status under the run's policy, exported as
/// `tlschecker_verdict`.
pub(crate) fn host_metric_families(
    tls: &TLS,
    verdict: Verdict,
    min_validity: i32,
) -> Vec<MetricFamily> {
    let registry = Registry::new();

    let register = |opts: Opts, value: f64| {
        let name = opts.name.clone();
        match Gauge::with_opts(opts) {
            Ok(gauge) => {
                gauge.set(value);
                if let Err(e) = registry.register(Box::new(gauge)) {
                    warn!("Failed to register metric {}: {}", name, e);
                }
            }
            Err(e) => warn!("Failed to create metric {}: {}", name, e),
        };
    };
    let register_gauge =
        |name: &str, help: &str, value: f64| register(Opts::new(name, help), value);

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

    // 0 = healthy, 1 = warning, 2 = critical
    let verdict_value = match verdict {
        Verdict::Healthy => 0.0,
        Verdict::Warning => 1.0,
        Verdict::Critical => 2.0,
    };
    register_gauge(
        "tlschecker_verdict",
        "host status: 0 healthy, 1 warning, 2 critical (same rules as the CLI status and exit code)",
        verdict_value,
    );

    register_gauge(
        "tlschecker_below_min_validity",
        "1 if certificate validity is below the configured minimum threshold, 0 otherwise",
        if is_below_min_validity(tls, min_validity) {
            1.0
        } else {
            0.0
        },
    );

    // Info metric (constant 1) carrying the descriptive, changeable labels. Keeping
    // these off the push grouping key is what prevents stale series from piling up in
    // the gateway when a cipher/issuer/grade changes between runs.
    let info = Opts::new(
        "tlschecker_certificate_info",
        "TLS certificate metadata (constant 1); labels carry cipher/issuer/grade",
    )
    .const_label("cipher", &tls.cipher.name)
    .const_label("cipher_protocol_version", &tls.cipher.version)
    .const_label("issuer", &tls.certificate.issued.organization)
    .const_label(
        "grade",
        tls.grade.as_ref().map_or("N/A", |g| g.grade.as_str()),
    );
    register(info, 1.0);

    registry.gather()
}

/// Pushes TLS certificate metrics to a Prometheus Push Gateway.
///
/// This function exports certificate metrics for each checked host to a Prometheus
/// Push Gateway, making the data available for monitoring, alerting, and visualization.
///
/// # Arguments
///
/// * `reports` - Checked hosts with their status
/// * `prometheus_address` - URL of the Prometheus Push Gateway (e.g., "http://localhost:9091")
/// * `min_validity` - Explicit `--min-validity` in days (0 = unset / disabled)
///
/// # Metrics Exported
///
/// For each certificate (one push per host, keyed by `instance=<target>`, i.e.
/// `host` or `host:port`):
/// - Days and hours until expiration
/// - Revocation status (0-3, see module documentation)
/// - Grade score (only when grading was performed)
/// - `tlschecker_verdict` (0 healthy, 1 warning, 2 critical)
/// - `below_min_validity` (0/1)
/// - `tlschecker_certificate_info` = 1, carrying the `cipher`/`issuer`/`grade` labels
///
/// # Error Handling
///
/// A failed push (network error, gateway unavailable, etc.) is logged via
/// `tracing::warn!` (stderr) per host and skipped; one unreachable host never
/// aborts the others, and the function never panics.
///
/// # Example
///
/// ```ignore
/// // `reports` come from `collect` in main.rs: each checked host with its status.
/// // `address` is the push gateway root — `/metrics/job/tlschecker/instance/<target>`
/// // is appended internally. `min_validity` (days, 0 = off) drives the
/// // `tlschecker_below_min_validity` gauge.
/// prometheus_metrics(&reports, "http://localhost:9091", 30);
/// ```
pub fn prometheus_metrics(reports: &[HostReport], prometheus_address: &str, min_validity: i32) {
    for report in reports {
        let tls = &report.tls;
        let metric_families = host_metric_families(tls, report.status.verdict, min_validity);

        // Grouping key = stable identity only. A push_metrics PUT replaces the series
        // under this exact key, so `instance` = target is what lets each host own (and
        // overwrite) its own series without orphaning previous runs. The target
        // carries the port when it is not 443; with the bare hostname, two ports of
        // one host shared a key and each push replaced the other's series. Volatile
        // labels (grade, cipher, expired, …) are metric values or live on the info
        // metric.
        let instance = report.target();
        let prometheus_client = prometheus::push_metrics(
            "tlschecker",
            labels! {
                "instance".to_owned() => instance.clone(),
            },
            // Base URL only: push_metrics appends `/metrics/job/<job>/<label>/<value>…`
            // itself. Passing `<addr>/metrics/job` here doubled the path so the gateway
            // parsed "metrics" as the job name (job label came out as "metrics").
            prometheus_address,
            metric_families,
            None,
        );

        if let Err(e) = prometheus_client {
            warn!(
                "Failed to push metrics to prometheus for {}: {}",
                instance, e
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tlschecker::verdict::{FindingCode, VerdictPolicy};
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
                revocation_detail: None,
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
                ocsp_urls: vec![],
                ca_issuer_urls: vec![],
                crl_urls: vec![],
                scts: Vec::new(),
                pem: String::new(),
            },
            grade: None,
            scan: None,
            ct: None,
            ct_detail: None,
        }
    }

    /// The host's metric families with its verdict under the default policy.
    fn families(tls: &TLS, min_validity: i32) -> Vec<MetricFamily> {
        let verdict = tls.assess(&VerdictPolicy::default()).verdict;
        host_metric_families(tls, verdict, min_validity)
    }

    fn gauge_value(families: &[MetricFamily], name: &str) -> f64 {
        families
            .iter()
            .find(|f| f.name() == name)
            .unwrap_or_else(|| panic!("{name} missing"))
            .get_metric()[0]
            .get_gauge()
            .value()
    }

    fn family_names(families: &[MetricFamily]) -> Vec<&str> {
        families.iter().map(|f| f.name()).collect()
    }

    #[test]
    fn test_no_grade_gauge_without_grade() {
        // Regression: with shared global gauges, a grade-less host pushed the
        // previous host's grade score under its own labels.
        let tls = make_test_tls();
        let families = families(&tls, 0);
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
        let families = families(&tls, 0);
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
    fn test_certificate_info_metric_carries_descriptive_labels() {
        // Descriptive labels (cipher/issuer/grade) must live on the info metric, not
        // the push grouping key, so changing values don't orphan series in the gateway.
        let mut tls = make_test_tls();
        tls.grade = Some(tlschecker::grading::TLSGrade {
            grade: "A".to_string(),
            score: 90,
            categories: vec![],
        });
        let families = families(&tls, 0);
        let info = families
            .iter()
            .find(|f| f.name() == "tlschecker_certificate_info")
            .expect("info metric present");
        let metric = &info.get_metric()[0];
        assert_eq!(metric.get_gauge().value(), 1.0);
        let labels: std::collections::HashMap<_, _> = metric
            .get_label()
            .iter()
            .map(|l| (l.name(), l.value()))
            .collect();
        assert_eq!(labels.get("cipher"), Some(&"TLS_AES_256_GCM_SHA384"));
        assert_eq!(labels.get("cipher_protocol_version"), Some(&"TLSv1.3"));
        assert_eq!(labels.get("issuer"), Some(&"Test CA"));
        assert_eq!(labels.get("grade"), Some(&"A"));
    }

    #[test]
    fn test_certificate_info_grade_defaults_to_na() {
        let tls = make_test_tls(); // no grade
        let families = families(&tls, 0);
        let info = families
            .iter()
            .find(|f| f.name() == "tlschecker_certificate_info")
            .expect("info metric present");
        let grade = info.get_metric()[0]
            .get_label()
            .iter()
            .find(|l| l.name() == "grade")
            .map(|l| l.value().to_string());
        assert_eq!(grade, Some("N/A".to_string()));
    }

    #[test]
    fn test_below_min_validity_gauge() {
        let tls = make_test_tls(); // 100 days left
        let get_value = |min_validity: i32| {
            families(&tls, min_validity)
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

    // 35
    #[test]
    fn test_verdict_gauge() {
        let healthy = make_test_tls(); // 100 days left
        let mut self_signed = make_test_tls();
        self_signed.certificate.is_self_signed = true;
        let mut expired = make_test_tls();
        expired.certificate.is_expired = true;
        expired.certificate.validity_days = -2;

        for (tls, expected) in [(healthy, 0.0), (self_signed, 1.0), (expired, 2.0)] {
            assert_eq!(
                gauge_value(&families(&tls, 0), "tlschecker_verdict"),
                expected
            );
        }

        // The gauge carries the run's policy: an allowed finding no longer counts.
        let mut mismatch = make_test_tls();
        mismatch
            .certificate
            .security_warnings
            .push(tlschecker::SecurityWarning::HostnameMismatch(
                "not valid".to_string(),
            ));
        assert_eq!(
            gauge_value(&families(&mismatch, 0), "tlschecker_verdict"),
            2.0
        );
        let allowed = mismatch
            .assess(&VerdictPolicy {
                allow: vec![FindingCode::HostnameMismatch],
                ..VerdictPolicy::default()
            })
            .verdict;
        assert_eq!(
            gauge_value(
                &host_metric_families(&mismatch, allowed, 0),
                "tlschecker_verdict"
            ),
            0.0
        );
    }

    #[test]
    fn test_below_min_validity_stays_explicit_only() {
        // 10 days left is Critical by the default window, but without an
        // explicit --min-validity the gauge stays 0.
        let mut tls = make_test_tls();
        tls.certificate.validity_days = 10;
        let gauges = families(&tls, 0);
        assert_eq!(gauge_value(&gauges, "tlschecker_verdict"), 2.0);
        assert_eq!(gauge_value(&gauges, "tlschecker_below_min_validity"), 0.0);
    }
}
