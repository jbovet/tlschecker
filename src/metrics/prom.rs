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

use lazy_static::lazy_static;
use prometheus::{labels, register_gauge, Gauge};

use tlschecker::RevocationStatus;
use tlschecker::TLS;

lazy_static! {
    /// Gauge metric tracking days until certificate expiration.
    static ref TLSCHECKER_DAYS_BEFORE_EXPIRED: Gauge =
        register_gauge!("tlschecker_days_before_expired", "days before expiration").unwrap();

    /// Gauge metric tracking hours until certificate expiration.
    static ref TLSCHECKER_HOURS_BEFORE_EXPIRED: Gauge =
        register_gauge!("tlschecker_hours_before_expired", "hours before expiration").unwrap();

    /// Gauge metric tracking certificate revocation status.
    /// Values: 0=not checked, 1=good, 2=unknown, 3=revoked
    static ref TLSCHECKER_REVOCATION_STATUS: Gauge = register_gauge!(
        "tlschecker_revocation_status",
        "certificate revocation status"
    )
    .unwrap();
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
///
/// # Metrics Exported
///
/// For each certificate:
/// - Days and hours until expiration
/// - Revocation status (0-3, see module documentation)
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
/// prometheus_metrics(results, "http://localhost:9091".to_string());
/// # }
/// ```
pub fn prometheus_metrics(results: Vec<TLS>, prometheus_address: String) {
    for tls in results.iter() {
        TLSCHECKER_DAYS_BEFORE_EXPIRED.set(f64::from(tls.certificate.validity_days.to_owned()));
        TLSCHECKER_HOURS_BEFORE_EXPIRED.set(f64::from(tls.certificate.validity_hours.to_owned()));

        // Set revocation status metric
        // 0 = Not checked, 1 = Good, 2 = Unknown, 3 = Revoked
        let revocation_value = match tls.certificate.revocation_status {
            RevocationStatus::NotChecked => 0.0,
            RevocationStatus::Good => 1.0,
            RevocationStatus::Unknown => 2.0,
            RevocationStatus::Revoked(_) => 3.0,
        };
        TLSCHECKER_REVOCATION_STATUS.set(revocation_value);

        let metric_families = prometheus::gather();
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
            },
            &format!("{}/metrics/job", prometheus_address),
            metric_families,
            None,
        );

        match prometheus_client {
            Ok(_) => {} //TODO
            Err(e) => println!("\nFailed to push metrics to prometheus: {}", e),
        }
    }
}
