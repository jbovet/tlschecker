use lazy_static::lazy_static;
use prometheus::{labels, register_gauge, Gauge};

use tlschecker::RevocationStatus;
use tlschecker::TLS;

lazy_static! {
    static ref TLSCHECKER_DAYS_BEFORE_EXPIRED: Gauge =
        register_gauge!("tlschecker_days_before_expired", "days before expiration").unwrap();
    static ref TLSCHECKER_HOURS_BEFORE_EXPIRED: Gauge =
        register_gauge!("tlschecker_hours_before_expired", "hours before expiration").unwrap();
    static ref TLSCHECKER_REVOCATION_STATUS: Gauge = register_gauge!(
        "tlschecker_revocation_status",
        "certificate revocation status"
    )
    .unwrap();
}
/// Function to push metrics to prometheus
/// # Arguments
/// * `results` - Vector of TLS structs
/// * `prometheus_address` - String of prometheus address
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
