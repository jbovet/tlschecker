//! Integration tests for the public API

use tlschecker::{TLS, TLSValidationError, RevocationStatus};

#[test]
fn test_public_api_compiles() {
    // This test ensures the public API is usable and compiles correctly
    fn check_certificate(hostname: &str) -> Result<(), TLSValidationError> {
        let _result = TLS::from(hostname, None, false)?;
        Ok(())
    }

    // We don't actually run this in tests (would require network)
    // but we verify it compiles
    let _ = check_certificate;
}

#[test]
fn test_error_types_are_public() {
    // Verify error types can be matched
    fn handle_error(err: TLSValidationError) -> String {
        match err {
            TLSValidationError::DnsResolution { hostname, .. } => {
                format!("DNS failed for {}", hostname)
            }
            TLSValidationError::ConnectionFailed { address, .. } => {
                format!("Connection failed to {}", address)
            }
            TLSValidationError::HandshakeFailed { details } => {
                format!("Handshake failed: {}", details)
            }
            TLSValidationError::CertificateError { reason } => {
                format!("Certificate error: {}", reason)
            }
            TLSValidationError::Timeout { operation } => {
                format!("Timeout: {}", operation)
            }
            TLSValidationError::InvalidInput { field, reason } => {
                format!("Invalid {}: {}", field, reason)
            }
            TLSValidationError::RevocationCheckFailed { reason } => {
                format!("Revocation check failed: {}", reason)
            }
            TLSValidationError::OpenSSLError { details } => {
                format!("OpenSSL error: {}", details)
            }
            TLSValidationError::IoError { source } => {
                format!("I/O error: {}", source)
            }
            TLSValidationError::Other { message } => {
                format!("Other: {}", message)
            }
        }
    }

    let err = TLSValidationError::InvalidInput {
        field: "test".to_string(),
        reason: "test reason".to_string(),
    };

    let msg = handle_error(err);
    assert!(msg.contains("test"));
}

#[test]
fn test_revocation_status_types() {
    // Verify RevocationStatus enum is public and usable
    let statuses = vec![
        RevocationStatus::Good,
        RevocationStatus::Revoked("test".to_string()),
        RevocationStatus::Unknown,
        RevocationStatus::NotChecked,
    ];

    assert_eq!(statuses.len(), 4);
}

#[test]
fn test_error_display() {
    let err = TLSValidationError::InvalidInput {
        field: "hostname".to_string(),
        reason: "cannot be empty".to_string(),
    };

    let display = format!("{}", err);
    assert!(display.contains("hostname"));
    assert!(display.contains("cannot be empty"));
}

#[test]
fn test_error_conversion_from_str() {
    let err: TLSValidationError = "test error".into();
    assert_eq!(err.to_string(), "test error");
}

#[test]
fn test_error_conversion_from_string() {
    let err: TLSValidationError = "test error".to_string().into();
    assert_eq!(err.to_string(), "test error");
}
