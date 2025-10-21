//! Error types for TLS certificate validation.
//!
//! This module defines the error types that can occur during TLS certificate
//! checking and validation operations.

use std::fmt;
use std::io;

/// Error type for TLS certificate validation failures.
///
/// This error is returned when certificate checking fails due to connection issues,
/// invalid certificates, or other validation problems.
#[derive(Debug)]
pub enum TLSValidationError {
    /// DNS resolution failed for the given hostname
    DnsResolution {
        /// The hostname that failed to resolve
        hostname: String,
        /// The underlying I/O error
        source: io::Error,
    },

    /// TCP connection failed to the target address
    ConnectionFailed {
        /// The address (host:port) that connection failed to
        address: String,
        /// The underlying I/O error
        source: io::Error,
    },

    /// TLS handshake failed
    HandshakeFailed {
        /// Details about why the handshake failed
        details: String,
    },

    /// Certificate parsing or validation error
    CertificateError {
        /// Description of what went wrong
        reason: String,
    },

    /// Network operation timeout
    Timeout {
        /// Description of which operation timed out
        operation: String,
    },

    /// Invalid input provided to the API
    InvalidInput {
        /// Which field/parameter was invalid
        field: String,
        /// Why it was invalid
        reason: String,
    },

    /// Certificate revocation check failed
    RevocationCheckFailed {
        /// Description of the failure
        reason: String,
    },

    /// OpenSSL error occurred
    OpenSSLError {
        /// The underlying OpenSSL error
        details: String,
    },

    /// Generic I/O error
    IoError {
        /// The underlying I/O error
        source: io::Error,
    },

    /// A generic error with a custom message
    Other {
        /// Error message
        message: String,
    },
}

impl fmt::Display for TLSValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DnsResolution { hostname, .. } => {
                write!(
                    f,
                    "Failed to resolve hostname: {}. Check that the hostname is spelled correctly and your DNS configuration is working.",
                    hostname
                )
            }
            Self::ConnectionFailed { address, .. } => {
                write!(
                    f,
                    "Connection failed to: {}. Verify the host is running a TLS service and is reachable.",
                    address
                )
            }
            Self::HandshakeFailed { details } => {
                write!(f, "TLS handshake failed: {}", details)
            }
            Self::CertificateError { reason } => {
                write!(f, "Certificate error: {}", reason)
            }
            Self::Timeout { operation } => {
                write!(f, "Operation timed out: {}", operation)
            }
            Self::InvalidInput { field, reason } => {
                write!(f, "Invalid input for '{}': {}", field, reason)
            }
            Self::RevocationCheckFailed { reason } => {
                write!(f, "Revocation check failed: {}", reason)
            }
            Self::OpenSSLError { details } => {
                write!(f, "OpenSSL error: {}", details)
            }
            Self::IoError { source } => {
                write!(f, "I/O error: {}", source)
            }
            Self::Other { message } => {
                write!(f, "{}", message)
            }
        }
    }
}

impl std::error::Error for TLSValidationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DnsResolution { source, .. } => Some(source),
            Self::ConnectionFailed { source, .. } => Some(source),
            Self::IoError { source } => Some(source),
            _ => None,
        }
    }
}

// Conversion implementations for compatibility

impl From<io::Error> for TLSValidationError {
    fn from(e: io::Error) -> Self {
        // Check if this is a DNS resolution error
        if e.kind() == io::ErrorKind::Other {
            let msg = e.to_string();
            if msg.contains("failed to lookup address information") {
                return Self::Other {
                    message: "DNS resolution failed".to_string(),
                };
            }
        }

        Self::IoError { source: e }
    }
}

impl From<&str> for TLSValidationError {
    fn from(s: &str) -> Self {
        Self::Other {
            message: s.to_string(),
        }
    }
}

impl From<String> for TLSValidationError {
    fn from(s: String) -> Self {
        Self::Other { message: s }
    }
}

impl From<openssl::error::ErrorStack> for TLSValidationError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Self::OpenSSLError {
            details: e.to_string(),
        }
    }
}

impl<S> From<openssl::ssl::HandshakeError<S>> for TLSValidationError {
    fn from(e: openssl::ssl::HandshakeError<S>) -> Self {
        Self::HandshakeFailed {
            details: format!("{}", e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = TLSValidationError::InvalidInput {
            field: "hostname".to_string(),
            reason: "cannot be empty".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "Invalid input for 'hostname': cannot be empty"
        );
    }

    #[test]
    fn test_error_from_str() {
        let err: TLSValidationError = "test error".into();
        assert_eq!(err.to_string(), "test error");
    }
}
