//! Certificate revocation checking example.
//!
//! This example demonstrates how to check certificate revocation status
//! using OCSP and CRL protocols.
//!
//! Run with: cargo run --example revocation_check

use tlschecker::{RevocationStatus, TLS};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TLS Certificate Revocation Check ===\n");

    let hosts = vec![
        "google.com",
        "github.com",
        // Note: revoked.badssl.com provides a revoked certificate for testing
        "revoked.badssl.com",
    ];

    for host in hosts {
        println!("Checking {}...", host);

        match TLS::from(host, None, true) {
            Ok(result) => {
                print!("  Status: ");
                match result.certificate.revocation_status {
                    RevocationStatus::Good => {
                        println!("✓ Valid (not revoked)");
                    }
                    RevocationStatus::Revoked(reason) => {
                        println!("✗ REVOKED - {}", reason);
                    }
                    RevocationStatus::Unknown => {
                        println!("? Unknown (could not determine status)");
                    }
                    RevocationStatus::NotChecked => {
                        println!("- Not checked");
                    }
                }

                println!("  Expires in {} days", result.certificate.validity_days);
            }
            Err(e) => {
                println!("  Error: {}", e);
            }
        }
        println!();
    }

    Ok(())
}
