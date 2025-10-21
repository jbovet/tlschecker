//! Basic certificate checking example.
//!
//! This example demonstrates how to perform a simple TLS certificate check
//! for a single host without revocation checking.
//!
//! Run with: cargo run --example basic_check

use tlschecker::TLS;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Basic TLS Certificate Check ===\n");

    // Check a certificate for google.com
    let result = TLS::from("google.com", None, false)?;

    println!("Certificate for: {}", result.certificate.hostname);
    println!("Subject: {}", result.certificate.subject.common_name);
    println!("Issuer: {}", result.certificate.issued.organization);
    println!("Valid from: {}", result.certificate.valid_from);
    println!("Valid to: {}", result.certificate.valid_to);
    println!("Days remaining: {}", result.certificate.validity_days);
    println!("Hours remaining: {}", result.certificate.validity_hours);
    println!("Is expired: {}", result.certificate.is_expired);
    println!("Is self-signed: {}", result.certificate.is_self_signed);
    println!();

    println!("Cipher Suite: {}", result.cipher.name);
    println!("Protocol Version: {}", result.cipher.version);
    println!();

    println!("Subject Alternative Names (SANs):");
    for san in &result.certificate.sans {
        println!("  - {}", san);
    }

    Ok(())
}
