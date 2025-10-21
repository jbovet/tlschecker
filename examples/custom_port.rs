//! Custom port checking example.
//!
//! This example demonstrates how to check TLS certificates on non-standard ports.
//!
//! Run with: cargo run --example custom_port

use tlschecker::TLS;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Custom Port Certificate Check ===\n");

    // Check certificate on standard HTTPS port (443)
    println!("Checking example.com:443 (standard HTTPS)...");
    match TLS::from("example.com", Some(443), false) {
        Ok(result) => {
            println!("  ✓ Certificate valid for {} days", result.certificate.validity_days);
            println!("  Issuer: {}", result.certificate.issued.organization);
        }
        Err(e) => {
            println!("  ✗ Error: {}", e);
        }
    }
    println!();

    // Check certificate on default port (None = 443)
    println!("Checking github.com (default port)...");
    match TLS::from("github.com", None, false) {
        Ok(result) => {
            println!("  ✓ Certificate valid for {} days", result.certificate.validity_days);
            println!("  Cipher: {}", result.cipher.name);
            println!("  Protocol: {}", result.cipher.version);
        }
        Err(e) => {
            println!("  ✗ Error: {}", e);
        }
    }
    println!();

    // Note: To test with a custom port, you would need a server listening on that port
    // Example: TLS::from("myserver.local", Some(8443), false)

    println!("Tip: Use custom ports for testing internal services or non-standard configurations");

    Ok(())
}
