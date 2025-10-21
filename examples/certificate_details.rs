//! Detailed certificate information example.
//!
//! This example shows how to extract and display comprehensive
//! certificate details including subject, issuer, SANs, and chain.
//!
//! Run with: cargo run --example certificate_details

use tlschecker::TLS;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Detailed Certificate Information ===\n");

    let result = TLS::from("github.com", None, false)?;
    let cert = &result.certificate;

    println!("┌─ Certificate Information");
    println!("│");
    println!("├─ Hostname: {}", cert.hostname);
    println!("├─ Serial Number: {}", cert.cert_sn);
    println!("├─ Version: {}", cert.cert_ver);
    println!("├─ Algorithm: {}", cert.cert_alg);
    println!("│");

    println!("├─ Subject:");
    println!("│  ├─ Common Name: {}", cert.subject.common_name);
    println!("│  ├─ Organization: {}", cert.subject.organization);
    println!("│  ├─ Org Unit: {}", cert.subject.organization_unit);
    println!("│  ├─ Locality: {}", cert.subject.locality);
    println!("│  ├─ State: {}", cert.subject.state_or_province);
    println!("│  └─ Country: {}", cert.subject.country_or_region);
    println!("│");

    println!("├─ Issuer:");
    println!("│  ├─ Common Name: {}", cert.issued.common_name);
    println!("│  ├─ Organization: {}", cert.issued.organization);
    println!("│  └─ Country: {}", cert.issued.country_or_region);
    println!("│");

    println!("├─ Validity:");
    println!("│  ├─ From: {}", cert.valid_from);
    println!("│  ├─ To: {}", cert.valid_to);
    println!("│  ├─ Days Remaining: {}", cert.validity_days);
    println!("│  ├─ Hours Remaining: {}", cert.validity_hours);
    println!("│  └─ Expired: {}", cert.is_expired);
    println!("│");

    println!("├─ Subject Alternative Names:");
    for (i, san) in cert.sans.iter().enumerate() {
        let prefix = if i == cert.sans.len() - 1 { "└─" } else { "├─" };
        println!("│  {} {}", prefix, san);
    }
    println!("│");

    println!("├─ Properties:");
    println!("│  ├─ Self-Signed: {}", cert.is_self_signed);
    println!("│  └─ Revocation Status: {:?}", cert.revocation_status);
    println!("│");

    if let Some(chain) = &cert.chain {
        println!("├─ Certificate Chain ({} certificates):", chain.len());
        for (i, chain_cert) in chain.iter().enumerate() {
            let prefix = if i == chain.len() - 1 { "└─" } else { "├─" };
            println!("│  {} Certificate #{}", prefix, i + 1);
            println!("│     ├─ Subject: {}", chain_cert.subject);
            println!("│     ├─ Issuer: {}", chain_cert.issuer);
            println!("│     └─ Valid Until: {}", chain_cert.valid_to);
        }
    }
    println!("│");

    println!("└─ TLS Connection:");
    println!("   ├─ Cipher Suite: {}", result.cipher.name);
    println!("   └─ Protocol Version: {}", result.cipher.version);

    Ok(())
}
