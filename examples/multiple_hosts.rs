//! Multi-threaded certificate checking example.
//!
//! This example demonstrates how to check multiple hosts concurrently
//! using threads for better performance.
//!
//! Run with: cargo run --example multiple_hosts

use std::sync::mpsc;
use std::thread;
use tlschecker::TLS;

fn main() {
    println!("=== Multi-Host Certificate Check ===\n");

    let hosts = vec![
        ("google.com", None),
        ("github.com", None),
        ("rust-lang.org", None),
        ("crates.io", None),
        ("docs.rs", None),
    ];

    let (tx, rx) = mpsc::channel();

    // Spawn a thread for each host
    for (host, port) in hosts.clone() {
        let tx = tx.clone();
        thread::spawn(move || {
            let result = TLS::from(host, port, false);
            tx.send((host, result)).unwrap();
        });
    }

    // Drop the original sender so the receiver knows when all threads are done
    drop(tx);

    // Collect and display results
    let mut results: Vec<_> = rx.iter().collect();
    results.sort_by_key(|(host, _)| *host);

    println!("{:<20} {:<15} {:<10} {}", "Host", "Status", "Days Left", "Issuer");
    println!("{}", "=".repeat(70));

    for (host, result) in results {
        match result {
            Ok(cert) => {
                let status = if cert.certificate.is_expired {
                    "EXPIRED"
                } else if cert.certificate.validity_days <= 30 {
                    "WARNING"
                } else {
                    "VALID"
                };

                println!(
                    "{:<20} {:<15} {:<10} {}",
                    host, status, cert.certificate.validity_days, cert.certificate.issued.organization
                );
            }
            Err(e) => {
                println!("{:<20} ERROR: {}", host, e);
            }
        }
    }
}
