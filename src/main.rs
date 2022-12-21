use clap::{App, Arg};
use std::process::exit;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use tlschecker::Certificate;

fn main() {
    let matches = App::new("tlschecker")
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .long_about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(
            Arg::with_name("addresses")
                .short("a")
                .takes_value(true)
                .multiple(true)
                .required(true)
                .help("A comma-delimited hosts list to be checked"),
        )
        .arg(
            Arg::with_name("json")
                .long("json")
                .help("Prints json output"),
        )
        .arg(
            Arg::with_name("chain")
                .long("chain")
                .help("Prints the certificate chain of the peer, if present."),
        )
        .get_matches();

    let (sender, receiver): (Sender<Certificate>, Receiver<Certificate>) = mpsc::channel();
    let hosts: Vec<String> = matches
        .values_of("addresses")
        .unwrap()
        .map(String::from)
        .collect();
    let hosts_len = hosts.len();
    thread::spawn(move || {
        for host in hosts {
            let thread_tx = sender.clone();
            thread::spawn(move || match Certificate::from(&host) {
                Ok(cert) => {
                    thread_tx.send(cert).unwrap();
                }
                Err(err) => {
                    println!("Fail to check host: {}  {} ", &host, &err.details);
                }
            });
        }
    });

    let mut certificates: Vec<Certificate> = Vec::with_capacity(hosts_len);
    for cert in receiver {
        certificates.push(cert);
    }

    if !matches.is_present("json") {
        for cert in certificates {
            println!("--------------------------------------");
            println!("Hostname: {}", cert.hostname);
            println!("Issued domain: {}", cert.subject.common_name);
            println!("Subject Name :");
            println!("\tCountry or Region: {}", cert.subject.country_or_region);
            println!("\tState or Province: {}", cert.subject.state_or_province);
            println!("\tLocality: {}", cert.subject.locality);
            println!("\tOrganizational Unit: {}", cert.subject.organization_unit);
            println!("\tOrganization: {}", cert.subject.organization);
            println!("\tCommon Name: {}", cert.subject.common_name);
            println!("Issuer Name:");
            println!("\tCountry or Region: {}", cert.issued.country_or_region);
            println!("\tOrganization: {}", cert.issued.organization);
            println!("\tCommon Name: {}", cert.issued.common_name);
            println!("Valid from: {}", cert.valid_from);
            println!("Valid to: {}", cert.valid_to);
            println!("Days left: {}", cert.validity_days);
            println!("Expired: {}", cert.is_expired);
            println!("Certificate version: {}", cert.cert_ver);
            println!("Certificate algorithm: {}", cert.cert_alg);
            println!("Certificate S/N: {}", cert.cert_sn);
            println!("Subject Alternative Names:");
            for san in cert.sans {
                println!("\tDNS Name: {}", san);
            }
            if matches.is_present("chain") {
                match cert.chain {
                    Some(chains) => {
                        println!("Additional Certificates (if supplied):");
                        for (i, c) in chains.iter().enumerate() {
                            println!("Chain #{:?}", i + 1);
                            println!("\tSubject: {:?}", c.subject);
                            println!("\tValid from: {:?}", c.valid_from);
                            println!("\tValid until: {:?}", c.valid_to);
                            println!("\tIssuer: {:?}", c.issuer);
                            println!("\tSignature algorithm: {:?}", c.signature_algorithm);
                        }
                    }
                    None => todo!(),
                }
            }
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&certificates).unwrap());
    }

    exit(0);
}
