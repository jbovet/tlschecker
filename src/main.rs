use clap::{Parser, ValueEnum};
use std::process::exit;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;
use tlschecker::Certificate;

/// Experimental TLS/SSL certificate checker
#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Args {
    /// A comma-delimited hosts list to be checked
    addresses: Vec<String>,

    /// Enable verbose to see what is going on
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Enable verbose to see what is going on
    #[arg(short, value_enum, default_value_t=OutFormat::Text)]
    output: OutFormat,
}
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutFormat {
    /// Enable JSON in the output
    Json,
    /// Enable Text in the output
    Text,
}

trait Formatter {
    fn format(&self, certificates: &Vec<Certificate>);
}

struct TextFormat;

impl Formatter for TextFormat {
    fn format(&self, certificates: &Vec<Certificate>) {
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
            for san in &cert.sans {
                println!("\tDNS Name: {}", san);
            }

            match &cert.chain {
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
}

struct JsonFormat;

impl Formatter for JsonFormat {
    fn format(&self, certificates: &Vec<Certificate>) {
        println!("{}", serde_json::to_string_pretty(&certificates).unwrap());
    }
}

struct FormatterFactory;

impl FormatterFactory {
    fn new_formatter(s: &OutFormat) -> Box<dyn Formatter> {
        match s {
            OutFormat::Json => Box::new(JsonFormat {}),
            OutFormat::Text => Box::new(TextFormat {}),
        }
    }
}

fn main() {
    let cli = Args::parse();

    let formatter = match cli.output {
        OutFormat::Json => FormatterFactory::new_formatter(&OutFormat::Json),
        OutFormat::Text => FormatterFactory::new_formatter(&OutFormat::Text),
    };

    let (sender, receiver): (Sender<Certificate>, Receiver<Certificate>) = mpsc::channel();
    let hosts: Vec<String> = cli.addresses.iter().map(String::from).collect();
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

    formatter.format(&certificates);
    exit(0);
}
