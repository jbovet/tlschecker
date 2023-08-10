use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use clap::{Parser, ValueEnum};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};

use tlschecker::Certificate;

/// Experimental TLS/SSL certificate checker
#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Args {
    /// A space-delimited hosts list to be checked
    addresses: Vec<String>,

    /// Enable verbose to see what is going on
    #[arg(short, value_enum, default_value_t = OutFormat::Summary)]
    output: OutFormat,

    /// Exits with code 0 even when certificate expired is detected
    #[arg(long, default_value_t = 0)]
    exit_code: i32,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutFormat {
    /// Enable JSON in the output
    Json,
    /// Enable Text in the output
    Text,
    /// Summary by default
    Summary,
}

trait Formatter {
    fn format(&self, certificates: &[Certificate]);
}

struct TextFormat;

struct JsonFormat;

struct SummaryFormat;

impl Formatter for TextFormat {
    fn format(&self, certificates: &[Certificate]) {
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
            println!("Hours left: {}", cert.validity_hours);
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

impl Formatter for SummaryFormat {
    fn format(&self, certificates: &[Certificate]) {
        let mut table = Table::new();

        table
            .set_content_arrangement(ContentArrangement::Dynamic)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .load_preset(UTF8_FULL)
            .set_header(vec![
                "Host",
                "Expired",
                "Status",
                "Days before expired",
                "Hours before expired",
            ]);

        for cert in certificates {
            let custom_cell = match cert.validity_days {
                days if days <= 0 => Cell::new("ERROR")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Red)
                    .set_alignment(CellAlignment::Center),
                days if days <= 15 => Cell::new("WARNING")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Yellow)
                    .set_alignment(CellAlignment::Center),
                _ => Cell::new("OK")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Green)
                    .set_alignment(CellAlignment::Center),
            };

            table.add_row(vec![
                Cell::new(&cert.hostname)
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Green),
                Cell::new(cert.is_expired)
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Blue)
                    .set_alignment(CellAlignment::Center),
                custom_cell,
                Cell::new(cert.validity_days).set_alignment(CellAlignment::Center),
                Cell::new(cert.validity_hours).set_alignment(CellAlignment::Center),
            ]);
        }
        println!("{table}");
    }
}

impl Formatter for JsonFormat {
    fn format(&self, certificates: &[Certificate]) {
        println!("{}", serde_json::to_string_pretty(&certificates).unwrap());
    }
}

struct FormatterFactory;

impl FormatterFactory {
    fn new_formatter(s: &OutFormat) -> Box<dyn Formatter> {
        match s {
            OutFormat::Json => Box::new(JsonFormat {}),
            OutFormat::Text => Box::new(TextFormat {}),
            OutFormat::Summary => Box::new(SummaryFormat {}),
        }
    }
}

fn main() {
    let cli = Args::parse();
    let exit_code = cli.exit_code;
    let mut failed_result = false;

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

    let expired_certs = &certificates
        .clone()
        .into_iter()
        .filter(|c| c.is_expired)
        .collect::<Vec<_>>();

    if !expired_certs.is_empty() {
        failed_result = true;
    }

    let formatter = match cli.output {
        OutFormat::Json => FormatterFactory::new_formatter(&OutFormat::Json),
        OutFormat::Text => FormatterFactory::new_formatter(&OutFormat::Text),
        OutFormat::Summary => FormatterFactory::new_formatter(&OutFormat::Summary),
    };

    formatter.format(&certificates);

    exit(exit_code, failed_result);
}

fn exit(exit_code: i32, failed_result: bool) {
    if exit_code != 0 && failed_result {
        std::process::exit(exit_code)
    }
}
