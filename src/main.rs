use std::sync::mpsc::sync_channel;
use std::thread;
mod metrics;

use clap::{Parser, ValueEnum};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};

use tlschecker::TLS;
use url::Url;

/// Experimental TLS/SSL certificate checker
#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Args {
    /// A space-delimited hosts list to be checked
    #[clap(value_parser, required = true)]
    addresses: Vec<String>,

    /// Enable verbose to see what is going on
    #[arg(short, value_enum, default_value_t = OutFormat::Summary)]
    output: OutFormat,

    /// Exits with code 0 even when certificate expired is detected
    #[arg(long, default_value_t = 0)]
    exit_code: i32,

    /// Enable prometheus push gateway metrics
    #[arg(long)]
    prometheus: bool,

    /// Prometheus push gateway address
    /// Default is http://localhost:9091
    #[arg(long, default_value = "http://localhost:9091")]
    prometheus_address: String,
}

/// Output format
/// Json, Text, Summary
/// Default is Summary
/// Json: Output as JSON format
/// Text: Output as text format
/// Summary: Output as summary format
/// Summary format is a table with the following columns:
/// Host, Expired, Status, Days before expired, Hours before expired
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutFormat {
    /// Enable JSON in the output
    Json,
    /// Enable Text in the output
    Text,
    /// Summary by default
    Summary,
}

/// Output Formatter trait
trait Formatter {
    fn format(&self, tls: &[TLS]);
}

/// Text format
struct TextFormat;

/// JSON format
struct JsonFormat;

/// Summary format
struct SummaryFormat;

/// Implement Formatter trait for TextFormat
impl Formatter for TextFormat {
    fn format(&self, tls: &[TLS]) {
        let certificates = tls
            .iter()
            .map(|c| c.certificate.clone())
            .collect::<Vec<_>>();

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

/// Implement Formatter trait for SummaryFormat
impl Formatter for SummaryFormat {
    fn format(&self, tls: &[TLS]) {
        let mut table = Table::new();

        table
            .set_content_arrangement(ContentArrangement::Dynamic)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .load_preset(UTF8_FULL)
            .set_header(vec![
                "Host",
                "Cipher Suite",
                "Protocol",
                "Issuer",
                "Expired",
                "Days before expired",
                "Hours before expired",
                "Status",
            ]);

        for rs in tls {
            let custom_cell: Cell = match rs.certificate.validity_days {
                days if days <= 15 => Cell::new("Critical")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Red)
                    .set_alignment(CellAlignment::Center),
                days if days <= 30 => Cell::new("Warning")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Yellow)
                    .set_alignment(CellAlignment::Center),
                _ => Cell::new("Healthy")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Green)
                    .set_alignment(CellAlignment::Center),
            };

            let expired_cell = match rs.certificate.is_expired {
                true => Cell::new("Yes")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Red)
                    .set_alignment(CellAlignment::Center),
                false => Cell::new("No")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Green)
                    .set_alignment(CellAlignment::Center),
            };
            table.add_row(vec![
                Cell::new(&rs.certificate.hostname)
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Green),
                Cell::new(&rs.cipher.name)
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Green),
                Cell::new(&rs.cipher.version)
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Green),
                Cell::new(&rs.certificate.issued.organization)
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Blue),
                expired_cell,
                Cell::new(rs.certificate.validity_days).set_alignment(CellAlignment::Center),
                Cell::new(rs.certificate.validity_hours).set_alignment(CellAlignment::Center),
                custom_cell,
            ]);
        }
        println!("{table}");
    }
}

/// Implement Formatter trait for JsonFormat
impl Formatter for JsonFormat {
    fn format(&self, tls: &[TLS]) {
        println!(
            "{}",
            serde_json::to_string_pretty(&tls).expect("Failed to format certificates as JSON")
        );
    }
}
/// FormatterFactory
struct FormatterFactory;

/// FormatterFactory implementation
impl FormatterFactory {
    fn new_formatter(s: &OutFormat) -> Box<dyn Formatter> {
        match s {
            OutFormat::Json => Box::new(JsonFormat {}),
            OutFormat::Text => Box::new(TextFormat {}),
            OutFormat::Summary => Box::new(SummaryFormat {}),
        }
    }
}

/// Main function
fn main() {
    let cli = Args::parse();
    let exit_code = cli.exit_code;
    let mut failed_result = false;
    //remove schema from the host
    let hosts: Vec<String> = cli
        .addresses
        .iter()
        .map(|address| {
            Url::parse(&address)
                .ok()
                .and_then(|url| url.host_str().map(String::from))
                .unwrap_or_else(|| address.clone())
        })
        .collect();

    let size = hosts.len();
    let (sender, receiver) = sync_channel(size);
    let hosts_len = hosts.len();
    thread::spawn(move || {
        for host in hosts {
            let thread_tx = sender.clone();
            let handle = thread::spawn(move || match TLS::from(&host) {
                Ok(cert) => {
                    thread_tx.send(cert).unwrap();
                }
                Err(err) => {
                    println!("Fail to check host: {}  {} ", &host, &err.details);
                }
            });
            handle.join().unwrap();
        }
    });

    let mut results: Vec<TLS> = Vec::with_capacity(hosts_len);

    for tls_result in receiver {
        results.push(tls_result);
    }

    let expired_certs = &results
        .clone()
        .into_iter()
        .filter(|c| c.certificate.is_expired)
        .collect::<Vec<_>>();

    if !expired_certs.is_empty() {
        failed_result = true;
    }

    let formatter = match cli.output {
        OutFormat::Json => FormatterFactory::new_formatter(&OutFormat::Json),
        OutFormat::Text => FormatterFactory::new_formatter(&OutFormat::Text),
        OutFormat::Summary => FormatterFactory::new_formatter(&OutFormat::Summary),
    };
    formatter.format(&results);

    if cli.prometheus {
        metrics::prom::prometheus_metrics(results, cli.prometheus_address);
    }

    exit(exit_code, failed_result);
}

fn exit(exit_code: i32, failed_result: bool) {
    if exit_code != 0 && failed_result {
        std::process::exit(exit_code)
    }
}
