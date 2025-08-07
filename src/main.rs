use std::sync::mpsc::sync_channel;
use std::thread;
mod config;
mod metrics;

use clap::{Parser, ValueEnum};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};

use tlschecker::RevocationStatus; // Import the new RevocationStatus enum
use tlschecker::TLS;
use url::Url;

use config::{Config, ConfigError};

/// Experimental TLS/SSL certificate checker
#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Args {
    /// A space-delimited hosts list to be checked
    #[clap(value_parser)]
    addresses: Vec<String>,

    /// Configuration file path (TOML format)
    #[arg(short, long)]
    config: Option<String>,

    /// Generate example configuration file
    #[arg(long)]
    generate_config: bool,

    /// Enable verbose to see what is going on
    #[arg(short, value_enum)]
    output: Option<OutFormat>,

    /// Exits with code 0 even when certificate expired is detected
    #[arg(long)]
    exit_code: Option<i32>,

    /// Enable prometheus push gateway metrics
    #[arg(long)]
    prometheus: Option<bool>,

    /// Prometheus push gateway address
    /// Default is http://localhost:9091
    #[arg(long)]
    prometheus_address: Option<String>,

    /// Enable certificate revocation checking
    #[arg(long, action = clap::ArgAction::SetTrue)]
    check_revocation: Option<bool>,
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

impl std::fmt::Display for OutFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutFormat::Json => write!(f, "json"),
            OutFormat::Text => write!(f, "text"),
            OutFormat::Summary => write!(f, "summary"),
        }
    }
}

impl std::str::FromStr for OutFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "json" => Ok(OutFormat::Json),
            "text" => Ok(OutFormat::Text),
            "summary" => Ok(OutFormat::Summary),
            _ => Err(format!("Invalid output format: {}", s)),
        }
    }
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
            println!("Self-signed: {}", cert.is_self_signed);
            println!("Expired: {}", cert.is_expired);
            println!("Certificate version: {}", cert.cert_ver);
            println!("Certificate algorithm: {}", cert.cert_alg);
            println!("Certificate S/N: {}", cert.cert_sn);

            // Add revocation status information
            println!(
                "Revocation Status: {}",
                match cert.revocation_status {
                    RevocationStatus::Good => "Good (Not Revoked)".to_string(),
                    RevocationStatus::Revoked(reason) => format!("Revoked ({})", reason),
                    RevocationStatus::Unknown => "Unknown (Could not determine)".to_string(),
                    RevocationStatus::NotChecked => "Not Checked".to_string(),
                }
            );

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
        if tls.is_empty() {
            return;
        }

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
                "Self-Signed",
                "Revocation",
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

            // Add revocation status cell
            let revocation_cell = match &rs.certificate.revocation_status {
                RevocationStatus::Good => Cell::new("Valid")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Green)
                    .set_alignment(CellAlignment::Center),
                RevocationStatus::Revoked(_) => Cell::new("Revoked")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Red)
                    .set_alignment(CellAlignment::Center),
                RevocationStatus::Unknown => Cell::new("Unknown")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Yellow)
                    .set_alignment(CellAlignment::Center),
                RevocationStatus::NotChecked => Cell::new("Not Checked")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::DarkGrey)
                    .set_alignment(CellAlignment::Center),
            };

            let self_signed_cell = match rs.certificate.is_self_signed {
                true => Cell::new("Yes")
                    .add_attribute(Attribute::Bold)
                    .fg(Color::Yellow)
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
                self_signed_cell,
                revocation_cell,
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
/// Struct to hold parsed host and port
struct HostPort {
    host: String,
    port: Option<u16>,
}

/// Struct to hold final configuration after merging CLI and file
struct FinalConfig {
    addresses: Vec<String>,
    output: OutFormat,
    exit_code: i32,
    prometheus: bool,
    prometheus_address: String,
    check_revocation: bool,
}

impl FinalConfig {
    fn from_merged_config(config: Config) -> Result<Self, ConfigError> {
        let addresses = config.hosts.unwrap_or_default();

        if addresses.is_empty() {
            return Err(ConfigError::Validation(
                "No hosts specified. Please provide at least one host via command line or config file.\n\
                 Usage: tlschecker <hosts...> [OPTIONS]\n\
                 Example: tlschecker example.com another.com:8443".to_string()
            ));
        }

        let output_str = config.output.unwrap_or_else(|| "summary".to_string());
        let output = output_str
            .parse::<OutFormat>()
            .map_err(ConfigError::Validation)?;

        let prometheus_config = config
            .prometheus
            .unwrap_or_else(|| config::PrometheusConfig {
                enabled: Some(false),
                address: Some("http://localhost:9091".to_string()),
            });

        Ok(FinalConfig {
            addresses,
            output,
            exit_code: config.exit_code.unwrap_or(0),
            prometheus: prometheus_config.enabled.unwrap_or(false),
            prometheus_address: prometheus_config
                .address
                .unwrap_or_else(|| "http://localhost:9091".to_string()),
            check_revocation: config.check_revocation.unwrap_or(false),
        })
    }
}

fn main() {
    let cli = Args::parse();

    // Handle config generation
    if cli.generate_config {
        println!("# TLSChecker Configuration File");
        println!(
            "# Save this as tlschecker.toml and use with: tlschecker --config tlschecker.toml"
        );
        println!();
        println!("{}", Config::example_toml());
        return;
    }

    // Load configuration
    let final_config = match load_config(&cli) {
        Ok(config) => config,
        Err(_e) => {
            eprintln!("Try running with --help for usage information");
            eprintln!("Or use --generate-config to create a sample configuration file");
            std::process::exit(1);
        }
    };

    let exit_code = final_config.exit_code;
    let mut failed_result = false;

    // Parse hosts and ports
    let hosts_and_ports: Vec<HostPort> = final_config
        .addresses
        .iter()
        .map(|address| parse_host_port(address))
        .collect();

    let size = hosts_and_ports.len();
    let (sender, receiver) = sync_channel(size);
    let hosts_len = hosts_and_ports.len();
    let check_revocation = final_config.check_revocation;

    thread::spawn(move || {
        for host_port in hosts_and_ports {
            let thread_tx = sender.clone();
            let check_revocation = check_revocation;
            let handle = thread::spawn(move || {
                let port_display = host_port.port.map_or(String::new(), |p| format!(":{}", p));

                match TLS::from(&host_port.host, host_port.port, check_revocation) {
                    Ok(cert) => {
                        thread_tx.send(cert).unwrap();
                    }
                    Err(err) => {
                        if err.details.contains("failed to lookup address information") {
                            eprintln!(
                                "ERROR: Cannot resolve hostname: {}{}",
                                host_port.host, port_display
                            );
                            eprintln!("  - Check that the hostname is spelled correctly");
                            eprintln!("  - Verify your network and DNS configuration");
                            eprintln!("  - Try using an IP address instead if DNS resolution is not available");
                        } else if err.details.contains("connection refused") {
                            eprintln!(
                                "ERROR: Connection refused for host: {}{}",
                                host_port.host, port_display
                            );
                            eprintln!(
                                "  - Verify the host is running a TLS service on port {}",
                                host_port.port.unwrap_or(443)
                            );
                            eprintln!("  - Check if a firewall might be blocking the connection");
                        } else if err.details.contains("certificate") {
                            eprintln!(
                                "ERROR: Certificate issue with host: {}{}",
                                host_port.host, port_display
                            );
                            eprintln!("  - Error details: {}", &err.details);
                        } else {
                            eprintln!(
                                "ERROR: Failed to check host: {}{}",
                                host_port.host, port_display
                            );
                            eprintln!("  - Error details: {}", &err.details);
                        }
                    }
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

    let revoked_certs = &results
        .clone()
        .into_iter()
        .filter(|c| {
            matches!(
                c.certificate.revocation_status,
                RevocationStatus::Revoked(_)
            )
        })
        .collect::<Vec<_>>();

    if !expired_certs.is_empty() || !revoked_certs.is_empty() {
        failed_result = true;
    }

    let formatter = match final_config.output {
        OutFormat::Json => FormatterFactory::new_formatter(&OutFormat::Json),
        OutFormat::Text => FormatterFactory::new_formatter(&OutFormat::Text),
        OutFormat::Summary => FormatterFactory::new_formatter(&OutFormat::Summary),
    };
    formatter.format(&results);

    if final_config.prometheus {
        metrics::prom::prometheus_metrics(results, final_config.prometheus_address);
    }

    exit(exit_code, failed_result);
}

/// Load and merge configuration from file and CLI arguments
fn load_config(cli: &Args) -> Result<FinalConfig, ConfigError> {
    // Start with default configuration
    let mut config = Config::default();

    // Load from config file if specified, otherwise try tlschecker.toml
    if let Some(config_path) = &cli.config {
        let file_config = Config::from_file(config_path)?;
        config = config.merge_with(file_config);
    } else {
        // Try to load from default tlschecker.toml if it exists
        if let Ok(file_config) = Config::from_file("tlschecker.toml") {
            config = config.merge_with(file_config);
        }
    }

    // Merge with CLI arguments (CLI takes precedence)
    let cli_addresses = if !cli.addresses.is_empty() {
        Some(cli.addresses.clone())
    } else {
        None
    };

    let cli_config = Config::from_cli_args(
        cli_addresses,
        cli.output.as_ref().map(|o| o.to_string()),
        cli.exit_code,
        cli.prometheus,
        cli.prometheus_address.clone(),
        cli.check_revocation,
    );

    config = config.merge_with(cli_config);

    // Convert to final configuration and validate
    FinalConfig::from_merged_config(config)
}

/// Exit function to handle exit codes
fn exit(exit_code: i32, failed_result: bool) {
    if exit_code != 0 && failed_result {
        std::process::exit(exit_code)
    }
}

// Function to parse a hostname with an optional port
fn parse_host_port(address: &str) -> HostPort {
    // Try to fix common user mistakes by adding https:// if missing a scheme
    let address_with_scheme = if !address.contains("://") {
        format!("https://{}", address)
    } else {
        address.to_string()
    };

    // Check if this might be a URL
    if let Ok(url) = Url::parse(&address_with_scheme) {
        // If it's a valid URL, extract host and port
        if let Some(host_str) = url.host_str() {
            return HostPort {
                host: host_str.to_string(),
                port: url.port(),
            };
        }
    }

    // Not a valid URL, check if it has a port specification (hostname:port)
    // This handles cases like "example.com:8443"
    if let Some((host, port_str)) = address.split_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            // Make sure we don't include IPv6 brackets in the hostname
            let clean_host = host.trim_start_matches('[').trim_end_matches(']');
            return HostPort {
                host: clean_host.to_string(),
                port: Some(port),
            };
        }
    }

    // No port specified, just a hostname
    // For IPv6 addresses, clean up any brackets
    let clean_address = address.trim_start_matches('[').trim_end_matches(']');
    HostPort {
        host: clean_address.to_string(),
        port: None,
    }
}
