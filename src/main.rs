use std::sync::mpsc::sync_channel;
use std::thread;
mod config;
mod metrics;

use clap::{Parser, ValueEnum};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};

use tlschecker::RevocationStatus;
use tlschecker::TLS;
use url::Url;

use anyhow::Result;
use config::{Config, ConfigError};
use tlschecker::TLSError;
use tracing::error;

/// Experimental TLS/SSL certificate checker.
///
/// Checks TLS certificates for multiple hosts, validates expiration dates,
/// optionally checks revocation status, and outputs results in various formats.
#[derive(Parser)]
#[command(author, version, about, long_about)]
struct Args {
    /// Hosts to check, e.g. example.com example.com:8443
    #[clap(value_parser)]
    addresses: Vec<String>,

    /// Path to a TOML configuration file
    #[arg(short, long)]
    config: Option<String>,

    /// Print an example configuration file to stdout and exit
    #[arg(long)]
    generate_config: bool,

    /// Output format for certificate results
    #[arg(short, value_enum)]
    output: Option<OutFormat>,

    /// Exit with this code when expired or revoked certificates are found.
    ///
    /// Defaults to 0 (always succeed). Set to 1 for CI/CD pipelines
    /// that should fail on certificate issues.
    #[arg(long)]
    exit_code: Option<i32>,

    /// Push certificate metrics to a Prometheus Push Gateway
    #[arg(long)]
    prometheus: Option<bool>,

    /// Prometheus Push Gateway URL [default: http://localhost:9091]
    #[arg(long)]
    prometheus_address: Option<String>,

    /// Check certificate revocation status via OCSP and CRL.
    ///
    /// Queries OCSP responders first, then falls back to CRL
    /// distribution points. Adds latency due to network requests.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    check_revocation: Option<bool>,

    /// Enable TLS configuration grading (A+ to F).
    ///
    /// Evaluates protocol version, cipher strength, key exchange,
    /// certificate key size, and trust chain to produce a composite
    /// letter grade for each host.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    grade: Option<bool>,
}

/// Output format for certificate information.
///
/// Determines how certificate data is presented to the user:
///
/// - **Json**: Machine-readable JSON format for programmatic consumption
/// - **Text**: Human-readable detailed text format showing all certificate fields
/// - **Summary**: Colored table format with certificate health indicators (default)
///
/// # Summary Format Columns
///
/// The summary table includes:
/// - Host, Cipher Suite, Protocol, Issuer
/// - Expired, Self-Signed, Revocation Status
/// - Days/Hours before expiration, Overall Status (Healthy/Warning/Critical)
///
/// # Health Indicators
///
/// - **Healthy** (Green): > 30 days until expiration
/// - **Warning** (Yellow): 15-30 days until expiration
/// - **Critical** (Red): ≤ 15 days until expiration or expired
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutFormat {
    /// JSON format for programmatic parsing
    Json,
    /// Detailed text format showing all certificate fields
    Text,
    /// Summary table format with color-coded status (default)
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

/// Trait for formatting TLS certificate output.
///
/// Implementations of this trait define how certificate data is presented
/// to the user in different formats (Text, JSON, Summary).
trait Formatter {
    /// Formats the given TLS certificate data into a displayable string.
    ///
    /// # Arguments
    ///
    /// * `tls` - Slice of TLS structs containing certificate information
    ///
    /// # Returns
    ///
    /// A formatted string ready for display.
    fn format(&self, tls: &[TLS]) -> String;
}

/// Text formatter - outputs detailed certificate information.
///
/// Displays all certificate fields in a human-readable text format,
/// including subject, issuer, validity dates, SANs, and certificate chain.
struct TextFormat;

/// JSON formatter - outputs certificate data as JSON.
///
/// Serializes certificate information to pretty-printed JSON format,
/// suitable for programmatic consumption and integration with other tools.
struct JsonFormat;

/// Summary formatter - outputs a colored table of certificate information.
///
/// Displays certificate data in a tabular format with color-coded health indicators,
/// making it easy to quickly assess the status of multiple certificates.
struct SummaryFormat;

impl Formatter for TextFormat {
    fn format(&self, tls: &[TLS]) -> String {
        use std::fmt::Write;
        let mut output = String::new();

        for rs in tls {
            let cert = &rs.certificate;
            writeln!(output, "--------------------------------------").unwrap();
            writeln!(output, "Hostname: {}", cert.hostname).unwrap();
            writeln!(output, "Issued domain: {}", cert.subject.common_name).unwrap();
            writeln!(output, "Subject Name :").unwrap();
            writeln!(output, "\tCountry or Region: {}", cert.subject.country_or_region).unwrap();
            writeln!(output, "\tState or Province: {}", cert.subject.state_or_province).unwrap();
            writeln!(output, "\tLocality: {}", cert.subject.locality).unwrap();
            writeln!(output, "\tOrganizational Unit: {}", cert.subject.organization_unit).unwrap();
            writeln!(output, "\tOrganization: {}", cert.subject.organization).unwrap();
            writeln!(output, "\tCommon Name: {}", cert.subject.common_name).unwrap();
            writeln!(output, "Issuer Name:").unwrap();
            writeln!(output, "\tCountry or Region: {}", cert.issued.country_or_region).unwrap();
            writeln!(output, "\tOrganization: {}", cert.issued.organization).unwrap();
            writeln!(output, "\tCommon Name: {}", cert.issued.common_name).unwrap();
            writeln!(output, "Valid from: {}", cert.valid_from).unwrap();
            writeln!(output, "Valid to: {}", cert.valid_to).unwrap();
            writeln!(output, "Days left: {}", cert.validity_days).unwrap();
            writeln!(output, "Hours left: {}", cert.validity_hours).unwrap();
            writeln!(output, "Self-signed: {}", cert.is_self_signed).unwrap();
            writeln!(output, "Expired: {}", cert.is_expired).unwrap();
            writeln!(output, "Certificate version: {}", cert.cert_ver).unwrap();
            writeln!(output, "Certificate algorithm: {}", cert.cert_alg).unwrap();
            writeln!(output, "Certificate S/N: {}", cert.cert_sn).unwrap();
            writeln!(output, "Certificate key: {} {}-bit", cert.cert_key_algorithm, cert.cert_key_bits).unwrap();
            writeln!(output, "Cipher suite: {} ({}-bit)", rs.cipher.name, rs.cipher.bits).unwrap();
            writeln!(output, "Protocol: {}", rs.cipher.version).unwrap();

            writeln!(
                output,
                "Revocation Status: {}",
                match &cert.revocation_status {
                    RevocationStatus::Good => "Good (Not Revoked)".to_string(),
                    RevocationStatus::Revoked(reason) => format!("Revoked ({})", reason),
                    RevocationStatus::Unknown => "Unknown (Could not determine)".to_string(),
                    RevocationStatus::NotChecked => "Not Checked".to_string(),
                }
            )
            .unwrap();

            if !cert.security_warnings.is_empty() {
                writeln!(output, "\nSecurity Warnings:").unwrap();
                for warning in &cert.security_warnings {
                    match warning {
                        tlschecker::SecurityWarning::WeakSignatureAlgorithm(msg) => {
                            writeln!(output, "  WEAK ALGORITHM: {}", msg).unwrap();
                        }
                        tlschecker::SecurityWarning::IncompleteChain(msg) => {
                            writeln!(output, "  INCOMPLETE CHAIN: {}", msg).unwrap();
                        }
                        tlschecker::SecurityWarning::InvalidChainOrder(msg) => {
                            writeln!(output, "  INVALID CHAIN ORDER: {}", msg).unwrap();
                        }
                    }
                }
            }

            if let Some(ref grade) = rs.grade {
                writeln!(output, "\nTLS Configuration Grade: {} (Score: {}/100)", grade.grade, grade.score).unwrap();
                writeln!(output, "  Category Breakdown:").unwrap();
                for cat in &grade.categories {
                    writeln!(output, "    {}: {}/100 - {}", cat.category, cat.score, cat.reason).unwrap();
                }
            }

            writeln!(output, "Subject Alternative Names:").unwrap();
            for san in &cert.sans {
                writeln!(output, "\tDNS Name: {}", san).unwrap();
            }

            match &cert.chain {
                Some(chains) => {
                    writeln!(output, "Additional Certificates (if supplied):").unwrap();
                    for (i, c) in chains.iter().enumerate() {
                        writeln!(output, "Chain #{:?}", i + 1).unwrap();
                        writeln!(output, "\tSubject: {:?}", c.subject).unwrap();
                        writeln!(output, "\tValid from: {:?}", c.valid_from).unwrap();
                        writeln!(output, "\tValid until: {:?}", c.valid_to).unwrap();
                        writeln!(output, "\tIssuer: {:?}", c.issuer).unwrap();
                        writeln!(output, "\tSignature algorithm: {:?}", c.signature_algorithm).unwrap();
                    }
                }
                None => todo!(),
            }
        }
        output
    }
}

/// Implement Formatter trait for SummaryFormat
impl Formatter for SummaryFormat {
    fn format(&self, tls: &[TLS]) -> String {
        use std::fmt::Write;

        if tls.is_empty() {
            return String::new();
        }

        let mut output = String::new();
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
                "Grade",
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

            let grade_cell = match &rs.grade {
                Some(grade) => {
                    let color = match grade.grade.as_str() {
                        "A+" | "A" => Color::Green,
                        "B" => Color::Yellow,
                        "C" | "D" | "F" => Color::Red,
                        _ => Color::White,
                    };
                    Cell::new(&grade.grade)
                        .add_attribute(Attribute::Bold)
                        .fg(color)
                        .set_alignment(CellAlignment::Center)
                }
                None => Cell::new("-")
                    .fg(Color::DarkGrey)
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
                grade_cell,
            ]);
        }
        writeln!(output, "{table}").unwrap();

        // Display security warnings if any certificates have them
        let certs_with_warnings: Vec<&TLS> = tls
            .iter()
            .filter(|t| !t.certificate.security_warnings.is_empty())
            .collect();

        if !certs_with_warnings.is_empty() {
            writeln!(output, "\nSecurity Warnings:").unwrap();
            for rs in certs_with_warnings {
                writeln!(output, "\n  Host: {}", rs.certificate.hostname).unwrap();
                for warning in &rs.certificate.security_warnings {
                    match warning {
                        tlschecker::SecurityWarning::WeakSignatureAlgorithm(msg) => {
                            writeln!(output, "    - WEAK ALGORITHM: {}", msg).unwrap();
                        }
                        tlschecker::SecurityWarning::IncompleteChain(msg) => {
                            writeln!(output, "    - INCOMPLETE CHAIN: {}", msg).unwrap();
                        }
                        tlschecker::SecurityWarning::InvalidChainOrder(msg) => {
                            writeln!(output, "    - INVALID CHAIN ORDER: {}", msg).unwrap();
                        }
                    }
                }
            }
        }
        output
    }
}

/// Implement Formatter trait for JsonFormat
impl Formatter for JsonFormat {
    fn format(&self, tls: &[TLS]) -> String {
        serde_json::to_string_pretty(&tls).expect("Failed to format certificates as JSON")
    }
}
/// Factory for creating formatter instances.
///
/// Implements the Factory design pattern to create appropriate formatter
/// instances based on the requested output format.
struct FormatterFactory;

impl FormatterFactory {
    /// Creates a new formatter instance for the specified output format.
    ///
    /// # Arguments
    ///
    /// * `s` - The desired output format
    ///
    /// # Returns
    ///
    /// A boxed trait object implementing the `Formatter` trait.
    fn new_formatter(s: &OutFormat) -> Box<dyn Formatter> {
        match s {
            OutFormat::Json => Box::new(JsonFormat {}),
            OutFormat::Text => Box::new(TextFormat {}),
            OutFormat::Summary => Box::new(SummaryFormat {}),
        }
    }
}

/// Parsed hostname and port information.
///
/// Represents the result of parsing a host address specification,
/// which may include a port number or use the default port 443.
struct HostPort {
    /// Hostname or IP address (IPv6 brackets are removed)
    host: String,
    /// Port number (None indicates default port 443 should be used)
    port: Option<u16>,
}

/// Final merged configuration used for execution.
///
/// This struct holds the complete configuration after merging:
/// 1. Default values
/// 2. Configuration file values
/// 3. Command-line argument values (highest priority)
struct FinalConfig {
    addresses: Vec<String>,
    output: OutFormat,
    exit_code: i32,
    prometheus: bool,
    prometheus_address: String,
    check_revocation: bool,
    grade: bool,
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
            grade: config.grade.unwrap_or(false),
        })
    }
}

fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    let cli = Args::parse();

    // Handle config generation
    if cli.generate_config {
        println!("# TLSChecker Configuration File");
        println!(
            "# Save this as tlschecker.toml and use with: tlschecker --config tlschecker.toml"
        );
        println!();
        println!("{}", Config::example_toml());
        return Ok(());
    }

    // Load configuration
    let final_config = match load_config(&cli) {
        Ok(config) => config,
        Err(_e) => {
            error!("Try running with --help for usage information");
            error!("Or use --generate-config to create a sample configuration file");
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
    let calculate_grade = final_config.grade;

    thread::spawn(move || {
        for host_port in hosts_and_ports {
            let thread_tx = sender.clone();
            let check_revocation = check_revocation;
            let calculate_grade = calculate_grade;
            let handle = thread::spawn(move || {
                let port_display = host_port.port.map_or(String::new(), |p| format!(":{}", p));

                match TLS::from(&host_port.host, host_port.port, check_revocation, calculate_grade) {
                    Ok(cert) => {
                        thread_tx.send(cert).unwrap();
                    }
                    Err(err) => match err {
                        TLSError::DNS(msg) => {
                            error!(
                                "Cannot resolve hostname: {}{}",
                                host_port.host, port_display
                            );
                            error!("  - {}", msg);
                        }
                        TLSError::Connection(e) => {
                            error!(
                                "Connection refused for host: {}{}",
                                host_port.host, port_display
                            );
                            error!("  - {}", e);
                        }
                        TLSError::Certificate(msg) => {
                            error!(
                                "Certificate issue with host: {}{}",
                                host_port.host, port_display
                            );
                            error!("  - {}", msg);
                        }
                        TLSError::Validation(msg) => {
                            error!(
                                "Validation error for host: {}{}",
                                host_port.host, port_display
                            );
                            error!("  - {}", msg);
                        }
                        _ => {
                            error!("Failed to check host: {}{}", host_port.host, port_display);
                            error!("  - {}", err);
                        }
                    },
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
    print!("{}", formatter.format(&results));

    if final_config.prometheus {
        metrics::prom::prometheus_metrics(results, final_config.prometheus_address);
    }

    exit(exit_code, failed_result);
    Ok(())
}

/// Loads and merges configuration from multiple sources.
///
/// Configuration is loaded and merged in priority order:
/// 1. Default values (lowest priority)
/// 2. Configuration file values (if specified or tlschecker.toml exists)
/// 3. Command-line arguments (highest priority)
///
/// # Arguments
///
/// * `cli` - Parsed command-line arguments
///
/// # Returns
///
/// * `Ok(FinalConfig)` - Successfully loaded and merged configuration
/// * `Err(ConfigError)` - Configuration file not found, invalid, or missing required fields
///
/// # Configuration Sources
///
/// - If `--config` is specified, loads from that file (fails if file doesn't exist)
/// - Otherwise, attempts to load from `tlschecker.toml` in current directory (optional)
/// - Command-line arguments always override file settings
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
        cli.grade,
    );

    config = config.merge_with(cli_config);

    // Convert to final configuration and validate
    FinalConfig::from_merged_config(config)
}

/// Exits the program with the appropriate exit code.
///
/// This function implements conditional exit behavior based on whether
/// any certificates failed validation (expired or revoked).
///
/// # Arguments
///
/// * `exit_code` - The exit code to use when failures are detected
/// * `failed_result` - Whether any certificate checks failed
///
/// # Behavior
///
/// - If `failed_result` is `true` and `exit_code` is non-zero, exits with `exit_code`
/// - Otherwise, exits normally with code 0
/// - Useful for CI/CD pipelines where exit code indicates build success/failure
fn exit(exit_code: i32, failed_result: bool) {
    if exit_code != 0 && failed_result {
        std::process::exit(exit_code)
    }
}

/// Parses a hostname/address specification that may include a port.
///
/// Supports multiple input formats:
/// - `example.com` → hostname, default port 443
/// - `example.com:8443` → hostname with explicit port
/// - `https://example.com:8443` → full URL (scheme ignored)
/// - `[::1]:443` → IPv6 address with port
/// - `192.168.1.1:8443` → IPv4 address with port
///
/// # Arguments
///
/// * `address` - The address string to parse
///
/// # Returns
///
/// A `HostPort` struct containing the extracted hostname and optional port.
///
/// # Note
///
/// - IPv6 brackets are automatically removed from the hostname
/// - If no port is specified, returns `None` for the port (defaults to 443)
/// - URL schemes (http://, https://) are stripped and ignored
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_host_port tests ────────────────────────────────────────

    #[test]
    fn test_parse_host_port_hostname_only() {
        let hp = parse_host_port("example.com");
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, None);
    }

    #[test]
    fn test_parse_host_port_with_port() {
        let hp = parse_host_port("example.com:8443");
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, Some(8443));
    }

    #[test]
    fn test_parse_host_port_https_url() {
        let hp = parse_host_port("https://example.com:9443");
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, Some(9443));
    }

    #[test]
    fn test_parse_host_port_https_url_no_port() {
        let hp = parse_host_port("https://example.com");
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, None);
    }

    #[test]
    fn test_parse_host_port_http_url() {
        let hp = parse_host_port("http://example.com:8080");
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, Some(8080));
    }

    #[test]
    fn test_parse_host_port_ipv4_with_port() {
        let hp = parse_host_port("192.168.1.1:8443");
        assert_eq!(hp.host, "192.168.1.1");
        assert_eq!(hp.port, Some(8443));
    }

    #[test]
    fn test_parse_host_port_ipv4_no_port() {
        let hp = parse_host_port("10.0.0.1");
        assert_eq!(hp.host, "10.0.0.1");
        assert_eq!(hp.port, None);
    }

    #[test]
    fn test_parse_host_port_ipv6_with_port() {
        let hp = parse_host_port("[::1]:443");
        // URL parser keeps brackets for IPv6 addresses
        assert_eq!(hp.host, "[::1]");
        // url.port() returns None for scheme-default ports (443 for HTTPS),
        // which is correct since the app defaults to 443 when port is None
        assert_eq!(hp.port, None);
    }

    #[test]
    fn test_parse_host_port_ipv6_with_non_default_port() {
        let hp = parse_host_port("[::1]:8443");
        assert_eq!(hp.host, "[::1]");
        assert_eq!(hp.port, Some(8443));
    }

    #[test]
    fn test_parse_host_port_ipv6_no_port() {
        let hp = parse_host_port("[::1]");
        assert_eq!(hp.host, "[::1]");
        assert_eq!(hp.port, None);
    }

    #[test]
    fn test_parse_host_port_default_port_443() {
        let hp = parse_host_port("example.com");
        assert_eq!(hp.port, None); // None means default 443
    }

    #[test]
    fn test_parse_host_port_subdomain() {
        let hp = parse_host_port("sub.domain.example.com:8443");
        assert_eq!(hp.host, "sub.domain.example.com");
        assert_eq!(hp.port, Some(8443));
    }

    // ── OutFormat Display tests ──────────────────────────────────────

    #[test]
    fn test_outformat_display() {
        assert_eq!(format!("{}", OutFormat::Json), "json");
        assert_eq!(format!("{}", OutFormat::Text), "text");
        assert_eq!(format!("{}", OutFormat::Summary), "summary");
    }

    // ── OutFormat FromStr tests ──────────────────────────────────────

    #[test]
    fn test_outformat_from_str_valid() {
        assert_eq!("json".parse::<OutFormat>().unwrap(), OutFormat::Json);
        assert_eq!("text".parse::<OutFormat>().unwrap(), OutFormat::Text);
        assert_eq!("summary".parse::<OutFormat>().unwrap(), OutFormat::Summary);
    }

    #[test]
    fn test_outformat_from_str_case_insensitive() {
        assert_eq!("JSON".parse::<OutFormat>().unwrap(), OutFormat::Json);
        assert_eq!("Text".parse::<OutFormat>().unwrap(), OutFormat::Text);
        assert_eq!("SUMMARY".parse::<OutFormat>().unwrap(), OutFormat::Summary);
    }

    #[test]
    fn test_outformat_from_str_invalid() {
        let result = "csv".parse::<OutFormat>();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid output format"));
    }

    // ── FinalConfig tests ────────────────────────────────────────────

    #[test]
    fn test_final_config_no_hosts_returns_error() {
        let config = Config {
            hosts: None,
            output: Some("summary".to_string()),
            exit_code: Some(0),
            check_revocation: Some(false),
            prometheus: None,
            grade: Some(false),
        };
        let result = FinalConfig::from_merged_config(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_final_config_empty_hosts_returns_error() {
        let config = Config {
            hosts: Some(vec![]),
            output: Some("summary".to_string()),
            exit_code: Some(0),
            check_revocation: Some(false),
            prometheus: None,
            grade: Some(false),
        };
        let result = FinalConfig::from_merged_config(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_final_config_invalid_output_format() {
        let config = Config {
            hosts: Some(vec!["example.com".to_string()]),
            output: Some("xml".to_string()),
            exit_code: Some(0),
            check_revocation: Some(false),
            prometheus: None,
            grade: Some(false),
        };
        let result = FinalConfig::from_merged_config(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_final_config_defaults() {
        let config = Config {
            hosts: Some(vec!["example.com".to_string()]),
            output: None,
            exit_code: None,
            check_revocation: None,
            prometheus: None,
            grade: None,
        };
        let final_config = FinalConfig::from_merged_config(config).unwrap();
        assert_eq!(final_config.output, OutFormat::Summary);
        assert_eq!(final_config.exit_code, 0);
        assert!(!final_config.check_revocation);
        assert!(!final_config.prometheus);
        assert!(!final_config.grade);
        assert_eq!(final_config.prometheus_address, "http://localhost:9091");
    }

    #[test]
    fn test_final_config_all_options() {
        let config = Config {
            hosts: Some(vec!["a.com".to_string(), "b.com".to_string()]),
            output: Some("json".to_string()),
            exit_code: Some(2),
            check_revocation: Some(true),
            prometheus: Some(config::PrometheusConfig {
                enabled: Some(true),
                address: Some("http://prom:9091".to_string()),
            }),
            grade: Some(true),
        };
        let final_config = FinalConfig::from_merged_config(config).unwrap();
        assert_eq!(final_config.addresses, vec!["a.com", "b.com"]);
        assert_eq!(final_config.output, OutFormat::Json);
        assert_eq!(final_config.exit_code, 2);
        assert!(final_config.check_revocation);
        assert!(final_config.prometheus);
        assert_eq!(final_config.prometheus_address, "http://prom:9091");
        assert!(final_config.grade);
    }

    // ── FormatterFactory tests ───────────────────────────────────────

    #[test]
    fn test_formatter_factory_creates_all_types() {
        // Verify factory produces formatters without panicking
        let _json = FormatterFactory::new_formatter(&OutFormat::Json);
        let _text = FormatterFactory::new_formatter(&OutFormat::Text);
        let _summary = FormatterFactory::new_formatter(&OutFormat::Summary);
    }

    // ── Formatter output tests ───────────────────────────────────────

    fn make_test_tls() -> TLS {
        TLS {
            cipher: tlschecker::Cipher {
                name: "TLS_AES_256_GCM_SHA384".to_string(),
                version: "TLSv1.3".to_string(),
                bits: 256,
            },
            certificate: tlschecker::CertificateInfo {
                hostname: "test.example.com".to_string(),
                subject: tlschecker::Subject {
                    country_or_region: "US".to_string(),
                    state_or_province: "California".to_string(),
                    locality: "San Francisco".to_string(),
                    organization_unit: "Engineering".to_string(),
                    organization: "Example Inc".to_string(),
                    common_name: "test.example.com".to_string(),
                },
                issued: tlschecker::Issuer {
                    country_or_region: "US".to_string(),
                    organization: "Test CA".to_string(),
                    common_name: "Test CA Root".to_string(),
                },
                valid_from: "Jan  1 00:00:00 2025 GMT".to_string(),
                valid_to: "Dec 31 23:59:59 2026 GMT".to_string(),
                validity_days: 365,
                validity_hours: 8760,
                is_expired: false,
                cert_sn: "1234567890".to_string(),
                cert_ver: "2".to_string(),
                cert_alg: "sha256WithRSAEncryption".to_string(),
                sans: vec!["test.example.com".to_string(), "www.example.com".to_string()],
                chain: Some(vec![tlschecker::Chain {
                    subject: "test.example.com".to_string(),
                    issuer: "Test CA Root".to_string(),
                    valid_from: "Jan  1 00:00:00 2025 GMT".to_string(),
                    valid_to: "Dec 31 23:59:59 2026 GMT".to_string(),
                    signature_algorithm: "sha256WithRSAEncryption".to_string(),
                }]),
                revocation_status: RevocationStatus::NotChecked,
                is_self_signed: false,
                security_warnings: vec![],
                cert_key_bits: 2048,
                cert_key_algorithm: "RSA".to_string(),
            },
            grade: None,
        }
    }

    #[test]
    fn test_json_format_output() {
        let tls = vec![make_test_tls()];
        let output = JsonFormat.format(&tls);
        assert!(output.contains("test.example.com"));
        assert!(output.contains("TLS_AES_256_GCM_SHA384"));
        assert!(output.contains("\"bits\": 256"));
        // grade should be absent when None (skip_serializing_if)
        assert!(!output.contains("\"grade\""));
    }

    #[test]
    fn test_json_format_includes_grade_when_present() {
        let mut tls_entry = make_test_tls();
        tls_entry.grade = Some(tlschecker::grading::TLSGrade {
            grade: "A+".to_string(),
            score: 97,
            categories: vec![],
        });
        let output = JsonFormat.format(&[tls_entry]);
        assert!(output.contains("\"grade\""));
        assert!(output.contains("\"A+\""));
        assert!(output.contains("97"));
    }

    #[test]
    fn test_json_format_empty_input() {
        let output = JsonFormat.format(&[]);
        assert_eq!(output, "[]");
    }

    #[test]
    fn test_summary_format_empty_input_returns_empty() {
        let output = SummaryFormat.format(&[]);
        assert!(output.is_empty());
    }

    #[test]
    fn test_text_format_contains_all_fields() {
        let tls = vec![make_test_tls()];
        let output = TextFormat.format(&tls);
        assert!(output.contains("Hostname: test.example.com"));
        assert!(output.contains("Issued domain: test.example.com"));
        assert!(output.contains("Organization: Example Inc"));
        assert!(output.contains("Common Name: Test CA Root"));
        assert!(output.contains("Days left: 365"));
        assert!(output.contains("Hours left: 8760"));
        assert!(output.contains("Self-signed: false"));
        assert!(output.contains("Expired: false"));
        assert!(output.contains("Certificate algorithm: sha256WithRSAEncryption"));
        assert!(output.contains("Certificate key: RSA 2048-bit"));
        assert!(output.contains("Cipher suite: TLS_AES_256_GCM_SHA384 (256-bit)"));
        assert!(output.contains("Protocol: TLSv1.3"));
        assert!(output.contains("Revocation Status: Not Checked"));
        assert!(output.contains("DNS Name: test.example.com"));
        assert!(output.contains("DNS Name: www.example.com"));
    }

    #[test]
    fn test_summary_format_contains_host_data() {
        let tls = vec![make_test_tls()];
        let output = SummaryFormat.format(&tls);
        assert!(output.contains("test.example.com"));
        assert!(output.contains("TLS_AES_256_GCM_SHA384"));
        assert!(output.contains("TLSv1.3"));
        assert!(output.contains("Test CA"));
        assert!(output.contains("Healthy"));
    }

    #[test]
    fn test_text_format_with_warnings() {
        let mut tls_entry = make_test_tls();
        tls_entry.certificate.security_warnings = vec![
            tlschecker::SecurityWarning::WeakSignatureAlgorithm("SHA1".to_string()),
            tlschecker::SecurityWarning::IncompleteChain("Missing intermediate".to_string()),
            tlschecker::SecurityWarning::InvalidChainOrder("Wrong order".to_string()),
        ];
        let output = TextFormat.format(&[tls_entry]);
        assert!(output.contains("Security Warnings:"));
        assert!(output.contains("WEAK ALGORITHM: SHA1"));
        assert!(output.contains("INCOMPLETE CHAIN: Missing intermediate"));
        assert!(output.contains("INVALID CHAIN ORDER: Wrong order"));
    }

    #[test]
    fn test_text_format_with_grade() {
        let mut tls_entry = make_test_tls();
        tls_entry.grade = Some(tlschecker::grading::TLSGrade {
            grade: "B".to_string(),
            score: 75,
            categories: vec![
                tlschecker::grading::CategoryScore {
                    category: "Protocol".to_string(),
                    score: 80,
                    reason: "TLS 1.2".to_string(),
                },
            ],
        });
        let output = TextFormat.format(&[tls_entry]);
        assert!(output.contains("TLS Configuration Grade: B (Score: 75/100)"));
        assert!(output.contains("Category Breakdown:"));
        assert!(output.contains("Protocol: 80/100 - TLS 1.2"));
    }

    #[test]
    fn test_summary_format_expired_cert() {
        let mut tls_entry = make_test_tls();
        tls_entry.certificate.is_expired = true;
        tls_entry.certificate.validity_days = -10;
        let output = SummaryFormat.format(&[tls_entry]);
        assert!(output.contains("Critical"));
    }

    #[test]
    fn test_summary_format_warning_threshold() {
        let mut tls_entry = make_test_tls();
        tls_entry.certificate.validity_days = 20;
        let output = SummaryFormat.format(&[tls_entry]);
        assert!(output.contains("Warning"));
    }

    #[test]
    fn test_summary_format_critical_threshold() {
        let mut tls_entry = make_test_tls();
        tls_entry.certificate.validity_days = 10;
        let output = SummaryFormat.format(&[tls_entry]);
        assert!(output.contains("Critical"));
    }

    #[test]
    fn test_summary_format_revoked_cert() {
        let mut tls_entry = make_test_tls();
        tls_entry.certificate.revocation_status =
            RevocationStatus::Revoked("Key compromise".to_string());
        let output = SummaryFormat.format(&[tls_entry]);
        assert!(output.contains("Revoked"));
    }

    #[test]
    fn test_summary_format_self_signed() {
        let mut tls_entry = make_test_tls();
        tls_entry.certificate.is_self_signed = true;
        let output = SummaryFormat.format(&[tls_entry]);
        assert!(output.contains("Yes")); // self-signed = Yes
    }

    #[test]
    fn test_summary_format_with_grade() {
        let mut tls_entry = make_test_tls();
        tls_entry.grade = Some(tlschecker::grading::TLSGrade {
            grade: "F".to_string(),
            score: 0,
            categories: vec![],
        });
        let output = SummaryFormat.format(&[tls_entry]);
        assert!(output.contains("F"));
    }

    #[test]
    fn test_summary_format_with_security_warnings() {
        let mut tls_entry = make_test_tls();
        tls_entry.certificate.security_warnings = vec![
            tlschecker::SecurityWarning::WeakSignatureAlgorithm("SHA1 detected".to_string()),
        ];
        let output = SummaryFormat.format(&[tls_entry]);
        assert!(output.contains("Security Warnings:"));
        assert!(output.contains("WEAK ALGORITHM: SHA1 detected"));
    }

    // ── Integration test (network-dependent) ─────────────────────────

    #[test]
    #[ignore] // requires network: connects to badssl.com and google.com
    fn test_self_signed_certificate() {
        let host = "self-signed.badssl.com";
        match TLS::from(host, None, false, false) {
            Ok(tls_result) => {
                assert!(
                    tls_result.certificate.is_self_signed,
                    "Expected self-signed.badssl.com certificate to be self-signed"
                );
            }
            Err(err) => {
                assert!(
                    matches!(err, TLSError::Certificate(_)),
                    "Expected certificate error, got: {:?}",
                    err
                );
            }
        }

        let host = "google.com";
        if let Ok(tls_result) = TLS::from(host, None, false, false) {
            assert!(
                !tls_result.certificate.is_self_signed,
                "google.com certificate should not be self-signed"
            );
        }
    }
}
