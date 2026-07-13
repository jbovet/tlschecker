use std::collections::VecDeque;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
mod config;
mod metrics;
mod tui;

use clap::{Parser, ValueEnum};
use comfy_table::modifiers::UTF8_ROUND_CORNERS;
use comfy_table::presets::UTF8_FULL;
use comfy_table::{Attribute, Cell, CellAlignment, Color, ContentArrangement, Table};

use tlschecker::RevocationStatus;
use tlschecker::TrustStatus;
use tlschecker::TLS;
use url::Url;

use anyhow::Result;
use config::{Config, ConfigError};
use tlschecker::TLSError;
use tracing::{error, warn};

/// Experimental TLS/SSL certificate checker.
///
/// Checks TLS certificates for multiple hosts, validates expiration dates, and
/// optionally checks revocation status.
///
/// On an interactive terminal it launches a live dashboard by default (j/k
/// move, Enter inspect a host, q quit). Pipe the output, pass `-o <format>`, or
/// use `--no-dashboard` for non-interactive JSON/text/summary output.
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
    #[arg(short, long, value_enum)]
    output: Option<OutFormat>,

    /// Disable the interactive dashboard and use the classic formatter.
    ///
    /// The dashboard is the default on an interactive terminal; this forces the
    /// non-interactive output (summary by default, or whatever `-o`/config
    /// selects) even when stdout is a TTY.
    #[arg(long)]
    no_dashboard: bool,

    /// Exit with this code when expired or revoked certificates are found.
    ///
    /// Defaults to 0 (always succeed). Set to 1 for CI/CD pipelines
    /// that should fail on certificate issues.
    #[arg(long)]
    exit_code: Option<i32>,

    /// Push certificate metrics to a Prometheus Push Gateway
    ///
    /// Can be passed as a bare flag (`--prometheus`) or with an explicit
    /// value (`--prometheus true|false`) to override a config-file setting.
    #[arg(long, num_args = 0..=1, default_missing_value = "true")]
    prometheus: Option<bool>,

    /// Prometheus Push Gateway URL [default: http://localhost:9091]
    #[arg(long)]
    prometheus_address: Option<String>,

    /// Check certificate revocation status via OCSP and CRL.
    ///
    /// Queries OCSP responders first, then falls back to CRL
    /// distribution points. Adds latency due to network requests.
    #[arg(long)]
    check_revocation: bool,

    /// Enable TLS configuration grading (A+ to F).
    ///
    /// Evaluates protocol version, cipher strength, key exchange,
    /// certificate key size, and trust chain to produce a composite
    /// letter grade for each host.
    #[arg(long)]
    grade: bool,

    /// Minimum number of days a certificate must remain valid.
    ///
    /// Certificates with fewer remaining days are treated as failures
    /// for exit-code purposes. Set to 0 to disable (default).
    /// Example: --min-validity 30 fails if any cert expires within 30 days.
    #[arg(long)]
    min_validity: Option<i32>,

    /// Enumerate all supported TLS protocol versions and cipher suites.
    ///
    /// Actively probes the server with many short handshakes (one per
    /// version/cipher), so it is slower than a normal check. Results appear in
    /// the dashboard's detail explorer and in text/JSON output. Implies --grade,
    /// so the grade (and thus the scan) is also surfaced in the summary table.
    #[arg(long)]
    scan: bool,

    /// Export the presented certificate chain as PEM and exit.
    ///
    /// Prints the leaf certificate followed by any intermediates the server
    /// sent, instead of the normal formatted report.
    #[arg(long)]
    export_pem: bool,

    /// Treat hosts that could not be checked at all as failures for
    /// exit-code purposes.
    ///
    /// By default an unreachable host (DNS failure, refused connection,
    /// handshake error, invalid address) is only logged and does not affect
    /// the exit code. With this flag, any such error makes the run exit with
    /// --exit-code, so CI pipelines can catch hosts that are down entirely.
    #[arg(long)]
    fail_on_error: bool,

    /// Look the presented leaf certificate up in public Certificate
    /// Transparency logs (via crt.sh).
    ///
    /// Confirms whether the certificate has been logged in CT — a requirement
    /// modern browsers enforce for publicly-trusted certificates. Performs a
    /// network request to an external service, so it adds latency and is
    /// opt-in. Results appear in the dashboard's detail explorer and in
    /// text/JSON output. A certificate absent from CT is reported as a security
    /// warning but does not affect the grade.
    #[arg(long)]
    ct_check: bool,
}

/// Output format for certificate information.
///
/// Selects the non-interactive output. On a TTY the interactive dashboard is
/// used by default instead; these formats apply when stdout is piped, when one
/// is chosen explicitly via `-o`/config, or with `--no-dashboard`.
///
/// - **Json**: Machine-readable JSON format for programmatic consumption
/// - **Text**: Human-readable detailed text format showing all certificate fields
/// - **Summary**: Colored table format with certificate health indicators
///   (default for non-interactive output)
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
///
/// The dashboard applies a broader verdict (self-signed certs or any security
/// warning also count as Warning); see `tui::state::verdict`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum OutFormat {
    /// JSON format for programmatic parsing
    Json,
    /// Detailed text format showing all certificate fields
    Text,
    /// Summary table format with color-coded status (default for
    /// non-interactive/piped output)
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

/// Returns the display label and message for a security warning.
///
/// Single source of truth for all frontends (text, summary, dashboard) so a
/// new `SecurityWarning` variant only needs one new arm here.
pub(crate) fn warning_label(warning: &tlschecker::SecurityWarning) -> (&'static str, &str) {
    use tlschecker::SecurityWarning::*;
    match warning {
        WeakSignatureAlgorithm(msg) => ("WEAK ALGORITHM", msg),
        IncompleteChain(msg) => ("INCOMPLETE CHAIN", msg),
        InvalidChainOrder(msg) => ("INVALID CHAIN ORDER", msg),
        HostnameMismatch(msg) => ("HOSTNAME MISMATCH", msg),
        ExpiringIntermediate(msg) => ("EXPIRING INTERMEDIATE", msg),
        WeakProtocol(msg) => ("WEAK PROTOCOL", msg),
        WeakCipher(msg) => ("WEAK CIPHER", msg),
        NotInCertificateTransparency(msg) => ("NOT IN CT LOG", msg),
        Untrusted(msg) => ("UNTRUSTED", msg),
        CertificateMisissuance(msg) => ("MISISSUANCE", msg),
        InvalidChainSignature(msg) => ("INVALID CHAIN SIGNATURE", msg),
    }
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
            writeln!(
                output,
                "\tCountry or Region: {}",
                cert.subject.country_or_region
            )
            .unwrap();
            writeln!(
                output,
                "\tState or Province: {}",
                cert.subject.state_or_province
            )
            .unwrap();
            writeln!(output, "\tLocality: {}", cert.subject.locality).unwrap();
            writeln!(
                output,
                "\tOrganizational Unit: {}",
                cert.subject.organization_unit
            )
            .unwrap();
            writeln!(output, "\tOrganization: {}", cert.subject.organization).unwrap();
            writeln!(output, "\tCommon Name: {}", cert.subject.common_name).unwrap();
            writeln!(output, "Issuer Name:").unwrap();
            writeln!(
                output,
                "\tCountry or Region: {}",
                cert.issued.country_or_region
            )
            .unwrap();
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
            writeln!(output, "SHA-256 Fingerprint: {}", cert.cert_sha256).unwrap();
            writeln!(output, "SHA-1 Fingerprint: {}", cert.cert_sha1).unwrap();
            if let Some(skid) = &cert.subject_key_id {
                writeln!(output, "Subject Key ID: {}", skid).unwrap();
            }
            if let Some(akid) = &cert.authority_key_id {
                writeln!(output, "Authority Key ID: {}", akid).unwrap();
            }
            if let Some(level) = &cert.validation_level {
                writeln!(output, "Validation Level: {}", level).unwrap();
            }
            if !cert.key_usage.is_empty() {
                writeln!(output, "Key Usage: {}", cert.key_usage.join(", ")).unwrap();
            }
            if !cert.ext_key_usage.is_empty() {
                writeln!(
                    output,
                    "Extended Key Usage: {}",
                    cert.ext_key_usage.join(", ")
                )
                .unwrap();
            }
            writeln!(
                output,
                "Basic Constraints: CA:{}{}",
                if cert.is_ca { "TRUE" } else { "FALSE" },
                match cert.path_len {
                    Some(n) => format!(", pathlen:{}", n),
                    None => String::new(),
                }
            )
            .unwrap();
            writeln!(
                output,
                "Certificate key: {} {}-bit",
                cert.cert_key_algorithm, cert.cert_key_bits
            )
            .unwrap();
            writeln!(
                output,
                "Cipher suite: {} ({}-bit)",
                rs.cipher.name, rs.cipher.bits
            )
            .unwrap();
            writeln!(output, "Protocol: {}", rs.cipher.version).unwrap();
            if let Some(alpn) = &rs.cipher.alpn {
                writeln!(output, "ALPN: {}", alpn).unwrap();
            }

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

            writeln!(
                output,
                "Trust: {}",
                match &cert.trust {
                    TrustStatus::Trusted => "Trusted (chains to a system root)".to_string(),
                    TrustStatus::Untrusted { reason } => format!("Untrusted ({})", reason),
                    TrustStatus::Unknown => "Unknown (no system trust store)".to_string(),
                }
            )
            .unwrap();

            if !cert.security_warnings.is_empty() {
                writeln!(output, "\nSecurity Warnings:").unwrap();
                for warning in &cert.security_warnings {
                    let (label, msg) = warning_label(warning);
                    writeln!(output, "  {}: {}", label, msg).unwrap();
                }
            }

            // Embedded SCTs are read offline from the leaf and always available;
            // shown only when present.
            if !cert.scts.is_empty() {
                writeln!(
                    output,
                    "\nEmbedded SCTs (Certificate Transparency): {}",
                    cert.scts.len()
                )
                .unwrap();
                for sct in &cert.scts {
                    writeln!(output, "  - log {} at {}", sct.log_id, sct.timestamp).unwrap();
                }
            }

            if let Some(ref ct) = rs.ct {
                writeln!(output, "\nCertificate Transparency:").unwrap();
                match ct {
                    tlschecker::ct::CtStatus::Logged { crtsh_url, .. } => {
                        writeln!(output, "  Logged: yes").unwrap();
                        writeln!(output, "  crt.sh: {}", crtsh_url).unwrap();
                    }
                    tlschecker::ct::CtStatus::NotLogged => {
                        writeln!(output, "  Logged: no").unwrap();
                    }
                    tlschecker::ct::CtStatus::Unknown => {
                        writeln!(output, "  Logged: unknown (could not query crt.sh)").unwrap();
                        // Offline evidence still applies even when crt.sh is down.
                        if !cert.scts.is_empty() {
                            writeln!(
                                output,
                                "  Note: {} embedded SCT(s) present — certificate was submitted to CT logs",
                                cert.scts.len()
                            )
                            .unwrap();
                        }
                    }
                }
            }

            if let Some(ref scan) = rs.scan {
                writeln!(output, "\nSupported Protocols & Ciphers:").unwrap();
                for proto in &scan.protocols {
                    if proto.supported {
                        writeln!(output, "  {}: supported", proto.version).unwrap();
                        for cipher in &proto.ciphers {
                            writeln!(output, "    - {}", cipher).unwrap();
                        }
                    } else {
                        writeln!(output, "  {}: not supported", proto.version).unwrap();
                    }
                }
            }

            if let Some(ref grade) = rs.grade {
                writeln!(
                    output,
                    "\nTLS Configuration Grade: {} (Score: {}/100)",
                    grade.grade, grade.score
                )
                .unwrap();
                writeln!(output, "  Category Breakdown:").unwrap();
                for cat in &grade.categories {
                    writeln!(
                        output,
                        "    {}: {}/100 - {}",
                        cat.category, cat.score, cat.reason
                    )
                    .unwrap();
                }
            }

            writeln!(output, "Subject Alternative Names:").unwrap();
            for san in &cert.sans {
                writeln!(output, "\tDNS Name: {}", san).unwrap();
            }

            if let Some(chains) = &cert.chain {
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

        // Only show the Grade column when grading was actually performed for at
        // least one host; otherwise it would just be a column full of "-".
        let show_grade = tls.iter().any(|t| t.grade.is_some());

        // Likewise, only show the CT column when a CT lookup was requested
        // (`--ct-check`) for at least one host. `ct.is_some()` ⇔ requested.
        let show_ct = tls.iter().any(|t| t.ct.is_some());

        let mut output = String::new();
        let mut table = Table::new();
        let mut header = vec![
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
        ];
        if show_grade {
            header.push("Grade");
        }
        if show_ct {
            header.push("CT");
        }
        table
            // `Disabled` (natural width, no wrapping) rather than `Dynamic`:
            // `Dynamic` queries the ambient terminal width and wraps cells to
            // fit, which makes the output non-deterministic (it differs between
            // a TTY and a pipe, breaking tests) and mangles values like
            // hostnames and fingerprints mid-word. A wide table simply scrolls.
            .set_content_arrangement(ContentArrangement::Disabled)
            .apply_modifier(UTF8_ROUND_CORNERS)
            .load_preset(UTF8_FULL)
            .set_header(header);

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

            let mut row = vec![
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
            ];

            if show_grade {
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
                row.push(grade_cell);
            }

            if show_ct {
                let ct_cell = match &rs.ct {
                    Some(tlschecker::ct::CtStatus::Logged { .. }) => Cell::new("✓")
                        .add_attribute(Attribute::Bold)
                        .fg(Color::Green)
                        .set_alignment(CellAlignment::Center),
                    Some(tlschecker::ct::CtStatus::NotLogged) => Cell::new("✗")
                        .add_attribute(Attribute::Bold)
                        .fg(Color::Red)
                        .set_alignment(CellAlignment::Center),
                    Some(tlschecker::ct::CtStatus::Unknown) => Cell::new("?")
                        .add_attribute(Attribute::Bold)
                        .fg(Color::Yellow)
                        .set_alignment(CellAlignment::Center),
                    // Lookup not requested for this host (mixed-input runs).
                    None => Cell::new("-")
                        .fg(Color::DarkGrey)
                        .set_alignment(CellAlignment::Center),
                };
                row.push(ct_cell);
            }

            table.add_row(row);
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
                    let (label, msg) = warning_label(warning);
                    writeln!(output, "    - {}: {}", label, msg).unwrap();
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
#[derive(Debug)]
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
    /// Whether the output format was explicitly requested (CLI `-o` or config
    /// file `output` key) rather than defaulted — an explicit choice opts out
    /// of the TTY dashboard.
    output_explicit: bool,
    exit_code: i32,
    prometheus: bool,
    prometheus_address: String,
    check_revocation: bool,
    grade: bool,
    min_validity: i32,
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

        if let Some(min_validity) = config.min_validity {
            if min_validity < 0 {
                return Err(ConfigError::Validation(format!(
                    "min_validity must be zero or positive, got {min_validity}"
                )));
            }
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
            // Explicitness cannot be derived from the merged config (the
            // defaults seed `output` with Some("summary")); `load_config`
            // overrides this from the file/CLI sources.
            output_explicit: false,
            exit_code: config.exit_code.unwrap_or(0),
            prometheus: prometheus_config.enabled.unwrap_or(false),
            prometheus_address: prometheus_config
                .address
                .unwrap_or_else(|| "http://localhost:9091".to_string()),
            check_revocation: config.check_revocation.unwrap_or(false),
            grade: config.grade.unwrap_or(false),
            min_validity: config.min_validity.unwrap_or(0),
        })
    }
}

/// Upper bound on concurrent host checks; the pool also never exceeds the
/// machine's available parallelism or the number of hosts.
const MAX_CONCURRENT_CHECKS: usize = 16;

/// Checks a single host: TLS connection plus the optional scan and CT lookup.
///
/// Returns the error unlogged so each frontend can present it its own way:
/// the CLI path logs to stderr, the dashboard renders it as a failed row.
fn check_host(host_port: &HostPort, opts: CheckOptions) -> Result<TLS, TLSError> {
    let port_display = host_port.port.map_or(String::new(), |p| format!(":{}", p));

    let mut cert = TLS::from(
        &host_port.host,
        host_port.port,
        opts.check_revocation,
        opts.calculate_grade,
    )?;

    if opts.do_scan {
        if let Ok(scan) = tlschecker::probe::scan_tls(&host_port.host, host_port.port) {
            // Fold scan-derived warnings into the result and
            // recompute the grade to reflect full posture.
            cert.apply_scan(scan);
        }
    }
    if opts.do_ct {
        // Look the leaf up in public CT logs (crt.sh, by
        // SHA-256 fingerprint). A failed/inconclusive lookup
        // is non-fatal: the reason is logged to stderr and the
        // result is recorded as `Unknown` rather than dropped,
        // so "could not check" is never mistaken for "absent".
        let ct = match tlschecker::ct::check_ct_status(&cert.certificate.cert_sha256) {
            Ok(ct) => ct,
            Err(e) => {
                warn!(
                    "CT lookup could not be completed for {}{}: {}",
                    host_port.host, port_display, e
                );
                tlschecker::ct::CtStatus::Unknown
            }
        };
        cert.apply_ct(ct);
    }
    Ok(cert)
}

/// Options controlling what a single host check performs.
#[derive(Clone, Copy)]
struct CheckOptions {
    check_revocation: bool,
    calculate_grade: bool,
    do_scan: bool,
    do_ct: bool,
}

/// The result of attempting to check one host.
enum HostOutcome {
    /// The check completed and produced certificate information.
    Checked(Box<TLS>),
    /// The host could not be checked at all.
    Failed {
        /// Short failure class for compact display (e.g. "DNS", "connection").
        kind: &'static str,
        /// Full error message for logs / detail views.
        detail: String,
    },
}

/// Maps a check error onto a short failure class for compact display.
fn error_kind(err: &TLSError) -> &'static str {
    match err {
        TLSError::DNS(_) => "DNS",
        TLSError::Connection(_) => "connection",
        TLSError::Handshake(_) => "handshake",
        TLSError::Certificate(_) => "certificate",
        TLSError::Validation(_) => "invalid",
        _ => "error",
    }
}

/// A host check job: the host's input-order index paired with its parsed
/// address (or the address parse error).
type HostJob = (usize, Result<HostPort, String>);

/// Runs all host checks on a bounded worker pool, streaming each outcome over
/// a channel as soon as it completes.
///
/// `jobs` pairs each host's input-order index with either a parsed address or
/// the parse-failure message (which is reported as an immediate
/// [`HostOutcome::Failed`], so invalid addresses still occupy a row). Worker
/// threads are detached; the channel closes once every job has been sent.
fn spawn_checks(
    jobs: Vec<HostJob>,
    opts: CheckOptions,
) -> std::sync::mpsc::Receiver<(usize, HostOutcome)> {
    let (tx, rx) = std::sync::mpsc::channel();

    // Bounded pool: a large host list would otherwise spawn an unbounded
    // number of threads, each potentially holding a 30s connection timeout.
    let worker_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
        .min(MAX_CONCURRENT_CHECKS)
        .min(jobs.len().max(1));

    let queue: Arc<Mutex<VecDeque<HostJob>>> = Arc::new(Mutex::new(jobs.into_iter().collect()));

    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        thread::spawn(move || loop {
            let job = queue.lock().unwrap().pop_front();
            let Some((index, job)) = job else { break };
            let outcome = match job {
                Ok(host_port) => match check_host(&host_port, opts) {
                    Ok(tls) => HostOutcome::Checked(Box::new(tls)),
                    Err(err) => HostOutcome::Failed {
                        kind: error_kind(&err),
                        detail: err.to_string(),
                    },
                },
                Err(msg) => HostOutcome::Failed {
                    kind: "invalid",
                    detail: msg,
                },
            };
            // A closed receiver means the frontend is gone; stop working.
            if tx.send((index, outcome)).is_err() {
                break;
            }
        });
    }

    rx
}

/// True while the dashboard owns the terminal. Checked by the tracing writer
/// so diagnostics are discarded instead of corrupting the alternate screen.
static TUI_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Tracing writer: stderr normally, discarded while the dashboard is active.
fn tracing_writer() -> Box<dyn std::io::Write> {
    if TUI_ACTIVE.load(Ordering::Relaxed) {
        Box::new(std::io::sink())
    } else {
        Box::new(std::io::stderr())
    }
}

/// Whether to run the interactive dashboard instead of a text formatter.
///
/// The dashboard is the default on an interactive terminal, but never when the
/// user asked for a specific output format (CLI `-o` or config `output` key),
/// passed `--no-dashboard`, or requested a PEM export — those must keep
/// producing the classic stream, and any piped/redirected stdout does too.
fn use_dashboard(
    stdout_is_tty: bool,
    output_explicit: bool,
    export_pem: bool,
    no_dashboard: bool,
) -> bool {
    stdout_is_tty && !output_explicit && !export_pem && !no_dashboard
}

fn main() -> Result<()> {
    // Initialize tracing. Diagnostics (errors, warnings) go to stderr so stdout
    // stays a clean machine-readable stream — e.g. `-o json ... | jq` is not
    // corrupted by log lines. (While the dashboard runs, they are discarded —
    // see `tracing_writer`.)
    tracing_subscriber::fmt().with_writer(tracing_writer).init();

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
        Err(e) => {
            error!("{}", e);
            error!("Try running with --help for usage information");
            error!("Or use --generate-config to create a sample configuration file");
            std::process::exit(1);
        }
    };

    let exit_code = final_config.exit_code;
    let mut failed_result = false;

    // The dashboard is the default on a TTY; explicit output selection, PEM
    // export, or piped stdout keep the classic formatters.
    let dashboard = use_dashboard(
        std::io::stdout().is_terminal(),
        final_config.output_explicit,
        cli.export_pem,
        cli.no_dashboard,
    );

    // Parse hosts and ports. Invalid addresses stay in the job list so they
    // surface as failed rows (dashboard) / logged errors (CLI) in input order.
    let labels: Vec<String> = final_config.addresses.clone();
    let jobs: Vec<HostJob> = final_config
        .addresses
        .iter()
        .map(|address| parse_host_port(address))
        .enumerate()
        .collect();
    let hosts_len = jobs.len();

    let opts = CheckOptions {
        check_revocation: final_config.check_revocation,
        // `--scan` implies `--grade` (the scan is surfaced via the grade), and
        // the dashboard always grades: its detail pane shows the breakdown and
        // grading is offline and cheap.
        calculate_grade: should_grade(final_config.grade, cli.scan) || dashboard,
        do_scan: cli.scan,
        do_ct: cli.ct_check,
    };

    let rx = spawn_checks(jobs, opts);

    // Collect into index-order slots so the output order matches the input
    // order regardless of which worker handled which host.
    let mut error_count: usize = 0;
    let slots: Vec<Option<HostOutcome>> = if dashboard {
        TUI_ACTIVE.store(true, Ordering::Relaxed);
        let outcome = tui::run(&labels, rx);
        TUI_ACTIVE.store(false, Ordering::Relaxed);
        outcome?
    } else {
        let mut slots: Vec<Option<HostOutcome>> = (0..hosts_len).map(|_| None).collect();
        for (index, outcome) in rx.iter() {
            if let HostOutcome::Failed { detail, .. } = &outcome {
                error!("Failed to check '{}': {}", labels[index], detail);
            }
            slots[index] = Some(outcome);
        }
        slots
    };

    let mut results: Vec<TLS> = Vec::with_capacity(hosts_len);
    for slot in slots {
        match slot {
            Some(HostOutcome::Checked(tls_result)) => results.push(*tls_result),
            // Error already reported by the frontend that observed it.
            Some(HostOutcome::Failed { .. }) => error_count += 1,
            // The dashboard was quit before this host finished; deliberately
            // not counted as an error.
            None => {}
        }
    }

    let any_expired = results.iter().any(|c| c.certificate.is_expired);
    let any_revoked = results.iter().any(|c| {
        matches!(
            c.certificate.revocation_status,
            RevocationStatus::Revoked(_)
        )
    });
    if any_expired || any_revoked {
        failed_result = true;
    }

    // With --fail-on-error, hosts that could not be checked at all (invalid
    // address, DNS failure, connection/handshake error) count as failures.
    if cli.fail_on_error && error_count > 0 {
        failed_result = true;
    }

    // Check certificates below minimum validity threshold
    if final_config.min_validity > 0 {
        let below_min_validity = results.iter().any(|c| {
            !c.certificate.is_expired && c.certificate.validity_days < final_config.min_validity
        });
        if below_min_validity {
            failed_result = true;
        }
    }

    if cli.export_pem {
        // Print the presented certificate chain(s) as PEM instead of a report.
        for r in &results {
            print!("{}", r.certificate.pem);
        }
    } else if !dashboard {
        // The dashboard already presented the results interactively.
        let formatter = FormatterFactory::new_formatter(&final_config.output);
        print!("{}", formatter.format(&results));
    }

    if final_config.prometheus {
        metrics::prom::prometheus_metrics(
            results,
            final_config.prometheus_address,
            final_config.min_validity,
        );
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

    // Whether the user chose an output format themselves (config file or CLI),
    // as opposed to inheriting the default. Must be captured before merging,
    // because the defaults seed `output` with Some("summary").
    let mut output_explicit = cli.output.is_some();

    // Load from config file if specified, otherwise try tlschecker.toml
    if let Some(config_path) = &cli.config {
        let file_config = Config::from_file(config_path)?;
        output_explicit |= file_config.output.is_some();
        config = config.merge_with(file_config);
    } else {
        // Try to load from default tlschecker.toml if it exists
        if let Ok(file_config) = Config::from_file("tlschecker.toml") {
            output_explicit |= file_config.output.is_some();
            config = config.merge_with(file_config);
        }
    }

    // Merge with CLI arguments (CLI takes precedence)
    let cli_addresses = if !cli.addresses.is_empty() {
        Some(cli.addresses.clone())
    } else {
        None
    };

    // Boolean flags are only forwarded when actually passed on the command
    // line: an absent flag must stay `None` so it does not override a value
    // set in the config file during the "last `Some` wins" merge.
    let cli_config = Config::from_cli_args(
        cli_addresses,
        cli.output.as_ref().map(|o| o.to_string()),
        cli.exit_code,
        cli.prometheus,
        cli.prometheus_address.clone(),
        cli.check_revocation.then_some(true),
        cli.grade.then_some(true),
        cli.min_validity,
    );

    config = config.merge_with(cli_config);

    // Convert to final configuration and validate
    let mut final_config = FinalConfig::from_merged_config(config)?;
    final_config.output_explicit = output_explicit;
    Ok(final_config)
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

/// Whether a TLS grade should be computed for this run.
///
/// Grading is enabled when explicitly requested (`--grade`/config) or whenever a
/// scan is performed (`--scan` implies `--grade`), since the scan's results are
/// surfaced through the grade.
fn should_grade(config_grade: bool, scan: bool) -> bool {
    config_grade || scan
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
/// `Ok(HostPort)` with the extracted hostname and optional port, or an error
/// message when the address carries a port specification that is not a valid
/// port number (e.g. `example.com:99999`).
///
/// # Note
///
/// - IPv6 brackets are automatically removed from the hostname
/// - If no port is specified, returns `None` for the port (defaults to 443)
/// - URL schemes (http://, https://) are stripped and ignored
fn parse_host_port(address: &str) -> Result<HostPort, String> {
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
            return Ok(HostPort {
                host: host_str.to_string(),
                port: url.port(),
            });
        }
    }

    // Not a valid URL, check if it has a port specification (hostname:port)
    // This handles cases like "example.com:8443"
    if let Some((host, port_str)) = address.split_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            // Make sure we don't include IPv6 brackets in the hostname
            let clean_host = host.trim_start_matches('[').trim_end_matches(']');
            return Ok(HostPort {
                host: clean_host.to_string(),
                port: Some(port),
            });
        }
        // The segment after the colon was clearly meant as a port but is not a
        // valid one; report it instead of silently treating "host:99999" as a
        // hostname (which would only surface later as a confusing DNS error).
        if !port_str.is_empty() && port_str.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!(
                "Invalid port '{}' in address '{}' (ports must be 1-65535)",
                port_str, address
            ));
        }
    }

    // No port specified, just a hostname
    // For IPv6 addresses, clean up any brackets
    let clean_address = address.trim_start_matches('[').trim_end_matches(']');
    Ok(HostPort {
        host: clean_address.to_string(),
        port: None,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // ── parse_host_port tests ────────────────────────────────────────

    #[test]
    fn test_parse_host_port_hostname_only() {
        let hp = parse_host_port("example.com").unwrap();
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, None);
    }

    #[test]
    fn test_parse_host_port_with_port() {
        let hp = parse_host_port("example.com:8443").unwrap();
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, Some(8443));
    }

    #[test]
    fn test_parse_host_port_https_url() {
        let hp = parse_host_port("https://example.com:9443").unwrap();
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, Some(9443));
    }

    #[test]
    fn test_parse_host_port_https_url_no_port() {
        let hp = parse_host_port("https://example.com").unwrap();
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, None);
    }

    #[test]
    fn test_parse_host_port_http_url() {
        let hp = parse_host_port("http://example.com:8080").unwrap();
        assert_eq!(hp.host, "example.com");
        assert_eq!(hp.port, Some(8080));
    }

    #[test]
    fn test_parse_host_port_ipv4_with_port() {
        let hp = parse_host_port("192.168.1.1:8443").unwrap();
        assert_eq!(hp.host, "192.168.1.1");
        assert_eq!(hp.port, Some(8443));
    }

    #[test]
    fn test_parse_host_port_ipv4_no_port() {
        let hp = parse_host_port("10.0.0.1").unwrap();
        assert_eq!(hp.host, "10.0.0.1");
        assert_eq!(hp.port, None);
    }

    #[test]
    fn test_parse_host_port_ipv6_with_port() {
        let hp = parse_host_port("[::1]:443").unwrap();
        // URL parser keeps brackets for IPv6 addresses
        assert_eq!(hp.host, "[::1]");
        // url.port() returns None for scheme-default ports (443 for HTTPS),
        // which is correct since the app defaults to 443 when port is None
        assert_eq!(hp.port, None);
    }

    #[test]
    fn test_parse_host_port_ipv6_with_non_default_port() {
        let hp = parse_host_port("[::1]:8443").unwrap();
        assert_eq!(hp.host, "[::1]");
        assert_eq!(hp.port, Some(8443));
    }

    #[test]
    fn test_parse_host_port_ipv6_no_port() {
        let hp = parse_host_port("[::1]").unwrap();
        assert_eq!(hp.host, "[::1]");
        assert_eq!(hp.port, None);
    }

    #[test]
    fn test_parse_host_port_default_port_443() {
        let hp = parse_host_port("example.com").unwrap();
        assert_eq!(hp.port, None); // None means default 443
    }

    #[test]
    fn test_parse_host_port_subdomain() {
        let hp = parse_host_port("sub.domain.example.com:8443").unwrap();
        assert_eq!(hp.host, "sub.domain.example.com");
        assert_eq!(hp.port, Some(8443));
    }

    // ── CLI flag / config precedence tests ───────────────────────────

    #[test]
    fn test_absent_bool_flags_do_not_override_config() {
        use clap::Parser;
        // Absent flags parse as plain `false`...
        let cli = Args::try_parse_from(["tlschecker", "example.com"]).unwrap();
        assert!(!cli.check_revocation);
        assert!(!cli.grade);

        // ...and a config file enabling them must survive a CLI run where the
        // flags are absent (regression: Option<bool> + SetTrue used to yield
        // Some(false), silently overriding the config file).
        let mut config_file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(
            &mut config_file,
            b"hosts = [\"example.com\"]\ncheck_revocation = true\ngrade = true\n",
        )
        .unwrap();
        let cli = Args::try_parse_from([
            "tlschecker",
            "--config",
            config_file.path().to_str().unwrap(),
        ])
        .unwrap();
        let final_config = load_config(&cli).unwrap();
        assert!(final_config.check_revocation);
        assert!(final_config.grade);
    }

    #[test]
    fn test_present_bool_flags_override_config() {
        use clap::Parser;
        let mut config_file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut config_file, b"hosts = [\"example.com\"]\n").unwrap();
        let cli = Args::try_parse_from([
            "tlschecker",
            "--config",
            config_file.path().to_str().unwrap(),
            "--check-revocation",
            "--grade",
        ])
        .unwrap();
        let final_config = load_config(&cli).unwrap();
        assert!(final_config.check_revocation);
        assert!(final_config.grade);
    }

    #[test]
    fn test_parse_host_port_invalid_port_is_error() {
        let result = parse_host_port("example.com:99999");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid port '99999'"));
    }

    #[test]
    fn test_parse_host_port_non_numeric_suffix_is_hostname() {
        // A colon followed by non-digits is not a port specification; the
        // address is treated as an (almost certainly unresolvable) hostname
        // rather than rejected here.
        let hp = parse_host_port("example.com:abc").unwrap();
        assert_eq!(hp.host, "example.com:abc");
        assert_eq!(hp.port, None);
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
            min_validity: None,
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
            min_validity: None,
        };
        let result = FinalConfig::from_merged_config(config);
        assert!(result.is_err());
    }

    #[test]
    fn test_final_config_negative_min_validity_returns_error() {
        let config = Config {
            hosts: Some(vec!["example.com".to_string()]),
            output: Some("summary".to_string()),
            exit_code: Some(0),
            check_revocation: Some(false),
            prometheus: None,
            grade: Some(false),
            min_validity: Some(-5),
        };
        match FinalConfig::from_merged_config(config) {
            Err(e) => assert!(e
                .to_string()
                .contains("min_validity must be zero or positive")),
            Ok(_) => panic!("negative min_validity should be rejected"),
        }
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
            min_validity: None,
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
            min_validity: None,
        };
        let final_config = FinalConfig::from_merged_config(config).unwrap();
        assert_eq!(final_config.output, OutFormat::Summary);
        assert_eq!(final_config.exit_code, 0);
        assert!(!final_config.check_revocation);
        assert!(!final_config.prometheus);
        assert!(!final_config.grade);
        assert_eq!(final_config.prometheus_address, "http://localhost:9091");
        assert_eq!(final_config.min_validity, 0);
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
            min_validity: Some(30),
        };
        let final_config = FinalConfig::from_merged_config(config).unwrap();
        assert_eq!(final_config.addresses, vec!["a.com", "b.com"]);
        assert_eq!(final_config.output, OutFormat::Json);
        assert_eq!(final_config.exit_code, 2);
        assert!(final_config.check_revocation);
        assert!(final_config.prometheus);
        assert_eq!(final_config.prometheus_address, "http://prom:9091");
        assert!(final_config.grade);
        assert_eq!(final_config.min_validity, 30);
    }

    // ── min_validity FinalConfig tests ──────────────────────────────

    #[test]
    fn test_final_config_min_validity_default_is_zero() {
        let config = Config {
            hosts: Some(vec!["example.com".to_string()]),
            output: None,
            exit_code: None,
            check_revocation: None,
            prometheus: None,
            grade: None,
            min_validity: None,
        };
        let final_config = FinalConfig::from_merged_config(config).unwrap();
        assert_eq!(final_config.min_validity, 0);
    }

    #[test]
    fn test_final_config_min_validity_explicit_value() {
        let config = Config {
            hosts: Some(vec!["example.com".to_string()]),
            output: None,
            exit_code: None,
            check_revocation: None,
            prometheus: None,
            grade: None,
            min_validity: Some(60),
        };
        let final_config = FinalConfig::from_merged_config(config).unwrap();
        assert_eq!(final_config.min_validity, 60);
    }

    #[test]
    fn test_final_config_min_validity_zero_means_disabled() {
        let config = Config {
            hosts: Some(vec!["example.com".to_string()]),
            output: None,
            exit_code: None,
            check_revocation: None,
            prometheus: None,
            grade: None,
            min_validity: Some(0),
        };
        let final_config = FinalConfig::from_merged_config(config).unwrap();
        assert_eq!(final_config.min_validity, 0);
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

    pub(crate) fn make_test_tls() -> TLS {
        TLS {
            cipher: tlschecker::Cipher {
                name: "TLS_AES_256_GCM_SHA384".to_string(),
                version: "TLSv1.3".to_string(),
                bits: 256,
                alpn: Some("h2".to_string()),
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
                valid_from_unix: 1_735_689_600,
                valid_to_unix: 1_798_761_599,
                validity_days: 365,
                validity_hours: 8760,
                is_expired: false,
                cert_sn: "1234567890".to_string(),
                cert_ver: "2".to_string(),
                cert_alg: "sha256WithRSAEncryption".to_string(),
                sans: vec![
                    "test.example.com".to_string(),
                    "www.example.com".to_string(),
                ],
                chain: Some(vec![tlschecker::Chain {
                    subject: "test.example.com".to_string(),
                    issuer: "Test CA Root".to_string(),
                    valid_from: "Jan  1 00:00:00 2025 GMT".to_string(),
                    valid_to: "Dec 31 23:59:59 2026 GMT".to_string(),
                    signature_algorithm: "sha256WithRSAEncryption".to_string(),
                }]),
                revocation_status: RevocationStatus::NotChecked,
                trust: TrustStatus::Unknown,
                is_self_signed: false,
                security_warnings: vec![],
                cert_key_bits: 2048,
                cert_key_algorithm: "RSA".to_string(),
                cert_sha256: "AB:CD:EF".to_string(),
                cert_sha1: "12:34:56".to_string(),
                subject_key_id: Some("AA:BB:CC".to_string()),
                authority_key_id: Some("DD:EE:FF".to_string()),
                validation_level: Some("OV".to_string()),
                key_usage: vec!["digitalSignature".to_string()],
                ext_key_usage: vec!["serverAuth".to_string()],
                is_ca: false,
                path_len: None,
                scts: Vec::new(),
                pem: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n".to_string(),
            },
            grade: None,
            scan: None,
            ct: None,
        }
    }

    #[test]
    fn test_text_format_without_chain_does_not_panic() {
        // Regression: the `chain: None` arm used to be `todo!()`.
        let mut tls = make_test_tls();
        tls.certificate.chain = None;
        let output = TextFormat.format(&[tls]);
        assert!(output.contains("Hostname: test.example.com"));
        assert!(!output.contains("Additional Certificates"));
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
    fn test_text_format_new_warning_variants() {
        let mut tls_entry = make_test_tls();
        tls_entry.certificate.security_warnings = vec![
            tlschecker::SecurityWarning::HostnameMismatch("not valid for evil.com".to_string()),
            tlschecker::SecurityWarning::ExpiringIntermediate("Int CA expires soon".to_string()),
        ];
        let output = TextFormat.format(&[tls_entry]);
        assert!(output.contains("HOSTNAME MISMATCH: not valid for evil.com"));
        assert!(output.contains("EXPIRING INTERMEDIATE: Int CA expires soon"));
    }

    #[test]
    fn test_text_format_includes_fingerprints() {
        let output = TextFormat.format(&[make_test_tls()]);
        assert!(output.contains("SHA-256 Fingerprint: AB:CD:EF"));
        assert!(output.contains("SHA-1 Fingerprint: 12:34:56"));
    }

    #[test]
    fn test_text_format_renders_scan() {
        let mut tls_entry = make_test_tls();
        tls_entry.scan = Some(tlschecker::probe::TlsScan {
            protocols: vec![
                tlschecker::probe::ProtocolSupport {
                    version: tlschecker::probe::ProtoVersion::Tls1_3,
                    supported: true,
                    ciphers: vec!["TLS_AES_256_GCM_SHA384".to_string()],
                },
                tlschecker::probe::ProtocolSupport {
                    version: tlschecker::probe::ProtoVersion::Ssl3,
                    supported: false,
                    ciphers: vec![],
                },
            ],
        });
        let output = TextFormat.format(&[tls_entry]);
        assert!(output.contains("Supported Protocols & Ciphers:"));
        assert!(output.contains("TLSv1.3: supported"));
        assert!(output.contains("- TLS_AES_256_GCM_SHA384"));
        assert!(output.contains("SSLv3: not supported"));
    }

    #[test]
    fn test_json_format_includes_scan_when_present() {
        let mut tls_entry = make_test_tls();
        tls_entry.scan = Some(tlschecker::probe::TlsScan {
            protocols: vec![tlschecker::probe::ProtocolSupport {
                version: tlschecker::probe::ProtoVersion::Tls1_2,
                supported: true,
                ciphers: vec!["ECDHE-RSA-AES256-GCM-SHA384".to_string()],
            }],
        });
        let output = JsonFormat.format(&[tls_entry]);
        assert!(output.contains("\"scan\""));
        assert!(output.contains("TLSv1.2"));
        // fingerprints serialize; pem is skipped.
        assert!(output.contains("cert_sha256"));
        assert!(!output.contains("\"pem\""));
    }

    #[test]
    fn test_json_format_omits_scan_when_absent() {
        let output = JsonFormat.format(&[make_test_tls()]);
        assert!(!output.contains("\"scan\""));
    }

    #[test]
    fn test_text_format_with_grade() {
        let mut tls_entry = make_test_tls();
        tls_entry.grade = Some(tlschecker::grading::TLSGrade {
            grade: "B".to_string(),
            score: 75,
            categories: vec![tlschecker::grading::CategoryScore {
                category: "Protocol".to_string(),
                score: 80,
                reason: "TLS 1.2".to_string(),
            }],
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
        // When a grade is present, the Grade column header is shown.
        assert!(output.contains("Grade"));
    }

    #[test]
    fn test_summary_format_hides_grade_column_when_no_grade() {
        // Default (ungraded) run: the Grade column should be omitted entirely
        // rather than rendered as a column of "-".
        let output = SummaryFormat.format(&[make_test_tls()]); // grade: None
        assert!(
            !output.contains("Grade"),
            "Grade column should be hidden when no result has a grade"
        );
    }

    #[test]
    fn test_summary_format_shows_grade_column_when_any_graded() {
        // Mixed input: if any host has a grade, the column is shown.
        let ungraded = make_test_tls();
        let mut graded = make_test_tls();
        graded.certificate.hostname = "graded.example.com".to_string();
        graded.grade = Some(tlschecker::grading::TLSGrade {
            grade: "A+".to_string(),
            score: 98,
            categories: vec![],
        });
        let output = SummaryFormat.format(&[ungraded, graded]);
        assert!(output.contains("Grade"));
        assert!(output.contains("A+"));
    }

    #[test]
    fn test_summary_format_with_security_warnings() {
        let mut tls_entry = make_test_tls();
        tls_entry.certificate.security_warnings =
            vec![tlschecker::SecurityWarning::WeakSignatureAlgorithm(
                "SHA1 detected".to_string(),
            )];
        let output = SummaryFormat.format(&[tls_entry]);
        assert!(output.contains("Security Warnings:"));
        assert!(output.contains("WEAK ALGORITHM: SHA1 detected"));
    }

    // ── Certificate Transparency (--ct-check) rendering ────────────
    #[test]
    fn test_text_format_shows_ct_block_when_logged() {
        let mut tls_entry = make_test_tls();
        tls_entry.apply_ct(tlschecker::ct::CtStatus::Logged {
            crtsh_id: 12345,
            crtsh_url: "https://crt.sh/?id=12345".to_string(),
        });
        let output = TextFormat.format(&[tls_entry]);
        assert!(output.contains("Certificate Transparency:"));
        assert!(output.contains("Logged: yes"));
        assert!(output.contains("crt.sh: https://crt.sh/?id=12345"));
    }

    #[test]
    fn test_text_format_ct_unknown_has_no_warning() {
        // "Could not check" must render as unknown and produce NO warning.
        let mut tls_entry = make_test_tls();
        tls_entry.apply_ct(tlschecker::ct::CtStatus::Unknown);
        let output = TextFormat.format(&[tls_entry]);
        assert!(output.contains("Logged: unknown"));
        assert!(!output.contains("NOT IN CT LOG"));
    }

    #[test]
    fn test_not_logged_surfaces_warning_in_both_formatters() {
        let mut tls_entry = make_test_tls();
        // A certificate absent from CT logs is reported as a warning.
        tls_entry.apply_ct(tlschecker::ct::CtStatus::NotLogged);
        let text = TextFormat.format(&[tls_entry.clone()]);
        assert!(text.contains("NOT IN CT LOG"));
        assert!(text.contains("Logged: no"));
        let summary = SummaryFormat.format(&[tls_entry]);
        assert!(summary.contains("NOT IN CT LOG"));
    }

    // ── Embedded SCTs (offline, always-on) ────────────────────────
    fn sample_sct() -> tlschecker::sct::Sct {
        tlschecker::sct::Sct {
            version: 0,
            log_id: "ab".repeat(32),
            timestamp_ms: 1_234_567_890_000,
            timestamp: "2009-02-13T23:31:30Z".to_string(),
        }
    }

    #[test]
    fn test_text_format_shows_embedded_scts() {
        let mut tls_entry = make_test_tls();
        tls_entry.certificate.scts = vec![sample_sct()];
        let output = TextFormat.format(&[tls_entry]);
        assert!(output.contains("Embedded SCTs (Certificate Transparency): 1"));
        assert!(output.contains(&"ab".repeat(32)));
        assert!(output.contains("2009-02-13T23:31:30Z"));
    }

    #[test]
    fn test_text_format_omits_sct_block_when_none() {
        let output = TextFormat.format(&[make_test_tls()]); // scts empty
        assert!(!output.contains("Embedded SCTs"));
    }

    #[test]
    fn test_ct_unknown_notes_embedded_scts() {
        // Offline SCT evidence is surfaced even when crt.sh could not be queried.
        let mut tls_entry = make_test_tls();
        tls_entry.certificate.scts = vec![sample_sct()];
        tls_entry.apply_ct(tlschecker::ct::CtStatus::Unknown);
        let output = TextFormat.format(&[tls_entry]);
        assert!(output.contains("Logged: unknown"));
        assert!(output.contains("embedded SCT(s) present"));
    }

    // ── Conditional CT column in the summary table ─────────────────
    #[test]
    fn test_summary_shows_ct_column_when_checked() {
        let mut logged = make_test_tls();
        logged.apply_ct(tlschecker::ct::CtStatus::Logged {
            crtsh_id: 1,
            crtsh_url: "https://crt.sh/?id=1".to_string(),
        });
        let output = SummaryFormat.format(&[logged]);
        // Column header present, and the logged ✓ marker rendered for a cert
        // that produces no warning (the summary-positive-case gap, now fixed).
        assert!(output.contains("CT"));
        assert!(output.contains("✓"));
    }

    #[test]
    fn test_summary_hides_ct_column_when_not_checked() {
        // Without --ct-check, ct is None and the column is omitted.
        let output = SummaryFormat.format(&[make_test_tls()]);
        assert!(
            !output.contains(" CT "),
            "CT column should be hidden when no host was CT-checked"
        );
    }

    // ── should_grade (scan implies grade) ──────────────────────────

    #[test]
    fn test_should_grade_scan_implies_grade() {
        // --scan alone enables grading.
        assert!(should_grade(false, true));
        // --grade alone enables grading.
        assert!(should_grade(true, false));
        // both.
        assert!(should_grade(true, true));
        // neither: no grade.
        assert!(!should_grade(false, false));
    }

    #[test]
    fn test_use_dashboard() {
        // Default on an interactive terminal with no overrides.
        assert!(use_dashboard(true, false, false, false));
        // Non-TTY (piped/redirected) never uses the dashboard.
        assert!(!use_dashboard(false, false, false, false));
        // An explicit `-o`/config output opts out.
        assert!(!use_dashboard(true, true, false, false));
        // `--export-pem` opts out.
        assert!(!use_dashboard(true, false, true, false));
        // `--no-dashboard` opts out even on a bare TTY.
        assert!(!use_dashboard(true, false, false, true));
    }

    // ── min_validity exit logic tests ──────────────────────────────

    #[test]
    fn test_min_validity_below_threshold_triggers_failure() {
        // Cert with 20 days left, threshold 30 → should be below min validity
        let mut tls = make_test_tls();
        tls.certificate.validity_days = 20;
        tls.certificate.is_expired = false;
        let results = vec![tls];

        let min_validity = 30;
        let below = results
            .iter()
            .any(|c| !c.certificate.is_expired && c.certificate.validity_days < min_validity);
        assert!(below);
    }

    #[test]
    fn test_min_validity_above_threshold_no_failure() {
        // Cert with 365 days left, threshold 30 → should be above min validity
        let tls = make_test_tls(); // validity_days = 365
        let results = vec![tls];

        let min_validity = 30;
        let below = results
            .iter()
            .any(|c| !c.certificate.is_expired && c.certificate.validity_days < min_validity);
        assert!(!below);
    }

    #[test]
    fn test_min_validity_exact_threshold_no_failure() {
        // Cert with exactly 30 days left, threshold 30 → not below, so no failure
        let mut tls = make_test_tls();
        tls.certificate.validity_days = 30;
        tls.certificate.is_expired = false;
        let results = vec![tls];

        let min_validity = 30;
        let below = results
            .iter()
            .any(|c| !c.certificate.is_expired && c.certificate.validity_days < min_validity);
        assert!(!below);
    }

    #[test]
    fn test_min_validity_disabled_when_zero() {
        // Even with low validity, when min_validity is 0 (disabled), no check
        let mut tls = make_test_tls();
        tls.certificate.validity_days = 5;
        tls.certificate.is_expired = false;
        let results = vec![tls];

        let min_validity = 0;
        // The exit logic only checks when min_validity > 0
        let would_check = min_validity > 0;
        assert!(!would_check);

        // Even if we checked, the result wouldn't matter since the check is skipped
        let below = results
            .iter()
            .any(|c| !c.certificate.is_expired && c.certificate.validity_days < min_validity);
        // 5 < 0 is false, so even without the guard the logic is safe
        assert!(!below);
    }

    #[test]
    fn test_min_validity_ignores_already_expired_certs() {
        // Already expired cert with negative days — should NOT trigger min_validity
        // (expired certs are handled by the expired check, not min_validity)
        let mut tls = make_test_tls();
        tls.certificate.validity_days = -10;
        tls.certificate.is_expired = true;
        let results = vec![tls];

        let min_validity = 30;
        let below = results
            .iter()
            .any(|c| !c.certificate.is_expired && c.certificate.validity_days < min_validity);
        assert!(!below); // is_expired = true, so filtered out
    }

    #[test]
    fn test_min_validity_multiple_certs_one_below() {
        // Two certs: one healthy (365 days), one close to expiry (10 days)
        let tls_healthy = make_test_tls(); // 365 days
        let mut tls_expiring = make_test_tls();
        tls_expiring.certificate.validity_days = 10;
        tls_expiring.certificate.is_expired = false;
        let results = vec![tls_healthy, tls_expiring];

        let min_validity = 30;
        let below = results
            .iter()
            .any(|c| !c.certificate.is_expired && c.certificate.validity_days < min_validity);
        assert!(below); // one cert is below threshold
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
