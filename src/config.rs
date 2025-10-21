//! Configuration file management for TLSChecker.
//!
//! This module handles loading, parsing, and merging configuration from TOML files
//! and command-line arguments. It supports a hierarchical configuration system where
//! settings can be specified in multiple places with clear precedence rules.
//!
//! # Configuration Precedence
//!
//! 1. Default values (lowest priority)
//! 2. Configuration file (tlschecker.toml or specified with --config)
//! 3. Command-line arguments (highest priority)
//!
//! # Example Configuration File
//!
//! ```toml
//! hosts = ["example.com", "example.com:8443"]
//! output = "summary"
//! exit_code = 1
//! check_revocation = true
//!
//! [prometheus]
//! enabled = true
//! address = "http://localhost:9091"
//! ```

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// Main configuration structure for TLSChecker.
///
/// All fields are optional to support partial configuration and merging.
/// Missing values will be filled in by defaults or overridden by CLI arguments.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    /// List of hosts to check
    pub hosts: Option<Vec<String>>,
    /// Output format: json, text, summary
    pub output: Option<String>,
    /// Exit code to use when certificates are expired/revoked
    pub exit_code: Option<i32>,
    /// Enable certificate revocation checking
    pub check_revocation: Option<bool>,
    /// Prometheus configuration
    pub prometheus: Option<PrometheusConfig>,
}

/// Prometheus integration configuration.
///
/// Controls whether metrics are pushed to a Prometheus Push Gateway
/// and specifies the gateway address.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PrometheusConfig {
    /// Enable prometheus metrics pushing
    pub enabled: Option<bool>,
    /// Prometheus push gateway address (e.g., "http://localhost:9091")
    pub address: Option<String>,
}

impl Config {
    /// Loads configuration from a TOML file.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the TOML configuration file
    ///
    /// # Returns
    ///
    /// * `Ok(Config)` - Successfully parsed configuration
    /// * `Err(ConfigError::Io)` - File could not be read
    /// * `Err(ConfigError::Parse)` - File contains invalid TOML
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use tlschecker::config::Config;
    /// let config = Config::from_file("tlschecker.toml")?;
    /// # Ok::<(), tlschecker::config::ConfigError>(())
    /// ```
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content =
            fs::read_to_string(path.as_ref()).map_err(|e| ConfigError::Io(e.to_string()))?;

        let config: Config =
            toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;

        Ok(config)
    }

    /// Creates a default configuration with sensible defaults.
    ///
    /// # Default Values
    ///
    /// - `hosts`: None (must be provided)
    /// - `output`: "summary"
    /// - `exit_code`: 0 (don't fail on expired certificates)
    /// - `check_revocation`: false
    /// - `prometheus.enabled`: false
    /// - `prometheus.address`: "http://localhost:9091"
    ///
    /// # Returns
    ///
    /// A `Config` struct with default values.
    pub fn default() -> Self {
        Config {
            hosts: None,
            output: Some("summary".to_string()),
            exit_code: Some(0),
            check_revocation: Some(false),
            prometheus: Some(PrometheusConfig {
                enabled: Some(false),
                address: Some("http://localhost:9091".to_string()),
            }),
        }
    }

    /// Merges this configuration with another, prioritizing the other's values.
    ///
    /// For each field, if the `other` config has a value (Some), it overrides
    /// this config's value. If the `other` value is None, keeps the current value.
    ///
    /// # Arguments
    ///
    /// * `other` - Configuration to merge (takes priority)
    ///
    /// # Returns
    ///
    /// The merged configuration with `other`'s values taking precedence.
    ///
    /// # Example
    ///
    /// ```
    /// # use tlschecker::config::Config;
    /// let defaults = Config::default();
    /// let file_config = Config::from_file("config.toml").unwrap_or_default();
    /// let merged = defaults.merge_with(file_config);
    /// ```
    pub fn merge_with(mut self, other: Config) -> Self {
        if other.hosts.is_some() {
            self.hosts = other.hosts;
        }
        if other.output.is_some() {
            self.output = other.output;
        }
        if other.exit_code.is_some() {
            self.exit_code = other.exit_code;
        }
        if other.check_revocation.is_some() {
            self.check_revocation = other.check_revocation;
        }
        if let Some(other_prom) = other.prometheus {
            if let Some(ref mut self_prom) = self.prometheus {
                if other_prom.enabled.is_some() {
                    self_prom.enabled = other_prom.enabled;
                }
                if other_prom.address.is_some() {
                    self_prom.address = other_prom.address;
                }
            } else {
                self.prometheus = Some(other_prom);
            }
        }
        self
    }

    /// Creates a Config from command-line arguments for merging.
    ///
    /// Converts CLI arguments into a Config structure that can be merged
    /// with file-based and default configurations. Only provided arguments
    /// (Some values) will override other configurations.
    ///
    /// # Arguments
    ///
    /// * `addresses` - List of hosts to check
    /// * `output` - Output format (json, text, summary)
    /// * `exit_code` - Exit code for failures
    /// * `prometheus` - Enable Prometheus metrics
    /// * `prometheus_address` - Prometheus push gateway address
    /// * `check_revocation` - Enable certificate revocation checking
    ///
    /// # Returns
    ///
    /// A `Config` struct with only the specified CLI values set.
    pub fn from_cli_args(
        addresses: Option<Vec<String>>,
        output: Option<String>,
        exit_code: Option<i32>,
        prometheus: Option<bool>,
        prometheus_address: Option<String>,
        check_revocation: Option<bool>,
    ) -> Self {
        Config {
            hosts: addresses,
            output,
            exit_code,
            check_revocation,
            prometheus: Some(PrometheusConfig {
                enabled: prometheus,
                address: prometheus_address,
            }),
        }
    }

    /// Generates an example configuration file in TOML format.
    ///
    /// Creates a sample configuration with all available options set to
    /// example values. Useful for bootstrapping a new configuration file.
    ///
    /// # Returns
    ///
    /// A pretty-printed TOML string containing example configuration.
    ///
    /// # Example
    ///
    /// ```
    /// # use tlschecker::config::Config;
    /// let example = Config::example_toml();
    /// println!("{}", example);
    /// // Save to file: std::fs::write("tlschecker.toml", example)?;
    /// ```
    pub fn example_toml() -> String {
        let example = Config {
            hosts: Some(vec![
                "example.com".to_string(),
                "example.com:8443".to_string(),
                "https://secure.example.com:9443".to_string(),
                "expired.badssl.com".to_string(),
            ]),
            output: Some("summary".to_string()),
            exit_code: Some(1),
            check_revocation: Some(true),
            prometheus: Some(PrometheusConfig {
                enabled: Some(true),
                address: Some("http://localhost:9091".to_string()),
            }),
        };

        toml::to_string_pretty(&example)
            .unwrap_or_else(|_| "# Error generating example".to_string())
    }
}

/// Errors that can occur during configuration loading and parsing.
#[derive(Debug)]
pub enum ConfigError {
    /// I/O error (file not found, permission denied, etc.)
    Io(String),
    /// TOML parsing error (invalid syntax, type mismatch, etc.)
    Parse(String),
    /// Validation error (missing required fields, invalid values, etc.)
    Validation(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(msg) => write!(f, "IO Error: {}", msg),
            ConfigError::Parse(msg) => write!(f, "Parse Error: {}", msg),
            ConfigError::Validation(msg) => write!(f, "Validation Error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_from_toml() {
        let toml_content = r#"
            hosts = ["jpbd.dev", "google.cl"]
            output = "json"
            exit_code = 1
            check_revocation = true

            [prometheus]
            enabled = true
            address = "http://localhost:9092"
        "#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(toml_content.as_bytes()).unwrap();

        let config = Config::from_file(temp_file.path()).unwrap();

        assert_eq!(
            config.hosts,
            Some(vec!["jpbd.dev".to_string(), "google.cl".to_string()])
        );
        assert_eq!(config.output, Some("json".to_string()));
        assert_eq!(config.exit_code, Some(1));
        assert_eq!(config.check_revocation, Some(true));

        let prometheus = config.prometheus.unwrap();
        assert_eq!(prometheus.enabled, Some(true));
        assert_eq!(
            prometheus.address,
            Some("http://localhost:9092".to_string())
        );
    }

    #[test]
    fn test_config_merge() {
        let base_config = Config {
            hosts: Some(vec!["base.com".to_string()]),
            output: Some("text".to_string()),
            exit_code: Some(0),
            check_revocation: Some(false),
            prometheus: Some(PrometheusConfig {
                enabled: Some(false),
                address: Some("http://base:9091".to_string()),
            }),
        };

        let override_config = Config {
            hosts: Some(vec!["override.com".to_string()]),
            output: None,
            exit_code: Some(1),
            check_revocation: Some(true),
            prometheus: Some(PrometheusConfig {
                enabled: Some(true),
                address: None,
            }),
        };

        let merged = base_config.merge_with(override_config);

        // Override config should take precedence where specified
        assert_eq!(merged.hosts, Some(vec!["override.com".to_string()]));
        assert_eq!(merged.output, Some("text".to_string())); // From base (not overridden)
        assert_eq!(merged.exit_code, Some(1)); // Overridden
        assert_eq!(merged.check_revocation, Some(true)); // Overridden

        let prometheus = merged.prometheus.unwrap();
        assert_eq!(prometheus.enabled, Some(true)); // Overridden
        assert_eq!(prometheus.address, Some("http://base:9091".to_string())); // From base
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();

        assert_eq!(config.hosts, None);
        assert_eq!(config.output, Some("summary".to_string()));
        assert_eq!(config.exit_code, Some(0));
        assert_eq!(config.check_revocation, Some(false));

        let prometheus = config.prometheus.unwrap();
        assert_eq!(prometheus.enabled, Some(false));
        assert_eq!(
            prometheus.address,
            Some("http://localhost:9091".to_string())
        );
    }

    #[test]
    fn test_config_from_cli_args() {
        let config = Config::from_cli_args(
            Some(vec!["cli.com".to_string()]),
            Some("json".to_string()),
            Some(2),
            Some(true),
            Some("http://cli:9091".to_string()),
            Some(true),
        );

        assert_eq!(config.hosts, Some(vec!["cli.com".to_string()]));
        assert_eq!(config.output, Some("json".to_string()));
        assert_eq!(config.exit_code, Some(2));
        assert_eq!(config.check_revocation, Some(true));

        let prometheus = config.prometheus.unwrap();
        assert_eq!(prometheus.enabled, Some(true));
        assert_eq!(prometheus.address, Some("http://cli:9091".to_string()));
    }

    #[test]
    fn test_invalid_toml() {
        let invalid_toml = "hosts = [invalid toml";

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(invalid_toml.as_bytes()).unwrap();

        let result = Config::from_file(temp_file.path());
        assert!(result.is_err());

        match result.unwrap_err() {
            ConfigError::Parse(_) => {} // Expected
            other => panic!("Expected ParseError, got {:?}", other),
        }
    }

    #[test]
    fn test_example_toml_generation() {
        let example = Config::example_toml();

        // Should be valid TOML
        let parsed: Config = toml::from_str(&example).unwrap();

        // Should contain expected fields
        assert!(parsed.hosts.is_some());
        assert!(parsed.output.is_some());
        assert!(parsed.prometheus.is_some());
    }
}
