use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

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

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PrometheusConfig {
    /// Enable prometheus metrics pushing
    pub enabled: Option<bool>,
    /// Prometheus push gateway address
    pub address: Option<String>,
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content =
            fs::read_to_string(path.as_ref()).map_err(|e| ConfigError::Io(e.to_string()))?;

        let config: Config =
            toml::from_str(&content).map_err(|e| ConfigError::Parse(e.to_string()))?;

        Ok(config)
    }

    /// Create a default configuration
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

    /// Merge this config with another, prioritizing the other config's values
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

    /// Convert CLI arguments to a Config for merging
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

    /// Generate an example configuration file
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

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Parse(String),
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
