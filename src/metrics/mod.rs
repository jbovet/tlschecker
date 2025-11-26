//! Metrics collection and export module.
//!
//! This module provides functionality for exporting TLS certificate metrics
//! to external monitoring systems. Currently supports Prometheus Push Gateway.
//!
//! # Submodules
//!
//! - `prom` - Prometheus metrics integration

pub mod prom;
