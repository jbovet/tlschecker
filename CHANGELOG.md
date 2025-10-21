# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2025-10-21

### Added
- 🎉 **Library API for crates.io** - tlschecker is now available as a reusable Rust library
- Comprehensive error handling with detailed error types
- Feature flags for optional dependencies (`cli`, `prometheus-metrics`)
- Five example programs demonstrating library usage
- Proper SPDX license identifier (MIT OR Apache-2.0)
- Documentation improvements for docs.rs
- Support for IP addresses in Subject Alternative Names (SANs)
- MSRV (Minimum Supported Rust Version) specification: 1.70

### Changed
- **BREAKING**: Updated to Rust 2021 edition
- **BREAKING**: Improved error types - `TLSValidationError` is now an enum with detailed variants
- **BREAKING**: License changed from "GNU" to dual MIT/Apache-2.0 (standard Rust license)
- CLI dependencies are now optional (use `--features cli` to include)
- Removed all `unwrap()` and `panic!` calls from library code
- Better handling of certificate parsing errors
- Improved documentation with more examples

### Fixed
- Fixed panic when parsing SANs containing IP addresses instead of DNS names
- Fixed panic when OpenSSL stack creation fails
- Fixed panic when serial number conversion fails
- Better error messages for DNS resolution and connection failures
- Graceful handling of missing or invalid certificate data

### Security
- No `unsafe` code in the library
- Proper error propagation instead of panics
- Better validation of certificate fields

## [1.1.1] - Previous Release

### Features
- TLS/SSL certificate checking from command line
- Certificate expiration validation
- OCSP and CRL revocation checking
- Prometheus metrics export
- Multiple output formats (JSON, Text, Summary)
- Configuration file support (TOML)
- Multi-threaded host checking

---

## Migration Guide: 1.1.1 → 1.2.0

### For Library Users

If you're using tlschecker as a library, the main changes are:

1. **Error Handling**: The error type is now more detailed
   ```rust
   // Before (if you were matching on error details)
   match result {
       Err(e) if e.details.contains("DNS") => { /* ... */ }
   }

   // After (use proper enum variants)
   match result {
       Err(TLSValidationError::DnsResolution { hostname, .. }) => { /* ... */ }
   }
   ```

2. **Import Path**: Error types now in separate module
   ```rust
   // Add to imports
   use tlschecker::error::TLSValidationError;
   // Or use the Result alias
   use tlschecker::Result;
   ```

### For CLI Users

The CLI remains backwards compatible. No changes needed.

### For Cargo.toml

If you don't need the CLI tool, you can now use:
```toml
[dependencies]
tlschecker = { version = "1.2.0", default-features = false }
```

This will include only the library without CLI dependencies.

[1.2.0]: https://github.com/jbovet/tlschecker/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/jbovet/tlschecker/releases/tag/v1.1.1
