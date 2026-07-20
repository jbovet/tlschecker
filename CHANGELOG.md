# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-07-20

A large feature release that turns `tlschecker` from a batch certificate checker
into an interactive inspection tool, plus configuration grading, protocol
scanning, and Certificate Transparency support.

### Breaking

- **JSON `cert_sn` is now colon-separated uppercase hex** (e.g.
  `F4:4A:01:...`) instead of the decimal value of the ASN.1 INTEGER. This
  matches CA portals, browsers, and `openssl x509 -text`, but any consumer
  parsing the old decimal serial must be updated.
- **MSRV raised to 1.88.0** (required by ratatui 0.30).

### Added

- **Interactive dashboard** (ratatui) — the default output when stdout is a TTY,
  with a full-screen certificate explorer (`Enter` on a host) showing every
  field: DNs, validity, serial, fingerprints, SANs, chain, SCTs, grade reasons,
  and scan results. Piped/redirected output, `-o`, or `--export-pem` keep the
  classic formatters.
- **TLS configuration grading** (A+→F), opt-in via `--grade` and implied by
  `--scan`. Weighted composite over protocol, cipher, key exchange, key size,
  and trust, with hard caps for expired/revoked, obsolete protocols, weak
  ciphers, self-signed, and hostname mismatch.
- **Protocol/cipher scanning** (`--scan`) enumerating supported versions
  (SSLv3–TLS 1.3) and accepted ciphers.
- **Certificate Transparency** — network inclusion lookup via crt.sh
  (`--ct-check`) and always-on offline embedded-SCT parsing (RFC 6962).
- **Hostname verification** (SAN DNS with wildcard support, CN fallback) and
  **certificate chain security analysis** (weak signature algorithms, incomplete
  and out-of-order chains, expiring intermediates).
- **Trust validation** — reports whether the chain builds to a system root.
- **Authority Information Access URLs** surfaced: OCSP responders, CA Issuers,
  and CRL distribution points, in text, JSON, and the dashboard.
- **Certificate export** (`--export-pem`) with an interactive filename prompt in
  the dashboard.
- `--min-validity` threshold and `--fail-on-error` exit-code control.
- Docker support and multi-architecture release binaries
  (linux/macos × x86_64/aarch64).

### Changed

- Negative certificate serial numbers are rendered with a leading `-` rather
  than silently shown as positive.
- Prometheus export now uses a fresh per-host registry so a grade value can't
  leak between hosts.
- IDN hostnames are converted to A-label form before matching and resolution.

### Fixed

- OCSP verification now supplies chain intermediates to the verification stack.
- Stale CRLs (`nextUpdate` in the past) are rejected during revocation checks.
- Invalid ports in host arguments are rejected instead of silently mishandled.
- Config-file `check_revocation`/`grade` are no longer overridden by absent CLI
  flags.
- Panic paths on malformed certificates and the hours-remaining calculation.

## [1.1.1]

See the Git history for changes in 1.1.1 and earlier.

[2.0.0]: https://github.com/jbovet/tlschecker/compare/v1.1.1...v2.0.0
[1.1.1]: https://github.com/jbovet/tlschecker/releases/tag/v1.1.1
