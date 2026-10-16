# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

One status for every frontend (#205), meaningful exit codes (#206) and a
versioned JSON schema (#208). See the README's *Status & exit codes* and *JSON
output* sections for the full rules.

### Breaking

1. **tlschecker fails by default.** It exits 1 when any host is Critical and 3
   when a host could not be checked. v2 exited 0 unless `--exit-code` was set.
2. **Fixed exit codes:** 0 ok, 1 certificate problem, 2 usage/config, 3 host(s)
   not checked, 4 internal. Precedence: 1 beats 3.
   - Config and validation errors, and out-of-range `--connect-timeout` /
     `--concurrency`, move from 1 to 2.
   - Runtime and dashboard terminal errors move from 1 to 4.
3. **One status everywhere (#205).** The summary Status column, text, JSON, the
   dashboard, Prometheus and the exit code all use
   `tlschecker::verdict::assess`.
   - The summary now shows Critical for hostname mismatch and revoked
     certificates (v2 showed Healthy), and Warning for self-signed, untrusted
     or any warning.
   - The dashboard now shows hostname mismatch as Critical (was Warning).
   - A host whose only finding is not-in-CT is now Healthy, because that
     finding is Info (was Warning).
4. **Expiry windows are now "fewer than".**
   - Critical below 15 days (was ≤ 15); Warning below 30 days (was ≤ 30).
   - Certificates with a lifetime under 90 days use the last sixth (Critical)
     or third (Warning) of their lifetime.
   - `--min-validity N` now also makes the status Critical below N days, with
     exactly v2's `< N`, and replaces the default critical window. 0 means only
     expired certificates are Critical.
5. **`--exit-code` / `exit_code` are deprecated.** 1 is a no-op (it is the
   default). 0 means `--fail-on never`, and unreachable hosts still exit 3. Any
   other value is an error (exit 2).
6. **`--fail-on-error` is a deprecated no-op.** Use `--allow-unreachable` to
   opt out.
7. **`--export-pem` follows the same exit rules.** Extraction scripts need
   `--fail-on never`.
8. **Prometheus `instance` includes the port when it is not 443** (#207):
   `example.com:8443` instead of `example.com`. Hosts on 443 keep their series.
   Before, two ports of one host shared a grouping key and each push replaced
   the other's series.
9. **New JSON schema (#208).** `-o json` prints
   `{"schema_version": 1, "results": [...]}` instead of a bare array of the
   library's `TLS` structs:
   - Hosts that could not be checked are listed (`"outcome": "error"` with an
     `error` object) instead of being missing from the output.
   - Missing values are `null`, never the string `"None"`; every key is always
     present.
   - Dates are RFC 3339 (`not_before` / `not_after`) with the Unix seconds
     alongside, also for each `chain` entry.
   - Fields are grouped and renamed, e.g. `certificate.validity_days` →
     `certificate.days_remaining`, `certificate.issued` → `certificate.issuer`,
     `cipher.name` / `cipher.version` → `connection.cipher` /
     `connection.protocol`, `cert_ver` "2" → `version` 3, `cert_sha256` →
     `fingerprints.sha256`, `revocation_status` / `revocation_detail` →
     `revocation.status` / `revocation.detail`, `ct_detail` → `ct.detail`.
   - `security_warnings` is gone: every warning is a finding in `status`, with
     its code and severity.
   From schema version 1 on, changes are additive; anything else bumps
   `schema_version`.

### Added

- `--fail-on <critical|warning|never>` and the `fail_on` config key.
- `--allow <finding>` to accept a finding: it is still reported, marked
  `allowed`, but no longer affects the status or the exit code.
- `--allow-unreachable` to tolerate hosts that cannot be reached, as long as at
  least one host was checked.
- A `status` object in each JSON result: `{"verdict": "critical",
  "findings": [{"code", "severity", "allowed", "message"}]}`.
- A `Status:` line and a "Findings" block in text output; a "Findings" footer
  in the summary table.
- The `tlschecker_verdict` Prometheus gauge (0 healthy, 1 warning, 2 critical).
- A stderr explanation of every non-zero exit, naming the findings, the counts
  and the flag that changes the outcome.
- The exit-status table in `--help`.
- `port`, `target` and `input` in each JSON result and a `Port:` line in text
  output.
- `--output` as the long form of `-o`; `--hosts-file <PATH>` and `-` to read
  hosts from a file or stdin; `--wide` for the summary table; `--completions
  <SHELL>` to print a shell completion script (#214).
- `-v` / `-vv` / `-q` to choose how much is shown on stderr (`-v`/`-vv` raise
  tlschecker's own messages; other crates stay at warnings), and `RUST_LOG`
  support (#209).
- `error.hint` in JSON error entries: the same plain-language explanation
  stderr shows. The dashboard shows it above the raw error.
- The `tlschecker::verdict` library module and `SecurityWarning::message()`.
- `tlschecker::rfc3339_from_unix`, and `valid_from_unix` / `valid_to_unix` on
  `Chain`.
- A `weak-protocol` / `weak-cipher` finding (Warning) for a weak protocol or
  cipher **negotiated** on the connection, without `--scan` (#217). A host
  reachable only through the legacy-protocol retry used to read Healthy while
  graded D.

### Changed

- **stderr reads like a CLI, not a log** (#209). Lines are `error: …` /
  `warning: …` with no timestamp, module path or span fields, and colour only
  when stderr is a terminal and `NO_COLOR` is unset. Info-level messages (e.g.
  the legacy-protocol retry) are no longer shown by default. A host that could
  not be checked reads `error: <host>: <plain-language reason>` for common
  errors (wrong port, refused, DNS, timeout, handshake rejected, client
  certificate required, …); the raw error is shown with `-v`.
- Running `tlschecker` with no arguments (and no `tlschecker.toml` in the
  current directory) prints the help instead of an error. The "no hosts" error is one line.
- **Slimmer summary table** (#214): `Host | Days left | Issuer | Protocol |
  Revocation | Status` (+ Grade / CT). The Expired and Self-Signed columns are
  gone — the Status column and the Findings section say both, with the reason
  — and Cipher Suite / Hours left moved behind `--wide`. The Issuer column falls
  back to the issuer's CN when it has no organization (it showed `None`).

### Fixed

- #205: the summary table, dashboard and exit code disagreed about the same
  host.
- #206: a run where every host was unreachable exited 0.
- #207: checking several ports of one host printed identical `host` labels in
  the summary table and findings; they now read `host:port`.
- #208: JSON silently dropped hosts that could not be checked.
- A `tlschecker.toml` in the current directory that failed to parse was
  silently ignored, dropping its hosts and settings; its error is now reported
  (exit 2).
- #221: a port written out that equals the scheme's default (`http://host:80`)
  was ignored and the host was checked on 443. A written port is now always
  used; a URL without a port (`http://host`) is still checked on 443.
- Config errors now print the actual error, not only the usage hints.
- `--fail-on-error` alone used to do nothing (it needed `--exit-code`).
- `--exit-code 256` silently exited 0.

### Migration

| v2 | v3 |
|---|---|
| `--exit-code 1` | drop it |
| `--exit-code 1 --fail-on-error` | drop both |
| relied on exit 0 / monitoring cron / Prometheus | `--fail-on never` (add `--allow-unreachable` to also ignore down hosts) |
| config `exit_code = 0` | `fail_on = "never"` |
| config `exit_code = 1` | delete it |
| `--exit-code N` with `$? -eq N` | test for 1 |
| matched 1 for config errors | match 2 |
| check by IP without IP SANs | `--allow hostname-mismatch` or check by name |
| short-lived certs with a fixed SLO | `--min-validity` |
| export chains from broken hosts | `--export-pem --fail-on never` |
| `jq '.[]'` | `jq '.results[]'` (and `select(.outcome == "checked")` to skip failed hosts) |
| `.certificate.validity_days` / `.certificate.issued` | `.certificate.days_remaining` / `.certificate.issuer` |
| `.cipher.name` / `.cipher.version` | `.connection.cipher` / `.connection.protocol` |
| `.certificate.cert_sha256` | `.certificate.fingerprints.sha256` |
| `.certificate.security_warnings` | `.status.findings` |
| summary columns Cipher Suite / Hours before expired | `--wide` (or `-o text` / `-o json`) |
| summary columns Expired / Self-Signed | the Status column and Findings section |
| `tlschecker $(cat hosts.txt)` | `tlschecker --hosts-file hosts.txt` (or `… \| tlschecker -`) |

## [2.0.2] - 2026-09-29

### Added

- Configurable connection timeout for host checks.

### Fixed

- Verify OCSP/CRL signatures and harden certificate-extension parsing against
  malformed input.

### Changed

- Update dependencies, improve interactive dashboard documentation, and expand
  configuration and integration-test coverage.
- Update GitHub Actions workflows and expand integration-test coverage.

## [2.0.1] - 2026-07-20

A maintenance release focused on Prometheus/observability robustness and the
example deployment assets. No library or CLI behavior changes beyond the
Prometheus push path.

### Fixed

- **Prometheus push grouping key is now stable identity only** (`job` +
  `instance`). Volatile metadata (grade, cipher, protocol version, issuer) moved
  onto a dedicated `tlschecker_certificate_info` info metric so changing values
  no longer orphan a previous run's series in the push gateway.
- `--prometheus` is now a plain boolean flag rather than taking an optional
  value.

### Added

- **Grafana dashboard** and **Prometheus alert rules** examples, hardened for
  SRE use, plus a **Kubernetes CronJob** example manifest.

### Changed

- Grafana dashboard: "Days until expiration" is shown in days (not auto-scaled
  units) and the cert-health stat tiles are scoped to the `Issuer` variable.
- CI: bumped `actions/checkout` to v7.

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

[2.0.1]: https://github.com/jbovet/tlschecker/compare/v2.0.0...v2.0.1
[2.0.2]: https://github.com/jbovet/tlschecker/compare/v2.0.1...v2.0.2
[2.0.0]: https://github.com/jbovet/tlschecker/compare/v1.1.1...v2.0.0
[1.1.1]: https://github.com/jbovet/tlschecker/releases/tag/v1.1.1
