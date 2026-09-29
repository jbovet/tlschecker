# TLSChecker

Experimental TLS/SSL certificate command-line checker

[![codecov](https://codecov.io/gh/jbovet/tlschecker/branch/main/graph/badge.svg?token=MN4EE3WYQ6)](https://codecov.io/gh/jbovet/tlschecker)

## Docker run

[DockerHub](https://hub.docker.com/repository/docker/josebovet/tlschecker)

Build the image locally:

```sh
docker build -t tlschecker:local .
```

Run the CLI from the container:

```sh
docker run --rm tlschecker:local example.com
```

For the interactive TUI, run the container with a pseudo-TTY and stdin attached:

```sh
docker run --rm -it tlschecker:local example.com
```

The TUI is only used when stdout is an interactive terminal. In non-interactive environments (pipelines, redirected output, CI), the container falls back to the classic text output.

If you are utilizing M1 or higher, please add the option --platform linux/x86_64.

```sh
docker run --platform linux/x86_64 josebovet/tlschecker:2.0.2 jpbd.dev
```

## Install

Linux (x86_64)

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v2.0.2/tlschecker-linux-x86_64.tar.gz
tar -xzf tlschecker-linux-x86_64.tar.gz
sudo install tlschecker /usr/local/bin/tlschecker
```

Linux (aarch64)

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v2.0.2/tlschecker-linux-aarch64.tar.gz
tar -xzf tlschecker-linux-aarch64.tar.gz
sudo install tlschecker /usr/local/bin/tlschecker
```

macOS (x86_64)

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v2.0.2/tlschecker-macos-x86_64.tar.gz
tar -xzf tlschecker-macos-x86_64.tar.gz
sudo install tlschecker /usr/local/bin/tlschecker
```

macOS (Apple Silicon)

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v2.0.2/tlschecker-macos-aarch64.tar.gz
tar -xzf tlschecker-macos-aarch64.tar.gz
sudo install tlschecker /usr/local/bin/tlschecker
```

## How to use

```sh
➜  tlschecker --help
```

### Interactive dashboard

When run in an interactive terminal, tlschecker opens a live dashboard by
default. Hosts stream in as they are checked:

```sh
➜ tlschecker jpbd.dev expired.badssl.com google.com cloudflare.com
```

![Dashboard: fleet list and tally on the left, the selected host's detail pane on the right](/img/dashboard.webp)

**Fleet list.** Every host with its verdict and grade:

- `✓` healthy · `⚠` warning (self-signed, any security warning, or ≤ 30 days
  left) · `✗` critical (expired, revoked, or ≤ 15 days left). A host that could
  not be checked shows why, e.g. `✗ host (DNS)`.
- A yellow `?` after the grade means a revocation or CT check you asked for
  could not reach a verdict (see *Not verified* below). It does not change the
  verdict: an unreachable OCSP responder or a crt.sh outage says nothing bad
  about the certificate.

The **Tally** below counts hosts per verdict, failed checks, and hosts with
unverified checks.

**Detail pane.** For the selected host:

- **Facts** — negotiated protocol, cipher and ALPN; issuer; key; `Revocation`
  (`Not revoked`, `Revoked (via CRL)`, `Unknown`, `Not checked`); `CT`
  (`Logged · <crt.sh link>`, `Not logged`, `Unknown` — shown once CT was
  checked); chain `Trust`; SHA-256 fingerprint.
- **Expiry gauge** — how much of the certificate's lifetime has elapsed.
- **Grade** with a gauge per category.
- **Not verified** — why a requested revocation or CT check came back
  `Unknown`, e.g. `OCSP: http://ocsp.example: response signature verification
  failed; CRL: certificate lists no CRL distribution point`.
- **Warnings** — every security warning for the host.

**Certificate explorer.** Press `Enter` on a host for the full report: subject
and issuer, validity, **Trust & Revocation** (self-signed, trust, revocation
and CT, with each failed OCSP responder / CRL distribution point on its own
`↳` line), certificate details (serial, fingerprints, key identifiers,
validation level, key usage, basic constraints), issuer and revocation URLs,
connection, SANs, embedded SCTs, the presented chain, the grade breakdown with
reasons, and scan results when `--scan` was used.

![Certificate explorer](/img/explorer.webp)

**Checks on demand.** Revocation and CT lookups are opt-in on the command line
because they cost network round trips — but you can run them from the
dashboard at any time for the selected host: `r` checks revocation (OCSP, then
CRL, against the chain already retrieved — no new TLS connection) and `c` looks
the certificate up in Certificate Transparency. The footer offers each one only
while the host has no definitive answer yet (never checked, or `Unknown`, so a
failed check can be retried). The pane shows `checking…` meanwhile; the verdict
and grade update when the result arrives, and a revocation found this way
counts toward `--exit-code`.

**Keys:**

| Key | Fleet list | Explorer |
|---|---|---|
| `j` / `k`, arrows | move | scroll |
| `PgUp` / `PgDn`, `Space` | — | page |
| `g` / `G` | first / last host | top / bottom |
| `Enter` | open the explorer | back |
| `Esc`, `Backspace` | `Esc` quits | back |
| `r` / `c` | check revocation / CT for the selected host | same |
| `e` | export the chain as PEM | same |
| `q`, `Ctrl+C` | quit | quit |

Press `e` on either screen to export the selected host's certificate chain as
PEM. The prompt is prefilled with a filename derived from the host (so
`https://example.com:8443` becomes `example.com.pem`); edit it as you like and
press `Enter` to write, or `Esc` to cancel (`Ctrl+U` clears the field, `Ctrl+W`
drops a path segment). An existing file is never
overwritten: the prompt stays open with the reason shown beneath the path, so
you can adjust the name and retry without retyping it. This is the interactive
equivalent of `--export-pem`.

The TUI requires an attached terminal. In Docker, that means using `-it` so the
container gets a pseudo-TTY and stdin. Without that, Docker will fall back to
the classic text output. The classic text outputs are also used automatically
whenever stdout is piped or redirected, and can always be forced with
`-o summary|json|text` or `--no-dashboard` (keeps the configured/`-o`
format) — so scripts, CI pipelines, and `tlschecker -o json | jq` behave
exactly as before.

## Examples

Basic usage:
```sh
➜ tlschecker --check-revocation x.com revoked.badssl.com jpbd.dev expired.badssl.com 
```
![](/img/1-2.png)

Using custom ports:
```sh
➜ tlschecker example.com:8443 secure-service.internal:9443
```

You can specify the port in three ways:
1. Using hostname:port format: `example.com:8443`
2. Using a full URL: `https://example.com:8443`
3. Using the default port (443) by just specifying the hostname: `example.com`

### Trust Validation

TLSChecker verifies that the presented certificate chain builds to a trusted root in your operating system's trust store — the same authoritative check a browser performs. This runs automatically for every host (it is offline and adds no latency) and is reported as a `Trust:` line and, in JSON, a `trust` field:

- **Trusted**: the chain builds to a system root CA
- **Untrusted (reason)**: the chain does not verify — the reason is the underlying error, e.g. `self-signed certificate`, `unable to get local issuer certificate`, or `certificate has expired`
- **Unknown**: no system trust store was available, so trust could not be determined (never reported as a problem)

An untrusted chain adds an `UNTRUSTED` security warning and caps the configuration grade at C. Because verification happens *after* inspection, expired and self-signed certificates are still fully reported rather than rejected at the handshake.

### Certificate Metadata

Every check also reports (offline, no extra flags) a set of certificate and
connection details:

- **ALPN** — the negotiated application protocol (`h2` / `http/1.1`).
- **Subject / Authority Key ID** — the SKI/AKI identifiers.
- **Validation Level** — `DV` / `OV` / `EV` / `IV`, derived from the CA/Browser-Forum policy OIDs.
- **Key Usage / Extended Key Usage / Basic Constraints** — what the certificate is authorized for.

It also raises **informational warnings** (which do *not* affect the grade, so
legitimate private/internal certificates are never penalized) for issuance
problems: a leaf asserting `CA:TRUE`, a missing `serverAuth` EKU, a low-entropy
serial, an over-long (> 398-day) validity period, or a chain link whose
signature does not cryptographically verify.

### Certificate Revocation Checking

TLSChecker supports comprehensive certificate revocation checking via both OCSP (Online Certificate Status Protocol) and CRL (Certificate Revocation List). These features allow you to verify if a certificate has been revoked by its issuing Certificate Authority.

To enable revocation checking, use the `--check-revocation` flag:

```sh
➜ tlschecker --check-revocation jpbd.dev
```

#### How Revocation Checking Works

When you enable revocation checking, TLSChecker will:

1. First check certificate status via OCSP, which provides real-time revocation information
2. If OCSP doesn't provide a definitive answer, fall back to CRL checking
3. Report the certificate as revoked if either method indicates revocation

The revocation status is shown the same way in every output (summary, text, and the dashboard):
- **Not revoked**: confirmed by OCSP or CRL
- **Revoked**: the certificate has been revoked, with how or when when available, e.g. `Revoked (via CRL)`
- **Unknown**: the status could not be determined. The reason — each OCSP responder and CRL distribution point that failed — is shown in `text` output, in JSON as `revocation_detail`, and in the dashboard's *Not verified* block
- **Not checked**: revocation was not requested (the default without the flag; in the dashboard, press `r` to check the selected host)

Example with a revoked certificate:
```sh
➜ tlschecker --check-revocation revoked.badssl.com
```

#### Revocation Checking Methods

**OCSP (Online Certificate Status Protocol)**:
- Real-time check with the certificate authority
- Faster and more up-to-date than CRLs
- May not be supported by all certificate authorities

**CRL (Certificate Revocation List)**:
- Downloads and checks the CA's published list of revoked certificates
- More widely supported than OCSP
- Lists may be larger and less frequently updated

Note: Revocation checking requires network connections to OCSP responders and CRL distribution points, which adds some latency to the checks.

#### Prometheus Integration with Revocation Metrics

When using Prometheus integration, the revocation status is included in the metrics:

```sh
tlschecker --prometheus --prometheus-address http://localhost:9091 --check-revocation example.com
```

A `tlschecker_revocation_status` metric is exported with the following values:

- 0 = Not checked
- 1 = Good (not revoked)
- 2 = Unknown
- 3 = Revoked

##### Metric labels and the push grouping key

Every pushed series carries only stable identity labels in the push **grouping key**: `job="tlschecker"` and `instance="<host>"`. This is deliberate — a `push_metrics` `PUT` replaces the series under its exact grouping key, so putting volatile values (grade, cipher, expired, …) in the key would leave the previous run's series orphaned in the gateway whenever one of those values changed.

Descriptive, changeable metadata therefore lives on a dedicated info metric, `tlschecker_certificate_info` (constant value `1`), with labels `cipher`, `cipher_protocol_version`, `issuer`, and `grade` (`N/A` when grading did not run). Join it to the numeric metrics on `instance` in your queries, e.g.:

```promql
tlschecker_days_before_expired * on(instance) group_left(grade, issuer) tlschecker_certificate_info
```

### Connection Timeout

Each host gets 30 seconds to connect by default. Use `--connect-timeout` to change that budget (1–3600 seconds):

```sh
➜ tlschecker --connect-timeout 5 example.com internal.example.com
```

The value is the budget for the **connect phase of one host** — shared across every address the hostname resolves to — and is also applied as the socket read timeout during the handshake. Because each check occupies a worker thread, lowering it keeps a large host list moving when some hosts are unreachable; raise it for slow links.

It is deliberately named for what it bounds: it does **not** cap the whole check. `--check-revocation` (OCSP and each CRL distribution point) and `--ct-check` keep their own separate timeouts, and `--scan` caps its per-handshake wait at 10 seconds regardless of this setting, since a scan performs on the order of a hundred connections. Note that lowering the timeout can make `--scan` report a protocol as unsupported when the probe merely timed out.

### Concurrency

Hosts are checked 32 at a time by default. Use `--concurrency` to change that (1–128):

```sh
➜ tlschecker --concurrency 64 $(cat hosts.txt)
```

A check spends its time waiting on the network, not the CPU, so the default does not depend on the machine's cores: a container limited to a single CPU checks as many hosts at once as a large server. Raise it for large host lists; lower it to go easy on a shared network or on many hosts behind a single address.

With `--check-revocation`, hosts whose certificates name the same CRL distribution point share one download of it, and a download is refused above 32 MiB (256 KiB for an OCSP response), so checking many hosts at once does not multiply memory use.

Hostnames that resolve to several addresses (an A and a AAAA record, or a pool of load-balanced servers) are tried **in resolution order until one accepts**, so a host that is up on one of its addresses is not reported as unreachable just because the first address it resolves to is not. This matters most on IPv4-only networks whose resolver still returns AAAA records.

### Certificate Fingerprints

Every check reports the SHA-256 and SHA-1 fingerprints of the leaf certificate (colon-separated uppercase hex, the same format as browsers and `openssl x509 -fingerprint`). They appear in `text` and `json` output and are useful for certificate pinning and comparison.

### Exporting the Certificate Chain (PEM)

Use `--export-pem` to print the presented certificate chain (leaf first, followed by any intermediates the server sent) as PEM instead of the normal report:

```sh
➜ tlschecker --export-pem example.com > example.pem
```

This works for multiple hosts too; each host's chain is printed in sequence.

### TLS Protocol & Cipher Scanning

By default tlschecker reports only the protocol and cipher that were negotiated for a single connection. With `--scan` it actively probes the server to enumerate **every** TLS protocol version (SSLv3 through TLS 1.3) and the cipher suites accepted at each version:

```sh
➜ tlschecker --scan example.com
```

Because this performs many short handshakes (one per version/cipher), it is slower than a normal check. Results are included in `text` and `json` output.

`--scan` implies `--grade` (the scan is surfaced through the grade, including in the summary table). Scan results feed the analysis: supporting an obsolete/deprecated protocol or accepting a weak cipher produces security warnings (see below) and lowers the grade. This makes the grade reflect the server's *full* posture rather than only the single negotiated connection (e.g. a server that negotiates TLS 1.3 but still allows TLS 1.0 will no longer score an A).

### Embedded SCTs (offline Certificate Transparency)

Every check also reads the leaf's **embedded Signed Certificate Timestamps** (SCTs) — the signed promises a CA receives when it submits a certificate to Certificate Transparency logs (RFC 6962). Their presence is offline proof that the certificate was submitted to CT, and unlike the `--ct-check` lookup below it needs **no network** and is always on:

```sh
➜ tlschecker -o text example.com
...
Embedded SCTs (Certificate Transparency): 2
  - log cb38f715897c84a1445f5bc1ddfbc96ef29a59cd470a690585b0cb14c31458e7 at 2026-05-18T19:35:22Z
  - log d809553b944f7affc816196f944f85abb0f8fc5e8755260f15d12e72bb454b14 at 2026-05-18T19:35:22Z
```

SCTs appear in `text` and `json` output only when present. They complement `--ct-check`: the lookup confirms *inclusion* against crt.sh, while embedded SCTs prove *submission* and stay available even when crt.sh is unreachable — so a `--ct-check` result of `Unknown` will note any embedded SCTs as offline evidence.

### Certificate Transparency Lookup

Modern browsers reject publicly-trusted certificates that are not logged in [Certificate Transparency](https://certificate.transparency.dev/) logs, and the same logs are what defenders watch for mis-issuance. With `--ct-check`, tlschecker looks the presented leaf up in public CT logs via [crt.sh](https://crt.sh), matched by its SHA-256 fingerprint (an exact, per-certificate lookup):

```sh
➜ tlschecker --ct-check example.com
```

This performs a network request to an external service (crt.sh), so it is opt-in and adds latency. The result is **tri-state**, like revocation status:

- **Logged** — the exact certificate was found in CT. The `text`/`json` output include a direct `crt.sh` link; the summary table shows `✓`.
- **Not logged** — crt.sh has no record of the certificate *and* it carries no embedded SCTs, so absence from CT is plausible. Reported as a security warning (see below) and shown as `✗` in the summary. A publicly-trusted certificate that is not logged will be rejected by modern browsers.
- **Unknown** — crt.sh was unreachable or rate-limited, or it has no record of a certificate that carries embedded SCTs (crt.sh is an aggregator and misses some certificates the logs do include), so the status could not be determined (`?` in the summary). This is kept distinct from "not logged" so an outage is never mistaken for a problem. The reason — together with any embedded-SCT evidence — is logged to **stderr** (stdout stays clean for `… -o json | jq`), kept in JSON as `ct_detail`, and shown in `text` output and the dashboard.

When `--ct-check` is used, the summary table gains a `CT` column (`✓`/`✗`/`?`); without it the column is hidden. Being absent from CT does **not** affect the grade — many legitimate internal/private certificates are intentionally absent from public CT logs, so what that means is left to you rather than the grade.

### Security Warnings

In addition to revocation and grading, tlschecker surfaces certificate problems as security warnings in all output formats:

- **Weak signature algorithm** — the certificate or a chain certificate is signed with SHA-1 or MD5
- **Incomplete chain** — the certificate's issuer was not found in the presented chain
- **Invalid chain order** — the chain is not in issuer order (each certificate should be followed by the one that issued it)
- **Hostname mismatch** — the certificate is not valid for the hostname you checked (no matching SAN, with wildcard support, or Common Name)
- **Invalid chain signature** — a presented certificate is not validly signed by the issuer found for it in the chain (forged or corrupted certificate)
- **Expiring intermediate** — an intermediate certificate in the chain has expired or expires within 30 days
- **Weak protocol** (`--scan`) — the server still supports an obsolete (SSLv3) or deprecated (TLS 1.0/1.1) protocol version
- **Weak cipher** (`--scan`) — the server accepts a weak cipher suite (RC4, DES/3DES, NULL, EXPORT, anonymous, ...)
- **Not in CT log** (`--ct-check`) — the presented certificate was not found in any public Certificate Transparency log

A hostname mismatch, an invalid chain signature, support for an obsolete protocol (SSLv3/TLS 1.0), or acceptance of a weak cipher each cap the TLS grade at C, the same as a self-signed certificate.

### Troubleshooting Connection Issues

If you encounter connection problems, here are some common error messages and solutions:

1. **"Cannot resolve hostname"**
   - Check that the hostname is spelled correctly
   - Verify your network and DNS configuration
   - Try using an IP address instead if DNS resolution is not available

2. **"Connection refused"**
   - Verify the host is running a TLS service on the specified port
   - Check if a firewall might be blocking the connection
   - Confirm the service is publicly accessible

3. **"TLS handshake failed"**
   - The server might be using an unsupported TLS version
   - There might be an issue with the server's certificate configuration
   - Your network might be intercepting the TLS connection

### Configuration File Support

You can use a TOML configuration file to check multiple hosts. Create a file like `tlschecker.toml`:

```toml
hosts = [
    "example.com",
    "example.com:8443",
    "secure-service.internal:9443",
]

# Optional settings
output = "summary"
exit_code = 1
check_revocation = true
grade = false
min_validity = 30

[prometheus]
enabled = false
address = "http://localhost:9091"
```

You can also generate a commented example with `tlschecker --generate-config`.

Then run TLSChecker with the config file:

```sh
➜ tlschecker -c example-tlschecker.toml
```

See [tlschecker-example.toml](tlschecker-example.toml) for a complete configuration example.
