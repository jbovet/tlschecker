# TLSChecker

Experimental TLS/SSL certificate command-line checker

[![codecov](https://codecov.io/gh/jbovet/tlschecker/branch/main/graph/badge.svg?token=MN4EE3WYQ6)](https://codecov.io/gh/jbovet/tlschecker)

## Docker run

[DockerHub](https://hub.docker.com/repository/docker/josebovet/tlschecker)

```sh
docker run josebovet/tlschecker:1.1.1 jpbd.dev
```

If you are utilizing M1 or higher, please add the option --platform linux/x86_64.

```sh
docker run --platform linux/x86_64 josebovet/tlschecker:1.1.1 jpbd.dev
```

## Install

Linux

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v1.1.1/tlschecker-linux.zip
unzip tlschecker-linux.zip
chmod 755 tlschecker
sudo install tlschecker /usr/local/bin/tlschecker
```

Osx

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v1.1.1/tlschecker-macos.zip
unzip tlschecker-macos.zip
chmod 755 tlschecker
sudo install tlschecker /usr/local/bin/tlschecker
```

## How to use

```sh
➜  tlschecker --help
```

### Interactive dashboard

When run in an interactive terminal, tlschecker opens a live dashboard by
default: hosts stream in as they are checked, with a fleet list and verdict
tally on the left and a detail pane (expiry lifetime gauge, TLS grade
breakdown, security warnings) for the selected host on the right. Navigate
with `j`/`k` (or arrow keys), jump with `g`/`G`, quit with `q`.

Press `Enter` on a host to open the full certificate explorer: subject and
issuer details, validity dates, serial number and fingerprints, SANs, the
presented chain, embedded SCTs, the grade breakdown with reasons, and scan
results when `--scan` was used. Scroll with `j`/`k` or `PgUp`/`PgDn`, and
return with `Esc`.

The classic text outputs are used automatically whenever stdout is piped or
redirected, and can always be forced with `-o summary|json|text` or
`--no-dashboard` (keeps the configured/`-o` format) — so scripts, CI
pipelines, and `tlschecker -o json | jq` behave exactly as before.

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

The revocation status will be displayed in the output:
- **Valid**: Certificate is not revoked (confirmed by OCSP or CRL)
- **Revoked**: Certificate has been revoked (with reason if available)
- **Unknown**: Revocation status couldn't be determined
- **Not Checked**: Revocation status was not checked (default when not using the flag)

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

Additionally, a `revoked` label is added to all metrics with a boolean value indicating whether the certificate is revoked.

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
- **Not logged** — definitively absent from CT. Reported as a security warning (see below) and shown as `✗` in the summary. A publicly-trusted certificate that is not logged will be rejected by modern browsers.
- **Unknown** — crt.sh was unreachable or rate-limited, so the status could not be determined (`?` in the summary). This is kept distinct from "not logged" so an outage is never mistaken for a problem; the reason is logged to **stderr** (stdout stays clean for `… -o json | jq`).

When `--ct-check` is used, the summary table gains a `CT` column (`✓`/`✗`/`?`); without it the column is hidden. Being absent from CT does **not** affect the grade — many legitimate internal/private certificates are intentionally absent from public CT logs, so what that means is left to you rather than the grade.

### Security Warnings

In addition to revocation and grading, tlschecker surfaces certificate problems as security warnings in all output formats:

- **Weak signature algorithm** — the certificate or a chain certificate is signed with SHA-1 or MD5
- **Incomplete chain** — the certificate's issuer was not found in the presented chain
- **Invalid chain order** — the chain is not in issuer order (each certificate should be followed by the one that issued it)
- **Hostname mismatch** — the certificate is not valid for the hostname you checked (no matching SAN, with wildcard support, or Common Name)
- **Expiring intermediate** — an intermediate certificate in the chain has expired or expires within 30 days
- **Weak protocol** (`--scan`) — the server still supports an obsolete (SSLv3) or deprecated (TLS 1.0/1.1) protocol version
- **Weak cipher** (`--scan`) — the server accepts a weak cipher suite (RC4, DES/3DES, NULL, EXPORT, anonymous, ...)
- **Not in CT log** (`--ct-check`) — the presented certificate was not found in any public Certificate Transparency log

A hostname mismatch, support for an obsolete protocol (SSLv3/TLS 1.0), or acceptance of a weak cipher each cap the TLS grade at C, the same as a self-signed certificate.

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
