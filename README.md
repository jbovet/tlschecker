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
    "secure-service.internal:9443"
]

# Optional settings
check_revocation = true
output_format = "json"
prometheus = false
prometheus_address = "http://localhost:9091"
```

Then run TLSChecker with the config file:

```sh
➜ tlschecker -c example-tlschecker.toml
```

See [tlschecker-example.toml](tlschecker-example.toml) for a complete configuration example.
