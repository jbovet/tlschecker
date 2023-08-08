# TLSChecker

Experimental TLS/SSL certificate command-line checker

[![codecov](https://codecov.io/gh/jbovet/tlschecker/branch/main/graph/badge.svg?token=MN4EE3WYQ6)](https://codecov.io/gh/jbovet/tlschecker)

## Docker run

[DockerHub](https://hub.docker.com/repository/docker/josebovet/tlschecker)

```sh
docker run josebovet/tlschecker:v0.1.13 jpbd.dev
```

## Install

Linux

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v0.1.13/tlschecker-linux
mv tlschecker-linux tlschecker
sudo install tlschecker /usr/local/bin/tlschecker
```

Osx

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v0.1.13/tlschecker-macos
mv tlschecker-macos tlschecker
sudo install tlschecker /usr/local/bin/tlschecker
```

##

```sh
➜  tlschecker --help
Experimental TLS/SSL certificate checker

Usage: tlschecker [OPTIONS] [ADDRESSES]...

Arguments:
  [ADDRESSES]...
          A space-delimited hosts list to be checked

Options:
  -o <OUTPUT>
          Enable verbose to see what is going on

          [default: text]

          Possible values:
          - json: Enable JSON in the output
          - text: Enable Text in the output

      --exit-code <EXIT_CODE>
          Exits with code 0 even when certificate expired is detected

          [default: 0]

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

## How to use

```sh
➜ tlschecker jpbd.dev expired.badssl.com
➜  ~ tlschecker jpbd.dev expired.badssl.com
--------------------------------------
Hostname: jpbd.dev
Issued domain: sni.cloudflaressl.com
Subject Name :
	Country or Region: US
	State or Province: California
	Locality: San Francisco
	Organizational Unit: None
	Organization: Cloudflare, Inc.
	Common Name: sni.cloudflaressl.com
Issuer Name:
	Country or Region: US
	Organization: Cloudflare, Inc.
	Common Name: Cloudflare Inc ECC CA-3
Valid from: Jul  2 00:00:00 2022 GMT
Valid to: Jul  2 23:59:59 2023 GMT
Days left: 123
Expired: false
Certificate version: 2
Certificate algorithm: ecdsa-with-SHA256
Certificate S/N: 20332696690017175202539153893006852358
Subject Alternative Names:
	DNS Name: sni.cloudflaressl.com
	DNS Name: jpbd.dev
	DNS Name: *.jpbd.dev
Additional Certificates (if supplied):
Chain #1
	Subject: "sni.cloudflaressl.com"
	Valid from: "Jul  2 00:00:00 2022 GMT"
	Valid until: "Jul  2 23:59:59 2023 GMT"
	Issuer: "Cloudflare Inc ECC CA-3"
	Signature algorithm: "ecdsa-with-SHA256"
Chain #2
	Subject: "Cloudflare Inc ECC CA-3"
	Valid from: "Jan 27 12:48:08 2020 GMT"
	Valid until: "Dec 31 23:59:59 2024 GMT"
	Issuer: "Baltimore CyberTrust Root"
	Signature algorithm: "sha256WithRSAEncryption"
--------------------------------------
Hostname: expired.badssl.com
Issued domain: *.badssl.com
Subject Name :
	Country or Region: None
	State or Province: None
	Locality: None
	Organizational Unit: Domain Control Validated
	Organization: None
	Common Name: *.badssl.com
Issuer Name:
	Country or Region: GB
	Organization: COMODO CA Limited
	Common Name: COMODO RSA Domain Validation Secure Server CA
Valid from: Apr  9 00:00:00 2015 GMT
Valid to: Apr 12 23:59:59 2015 GMT
Days left: -2879
Expired: true
Certificate version: 2
Certificate algorithm: sha256WithRSAEncryption
Certificate S/N: 99565320202650452861752791156765321481
Subject Alternative Names:
	DNS Name: *.badssl.com
	DNS Name: badssl.com
Additional Certificates (if supplied):
Chain #1
	Subject: "*.badssl.com"
	Valid from: "Apr  9 00:00:00 2015 GMT"
	Valid until: "Apr 12 23:59:59 2015 GMT"
	Issuer: "COMODO RSA Domain Validation Secure Server CA"
	Signature algorithm: "sha256WithRSAEncryption"
Chain #2
	Subject: "COMODO RSA Domain Validation Secure Server CA"
	Valid from: "Feb 12 00:00:00 2014 GMT"
	Valid until: "Feb 11 23:59:59 2029 GMT"
	Issuer: "COMODO RSA Certification Authority"
	Signature algorithm: "sha384WithRSAEncryption"
Chain #3
	Subject: "COMODO RSA Certification Authority"
	Valid from: "May 30 10:48:38 2000 GMT"
	Valid until: "May 30 10:48:38 2020 GMT"
	Issuer: "AddTrust External CA Root"
	Signature algorithm: "sha384WithRSAEncryption"
➜  ~
```

```sh
➜ tlschecker jpbd.dev -o json
[
  {
    "hostname": "jpbd.dev",
    "subject": {
      "country_or_region": "US",
      "state_or_province": "California",
      "locality": "San Francisco",
      "organization_unit": "None",
      "organization": "Cloudflare, Inc.",
      "common_name": "sni.cloudflaressl.com"
    },
    "issued": {
      "country_or_region": "US",
      "organization": "Cloudflare, Inc.",
      "common_name": "Cloudflare Inc ECC CA-3"
    },
    "valid_from": "Jul  2 00:00:00 2022 GMT",
    "valid_to": "Jul  2 23:59:59 2023 GMT",
    "validity_days": 123,
    "is_expired": false,
    "cert_sn": "20332696690017175202539153893006852358",
    "cert_ver": "2",
    "cert_alg": "ecdsa-with-SHA256",
    "sans": [
      "sni.cloudflaressl.com",
      "jpbd.dev",
      "*.jpbd.dev"
    ],
    "chain": [
      {
        "subject": "sni.cloudflaressl.com",
        "issuer": "Cloudflare Inc ECC CA-3",
        "valid_from": "Jul  2 00:00:00 2022 GMT",
        "valid_to": "Jul  2 23:59:59 2023 GMT",
        "signature_algorithm": "ecdsa-with-SHA256"
      },
      {
        "subject": "Cloudflare Inc ECC CA-3",
        "issuer": "Baltimore CyberTrust Root",
        "valid_from": "Jan 27 12:48:08 2020 GMT",
        "valid_to": "Dec 31 23:59:59 2024 GMT",
        "signature_algorithm": "sha256WithRSAEncryption"
      }
    ]
  }
]
```
