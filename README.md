# TLSChecker

Experimental TLS/SSL certificate command-line checker

[![codecov](https://codecov.io/gh/jbovet/tlschecker/branch/main/graph/badge.svg?token=MN4EE3WYQ6)](https://codecov.io/gh/jbovet/tlschecker)

## Docker run

[DockerHub](https://hub.docker.com/repository/docker/josebovet/tlschecker)

```sh
docker run josebovet/tlschecker:latest jpbd.dev
```

If you are utilizing M1 or higher, please add the option --platform linux/x86_64.

```sh
docker run --platform linux/x86_64 josebovet/tlschecker:latest jpbd.dev
```

## Install

Linux

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v1.0.0/tlschecker-linux.zip
unzip tlschecker-linux.zip
chmod 755 tlschecker
sudo install tlschecker /usr/local/bin/tlschecker
```

Osx

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v1.0.0/tlschecker-macos.zip
unzip tlschecker-macos.zip
chmod 755 tlschecker
sudo install tlschecker /usr/local/bin/tlschecker
```

## How to use

```sh
➜  tlschecker --help
```
![](/img/1-1.png)

## Examples

```sh
➜ tlschecker jpbd.dev expired.badssl.com
```
![](/img/1-2.png)

```sh
➜ tlschecker jpbd.dev -o json
[
  {
    "hostname": "jpbd.dev",
    "subject": {
      "country_or_region": "None",
      "state_or_province": "None",
      "locality": "None",
      "organization_unit": "None",
      "organization": "None",
      "common_name": "jpbd.dev"
    },
    "issued": {
      "country_or_region": "US",
      "organization": "Let's Encrypt",
      "common_name": "E1"
    },
    "valid_from": "Jul 31 07:41:38 2023 GMT",
    "valid_to": "Oct 29 07:41:37 2023 GMT",
    "validity_days": 79,
    "validity_hours": 1896,
    "is_expired": false,
    "cert_sn": "417275593632489451472716682020094135372872",
    "cert_ver": "2",
    "cert_alg": "ecdsa-with-SHA384",
    "sans": [
      "*.jpbd.dev",
      "jpbd.dev"
    ],
    "chain": [
      {
        "subject": "jpbd.dev",
        "issuer": "E1",
        "valid_from": "Jul 31 07:41:38 2023 GMT",
        "valid_to": "Oct 29 07:41:37 2023 GMT",
        "signature_algorithm": "ecdsa-with-SHA384"
      },
      {
        "subject": "E1",
        "issuer": "ISRG Root X2",
        "valid_from": "Sep  4 00:00:00 2020 GMT",
        "valid_to": "Sep 15 16:00:00 2025 GMT",
        "signature_algorithm": "ecdsa-with-SHA384"
      },
      {
        "subject": "ISRG Root X2",
        "issuer": "ISRG Root X1",
        "valid_from": "Sep  4 00:00:00 2020 GMT",
        "valid_to": "Sep 15 16:00:00 2025 GMT",
        "signature_algorithm": "sha256WithRSAEncryption"
      },
      {
        "subject": "ISRG Root X1",
        "issuer": "DST Root CA X3",
        "valid_from": "Jan 20 19:14:03 2021 GMT",
        "valid_to": "Sep 30 18:14:03 2024 GMT",
        "signature_algorithm": "sha256WithRSAEncryption"
      }
    ]
  }
]
```

```sh
➜ tlschecker jpbd.dev -o text
--------------------------------------
Hostname: jpbd.dev
Issued domain: jpbd.dev
Subject Name :
 Country or Region: None
 State or Province: None
 Locality: None
 Organizational Unit: None
 Organization: None
 Common Name: jpbd.dev
Issuer Name:
 Country or Region: US
 Organization: Let's Encrypt
 Common Name: E1
Valid from: Jul 31 07:41:38 2023 GMT
Valid to: Oct 29 07:41:37 2023 GMT
Days left: 79
Hours left: 1896
Expired: false
Certificate version: 2
Certificate algorithm: ecdsa-with-SHA384
Certificate S/N: 417275593632489451472716682020094135372872
Subject Alternative Names:
 DNS Name: *.jpbd.dev
 DNS Name: jpbd.dev
Additional Certificates (if supplied):
Chain #1
 Subject: "jpbd.dev"
 Valid from: "Jul 31 07:41:38 2023 GMT"
 Valid until: "Oct 29 07:41:37 2023 GMT"
 Issuer: "E1"
 Signature algorithm: "ecdsa-with-SHA384"
Chain #2
 Subject: "E1"
 Valid from: "Sep  4 00:00:00 2020 GMT"
 Valid until: "Sep 15 16:00:00 2025 GMT"
 Issuer: "ISRG Root X2"
 Signature algorithm: "ecdsa-with-SHA384"
Chain #3
 Subject: "ISRG Root X2"
 Valid from: "Sep  4 00:00:00 2020 GMT"
 Valid until: "Sep 15 16:00:00 2025 GMT"
 Issuer: "ISRG Root X1"
 Signature algorithm: "sha256WithRSAEncryption"
Chain #4
 Subject: "ISRG Root X1"
 Valid from: "Jan 20 19:14:03 2021 GMT"
 Valid until: "Sep 30 18:14:03 2024 GMT"
 Issuer: "DST Root CA X3"
 Signature algorithm: "sha256WithRSAEncryption"
```
