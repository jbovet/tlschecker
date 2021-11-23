# TLSChecker

Rust TLS/SSL certificate expiration date from command-line checker

[![codecov](https://codecov.io/gh/jbovet/tlschecker/branch/main/graph/badge.svg?token=MN4EE3WYQ6)](https://codecov.io/gh/jbovet/tlschecker)

## Docker run

[DockerHub](https://hub.docker.com/repository/docker/josebovet/tlschecker)

```sh
docker run josebovet/tlschecker:v0.1.5 -h jpbd.dev
```

## Install

Linux

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v0.1.5/tlschecker-linux
mv tlschecker-linux tlschecker
sudo install tlschecker /usr/local/bin/tlschecker
```

Osx

```sh
curl -LO https://github.com/jbovet/tlschecker/releases/download/v0.1.5/tlschecker-macos
mv tlschecker-macos tlschecker
sudo install tlschecker /usr/local/bin/tlschecker
```

##

```sh
➜  tlschecker --help
TLS Checker 0.1.5
Jose Bovet Derpich. <jose.bovet@gmail.com>
TLS/SSL certificate expiration date from command-line checker

USAGE:
    tlschecker [FLAGS] -h <host>...

FLAGS:
        --help       Prints help information
        --json       Prints json output
    -V, --version    Prints version information

OPTIONS:
    -h <host>...        Set hostname(s) to check
```

## How to use:

```sh
➜ tlschecker -h jpbd.dev expired.badssl.com
--------------------------------------
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
Valid from: Aug  2 00:00:00 2021 GMT
Valid to: Aug  1 23:59:59 2022 GMT
Days left: 263
Expired: false
Certificate version: 2
Certificate algorithm: ecdsa-with-SHA256
Certificate S/N: 2345778240388436345227316531320586380
Subject Alternative Names:
	DNS Name: sni.cloudflaressl.com
	DNS Name: *.jpbd.dev
	DNS Name: jpbd.dev
--------------------------------------
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
Days left: -2404
Expired: true
Certificate version: 2
Certificate algorithm: sha256WithRSAEncryption
Certificate S/N: 99565320202650452861752791156765321481
Subject Alternative Names:
	DNS Name: *.badssl.com
	DNS Name: badssl.com

```

```sh
➜ tlschecker --json  -h jpbd.dev                  
{
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
	"valid_from": "Aug  2 00:00:00 2021 GMT",
	"valid_to": "Aug  1 23:59:59 2022 GMT",
	"validity_days": 263,
	"is_expired": false,
	"cert_sn": "2345778240388436345227316531320586380",
	"cert_ver": "2",
	"cert_alg": "ecdsa-with-SHA256",
	"sans": ["sni.cloudflaressl.com", "*.jpbd.dev", "jpbd.dev"]
}
```
