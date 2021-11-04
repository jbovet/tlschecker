# TLSChecker
Rust TLS/SSL certificate expiration date from command-line checker

```sh
➜  tlschecker --help
TLS Checker 1.0
Jose Bovet Derpich. <jose.bovet@gmail.com>
TLS/SSL certificate expiration date from command-line checker

USAGE:
    tlschecker [FLAGS] -h <host>...

FLAGS:
        --help       Prints help information
        --json       Prints json output
    -V, --version    Prints version information

OPTIONS:
    -h <host>...        Set hostname to check
```

## How to use:
```sh
➜ tlschecker -h jpbd.dev expired.badssl.com
--------------------------------------
Issued domain: sni.cloudflaressl.com
Issued to: Cloudflare, Inc.
Issued by: Cloudflare Inc ECC CA-3
Valid from: Aug  2 00:00:00 2021 GMT
Valid to: Aug  1 23:59:59 2022 GMT
Days left: 270
Expired: false
Certificate version: 2
Certificate algorithm: ecdsa-with-SHA256
Certificate S/N: 2345778240388436345227316531320586380
--------------------------------------
Issued domain: *.badssl.com
Issued to: None
Issued by: COMODO RSA Domain Validation Secure Server CA
Valid from: Apr  9 00:00:00 2015 GMT
Valid to: Apr 12 23:59:59 2015 GMT
Days left: -2397
Expired: true
Certificate version: 2
Certificate algorithm: sha256WithRSAEncryption
Certificate S/N: 99565320202650452861752791156765321481

```

```sh
➜ tlschecker --json  -h jpbd.dev                  
{"issued_domain":"sni.cloudflaressl.com","issued_to":"Cloudflare, Inc.","issued_by":"Cloudflare Inc ECC CA-3","valid_from":"Aug  2 00:00:00 2021 GMT","valid_to":"Aug  1 23:59:59 2022 GMT","validity_days":270,"is_expired":false,"cert_sn":"2345778240388436345227316531320586380","cert_ver":"2","cert_alg":"ecdsa-with-SHA256"}
```