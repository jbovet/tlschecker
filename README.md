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
jpbd.dev is expired=false, valid days=280, expired days=0
expired.badssl.com is expired=true, valid days=0, expired days=238
```

```sh
➜ tlschecker --json -h jpbd.dev expired.badssl.com
{"host":"jpbd.dev","is_expired":false,"validity_days":280,"expired_days":0}
{"host":"expired.badssl.com","is_expired":true,"validity_days":0,"expired_days":2387}
```