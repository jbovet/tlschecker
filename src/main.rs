use clap::{App, Arg};
use std::process::exit;
use tlschecker::Certificate;

fn main() {
    let matches = App::new("TLS Checker")
        .version("1.0")
        .author("Jose Bovet Derpich. <jose.bovet@gmail.com>")
        .about("TLS/SSL certificate expiration date from command-line checker")
        .arg(
            Arg::with_name("host")
                .short("h")
                .takes_value(true)
                .multiple(true)
                .required(true)
                .help("Set hostname to check"),
        )
        .arg(
            Arg::with_name("json")
                .long("json")
                .help("Prints json output"),
        )
        .get_matches();

    let hosts = matches.values_of("host").unwrap();
    let json_output = matches.is_present("json");

    for host in hosts {
        match Certificate::from(host) {
            Ok(cert) => {
                if json_output {
                    let json = serde_json::to_string(&cert).unwrap();
                    println!("{}", json);
                } else {
                    println!("--------------------------------------");
                    println!("Issued domain: {}", cert.issued_domain);
                    println!("Issued to: {}", cert.issued_to);
                    println!("Issued by: {}", cert.issued_by);
                    println!("Valid from: {}", cert.valid_from);
                    println!("Valid to: {}", cert.valid_to);
                    println!("Days left: {}", cert.validity_days);
                    println!("Expired: {}", cert.is_expired);
                    println!("Certificate version: {}", cert.cert_ver);
                    println!("Certificate algorithm: {}", cert.cert_alg);
                    println!("Certificate S/N: {}", cert.cert_sn);
                    //TODO
                    // println!("Certificate SAN's");
                }
            }
            Err(_) => {
                println!("Couldn't resolve any address from server {} ", host)
            }
        }
    }
    exit(0);
}
