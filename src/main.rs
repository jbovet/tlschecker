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
                    println!("Issued domain: {}", cert.subject.common_name);
                    println!("Subject Name :");
                    println!("\tCountry or Region: {}", cert.subject.country_or_region);
                    println!("\tState or Province: {}", cert.subject.state_or_province);
                    println!("\tLocality: {}", cert.subject.locality);
                    println!("\tOrganizational Unit: {}", cert.subject.organization_unit);
                    println!("\tOrganization: {}", cert.subject.organization);
                    println!("\tCommon Name: {}", cert.subject.common_name);
                    println!("Issuer Name:");
                    println!("\tCountry or Region: {}", cert.issued.country_or_region);
                    println!("\tOrganization: {}", cert.issued.organization);
                    println!("\tCommon Name: {}", cert.issued.common_name);
                    println!("Valid from: {}", cert.valid_from);
                    println!("Valid to: {}", cert.valid_to);
                    println!("Days left: {}", cert.validity_days);
                    println!("Expired: {}", cert.is_expired);
                    println!("Certificate version: {}", cert.cert_ver);
                    println!("Certificate algorithm: {}", cert.cert_alg);
                    println!("Certificate S/N: {}", cert.cert_sn);
                    println!("Subject Alternative Names:");
                    for san in cert.sans {
                        println!("\tDNS Name: {}", san);
                    }
                }
            }
            Err(err) => {
                println!("Fail to check host: {} ", &err.details);
            }
        }
    }
    exit(0);
}
