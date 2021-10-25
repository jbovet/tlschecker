use clap::{App, Arg};
use std::process::exit;
use tlschecker::TLSValidation;

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
    for host in hosts {
        match TLSValidation::new(host).from() {
            Ok(tls_validation) => {
                if matches.is_present("json") {
                    let json = serde_json::to_string(&tls_validation).unwrap();
                    println!("{}", json);
                } else {
                    println!(
                        "{} is_expired:{} validity_days:{} - expired_days:{}",
                        tls_validation.host(),
                        tls_validation.is_expired(),
                        tls_validation.validity_days(),
                        tls_validation.expired_days(),
                    );
                }
            }
            Err(_) => {
                println!("Couldn't resolve any address from server {} ", host)
            }
        }
    }
    exit(0);
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_expired() {}
}
