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
    let json_output = matches.is_present("json");

    for host in hosts {
        match TLSValidation::new(host).from() {
            Ok(validation_result) => {
                //TODO implement better console output
                if json_output {
                    let json = serde_json::to_string(&validation_result).unwrap();
                    println!("{}", json);
                } else {
                    println!(
                        "{} is expired={}, valid days={}, expired days={}",
                        validation_result.host(),
                        validation_result.is_expired(),
                        validation_result.validity_days(),
                        validation_result.expired_days(),
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
    use tlschecker::TLSValidation;

    #[test]
    fn test_check_tls_for_expired_host() {
        let host = "expired.badssl.com";
        let mut tlsvalidation = TLSValidation::new(host);
        let result = tlsvalidation.from();
        match result {
            Ok(t) => {
                assert_eq!(t.is_expired(), true);
                assert!(t.expired_days() > 0);
                assert_eq!(t.validity_days(), 0);
            }
            Err(_) => {}
        }
    }

    #[test]
    fn test_check_tls_for_valid_host() {
        let host = "jpbd.dev";
        let mut tlsvalidation = TLSValidation::new(host);
        let result = tlsvalidation.from();
        match result {
            Ok(t) => {
                assert_eq!(t.is_expired(), false);
                assert_eq!(t.expired_days(), 0);
                assert!(t.validity_days() > 0);
            }
            Err(_) => {}
        }
    }
}
