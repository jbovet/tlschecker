use std::env;
use std::process::exit;
use tlschecker::TLSValidation;

fn main() {
    let exit_code = 0;
    for server_name in env::args().skip(1) {
        match TLSValidation::from_server_name(&server_name) {
            Ok(tls_validation) => {
                if tls_validation.is_expired() {
                    println!("{} SSL certificate expired {} days ago", server_name, tls_validation.expired_days());
                } else {
                    println!("{} SSL certificate will expire in {} days", server_name, tls_validation.validity_days());
                }
            }
            Err(_) => {
                println!("Couldn't resolve any address from server {} ", server_name)
            }
        }
    }
    exit(exit_code);
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_expired() {}
}