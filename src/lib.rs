use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use std::net::{TcpStream, ToSocketAddrs};
use std::ops::Deref;
use std::time::Duration;

static TIMEOUT: u64 = 30;

pub struct TLSValidation {
    is_expired: bool,
    validity_days: i32,
    expired_days: i32,
}

impl TLSValidation {
    pub fn new() -> TLSValidation {
        TLSValidation {
            is_expired: false,
            validity_days: 0,
            expired_days: 0,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired
    }

    pub fn validity_days(&self) -> i32 {
        self.validity_days
    }

    pub fn expired_days(&self) -> i32 {
        self.expired_days
    }

    pub fn from_server_name(server_name: &str) -> Result<TLSValidation, TLSValidationError> {
        let mut context = SslContext::builder(SslMethod::tls()).unwrap();
        context.set_verify(SslVerifyMode::empty());
        let context_builder = context.build();

        let mut connector = Ssl::new(&context_builder).unwrap();
        connector.set_hostname(&server_name).unwrap();
        let remote = format!("{}:443", server_name);
        match remote.to_socket_addrs() {
            Ok(mut address) => {
                let socket_addr = address.next().unwrap();
                let tcp_stream =
                    TcpStream::connect_timeout(&socket_addr, Duration::from_secs(TIMEOUT)).unwrap();
                tcp_stream
                    .set_read_timeout(Some(Duration::from_secs(TIMEOUT)))
                    .unwrap();

                let stream = connector
                    .connect(tcp_stream)
                    .expect("TLS handshake failed.");
                let cert = stream
                    .ssl()
                    .peer_certificate()
                    .ok_or("Certificate not found")
                    .unwrap();

                let expiry = cert.not_after();
                let threshold = Asn1Time::days_from_now(0).unwrap();
                let mut tls_validation = TLSValidation::new();

                let expiration_days = TLSValidation::get_expiration_days(expiry, &threshold);

                if expiry < threshold {
                    tls_validation.is_expired = true;
                    tls_validation.expired_days = expiration_days;
                }
                tls_validation.validity_days = expiration_days;
                Ok(tls_validation)
            }
            Err(_) => Err(TLSValidationError::new("couldn't resolve host address {}")),
        }
    }

    fn get_expiration_days(expiry: &Asn1TimeRef, threshold: &Asn1Time) -> i32 {
        threshold.deref().diff(expiry).unwrap().days
    }
}

#[derive(Debug)]
pub struct TLSValidationError {
    details: String,
}

impl TLSValidationError {
    fn new(msg: &str) -> TLSValidationError {
        TLSValidationError {
            details: msg.to_string(),
        }
    }
}
