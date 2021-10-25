use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use serde::{Deserialize, Serialize};
use std::net::{TcpStream, ToSocketAddrs};
use std::ops::Deref;
use std::time::Duration;

static TIMEOUT: u64 = 30;

#[derive(Serialize, Deserialize)]
pub struct TLSValidation {
    host: String,
    is_expired: bool,
    validity_days: i32,
    expired_days: i32,
}

impl TLSValidation {
    pub fn new(host_name: &str) -> TLSValidation {
        TLSValidation {
            host: host_name.to_owned(),
            is_expired: false,
            validity_days: 0,
            expired_days: 0,
        }
    }

    pub fn host(&self) -> String {
        self.host.to_owned()
    }

    pub fn is_expired(&self) -> bool {
        self.is_expired
    }

    pub fn set_expired(&mut self, is_expired: bool) {
        self.is_expired = is_expired;
    }

    pub fn validity_days(&self) -> i32 {
        self.validity_days
    }

    pub fn set_validity_days(&mut self, days: i32) {
        self.validity_days = days;
    }

    pub fn expired_days(&self) -> i32 {
        self.expired_days
    }

    pub fn set_expired_days(&mut self, expired_days: i32) {
        self.expired_days = expired_days;
    }

    pub fn from(&mut self) -> Result<&TLSValidation, TLSValidationError> {
        let mut context = SslContext::builder(SslMethod::tls()).unwrap();
        context.set_verify(SslVerifyMode::empty());
        let context_builder = context.build();

        let mut connector = Ssl::new(&context_builder).unwrap();
        connector.set_hostname(&self.host).unwrap();
        let remote = format!("{}:443", &self.host);
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

                let expiration_days = TLSValidation::get_expiration_days(expiry, &threshold);

                if expiry < threshold {
                    self.set_expired(true);
                    self.set_expired_days(expiration_days);
                    self.set_validity_days(0);
                }

                self.set_validity_days(expiration_days);
                self.set_expired_days(0);
                
                Ok(self)
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
