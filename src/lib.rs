use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::nid::Nid;
use openssl::ssl::{Ssl, SslContext, SslMethod, SslVerifyMode};
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::net::{TcpStream, ToSocketAddrs};
use std::ops::Deref;
use std::time::Duration;

static TIMEOUT: u64 = 30;

#[derive(Serialize, Deserialize)]
pub struct Certificate {
    pub issued_domain: String,
    pub issued_to: String,
    pub issued_by: String,
    pub valid_from: String,
    pub valid_to: String,
    pub validity_days: i32,
    pub is_cert_valid: bool,
    pub cert_sn: String,
    pub cert_ver: String,
    pub cert_alg: String,
}

impl Certificate {
    pub fn from(host: &str) -> Result<Certificate, TLSValidationError> {
        let mut context = SslContext::builder(SslMethod::tls()).unwrap();
        context.set_verify(SslVerifyMode::empty());
        let context_builder = context.build();

        let mut connector = Ssl::new(&context_builder).unwrap();
        connector.set_hostname(host).unwrap();
        let remote = format!("{}:443", host);
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

                let x509_ref = stream
                    .ssl()
                    .peer_certificate()
                    .ok_or("Certificate not found")
                    .unwrap();
                let data = get_certificate_info(&x509_ref);
                let certificate = Certificate {
                    issued_domain: data.issued_domain,
                    issued_to: data.issued_to,
                    issued_by: data.issued_by,
                    valid_from: data.valid_from,
                    valid_to: data.valid_to,
                    validity_days: data.validity_days,
                    is_cert_valid: data.is_cert_valid,
                    cert_sn: data.cert_sn,
                    cert_ver: data.cert_ver,
                    cert_alg: data.cert_alg,
                };
                Ok(certificate)
            }
            Err(_) => Err(TLSValidationError::new("couldn't resolve host address {}")),
        }
    }
}

fn get_certificate_info(cert_ref: &X509) -> Certificate {
    let subject_name = cert_ref
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap();
    let issuer_name = cert_ref
        .issuer_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .unwrap();
    let organization_name_entities = cert_ref
        .subject_name()
        .entries_by_nid(Nid::ORGANIZATIONNAME);

    let mut organization_name = String::from("None");
    for entity in organization_name_entities {
        organization_name = entity.data().as_utf8().unwrap().to_string();
    }
    return Certificate {
        issued_domain: subject_name.data().as_utf8().unwrap().to_string(),
        issued_to: organization_name,
        issued_by: issuer_name.data().as_utf8().unwrap().to_string(),
        valid_from: cert_ref.not_before().to_string(),
        valid_to: cert_ref.not_after().to_string(),
        validity_days: get_validity_days(cert_ref.not_after()),
        is_cert_valid: !has_expired(cert_ref.not_after()),
        cert_sn: cert_ref.serial_number().to_bn().unwrap().to_string(),
        cert_ver: cert_ref.version().to_string(),
        cert_alg: cert_ref.signature_algorithm().object().to_string(),
    };
}

fn get_validity_days(not_after: &Asn1TimeRef) -> i32 {
    return Asn1Time::days_from_now(0)
        .unwrap()
        .deref()
        .diff(not_after)
        .unwrap()
        .days;
}
fn has_expired(not_after: &Asn1TimeRef) -> bool {
    not_after < Asn1Time::days_from_now(0).unwrap()
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
