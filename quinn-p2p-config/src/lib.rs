use anyhow::Result;
use quinn_proto::{ClientConfig, ServerConfig};
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ServerName};
use std::sync::Arc;
use std::time::SystemTime;

pub const SERVER_NAME: &str = "we-only-verify-the-public-key.com";

pub fn client(ed25519_der_public_key: Vec<u8>) -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(PublicKeyVerification {
            expected_key: ed25519_der_public_key,
        }))
        .with_no_client_auth();

    ClientConfig::new(Arc::new(crypto))
}

pub fn server(ed25519_der_private_key: Vec<u8>) -> Result<ServerConfig> {
    let key_pair = rcgen::KeyPair::from_der(&ed25519_der_private_key)?;

    let mut params =
        rcgen::CertificateParams::new(vec!["we-only-verify-the-public-key.com".into()]);
    params.alg = &rcgen::PKCS_ED25519;
    params.key_pair = Some(key_pair);

    let cert = rcgen::Certificate::from_params(params)?;

    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der)];

    let server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;

    Ok(server_config)
}

struct PublicKeyVerification {
    expected_key: Vec<u8>,
}

impl ServerCertVerifier for PublicKeyVerification {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::General(
                "Intermediate certificates are not allowed".to_owned(),
            ));
        }

        if server_name != &ServerName::try_from(SERVER_NAME).expect("a valid name") {
            return Err(rustls::Error::General(
                "Invalid server name used".to_owned(),
            ));
        }

        let certificate = x509_certificate::CapturedX509Certificate::from_der(end_entity.0.clone())
            .map_err(|_| {
                rustls::Error::InvalidCertificateData(
                    "Unable to parse certificate data as x509".to_owned(),
                )
            })?;
        certificate
            .verify_signed_by_public_key(&self.expected_key)
            .map_err(|_| rustls::Error::InvalidCertificateSignature)?;

        Ok(ServerCertVerified::assertion())
    }
}
