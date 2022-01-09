use anyhow::{anyhow, Context, Result};
use quinn::{ClientConfig, NewConnection, ServerConfig};
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::server::{ClientCertVerified, ClientCertVerifier};
use rustls::{Certificate, DistinguishedNames, PrivateKey, ServerName};
use std::sync::Arc;
use std::time::SystemTime;

pub const SERVER_NAME: &str = "we-only-verify-the-public-key.com";

pub fn client(
    ed25519_der_public_key: Vec<u8>,
    ed25519_der_private_key: Vec<u8>,
) -> Result<ClientConfig> {
    let (cert_chain, priv_key) = self_signed_certificate_from_key(ed25519_der_private_key)?;

    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(PublicKeyVerification {
            expected_key: ed25519_der_public_key,
        }))
        .with_single_cert(cert_chain, priv_key)?;

    Ok(ClientConfig::new(Arc::new(crypto)))
}

pub fn server(ed25519_der_private_key: Vec<u8>) -> Result<ServerConfig> {
    let (cert_chain, priv_key) = self_signed_certificate_from_key(ed25519_der_private_key)?;

    let mut crypto = rustls::ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_client_cert_verifier(Arc::new(AllowSelfSignedCerts))
        .with_single_cert(cert_chain, priv_key)?;
    crypto.max_early_data_size = u32::MAX;

    let server_config = ServerConfig::with_crypto(Arc::new(crypto));

    Ok(server_config)
}

fn self_signed_certificate_from_key(
    ed25519_der_private_key: Vec<u8>,
) -> Result<(Vec<Certificate>, PrivateKey)> {
    let key_pair = rcgen::KeyPair::from_der(&ed25519_der_private_key)?;

    let mut params = rcgen::CertificateParams::new(vec![SERVER_NAME.into()]);
    params.alg = &rcgen::PKCS_ED25519;
    params.key_pair = Some(key_pair);

    let cert = rcgen::Certificate::from_params(params)?;

    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der)];

    Ok((cert_chain, priv_key))
}

struct AllowSelfSignedCerts;

impl ClientCertVerifier for AllowSelfSignedCerts {
    fn client_auth_root_subjects(&self) -> Option<DistinguishedNames> {
        Some(vec![])
    }

    fn verify_client_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        _: SystemTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(rustls::Error::General(
                "Intermediate certificates are not allowed".to_owned(),
            ));
        }

        let certificate = x509_certificate::CapturedX509Certificate::from_der(
            end_entity.0.as_slice(),
        )
        .map_err(|_| {
            rustls::Error::InvalidCertificateData(
                "Unable to parse certificate data as x509".to_owned(),
            )
        })?;

        let public_key = certificate.public_key_data();

        certificate
            .verify_signed_by_public_key(public_key)
            .map_err(|_| rustls::Error::InvalidCertificateSignature)?;

        Ok(ClientCertVerified::assertion())
    }
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
        _: &mut dyn Iterator<Item = &[u8]>,
        _: &[u8],
        _: SystemTime,
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

pub trait NewConnectionExt {
    fn peer_public_key(&self) -> Result<Vec<u8>>;
}

impl NewConnectionExt for NewConnection {
    fn peer_public_key(&self) -> Result<Vec<u8>> {
        let certificate = self
            .connection
            .peer_identity()
            .context("Endpoint was not constructed with authentication configured")?
            .downcast::<Vec<rustls::Certificate>>()
            .map_err(|_| anyhow!("Endpoint was not configured with rustls crypto"))?
            .into_iter()
            .next()
            .context("Peer did not present any certificates")?;

        let certificate = x509_certificate::X509Certificate::from_der(certificate.0)?;

        Ok(certificate.public_key_data().to_vec())
    }
}
