use anyhow::{Context, Result};
use multistream_select::NegotiationError;
use multistream_select::Version;
use quinn::{ClientConfig, Endpoint};
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate, ServerName};
use std::sync::Arc;
use std::time::SystemTime;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use xtra_quinn_prototype::{handle_protocol, BiStream};

#[tokio::main]
async fn main() -> Result<()> {
    let port = std::env::args()
        .nth(1)
        .context("Expected port to connect to")?
        .parse::<u16>()
        .context("Cannot parse port as u16")?;

    let public_key = base64::decode(std::env::args().nth(2).context("Expected public key")?)
        .context("Expected hex-encoded public key")?;

    let endpoint = make_client_endpoint(public_key)?;

    let connection = endpoint
        .connect(format!("127.0.0.1:{}", port).parse()?, "localhost")?
        .await?;

    println!("Connected! Enter the protocol you would like to start.");

    // use stdin to model some user triggered spawning of actors
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Some(protocol) = lines.next_line().await? {
        println!("Attempting to start protocol: '{}'", protocol);

        // open a new stream for the protocol to start
        let (mut send, mut recv) = connection.connection.open_bi().await?;

        let protocol = match multistream_select::dialer_select_proto(
            BiStream::new(&mut send, &mut recv),
            vec![protocol.as_str()],
            Version::V1,
        )
        .await
        {
            Ok((protocol, _)) => protocol,
            Err(NegotiationError::Failed) => {
                eprintln!(
                    "Protocol negotiation failed: Protocol {} is unsupported by server",
                    protocol
                );
                continue;
            }
            Err(NegotiationError::ProtocolError(e)) => {
                eprintln!("Protocol negotiation failed: {}", e);
                continue;
            }
        };

        handle_protocol(protocol, send, recv);
    }

    Ok(())
}

fn make_client_endpoint(public_key: Vec<u8>) -> Result<Endpoint> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(skip_verification_client_config(public_key));

    Ok(endpoint)
}

struct PublickeyVerification {
    expected_key: Vec<u8>,
}

impl ServerCertVerifier for PublickeyVerification {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
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

fn skip_verification_client_config(public_key: Vec<u8>) -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(PublickeyVerification {
            expected_key: public_key,
        }))
        .with_no_client_auth();

    ClientConfig::new(Arc::new(crypto))
}
