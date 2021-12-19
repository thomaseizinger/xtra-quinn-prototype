use anyhow::Result;
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
    let mut endpoint = Endpoint::client("127.0.0.1:0".parse()?)?;
    endpoint.set_default_client_config(configure_client());

    let connection = endpoint
        .connect("127.0.0.1:8080".parse()?, "localhost")?
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
            Err(e) => {
                eprintln!("Protocol negotiation failed: {}", e);
                continue;
            }
        };

        handle_protocol(protocol, send, recv);
    }

    Ok(())
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
}

fn configure_client() -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(SkipServerVerification::new())
        .with_no_client_auth();

    ClientConfig::new(Arc::new(crypto))
}
