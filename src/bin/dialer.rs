use anyhow::{anyhow, Context, Result};
use multistream_select::NegotiationError;
use multistream_select::Version;
use quinn::Endpoint;
use quinn_p2p_config::NewConnectionExt;
use ring::rand::SystemRandom;
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

    let ed25519_der_public_key =
        base64::decode(std::env::args().nth(2).context("Expected public key")?)
            .context("Expected hex-encoded public key")?;

    let ed25519_der_private_key = match std::env::args().nth(3) {
        Some(private_key) => base64::decode(private_key)?,
        None => {
            let private_key = ring::signature::Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
                .map_err(|_| anyhow!("Failed to generate new ed25519 keypair"))?
                .as_ref()
                .to_vec();

            println!("Private key: {}", base64::encode(&private_key));

            private_key
        }
    };

    let endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;

    let connection = endpoint
        .connect_with(
            quinn_p2p_config::client(ed25519_der_public_key, ed25519_der_private_key)?,
            format!("127.0.0.1:{}", port).parse()?,
            quinn_p2p_config::SERVER_NAME,
        )?
        .await?;

    let public_key = connection.peer_public_key()?;

    println!(
        "Connected to {}! Enter the protocol you would like to start.",
        base64::encode(public_key)
    );

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
