use anyhow::{anyhow, Context, Result};
use futures::StreamExt;
use quinn::Endpoint;
use quinn_p2p_config::NewConnectionExt;
use ring::rand::SystemRandom;
use ring::signature::KeyPair;
use xtra_quinn_prototype::{handle_protocol, BiStream, PingActor};

#[tokio::main]
async fn main() -> Result<()> {
    let ed25519_der_private_key = match std::env::args().nth(1) {
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

    println!(
        "Public key: {}",
        base64::encode(
            ring::signature::Ed25519KeyPair::from_pkcs8(&ed25519_der_private_key)
                .unwrap()
                .public_key()
                .as_ref()
                .to_vec()
        )
    );

    let (endpoint, incoming) = Endpoint::server(
        quinn_p2p_config::server(ed25519_der_private_key)?,
        "0.0.0.0:0".parse()?,
    )?;

    println!("Listening on {}", endpoint.local_addr()?);

    let mut incoming = incoming.fuse();

    loop {
        match incoming.select_next_some().await.await {
            Ok(new_connection) => {
                let public_key = new_connection
                    .peer_public_key()
                    .context("Failed to get peer's public key")?;

                println!("New connection from: {}", base64::encode(public_key));

                tokio::spawn(async move {
                    let mut bi_streams = new_connection.bi_streams.fuse();

                    while let Ok((mut send, mut recv)) = bi_streams.select_next_some().await {
                        let protocol = match multistream_select::listener_select_proto(
                            BiStream::new(&mut send, &mut recv),
                            vec![PingActor::PROTOCOL],
                        )
                        .await
                        {
                            Ok((protocol, _)) => protocol,
                            Err(e) => {
                                eprintln!("Failed to negotiate protocol: {}", e);
                                continue;
                            }
                        };

                        handle_protocol(protocol, send, recv);
                    }

                    anyhow::Ok(())
                });
            }
            Err(e) => {
                eprintln!("Encountered error with new incoming connection: {}", e);
            }
        }
    }
}
