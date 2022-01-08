use anyhow::{anyhow, Result};
use futures::StreamExt;
use quinn::{Endpoint, Incoming, ServerConfig};
use ring::rand::SystemRandom;
use ring::signature::KeyPair;
use rustls::PrivateKey;
use std::net::SocketAddr;
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

    let mut incoming = make_server_endpoint("0.0.0.0:0".parse()?, ed25519_der_private_key)?.fuse();

    loop {
        match incoming.select_next_some().await.await {
            Ok(new_connection) => {
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

pub fn make_server_endpoint(
    bind_addr: SocketAddr,
    ed25519_der_private_key: Vec<u8>,
) -> Result<Incoming> {
    let server_config = self_signed_cert_config(ed25519_der_private_key)?;
    let (endpoint, incoming) = Endpoint::server(server_config, bind_addr)?;

    println!("Listening on {}", endpoint.local_addr()?);

    Ok(incoming)
}

fn self_signed_cert_config(ed25519_der_private_key: Vec<u8>) -> Result<ServerConfig> {
    let key_pair = rcgen::KeyPair::from_der(&ed25519_der_private_key)?;

    let mut params = rcgen::CertificateParams::new(vec!["example.com".into()]);
    params.alg = &key_pair.compatible_algs().next().expect("always an algo");
    params.key_pair = Some(key_pair);

    let cert = rcgen::Certificate::from_params(params)?;

    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();
    let priv_key = PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der)];

    let server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;

    Ok(server_config)
}
