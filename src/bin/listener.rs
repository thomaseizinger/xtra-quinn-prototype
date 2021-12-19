use anyhow::Result;
use futures::StreamExt;
use quinn::{Endpoint, Incoming, ServerConfig};
use rustls::PrivateKey;
use std::{net::SocketAddr, sync::Arc};
use xtra_quinn_prototype::{handle_protocol, BiStream, PingActor};

#[tokio::main]
async fn main() -> Result<()> {
    let (incoming, _) = make_server_endpoint("0.0.0.0:8080".parse()?)?;
    let mut incoming = incoming.fuse();

    while let Ok(new_connection) = incoming.select_next_some().await.await {
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

    Ok(())
}

/// Constructs a QUIC endpoint configured to listen for incoming connections on a certain address
/// and port.
///
/// ## Returns
///
/// - a stream of incoming QUIC connections
/// - server certificate serialized into DER format
#[allow(unused)]
pub fn make_server_endpoint(bind_addr: SocketAddr) -> Result<(Incoming, Vec<u8>)> {
    let (server_config, server_cert) = configure_server()?;
    let (_endpoint, incoming) = Endpoint::server(server_config, bind_addr)?;
    Ok((incoming, server_cert))
}

/// Returns default server configuration along with its certificate.
#[allow(clippy::field_reassign_with_default)] // https://github.com/rust-lang/rust-clippy/issues/6527
fn configure_server() -> Result<(ServerConfig, Vec<u8>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der.clone())];

    let mut server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;
    Arc::get_mut(&mut server_config.transport)
        .unwrap()
        .max_concurrent_uni_streams(0_u8.into());

    Ok((server_config, cert_der))
}
