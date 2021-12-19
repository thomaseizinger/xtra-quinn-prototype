use anyhow::Result;
use futures::StreamExt;
use quinn::{Endpoint, Incoming, ServerConfig};
use rustls::PrivateKey;
use std::net::SocketAddr;
use xtra_quinn_prototype::{handle_protocol, BiStream, PingActor};

#[tokio::main]
async fn main() -> Result<()> {
    let mut incoming = make_server_endpoint("0.0.0.0:8080".parse()?)?.fuse();

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

pub fn make_server_endpoint(bind_addr: SocketAddr) -> Result<Incoming> {
    let server_config = self_signed_cert_config()?;
    let (_endpoint, incoming) = Endpoint::server(server_config, bind_addr)?;

    Ok(incoming)
}

fn self_signed_cert_config() -> Result<ServerConfig> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
    let cert_der = cert.serialize_der()?;
    let priv_key = cert.serialize_private_key_der();
    let priv_key = PrivateKey(priv_key);
    let cert_chain = vec![rustls::Certificate(cert_der)];

    let server_config = ServerConfig::with_single_cert(cert_chain, priv_key)?;

    Ok(server_config)
}
