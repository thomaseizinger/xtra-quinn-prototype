use futures::StreamExt;
use quinn::ConnectionError;
use quinn::Endpoint;
use quinn_p2p_config::NewConnectionExt;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

#[tokio::test]
async fn connect() {
    let (server_private_key, server_public_key) = make_keypair();
    let (client_private_key, client_public_key) = make_keypair();

    let server_config = quinn_p2p_config::server(server_private_key).unwrap();
    let (endpoint, mut server) =
        Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_port = endpoint.local_addr().unwrap().port();

    let client_config =
        quinn_p2p_config::client(server_public_key.clone(), client_private_key).unwrap();
    let client = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();

    let accept = tokio::spawn(async move { server.next().await.unwrap().await.unwrap() });

    let connect = tokio::spawn(async move {
        client
            .connect_with(
                client_config,
                format!("127.0.0.1:{}", server_port).parse().unwrap(),
                quinn_p2p_config::SERVER_NAME,
            )
            .unwrap()
            .await
            .unwrap()
    });

    let client_connection = connect.await.unwrap();
    let server_connection = accept.await.unwrap();

    let expected_server_pubkey = client_connection.peer_public_key().unwrap();
    let expected_client_pubkey = server_connection.peer_public_key().unwrap();

    assert_eq!(server_public_key, expected_server_pubkey);
    assert_eq!(client_public_key, expected_client_pubkey);
}

#[tokio::test]
async fn bad_public_key() {
    let private_key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .unwrap()
        .as_ref()
        .to_vec();
    let public_key =
        hex::decode("16ab28dd383ccc8083c40f031efb380a9672499e1b1c89185730bd66c25cb55b").unwrap();

    let (client_private_key, _client_public_key) = make_keypair();

    let server_config = quinn_p2p_config::server(private_key).unwrap();
    let (endpoint, mut server) =
        Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_port = endpoint.local_addr().unwrap().port();

    let client_config = quinn_p2p_config::client(public_key, client_private_key).unwrap();
    let client = Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();

    let accept = tokio::spawn(async move { server.next().await.unwrap().await.unwrap_err() });

    let connect = tokio::spawn(async move {
        client
            .connect_with(
                client_config,
                format!("127.0.0.1:{}", server_port).parse().unwrap(),
                quinn_p2p_config::SERVER_NAME,
            )
            .unwrap()
            .await
            .unwrap_err()
    });

    match connect.await.unwrap() {
        ConnectionError::TransportError(transport_error) => {
            assert_eq!(transport_error.reason, "invalid peer certificate signature")
        }
        _ => panic!("expected `TransportError`"),
    };
    match accept.await.unwrap() {
        ConnectionError::ConnectionClosed(_) => {}
        _ => panic!("expected `ConnectionClosed`"),
    };
}

fn make_keypair() -> (Vec<u8>, Vec<u8>) {
    let private_key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .unwrap()
        .as_ref()
        .to_vec();
    let public_key = Ed25519KeyPair::from_pkcs8(&private_key)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();
    (private_key, public_key)
}
