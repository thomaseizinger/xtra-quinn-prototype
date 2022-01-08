use futures::StreamExt;
use quinn::ConnectionError;
use quinn::Endpoint;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};

#[tokio::test]
async fn connect() {
    let private_key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .unwrap()
        .as_ref()
        .to_vec();
    let public_key = Ed25519KeyPair::from_pkcs8(&private_key)
        .unwrap()
        .public_key()
        .as_ref()
        .to_vec();

    println!("{}", hex::encode(&private_key));
    println!("{}", hex::encode(&public_key));

    let server_config = quinn_p2p_config::server(private_key).unwrap();
    let (endpoint, mut server) =
        Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_port = endpoint.local_addr().unwrap().port();

    let client_config = quinn_p2p_config::client(public_key);
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

    let _client_connection = connect.await.unwrap();
    let _server_connection = accept.await.unwrap();
}

#[tokio::test]
async fn bad_public_key() {
    let private_key = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .unwrap()
        .as_ref()
        .to_vec();
    let public_key =
        hex::decode("16ab28dd383ccc8083c40f031efb380a9672499e1b1c89185730bd66c25cb55b").unwrap();

    let server_config = quinn_p2p_config::server(private_key).unwrap();
    let (endpoint, mut server) =
        Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_port = endpoint.local_addr().unwrap().port();

    let client_config = quinn_p2p_config::client(public_key);
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
