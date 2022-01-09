# Prototype for combining `xtra` and `quinn`

The question we started out with was: How can we use QUIC's multiplexing to establishing a direct connection between two actors in a p2p application?

The answer is:

- Use a custom certificate verifier so we can use self-signed certificates.
  We expect the certificate to be signed with a specific public key.
  This has not been audited by a cryptographer so might be complete bogus.
- Use libp2p `multistream-select` to negotiate the purpose of a newly opened, bi-directional stream.
- Once established, spawn the actor appropriate for the given protocol and hand the reading and writing end to it.

## Usage:

Check the output of `--help` for the two binaries provided.

```shell
cargo run --bin listener -- --help
cargo run --bin dialer -- --help
```

The listener supports protocol `/ping/1.0.0`, so once the dialer asks for which protocol to use you can enter that to upgrade successfully and receive ping/pong message.
