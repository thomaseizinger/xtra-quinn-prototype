# Prototype for combining `xtra` and `quinn`

The question we started out with was: How can we use QUIC's multiplexing to establishing a direct connection between two actors in a p2p application?

The answer is:

- Use a custom certificate verifier so we can use self-signed certificates.
In a real application, we obviously want _some_ cryptography here but for this PoC we simply disable the verification.
**DO NOT COPY THIS INTO A PRODUCTION SYSTEM!**
- Use libp2p `multistream-select` to negotiate the purpose of a newly opened, bi-directional stream.
- Once established, spawn the actor appropriate for the given protocol and hand the reading and writing end to it.

## Usage:

```shell
cargo run --bin listener
cargo run --bin dialer
```
