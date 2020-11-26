# Simple SOCKS

Be young and be simple.

## Protocol

The client and server use [X25519](https://tools.ietf.org/html/rfc8418) for key exchange and [ChaCha20](https://tools.ietf.org/html/rfc8439) for encryption.
See `conn.go` for the protocol.

A reference client is implemented in `cmd/ss-client`.

  - Generate an ephemeral key.
  - Listen on a local port.
  - Dial to the server.
  - Perform key exchange.
  - Encrypt all traffic from local port and forward to the server.

A reference server is implemented in `cmd/ss-server`.

  - Load a key from file or generates an ephemeral key.
  - Listen on a local port.
  - Perform key exchange.
  - Decrypt incoming traffic, and depending on the operating mode:
    1. Dial to a remote port and forward all traffic.
    2. Serve in incoming traffic using SOCKS5 protocol.
