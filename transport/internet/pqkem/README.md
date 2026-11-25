# PQ KEM Transport

`pqkem` provides an opt-in hybrid post-quantum key-exchange and record layer:

- ML-KEM-768 (`crypto/mlkem`, FIPS 203)
- X25519 ephemeral ECDH
- HKDF-SHA-256 key derivation
- AES-256-GCM framed records with direction-specific nonces
- Optional pre-shared key for peer authentication binding

The handshake runs over any ordered byte transport. Tests cover raw TCP,
WebSocket, and gRPC/Gun.

## Configuration

Existing configurations are unchanged. Enable the layer in any TCP-family
`streamSettings`:

```json
{
  "network": "ws",
  "pqkemSettings": {
    "enabled": true,
    "psk": "deployment-shared-secret",
    "handshakeTimeout": "5s"
  }
}
```

`"pqkem": true` is accepted as a shorthand for the secure defaults.

## Audit Log

Attach a `pqkem.Sink` (for example `pqkem.NewJSONSink(os.Stdout)`) to receive
one verifiable JSON record per side. Client and server records share
`sessionId`, `transcriptHash`, and key fingerprints, but never contain key
material or plaintext traffic.

V2Ray's normal logger also emits a correlation line when no custom sink is
supplied by the embedding process.
