package pqkem

import (
	"context"
	"net"
)

// PQKEMTransport is the reusable post-quantum key-exchange transport layer.
// It wraps any ordered byte transport such as TCP, WebSocket, or gRPC/Gun.
type PQKEMTransport struct {
	config *Config
}

// NewPQKEMTransport creates a transport with the supplied configuration.
func NewPQKEMTransport(config *Config) *PQKEMTransport {
	return &PQKEMTransport{config: normalizeConfig(config)}
}

// Client performs the client handshake and returns an encrypted connection.
func (t *PQKEMTransport) Client(ctx context.Context, conn net.Conn, transport string) (*Conn, KeyExchangeLog, error) {
	return Client(ctx, conn, transport, t.config)
}

// Server performs the server handshake and returns an encrypted connection.
func (t *PQKEMTransport) Server(ctx context.Context, conn net.Conn, transport string) (*Conn, KeyExchangeLog, error) {
	return Server(ctx, conn, transport, t.config)
}

// Config returns a copy of the transport configuration.
func (t *PQKEMTransport) Config() *Config {
	return t.config.Clone()
}

// KeyExchangeRecord is a descriptive alias for audit consumers.
type KeyExchangeRecord = KeyExchangeLog

// ExchangeLogger is a descriptive alias for audit sinks.
type ExchangeLogger = Sink
