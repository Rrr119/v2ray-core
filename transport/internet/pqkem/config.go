package pqkem

import (
	"bytes"
	"encoding/json"
	"time"
)

const (
	AlgorithmMLKEM768 = "ML-KEM-768"
	ClassicalX25519   = "X25519"
	NegotiatedGroup   = "X25519MLKEM768"
	Suite             = "X25519+ML-KEM-768/AES-256-GCM"
	ProtocolVersion   = byte(1)

	DefaultHandshakeTimeout = 10 * time.Second
	MaxFrameSize            = 16 * 1024
)

// Config configures the opt-in post-quantum KEM transport layer.
//
// The zero value is disabled. Existing configurations remain valid because
// PQ KEM is only negotiated when Enabled is true.
type Config struct {
	Enabled          bool          `json:"enabled"`
	PSK              string        `json:"psk,omitempty"`
	HandshakeTimeout time.Duration `json:"handshakeTimeout,omitempty"`

	// Require makes a failed PQ handshake fatal. It is retained for
	// configuration readability; an enabled Config already fails closed.
	Require bool `json:"require,omitempty"`

	sink Sink `json:"-"`
}

// DefaultConfig returns an enabled configuration with safe defaults.
func DefaultConfig() *Config {
	return &Config{
		Enabled:          true,
		Require:          true,
		HandshakeTimeout: DefaultHandshakeTimeout,
	}
}

// WithSink returns c with an audit sink attached without mutating c.
func (c *Config) WithSink(sink Sink) *Config {
	copied := c.Clone()
	copied.sink = sink
	return copied
}

// Sink returns the configured audit sink, if any.
func (c *Config) Sink() Sink {
	if c == nil {
		return nil
	}
	return c.sink
}

// Clone returns a deep-enough copy for concurrent use.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	copied := *c
	return &copied
}

func (c *Config) withDefaults() *Config {
	copied := c.Clone()
	if copied == nil {
		copied = new(Config)
	}
	if copied.Enabled && copied.HandshakeTimeout <= 0 {
		copied.HandshakeTimeout = DefaultHandshakeTimeout
	}
	return copied
}

// UnmarshalJSON accepts either a duration string ("5s") or nanoseconds.
func (c *Config) UnmarshalJSON(data []byte) error {
	if bytes.Equal(bytes.TrimSpace(data), []byte("true")) {
		*c = *DefaultConfig()
		return nil
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("false")) || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		*c = Config{}
		return nil
	}

	type plain Config
	type alias struct {
		plain
		HandshakeTimeout any `json:"handshakeTimeout"`
	}

	var raw alias
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*c = Config(raw.plain)

	switch value := raw.HandshakeTimeout.(type) {
	case nil:
	case string:
		timeout, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		c.HandshakeTimeout = timeout
	case float64:
		c.HandshakeTimeout = time.Duration(value)
	}
	return nil
}
