package pqkem

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

const AuditEvent = "pq_kem_key_exchange"

// KeyExchangeLog is the verifiable audit record for one PQ handshake.
// It contains only public fingerprints and correlation identifiers.
type KeyExchangeLog struct {
	Timestamp            time.Time `json:"timestamp"`
	Event                string    `json:"event"`
	Transport            string    `json:"transport"`
	Role                 string    `json:"role"`
	Suite                string    `json:"suite"`
	Group                string    `json:"group"`
	KEM                  string    `json:"kem"`
	Classical            string    `json:"classical"`
	SessionID            string    `json:"sessionId"`
	TranscriptHash       string    `json:"transcriptHash"`
	ClientKeyFingerprint string    `json:"clientKeyFingerprint"`
	ServerKeyFingerprint string    `json:"serverKeyFingerprint"`
	PeerAddr             string    `json:"peerAddr,omitempty"`
	PSKConfigured        bool      `json:"pskConfigured"`
	Confirmed            bool      `json:"confirmed"`
}

// Sink receives key exchange audit records.
type Sink interface {
	RecordPQKEMExchange(KeyExchangeLog)
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(KeyExchangeLog)

func (f SinkFunc) RecordPQKEMExchange(record KeyExchangeLog) {
	if f != nil {
		f(record)
	}
}

// MemorySink keeps audit records for tests and diagnostics.
type MemorySink struct {
	mu      sync.RWMutex
	records []KeyExchangeLog
}

func (s *MemorySink) RecordPQKEMExchange(record KeyExchangeLog) {
	s.mu.Lock()
	s.records = append(s.records, record)
	s.mu.Unlock()
}

func (s *MemorySink) Records() []KeyExchangeLog {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]KeyExchangeLog, len(s.records))
	copy(out, s.records)
	return out
}

// JSONSink writes one JSON object per handshake to an io.Writer.
type JSONSink struct {
	mu sync.Mutex
	w  io.Writer
}

func NewJSONSink(w io.Writer) *JSONSink {
	return &JSONSink{w: w}
}

func (s *JSONSink) RecordPQKEMExchange(record KeyExchangeLog) {
	if s == nil || s.w == nil {
		return
	}
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.w.Write(append(data, '\n'))
}

// NormalizeTransport canonicalizes transport names used in audit logs.
func NormalizeTransport(transport string) string {
	switch strings.ToLower(strings.TrimSpace(transport)) {
	case "", "raw", "stream":
		return "stream"
	case "ws", "websocket":
		return "websocket"
	case "gun", "grpc":
		return "grpc"
	case "ds", "domainsocket":
		return "domainsocket"
	case "h2", "http":
		return "http"
	case "mkcp", "kcp":
		return "mkcp"
	default:
		return strings.ToLower(transport)
	}
}

func newExchangeLog(role, transport string, transcript, clientFingerprint, serverFingerprint []byte, conn net.Conn, psk bool) KeyExchangeLog {
	transcriptFingerprint := sha256Sum(transcript)
	log := KeyExchangeLog{
		Timestamp:            time.Now().UTC(),
		Event:                AuditEvent,
		Transport:            NormalizeTransport(transport),
		Role:                 role,
		Suite:                Suite,
		Group:                NegotiatedGroup,
		KEM:                  AlgorithmMLKEM768,
		Classical:            ClassicalX25519,
		SessionID:            hex.EncodeToString(transcriptFingerprint[:16]),
		TranscriptHash:       hex.EncodeToString(transcriptFingerprint[:]),
		ClientKeyFingerprint: fingerprint(clientFingerprint),
		ServerKeyFingerprint: fingerprint(serverFingerprint),
		PSKConfigured:        psk,
		Confirmed:            true,
	}
	if conn != nil && conn.RemoteAddr() != nil {
		log.PeerAddr = conn.RemoteAddr().String()
	}
	return log
}

// Validate checks that a log is complete and internally consistent.
func (l KeyExchangeLog) Validate(expectedTransport ...string) error {
	if l.Event != AuditEvent {
		return fmt.Errorf("unexpected audit event %q", l.Event)
	}
	if l.Suite != Suite || l.Group != NegotiatedGroup || l.KEM != AlgorithmMLKEM768 || l.Classical != ClassicalX25519 {
		return fmt.Errorf("unsupported PQ suite in audit record")
	}
	if !l.Confirmed {
		return fmt.Errorf("key exchange is not confirmed")
	}
	if len(l.SessionID) != 32 || len(l.TranscriptHash) != 64 {
		return fmt.Errorf("audit record has invalid exchange identifiers")
	}
	if !strings.HasPrefix(l.TranscriptHash, l.SessionID) {
		return fmt.Errorf("session id does not match transcript hash")
	}
	if len(l.ClientKeyFingerprint) != 71 || len(l.ServerKeyFingerprint) != 71 {
		return fmt.Errorf("audit record has invalid key fingerprints")
	}
	for _, transport := range expectedTransport {
		if NormalizeTransport(transport) != l.Transport {
			return fmt.Errorf("transport mismatch: want %q, got %q", transport, l.Transport)
		}
	}
	return nil
}

// SameExchange reports whether two role logs describe the same handshake.
func (l KeyExchangeLog) SameExchange(other KeyExchangeLog) bool {
	return l.SessionID == other.SessionID &&
		l.TranscriptHash == other.TranscriptHash &&
		l.ClientKeyFingerprint == other.ClientKeyFingerprint &&
		l.ServerKeyFingerprint == other.ServerKeyFingerprint &&
		l.Suite == other.Suite
}

// VerifyLog validates one audit record for the expected transport.
func VerifyLog(record KeyExchangeLog, expectedTransport ...string) error {
	return record.Validate(expectedTransport...)
}

// VerifyExchangePair validates that two role logs describe the same exchange.
func VerifyExchangePair(client, server KeyExchangeLog, transport string) error {
	if err := client.Validate(transport); err != nil {
		return fmt.Errorf("client log: %w", err)
	}
	if err := server.Validate(transport); err != nil {
		return fmt.Errorf("server log: %w", err)
	}
	if !client.SameExchange(server) {
		return errors.New("client and server PQ KEM logs do not match")
	}
	return nil
}

// ParseJSONLogs reads newline-delimited JSON audit records.
func ParseJSONLogs(data []byte) ([]KeyExchangeLog, error) {
	var records []KeyExchangeLog
	decoder := json.NewDecoder(bytes.NewReader(data))
	for decoder.More() {
		var record KeyExchangeLog
		if err := decoder.Decode(&record); err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}

func fingerprint(publicMaterial []byte) string {
	sum := sha256Sum(publicMaterial)
	return "sha256:" + hex.EncodeToString(sum[:])
}
