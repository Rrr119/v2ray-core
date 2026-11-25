package pqkem

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/hkdf"
)

const suiteX25519MLKEM768 byte = 0x01

var ErrDisabled = errors.New("pqkem: transport is disabled")

// Client performs the client side of the PQ KEM handshake.
func Client(ctx context.Context, raw net.Conn, transport string, config *Config) (*Conn, KeyExchangeLog, error) {
	cfg := normalizeConfig(config)
	if !cfg.Enabled {
		return nil, KeyExchangeLog{}, ErrDisabled
	}
	if raw == nil {
		return nil, KeyExchangeLog{}, errors.New("pqkem: nil connection")
	}

	clearDeadline, stopWatchdog, err := applyHandshakeDeadline(ctx, raw, cfg.HandshakeTimeout)
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}
	defer stopWatchdog()
	defer clearDeadline()

	decapsulationKey, err := mlkem.GenerateKey768()
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: generate ML-KEM key: %w", err)
	}
	classicalKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: generate X25519 key: %w", err)
	}

	kemPublic := decapsulationKey.EncapsulationKey().Bytes()
	classicalPublic := classicalKey.PublicKey().Bytes()
	hello := []byte{ProtocolVersion, suiteX25519MLKEM768}
	hello, err = appendUint16Bytes(hello, kemPublic)
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}
	hello, err = appendUint16Bytes(hello, classicalPublic)
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}
	if err := writeFrame(raw, hello); err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: write client hello: %w", err)
	}

	serverHello, err := readFrame(raw)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: read server hello: %w", err)
	}
	ciphertext, serverClassicalPublic, err := parseServerHello(serverHello)
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}

	kemShared, err := decapsulationKey.Decapsulate(ciphertext)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: decapsulate: %w", err)
	}
	serverPublicKey, err := ecdh.X25519().NewPublicKey(serverClassicalPublic)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: parse server X25519 key: %w", err)
	}
	classicalShared, err := classicalKey.ECDH(serverPublicKey)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: X25519 ECDH: %w", err)
	}

	transcript := append(append([]byte(nil), hello...), serverHello...)
	keys, err := deriveKeys(kemShared, classicalShared, cfg.PSK, transcript)
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}

	clientFinished := finishedMAC(keys.finishedKey, transcript, "client")
	if err := writeFrame(raw, clientFinished); err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: write client finished: %w", err)
	}
	serverFinished, err := readFrame(raw)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: read server finished: %w", err)
	}
	expectedServerFinished := finishedMAC(keys.finishedKey, transcript, "server")
	if !hmac.Equal(serverFinished, expectedServerFinished) {
		return nil, KeyExchangeLog{}, errors.New("pqkem: server confirmation mismatch")
	}

	encryptedConn, err := newConn(raw, keys, "client")
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}
	clientFingerprintMaterial := append(append([]byte(nil), kemPublic...), classicalPublic...)
	serverFingerprintMaterial := append(append([]byte(nil), ciphertext...), serverClassicalPublic...)
	audit := newExchangeLog("client", transport, transcript, clientFingerprintMaterial, serverFingerprintMaterial, raw, cfg.PSK != "")
	recordAudit(cfg.sink, audit)
	return encryptedConn, audit, nil
}

// Server performs the server side of the PQ KEM handshake.
func Server(ctx context.Context, raw net.Conn, transport string, config *Config) (*Conn, KeyExchangeLog, error) {
	cfg := normalizeConfig(config)
	if !cfg.Enabled {
		return nil, KeyExchangeLog{}, ErrDisabled
	}
	if raw == nil {
		return nil, KeyExchangeLog{}, errors.New("pqkem: nil connection")
	}

	clearDeadline, stopWatchdog, err := applyHandshakeDeadline(ctx, raw, cfg.HandshakeTimeout)
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}
	defer stopWatchdog()
	defer clearDeadline()

	hello, err := readFrame(raw)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: read client hello: %w", err)
	}
	kemPublic, clientClassicalPublic, err := parseClientHello(hello)
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}

	encapsulationKey, err := mlkem.NewEncapsulationKey768(kemPublic)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: parse ML-KEM key: %w", err)
	}
	kemShared, ciphertext := encapsulationKey.Encapsulate()

	classicalKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: generate X25519 key: %w", err)
	}
	clientPublicKey, err := ecdh.X25519().NewPublicKey(clientClassicalPublic)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: parse client X25519 key: %w", err)
	}
	classicalShared, err := classicalKey.ECDH(clientPublicKey)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: X25519 ECDH: %w", err)
	}

	classicalPublic := classicalKey.PublicKey().Bytes()
	serverHello := []byte{ProtocolVersion, suiteX25519MLKEM768}
	serverHello, err = appendUint16Bytes(serverHello, ciphertext)
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}
	serverHello, err = appendUint16Bytes(serverHello, classicalPublic)
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}
	if err := writeFrame(raw, serverHello); err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: write server hello: %w", err)
	}

	transcript := append(append([]byte(nil), hello...), serverHello...)
	keys, err := deriveKeys(kemShared, classicalShared, cfg.PSK, transcript)
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}

	clientFinished, err := readFrame(raw)
	if err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: read client finished: %w", err)
	}
	expectedClientFinished := finishedMAC(keys.finishedKey, transcript, "client")
	if !hmac.Equal(clientFinished, expectedClientFinished) {
		return nil, KeyExchangeLog{}, errors.New("pqkem: client confirmation mismatch")
	}
	serverFinished := finishedMAC(keys.finishedKey, transcript, "server")
	if err := writeFrame(raw, serverFinished); err != nil {
		return nil, KeyExchangeLog{}, fmt.Errorf("pqkem: write server finished: %w", err)
	}

	encryptedConn, err := newConn(raw, keys, "server")
	if err != nil {
		return nil, KeyExchangeLog{}, err
	}
	clientFingerprintMaterial := append(append([]byte(nil), kemPublic...), clientClassicalPublic...)
	serverFingerprintMaterial := append(append([]byte(nil), ciphertext...), classicalPublic...)
	audit := newExchangeLog("server", transport, transcript, clientFingerprintMaterial, serverFingerprintMaterial, raw, cfg.PSK != "")
	recordAudit(cfg.sink, audit)
	return encryptedConn, audit, nil
}

func normalizeConfig(config *Config) *Config {
	if config == nil {
		return DefaultConfig().withDefaults()
	}
	return config.withDefaults()
}

func recordAudit(sink Sink, record KeyExchangeLog) {
	if sink != nil {
		sink.RecordPQKEMExchange(record)
	}
}

func applyHandshakeDeadline(ctx context.Context, conn net.Conn, timeout time.Duration) (func(), func(), error) {
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}
	deadline := time.Now().Add(timeout)
	if ctx != nil {
		if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
			deadline = contextDeadline
		}
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}

	stop := func() {}
	if ctx != nil {
		watchdogStopped := false
		stopped := make(chan struct{})
		stop = func() {
			if !watchdogStopped {
				close(stopped)
				watchdogStopped = true
			}
		}
		go func() {
			select {
			case <-ctx.Done():
				_ = conn.Close()
			case <-stopped:
			}
		}()
	}

	clear := func() {
		_ = conn.SetDeadline(time.Time{})
	}
	return clear, stop, nil
}

func parseClientHello(payload []byte) ([]byte, []byte, error) {
	if len(payload) < 2 || payload[0] != ProtocolVersion || payload[1] != suiteX25519MLKEM768 {
		return nil, nil, errors.New("pqkem: unsupported client hello version or suite")
	}
	kemPublic, offset, err := readUint16Bytes(payload, 2)
	if err != nil {
		return nil, nil, fmt.Errorf("pqkem: parse ML-KEM public key: %w", err)
	}
	classicalPublic, _, err := readUint16Bytes(payload, offset)
	if err != nil {
		return nil, nil, fmt.Errorf("pqkem: parse X25519 public key: %w", err)
	}
	if len(kemPublic) != mlkem.EncapsulationKeySize768 {
		return nil, nil, fmt.Errorf("pqkem: invalid ML-KEM public key size %d", len(kemPublic))
	}
	if len(classicalPublic) != 32 {
		return nil, nil, fmt.Errorf("pqkem: invalid X25519 public key size %d", len(classicalPublic))
	}
	return kemPublic, classicalPublic, nil
}

func parseServerHello(payload []byte) ([]byte, []byte, error) {
	if len(payload) < 2 || payload[0] != ProtocolVersion || payload[1] != suiteX25519MLKEM768 {
		return nil, nil, errors.New("pqkem: unsupported server hello version or suite")
	}
	ciphertext, offset, err := readUint16Bytes(payload, 2)
	if err != nil {
		return nil, nil, fmt.Errorf("pqkem: parse ML-KEM ciphertext: %w", err)
	}
	classicalPublic, _, err := readUint16Bytes(payload, offset)
	if err != nil {
		return nil, nil, fmt.Errorf("pqkem: parse X25519 public key: %w", err)
	}
	if len(ciphertext) != mlkem.CiphertextSize768 {
		return nil, nil, fmt.Errorf("pqkem: invalid ML-KEM ciphertext size %d", len(ciphertext))
	}
	if len(classicalPublic) != 32 {
		return nil, nil, fmt.Errorf("pqkem: invalid X25519 public key size %d", len(classicalPublic))
	}
	return ciphertext, classicalPublic, nil
}

func deriveKeys(kemShared, classicalShared []byte, psk string, transcript []byte) (sessionKeys, error) {
	shared := make([]byte, 0, len(kemShared)+len(classicalShared)+len(psk))
	shared = append(shared, kemShared...)
	shared = append(shared, classicalShared...)
	shared = append(shared, psk...)

	transcriptHash := sha256.Sum256(transcript)
	prk := hkdf.Extract(sha256.New, shared, transcriptHash[:])
	reader := hkdf.Expand(sha256.New, prk, []byte("v2ray.core/transport/internet/pqkem/v1"))

	keys := sessionKeys{
		clientKey:    make([]byte, 32),
		serverKey:    make([]byte, 32),
		clientPrefix: make([]byte, 4),
		serverPrefix: make([]byte, 4),
		finishedKey:  make([]byte, 32),
	}
	for _, destination := range [][]byte{
		keys.clientKey,
		keys.serverKey,
		keys.clientPrefix,
		keys.serverPrefix,
		keys.finishedKey,
	} {
		if _, err := io.ReadFull(reader, destination); err != nil {
			return sessionKeys{}, fmt.Errorf("pqkem: derive keys: %w", err)
		}
	}
	return keys, nil
}

func finishedMAC(key, transcript []byte, role string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(transcript)
	_, _ = mac.Write([]byte(role))
	return mac.Sum(nil)
}

var _ net.Conn = (*Conn)(nil)
