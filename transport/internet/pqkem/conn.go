package pqkem

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

type sessionKeys struct {
	clientKey    []byte
	serverKey    []byte
	clientPrefix []byte
	serverPrefix []byte
	finishedKey  []byte
}

// Conn is the encrypted post-quantum record connection.
type Conn struct {
	conn net.Conn

	readCipher  cipher.AEAD
	writeCipher cipher.AEAD
	readPrefix  []byte
	writePrefix []byte

	readSeq  uint64
	writeSeq uint64

	readMu    sync.Mutex
	writeMu   sync.Mutex
	buffered  []byte
	closeOnce sync.Once
}

func newConn(raw net.Conn, keys sessionKeys, role string) (*Conn, error) {
	clientBlock, err := aes.NewCipher(keys.clientKey)
	if err != nil {
		return nil, err
	}
	serverBlock, err := aes.NewCipher(keys.serverKey)
	if err != nil {
		return nil, err
	}
	clientAEAD, err := cipher.NewGCM(clientBlock)
	if err != nil {
		return nil, err
	}
	serverAEAD, err := cipher.NewGCM(serverBlock)
	if err != nil {
		return nil, err
	}

	conn := &Conn{conn: raw}
	if role == "client" {
		conn.writeCipher = clientAEAD
		conn.readCipher = serverAEAD
		conn.writePrefix = append([]byte(nil), keys.clientPrefix...)
		conn.readPrefix = append([]byte(nil), keys.serverPrefix...)
	} else {
		conn.writeCipher = serverAEAD
		conn.readCipher = clientAEAD
		conn.writePrefix = append([]byte(nil), keys.serverPrefix...)
		conn.readPrefix = append([]byte(nil), keys.clientPrefix...)
	}
	return conn, nil
}

// Read decrypts the next application record.
func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}
	if len(c.buffered) > 0 {
		n := copy(p, c.buffered)
		c.buffered = c.buffered[n:]
		if len(c.buffered) == 0 {
			c.buffered = nil
		}
		return n, nil
	}

	ciphertext, err := readFrame(c.conn)
	if err != nil {
		return 0, err
	}

	nonce := recordNonce(c.readPrefix, c.readSeq)
	c.readSeq++
	plaintext, err := c.readCipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, err
	}

	n := copy(p, plaintext)
	if n < len(plaintext) {
		c.buffered = append([]byte(nil), plaintext[n:]...)
	}
	return n, nil
}

// Write encrypts and sends p as one record.
func (c *Conn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(p) > MaxFrameSize-c.writeCipher.Overhead() {
		return 0, errors.New("pqkem: plaintext record too large")
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	nonce := recordNonce(c.writePrefix, c.writeSeq)
	c.writeSeq++
	ciphertext := c.writeCipher.Seal(nil, nonce, p, nil)
	if err := writeFrame(c.conn, ciphertext); err != nil {
		return 0, err
	}
	return len(p), nil
}

func recordNonce(prefix []byte, sequence uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce[:4], prefix)
	nonce[4] = byte(sequence >> 56)
	nonce[5] = byte(sequence >> 48)
	nonce[6] = byte(sequence >> 40)
	nonce[7] = byte(sequence >> 32)
	nonce[8] = byte(sequence >> 24)
	nonce[9] = byte(sequence >> 16)
	nonce[10] = byte(sequence >> 8)
	nonce[11] = byte(sequence)
	return nonce
}

// Close closes the underlying transport connection.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		err = c.conn.Close()
	})
	return err
}

func (c *Conn) LocalAddr() net.Addr  { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.conn.RemoteAddr() }

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

var _ net.Conn = (*Conn)(nil)
var _ io.Reader = (*Conn)(nil)
