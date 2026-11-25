package pqkem

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

func sha256Sum(data ...[]byte) [32]byte {
	hash := sha256.New()
	for _, chunk := range data {
		_, _ = hash.Write(chunk)
	}
	var sum [32]byte
	copy(sum[:], hash.Sum(nil))
	return sum
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("pqkem: frame too large: %d", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	return writeFull(w, payload)
}

func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > MaxFrameSize {
		return nil, fmt.Errorf("pqkem: invalid frame length %d", length)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func writeFull(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func appendUint16Bytes(dst []byte, data []byte) ([]byte, error) {
	if len(data) > 65535 {
		return nil, fmt.Errorf("pqkem: field too long: %d", len(data))
	}
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(data)))
	dst = append(dst, length[:]...)
	dst = append(dst, data...)
	return dst, nil
}

func readUint16Bytes(payload []byte, offset int) ([]byte, int, error) {
	if len(payload) < offset+2 {
		return nil, offset, io.ErrUnexpectedEOF
	}
	length := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	if len(payload) < offset+length {
		return nil, offset, io.ErrUnexpectedEOF
	}
	value := append([]byte(nil), payload[offset:offset+length]...)
	return value, offset + length, nil
}
