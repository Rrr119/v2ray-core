package internet

import (
	"context"

	"github.com/v2fly/v2ray-core/v5/transport/internet/pqkem"
)

type v2rayPQKEMSink struct{}

func (v2rayPQKEMSink) RecordPQKEMExchange(record pqkem.KeyExchangeLog) {
	if err := record.Validate(record.Transport); err != nil {
		newError("invalid PQ KEM audit record: ", err).AtWarning().WriteToLog()
		return
	}
	newError(
		"PQ KEM ", record.Role,
		" exchange verified transport=", record.Transport,
		" suite=", record.Suite,
		" session=", record.SessionID,
		" transcript=", record.TranscriptHash,
	).AtInfo().WriteToLog()
}

func pqkemConfig(streamSettings *MemoryStreamConfig) *pqkem.Config {
	if streamSettings == nil || streamSettings.PQKEM == nil || !streamSettings.PQKEM.Enabled {
		return nil
	}
	config := streamSettings.PQKEM
	if config.Sink() == nil {
		config = config.WithSink(v2rayPQKEMSink{})
	}
	return config
}

// ApplyPQKEMClient upgrades a TCP-family connection with PQ KEM when configured.
func ApplyPQKEMClient(ctx context.Context, conn Connection, streamSettings *MemoryStreamConfig) (Connection, error) {
	config := pqkemConfig(streamSettings)
	if config == nil {
		return conn, nil
	}
	wrapped, _, err := pqkem.Client(ctx, conn, streamSettings.ProtocolName, config)
	if err != nil {
		_ = conn.Close()
		return nil, newError("PQ KEM client handshake failed").Base(err)
	}
	return wrapped, nil
}

// ApplyPQKEMServer upgrades an accepted TCP-family connection when configured.
func ApplyPQKEMServer(ctx context.Context, conn Connection, streamSettings *MemoryStreamConfig) (Connection, error) {
	config := pqkemConfig(streamSettings)
	if config == nil {
		return conn, nil
	}
	wrapped, _, err := pqkem.Server(ctx, conn, streamSettings.ProtocolName, config)
	if err != nil {
		_ = conn.Close()
		return nil, newError("PQ KEM server handshake failed").Base(err)
	}
	return wrapped, nil
}
