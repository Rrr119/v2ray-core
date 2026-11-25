package v4_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	v4 "github.com/v2fly/v2ray-core/v5/infra/conf/v4"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
)

func TestPQKEMStreamSettingsJSONCompatibility(t *testing.T) {
	var settings v4.StreamConfig
	require.NoError(t, json.Unmarshal([]byte(`{
		"network": "ws",
		"security": "none",
		"pqkemSettings": {"enabled": true, "psk": "test-psk", "handshakeTimeout": "3s"}
	}`), &settings))

	built, err := settings.Build()
	require.NoError(t, err)
	require.Equal(t, "websocket", built.ProtocolName)

	wire, err := proto.Marshal(built)
	require.NoError(t, err)
	var roundTripped internet.StreamConfig
	require.NoError(t, proto.Unmarshal(wire, &roundTripped))

	memory, err := internet.ToMemoryStreamConfig(&roundTripped)
	require.NoError(t, err)
	require.NotNil(t, memory.PQKEM)
	require.True(t, memory.PQKEM.Enabled)
	require.Equal(t, "test-psk", memory.PQKEM.PSK)
}

func TestPQKEMStreamSettingsBoolShorthand(t *testing.T) {
	var settings v4.StreamConfig
	require.NoError(t, json.Unmarshal([]byte(`{"network":"grpc","pqkem":true}`), &settings))

	built, err := settings.Build()
	require.NoError(t, err)
	memory, err := internet.ToMemoryStreamConfig(built)
	require.NoError(t, err)
	require.NotNil(t, memory.PQKEM)
	require.True(t, memory.PQKEM.Enabled)
}

func TestLegacyStreamSettingsHasNoPQKEM(t *testing.T) {
	var settings v4.StreamConfig
	require.NoError(t, json.Unmarshal([]byte(`{"network":"tcp","security":"none"}`), &settings))

	built, err := settings.Build()
	require.NoError(t, err)
	memory, err := internet.ToMemoryStreamConfig(built)
	require.NoError(t, err)
	require.Nil(t, memory.PQKEM)
}
