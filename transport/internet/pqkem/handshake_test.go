package pqkem_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/v2fly/v2ray-core/v5/transport/internet/pqkem"
)

func TestPSKMismatchFailsClosed(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() { _ = clientRaw.Close() })
	t.Cleanup(func() { _ = serverRaw.Close() })

	serverErr := make(chan error, 1)
	go func() {
		_, _, err := pqkem.Server(context.Background(), serverRaw, "tcp", &pqkem.Config{
			Enabled:          true,
			PSK:              "server-secret",
			HandshakeTimeout: 2 * time.Second,
		})
		if err != nil {
			_ = serverRaw.Close()
		}
		serverErr <- err
	}()

	_, _, err := pqkem.Client(context.Background(), clientRaw, "tcp", &pqkem.Config{
		Enabled:          true,
		PSK:              "client-secret",
		HandshakeTimeout: 2 * time.Second,
	})
	require.Error(t, err)

	select {
	case err := <-serverErr:
		require.Error(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not reject mismatched PSK")
	}
}

func TestDisabledConfigIsNotSilentlyUpgraded(t *testing.T) {
	raw, _ := net.Pipe()
	_, _, err := pqkem.Client(context.Background(), raw, "tcp", &pqkem.Config{Enabled: false})
	require.ErrorIs(t, err, pqkem.ErrDisabled)
	require.NoError(t, raw.Close())
}
