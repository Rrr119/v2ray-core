package internet_test

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v2net "github.com/v2fly/v2ray-core/v5/common/net"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/pqkem"
	"github.com/v2fly/v2ray-core/v5/transport/internet/tcp"
)

func TestInternetDialAppliesPQKEM(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	serverLogs := new(pqkem.MemorySink)
	serverStream := &internet.MemoryStreamConfig{
		ProtocolName: "tcp",
		PQKEM:        pqkem.DefaultConfig().WithSink(serverLogs),
	}

	serverErr := make(chan error, 1)
	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverErr <- acceptErr
			return
		}
		conn, wrapErr := internet.ApplyPQKEMServer(context.Background(), raw, serverStream)
		if wrapErr != nil {
			serverErr <- wrapErr
			return
		}
		buffer := make([]byte, len("ping"))
		if _, err := io.ReadFull(conn, buffer); err != nil {
			serverErr <- err
			return
		}
		if _, err := conn.Write(buffer); err != nil {
			serverErr <- err
			return
		}
		serverErr <- conn.Close()
	}()

	address := listener.Addr().(*net.TCPAddr)
	destination := v2net.TCPDestination(v2net.IPAddress(address.IP), v2net.Port(address.Port))
	clientLogs := new(pqkem.MemorySink)
	stream := &internet.MemoryStreamConfig{
		ProtocolName:     "tcp",
		ProtocolSettings: &tcp.Config{},
		PQKEM:            pqkem.DefaultConfig().WithSink(clientLogs),
	}

	conn, err := internet.Dial(context.Background(), destination, stream)
	require.NoError(t, err)
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	response := make([]byte, 4)
	_, err = io.ReadFull(conn, response)
	require.NoError(t, err)
	require.Equal(t, "ping", string(response))
	require.NoError(t, conn.Close())

	select {
	case err := <-serverErr:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("server did not finish")
	}

	require.Len(t, clientLogs.Records(), 1)
	require.Eventually(t, func() bool { return len(serverLogs.Records()) == 1 }, time.Second, 10*time.Millisecond)
	require.True(t, clientLogs.Records()[0].SameExchange(serverLogs.Records()[0]))
}
