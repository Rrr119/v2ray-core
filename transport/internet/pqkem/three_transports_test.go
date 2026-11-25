package pqkem_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/v2fly/v2ray-core/v5/app/router/userpolicy"
	v2net "github.com/v2fly/v2ray-core/v5/common/net"
	testtcp "github.com/v2fly/v2ray-core/v5/testing/servers/tcp"
	"github.com/v2fly/v2ray-core/v5/transport/internet"
	"github.com/v2fly/v2ray-core/v5/transport/internet/grpc/encoding"
	"github.com/v2fly/v2ray-core/v5/transport/internet/pqkem"
	v2websocket "github.com/v2fly/v2ray-core/v5/transport/internet/websocket"
)

const testPayload = "post-quantum-key-exchange-ok"

type transportHarness struct {
	name       string
	dial       func(t *testing.T) net.Conn
	serverLogs *pqkem.MemorySink
}

func TestKeyExchangeLogsAndUserRoutingAcrossThreeTransports(t *testing.T) {
	policies := testUserPolicyTable(t)

	for _, harness := range []transportHarness{
		newTCPHarness(t),
		newWebSocketHarness(t),
		newGRPCHarness(t),
	} {
		t.Run(harness.name, func(t *testing.T) {
			var clientLogBuffer bytes.Buffer
			clientSink := pqkem.NewJSONSink(&clientLogBuffer)
			clientConfig := pqkem.DefaultConfig().WithSink(clientSink)
			rawClient := harness.dial(t)
			clientConn, clientLog, err := pqkem.Client(context.Background(), rawClient, harness.name, clientConfig)
			require.NoError(t, err)

			require.Eventually(t, func() bool {
				return len(harness.serverLogs.Records()) == 1
			}, 2*time.Second, 10*time.Millisecond)
			serverLog := harness.serverLogs.Records()[0]
			require.NoError(t, pqkem.VerifyExchangePair(clientLog, serverLog, harness.name))

			logs, err := pqkem.ParseJSONLogs(clientLogBuffer.Bytes())
			require.NoError(t, err)
			require.Len(t, logs, 1)
			require.NoError(t, pqkem.VerifyExchangePair(logs[0], serverLog, harness.name))
			require.NotContains(t, clientLogBuffer.String(), testPayload)

			_, err = clientConn.Write([]byte(testPayload))
			require.NoError(t, err)
			received := make([]byte, len(testPayload))
			_, err = io.ReadFull(clientConn, received)
			require.NoError(t, err)
			require.Equal(t, testPayload, string(received))
			require.NoError(t, clientConn.Close())

			assertUserRouting(t, policies)
		})
	}
}

func testUserPolicyTable(t *testing.T) *userpolicy.Table {
	t.Helper()
	table, err := userpolicy.NewTable(userpolicy.Config{
		Policies: []userpolicy.Policy{
			{User: "alice@example.com", OutboundTag: "direct"},
			{Users: []string{"bob@example.com", "ci@example.com"}, OutboundTag: "safe-proxy"},
			{User: "mallory@example.com", Action: userpolicy.ActionBlock},
		},
		DefaultDeny: true,
		BlockTag:    "blocked",
	})
	require.NoError(t, err)
	return table
}

func assertUserRouting(t *testing.T, table *userpolicy.Table) {
	t.Helper()

	alice, err := table.Route("alice@example.com")
	require.NoError(t, err)
	require.Equal(t, "direct", alice)

	bob, err := table.Route("bob@example.com")
	require.NoError(t, err)
	require.Equal(t, "safe-proxy", bob)

	ci, err := table.Route("ci@example.com")
	require.NoError(t, err)
	require.Equal(t, "safe-proxy", ci)

	_, err = table.Route("mallory@example.com")
	require.ErrorIs(t, err, userpolicy.ErrAccessDenied)

	_, err = table.Route("stranger@example.com")
	require.ErrorIs(t, err, userpolicy.ErrAccessDenied)
}

func newTCPHarness(t *testing.T) transportHarness {
	t.Helper()
	serverLogs := new(pqkem.MemorySink)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		raw, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		serverConn, _, handshakeErr := pqkem.Server(context.Background(), raw, "tcp", pqkem.DefaultConfig().WithSink(serverLogs))
		if handshakeErr != nil {
			_ = raw.Close()
			return
		}
		echo(serverConn)
	}()

	return transportHarness{
		name:       "tcp",
		serverLogs: serverLogs,
		dial: func(t *testing.T) net.Conn {
			conn, dialErr := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
			require.NoError(t, dialErr)
			return conn
		},
	}
}

func newWebSocketHarness(t *testing.T) transportHarness {
	t.Helper()
	serverLogs := new(pqkem.MemorySink)
	wsConfig := &v2websocket.Config{Path: "/pqkem"}
	listener, err := v2websocket.ListenWS(
		context.Background(),
		v2net.LocalHostIP,
		testtcp.PickPort(),
		&internet.MemoryStreamConfig{ProtocolName: "websocket", ProtocolSettings: wsConfig},
		func(conn internet.Connection) {
			serverConn, _, handshakeErr := pqkem.Server(
				context.Background(), conn, "websocket", pqkem.DefaultConfig().WithSink(serverLogs),
			)
			if handshakeErr != nil {
				_ = conn.Close()
				return
			}
			echo(serverConn)
		},
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	port := listener.Addr().(*net.TCPAddr).Port

	return transportHarness{
		name:       "websocket",
		serverLogs: serverLogs,
		dial: func(t *testing.T) net.Conn {
			conn, dialErr := v2websocket.Dial(
				context.Background(),
				v2net.TCPDestination(v2net.LocalHostIP, v2net.Port(port)),
				&internet.MemoryStreamConfig{ProtocolName: "websocket", ProtocolSettings: &v2websocket.Config{Path: "/pqkem"}},
			)
			require.NoError(t, dialErr)
			return conn
		},
	}
}

type gunTestService struct {
	encoding.UnimplementedGunServiceServer
	serverLogs *pqkem.MemorySink
}

func (s *gunTestService) Tun(stream encoding.GunService_TunServer) error {
	ctx, cancel := context.WithCancel(stream.Context())
	defer cancel()
	raw := encoding.NewGunConn(stream, cancel, false)
	serverConn, _, err := pqkem.Server(ctx, raw, "grpc", pqkem.DefaultConfig().WithSink(s.serverLogs))
	if err != nil {
		return err
	}
	echo(serverConn)
	return nil
}

func newGRPCHarness(t *testing.T) transportHarness {
	t.Helper()
	serverLogs := new(pqkem.MemorySink)
	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	encoding.RegisterGunServiceServer(grpcServer, &gunTestService{serverLogs: serverLogs})
	serveErr := make(chan error, 1)
	go func() { serveErr <- grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
		select {
		case err := <-serveErr:
			if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				t.Logf("grpc serve: %v", err)
			}
		case <-time.After(time.Second):
		}
	})

	return transportHarness{
		name:       "grpc",
		serverLogs: serverLogs,
		dial: func(t *testing.T) net.Conn {
			clientConn, err := grpc.NewClient(
				"passthrough:///bufnet",
				grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
					return listener.Dial()
				}),
				grpc.WithTransportCredentials(insecure.NewCredentials()),
			)
			require.NoError(t, err)
			t.Cleanup(func() { _ = clientConn.Close() })

			streamCtx, cancel := context.WithCancel(context.Background())
			client, err := encoding.NewGunServiceClient(clientConn).Tun(streamCtx)
			require.NoError(t, err)
			return encoding.NewGunConn(client, cancel, false)
		},
	}
}

func echo(conn net.Conn) {
	_, _ = io.Copy(conn, conn)
	_ = conn.Close()
}

func TestConfigBoolShorthand(t *testing.T) {
	var enabled pqkem.Config
	require.NoError(t, enabled.UnmarshalJSON([]byte(`true`)))
	require.True(t, enabled.Enabled)
	require.Equal(t, pqkem.AlgorithmMLKEM768, pqkem.AlgorithmMLKEM768)

	var object pqkem.Config
	require.NoError(t, object.UnmarshalJSON([]byte(fmt.Sprintf(`{"enabled":true,"handshakeTimeout":"%s"}`, 2*time.Second))))
	require.True(t, object.Enabled)
	require.Equal(t, 2*time.Second, object.HandshakeTimeout)
}
