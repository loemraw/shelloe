package relay_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/loemraw/shelloe/internal/relay"
)

const origin = "https://shell.example.com"

// targetServer listens on localhost and calls serve for each connection,
// counting them in accepted.
func targetServer(t *testing.T, serve func(net.Conn)) (addr string, accepted *atomic.Int32) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	accepted = new(atomic.Int32)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer conn.Close()
				serve(conn)
			}()
		}
	}()
	return listener.Addr().String(), accepted
}

func echo(conn net.Conn) { io.Copy(conn, conn) }

func startRelay(t *testing.T, target string) *httptest.Server {
	t.Helper()
	handler, err := relay.Handler(target, origin)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/ws", handler)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func dial(ctx context.Context, server *httptest.Server, originHeader string) (*websocket.Conn, *http.Response, error) {
	header := http.Header{}
	if originHeader != "" {
		header.Set("Origin", originHeader)
	}
	return websocket.Dial(ctx, server.URL+"/ws", &websocket.DialOptions{HTTPHeader: header})
}

func connect(t *testing.T, ctx context.Context, server *httptest.Server) *websocket.Conn {
	t.Helper()
	conn, _, err := dial(ctx, server, origin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func TestRelayCarriesBytesBothWays(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	addr, _ := targetServer(t, echo)
	server := startRelay(t, addr)
	conn := connect(t, ctx, server)
	stream := websocket.NetConn(ctx, conn, websocket.MessageBinary)

	long := bytes.Repeat([]byte("0123456789abcdef"), 300*1024/16)
	for _, message := range [][]byte{[]byte("hello"), long} {
		go func() { stream.Write(message) }()
		got := make([]byte, len(message))
		if _, err := io.ReadFull(stream, got); err != nil {
			t.Fatalf("reading %d bytes back: %v", len(message), err)
		}
		if !bytes.Equal(got, message) {
			t.Errorf("a %d byte message came back different", len(message))
		}
	}
}

func TestRelayRefusesOtherOrigins(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	addr, accepted := targetServer(t, echo)
	server := startRelay(t, addr)

	tests := []struct{ name, origin string }{
		{"missing origin", ""},
		{"another host", "https://other.example.com"},
		{"http instead of https", "http://shell.example.com"},
		{"another port", "https://shell.example.com:8443"},
		{"look-alike host", origin + ".evil.example"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn, response, err := dial(ctx, server, test.origin)
			if err == nil {
				conn.CloseNow()
				t.Fatal("the connection was accepted")
			}
			if response == nil || response.StatusCode != http.StatusForbidden {
				t.Errorf("response = %v, want 403 (error: %v)", response, err)
			}
		})
	}
	if got := accepted.Load(); got != 0 {
		t.Errorf("the target accepted %d connections, want 0", got)
	}
}

func TestRelayAcceptsAnIPv6OriginOnAnotherHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	addr, _ := targetServer(t, echo)
	const ipv6Origin = "http://[fd00::1]:8080"
	handler, err := relay.Handler(addr, ipv6Origin)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	header := http.Header{"Origin": {ipv6Origin}}
	conn, _, err := websocket.Dial(ctx, server.URL, &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		t.Fatalf("connecting from %s to a relay on %s: %v", ipv6Origin, server.URL, err)
	}
	conn.CloseNow()
}

func TestRelayClosesWhenTargetIsUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	server := startRelay(t, addr)
	conn := connect(t, ctx, server)

	_, _, err = conn.Read(ctx)
	if got := websocket.CloseStatus(err); got != websocket.StatusTryAgainLater {
		t.Fatalf("close status = %v, want %v (error: %v)", got, websocket.StatusTryAgainLater, err)
	}
	var closeError websocket.CloseError
	if !errors.As(err, &closeError) {
		t.Fatalf("error %v isn't a close error", err)
	}
	if want := "can't reach the SSH server"; closeError.Reason != want {
		t.Errorf("close reason = %q, want %q", closeError.Reason, want)
	}
}

func TestRelayClosesTheTargetWhenTheBrowserLeaves(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result := make(chan error, 1)
	connected := make(chan struct{})
	addr, _ := targetServer(t, func(conn net.Conn) {
		close(connected)
		_, err := conn.Read(make([]byte, 1))
		result <- err
	})
	server := startRelay(t, addr)
	conn := connect(t, ctx, server)
	select {
	case <-connected:
	case <-ctx.Done():
		t.Fatal("the target never got a connection")
	}

	conn.Close(websocket.StatusNormalClosure, "")
	select {
	case err := <-result:
		if err == nil {
			t.Error("the target read data, want it closed")
		}
	case <-ctx.Done():
		t.Fatal("the target's connection stayed open")
	}
}

func TestRelayClosesTheBrowserWhenTheTargetLeaves(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	addr, _ := targetServer(t, func(conn net.Conn) {})
	server := startRelay(t, addr)
	conn := connect(t, ctx, server)

	_, _, err := conn.Read(ctx)
	if got := websocket.CloseStatus(err); got != websocket.StatusNormalClosure {
		t.Errorf("close status = %v, want %v (error: %v)", got, websocket.StatusNormalClosure, err)
	}
}

func TestRelayRefusesMessagesOverOneMiB(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	addr, _ := targetServer(t, echo)
	server := startRelay(t, addr)
	conn := connect(t, ctx, server)
	stream := websocket.NetConn(ctx, conn, websocket.MessageBinary)

	// Exactly at the limit: this one must pass.
	go func() { stream.Write(make([]byte, 1<<20)) }()
	if _, err := io.ReadFull(stream, make([]byte, 1<<20)); err != nil {
		t.Fatalf("a 1 MiB message: %v", err)
	}

	// The write may fail if the relay has already hung up on the oversized message.
	stream.Write(make([]byte, 1<<20+1))
	// The relay forwards the start of the message before it hits the limit,
	// so some of it may be echoed first.
	_, err := io.Copy(io.Discard, stream)
	if got := websocket.CloseStatus(err); got != websocket.StatusMessageTooBig {
		t.Errorf("close status = %v, want %v (error: %v)", got, websocket.StatusMessageTooBig, err)
	}
}

func TestRelayDeliversEverythingTheTargetSentBeforeHangingUp(t *testing.T) {
	const total = 8 << 20
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	pattern := make([]byte, total)
	for i := range pattern {
		pattern[i] = byte(i * 7)
	}
	addr, _ := targetServer(t, func(conn net.Conn) {
		drained := make(chan struct{})
		go func() { io.Copy(io.Discard, conn); close(drained) }()
		conn.Write(pattern)
		conn.(*net.TCPConn).CloseWrite()
		<-drained
	})
	server := startRelay(t, addr)
	conn := connect(t, ctx, server)
	stream := websocket.NetConn(ctx, conn, websocket.MessageBinary)

	// Unread data from the browser is what made the relay's close lose output.
	var stop atomic.Bool
	defer stop.Store(true)
	go func() {
		for !stop.Load() {
			if _, err := stream.Write(make([]byte, 64)); err != nil {
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()

	var got bytes.Buffer
	buf := make([]byte, 16<<10)
	var err error
	for err == nil {
		var n int
		n, err = stream.Read(buf)
		got.Write(buf[:n])
		time.Sleep(50 * time.Microsecond)
	}
	if !bytes.Equal(got.Bytes(), pattern) {
		t.Errorf("received %d of %d bytes, or different ones; then %v", got.Len(), total, err)
	}
	if err != io.EOF {
		t.Errorf("ended with %v, want a normal close (io.EOF)", err)
	}
}

func TestRelayAnswersPlainRequestsWithAnError(t *testing.T) {
	addr, accepted := targetServer(t, echo)
	server := startRelay(t, addr)

	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Origin", origin)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()

	if response.StatusCode < 400 {
		t.Errorf("status = %d, want an error", response.StatusCode)
	}
	if got := accepted.Load(); got != 0 {
		t.Errorf("the target accepted %d connections, want 0", got)
	}
}

func TestHandlerRefusesBadArguments(t *testing.T) {
	const goodTarget = "ssh.example.com:22"
	tests := []struct {
		name, target, origin string
	}{
		{"target without a port", "example.com", origin},
		{"target without a host", ":22", origin},
		{"target with an empty port", "example.com:", origin},
		{"empty target", "", origin},
		{"empty origin", goodTarget, ""},
		{"origin without a scheme", goodTarget, "shell.example.com"},
		{"origin with another scheme", goodTarget, "ftp://shell.example.com"},
		{"origin with a trailing slash", goodTarget, "https://shell.example.com/"},
		{"origin with a path", goodTarget, "https://shell.example.com/path"},
		{"origin with a query", goodTarget, "https://shell.example.com?x=1"},
		{"origin with user info", goodTarget, "https://user@shell.example.com"},
		{"origin with an empty fragment", goodTarget, "https://shell.example.com#"},
		{"origin with an empty port", goodTarget, "https://shell.example.com:"},
		{"origin with an uppercase scheme", goodTarget, "HTTPS://shell.example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := relay.Handler(test.target, test.origin); err == nil {
				t.Error("Handler returned no error")
			}
		})
	}

	t.Run("valid", func(t *testing.T) {
		if _, err := relay.Handler(goodTarget, origin); err != nil {
			t.Errorf("Handler returned %v", err)
		}
	})
}
