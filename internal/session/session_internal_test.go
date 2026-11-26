package session

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/loemraw/shelloe/internal/securitykey"
	"github.com/loemraw/shelloe/internal/securitykey/securitykeytest"
)

// testServer is an SSH server in the test process that lets in any password.
type testServer struct {
	addr     string
	hostKey  ssh.PublicKey
	stalled  chan struct{} // closed by stopReading
	released chan struct{} // closed when the test ends, if stalled
}

func startTestServer(t *testing.T) *testServer {
	t.Helper()
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil },
	}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	server := &testServer{
		addr:     listener.Addr().String(),
		hostKey:  hostSigner.PublicKey(),
		stalled:  make(chan struct{}),
		released: make(chan struct{}),
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.serve(stallingConn{conn, server}, config)
		}
	}()
	return server
}

// stopReading makes the server stop reading its connections until the test ends.
func (server *testServer) stopReading(t *testing.T) {
	close(server.stalled)
	t.Cleanup(func() { close(server.released) })
}

// stallingConn is the server's end of a connection, which stops reading while the server is stalled.
type stallingConn struct {
	net.Conn
	server *testServer
}

func (c stallingConn) Read(p []byte) (int, error) {
	select {
	case <-c.server.stalled:
		<-c.server.released
	default:
	}
	return c.Conn.Read(p)
}

func (server *testServer) serve(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	_, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go runSession(channel, channelRequests)
	}
}

// runSession answers a session's requests. Its login shell reads input and
// ignores it. It knows two commands: "exit" prints a line and exits with
// status 0, and "flood" prints until the session ends.
func runSession(channel ssh.Channel, requests <-chan *ssh.Request) {
	for request := range requests {
		switch request.Type {
		case "pty-req":
			request.Reply(true, nil)
		case "shell":
			request.Reply(true, nil)
			go func() {
				io.Copy(io.Discard, channel)
				channel.Close()
			}()
		case "exec":
			var exec struct{ Command string }
			ssh.Unmarshal(request.Payload, &exec)
			request.Reply(true, nil)
			go runCommand(channel, exec.Command)
		default:
			request.Reply(false, nil)
		}
	}
}

func runCommand(channel ssh.Channel, command string) {
	defer channel.Close()
	switch command {
	case "exit":
		io.WriteString(channel, "done\r\n")
		channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	case "flood":
		output := bytes.Repeat([]byte("y\r\n"), 10000)
		for {
			if _, err := channel.Write(output); err != nil {
				return
			}
		}
	}
}

// startSession logs in to server with a password, which x/crypto's server can
// check unlike a security key's signature, and then does what Start does.
func startSession(t *testing.T, server *testServer, command string) *Session {
	t.Helper()
	fake, err := securitykeytest.New("shell.example.com", "https://shell.example.com")
	if err != nil {
		t.Fatalf("securitykeytest.New: %v", err)
	}
	key, err := securitykey.ParseKey(fake.AuthorizedKey("sk-ecdsa-sha2-nistp256@openssh.com", ""))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	conn, err := net.Dial("tcp", server.addr)
	if err != nil {
		t.Fatal(err)
	}
	sshConn, channels, requests, err := ssh.NewClientConn(conn, "server", &ssh.ClientConfig{
		User:            "someone",
		Auth:            []ssh.AuthMethod{ssh.Password("password")},
		HostKeyCallback: ssh.FixedHostKey(server.hostKey),
	})
	if err != nil {
		t.Fatalf("logging in: %v", err)
	}
	client := ssh.NewClient(sshConn, channels, requests)

	s, err := start(client, key.Signer(fake.Get), Config{Key: key, Command: command, Cols: 80, Rows: 24})
	if err != nil {
		client.Close()
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// within fails the test unless f returns within limit.
func within(t *testing.T, limit time.Duration, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
	case <-time.After(limit):
		t.Fatalf("%s didn't return within %v", what, limit)
	}
}

func TestCloseReturnsWhileAWriteIsStuck(t *testing.T) {
	server := startTestServer(t)
	s := startSession(t, server, "")
	server.stopReading(t)

	written := make(chan error, 1)
	go func() {
		_, err := s.Write(make([]byte, 4<<20))
		written <- err
	}()
	select {
	case err := <-written:
		t.Fatalf("a 4 MB Write returned %v though the server had stopped reading", err)
	case <-time.After(300 * time.Millisecond):
	}

	within(t, 2*time.Second, "Close", func() { s.Close() })
	select {
	case err := <-written:
		if err == nil {
			t.Error("the stuck Write succeeded after Close, want an error")
		}
	case <-time.After(2 * time.Second):
		t.Error("the stuck Write didn't return within 2s of Close")
	}
}

func TestCloseEndsASessionWithUnreadOutput(t *testing.T) {
	server := startTestServer(t)
	s := startSession(t, server, "flood")
	within(t, 2*time.Second, "reading the first byte", func() {
		if _, err := s.Read(make([]byte, 1)); err != nil {
			t.Errorf("Read: %v", err)
		}
	})

	s.Close()
	within(t, 2*time.Second, "Wait after Close", func() { s.Wait() })
}

func TestCloseReturnsNilAfterTheEndAndWhenRepeated(t *testing.T) {
	t.Run("after the end", func(t *testing.T) {
		server := startTestServer(t)
		s := startSession(t, server, "exit")
		within(t, 2*time.Second, "reading to EOF and Wait", func() {
			io.ReadAll(s)
			if err := s.Wait(); err != nil {
				t.Errorf("Wait = %v, want nil", err)
			}
		})
		if err := s.Close(); err != nil {
			t.Errorf("Close after the session ended = %v, want nil", err)
		}
	})

	t.Run("repeated", func(t *testing.T) {
		server := startTestServer(t)
		s := startSession(t, server, "")
		if err := s.Close(); err != nil {
			t.Errorf("Close on a live session = %v, want nil", err)
		}
		if err := s.Close(); err != nil {
			t.Errorf("second Close = %v, want nil", err)
		}
	})
}
