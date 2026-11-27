package e2e_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// fakeServer is an SSH server in the test process. It lets anyone in without
// a signature and hands each session to the test once its shell or command
// has started.
type fakeServer struct {
	addr     string
	hostKey  ssh.PublicKey
	sessions chan *fakeSession
}

func startFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	_, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	server := &fakeServer{
		addr:     listener.Addr().String(),
		hostKey:  hostSigner.PublicKey(),
		sessions: make(chan *fakeSession, 8),
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go server.serve(conn, config)
		}
	}()
	return server
}

func (server *fakeServer) serve(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	serverConn, channels, requests, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(requests)
	for newChannel := range channels {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "the fake server only has sessions")
			continue
		}
		channel, channelRequests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		s := &fakeSession{conn: serverConn, channel: channel}
		go s.readInput()
		go s.answer(channelRequests, server.sessions)
	}
}

// nextSession returns the next session whose shell or command has started.
func (server *fakeServer) nextSession(t *testing.T) *fakeSession {
	t.Helper()
	select {
	case s := <-server.sessions:
		return s
	case <-time.After(timeout):
		t.Fatalf("no session started within %v", timeout)
		return nil
	}
}

// fakeSession is a session channel of the fake server.
type fakeSession struct {
	conn    *ssh.ServerConn
	channel ssh.Channel

	mu             sync.Mutex
	input          []byte // everything the client has sent
	cols, rows     int    // pty-req's size, then the latest window-change's
	agentRequested bool
}

// answer answers the session's requests, and hands the session to sessions
// once its shell or command has started.
func (s *fakeSession) answer(requests <-chan *ssh.Request, sessions chan<- *fakeSession) {
	for request := range requests {
		switch request.Type {
		case "pty-req":
			var pty struct {
				Term                      string
				Cols, Rows, Width, Height uint32
				Modes                     string
			}
			ssh.Unmarshal(request.Payload, &pty)
			s.setSize(pty.Cols, pty.Rows)
			request.Reply(true, nil)
		case "window-change":
			var size struct{ Cols, Rows, Width, Height uint32 }
			ssh.Unmarshal(request.Payload, &size)
			s.setSize(size.Cols, size.Rows)
			request.Reply(true, nil)
		case "auth-agent-req@openssh.com":
			s.mu.Lock()
			s.agentRequested = true
			s.mu.Unlock()
			request.Reply(true, nil)
		case "env":
			request.Reply(true, nil)
		case "shell", "exec":
			request.Reply(true, nil)
			sessions <- s
		default:
			request.Reply(false, nil)
		}
	}
}

func (s *fakeSession) setSize(cols, rows uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cols, s.rows = int(cols), int(rows)
}

func (s *fakeSession) readInput() {
	buffer := make([]byte, 4096)
	for {
		n, err := s.channel.Read(buffer)
		s.mu.Lock()
		s.input = append(s.input, buffer[:n]...)
		s.mu.Unlock()
		if err != nil {
			return
		}
	}
}

// Write sends p to the client as the session's output.
func (s *fakeSession) Write(p []byte) (int, error) { return s.channel.Write(p) }

// Exit ends the session with status.
func (s *fakeSession) Exit(status uint32) {
	s.channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
	s.channel.Close()
}

// waitForInput waits until what the client has sent contains want, and returns all of it.
func (s *fakeSession) waitForInput(t *testing.T, want []byte) []byte {
	t.Helper()
	var input []byte
	if !poll(func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		input = bytes.Clone(s.input)
		return bytes.Contains(input, want)
	}) {
		t.Fatalf("the server didn't receive %q within %v; it received %q", want, timeout, input)
	}
	return input
}

// size returns pty-req's size, or the latest window-change's.
func (s *fakeSession) size() (cols, rows int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cols, s.rows
}

// waitForSize waits until the session's size satisfies ok, and returns it.
func (s *fakeSession) waitForSize(t *testing.T, ok func(cols, rows int) bool) (cols, rows int) {
	t.Helper()
	if !poll(func() bool {
		cols, rows = s.size()
		return ok(cols, rows)
	}) {
		t.Fatalf("the size didn't change as expected within %v; it's %d columns by %d rows", timeout, cols, rows)
	}
	return cols, rows
}

// AgentSign asks the forwarded agent to sign data with its first key, as a
// program on the server would. The client checks each assertion against the
// configured key before it returns a signature, so a signature means the
// browser signed with that key.
func (s *fakeSession) AgentSign(data []byte) (*ssh.Signature, error) {
	s.mu.Lock()
	agentRequested := s.agentRequested
	s.mu.Unlock()
	if !agentRequested {
		return nil, errors.New("the client didn't ask to forward the agent")
	}
	channel, requests, err := s.conn.OpenChannel("auth-agent@openssh.com", nil)
	if err != nil {
		return nil, err
	}
	defer channel.Close()
	go ssh.DiscardRequests(requests)

	client := agent.NewClient(channel)
	keys, err := client.List()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("the agent has no keys")
	}
	return client.Sign(keys[0], data)
}
