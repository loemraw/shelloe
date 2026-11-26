package session_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/loemraw/shelloe/internal/securitykey"
	"github.com/loemraw/shelloe/internal/securitykey/securitykeytest"
	"github.com/loemraw/shelloe/internal/session"
	"github.com/loemraw/shelloe/internal/sshdtest"
)

const (
	rpID   = "shell.example.com"
	origin = "https://shell.example.com"

	timeout = 10 * time.Second
)

// login is an sshd that lets in a fake security key, and a Config that logs in with it.
type login struct {
	server *sshdtest.Server
	config session.Config
	// signatures counts the signatures asked of the security key.
	signatures atomic.Int32
}

// setUp starts sshd for a fake security key and returns a Config that logs
// in with it as the current user, on an 80x24 terminal.
func setUp(t *testing.T) *login {
	t.Helper()
	fake, err := securitykeytest.New(rpID, origin)
	if err != nil {
		t.Fatalf("securitykeytest.New: %v", err)
	}
	// authorized_keys may spell the key type as its signature format.
	server := sshdtest.Start(t, fake.AuthorizedKey("webauthn-sk-ecdsa-sha2-nistp256@openssh.com", ""))
	key, err := securitykey.ParseKey(fake.AuthorizedKey("sk-ecdsa-sha2-nistp256@openssh.com", "shelloe-test"))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	osUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}

	l := &login{server: server}
	l.config = session.Config{
		User:    osUser.Username,
		HostKey: server.HostKey,
		Key:     key,
		Authenticator: func(rpID string, challenge []byte) (*securitykey.Assertion, error) {
			l.signatures.Add(1)
			return fake.Get(rpID, challenge)
		},
		Cols: 80,
		Rows: 24,
	}
	return l
}

// dial connects to the test's sshd.
func (l *login) dial(t *testing.T) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", l.server.Addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

// start logs in with config and closes the session when the test ends.
func (l *login) start(t *testing.T, config session.Config) *session.Session {
	t.Helper()
	s, err := session.Start(l.dial(t), config)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// read reads r until want appears in what it has read or, if want is "",
// until EOF, and returns all it read. It gives up after timeout, or when the
// test ends, with the context's error.
func read(t *testing.T, r io.Reader, want string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	var mu sync.Mutex
	var output []byte
	finished := make(chan error, 1)
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, err := r.Read(buffer)
			mu.Lock()
			output = append(output, buffer[:n]...)
			found := want != "" && bytes.Contains(output, []byte(want))
			mu.Unlock()
			if found || (want == "" && err == io.EOF) {
				finished <- nil
				return
			}
			if err != nil {
				finished <- err
				return
			}
		}
	}()

	var err error
	select {
	case err = <-finished:
	case <-ctx.Done():
		err = ctx.Err()
	}
	mu.Lock()
	defer mu.Unlock()
	return string(output), err
}

// readUntil reads r until want appears and returns all it read.
func readUntil(t *testing.T, r io.Reader, want string) string {
	t.Helper()
	output, err := read(t, r, want)
	if err != nil {
		t.Fatalf("reading until %q: %v; read %q", want, err, output)
	}
	return output
}

// readToEOF reads r until EOF and returns all it read.
func readToEOF(t *testing.T, r io.Reader) string {
	t.Helper()
	output, err := read(t, r, "")
	if err != nil {
		t.Fatalf("reading until EOF: %v; read %q", err, output)
	}
	return output
}

// wait returns what s.Wait returns, failing the test if that takes longer than limit.
func wait(t *testing.T, s *session.Session, limit time.Duration) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), limit)
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- s.Wait() }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		t.Fatalf("Wait didn't return within %v", limit)
		return nil
	}
}

// write types input into s.
func write(t *testing.T, s *session.Session, input string) {
	t.Helper()
	if _, err := s.Write([]byte(input)); err != nil {
		t.Fatalf("Write(%q): %v", input, err)
	}
}

func TestSessionRunsTheLoginShellOnAPty(t *testing.T) {
	l := setUp(t)
	s := l.start(t, l.config)

	write(t, s, `echo "term=$TERM"; test -t 0 && echo "tty-$((1+1))"; exit`+"\r")
	output := readToEOF(t, s)
	for _, want := range []string{"term=xterm-256color", "tty-2"} {
		if !strings.Contains(output, want) {
			t.Errorf("the shell printed %q, want %q in it", output, want)
		}
	}
	if err := wait(t, s, timeout); err != nil {
		t.Errorf("Wait = %v, want nil", err)
	}
	if got := l.signatures.Load(); got != 1 {
		t.Errorf("the security key was asked for %d signatures, want 1 (the login)", got)
	}
}

func TestSessionRunsTheConfiguredCommand(t *testing.T) {
	l := setUp(t)
	config := l.config
	config.Command = "echo $((6*7)); exit 3"
	s := l.start(t, config)

	if output := readToEOF(t, s); !strings.Contains(output, "42") {
		t.Errorf("the command printed %q, want 42 in it", output)
	}
	err := wait(t, s, timeout)
	var exitError *ssh.ExitError
	if !errors.As(err, &exitError) || exitError.ExitStatus() != 3 {
		t.Errorf("Wait = %v, want exit status 3", err)
	}
}

func TestSessionPassesOutputThroughUnchanged(t *testing.T) {
	l := setUp(t)
	config := l.config
	config.Command = `printf 'a\nb\r\n\033[31mc'`
	s := l.start(t, config)

	// The pty turns each \n into \r\n.
	if output, want := readToEOF(t, s), "a\r\nb\r\r\n\x1b[31mc"; output != want {
		t.Errorf("output = %q, want %q", output, want)
	}
}

func TestSessionResizes(t *testing.T) {
	l := setUp(t)
	config := l.config
	config.Command = "stty size; read line; stty size"
	s := l.start(t, config)

	readUntil(t, s, "24 80")
	if err := s.Resize(100, 30); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	write(t, s, "\r")
	readUntil(t, s, "30 100")
}

// findSSHKeygen returns $SHELLOE_SSH_KEYGEN, or else ssh-keygen from PATH.
func findSSHKeygen(t *testing.T) string {
	t.Helper()
	if path := os.Getenv("SHELLOE_SSH_KEYGEN"); path != "" {
		return path
	}
	path, err := exec.LookPath("ssh-keygen")
	if err != nil {
		t.Fatalf("ssh-keygen not found; install OpenSSH or set SHELLOE_SSH_KEYGEN: %v", err)
	}
	return path
}

func TestSessionForwardsTheAgent(t *testing.T) {
	l := setUp(t)
	config := l.config
	var notifyMu sync.Mutex
	var notified []bool
	config.Notify = func(signing bool) {
		notifyMu.Lock()
		defer notifyMu.Unlock()
		notified = append(notified, signing)
	}

	// sshd runs on this machine as this user, so the command sees these files.
	dir := t.TempDir()
	publicKeyPath := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(publicKeyPath, ssh.MarshalAuthorizedKey(config.Key.PublicKey()), 0o600); err != nil {
		t.Fatal(err)
	}
	message := []byte("a message to sign\n")
	messagePath := filepath.Join(dir, "message")
	if err := os.WriteFile(messagePath, message, 0o600); err != nil {
		t.Fatal(err)
	}
	config.Command = fmt.Sprintf("ssh-add -L && ssh-keygen -Y sign -U -f '%s' -n test '%s'", publicKeyPath, messagePath)
	s := l.start(t, config)

	output := readToEOF(t, s)
	if err := wait(t, s, timeout); err != nil {
		t.Fatalf("the command failed: %v\n%s", err, output)
	}
	blob := base64.StdEncoding.EncodeToString(config.Key.PublicKey().Marshal())
	if !strings.Contains(output, blob) {
		t.Errorf("ssh-add -L on the server printed %q, want the key %s in it", output, blob)
	}

	check := exec.Command(findSSHKeygen(t), "-Y", "check-novalidate", "-n", "test", "-s", messagePath+".sig")
	check.Stdin = bytes.NewReader(message)
	if checkOutput, err := check.CombinedOutput(); err != nil {
		t.Errorf("ssh-keygen -Y check-novalidate: %v\n%s", err, checkOutput)
	}

	notifyMu.Lock()
	defer notifyMu.Unlock()
	if want := []bool{true, false}; !slices.Equal(notified, want) {
		t.Errorf("Notify calls = %v, want %v", notified, want)
	}
	if got := l.signatures.Load(); got != 2 {
		t.Errorf("the security key was asked for %d signatures, want 2 (the login and the agent's)", got)
	}
}

func TestSessionRefusesAnotherHostKey(t *testing.T) {
	l := setUp(t)
	otherPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	config := l.config
	config.HostKey, err = ssh.NewPublicKey(otherPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	s, err := session.Start(l.dial(t), config)
	if err == nil {
		s.Close()
		t.Fatal("Start logged in to a server with another host key than the configured one")
	}
	if got := l.signatures.Load(); got != 0 {
		t.Errorf("the security key was asked for %d signatures, want none", got)
	}
}

func TestSessionPrefersChaCha20(t *testing.T) {
	l := setUp(t)
	config := l.config
	config.Command = "true"
	s := l.start(t, config)

	readToEOF(t, s)
	if err := wait(t, s, timeout); err != nil {
		t.Fatalf("Wait = %v, want nil", err)
	}
	// sshd's log reaches the buffer through a pipe, so it can lag behind.
	const want = "cipher: chacha20-poly1305@openssh.com"
	deadline := time.Now().Add(timeout)
	for !strings.Contains(l.server.Log(), want) {
		if time.Now().After(deadline) {
			t.Fatalf("sshd's log doesn't have %q", want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestSessionCloseEndsIt(t *testing.T) {
	l := setUp(t)
	config := l.config
	config.Command = "yes"
	s := l.start(t, config)

	s.Close()
	wait(t, s, 5*time.Second)
	if err := s.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
}

func TestStartRefusesIncompleteConfig(t *testing.T) {
	fake, err := securitykeytest.New(rpID, origin)
	if err != nil {
		t.Fatalf("securitykeytest.New: %v", err)
	}
	key, err := securitykey.ParseKey(fake.AuthorizedKey("sk-ecdsa-sha2-nistp256@openssh.com", ""))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	hostPublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewPublicKey(hostPublicKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		change func(*session.Config)
	}{
		{"no user", func(c *session.Config) { c.User = "" }},
		{"no host key", func(c *session.Config) { c.HostKey = nil }},
		{"no key", func(c *session.Config) { c.Key = nil }},
		{"no authenticator", func(c *session.Config) { c.Authenticator = nil }},
		{"no columns", func(c *session.Config) { c.Cols = 0 }},
		{"no rows", func(c *session.Config) { c.Rows = 0 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := session.Config{
				User:          "someone",
				HostKey:       hostKey,
				Key:           key,
				Authenticator: fake.Get,
				Cols:          80,
				Rows:          24,
			}
			test.change(&config)

			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			written := make(chan []byte, 1)
			go func() {
				peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				buffer := make([]byte, 256)
				n, _ := peer.Read(buffer)
				// Ends a Start that wrote and now waits for the server's answer.
				peer.Close()
				written <- buffer[:n]
			}()

			s, err := session.Start(conn, config)
			if err == nil {
				s.Close()
				t.Fatal("Start succeeded, want an error")
			}
			if !strings.HasPrefix(err.Error(), "session: ") {
				t.Errorf("Start error = %q, want it to start with \"session: \"", err)
			}
			if got := <-written; len(got) != 0 {
				t.Errorf("Start wrote %q to the connection before refusing the config", got)
			}
		})
	}
}
