// Package sshdtest runs OpenSSH's sshd for tests.
package sshdtest

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Server is an sshd started by Start.
type Server struct {
	Addr    string        // 127.0.0.1:port
	HostKey ssh.PublicKey // its ed25519 host key

	log *lockedBuffer
}

// Start runs sshd on 127.0.0.1, letting in authorizedKeys, and stops it when
// the test ends. It skips the test unless SHELLOE_SSHD names an sshd binary
// that can run unprivileged.
func Start(t *testing.T, authorizedKeys []byte) *Server {
	t.Helper()
	sshd := os.Getenv("SHELLOE_SSHD")
	if sshd == "" {
		t.Skip("set SHELLOE_SSHD to an sshd that can run unprivileged to run this test")
	}
	dir := t.TempDir()

	hostPublicKey, hostPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ssh.NewPublicKey(hostPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	hostKeyPEM, err := ssh.MarshalPrivateKey(hostPrivateKey, "")
	if err != nil {
		t.Fatal(err)
	}
	hostKeyPath := filepath.Join(dir, "ssh_host_ed25519_key")
	if err := os.WriteFile(hostKeyPath, pem.EncodeToMemory(hostKeyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	authorizedKeysPath := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(authorizedKeysPath, authorizedKeys, 0o600); err != nil {
		t.Fatal(err)
	}

	server := &Server{Addr: freeAddress(t), HostKey: hostKey, log: new(lockedBuffer)}
	config := fmt.Sprintf(`ListenAddress %s
HostKey %s
AuthorizedKeysFile %s
PidFile none
StrictModes no
LogLevel DEBUG1
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAcceptedAlgorithms +webauthn-sk-ecdsa-sha2-nistp256@openssh.com
PubkeyAuthOptions verify-required
HostKeyAlgorithms ssh-ed25519
`, server.Addr, hostKeyPath, authorizedKeysPath)
	configPath := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(sshd, "-D", "-e", "-f", configPath)
	cmd.Stdout = server.log
	cmd.Stderr = server.log
	// sshd's session processes hold its stderr; don't wait for them forever.
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting sshd: %v", err)
	}
	exited := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-exited
		t.Logf("sshd log:\n%s", server.log.String())
	})

	deadline := time.Now().Add(10 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", server.Addr, time.Second)
		if err == nil {
			conn.Close()
			return server
		}
		if time.Now().After(deadline) {
			t.Fatalf("sshd didn't accept connections on %s within 10 seconds: %v", server.Addr, err)
		}
		select {
		case <-exited:
			t.Fatalf("sshd exited before accepting connections: %v", waitErr)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Log returns what sshd has logged so far.
func (s *Server) Log() string { return s.log.String() }

// freeAddress returns a 127.0.0.1 address whose port nothing listens on.
func freeAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().String()
}

// lockedBuffer is a bytes.Buffer that sshd's output can go to while a test reads it.
type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}
