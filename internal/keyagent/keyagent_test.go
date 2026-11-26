package keyagent_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/loemraw/shelloe/internal/keyagent"
	"github.com/loemraw/shelloe/internal/securitykey"
	"github.com/loemraw/shelloe/internal/securitykey/securitykeytest"
)

const (
	rpID          = "shell.example.com"
	origin        = "https://shell.example.com"
	canonicalType = "sk-ecdsa-sha2-nistp256@openssh.com"
)

func newKey(t *testing.T) (*securitykeytest.Authenticator, *securitykey.Key) {
	t.Helper()
	fake, err := securitykeytest.New(rpID, origin)
	if err != nil {
		t.Fatalf("securitykeytest.New: %v", err)
	}
	key, err := securitykey.ParseKey(fake.AuthorizedKey(canonicalType, ""))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	return fake, key
}

func TestListShowsTheOneKey(t *testing.T) {
	fake, key := newKey(t)
	keyAgent := keyagent.New(key.Signer(fake.Get), "web-shell", nil)

	keys, err := keyAgent.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("List returned %d keys, want 1", len(keys))
	}
	if !bytes.Equal(keys[0].Blob, key.PublicKey().Marshal()) {
		t.Errorf("listed key = %x, want %x", keys[0].Blob, key.PublicKey().Marshal())
	}
	if keys[0].Format != canonicalType {
		t.Errorf("listed key format = %q, want %q", keys[0].Format, canonicalType)
	}
	if keys[0].Comment != "web-shell" {
		t.Errorf("listed key comment = %q, want %q", keys[0].Comment, "web-shell")
	}
}

func TestSignUsesTheKey(t *testing.T) {
	fake, key := newKey(t)
	keyAgent := keyagent.New(key.Signer(fake.Get), "", nil)

	signature, err := keyAgent.Sign(key.PublicKey(), []byte("data to sign"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if signature.Format != "webauthn-sk-ecdsa-sha2-nistp256@openssh.com" {
		t.Errorf("signature format = %q, want the webauthn one", signature.Format)
	}
	if _, err := keyAgent.SignWithFlags(key.PublicKey(), []byte("data to sign"), agent.SignatureFlagRsaSha512); err != nil {
		t.Errorf("SignWithFlags with an RSA flag: %v", err)
	}
}

func TestSignRefusesOtherKeys(t *testing.T) {
	fake, key := newKey(t)
	asked := false
	authenticator := func(rpID string, challenge []byte) (*securitykey.Assertion, error) {
		asked = true
		return fake.Get(rpID, challenge)
	}
	keyAgent := keyagent.New(key.Signer(authenticator), "", nil)
	_, otherKey := newKey(t)

	if _, err := keyAgent.Sign(otherKey.PublicKey(), []byte("data")); err == nil {
		t.Error("Sign with a key the agent doesn't hold succeeded")
	}
	if _, err := keyAgent.SignWithFlags(otherKey.PublicKey(), []byte("data"), 0); err == nil {
		t.Error("SignWithFlags with a key the agent doesn't hold succeeded")
	}
	if asked {
		t.Error("the agent asked the security key to sign for a key it doesn't hold")
	}
}

func TestAgentIsReadOnly(t *testing.T) {
	fake, key := newKey(t)
	keyAgent := keyagent.New(key.Signer(fake.Get), "", nil)
	_, otherPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	changes := map[string]error{
		"Add":       keyAgent.Add(agent.AddedKey{PrivateKey: otherPrivateKey}),
		"Remove":    keyAgent.Remove(key.PublicKey()),
		"RemoveAll": keyAgent.RemoveAll(),
		"Lock":      keyAgent.Lock([]byte("passphrase")),
		"Unlock":    keyAgent.Unlock([]byte("passphrase")),
	}
	for method, err := range changes {
		if err == nil {
			t.Errorf("%s succeeded, want an error", method)
		}
	}
	if keys, err := keyAgent.List(); err != nil || len(keys) != 1 {
		t.Errorf("after the changes List = %d keys, %v; want the one key", len(keys), err)
	}

	if _, err := keyAgent.Extension("session-bind@openssh.com", nil); !errors.Is(err, agent.ErrExtensionUnsupported) {
		t.Errorf("Extension error = %v, want ErrExtensionUnsupported", err)
	}

	signers, err := keyAgent.Signers()
	if err != nil {
		t.Fatalf("Signers: %v", err)
	}
	if len(signers) != 1 || !bytes.Equal(signers[0].PublicKey().Marshal(), key.PublicKey().Marshal()) {
		t.Errorf("Signers = %v, want the one signer", signers)
	}
}

func TestNotifyAroundEachSignature(t *testing.T) {
	fake, key := newKey(t)
	var events []bool
	failNext := false
	authenticator := func(rpID string, challenge []byte) (*securitykey.Assertion, error) {
		if len(events) == 0 || !events[len(events)-1] {
			t.Error("the agent asked the security key before notify(true)")
		}
		if failNext {
			return nil, errors.New("NotAllowedError: the request was cancelled")
		}
		return fake.Get(rpID, challenge)
	}
	keyAgent := keyagent.New(key.Signer(authenticator), "", func(signing bool) {
		events = append(events, signing)
	})

	if _, err := keyAgent.Sign(key.PublicKey(), []byte("data")); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if want := []bool{true, false}; !slices.Equal(events, want) {
		t.Errorf("notify calls = %v, want %v", events, want)
	}

	failNext = true
	if _, err := keyAgent.Sign(key.PublicKey(), []byte("data")); err == nil {
		t.Fatal("Sign succeeded though the security key refused")
	}
	if want := []bool{true, false, true, false}; !slices.Equal(events, want) {
		t.Errorf("notify calls after a refused signature = %v, want %v", events, want)
	}

	failNext = false
	signers, err := keyAgent.Signers()
	if err != nil {
		t.Fatalf("Signers: %v", err)
	}
	if _, err := signers[0].Sign(rand.Reader, []byte("data")); err != nil {
		t.Fatalf("Sign through Signers: %v", err)
	}
	if want := []bool{true, false, true, false, true, false}; !slices.Equal(events, want) {
		t.Errorf("notify calls after signing through Signers = %v, want %v", events, want)
	}
}

func TestSignsOneAtATime(t *testing.T) {
	fake, key := newKey(t)
	var inFlight atomic.Int32
	var overlapped atomic.Bool
	authenticator := func(rpID string, challenge []byte) (*securitykey.Assertion, error) {
		if inFlight.Add(1) > 1 {
			overlapped.Store(true)
		}
		defer inFlight.Add(-1)
		time.Sleep(20 * time.Millisecond)
		return fake.Get(rpID, challenge)
	}
	var eventsMu sync.Mutex
	var events []bool
	keyAgent := keyagent.New(key.Signer(authenticator), "", func(signing bool) {
		eventsMu.Lock()
		defer eventsMu.Unlock()
		events = append(events, signing)
	})

	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			if _, err := keyAgent.Sign(key.PublicKey(), []byte("data")); err != nil {
				t.Errorf("Sign: %v", err)
			}
		})
	}
	wg.Wait()

	if overlapped.Load() {
		t.Error("two signatures reached the security key at once")
	}
	for i, signing := range events {
		if want := i%2 == 0; signing != want {
			t.Errorf("notify calls = %v, want true and false alternating", events)
			break
		}
	}
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

// serveAgent serves keyAgent on a unix socket and returns the socket's path.
func serveAgent(t *testing.T, keyAgent agent.Agent) string {
	t.Helper()
	// macOS limits unix socket paths to 104 bytes, which t.TempDir() can pass.
	dir, err := os.MkdirTemp("", "sa")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "agent.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				agent.ServeAgent(keyAgent, conn)
			}()
		}
	}()
	return socketPath
}

func TestOpenSSHSignsThroughTheAgent(t *testing.T) {
	sshKeygen := findSSHKeygen(t)
	fake, key := newKey(t)
	socketPath := serveAgent(t, keyagent.New(key.Signer(fake.Get), "web-shell", nil))

	dir := t.TempDir()
	authorizedKey := ssh.MarshalAuthorizedKey(key.PublicKey())
	publicKeyPath := filepath.Join(dir, "web-shell.pub")
	if err := os.WriteFile(publicKeyPath, authorizedKey, 0o600); err != nil {
		t.Fatal(err)
	}
	allowedSignersPath := filepath.Join(dir, "allowed_signers")
	allowedSigners := append([]byte(`web-shell namespaces="git" `), authorizedKey...)
	if err := os.WriteFile(allowedSignersPath, allowedSigners, 0o600); err != nil {
		t.Fatal(err)
	}
	message := []byte("tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\na commit to sign\n")
	messagePath := filepath.Join(dir, "commit")
	if err := os.WriteFile(messagePath, message, 0o600); err != nil {
		t.Fatal(err)
	}

	// What git runs for a key:: signing key.
	sign := exec.Command(sshKeygen, "-Y", "sign", "-U", "-f", publicKeyPath, "-n", "git", messagePath)
	sign.Env = append(os.Environ(), "SSH_AUTH_SOCK="+socketPath)
	if output, err := sign.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v\n%s", err, output)
	}

	verify := func(message []byte) ([]byte, error) {
		cmd := exec.Command(sshKeygen, "-Y", "verify", "-f", allowedSignersPath, "-I", "web-shell", "-n", "git", "-s", messagePath+".sig")
		cmd.Stdin = bytes.NewReader(message)
		return cmd.CombinedOutput()
	}
	if output, err := verify(message); err != nil {
		t.Fatalf("ssh-keygen -Y verify: %v\n%s", err, output)
	}
	tampered := bytes.Replace(message, []byte("a commit"), []byte("another commit"), 1)
	if output, err := verify(tampered); err == nil {
		t.Fatalf("ssh-keygen -Y verify accepted the signature for a changed message:\n%s", output)
	}
}
