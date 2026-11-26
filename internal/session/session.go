// Package session logs in to an SSH server with a security key and runs a shell on a pty, forwarding an agent that signs with the same key.
package session

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/loemraw/shelloe/internal/keyagent"
	"github.com/loemraw/shelloe/internal/securitykey"
)

// Config says how to log in and what to run.
type Config struct {
	User    string
	HostKey ssh.PublicKey // the only host key accepted
	Key     *securitykey.Key
	// Authenticator makes the security key's signatures, for the login and for the forwarded agent.
	// If the session ends during a signature for the forwarded agent, that signature waits until
	// Authenticator returns, so Authenticator should give up when the session ends.
	Authenticator securitykey.Authenticator
	// Command runs instead of the login shell when not empty.
	Command    string
	Term       string // TERM for the pty; "xterm-256color" when empty
	Cols, Rows int
	// Notify, if not nil, is called with true before the forwarded agent asks
	// the security key for a signature and with false after.
	Notify func(signing bool)
}

// check returns an error if cfg lacks something Start needs.
func (cfg *Config) check() error {
	switch {
	case cfg.User == "":
		return errors.New("session: no User to log in as")
	case cfg.HostKey == nil:
		return errors.New("session: no HostKey to accept")
	case cfg.Key == nil:
		return errors.New("session: no Key to log in with")
	case cfg.Authenticator == nil:
		return errors.New("session: no Authenticator to sign with the Key")
	case cfg.Cols <= 0 || cfg.Rows <= 0:
		return fmt.Errorf("session: the terminal is %d columns by %d rows; both must be at least 1", cfg.Cols, cfg.Rows)
	}
	return nil
}

// Session is a logged-in shell or command on a pty.
type Session struct {
	client  *ssh.Client
	session *ssh.Session
	input   io.WriteCloser
	output  *io.PipeReader

	done chan struct{}
	err  error // session.Wait's result, set before done is closed

	closeOnce sync.Once
}

// Start logs in over conn and starts the command, or the login shell, on a pty.
// If the server refuses to forward the agent, the session runs without it:
// the shell works, but programs on the server can't sign with the key.
func Start(conn net.Conn, cfg Config) (*Session, error) {
	if err := cfg.check(); err != nil {
		return nil, err
	}
	signer := cfg.Key.Signer(cfg.Authenticator)
	config := &ssh.ClientConfig{
		Config: ssh.Config{
			// ChaCha20 comes first: WebAssembly has no AES instructions, so it's the fastest cipher there.
			Ciphers: []string{
				ssh.CipherChaCha20Poly1305,
				ssh.CipherAES128GCM,
				ssh.CipherAES256GCM,
				ssh.CipherAES128CTR,
				ssh.CipherAES192CTR,
				ssh.CipherAES256CTR,
			},
		},
		User:              cfg.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback:   ssh.FixedHostKey(cfg.HostKey),
		HostKeyAlgorithms: hostKeyAlgorithms(cfg.HostKey),
	}
	sshConn, channels, requests, err := ssh.NewClientConn(conn, "server", config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("session: logging in: %w", err)
	}
	client := ssh.NewClient(sshConn, channels, requests)

	s, err := start(client, signer, cfg)
	if err != nil {
		client.Close()
		return nil, err
	}
	return s, nil
}

// hostKeyAlgorithms returns the host key algorithms that make the server
// present key: for an RSA key, its SHA-2 signature algorithms.
func hostKeyAlgorithms(key ssh.PublicKey) []string {
	if key.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{key.Type()}
}

// start does Start's work after the login; the caller closes client if it fails.
func start(client *ssh.Client, signer ssh.Signer, cfg Config) (*Session, error) {
	if err := agent.ForwardToAgent(client, keyagent.New(signer, cfg.Key.Comment(), cfg.Notify)); err != nil {
		return nil, fmt.Errorf("session: serving the agent: %w", err)
	}
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("session: opening a session: %w", err)
	}
	// A refusal leaves the session without the agent; see Start.
	agent.RequestAgentForwarding(session)

	term := cfg.Term
	if term == "" {
		term = "xterm-256color"
	}
	if err := session.RequestPty(term, cfg.Rows, cfg.Cols, ssh.TerminalModes{ssh.ECHO: 1, ssh.IUTF8: 1}); err != nil {
		return nil, fmt.Errorf("session: requesting a pty: %w", err)
	}
	output, outputWriter := io.Pipe()
	session.Stdout = outputWriter
	session.Stderr = outputWriter
	input, err := session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("session: connecting the pty's input: %w", err)
	}
	if cfg.Command == "" {
		if err := session.Shell(); err != nil {
			return nil, fmt.Errorf("session: starting the login shell: %w", err)
		}
	} else if err := session.Start(cfg.Command); err != nil {
		return nil, fmt.Errorf("session: starting the command: %w", err)
	}

	s := &Session{
		client:  client,
		session: session,
		input:   input,
		output:  output,
		done:    make(chan struct{}),
	}
	go func() {
		s.err = session.Wait()
		outputWriter.Close()
		client.Close()
		close(s.done)
	}()
	return s, nil
}

// Read reads the pty's output, unchanged. It returns io.EOF once the command
// has exited and all its output has been read.
func (s *Session) Read(p []byte) (int, error) { return s.output.Read(p) }

// Write sends input to the pty.
func (s *Session) Write(p []byte) (int, error) { return s.input.Write(p) }

// Resize tells the server the terminal's new size.
func (s *Session) Resize(cols, rows int) error { return s.session.WindowChange(rows, cols) }

// Wait waits for the command to exit and returns nil for status 0, or the
// *ssh.ExitError. The output must be read until EOF for it to return. It may
// be called more than once, from any goroutine, and always returns the same.
func (s *Session) Wait() error {
	<-s.done
	return s.err
}

// Close ends the session and the connection. It may be called more than once, and after the session has ended.
func (s *Session) Close() error {
	s.closeOnce.Do(func() {
		// The connection first: a Write stuck on a stalled connection holds the channel's lock until it closes.
		s.client.Close()
		// Output nobody reads would otherwise keep the session from ending.
		s.output.Close()
	})
	return nil
}
