// Package keyagent is a read-only SSH agent holding one key, for forwarding
// over SSH so that programs on the other end, like git, can sign with it.
package keyagent

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"sync"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

var errReadOnly = errors.New("keyagent: the agent is read-only; it only signs with its one key")

type keyAgent struct {
	signer  ssh.Signer
	comment string
	notify  func(signing bool)

	signing sync.Mutex
}

// New returns an agent that lists signer's key with comment and signs with it, calling notify (if not nil) around each signature.
func New(signer ssh.Signer, comment string, notify func(signing bool)) agent.ExtendedAgent {
	return &keyAgent{signer: signer, comment: comment, notify: notify}
}

func (a *keyAgent) List() ([]*agent.Key, error) {
	publicKey := a.signer.PublicKey()
	return []*agent.Key{{
		Format:  publicKey.Type(),
		Blob:    publicKey.Marshal(),
		Comment: a.comment,
	}}, nil
}

func (a *keyAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags ignores flags: they only choose an RSA signature's hash.
func (a *keyAgent) SignWithFlags(key ssh.PublicKey, data []byte, _ agent.SignatureFlags) (*ssh.Signature, error) {
	if !bytes.Equal(key.Marshal(), a.signer.PublicKey().Marshal()) {
		return nil, errors.New("keyagent: the agent doesn't hold the requested key")
	}

	// One signature at a time: each is a WebAuthn request in the browser.
	a.signing.Lock()
	defer a.signing.Unlock()
	if a.notify != nil {
		a.notify(true)
		defer a.notify(false)
	}
	return a.signer.Sign(rand.Reader, data)
}

func (a *keyAgent) Add(agent.AddedKey) error { return errReadOnly }

func (a *keyAgent) Remove(ssh.PublicKey) error { return errReadOnly }

func (a *keyAgent) RemoveAll() error { return errReadOnly }

func (a *keyAgent) Lock([]byte) error { return errReadOnly }

func (a *keyAgent) Unlock([]byte) error { return errReadOnly }

// Signers returns the key behind the agent's lock and notify, like Sign.
func (a *keyAgent) Signers() ([]ssh.Signer, error) {
	return []ssh.Signer{agentSigner{a}}, nil
}

type agentSigner struct{ agent *keyAgent }

func (s agentSigner) PublicKey() ssh.PublicKey { return s.agent.signer.PublicKey() }

func (s agentSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.agent.Sign(s.PublicKey(), data)
}

func (a *keyAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
