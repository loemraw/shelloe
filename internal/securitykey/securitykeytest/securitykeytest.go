// Package securitykeytest is a software security key for tests of code that signs through securitykey.
package securitykeytest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"

	"golang.org/x/crypto/ssh"

	"github.com/loemraw/shelloe/internal/securitykey"
)

// Authenticator is a software security key that answers like Chrome with a hardware security key.
type Authenticator struct {
	// Flags is the authenticator data's flags byte. New sets user present
	// and user verified (0x05), like a security key after its PIN and a touch.
	Flags byte

	privateKey *ecdsa.PrivateKey
	rpID       string
	origin     string

	mu      sync.Mutex
	counter uint32
}

// New returns an Authenticator holding a fresh P-256 key for the site rpID, used from origin.
func New(rpID, origin string) (*Authenticator, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Authenticator{
		Flags:      0x05,
		privateKey: privateKey,
		rpID:       rpID,
		origin:     origin,
	}, nil
}

// AuthorizedKey returns the key as an authorized_keys line of type spelling, ending in comment unless it's "".
func (a *Authenticator) AuthorizedKey(spelling string, comment string) []byte {
	point, err := a.privateKey.PublicKey.Bytes()
	if err != nil {
		panic(err) // can't happen for a key from ecdsa.GenerateKey
	}
	blob := ssh.Marshal(struct {
		Type        string
		Curve       string
		Point       []byte
		Application string
	}{spelling, "nistp256", point, a.rpID})
	line := spelling + " " + base64.StdEncoding.EncodeToString(blob)
	if comment != "" {
		line += " " + comment
	}
	return []byte(line + "\n")
}

// Get signs challenge for rpID like navigator.credentials.get; use a.Get as a securitykey.Authenticator.
func (a *Authenticator) Get(rpID string, challenge []byte) (*securitykey.Assertion, error) {
	if rpID != a.rpID {
		return nil, fmt.Errorf("securitykeytest: no credential for the site %q", rpID)
	}
	a.mu.Lock()
	a.counter++
	counter := a.counter
	a.mu.Unlock()

	// Chrome writes the challenge as is and JSON-escapes the origin.
	origin, err := json.Marshal(a.origin)
	if err != nil {
		return nil, err
	}
	clientDataJSON := []byte(`{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString(challenge) +
		`","origin":` + string(origin) + `,"crossOrigin":false}`)

	rpIDHash := sha256.Sum256([]byte(rpID))
	authenticatorData := make([]byte, 0, 37)
	authenticatorData = append(authenticatorData, rpIDHash[:]...)
	authenticatorData = append(authenticatorData, a.Flags)
	authenticatorData = binary.BigEndian.AppendUint32(authenticatorData, counter)

	clientDataHash := sha256.Sum256(clientDataJSON)
	digest := sha256.Sum256(append(bytes.Clone(authenticatorData), clientDataHash[:]...))
	signature, err := ecdsa.SignASN1(rand.Reader, a.privateKey, digest[:])
	if err != nil {
		return nil, err
	}
	return &securitykey.Assertion{
		AuthenticatorData: authenticatorData,
		ClientDataJSON:    clientDataJSON,
		Signature:         signature,
	}, nil
}
