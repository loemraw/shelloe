// Package securitykey makes OpenSSH signatures with a FIDO security key that the
// browser reaches through WebAuthn, in OpenSSH's
// webauthn-sk-ecdsa-sha2-nistp256@openssh.com signature format (PROTOCOL.u2f).
package securitykey

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"golang.org/x/crypto/ssh"
)

const (
	keyType         = ssh.KeyAlgoSKECDSA256
	signatureFormat = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"

	// SSH Term writes its keys with the signature format as the key type,
	// and OpenSSH reads that spelling as the same key.
	sshTermKeyType = signatureFormat
)

// Bits of the authenticator data's flags byte.
const (
	flagUserPresent   = 0x01
	flagUserVerified  = 0x04
	flagAttestedData  = 0x40
	flagExtensionData = 0x80
)

// authenticatorDataLength is rpIdHash (32 bytes), flags (1) and counter (4):
// an assertion with no attested credential and no extensions.
const authenticatorDataLength = 37

// Assertion is what the browser's navigator.credentials.get returns.
type Assertion struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte // ASN.1 DER ECDSA signature
}

// Authenticator asks the security key, through the browser, to sign challenge for the site rpID.
type Authenticator func(rpID string, challenge []byte) (*Assertion, error)

// Key is the public half of a security key made in the browser for one site.
type Key struct {
	publicKey ssh.PublicKey
	ecdsaKey  *ecdsa.PublicKey
	rpID      string
	comment   string
}

// ParseKey parses an authorized_keys line, without options, holding an sk-ecdsa-sha2-nistp256@openssh.com key.
func ParseKey(authorizedKeyLine []byte) (*Key, error) {
	line := strings.TrimSpace(string(authorizedKeyLine))
	lineType, rest := cutField(line)
	encoded, comment := cutField(rest)
	if encoded == "" {
		return nil, errors.New(`securitykey: expected an authorized_keys line "<type> <base64 key> [comment]"`)
	}
	if lineType != keyType && lineType != sshTermKeyType {
		return nil, fmt.Errorf("securitykey: key type is %q, want %q", lineType, keyType)
	}
	blob, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("securitykey: the key is not valid base64: %v", err)
	}

	var fields struct {
		Type        string
		Curve       string
		Point       []byte
		Application string
		Trailing    []byte `ssh:"rest"`
	}
	if err := ssh.Unmarshal(blob, &fields); err != nil {
		return nil, fmt.Errorf("securitykey: can't decode the key: %v", err)
	}
	if fields.Type != lineType {
		return nil, fmt.Errorf("securitykey: the line's key type is %q but the key itself says %q", lineType, fields.Type)
	}
	if fields.Curve != "nistp256" {
		return nil, fmt.Errorf("securitykey: key curve is %q, want \"nistp256\"", fields.Curve)
	}
	ecdsaKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), fields.Point)
	if err != nil {
		return nil, fmt.Errorf("securitykey: the key is not a valid P-256 point: %v", err)
	}
	if fields.Application == "" {
		return nil, errors.New("securitykey: the key has no application (the site it was made for)")
	}
	if strings.HasPrefix(fields.Application, "ssh:") {
		return nil, fmt.Errorf("securitykey: the key's application is %q, so ssh-keygen made it on the security key; "+
			"a browser can't use such a key, so make one in the browser instead", fields.Application)
	}
	if len(fields.Trailing) != 0 {
		return nil, fmt.Errorf("securitykey: the key has %d trailing bytes", len(fields.Trailing))
	}

	canonical := ssh.Marshal(struct {
		Type        string
		Curve       string
		Point       []byte
		Application string
	}{keyType, fields.Curve, fields.Point, fields.Application})
	publicKey, err := ssh.ParsePublicKey(canonical)
	if err != nil {
		return nil, fmt.Errorf("securitykey: %v", err)
	}
	return &Key{
		publicKey: publicKey,
		ecdsaKey:  ecdsaKey,
		rpID:      fields.Application,
		comment:   comment,
	}, nil
}

// KeyForSite returns the line of authorizedKeys, the contents of an authorized_keys file, that
// holds the key made in the browser for host or a parent domain of it, as WebAuthn allows. It skips
// blank lines, comments, lines with options, and lines that ParseKey refuses or that hold another
// site's key, and fails unless exactly one line is left.
func KeyForSite(authorizedKeys []byte, host string) (string, error) {
	var matches []string
	for _, line := range strings.Split(string(authorizedKeys), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, err := ParseKey([]byte(line))
		if err != nil || (key.RPID() != host && !strings.HasSuffix(host, "."+key.RPID())) {
			continue
		}
		matches = append(matches, line)
	}
	switch len(matches) {
	case 0:
		return "", fmt.Errorf("securitykey: no key made in the browser for %q (lines with options are skipped)", host)
	case 1:
		return matches[0], nil
	}
	return "", fmt.Errorf("securitykey: %d keys made in the browser for %q, want one", len(matches), host)
}

// cutField splits s at its first run of spaces or tabs.
func cutField(s string) (field, rest string) {
	end := strings.IndexAny(s, " \t")
	if end < 0 {
		return s, ""
	}
	return s[:end], strings.TrimLeft(s[end:], " \t")
}

// PublicKey returns the key as an sk-ecdsa-sha2-nistp256@openssh.com key, whatever the line's spelling.
func (k *Key) PublicKey() ssh.PublicKey { return k.publicKey }

// RPID returns the key's application string: the WebAuthn site (relying party ID) it was made for.
func (k *Key) RPID() string { return k.rpID }

// Comment returns the authorized_keys line's comment, or "" if it has none.
func (k *Key) Comment() string { return k.comment }

// Signer returns an ssh.Signer that has auth make every signature.
func (k *Key) Signer(auth Authenticator) ssh.Signer {
	return &keySigner{key: k, authenticate: auth}
}

type keySigner struct {
	key          *Key
	authenticate Authenticator
}

func (signer *keySigner) PublicKey() ssh.PublicKey { return signer.key.publicKey }

// Sign ignores rand: the security key makes the signature's randomness.
func (signer *keySigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	// OpenSSH expects the data itself as the challenge, not a hash of it.
	assertion, err := signer.authenticate(signer.key.rpID, data)
	if err != nil {
		return nil, fmt.Errorf("securitykey: the security key didn't sign: %w", err)
	}
	flags, counter, err := checkAuthenticatorData(assertion.AuthenticatorData, signer.key.rpID)
	if err != nil {
		return nil, err
	}
	origin, err := checkClientData(assertion.ClientDataJSON, data)
	if err != nil {
		return nil, err
	}
	r, s, err := parseDERSignature(assertion.Signature)
	if err != nil {
		return nil, err
	}
	if !signer.key.verify(assertion, r, s) {
		return nil, errors.New("securitykey: the security key signed with a different key than the configured one " +
			"(it may hold several keys for this site)")
	}

	return &ssh.Signature{
		Format: signatureFormat,
		Blob:   ssh.Marshal(struct{ R, S *big.Int }{r, s}),
		Rest: ssh.Marshal(webauthnFields{
			Flags:      flags,
			Counter:    counter,
			Origin:     origin,
			ClientData: assertion.ClientDataJSON,
			Extensions: []byte{}, // checkAuthenticatorData refuses assertions with extensions
		}),
	}, nil
}

// webauthnFields follow the ECDSA signature in a webauthn signature (PROTOCOL.u2f).
type webauthnFields struct {
	Flags      byte
	Counter    uint32
	Origin     string
	ClientData []byte
	Extensions []byte
}

// checkAuthenticatorData returns the flags and counter of an assertion for
// rpID, or an error if OpenSSH or sshd's verify-required would refuse it.
func checkAuthenticatorData(authenticatorData []byte, rpID string) (flags byte, counter uint32, err error) {
	if len(authenticatorData) != authenticatorDataLength {
		return 0, 0, fmt.Errorf("securitykey: authenticator data is %d bytes, want %d (no attested credential, no extensions)",
			len(authenticatorData), authenticatorDataLength)
	}
	rpIDHash := sha256.Sum256([]byte(rpID))
	if !bytes.Equal(authenticatorData[:32], rpIDHash[:]) {
		return 0, 0, fmt.Errorf("securitykey: the security key signed for a different site than %q", rpID)
	}
	flags = authenticatorData[32]
	counter = binary.BigEndian.Uint32(authenticatorData[33:37])
	switch {
	case flags&flagUserPresent == 0:
		return 0, 0, errors.New("securitykey: the security key wasn't touched (user-present flag missing)")
	case flags&flagUserVerified == 0:
		return 0, 0, errors.New("securitykey: the security key didn't check the PIN (user-verified flag missing)")
	case flags&flagAttestedData != 0:
		return 0, 0, errors.New("securitykey: authenticator data has the attested-credential flag, which an assertion can't have")
	case flags&flagExtensionData != 0:
		return 0, 0, errors.New("securitykey: authenticator data has the extensions flag, but it has no extensions")
	}
	return flags, counter, nil
}

// checkClientData returns clientData's origin, or an error if OpenSSH would
// refuse clientData as the wrapper of a signature over challenge.
func checkClientData(clientDataJSON, challenge []byte) (origin string, err error) {
	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataJSON, &clientData); err != nil {
		return "", fmt.Errorf("securitykey: clientDataJSON is not JSON: %v", err)
	}
	if clientData.Type != "webauthn.get" {
		return "", fmt.Errorf("securitykey: clientData type is %q, want \"webauthn.get\"", clientData.Type)
	}
	encodedChallenge := base64.RawURLEncoding.EncodeToString(challenge)
	if clientData.Challenge != encodedChallenge {
		return "", errors.New("securitykey: clientData's challenge is not the data to sign")
	}
	if clientData.Origin == "" {
		return "", errors.New("securitykey: clientData has no origin")
	}
	if strings.Contains(clientData.Origin, `"`) {
		return "", fmt.Errorf("securitykey: clientData's origin %q contains a quote, which OpenSSH refuses", clientData.Origin)
	}

	// OpenSSH doesn't parse the JSON: it compares the start of it with this.
	prefix := `{"type":"webauthn.get","challenge":"` + encodedChallenge + `","origin":"` + clientData.Origin + `"`
	if !bytes.HasPrefix(clientDataJSON, []byte(prefix)) {
		return "", errors.New(`securitykey: clientData doesn't start with {"type":"webauthn.get","challenge":"…","origin":"…" ` +
			"written exactly so, which OpenSSH requires")
	}
	return clientData.Origin, nil
}

// parseDERSignature splits an ASN.1 DER ECDSA signature, SEQUENCE { r, s } and nothing else, into r and s.
func parseDERSignature(der []byte) (r, s *big.Int, err error) {
	r, s = new(big.Int), new(big.Int)
	input := cryptobyte.String(der)
	var sequence cryptobyte.String
	if !input.ReadASN1(&sequence, cryptobyteasn1.SEQUENCE) || !input.Empty() ||
		!sequence.ReadASN1Integer(r) || !sequence.ReadASN1Integer(s) || !sequence.Empty() {
		return nil, nil, errors.New("securitykey: the security key's signature is not a DER ECDSA signature")
	}
	return r, s, nil
}

// verify reports whether r and s sign the assertion with k, as WebAuthn defines it.
func (k *Key) verify(assertion *Assertion, r, s *big.Int) bool {
	clientDataHash := sha256.Sum256(assertion.ClientDataJSON)
	signed := append(bytes.Clone(assertion.AuthenticatorData), clientDataHash[:]...)
	digest := sha256.Sum256(signed)
	return ecdsa.Verify(k.ecdsaKey, digest[:], r, s)
}
