package securitykey_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/loemraw/shelloe/internal/securitykey"
	"github.com/loemraw/shelloe/internal/securitykey/securitykeytest"
	"github.com/loemraw/shelloe/internal/sshdtest"
)

const (
	rpID   = "shell.example.com"
	origin = "https://shell.example.com"

	canonicalType   = "sk-ecdsa-sha2-nistp256@openssh.com"
	sshTermType     = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
	signatureFormat = "webauthn-sk-ecdsa-sha2-nistp256@openssh.com"
)

func newAuthenticator(t *testing.T) *securitykeytest.Authenticator {
	t.Helper()
	fake, err := securitykeytest.New(rpID, origin)
	if err != nil {
		t.Fatalf("securitykeytest.New: %v", err)
	}
	return fake
}

func parseKey(t *testing.T, line []byte) *securitykey.Key {
	t.Helper()
	key, err := securitykey.ParseKey(line)
	if err != nil {
		t.Fatalf("ParseKey(%q): %v", line, err)
	}
	return key
}

// authorizedKeyLine builds an authorized_keys line around a key blob made of these fields.
func authorizedKeyLine(lineType, blobType, curve string, point []byte, application string, trailing []byte) []byte {
	blob := ssh.Marshal(struct {
		Type        string
		Curve       string
		Point       []byte
		Application string
	}{blobType, curve, point, application})
	blob = append(blob, trailing...)
	return []byte(lineType + " " + base64.StdEncoding.EncodeToString(blob))
}

func TestParseKeyReadsBothSpellingsAsOneKey(t *testing.T) {
	fake := newAuthenticator(t)
	canonical := parseKey(t, fake.AuthorizedKey(canonicalType, "web-shell"))
	sshTerm := parseKey(t, fake.AuthorizedKey(sshTermType, "web-shell"))

	if !bytes.Equal(canonical.PublicKey().Marshal(), sshTerm.PublicKey().Marshal()) {
		t.Errorf("the two spellings give different keys:\n%x\n%x", canonical.PublicKey().Marshal(), sshTerm.PublicKey().Marshal())
	}
	for _, key := range []*securitykey.Key{canonical, sshTerm} {
		if got := key.PublicKey().Type(); got != canonicalType {
			t.Errorf("PublicKey().Type() = %q, want %q", got, canonicalType)
		}
		if got := key.RPID(); got != rpID {
			t.Errorf("RPID() = %q, want %q", got, rpID)
		}
		if got := key.Comment(); got != "web-shell" {
			t.Errorf("Comment() = %q, want %q", got, "web-shell")
		}
	}
}

func TestParseKeyComment(t *testing.T) {
	fake := newAuthenticator(t)
	line := strings.TrimSpace(string(fake.AuthorizedKey(canonicalType, "")))
	tests := []struct {
		name string
		line string
		want string
	}{
		{"no comment", line, ""},
		{"one word", line + " user@laptop", "user@laptop"},
		{"several words keep their spacing", line + "\tweb shell  key", "web shell  key"},
		{"surrounding whitespace", "  " + line + " web-shell \r\n", "web-shell"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := parseKey(t, []byte(test.line)).Comment(); got != test.want {
				t.Errorf("Comment() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestKeyForSitePicksTheSitesKey(t *testing.T) {
	sshKeygenEd25519 := ssh.Marshal(struct {
		Type        string
		PublicKey   []byte
		Application string
	}{"sk-ssh-ed25519@openssh.com", make([]byte, 32), "ssh:"})
	sshKeygenECDSA, err := securitykeytest.New("ssh:", "https://ssh.invalid")
	if err != nil {
		t.Fatal(err)
	}
	other, err := securitykeytest.New("other.example.com", "https://other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	mine := strings.TrimSpace(string(newAuthenticator(t).AuthorizedKey(canonicalType, "mine")))

	var file []byte
	file = append(file, "# comment\n\n"...)
	file = append(file, "sk-ssh-ed25519@openssh.com "+base64.StdEncoding.EncodeToString(sshKeygenEd25519)+"\n"...)
	file = append(file, sshKeygenECDSA.AuthorizedKey(canonicalType, "")...)
	file = append(file, other.AuthorizedKey(canonicalType, "")...)
	file = append(file, mine+"\r\n"...)

	got, err := securitykey.KeyForSite(file, rpID)
	if err != nil {
		t.Fatalf("KeyForSite: %v", err)
	}
	if got != mine {
		t.Errorf("KeyForSite = %q, want %q", got, mine)
	}
}

func TestKeyForSiteRefuses(t *testing.T) {
	sshKeygen, err := securitykeytest.New("ssh:", "https://ssh.invalid")
	if err != nil {
		t.Fatal(err)
	}
	other, err := securitykeytest.New("other.example.com", "https://other.example.com")
	if err != nil {
		t.Fatal(err)
	}
	first, second := newAuthenticator(t), newAuthenticator(t)

	tests := []struct {
		name    string
		file    []byte
		wantErr string
	}{
		{
			"only other sites and ssh-keygen keys",
			append(sshKeygen.AuthorizedKey(canonicalType, ""), other.AuthorizedKey(canonicalType, "")...),
			"no key made in the browser for",
		},
		{
			"two keys for the site",
			append(first.AuthorizedKey(canonicalType, "one"), second.AuthorizedKey(canonicalType, "two")...),
			"2 keys made in the browser for",
		},
		{"empty file", nil, "no key made in the browser for"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			line, err := securitykey.KeyForSite(test.file, rpID)
			if err == nil {
				t.Fatalf("KeyForSite = %q, want an error containing %q", line, test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("KeyForSite error = %q, want it to contain %q", err, test.wantErr)
			}
		})
	}
}

func TestParseKeyRejects(t *testing.T) {
	fake := newAuthenticator(t)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	point, err := privateKey.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	pointAtOrigin := append([]byte{0x04}, make([]byte, 64)...) // (0, 0) isn't on P-256

	canonicalLine := string(fake.AuthorizedKey(canonicalType, ""))
	tests := []struct {
		name    string
		line    []byte
		wantErr string
	}{
		{"no key", []byte(canonicalType), "expected an authorized_keys line"},
		{"unknown type", fake.AuthorizedKey("ssh-ed25519", ""), `key type is "ssh-ed25519"`},
		{
			"line type differs from the key's",
			[]byte(strings.Replace(canonicalLine, canonicalType, sshTermType, 1)),
			"the key itself says",
		},
		{"curve other than nistp256", authorizedKeyLine(canonicalType, canonicalType, "nistp384", point, rpID, nil), "curve"},
		{"invalid point", authorizedKeyLine(canonicalType, canonicalType, "nistp256", pointAtOrigin, rpID, nil), "not a valid P-256 point"},
		{"made by ssh-keygen", authorizedKeyLine(canonicalType, canonicalType, "nistp256", point, "ssh:", nil), "a browser can't use"},
		{"no application", authorizedKeyLine(canonicalType, canonicalType, "nistp256", point, "", nil), "no application"},
		{"trailing bytes", authorizedKeyLine(canonicalType, canonicalType, "nistp256", point, rpID, []byte{0}), "trailing bytes"},
		{"bad base64", []byte(canonicalType + " AAAA$$$$"), "not valid base64"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := securitykey.ParseKey(test.line)
			if err == nil {
				t.Fatalf("ParseKey(%q) = %v, want an error containing %q", test.line, key.PublicKey().Type(), test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("ParseKey(%q) error = %q, want it to contain %q", test.line, err, test.wantErr)
			}
		})
	}
}

func TestSignerMakesWebauthnSignatures(t *testing.T) {
	fake := newAuthenticator(t)
	signer := parseKey(t, fake.AuthorizedKey(sshTermType, "")).Signer(fake.Get)
	if got := signer.PublicKey().Type(); got != canonicalType {
		t.Errorf("PublicKey().Type() = %q, want %q", got, canonicalType)
	}

	for i, data := range []string{"first data to sign", "second data to sign"} {
		signature, err := signer.Sign(rand.Reader, []byte(data))
		if err != nil {
			t.Fatalf("Sign(%q): %v", data, err)
		}
		if signature.Format != signatureFormat {
			t.Errorf("Format = %q, want %q", signature.Format, signatureFormat)
		}
		var ecdsaSignature struct{ R, S *big.Int }
		if err := ssh.Unmarshal(signature.Blob, &ecdsaSignature); err != nil {
			t.Errorf("Blob isn't two mpints: %v", err)
		}

		var fields struct {
			Flags      byte
			Counter    uint32
			Origin     string
			ClientData string
			Extensions string
		}
		if err := ssh.Unmarshal(signature.Rest, &fields); err != nil {
			t.Fatalf("Rest isn't flags, counter, origin, clientData, extensions: %v", err)
		}
		if fields.Flags != 0x05 {
			t.Errorf("flags = %#x, want 0x05", fields.Flags)
		}
		if want := uint32(i + 1); fields.Counter != want {
			t.Errorf("counter = %d, want %d", fields.Counter, want)
		}
		if fields.Origin != origin {
			t.Errorf("origin = %q, want %q", fields.Origin, origin)
		}
		wantClientData := `{"type":"webauthn.get","challenge":"` + base64.RawURLEncoding.EncodeToString([]byte(data)) +
			`","origin":"` + origin + `","crossOrigin":false}`
		if fields.ClientData != wantClientData {
			t.Errorf("clientData = %s\nwant %s", fields.ClientData, wantClientData)
		}
		if fields.Extensions != "" {
			t.Errorf("extensions = %q, want none", fields.Extensions)
		}
	}
}

func TestSignerAsksForTheKeysSiteWithTheDataAsChallenge(t *testing.T) {
	fake := newAuthenticator(t)
	var gotRPID string
	var gotChallenge []byte
	recording := func(rpID string, challenge []byte) (*securitykey.Assertion, error) {
		gotRPID, gotChallenge = rpID, challenge
		return fake.Get(rpID, challenge)
	}
	signer := parseKey(t, fake.AuthorizedKey(canonicalType, "")).Signer(recording)

	data := []byte("data to sign")
	if _, err := signer.Sign(rand.Reader, data); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if gotRPID != rpID {
		t.Errorf("authenticator got rpID %q, want %q", gotRPID, rpID)
	}
	if !bytes.Equal(gotChallenge, data) {
		t.Errorf("authenticator got challenge %q, want the data itself, %q", gotChallenge, data)
	}
}

// tamper returns an authenticator that lets change edit what auth returns.
func tamper(auth securitykey.Authenticator, change func(*securitykey.Assertion)) securitykey.Authenticator {
	return func(rpID string, challenge []byte) (*securitykey.Assertion, error) {
		assertion, err := auth(rpID, challenge)
		if err != nil {
			return nil, err
		}
		change(assertion)
		return assertion, nil
	}
}

func TestSignerRefuses(t *testing.T) {
	errCancelled := errors.New("NotAllowedError: the request was cancelled")
	tests := []struct {
		name string
		// authenticator answers for fake, which holds the configured key.
		authenticator func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator
		wantErr       string
	}{
		{
			"no PIN check",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				fake.Flags = 0x01
				return fake.Get
			},
			"didn't check the PIN",
		},
		{
			"no touch",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				fake.Flags = 0x04
				return fake.Get
			},
			"wasn't touched",
		},
		{
			"extensions flag",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				fake.Flags = 0x85
				return fake.Get
			},
			"extensions flag",
		},
		{
			"attested credential flag",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				fake.Flags = 0x45
				return fake.Get
			},
			"attested-credential flag",
		},
		{
			"authenticator data longer than 37 bytes",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				return tamper(fake.Get, func(assertion *securitykey.Assertion) {
					assertion.AuthenticatorData = append(assertion.AuthenticatorData, 0xa0) // an empty CBOR map of extensions
				})
			},
			"authenticator data is 38 bytes",
		},
		{
			"signed for another site",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				other, err := securitykeytest.New("other.example.com", origin)
				if err != nil {
					t.Fatal(err)
				}
				return func(_ string, challenge []byte) (*securitykey.Assertion, error) {
					return other.Get("other.example.com", challenge)
				}
			},
			"different site",
		},
		{
			"clientData with another challenge",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				return func(rpID string, _ []byte) (*securitykey.Assertion, error) {
					return fake.Get(rpID, []byte("other data"))
				}
			},
			"challenge is not the data to sign",
		},
		{
			"clientData of webauthn.create",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				return tamper(fake.Get, func(assertion *securitykey.Assertion) {
					assertion.ClientDataJSON = bytes.Replace(assertion.ClientDataJSON,
						[]byte(`"webauthn.get"`), []byte(`"webauthn.create"`), 1)
				})
			},
			`type is "webauthn.create"`,
		},
		{
			"origin with a quote",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				return tamper(fake.Get, func(assertion *securitykey.Assertion) {
					assertion.ClientDataJSON = bytes.Replace(assertion.ClientDataJSON,
						[]byte(`"origin":"`+origin+`"`), []byte(`"origin":"`+origin+`\"x"`), 1)
				})
			},
			"contains a quote",
		},
		{
			"no origin",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				return tamper(fake.Get, func(assertion *securitykey.Assertion) {
					assertion.ClientDataJSON = bytes.Replace(assertion.ClientDataJSON,
						[]byte(`"origin":"`+origin+`"`), []byte(`"origin":""`), 1)
				})
			},
			"no origin",
		},
		{
			"clientData fields in another order",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				return tamper(fake.Get, func(assertion *securitykey.Assertion) {
					var fields map[string]any
					if err := json.Unmarshal(assertion.ClientDataJSON, &fields); err != nil {
						t.Fatal(err)
					}
					// json.Marshal sorts the keys, putting challenge first.
					reordered, err := json.Marshal(fields)
					if err != nil {
						t.Fatal(err)
					}
					assertion.ClientDataJSON = reordered
				})
			},
			"written exactly so",
		},
		{
			"signature from another key",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				return newAuthenticator(t).Get
			},
			"different key than the configured one",
		},
		{
			"signature not DER",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				return tamper(fake.Get, func(assertion *securitykey.Assertion) {
					assertion.Signature = []byte("not a signature")
				})
			},
			"not a DER ECDSA signature",
		},
		{
			"signature with trailing bytes",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				return tamper(fake.Get, func(assertion *securitykey.Assertion) {
					assertion.Signature = append(assertion.Signature, 0)
				})
			},
			"not a DER ECDSA signature",
		},
		{
			"signature with a third element after r and s",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				return tamper(fake.Get, func(assertion *securitykey.Assertion) {
					// A P-256 signature's SEQUENCE length fits in one byte, so INTEGER 0 adds 3 to it.
					assertion.Signature[1] += 3
					assertion.Signature = append(assertion.Signature, 0x02, 0x01, 0x00)
				})
			},
			"not a DER ECDSA signature",
		},
		{
			"authenticator error",
			func(t *testing.T, fake *securitykeytest.Authenticator) securitykey.Authenticator {
				return func(string, []byte) (*securitykey.Assertion, error) {
					return nil, errCancelled
				}
			},
			"NotAllowedError",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := newAuthenticator(t)
			signer := parseKey(t, fake.AuthorizedKey(canonicalType, "")).Signer(test.authenticator(t, fake))
			signature, err := signer.Sign(rand.Reader, []byte("data to sign"))
			if err == nil {
				t.Fatalf("Sign = %+v, want an error containing %q", signature, test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Errorf("Sign error = %q, want it to contain %q", err, test.wantErr)
			}
		})
	}

	t.Run("authenticator error is wrapped", func(t *testing.T) {
		fake := newAuthenticator(t)
		failing := func(string, []byte) (*securitykey.Assertion, error) { return nil, errCancelled }
		_, err := parseKey(t, fake.AuthorizedKey(canonicalType, "")).Signer(failing).Sign(rand.Reader, []byte("data"))
		if !errors.Is(err, errCancelled) {
			t.Errorf("Sign error = %v, want it to wrap %v", err, errCancelled)
		}
	})
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

// sshsig signs message like ssh-keygen -Y sign (PROTOCOL.sshsig) and returns the armored signature.
func sshsig(t *testing.T, signer ssh.Signer, namespace string, message []byte) []byte {
	t.Helper()
	messageHash := sha512.Sum512(message)
	signedData := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace     string
		Reserved      string
		HashAlgorithm string
		MessageHash   []byte
	}{namespace, "", "sha512", messageHash[:]})...)
	signature, err := signer.Sign(rand.Reader, signedData)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	blob := append([]byte("SSHSIG"), ssh.Marshal(struct {
		Version       uint32
		PublicKey     []byte
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Signature     []byte
	}{1, signer.PublicKey().Marshal(), namespace, "", "sha512", ssh.Marshal(signature)})...)
	return pem.EncodeToMemory(&pem.Block{Type: "SSH SIGNATURE", Bytes: blob})
}

func TestOpenSSHAcceptsTheSignature(t *testing.T) {
	sshKeygen := findSSHKeygen(t)
	fake := newAuthenticator(t)
	signer := parseKey(t, fake.AuthorizedKey(sshTermType, "")).Signer(fake.Get)

	message := []byte("a message to sign\n")
	signaturePath := filepath.Join(t.TempDir(), "message.sig")
	if err := os.WriteFile(signaturePath, sshsig(t, signer, "file", message), 0o600); err != nil {
		t.Fatal(err)
	}
	checkSignature := func(message []byte) ([]byte, error) {
		// check-novalidate checks the signature without an allowed_signers file.
		check := exec.Command(sshKeygen, "-Y", "check-novalidate", "-n", "file", "-s", signaturePath)
		check.Stdin = bytes.NewReader(message)
		return check.CombinedOutput()
	}

	if output, err := checkSignature(message); err != nil {
		t.Fatalf("ssh-keygen -Y check-novalidate: %v\n%s", err, output)
	}
	if output, err := checkSignature([]byte("another message\n")); err == nil {
		t.Fatalf("ssh-keygen accepted the signature for another message:\n%s", output)
	}
}

func TestLoginWithOpenSSH(t *testing.T) {
	osUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	fake := newAuthenticator(t)
	// authorized_keys holds the key as SSH Term writes it.
	server := sshdtest.Start(t, fake.AuthorizedKey(sshTermType, "web-shell"))

	t.Run("configured key", func(t *testing.T) {
		signer := parseKey(t, fake.AuthorizedKey(sshTermType, "")).Signer(fake.Get)
		output, err := runCommand(server.Addr, osUser.Username, server.HostKey, signer, "echo hello")
		if err != nil {
			t.Fatalf("logging in and running echo hello: %v", err)
		}
		if output != "hello\n" {
			t.Errorf("echo hello printed %q, want %q", output, "hello\n")
		}
	})

	t.Run("key not in authorized_keys", func(t *testing.T) {
		stranger := newAuthenticator(t)
		signer := parseKey(t, stranger.AuthorizedKey(canonicalType, "")).Signer(stranger.Get)
		_, err := runCommand(server.Addr, osUser.Username, server.HostKey, signer, "echo hello")
		if err == nil {
			t.Fatal("sshd let in a key that isn't in authorized_keys")
		}
		if !strings.Contains(err.Error(), "unable to authenticate") {
			t.Errorf("login error = %q, want sshd to refuse the key", err)
		}
	})
}

// runCommand logs in to addr as username with signer and returns what command prints.
func runCommand(addr, username string, hostKey ssh.PublicKey, signer ssh.Signer, command string) (string, error) {
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.FixedHostKey(hostKey),
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return "", err
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	output, err := session.Output(command)
	return string(output), err
}
