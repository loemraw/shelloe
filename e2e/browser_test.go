package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/input"
	cdppage "github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/webauthn"
	"github.com/chromedp/chromedp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/image/font/gofont/gomono"
	"golang.org/x/image/font/gofont/gomonobold"
	"golang.org/x/image/font/gofont/gomonobolditalic"
	"golang.org/x/image/font/gofont/gomonoitalic"

	"github.com/loemraw/shelloe/internal/flowcontrol"
	"github.com/loemraw/shelloe/internal/page"
	"github.com/loemraw/shelloe/internal/relay"
	"github.com/loemraw/shelloe/internal/securitykey/securitykeytest"
	"github.com/loemraw/shelloe/internal/sshdtest"
)

const (
	keyType = "sk-ecdsa-sha2-nistp256@openssh.com"
	rpID    = "localhost"

	timeout = 10 * time.Second // how long a wait gives the page
	// tabTimeout limits a whole test's tab, so a browser that stops answering fails the test.
	tabTimeout = 2 * time.Minute
)

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	defer stopBrowser()
	defer removeBuiltPage()
	return m.Run()
}

// thePage is the page with its client, built by the first test that needs it.
// Not by TestMain: go test notes the files that a test reads, so as to rerun
// it when one changes, only once m.Run has started.
var thePage struct {
	once sync.Once
	dir  string
	err  error
}

// builtPage returns the directory of the built page, building it the first
// time. It fails the test if the page didn't build.
func builtPage(t *testing.T) string {
	t.Helper()
	thePage.once.Do(func() {
		thePage.dir, thePage.err = os.MkdirTemp("", "shelloe-page-")
		if thePage.err == nil {
			thePage.err = buildPage(thePage.dir)
		}
	})
	if thePage.err != nil {
		t.Fatal(thePage.err)
	}
	return thePage.dir
}

func removeBuiltPage() {
	if thePage.dir != "" {
		os.RemoveAll(thePage.dir)
	}
}

// buildPage copies the page's files into dir and builds the client next to them.
func buildPage(dir string) error {
	if err := checkVendored(); err != nil {
		return err
	}
	if err := statSources(); err != nil {
		return err
	}
	web := filepath.Join("..", "web")
	err := filepath.WalkDir(web, func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name, err := filepath.Rel(web, p)
		switch {
		case err != nil:
			return err
		case entry.IsDir():
			return os.MkdirAll(filepath.Join(dir, name), 0o755)
		case name == "shelloe.wasm" || name == "wasm_exec.js":
			return nil
		}
		return copyFile(p, filepath.Join(dir, name))
	})
	if err != nil {
		return fmt.Errorf("copying the page: %w", err)
	}

	build := exec.Command("go", "build", "-o", filepath.Join(dir, "shelloe.wasm"), "./cmd/shelloe-wasm")
	build.Dir = ".."
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if output, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("building the client: %v\n%s", err, output)
	}

	goroot, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return fmt.Errorf("go env GOROOT: %w", err)
	}
	wasmExec := filepath.Join(strings.TrimSpace(string(goroot)), "lib", "wasm", "wasm_exec.js")
	return copyFile(wasmExec, filepath.Join(dir, "wasm_exec.js"))
}

// statSources stats the module's Go files, go.mod and go.sum. go test reruns
// a cached test when a file the test looked at has changed, and it doesn't
// see what the go build of the client reads.
func statSources() error {
	return filepath.WalkDir("..", func(p string, entry fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case entry.IsDir() && p != ".." && strings.HasPrefix(entry.Name(), "."):
			return filepath.SkipDir
		case entry.IsDir():
			return nil
		case strings.HasSuffix(p, ".go") || p == filepath.Join("..", "go.mod") || p == filepath.Join("..", "go.sum"):
			_, err := os.Stat(p)
			return err
		}
		return nil
	})
}

// checkVendored makes sure that web/vendor holds every file that
// scripts/vendor-xterm.json lists.
func checkVendored() error {
	pins, err := os.ReadFile(filepath.Join("..", "scripts", "vendor-xterm.json"))
	if err != nil {
		return err
	}
	var packages []struct{ Files map[string]string }
	if err := json.Unmarshal(pins, &packages); err != nil {
		return fmt.Errorf("scripts/vendor-xterm.json: %w", err)
	}
	var missing []string
	for _, p := range packages {
		for _, name := range p.Files {
			if _, err := os.Stat(filepath.Join("..", "web", "vendor", name)); err != nil {
				missing = append(missing, name)
			}
		}
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return fmt.Errorf("web/vendor lacks %s: run scripts/vendor-xterm.py", strings.Join(missing, ", "))
	}
	return nil
}

func copyFile(from, to string) error {
	content, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, content, 0o644)
}

// browser is the test binary's one browser, started by the first test that needs it.
var browser struct {
	once   sync.Once
	ctx    context.Context
	cancel context.CancelFunc
	err    error
}

func startBrowser() (context.Context, error) {
	browser.once.Do(func() {
		options := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.ExecPath(os.Getenv("SHELLOE_CHROME")),
			chromedp.NoSandbox,
		)
		allocatorCtx, cancelAllocator := chromedp.NewExecAllocator(context.Background(), options...)
		ctx, cancelBrowser := chromedp.NewContext(allocatorCtx)
		browser.ctx = ctx
		browser.cancel = func() {
			cancelBrowser()
			cancelAllocator()
		}
		browser.err = chromedp.Do(ctx)
	})
	return browser.ctx, browser.err
}

func stopBrowser() {
	if browser.cancel != nil {
		browser.cancel()
	}
}

// newKey returns a new security key, for the browser's virtual authenticator
// to hold. Every test with a key needs the browser, so newKey skips the test
// unless SHELLOE_CHROME is set, and fails it if the page didn't build.
func newKey(t *testing.T) *securitykeytest.Authenticator {
	t.Helper()
	if os.Getenv("SHELLOE_CHROME") == "" {
		t.Skip("set SHELLOE_CHROME to a Chrome binary to run this test")
	}
	builtPage(t)
	key, err := securitykeytest.New(rpID, "http://localhost")
	if err != nil {
		t.Fatalf("securitykeytest.New: %v", err)
	}
	return key
}

// recordErrors runs in the page before its own scripts. Go's wasm_exec.js
// prints a panic with console.log, and syscall/js reports a call to a
// released Func with console.error.
const recordErrors = `
window.__errors = [];
addEventListener("error", (event) => __errors.push("error: " + event.message));
addEventListener("unhandledrejection", (event) => __errors.push("unhandled rejection: " + event.reason));
addEventListener("securitypolicyviolation", (event) => __errors.push("CSP: " + event.violatedDirective + " " + event.blockedURI));
const consoleError = console.error;
console.error = (...args) => {
  __errors.push("console.error: " + args.join(" "));
  consoleError.apply(console, args);
};
const consoleLog = console.log;
console.log = (...args) => {
  const first = String(args[0]);
  if (first.startsWith("panic:") || first.startsWith("fatal error:")) {
    __errors.push("console.log: " + args.join(" "));
  }
  consoleLog.apply(console, args);
};
`

// testPage is the page, open in a tab of the browser.
type testPage struct {
	t             *testing.T
	ctx           context.Context
	authenticator webauthn.AuthenticatorID
	credentialID  []byte
}

// openPage serves the page, with its relay to the SSH server at serverAddr,
// and opens it in a new tab whose virtual authenticator holds key. The test
// fails if the page logs an error.
func openPage(t *testing.T, key *securitykeytest.Authenticator, serverAddr string, hostKey ssh.PublicKey) *testPage {
	t.Helper()
	return openPageWith(t, key, serverAddr, hostKey, pageOptions{})
}

// pageOptions change what openPageWith serves and how it opens the page.
// The zero value does what openPage does.
type pageOptions struct {
	dir          string        // the directory to serve instead of the built page
	noRelay      bool          // serve no /ws
	untouched    bool          // the security key waits for a touch, until setPresence(true)
	initScript   string        // runs in the page before its own scripts, after recordErrors
	font         page.Font     // the terminal's font
	fontsHeld    chan struct{} // the font's files arrive only once this is closed, or the test has ended
	heldFont     string        // with fontsHeld, the one font URL path to hold, like /fonts/<hex>.ttf; "" holds them all
	localhostURL string        // where links to the SSH server's localhost open, with {port} for the port
}

func openPageWith(t *testing.T, key *securitykeytest.Authenticator, serverAddr string, hostKey ssh.PublicKey, options pageOptions) *testPage {
	t.Helper()
	osUser, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	// The virtual credential is for the site localhost, and http://localhost is a secure context.
	origin := fmt.Sprintf("http://localhost:%d", listener.Addr().(*net.TCPAddr).Port)
	dir := options.dir
	if dir == "" {
		dir = builtPage(t)
	}
	pageHandler, err := page.Handler(dir, page.Config{
		User:         osUser.Username,
		Key:          string(key.AuthorizedKey(keyType, "")),
		HostKey:      string(ssh.MarshalAuthorizedKey(hostKey)),
		LocalhostURL: options.localhostURL,
	}, options.font)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", pageHandler)
	testEnded := make(chan struct{})
	if options.fontsHeld != nil {
		mux.Handle("/fonts/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if options.heldFont == "" || r.URL.Path == options.heldFont {
				select {
				case <-options.fontsHeld:
				case <-testEnded:
				}
			}
			pageHandler.ServeHTTP(w, r)
		}))
	}
	if !options.noRelay {
		relayHandler, err := relay.Handler(serverAddr, origin)
		if err != nil {
			t.Fatal(err)
		}
		mux.Handle("/ws", relayHandler)
	}
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	t.Cleanup(func() { close(testEnded) })

	browserCtx, err := startBrowser()
	if err != nil {
		t.Fatalf("starting the browser: %v", err)
	}
	timeoutCtx, cancelTimeout := context.WithTimeout(browserCtx, tabTimeout)
	t.Cleanup(cancelTimeout)
	ctx, cancelTab := chromedp.NewContext(timeoutCtx)
	t.Cleanup(cancelTab)
	p := &testPage{t: t, ctx: ctx}

	if _, err := chromedp.Call(ctx, webauthn.Enable, webauthn.EnableParams{EnableUI: new(false)}); err != nil {
		t.Fatalf("WebAuthn.enable: %v", err)
	}
	added, err := chromedp.Call(ctx, webauthn.AddVirtualAuthenticator, webauthn.AddVirtualAuthenticatorParams{
		Options: &webauthn.VirtualAuthenticatorOptions{
			Protocol:                    webauthn.AuthenticatorProtocolCtap2,
			Transport:                   webauthn.AuthenticatorTransportUsb,
			HasResidentKey:              true,
			HasUserVerification:         true,
			IsUserVerified:              true,
			AutomaticPresenceSimulation: !options.untouched,
		},
	})
	if err != nil {
		t.Fatalf("WebAuthn.addVirtualAuthenticator: %v", err)
	}
	p.authenticator = added.AuthenticatorID
	privateKey, err := x509.MarshalPKCS8PrivateKey(key.PrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	p.credentialID = randomBytes(t, 16)
	_, err = chromedp.Call(ctx, addCredential, addCredentialParams{
		AuthenticatorID: p.authenticator,
		Credential: credential{
			CredentialID:         p.credentialID,
			IsResidentCredential: true,
			RpID:                 rpID,
			PrivateKey:           privateKey,
			UserHandle:           randomBytes(t, 16),
		},
	})
	if err != nil {
		t.Fatalf("WebAuthn.addCredential: %v", err)
	}

	for _, script := range []string{recordErrors, options.initScript} {
		if script == "" {
			continue
		}
		if _, err := chromedp.Call(ctx, cdppage.AddScriptToEvaluateOnNewDocument, cdppage.AddScriptToEvaluateOnNewDocumentParams{Source: script}); err != nil {
			t.Fatalf("Page.addScriptToEvaluateOnNewDocument: %v", err)
		}
	}
	// Registered after the tab's cleanups, so it runs before the tab closes.
	t.Cleanup(func() {
		logged, err := chromedp.Run(ctx, chromedp.Evaluate[[]string](`window.__errors`))
		if err != nil {
			t.Errorf("reading the page's errors: %v", err)
		} else if len(logged) > 0 {
			t.Errorf("the page logged errors:\n%s", strings.Join(logged, "\n"))
		}
	})
	if err := chromedp.Do(ctx, chromedp.Navigate(origin+"/")); err != nil {
		t.Fatalf("opening %s: %v", origin, err)
	}
	return p
}

// addCredential is WebAuthn.addCredential, sending only the fields set
// here. cdproto's Credential sends every field, and Chrome refuses some
// unless the authenticator supports them, such as
// generateCmtgKeyOnNextOperation.
var addCredential = cdp.Command[addCredentialParams, cdp.Empty]{Method: webauthn.CommandAddCredential}

type addCredentialParams struct {
	AuthenticatorID webauthn.AuthenticatorID `json:"authenticatorId"`
	Credential      credential               `json:"credential"`
}

type credential struct {
	CredentialID         []byte `json:"credentialId"`
	IsResidentCredential bool   `json:"isResidentCredential"`
	RpID                 string `json:"rpId"`
	PrivateKey           []byte `json:"privateKey"` // PKCS #8
	UserHandle           []byte `json:"userHandle"`
	SignCount            int    `json:"signCount"`
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// poll calls done every 50ms until it returns true or timeout has passed, and reports whether it returned true.
func poll(done func() bool) bool {
	deadline := time.Now().Add(timeout)
	for {
		if done() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// evaluate returns the value of a JavaScript expression in the page.
func evaluate[T any](p *testPage, expression string) T {
	p.t.Helper()
	value, err := chromedp.Run(p.ctx, chromedp.Evaluate[T](expression))
	if err != nil {
		p.t.Fatalf("evaluating %s: %v", expression, err)
	}
	return value
}

func (p *testPage) do(what string, actions ...chromedp.Action[chromedp.Void]) {
	p.t.Helper()
	if err := chromedp.Do(p.ctx, actions...); err != nil {
		p.t.Fatalf("%s: %v", what, err)
	}
}

// screen returns the text on the terminal's screen, "" until the terminal has opened.
func (p *testPage) screen() string {
	p.t.Helper()
	return evaluate[string](p, `document.querySelector(".xterm-rows")?.innerText ?? ""`)
}

// waitForScreen waits until the screen shows want, and returns the screen.
func (p *testPage) waitForScreen(want string) string {
	p.t.Helper()
	var screen string
	if !poll(func() bool {
		screen = p.screen()
		return strings.Contains(screen, want)
	}) {
		p.t.Fatalf("the screen didn't show %q within %v; it shows:\n%s", want, timeout, screen)
	}
	return screen
}

// waitForPrompt waits until the login shell has printed something, such as its prompt.
func (p *testPage) waitForPrompt() {
	p.t.Helper()
	if !poll(func() bool { return strings.TrimSpace(p.screen()) != "" }) {
		p.t.Fatalf("the screen stayed empty for %v", timeout)
	}
}

// typeText types text into the terminal. Each "\r" is a press of Enter, and
// the text between goes in as an input method, such as an emoji picker, puts it.
func (p *testPage) typeText(text string) {
	p.t.Helper()
	// SendKeys's events reach xterm.js twice for most keys, as a key and as a
	// character, and an emoji arrives as half of one.
	p.do("focusing the terminal", chromedp.Focus(chromedp.CSS(".xterm-helper-textarea")))
	for i, part := range strings.Split(text, "\r") {
		if i > 0 {
			p.do("pressing Enter", chromedp.Func(pressEnter))
		}
		if part != "" {
			if _, err := chromedp.Call(p.ctx, input.InsertText, input.InsertTextParams{Text: part}); err != nil {
				p.t.Fatalf("typing %q: %v", part, err)
			}
		}
	}
}

// pressEnter presses Enter and lets it go, without typing a character as well.
func pressEnter(ctx context.Context, t *chromedp.Target) error {
	for _, eventType := range []input.DispatchKeyEventType{input.DispatchKeyEventTypeRawKeyDown, input.DispatchKeyEventTypeKeyUp} {
		_, err := cdp.Call(ctx, t, input.DispatchKeyEvent, input.DispatchKeyEventParams{
			Type:                  eventType,
			Key:                   "Enter",
			Code:                  "Enter",
			WindowsVirtualKeyCode: 13,
			NativeVirtualKeyCode:  13,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

type overlayState struct {
	Shown   bool   `json:"shown"`
	Message string `json:"message"`
	Button  bool   `json:"button"`
}

// overlay returns whether the overlay is shown, its message, and whether its Reconnect button is shown.
func (p *testPage) overlay() (shown bool, message string, button bool) {
	p.t.Helper()
	state := evaluate[overlayState](p, `({
		shown: !document.getElementById("overlay").hidden,
		message: document.getElementById("message").textContent,
		button: !document.getElementById("reconnect").hidden,
	})`)
	return state.Shown, state.Message, state.Button
}

// waitForOverlay waits until the overlay shows a message that starts with
// prefix, or until it's hidden if prefix is "". It returns the message and
// whether the Reconnect button is shown.
func (p *testPage) waitForOverlay(prefix string) (message string, button bool) {
	p.t.Helper()
	var shown bool
	if !poll(func() bool {
		shown, message, button = p.overlay()
		if prefix == "" {
			return !shown
		}
		return shown && strings.HasPrefix(message, prefix)
	}) {
		want := "hidden"
		if prefix != "" {
			want = fmt.Sprintf("showing %q…", prefix)
		}
		p.t.Fatalf("the overlay wasn't %s within %v; shown: %v, message: %q", want, timeout, shown, message)
	}
	return message, button
}

// recordOverlay starts recording each change of the overlay, as its message or "" when it's hidden.
func (p *testPage) recordOverlay() {
	p.t.Helper()
	evaluate[chromedp.Void](p, `
		window.__overlays = [];
		new MutationObserver(() => {
			const overlay = document.getElementById("overlay");
			__overlays.push(overlay.hidden ? "" : document.getElementById("message").textContent);
		}).observe(document.getElementById("overlay"), {attributes: true, subtree: true, childList: true});
	`)
}

// overlays returns what recordOverlay has recorded.
func (p *testPage) overlays() []string {
	p.t.Helper()
	return evaluate[[]string](p, `window.__overlays`)
}

// takeErrors returns the errors the page has logged so far and forgets them,
// for a test that expects some.
func (p *testPage) takeErrors() []string {
	p.t.Helper()
	return evaluate[[]string](p, `window.__errors.splice(0)`)
}

// signatures returns how many signatures the virtual authenticator has made.
func (p *testPage) signatures() int {
	p.t.Helper()
	result, err := chromedp.Call(p.ctx, webauthn.GetCredentials, webauthn.GetCredentialsParams{AuthenticatorID: p.authenticator})
	if err != nil {
		p.t.Fatalf("WebAuthn.getCredentials: %v", err)
	}
	for _, credential := range result.Credentials {
		if bytes.Equal(credential.CredentialID, p.credentialID) {
			return int(credential.SignCount)
		}
	}
	p.t.Fatal("the virtual authenticator doesn't hold the credential any more")
	return 0
}

// setPresence sets whether the virtual authenticator is touched as soon as it's asked.
func (p *testPage) setPresence(touched bool) {
	p.t.Helper()
	_, err := chromedp.Call(p.ctx, webauthn.SetAutomaticPresenceSimulation, webauthn.SetAutomaticPresenceSimulationParams{
		AuthenticatorID: p.authenticator,
		Enabled:         touched,
	})
	if err != nil {
		p.t.Fatalf("WebAuthn.setAutomaticPresenceSimulation: %v", err)
	}
}

func (p *testPage) clickReconnect() {
	p.t.Helper()
	p.do("clicking Reconnect", chromedp.Click(chromedp.ID("reconnect")))
}

func (p *testPage) resizeViewport(width, height int) {
	p.t.Helper()
	p.do("resizing the viewport", chromedp.EmulateViewport(int64(width), int64(height)))
}

// domRows returns how many rows the terminal shows.
func (p *testPage) domRows() int {
	p.t.Helper()
	return evaluate[int](p, `document.querySelectorAll(".xterm-rows > div").length`)
}

// terminalFont returns the font-family that the terminal's text is drawn in.
func (p *testPage) terminalFont() string {
	p.t.Helper()
	return evaluate[string](p, `getComputedStyle(document.querySelector(".xterm-rows")).fontFamily`)
}

// writeFontFile writes a font file that holds content, and returns its path.
func writeFontFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "font")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// openPageShowingAPrompt opens the page with options, its relay to a fake
// server, and waits until the session has started and the screen shows the
// server's prompt.
func openPageShowingAPrompt(t *testing.T, options pageOptions) *testPage {
	t.Helper()
	key := newKey(t)
	server := startFakeServer(t)
	p := openPageWith(t, key, server.addr, server.hostKey, options)
	if _, err := server.nextSession(t).Write([]byte("prompt$ ")); err != nil {
		t.Fatal(err)
	}
	p.waitForScreen("prompt$")
	return p
}

// otherHostKey returns a host key that no server has.
func otherHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return key
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

func TestPageLogsInWithTheSecurityKeyAndRunsTheLoginShell(t *testing.T) {
	key := newKey(t)
	server := sshdtest.Start(t, key.AuthorizedKey(keyType, ""))
	p := openPage(t, key, server.Addr, server.HostKey)

	p.waitForPrompt()
	p.typeText("echo answer-$((6*7))\r")
	p.waitForScreen("answer-42")
	p.typeText("echo term=$TERM\r")
	p.waitForScreen("term=xterm-256color")

	if got := p.signatures(); got != 1 {
		t.Errorf("the security key made %d signatures, want 1 (the login)", got)
	}
	if shown, message, _ := p.overlay(); shown {
		t.Errorf("the overlay shows %q, want it hidden", message)
	}
}

func TestPageForwardsTheAgent(t *testing.T) {
	key := newKey(t)
	server := sshdtest.Start(t, key.AuthorizedKey(keyType, ""))
	p := openPage(t, key, server.Addr, server.HostKey)

	// sshd runs on this machine as this user, so the shell sees these files.
	dir := t.TempDir()
	publicKeyPath := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(publicKeyPath, key.AuthorizedKey(keyType, ""), 0o600); err != nil {
		t.Fatal(err)
	}
	message := []byte("a message to sign\n")
	messagePath := filepath.Join(dir, "message")
	if err := os.WriteFile(messagePath, message, 0o600); err != nil {
		t.Fatal(err)
	}

	p.waitForPrompt()
	p.recordOverlay()
	p.typeText(fmt.Sprintf("ssh-add -L && ssh-keygen -Y sign -U -f '%s' -n test '%s' && echo signed-$((1+1))\r", publicKeyPath, messagePath))
	p.waitForScreen("signed-2")

	if got := p.signatures(); got != 2 {
		t.Errorf("the security key made %d signatures, want 2 (the login and the agent's)", got)
	}
	if overlays, want := p.overlays(), "Touch your security key to sign."; !slices.Contains(overlays, want) {
		t.Errorf("the overlay showed %q, want %q among them", overlays, want)
	}
	p.waitForOverlay("")

	check := exec.Command(findSSHKeygen(t), "-Y", "check-novalidate", "-n", "test", "-s", messagePath+".sig")
	check.Stdin = bytes.NewReader(message)
	if output, err := check.CombinedOutput(); err != nil {
		t.Errorf("ssh-keygen -Y check-novalidate: %v\n%s", err, output)
	}
}

func TestPagePassesBytesThroughUnchanged(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPage(t, key, server.addr, server.hostKey)
	s := server.nextSession(t)

	p.typeText("é€😀\r")
	if got, want := s.waitForInput(t, []byte("é€😀\r")), []byte("é€😀\r"); !bytes.Equal(got, want) {
		t.Errorf("the server received %q, want exactly %q", got, want)
	}

	// € split across two writes.
	if _, err := s.Write([]byte{0xe2}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := s.Write([]byte{0x82, 0xac}); err != nil {
		t.Fatal(err)
	}
	p.waitForScreen("€")
}

// recordCopies records the text the page writes to the clipboard in __copied.
const recordCopies = `
window.__copied = [];
Clipboard.prototype.writeText = function (text) {
  window.__copied.push(text);
  return Promise.resolve();
};
`

func TestPageCopiesToTheClipboardForTheDefaultSelectionAndAnyNamingIt(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{initScript: recordCopies})
	s := server.nextSession(t)
	if _, err := s.Write([]byte("prompt$ ")); err != nil {
		t.Fatal(err)
	}
	p.waitForScreen("prompt$")

	var osc52 strings.Builder
	for _, c := range []struct{ selection, text string }{
		{"c", "for c"},
		{"", "for the default"},
		{"pc", "for a list naming c"},
		{"p", "for p only"},
		{"s", "for s only"},
		{"0", "for cut buffer 0"},
		{"c", "last"},
	} {
		osc52.WriteString("\x1b]52;" + c.selection + ";" + base64.StdEncoding.EncodeToString([]byte(c.text)) + "\x07")
	}
	if _, err := s.Write([]byte(osc52.String())); err != nil {
		t.Fatal(err)
	}

	copied := func() []string { return evaluate[[]string](p, `window.__copied`) }
	if !poll(func() bool { c := copied(); return len(c) > 0 && c[len(c)-1] == "last" }) {
		t.Fatalf("the page copied %q within %v, want it to end with %q", copied(), timeout, "last")
	}
	if got, want := copied(), []string{"for c", "for the default", "for a list naming c", "last"}; !slices.Equal(got, want) {
		t.Errorf("the page copied %q, want %q", got, want)
	}
}

// recordOpens records the arguments of each call of window.open in __opened.
const recordOpens = `
window.__opened = [];
window.open = (...args) => {
  window.__opened.push(args);
  return null;
};
`

// recordConfirms records the message of each call of confirm in
// __confirmed, and answers no.
const recordConfirms = `
window.__confirmed = [];
window.confirm = (message) => {
  window.__confirmed.push(String(message));
  return false;
};
`

const (
	// trackMouse has the terminal report presses and releases of the mouse's
	// buttons to the program, in SGR's encoding, as tmux with mouse on does.
	trackMouse = "\x1b[?1000h\x1b[?1006h"
	// clearScreen clears the screen and moves the cursor to its top-left.
	clearScreen = "\x1b[H\x1b[2J"
	// mouseReport starts every report of the mouse in SGR's encoding.
	mouseReport = "\x1b[<"
)

// openPageWithOutput opens the page with options and its relay to a fake
// server, has the server write output, and waits until the screen shows shown.
func openPageWithOutput(t *testing.T, options pageOptions, output, shown string) (*testPage, *fakeSession) {
	t.Helper()
	key := newKey(t)
	server := startFakeServer(t)
	p := openPageWith(t, key, server.addr, server.hostKey, options)
	s := server.nextSession(t)
	if _, err := s.Write([]byte(output)); err != nil {
		t.Fatal(err)
	}
	p.waitForScreen(shown)
	return p, s
}

// writeAndWait has the server write output in the session s, and waits until
// the screen shows shown.
func (p *testPage) writeAndWait(s *fakeSession, output, shown string) {
	p.t.Helper()
	if _, err := s.Write([]byte(output)); err != nil {
		p.t.Fatal(err)
	}
	p.waitForScreen(shown)
}

// opened returns the arguments of each call of window.open that recordOpens
// recorded, once the timers already set have run: the page opens a link from a timer.
func (p *testPage) opened() [][]string {
	p.t.Helper()
	opened, err := chromedp.Run(p.ctx, chromedp.Evaluate[[][]string](
		`new Promise((resolve) => setTimeout(() => resolve(window.__opened)))`, chromedp.EvalAwaitPromise))
	if err != nil {
		p.t.Fatalf("reading the calls of window.open: %v", err)
	}
	return opened
}

// waitForOpened waits until the page has called window.open n times, and
// returns the arguments of each call.
func (p *testPage) waitForOpened(n int) [][]string {
	p.t.Helper()
	var opened [][]string
	if !poll(func() bool {
		opened = p.opened()
		return len(opened) >= n
	}) {
		p.t.Fatalf("the page called window.open %d times within %v, want %d; it opened %q", len(opened), timeout, n, opened)
	}
	return opened
}

// charCenter returns where in the viewport the middle of the character at
// col on the screen's row is, both counted from 0.
func (p *testPage) charCenter(row, col int) (x, y float64) {
	p.t.Helper()
	center := evaluate[[]float64](p, fmt.Sprintf(`(() => {
		const row = document.querySelectorAll(".xterm-rows > div")[%d];
		const walker = document.createTreeWalker(row, NodeFilter.SHOW_TEXT);
		let offset = %d;
		for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
			if (offset < node.length) {
				const range = document.createRange();
				range.setStart(node, offset);
				range.setEnd(node, offset + 1);
				const rect = range.getBoundingClientRect();
				return [rect.left + rect.width / 2, rect.top + rect.height / 2];
			}
			offset -= node.length;
		}
		return null;
	})()`, row, col))
	if center == nil {
		p.t.Fatalf("row %d of the screen has no character at column %d", row, col)
	}
	return center[0], center[1]
}

// linkHovered reports whether xterm.js shows that a link is under the pointer.
func (p *testPage) linkHovered() bool {
	p.t.Helper()
	return evaluate[bool](p, `document.querySelector(".xterm-screen").classList.contains("xterm-cursor-pointer")`)
}

// dispatchMouse dispatches the mouse event that params describe.
func (p *testPage) dispatchMouse(params input.DispatchMouseEventParams) {
	p.t.Helper()
	if _, err := chromedp.Call(p.ctx, input.DispatchMouseEvent, params); err != nil {
		p.t.Fatalf("dispatching %s at (%.0f, %.0f): %v", params.Type, params.X, params.Y, err)
	}
}

// moveMouse moves the pointer to x, y in the viewport, with no button or key held.
func (p *testPage) moveMouse(x, y float64) {
	p.t.Helper()
	p.dispatchMouse(input.DispatchMouseEventParams{Type: input.DispatchMouseEventTypeMouseMoved, X: x, Y: y})
}

// buttonBits are the mouse's buttons, as bits of DispatchMouseEventParams.Buttons.
var buttonBits = map[input.MouseButton]int64{input.MouseButtonLeft: 1, input.MouseButtonMiddle: 4}

// pressMouse presses button at x, y in the viewport, with modifiers held.
func (p *testPage) pressMouse(x, y float64, button input.MouseButton, modifiers chromedp.Modifier) {
	p.t.Helper()
	p.dispatchMouse(input.DispatchMouseEventParams{
		Type:       input.DispatchMouseEventTypeMousePressed,
		X:          x,
		Y:          y,
		Modifiers:  int64(modifiers),
		Button:     button,
		Buttons:    buttonBits[button],
		ClickCount: 1,
	})
}

// dragMouse moves the pointer to x, y in the viewport, with the primary
// button and modifiers held.
func (p *testPage) dragMouse(x, y float64, modifiers chromedp.Modifier) {
	p.t.Helper()
	p.dispatchMouse(input.DispatchMouseEventParams{
		Type:      input.DispatchMouseEventTypeMouseMoved,
		X:         x,
		Y:         y,
		Modifiers: int64(modifiers),
		Buttons:   buttonBits[input.MouseButtonLeft],
	})
}

// releaseMouse lets button go at x, y in the viewport, with modifiers held.
func (p *testPage) releaseMouse(x, y float64, button input.MouseButton, modifiers chromedp.Modifier) {
	p.t.Helper()
	p.dispatchMouse(input.DispatchMouseEventParams{
		Type:       input.DispatchMouseEventTypeMouseReleased,
		X:          x,
		Y:          y,
		Modifiers:  int64(modifiers),
		Button:     button,
		ClickCount: 1,
	})
}

// click presses the primary button at x, y in the viewport and lets it go,
// with modifiers held.
func (p *testPage) click(x, y float64, modifiers chromedp.Modifier) {
	p.t.Helper()
	p.pressMouse(x, y, input.MouseButtonLeft, modifiers)
	p.releaseMouse(x, y, input.MouseButtonLeft, modifiers)
}

// hoverLink moves the pointer onto the character at col on the screen's row,
// waits until xterm.js shows a link under it, and returns where it is.
func (p *testPage) hoverLink(row, col int) (x, y float64) {
	p.t.Helper()
	x, y = p.charCenter(row, col)
	p.moveMouse(x, y)
	if !poll(p.linkHovered) {
		p.t.Fatalf("xterm.js showed no link under the pointer at row %d, column %d within %v", row, col, timeout)
	}
	return x, y
}

// clickCell moves the pointer onto the character at col on the screen's row,
// and clicks there with modifiers held.
func (p *testPage) clickCell(row, col int, modifiers chromedp.Modifier) {
	p.t.Helper()
	x, y := p.charCenter(row, col)
	p.moveMouse(x, y)
	p.click(x, y, modifiers)
}

// pointAt moves the pointer onto the character at col on the screen's row,
// and returns where it is.
func (p *testPage) pointAt(row, col int) (x, y float64) {
	p.t.Helper()
	x, y = p.charCenter(row, col)
	p.moveMouse(x, y)
	return x, y
}

// typeMarker types marker, and returns what the server received before it.
func (p *testPage) typeMarker(s *fakeSession, marker string) []byte {
	p.t.Helper()
	p.typeText(marker)
	input := s.waitForInput(p.t, []byte(marker))
	return input[:bytes.Index(input, []byte(marker))]
}

func TestPageOpensALinkClickedWithShiftAltOrMetaWithoutTellingTheProgram(t *testing.T) {
	link := "https://example.com/a?b#c"
	p, s := openPageWithOutput(t, pageOptions{initScript: recordOpens}, trackMouse+clearScreen+link, link)

	modifiers := []chromedp.Modifier{chromedp.ModifierShift, chromedp.ModifierAlt, chromedp.ModifierMeta}
	for _, modifier := range modifiers {
		p.clickCell(0, 5, modifier)
	}

	if before := p.typeMarker(s, "after-the-clicks"); bytes.Contains(before, []byte(mouseReport)) {
		t.Errorf("the server received %q for the clicks, want no report of the mouse", before)
	}
	var want [][]string
	for range modifiers {
		want = append(want, []string{link, "_blank", "noopener,noreferrer"})
	}
	if got := p.waitForOpened(len(want)); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("the page opened %q, want %q", got, want)
	}
}

func TestPageLeavesAPlainClickOnALinkToTheProgram(t *testing.T) {
	link := "https://example.com/a?b#c"
	p, s := openPageWithOutput(t, pageOptions{initScript: recordOpens}, trackMouse+clearScreen+link, link)

	p.clickCell(0, 5, chromedp.ModifierNone)
	// The press and the release of the primary button on column 6 of row 1.
	s.waitForInput(t, []byte(mouseReport+"0;6;1M"))
	s.waitForInput(t, []byte(mouseReport+"0;6;1m"))
	if opened := p.opened(); len(opened) != 0 {
		t.Errorf("the page opened %q for a plain click, want nothing", opened)
	}
}

func TestPageOpensALinkCtrlClickedUnlessThePlatformIsApples(t *testing.T) {
	link := "https://example.com/a?b#c"
	p, s := openPageWithOutput(t, pageOptions{initScript: recordOpens}, trackMouse+clearScreen+link, link)
	platform := evaluate[string](p, `navigator.platform`)
	apple := regexp.MustCompile(`Mac|iPhone|iPad`).MatchString(platform)

	p.clickCell(0, 5, chromedp.ModifierCtrl)

	// On Apple's systems, Ctrl-click is the context menu's click, which may reach the program.
	before := p.typeMarker(s, "after-the-click")
	var opened [][]string
	if apple {
		opened = p.opened()
	} else {
		opened = p.waitForOpened(1)
	}
	switch {
	case apple && len(opened) != 0:
		t.Errorf("on %s, the page opened %q for a Ctrl-click, want nothing", platform, opened)
	case !apple && !slices.EqualFunc(opened, [][]string{{link, "_blank", "noopener,noreferrer"}}, slices.Equal):
		t.Errorf("on %s, the page opened %q for a Ctrl-click, want %s once", platform, opened, link)
	case !apple && bytes.Contains(before, []byte(mouseReport)):
		t.Errorf("on %s, the server received %q for the Ctrl-click, want no report of the mouse", platform, before)
	}
}

func TestPageOpensNoOSC8LinkAndNeverAsks(t *testing.T) {
	output := clearScreen +
		"\x1b]8;;https://example.com/osc\x1b\\label\x1b]8;;\x1b\\\r\n" +
		"\x1b]8;;https://example.com/behind\x1b\\https://example.com/shown\x1b]8;;\x1b\\"
	p, _ := openPageWithOutput(t, pageOptions{initScript: recordOpens + recordConfirms}, output, "shown")

	p.clickCell(0, 2, chromedp.ModifierShift)
	// xterm.js activates the link itself on a plain click; its own handler would ask with confirm.
	p.clickCell(0, 2, chromedp.ModifierNone)
	// A label that is a web address opens as one.
	p.clickCell(1, 5, chromedp.ModifierShift)

	want := [][]string{{"https://example.com/shown", "_blank", "noopener,noreferrer"}}
	if got := p.waitForOpened(len(want)); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("the page opened %q, want %q", got, want)
	}
	if confirmed := evaluate[[]string](p, `window.__confirmed`); len(confirmed) != 0 {
		t.Errorf("the page asked %q, want no question", confirmed)
	}
}

func TestPageOpensTheLinkTheScreenShowsUnderThePointer(t *testing.T) {
	// The pointer rests on row 0 off any link, so xterm.js keeps row 0's links
	// while the program redraws it.
	redrawn := func(t *testing.T, before, after, shown string) *testPage {
		t.Helper()
		p, s := openPageWithOutput(t, pageOptions{initScript: recordOpens}, clearScreen+before, before)
		p.pointAt(0, 1)
		p.writeAndWait(s, after, shown)
		return p
	}

	t.Run("a row redrawn under a pointer resting off its link", func(t *testing.T) {
		p := redrawn(t, "xxxx https://example.com/old-one", clearScreen+"yyyy https://example.com/new-one", "new-one")
		p.clickCell(0, 10, chromedp.ModifierShift)
		want := [][]string{{"https://example.com/new-one", "_blank", "noopener,noreferrer"}}
		if got := p.waitForOpened(1); !slices.EqualFunc(got, want, slices.Equal) {
			t.Errorf("the page opened %q, want %q", got, want)
		}
	})

	t.Run("a longer URL now shown where a shorter one was", func(t *testing.T) {
		p := redrawn(t, "xxxx http://localhost:5173/", clearScreen+"yyyy http://localhost:5173/settings", "settings")
		p.clickCell(0, 10, chromedp.ModifierShift)
		want := [][]string{{"http://localhost:5173/settings", "_blank", "noopener,noreferrer"}}
		if got := p.waitForOpened(1); !slices.EqualFunc(got, want, slices.Equal) {
			t.Errorf("the page opened %q, want %q", got, want)
		}
	})

	t.Run("a wrapped link partly redrawn", func(t *testing.T) {
		key := newKey(t)
		server := startFakeServer(t)
		p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{initScript: recordOpens})
		s := server.nextSession(t)
		cols, _ := s.size()
		// It fills row 2 and goes on into row 3.
		link := "https://example.com/" + strings.Repeat("a", cols-len("https://example.com/")) + "tail123456"
		p.writeAndWait(s, clearScreen+"row zero\r\nrow one\r\n"+link, "tail123456")
		// xterm.js holds the link as the one under the pointer while row 3 is redrawn.
		x, y := p.hoverLink(3, 2)
		p.writeAndWait(s, "\x1b[4;1H\x1b[2Kplain text here", "plain text here")

		p.click(x, y, chromedp.ModifierShift)
		p.typeMarker(s, "after-the-click")
		if opened := p.opened(); len(opened) != 0 {
			t.Errorf("the page opened %q, want nothing", opened)
		}
	})

	t.Run("a full scrollback", func(t *testing.T) {
		key := newKey(t)
		server := startFakeServer(t)
		p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{initScript: recordOpens})
		s := server.nextSession(t)
		_, rows := s.size()
		// More lines than the screen and xterm.js's scrollback of 1000 hold, so
		// new output moves every line's text up a row without moving the line.
		var output strings.Builder
		lines := 1000 + rows + 50
		for i := range lines {
			fmt.Fprintf(&output, "\r\nGET https://example.com/r%05d", i)
		}
		p.writeAndWait(s, output.String(), fmt.Sprintf("r%05d", lines-1))
		p.pointAt(3, 1)
		output.Reset()
		for i := range 5 {
			fmt.Fprintf(&output, "\r\nGET https://example.com/s%05d", i)
		}
		p.writeAndWait(s, output.String(), "s00004")

		row := strings.Fields(strings.Split(p.screen(), "\n")[3])
		if len(row) != 2 {
			t.Fatalf("row 3 shows %q, want GET and a URL", row)
		}
		p.clickCell(3, 12, chromedp.ModifierShift)
		want := [][]string{{row[1], "_blank", "noopener,noreferrer"}}
		if got := p.waitForOpened(1); !slices.EqualFunc(got, want, slices.Equal) {
			t.Errorf("the page opened %q, want %q, which row 3 shows", got, want)
		}
	})
}

func TestPageOpensAWrappedLinkWhoseWideCharacterWrappedEarly(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{initScript: recordOpens})
	s := server.nextSession(t)
	cols, _ := s.size()
	prefix := "https://example.com/wiki/"
	// The first row has room for all but its last column, and 日 takes two.
	middle := strings.Repeat("a", cols-1-len(prefix))
	p.writeAndWait(s, clearScreen+prefix+middle+"日本語\r\nend", "end")

	p.clickCell(0, 5, chromedp.ModifierShift)
	// 日本語, as the URL's href writes it.
	want := [][]string{{prefix + middle + "%E6%97%A5%E6%9C%AC%E8%AA%9E", "_blank", "noopener,noreferrer"}}
	if got := p.waitForOpened(1); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("the page opened %q, want %q", got, want)
	}
}

func TestPageOpensAWrappedLinkPressedOnOneRowAndReleasedOnTheNext(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{initScript: recordOpens})
	s := server.nextSession(t)
	cols, _ := s.size()
	// It fills row 0 and goes on into row 1.
	link := "https://example.com/" + strings.Repeat("c", cols-len("https://example.com/")) + "rest12345"
	p.writeAndWait(s, clearScreen+link+"\r\nend", "end")

	x, y := p.pointAt(0, 5)
	p.pressMouse(x, y, input.MouseButtonLeft, chromedp.ModifierShift)
	x, y = p.charCenter(1, 3)
	p.dragMouse(x, y, chromedp.ModifierShift)
	p.releaseMouse(x, y, input.MouseButtonLeft, chromedp.ModifierShift)

	want := [][]string{{link, "_blank", "noopener,noreferrer"}}
	if got := p.waitForOpened(1); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("the page opened %q, want %q", got, want)
	}
}

func TestPageOpensALinkThatEndsInTheBottomRightCorner(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{initScript: recordOpens})
	s := server.nextSession(t)
	cols, rows := s.size()
	link := "https://example.com/" + strings.Repeat("b", cols-len("https://example.com/"))
	if _, err := s.Write([]byte(fmt.Sprintf("%s\x1b[%d;1H%s", clearScreen, rows, link))); err != nil {
		t.Fatal(err)
	}
	p.waitForScreen(link)

	p.clickCell(rows-1, 5, chromedp.ModifierShift)
	want := [][]string{{link, "_blank", "noopener,noreferrer"}}
	if got := p.waitForOpened(1); !slices.EqualFunc(got, want, slices.Equal) {
		t.Errorf("the page opened %q, want %q", got, want)
	}
}

func TestPageTreatsTheSameURLOnAnotherRowAsAnotherLink(t *testing.T) {
	link := "https://example.com/same"
	p, s := openPageWithOutput(t, pageOptions{initScript: recordOpens}, clearScreen+link+"\r\n\r\n"+link, link)

	x, y := p.pointAt(0, 5)
	p.pressMouse(x, y, input.MouseButtonLeft, chromedp.ModifierShift)
	x, y = p.charCenter(2, 5)
	p.dragMouse(x, y, chromedp.ModifierShift)
	p.releaseMouse(x, y, input.MouseButtonLeft, chromedp.ModifierShift)

	p.typeMarker(s, "after-the-click")
	if opened := p.opened(); len(opened) != 0 {
		t.Errorf("the page opened %q for a press on one link and a release on another, want nothing", opened)
	}
}

func TestPageOpensALinkWhereverXtermJSUnderlinesIt(t *testing.T) {
	link := "https://example.com/abc"
	p, s := openPageWithOutput(t, pageOptions{initScript: recordOpens}, clearScreen+link+" tail\r\nplain", "plain")
	cols, rows := s.size()
	screen := evaluate[[]float64](p, `(() => {
		const rect = document.querySelector(".xterm-screen").getBoundingClientRect();
		return [rect.left, rect.top, rect.width, rect.height];
	})()`)
	left, top := screen[0], screen[1]
	cellWidth, cellHeight := screen[2]/float64(cols), screen[3]/float64(rows)

	// Whole pixels on each side of the link's right end and of its row's
	// bottom border, where the cell under the pointer is a matter of rounding.
	var points [][2]float64
	linkEnd, rowEnd := left+float64(len(link))*cellWidth, top+cellHeight
	for d := -1.0; d <= 1; d++ {
		points = append(points, [2]float64{math.Floor(linkEnd) + d, top + cellHeight/2})
		points = append(points, [2]float64{left + 5*cellWidth, math.Floor(rowEnd) + d})
	}
	for _, point := range points {
		x, y := point[0], point[1]
		p.moveMouse(x, y)
		// xterm.js looks the pointer's link up in a task of its own.
		if _, err := chromedp.Run(p.ctx, chromedp.Evaluate[bool](
			`new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve(true))))`,
			chromedp.EvalAwaitPromise)); err != nil {
			t.Fatalf("waiting for two frames: %v", err)
		}
		hovered := p.linkHovered()
		before := len(p.opened())
		p.click(x, y, chromedp.ModifierShift)
		p.typeMarker(s, fmt.Sprintf("after-%v-%v", x, y))
		if opened := len(p.opened()) > before; opened != hovered {
			t.Errorf("at (%v, %v) xterm.js underlined a link: %v; a Shift-click opened one: %v", x, y, hovered, opened)
		}
	}
}

func TestPageOpensNothingWhenALinkClickIsReleasedOffTheLink(t *testing.T) {
	link := "https://example.com/a"
	p, s := openPageWithOutput(t, pageOptions{initScript: recordOpens}, trackMouse+clearScreen+link+"\r\n\r\nplain", "plain")

	x, y := p.pointAt(0, 5)
	p.pressMouse(x, y, input.MouseButtonLeft, chromedp.ModifierShift)
	x, y = p.charCenter(2, 2)
	p.dragMouse(x, y, chromedp.ModifierShift)
	p.releaseMouse(x, y, input.MouseButtonLeft, chromedp.ModifierShift)

	if before := p.typeMarker(s, "after-the-click"); bytes.Contains(before, []byte(mouseReport)) {
		t.Errorf("the server received %q for the click, want no report of the mouse", before)
	}
	if opened := p.opened(); len(opened) != 0 {
		t.Errorf("the page opened %q for a click released off the link, want nothing", opened)
	}
}

func TestPageLetsTheProgramHaveClicksThatArentLinkClicks(t *testing.T) {
	link := "https://example.com/a"
	p, s := openPageWithOutput(t, pageOptions{initScript: recordOpens}, trackMouse+clearScreen+link+"\r\n\r\nplain", "plain")

	// Alt, as off Apple's systems xterm.js never reports a Shift-click.
	x, y := p.pointAt(2, 2)
	p.click(x, y, chromedp.ModifierAlt)
	// The press and the release of the primary button with Alt, on column 3 of row 3.
	s.waitForInput(t, []byte(mouseReport+"8;3;3M"))
	s.waitForInput(t, []byte(mouseReport+"8;3;3m"))

	x, y = p.pointAt(0, 5)
	p.pressMouse(x, y, input.MouseButtonMiddle, chromedp.ModifierAlt)
	p.releaseMouse(x, y, input.MouseButtonMiddle, chromedp.ModifierAlt)
	// The middle button with Alt, on column 6 of row 1.
	s.waitForInput(t, []byte(mouseReport+"9;6;1M"))
	s.waitForInput(t, []byte(mouseReport+"9;6;1m"))

	if opened := p.opened(); len(opened) != 0 {
		t.Errorf("the page opened %q, want nothing", opened)
	}
}

func TestPageOpensLinksToLocalhostAtTheLocalhostURL(t *testing.T) {
	link := "http://localhost:5173/a?b#c"
	tests := []struct {
		name         string
		localhostURL string
		want         string
	}{
		{"with a localhost URL", "https://dev-{port}.example.com", "https://dev-5173.example.com/a?b#c"},
		{"without one", "", link},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p, _ := openPageWithOutput(t, pageOptions{initScript: recordOpens, localhostURL: test.localhostURL}, clearScreen+link, link)

			p.clickCell(0, 5, chromedp.ModifierShift)
			want := [][]string{{test.want, "_blank", "noopener,noreferrer"}}
			if got := p.waitForOpened(1); !slices.EqualFunc(got, want, slices.Equal) {
				t.Errorf("the page opened %q, want %q", got, want)
			}
		})
	}
}

func TestPageResolvesWhereEachLinkOpens(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPage(t, key, server.addr, server.hostKey)

	const template = "https://dev-{port}.example.com"
	tests := []struct {
		uri, localhostURL string
		want              string // "" for null, nothing to open
	}{
		{"http://localhost:5173/", template, "https://dev-5173.example.com/"},
		{"http://localhost:5173", template, "https://dev-5173.example.com/"},
		{"http://127.0.0.1:8000/x?y=1#z", template, "https://dev-8000.example.com/x?y=1#z"},
		{"http://127.1.2.3:9/", template, "https://dev-9.example.com/"},
		{"http://[::1]:3000/", template, "https://dev-3000.example.com/"},
		{"http://0.0.0.0:8000/", template, "https://dev-8000.example.com/"},
		{"http://[::]:8000/", template, "https://dev-8000.example.com/"},
		{"http://app.localhost:3000/", template, "https://dev-3000.example.com/"},
		{"http://localhost/", template, "https://dev-80.example.com/"},
		{"https://localhost/", template, "https://dev-443.example.com/"},
		{"http://user:pw@localhost:3000/p", template, "https://dev-3000.example.com/p"},
		{"http://localhostx:1/", template, "http://localhostx:1/"},
		{"http://192.168.1.5:5173/", template, "http://192.168.1.5:5173/"},
		{"https://example.com/a", template, "https://example.com/a"},
		{"http://localhost:5173/", "", "http://localhost:5173/"},
		{"http://localhost:5173/", "http://example.com:{port}", "http://example.com:5173/"},
		{"ftp://localhost/", template, ""},
		{"javascript:alert(1)", template, ""},
		{"not a url", template, ""},
	}
	var calls [][2]string
	for _, test := range tests {
		calls = append(calls, [2]string{test.uri, test.localhostURL})
	}
	encoded, err := json.Marshal(calls)
	if err != nil {
		t.Fatal(err)
	}
	expression := fmt.Sprintf(`import("./links.mjs").then(({ resolveLink }) =>
		%s.map(([uri, localhostURL]) => resolveLink(uri, localhostURL)))`, encoded)
	resolved, err := chromedp.Run(p.ctx, chromedp.Evaluate[[]*string](expression, chromedp.EvalAwaitPromise))
	if err != nil {
		t.Fatalf("calling resolveLink: %v", err)
	}
	if len(resolved) != len(tests) {
		t.Fatalf("resolveLink returned %d results, want %d", len(resolved), len(tests))
	}
	for i, test := range tests {
		t.Run(fmt.Sprintf("%s with %q", test.uri, test.localhostURL), func(t *testing.T) {
			got := resolved[i]
			switch {
			case test.want == "" && got != nil:
				t.Errorf("resolveLink returned %q, want null", *got)
			case test.want != "" && got == nil:
				t.Errorf("resolveLink returned null, want %q", test.want)
			case test.want != "" && *got != test.want:
				t.Errorf("resolveLink returned %q, want %q", *got, test.want)
			}
		})
	}
}

func TestPageShowsEverythingAFloodOfOutputSends(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPage(t, key, server.addr, server.hostKey)
	s := server.nextSession(t)

	var flood bytes.Buffer
	for i := 0; flood.Len() < 4<<20; i++ {
		fmt.Fprintf(&flood, "line %d\r\n", i)
	}
	flood.WriteString("end-of-flood\r\n")
	written := make(chan error, 1)
	go func() {
		_, err := s.Write(flood.Bytes())
		written <- err
	}()

	p.waitForScreen("end-of-flood")
	if err := <-written; err != nil {
		t.Errorf("writing the flood: %v", err)
	}
}

func TestPageTellsTheServerTheTerminalsSize(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPage(t, key, server.addr, server.hostKey)
	s := server.nextSession(t)

	cols, rows := s.size()
	if domRows := p.domRows(); rows != domRows || cols <= 0 {
		t.Errorf("pty-req asked for %d columns by %d rows; want the terminal's %d rows and some columns", cols, rows, domRows)
	}

	viewport := evaluate[[]int](p, `[innerWidth, innerHeight]`)
	p.resizeViewport(viewport[0]/2, viewport[1]/2)
	newCols, newRows := s.waitForSize(t, func(c, r int) bool { return c < cols && r < rows })
	if domRows := p.domRows(); newRows != domRows {
		t.Errorf("window-change asked for %d columns by %d rows; want the terminal's %d rows", newCols, newRows, domRows)
	}
}

func TestPageOffersToReconnectWhenTheSessionEnds(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPage(t, key, server.addr, server.hostKey)

	first := server.nextSession(t)
	if _, err := first.Write([]byte("from-the-first-session\r\n")); err != nil {
		t.Fatal(err)
	}
	p.waitForScreen("from-the-first-session")
	first.Exit(3)
	if _, button := p.waitForOverlay("The session ended with exit status 3."); !button {
		t.Error("the Reconnect button is hidden after the session ended")
	}

	p.clickReconnect()
	second := server.nextSession(t)
	if _, err := second.Write([]byte("from-the-second-session\r\n")); err != nil {
		t.Fatal(err)
	}
	if screen := p.waitForScreen("from-the-second-session"); strings.Contains(screen, "from-the-first-session") {
		t.Errorf("the screen still shows the first session's output:\n%s", screen)
	}
	p.waitForOverlay("")
}

func TestPageShowsWhyItCouldntLogIn(t *testing.T) {
	key := newKey(t)
	server := startKeyAskingServer(t)
	p := openPage(t, key, server.addr, otherHostKey(t))

	message, button := p.waitForOverlay("Couldn't log in:")
	t.Logf("the overlay says %q", message)
	if !button {
		t.Error("the Reconnect button is hidden after the login failed")
	}
	if got := p.signatures(); got != 0 {
		t.Errorf("the security key made %d signatures, want none", got)
	}
}

func TestPageCancelsTheSecurityKeysRequestWhenTheSessionEnds(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPage(t, key, server.addr, server.hostKey)
	first := server.nextSession(t)

	p.setPresence(false)
	signed := make(chan error, 1)
	go func() {
		_, err := first.AgentSign([]byte("data to sign"))
		signed <- err
	}()
	p.waitForOverlay("Touch your security key to sign.")
	first.Exit(0)
	p.waitForOverlay("The session ended.")
	select {
	case err := <-signed:
		if err == nil {
			t.Error("the agent signed, though the security key wasn't touched")
		}
	case <-time.After(timeout):
		t.Fatalf("the agent's signature didn't fail within %v of the session's end", timeout)
	}

	p.setPresence(true)
	p.clickReconnect()
	second := server.nextSession(t)
	go func() {
		_, err := second.AgentSign([]byte("more data to sign"))
		signed <- err
	}()
	select {
	case err := <-signed:
		if err != nil {
			t.Errorf("the agent didn't sign in the new session: %v", err)
		}
	case <-time.After(timeout):
		t.Fatalf("the agent didn't sign in the new session within %v", timeout)
	}
}

func TestPageGivesUpTheLoginWhenTheRelayHangsUp(t *testing.T) {
	key := newKey(t)
	server := startKeyAskingServer(t)
	p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{untouched: true})

	// The server checks the key when the client offers it, before the
	// signature. Half a second after the check, the client has the server's
	// PK_OK and waits for the security key, which nobody touches.
	if !poll(func() bool { return server.keyQueries.Load() > 0 }) {
		t.Fatalf("the client didn't offer its key within %v", timeout)
	}
	time.Sleep(500 * time.Millisecond)
	server.closeConnections()
	if _, button := p.waitForOverlay("Couldn't log in:"); !button {
		t.Error("the Reconnect button is hidden after the login failed")
	}

	p.setPresence(true)
	p.clickReconnect()
	if !poll(func() bool { return p.signatures() == 1 }) {
		t.Fatalf("the security key didn't sign the next login within %v; the abandoned request may still be pending", timeout)
	}
	p.waitForOverlay("Couldn't log in:")
}

func TestPageSaysWhenTheBrowserCantUseASecurityKey(t *testing.T) {
	key := newKey(t)
	server := startKeyAskingServer(t)
	p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{
		// As on a page served over plain HTTP from another host than localhost.
		initScript: `Object.defineProperty(Navigator.prototype, "credentials", {get: () => undefined});`,
	})

	message, button := p.waitForOverlay("Couldn't log in:")
	if !strings.Contains(message, "HTTPS or from localhost") {
		t.Errorf("the overlay says %q, want it to say to serve the page over HTTPS or from localhost", message)
	}
	if !button {
		t.Error("the Reconnect button is hidden after the login failed")
	}
}

func TestPageSaysWhenTheBrowserReturnsNoCredential(t *testing.T) {
	key := newKey(t)
	server := startKeyAskingServer(t)
	p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{
		initScript: `CredentialsContainer.prototype.get = () => Promise.resolve(null);`,
	})

	message, button := p.waitForOverlay("Couldn't log in:")
	if !strings.Contains(message, "the browser returned no credential") {
		t.Errorf("the overlay says %q, want it to say that the browser returned no credential", message)
	}
	if !button {
		t.Error("the Reconnect button is hidden after the login failed")
	}
}

func TestPageSaysWhenTheConnectionIsLost(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPage(t, key, server.addr, server.hostKey)
	server.nextSession(t)

	server.closeConnections()
	if _, button := p.waitForOverlay("The connection to the server was lost."); !button {
		t.Error("the Reconnect button is hidden after the connection was lost")
	}
}

func TestPageSaysWhichSignalEndedTheSession(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPage(t, key, server.addr, server.hostKey)

	server.nextSession(t).ExitSignal("TERM")
	if _, button := p.waitForOverlay("The session ended: signal TERM."); !button {
		t.Error("the Reconnect button is hidden after the session ended")
	}
}

func TestPageSaysWhenItCantReachTheServer(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{noRelay: true})

	message, button := p.waitForOverlay("Couldn't reach the server:")
	t.Logf("the overlay says %q", message)
	if !button {
		t.Error("the Reconnect button is hidden though the server couldn't be reached")
	}
}

func TestPageSaysWhenItCantLoadTheClient(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(builtPage(t))); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "shelloe.wasm")); err != nil {
		t.Fatal(err)
	}
	// The browser logs the failed request itself, but not with console.error,
	// so the test's check for errors doesn't see it.
	p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{dir: dir})

	message, button := p.waitForOverlay("Couldn't load shelloe:")
	t.Logf("the overlay says %q", message)
	if button {
		t.Error("the Reconnect button is shown, though reconnecting can't load the client")
	}
	if evaluate[bool](p, `document.querySelector(".xterm") !== null`) {
		t.Error("the page opened a terminal, though the client didn't load")
	}
}

func TestPageSaysWhenTheClientStops(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPage(t, key, server.addr, server.hostKey)
	server.nextSession(t)

	// connect without its options panics, which ends the client.
	p.do("stopping the client", chromedp.Evaluate[chromedp.Void](`setTimeout(() => shelloe.connect())`))
	if _, button := p.waitForOverlay("The shelloe client stopped. Reload the page."); button {
		t.Error("the Reconnect button is shown, though the client has stopped")
	}
	logged := p.takeErrors()
	if !slices.ContainsFunc(logged, func(e string) bool { return strings.HasPrefix(e, "console.log: panic:") }) {
		t.Errorf("the page logged %q, want the client's panic among them", logged)
	}
}

// holdWrites stands in for a terminal that hasn't processed anything yet: the
// client's writes wait in __held, their done uncalled, until __release passes
// them on to the page's terminal. __earlyDone counts the dones called before
// the write that was handed them returned.
const holdWrites = `
(() => {
  window.__holding = true;
  window.__held = [];
  window.__earlyDone = 0;
  let pageWrite;
  const passOn = (bytes, done) => {
    let returned = false;
    pageWrite(bytes, () => {
      if (!returned) {
        __earlyDone++;
      }
      done();
    });
    returned = true;
  };
  window.__release = () => {
    __holding = false;
    for (const [bytes, done] of __held) {
      passOn(bytes, done);
    }
  };
  let client;
  Object.defineProperty(globalThis, "shelloe", {
    configurable: true,
    get: () => client,
    set: (real) => {
      client = {
        connect: (options) => {
          pageWrite = options.write;
          const write = (bytes, done) => {
            if (__holding) {
              __held.push([bytes, done]);
            } else {
              passOn(bytes, done);
            }
          };
          return real.connect({...options, write});
        },
      };
    },
  });
})();
`

func TestPageWaitsForTheTerminalBeforeReadingMore(t *testing.T) {
	key := newKey(t)
	server := startFakeServer(t)
	p := openPageWith(t, key, server.addr, server.hostKey, pageOptions{initScript: holdWrites})
	s := server.nextSession(t)

	var output bytes.Buffer
	for i := 0; output.Len() < 8<<20; i++ {
		fmt.Fprintf(&output, "line %d\r\n", i)
	}
	output.WriteString("end-of-output\r\n")
	written := make(chan error, 1)
	go func() {
		_, err := s.Write(output.Bytes())
		written <- err
	}()

	held := func() int { return evaluate[int](p, `window.__held.length`) }
	if !poll(func() bool { return held() >= flowcontrol.ChunksInFlight }) {
		t.Fatalf("the client passed %d chunks to the terminal within %v, want %d", held(), timeout, flowcontrol.ChunksInFlight)
	}
	// The SSH window, 2 MB, and the chunks in the terminal hold far less than the output.
	time.Sleep(500 * time.Millisecond)
	if n := held(); n != flowcontrol.ChunksInFlight {
		t.Fatalf("the client passed %d chunks to a terminal that had processed none, want %d", n, flowcontrol.ChunksInFlight)
	}
	select {
	case err := <-written:
		t.Fatalf("the server wrote all its output (error: %v) while the terminal had processed none of it", err)
	default:
	}

	p.do("releasing the terminal", chromedp.Evaluate[chromedp.Void](`__release()`))
	select {
	case err := <-written:
		if err != nil {
			t.Fatalf("writing the output: %v", err)
		}
	case <-time.After(timeout):
		t.Fatalf("the server's write didn't return within %v of the terminal processing its chunks", timeout)
	}
	p.waitForScreen("end-of-output")
	if early := evaluate[int](p, `window.__earlyDone`); early != 0 {
		t.Errorf("the terminal called done %d times before it had processed the chunk", early)
	}
}

// recordFontLoading records when the client sets globalThis.shelloe, in
// __clientAt, and when the terminal opens, in __terminalAt. __fontWarnings
// holds what the page passes to console.warn, and __facesLoaded counts the
// font faces that have loaded.
const recordFontLoading = `
(() => {
  window.__fontWarnings = [];
  window.__facesLoaded = 0;
  let client;
  Object.defineProperty(globalThis, "shelloe", {
    configurable: true,
    get: () => client,
    set: (value) => {
      if (window.__clientAt === undefined) {
        window.__clientAt = performance.now();
      }
      client = value;
    },
  });
  new MutationObserver((records, observer) => {
    if (document.querySelector("#terminal .xterm") !== null) {
      window.__terminalAt = performance.now();
      observer.disconnect();
    }
  }).observe(document, {childList: true, subtree: true});
  const consoleWarn = console.warn;
  console.warn = (...args) => {
    __fontWarnings.push(args.join(" "));
    consoleWarn.apply(console, args);
  };
  const load = FontFace.prototype.load;
  FontFace.prototype.load = function () {
    const loading = load.call(this);
    loading.then(() => __facesLoaded++, () => {});
    return loading;
  };
})();
`

// hasFontFace reports whether the document has a face of the family shelloe.
func (p *testPage) hasFontFace() bool {
	p.t.Helper()
	return evaluate[bool](p, `[...document.fonts].some((face) => face.family === "shelloe")`)
}

func TestPageDrawsTheTerminalInTheServedFont(t *testing.T) {
	p := openPageShowingAPrompt(t, pageOptions{font: page.Font{Regular: writeFontFile(t, gomono.TTF)}})

	if family := p.terminalFont(); !strings.HasPrefix(strings.TrimLeft(family, `"`), "shelloe") {
		t.Errorf("the terminal's font-family is %s, want it to start with shelloe", family)
	}
	if !evaluate[bool](p, `[...document.fonts].some((face) => face.family === "shelloe" && face.status === "loaded")`) {
		t.Error("the document has no loaded face of the family shelloe")
	}
}

func TestPageLoadsEveryStyleOfTheFont(t *testing.T) {
	p := openPageShowingAPrompt(t, pageOptions{font: page.Font{
		Regular:    writeFontFile(t, gomono.TTF),
		Bold:       writeFontFile(t, gomonobold.TTF),
		Italic:     writeFontFile(t, gomonoitalic.TTF),
		BoldItalic: writeFontFile(t, gomonobolditalic.TTF),
	}})

	faces := evaluate[[]string](p, `[...document.fonts]
		.filter((face) => face.family === "shelloe" && face.status === "loaded")
		.map((face) => face.weight + " " + face.style)`)
	slices.Sort(faces)
	if want := []string{"bold italic", "bold normal", "normal italic", "normal normal"}; !slices.Equal(faces, want) {
		t.Errorf("the document's loaded faces of shelloe are %q (weight and style), want %q", faces, want)
	}
}

func TestPageUsesTheSystemFontWhenTheFontIsSlow(t *testing.T) {
	p := openPageShowingAPrompt(t, pageOptions{
		font:       page.Font{Regular: writeFontFile(t, gomono.TTF)},
		fontsHeld:  make(chan struct{}),
		initScript: recordFontLoading,
	})

	if family := p.terminalFont(); strings.Contains(family, "shelloe") {
		t.Errorf("the terminal's font-family is %s, want the system's monospace font", family)
	}
	clientAt := evaluate[float64](p, `window.__clientAt`)
	terminalAt := evaluate[float64](p, `window.__terminalAt`)
	if terminalAt < 1000 {
		t.Errorf("the terminal opened %.0f ms after the page started loading, want 1000 ms or later", terminalAt)
	}
	if waited := terminalAt - max(clientAt, 1000); waited >= 500 {
		t.Errorf("the terminal opened %.0f ms after the client had loaded (at %.0f ms) and 1000 ms had passed, want less than 500 ms", waited, clientAt)
	}
}

func TestPageUsesTheSystemFontWhenOneStyleIsSlow(t *testing.T) {
	bold := sha256.Sum256(gomonobold.TTF)
	p := openPageShowingAPrompt(t, pageOptions{
		font: page.Font{
			Regular:    writeFontFile(t, gomono.TTF),
			Bold:       writeFontFile(t, gomonobold.TTF),
			Italic:     writeFontFile(t, gomonoitalic.TTF),
			BoldItalic: writeFontFile(t, gomonobolditalic.TTF),
		},
		fontsHeld:  make(chan struct{}),
		heldFont:   "/fonts/" + hex.EncodeToString(bold[:]) + ".ttf",
		initScript: recordFontLoading,
	})

	if family := p.terminalFont(); strings.Contains(family, "shelloe") {
		t.Errorf("the terminal's font-family is %s, want the system's monospace font", family)
	}
	if p.hasFontFace() {
		t.Error("the document has a face of the family shelloe, though the bold face hasn't arrived")
	}
	if loaded := evaluate[int](p, `window.__facesLoaded`); loaded < 3 {
		t.Errorf("%d faces loaded, want the 3 that weren't held", loaded)
	}
}

func TestPageKeepsTheSystemFontWhenTheFontArrivesLate(t *testing.T) {
	fontsHeld := make(chan struct{})
	p := openPageShowingAPrompt(t, pageOptions{
		font:       page.Font{Regular: writeFontFile(t, gomono.TTF)},
		fontsHeld:  fontsHeld,
		initScript: recordFontLoading,
	})

	close(fontsHeld)
	if !poll(func() bool { return evaluate[int](p, `window.__facesLoaded`) == 1 }) {
		t.Fatalf("the font didn't load within %v of arriving", timeout)
	}
	if family := p.terminalFont(); strings.Contains(family, "shelloe") {
		t.Errorf("the terminal's font-family is %s, want the system's monospace font", family)
	}
	if p.hasFontFace() {
		t.Error("the document has a face of the family shelloe, which arrived after the terminal opened")
	}
}

func TestPageUsesTheSystemFontWhenTheFontIsBroken(t *testing.T) {
	// The server takes it for TrueType, and the browser can't read it.
	broken := append([]byte("\x00\x01\x00\x00"), bytes.Repeat([]byte("not a font "), 100)...)
	p := openPageShowingAPrompt(t, pageOptions{
		font:       page.Font{Regular: writeFontFile(t, broken)},
		initScript: recordFontLoading,
	})

	if family := p.terminalFont(); strings.Contains(family, "shelloe") {
		t.Errorf("the terminal's font-family is %s, want the system's monospace font", family)
	}
	warnings := evaluate[[]string](p, `window.__fontWarnings`)
	if len(warnings) != 1 || !strings.Contains(warnings[0], "Couldn't load the font") {
		t.Errorf("the page warned %q, want one warning that it couldn't load the font", warnings)
	}
}
