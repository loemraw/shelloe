package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
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

// builtPage is the directory TestMain builds the page in, unless buildError says why it couldn't.
var (
	builtPage  string
	buildError error
)

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	dir, err := os.MkdirTemp("", "shelloe-page-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)
	builtPage = dir
	buildError = buildPage(dir)
	defer stopBrowser()
	return m.Run()
}

// buildPage copies the page's files into dir and builds the client next to them.
func buildPage(dir string) error {
	if err := checkVendored(); err != nil {
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
	if buildError != nil {
		t.Fatal(buildError)
	}
	key, err := securitykeytest.New(rpID, "http://localhost")
	if err != nil {
		t.Fatalf("securitykeytest.New: %v", err)
	}
	return key
}

// recordErrors runs in the page before its own scripts.
const recordErrors = `
window.__errors = [];
addEventListener("error", (event) => __errors.push("error: " + event.message));
addEventListener("unhandledrejection", (event) => __errors.push("unhandled rejection: " + event.reason));
addEventListener("securitypolicyviolation", (event) => __errors.push("CSP: " + event.violatedDirective + " " + event.blockedURI));
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
	relayHandler, err := relay.Handler(serverAddr, origin)
	if err != nil {
		t.Fatal(err)
	}
	pageHandler, err := page.Handler(builtPage, page.Config{
		User:    osUser.Username,
		Key:     string(key.AuthorizedKey(keyType, "")),
		HostKey: string(ssh.MarshalAuthorizedKey(hostKey)),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/ws", relayHandler)
	mux.Handle("/", pageHandler)
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })

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
			AutomaticPresenceSimulation: true,
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
	_, err = chromedp.Call(ctx, webauthn.AddCredential, webauthn.AddCredentialParams{
		AuthenticatorID: p.authenticator,
		Credential: &webauthn.Credential{
			CredentialID:         p.credentialID,
			IsResidentCredential: true,
			RpID:                 rpID,
			PrivateKey:           privateKey,
			UserHandle:           randomBytes(t, 16),
			SignCount:            0,
		},
	})
	if err != nil {
		t.Fatalf("WebAuthn.addCredential: %v", err)
	}

	if _, err := chromedp.Call(ctx, cdppage.AddScriptToEvaluateOnNewDocument, cdppage.AddScriptToEvaluateOnNewDocumentParams{Source: recordErrors}); err != nil {
		t.Fatalf("Page.addScriptToEvaluateOnNewDocument: %v", err)
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

// screen returns the text on the terminal's screen.
func (p *testPage) screen() string {
	p.t.Helper()
	return evaluate[string](p, `document.querySelector(".xterm-rows").innerText`)
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
	server := startFakeServer(t)
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
