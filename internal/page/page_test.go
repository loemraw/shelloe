package page_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/loemraw/shelloe/internal/page"
	"github.com/loemraw/shelloe/internal/securitykey/securitykeytest"
)

const csp = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

var files = map[string]string{
	"index.html":       "<!doctype html><title>shell</title>",
	"main.mjs":         "export const main = 1;",
	"style.css":        "body { margin: 0 }",
	"shelloe.wasm":     "\x00asm\x01\x00\x00\x00",
	"vendor/xterm.mjs": "export class Terminal {}",
	".secret":          "hidden",
}

func writeFiles(t *testing.T, contents map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range contents {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func ed25519AuthorizedKey(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return string(ssh.MarshalAuthorizedKey(key))
}

func validConfig(t *testing.T) page.Config {
	t.Helper()
	authenticator, err := securitykeytest.New("shell.example.com", "https://shell.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return page.Config{
		User:    "alice",
		Key:     string(authenticator.AuthorizedKey("sk-ecdsa-sha2-nistp256@openssh.com", "")),
		HostKey: ed25519AuthorizedKey(t),
		Command: "tmux attach",
	}
}

func startPage(t *testing.T) (*httptest.Server, page.Config) {
	t.Helper()
	config := validConfig(t)
	handler, err := page.Handler(writeFiles(t, files), config, page.Font{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server, config
}

func get(t *testing.T, server *httptest.Server, method, path string, header http.Header) (*http.Response, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, server.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range header {
		request.Header[name] = values
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var body bytes.Buffer
	body.ReadFrom(response.Body)
	return response, body.Bytes()
}

func checkSecurityHeaders(t *testing.T, response *http.Response) {
	t.Helper()
	for name, want := range map[string]string{
		"Content-Security-Policy": csp,
		"X-Content-Type-Options":  "nosniff",
		"Referrer-Policy":         "no-referrer",
	} {
		if got := response.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestIndexIsServedWithSecurityHeaders(t *testing.T) {
	server, _ := startPage(t)
	response, body := get(t, server, "GET", "/", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	if string(body) != files["index.html"] {
		t.Errorf("body = %q", body)
	}
	if got := response.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	checkSecurityHeaders(t, response)
	if got := response.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
	if response.Header.Get("ETag") == "" {
		t.Error("no ETag")
	}
	if got := response.Header.Get("Last-Modified"); got != "" {
		t.Errorf("Last-Modified = %q, want none", got)
	}
}

func TestFilesAreServedWithTheirContentTypes(t *testing.T) {
	server, _ := startPage(t)
	tests := []struct{ path, name, contentType string }{
		{"/main.mjs", "main.mjs", "text/javascript; charset=utf-8"},
		{"/style.css", "style.css", "text/css; charset=utf-8"},
		{"/shelloe.wasm", "shelloe.wasm", "application/wasm"},
		{"/vendor/xterm.mjs", "vendor/xterm.mjs", "text/javascript; charset=utf-8"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			response, body := get(t, server, "GET", test.path, nil)
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.StatusCode)
			}
			if string(body) != files[test.name] {
				t.Errorf("body = %q", body)
			}
			if got := response.Header.Get("Content-Type"); got != test.contentType {
				t.Errorf("Content-Type = %q, want %q", got, test.contentType)
			}
		})
	}
}

func TestMatchingETagGetsNotModified(t *testing.T) {
	server, _ := startPage(t)
	first, _ := get(t, server, "GET", "/main.mjs", nil)
	etag := first.Header.Get("ETag")

	response, body := get(t, server, "GET", "/main.mjs", http.Header{"If-None-Match": {etag}})
	if response.StatusCode != http.StatusNotModified {
		t.Errorf("status = %d, want 304", response.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("body = %q, want none", body)
	}

	other, _ := get(t, server, "GET", "/style.css", nil)
	if other.Header.Get("ETag") == etag {
		t.Error("two files with different content have the same ETag")
	}
}

func TestConfigIsServedAsJSON(t *testing.T) {
	server, config := startPage(t)
	response, body := get(t, server, "GET", "/config.json", nil)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}
	var got page.Config
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got != config {
		t.Errorf("config = %+v, want %+v", got, config)
	}
	if got := response.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
	if got := response.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	checkSecurityHeaders(t, response)
}

func TestConfigJSONTakesPrecedenceOverAFile(t *testing.T) {
	config := validConfig(t)
	dir := writeFiles(t, map[string]string{"index.html": "x", "config.json": `{"user":"mallory"}`})
	handler, err := page.Handler(dir, config, page.Font{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	_, body := get(t, server, "GET", "/config.json", nil)
	var got page.Config
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.User != config.User {
		t.Errorf("user = %q, want %q", got.User, config.User)
	}
}

func TestUnknownPathsGetNotFoundWithSecurityHeaders(t *testing.T) {
	server, _ := startPage(t)
	for _, path := range []string{"/missing", "/vendor", "/vendor/", "/.secret", "/index.html/"} {
		t.Run(path, func(t *testing.T) {
			response, _ := get(t, server, "GET", path, nil)
			if response.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want 404", response.StatusCode)
			}
			checkSecurityHeaders(t, response)
		})
	}
}

func TestOtherMethodsAreRefused(t *testing.T) {
	server, _ := startPage(t)
	response, _ := get(t, server, "POST", "/", nil)
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", response.StatusCode)
	}
	if got := response.Header.Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow = %q, want \"GET, HEAD\"", got)
	}
	checkSecurityHeaders(t, response)
}

func TestHeadGetsHeadersWithoutABody(t *testing.T) {
	server, _ := startPage(t)
	getResponse, _ := get(t, server, "GET", "/main.mjs", nil)
	response, body := get(t, server, "HEAD", "/main.mjs", nil)
	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", response.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("body = %q, want none", body)
	}
	if got, want := response.Header.Get("Content-Type"), "text/javascript; charset=utf-8"; got != want {
		t.Errorf("Content-Type = %q, want %q", got, want)
	}
	if got, want := response.Header.Get("ETag"), getResponse.Header.Get("ETag"); got == "" || got != want {
		t.Errorf("ETag = %q, want GET's %q", got, want)
	}
	if got := response.Header.Get("Cache-Control"); got != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", got)
	}
	checkSecurityHeaders(t, response)

	t.Run("missing file", func(t *testing.T) {
		response, body := get(t, server, "HEAD", "/missing", nil)
		if response.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d, want 404", response.StatusCode)
		}
		if len(body) != 0 {
			t.Errorf("body = %q, want none", body)
		}
	})
}

func TestHandlerRefusesBadArguments(t *testing.T) {
	good := validConfig(t)
	goodDir := writeFiles(t, files)
	edKey := ed25519AuthorizedKey(t)

	tests := []struct {
		name   string
		dir    string
		modify func(*page.Config)
	}{
		{"directory without an index.html", writeFiles(t, map[string]string{"main.mjs": "x"}), func(*page.Config) {}},
		{"directory that doesn't exist", filepath.Join(t.TempDir(), "missing"), func(*page.Config) {}},
		{"empty user", goodDir, func(c *page.Config) { c.User = "" }},
		{"key that isn't a security key", goodDir, func(c *page.Config) { c.Key = edKey }},
		{"host key that isn't a key", goodDir, func(c *page.Config) { c.HostKey = "not a key" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := good
			test.modify(&config)
			if _, err := page.Handler(test.dir, config, page.Font{}); err == nil {
				t.Error("Handler returned no error")
			}
		})
	}

	t.Run("valid", func(t *testing.T) {
		if _, err := page.Handler(goodDir, good, page.Font{}); err != nil {
			t.Errorf("Handler returned %v", err)
		}
	})
}

func TestHandlerFollowsSymlinks(t *testing.T) {
	outside := writeFiles(t, map[string]string{"outside.mjs": "export const outside = 1;"})
	real := writeFiles(t, map[string]string{"index.html": "x", "subdir/x.mjs": "x"})
	links := map[string]string{
		"linked.mjs":  filepath.Join(outside, "outside.mjs"),
		"subdir-link": filepath.Join(real, "subdir"),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(real, name)); err != nil {
			t.Fatal(err)
		}
	}
	dir := filepath.Join(t.TempDir(), "page")
	if err := os.Symlink(real, dir); err != nil {
		t.Fatal(err)
	}
	handler, err := page.Handler(dir, validConfig(t), page.Font{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	for path, want := range map[string]string{"/": "x", "/linked.mjs": "export const outside = 1;"} {
		if _, body := get(t, server, "GET", path, nil); string(body) != want {
			t.Errorf("%s body = %q, want %q", path, body, want)
		}
	}
	if response, _ := get(t, server, "GET", "/subdir-link/x.mjs", nil); response.StatusCode != http.StatusNotFound {
		t.Errorf("/subdir-link/x.mjs status = %d, want 404", response.StatusCode)
	}
}

// writeFont writes a font file that holds content, and returns its path.
func writeFont(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "font")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func startPageWithFont(t *testing.T, font page.Font) *httptest.Server {
	t.Helper()
	handler, err := page.Handler(writeFiles(t, files), validConfig(t), font)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

type fontFace struct {
	URL    string `json:"url"`
	Weight string `json:"weight"`
	Style  string `json:"style"`
}

// fontFaces returns the faces of the font that config.json lists.
func fontFaces(t *testing.T, server *httptest.Server) []fontFace {
	t.Helper()
	_, body := get(t, server, "GET", "/config.json", nil)
	var config struct {
		Font []fontFace `json:"font"`
	}
	if err := json.Unmarshal(body, &config); err != nil {
		t.Fatal(err)
	}
	return config.Font
}

func sha256Hex(content string) string {
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

func TestFontIsServedAtTheURLConfigListsWithItsContentType(t *testing.T) {
	tests := []struct{ name, signature, extension, contentType string }{
		{"WOFF2", "wOF2", ".woff2", "font/woff2"},
		{"WOFF", "wOFF", ".woff", "font/woff"},
		{"TrueType 00010000", "\x00\x01\x00\x00", ".ttf", "font/ttf"},
		{"TrueType true", "true", ".ttf", "font/ttf"},
		{"OpenType", "OTTO", ".otf", "font/otf"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			content := test.signature + " and the rest of the font"
			server := startPageWithFont(t, page.Font{Regular: writeFont(t, content)})
			faces := fontFaces(t, server)
			if len(faces) != 1 {
				t.Fatalf("config.json lists %d faces, want 1", len(faces))
			}
			if want := "fonts/" + sha256Hex(content) + test.extension; faces[0].URL != want {
				t.Errorf("url = %q, want %q", faces[0].URL, want)
			}

			response, body := get(t, server, "GET", "/"+faces[0].URL, nil)
			if response.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.StatusCode)
			}
			if string(body) != content {
				t.Errorf("body = %q, want %q", body, content)
			}
			if got := response.Header.Get("Content-Type"); got != test.contentType {
				t.Errorf("Content-Type = %q, want %q", got, test.contentType)
			}
			if got, want := response.Header.Get("Cache-Control"), "public, max-age=31536000, immutable"; got != want {
				t.Errorf("Cache-Control = %q, want %q", got, want)
			}
			checkSecurityHeaders(t, response)

			notModified, _ := get(t, server, "GET", "/"+faces[0].URL, http.Header{"If-None-Match": {response.Header.Get("ETag")}})
			if notModified.StatusCode != http.StatusNotModified {
				t.Errorf("status with the ETag = %d, want 304", notModified.StatusCode)
			}
		})
	}
}

func TestHeadOnAFontGetsItsHeadersWithoutABody(t *testing.T) {
	content := "wOF2 and the rest of the font"
	server := startPageWithFont(t, page.Font{Regular: writeFont(t, content)})
	response, body := get(t, server, "HEAD", "/"+fontFaces(t, server)[0].URL, nil)
	if response.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", response.StatusCode)
	}
	if len(body) != 0 {
		t.Errorf("body = %q, want none", body)
	}
	if got := response.Header.Get("Content-Type"); got != "font/woff2" {
		t.Errorf("Content-Type = %q, want font/woff2", got)
	}
	if got, want := response.Header.Get("Content-Length"), strconv.Itoa(len(content)); got != want {
		t.Errorf("Content-Length = %q, want %q", got, want)
	}
}

func TestFontTakesPrecedenceOverAFile(t *testing.T) {
	content := "wOF2 and the rest of the font"
	name := "fonts/" + sha256Hex(content) + ".woff2"
	dir := writeFiles(t, map[string]string{"index.html": "x", name: "not the font"})
	handler, err := page.Handler(dir, validConfig(t), page.Font{Regular: writeFont(t, content)})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	if _, body := get(t, server, "GET", "/"+name, nil); string(body) != content {
		t.Errorf("body = %q, want the font's %q", body, content)
	}
}

func TestConfigListsEachGivenStyleOfTheFontInOrder(t *testing.T) {
	regular, bold, italic, boldItalic := "wOF2 regular", "wOF2 bold", "wOF2 italic", "wOF2 bold italic"
	regularFile, boldFile, italicFile, boldItalicFile := writeFont(t, regular), writeFont(t, bold), writeFont(t, italic), writeFont(t, boldItalic)
	face := func(content, weight, style string) fontFace {
		return fontFace{URL: "fonts/" + sha256Hex(content) + ".woff2", Weight: weight, Style: style}
	}

	tests := []struct {
		name string
		font page.Font
		want []fontFace
	}{
		{
			"every style",
			page.Font{Regular: regularFile, Bold: boldFile, Italic: italicFile, BoldItalic: boldItalicFile},
			[]fontFace{face(regular, "normal", "normal"), face(bold, "bold", "normal"), face(italic, "normal", "italic"), face(boldItalic, "bold", "italic")},
		},
		{
			"regular only",
			page.Font{Regular: regularFile},
			[]fontFace{face(regular, "normal", "normal")},
		},
		{
			"regular and bold italic",
			page.Font{Regular: regularFile, BoldItalic: boldItalicFile},
			[]fontFace{face(regular, "normal", "normal"), face(boldItalic, "bold", "italic")},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := fontFaces(t, startPageWithFont(t, test.font)); !slices.Equal(got, test.want) {
				t.Errorf("config.json lists %+v, want %+v", got, test.want)
			}
		})
	}
}

func TestConfigHasNoFontWithoutAFont(t *testing.T) {
	server, config := startPage(t)
	_, body := get(t, server, "GET", "/config.json", nil)
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	if font, ok := fields["font"]; ok {
		t.Errorf("config.json has the font %s, want none", font)
	}
	want, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(body, want) {
		t.Errorf("config.json = %s, want the config alone, %s", body, want)
	}
}

func TestHandlerRefusesBadFonts(t *testing.T) {
	config := validConfig(t)
	dir := writeFiles(t, files)
	font := writeFont(t, "wOF2 a font")

	tests := []struct {
		name string
		font page.Font
	}{
		{"bold file without a regular one", page.Font{Bold: font}},
		{"italic file without a regular one", page.Font{Italic: font}},
		{"bold italic file without a regular one", page.Font{BoldItalic: font}},
		{"file that isn't a font", page.Font{Regular: writeFont(t, "<!doctype html>")}},
		{"file shorter than a signature", page.Font{Regular: writeFont(t, "wOF")}},
		{"bold file that isn't a font", page.Font{Regular: font, Bold: writeFont(t, "not a font")}},
		{"file that doesn't exist", page.Font{Regular: filepath.Join(t.TempDir(), "missing.woff2")}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := page.Handler(dir, config, test.font)
			if err == nil {
				t.Fatal("Handler returned no error")
			}
			if !strings.HasPrefix(err.Error(), "page: font: ") {
				t.Errorf("error = %q, want it to start with %q", err, "page: font: ")
			}
		})
	}
}
