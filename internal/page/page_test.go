package page_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/loemraw/shelloe/internal/page"
	"github.com/loemraw/shelloe/internal/securitykey/securitykeytest"
)

const csp = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

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
	handler, err := page.Handler(writeFiles(t, files), config)
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
	handler, err := page.Handler(dir, config)
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
			if _, err := page.Handler(test.dir, config); err == nil {
				t.Error("Handler returned no error")
			}
		})
	}

	t.Run("valid", func(t *testing.T) {
		if _, err := page.Handler(goodDir, good); err != nil {
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
	handler, err := page.Handler(dir, validConfig(t))
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
