// Package page serves the web shell's page: the files of one directory, and the page's configuration as /config.json.
package page

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/loemraw/shelloe/internal/securitykey"
)

// contentSecurityPolicy lets the page load only its own files.
//
// 'wasm-unsafe-eval' lets the page compile its WebAssembly client.
// 'unsafe-inline' for styles is there because xterm.js adds <style> elements.
const contentSecurityPolicy = "default-src 'none'; " +
	"script-src 'self' 'wasm-unsafe-eval'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"connect-src 'self'; " +
	"base-uri 'none'; " +
	"form-action 'none'; " +
	"frame-ancestors 'none'"

var contentTypes = map[string]string{
	".html": "text/html; charset=utf-8",
	".js":   "text/javascript; charset=utf-8",
	".mjs":  "text/javascript; charset=utf-8",
	".css":  "text/css; charset=utf-8",
	".wasm": "application/wasm",
	".json": "application/json",
}

// Config is what the page needs to log in.
type Config struct {
	User    string `json:"user"`              // the user to log in as
	Key     string `json:"key"`               // the security key's public key: an authorized_keys line that securitykey.ParseKey accepts
	HostKey string `json:"hostKey"`           // the SSH server's host key, an authorized_keys line
	Command string `json:"command,omitempty"` // the command to run instead of the login shell; "" runs the login shell
}

type file struct {
	content     []byte
	contentType string
	etag        string
}

type handler struct {
	files  map[string]file
	config []byte
}

// Handler returns an http.Handler that serves the files under dir as they are
// when it's called, and config as /config.json.
func Handler(dir string, config Config) (http.Handler, error) {
	if config.User == "" {
		return nil, errors.New("page: the user is empty")
	}
	if _, err := securitykey.ParseKey([]byte(config.Key)); err != nil {
		return nil, fmt.Errorf("page: key: %w", err)
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(config.HostKey)); err != nil {
		return nil, fmt.Errorf("page: host key: %w", err)
	}

	files, err := loadFiles(dir)
	if err != nil {
		return nil, err
	}
	if _, ok := files["index.html"]; !ok {
		return nil, fmt.Errorf("page: %s has no index.html", dir)
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("page: %w", err)
	}
	return &handler{files: files, config: encoded}, nil
}

func loadFiles(dir string) (map[string]file, error) {
	root, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("page: %w", err)
	}
	files := map[string]file{}
	err = filepath.WalkDir(root, func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == root {
			return nil
		}
		if strings.HasPrefix(entry.Name(), ".") {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		content, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(content)
		files[filepath.ToSlash(rel)] = file{
			content:     content,
			contentType: contentTypes[strings.ToLower(path.Ext(p))],
			etag:        `"` + hex.EncodeToString(sum[:]) + `"`,
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("page: %w", err)
	}
	return files, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	header := w.Header()
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		header.Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if r.URL.Path == "/config.json" {
		header.Set("Content-Type", "application/json")
		header.Set("Cache-Control", "no-store")
		http.ServeContent(w, r, "config.json", time.Time{}, bytes.NewReader(h.config))
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
	}
	f, ok := h.files[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	if f.contentType != "" {
		header.Set("Content-Type", f.contentType)
	}
	header.Set("Cache-Control", "no-cache")
	header.Set("ETag", f.etag)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(f.content))
}
