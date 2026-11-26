// Package relay carries a browser's WebSocket to a fixed TCP address.
package relay

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// maxMessageSize is the largest WebSocket message the relay accepts. SSH
// packets can reach 256 KiB.
const maxMessageSize = 1 << 20

// Handler returns an http.Handler that accepts WebSocket connections whose
// Origin header is exactly origin, and pipes each one to a new TCP connection
// to target.
func Handler(target, origin string) (http.Handler, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, fmt.Errorf("relay: target %q isn't host:port: %w", target, err)
	}
	if host == "" || port == "" {
		return nil, fmt.Errorf("relay: target %q needs both a host and a port", target)
	}

	u, err := url.Parse(origin)
	if err != nil {
		return nil, fmt.Errorf("relay: origin %q isn't a URL: %w", origin, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, fmt.Errorf("relay: origin %q must start with https:// or http://", origin)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("relay: origin %q has no host", origin)
	}
	if origin != u.Scheme+"://"+u.Host || strings.HasSuffix(u.Host, ":") {
		return nil, fmt.Errorf("relay: origin %q must be only a scheme, host and optional port", origin)
	}

	return &handler{target: target, origin: origin}, nil
}

type handler struct {
	target string
	origin string
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != h.origin {
		log.Printf("relay: %s: refused origin %q", r.RemoteAddr, r.Header.Get("Origin"))
		http.Error(w, "forbidden origin", http.StatusForbidden)
		return
	}

	// The exact Origin check above replaces the library's.
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		log.Printf("relay: %s: %v", r.RemoteAddr, err)
		return
	}

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	dialer := net.Dialer{Timeout: 10 * time.Second}
	tcp, err := dialer.DialContext(ctx, "tcp", h.target)
	if err != nil {
		log.Printf("relay: %s: %v", r.RemoteAddr, err)
		ws.Close(websocket.StatusTryAgainLater, "can't reach the SSH server")
		return
	}

	start := time.Now()
	log.Printf("relay: %s connected", r.RemoteAddr)
	defer func() {
		log.Printf("relay: %s disconnected after %s", r.RemoteAddr, time.Since(start).Round(time.Second))
	}()

	browser := websocket.NetConn(ctx, ws, websocket.MessageBinary)
	// NetConn turns the read limit off, so set it after.
	ws.SetReadLimit(maxMessageSize)

	var wg sync.WaitGroup
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			tcp.Close()
			// Not browser.Close: it cancels the read first, which can drop the close frame and unsent output.
			ws.Close(websocket.StatusNormalClosure, "")
		})
	}
	copyAndClose := func(dst io.Writer, src io.Reader) {
		defer wg.Done()
		io.Copy(dst, src) // an error just means the other side went away
		closeBoth()
	}
	wg.Add(2)
	go copyAndClose(tcp, browser)
	go copyAndClose(browser, tcp)
	wg.Wait()
}
