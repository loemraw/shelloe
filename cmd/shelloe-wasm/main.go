//go:build js && wasm

// Command shelloe-wasm is the web shell's SSH client, compiled to WebAssembly
// for the page. It logs in and signs through the browser's WebAuthn, so the
// server only ever relays encrypted bytes. It sets globalThis.shelloe =
// {connect}; see web/main.mjs for how the page uses it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall/js"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"

	"github.com/loemraw/shelloe/internal/page"
	"github.com/loemraw/shelloe/internal/securitykey"
	"github.com/loemraw/shelloe/internal/session"
)

const (
	dialTimeout = 15 * time.Second
	chunkSize   = 32 << 10 // the most output passed to the terminal in one write
	// writesInFlight is how many chunks the terminal may hold before it has processed them.
	writesInFlight = 4
)

var uint8Array = js.Global().Get("Uint8Array")

func main() {
	js.Global().Set("shelloe", map[string]any{"connect": js.FuncOf(connect)})
	select {}
}

// connect is shelloe.connect({url, config, cols, rows, write, status}). It
// returns {input, resize} at once and connects in the background. status gets,
// in order, "signing-in", "connected", "signing" and "signed" around each
// signature for the forwarded agent, and "ended" with a message. After
// "ended", write and status aren't called, and input and resize do nothing.
func connect(_ js.Value, args []js.Value) any {
	options := args[0]
	c := &client{
		write:      options.Get("write"),
		status:     options.Get("status"),
		inputReady: make(chan struct{}, 1),
		sizes:      make(chan size, 1),
		slots:      make(chan struct{}, writesInFlight),
	}
	// The Funcs are never released: JS may call them after the session has
	// ended, and a released Func must not be called.
	c.done = js.FuncOf(c.writeDone)
	go c.run(options.Get("url").String(), options.Get("config"), options.Get("cols").Int(), options.Get("rows").Int())
	return map[string]any{
		"input":  js.FuncOf(c.input),
		"resize": js.FuncOf(c.resize),
	}
}

// client is one call of connect: a connection to the server, from the login until the session ends.
type client struct {
	write  js.Value // the page's write(bytes, done)
	status js.Value // the page's status(state, message)

	statusMu sync.Mutex
	ended    atomic.Bool // set, under statusMu, as the "ended" status is sent

	inputMu      sync.Mutex
	pending      []byte // input not yet written to the session
	inputStopped bool   // a write failed, so input is dropped
	inputReady   chan struct{}

	sizes chan size // the latest size not yet sent to the server

	slots chan struct{} // one for each chunk the terminal hasn't processed yet
	done  js.Func       // the write callback's done, which frees a slot
}

type size struct{ cols, rows int }

// run logs in, runs the session and reports its end.
func (c *client) run(url string, config js.Value, cols, rows int) {
	c.setStatus("signing-in")
	cfg, err := parseConfig(config)
	if err != nil {
		c.end("The page's configuration is invalid: " + err.Error())
		return
	}

	// Cancelling ctx aborts any WebAuthn request in flight.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dialCtx, cancelDial := context.WithTimeout(ctx, dialTimeout)
	ws, _, err := websocket.Dial(dialCtx, url, nil)
	cancelDial()
	if err != nil {
		c.end("Couldn't reach the server: " + err.Error())
		return
	}
	conn := relayConn{websocket.NetConn(ctx, ws, websocket.MessageBinary), cancel}

	cfg.Term = "xterm-256color"
	cfg.Cols, cfg.Rows = cols, rows
	cfg.Authenticator = webAuthn(ctx)
	cfg.Notify = func(signing bool) {
		if signing {
			c.setStatus("signing")
		} else {
			c.setStatus("signed")
		}
	}
	s, err := session.Start(conn, cfg)
	if err != nil {
		conn.Close()
		c.end("Couldn't log in: " + err.Error())
		return
	}
	c.setStatus("connected")

	outputDone := make(chan struct{})
	go func() {
		defer close(outputDone)
		c.copyOutput(s)
	}()
	go c.copyInput(ctx, s)
	go c.resizeSession(ctx, s)

	err = s.Wait()
	cancel()
	<-outputDone
	s.Close()
	c.end(endMessage(err))
}

// parseConfig reads the page's config.json, which the page passes as an object.
func parseConfig(value js.Value) (session.Config, error) {
	var config page.Config
	if err := json.Unmarshal([]byte(js.Global().Get("JSON").Call("stringify", value).String()), &config); err != nil {
		return session.Config{}, err
	}
	key, err := securitykey.ParseKey([]byte(config.Key))
	if err != nil {
		return session.Config{}, err
	}
	hostKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(config.HostKey))
	if err != nil {
		return session.Config{}, fmt.Errorf("host key: %w", err)
	}
	return session.Config{User: config.User, HostKey: hostKey, Key: key, Command: config.Command}, nil
}

// endMessage says why the session ended, given what Wait returned.
func endMessage(err error) string {
	var exitError *ssh.ExitError
	switch {
	case err == nil:
		return "The session ended."
	case errors.As(err, &exitError) && exitError.Signal() != "":
		return fmt.Sprintf("The session ended: signal %s.", exitError.Signal())
	case errors.As(err, &exitError):
		return fmt.Sprintf("The session ended with exit status %d.", exitError.ExitStatus())
	default:
		return "The connection to the server was lost."
	}
}

// setStatus tells the page the session's state, unless it has ended.
func (c *client) setStatus(state string) {
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	if !c.ended.Load() {
		c.status.Invoke(state, "")
	}
}

// end tells the page that the session has ended, and why. The page hears nothing more after it.
func (c *client) end(message string) {
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	c.ended.Store(true)
	c.status.Invoke("ended", message)
}

// copyOutput passes the session's output to the page until it ends.
func (c *client) copyOutput(s *session.Session) {
	buffer := make([]byte, chunkSize)
	for {
		n, err := s.Read(buffer)
		if n > 0 {
			// Waiting for the terminal to process earlier chunks stops the reading
			// when it falls behind, so the SSH window fills and the server stops sending.
			c.slots <- struct{}{}
			chunk := uint8Array.New(n)
			js.CopyBytesToJS(chunk, buffer[:n])
			c.write.Invoke(chunk, c.done)
		}
		if err != nil {
			return
		}
	}
}

func (c *client) writeDone(js.Value, []js.Value) any {
	select {
	case <-c.slots:
	default:
	}
	return nil
}

// input is session.input(bytes): it queues what the user typed for copyInput.
func (c *client) input(_ js.Value, args []js.Value) any {
	if c.ended.Load() {
		return nil
	}
	data := make([]byte, args[0].Length())
	js.CopyBytesToGo(data, args[0])
	c.inputMu.Lock()
	if !c.inputStopped {
		c.pending = append(c.pending, data...)
	}
	c.inputMu.Unlock()
	select {
	case c.inputReady <- struct{}{}:
	default:
	}
	return nil
}

// copyInput writes the queued input to the session, in order, until a write fails or ctx ends.
func (c *client) copyInput(ctx context.Context, s *session.Session) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.inputReady:
		}
		c.inputMu.Lock()
		pending := c.pending
		c.pending = nil
		c.inputMu.Unlock()
		if len(pending) == 0 {
			continue
		}
		if _, err := s.Write(pending); err != nil {
			c.inputMu.Lock()
			c.inputStopped = true
			c.pending = nil
			c.inputMu.Unlock()
			return
		}
	}
}

// resize is session.resize(cols, rows): it hands the latest size to resizeSession.
func (c *client) resize(_ js.Value, args []js.Value) any {
	if c.ended.Load() {
		return nil
	}
	select {
	case <-c.sizes:
	default:
	}
	// Only resize sends, one call at a time, so the drain above leaves room.
	c.sizes <- size{args[0].Int(), args[1].Int()}
	return nil
}

// resizeSession tells the server each size that resize hands it, until ctx ends.
func (c *client) resizeSession(ctx context.Context, s *session.Session) {
	for {
		select {
		case <-ctx.Done():
			return
		case size := <-c.sizes:
			s.Resize(size.cols, size.rows) // an error means the session is ending
		}
	}
}

// relayConn is the relay's WebSocket. A failed Read cancels the connection's
// context: the relay has hung up, so a WebAuthn request in flight, such as the
// login's, must give up rather than wait for a touch.
type relayConn struct {
	net.Conn
	cancel context.CancelFunc
}

func (c relayConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err != nil {
		c.cancel()
	}
	return n, err
}
