// Command shelloe serves the web shell: its page and its relay to the SSH server.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/loemraw/shelloe/internal/page"
	"github.com/loemraw/shelloe/internal/relay"
)

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	target := flag.String("target", "", "the SSH server's host:port")
	origin := flag.String("origin", "", "the web page's origin, like https://shell.example.com; WebSocket connections from any other origin are refused")
	web := flag.String("web", "", "directory of the web page's files")
	user := flag.String("user", "", "the user to log in as on the SSH server")
	keyFile := flag.String("key", "", "file holding the security key's public key, an authorized_keys line")
	hostKeyFile := flag.String("host-key", "", "file holding the SSH server's public host key, like /etc/ssh/ssh_host_ed25519_key.pub")
	command := flag.String("command", "", "command to run instead of the login shell")
	fontFile := flag.String("font", "", "font file for the terminal's text: WOFF2, WOFF, TrueType or OpenType; the system's monospace font if unset")
	boldFontFile := flag.String("font-bold", "", "font file for bold text; drawn from -font if unset")
	italicFontFile := flag.String("font-italic", "", "font file for italic text; drawn from -font if unset")
	boldItalicFontFile := flag.String("font-bold-italic", "", "font file for bold italic text; drawn from -font if unset")
	flag.Parse()

	if *target == "" || *origin == "" || *web == "" || *user == "" || *keyFile == "" || *hostKeyFile == "" {
		fmt.Fprintln(os.Stderr, "shelloe: -target, -origin, -web, -user, -key and -host-key are required")
		flag.Usage()
		os.Exit(2)
	}

	key, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shelloe: %v\n", err)
		os.Exit(2)
	}
	hostKey, err := os.ReadFile(*hostKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "shelloe: %v\n", err)
		os.Exit(2)
	}

	relayHandler, err := relay.Handler(*target, *origin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	pageHandler, err := page.Handler(*web, page.Config{
		User:    *user,
		Key:     strings.TrimSpace(string(key)),
		HostKey: strings.TrimSpace(string(hostKey)),
		Command: *command,
	}, page.Font{
		Regular:    *fontFile,
		Bold:       *boldFontFile,
		Italic:     *italicFontFile,
		BoldItalic: *boldItalicFontFile,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	mux := http.NewServeMux()
	mux.Handle("/ws", relayHandler)
	mux.Handle("/", pageHandler)
	server := http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}
