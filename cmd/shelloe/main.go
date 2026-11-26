// Command shelloe serves the web shell's relay.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/loemraw/shelloe/internal/relay"
)

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	target := flag.String("target", "", "the SSH server's host:port")
	origin := flag.String("origin", "", "the web page's origin, like https://shell.example.com; WebSocket connections from any other origin are refused")
	flag.Parse()

	if *target == "" || *origin == "" {
		fmt.Fprintln(os.Stderr, "shelloe: -target and -origin are required")
		flag.Usage()
		os.Exit(2)
	}

	handler, err := relay.Handler(*target, *origin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	mux := http.NewServeMux()
	mux.Handle("/ws", handler)
	server := http.Server{Addr: *listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(server.ListenAndServe())
}
