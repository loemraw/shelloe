# shelloe

A web shell: SSH from the browser to one machine, with every signature made by a security key.

## Running it

Fetch xterm.js, pinned in `scripts/vendor-xterm.json`, and build the client, which runs in the browser, next to the page:

```sh
scripts/vendor-xterm.py
GOOS=js GOARCH=wasm go build -o web/shelloe.wasm ./cmd/shelloe-wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" web/
```

Then serve the page and its relay to the SSH server:

```sh
go run ./cmd/shelloe -web web -target server:22 -origin https://shell.example.com \
  -user you -key key.pub -host-key host.pub
```

To draw the terminal in your own typeface, add `-font` with its font file, and `-font-bold`, `-font-italic` and `-font-bold-italic` for those styles if you have them. WOFF2 files are the smallest. If the font hasn't arrived by the time the client has loaded, and at least a second has passed, that visit uses the system's monospace font; the browser keeps the font for the next visit.

Shift-, Option- or Cmd-click a link (Ctrl-click off macOS) to open it in a new tab: web addresses in the output, http and https. A plain click goes to the program, as in tmux with `mouse on`. A link to the server's localhost (`localhost`, `127.0.0.1`, `[::1]`, `0.0.0.0`) means nothing to the browser. With `-localhost-url https://dev-{port}.example.com`, such links open at that URL with their port in place of `{port}`, and their path, query and fragment kept. Serving those names, by something that reaches the server's localhost, is up to the deployment.

The page must be served from the security key's site (its rpID), over HTTPS or on localhost.

Run the tests with `go test ./...`. Tests that need sshd or Chrome skip unless `SHELLOE_SSHD` (an sshd binary) and `SHELLOE_CHROME` (a Chrome binary) are set. The browser tests need xterm.js fetched first.

## With Nix

The flake's package holds the server, and the page with the client and xterm.js in `share/shelloe/web`. Building it runs the tests that need neither sshd nor Chrome.

```sh
nix build github:loemraw/shelloe
result/bin/shelloe -web result/share/shelloe/web -target server:22 …
```

When go.mod's requirements change, set `vendorHash` in `package.nix` to the hash `nix build` reports.
