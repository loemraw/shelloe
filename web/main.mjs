import { openTerminal } from "./term.mjs";

const overlay = document.getElementById("overlay");
const message = document.getElementById("message");
const reconnect = document.getElementById("reconnect");

const terminal = openTerminal(document.getElementById("terminal"));
let config;
let session;
let connectedBefore = false;

terminal.onInput((bytes) => session?.input(bytes));
terminal.onResize((cols, rows) => session?.resize(cols, rows));

function show(text, withButton = false) {
  message.textContent = text;
  reconnect.hidden = !withButton;
  overlay.hidden = false;
  if (withButton) {
    reconnect.focus();
  }
}

function hide() {
  overlay.hidden = true;
}

function status(state, text) {
  switch (state) {
    case "signing-in":
      show("Touch your security key to log in.");
      break;
    case "connected":
      hide();
      terminal.focus();
      break;
    case "signing":
      show("Touch your security key to sign.");
      break;
    case "signed":
      hide();
      break;
    case "ended":
      show(text, true);
      break;
  }
}

function connect() {
  if (connectedBefore) {
    terminal.reset();
  }
  connectedBefore = true;
  session = shelloe.connect({
    url: new URL("ws", location.href).href,
    config,
    cols: terminal.cols,
    rows: terminal.rows,
    write: (bytes, done) => terminal.write(bytes, done),
    status,
  });
}

reconnect.addEventListener("click", () => {
  reconnect.hidden = true;
  connect();
});

// load starts the client, which sets globalThis.shelloe, and returns the config.
async function load() {
  const go = new Go();
  const [{ instance }, config] = await Promise.all([
    WebAssembly.instantiateStreaming(fetch("shelloe.wasm"), go.importObject),
    fetch("config.json").then((response) => response.json()),
  ]);
  const stopped = () => show("The shelloe client stopped. Reload the page.");
  go.run(instance).then(stopped, stopped);
  return config;
}

try {
  config = await load();
} catch (err) {
  show(`Couldn't load shelloe: ${err}`);
}
if (config !== undefined) {
  connect();
}
