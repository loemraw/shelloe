import { openTerminal } from "./term.mjs";

// The page waits for the font at least until this many milliseconds after it started loading.
const fontDeadline = 1000;

const element = document.getElementById("terminal");
const overlay = document.getElementById("overlay");
const message = document.getElementById("message");
const reconnect = document.getElementById("reconnect");

let terminal;
let config;
let session;
let connectedBefore = false;

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

// loadFont starts loading the faces that config.json lists, and returns a
// promise of them, which rejects if one fails to load.
function loadFont(faces = []) {
  return Promise.all(
    faces.map(({ url, weight, style }) => new FontFace("shelloe", `url(${url})`, { weight, style }).load()),
  );
}

// fontInTime waits for the font until fontDeadline at the latest. If every
// face has loaded by then, it adds them to the document and returns their
// family; otherwise it returns undefined.
async function fontInTime(fontLoaded) {
  const wait = fontDeadline - performance.now();
  const late = wait <= 0 ? Promise.resolve({}) : new Promise((resolve) => setTimeout(() => resolve({}), wait));
  const { faces, error } = await Promise.race([fontLoaded, late]);
  if (error !== undefined) {
    console.warn("Couldn't load the font:", error);
    return undefined;
  }
  if (faces === undefined || faces.length === 0) {
    return undefined;
  }
  for (const face of faces) {
    document.fonts.add(face);
  }
  return "shelloe";
}

// load starts the client, which sets globalThis.shelloe, and returns the
// config and the font family to draw the terminal in, undefined for the
// system's.
async function load() {
  const go = new Go();
  const configLoaded = fetch("config.json").then((response) => response.json());
  const fontLoaded = configLoaded
    .then((config) => loadFont(config.font))
    .then((faces) => ({ faces }), (error) => ({ error }));
  const [{ instance }, config] = await Promise.all([
    WebAssembly.instantiateStreaming(fetch("shelloe.wasm"), go.importObject),
    configLoaded,
  ]);
  const stopped = () => show("The shelloe client stopped. Reload the page.");
  go.run(instance).then(stopped, stopped);
  return [config, await fontInTime(fontLoaded)];
}

let fontFamily;
try {
  [config, fontFamily] = await load();
} catch (err) {
  show(`Couldn't load shelloe: ${err}`);
}
if (config !== undefined) {
  terminal = openTerminal(element, fontFamily);
  terminal.onInput((bytes) => session?.input(bytes));
  terminal.onResize((cols, rows) => session?.resize(cols, rows));
  connect();
}
