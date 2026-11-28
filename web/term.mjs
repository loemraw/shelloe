// The terminal, in xterm.js. No other file knows xterm.js.

import { Terminal } from "./vendor/xterm.mjs";
import { Base64, BrowserClipboardProvider, ClipboardAddon } from "./vendor/addon-clipboard.mjs";
import { FitAddon } from "./vendor/addon-fit.mjs";
import { UnicodeGraphemesAddon } from "./vendor/addon-unicode-graphemes.mjs";
import { WebLinksAddon } from "./vendor/addon-web-links.mjs";

const systemFonts = 'ui-monospace, Menlo, Consolas, "DejaVu Sans Mono", monospace';

// The add-on copies only for the selection "c". tmux sends "", the terminal's
// default, and a browser has one clipboard, for that and for lists like "pc".
class BrowserClipboard extends BrowserClipboardProvider {
  async writeText(selection, text) {
    if (selection === "" || selection.includes("c")) {
      await navigator.clipboard.writeText(text);
    }
  }
}

const isApple = /Mac|iPhone|iPad/.test(navigator.platform);

function opensLink(event) {
  // Ctrl-click on Apple's systems is the context menu's click.
  return event.shiftKey || event.altKey || event.metaKey || (event.ctrlKey && !isApple);
}

function sameLink(a, b) {
  return (
    a.text === b.text &&
    a.range.start.x === b.range.start.x &&
    a.range.start.y === b.range.start.y &&
    a.range.end.x === b.range.end.x &&
    a.range.end.y === b.range.end.y
  );
}

// listenForLinkClicks calls onLink with the URI of the web link under the
// pointer when the primary button clicks it with a key that opens links.
// webLinks is the web-links add-on's link provider.
function listenForLinkClicks(element, terminal, webLinks, onLink) {
  let pressed = null;

  function cellAt(event) {
    const rect = terminal.element.querySelector(".xterm-screen").getBoundingClientRect();
    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;
    if (x < 0 || x > rect.width || y < 0 || y > rect.height) {
      return null;
    }
    // Rounded up, as xterm.js rounds, so a pixel on a cell's border is in the
    // cell whose link xterm.js underlines.
    const column = Math.min(Math.max(Math.ceil(x / (rect.width / terminal.cols)), 1), terminal.cols);
    const row = Math.min(Math.max(Math.ceil(y / (rect.height / terminal.rows)), 1), terminal.rows);
    return { x: column, y: terminal.buffer.active.viewportY + row };
  }

  function rangeContains(range, cell) {
    let end = range.end;
    // The add-on ends a link that ends in a row's last column at column 0 of
    // the next row.
    if (end.x === 0) {
      end = { x: terminal.cols, y: end.y - 1 };
    }
    const fromStart = cell.y > range.start.y || (cell.y === range.start.y && cell.x >= range.start.x);
    const toEnd = cell.y < end.y || (cell.y === end.y && cell.x <= end.x);
    return fromStart && toEnd;
  }

  function linkAt(cell) {
    if (cell === null) {
      return null;
    }
    let links = [];
    webLinks.provideLinks(cell.y, (provided) => {
      links = provided ?? [];
    });
    return links.find((link) => rangeContains(link.range, cell)) ?? null;
  }

  function press(event) {
    pressed = null;
    if (event.button !== 0 || !opensLink(event)) {
      return;
    }
    const link = linkAt(cellAt(event));
    if (link !== null) {
      event.preventDefault();
      event.stopPropagation();
      pressed = link;
    }
  }

  function release(event) {
    if (pressed === null) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    const link = linkAt(cellAt(event));
    if (link !== null && sameLink(link, pressed)) {
      onLink(link.text);
    }
    pressed = null;
  }

  // Captured on the terminal's parent, a click that opens a link stops before
  // xterm.js's listeners, so neither the program nor xterm.js's selection sees it.
  element.addEventListener("mousedown", press, { capture: true });
  element.addEventListener("mouseup", release, { capture: true });
}

export function openTerminal(element, fontFamily, onLink) {
  const terminal = new Terminal({
    allowProposedApi: true,
    fontFamily: fontFamily === undefined ? systemFonts : `"${fontFamily}", ${systemFonts}`,
  });
  // xterm.js activates a link only on a click that reaches it, a plain click,
  // and that opens nothing: it's for the program, as in tmux with mouse on.
  const activate = () => {};
  // Setting a handler stops xterm.js's own, which asks with confirm(). OSC 8
  // links open nothing: xterm.js has no public way to tell which link a cell
  // holds at the click, and its own record can be stale.
  terminal.options.linkHandler = { activate };
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  terminal.loadAddon(new ClipboardAddon(new Base64(), new BrowserClipboard()));
  terminal.loadAddon(new UnicodeGraphemesAddon());

  // The add-on keeps its link finder to itself, and the page asks it at each
  // click for the links shown then: xterm.js keeps a row's links until the
  // pointer moves to another row.
  let webLinks;
  const registerLinkProvider = terminal.registerLinkProvider;
  terminal.registerLinkProvider = (provider) => {
    webLinks = provider;
    return registerLinkProvider.call(terminal, provider);
  };
  terminal.loadAddon(new WebLinksAddon(activate));
  delete terminal.registerLinkProvider;
  listenForLinkClicks(element, terminal, webLinks, onLink);

  terminal.open(element);
  fit.fit();
  new ResizeObserver(() => fit.fit()).observe(element);

  const encoder = new TextEncoder();
  return {
    get cols() {
      return terminal.cols;
    },
    get rows() {
      return terminal.rows;
    },
    write(bytes, done) {
      terminal.write(bytes, done);
    },
    onInput(callback) {
      terminal.onData((data) => callback(encoder.encode(data)));
      terminal.onBinary((data) => callback(Uint8Array.from(data, (char) => char.charCodeAt(0))));
    },
    onResize(callback) {
      terminal.onResize(({ cols, rows }) => callback(cols, rows));
    },
    focus() {
      terminal.focus();
    },
    reset() {
      terminal.reset();
    },
  };
}
