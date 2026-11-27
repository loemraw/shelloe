// The terminal, in xterm.js. No other file knows xterm.js.

import { Terminal } from "./vendor/xterm.mjs";
import { Base64, BrowserClipboardProvider, ClipboardAddon } from "./vendor/addon-clipboard.mjs";
import { FitAddon } from "./vendor/addon-fit.mjs";
import { UnicodeGraphemesAddon } from "./vendor/addon-unicode-graphemes.mjs";

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

export function openTerminal(element, fontFamily) {
  const terminal = new Terminal({
    allowProposedApi: true,
    fontFamily: fontFamily === undefined ? systemFonts : `"${fontFamily}", ${systemFonts}`,
  });
  const fit = new FitAddon();
  terminal.loadAddon(fit);
  terminal.loadAddon(new ClipboardAddon(new Base64(), new BrowserClipboard()));
  terminal.loadAddon(new UnicodeGraphemesAddon());
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
