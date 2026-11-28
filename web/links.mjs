// What a link in the terminal opens.

function isLoopback(hostname) {
  return (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    /^127\.\d+\.\d+\.\d+$/.test(hostname) ||
    hostname === "[::1]" ||
    // Not loopback, but what a server listening on every address prints.
    hostname === "0.0.0.0" ||
    hostname === "[::]"
  );
}

function portOf(url) {
  if (url.port !== "") {
    return url.port;
  }
  return url.protocol === "https:" ? "443" : "80";
}

// resolveLink returns the URL that a link to uri opens, or null if it opens
// nothing. localhostURL, with {port} for the port, is where the browser
// reaches the SSH server's localhost; without it, links to localhost open as
// they are.
export function resolveLink(uri, localhostURL) {
  let url;
  try {
    url = new URL(uri);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return null;
  }
  if (typeof localhostURL === "string" && localhostURL !== "" && isLoopback(url.hostname)) {
    return localhostURL.replace("{port}", portOf(url)) + url.pathname + url.search + url.hash;
  }
  return url.href;
}

// openLink opens the URL that a link to uri resolves to in a new tab.
export function openLink(uri, localhostURL) {
  const resolved = resolveLink(uri, localhostURL);
  if (resolved === null) {
    return;
  }
  // In the click's handler, Chromium would open a window for Shift and a tab
  // behind for Cmd or Ctrl. From a timer it opens a tab in front, and the
  // click's user activation still allows it.
  setTimeout(() => window.open(resolved, "_blank", "noopener,noreferrer"), 0);
}
