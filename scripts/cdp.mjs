/**
 * LOCKON EWAC — shared Chrome DevTools Protocol plumbing for the app harnesses.
 *
 * Two harnesses drive the real app: `csp-smoke-test.mjs` and
 * `export-smoke-test.mjs`. Everything about *getting attached* is identical for
 * both, and every part of it exists because it was got wrong once:
 *
 *   * WebView2 exposes an `about:blank` target before it navigates, and a
 *     session attached to that one has no page, no events and therefore looks
 *     exactly like a clean run;
 *   * a second launch is handed to the existing window by
 *     `tauri-plugin-single-instance` and exits, so a harness started while the
 *     app is open waits out its whole timeout for a target that cannot arrive;
 *   * the first launch compiles the Rust side, which is minutes;
 *   * Node 22's built-in WebSocket is the browser API, not the `ws` package's
 *     EventEmitter, so these harnesses need no dependency to run.
 *
 * Keeping one copy means a harness cannot be fixed while the other keeps the
 * bug. What is *not* shared is each harness's own `onEvent`: what counts as a
 * failure is the thing they disagree about, and that belongs with each one.
 */
import { spawn, execSync } from 'node:child_process';
import { resolve } from 'node:path';

/** Both spellings of the dev server's address, plus Tauri's own schemes.
 *
 * Vite prints `localhost:1420` but WebView2 reports `127.0.0.1:1420`. Matching
 * only one leaves the harness on `about:blank`.
 */
export const APP_URL_HINTS = ['localhost:1420', '127.0.0.1:1420'];

export async function cdp(port, path) {
  const res = await fetch(`http://127.0.0.1:${port}${path}`);
  if (!res.ok) throw new Error(`${path} -> ${res.status}`);
  return res.json();
}

/** Resolve once a real app page is debuggable, never the `about:blank` target. */
export async function waitForDebugger(port, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastSeen = null;
  while (Date.now() < deadline) {
    try {
      const targets = await cdp(port, '/json/list');
      const pages = targets.filter(t => t.type === 'page' && t.webSocketDebuggerUrl);
      lastSeen = pages.map(p => p.url);
      const real = pages.find(p => APP_URL_HINTS.some(h => p.url.includes(h))
        || p.url.startsWith('tauri://') || p.url.startsWith('http://tauri.'));
      if (real) return real;
    } catch {
      // Not listening yet.
    }
    await new Promise(r => setTimeout(r, 500));
  }
  throw new Error(
    `No WebView2 debug target on port ${port} within ${timeoutMs}ms. `
    + 'On Windows this needs WebView2; if the app window never appeared, run '
    + '`npm run tauri dev` by hand and read its output.'
    + (lastSeen ? ` Targets seen: ${JSON.stringify(lastSeen)}` : '')
  );
}

/**
 * Refuse to start when the app is already running without a debugging port.
 *
 * Exits the process rather than throwing: there is nothing a caller can do
 * about it, and the whole point is to say so in one line instead of hanging.
 */
export async function refuseIfAppAlreadyRunning(port, tag) {
  try {
    const listening = await fetch(`http://127.0.0.1:${port}/json/list`, {
      signal: AbortSignal.timeout(1500),
    }).then(r => r.ok, () => false);
    if (listening) return;
    const running = execSync('tasklist /FI "IMAGENAME eq lockon-ewac.exe" /NH',
      { encoding: 'utf8' });
    if (running.includes('lockon-ewac.exe')) {
      console.error([
        `[${tag}] LOCKON is already running without a debugging port.`,
        '      A second launch is handed to that window by the single-instance',
        '      plugin and exits, so this harness would wait for a target that',
        '      never appears. Close the running app and try again.',
      ].join('\n'));
      process.exit(2);
    }
  } catch {
    // Not on Windows, or tasklist is unavailable: let waitForDebugger report it.
  }
}

/** Launch `npm run tauri dev` with WebView2's remote debugging port open. */
/** The built binary a release run drives, rather than the dev server. */
export const RELEASE_EXE = 'src-tauri/target/release/lockon-ewac.exe';

/**
 * Launch the app with WebView2's remote debugging port open.
 *
 * `mode: 'release'` drives the **built** binary instead of `npm run tauri dev`,
 * and the difference is not cosmetic. Tauri injects `devCsp` under `tauri dev`
 * and `csp` in a build, so a dev run cannot test the policy that ships. That is
 * not theoretical: `csp` allowed `basemaps.cartocdn.com` while the style served
 * from it loads its tiles, glyphs and sprite from `tiles.basemaps.cartocdn.com`,
 * so every installed copy fell back to the offline grid while every dev run — and
 * the harness — reported a clean pass.
 *
 * The same environment variable works for both, because WebView2 reads it from
 * the process environment whoever starts the webview.
 */
export function launchApp(port, mode = 'dev') {
  const release = mode === 'release';
  /*
    The built binary is spawned directly, without a shell.

    `npm` needs `shell: true` on Windows because it is a `.cmd`. An `.exe` does
    not, and routing it through `cmd /d /s /c` actively broke it: the relative
    path uses forward slashes, cmd did not launch it, and the harness then waited
    out its whole fifteen-minute attach timeout with nothing to attach to. It
    looked like WebView2 refusing the debugging port; it was the shell.

    The path is resolved here too, so the spawn does not depend on the working
    directory being the project root.
  */
  const [cmd, args] = release
    ? [resolve(process.cwd(), RELEASE_EXE), []]
    : ['npm', ['run', 'tauri', 'dev']];
  const app = spawn(cmd, args, {
    cwd: process.cwd(),
    env: {
      ...process.env,
      // WebView2 reads this; Tauri passes it through to the webview.
      WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port}`,
    },
    shell: !release,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  const output = [];
  const capture = stream => stream.on('data', d => {
    const text = d.toString();
    output.push(text);
    if (/error|panic|failed/i.test(text)) process.stdout.write(`[app] ${text}`);
  });
  capture(app.stdout);
  capture(app.stderr);
  return { app, output };
}

/**
 * Shut the app down, including the processes `npm run tauri dev` left behind.
 *
 * `app.kill()` alone is not enough: npm spawns a tree, and the webview and the
 * Python sidecar outlive the parent. A survivor is not harmless — the next
 * harness run is refused by `refuseIfAppAlreadyRunning` because the window that
 * is still open has no debugging port, so two consecutive runs could never both
 * work. Found by running the two harnesses back to back.
 */
export async function shutdownApp(app) {
  try { app.kill(); } catch { /* already gone */ }
  for (const image of ['lockon-ewac.exe', 'ewac-engine.exe']) {
    try {
      execSync(`taskkill /IM ${image} /F`, { stdio: 'ignore' });
    } catch {
      // Not running, or not Windows. Either way there is nothing to reap.
    }
  }
  // The tree takes a moment to unwind.
  await new Promise(r => setTimeout(r, 2000));
}

/**
 * One CDP session. Subclass and override `onEvent` to decide what counts as a
 * failure; the request/response plumbing is the same for every harness.
 */
export class Session {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();

    // `addEventListener`, not `.on()`: Node's built-in WebSocket implements the
    // browser API, and the `ws` package's EventEmitter interface is not here.
    ws.addEventListener('message', event => {
      const msg = JSON.parse(typeof event.data === 'string'
        ? event.data
        : Buffer.from(event.data).toString('utf8'));
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
        return;
      }
      this.onEvent(msg);
    });
  }

  /** Overridden by each harness. */
  onEvent() {}

  send(method, params = {}) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`${method} timed out`));
      }, 30000);
    });
  }

  async evaluate(expression) {
    const res = await this.send('Runtime.evaluate', {
      expression, awaitPromise: true, returnByValue: true,
    });
    if (res.exceptionDetails) {
      throw new Error(res.exceptionDetails.exception?.description ?? 'evaluate threw');
    }
    return res.result.value;
  }
}

/** Open the debugger socket and return a session of the given class. */
export async function connect(page, SessionClass = Session) {
  const WebSocket = globalThis.WebSocket;
  if (!WebSocket) {
    throw new Error('No WebSocket available. Node 22 has one built in; check your runtime.');
  }
  const ws = new WebSocket(page.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true });
    ws.addEventListener('error', () => reject(new Error('debugger socket failed')), { once: true });
    setTimeout(() => reject(new Error('debugger socket did not open in 30s')), 30000);
  });
  return new SessionClass(ws);
}

/**
 * Poll a condition with short evaluates.
 *
 * Deliberately not one long `awaitPromise` evaluate: that outlives the 30s CDP
 * send timeout and dies as "Runtime.evaluate timed out", which reads as a broken
 * harness rather than as a condition that has not happened yet. `document.body`
 * is also null while the page reloads, so every probe has to tolerate it.
 */
export async function pollFor(session, label, expression, timeoutMs, log = () => {}) {
  const deadline = Date.now() + timeoutMs;
  let last = null;
  while (Date.now() < deadline) {
    try {
      const value = await session.evaluate(expression);
      if (value) return value;
      last = value;
    } catch (err) {
      last = `threw: ${err.message}`;
    }
    await new Promise(r => setTimeout(r, 1000));
  }
  throw new Error(`timed out after ${timeoutMs}ms waiting for ${label}`
    + (last ? ` (last value: ${JSON.stringify(last)})` : ''));
}
