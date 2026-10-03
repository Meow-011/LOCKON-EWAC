/** LOCKON EWAC — Engine IPC Wrapper (Tauri Sidecar) */
import { Command } from '@tauri-apps/plugin-shell';
import type { EngineMessage, EngineCommand } from '../types/engine';

export type MessageHandler = (msg: EngineMessage) => void;

class EngineIPC {
  private child: Awaited<ReturnType<typeof Command.prototype.spawn>> | null = null;
  private listeners: Map<string, MessageHandler[]> = new Map();
  private _connected = false;
  private _reconnectAttempts = 0;
  private _maxReconnectAttempts = 10;
  private _reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  /**
   * In-flight connect, so concurrent callers share one sidecar.
   *
   * React StrictMode mounts effects twice in dev. `connect()` is async and was
   * not awaited by the cleanup, so cleanup ran while `child` was still null,
   * killed nothing, and the second connect spawned a *second* engine process.
   * Both fed the same listener map, so every AP was written to the database
   * twice and every sonar ping fired twice.
   */
  private _connecting: Promise<void> | null = null;
  /** Set while disconnecting so a late reconnect cannot resurrect the child. */
  private _shuttingDown = false;

  get connected() { return this._connected; }

  async connect(): Promise<void> {
    // `_shuttingDown` is part of this condition on purpose. A disconnect that
    // has already decided to kill the child, but has not finished doing so,
    // still leaves `_connected` true for a moment; returning early there would
    // hand the caller a connection that is about to be destroyed.
    if (this._connected && this.child && !this._shuttingDown) return;

    // Cancel any pending shutdown FIRST, before the in-flight check below.
    //
    // Getting this order wrong left the engine permanently offline. Under React
    // StrictMode the sequence is: mount spawns the sidecar; cleanup calls
    // disconnect(), which sets the shutdown flag and then awaits the in-flight
    // spawn; the second mount calls connect() again, which returned the very
    // same in-flight promise without clearing the flag. That spawn then resolved
    // into its own "we are shutting down" branch, killed the process it had just
    // created, and nothing ever spawned again. The engine log showed it exactly:
    // "Engine starting" followed immediately by "stdin closed; engine exiting",
    // and no second start.
    this._shuttingDown = false;

    if (this._connecting) return this._connecting;

    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }

    this._connecting = this._spawn()
      .finally(() => { this._connecting = null; });
    return this._connecting;
  }

  private async _spawn(): Promise<void> {
    /*
      The path here must match `externalBin` in `tauri.conf.json` exactly.

      The sidecar is built one-directory rather than one-file — onefile unpacked
      72 MB into %TEMP% on every launch and took ~20 s to answer, against ~2 s
      now — so the executable lives in `binaries/ewac-engine/` beside its
      `_internal/`. Tauri matches this string against the configured list, and a
      mismatch fails at spawn with "sidecar not configured under
      tauri.conf.json > bundle > externalBin", which the reconnect loop then
      retries ten times before giving up.
    */
    const command = Command.sidecar('binaries/ewac-engine/ewac-engine');

    command.stdout.on('data', (line: string) => {
      try {
        const msg: EngineMessage = JSON.parse(line);
        this.dispatch(msg);
      } catch { /* ignore non-JSON lines */ }
    });

    command.stderr.on('data', (line: string) => {
      // Not everything on stderr is a failure. Python writes warnings there,
      // and logging its own WARNING records there is deliberate — the engine
      // keeps stdout clean because that is the IPC channel. Shouting
      // "[Engine STDERR]" through console.error at a deprecation notice from a
      // third-party library trains you to ignore the channel that also carries
      // real tracebacks, so classify instead.
      const text = String(line ?? '');
      if (!text.trim()) return;

      const looksFatal = /Traceback \(most recent call last\)|^\s*(CRITICAL|ERROR)\b|Error:|Exception\b/m.test(text);
      const looksWarning = /\bWARNING\b|Warning:/m.test(text);

      if (looksFatal) console.error('[Engine]', text);
      else if (looksWarning) console.warn('[Engine]', text);
      else console.debug('[Engine]', text);
    });

    command.on('close', () => {
      this._connected = false;
      this.child = null;
      this.dispatch({ event: 'disconnected', data: {}, ts: new Date().toISOString() });
      if (!this._shuttingDown) this._attemptReconnect();
    });

    const child = await command.spawn();
    if (this._shuttingDown) {
      // disconnect() was called while the spawn was in flight.
      await child.kill().catch(() => {});
      return;
    }
    this.child = child;
    this._connected = true;
    this._reconnectAttempts = 0; // Reset on successful connect
  }

  /**
   * Retry a failed connect.
   *
   * Spawn failures used to be terminal: auto-reconnect only ran from the
   * `close` handler, which never fires when the process could not start, so a
   * missing or AV-quarantined sidecar left the app permanently offline with no
   * recovery short of a restart.
   */
  async connectWithRetry(): Promise<void> {
    try {
      await this.connect();
    } catch (err) {
      console.error('[Engine IPC] Spawn failed:', err);
      this.dispatch({
        event: 'spawn_failed',
        data: { message: String(err), attempt: this._reconnectAttempts + 1 },
        ts: new Date().toISOString(),
      });
      this._attemptReconnect();
      throw err;
    }
  }

  private _attemptReconnect() {
    if (this._shuttingDown) return;
    if (this._reconnectAttempts >= this._maxReconnectAttempts) {
      console.error(`[Engine IPC] Max reconnect attempts (${this._maxReconnectAttempts}) reached. Giving up.`);
      this.dispatch({ event: 'reconnect_failed', data: { attempts: this._reconnectAttempts }, ts: new Date().toISOString() });
      return;
    }

    const delay = Math.min(1000 * Math.pow(2, this._reconnectAttempts), 30000); // 1s, 2s, 4s... max 30s
    this._reconnectAttempts++;
    console.warn(`[Engine IPC] Reconnecting in ${delay}ms (attempt ${this._reconnectAttempts}/${this._maxReconnectAttempts})...`);

    this.dispatch({ event: 'reconnecting', data: { attempt: this._reconnectAttempts, delay }, ts: new Date().toISOString() });

    this._reconnectTimer = setTimeout(async () => {
      this._reconnectTimer = null;
      try {
        await this.connect();
        console.log('[Engine IPC] Reconnected successfully.');
        this.dispatch({ event: 'reconnected', data: {}, ts: new Date().toISOString() });
      } catch (err) {
        console.error('[Engine IPC] Reconnect failed:', err);
        this._attemptReconnect();
      }
    }, delay);
  }

  /**
   * Send a command to the engine.
   *
   * Typed against EngineCommand so a mistyped name is a compile error rather
   * than a silent "Unknown command" at runtime — the union existed already but
   * the signature took a bare string, so it protected nothing.
   */
  async send(cmd: EngineCommand, data?: Record<string, unknown>) {
    if (!this.child) throw new Error('Engine not connected');
    const message = JSON.stringify({ cmd, data: data ?? {} }) + '\n';
    await this.child.write(message);
  }

  on(event: string, handler: MessageHandler) {
    const handlers = this.listeners.get(event) ?? [];
    handlers.push(handler);
    this.listeners.set(event, handlers);
    return () => this.off(event, handler); // Return unsubscribe function
  }

  off(event: string, handler: MessageHandler) {
    const handlers = this.listeners.get(event) ?? [];
    this.listeners.set(event, handlers.filter(h => h !== handler));
  }

  /**
   * Wait for the one `event` message whose `id` matches, or give up.
   *
   * The engine answers some commands per subject rather than per call:
   * `verify_evidence` echoes back the row id it was given precisely so a caller
   * re-hashing a whole register can tell which answer belongs to which artifact.
   * Without a keyed wait, the only way to consume those replies is a flat
   * listener plus caller-side bookkeeping, which is part of why the register
   * verifier shipped with no caller at all.
   *
   * It rejects on timeout rather than resolving with a default. A silent default
   * here would be recorded as a verification result, and an artifact that was
   * never actually checked must not end up in the report as one that was. The
   * caller counts a rejection as `failed`, which the PDF states separately.
   *
   * The listener is removed on every exit path, including the timeout, so a
   * late reply cannot settle an already-abandoned promise or accumulate.
   */
  awaitKeyed<T extends { id?: unknown }>(
    event: string,
    id: number,
    timeoutMs = 15000,
  ): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      let unsubscribe: (() => void) | null = null;
      const timer = setTimeout(() => {
        unsubscribe?.();
        reject(new Error(`No ${event} for id ${id} within ${timeoutMs}ms`));
      }, timeoutMs);

      unsubscribe = this.on(event, (msg) => {
        const payload = msg.data as T | undefined;
        // Compared as numbers on purpose: the id crosses a JSON boundary, and a
        // sidecar that echoed it back as a string would otherwise never match,
        // which would read as a timeout -- an artifact reported unchecked when
        // the engine did in fact check it.
        if (!payload || Number(payload.id) !== id) return;
        clearTimeout(timer);
        unsubscribe?.();
        resolve(payload);
      });
    });
  }

  private dispatch(msg: EngineMessage) {
    /*
      Each handler is isolated, and a throw is reported rather than discarded.

      There was no isolation at all: two bare `forEach` calls. A single handler
      throwing synchronously — a `msg.data as {...}` field arriving undefined and a
      `.map` or `.toUpperCase` run on it — aborted the `forEach`, so every later
      handler for that event and all the wildcard listeners were skipped for that
      message. With 61 subscriptions registered in one place, the ones that lost
      their event depended on registration order.

      Worse, the only call site that matters sits inside
      `try { JSON.parse(line); this.dispatch(msg) } catch {}`, whose comment reads
      "ignore non-JSON lines". So the throw was swallowed with no console line,
      indistinguishable from a stray print on the engine's stdout, and a database
      write or a store update simply did not happen. (One of the other dispatch
      sites is inside the reconnect timer's `try`, where a handler throw also
      produced a spurious "Reconnect failed" and another reconnect attempt.)

      Reported per handler and per listener list, so one bad handler costs its own
      update and nothing else.
    */
    this.deliver(this.listeners.get(msg.event), msg, msg.event);
    this.deliver(this.listeners.get('*'), msg, `${msg.event} (wildcard)`);
  }

  /** Call each handler in its own try, so one failure cannot silence the rest. */
  private deliver(handlers: MessageHandler[] | undefined, msg: EngineMessage, label: string) {
    if (!handlers?.length) return;
    // A copy: a handler may call `off()` (several unsubscribe on their own
    // terminal event), and mutating the array being iterated skips a neighbour.
    for (const h of [...handlers]) {
      try {
        h(msg);
      } catch (err) {
        console.error(`[Engine IPC] handler for '${label}' threw:`, err);
      }
    }
  }

  /**
   * Shut the sidecar down.
   *
   * Call this when the application is closing, not from a component cleanup.
   * The engine is an app-lifetime singleton: tearing it down whenever a
   * component unmounts fights React's development double-mount and, when it
   * loses, leaves the app with no engine at all.
   */
  async disconnect() {
    this._shuttingDown = true;

    if (this._reconnectTimer) {
      clearTimeout(this._reconnectTimer);
      this._reconnectTimer = null;
    }

    // Wait for an in-flight spawn so we kill the process it produced instead of
    // leaving it orphaned.
    if (this._connecting) {
      await this._connecting.catch(() => {});
    }

    // A connect() issued while we were waiting cancels this shutdown — it means
    // something still wants the engine, and killing it now would strand them.
    if (!this._shuttingDown) return;

    // Clear the state against *this* child, not whatever is in the field by the
    // time the kill resolves. A connect() racing the kill installs a fresh child
    // mid-await, and blanking the field unconditionally would throw that new,
    // healthy connection away and leave the app offline with no way back.
    const doomed = this.child;
    if (doomed) {
      await doomed.kill().catch(err => console.error('[Engine IPC] Kill failed:', err));
      if (this.child === doomed) {
        this.child = null;
        this._connected = false;
      }
    } else if (this._shuttingDown) {
      this._connected = false;
    }
  }
}

export const engineIPC = new EngineIPC();
