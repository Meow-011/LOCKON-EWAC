/**
 * Regression tests for the engine connection state machine.
 *
 *     npm run test:ipc
 *
 * These exist because of a real failure: the app launched, the sidecar started,
 * and the UI sat on "Engine: OFFLINE" forever. The engine's own log told the
 * story in two lines —
 *
 *     Engine starting
 *     stdin closed; engine exiting
 *
 * — with no second start. React's development double-mount spawned the engine,
 * the effect cleanup called disconnect() which set the shutdown flag and then
 * awaited the in-flight spawn, and the second mount called connect() again.
 * connect() returned that same in-flight promise *before* clearing the flag, so
 * the spawn resolved into its own shutdown branch, killed the process it had
 * just created, and nothing ever spawned again.
 *
 * The ordering inside connect() is therefore load-bearing, which is exactly the
 * kind of thing that gets "tidied" later. Hence these tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { engineIPC } from '../.test-build/ipc.mjs';
import { resetShellStub, spawned, liveChildren } from './stubs/plugin-shell.mjs';

const tick = (ms = 0) => new Promise(r => setTimeout(r, ms));

async function freshIPC() {
  // The module exports a singleton, so reset it between tests.
  await engineIPC.disconnect().catch(() => {});
  resetShellStub();
  return engineIPC;
}

test('a normal connect produces exactly one live engine', async () => {
  const ipc = await freshIPC();
  await ipc.connect();
  assert.equal(spawned.length, 1);
  assert.equal(liveChildren().length, 1);
  assert.equal(ipc.connected, true);
});

test('React StrictMode double-mount leaves the engine running', async () => {
  // The exact sequence that produced the OFFLINE bug: mount, cleanup, mount —
  // with the cleanup's disconnect racing an in-flight spawn.
  const ipc = await freshIPC();
  resetShellStub({ delay: 20 });          // spawn is slow enough to overlap

  const mount1 = ipc.connect();           // mount 1, not awaited
  const cleanup = ipc.disconnect();       // effect cleanup, not awaited
  const mount2 = ipc.connect();           // mount 2, immediately after

  await Promise.all([mount1, cleanup, mount2]);
  await tick(30);

  assert.equal(ipc.connected, true, 'the app must end up connected');
  assert.equal(liveChildren().length, 1, 'exactly one engine should be alive');
});

test('a late connect cancels a pending shutdown', async () => {
  const ipc = await freshIPC();
  resetShellStub({ delay: 20 });

  await ipc.connect();
  assert.equal(liveChildren().length, 1);

  const closing = ipc.disconnect();
  const reopening = ipc.connect();        // something still wants the engine
  await Promise.all([closing, reopening]);
  await tick(30);

  assert.equal(ipc.connected, true, 'the reconnect must win over the shutdown');
  assert.equal(liveChildren().length, 1);
});

test('concurrent connects never spawn a second engine', async () => {
  // Two engines feeding the same listener map is what wrote every access point
  // to the database twice.
  const ipc = await freshIPC();
  resetShellStub({ delay: 10 });

  await Promise.all([ipc.connect(), ipc.connect(), ipc.connect()]);
  await tick(20);

  assert.equal(spawned.length, 1, `spawned ${spawned.length} engines`);
  assert.equal(liveChildren().length, 1);
});

test('connect is a no-op once already connected', async () => {
  const ipc = await freshIPC();
  await ipc.connect();
  await ipc.connect();
  await ipc.connect();
  assert.equal(spawned.length, 1);
});

test('an explicit disconnect really stops the engine', async () => {
  const ipc = await freshIPC();
  await ipc.connect();
  await ipc.disconnect();
  assert.equal(liveChildren().length, 0, 'the child must be killed');
  assert.equal(ipc.connected, false);
});

test('after a disconnect the engine can be started again', async () => {
  const ipc = await freshIPC();
  await ipc.connect();
  await ipc.disconnect();
  await ipc.connect();
  assert.equal(ipc.connected, true);
  assert.equal(liveChildren().length, 1);
});

test('a failed spawn reports the failure and schedules a retry', async () => {
  const ipc = await freshIPC();
  resetShellStub({ fail: true });

  const events = [];
  const off = ipc.on('spawn_failed', m => events.push(m));

  await assert.rejects(() => ipc.connectWithRetry());
  assert.equal(events.length, 1, 'a spawn failure must be announced');
  assert.equal(ipc.connected, false);

  off();
  await ipc.disconnect().catch(() => {});
});

test('send throws rather than silently dropping when not connected', async () => {
  const ipc = await freshIPC();
  await assert.rejects(() => ipc.send('ping'), /not connected/i);
});

test('messages reach subscribers and unsubscribe cleanly', async () => {
  const ipc = await freshIPC();
  await ipc.connect();

  const seen = [];
  const off = ipc.on('ready', m => seen.push(m));
  const command = spawned[0].command;

  command.stdout.emit('data', JSON.stringify({ event: 'ready', data: { version: '0.1.0' }, ts: 't' }));
  assert.equal(seen.length, 1);
  assert.equal(seen[0].data.version, '0.1.0');

  off();
  command.stdout.emit('data', JSON.stringify({ event: 'ready', data: {}, ts: 't' }));
  assert.equal(seen.length, 1, 'no delivery after unsubscribe');
});

test('malformed engine output does not throw', async () => {
  const ipc = await freshIPC();
  await ipc.connect();
  const command = spawned[0].command;
  // The engine prints a CryptographyDeprecationWarning to stdout's neighbour on
  // startup; non-JSON must simply be ignored.
  assert.doesNotThrow(() => command.stdout.emit('data', 'not json at all'));
  assert.doesNotThrow(() => command.stdout.emit('data', ''));
});

test('an engine that dies on its own is reported as disconnected', async () => {
  const ipc = await freshIPC();
  await ipc.connect();

  const events = [];
  const off = ipc.on('disconnected', m => events.push(m));
  spawned[0].command.handlers.close?.();

  assert.equal(events.length, 1);
  assert.equal(ipc.connected, false);
  off();
  await ipc.disconnect().catch(() => {});
});

/*
  ── One bad handler used to silence every handler after it ────────────────────

  `dispatch` was two bare `forEach` calls with no isolation, and its only real call
  site sits inside `try { JSON.parse(line); this.dispatch(msg) } catch {}` — whose
  comment reads "ignore non-JSON lines".

  So a handler throwing synchronously (a `msg.data as {...}` field arriving undefined
  and a `.map` run on it) aborted the forEach, skipping every later handler for that
  event and all the wildcard listeners, and the error was discarded with no console
  line at all — indistinguishable from a stray print on the engine's stdout. Which
  handlers lost their event depended on registration order, and 61 are registered in
  one place.
*/

test('a handler that throws does not stop the handlers after it', async () => {
  const ipc = await freshIPC();
  await ipc.connect();
  const command = spawned[0].command;

  const reached = [];
  const offA = ipc.on('ready', () => { reached.push('first'); });
  const offB = ipc.on('ready', () => { throw new Error('field was undefined'); });
  const offC = ipc.on('ready', () => { reached.push('third'); });

  command.stdout.emit('data', JSON.stringify({ event: 'ready', data: {}, ts: 't' }));

  assert.deepEqual(reached, ['first', 'third'],
    'a throw in the middle handler cost the one registered after it');
  offA(); offB(); offC();
});

test('a throwing event handler does not cost the wildcard listeners', async () => {
  // The wildcard list is dispatched after the per-event one, so it used to be
  // skipped entirely whenever any event handler threw.
  const ipc = await freshIPC();
  await ipc.connect();
  const command = spawned[0].command;

  let wildcardSaw = 0;
  const offThrow = ipc.on('ready', () => { throw new Error('boom'); });
  const offStar = ipc.on('*', () => { wildcardSaw += 1; });

  command.stdout.emit('data', JSON.stringify({ event: 'ready', data: {}, ts: 't' }));

  assert.equal(wildcardSaw, 1);
  offThrow(); offStar();
});

test('a handler throw is reported rather than swallowed', async () => {
  /*
    The dispatch call sits inside the JSON.parse catch, so the throw produced no
    output of any kind. A database write that silently did not happen is the worst
    possible shape for this failure in a tool that produces evidence.
  */
  const ipc = await freshIPC();
  await ipc.connect();
  const command = spawned[0].command;

  const originalError = console.error;
  const logged = [];
  console.error = (...args) => { logged.push(args.map(String).join(' ')); };
  try {
    const off = ipc.on('ready', () => { throw new Error('field was undefined'); });
    command.stdout.emit('data', JSON.stringify({ event: 'ready', data: {}, ts: 't' }));
    off();
  } finally {
    console.error = originalError;
  }

  assert.ok(logged.some(l => l.includes('ready') && l.includes('field was undefined')),
    `the throw was not reported; console.error got ${JSON.stringify(logged)}`);
});

test('a handler that unsubscribes during dispatch does not skip its neighbour', async () => {
  // Several handlers call `off()` on their own terminal event. Mutating the array
  // being iterated drops the next element, so dispatch iterates a copy.
  const ipc = await freshIPC();
  await ipc.connect();
  const command = spawned[0].command;

  const reached = [];
  const offA = ipc.on('ready', () => { reached.push('first'); offA(); });
  const offB = ipc.on('ready', () => { reached.push('second'); });

  command.stdout.emit('data', JSON.stringify({ event: 'ready', data: {}, ts: 't' }));

  assert.deepEqual(reached, ['first', 'second']);
  offB();
});
