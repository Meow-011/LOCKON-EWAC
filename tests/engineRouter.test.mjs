/**
 * Tests for the engine's contract with the application.
 *
 *     npm run test:router
 *
 * Why this exists.
 *
 * Sixty-one `engineIPC.on()` handlers lived inside `AppShell`, a layout
 * component, in one 900-line `useEffect`. Forty-eight were pure routing: take an
 * event off the sidecar, write it to a store or to SQLite. That is the boundary
 * where the engine's vocabulary meets this app's schema — and it is exactly the
 * boundary where a field renamed on one side and not the other stops being
 * stored at all, silently. This project has paid for that twice: `cipher` and
 * `auth_type` were declared in the schema, in the types and in the table, and
 * never once populated; `radio_type` reached the live feed and had no column.
 * Neither was visible from the outside, because nothing could reach the wiring.
 *
 * These tests drive the whole path — the real `ipc.ts`, a stub child process,
 * a line of JSON on its stdout, the real handlers, real stores, real SQLite with
 * the project's migrations — and assert what came out the far end.
 */

import test, { before, beforeEach, after } from 'node:test';
import assert from 'node:assert/strict';

import { migrationFiles } from './stubs/plugin-sql-sqlite.mjs';
import {
  engineIPC,
  liveChildren,
  registerEngineHandlers,
  resetShellStub,
  useEngineStore,
  useIntrusionStore,
  useMissionStore,
  registerEngineHandlers as register,
} from '../.test-build/db.mjs';

/** Everything the hooks were asked to show, so a test can assert on it. */
let toasts = [];
let connErrors = [];
let pings = [];
let stopRouting = null;

const hooks = {
  showToast: (message, type, duration) => toasts.push({ message, type, duration }),
  setConnError: message => connErrors.push(message),
  sonarPing: isHighRisk => pings.push(isHighRisk),
};

/**
 * Push one engine event down the sidecar's stdout, as the real process would.
 *
 * The stream hangs off the `Command`, not the child — the child is what you
 * write *to*. Reaching for `child.stdout` finds undefined, which fails every
 * test at once and says nothing about the router.
 */
function emit(event, data = {}) {
  const child = liveChildren()[0];
  assert.ok(child, 'no live sidecar; did connect() run?');
  child.command.stdout.emit('data', JSON.stringify({ event, data, ts: '2026-09-30T00:00:00Z' }));
}

before(async () => {
  resetShellStub();
  await engineIPC.connectWithRetry();
});

beforeEach(() => {
  migrationFiles.reset?.();
  toasts = [];
  connErrors = [];
  pings = [];
  stopRouting?.();
  stopRouting = registerEngineHandlers(hooks);
});

after(() => stopRouting?.());

// ── An access point has to survive the trip ─────────────────────────────────

test('an ap_found event reaches the mission store with its fields intact', () => {
  /*
    The fields listed here are the ones this project has lost before. `cipher`
    and `auth_type` were declared everywhere and populated nowhere for weeks;
    `radio_type`, `connected_stations` and `channel_utilization_pct` reached the
    live feed and had no column to land in. Asserting them by name is the cheap
    way to notice a rename that only half happened.
  */
  emit('ap_found', {
    bssid: 'AA:BB:CC:DD:EE:01', ssid: 'GUEST', encryption: 'OPEN',
    cipher: 'NONE', auth_type: 'Open', radio_type: '802.11ax',
    connected_stations: 12, channel_utilization_pct: 41,
    channel: 6, frequency: 2437, rssi: -55, is_vulnerable: true, simulated: false,
  });

  const ap = useMissionStore.getState().accessPoints.get('AA:BB:CC:DD:EE:01');
  assert.ok(ap, 'the access point never reached the store');
  assert.equal(ap.ssid, 'GUEST');
  assert.equal(ap.encryption, 'OPEN');
  assert.equal(ap.cipher, 'NONE');
  assert.equal(ap.auth_type, 'Open');
  assert.equal(ap.radio_type, '802.11ax');
  assert.equal(ap.connected_stations, 12);
  assert.equal(ap.channel_utilization_pct, 41);
  assert.equal(ap.rssi, -55);
});

test('a station count of zero survives, because it is a measurement', () => {
  // "The adapter published a count and it was zero" and "the adapter published
  // nothing" are different findings, and a `||`-style read anywhere along this
  // path collapses them.
  emit('ap_found', { bssid: 'AA:BB:CC:DD:EE:02', encryption: 'OPEN', connected_stations: 0 });
  const ap = useMissionStore.getState().accessPoints.get('AA:BB:CC:DD:EE:02');
  assert.equal(ap.connected_stations, 0);
});

test('the sonar pings once for a new access point, not again for a repeat sighting', () => {
  emit('ap_found', { bssid: 'AA:BB:CC:DD:EE:03', encryption: 'WPA2' });
  emit('ap_found', { bssid: 'AA:BB:CC:DD:EE:03', encryption: 'WPA2', rssi: -60 });
  assert.equal(pings.length, 1, 'a re-sighting is not a discovery');
});

test('the ping is told whether the network is high risk', () => {
  emit('ap_found', { bssid: 'AA:BB:CC:DD:EE:04', encryption: 'OPEN' });
  assert.equal(pings.at(-1), true, 'an open network is high risk without needing is_vulnerable');
  emit('ap_found', { bssid: 'AA:BB:CC:DD:EE:05', encryption: 'WPA2' });
  assert.equal(pings.at(-1), false);
});

test('routing runs with no sonarPing hook at all', () => {
  // The hook is optional so the routing can be exercised without Web Audio.
  // If this throws, the split has leaked a UI dependency back into the router.
  stopRouting?.();
  stopRouting = register({ showToast: hooks.showToast, setConnError: hooks.setConnError });
  assert.doesNotThrow(() => emit('ap_found', { bssid: 'AA:BB:CC:DD:EE:06', encryption: 'OPEN' }));
  assert.ok(useMissionStore.getState().accessPoints.has('AA:BB:CC:DD:EE:06'));
});

// ── GPS ────────────────────────────────────────────────────────────────────

test('a gps_update carries fix quality, not just a position', () => {
  // `satellites` and `hdop` are why this matters: the KPI tile used to show a
  // hardcoded 8 satellites, so a bad fix looked like a good one.
  emit('gps_update', {
    latitude: 13.7, longitude: 100.5, heading: 90, speed: 12, satellites: 6, hdop: 1.8,
  });
  const s = useEngineStore.getState();
  assert.equal(s.latitude, 13.7);
  assert.equal(s.longitude, 100.5);
  assert.equal(s.satellites, 6);
  assert.equal(s.hdop, 1.8);
});

// ── Engine state ───────────────────────────────────────────────────────────

test('a pong marks the engine connected', () => {
  useEngineStore.getState().setConnected(false);
  emit('pong');
  assert.equal(useEngineStore.getState().connected, true);
});

test('a disconnect marks it offline rather than leaving the last state showing', () => {
  useEngineStore.getState().setConnected(true);
  emit('disconnected');
  assert.equal(useEngineStore.getState().connected, false);
});

test('a ready event records the build stamp, which is what names a sidecar', () => {
  /*
    "0.1.0" names every build ever made. The git describe and the build time are
    what let a severity in a report be traced to the software that produced it,
    and the store field existed for a while with nothing writing to it.
  */
  emit('ready', {
    version: '0.1.0',
    build: {
      version: '0.1.0', frozen: true, built_at: '2026-09-29T08:23:10+00:00',
      git_describe: '19fc107', python: '3.13.5', bundle_dir: null,
    },
  });
  const build = useEngineStore.getState().engineBuild;
  assert.ok(build, 'the build stamp was dropped');
  assert.equal(build.git_describe, '19fc107');
  assert.equal(build.frozen, true);
});

// ── Intrusion ──────────────────────────────────────────────────────────────

test('intrusion progress reaches the intrusion store with all three numbers', () => {
  /*
    Three separate figures, and the report reads all of them: a percentage is
    not enough to state what the sweep covered. `progress` is a number, so a
    truthiness check would pass on a store that recorded nothing — assert the
    values.
  */
  emit('intrusion_progress', { progress: 37, scanned: 94, total: 254 });
  const s = useIntrusionStore.getState();
  assert.equal(s.progress, 37);
  assert.equal(s.scannedCount, 94);
  assert.equal(s.totalCount, 254);
});

test('a host found during a sweep is keyed by address, so a re-sighting is one host', () => {
  // `hosts` is keyed on the IP, which is what makes this true by construction —
  // the test is here so a change to a list would have to justify itself.
  emit('intrusion_host_found', { ip: '10.0.0.5', hostname: 'nas', open_ports: [] });
  emit('intrusion_host_found', { ip: '10.0.0.5', hostname: 'nas-renamed', open_ports: [] });
  const hosts = useIntrusionStore.getState().hosts;
  assert.equal(Object.keys(hosts).filter(ip => ip === '10.0.0.5').length, 1);
  assert.equal(hosts['10.0.0.5'].hostname, 'nas-renamed', 'the later sighting wins');
});

// ── Failures the operator has to be told about ──────────────────────────────

test('an engine error is surfaced rather than swallowed', () => {
  // A capture that cannot run and a target that is secure produce the same
  // silence. Every failure path here has to reach the operator.
  emit('error', { message: 'monitor mode unavailable' });
  assert.ok(toasts.length > 0, 'nothing was shown for an engine error');
  assert.match(toasts.at(-1).message, /monitor mode unavailable/);
});

test('a gps_error says the receiver is absent instead of inventing a position', () => {
  emit('gps_error', { message: 'COM3 did not respond in time' });
  assert.ok(toasts.some(t => /COM3/.test(t.message)));
  const s = useEngineStore.getState();
  assert.ok(s.latitude === null || typeof s.latitude === 'number',
    'a GPS error must not leave a fabricated coordinate');
});

// ── Unsubscribing has to actually unsubscribe ──────────────────────────────

test('the returned cleanup detaches every handler', () => {
  /*
    61 subscriptions and 61 unsubscribe calls. A handler left attached after
    cleanup is how a development double-mount ends up writing every access point
    twice — which looks like the engine reporting duplicates.
  */
  emit('ap_found', { bssid: 'AA:BB:CC:DD:EE:07', encryption: 'WPA2' });
  assert.ok(useMissionStore.getState().accessPoints.has('AA:BB:CC:DD:EE:07'));

  stopRouting();
  stopRouting = null;
  const before = useMissionStore.getState().accessPoints.size;
  const pingsBefore = pings.length;

  emit('ap_found', { bssid: 'AA:BB:CC:DD:EE:08', encryption: 'OPEN' });
  emit('gps_update', { latitude: 1, longitude: 2 });
  emit('error', { message: 'should not be shown' });

  assert.equal(useMissionStore.getState().accessPoints.size, before,
    'a handler survived cleanup');
  assert.equal(pings.length, pingsBefore);
  assert.ok(!toasts.some(t => /should not be shown/.test(t.message)));
});

test('registering twice and cleaning up both leaves no listener behind', () => {
  // The cleanup returned by one registration must not detach another's handlers,
  // and must fully detach its own. The ambient registration from `beforeEach` has
  // to come down too, or it routes the event and the assertion blames the wrong
  // thing — which is exactly what happened when this was first written.
  stopRouting();
  stopRouting = null;
  const first = register(hooks);
  const second = register(hooks);
  first();
  second();
  const before = useMissionStore.getState().accessPoints.size;
  emit('ap_found', { bssid: 'AA:BB:CC:DD:EE:09', encryption: 'OPEN' });
  assert.equal(useMissionStore.getState().accessPoints.size, before);
  stopRouting = register(hooks);
});

// ── Malformed input from a process we do not control ────────────────────────

test('an event with no data does not take the router down', () => {
  // The sidecar is a separate process and its output is not a contract this
  // module can enforce. A handler that throws would break the whole event loop
  // for every later event, not just its own.
  for (const event of ['ap_found', 'gps_update', 'status', 'intrusion_progress', 'ready']) {
    assert.doesNotThrow(() => emit(event, {}), `${event} with empty data`);
  }
  // Still routing afterwards.
  emit('ap_found', { bssid: 'AA:BB:CC:DD:EE:0A', encryption: 'WPA2' });
  assert.ok(useMissionStore.getState().accessPoints.has('AA:BB:CC:DD:EE:0A'));
});
