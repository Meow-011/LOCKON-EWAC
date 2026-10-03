/**
 * Tests for the four stores that had none.
 *
 *     npm run test:stores
 *
 * Why these four, and why these cases.
 *
 * None of them is large, and none holds an algorithm. What they hold is a set of
 * decisions about **what the application is allowed to claim** when something
 * goes wrong or arrives twice, and every one of those decisions is written down
 * in a comment next to the code that makes it. A comment is not a guarantee, so
 * each of those comments has an assertion here.
 *
 * Three recurring shapes, all of them things this project has been burned by:
 *
 *   * **A failed write must not look like a successful one.** `addReport` used
 *     to swallow a duplicate-id failure and still show a success toast, so the
 *     operator believed an archive was stored when nothing had been.
 *   * **A failed read must not look like an empty result.** An empty archive list
 *     reads as "no surveys were ever done", which is a different statement from
 *     "the database could not be read".
 *   * **A session that runs for hours must stay bounded**, and the caps are the
 *     only thing making that true.
 *
 * `reportStore` runs against real SQLite with the project's migrations, so the
 * duplicate-id case is exercised by the actual primary key rather than a mock.
 */

import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';

/*
  zustand's `persist` middleware reaches for `localStorage` at import time.
  Node has none, so `uiStore` would be imported through a warning path that
  behaves differently from the browser. This is the smallest shim that lets the
  real middleware run, and the persistence test below asserts against it
  directly.
*/
const store = new Map();
const shim = {
  getItem: k => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: k => store.delete(k),
  clear: () => store.clear(),
};
globalThis.localStorage = shim;
// zustand's default persist storage looks for `window.localStorage`, not the
// bare global, so both have to be present before the store module is imported.
globalThis.window = globalThis.window ?? {};
globalThis.window.localStorage = shim;

const {
  getDb,
  usePassiveSigintStore,
  useReportStore,
  useStrikeStore,
  useUIStore,
} = await import('../.test-build/db.mjs');

const report = (over = {}) => ({
  id: 'R1',
  type: 'WIFI_WARDRIVE',
  targetName: 'FIELD SCAN',
  timestamp: 1790580589986,
  summary: { totalAPs: 10, vulnerableAPs: 2 },
  rawData: { accessPoints: [] },
  ...over,
});

beforeEach(async () => {
  /*
    Wipe the tables rather than the database. `resetDatabase()` closes the
    connection, and the modules under test hold their own handle to it — so the
    next call would run against a closed database. This is the same approach
    `database.test.mjs` takes, and for the same reason.
  */
  const db = await getDb();
  db.raw.exec('PRAGMA foreign_keys = OFF');
  for (const { name } of db.raw
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    .all()) {
    if (name === '_sqlx_migrations') continue;
    db.raw.exec(`DELETE FROM "${name}"`);
  }
  db.raw.exec('PRAGMA foreign_keys = ON');

  useReportStore.setState({ reports: [] });
  usePassiveSigintStore.getState().reset();
  useStrikeStore.setState({ activeStrikes: {} });
  store.clear();
});

// ── reportStore: a write that failed must not read as one that worked ────────

test('a stored archive appears newest first', async () => {
  await useReportStore.getState().addReport(report({ id: 'R1' }));
  await useReportStore.getState().addReport(report({ id: 'R2' }));
  assert.deepEqual(useReportStore.getState().reports.map(r => r.id), ['R2', 'R1']);
});

test('re-importing the same archive rejects instead of reporting success', async () => {
  /*
    The defect this behaviour exists for: the duplicate INSERT failed, the error
    was swallowed, and the UI showed a success toast — so the operator believed a
    report had been stored when nothing had. `addReport` deliberately does not
    catch, so the caller has to deal with it.
  */
  await useReportStore.getState().addReport(report({ id: 'DUP' }));
  await assert.rejects(() => useReportStore.getState().addReport(report({ id: 'DUP' })));
});

test('a rejected write does not leave the archive in the list either', async () => {
  // The in-memory list is what the UI renders. A phantom row there is the same
  // lie as a success toast, one render later.
  await useReportStore.getState().addReport(report({ id: 'DUP' }));
  await useReportStore.getState().addReport(report({ id: 'DUP' })).catch(() => {});
  assert.equal(useReportStore.getState().reports.filter(r => r.id === 'DUP').length, 1);
});

test('loading archives replaces the list with what the database holds', async () => {
  await useReportStore.getState().addReport(report({ id: 'R1' }));
  useReportStore.setState({ reports: [] });
  await useReportStore.getState().loadReports();
  assert.deepEqual(useReportStore.getState().reports.map(r => r.id), ['R1']);
});

test('a failed load leaves the previous list alone rather than emptying it', async () => {
  /*
    An empty archive index reads as "no survey was ever done". That is a
    different statement from "the database could not be read", and only one of
    them is true when a read throws. The store keeps what it had; the console
    carries the error.
  */
  await useReportStore.getState().addReport(report({ id: 'KEEP' }));
  const { getDb } = await import('../.test-build/db.mjs');
  const db = await getDb();
  const realSelect = db.select;
  db.select = async () => { throw new Error('database is locked'); };
  try {
    await useReportStore.getState().loadReports();
  } finally {
    db.select = realSelect;
  }
  assert.deepEqual(useReportStore.getState().reports.map(r => r.id), ['KEEP']);
});

test('deleting an archive removes exactly that one', async () => {
  await useReportStore.getState().addReport(report({ id: 'R1' }));
  await useReportStore.getState().addReport(report({ id: 'R2' }));
  await useReportStore.getState().deleteReport('R1');
  assert.deepEqual(useReportStore.getState().reports.map(r => r.id), ['R2']);
});

test('renaming changes the title of one archive and nothing else about it', async () => {
  // The title is what the operator recognises the engagement by, and it is
  // printed on the PDF cover — but it must not disturb the payload.
  await useReportStore.getState().addReport(report({ id: 'R1', targetName: 'OLD' }));
  await useReportStore.getState().renameReport('R1', 'NEW NAME');
  const [r] = useReportStore.getState().reports;
  assert.equal(r.targetName, 'NEW NAME');
  assert.equal(r.id, 'R1');
  assert.deepEqual(r.summary, { totalAPs: 10, vulnerableAPs: 2 });
});

test('renaming an archive that is not there changes nothing', async () => {
  await useReportStore.getState().addReport(report({ id: 'R1', targetName: 'OLD' }));
  await useReportStore.getState().renameReport('NOPE', 'NEW');
  assert.equal(useReportStore.getState().reports[0].targetName, 'OLD');
});

test('clearing removes every archive from the list and the database', async () => {
  await useReportStore.getState().addReport(report({ id: 'R1' }));
  await useReportStore.getState().addReport(report({ id: 'R2' }));
  await useReportStore.getState().clearAll();
  assert.deepEqual(useReportStore.getState().reports, []);
  await useReportStore.getState().loadReports();
  assert.deepEqual(useReportStore.getState().reports, []);
});

test('the provenance fields survive a round trip through the database', async () => {
  /*
    `simulated` and `origin` are provenance claims the PDF cover prints.
    `markImported` once existed with no callers, so every imported archive kept
    the schema default of LOCAL and the cover asserted "LIVE HARDWARE [FIELD
    DATA]" for a hand-written JSON file — a way around the simulated chain
    entirely, through the one door that takes input from outside.
  */
  await useReportStore.getState().addReport(report({ id: 'SIM', simulated: true }));
  useReportStore.setState({ reports: [] });
  await useReportStore.getState().loadReports();
  const [r] = useReportStore.getState().reports;
  assert.equal(r.simulated, true);
  assert.ok(r.origin !== undefined, 'origin must come back from the database, not be inferred');
});

// ── passiveSigintStore: a run that lasts hours must stay bounded ─────────────

test('the same station seen twice is one row, merged', async () => {
  const s = usePassiveSigintStore.getState();
  s.addPassiveHost({ ip: '10.0.0.5', mac: 'AA:BB', hostname: null, source: 'ARP', timestamp: 't1' });
  s.addPassiveHost({ ip: '10.0.0.5', mac: 'AA:BB', hostname: 'nas', source: 'MDNS', timestamp: 't2' });
  const hosts = usePassiveSigintStore.getState().passiveHosts;
  assert.equal(hosts.length, 1);
  assert.equal(hosts[0].hostname, 'nas', 'the later sighting fills in what it learned');
  assert.equal(hosts[0].timestamp, 't2');
});

test('the same MAC on a different address is a different row', async () => {
  // A device that moved or was re-addressed is two observations, and collapsing
  // them would hide one of the addresses it was actually seen at.
  const s = usePassiveSigintStore.getState();
  s.addPassiveHost({ ip: '10.0.0.5', mac: 'AA:BB', hostname: null, source: 'ARP', timestamp: 't1' });
  s.addPassiveHost({ ip: '10.0.0.9', mac: 'AA:BB', hostname: null, source: 'ARP', timestamp: 't2' });
  assert.equal(usePassiveSigintStore.getState().passiveHosts.length, 2);
});

test('the host list is capped, and keeps the newest', async () => {
  const s = usePassiveSigintStore.getState();
  for (let i = 0; i < 60; i++) {
    s.addPassiveHost({ ip: `10.0.0.${i}`, mac: `AA:${i}`, hostname: null, source: 'ARP', timestamp: `t${i}` });
  }
  const hosts = usePassiveSigintStore.getState().passiveHosts;
  assert.equal(hosts.length, 50);
  assert.equal(hosts[0].mac, 'AA:59', 'newest first');
});

test('the probe list is capped too, and keeps the newest', async () => {
  const s = usePassiveSigintStore.getState();
  for (let i = 0; i < 120; i++) {
    s.addProbeRequest({ client_mac: `CC:${i}`, ssid: `net${i}`, timestamp: `t${i}` });
  }
  const probes = usePassiveSigintStore.getState().probeRequests;
  assert.equal(probes.length, 100);
  assert.equal(probes[0].client_mac, 'CC:119');
});

test('reset clears everything a session accumulated', async () => {
  const s = usePassiveSigintStore.getState();
  s.setActive(true);
  s.setStartTime(1234);
  s.addPassiveHost({ ip: '1', mac: 'a', hostname: null, source: 'ARP', timestamp: 't' });
  s.addProbeRequest({ client_mac: 'c', ssid: 'n', timestamp: 't' });
  s.reset();
  assert.deepEqual(usePassiveSigintStore.getState(), {
    ...usePassiveSigintStore.getState(),
    isActive: false, passiveHosts: [], probeRequests: [], startTime: null,
  });
  assert.equal(usePassiveSigintStore.getState().isActive, false);
  assert.equal(usePassiveSigintStore.getState().startTime, null);
});

// ── strikeStore: a record of frames this tool put on the air ─────────────────

test('starting a strike records it as ACTIVE with nothing sent yet', () => {
  useStrikeStore.getState().startStrike('AA:BB:CC:DD:EE:FF', 'GW:BSSID');
  const s = useStrikeStore.getState().activeStrikes['AA:BB:CC:DD:EE:FF'];
  assert.equal(s.status, 'ACTIVE');
  assert.equal(s.packetsSent, 0, 'a count of frames must start at what was actually sent');
  assert.equal(s.gatewayBSSID, 'GW:BSSID');
  assert.ok(s.startedAt > 0);
});

test('an update for a target that never started does not invent a strike', () => {
  /*
    This store is the record of deauthentication frames this tool put on the air
    against a third party's equipment. A phantom entry created by a stray
    progress event would be a record of an action nobody took — in the one part
    of the app whose contents are an admission.
  */
  useStrikeStore.getState().updateStrike('NEVER:STARTED', { packetsSent: 500 });
  assert.deepEqual(useStrikeStore.getState().activeStrikes, {});
});

test('an update keeps the fields it does not mention', () => {
  useStrikeStore.getState().startStrike('AA:BB', 'GW');
  useStrikeStore.getState().updateStrike('AA:BB', { packetsSent: 42 });
  const s = useStrikeStore.getState().activeStrikes['AA:BB'];
  assert.equal(s.packetsSent, 42);
  assert.equal(s.status, 'ACTIVE');
  assert.equal(s.gatewayBSSID, 'GW');
});

test('stopping a strike marks it ceased and keeps the record', () => {
  // Deleting it would erase the evidence that it happened. CEASED is a state, not
  // an absence.
  useStrikeStore.getState().startStrike('AA:BB', 'GW');
  useStrikeStore.getState().updateStrike('AA:BB', { packetsSent: 120 });
  useStrikeStore.getState().stopStrike('AA:BB');
  const s = useStrikeStore.getState().activeStrikes['AA:BB'];
  assert.equal(s.status, 'CEASED');
  assert.equal(s.packetsSent, 120, 'the count of frames sent must survive the stop');
});

test('stopping a strike that was never started does nothing', () => {
  useStrikeStore.getState().stopStrike('NEVER:STARTED');
  assert.deepEqual(useStrikeStore.getState().activeStrikes, {});
});

test('clearing a strike removes only that target', () => {
  useStrikeStore.getState().startStrike('AA:BB', 'GW');
  useStrikeStore.getState().startStrike('CC:DD', 'GW');
  useStrikeStore.getState().clearStrike('AA:BB');
  assert.deepEqual(Object.keys(useStrikeStore.getState().activeStrikes), ['CC:DD']);
});

// ── uiStore ─────────────────────────────────────────────────────────────────

test('the dashboard cannot hide both the map and the feed at once', () => {
  /*
    The reason focus is one value rather than a boolean per panel: two
    independent flags can both be true, and the dashboard then hides the map
    *and* the feed and renders an empty grid. This asserts the state that would
    allow that is unrepresentable.
  */
  const s = () => useUIStore.getState();
  s().toggleDashboardFocus('map');
  assert.equal(s().dashboardFocus, 'map');
  s().toggleDashboardFocus('feed');
  assert.equal(s().dashboardFocus, 'feed', 'focusing one panel releases the other');
  s().toggleDashboardFocus('feed');
  assert.equal(s().dashboardFocus, null, 'the same panel twice collapses back to the split view');
});

test('clearing focus returns to the split view from either panel', () => {
  useUIStore.getState().toggleDashboardFocus('map');
  useUIStore.getState().clearDashboardFocus();
  assert.equal(useUIStore.getState().dashboardFocus, null);
});

test('only the vehicle choice is persisted, not the rest of the session', () => {
  /*
    `partialize` is the whole point. Persisting `selectedBssid` or
    `showMissionArchive` would reopen a drawer about an access point from a
    survey that is no longer loaded — and persisting `dashboardFocus` would make
    a collapsed panel look like a broken layout on the next launch.
  */
  const s = useUIStore.getState();
  s.setEgoVehicle('car3.svg');
  s.setSelectedBssid('AA:BB:CC:DD:EE:FF');
  s.setShowMissionArchive(true);
  s.toggleDashboardFocus('map');
  s.toggleSidebar();

  const raw = shim.getItem('lockon-uistore-storage');
  assert.ok(raw, 'nothing was persisted at all');
  const persisted = JSON.parse(raw).state;
  assert.deepEqual(Object.keys(persisted), ['egoVehicle']);
  assert.equal(persisted.egoVehicle, 'car3.svg');
});

test('toggles flip and flip back', () => {
  const before = useUIStore.getState().sidebarCollapsed;
  useUIStore.getState().toggleSidebar();
  assert.equal(useUIStore.getState().sidebarCollapsed, !before);
  useUIStore.getState().toggleSidebar();
  assert.equal(useUIStore.getState().sidebarCollapsed, before);

  const feed = useUIStore.getState().showScanFeed;
  useUIStore.getState().toggleScanFeed();
  assert.equal(useUIStore.getState().showScanFeed, !feed);
});

/*
  ── Provenance has to survive the trip into the store ────────────────────────

  `markImported` writes `origin = 'IMPORTED'` to the database and was the only
  half of that mark. The store received the parsed file object verbatim, and
  `loadReports()` has exactly one caller, at app start -- so for the rest of the
  session the in-memory record said nothing about where the archive came from.

  The PDF cover reads `r.origin === 'IMPORTED'` off the store. The filter came
  back empty, the `!! IMPORTED DATA - NOT GATHERED BY THIS RIG !!` banner was
  skipped, and the cover printed "LIVE HARDWARE [FIELD DATA]" in green for a JSON
  file that arrived from somewhere unknown. It corrected itself after a restart,
  because the database was right, which is exactly what kept it hidden.

  `ReportsPage` now stamps `origin` on the record before handing it over. These
  pin the part of that fix the store is responsible for: a field set by the caller
  reaches the list unchanged. `addReport` builds no record of its own, so if it
  ever starts projecting a fixed set of columns the import fix breaks silently and
  the symptom is a false cover page.
*/

test('a record keeps the origin its caller stamped on it', async () => {
  await useReportStore.getState().addReport(report({ id: 'IMP-1', origin: 'IMPORTED' }));
  assert.equal(useReportStore.getState().reports[0].origin, 'IMPORTED');
});

test('an archive produced locally is not labelled imported by accident', async () => {
  // The other direction: nothing may invent provenance either. A field left
  // unset must stay unset rather than acquiring a default.
  await useReportStore.getState().addReport(report({ id: 'LOC-1' }));
  assert.equal(useReportStore.getState().reports[0].origin, undefined);
});

test('a rejected write leaves no half-marked record in the list', async () => {
  // The duplicate-id path again, now with provenance attached: a failed INSERT
  // must not leave a record the cover page would then describe.
  await useReportStore.getState().addReport(report({ id: 'DUP-IMP', origin: 'IMPORTED' }));
  await assert.rejects(
    () => useReportStore.getState().addReport(report({ id: 'DUP-IMP', origin: 'IMPORTED' })));
  assert.equal(
    useReportStore.getState().reports.filter(r => r.id === 'DUP-IMP').length, 1);
});
