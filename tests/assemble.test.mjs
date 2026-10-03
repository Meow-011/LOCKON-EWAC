/**
 * Tests for the numbers a report puts in front of a manager.
 *
 *     npm run test:assemble
 *
 * Why this exists.
 *
 * `assembleReportData` decides every figure in the document: the headline
 * counts, which findings survive deduplication, which rogue verdict wins when
 * two archives disagree, whether a coverage row is the archive's own frozen copy
 * or one recomputed from a table that may no longer describe it. Until it was
 * lifted out of `ReportsPage`, all of that lived in a component closure and
 * nothing could assert against it.
 *
 * The defects it already carries scar tissue for are all one shape: **a number
 * that was right in one place and wrong in another, inside a document nobody
 * could check.** The headline "VULNERABLE APs" figure came from the engine's
 * binary flag while the table on the same page recomputed `WEP || OPEN`, so a
 * WPA1 network was counted in the headline and printed as LOW below it. A
 * multi-archive export `flatMap`ped its findings, so one estate surveyed twice
 * doubled the risk figure a manager read. Those are the tests here.
 *
 * Runs against real SQLite with the project's real migrations, through the same
 * stub `database.test.mjs` uses — the reads are reconciliations of one query
 * against another, and a mocked `select()` would prove only that they were
 * called.
 */

import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { migrationFiles } from './stubs/plugin-sql-sqlite.mjs';
import { assembleReportData } from '../.test-build/db.mjs';

beforeEach(() => migrationFiles.reset?.());

const NO_BASELINE = { baselineId: null, baselineDelta: null };

let seq = 0;
const wifi = (aps, over = {}) => ({
  id: `R${++seq}`,
  type: 'WIFI_WARDRIVE',
  targetName: 'FIELD SCAN',
  timestamp: Date.now(),
  rawData: { accessPoints: aps },
  ...over,
});
const openAp = (bssid, over = {}) => ({ bssid, ssid: 'GUEST', encryption: 'OPEN', ...over });

// ── The deduplication that stops one estate counting twice ──────────────────

test('one access point surveyed twice is one access point and one finding', async () => {
  /*
    A multi-archive export is the normal way a manager-facing report is made,
    and this used to be a plain flatMap. The same physical radio present in two
    archives was counted twice in the ACCESS POINTS tile, FINDINGS RAISED, the
    CRITICAL + HIGH headline, the severity and confidence tables, the WPS and
    rogue counts, POSITION QUALITY, and PRIORITISED FINDINGS — which printed the
    identical row twice. Two surveys of one site doubled the headline risk.
  */
  const a = wifi([openAp('AA:BB:CC:DD:EE:01')]);
  const b = wifi([openAp('AA:BB:CC:DD:EE:01')]);
  const data = await assembleReportData([a, b], NO_BASELINE);

  assert.equal(data.totalAPs, 1);
  assert.equal(data.allFindings.length, 1);
  assert.equal(data.allFindings[0].occurrences, 2, 'seen twice is a fact worth keeping');
});

test('deduplication is by identity, not by position in the list', async () => {
  const data = await assembleReportData([
    wifi([openAp('AA:BB:CC:DD:EE:01'), openAp('AA:BB:CC:DD:EE:02')]),
    wifi([openAp('AA:BB:CC:DD:EE:02'), openAp('AA:BB:CC:DD:EE:03')]),
  ], NO_BASELINE);
  assert.equal(data.totalAPs, 3);
  assert.equal(data.allFindings.length, 3);
});

test('a BSSID differing only in case is the same radio', async () => {
  const data = await assembleReportData([
    wifi([openAp('aa:bb:cc:dd:ee:01')]),
    wifi([openAp('AA:BB:CC:DD:EE:01')]),
  ], NO_BASELINE);
  assert.equal(data.totalAPs, 1);
});

test('an access point with no BSSID is counted as its own row', async () => {
  // Blank identifiers cannot be deduplicated. Collapsing them would report three
  // unnamed access points as one, which understates the survey.
  const data = await assembleReportData([wifi([
    openAp(''), openAp(''), openAp('AA:BB:CC:DD:EE:01'),
  ])], NO_BASELINE);
  assert.equal(data.totalAPs, 3);
});

test('the worse instance of a repeated finding is the one reported', async () => {
  // A later survey that saw the AP under better conditions is the one that
  // should reach the document, not whichever archive was exported first.
  const data = await assembleReportData([
    wifi([{ bssid: 'AA:BB:CC:DD:EE:01', encryption: 'WPA' }]),
    wifi([{ bssid: 'AA:BB:CC:DD:EE:01', encryption: 'WPA' }]),
  ], NO_BASELINE);
  const enc = data.allFindings.filter(f => f.category === 'encryption');
  assert.equal(enc.length, 1);
  assert.equal(enc[0].severity, 'HIGH');
});

test('the headline summary is computed from the deduplicated set', async () => {
  // The whole reason the dedup exists: `overall` is what the cover page prints.
  const data = await assembleReportData([
    wifi([openAp('AA:BB:CC:DD:EE:01')]),
    wifi([openAp('AA:BB:CC:DD:EE:01')]),
  ], NO_BASELINE);
  assert.equal(data.overall.total, 1);
  assert.equal(data.overall.bySeverity.CRITICAL, 1);
});

// ── Provenance ──────────────────────────────────────────────────────────────

test('a mixed export is flagged as mixed, not as field data', async () => {
  // Simulated data presented alongside real data without saying so is the
  // failure this project treats as blocking rather than cosmetic.
  const data = await assembleReportData([
    wifi([openAp('AA:BB:CC:DD:EE:01')], { simulated: true }),
    wifi([openAp('AA:BB:CC:DD:EE:02')]),
  ], NO_BASELINE);
  assert.equal(data.anySimulated, true);
  assert.equal(data.allSimulated, false);
  assert.equal(data.isMixedProvenance, true);
  assert.equal(data.simulatedReports.length, 1);
  assert.equal(data.fieldReports.length, 1);
});

test('an all-simulated export is not "mixed", and field data is neither', async () => {
  const sim = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')], { simulated: true })], NO_BASELINE);
  assert.equal(sim.allSimulated, true);
  assert.equal(sim.isMixedProvenance, false);

  const field = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')])], NO_BASELINE);
  assert.equal(field.anySimulated, false);
  assert.equal(field.allSimulated, false);
  assert.equal(field.isMixedProvenance, false);
});

test('the simulated flag reaches the findings, not only the header', async () => {
  const data = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')], { simulated: true })], NO_BASELINE);
  assert.equal(data.allFindings[0].is_simulated, true);
});

// ── Rogue and WPS: prose counts a reader takes as population figures ────────

test('the better-informed rogue verdict wins, decided by score not by order', async () => {
  const weak = { ...openAp('AA:BB:CC:DD:EE:01'), rogue_verdict: 'SUSPECTED', rogue_score: 30 };
  const strong = { ...openAp('AA:BB:CC:DD:EE:01'), rogue_verdict: 'CONFIRMED', rogue_score: 90 };

  for (const order of [[weak, strong], [strong, weak]]) {
    const data = await assembleReportData([wifi([order[0]]), wifi([order[1]])], NO_BASELINE);
    assert.equal(data.rogueEntries.length, 1, 'one radio, one row');
    assert.equal(data.rogueEntries[0].verdict, 'CONFIRMED');
    assert.equal(data.rogueEntries[0].score, 90);
  }
});

test('a CLEAR verdict is not a rogue row', async () => {
  // CLEAR means the scorer ran and found nothing. Listing it under "access
  // points carrying rogue indicators" would inflate a sentence a reader takes
  // as a count of suspicious devices.
  const data = await assembleReportData([wifi([
    { ...openAp('AA:BB:CC:DD:EE:01'), rogue_verdict: 'CLEAR', rogue_score: 0 },
    { ...openAp('AA:BB:CC:DD:EE:02'), rogue_verdict: 'LIKELY', rogue_score: 60 },
  ])], NO_BASELINE);
  assert.equal(data.rogueEntries.length, 1);
  assert.equal(data.rogueEntries[0].ap.bssid, 'AA:BB:CC:DD:EE:02');
});

test('rogue rows are ordered worst first', async () => {
  const data = await assembleReportData([wifi([
    { ...openAp('AA:BB:CC:DD:EE:01'), rogue_verdict: 'SUSPECTED', rogue_score: 30 },
    { ...openAp('AA:BB:CC:DD:EE:02'), rogue_verdict: 'CONFIRMED', rogue_score: 90 },
  ])], NO_BASELINE);
  assert.deepEqual(data.rogueEntries.map(e => e.verdict), ['CONFIRMED', 'SUSPECTED']);
});

test('a legacy is_evil_twin row is carried as heuristic-only', async () => {
  const data = await assembleReportData([wifi([
    { ...openAp('AA:BB:CC:DD:EE:01'), is_evil_twin: 1 },
  ])], NO_BASELINE);
  assert.equal(data.rogueEntries[0].verdict, 'SUSPECTED');
  assert.equal(data.rogueEntries[0].heuristicOnly, true);
});

test('only a measured WPS observation produces a WPS row', async () => {
  /*
    `wps_enabled` is NOT NULL DEFAULT 0, so an unscanned access point has a zero
    there. Reading it as an observation is how the report came to describe a
    beacon parse that never ran.
  */
  const data = await assembleReportData([wifi([
    { ...openAp('AA:BB:CC:DD:EE:01'), wps_enabled: 0 },
    { ...openAp('AA:BB:CC:DD:EE:02'), wps_enabled: 0, wps_scanned_at: '2026-09-29T10:00:00Z' },
    { ...openAp('AA:BB:CC:DD:EE:03'), wps_enabled: 1 },
  ])], NO_BASELINE);
  assert.equal(data.wpsEntries.length, 1, 'only the one that actually advertises WPS');
  assert.equal(data.wpsEntries[0].ap.bssid, 'AA:BB:CC:DD:EE:03');
});

test('one radio advertising WPS in two archives is one WPS row', async () => {
  const ap = { ...openAp('AA:BB:CC:DD:EE:01'), wps_enabled: 1 };
  const data = await assembleReportData([wifi([ap]), wifi([ap])], NO_BASELINE);
  assert.equal(data.wpsEntries.length, 1);
});

// ── Reads that are allowed to fail ──────────────────────────────────────────

test('an export with no engagement scope still produces a document', async () => {
  // The scope gate denies by default, but an export is not a gated action: a
  // report that refuses to render because no engagement is active would be the
  // gate leaking into the evidence path.
  const data = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')])], NO_BASELINE);
  assert.equal(data.activeScope, null);
  assert.equal(data.scopeReadError, null);
  assert.ok(Array.isArray(data.auditRows));
});

test('an unreachable engine leaves the method appendix empty rather than guessed', async () => {
  // `engineIPC.connected` is false here, so `fetchEngineMethodology` resolves
  // null. Every one of these has a section that states it was not available;
  // none of them may be filled in with a plausible default.
  const data = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')])], NO_BASELINE);
  assert.equal(data.engineMethodology, null);
  assert.equal(data.evilTwinMethod, null);
  assert.equal(data.cveData, null);
  assert.equal(data.capabilities, null);
});

test('the rule set is described from the code, always', async () => {
  // The methodology appendix is what makes a severity auditable, so unlike the
  // engine's answer it is never absent.
  const data = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')])], NO_BASELINE);
  assert.equal(typeof data.methodology.id, 'string');
  assert.ok(data.methodology.version >= 1);
  assert.ok(data.methodology.limitations.length > 0);
});

// ── Coverage ────────────────────────────────────────────────────────────────

test("the archive's own frozen coverage wins over the live table", async () => {
  /*
    `mission_coverage` cascades away when its mission is deleted, so the table
    cannot be relied on to still describe what this archive was surveyed over —
    which is the opposite of why migration 009 freezes a copy into the archive.
  */
  const frozen = { mission_id: 'm1', ap_count: 42 };
  const data = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')], {
    rawData: { accessPoints: [openAp('AA:BB:CC:DD:EE:01')], missionId: 'm1', coverage: frozen },
  })], NO_BASELINE);
  assert.equal(data.coverageSections.length, 1);
  assert.deepEqual(data.coverageSections[0].row, frozen);
  assert.equal(data.coverageSections[0].error, null);
});

test('an archive with no mission id gets a coverage section that says so', async () => {
  // Dropping the section silently would let a reader assume coverage was fine.
  const data = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')])], NO_BASELINE);
  assert.equal(data.coverageSections.length, 1);
  assert.equal(data.coverageSections[0].missionId, null);
  assert.equal(data.coverageSections[0].row, null);
});

// ── Shape ───────────────────────────────────────────────────────────────────

test('a single archive is not a multi-archive export', async () => {
  const one = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')])], NO_BASELINE);
  const two = await assembleReportData([
    wifi([openAp('AA:BB:CC:DD:EE:01')]), wifi([openAp('AA:BB:CC:DD:EE:02')]),
  ], NO_BASELINE);
  assert.equal(one.isMulti, false);
  assert.equal(two.isMulti, true);
});

test('an empty archive assembles without throwing and claims nothing', async () => {
  const data = await assembleReportData([wifi([])], NO_BASELINE);
  assert.equal(data.totalAPs, 0);
  assert.equal(data.allFindings.length, 0);
  assert.equal(data.rogueEntries.length, 0);
  assert.equal(data.wpsEntries.length, 0);
  assert.equal(data.overall.total, 0);
});

test('no baseline selected means no retest delta and no error', async () => {
  const data = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')])], NO_BASELINE);
  assert.equal(data.retest, null);
  assert.equal(data.retestError, null);
});

test('a delta the page already computed is used rather than recomputed', async () => {
  const delta = { fixed: 1, regressed: 0, stillOpen: 2, newlyFound: 3 };
  const data = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')])],
    { baselineId: 7, baselineDelta: delta });
  assert.deepEqual(data.retest, delta);
  assert.equal(data.retestError, null);
});

test('the per-row label comes from the same rule as every other view', async () => {
  // `worstFor` is what the telemetry tables print. A row cannot carry one
  // confidence label in the PDF and a different one in the CSV.
  const data = await assembleReportData([wifi([openAp('AA:BB:CC:DD:EE:01')])], NO_BASELINE);
  assert.equal(data.worstFor('AA:BB:CC:DD:EE:01').severity, 'CRITICAL');
  assert.equal(data.worstFor('aa:bb:cc:dd:ee:01').severity, 'CRITICAL', 'case must not matter');
  assert.equal(data.worstFor('99:99:99:99:99:99').severity, 'INFO');
});
