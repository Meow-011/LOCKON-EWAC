/**
 * Tests for the report-archive helpers.
 *
 *     npm run test:archive
 *
 * Why this exists.
 *
 * `src/lib/report/archive.ts` is 777 lines and 51 exports, and it was extracted
 * out of `ReportsPage.tsx` precisely so it could be reached from a test — the
 * file's own header says so. The extraction landed; the tests did not. It sat
 * untested for three days while being the layer that decides what every export
 * says: which rows an archive yields, whether a measurement was taken at all,
 * and how an uncertain position is worded.
 *
 * That matters more here than line count suggests. Nearly every function in this
 * module encodes a distinction the project has already been burned by, and the
 * distinctions are all of the same shape: **absent is not zero, and unmeasured is
 * not negative.** A NULL mirror coordinate read as `0, 0` drew 189 access points
 * into the Gulf of Guinea. A `wps_enabled` column default read as an observation
 * printed a beacon parse that never ran. A missing error radius printed as
 * "+/- 0 m" — a perfect fix. Each of those was a one-character coercion, and each
 * one reached a document somebody was meant to act on.
 *
 * So these tests are mostly about the null and empty cases, not the happy path.
 * Where a function has a "this was not measured" branch, the test states what the
 * report would claim if the branch broke, because that sentence is the actual
 * regression — not the assertion.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  AMBIGUOUS_FLAG,
  AUDIT_ROWS_IN_PDF,
  HEURISTIC_ONLY_INDICATOR,
  LOCATION_METHOD_LABEL,
  LOCATION_METHOD_NOTE,
  PATH_LOSS_EXPONENT,
  SEVERITY_RGB,
  TARGET_KIND_LABEL,
  TARGET_KIND_ORDER,
  apMirror,
  apsOf,
  ascii,
  assessReport,
  circlePolygon,
  credentialsOf,
  dirbusterOf,
  errText,
  formatCoord,
  formatErrorRadius,
  formatLocationConfidence,
  formatMetres,
  hostsOf,
  isMirrorAmbiguous,
  isWirelessReport,
  locationMethodLabel,
  locationMethodNote,
  locationNotesOf,
  maskSecret,
  medianOf,
  missionIdOf,
  positionCaveats,
  rogueIndicatorsOf,
  rogueVerdictOf,
  serviceObservationsOf,
  smbEnumOf,
  stableSelectionId,
  summarisePositions,
  sweepScopesOf,
  toApInput,
  toHostInput,
  traceroutePathOf,
  worstBySubject,
  worstOf,
  wpsLabel,
  wpsMeasured,
  wpsObserved,
  xmlEscape,
  dedupeApsByBssid,
  featuresFor,
  plottedCount,
} from '../.test-build/archive.mjs';

/** Values that are all falsy or all `Number()`-coercible to 0, in one place. */
const EMPTY_ISH = [null, undefined, '', 0, false, NaN, [], {}];
const ap = (over = {}) => ({ bssid: 'AA:BB:CC:DD:EE:FF', ...over });
const report = (over = {}) => ({ id: 'R1', type: 'WIFI_WARDRIVE', rawData: {}, ...over });
const finding = (over = {}) => ({
  subject_type: 'AP', subject_id: 'AA:BB:CC:DD:EE:FF', category: 'encryption',
  title: 't', severity: 'LOW', risk_score: 20, confidence: 'CONFIRMED',
  rationale: 'r', methodology: 'm', fingerprint: 'f', ...over,
});

// ── Masking a recovered secret ──────────────────────────────────────────────

test('a short secret reveals its length and nothing else', () => {
  // First-and-last on a 2-character password is the whole password, which is why
  // the threshold exists at all.
  assert.equal(maskSecret('ab'), '** (len 2)');
  assert.equal(maskSecret('abc'), '*** (len 3)');
  assert.equal(maskSecret('abcd'), 'a**d (len 4)');
});

test('a long secret does not leak its length through the number of stars', () => {
  // The star run is capped, so a 200-character passphrase and a 30-character one
  // look the same in the middle. The true length is stated once, in words.
  const long = maskSecret('x'.repeat(200));
  assert.match(long, /^x\*{10}x \(len 200\)$/);
});

test('an empty secret is reported as empty, not as absent', () => {
  // A blank service password is a real finding. This string is also why a locked
  // vault row must read `password: null` and never `''` — `maskSecret(null)`
  // would then state that a live account has a blank password.
  for (const v of [null, undefined, '']) {
    assert.equal(maskSecret(v), '(empty) (len 0)');
  }
});

// ── Text that has to survive a PDF font and an XML parser ───────────────────

test('ascii() folds the punctuation a field capture actually contains', () => {
  assert.equal(ascii('‘q’ “q” – • … →'), "'q' \"q\" - - ... ->");
});

test('ascii() replaces anything else with a question mark rather than dropping it', () => {
  // jsPDF's standard fonts are WinAnsi: an un-mapped glyph is silently lost, so a
  // Thai or Cyrillic SSID would leave a blank cell that reads as "no SSID".
  // Six code units, not five: the Thai vowel marks are separate characters, and
  // each unmappable one becomes its own '?'. An SSID in Thai therefore reaches
  // the page as a run of question marks rather than as an empty cell, which is
  // the point — an empty cell reads as "this network has no name".
  assert.equal(ascii('สวัสดี'), '??????');
  assert.equal(ascii('café'), 'caf?');
  assert.equal(ascii(null), '');
  assert.equal(ascii(0), '0', 'a zero is a value, not an absent string');
});

test('ascii() keeps tabs and newlines, which carry table layout', () => {
  assert.equal(ascii('a\tb\nc'), 'a\tb\nc');
});

test('xmlEscape() escapes the ampersand first, so an entity cannot be double-built', () => {
  // `&` last would turn `<` into `&lt;` and then into `&amp;lt;`.
  assert.equal(xmlEscape('<a href="x">&\'</a>'), '&lt;a href=&quot;x&quot;&gt;&amp;&apos;&lt;/a&gt;');
});

test('xmlEscape() strips control characters that are illegal in XML 1.0', () => {
  // An SSID is chosen by whoever owns the access point, including the one being
  // investigated. A raw 0x01 makes the whole KML unparseable.
  assert.equal(xmlEscape('a\x00\x01\x08\x0b\x0c\x1fb'), 'ab');
  assert.equal(xmlEscape('keep\ttab\nand\rreturn'), 'keep\ttab\nand\rreturn');
});

test('an SSID cannot close a KML tag', () => {
  const hostile = ']]></name><Placemark><name>injected';
  assert.doesNotMatch(xmlEscape(hostile), /[<>]/);
});

test('errText() prefers the message but never returns "[object Object]" silently', () => {
  assert.equal(errText(new Error('boom')), 'boom');
  assert.equal(errText('plain'), 'plain');
  assert.equal(errText(null), 'null');
  assert.equal(errText({ code: 5 }), '[object Object]');
});

// ── Numbers that must not be invented ───────────────────────────────────────

test('a coordinate that is not a finite pair reads "no fix", never 0.00000', () => {
  assert.equal(formatCoord(13.7, 100.5), '13.70000, 100.50000');
  for (const v of [null, undefined, NaN, Infinity, '13.7']) {
    assert.equal(formatCoord(v, 100.5), 'no fix', `lat ${String(v)}`);
    assert.equal(formatCoord(13.7, v), 'no fix', `lon ${String(v)}`);
  }
});

test('an absent error radius is "no stated radius", not a perfect fix', () => {
  // `+/- 0 m` claims the transmitter was located exactly. That is what a
  // `Number(null)`-based read printed for every unpositioned access point.
  assert.equal(formatErrorRadius(null), 'no stated radius');
  assert.equal(formatErrorRadius(undefined), 'no stated radius');
  assert.equal(formatErrorRadius(NaN), 'no stated radius');
  assert.equal(formatErrorRadius(-1), 'no stated radius');
  assert.equal(formatErrorRadius(0), '+/- 0.0 m', 'a measured zero is still a measurement');
});

test('a radius is printed whole above 10 m and to a decimal below it', () => {
  assert.equal(formatErrorRadius(42.4), '+/- 42 m');
  assert.equal(formatErrorRadius(10), '+/- 10 m');
  assert.equal(formatErrorRadius(9.94), '+/- 9.9 m');
});

test('formatMetres() reports an absent separation as n/r', () => {
  assert.equal(formatMetres(null), 'n/r');
  assert.equal(formatMetres(-5), 'n/r');
  assert.equal(formatMetres(0), '0.0 m');
  assert.equal(formatMetres(123.6), '124 m');
});

test('a localization confidence of 1 is the worst case, not 100%', () => {
  /*
    The regression this locks. Both producers clamp to a whole 1..99
    (`radiusToConfidence`, `gpr_engine.py`), so `1` is the floor — reached by any
    error radius past roughly 295 m. An earlier implementation multiplied
    anything `<= 1` by 100 and printed that single worst case as "100%": the
    least certain position in the survey, presented as the most certain.
  */
  assert.equal(formatLocationConfidence(1), '1%');
  assert.equal(formatLocationConfidence(0.9), '1%', 'rounds into the domain');
  assert.equal(formatLocationConfidence(99), '99%');
});

test('a confidence outside the scale is unavailable rather than coerced', () => {
  for (const v of [null, undefined, NaN, Infinity, 0, 0.4, 101, -5, '50']) {
    assert.equal(formatLocationConfidence(v), 'n/r', `confidence ${String(v)}`);
  }
});

test('medianOf() returns null for an empty set rather than 0', () => {
  // A median of 0 m would appear in the report as a survey that located
  // everything perfectly.
  assert.equal(medianOf([]), null);
  assert.equal(medianOf([5]), 5);
  assert.equal(medianOf([1, 3]), 2);
  assert.equal(medianOf([3, 1, 2]), 2);
});

test('medianOf() does not sort lexicographically and does not mutate its input', () => {
  const input = [10, 9, 100];
  assert.equal(medianOf(input), 10, 'default Array.sort() would answer 100 here');
  assert.deepEqual(input, [10, 9, 100]);
});

// ── The mirror candidate: the bug that drew a line to the Gulf of Guinea ─────

test('an access point with no mirror candidate has no mirror', () => {
  /*
    The premise, stated so this file cannot quietly become about a problem that
    no longer exists: `Number(null)` is 0, and 0 is finite. A `finiteNumber`
    helper built on `Number()` therefore turned two NULL columns into the
    coordinate `0, 0`, and the archive map drew a dashed line from Thailand to
    the Gulf of Guinea for 189 of 196 access points, each labelled as the second
    equally good position for that network.
  */
  assert.equal(Number(null), 0);
  assert.ok(Number.isFinite(Number(null)));

  for (const v of EMPTY_ISH) {
    assert.equal(apMirror(ap({ location_mirror_lat: v, location_mirror_lon: v })), null,
      `mirror from ${JSON.stringify(v)} must not be a position`);
  }
  assert.equal(apMirror(ap()), null);
  assert.equal(apMirror(null), null);
});

test('a real mirror candidate survives, with its separation', () => {
  const m = apMirror(ap({
    location_mirror_lat: 13.7, location_mirror_lon: 100.5, location_mirror_distance_m: 80,
  }));
  assert.deepEqual(m, { lat: 13.7, lon: 100.5, distanceM: 80 });
});

test('a mirror candidate with no recorded separation is still a candidate', () => {
  // Losing the whole alternative position because one number was missing would
  // turn an ambiguous fix back into a confident one.
  const m = apMirror(ap({ location_mirror_lat: 13.7, location_mirror_lon: 100.5 }));
  assert.equal(m.distanceM, null);
});

test('either signal alone makes a position mirror-ambiguous', () => {
  // The flag is the estimator's verdict on the route; a stored candidate means it
  // produced one. Requiring both would let a null flag column present an
  // ambiguous fix as decided.
  assert.equal(isMirrorAmbiguous(ap({ geometry_ambiguous: 1 })), true);
  assert.equal(isMirrorAmbiguous(ap({ location_mirror_lat: 13.7, location_mirror_lon: 100.5 })), true);
  assert.equal(isMirrorAmbiguous(ap()), false);
});

test('the mirror warning names the alternative position and how to resolve it', () => {
  const caveats = positionCaveats(ap({
    location_mirror_lat: 13.7, location_mirror_lon: 100.5, location_mirror_distance_m: 80,
  }));
  assert.equal(caveats.length, 1);
  assert.match(caveats[0], /MIRROR-AMBIGUOUS/);
  assert.match(caveats[0], /13\.70000, 100\.50000/);
  assert.match(caveats[0], /about 80 m away/);
  assert.match(caveats[0], /at least one turn/, 'a caveat the reader cannot act on is half a caveat');
});

test('an ambiguous position with no recorded candidate still warns', () => {
  const caveats = positionCaveats(ap({ geometry_ambiguous: 1 }));
  assert.equal(caveats.length, 1);
  assert.match(caveats[0], /alternative position was not recorded/);
});

test('the warning is not duplicated when the estimator already wrote one', () => {
  const caveats = positionCaveats(ap({
    geometry_ambiguous: 1,
    location_notes: JSON.stringify(['Mirror candidate present; side of track undetermined.']),
  }));
  assert.equal(caveats.length, 1);
  assert.match(caveats[0], /^Mirror candidate present/);
});

test('a confident position carries only the estimator notes', () => {
  assert.deepEqual(positionCaveats(ap({ location_notes: '["fewer than 5 sightings"]' })),
    ['fewer than 5 sightings']);
  assert.deepEqual(positionCaveats(ap()), []);
});

// ── Caveats arrive from a database column and from imported files ───────────

test('location notes are read from a JSON array, an array, or neither', () => {
  assert.deepEqual(locationNotesOf(ap({ location_notes: '["a","b"]' })), ['a', 'b']);
  assert.deepEqual(locationNotesOf(ap({ location_notes: ['a', 'b'] })), ['a', 'b']);
  assert.deepEqual(locationNotesOf(ap({ location_notes: null })), []);
  assert.deepEqual(locationNotesOf(ap({ location_notes: '' })), []);
  assert.deepEqual(locationNotesOf(ap({ location_notes: '   ' })), []);
  assert.deepEqual(locationNotesOf(ap()), []);
});

test('blank and non-string entries are dropped, and the rest are trimmed', () => {
  assert.deepEqual(locationNotesOf(ap({ location_notes: ['  a  ', '', '   ', 7, null, 'b'] })), ['a', 'b']);
});

test('an unparseable caveat is shown rather than lost', () => {
  // A caveat is the last thing that should disappear into a catch block: the
  // reader ends up with a position and no statement of its limits.
  assert.deepEqual(locationNotesOf(ap({ location_notes: 'not json at all' })), ['not json at all']);
  assert.deepEqual(locationNotesOf(ap({ location_notes: '"just a string"' })), ['just a string']);
});

test('an unparseable caveat is capped so one bad column cannot flood a page', () => {
  const notes = locationNotesOf(ap({ location_notes: 'x'.repeat(5000) }));
  assert.equal(notes[0].length, 500);
});

// ── WPS: the three states that must never collapse into two ─────────────────

test('an unscanned access point is "not measured", not "not advertised"', () => {
  /*
    `wps_enabled` is INTEGER NOT NULL DEFAULT 0 (migration 008), so a zero is the
    column default for every row ever inserted. Reading it as an observation made
    the report state that no access point advertised WPS "in its beacon" —
    describing a beacon parse that had never run, hedged in language that read as
    rigour. `wps_scanned_at` (migration 013) is what tells the two apart.
  */
  assert.equal(wpsMeasured(ap({ wps_enabled: 0 })), false);
  assert.equal(wpsLabel(ap({ wps_enabled: 0 })), 'not measured');
  assert.equal(wpsLabel(ap()), 'not measured');
});

test('a scan that found no WPS is a real negative result', () => {
  const scanned = ap({ wps_enabled: 0, wps_scanned_at: '2026-09-29T10:00:00Z' });
  assert.equal(wpsMeasured(scanned), true);
  assert.equal(wpsObserved(scanned), false);
  assert.equal(wpsLabel(scanned), 'not advertised');
});

test('a blank scan timestamp does not count as a scan', () => {
  assert.equal(wpsMeasured(ap({ wps_enabled: 0, wps_scanned_at: '   ' })), false);
});

test('a positive WPS flag is trusted on its own, for archives predating migration 013', () => {
  // A true there could only have come from a real beacon parse.
  assert.equal(wpsMeasured(ap({ wps_enabled: 1 })), true);
  assert.equal(wpsObserved(ap({ wps_enabled: true })), true);
  assert.equal(wpsLabel(ap({ wps_enabled: 1 })), 'ENABLED (unlocked)');
  assert.equal(wpsLabel(ap({ wps_enabled: 1, wps_locked: 1 })), 'ENABLED (rate-limited)');
});

test('only a positive observation reaches the rule set as WPS', () => {
  assert.equal(toApInput(ap({ wps_enabled: 0 }), false).wps_enabled, false);
  assert.equal(toApInput(ap({ wps_enabled: 1 }), false).wps_enabled, true);
});

// ── A bare boolean is not a verdict ────────────────────────────────────────

test('an engine verdict is carried through, upper-cased', () => {
  const r = rogueVerdictOf(ap({ rogue_verdict: 'confirmed', rogue_indicators: [{ code: 'c', weight: 50, detail: 'd' }] }));
  assert.equal(r.verdict, 'CONFIRMED');
  assert.equal(r.heuristicOnly, false);
  assert.deepEqual(r.indicators, [{ code: 'c', weight: 50, detail: 'd' }]);
});

test('a legacy is_evil_twin boolean becomes SUSPECTED with the reason spelled out', () => {
  /*
    The old same-SSID/different-encryption rule labelled every WPA2/WPA3
    transition deployment an evil twin and accused the legitimate access point
    alongside the impostor. Presenting that as CONFIRMED would put an accusation
    in a report with a heuristic behind it.
  */
  const r = rogueVerdictOf(ap({ is_evil_twin: 1 }));
  assert.equal(r.verdict, 'SUSPECTED');
  assert.equal(r.heuristicOnly, true);
  assert.deepEqual(r.indicators, [HEURISTIC_ONLY_INDICATOR]);
  assert.match(HEURISTIC_ONLY_INDICATOR.detail, /equally the pattern of a legitimate/);
});

test('no verdict and no flag yields no verdict, not CLEAR', () => {
  // CLEAR is a statement that the scorer ran and found nothing. Undefined means
  // it did not run, and the caller is the one that decides how to word that.
  const r = rogueVerdictOf(ap());
  assert.equal(r.verdict, undefined);
  assert.deepEqual(r.indicators, []);
  assert.equal(rogueVerdictOf(ap({ rogue_verdict: '   ' })).verdict, undefined);
});

test('malformed indicators are dropped rather than rendered as blank rows', () => {
  const got = rogueIndicatorsOf(ap({
    rogue_indicators: [{ detail: 'kept' }, { code: 'x' }, null, 'string', { detail: 7 }],
  }));
  assert.deepEqual(got, [{ code: 'indicator', weight: 0, detail: 'kept' }]);
  assert.deepEqual(rogueIndicatorsOf(ap({ rogue_indicators: 'not an array' })), []);
});

// ── Reading an archive ─────────────────────────────────────────────────────

test('AP rows are found under either key the engine has used', () => {
  assert.deepEqual(apsOf(report({ rawData: { accessPoints: [1] } })), [1]);
  assert.deepEqual(apsOf(report({ rawData: { aps: [2] } })), [2]);
  assert.deepEqual(apsOf(report({ rawData: {} })), []);
  assert.deepEqual(apsOf(report({ rawData: { accessPoints: 'nope' } })), []);
  assert.deepEqual(apsOf(report({ rawData: null })), []);
});

test('every archive that is not an INTRUSION sweep is a wireless survey', () => {
  // Testing for WIFI_WARDRIVE exactly meant a WIFI_SCAN archive was rendered
  // through the LAN-host path and came out empty.
  assert.equal(isWirelessReport(report({ type: 'WIFI_WARDRIVE' })), true);
  assert.equal(isWirelessReport(report({ type: 'WIFI_SCAN' })), true);
  assert.equal(isWirelessReport(report({ type: 'INTRUSION' })), false);
});

test('the optional archive sections are absent rather than empty when unrecorded', () => {
  const bare = report({ type: 'INTRUSION' });
  assert.deepEqual(hostsOf(bare), []);
  assert.deepEqual(credentialsOf(bare), []);
  assert.deepEqual(sweepScopesOf(bare), []);
  assert.deepEqual(serviceObservationsOf(bare), []);
  assert.equal(smbEnumOf(bare), null);
  assert.equal(traceroutePathOf(bare), null);
  assert.equal(missionIdOf(bare), null);
});

test('an SMB or traceroute payload must be an object, not an array', () => {
  assert.equal(smbEnumOf(report({ rawData: { smbEnum: [] } })), null);
  assert.deepEqual(smbEnumOf(report({ rawData: { smbEnum: { target: 'x' } } })), { target: 'x' });
  assert.equal(traceroutePathOf(report({ rawData: { traceroutePath: [] } })), null);
});

test('a dirbuster run that did not record completeness is null, not false', () => {
  /*
    Three distinct states, kept distinct all the way to the page: only an
    exhausted wordlist licenses a statement about the paths that did *not*
    respond. `false` would let the report say the enumeration finished.
  */
  assert.deepEqual(dirbusterOf(report()), { hits: [], complete: null });
  assert.deepEqual(dirbusterOf(report({ rawData: { dirbuster: { hits: [1] } } })), { hits: [1], complete: null });
  assert.equal(dirbusterOf(report({ rawData: { dirbuster: { complete: false } } })).complete, false);
  assert.equal(dirbusterOf(report({ rawData: { dirbuster: { complete: true } } })).complete, true);
  assert.equal(dirbusterOf(report({ rawData: { dirbuster: { complete: 'yes' } } })).complete, null);
});

test('a mission id is read under any of the three keys, and blank is none', () => {
  assert.equal(missionIdOf(report({ rawData: { missionId: 'm1' } })), 'm1');
  assert.equal(missionIdOf(report({ rawData: { mission_id: 'm2' } })), 'm2');
  assert.equal(missionIdOf(report({ rawData: { mission: { id: 'm3' } } })), 'm3');
  assert.equal(missionIdOf(report({ rawData: { missionId: '  ' } })), null);
});

// ── One label per subject, everywhere ──────────────────────────────────────

test('the worst finding wins, and ties break on score rather than arrival order', () => {
  const worst = worstOf([
    finding({ severity: 'LOW', risk_score: 20 }),
    finding({ severity: 'CRITICAL', risk_score: 95, confidence: 'SUSPECTED' }),
    finding({ severity: 'CRITICAL', risk_score: 92, confidence: 'CONFIRMED' }),
  ]);
  assert.deepEqual(worst, { severity: 'CRITICAL', confidence: 'SUSPECTED' });
});

test('no findings is INFO with no confidence, not CRITICAL and not a crash', () => {
  assert.deepEqual(worstOf([]), { severity: 'INFO', confidence: null });
});

test('worstBySubject matches a BSSID regardless of case', () => {
  // The engine emits BSSIDs with a trailing colon and mixed case; a lookup that
  // missed would silently label a vulnerable access point INFO.
  const lookup = worstBySubject([finding({ subject_id: 'aa:bb:cc:dd:ee:ff', severity: 'CRITICAL', risk_score: 95 })]);
  assert.equal(lookup('AA:BB:CC:DD:EE:FF').severity, 'CRITICAL');
  assert.equal(lookup('aa:BB:cc:DD:ee:FF').severity, 'CRITICAL');
  assert.equal(lookup('99:99:99:99:99:99').severity, 'INFO');
  assert.equal(lookup(null).severity, 'INFO');
});

// ── A selection id that means something ────────────────────────────────────

test('the same selection always produces the same id, in any order', () => {
  // `MULTI-${Date.now()}` was a fresh number on every export of identical
  // content, recorded nowhere, so a reader could not tie two copies together.
  assert.equal(stableSelectionId(['a', 'b']), stableSelectionId(['b', 'a']));
  assert.notEqual(stableSelectionId(['a', 'b']), stableSelectionId(['a', 'c']));
  assert.match(stableSelectionId(['a']), /^[0-9A-F]{8}$/);
  assert.match(stableSelectionId([]), /^[0-9A-F]{8}$/);
});

// ── Position quality across a survey ───────────────────────────────────────

test('an access point with no fix is not counted as positioned', () => {
  const q = summarisePositions([
    ap({ latitude: 13.7, longitude: 100.5, location_error_m: 40 }),
    ap({ latitude: null, longitude: null }),
    ap({}),
  ]);
  assert.equal(q.total, 3);
  assert.equal(q.positioned, 1);
  assert.equal(q.medianErrorM, 40);
});

test('exactly 0, 0 is rejected, because no survey here produces it', () => {
  assert.equal(summarisePositions([ap({ latitude: 0, longitude: 0 })]).positioned, 0);
  assert.equal(summarisePositions([ap({ latitude: 0, longitude: 100.5 })]).positioned, 1,
    'a single zero component is still a real place');
});

test('a positioned access point with no radius is counted as missing one, not as zero', () => {
  const q = summarisePositions([
    ap({ latitude: 13.7, longitude: 100.5 }),
    ap({ latitude: 13.8, longitude: 100.6, location_error_m: 20 }),
  ]);
  assert.equal(q.positioned, 2);
  assert.equal(q.radiusStated, 1);
  assert.equal(q.radiusMissing, 1);
  assert.equal(q.medianErrorM, 20, 'the missing radius must not drag the median toward 0');
  assert.equal(q.worstErrorM, 20);
});

test('well constrained means one side of the road was determined, and is counted apart', () => {
  const q = summarisePositions([
    ap({ latitude: 13.7, longitude: 100.5, location_error_m: 10 }),
    ap({ latitude: 13.8, longitude: 100.6, location_error_m: 90, geometry_ambiguous: 1 }),
  ]);
  assert.equal(q.ambiguous, 1);
  assert.equal(q.wellConstrained, 1);
  assert.equal(q.medianErrorM, 50);
  assert.equal(q.medianWellConstrainedM, 10);
  assert.equal(q.ambiguousAps.length, 1);
});

test('an empty survey reports nulls, not zeroes', () => {
  const q = summarisePositions([]);
  assert.equal(q.medianErrorM, null);
  assert.equal(q.medianWellConstrainedM, null);
  assert.equal(q.worstErrorM, null);
  assert.equal(q.positioned, 0);
});

test('an unrecorded estimator is grouped as "not recorded" rather than dropped', () => {
  const q = summarisePositions([
    ap({ latitude: 13.7, longitude: 100.5, location_method: 'bayesian_grid' }),
    ap({ latitude: 13.8, longitude: 100.6 }),
    ap({ latitude: 13.9, longitude: 100.7, location_method: '' }),
  ]);
  assert.equal(q.methods.get('bayesian_grid'), 1);
  assert.equal(q.methods.get('not recorded'), 2);
});

// ── The estimator has to be named next to its coordinate ───────────────────

test('every estimator the app can select has a label and a note', () => {
  // A latitude with no method attached invites a reader to treat an
  // RSSI-weighted guess as a surveyed position.
  for (const key of ['gpr', 'bayesian_grid', 'trilateration', 'weighted_centroid', 'peak_rssi']) {
    assert.equal(typeof LOCATION_METHOD_LABEL[key], 'string');
    assert.ok(locationMethodNote(key).length > 40, `${key} needs a real note`);
  }
});

test('the printed method description is not the one the documentation retracted', () => {
  /*
    These notes are what the PDF, the CSV and the KML print beside a coordinate,
    and two of them described an implementation the code does not have.

    `docs/AP_LOCATION_METHODS.md` §3 retracted both in writing — "this section
    previously described two things the code does not do: an FSPL formula, which
    appears nowhere in the codebase, and taking the 3 strongest observations and
    intersecting circles" — and the table that the reader actually holds was not
    changed with it. The correction reached whoever went looking and not whoever
    was handed the document.

    The direction matters. "The three strongest observations intersected" is not a
    loose paraphrase of a least-squares fit over every sighting; it is the exact
    mistake §2 of that document warns about, because the weak distant readings are
    what carry the range information. A reader weighing a position was told the
    tool did the naive thing.
  */
  const note = LOCATION_METHOD_NOTE.trilateration;
  assert.doesNotMatch(note, /free[- ]space path loss|FSPL/i,
    'the FSPL formula appears nowhere in the estimator');
  assert.doesNotMatch(note, /three strongest|3 strongest/i,
    'the solver fits every sighting, and using only the strongest is the documented mistake');
  assert.match(note, /least squares/i, 'the note should say what the solver does');

  // Tied to the constant, so changing the model fails here rather than leaving
  // the document quoting an exponent nothing uses any more.
  assert.ok(note.includes(`exponent ${PATH_LOSS_EXPONENT}`),
    `the note quotes an exponent that is not PATH_LOSS_EXPONENT (${PATH_LOSS_EXPONENT})`);
});

test('the track position does not describe itself as merely biased', () => {
  /*
    "Biased toward the route travelled" invites a reader to picture a position
    that leans toward the road. It cannot leave it: a weighted average of the
    sighting positions is a convex combination of them, so with the transmitter
    40 m from a single road the measured off-track displacement was 0.0 m in
    every trial. That is a different claim and a reader is entitled to it.
  */
  const note = LOCATION_METHOD_NOTE.weighted_centroid;
  assert.match(note, /cannot report a position off the route|0\.0 m/i,
    'the note understates a hard limit as a bias');
  assert.doesNotMatch(note, /signal-strength-weighted/i,
    'the weight is inverse modelled range, not signal strength');
});

test('the estimator is named the same in the report as in the app', () => {
  // The operator selects MULTILATERATION or TRACK POSITION in Settings; the
  // report called them "FSPL trilateration" and "RSSI-weighted centroid", which
  // is two names for one method and one of them for a method that does not exist.
  assert.match(LOCATION_METHOD_LABEL.trilateration, /multilateration/i);
  assert.match(LOCATION_METHOD_LABEL.weighted_centroid, /track position/i);
});

test('an unknown or absent estimator says so instead of guessing', () => {
  assert.equal(locationMethodLabel(null), 'not recorded');
  assert.equal(locationMethodLabel('future_method'), 'future_method');
  assert.match(locationMethodNote(null), /was not recorded/);
  assert.match(locationMethodNote('future_method'), /not described in this build/);
});

// ── Drawing an uncertainty circle ──────────────────────────────────────────

test('an error circle is closed and is a circle rather than an ellipse', () => {
  const ring = circlePolygon(100.5, 13.7, 100);
  assert.equal(ring.length, 65, '64 steps plus the closing point');
  assert.deepEqual(ring[0], ring[64]);

  // A degree of longitude is shorter than a degree of latitude by cos(lat), so
  // one scale for both axes draws the wrong shape at the wrong size.
  const north = ring[16];
  const east = ring[0];
  const dLat = Math.abs(north[1] - 13.7) * 111320;
  const dLon = Math.abs(east[0] - 100.5) * 111320 * Math.cos((13.7 * Math.PI) / 180);
  assert.ok(Math.abs(dLat - 100) < 1, `north radius ${dLat}`);
  assert.ok(Math.abs(dLon - 100) < 1, `east radius ${dLon}`);
});

test('a circle near the pole does not divide by zero', () => {
  const ring = circlePolygon(0, 90, 100);
  assert.ok(ring.every(([lon, lat]) => Number.isFinite(lon) && Number.isFinite(lat)));
});

// ── Assessing a whole archive ──────────────────────────────────────────────

test('a wireless archive is assessed through the AP path', () => {
  const findings = assessReport(report({
    rawData: { accessPoints: [{ bssid: 'AA:BB:CC:DD:EE:FF', encryption: 'OPEN' }] },
  }));
  assert.equal(findings.length, 1);
  assert.equal(findings[0].severity, 'CRITICAL');
  assert.equal(findings[0].is_simulated, false);
});

test("an archive's simulated flag reaches every finding it produces", () => {
  // Simulated data stored unflagged beside real data is the failure this project
  // treats as blocking, so the flag has to survive the whole chain.
  const findings = assessReport(report({
    simulated: true,
    rawData: { accessPoints: [{ bssid: 'AA:BB:CC:DD:EE:FF', encryption: 'OPEN' }] },
  }));
  assert.equal(findings[0].is_simulated, true);
});

test('an empty archive raises nothing and does not throw', () => {
  assert.deepEqual(assessReport(report()), []);
  assert.deepEqual(assessReport(report({ type: 'INTRUSION' })), []);
});

test('a per-AP simulated flag is enough on its own', () => {
  const findings = assessReport(report({
    rawData: { accessPoints: [{ bssid: 'AA:BB:CC:DD:EE:FF', encryption: 'OPEN', simulated: true }] },
  }));
  assert.equal(findings[0].is_simulated, true);
});

// ── Constants the document's layout and wording depend on ──────────────────

test('every severity level has a print colour', () => {
  for (const level of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']) {
    const rgb = SEVERITY_RGB[level];
    assert.equal(rgb.length, 3, `${level} needs an RGB triple`);
    assert.ok(rgb.every(c => Number.isInteger(c) && c >= 0 && c <= 255), `${level} out of range`);
  }
});

test('every authorized-target kind in the order has a label', () => {
  // A group rendered with no heading reads as an unexplained list of addresses
  // in the authorization record.
  for (const kind of TARGET_KIND_ORDER) {
    assert.equal(typeof TARGET_KIND_LABEL[kind], 'string', `${kind} has no label`);
  }
});

test('the audit row cap is a positive integer, because the page states the true total', () => {
  assert.ok(Number.isInteger(AUDIT_ROWS_IN_PDF) && AUDIT_ROWS_IN_PDF > 0);
  assert.equal(AMBIGUOUS_FLAG, 'AMBIGUOUS');
});

// ── Host input ─────────────────────────────────────────────────────────────

test('a credential is matched to its host by IP, and absent otherwise', () => {
  const creds = [{ target_ip: '10.0.0.5', username: 'root', password: 'x' }];
  assert.deepEqual(toHostInput({ ip: '10.0.0.5' }, creds, false).default_creds,
    { username: 'root', password: 'x' });
  assert.equal(toHostInput({ ip: '10.0.0.9' }, creds, false).default_creds, undefined);
});

test('a credential with no username is not a recovered credential', () => {
  // The rule set scores `credentials.recovered` at 100 — the top of the scale.
  // A row with a password and no account to use it on is not that finding.
  const creds = [{ target_ip: '10.0.0.5', password: 'x' }];
  assert.equal(toHostInput({ ip: '10.0.0.5' }, creds, false).default_creds, undefined);
});

test('a port with no number is dropped rather than becoming port 0', () => {
  // `Number(undefined)` is NaN and `Number(null)` is 0; either one reaches the
  // rule set as a service on a port nobody scanned.
  const input = toHostInput({
    ip: '10.0.0.5',
    open_ports: [{ port: 22, service: 'ssh' }, { port: null }, { port: undefined }, null],
  }, [], false);
  assert.equal(input.open_ports.length, 1);
  assert.equal(input.open_ports[0].port, 22);
});

test('a host in a simulated archive is flagged even when the row is not', () => {
  assert.equal(toHostInput({ ip: '10.0.0.5' }, [], true).simulated, true);
  assert.equal(toHostInput({ ip: '10.0.0.5', simulated: true }, [], false).simulated, true);
  assert.equal(toHostInput({ ip: '10.0.0.5' }, [], false).simulated, false);
});

test("a credential the sweep itself demonstrated is not lost", () => {
  /*
    `engine/scanner/lan.py` runs a quick credential check during a DEEP sweep and
    puts the result on the host as `default_creds`. This helper only read the
    vault's credentials array, so that credential was dropped unless it also
    happened to be in the snapshot — and `credentials.recovered` is the top of
    the scale at 100. A demonstrated login is the strongest statement this tool
    can make; it must not depend on which subsystem recorded it.
  */
  const input = toHostInput({ ip: '10.0.0.5', default_creds: { username: 'admin', password: 'admin' } }, [], false);
  assert.deepEqual(input.default_creds, { username: 'admin', password: 'admin' });
});

test('the vault snapshot wins over the host record when both have one', () => {
  // The snapshot is the durable record and may carry a later, better credential.
  const creds = [{ target_ip: '10.0.0.5', username: 'root', password: 'toor' }];
  const input = toHostInput({ ip: '10.0.0.5', default_creds: { username: 'admin' } }, creds, false);
  assert.equal(input.default_creds.username, 'root');
});

test('a host-record credential with no username is not a recovered credential', () => {
  const input = toHostInput({ ip: '10.0.0.5', default_creds: { password: 'x' } }, [], false);
  assert.equal(input.default_creds, undefined);
});

/*
  ── Population figures, and the figure that disagreed with its own caption ────

  Every count in the document deduplicates by BSSID, because two archives of one
  estate are still one estate. `totalAPs` in `assemble.ts` sets the rule and
  `allFindings`, `wpsEntries`, `rogueEntries` and POSITION QUALITY all follow it.

  Two places did not, and one of them mattered more than a doubled count: the WPS
  denominator was a plain flatMap while `wpsEntries` *was* deduplicated, so merging
  two archives of the same 50 radios printed "Of the 100 access point(s) in this
  archive" beside an ACCESS POINTS tile reading 50 — and halved the stated coverage
  rate, which is the number a reader acts on.
*/

test('one radio seen in two archives is one radio', () => {
  const aps = [
    { bssid: 'AA:BB:CC:DD:EE:01', ssid: 'A' },
    { bssid: 'aa:bb:cc:dd:ee:01', ssid: 'A' },
    { bssid: 'AA:BB:CC:DD:EE:02', ssid: 'B' },
  ];
  // Case-insensitive, because the ARP table and the scanner disagree on case and
  // the same radio must not count twice over it.
  assert.equal(dedupeApsByBssid(aps).length, 2);
});

test('the first sighting is the one kept', () => {
  const out = dedupeApsByBssid([
    { bssid: 'AA:BB:CC:DD:EE:01', ssid: 'first' },
    { bssid: 'AA:BB:CC:DD:EE:01', ssid: 'second' },
  ]);
  assert.equal(out.length, 1);
  assert.equal(out[0].ssid, 'first');
});

test('an access point with no BSSID is its own entry, not collapsed', () => {
  // Matching `totalAPs`: blanks cannot be deduplicated, and silently merging them
  // would erase real radios from the count.
  const out = dedupeApsByBssid([
    { bssid: '', ssid: 'one' },
    { bssid: null, ssid: 'two' },
    { ssid: 'three' },
  ]);
  assert.equal(out.length, 3);
});

test('an empty list stays empty', () => {
  assert.deepEqual(dedupeApsByBssid([]), []);
});

// ── The survey figure's own census ──────────────────────────────────────────

const sevInfo = () => 'INFO';

test('every mark that stands for a radio is counted as plotted', () => {
  /*
    `mirror` was overloaded: it meant "draw this hollow" and also "this is a second
    answer". An unresolved AP got `mirror: true` for the paint, and `plotted` was
    `points.filter(p => !p.properties.mirror)` — so it was left out of the plotted
    count while `counts[sev]` had already included it. The KEY summed higher than the
    "N plotted" sentence printed directly underneath, for dots that are on the map.
  */
  const aps = [
    { bssid: 'AA:BB:CC:DD:EE:01', latitude: 13.75, longitude: 100.5 },
    { bssid: 'AA:BB:CC:DD:EE:02', latitude: 13.76, longitude: 100.5, location_resolved: false },
  ];
  const f = featuresFor(aps, [], sevInfo);
  const keyTotal = Object.values(f.counts).reduce((a, b) => a + b, 0);
  // The production rule itself, not a copy: a mirror of it in this file would
  // have kept passing while `plotted` went back to excluding unresolved marks.
  const plotted = plottedCount(f.points);
  assert.equal(plotted, keyTotal, 'the KEY and the plotted count disagree');
});

test('an unresolved access point is still drawn hollow', () => {
  // The paint behaviour has to survive the split, or the caveat stops being visible.
  const f = featuresFor(
    [{ bssid: 'AA:BB:CC:DD:EE:02', latitude: 13.76, longitude: 100.5, location_resolved: false }],
    [], sevInfo);
  assert.equal(f.points[0].properties.mirror, true);
  assert.equal(f.points[0].properties.twin, false);
  assert.equal(f.unresolvedCount, 1);
});

test('a mirror twin is excluded from the plotted count', () => {
  // It is a second answer for one radio, not a second radio on the street.
  const f = featuresFor([{
    bssid: 'AA:BB:CC:DD:EE:03', latitude: 13.75, longitude: 100.5,
    geometry_ambiguous: 1, location_mirror_lat: 13.74, location_mirror_lon: 100.49,
  }], [], sevInfo);
  assert.equal(f.points.length, 2);
  assert.equal(plottedCount(f.points), 1);
  assert.equal(f.mirrorsDrawn, 1);
});

test('an ambiguous access point with no mirror coordinates draws one dot and says so', () => {
  /*
    The caption claimed every ambiguous AP "is drawn twice". `isMirrorAmbiguous`
    returns true on `geometry_ambiguous === 1` alone, while the twin is only pushed
    when both mirror coordinates are finite — the flag column and the coordinate
    columns are independent. So the stated count of double dots exceeded what was on
    the map, and a reader counting them found the figure wrong.
  */
  const f = featuresFor([{
    bssid: 'AA:BB:CC:DD:EE:04', latitude: 13.75, longitude: 100.5,
    geometry_ambiguous: 1, location_mirror_lat: null, location_mirror_lon: null,
  }], [], sevInfo);
  assert.equal(f.points.length, 1);
  assert.equal(f.ambiguous, 1);
  assert.equal(f.mirrorsDrawn, 0, 'a twin was counted that was never drawn');
});
