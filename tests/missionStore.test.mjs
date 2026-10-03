/**
 * Tests for what happens when the engine reports an access point twice.
 *
 *     npm run test:mission
 *
 * Why this exists.
 *
 * `mergeEngineFields` decides which fields of a second sighting overwrite the
 * first, and the live map it maintains is what a report is archived from. It had
 * no test, and neither did anything else in `missionStore`.
 *
 * The merge exists because of a defect worth restating, since these tests are the
 * only thing holding the fix in place. Both callers used to inline a spread that
 * re-applied ten fields and dropped everything else on the incoming record —
 * including all three rogue fields. That interacts badly with how the engine is
 * deliberately built: rogue scoring runs over the whole session cache rather than
 * the current batch, because a twin is only visible relative to its peers. So the
 * verdict *upgrades* on a later cycle than first sighting, which was exactly the
 * update being discarded. **An access point first seen as CLEAR stayed CLEAR
 * forever.** Meanwhile `wardrivingDB.logAccessPoint` wrote the raw engine record
 * to SQLite and kept the highest-scoring verdict — so the database held the
 * correct verdict, the exported report did not, and the report was the one going
 * to a manager.
 *
 * The rules here mirror that table's `ON CONFLICT` clause on purpose. Each test
 * names the SQL behaviour it is holding the store to, because the point is not
 * that either is right in isolation — it is that they cannot disagree.
 */

import test, { beforeEach } from 'node:test';
import assert from 'node:assert/strict';

import { useMissionStore } from '../.test-build/db.mjs';

const add = ap => useMissionStore.getState().addAccessPoint(ap);
const get = bssid => useMissionStore.getState().accessPoints.get(bssid);
const BSSID = 'AA:BB:CC:DD:EE:FF';
const seen = (over = {}) => ({ bssid: BSSID, encryption: 'WPA2', rssi: -60, ...over });

beforeEach(() => useMissionStore.getState().reset());

// ── The rogue verdict that used to be frozen at first sighting ──────────────

test('a verdict that upgrades on a later cycle reaches the store', () => {
  // The original defect. The engine scores rogues across the whole session
  // cache, so CONFIRMED routinely arrives after the AP was first seen CLEAR.
  add(seen({ rogue_verdict: 'CLEAR', rogue_score: 0 }));
  add(seen({ rogue_verdict: 'CONFIRMED', rogue_score: 90, rogue_indicators: [{ code: 'x', weight: 50, detail: 'd' }] }));

  const ap = get(BSSID);
  assert.equal(ap.rogue_verdict, 'CONFIRMED');
  assert.equal(ap.rogue_score, 90);
  assert.equal(ap.rogue_indicators.length, 1);
});

test('a later scan that saw fewer peers does not erase a better verdict', () => {
  /*
    Decided by the engine's own score, never by recency — the same rule as the
    table's `CASE WHEN excluded.rogue_score >= access_points.rogue_score`. A scan
    that happened to catch fewer members of the SSID group is less informed, not
    more recent in any way that matters.
  */
  add(seen({ rogue_verdict: 'CONFIRMED', rogue_score: 90, rogue_indicators: [{ code: 'x', weight: 50, detail: 'd' }] }));
  add(seen({ rogue_verdict: 'CLEAR', rogue_score: 0, rogue_indicators: [] }));

  const ap = get(BSSID);
  assert.equal(ap.rogue_verdict, 'CONFIRMED');
  assert.equal(ap.rogue_score, 90);
  assert.equal(ap.rogue_indicators.length, 1, 'the indicators must stay with their verdict');
});

test('the three rogue fields move together or not at all', () => {
  // A verdict without its own score and indicators cannot be explained to a
  // reader, and the report prints all three side by side.
  add(seen({ rogue_verdict: 'LIKELY', rogue_score: 60, rogue_indicators: [{ code: 'a', weight: 30, detail: 'first' }] }));
  add(seen({ rogue_verdict: 'SUSPECTED', rogue_score: 30, rogue_indicators: [{ code: 'b', weight: 10, detail: 'second' }] }));

  const ap = get(BSSID);
  assert.equal(ap.rogue_verdict, 'LIKELY');
  assert.equal(ap.rogue_indicators[0].detail, 'first', 'indicators from the losing verdict must not survive');
});

test('an equal score lets the newer verdict through', () => {
  // Ties go to the incoming record, matching the SQL's `>=`.
  add(seen({ rogue_verdict: 'SUSPECTED', rogue_score: 45 }));
  add(seen({ rogue_verdict: 'LIKELY', rogue_score: 45 }));
  assert.equal(get(BSSID).rogue_verdict, 'LIKELY');
});

// ── Sticky flags: the worst state observed is what belongs in a report ──────

test('is_vulnerable and is_evil_twin are sticky, like the database MAX()', () => {
  add(seen({ is_vulnerable: true, is_evil_twin: true }));
  add(seen({ is_vulnerable: false, is_evil_twin: false }));
  const ap = get(BSSID);
  assert.equal(ap.is_vulnerable, true);
  assert.equal(ap.is_evil_twin, true);
});

test('a flag can still be raised by a later sighting', () => {
  add(seen({ is_vulnerable: false }));
  add(seen({ is_vulnerable: true }));
  assert.equal(get(BSSID).is_vulnerable, true);
});

// ── Provenance ─────────────────────────────────────────────────────────────

test('a real sighting clears a simulated-only record, like the database MIN()', () => {
  add(seen({ simulated: true }));
  add(seen({ simulated: false }));
  assert.equal(get(BSSID).simulated, false);
});

test('a simulated sighting never downgrades an access point seen for real', () => {
  // Simulated data presented as field data is the failure this project treats as
  // blocking, so this direction matters more than the other one.
  add(seen({ simulated: false }));
  add(seen({ simulated: true }));
  assert.equal(get(BSSID).simulated, false);
});

// ── The twelve fields that used to be dropped ──────────────────────────────

test('every field the old spread dropped now survives a second sighting', () => {
  /*
    Named individually because that is the failure mode: a field is added to the
    engine, to the types and to the table, and silently never re-applied here. It
    then exists during the first sighting and vanishes on the second, which looks
    like the adapter being inconsistent rather than like a merge bug.
  */
  add(seen({}));
  add(seen({
    cipher: 'CCMP', auth_type: 'WPA3-Personal', radio_type: '802.11ax',
    band: '5G', frequency: 5745, connected_stations: 12,
    channel_utilization_pct: 41, rssi_trend: 'RISING', channel: 149,
  }));

  const ap = get(BSSID);
  assert.equal(ap.cipher, 'CCMP');
  assert.equal(ap.auth_type, 'WPA3-Personal');
  assert.equal(ap.radio_type, '802.11ax');
  assert.equal(ap.band, '5G');
  assert.equal(ap.frequency, 5745);
  assert.equal(ap.connected_stations, 12);
  assert.equal(ap.channel_utilization_pct, 41);
  assert.equal(ap.rssi_trend, 'RISING');
  assert.equal(ap.channel, 149);
});

test('a measured zero is kept, not treated as a missing value', () => {
  // `connected_stations: 0` means the AP published a BSS Load and nobody was on
  // it. A `||`-style merge would fall back to the previous reading and turn a
  // measurement into stale data.
  add(seen({ connected_stations: 7, channel_utilization_pct: 30 }));
  add(seen({ connected_stations: 0, channel_utilization_pct: 0 }));
  const ap = get(BSSID);
  assert.equal(ap.connected_stations, 0);
  assert.equal(ap.channel_utilization_pct, 0);
});

test('a field the adapter stopped reporting keeps its last known value', () => {
  // netsh enrichment is best-effort and can miss an AP on a later cycle. A gap
  // scattered through a scan reads as a finding, so the last real reading stays.
  add(seen({ radio_type: '802.11ac', connected_stations: 3 }));
  add(seen({}));
  const ap = get(BSSID);
  assert.equal(ap.radio_type, '802.11ac');
  assert.equal(ap.connected_stations, 3);
});

test('an empty string does not overwrite a real value', () => {
  add(seen({ ssid: 'REAL-SSID', cipher: 'CCMP' }));
  add(seen({ ssid: '', cipher: '' }));
  const ap = get(BSSID);
  assert.equal(ap.ssid, 'REAL-SSID');
  assert.equal(ap.cipher, 'CCMP');
});

// ── Timestamps ─────────────────────────────────────────────────────────────

test('first_seen is the first sighting and last_seen is the latest', () => {
  add(seen({ first_seen: '2026-09-30T10:00:00Z', last_seen: '2026-09-30T10:00:00Z' }));
  add(seen({ first_seen: '2026-09-30T10:05:00Z', last_seen: '2026-09-30T10:05:00Z' }));
  const ap = get(BSSID);
  assert.equal(ap.first_seen, '2026-09-30T10:00:00Z', 'a later batch must not reset the first sighting');
  assert.equal(ap.last_seen, '2026-09-30T10:05:00Z');
});

// ── Signal ─────────────────────────────────────────────────────────────────

test('the newest signal reading always wins, because it is a fresh measurement', () => {
  // Unlike the enrichment fields, RSSI is not carried forward: it describes this
  // sighting from this position, and an old value would be attributed to a new
  // place.
  add(seen({ rssi: -40 }));
  add(seen({ rssi: -75 }));
  assert.equal(get(BSSID).rssi, -75);
});

test('a sighting that carries no signal reading leaves rssi unset rather than inventing one', () => {
  /*
    Current behaviour, recorded deliberately: `rssi` takes the incoming value
    unconditionally, so a record with no reading clears it. That is consistent
    with the rest of the project — `scan_logs.rssi` used to be written as
    `ap.rssi ?? -90`, which stored an invented reading that then fed the
    localizer, and the fix was to stop substituting. An absent reading showing as
    absent is the honest outcome; the display layer reads it as "not reported".

    If this is ever changed to carry the previous reading forward, that is a
    decision to attribute an old measurement to a new position, and it should
    fail this test first.
  */
  add(seen({ rssi: -40 }));
  add({ bssid: BSSID, encryption: 'WPA2' });
  assert.equal(get(BSSID).rssi, undefined);
});

// ── First sighting ─────────────────────────────────────────────────────────

test('a first sighting is stored as given', () => {
  add(seen({ ssid: 'NEW', cipher: 'CCMP', connected_stations: 0 }));
  const ap = get(BSSID);
  assert.equal(ap.ssid, 'NEW');
  assert.equal(ap.cipher, 'CCMP');
  assert.equal(ap.connected_stations, 0);
  assert.equal(useMissionStore.getState().accessPoints.size, 1);
});

test('two different radios are two entries', () => {
  add(seen({ bssid: 'AA:AA:AA:AA:AA:AA' }));
  add(seen({ bssid: 'BB:BB:BB:BB:BB:BB' }));
  assert.equal(useMissionStore.getState().accessPoints.size, 2);
});

// ── The position caveat that never reached a live archive ────────────────────

/*
  `location_resolved` was written by `addAccessPoint` and not by `addAccessPoints`,
  which took six other fields off the same `estimate` object.

  That was not an edge case. The engine has no `ap_found` emitter at all --
  `handler.py` only ever sends `aps_batch` -- so `addAccessPoint` is dead code and
  the batch path is the one every live survey takes. `isUnresolved` in
  `report/archive.ts` reads `location_resolved === false`, so it was permanently
  false for a live archive: an access point the receiver never moved far enough to
  place was drawn on the survey map as an ordinary measured fix. A mission replayed
  from SQLite showed the caveat correctly, because `wardrivingDB` sets the field,
  so one mission produced two different documents depending on how it was read.
*/

const addBatch = aps => useMissionStore.getState().addAccessPoints(aps);

/** `count` sightings of one radio, all reported from the same coordinate. */
const stationary = (count, lat = 13.7563, lon = 100.5018) =>
  Array.from({ length: count }, (_, i) => seen({
    latitude: lat, longitude: lon, rssi: -55 - (i % 3), frequency: 2437,
  }));

/** `count` sightings along a line, as a vehicle driving past would report. */
const driving = count =>
  Array.from({ length: count }, (_, i) => seen({
    latitude: 13.7563 + i * 0.0004,
    longitude: 100.5018 + i * 0.0004,
    rssi: -45 - Math.abs(i - count / 2) * 4,
    frequency: 2437,
  }));

test('the batch path writes location_resolved at all', () => {
  // The whole defect in one assertion: the field was simply absent, and absent
  // is not false, so every caveat downstream was unreachable.
  for (const ap of driving(14)) addBatch([ap]);
  assert.notEqual(get(BSSID).location_resolved, undefined,
    'addAccessPoints produced an access point with no location_resolved field');
});

test('a receiver that never moved reports its position as unresolved', () => {
  // The case the caveat exists for. Every reading from one spot constrains
  // nothing, and the estimator says so; the store has to carry that through.
  for (const ap of stationary(14)) addBatch([ap]);
  const ap = get(BSSID);
  assert.equal(ap.location_resolved, false,
    `a stationary survey was recorded as resolved (method ${ap.location_method})`);
});

test('a real drive-past is resolved', () => {
  // The other side of it: the fix must not start labelling good surveys as
  // unresolved, or the caveat becomes noise and gets ignored.
  for (const ap of driving(14)) addBatch([ap]);
  assert.equal(get(BSSID).location_resolved, true);
});

test('location_resolved is a boolean, never a truthy estimate object', () => {
  for (const ap of driving(14)) addBatch([ap]);
  assert.equal(typeof get(BSSID).location_resolved, 'boolean');
});
