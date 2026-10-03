/**
 * The three text exports, and what they are allowed to place on a map.
 *
 *     npm run test:exports
 *
 * Why this exists.
 *
 * The CSV, the KML and the GeoJSON are what a client actually receives alongside
 * the PDF, and until now the only one with any coverage was the zip container the
 * KML travels inside — `tests/kmz.test.mjs` packs the literal `<kml>hello</kml>`.
 * Nothing had ever asserted a placemark, a coordinate, an escape, or which access
 * points were in the file at all.
 *
 * The first thing this found is why it was worth writing. Each export decided
 * separately whether an access point had a position, and they did not agree:
 *
 *   - KML filtered on `coordinatePair`, which rejects exactly `0, 0` — the value
 *     a NULL column decays into — and anything out of range;
 *   - GeoJSON filtered on `typeof === 'number' && Number.isFinite`, so it placed
 *     that access point in the Gulf of Guinea;
 *   - CSV did not filter at all and printed `0.000000, 0.000000` as a coordinate.
 *
 * One archive, three documents, three different sets of located transmitters. The
 * rule lives in `apRows.ts` now and these tests hold all three to it.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  apExportRows,
  positionedRows,
  exportBaseName,
  buildCsv,
  buildKml,
  buildGeoJson,
} from '../.test-build/exports.mjs';

const AP = (over = {}) => ({
  bssid: 'AA:BB:CC:DD:EE:01',
  ssid: 'TEST-NET',
  encryption: 'WPA2',
  latitude: 13.7563,
  longitude: 100.5018,
  ...over,
});

function wirelessReport(aps, over = {}) {
  return {
    id: 'WIFI-1',
    targetName: 'Test Survey',
    type: 'WIFI_WARDRIVE',
    timestamp: '2026-01-01T00:00:00Z',
    simulated: false,
    rawData: { accessPoints: aps, pathCoords: [] },
    ...over,
  };
}

// ── One rule for what counts as a position ──────────────────────────────────

test('exactly 0, 0 is an absent column in every export, not the Atlantic', () => {
  /*
    The defect this file was written for. A NULL latitude read as 0 is the single
    most common way a coordinate goes wrong in this codebase — the survey map once
    drew 189 access points into the Gulf of Guinea over it — and two of the three
    exports still placed it.
  */
  const report = wirelessReport([
    AP({ bssid: 'AA:BB:CC:DD:EE:01', latitude: 0, longitude: 0 }),
    AP({ bssid: 'AA:BB:CC:DD:EE:02' }),
  ]);

  assert.equal(positionedRows(report).length, 1, 'the 0,0 row was treated as placed');

  const geo = buildGeoJson(report);
  assert.equal(geo.features.length, 1);
  assert.deepEqual(geo.features[0].geometry.coordinates, [100.5018, 13.7563]);

  const kml = buildKml(report);
  assert.equal((kml.match(/<Placemark>/g) ?? []).length, 1);
  assert.doesNotMatch(kml, /0\.000000,0\.000000/);

  // The CSV keeps the row — it is an inventory — but states no coordinate for it.
  const csv = buildCsv(report);
  const rows = csv.trim().split('\n');
  const zeroRow = rows.find(r => r.includes('EE:01'));
  assert.ok(zeroRow, 'the unplaced access point was dropped from the inventory');
  assert.doesNotMatch(zeroRow, /0\.000000/, 'the CSV printed 0,0 as a measurement');
});

test('an out-of-range coordinate is not a position either', () => {
  // A corrupted row that survives `finiteNumber` still has to be kept off a map.
  const report = wirelessReport([AP({ latitude: 95, longitude: 200 })]);
  assert.equal(positionedRows(report).length, 0);
  assert.equal(buildKml(report), null);
  assert.equal(buildGeoJson(report), null);
});

test('a single zero component is a real place', () => {
  // The equator and the prime meridian are not absences.
  for (const over of [{ latitude: 0 }, { longitude: 0 }]) {
    const report = wirelessReport([AP(over)]);
    assert.equal(positionedRows(report).length, 1, JSON.stringify(over));
  }
});

test('nothing placed produces no document rather than an empty one', () => {
  /*
    Null, not an empty `FeatureCollection` or a `<kml>` with no placemarks: an
    empty map reads as "nothing was there", and the caller has to be able to say
    "nothing could be located" instead.
  */
  const report = wirelessReport([AP({ latitude: null, longitude: null })]);
  assert.equal(buildKml(report), null);
  assert.equal(buildGeoJson(report), null);
});

// ── The KML document ────────────────────────────────────────────────────────

test('an SSID cannot close a tag', () => {
  /*
    An SSID is text chosen by whoever owns the access point. This one is a valid
    network name and a KML injection at the same time.
  */
  const nasty = ']]></name><Placemark><name>INJECTED</name></Placemark><name>';
  const kml = buildKml(wirelessReport([AP({ ssid: nasty })]));
  assert.doesNotMatch(kml, /INJECTED<\/name><\/Placemark>/);
  assert.equal((kml.match(/<Placemark>/g) ?? []).length, 1, 'a second placemark was injected');
  assert.match(kml, /&lt;Placemark&gt;/, 'the angle brackets were not escaped');
});

test('coordinates are written longitude first, as KML requires', () => {
  // The one ordering mistake that produces a plausible-looking map in the wrong
  // hemisphere, and the reason this is asserted rather than eyeballed.
  const kml = buildKml(wirelessReport([AP()]));
  assert.match(kml, /<coordinates>100\.501800,13\.756300,0<\/coordinates>/);
});

test('an ambiguous access point is drawn twice and joined', () => {
  /*
    The second placemark is the same transmitter in the place the survey geometry
    cannot rule out. A document that draws only one of the two is asserting a coin
    flip, and one that draws the second without the line joining them is claiming
    a radio that does not exist.
  */
  const report = wirelessReport([AP({
    geometry_ambiguous: 1,
    location_mirror_lat: 13.7571,
    location_mirror_lon: 100.5018,
    location_mirror_distance_m: 89,
  })]);
  const kml = buildKml(report);
  // Three placemarks, not two: KML has no bare geometry, so the line joining the
  // pair is a placemark of its own. Counted by geometry rather than by element,
  // which is the distinction that matters -- two *points* is the claim.
  assert.equal((kml.match(/<Point>/g) ?? []).length, 2, 'the second candidate was not drawn');
  assert.equal((kml.match(/<LineString>/g) ?? []).length, 1, 'the two candidates were not joined');
  assert.equal((kml.match(/<Placemark>/g) ?? []).length, 3);
  assert.match(kml, /89(\.0)? m/, 'the separation was not stated');
});

test('a mirror flag with no stored candidate draws one placemark, not two', () => {
  // `geometry_ambiguous` and the coordinates are independent columns; a flag on
  // its own is not a second position and must not become one.
  const kml = buildKml(wirelessReport([AP({ geometry_ambiguous: 1 })]));
  assert.equal((kml.match(/<Point>/g) ?? []).length, 1);
  assert.doesNotMatch(kml, /<LineString>/);
});

// ── The GeoJSON document ────────────────────────────────────────────────────

test('the collection carries the model behind its own coordinates', () => {
  /*
    A consumer weighing a radius needs the path-loss model that produced it, and
    will not have this application to hand.
  */
  const geo = buildGeoJson(wirelessReport([AP()]));
  assert.equal(geo.type, 'FeatureCollection');
  assert.ok(geo.properties.localization, 'no localization methodology was stated');
  assert.match(String(geo.properties.methodology), /@/, 'no rule set version');
  assert.equal(geo.properties.report_id, 'WIFI-1');
});

test('GeoJSON is longitude, latitude — the opposite of how it is usually said', () => {
  const geo = buildGeoJson(wirelessReport([AP()]));
  assert.deepEqual(geo.features[0].geometry.coordinates, [100.5018, 13.7563]);
});

// ── The CSV ─────────────────────────────────────────────────────────────────

test('a quote in an SSID does not shift every following column', () => {
  const csv = buildCsv(wirelessReport([AP({ ssid: 'HOME "GUEST" NET' })]));
  const header = csv.trim().split('\n')[0].split(',').length;
  const row = csv.trim().split('\n')[1];
  // Counting commas outside quotes is the point: a naive writer produces more
  // fields than the header has.
  let fields = 1, inQuotes = false;
  for (const ch of row) {
    if (ch === '"') inQuotes = !inQuotes;
    else if (ch === ',' && !inQuotes) fields++;
  }
  assert.equal(fields, header, 'the row and the header disagree about column count');
});

test('an SSID is not handed to a spreadsheet as a program', () => {
  // The cell is chosen by whoever owns the access point.
  const csv = buildCsv(wirelessReport([AP({ ssid: '=cmd|\' /C calc\'!A0' })]));
  const row = csv.trim().split('\n')[1];
  assert.doesNotMatch(row, /(^|,)"?=cmd/, 'a formula reached the cell unneutralised');
});

test('the filename is derived from the archive, not invented', () => {
  assert.equal(
    exportBaseName({ targetName: 'Sukhumvit / Soi 11', id: 'WIFI-9' }),
    'Sukhumvit_Soi_11_WIFI-9'
  );
});

test('every row carries the rule set\'s verdict, not a second opinion', () => {
  const rows = apExportRows(wirelessReport([AP({ encryption: 'WEP' })]));
  assert.equal(rows.length, 1);
  assert.ok(rows[0].findings.length > 0);
  // WEP is CRITICAL in this rule set, not HIGH -- the export must report what the
  // rule set says rather than a severity chosen at the call site.
  assert.equal(rows[0].worst.severity, 'CRITICAL');
  assert.equal(rows[0].verdict, 'CLEAR');
});
