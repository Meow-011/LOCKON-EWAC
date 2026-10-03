/**
 * The live map has to admit what it does not know.
 *
 *     npm run test:livemap
 *
 * Why this exists.
 *
 * Every access point on the tactical map was a 5 or 7 pixel dot, and a dot is an
 * assertion. The estimators have published an uncertainty radius and, on a
 * straight pass, a second equally good position on the other side of the road
 * since migration 011; the exported PDF, CSV and KML all print both.
 * `location_error_m`, `geometry_ambiguous` and `location_mirror_lat`/`lon` reached
 * `MapView` on every feature and were never read.
 *
 * So one mission produced two different pictures. On screen, during the survey, a
 * transmitter known to ±90 m that could equally well be across the street looked
 * exactly like one pinned to five metres; in the report afterwards the same radio
 * carried a ring, an AMBIGUOUS flag and a twin. The screen was the confident one,
 * and the screen is what decides where the operator drives next.
 *
 * These tests are mostly about absences, because that is where this goes wrong.
 * A radius too wide to draw, a position with no radius at all, and an access
 * point flagged ambiguous whose second candidate was never stored are three
 * different states, and on a map all three look like a clean dot unless something
 * counts them and says so.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  RING_LIMIT_M,
  uncertaintyCaveat,
  uncertaintyFeatures,
} from '../.test-build/liveMap.mjs';

const LAT = 13.7563;
const LON = 100.5018;

function ap(over = {}) {
  return { bssid: 'AA:BB:CC:DD:EE:FF', ssid: 'TEST', latitude: LAT, longitude: LON, ...over };
}

const kinds = (u, kind) => u.features.filter(f => f.properties.kind === kind);

// ── The ring ────────────────────────────────────────────────────────────────

test('a stated radius is drawn as a closed ring around its own dot', () => {
  const u = uncertaintyFeatures([ap({ location_error_m: 40 })]);
  const rings = kinds(u, 'ring');
  assert.equal(rings.length, 1);
  assert.equal(u.noRadius, 0);

  const outline = rings[0].geometry.coordinates[0];
  assert.deepEqual(outline[0], outline[outline.length - 1], 'the ring is not closed');

  // Centred on the access point, at the radius it was given. A degree of
  // longitude is shorter than one of latitude by cos(lat), so one scale for both
  // axes would draw the wrong shape at the wrong size.
  const north = outline[16];
  const east = outline[0];
  const dLat = Math.abs(north[1] - LAT) * 111320;
  const dLon = Math.abs(east[0] - LON) * 111320 * Math.cos((LAT * Math.PI) / 180);
  assert.ok(Math.abs(dLat - 40) < 0.5, `north radius ${dLat}`);
  assert.ok(Math.abs(dLon - 40) < 0.5, `east radius ${dLon}`);
});

test('a radius too wide to draw is counted, not dropped', () => {
  /*
    Drawing every radius was tried on the report figure and produced a solid disc
    with the city underneath it: a real survey puts a hundred and sixty rings
    within a few streets, overlapping hundreds deep, and no fill opacity is low
    enough to survive that. So wide ones are left out — and a map that quietly
    leaves out the widest uncertainties it has is worse than one that draws none,
    because the dots that remain look like the well-measured ones.
  */
  const u = uncertaintyFeatures([
    ap({ bssid: '1', location_error_m: RING_LIMIT_M }),
    ap({ bssid: '2', location_error_m: RING_LIMIT_M + 1 }),
    ap({ bssid: '3', location_error_m: 4000 }),
  ]);
  assert.equal(kinds(u, 'ring').length, 1, 'the limit itself is inclusive');
  assert.equal(u.ringsOmitted, 2);
  assert.match(uncertaintyCaveat(u), /2 radius over 120 m not drawn/);
});

test('no radius at all is its own state', () => {
  /*
    Three rows that all render as a bare dot and mean different things: a null
    column, a column the estimator could not fill, and a zero. None of them is a
    tight position, and on a map where most dots carry a ring the bare ones read
    as the precise ones — the exact inversion of the truth.
  */
  const u = uncertaintyFeatures([
    ap({ bssid: '1' }),
    ap({ bssid: '2', location_error_m: null }),
    ap({ bssid: '3', location_error_m: 0 }),
  ]);
  assert.equal(kinds(u, 'ring').length, 0);
  assert.equal(u.noRadius, 3);
  assert.match(uncertaintyCaveat(u), /3 with no stated radius/);
});

test('an access point with no position is not annotated at all', () => {
  const u = uncertaintyFeatures([
    ap({ latitude: null, location_error_m: 40 }),
    ap({ latitude: 0, longitude: 0, location_error_m: 40 }),
  ]);
  assert.equal(u.features.length, 0);
  // And it is not counted as a position whose radius is missing, because it is
  // not a position.
  assert.equal(u.noRadius, 0);
  assert.equal(uncertaintyCaveat(u), null);
});

// ── The second candidate ────────────────────────────────────────────────────

test('an ambiguous position is drawn twice, joined', () => {
  const u = uncertaintyFeatures([ap({
    location_error_m: 90,
    geometry_ambiguous: 1,
    location_mirror_lat: LAT + 0.0008,
    location_mirror_lon: LON,
    location_mirror_distance_m: 89,
  })]);

  assert.equal(u.ambiguous, 1);
  assert.equal(u.mirrorsDrawn, 1);

  const mirrors = kinds(u, 'mirror');
  const links = kinds(u, 'link');
  assert.equal(mirrors.length, 1);
  assert.equal(links.length, 1);

  /*
    The line is not decoration. Without it an amber ring 90 m from a dot is read
    as another radio on the next street, which is the opposite of what it means:
    it is the same transmitter, in the place the geometry cannot rule out.
  */
  assert.deepEqual(links[0].geometry.coordinates[0], [LON, LAT], 'the link does not start at the dot');
  assert.deepEqual(links[0].geometry.coordinates[1], mirrors[0].geometry.coordinates);

  // The separation travels with both, so the popup can state what the ambiguity
  // costs instead of printing "n/r apart".
  assert.equal(mirrors[0].properties.distanceM, 89);
  assert.equal(links[0].properties.distanceM, 89);

  // The ring belongs to the access point, not to the candidate.
  assert.equal(kinds(u, 'ring').length, 1);
});

test('the ambiguity flag and a stored candidate are independent', () => {
  /*
    `isMirrorAmbiguous` ORs the two columns, and the report's survey map learned
    why: a row can carry mirror coordinates with a null flag, and treating it as a
    confident fix because one column happened to be empty is precisely the failure
    being guarded against.
  */
  const u = uncertaintyFeatures([ap({
    location_error_m: 60,
    geometry_ambiguous: null,
    location_mirror_lat: LAT + 0.0005,
    location_mirror_lon: LON,
  })]);
  assert.equal(u.ambiguous, 1);
  assert.equal(u.mirrorsDrawn, 1);
  // Amber, not grey: which side of the road is undetermined, and that is a
  // different statement from a position that is merely imprecise.
  assert.equal(kinds(u, 'ring')[0].properties.ambiguous, true);
});

test('flagged ambiguous with no candidate recorded says so', () => {
  /*
    The count the report's caption got wrong in the other direction: it claimed
    every ambiguous access point was drawn twice, while a twin is only drawn when
    both mirror coordinates are present and finite, so a reader counting double
    dots found the figure short.

    Here the consequence is worse, because the map is what the operator acts on: a
    single dot for a radio the estimator says could be in two places reads as a
    resolved position. `ambiguous` and `mirrorsDrawn` are therefore separate
    numbers and the difference is stated.
  */
  const u = uncertaintyFeatures([ap({
    location_error_m: 60,
    geometry_ambiguous: 1,
    location_mirror_lat: null,
    location_mirror_lon: null,
  })]);
  assert.equal(u.ambiguous, 1);
  assert.equal(u.mirrorsDrawn, 0);
  assert.equal(kinds(u, 'mirror').length, 0);
  assert.match(uncertaintyCaveat(u), /1 ambiguous with no second candidate recorded/);
});

test('a mirror at 0, 0 is an absent column, not the Atlantic', () => {
  // The old helper turned a NULL into 0, and the map ran a dashed line to the
  // Gulf of Guinea labelled "equally good position".
  const u = uncertaintyFeatures([ap({
    location_error_m: 60,
    geometry_ambiguous: 1,
    location_mirror_lat: 0,
    location_mirror_lon: 0,
  })]);
  assert.equal(u.mirrorsDrawn, 0);
  assert.equal(u.features.filter(f => f.properties.kind !== 'ring').length, 0);
});

// ── What the caveat line is allowed to say ──────────────────────────────────

test('nothing outstanding renders no caveat rather than a reassuring zero', () => {
  /*
    A permanent line reading "0 omitted" is a line the operator stops seeing, and
    the only survey it matters on is the one where it is not zero.
  */
  const u = uncertaintyFeatures([ap({ location_error_m: 30 })]);
  assert.equal(u.ringsOmitted, 0);
  assert.equal(u.noRadius, 0);
  assert.equal(uncertaintyCaveat(u), null);
});

test('every kind of absence appears in the caveat together', () => {
  const u = uncertaintyFeatures([
    ap({ bssid: '1', location_error_m: 900 }),
    ap({ bssid: '2' }),
    ap({ bssid: '3', location_error_m: 50, geometry_ambiguous: 1 }),
  ]);
  const note = uncertaintyCaveat(u);
  assert.match(note, /1 radius over 120 m not drawn/);
  assert.match(note, /1 with no stated radius/);
  assert.match(note, /1 ambiguous with no second candidate recorded/);
});

test('an absence the estimator always produces is named, not reported as a loss', () => {
  /*
    TRACK POSITION publishes no radius for anything. `estimateTrackPosition`
    returns `errorRadiusM: null` by construction -- a weighted average of the
    sighting positions has no uncertainty model behind it -- and `assessGeometry`
    still reports a straight route as mirror-ambiguous, which is true of the route
    while the estimator has no second candidate to offer.

    So on a straight survey using it, *every* access point lands in both counts.
    "47 with no stated radius - 47 ambiguous with no second candidate recorded"
    describes the method the operator chose, not damage to the data, and a caveat
    that says the same alarming thing on every survey is wallpaper by the second
    one.
  */
  const aps = Array.from({ length: 5 }, (_, i) => ap({
    bssid: `0${i}`,
    location_method: 'weighted_centroid',
    location_error_m: null,
    geometry_ambiguous: 1,
  }));
  const u = uncertaintyFeatures(aps);

  assert.equal(u.noRadius, 5);
  assert.equal(u.ambiguous, 5);
  assert.equal(u.mirrorsDrawn, 0);

  const note = uncertaintyCaveat(u);
  assert.match(note, /5 from Track position[^,]*, which states no radius/i);
  assert.match(note, /5 from Track position[^,]*, which offers no second candidate/i);
  // And it does not describe the method's own behaviour as a missing record.
  assert.doesNotMatch(note, /no second candidate recorded/);
});

test('a mixed set does not blame one estimator for the others', () => {
  /*
    The attribution is only honest when one estimator accounts for all of it.
    Here the grid produced a radius for one access point and not for another, which
    is a per-position absence and has to be reported as one.
  */
  const u = uncertaintyFeatures([
    ap({ bssid: '1', location_method: 'weighted_centroid', location_error_m: null }),
    ap({ bssid: '2', location_method: 'bayesian_grid', location_error_m: null }),
  ]);
  assert.equal(u.noRadiusMethod, null);
  assert.match(uncertaintyCaveat(u), /2 with no stated radius/);
});

test('a row that does not name its estimator explains nothing', () => {
  /*
    `locationMethodLabel(null)` is "not recorded", and reading that as the single
    shared estimator would have produced "3 from not recorded, which states no
    radius" -- a missing field offered as the explanation for itself.
  */
  const u = uncertaintyFeatures([
    ap({ bssid: '1', location_error_m: null }),
    ap({ bssid: '2', location_method: 'weighted_centroid', location_error_m: null }),
  ]);
  assert.equal(u.noRadiusMethod, null);
  assert.match(uncertaintyCaveat(u), /2 with no stated radius/);
});

test('an empty or absent list is not an error', () => {
  for (const input of [[], null, undefined]) {
    const u = uncertaintyFeatures(input);
    assert.equal(u.features.length, 0);
    assert.equal(uncertaintyCaveat(u), null);
  }
});

test('the ring limit is the report\'s, not a second opinion', () => {
  // Shared so the live map and the exported figure omit the same radii. Two
  // constants is how the screen and the document came to disagree in the first
  // place.
  assert.equal(RING_LIMIT_M, 120);
});
