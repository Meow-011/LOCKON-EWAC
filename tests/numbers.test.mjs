/**
 * Tests for reading numbers out of records that may not hold one.
 *
 *     npm run test:numbers
 *
 * Why this exists.
 *
 * The report read every optional numeric column through a helper that did
 * `Number(value)` and kept the result if it was finite. `Number(null)` is `0`,
 * and `0` is finite — so a column that had never been written came back as a
 * hard zero rather than as "not recorded".
 *
 * That put a fabricated measurement into an evidence document:
 *
 *   * `location_mirror_lat` / `location_mirror_lon` are NULL for an access point
 *     with no mirrored candidate. They became `0, 0` — a real coordinate in the
 *     Gulf of Guinea — and the archive map drew a dashed line from Thailand to
 *     the Atlantic for 189 of 196 access points, labelled as the second equally
 *     good position for that network.
 *   * `location_error_m` NULL became `0`, printed as "+/- 0 m": a perfect fix.
 *   * An access point with no position at all counted as positioned at 0, 0.
 *
 * The first test is the premise. If `Number(null)` ever stops being 0 the rest
 * of this file is about a problem that no longer exists, and that should be
 * visible rather than silently assumed.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  finiteNumber,
  coordinatePair,
  degreesWithHemisphere,
  formatFix,
} from '../.test-build/numbers.mjs';

test('the premise: JavaScript turns absent values into zero', () => {
  assert.equal(Number(null), 0);
  assert.equal(Number(''), 0);
  assert.equal(Number(false), 0);
  assert.equal(Number([]), 0);
  assert.equal(Number.isFinite(0), true);
});

test('an absent value is null, never zero', () => {
  for (const absent of [null, undefined, '', '   ', '\\t\\n']) {
    assert.equal(finiteNumber(absent), null, `${JSON.stringify(absent)} became a number`);
  }
});

test('non-numeric types are not coerced, however numeric they look', () => {
  for (const value of [false, true, [], [5], {}, new Date(0), () => 1]) {
    assert.equal(finiteNumber(value), null, `${String(value)} became a number`);
  }
});

test('a real number survives, including a real zero', () => {
  assert.equal(finiteNumber(0), 0);
  assert.equal(finiteNumber(-0), -0);
  assert.equal(finiteNumber(13.7563), 13.7563);
  assert.equal(finiteNumber(-85), -85);
});

test('numeric strings are read, because SQLite and CSV both hand them back', () => {
  assert.equal(finiteNumber('13.7563'), 13.7563);
  assert.equal(finiteNumber('  -85  '), -85);
  assert.equal(finiteNumber('0'), 0);
});

test('NaN and the infinities are not measurements', () => {
  for (const value of [NaN, Infinity, -Infinity, 'NaN', 'Infinity']) {
    assert.equal(finiteNumber(value), null, `${String(value)} was accepted`);
  }
});

test('a partial coordinate is no coordinate', () => {
  assert.equal(coordinatePair(13.7563, null), null);
  assert.equal(coordinatePair(null, 100.5018), null);
  assert.equal(coordinatePair(null, null), null);
  assert.equal(coordinatePair(undefined, undefined), null);
});

test('the Gulf of Guinea is rejected, because it is what absence used to look like', () => {
  // 0, 0 is a legal coordinate, and no survey this tool runs will produce it.
  // Keeping it out is what stops a NULL column being drawn as a position.
  assert.equal(coordinatePair(0, 0), null);
});

test('a genuine coordinate passes', () => {
  assert.deepEqual(coordinatePair(13.7563, 100.5018), { lat: 13.7563, lon: 100.5018 });
  assert.deepEqual(coordinatePair('13.7563', '100.5018'), { lat: 13.7563, lon: 100.5018 });
});

test('out-of-range values are rejected rather than plotted', () => {
  assert.equal(coordinatePair(91, 0), null);
  assert.equal(coordinatePair(-91, 0), null);
  assert.equal(coordinatePair(0, 181), null);
  assert.equal(coordinatePair(0, -181), null);
  // The poles and the date line are legal.
  assert.notEqual(coordinatePair(90, 180), null);
  assert.notEqual(coordinatePair(-90, -180), null);
});

test('a single zero component is still a position', () => {
  // Only the 0,0 pair is treated as absence; the equator and the prime
  // meridian individually are real places.
  assert.notEqual(coordinatePair(0, 100.5018), null);
  assert.notEqual(coordinatePair(13.7563, 0), null);
});


// ── Hemispheres come from the sign ──────────────────────────────────────────

test('a negative degree is the other hemisphere, not a minus sign', () => {
  /*
    The top bar printed `${latitude.toFixed(4)}°N ${longitude.toFixed(4)}°E` with
    the letters written in, so a fix south of the equator or west of Greenwich read
    as "-13.7563°N" -- a minus sign and a hemisphere letter contradicting each
    other, in the readout an operator checks most often.

    The offline-basemap card was fixed for exactly this, and the fix did not reach
    the live readout because each surface had its own formatter. There is now one.
  */
  assert.equal(degreesWithHemisphere(13.7563, 'lat'), '13.7563°N');
  assert.equal(degreesWithHemisphere(-13.7563, 'lat'), '13.7563°S');
  assert.equal(degreesWithHemisphere(100.5018, 'lon'), '100.5018°E');
  assert.equal(degreesWithHemisphere(-100.5018, 'lon'), '100.5018°W');
  // No "-" survives anywhere in the output, which is the property that failed.
  for (const axis of ['lat', 'lon']) {
    for (const v of [-0.0001, -1, -89, -0.5]) {
      assert.doesNotMatch(degreesWithHemisphere(v, axis), /-/, `${v} ${axis}`);
    }
  }
});

test('zero is on the positive side of each axis, and says so', () => {
  // The equator is 0°N by convention and the prime meridian 0°E; the point is
  // that neither renders as an absence or as "-0".
  assert.equal(degreesWithHemisphere(0, 'lat'), '0.0000°N');
  assert.equal(degreesWithHemisphere(0, 'lon'), '0.0000°E');
});

test('a value that is not a reading gets no degrees at all', () => {
  /*
    Null rather than a string, so the caller decides what absence looks like. The
    alternative is "NaN°N" in a coordinate readout, which is the house rule this
    whole module exists for.
  */
  for (const bad of [null, undefined, '', 'abc', NaN, Infinity, {}, []]) {
    assert.equal(degreesWithHemisphere(bad, 'lat'), null, String(bad));
  }
  // And out of range is not a coordinate either, per axis.
  assert.equal(degreesWithHemisphere(91, 'lat'), null);
  assert.equal(degreesWithHemisphere(91, 'lon'), '91.0000°E');
  assert.equal(degreesWithHemisphere(181, 'lon'), null);
});

test('a fix is formatted by the same rule that decides it is a fix', () => {
  assert.equal(formatFix(13.7563, 100.5018), '13.7563°N 100.5018°E');
  assert.equal(formatFix(-33.8688, 151.2093), '33.8688°S 151.2093°E');
  assert.equal(formatFix(40.7128, -74.006), '40.7128°N 74.0060°W');
});

test('what counts as a fix is not decided twice', () => {
  /*
    `formatFix` defers to `coordinatePair`, so the readout and the map agree about
    which pairs are positions: exactly 0, 0 is the absent value a NULL column used
    to decay into, and a single zero component is a real place.
  */
  assert.equal(formatFix(0, 0), null);
  assert.equal(formatFix(0, 100.5018), '0.0000°N 100.5018°E');
  assert.equal(formatFix(13.7563, 0), '13.7563°N 0.0000°E');
  assert.equal(formatFix(null, 100.5018), null);
  assert.equal(formatFix(13.7563, undefined), null);
  assert.equal(formatFix(95, 100), null);
});
