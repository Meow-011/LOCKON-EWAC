/**
 * LOCKON EWAC — reading numbers out of records that may not hold one.
 *
 * This exists because of a bug that put a fabricated measurement into a report.
 *
 * The report read every optional numeric column through a helper that did
 * `Number(value)` and kept the result if it was finite. JavaScript makes
 * `Number(null)` equal to `0`, and `0` is finite — so a column that had never
 * been written came back as a hard zero rather than as "not recorded". The
 * consequences were not cosmetic:
 *
 *   * `location_mirror_lat` / `location_mirror_lon` are NULL for an access
 *     point with no mirrored candidate. They became `0, 0` — a real coordinate
 *     in the Gulf of Guinea — so the archive map drew a dashed line from
 *     Thailand to the Atlantic for 189 of 196 access points, labelled as the
 *     second equally good position.
 *   * `location_error_m` NULL became `0`, which reads as "+/- 0 m": a perfect
 *     fix, printed in the one table a reader treats as evidence.
 *   * An access point with no position at all counted as positioned at 0, 0.
 *
 * `Number('')` and `Number(false)` are `0` too, and `Number([])` is `0`, so an
 * empty string from a CSV import had the same effect.
 *
 * The rule here is narrow on purpose: a value is a number only if it already is
 * one, or if it is a string that entirely represents one. Everything else is
 * absent, and absent is never zero.
 */

/**
 * The value as a number, or null when it does not hold one.
 *
 * Null, undefined, empty and whitespace-only strings, booleans, arrays and
 * objects are all "not recorded". NaN and the infinities are rejected too: they
 * are not measurements either.
 */
export function finiteNumber(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;

  if (typeof value === 'string') {
    const trimmed = value.trim();
    // Number('') and Number('  ') are both 0, which is the whole problem.
    if (trimmed === '') return null;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : null;
  }

  // Deliberately not falling through to Number(): booleans, arrays, dates and
  // objects all have numeric coercions, and none of them is a reading.
  return null;
}

/**
 * A latitude/longitude pair, or null unless both are present and in range.
 *
 * Range-checked because a corrupted row that survives `finiteNumber` still has
 * to be kept off the map, and because 0, 0 — the value the old helper invented
 * — is a legal coordinate that no survey in this tool will ever legitimately
 * produce.
 */
export function coordinatePair(
  lat: unknown, lon: unknown
): { lat: number; lon: number } | null {
  const latitude = finiteNumber(lat);
  const longitude = finiteNumber(lon);
  if (latitude === null || longitude === null) return null;
  if (latitude < -90 || latitude > 90) return null;
  if (longitude < -180 || longitude > 180) return null;
  // Exactly 0, 0 is the Atlantic off West Africa. It is a legal coordinate and
  // no survey this tool runs will produce it, but it is precisely what an
  // absent column used to decay into — so it is treated as absence. A single
  // zero component is left alone: the equator and the prime meridian are real.
  if (latitude === 0 && longitude === 0) return null;
  return { lat: latitude, lon: longitude };
}

/**
 * A signed degree as a magnitude and a hemisphere.
 *
 * Because the top bar printed `${latitude.toFixed(4)}°N ${longitude.toFixed(4)}°E`
 * with the letters hardcoded, so a fix south of the equator or west of Greenwich
 * read as "-13.7563°N" -- a minus sign and a hemisphere letter contradicting
 * each other, in the readout an operator checks most often. The offline-basemap
 * card was fixed for exactly this ("hemispheres rather than minus signs, since a
 * careless formatter prints -0.13°E"); the live readout was not.
 *
 * Returns null rather than a string for a value that is not a reading, so the
 * caller decides what absence looks like instead of being handed "NaN°N".
 */
export function degreesWithHemisphere(
  value: unknown,
  axis: 'lat' | 'lon',
  decimals = 4
): string | null {
  const n = finiteNumber(value);
  if (n === null) return null;
  const limit = axis === 'lat' ? 90 : 180;
  if (n < -limit || n > limit) return null;
  const letter = axis === 'lat' ? (n < 0 ? 'S' : 'N') : (n < 0 ? 'W' : 'E');
  return `${Math.abs(n).toFixed(decimals)}°${letter}`;
}

/**
 * A fix as two hemisphere-qualified degrees, or null if it is not a position.
 *
 * `coordinatePair` decides what counts as one, so the readout and the map agree
 * about that: exactly 0, 0 is the absent value and a single zero component is the
 * equator or the prime meridian.
 */
export function formatFix(lat: unknown, lon: unknown, decimals = 4): string | null {
  const fix = coordinatePair(lat, lon);
  if (!fix) return null;
  const a = degreesWithHemisphere(fix.lat, 'lat', decimals);
  const b = degreesWithHemisphere(fix.lon, 'lon', decimals);
  return a && b ? `${a} ${b}` : null;
}
