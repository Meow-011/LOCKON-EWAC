/**
 * A position, what it is worth, and how to draw it.
 *
 * Why this is its own module.
 *
 * These are the words and the geometry that go with a coordinate: which estimator
 * produced it, the radius it is entitled to, whether a second position fits the
 * measurements equally well, and the ring that says so on a map. They lived in
 * `report/archive.ts`, which is the right home for wording an archive into a
 * document and the wrong one for everything else that needs them -- and by the
 * end that was the live map, the target drawer and the uncertainty overlay.
 *
 * The cost was not only tidiness. `archive.ts` reaches `engineIPC` and `scopeDB`,
 * so asking it how to format a radius pulled the sidecar bridge and the SQL
 * plugin into the dashboard, and a test of the overlay needed both stubbed.
 *
 * Nothing here touches Tauri, MapLibre, jsPDF or the DOM, and that is the
 * property worth keeping: it is what lets the screen and the document describe
 * one position the same way. `archive.ts` re-exports every name below, so the
 * move changed no call site and the compiler verified it.
 */
import { coordinatePair, finiteNumber } from './numbers';

/**
 * How a coordinate in this document was arrived at. A latitude and longitude
 * with no method attached invites a reader to treat an RSSI-weighted guess as a
 * surveyed position. The estimators themselves are documented in
 * docs/AP_LOCATION_METHODS.md.
 */
/*
  Two of these described an implementation the code does not have, and the
  documentation had already said so.

  `docs/AP_LOCATION_METHODS.md` §3 carries an explicit retraction: the section
  "previously described two things the code does not do — an FSPL formula, which
  appears nowhere in the codebase, and taking the 3 strongest observations and
  intersecting circles". The doc was corrected; this table, which is what the
  exported PDF, CSV and KML actually print, still said both. So the retraction
  reached the reader who went looking for it and not the reader holding the
  document.

  It is the worst direction for the error to run. "The three strongest
  observations intersected" is not a vague description of a least-squares fit over
  every sighting — it is a description of the specific mistake §2 of that document
  exists to warn about, because the distant weak readings are what carry the
  distance information. A reader judging how much weight to put on a position was
  being told the tool did the naive thing.

  The labels were also two names for one method: an operator selects
  MULTILATERATION or TRACK POSITION in Settings and the report named them "FSPL
  trilateration" and "RSSI-weighted centroid". The keys stay as they are — they
  are in the database — but what is printed now matches both the UI and the code.
*/
export const LOCATION_METHOD_LABEL: Record<string, string> = {
  gpr: 'Gaussian-process regression',
  bayesian_grid: 'Bayesian probability grid',
  trilateration: 'Multilateration (least squares)',
  weighted_centroid: 'Track position (inverse-distance weighted)',
  peak_rssi: 'Strongest-observation fix',
};

export const LOCATION_METHOD_NOTE: Record<string, string> = {
  gpr: 'Signal strength is modelled as a continuous field over the surveyed track and the position taken at the modelled maximum; the best estimate available here, but still inferred only from where the operator actually travelled.',
  bayesian_grid: 'The area is divided into a fine grid and each cell scored for the probability that it holds the transmitter; more resistant to a single reflected observation than an average.',
  trilateration: 'The received power of each sighting is converted to a range with the frequency-corrected log-distance model (exponent 2.5), and the position is solved for by damped least squares over every sighting, not by intersecting the strongest few. The stated radius comes from the covariance of that solution, so collinear sightings widen it along the axis they fail to constrain. The least stable method in built-up areas, because a wall reads as distance.',
  weighted_centroid: 'An average of every point the access point was seen from, weighted by inverse modelled range. It cannot report a position off the route that was driven: an average of the sighting positions always lies between them, so with the transmitter 40 m from a single road the measured off-track displacement was 0.0 m in every trial. Read it as a fast summary of where the signal was strongest, not as a located transmitter.',
  peak_rssi: 'The coordinate of the single strongest observation; this always places the access point on the survey route and never inside a building.',
};

export function locationMethodLabel(method?: string | null): string {
  if (!method) return 'not recorded';
  return LOCATION_METHOD_LABEL[method] || String(method);
}

export function locationMethodNote(method?: string | null): string {
  if (!method) return 'The estimator that produced this position was not recorded, so its accuracy characteristics cannot be stated.';
  return LOCATION_METHOD_NOTE[method]
    || 'This estimator is not described in this build, so its accuracy characteristics cannot be stated here.';
}

/** Short position string for a table cell. */
export function formatCoord(lat?: number | null, lon?: number | null): string {
  if (typeof lat !== 'number' || typeof lon !== 'number' || !Number.isFinite(lat) || !Number.isFinite(lon)) {
    return 'no fix';
  }
  return `${lat.toFixed(5)}, ${lon.toFixed(5)}`;
}

/**
 * Localization confidence, as a percentage.
 *
 * The previous implementation carried the comment "estimators in this codebase
 * emit 0..1; anything larger is already a percentage" and multiplied anything
 * `<= 1` by 100. That was wrong about its own codebase, and wrong in the worst
 * possible direction.
 *
 * Both producers clamp to a whole number in 1..99 and never emit a fraction:
 * `radiusToConfidence` in `src/lib/localization.ts` ends in
 * `Math.max(1, Math.min(99, Math.round(c)))`, and `gpr_engine.py` does the same.
 * A confidence of exactly `1` is therefore not "100% of a 0..1 scale" — it is
 * the *lowest* value the scale can produce, reached by any error radius beyond
 * roughly 295 m. The old branch printed that single worst case as "100%".
 *
 * So the domain here is 1..99 and the value is already a percentage. Nothing is
 * rescaled. Out-of-domain values are reported as unavailable rather than
 * silently coerced, because a confidence figure that was never computed must not
 * be presented as one that was.
 */
export function formatLocationConfidence(value?: number | null): string {
  if (typeof value !== 'number' || !Number.isFinite(value)) return 'n/r';
  const pct = Math.round(value);
  if (pct < 1 || pct > 100) return 'n/r';
  return `${pct}%`;
}

/**
 * The 95% radius, printed next to the coordinate it belongs to.
 *
 * It is never shortened, clipped or "tidied". A mirror-ambiguous estimate carries
 * a radius wide enough to cover both candidate positions, which is exactly what
 * the reader has to see — a narrower number would be a claim the data does not
 * support.
 */
export function formatErrorRadius(metres?: number | null): string {
  if (typeof metres !== 'number' || !Number.isFinite(metres) || metres < 0) return 'no stated radius';
  return `+/- ${metres >= 10 ? Math.round(metres) : metres.toFixed(1)} m`;
}

/** Metres, plain, for a separation figure. */
export function formatMetres(metres?: number | null): string {
  if (typeof metres !== 'number' || !Number.isFinite(metres) || metres < 0) return 'n/r';
  return `${metres >= 10 ? Math.round(metres) : metres.toFixed(1)} m`;
}


/**
 * The second, equally good position on the other side of the line of travel.
 *
 * With collinear sightings the likelihood is symmetric about the driving line, so
 * an AP 40 m north and an AP 40 m south fit the measurements equally well. The
 * estimator records the mirrored solution whenever the route geometry cannot rule
 * it out; a report that draws only one of the two is asserting a coin flip.
 */
export function apMirror(ap: any): { lat: number; lon: number; distanceM: number | null } | null {
  // Range-checked as a pair. The old helper turned a NULL column into 0, so an
  // access point with no mirrored candidate was drawn at 0, 0 and the map ran a
  // dashed line to the Gulf of Guinea labelled "equally good position".
  const point = coordinatePair(ap?.location_mirror_lat, ap?.location_mirror_lon);
  if (!point) return null;
  return { ...point, distanceM: finiteNumber(ap?.location_mirror_distance_m) };
}

/**
 * True when which side of the road the access point sits on is undetermined.
 *
 * Either flag alone is enough: `geometry_ambiguous` is the estimator's verdict on
 * the route, and a stored mirror candidate means it produced one. Treating a row
 * with a mirror candidate as a confident fix because the flag column happened to
 * be null is precisely the failure this exists to prevent.
 */
export function isMirrorAmbiguous(ap: any): boolean {
  if (finiteNumber(ap?.geometry_ambiguous) === 1) return true;
  return apMirror(ap) !== null;
}

/**
 * Whether no estimator could run for this access point at all.
 *
 * Distinct from mirror ambiguity, and weaker. Ambiguous means two positions fit
 * and the survey cannot choose between them --- both are real candidates.
 * Unresolved means the receiver never moved far enough for any position to be
 * derived, so the coordinate marks where the operator stood and the only claim
 * being made is the radius.
 *
 * Absent on archives written before the flag existed, which is why this tests
 * for `false` rather than falsiness: an older archive should keep reading as a
 * resolved position, because at the time it was written the estimator did run.
 */
export function isUnresolved(ap: any): boolean {
  return ap?.location_resolved === false;
}

/**
 * The caveats the estimator attached to this position.
 *
 * Stored as a JSON array of ready-to-print strings, but it arrives from a
 * database column and from imported archives, so it may be null, already an
 * array, or malformed. A caveat is the last thing that should be lost to a parse
 * error: unparseable text is shown as-is rather than dropped.
 */
export function locationNotesOf(ap: any): string[] {
  const raw = ap?.location_notes;
  const clean = (arr: unknown[]) =>
    arr.filter(n => typeof n === 'string' && n.trim()).map(n => String(n).trim());
  if (Array.isArray(raw)) return clean(raw);
  if (typeof raw !== 'string' || !raw.trim()) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) return clean(parsed);
    if (typeof parsed === 'string' && parsed.trim()) return [parsed.trim()];
    return [];
  } catch {
    return [raw.trim().slice(0, 500)];
  }
}

/** Every caveat that belongs with this position, including the mirror warning. */
export function positionCaveats(ap: any): string[] {
  const notes = locationNotesOf(ap);
  if (!isMirrorAmbiguous(ap)) return notes;
  const mirror = apMirror(ap);
  const separation = mirror?.distanceM;
  const warning =
    'MIRROR-AMBIGUOUS: the route past this access point was effectively a straight line, so the measurements fit a position on either side of it equally well. '
    + (mirror
      ? `The alternative position is ${formatCoord(mirror.lat, mirror.lon)}`
        + (separation !== null && separation !== undefined ? `, about ${formatMetres(separation)} away. ` : '. ')
      : 'The alternative position was not recorded. ')
    + 'Which side is correct cannot be determined from this data. Re-driving the area with at least one turn in the route resolves it.';
  // Do not duplicate a warning the estimator already wrote in its own words.
  return notes.some(n => /mirror/i.test(n)) ? notes : [warning, ...notes];
}

export const AMBIGUOUS_FLAG = 'AMBIGUOUS';

/**
 * A closed ring of `steps` points at `radiusM` around a coordinate, for drawing
 * an error radius on the map.
 *
 * Metres are converted per axis: a degree of longitude is shorter than a degree
 * of latitude by cos(lat), so a circle drawn with one scale for both would be an
 * ellipse of the wrong size.
 */
export function circlePolygon(lon: number, lat: number, radiusM: number, steps = 64): number[][] {
  const degLat = radiusM / 111320;
  const degLon = radiusM / Math.max(1e-6, 111320 * Math.cos((lat * Math.PI) / 180));
  const ring: number[][] = [];
  for (let i = 0; i <= steps; i++) {
    const theta = (i / steps) * 2 * Math.PI;
    ring.push([lon + degLon * Math.cos(theta), lat + degLat * Math.sin(theta)]);
  }
  return ring;
}

/**
 * Largest radius still worth drawing on an overview figure, in metres.
 *
 * Set by looking at the output twice. Drawing every ring produced a solid disc.
 * At 250 m the map came back but the surviving rings still crossed each other in
 * sweeping arcs that read as a moire pattern — a reader could easily take it for
 * a feature of the data. At 120 m a ring is small enough to sit around its own
 * dot, which is the only thing it is for: a reminder that the dot is an
 * inference with a width, not a pin.
 *
 * Positions with a wider radius are still plotted, and every radius appears in
 * the position-quality table. The count left undrawn is stated in the caption.
 */
export const RING_LIMIT_M = 120;
