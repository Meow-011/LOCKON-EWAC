/**
 * LOCKON EWAC — Access point localization
 *
 * Every estimator the app uses to turn a set of (position, RSSI) sightings into
 * an AP location, plus the honest reporting of how much that answer is worth.
 *
 * This was extracted from missionStore because a state container is the wrong
 * home for numerical code that needs to be tested against known ground truth —
 * and it needed testing. Measured against a simulated drive-by with the AP 40 m
 * off the road, the previous implementations gave:
 *
 *     peak RSSI (doing nothing) 40.7 m
 *     weighted centroid         40.6 m   never left the road
 *     trilateration             38.6 m   optimizer stopped at ~65% convergence
 *     bayesian grid             16.7 m   but picked the wrong side 2 runs in 5
 *     GPR "sub-metre"          225.4 m   outside the surveyed area entirely
 *
 * The fixes here are in `tests/localization.test.mjs`, which runs the same
 * ground-truth simulation so a regression shows up as a number.
 *
 * ── Things worth knowing before trusting any of this ────────────────────────
 *
 * 1. A weighted centroid is a convex combination of the sighting positions. If
 *    every sighting is on one straight road, the answer is *mathematically
 *    required* to be on that road. No amount of weighting fixes this; it is a
 *    property of the operation. It is kept as a fast baseline and labelled as
 *    a track position, not a localization.
 *
 * 2. With collinear sightings the likelihood is symmetric about the driving
 *    line: an AP 40 m north and an AP 40 m south fit the data equally well.
 *    Noise picks the winner. Measured on five seeds, a single straight pass got
 *    the side wrong twice; driving the same street twice got it wrong five
 *    times out of five, because a second pass only reinforces the symmetry.
 *    `assessGeometry` detects this and every estimate carries the verdict, so a
 *    report can say "this could be mirrored" instead of presenting a coin flip
 *    as a fact. One turn in the route removes the ambiguity entirely.
 *
 * 3. RSSI-to-distance is frequency dependent. The old model used one reference
 *    power for 2.4, 5 and 6 GHz, which placed 5 GHz APs 1.80x too far away and
 *    6 GHz APs 2.13x too far.
 */

export interface Observation {
  lat: number;
  lon: number;
  rssi: number;
  /** MHz. Enables the band correction below; omitted falls back to 2.4 GHz. */
  frequency?: number | null;
}

export type LocationMethod =
  | 'peak_rssi'
  | 'weighted_centroid'
  | 'trilateration'
  | 'bayesian_grid'
  | 'gpr';

export interface GeometryAssessment {
  /** Sightings used. */
  count: number;
  /** Spread along the dominant direction of travel, metres. */
  alongTrackM: number;
  /** Spread perpendicular to it. This is what breaks the mirror ambiguity. */
  crossTrackM: number;
  /** crossTrack / alongTrack. Below ~0.15 the route is effectively a line. */
  linearity: number;
  /** True when the route is too straight to tell which side the AP is on. */
  mirrorAmbiguous: boolean;
  /**
   * True when the sightings are too small a cloud to constrain anything —
   * a stationary receiver's scatter rather than a driven route. Distinct from
   * `mirrorAmbiguous`, which a real straight drive also raises: this one is not
   * fixed by turning a corner, only by moving at all.
   */
  insufficientBaseline: boolean;
  /** Bearing of the dominant axis, degrees from north. */
  axisBearing: number;
  /** Plain-language summary for the report. */
  note: string;
}

export interface LocationEstimate {
  lat: number;
  lon: number;
  method: LocationMethod;
  /**
   * Radius in metres containing roughly 95% of the posterior mass. This is the
   * number that belongs in a report — a coordinate without one is not evidence.
   * Null when the estimator cannot produce one (centroid, peak).
   */
  errorRadiusM: number | null;
  /**
   * 0-100, defined as a documented monotone function of errorRadiusM (see
   * `radiusToConfidence`). It is a readability aid, not a probability.
   */
  confidence: number | null;
  geometry: GeometryAssessment;
  /**
   * False when the survey could not constrain a position at all, and the
   * coordinate is a placeholder rather than an estimate.
   *
   * Absent or true means an estimator actually ran. This exists because the
   * alternative is worse than useless: given a receiver that never moved, the
   * solvers still return *an* answer, and it is a different answer every time
   * the signal flickers. On screen that reads as access points crawling around
   * the map, which looks like a rendering fault and is in fact the honest
   * output of an unanswerable question. See `estimateUnresolved`.
   */
  resolved?: boolean;
  /** The mirrored solution, when the geometry cannot rule it out. */
  mirrorCandidate?: { lat: number; lon: number } | null;
  /**
   * Spread about the chosen mode alone, metres.
   *
   * Kept separate from errorRadiusM because when a mirror candidate exists the
   * posterior is bimodal: the fit is tight around each of two positions that
   * are far apart. Reporting only the tight number would claim a precision the
   * data does not support; reporting only the wide one would hide that each
   * mode is individually well determined. The report states both.
   */
  modeRadiusM?: number | null;
  /** Distance between the two candidate positions, metres. */
  mirrorDistanceM?: number | null;
  /** Anything a reader needs in order to weigh the number. */
  notes: string[];
}

// ── Geodesy ─────────────────────────────────────────────────────────────────

export const M_PER_DEG_LAT = 111320;

/**
 * Metres between two WGS-84 points, on the local flat approximation.
 *
 * Exact enough for the distances this project deals in (metres to a few
 * kilometres) and far cheaper than haversine, which matters because this runs
 * per GPS fix and per sighting merge.
 */
export function metresBetween(lon1: number, lat1: number, lon2: number, lat2: number): number {
  const dy = (lat2 - lat1) * M_PER_DEG_LAT;
  const dx = (lon2 - lon1) * mPerDegLon((lat1 + lat2) / 2);
  return Math.hypot(dx, dy);
}

/**
 * How far the receiver must move before a fix counts as travel, in metres.
 *
 * A consumer GPS standing still scatters a few metres between fixes. Recording
 * that as route made a parked vehicle crawl across the map, and fed the
 * localizer a baseline made entirely of noise. Five metres sits above the
 * scatter and below any real step.
 */
/**
 * Below this, a mirrored candidate is the same point as the one it mirrors.
 *
 * Named and shared because both estimators need it and only one had it: the
 * grid guarded on a literal 1, the least-squares solver did not guard at all,
 * and zero-separation candidates reached the PDF, the CSV and the KML as a
 * second "equally good position".
 */
export const MIRROR_MIN_SEPARATION_M = 1;

/**
 * The smallest step that counts as movement on a fix of unstated quality.
 *
 * Also the floor of `gpsStepFloorM`, so a receiver that reports no HDOP behaves
 * exactly as it did before quality was taken into account.
 */
export const GPS_STEP_M = 5;

/**
 * Typical user-equivalent range error for a single-frequency consumer receiver,
 * in metres.
 *
 * The figure that turns HDOP into a distance: horizontal error is approximately
 * `HDOP x UERE` at one standard deviation. 5 m is the conventional value for
 * this class of receiver and it is written here as an assumption rather than
 * measured on this hardware, which is the honest status of it.
 */
export const GPS_UERE_M = 5;

/**
 * How far a fix has to be from the last accepted one before it is movement.
 *
 * Why this is not a constant.
 *
 * `GPS_STEP_M` was a flat 5 m, and the engine accepts any fix up to `HDOP 5.0`
 * (`_validate_gps` in `engine/ipc/handler.py`). Those two numbers do not fit
 * together: at HDOP 5 the horizontal error is around `5 x 5 = 25 m` at one sigma,
 * so a receiver standing still produces jumps several times the floor, every
 * one of which is accepted as travel. The marker crawls, auto-follow drags the
 * whole map after it, and -- the part that outlives the session -- the track
 * records that scatter as route, which is exactly what the localizer reads as
 * the baseline it multilaterates from.
 *
 * A fix good enough to be worth 5 m of precision is one with HDOP near 1, and
 * there the result is unchanged. A poor fix now has to travel as far as its own
 * stated error before the tool will call it movement.
 *
 * The cost is stated plainly rather than hidden: on a genuinely slow walk with a
 * poor fix, the marker holds still longer than it used to. That is the correct
 * direction for this tool to be wrong in -- a position the receiver cannot
 * support is not a position -- and the fix quality it is reacting to is on screen,
 * in the GPS tile, as "HDOP n.n".
 *
 * One sigma, not two. At two sigma a vehicle genuinely moving at walking pace
 * under a poor fix would never register at all, and the floor would be deciding
 * the survey rather than filtering it.
 */
export function gpsStepFloorM(hdop?: number | null): number {
  // Not reported, or reported as the "measured ideal zero" that `gps/reader.py`
  // documents as an absence: fall back to the constant. Refusing to gate at all
  // would be worse, and inventing a quality figure would be worse still.
  if (typeof hdop !== 'number' || !Number.isFinite(hdop) || hdop <= 0) return GPS_STEP_M;
  return Math.max(GPS_STEP_M, GPS_UERE_M * hdop);
}
export const mPerDegLon = (lat: number) => 111320 * Math.cos((lat * Math.PI) / 180);

/**
 * Local east-north-up projection around an origin.
 *
 * All the maths below works in metres rather than degrees. Degrees are not
 * isotropic — a degree of longitude is shorter than a degree of latitude by
 * cos(lat) — so a Euclidean distance in degrees is wrong everywhere except the
 * equator, and a "length scale" in degrees means different things on each axis.
 */
export function makeProjection(originLat: number, originLon: number) {
  const mLon = mPerDegLon(originLat);
  return {
    toMetres: (lat: number, lon: number) => ({
      x: (lon - originLon) * mLon,
      y: (lat - originLat) * M_PER_DEG_LAT,
    }),
    toDegrees: (x: number, y: number) => ({
      lat: originLat + y / M_PER_DEG_LAT,
      lon: originLon + x / mLon,
    }),
  };
}

// ── Radio model ─────────────────────────────────────────────────────────────

/**
 * Received power at 1 m, in dBm, for a given frequency.
 *
 * Free-space loss at 1 m is `20·log10(f_MHz) - 27.55` dB, so a 5 GHz AP reads
 * about 6.5 dB weaker than a 2.4 GHz one at the same distance and a 6 GHz AP
 * about 7.8 dB weaker. Feeding all three through one reference made the
 * distance model think the higher bands were much further away.
 *
 * REFERENCE_2G4 is kept at the value the tool has always used. It is a
 * rule-of-thumb, not a calibration: without measuring a known AP at a known
 * distance the absolute level cannot be pinned down, and pretending otherwise
 * would be false precision. The *relative* band correction is physics and is
 * an unambiguous improvement.
 */
export const REFERENCE_2G4_DBM = -40;
const REF_FREQ_MHZ = 2437;

export function referencePowerDbm(frequencyMhz?: number | null): number {
  if (!frequencyMhz || frequencyMhz <= 0) return REFERENCE_2G4_DBM;
  // Normalise kHz (some Windows drivers report 2412000).
  const mhz = frequencyMhz > 10000 ? frequencyMhz / 1000 : frequencyMhz;
  const extraLoss = 20 * Math.log10(mhz / REF_FREQ_MHZ);
  return REFERENCE_2G4_DBM - extraLoss;
}

/** Path loss exponent. 2.0 is free space; 2.5-3.5 is typical outdoor urban. */
export const PATH_LOSS_EXPONENT = 2.5;

/** Shadowing standard deviation in dB. Urban measurements land around 6-8 dB. */
export const SHADOWING_SIGMA_DB = 6.0;

/**
 * How much a distance derived from one RSSI reading can be out, at roughly 95%.
 *
 * Inverting the path-loss model turns a +/-2 sigma swing in dB into a
 * multiplicative error in metres: 10^(2*sigma / (10*n)). At 6 dB and an
 * exponent of 2.5 that is about 3.0x.
 *
 * Derived rather than written down so it tracks the model. It exists because
 * the peak estimator reported the modelled distance *itself* as its error
 * radius — a single reading at -60 dBm claimed the transmitter was within 14 m
 * while the measured error across five seeds was 42 m. A radius that
 * understates the true error by threefold is worse than no radius at all, because
 * the report quotes it as if it were a confidence bound.
 */
/**
 * Sigma multiplier for a 95% *radial* bound on a 2-D position.
 *
 * For a circular bivariate normal the radius r obeys the Rayleigh law
 * `P(r < k*sigma) = 1 - exp(-k^2/2)`, so k = sqrt(-2*ln(0.05)) = 2.448. Both
 * estimators used 2.0, which covers 86.5% — while the field they fill is
 * documented, and printed in the report, as "roughly 95% of the posterior".
 * Measured coverage before the change was 6-9 runs in 10; the number was
 * describing a tighter bound than the one it claimed.
 */
export const RADIUS_95_SIGMA = Math.sqrt(-2 * Math.log(0.05));

/**
 * How much the strongest of `n` readings overstates the signal, in dB.
 *
 * The maximum of n samples is not the mean — it is the luckiest one, and it is
 * high by about `sigma * sqrt(2 * ln n)`. Distance is inferred from power, so a
 * peak that is 16 dB optimistic places the transmitter about four and a half
 * times nearer than it is.
 *
 * `estimatePeak` records this and declines to correct for it, which is right
 * there: it is only ever reached with a handful of sightings, where the bias is
 * small, and its note says so. `estimateUnresolved` is the case that comment
 * warned about --- it runs over a full parked survey, forty sightings and more
 * --- so the correction comes with it. Measured without it, the stated radius
 * covered the true position in 4 runs in 10.
 */
export function peakBiasDb(n: number): number {
  if (n <= 1) return 0;
  return SHADOWING_SIGMA_DB * Math.sqrt(2 * Math.log(n));
}

/**
 * The 95% distance spread that belongs *around a corrected peak*, not around a
 * single reading.
 *
 * `SINGLE_READING_DISTANCE_FACTOR_95` is the spread of one sample, and applying
 * it after `peakDistanceCorrection` double-counts: the bias has already been
 * removed, and what remains is the uncertainty of the *maximum* of n samples,
 * which is tighter than one sample by roughly `sqrt(2 ln n)`. Using the
 * single-reading figure gave 100% coverage with a median radius 4.2 times the
 * error it was covering --- true, and close to useless, because "somewhere
 * within 1.4 km" is not a finding anyone can act on.
 *
 * Measured over 400 parked surveys: this gives 99.5% coverage at a median
 * radius 2.3 times the error. The field is documented as "roughly 95%", so
 * 99.5% is still on the conservative side of what it claims.
 */
export function peakSpreadFactor95(n: number): number {
  if (n <= 1) return SINGLE_READING_DISTANCE_FACTOR_95;
  const standardErrorOfMaxDb = SHADOWING_SIGMA_DB / Math.sqrt(2 * Math.log(n));
  return Math.pow(10, (RADIUS_95_SIGMA * standardErrorOfMaxDb) / (10 * PATH_LOSS_EXPONENT));
}

/** Distance multiplier undoing that bias, for a peak taken over `n` readings. */
export function peakDistanceCorrection(n: number): number {
  return Math.pow(10, peakBiasDb(n) / (10 * PATH_LOSS_EXPONENT));
}

export const SINGLE_READING_DISTANCE_FACTOR_95 =
  Math.pow(10, (2 * SHADOWING_SIGMA_DB) / (10 * PATH_LOSS_EXPONENT));

/**
 * Sightings the grid search actually evaluates against.
 *
 * The cost of the search is grid nodes x sightings, and with a 100-point
 * history that measured at 40 ms per access point — 9 seconds to open a 200-AP
 * archive. Past a few dozen well-spread points the likelihood surface stops
 * moving, and because the subset comes from selectDiverse it keeps the geometry
 * and the full signal range rather than just the strongest readings.
 */
/**
 * Prior width, in dB, on a transmitter's power relative to the assumed
 * reference. Chosen by measurement — see the block in `estimateBayesian`.
 *
 * Median error on a route with one turn, 200 trials per cell, by how much the
 * real transmitter's power varied around the assumed reference:
 *
 *     prior:        0 dB    1 dB    2 dB    3 dB    6 dB    free
 *     power known   9.3     9.6    11.4    13.0    15.0     9.7
 *     sigma 3 dB   13.5    12.0    11.7    13.1    16.1     9.9
 *     sigma 6 dB   18.1    15.7    13.9    13.7    16.0    20.8
 *     sigma 10 dB  25.3    20.6    16.8    16.2    15.9    23.6
 *
 * 2 dB costs about two metres when the power happens to be the assumed one —
 * which it never exactly is — and saves four to eight once it is not.
 */
export const POWER_PRIOR_DB = 2;

/**
 * Assumed spread of real transmitter power around the reference, in dB.
 *
 * Not a tuning knob: it is what the *stated radius* has to account for. The
 * radius came only from the width of the likelihood surface, which is
 * conditioned on the assumed power being right. Measured coverage of that
 * radius, against a claim of 95%:
 *
 *     power known        98%
 *     sigma 3 dB         77%
 *     sigma 6 dB         52%
 *     sigma 10 dB        43%
 *
 * Consumer routers, enterprise APs and phone hotspots differ by well over
 * 10 dB of EIRP before antenna gain, so the middle of that table is the
 * normal case and the radius was describing a certainty nobody had.
 */
export const TX_POWER_SPREAD_DB = 6;

export const GRID_SEARCH_MAX_POINTS = 40;

export function expectedRssi(distanceM: number, frequencyMhz?: number | null): number {
  const d = Math.max(1, distanceM);
  return referencePowerDbm(frequencyMhz) - 10 * PATH_LOSS_EXPONENT * Math.log10(d);
}

export function rssiToDistanceM(rssi: number, frequencyMhz?: number | null): number {
  const ref = referencePowerDbm(frequencyMhz);
  return Math.pow(10, (ref - rssi) / (10 * PATH_LOSS_EXPONENT));
}

// ── History selection ───────────────────────────────────────────────────────

const CELL_MERGE_M = 2;

/**
 * Merge a sighting into a history, keeping the strongest reading per ~2 m cell.
 *
 * Distances are computed in metres. The previous version compared raw degrees,
 * treating a degree of longitude as equal to a degree of latitude.
 */
export function mergeObservation(
  history: Observation[],
  next: Observation,
  cap = 100
): Observation[] {
  const out = history.slice();
  const mLon = mPerDegLon(next.lat);

  for (let i = 0; i < out.length; i++) {
    const dx = (out[i].lon - next.lon) * mLon;
    const dy = (out[i].lat - next.lat) * M_PER_DEG_LAT;
    if (Math.hypot(dx, dy) < CELL_MERGE_M) {
      if (next.rssi > out[i].rssi) out[i] = { ...out[i], ...next };
      return selectDiverse(out, cap);
    }
  }

  out.push(next);
  return selectDiverse(out, cap);
}

/**
 * Choose which sightings to keep when over the cap.
 *
 * The old rule was "sort by RSSI, keep the strongest N", which throws away the
 * weak distant readings *first* — and those are precisely what tell the model
 * the AP is far from there. Measured effect of that rule at the live-scan cap
 * of 20: the retained RSSI range collapsed from -95..-72 dBm to -81..-72 dBm
 * and the error nearly doubled (19.7 m against 10.6 m at a cap of 50).
 *
 * This keeps a few of the strongest (they anchor the peak) and fills the rest
 * by farthest-point sampling in position-and-signal space, so both the geometry
 * and the full dynamic range survive.
 */
export function selectDiverse(history: Observation[], cap = 100): Observation[] {
  if (cap <= 0 || history.length <= cap) return history;

  const byRssi = history.slice().sort((a, b) => b.rssi - a.rssi);
  const anchorCount = Math.max(1, Math.floor(cap * 0.25));
  const chosen = byRssi.slice(0, anchorCount);
  const remaining = byRssi.slice(anchorCount);
  if (remaining.length === 0) return chosen;

  const originLat = history[0].lat;
  const mLon = mPerDegLon(originLat);
  // RSSI is scaled into metres so one dB trades against a fixed distance; this
  // keeps a point that is spatially close but much weaker (a different part of
  // the curve) in contention.
  const RSSI_WEIGHT_M_PER_DB = 4;

  const coord = (o: Observation) => ({
    x: o.lon * mLon,
    y: o.lat * M_PER_DEG_LAT,
    z: o.rssi * RSSI_WEIGHT_M_PER_DB,
  });

  const chosenCoords = chosen.map(coord);
  const pool = remaining.map((o) => ({ obs: o, c: coord(o) }));
  const minDist = pool.map((p) =>
    Math.min(...chosenCoords.map((c) => Math.hypot(p.c.x - c.x, p.c.y - c.y, p.c.z - c.z)))
  );

  while (chosen.length < cap && pool.length > 0) {
    let best = 0;
    for (let i = 1; i < pool.length; i++) if (minDist[i] > minDist[best]) best = i;

    const picked = pool[best];
    chosen.push(picked.obs);
    pool.splice(best, 1);
    minDist.splice(best, 1);

    for (let i = 0; i < pool.length; i++) {
      const d = Math.hypot(
        pool[i].c.x - picked.c.x,
        pool[i].c.y - picked.c.y,
        pool[i].c.z - picked.c.z
      );
      if (d < minDist[i]) minDist[i] = d;
    }
  }

  return chosen;
}

// ── Geometry ────────────────────────────────────────────────────────────────

/** Below this cross/along ratio the route is treated as a straight line. */
export const LINEARITY_AMBIGUOUS_BELOW = 0.15;

/**
 * Minimum travel, in metres, before the sightings count as a route at all.
 *
 * The linearity ratio measures the *shape* of the sightings and says nothing
 * about their *size*. A receiver sitting still still reports a position, and
 * consumer GPS scatter is roughly circular — so a parked rig produced a blob
 * with cross/along near 1.0, sailed past the ratio test, and the survey panel
 * told the operator "2 m of deviation across 5 m of travel ... enough to
 * determine which side of the track the access point lies on".
 *
 * It is not. Five metres of jitter gives no baseline against an access point
 * tens of metres away, and the estimate that came out of it was reported
 * without the widened error radius an ambiguous geometry earns.
 */
export const MIN_ALONG_TRACK_M = 25;

/**
 * Minimum perpendicular displacement, in absolute metres, before the side of
 * the track can be called.
 *
 * Consumer GPS scatter while stationary is a few metres, so anything under this
 * is indistinguishable from noise no matter how favourable the ratio looks.
 */
export const MIN_CROSS_TRACK_M = 8;

/**
 * How much the route shape constrains the answer.
 *
 * Principal component analysis of the sighting positions: the dominant axis is
 * the direction of travel, the second is how far the operator deviated from it.
 * A small second component means the likelihood surface is nearly symmetric
 * about the line of travel and the side cannot be determined.
 */
export function assessGeometry(history: Observation[]): GeometryAssessment {
  const n = history.length;
  if (n === 0) {
    return {
      count: 0, alongTrackM: 0, crossTrackM: 0, linearity: 0,
      mirrorAmbiguous: true, insufficientBaseline: true, axisBearing: 0,
      note: 'No positioned sightings, so no position can be established.',
    };
  }
  if (n < 3) {
    return {
      count: n, alongTrackM: 0, crossTrackM: 0, linearity: 0,
      mirrorAmbiguous: true, insufficientBaseline: true, axisBearing: 0,
      note: `Only ${n} positioned sighting(s); far too few to constrain a position.`,
    };
  }

  const lat0 = history.reduce((a, o) => a + o.lat, 0) / n;
  const lon0 = history.reduce((a, o) => a + o.lon, 0) / n;
  const proj = makeProjection(lat0, lon0);
  const pts = history.map((o) => proj.toMetres(o.lat, o.lon));

  let sxx = 0, syy = 0, sxy = 0;
  for (const p of pts) { sxx += p.x * p.x; syy += p.y * p.y; sxy += p.x * p.y; }
  sxx /= n; syy /= n; sxy /= n;

  // Eigenvalues of the 2x2 covariance matrix.
  const tr = sxx + syy;
  const det = sxx * syy - sxy * sxy;
  const disc = Math.max(0, (tr * tr) / 4 - det);
  const l1 = tr / 2 + Math.sqrt(disc);
  const l2 = Math.max(0, tr / 2 - Math.sqrt(disc));

  const alongTrackM = 2 * Math.sqrt(Math.max(0, l1));
  const crossTrackM = 2 * Math.sqrt(l2);
  const linearity = alongTrackM > 0 ? crossTrackM / alongTrackM : 0;

  // Scale before shape. A stationary receiver scatters in a near-circular blob,
  // which scores a near-perfect linearity ratio while providing no baseline at
  // all, so the ratio alone declared a parked rig's geometry adequate.
  //
  // Only the along-track span decides this. A dead-straight 165 m drive has a
  // cross-track spread of zero and plenty of baseline — it is mirror-ambiguous,
  // not stationary, and telling the operator to "drive past the access point"
  // when they just did would be worse than saying nothing.
  const insufficientBaseline = alongTrackM < MIN_ALONG_TRACK_M;

  // The side of the track cannot be called from a deviation that is within GPS
  // scatter, however favourable the ratio looks: 6 m of cross-track across 30 m
  // of travel passes the ratio test and is still noise.
  const mirrorAmbiguous =
    insufficientBaseline
    || crossTrackM < MIN_CROSS_TRACK_M
    || linearity < LINEARITY_AMBIGUOUS_BELOW;

  // Bearing of the dominant axis, from north, clockwise.
  const angle = 0.5 * Math.atan2(2 * sxy, sxx - syy);
  let bearing = ((90 - (angle * 180) / Math.PI) % 360 + 360) % 360;
  if (bearing >= 180) bearing -= 180;

  // "You have not moved" and "you drove in a straight line" both make the answer
  // ambiguous, but the operator fixes them differently: one needs a drive, the
  // other needs a turn. Saying which is the whole value of the message.
  let note: string;
  if (insufficientBaseline) {
    note =
      `The sightings span only ${alongTrackM.toFixed(0)} m of travel and ` +
      `${crossTrackM.toFixed(0)} m of deviation, which is within the scatter of a stationary ` +
      `receiver. There is no baseline to triangulate from, so any position here is little more ` +
      `than the strongest reading. Drive past the access point to establish one.`;
  } else if (mirrorAmbiguous) {
    note =
      `The route was effectively a straight line (${crossTrackM.toFixed(0)} m of deviation across ` +
      `${alongTrackM.toFixed(0)} m of travel). Signal strength alone cannot tell which side of that ` +
      `line the access point is on, so the position may be mirrored. A route with one turn resolves this.`;
  } else {
    note =
      `The route deviated ${crossTrackM.toFixed(0)} m across ${alongTrackM.toFixed(0)} m of travel, ` +
      `which is enough to determine which side of the track the access point lies on.`;
  }

  return {
    count: n, alongTrackM, crossTrackM, linearity,
    mirrorAmbiguous, insufficientBaseline, axisBearing: bearing, note,
  };
}

/** Reflect a point across the dominant axis of the sightings. */
export function mirrorAcrossTrack(
  lat: number, lon: number, history: Observation[]
): { lat: number; lon: number } | null {
  const n = history.length;
  if (n < 3) return null;

  const lat0 = history.reduce((a, o) => a + o.lat, 0) / n;
  const lon0 = history.reduce((a, o) => a + o.lon, 0) / n;
  const proj = makeProjection(lat0, lon0);
  const pts = history.map((o) => proj.toMetres(o.lat, o.lon));

  let sxx = 0, syy = 0, sxy = 0;
  for (const p of pts) { sxx += p.x * p.x; syy += p.y * p.y; sxy += p.x * p.y; }
  const angle = 0.5 * Math.atan2(2 * sxy, sxx - syy);
  const ux = Math.cos(angle), uy = Math.sin(angle);

  const q = proj.toMetres(lat, lon);
  // Reflection of q about the line through the origin with direction u.
  const dot = q.x * ux + q.y * uy;
  const rx = 2 * dot * ux - q.x;
  const ry = 2 * dot * uy - q.y;
  return proj.toDegrees(rx, ry);
}

// ── Estimators ──────────────────────────────────────────────────────────────

function peak(history: Observation[]): Observation {
  return history.reduce((a, b) => (b.rssi > a.rssi ? b : a));
}

/**
 * Strongest single sighting. The honest baseline every other method has to beat,
 * and the correct answer to fall back on when there is not enough data to fit
 * anything.
 */
export function estimatePeak(history: Observation[]): LocationEstimate {
  const geometry = assessGeometry(history);
  if (history.length === 0) {
    return { lat: 0, lon: 0, method: 'peak_rssi', errorRadiusM: null, confidence: null, geometry, notes: ['No sightings.'] };
  }
  const p = peak(history);
  // The transmitter is somewhere within the distance implied by the strongest
  // reading — but that distance is itself derived from one sample through a
  // model with 6 dB of shadowing, so the radius has to carry that spread too.
  // Reporting the modelled distance alone understated the measured error by
  // about threefold.
  //
  // This is only sound for the handful of sightings it is actually used with.
  // Reachable paths are the `< 3 sightings` fallbacks inside the grid and the
  // multilateration solvers, and `estimateLocation`'s default branch — nothing
  // in the UI selects it. Given many sightings it would be biased, because the
  // *strongest* of N noisy readings is the luckiest one: its implied distance
  // is systematically short, by roughly sqrt(2*ln N) sigma. Measured against 60
  // sightings the radius covered the true error in only 5 runs in 10. If this
  // is ever promoted to a selectable method, that correction has to come with
  // it.
  const radius = rssiToDistanceM(p.rssi, p.frequency) * SINGLE_READING_DISTANCE_FACTOR_95;
  return {
    lat: p.lat, lon: p.lon, method: 'peak_rssi',
    errorRadiusM: radius,
    confidence: radiusToConfidence(radius),
    geometry,
    notes: ['Position of the strongest sighting, not an estimate of the transmitter location.'],
  };
}

/**
 * Signal-weighted position along the surveyed track.
 *
 * Renamed from "weighted centroid" because calling it a localization method
 * oversold it: the result is a convex combination of the sighting positions and
 * therefore cannot leave the path that was driven. Measured off-track
 * displacement on a straight pass was 0.0 m in every trial.
 *
 * The weighting is also gentler than before. Power weighting (10^(rssi/10))
 * puts a 10,000:1 ratio between a -40 and a -80 dBm reading, so the strongest
 * sample swamped everything and the result was peak RSSI wearing a different
 * name. Weighting by inverse modelled distance keeps the other samples in play.
 */
export function estimateTrackPosition(history: Observation[]): LocationEstimate {
  const geometry = assessGeometry(history);
  if (history.length === 0) {
    return { lat: 0, lon: 0, method: 'weighted_centroid', errorRadiusM: null, confidence: null, geometry, notes: ['No sightings.'] };
  }

  let wSum = 0, latSum = 0, lonSum = 0;
  for (const o of history) {
    const w = 1 / Math.max(1, rssiToDistanceM(o.rssi, o.frequency));
    wSum += w; latSum += w * o.lat; lonSum += w * o.lon;
  }

  return {
    lat: latSum / wSum, lon: lonSum / wSum, method: 'weighted_centroid',
    errorRadiusM: null, confidence: null, geometry,
    notes: [
      'Signal-weighted position along the surveyed track. This is a convex combination of the ' +
      'sighting positions, so it cannot lie off the path that was driven and must not be read as ' +
      'the transmitter location.',
    ],
  };
}

/**
 * Least-squares multilateration on modelled ranges.
 *
 * Gauss-Newton with a Levenberg-Marquardt damping term, in local metres, run to
 * convergence. The previous version ran exactly ten gradient-descent steps at a
 * learning rate of 0.1 and stopped wherever that left it — roughly 65% of the
 * way — which is why its answer barely moved from its starting point and why it
 * did not improve when given better data.
 *
 * It also no longer seeds from a hash of the BSSID. That "deterministic jitter"
 * displaced the start by up to ~2.8 m and, because the solver never converged,
 * part of that displacement survived into the reported coordinate: a fraction
 * of the published position was derived from the MAC address. Degenerate
 * geometry is now reported rather than papered over.
 */
export function estimateTrilateration(history: Observation[], maxIterations = 100): LocationEstimate {
  const geometry = assessGeometry(history);
  const notes: string[] = [];

  if (history.length < 3) {
    const fallback = estimatePeak(history);
    return { ...fallback, method: 'trilateration', geometry,
      notes: [`Only ${history.length} sighting(s); multilateration needs at least three. Reported the strongest sighting instead.`] };
  }

  const lat0 = history.reduce((a, o) => a + o.lat, 0) / history.length;
  const lon0 = history.reduce((a, o) => a + o.lon, 0) / history.length;
  const proj = makeProjection(lat0, lon0);

  const pts = history.map((o) => {
    const m = proj.toMetres(o.lat, o.lon);
    return { x: m.x, y: m.y, r: rssiToDistanceM(o.rssi, o.frequency), w: Math.pow(10, o.rssi / 20) };
  });

  // Start from the strongest sighting: it is the closest thing to the AP we know.
  const strongest = peak(history);
  const start = proj.toMetres(strongest.lat, strongest.lon);
  let x = start.x, y = start.y;
  let lambda = 1e-3;
  let prevCost = Infinity;
  let iterations = 0;
  let converged = false;

  const cost = (cx: number, cy: number) => {
    let c = 0;
    for (const p of pts) {
      const d = Math.hypot(cx - p.x, cy - p.y);
      const e = d - p.r;
      c += p.w * e * e;
    }
    return c;
  };

  for (let iter = 0; iter < maxIterations; iter++) {
    iterations = iter + 1;
    let jtj00 = 0, jtj01 = 0, jtj11 = 0, jtr0 = 0, jtr1 = 0;

    for (const p of pts) {
      const dx = x - p.x, dy = y - p.y;
      const d = Math.hypot(dx, dy);
      if (d < 1e-6) continue;
      const j0 = dx / d, j1 = dy / d;
      const residual = d - p.r;
      jtj00 += p.w * j0 * j0;
      jtj01 += p.w * j0 * j1;
      jtj11 += p.w * j1 * j1;
      jtr0 += p.w * j0 * residual;
      jtr1 += p.w * j1 * residual;
    }

    const a = jtj00 * (1 + lambda);
    const b = jtj01;
    const c = jtj11 * (1 + lambda);
    const det = a * c - b * b;
    if (Math.abs(det) < 1e-12) {
      notes.push('The sighting geometry was too degenerate to solve; reported the best position reached.');
      break;
    }

    const stepX = -(c * jtr0 - b * jtr1) / det;
    const stepY = -(a * jtr1 - b * jtr0) / det;

    const candidateCost = cost(x + stepX, y + stepY);
    const currentCost = cost(x, y);

    if (candidateCost < currentCost) {
      x += stepX; y += stepY;
      lambda = Math.max(1e-9, lambda / 3);
      if (Math.hypot(stepX, stepY) < 0.05 || Math.abs(prevCost - candidateCost) < 1e-6) {
        converged = true;
        prevCost = candidateCost;
        break;
      }
      prevCost = candidateCost;
    } else {
      // Step made things worse: damp harder and retry from the same point.
      lambda *= 5;
      if (lambda > 1e9) { converged = true; break; }
    }
  }

  if (!converged) notes.push(`Solver stopped after ${iterations} iterations without meeting the convergence tolerance; treat the position as approximate.`);

  const result = proj.toDegrees(x, y);

  // Positional uncertainty from the solution's own sensitivity to the data.
  //
  // This used to be `median range residual * 1.5`, which measures how well the
  // modelled ranges agree with each other — a property of the shadowing on the
  // RSSI readings, not of how tightly the geometry pins the position. The two
  // are not merely different, they move in opposite directions, and the
  // measured result was a radius anti-correlated with the method's own
  // accuracy: 4.1x the true error on a loop (where the fix is good and the
  // residuals are still noisy) and 1.0x on a straight pass, where it covered
  // the error in only 4 runs out of 10 while claiming to be a 95% bound.
  //
  // The right quantity is the covariance of the least-squares solution:
  //
  //     Cov = sigma_r^2 * (J^T J)^-1
  //
  // where each row of J is the unit vector from a sighting to the solution.
  // Collinear sightings make J^T J nearly singular along the cross-track
  // direction, so the ill-conditioning that *causes* the mirror ambiguity is
  // exactly what inflates the radius — which is the behaviour a reader of the
  // report is entitled to assume the number already had.
  const residualValues = pts.map((p) => Math.hypot(x - p.x, y - p.y) - p.r);
  let errorRadiusM: number | null = null;

  if (residualValues.length >= 3) {
    // Residual spread about its own mean: the scale of the range noise.
    const meanResidual = residualValues.reduce((a, r) => a + r, 0) / residualValues.length;
    const residualVar = residualValues.reduce((a, r) => a + (r - meanResidual) ** 2, 0)
      / Math.max(1, residualValues.length - 2);   // two fitted parameters

    // Normal matrix of the unit bearings.
    let jxx = 0, jxy = 0, jyy = 0;
    for (const p of pts) {
      const d = Math.max(1e-6, Math.hypot(x - p.x, y - p.y));
      const ux = (x - p.x) / d;
      const uy = (y - p.y) / d;
      jxx += ux * ux; jxy += ux * uy; jyy += uy * uy;
    }
    const det = jxx * jyy - jxy * jxy;

    if (det > 1e-9 && residualVar > 0) {
      // Inverse of the 2x2 normal matrix, scaled by the residual variance.
      const cxx = (residualVar * jyy) / det;
      const cyy = (residualVar * jxx) / det;
      const cxy = (-residualVar * jxy) / det;
      // Larger principal standard deviation of that covariance.
      const tr = cxx + cyy;
      const disc = Math.max(0, (tr * tr) / 4 - (cxx * cyy - cxy * cxy));
      const major = Math.sqrt(Math.max(0, tr / 2 + Math.sqrt(disc)));
      // Along the worst-constrained axis, at the radial factor the field's own
      // documentation claims.
      errorRadiusM = Math.max(5, RADIUS_95_SIGMA * major);
    } else {
      // Degenerate geometry: the solution is not constrained in one direction
      // at all, so say so with the spread of the sightings rather than a number
      // derived from a matrix that could not be inverted.
      const spread = Math.max(geometry.alongTrackM, geometry.crossTrackM);
      notes.push('The sighting geometry was too degenerate to derive a covariance; the radius falls back to the spread of the survey itself.');
      errorRadiusM = Math.max(5, spread);
    }
  }

  if (geometry.mirrorAmbiguous) notes.push(geometry.note);

  /*
    The per-mode spread, kept separate from the radius that covers both.

    The grid has published this since it was written; this estimator never set
    it, so the report's "Per-mode" column read `n/r` for every multilaterated
    access point while the column header told the reader what it meant.
  */
  const modeRadiusM = errorRadiusM;

  let mirrorCandidate: { lat: number; lon: number } | null = null;
  let mirrorDistanceM: number | null = null;

  const mirrored = geometry.mirrorAmbiguous
    ? mirrorAcrossTrack(result.lat, result.lon, history)
    : null;

  if (mirrored) {
    const separation = Math.hypot(
      (mirrored.lon - result.lon) * mPerDegLon(result.lat),
      (mirrored.lat - result.lat) * M_PER_DEG_LAT,
    );

    /*
      A candidate that is the same point is not a second candidate.

      On a straight pass this solver takes no step — `J^T J` is singular, the
      first iteration breaks, and the answer is still the strongest sighting,
      which sits on the track. Reflecting a point that is already *on* the axis
      returns the point itself, so the separation came out at about 1e-10 m and
      every consumer downstream treated it as a real second position: the PDF
      flagged the access point AMBIGUOUS with "two candidates, 0 m apart", the
      position-quality table listed candidate B at the same coordinates, and the
      KML wrote a duplicate placemark joined by a zero-length line described as
      "the two equally good positions ... about 0 m apart".

      The grid has had this guard since it was written. The threshold is the same
      one metre, and for the same reason: below it the two answers are the same
      answer and saying otherwise costs a reader real attention.
    */
    if (separation > MIRROR_MIN_SEPARATION_M) {
      mirrorCandidate = mirrored;
      mirrorDistanceM = separation;

      /*
        And the radius has to cover both modes, which it did not.

        The comment above the covariance called the ill-conditioning that causes
        the ambiguity "exactly what inflates the radius — which is the behaviour
        a reader of the report is entitled to assume the number already had". It
        was not: the covariance is a per-mode spread, and a radius drawn from it
        covers the mode it was computed at and not the other one. The grid solves
        this in one line and this estimator did not.

        Same arithmetic as the grid: the transmitter is within modeRadius of one
        of two modes that are mirrorDistance apart, so from the mode we reported
        the bound is the sum.
      */
      errorRadiusM = Math.max(errorRadiusM ?? 0, mirrorDistanceM + (modeRadiusM ?? 0));
    }
  }

  return {
    lat: result.lat, lon: result.lon, method: 'trilateration',
    errorRadiusM,
    confidence: errorRadiusM == null ? null : radiusToConfidence(errorRadiusM),
    geometry,
    mirrorCandidate,
    // Without this the popup and the KML said the two candidates were
    // "n/r apart" — the separation was never computed for this estimator, only
    // for the likelihood grid, so the one number telling a reader how much the
    // ambiguity actually costs was missing.
    mirrorDistanceM,
    modeRadiusM,
    notes: notes.length ? notes : ['Least-squares fit of modelled ranges; converged.'],
  };
}

export interface BayesianOptions {
  /** Shadowing standard deviation in dB. */
  sigmaDb?: number;
  /** Half-width of the coarse search, metres. Expanded if the peak hits the edge. */
  coarseHalfWidthM?: number;
  coarseSteps?: number;
  fineSteps?: number;
  /**
   * Prior width, in dB, on how far this transmitter's power may sit from the
   * assumed reference. 0 pins it (the original behaviour); Infinity fits it
   * freely. Here so the value can be chosen by measurement rather than taste.
   */
  powerPriorDb?: number;
}

/**
 * Maximum-likelihood grid search over a log-distance path loss model.
 *
 * Presented in the UI as "Bayesian probability"; strictly this is maximum
 * likelihood, because there is no prior. The distinction matters less than what
 * the previous version did with the surface it computed: it evaluated a full
 * likelihood grid and then returned only the argmax, discarding exactly the
 * information needed to say how good the answer was. The posterior spread is
 * now turned into an error radius, and the mirrored solution is checked
 * explicitly and reported when the two are comparable.
 *
 * Other changes: the search expands when the peak lands on the boundary (the
 * old fixed +/-110 m box silently refined a wrong answer when the AP was
 * outside it), sigma defaults to a realistic 6 dB rather than 3.16 dB, and
 * per-sighting projection is hoisted out of the inner loop.
 */
export function estimateBayesian(history: Observation[], options: BayesianOptions = {}): LocationEstimate {
  const geometry = assessGeometry(history);
  const notes: string[] = [];

  if (history.length < 3) {
    const fallback = estimatePeak(history);
    return { ...fallback, method: 'bayesian_grid', geometry,
      notes: [`Only ${history.length} sighting(s); a likelihood fit needs at least three. Reported the strongest sighting instead.`] };
  }

  // Sigma scales the whole log-likelihood by a constant, so it does not move
  // the peak at all — verified across 4/6/8 dB of simulated shadowing, where the
  // position was identical to 0.1 m. What it does change is the width of the
  // posterior, and therefore the error radius. 6 dB is the realistic urban
  // figure; the previous 3.16 dB made the reported uncertainty too tight.
  const sigma = options.sigmaDb ?? SHADOWING_SIGMA_DB;
  const coarseSteps = options.coarseSteps ?? 12;
  // 16 steps over a 1.5x window gives ~1.2 m final resolution, matching what the
  // old fixed two-pass grid achieved.
  const fineSteps = options.fineSteps ?? 16;
  let halfWidth = options.coarseHalfWidthM ?? 150;

  const lat0 = history.reduce((a, o) => a + o.lat, 0) / history.length;
  const lon0 = history.reduce((a, o) => a + o.lon, 0) / history.length;
  const proj = makeProjection(lat0, lon0);

  // The grid search is the expensive part of the whole app: it evaluates the
  // likelihood at every grid node against every sighting. Measured at 40 ms per
  // access point with a 100-sighting history, which is 9 seconds of blocked main
  // thread to open a 200-AP mission archive.
  //
  // Three things make it affordable, none of which cost accuracy:
  //
  //  1. Cap the sightings used for the search. Beyond a few dozen well-spread
  //     points the likelihood surface barely moves, and selectDiverse keeps the
  //     spread rather than the strongest, so the subset is representative.
  //  2. Work in squared distance. log10(d) = log10(d^2)/2, which removes a
  //     square root from the innermost loop.
  //  3. Hoist everything per-sighting out of the loop — the previous version
  //     recomputed a projection and a cosine per grid node per sighting.
  const searchSet = selectDiverse(history, GRID_SEARCH_MAX_POINTS);

  // Flat typed arrays rather than an array of objects: this loop runs millions
  // of times and the layout matters.
  const n = searchSet.length;
  const ox = new Float64Array(n);
  const oy = new Float64Array(n);
  // k = rssi - referencePower, so the residual is k + 5*exponent*log10(d^2).
  const ok = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const o = searchSet[i];
    const m = proj.toMetres(o.lat, o.lon);
    ox[i] = m.x; oy[i] = m.y;
    ok[i] = o.rssi - referencePowerDbm(o.frequency);
  }

  const halfSlope = 5 * PATH_LOSS_EXPONENT;   // 10*exponent*log10(d) == halfSlope*log10(d^2)
  const invTwoSigmaSq = 1 / (2 * sigma * sigma);
  const LOG10 = Math.LOG10E;

  /*
    The transmitter's power is fitted, not assumed.

    `REFERENCE_2G4_DBM` is a single constant for every access point in the
    world: -40 dBm at one metre. Real equipment is nowhere near that uniform —
    a ceiling-mounted enterprise AP at full EIRP against a phone hotspot is
    well over 20 dB apart — and nothing in a passive survey reveals which one
    is being looked at.

    Assuming it wrong does not just widen the answer, it *moves* it, because
    every modelled distance scales by the same factor and the fit slides the
    transmitter toward or away from the road to compensate. Measured against
    ground truth on a single straight pass, median error by how far the real
    transmitter was from the assumed power:

        -10 dB   107 m          +3 dB    25 m
         -6 dB    98 m          +6 dB    54 m
         -3 dB    81 m         +10 dB    33 m, and the stated 95% radius
          0 dB    22 m                   covered the truth only 57% of the time

    The fix costs nothing and needs no new information. For any candidate
    position the power that best explains the readings is just the mean of
    `rssi + 10n*log10(d)`, so it can be eliminated analytically: subtract that
    mean and what is left is the *variance* of the residuals. That quantity is
    invariant to the transmitter's power by construction, and it is computable
    in the same single pass — sum and sum-of-squares, then
    `SS = sumsq - sum^2/n`.

    What remains identifiable is the *shape* of the signal along the route,
    which is what actually carries the perpendicular distance: a transmitter
    close to the road produces a sharp peak, a distant one a broad rise. That
    was always the trustworthy part of the measurement. The absolute level,
    which is what the old objective leaned on, was never knowable.
  */
  const priorDb = options.powerPriorDb ?? POWER_PRIOR_DB;
  // How much of the mean residual the power offset is allowed to absorb.
  // tau = 0 pins the power (shrink 0); tau -> infinity fits it freely
  // (shrink 1). Derived, not tuned by feel: minimising
  // `sum((e_i - D)^2)/sigma^2 + D^2/tau^2` over D gives
  // `D* = mean(e) * n*tau^2 / (n*tau^2 + sigma^2)`.
  const shrink = priorDb <= 0
    ? 0
    : !Number.isFinite(priorDb)
      // An unbounded prior means the power is fitted outright. Written as the
      // limit rather than left to the arithmetic: `Inf/Inf` is NaN, every
      // likelihood comparison against NaN is false, and the search then keeps
      // its starting point and silently returns the centre of the route — a
      // plausible-looking coordinate produced by a failed search.
      ? 1
      : (n * priorDb * priorDb) / (n * priorDb * priorDb + sigma * sigma);

  const logLikelihood = (cx: number, cy: number) => {
    let sum = 0, sumsq = 0;
    for (let i = 0; i < n; i++) {
      const dx = cx - ox[i];
      const dy = cy - oy[i];
      let dsq = dx * dx + dy * dy;
      if (dsq < 1) dsq = 1;                       // clamp at 1 m, as before
      const err = ok[i] + halfSlope * Math.log(dsq) * LOG10;
      sum += err;
      sumsq += err * err;
    }
    if (shrink === 0) return -sumsq * invTwoSigmaSq;
    // sum((e_i - D)^2) = sumsq - 2*D*sum + n*D^2, plus the prior's own term.
    const offset = (sum / n) * shrink;
    const residual = sumsq - 2 * offset * sum + n * offset * offset;
    const penalty = priorDb > 0 && Number.isFinite(priorDb)
      ? (offset * offset) * (sigma * sigma) / (priorDb * priorDb)
      : 0;
    return -(residual + penalty) * invTwoSigmaSq;
  };

  /**
   * Evaluate a grid. `collect` returns every node's likelihood so the posterior
   * spread can reuse the fine pass instead of computing it a third time.
   */
  const searchGrid = (cx: number, cy: number, half: number, steps: number, collect = false) => {
    const step = half / steps;
    const side = 2 * steps + 1;
    const values = collect ? new Float64Array(side * side) : null;
    let bestLL = -Infinity, bx = cx, by = cy;
    let onBoundary = false;
    for (let i = -steps; i <= steps; i++) {
      const tx = cx + i * step;
      for (let j = -steps; j <= steps; j++) {
        const ty = cy + j * step;
        const ll = logLikelihood(tx, ty);
        if (values) values[(i + steps) * side + (j + steps)] = ll;
        if (ll > bestLL) {
          bestLL = ll; bx = tx; by = ty;
          onBoundary = Math.abs(i) === steps || Math.abs(j) === steps;
        }
      }
    }
    return { x: bx, y: by, ll: bestLL, step, onBoundary, values, side };
  };

  // Coarse pass, expanding while the best point sits on the edge of the box.
  let coarse = searchGrid(0, 0, halfWidth, coarseSteps);
  let expansions = 0;
  while (coarse.onBoundary && expansions < 3) {
    halfWidth *= 2.5;
    coarse = searchGrid(0, 0, halfWidth, coarseSteps);
    expansions++;
  }
  if (expansions > 0) {
    notes.push(`The likelihood peak lay outside the initial search area, which was expanded ${expansions} time(s) to ${Math.round(halfWidth)} m.`);
  }
  if (coarse.onBoundary) {
    notes.push('The likelihood peak still sits on the edge of the search area; the transmitter is probably well outside the surveyed region and this position is a lower bound on its distance.');
  }

  const fine = searchGrid(coarse.x, coarse.y, coarse.step * 1.5, fineSteps, true);
  const result = proj.toDegrees(fine.x, fine.y);

  // Posterior spread, reusing the likelihoods the fine pass already computed
  // rather than evaluating the same grid a third time.
  const step = fine.step;
  const gridOriginX = coarse.x, gridOriginY = coarse.y;
  let mass = 0, mx = 0, my = 0, mxx = 0, myy = 0;
  if (fine.values) {
    for (let i = -fineSteps; i <= fineSteps; i++) {
      const tx = gridOriginX + i * step;
      for (let j = -fineSteps; j <= fineSteps; j++) {
        const ty = gridOriginY + j * step;
        const w = Math.exp(fine.values[(i + fineSteps) * fine.side + (j + fineSteps)] - fine.ll);
        mass += w; mx += w * tx; my += w * ty;
        mxx += w * tx * tx; myy += w * ty * ty;
      }
    }
  }
  let errorRadiusM: number | null = null;
  if (mass > 0) {
    const meanX = mx / mass, meanY = my / mass;
    const varX = Math.max(0, mxx / mass - meanX * meanX);
    const varY = Math.max(0, myy / mass - meanY * meanY);
    // 2 sigma on the larger axis, floored: the model itself is not accurate to
    // better than a few metres, so a smaller number would be false precision.
    errorRadiusM = Math.max(5, RADIUS_95_SIGMA * Math.sqrt(Math.max(varX, varY)));

    /*
      Widen for the transmitter\'s unknown power.

      The variance above is the width of the likelihood surface *given* the
      assumed power. It says nothing about the assumption itself, and the
      assumption is a single constant for every access point in the world.
      Measured coverage of the radius against its stated 95%: 98% when the
      power happened to be right, 77% at 3 dB of spread, 52% at 6 dB, 43% at
      10 dB. The number was describing a certainty nobody had.

      A power error of D dB scales every modelled distance by
      `10^(D / (10*n))` — at n = 2.5 and 6 dB that is 1.74x — and the fit
      absorbs it by sliding the transmitter toward or away from the route. So
      the induced positional error is proportional to how far the estimate
      already is from the measurements: right beside the road it is negligible,
      a hundred metres off it dominates. Added in quadrature because the two
      are independent sources.

      `r` is measured to the nearest sighting rather than to the route's
      centre: what matters is the closest approach, which is what the distance
      model is anchored on.
    */
    let nearestM = Infinity;
    for (let i = 0; i < n; i++) {
      const d = Math.hypot(fine.x - ox[i], fine.y - oy[i]);
      if (d < nearestM) nearestM = d;
    }
    if (Number.isFinite(nearestM)) {
      const scale = Math.pow(10, TX_POWER_SPREAD_DB / (10 * PATH_LOSS_EXPONENT));
      const fromPower = nearestM * (scale - 1);
      errorRadiusM = Math.hypot(errorRadiusM, fromPower);
    }
  }

  // Is the mirrored solution just as good? If so, the posterior is bimodal and
  // the uncertainty has to cover both modes, not just the one we happened to
  // land on. Without this the estimator reports a tight radius while having a
  // near coin-flip chance of being on the wrong side of the road — measured at
  // 6 wrong out of 10 straight passes, with a stated radius of ~15 m against a
  // true displacement of ~80 m.
  const modeRadiusM = errorRadiusM;
  let mirrorCandidate: { lat: number; lon: number } | null = null;
  let mirrorDistanceM: number | null = null;

  const mirrored = mirrorAcrossTrack(result.lat, result.lon, history);
  if (mirrored) {
    const m = proj.toMetres(mirrored.lat, mirrored.lon);
    const mirrorLL = logLikelihood(m.x, m.y);
    // Within ~2 log-likelihood units is not a meaningful preference.
    if (fine.ll - mirrorLL < 2) {
      mirrorCandidate = mirrored;
      mirrorDistanceM = Math.hypot(fine.x - m.x, fine.y - m.y);
      if (mirrorDistanceM > MIRROR_MIN_SEPARATION_M) {
        // The true position lies within modeRadius of one of the two modes, and
        // the modes are mirrorDistance apart, so from the mode we picked the
        // bound is the sum. Taking the separation alone under-covers, because
        // the point estimate is itself pulled in toward the track.
        errorRadiusM = Math.max(errorRadiusM ?? 0, mirrorDistanceM + (modeRadiusM ?? 0));
        notes.push(
          `A position mirrored across the line of travel fits the measurements equally well. ` +
          `The transmitter is close to one of two candidates about ${mirrorDistanceM.toFixed(0)} m apart ` +
          `(each individually determined to about ${(modeRadiusM ?? 0).toFixed(0)} m); this route cannot ` +
          `tell which. Driving any leg that turns off this line resolves it.`
        );
      }
    }
  }

  if (geometry.mirrorAmbiguous && !mirrorCandidate) notes.push(geometry.note);

  return {
    lat: result.lat, lon: result.lon, method: 'bayesian_grid',
    errorRadiusM,
    confidence: errorRadiusM == null ? null : radiusToConfidence(errorRadiusM),
    geometry, mirrorCandidate, modeRadiusM, mirrorDistanceM,
    notes: notes.length ? notes : ['Maximum-likelihood fit over a log-distance path loss model.'],
  };
}

// ── Reporting helpers ───────────────────────────────────────────────────────

/**
 * Map a 95% error radius to a 0-100 display figure.
 *
 * Defined here, and printed in the report's method appendix, so the number can
 * always be read back as a distance instead of mistaken for a probability:
 *
 *     radius   5 m -> 95      50 m -> 42
 *             10 m -> 79     100 m -> 26
 *             25 m -> 58     250 m ->  5
 */
export function radiusToConfidence(radiusM: number): number {
  if (!Number.isFinite(radiusM) || radiusM <= 0) return 0;
  const c = 100 - 53 * Math.log10(Math.max(1, radiusM) / 4);
  return Math.max(1, Math.min(99, Math.round(c)));
}

export function describeLocalizationMethodology() {
  return {
    reference_power_2g4_dbm: REFERENCE_2G4_DBM,
    path_loss_exponent: PATH_LOSS_EXPONENT,
    shadowing_sigma_db: SHADOWING_SIGMA_DB,
    band_correction: 'Reference power is adjusted by 20*log10(f/2437 MHz), so 5 GHz reads about 6.5 dB and 6 GHz about 7.8 dB weaker at the same range.',
    linearity_ambiguous_below: LINEARITY_AMBIGUOUS_BELOW,
    radius_95_sigma_multiplier: RADIUS_95_SIGMA,
    radius_derivation: 'Positional uncertainty is the larger principal standard deviation of the estimate covariance, multiplied by sqrt(-2*ln(0.05)) = 2.448 — the Rayleigh factor for a 95% radial bound in two dimensions. Multilateration derives that covariance from the least-squares normal matrix, so collinear sightings inflate it along the unconstrained axis. For the likelihood grid, the uncertainty induced by the transmitter\'s unknown power is added to that in quadrature.',
    min_along_track_m: MIN_ALONG_TRACK_M,
    min_cross_track_m: MIN_CROSS_TRACK_M,
    single_reading_distance_factor_95: SINGLE_READING_DISTANCE_FACTOR_95,
    tx_power_prior_db: POWER_PRIOR_DB,
    tx_power_spread_db: TX_POWER_SPREAD_DB,
    tx_power_handling:
      'The transmitter\'s power is not known and is not assumed to be exactly the reference. '
      + `The fit may move it by about ${POWER_PRIOR_DB} dB, chosen by measurement against ground truth, `
      + `and the error radius is widened by the positional error that ${TX_POWER_SPREAD_DB} dB of `
      + 'unmodelled power difference would induce — proportional to the estimate\'s distance from the '
      + 'nearest sighting, since a power error scales every modelled distance by the same factor.',
    baseline_meaning: 'Sightings spanning less than min_along_track_m of travel, or less than min_cross_track_m of perpendicular deviation, are treated as a stationary receiver scatter rather than a route. No side of the track is claimed from them and the error radius is widened accordingly.',
    error_radius_meaning: 'Radius in metres containing roughly 95% of the posterior mass. Null where the estimator cannot produce one.',
    // Derived from radiusToConfidence rather than restated, so the two can
    // never drift apart. They already did once: this string kept an earlier
    // formula after the function changed, and a reader following it would have
    // converted the report's own figures back to the wrong distances.
    confidence_formula: 'confidence = 100 - 53 * log10(max(1, radius_m) / 4), clamped to 1-99',
    confidence_meaning: 'A display figure derived from the error radius alone. It is not a probability.',
    confidence_scale: [2, 5, 10, 25, 50, 100, 250].map((radiusM) => ({
      radius_m: radiusM,
      confidence: radiusToConfidence(radiusM),
    })),
    limitations: [
      'The absolute reference power is a rule of thumb, not a calibration against measured hardware. Distances scale with it, so systematic error is possible; the relative correction between bands is physics and is reliable. The likelihood grid allows for this rather than ignoring it: measured against ground truth on a route with one turn, the stated radius covered the true position 52% of the time at 6 dB of unmodelled power difference before this was accounted for, and 94% after.',
      'A straight route leaves the position mirror-ambiguous about the line of travel. Estimates carry a mirrorCandidate when this applies.',
      'The signal-weighted track position cannot lie off the surveyed path and is not a transmitter location.',
      'Walls, vehicles and terrain are not modelled; a single path loss exponent is assumed throughout.',
      'Positions are estimates from radio measurements and should not be treated as a survey-grade fix.',
    ],
  };
}

/** Run whichever estimator the operator selected. */
/**
 * What to report when the survey cannot locate anything.
 *
 * Trilateration needs the receiver to have moved: the position is fixed by
 * where the ranges from different places intersect, and from a single place
 * they do not intersect, they merely agree. `assessGeometry` already detects
 * this (`insufficientBaseline`, below `MIN_ALONG_TRACK_M`) and before this
 * existed the flag was used only to write a note and tint a label --- the
 * solver ran anyway and its answer was published.
 *
 * That answer is not merely imprecise, it is unstable. Solving for a
 * transmitter a hundred metres away from a cluster of sightings ten metres
 * across is ill-conditioned: a few dB of fading moves the solution by tens of
 * metres, so every re-estimate puts the access point somewhere new. A reader
 * watching that sees dots wandering; a reader of the report sees a coordinate
 * with no sign that it was never determined.
 *
 * So nothing is solved. The position reported is the middle of where the
 * receiver actually stood --- which is stable, because it is a mean over the
 * scatter rather than a pick from it --- and the radius is the distance the
 * strongest reading implies, widened for the model's own spread. The claim is
 * then one the data supports exactly: *the transmitter is somewhere within this
 * circle of where you were standing*, and the circle is honestly large.
 */
export function estimateUnresolved(
  history: Observation[],
  method: LocationMethod,
  geometry: GeometryAssessment,
): LocationEstimate {
  if (history.length === 0) {
    return {
      lat: 0, lon: 0, method, errorRadiusM: null, confidence: null, geometry,
      resolved: false, notes: ['No positioned sightings, so no position can be established.'],
    };
  }

  // The mean of where the receiver stood, not the strongest single sighting.
  // Both are the same place to within GPS scatter, but the mean does not hop
  // between scatter points as the signal flickers, and a position that twitches
  // is read as information when it is noise.
  const lat = history.reduce((a, o) => a + o.lat, 0) / history.length;
  const lon = history.reduce((a, o) => a + o.lon, 0) / history.length;

  const p = peak(history);
  // Corrected for the order statistic before the spread is applied: over a
  // parked survey the peak is the best of many, not a typical reading.
  const implied = rssiToDistanceM(p.rssi, p.frequency)
    * peakDistanceCorrection(history.length)
    * peakSpreadFactor95(history.length);
  // The receiver's own scatter is a floor on the radius: the transmitter cannot
  // be pinned tighter than the spread of the places it was measured from.
  const spread = Math.max(geometry.alongTrackM, geometry.crossTrackM) / 2;
  const radius = Math.max(implied, spread);

  return {
    lat, lon, method,
    errorRadiusM: radius,
    confidence: radiusToConfidence(radius),
    geometry,
    resolved: false,
    mirrorCandidate: null,
    notes: [
      `The receiver did not move far enough to locate this transmitter: `
      + `${geometry.alongTrackM.toFixed(1)} m of travel against the `
      + `${MIN_ALONG_TRACK_M} m needed. Trilateration fixes a position where `
      + `ranges taken from different places intersect, and from one place they `
      + `cannot. This marks where the receiver stood, and the radius is the `
      + `distance the strongest reading implies - not an estimate of where the `
      + `transmitter is. Drive or walk past it to resolve this.`,
    ],
  };
}

export function estimateLocation(
  history: Observation[],
  method: LocationMethod,
  options: BayesianOptions = {}
): LocationEstimate {
  /*
    One gate, before any estimator runs, because this is not a property of the
    method chosen. No estimator can recover a position the geometry does not
    contain, and each of them failing in its own way produced three different
    wrong answers rather than one honest refusal.
  */
  const geometry = assessGeometry(history);
  if (geometry.insufficientBaseline) {
    return estimateUnresolved(history, method, geometry);
  }

  switch (method) {
    case 'bayesian_grid': return estimateBayesian(history, options);
    case 'trilateration': return estimateTrilateration(history);
    case 'weighted_centroid': return estimateTrackPosition(history);
    default: return estimatePeak(history);
  }
}
