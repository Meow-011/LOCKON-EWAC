/**
 * Ground-truth regression tests for AP localization.
 *
 *     npm run test:localization
 *
 * These exist because the estimators were wrong and nothing caught it. Reading
 * the code did not reveal that the weighted centroid could never leave the road
 * or that the trilateration solver stopped at two thirds of its correction —
 * only measuring against a known answer did.
 *
 * Each test simulates a drive with the transmitter at a known position, runs the
 * real estimator, and asserts on the error in metres. Thresholds are set a
 * little looser than measured so noise does not cause spurious failures; if one
 * starts failing, the accuracy genuinely regressed.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  describeLocalizationMethodology,
  estimateBayesian,
  estimateTrilateration,
  estimateTrackPosition,
  estimatePeak,
  estimateLocation,
  assessGeometry,
  RADIUS_95_SIGMA,
  SINGLE_READING_DISTANCE_FACTOR_95,
  MIN_ALONG_TRACK_M,
  MIN_CROSS_TRACK_M,
  MIRROR_MIN_SEPARATION_M,
  selectDiverse,
  mergeObservation,
  referencePowerDbm,
  rssiToDistanceM,
  radiusToConfidence,
  POWER_PRIOR_DB,
  TX_POWER_SPREAD_DB,
  M_PER_DEG_LAT,
  mPerDegLon,
} from '../.test-build/localization.mjs';

/** The old rule passed anything above 0.15; a blob scores far higher. */
const LINEARITY_RATIO_THAT_WOULD_HAVE_PASSED = 0.15;

const AP_LAT = 13.7563;
const AP_LON = 100.5018;
const M_LON = mPerDegLon(AP_LAT);

function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function gauss(rng, sd) {
  const u = Math.max(1e-9, rng()), v = rng();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v) * sd;
}

/** Sample the radio model at a point, returning null below the noise floor. */
function sampleAt(rng, lat, lon, { frequency = 2437, sigmaDb = 6 } = {}) {
  const dx = (lon - AP_LON) * M_LON;
  const dy = (lat - AP_LAT) * M_PER_DEG_LAT;
  const d = Math.max(1, Math.hypot(dx, dy));
  const ref = referencePowerDbm(frequency);
  const rssi = ref - 25 * Math.log10(d) + gauss(rng, sigmaDb);
  return rssi < -95 ? null : { lat, lon, rssi: Math.round(rssi), frequency };
}

/** A straight leg offset `offsetM` across-track, spanning `fromM`..`toM`. */
function eastWestLeg(offsetM, fromM, toM, n) {
  const lat = AP_LAT + offsetM / M_PER_DEG_LAT;
  return Array.from({ length: n }, (_, i) => {
    const m = fromM + ((toM - fromM) * i) / (n - 1);
    return [lat, AP_LON + m / M_LON];
  });
}
function northSouthLeg(offsetM, fromM, toM, n) {
  const lon = AP_LON + offsetM / M_LON;
  return Array.from({ length: n }, (_, i) => {
    const m = fromM + ((toM - fromM) * i) / (n - 1);
    return [AP_LAT + m / M_PER_DEG_LAT, lon];
  });
}

function collect(points, { seed = 7, cap = 100, frequency = 2437 } = {}) {
  const rng = mulberry32(seed);
  let history = [];
  for (const [lat, lon] of points) {
    const s = sampleAt(rng, lat, lon, { frequency });
    if (s) history = mergeObservation(history, s, cap);
  }
  return history;
}

const errM = (lat, lon) =>
  Math.hypot((lat - AP_LAT) * M_PER_DEG_LAT, (lon - AP_LON) * M_LON);

/** Median error across several noise seeds — robust to one unlucky draw. */
function medianError(points, estimator, { cap = 100, trials = 5, frequency = 2437 } = {}) {
  const errs = [];
  for (let t = 0; t < trials; t++) {
    const history = collect(points, { seed: 11 + t * 97, cap, frequency });
    if (history.length < 3) continue;
    const e = estimator(history);
    errs.push(errM(e.lat, e.lon));
  }
  errs.sort((a, b) => a - b);
  return errs[Math.floor(errs.length / 2)];
}

// Routes used throughout. The AP sits 40 m north of the main road.
const STRAIGHT = eastWestLeg(-40, -150, 150, 60);
const L_SHAPED = [...eastWestLeg(-40, -150, 60, 40), ...northSouthLeg(60, -40, 160, 40)];
const TWO_STREETS = [...eastWestLeg(-40, -150, 150, 40), ...eastWestLeg(60, -150, 150, 40)];

/**
 * The same pass, driven by someone rather than ruled with a straight edge.
 *
 * `STRAIGHT` puts all sixty sightings at one exact latitude, and that turned out
 * to be too clean to test the ambiguity code at all. With every point on one
 * line, `J^T J` is exactly singular: the solver's first iteration breaks, the
 * answer stays at the strongest sighting — which is *on* the track — and
 * reflecting a point across an axis it already lies on returns the point itself.
 * So `estimateTrilateration` produced no second candidate on this fixture, ever,
 * and every mirror assertion written against it took the `continue` and passed
 * without running.
 *
 * A metre and a half of lateral wobble is less than any real receiver's scatter,
 * and it is enough: the matrix inverts, the solver leaves the road, the
 * reflection lands on the far side, and all forty seeds exercise the branch. The
 * geometry is still reported as mirror-ambiguous — 1.5 m of cross-track is far
 * below `MIN_CROSS_TRACK_M`, as it should be, because a wobble is not a survey
 * of the other side of the street.
 */
function drivenStraight(seed, { wobbleM = 1.5, offsetM = -40, n = 60 } = {}) {
  const rng = mulberry32(seed * 7919);
  return Array.from({ length: n }, (_, i) => [
    AP_LAT + (offsetM + gauss(rng, wobbleM)) / M_PER_DEG_LAT,
    AP_LON + (-150 + (300 * i) / (n - 1)) / M_LON,
  ]);
}

// ── The radio model ─────────────────────────────────────────────────────────

test('reference power is corrected for band', () => {
  const p24 = referencePowerDbm(2437);
  const p5 = referencePowerDbm(5180);
  const p6 = referencePowerDbm(5955);
  assert.equal(Math.round(p24), -40);
  // 5 GHz should read ~6.5 dB weaker at the same range, 6 GHz ~7.8 dB.
  assert.ok(p24 - p5 > 6 && p24 - p5 < 7, `5 GHz offset was ${(p24 - p5).toFixed(2)} dB`);
  assert.ok(p24 - p6 > 7 && p24 - p6 < 8.5, `6 GHz offset was ${(p24 - p6).toFixed(2)} dB`);
});

test('kHz frequencies are normalised', () => {
  assert.equal(referencePowerDbm(2412000).toFixed(3), referencePowerDbm(2412).toFixed(3));
});

test('a 5 GHz AP is not placed further away than a 2.4 GHz one at the same range', () => {
  // The old single-reference model put 5 GHz APs 1.8x too far out.
  const d24 = rssiToDistanceM(-70, 2437);
  const d5 = rssiToDistanceM(-70 - (referencePowerDbm(2437) - referencePowerDbm(5180)), 5180);
  assert.ok(Math.abs(d24 - d5) / d24 < 0.02, `expected equal ranges, got ${d24.toFixed(1)} vs ${d5.toFixed(1)} m`);
});

// ── History selection ───────────────────────────────────────────────────────

test('diverse selection preserves the full RSSI range, unlike top-N by strength', () => {
  const history = collect(TWO_STREETS, { cap: 5000 });
  assert.ok(history.length > 30, 'need a decent sample for this test');

  const kept = selectDiverse(history, 20);
  const keptRange = Math.max(...kept.map(o => o.rssi)) - Math.min(...kept.map(o => o.rssi));
  const fullRange = Math.max(...history.map(o => o.rssi)) - Math.min(...history.map(o => o.rssi));

  const strongestOnly = history.slice().sort((a, b) => b.rssi - a.rssi).slice(0, 20);
  const naiveRange = Math.max(...strongestOnly.map(o => o.rssi)) - Math.min(...strongestOnly.map(o => o.rssi));

  assert.equal(kept.length, 20);
  assert.ok(keptRange > naiveRange,
    `diverse kept ${keptRange} dB of range, strongest-N kept ${naiveRange} dB (of ${fullRange} available)`);
});

test('a tight history cap no longer doubles the error', () => {
  const tight = medianError(TWO_STREETS, estimateBayesian, { cap: 20 });
  const loose = medianError(TWO_STREETS, estimateBayesian, { cap: 100 });
  // Measured with the old strongest-N rule: 19.7 m at cap 20 against 10.6 m at
  // cap 50. Keeping the spread should hold the penalty well under 2x.
  assert.ok(tight < loose * 1.8 + 5,
    `cap 20 gave ${tight.toFixed(1)} m against ${loose.toFixed(1)} m at cap 100`);
});

test('merging keeps the strongest reading within a cell', () => {
  let h = [];
  h = mergeObservation(h, { lat: AP_LAT, lon: AP_LON, rssi: -80 }, 50);
  h = mergeObservation(h, { lat: AP_LAT + 0.000005, lon: AP_LON, rssi: -60 }, 50);
  assert.equal(h.length, 1, 'sightings ~0.5 m apart should merge into one cell');
  assert.equal(h[0].rssi, -60);
});

// ── Geometry ────────────────────────────────────────────────────────────────

/**
 * A parked receiver still reports a position, and consumer GPS scatter is
 * roughly circular. That blob scored a near-perfect cross/along ratio, so the
 * linearity test passed it and the survey panel told the operator:
 *
 *   "2 m of deviation across 5 m of travel. Enough shape to determine which
 *    side of the track an AP lies on."
 *
 * It is not enough for anything. The ratio measures the shape of the cloud and
 * never asked how big it was, so an estimate built from five metres of jitter
 * was reported without the widened error radius an ambiguous geometry earns.
 */
function parkedJitter(seed = 5, n = 40, scatterM = 2.5) {
  const rng = mulberry32(seed);
  const out = [];
  // Sitting 40 m from the AP, not moving.
  const baseLat = AP_LAT + 40 / M_PER_DEG_LAT;
  const baseLon = AP_LON;
  for (let i = 0; i < n; i += 1) {
    const lat = baseLat + gauss(rng, scatterM) / M_PER_DEG_LAT;
    const lon = baseLon + gauss(rng, scatterM) / M_LON;
    const s = sampleAt(rng, lat, lon);
    if (s) out.push(s);
  }
  return out;
}

/*
  A receiver that never moved cannot locate anything, and must say so.

  This is the defect these three tests exist for: the solvers ran anyway. They
  returned a position, the position was different every time the signal
  flickered, and the access points visibly crawled around the map while the
  operator stood still. `insufficientBaseline` had been detected all along and
  was used only to write a note.
*/
test('a parked receiver reports its position as unresolved, whatever method is selected', () => {
  const parked = parkedJitter();
  for (const method of ['trilateration', 'bayesian_grid', 'weighted_centroid']) {
    const est = estimateLocation(parked, method);
    assert.equal(est.resolved, false, `${method} claimed to resolve a parked survey`);
    assert.ok(
      est.notes.join(' ').includes('did not move far enough'),
      `${method} did not say why it could not resolve`,
    );
    // The method asked for is still reported, so the document does not quietly
    // substitute a different one.
    assert.equal(est.method, method);
  }
});

test('the unresolved position does not wander as the signal flickers', () => {
  // Ten independent parked surveys of the same spot: same place, different
  // fading. A stable answer barely moves between them; the raw solver does not.
  const runs = [];
  const solved = [];
  for (let seed = 1; seed <= 10; seed += 1) {
    const parked = parkedJitter(seed);
    runs.push(estimateLocation(parked, 'trilateration'));
    solved.push(estimateTrilateration(parked));
  }
  const spreadOf = (list) => {
    let worst = 0;
    for (let i = 0; i < list.length; i += 1) {
      for (let j = i + 1; j < list.length; j += 1) {
        const dy = (list[i].lat - list[j].lat) * M_PER_DEG_LAT;
        const dx = (list[i].lon - list[j].lon) * M_LON;
        worst = Math.max(worst, Math.hypot(dx, dy));
      }
    }
    return worst;
  };

  const gated = spreadOf(runs);
  const ungated = spreadOf(solved);

  // The point of the gate: the reported position stays put.
  assert.ok(gated < 10, `the unresolved position moved ${gated.toFixed(1)} m between runs`);
  // And it is not that this data is easy — the solver on the same input is all
  // over the place. If this ever stops holding, the gate is no longer earning
  // its keep and the assertion above has become vacuous.
  assert.ok(
    ungated > gated * 2,
    `the raw solver moved only ${ungated.toFixed(1)} m, so this input no longer demonstrates the problem`,
  );
});

test('the unresolved radius covers the transmitter it refused to locate', () => {
  // Refusing to solve is only honest if the circle actually contains the answer.
  let covered = 0;
  for (let seed = 1; seed <= 10; seed += 1) {
    const est = estimateLocation(parkedJitter(seed), 'trilateration');
    if (errM(est.lat, est.lon) <= est.errorRadiusM) covered += 1;
  }
  assert.ok(covered >= 9, `the stated radius covered the true position in only ${covered}/10 runs`);
});

test('the unresolved radius is honest without being useless', () => {
  /*
    The other half of coverage, and it needs its own test because the two pull
    against each other: any radius can be made to cover by making it enormous.

    The first version did exactly that. It applied the single-reading spread on
    top of the order-statistic correction, which double-counts -- the bias has
    already been removed, and what is left is the uncertainty of the *maximum*
    of n samples, tighter than one sample by about sqrt(2 ln n). That gave 100%
    coverage at a median radius 4.2x the error it covered. "Somewhere within
    1.4 km" is true and is not a finding anyone can act on.
  */
  const ratios = [];
  for (let seed = 1; seed <= 40; seed += 1) {
    const est = estimateLocation(parkedJitter(seed), 'trilateration');
    ratios.push(est.errorRadiusM / Math.max(1, errM(est.lat, est.lon)));
  }
  ratios.sort((a, b) => a - b);
  const median = ratios[ratios.length >> 1];
  assert.ok(median >= 1, `the radius does not cover its own error (median ratio ${median.toFixed(1)})`);
  assert.ok(median < 4, `the radius is ${median.toFixed(1)}x the error it covers, which is too wide to act on`);
});

test('a survey with a real baseline still resolves', () => {
  // The gate must not swallow working surveys. A 300 m straight pass is well
  // past the threshold, so it has to reach the estimator exactly as before --
  // and come back with the accuracy the benchmark in AP_LOCATION_METHODS.md
  // records for that route, not merely with `resolved` set.
  const driven = collect(STRAIGHT);
  const est = estimateLocation(driven, 'trilateration');
  assert.notEqual(est.resolved, false, 'a 300 m pass was reported as unresolved');

  const gated = medianError(STRAIGHT, (h) => estimateLocation(h, 'trilateration'));
  const direct = medianError(STRAIGHT, estimateTrilateration);
  assert.ok(gated < 60, `the resolved estimate regressed to ${gated.toFixed(1)} m`);
  // Going through the gate must not change the answer on a survey that resolves.
  assert.ok(
    Math.abs(gated - direct) < 1,
    `the gate altered a resolved estimate: ${gated.toFixed(1)} m vs ${direct.toFixed(1)} m`,
  );
});

test("the peak fallback's error radius covers the error it actually makes", () => {
  // It used to report the modelled distance itself — 14 m of claimed radius
  // against 42 m of measured error, quoted in the report as a confidence bound.
  const errs = [];
  let covered = 0;
  for (const seed of [1, 2, 3, 4, 5]) {
    const history = collect(STRAIGHT, { seed });
    const est = estimatePeak(history);
    const dx = (est.lon - AP_LON) * M_LON;
    const dy = (est.lat - AP_LAT) * M_PER_DEG_LAT;
    const err = Math.hypot(dx, dy);
    errs.push(err);
    if (est.errorRadiusM >= err) covered += 1;
  }
  assert.ok(covered >= 3,
    `radius covered the true error in only ${covered}/5 runs ` +
    `(errors ${errs.map((e) => e.toFixed(0)).join(', ')} m)`);
});

test('the single-reading spread is derived from the radio model, not hardcoded', () => {
  // 10^(2*sigma / (10*n)). If sigma or the exponent changes, this must follow.
  const expected = Math.pow(10, (2 * 6.0) / (10 * 2.5));
  assert.ok(Math.abs(SINGLE_READING_DISTANCE_FACTOR_95 - expected) < 1e-9);
  const m = describeLocalizationMethodology();
  assert.equal(m.single_reading_distance_factor_95, SINGLE_READING_DISTANCE_FACTOR_95);
});

test('both estimators state how far apart the two candidates are', () => {
  /*
    `> 0` was the assertion here, and it was vacuous.

    On a straight pass the least-squares solver takes no step, so its answer sits
    on the track; reflecting a point that is already on the axis returns the
    point itself. The measured separation was about 1e-10 m, `7.9e-10 > 0` is
    true, and the test passed while the PDF, the CSV and the KML each described
    two "equally good positions, 0 m apart" and drew a duplicate placemark joined
    by a zero-length line.

    A second candidate that is the same point is not a second candidate. The
    threshold is the one both estimators now share.
  */
  for (const [name, fn] of [['bayesian', estimateBayesian], ['trilateration', estimateTrilateration]]) {
    const est = fn(collect(drivenStraight(2), { seed: 2 }));
    // No `continue` here any more. On a drive that wobbles like a real one both
    // estimators find the ambiguity, so an estimator that reports no second
    // candidate on this route is a finding and not a case to skip.
    assert.ok(est.mirrorCandidate, `${name} found no mirror candidate on an ambiguous pass`);
    assert.ok(
      typeof est.mirrorDistanceM === 'number' && est.mirrorDistanceM > MIRROR_MIN_SEPARATION_M,
      `${name} produced a mirror candidate ${est.mirrorDistanceM} m from the point it mirrors`
    );
  }
});

test('a candidate that is the same point is not offered as a second one', () => {
  /*
    Driven across many seeds rather than one, because the defect is not that the
    separation is small on a particular run — it is that a degenerate solve
    produces a reflection of a point about an axis it already lies on, and the
    estimator offered it anyway.
  */
  for (let seed = 1; seed <= 40; seed++) {
    const est = estimateTrilateration(collect(drivenStraight(seed), { seed }));
    if (!est.mirrorCandidate) continue;
    assert.ok(
      est.mirrorDistanceM > MIRROR_MIN_SEPARATION_M,
      `seed ${seed}: offered a candidate ${est.mirrorDistanceM} m away`
    );
  }

  /*
    And the degenerate case the guard exists for, kept because it is the one that
    shipped: on a mathematically exact line the reflection *is* the point, and
    the only correct number of second candidates is none.
  */
  const exact = estimateTrilateration(collect(STRAIGHT, { seed: 2 }));
  assert.equal(exact.mirrorCandidate, null,
    `an exactly straight pass offered a candidate ${exact.mirrorDistanceM} m away`);
  assert.equal(exact.mirrorDistanceM, null, 'and a separation to go with it');
});

test('multilateration covers both modes, as the grid does', () => {
  /*
    The radius was documented as already doing this — "the ill-conditioning that
    causes the mirror ambiguity is exactly what inflates the radius, which is the
    behaviour a reader of the report is entitled to assume the number already
    had". It was not: the covariance is a per-mode spread, and a radius drawn
    from it covers the mode it was computed at and not the other one.

    `modeRadiusM` is asserted too, because it was never set at all — the
    report's "Per-mode" column read `n/r` for every multilaterated access point
    while its header explained what the column meant.
  */
  let n = 0, coveredByMode = 0, coveredByBoth = 0, mirrorWasBetter = 0;

  for (let seed = 1; seed <= 60; seed++) {
    const est = estimateTrilateration(collect(drivenStraight(seed), { seed }));
    assert.ok(est.mirrorCandidate, `seed ${seed}: no mirror candidate on an ambiguous pass`);
    n++;

    assert.ok(typeof est.modeRadiusM === 'number',
      `seed ${seed}: no per-mode radius was published`);
    assert.ok(est.errorRadiusM >= est.mirrorDistanceM + est.modeRadiusM - 1e-6,
      `seed ${seed}: radius ${est.errorRadiusM?.toFixed(1)} m does not cover a mode ` +
      `${est.mirrorDistanceM?.toFixed(1)} m away with a ${est.modeRadiusM?.toFixed(1)} m spread`);
    assert.ok(est.modeRadiusM <= est.errorRadiusM,
      `seed ${seed}: the per-mode radius exceeds the radius covering both modes`);

    const err = errM(est.lat, est.lon);
    if (err <= est.modeRadiusM) coveredByMode++;
    if (err <= est.errorRadiusM) coveredByBoth++;
    if (errM(est.mirrorCandidate.lat, est.mirrorCandidate.lon) < err) mirrorWasBetter++;
  }

  /*
    The measurement that makes this worth a test rather than a tidy-up.

    Over 200 runs of this route the solver picked the wrong side of the road 48%
    of the time — which is what "mirror ambiguous" means, and why the radius has
    to reach the other mode. The per-mode radius contained the transmitter in 52%
    of runs while the report printed it under a heading that says 95%. The radius
    that covers both contained it in every one.

    A bound that holds half the time is not a bound, and this is the kind of wrong
    that reads as careful work: a plausible number, correctly computed, labelled
    as something it is not.
  */
  assert.ok(coveredByBoth / n >= 0.95,
    `the stated radius covered the truth in only ${coveredByMode}/${n} runs`);
  assert.ok(coveredByMode / n < 0.8,
    `the per-mode radius covered ${coveredByMode}/${n} — if it is now a 95% bound on ` +
    'its own then this route is no longer ambiguous and the fixture has drifted');
  assert.ok(mirrorWasBetter > n / 5,
    `the mirror was the better answer in only ${mirrorWasBetter}/${n} runs, so this ` +
    'route no longer models an ambiguous pass');
});

test('the stated radius is the factor a 95% radial bound needs', () => {
  // Both estimators used 2.0 sigma, which covers 86.5% of a 2-D normal, while
  // the field is documented and printed as "roughly 95% of the posterior".
  const expected = Math.sqrt(-2 * Math.log(0.05));
  assert.ok(Math.abs(RADIUS_95_SIGMA - expected) < 1e-9);
  assert.ok(RADIUS_95_SIGMA > 2.4 && RADIUS_95_SIGMA < 2.5, RADIUS_95_SIGMA);
  const m = describeLocalizationMethodology();
  assert.equal(m.radius_95_sigma_multiplier, RADIUS_95_SIGMA);
});

test("multilateration's radius tracks its geometry, not its range residuals", () => {
  // It used to report `median range residual * 1.5`, which measures how well
  // the modelled ranges agree — a property of the shadowing, not of how tightly
  // the geometry pins the position. The two move in opposite directions: the
  // radius came out 4.1x the true error on a loop and 1.0x on a straight pass,
  // where it covered the error in only 4 runs of 10.
  const straight = estimateTrilateration(collect(STRAIGHT, { seed: 3 }));
  const shaped = estimateTrilateration(collect(L_SHAPED, { seed: 3 }));
  assert.ok(straight.errorRadiusM != null && shaped.errorRadiusM != null);
  assert.ok(
    straight.errorRadiusM > shaped.errorRadiusM * 1.5,
    `a straight pass leaves the cross-track direction unconstrained, so its `
    + `radius must be far larger: straight ${straight.errorRadiusM.toFixed(0)} m `
    + `vs shaped ${shaped.errorRadiusM.toFixed(0)} m`
  );
});

test('a stationary receiver is not mistaken for a surveyed route', () => {
  const g = assessGeometry(parkedJitter());
  assert.equal(g.insufficientBaseline, true,
    `${g.alongTrackM.toFixed(1)} m of travel was accepted as a route`);
  assert.equal(g.mirrorAmbiguous, true,
    'a position with no baseline must still carry the widened error radius');
  assert.ok(g.alongTrackM < MIN_ALONG_TRACK_M,
    `along-track ${g.alongTrackM.toFixed(1)} m should be below the floor`);
});

test('the stationary case says to drive, not to turn a corner', () => {
  // The two problems need different fixes, so the message has to name which.
  const g = assessGeometry(parkedJitter());
  assert.match(g.note, /stationary|no baseline|Drive past/i, g.note);
  assert.doesNotMatch(g.note, /one turn resolves/i, g.note);
});

test('a jitter blob does not pass on its shape alone', () => {
  // The exact defect: cross/along near 1.0 sails past the ratio test.
  const g = assessGeometry(parkedJitter());
  assert.ok(g.linearity > LINEARITY_RATIO_THAT_WOULD_HAVE_PASSED,
    `linearity was ${g.linearity.toFixed(2)}; this test is meaningless if the ` +
    'ratio alone would have rejected it');
});

test('a real straight drive is ambiguous but not called stationary', () => {
  const g = assessGeometry(collect(STRAIGHT));
  assert.equal(g.mirrorAmbiguous, true);
  assert.equal(g.insufficientBaseline, false,
    'a 165 m drive has a baseline; telling the operator to drive would be wrong');
  assert.match(g.note, /straight line|mirrored/i, g.note);
});

test('a deviation within GPS scatter does not decide the side of the track', () => {
  // 30 m of travel with 6 m of wobble passes the 0.15 ratio test at 0.2, and is
  // still noise. The absolute floor is what catches it.
  const rng = mulberry32(11);
  const obs = [];
  for (let i = 0; i < 40; i += 1) {
    const along = (i / 39) * 30 - 15;
    const lat = AP_LAT + (40 + gauss(rng, 3)) / M_PER_DEG_LAT;
    const lon = AP_LON + along / M_LON;
    const s = sampleAt(rng, lat, lon);
    if (s) obs.push(s);
  }
  const g = assessGeometry(obs);
  assert.ok(g.crossTrackM < MIN_CROSS_TRACK_M,
    `cross-track was ${g.crossTrackM.toFixed(1)} m; fixture no longer models the case`);
  assert.equal(g.mirrorAmbiguous, true);
});

test('an L-shaped drive still clears both the shape and the scale tests', () => {
  const g = assessGeometry(collect(L_SHAPED));
  assert.equal(g.insufficientBaseline, false);
  assert.equal(g.mirrorAmbiguous, false);
  assert.ok(g.alongTrackM >= MIN_ALONG_TRACK_M);
  assert.ok(g.crossTrackM >= MIN_CROSS_TRACK_M);
});

test('the published methodology states the baseline floors', () => {
  // The report quotes these; a reader who cannot see them cannot judge a fix.
  const m = describeLocalizationMethodology();
  assert.equal(m.min_along_track_m, MIN_ALONG_TRACK_M);
  assert.equal(m.min_cross_track_m, MIN_CROSS_TRACK_M);
});

test('a straight route is reported as mirror-ambiguous', () => {
  const g = assessGeometry(collect(STRAIGHT));
  assert.equal(g.mirrorAmbiguous, true);
  assert.ok(g.crossTrackM < 15, `cross-track spread was ${g.crossTrackM.toFixed(1)} m`);
  assert.match(g.note, /mirrored|straight line/i);
});

test('a route with a turn is not reported as ambiguous', () => {
  const g = assessGeometry(collect(L_SHAPED));
  assert.equal(g.mirrorAmbiguous, false);
  assert.ok(g.crossTrackM > 30, `cross-track spread was ${g.crossTrackM.toFixed(1)} m`);
});

test('two parallel streets resolve the ambiguity', () => {
  const g = assessGeometry(collect(TWO_STREETS));
  assert.equal(g.mirrorAmbiguous, false);
});

// ── Estimators ──────────────────────────────────────────────────────────────

test('trilateration converges and beats the peak-RSSI baseline', () => {
  // Previously 38.6 m against a 40.7 m baseline: it barely moved from its start.
  const tri = medianError(TWO_STREETS, estimateTrilateration);
  const peak = medianError(TWO_STREETS, estimatePeak);
  assert.ok(tri < peak, `trilateration ${tri.toFixed(1)} m did not beat peak ${peak.toFixed(1)} m`);
  assert.ok(tri < 30, `trilateration error was ${tri.toFixed(1)} m`);
});

test('trilateration output does not depend on the BSSID', () => {
  // The old solver seeded from a hash of the MAC and never fully converged, so
  // part of the published coordinate came from the BSSID.
  const history = collect(TWO_STREETS);
  const a = estimateTrilateration(history);
  const b = estimateTrilateration(history.map(o => ({ ...o })));
  assert.equal(a.lat, b.lat);
  assert.equal(a.lon, b.lon);
});

test('estimators do not mutate the history they are given', () => {
  const history = collect(TWO_STREETS);
  const before = JSON.stringify(history);
  estimateTrilateration(history);
  estimateBayesian(history);
  estimateTrackPosition(history);
  assert.equal(JSON.stringify(history), before);
});

test('bayesian beats the peak baseline when the geometry allows it', () => {
  const bay = medianError(L_SHAPED, estimateBayesian);
  const peak = medianError(L_SHAPED, estimatePeak);
  assert.ok(bay < peak * 0.6, `bayesian ${bay.toFixed(1)} m against peak ${peak.toFixed(1)} m`);
  assert.ok(bay < 25, `bayesian error was ${bay.toFixed(1)} m on a route with a turn`);
});

test('a route with a turn localises better than a straight one', () => {
  const straight = medianError(STRAIGHT, estimateBayesian);
  const turned = medianError(L_SHAPED, estimateBayesian);
  assert.ok(turned < straight,
    `turn ${turned.toFixed(1)} m should beat straight ${straight.toFixed(1)} m`);
});

test('the track position is honest about being on the track', () => {
  const history = collect(STRAIGHT);
  const est = estimateTrackPosition(history);
  const offTrackM = (est.lat - (AP_LAT - 40 / M_PER_DEG_LAT)) * M_PER_DEG_LAT;
  assert.ok(Math.abs(offTrackM) < 5, `expected it to stay on the road, was ${offTrackM.toFixed(1)} m off`);
  assert.equal(est.errorRadiusM, null, 'it must not claim an error radius it cannot support');
  assert.match(est.notes.join(' '), /cannot lie off the path|must not be read as/i);
});

test('the search expands when the transmitter is outside the initial box', () => {
  // Drive a leg 400 m away from the AP: the peak is outside the default 150 m box.
  const far = eastWestLeg(-400, -150, 150, 50);
  const history = collect(far, { seed: 3 });
  if (history.length < 3) return; // too far to hear; nothing to assert
  const est = estimateBayesian(history);
  assert.ok(
    est.notes.some(n => /expanded|edge of the search area/i.test(n)),
    `expected a note about the search area, got: ${est.notes.join(' | ')}`
  );
});

// ── Uncertainty reporting ───────────────────────────────────────────────────

test('bayesian reports an error radius and a mirror candidate on a straight route', () => {
  const est = estimateBayesian(collect(STRAIGHT));
  assert.ok(est.errorRadiusM != null && est.errorRadiusM > 0, 'an error radius is required');
  assert.ok(est.confidence != null && est.confidence > 0 && est.confidence < 100);
  assert.ok(est.mirrorCandidate || est.geometry.mirrorAmbiguous,
    'a straight route must surface the mirror ambiguity');
});

test('a bimodal posterior widens the stated uncertainty to cover both modes', () => {
  // The failure this guards against: on a straight pass the fit is tight around
  // whichever side it picked (~15 m) while being a near coin flip between two
  // positions ~80 m apart. Reporting 15 m there would be a false precision.
  const errs = [];
  let sawMirror = false;
  for (let t = 0; t < 10; t++) {
    const est = estimateBayesian(collect(STRAIGHT, { seed: 11 + t * 97 }));
    if (!est.mirrorCandidate) continue;
    sawMirror = true;
    const trueErr = errM(est.lat, est.lon);
    errs.push(trueErr);
    assert.ok(est.mirrorDistanceM > 0, 'a mirror candidate needs a distance');
    assert.ok(est.errorRadiusM >= est.mirrorDistanceM,
      `stated radius ${est.errorRadiusM?.toFixed(1)} m must cover the ${est.mirrorDistanceM?.toFixed(1)} m mirror separation`);
    assert.ok(est.modeRadiusM <= est.errorRadiusM,
      'the per-mode spread should be the tighter of the two numbers');
    assert.match(est.notes.join(' '), /two candidates|mirrored/i);
  }
  assert.ok(sawMirror, 'a straight pass should produce a mirror candidate');
  // The whole point: the stated radius must not be smaller than the error we
  // actually make when the coin lands badly.
  const worst = Math.max(...errs);
  const est = estimateBayesian(collect(STRAIGHT));
  assert.ok(est.errorRadiusM >= worst * 0.8,
    `worst observed error ${worst.toFixed(0)} m against a stated radius of ${est.errorRadiusM?.toFixed(0)} m`);
});

test('the error radius actually reflects the difficulty of the fit', () => {
  const easy = estimateBayesian(collect(L_SHAPED));
  const hard = estimateBayesian(collect(STRAIGHT));
  assert.ok(easy.errorRadiusM <= hard.errorRadiusM,
    `a well-constrained route (${easy.errorRadiusM?.toFixed(1)} m) should not report a larger radius than a straight one (${hard.errorRadiusM?.toFixed(1)} m)`);
});

test('confidence matches the mapping the report documents', () => {
  // These anchors are printed in the method appendix, so they are part of the
  // contract with the reader and must not drift silently.
  const expected = [[5, 95], [10, 79], [25, 58], [50, 42], [100, 26], [250, 5]];
  for (const [radius, want] of expected) {
    const got = radiusToConfidence(radius);
    assert.ok(Math.abs(got - want) <= 1,
      `radius ${radius} m should read ~${want}, got ${got}`);
  }
  // And it must be monotone, or the display would be misleading.
  const confs = [2, 5, 10, 25, 50, 100, 250].map(radiusToConfidence);
  for (let i = 1; i < confs.length; i++) {
    assert.ok(confs[i] < confs[i - 1], `confidence rose from ${confs[i - 1]} to ${confs[i]}`);
  }
});

test('the published methodology matches the code that produced the numbers', () => {
  // This caught a real drift: the methodology string kept an older confidence
  // formula after the function changed, so a reader following it would have
  // converted the report's own figures back to the wrong distances. The report
  // is only auditable if the stated method is the one that actually ran.
  const m = describeLocalizationMethodology();

  for (const { radius_m, confidence } of m.confidence_scale) {
    assert.equal(confidence, radiusToConfidence(radius_m),
      `published scale disagrees with radiusToConfidence at ${radius_m} m`);
  }

  // The printed formula has to reproduce the function, not merely resemble it.
  const match = m.confidence_formula.match(/100 - ([\d.]+) \* log10\(max\(1, radius_m\) \/ ([\d.]+)\)/);
  assert.ok(match, `formula not in the expected form: ${m.confidence_formula}`);
  const [, k, divisor] = match.map(Number);
  for (const radius of [2, 7, 18, 60, 140]) {
    const fromFormula = Math.max(1, Math.min(99,
      Math.round(100 - k * Math.log10(Math.max(1, radius) / divisor))));
    assert.equal(fromFormula, radiusToConfidence(radius),
      `published formula gives ${fromFormula} at ${radius} m, code gives ${radiusToConfidence(radius)}`);
  }

  assert.ok(m.limitations.length >= 3, 'the limitations must travel with the method');
  assert.match(m.confidence_meaning, /not a probability/i);
});

test('too few sightings falls back to the peak and says so', () => {
  const history = [{ lat: AP_LAT, lon: AP_LON, rssi: -50 }];
  for (const est of [estimateBayesian(history), estimateTrilateration(history)]) {
    assert.match(est.notes.join(' '), /at least three|too few|strongest sighting/i);
  }
});

test('an empty history never throws', () => {
  for (const fn of [estimateBayesian, estimateTrilateration, estimateTrackPosition, estimatePeak]) {
    const est = fn([]);
    assert.ok(Number.isFinite(est.lat) && Number.isFinite(est.lon));
  }
});

// ── The transmitter's unknown power ─────────────────────────────────────────
//
// Everything above simulates a transmitter whose power is exactly the constant
// the estimator assumes, which makes it a test of the search rather than of the
// model. Real access points are nowhere near that uniform: a ceiling-mounted
// enterprise AP against a phone hotspot is well over 10 dB of EIRP apart before
// antenna gain, and a passive survey cannot tell which it is looking at.
//
// A power error does not merely widen the answer, it moves it — every modelled
// distance scales by the same factor and the fit slides the transmitter toward
// or away from the road to compensate.

/** As `sampleAt`, but the real transmitter is `powerOffsetDb` off the reference. */
function sampleAtPower(rng, lat, lon, powerOffsetDb, { frequency = 2437, sigmaDb = 6 } = {}) {
  const dx = (lon - AP_LON) * M_LON;
  const dy = (lat - AP_LAT) * M_PER_DEG_LAT;
  const d = Math.max(1, Math.hypot(dx, dy));
  const rssi = referencePowerDbm(frequency) + powerOffsetDb - 25 * Math.log10(d) + gauss(rng, sigmaDb);
  return rssi < -95 ? null : { lat, lon, rssi: Math.round(rssi), frequency };
}

function collectAtPower(points, powerOffsetDb, seed) {
  const rng = mulberry32(seed);
  let history = [];
  for (const [lat, lon] of points) {
    const s = sampleAtPower(rng, lat, lon, powerOffsetDb);
    if (s) history = mergeObservation(history, s, 100);
  }
  return history;
}

/** Median error and radius coverage over many noise draws and power offsets. */
function survey(points, { trials = 120, powerSpreadDb = 6, estimator = estimateBayesian } = {}) {
  const errors = [];
  let covered = 0, withRadius = 0;
  for (let t = 0; t < trials; t++) {
    const rng = mulberry32(5000 + t * 7919);
    const offset = gauss(rng, powerSpreadDb);
    let history = [];
    for (const [lat, lon] of points) {
      const s = sampleAtPower(rng, lat, lon, offset);
      if (s) history = mergeObservation(history, s, 100);
    }
    if (history.length < 3) continue;
    const e = estimator(history);
    const err = errM(e.lat, e.lon);
    errors.push(err);
    if (typeof e.errorRadiusM === 'number') {
      withRadius++;
      // A bimodal answer is covered when either candidate is within the radius.
      let best = err;
      if (e.mirrorCandidate) best = Math.min(best, errM(e.mirrorCandidate.lat, e.mirrorCandidate.lon));
      if (best <= e.errorRadiusM) covered++;
    }
  }
  errors.sort((a, b) => a - b);
  return {
    median: errors[Math.floor(errors.length / 2)],
    coverage: withRadius ? covered / withRadius : NaN,
  };
}

test('the method states how it handles the transmitter power it cannot know', () => {
  // This travels into the report's method appendix. A radius that silently
  // depends on an unstated assumption is the thing this whole section exists
  // to prevent.
  const m = describeLocalizationMethodology();
  assert.equal(m.tx_power_prior_db, POWER_PRIOR_DB);
  assert.equal(m.tx_power_spread_db, TX_POWER_SPREAD_DB);
  assert.match(m.tx_power_handling, /not known/i);
  assert.ok(m.limitations.some(l => /reference power/i.test(l)));
});

test('the stated radius still covers the truth when the transmit power is unknown', () => {
  /*
    The defect this pins, measured before the fix on the route with one turn:

        power exactly as assumed   98% coverage
        3 dB of spread             77%
        6 dB                       52%
        10 dB                      43%

    The report prints that radius as "roughly 95% of the posterior". At 6 dB it
    was covering half the time — and 6 dB is the ordinary case, not a bad day.
  */
  for (const spread of [0, 3, 6]) {
    const r = survey(L_SHAPED, { powerSpreadDb: spread });
    assert.ok(r.coverage >= 0.85,
      `at ${spread} dB of transmit-power spread the stated 95% radius covered only `
      + `${(r.coverage * 100).toFixed(0)}% of runs`);
  }
});

test('unknown transmit power does not wreck the position either', () => {
  // Median error on the turn route was 18.1 m at 6 dB of spread and 25.3 m at
  // 10 dB before the power was allowed any slack.
  assert.ok(survey(L_SHAPED, { powerSpreadDb: 6 }).median < 16,
    'the fit should absorb a few dB rather than sliding the transmitter to compensate');
  assert.ok(survey(L_SHAPED, { powerSpreadDb: 10 }).median < 20);
});

test('a known transmit power is not paid for too dearly', () => {
  // Giving the power slack costs a little when the assumption happens to hold.
  // Recorded so the trade is visible if the prior is ever changed.
  const r = survey(L_SHAPED, { powerSpreadDb: 0 });
  assert.ok(r.median < 14, `median ${r.median.toFixed(1)} m with the power exactly as assumed`);
  assert.ok(r.coverage >= 0.95);
});

test('the radius grows with distance from the measurements, not as a flat margin', () => {
  /*
    A power error scales every modelled distance by the same factor, so the
    positional error it induces is proportional to how far the estimate already
    is from the sightings: negligible beside the road, dominant a long way off.
    A flat margin would be wrong in both directions.
  */
  const near = collectAtPower(eastWestLeg(-12, -150, 150, 40), 0, 4242);
  const far = collectAtPower(eastWestLeg(-90, -150, 150, 40), 0, 4242);
  const nearRadius = estimateBayesian(near).modeRadiusM;
  const farRadius = estimateBayesian(far).modeRadiusM;
  assert.ok(nearRadius !== null && farRadius !== null);
  assert.ok(farRadius > nearRadius,
    `radius should widen with range: ${nearRadius?.toFixed(1)} m at 12 m out, `
    + `${farRadius?.toFixed(1)} m at 90 m out`);
});

test('an unbounded power prior is a limit, not a division that yields NaN', () => {
  /*
    `shrink = n*tau^2 / (n*tau^2 + sigma^2)` is 1 in the limit, but evaluates to
    `Infinity / Infinity` = NaN if written literally. Every `ll > best`
    comparison against NaN is false, so the grid search keeps its starting point
    and returns the centre of the route — a plausible coordinate produced by a
    search that never ran. It was measured at exactly the route's perpendicular
    offset before this was caught.
  */
  const history = collectAtPower(STRAIGHT, 0, 99);
  const est = estimateBayesian(history, { powerPriorDb: Infinity });
  assert.ok(Number.isFinite(est.lat) && Number.isFinite(est.lon));
  assert.ok(Number.isFinite(est.errorRadiusM ?? NaN), 'a NaN likelihood surface yields no radius');
  // And it must not be sitting exactly on the route, which is what the failed
  // search returned.
  const offsetFromRoute = Math.abs((est.lat - (AP_LAT - 40 / M_PER_DEG_LAT)) * M_PER_DEG_LAT);
  assert.ok(offsetFromRoute > 1, 'the estimate collapsed onto the route');
});
