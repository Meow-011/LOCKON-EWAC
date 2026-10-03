/**
 * Standing still is not travelling.
 *
 *     npm run test:gps
 *
 * Why this exists.
 *
 * A consumer GPS receiver scatters a few metres while stationary. The track
 * already refused to record that as travel — a fix is appended only once it is
 * `GPS_STEP_M` from the last one — and the troubleshooting guide said the
 * vehicle marker had been fixed in v1.0.0 along with it.
 *
 * It had not. `setGpsFix` wrote the raw pair into the store on every fix, and the
 * marker was drawn straight from it, so parked the car crawled around the map,
 * span on the spot, and with auto-follow on dragged the whole map with it. Three
 * symptoms, one cause, and a documented fix that covered the track and nothing
 * else — which is worse than no note, because it closes the question.
 *
 * The gate now lives in the store, so everything that draws a *position* gets
 * the accepted one and everything that reports on the *fix* still gets the raw
 * one. These tests pin that split, because collapsing it either way is an easy
 * and invisible change: make them all raw and the drift returns; make them all
 * accepted and the satellite readout starts lying about what the receiver said.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  useEngineStore,
  gpsStepFloorM,
  GPS_STEP_M,
  GPS_UERE_M,
} from '../.test-build/engineStore.mjs';

/** Roughly 1 m of latitude, which is far below the 5 m floor. */
const ONE_METRE_LAT = 1 / 110_574;

function reset() {
  useEngineStore.setState({
    latitude: null, longitude: null, heading: null,
    acceptedLatitude: null, acceptedLongitude: null, acceptedHeading: null,
    speed: null, satellites: null, hdop: null, gpsLocked: false,
  });
}

test('the first fix is accepted, because there is nothing to be noise around', () => {
  reset();
  useEngineStore.getState().setGpsFix({ latitude: 13.7563, longitude: 100.5018, heading: 90 });
  const s = useEngineStore.getState();
  assert.equal(s.acceptedLatitude, 13.7563);
  assert.equal(s.acceptedHeading, 90);
});

test('scatter below the floor does not move the accepted position', () => {
  /*
    The defect, as an operator meets it: parked, and the car crawls around the
    map. One archived survey held 280 fixes spanning 9.9 m end to end.
  */
  reset();
  const { setGpsFix } = useEngineStore.getState();
  setGpsFix({ latitude: 13.7563, longitude: 100.5018, heading: 90 });

  for (let i = 1; i <= 20; i++) {
    // A metre either side, which is what a stationary receiver does.
    setGpsFix({
      latitude: 13.7563 + (i % 2 ? 1 : -1) * ONE_METRE_LAT * 2,
      longitude: 100.5018,
      heading: (i * 47) % 360,
    });
  }

  const s = useEngineStore.getState();
  assert.equal(s.acceptedLatitude, 13.7563, 'the accepted position drifted');
  assert.equal(s.acceptedHeading, 90, 'the accepted heading followed the noise');
});

test('a real step moves it', () => {
  reset();
  const { setGpsFix } = useEngineStore.getState();
  setGpsFix({ latitude: 13.7563, longitude: 100.5018, heading: 90 });

  const moved = 13.7563 + ONE_METRE_LAT * 10;   // 10 m, twice the floor
  setGpsFix({ latitude: moved, longitude: 100.5018, heading: 180 });

  const s = useEngineStore.getState();
  assert.equal(s.acceptedLatitude, moved);
  assert.equal(s.acceptedHeading, 180);
});

test('the raw fix still follows every report', () => {
  /*
    The other half of the split, and the one a careless simplification breaks.
    Satellite count, HDOP and the coordinate readout are facts *about the fix*;
    holding them back would make the quality panel describe a fix the receiver
    is no longer reporting.
  */
  reset();
  const { setGpsFix } = useEngineStore.getState();
  setGpsFix({ latitude: 13.7563, longitude: 100.5018, satellites: 9, hdop: 0.9 });

  const nudged = 13.7563 + ONE_METRE_LAT;
  setGpsFix({ latitude: nudged, longitude: 100.5018, satellites: 7, hdop: 1.4 });

  const s = useEngineStore.getState();
  assert.equal(s.latitude, nudged, 'the raw position was gated, which it must not be');
  assert.equal(s.satellites, 7);
  assert.equal(s.hdop, 1.4);
  // And the accepted one did not follow it.
  assert.equal(s.acceptedLatitude, 13.7563);
});

test('a heading is held, not cleared, when a fix carries none', () => {
  // A receiver that drops the course field should not swing the icon to north.
  reset();
  const { setGpsFix } = useEngineStore.getState();
  setGpsFix({ latitude: 13.7563, longitude: 100.5018, heading: 270 });
  setGpsFix({ latitude: 13.7563 + ONE_METRE_LAT * 10, longitude: 100.5018, heading: null });

  assert.equal(useEngineStore.getState().acceptedHeading, 270);
});

test('many small steps do not add up to movement', () => {
  /*
    The trap in gating against the *last accepted* position rather than the last
    raw one: 1 m at a time in the same direction is a real walk, and gating
    against the previous raw fix would reject every step of it for ever. Gating
    against the accepted position lets the fifth metre through.
  */
  reset();
  const { setGpsFix } = useEngineStore.getState();
  setGpsFix({ latitude: 13.7563, longitude: 100.5018 });

  for (let i = 1; i <= 6; i++) {
    setGpsFix({ latitude: 13.7563 + ONE_METRE_LAT * i, longitude: 100.5018 });
  }

  // Six metres walked in one direction is movement and must be accepted.
  assert.ok(
    useEngineStore.getState().acceptedLatitude > 13.7563,
    'a slow walk never moved the marker'
  );
});


// ── The floor is the one the fix can support ───────────────────────────────

test('a poor fix has to travel as far as its own error before it counts', () => {
  /*
    The drift came back, and the reason was an arithmetic mismatch between two
    numbers nobody had put side by side. The engine accepts any fix up to
    `HDOP 5.0` (`_validate_gps` in `engine/ipc/handler.py`), and the frontend
    called anything past a flat 5 m "movement". At HDOP 5 the horizontal error is
    about `5 x 5 = 25 m` at one sigma -- so a parked receiver on a mediocre fix
    produced jumps several times the floor, and every one of them was accepted.

    A fix good enough to be worth 5 m of precision has HDOP near 1, and there
    nothing changes.
  */
  assert.equal(gpsStepFloorM(1), GPS_STEP_M, 'a good fix keeps the original floor');
  assert.equal(gpsStepFloorM(0.8), GPS_STEP_M, 'and a better one is not tightened below it');
  assert.equal(gpsStepFloorM(2), 2 * GPS_UERE_M);
  assert.equal(gpsStepFloorM(5), 5 * GPS_UERE_M, 'the worst fix the engine accepts');
  // Monotone: a worse fix can never require a shorter step than a better one.
  let last = 0;
  for (const h of [0.5, 1, 1.5, 2, 3, 4, 5]) {
    const f = gpsStepFloorM(h);
    assert.ok(f >= last, `HDOP ${h} asked for ${f} m after ${last} m`);
    last = f;
  }
});

test('an unreported quality falls back to the constant, not to no gate at all', () => {
  /*
    `gps/reader.py` writes `hdop` only in the GGA branch and sets it to None
    otherwise, precisely because an RMC-only receiver used to leave the key
    missing and the caller read it as a measured, ideal 0. Neither absence may
    become a licence to accept every fix, and neither may be turned into an
    invented quality figure.
  */
  for (const absent of [null, undefined, 0, NaN, Infinity, -1, 'abc']) {
    assert.equal(gpsStepFloorM(absent), GPS_STEP_M, String(absent));
  }
});

test('a parked receiver on a poor fix does not crawl', () => {
  /*
    The defect as the operator met it, twice. 12 m of scatter is well inside what
    HDOP 4 describes and was more than twice the old flat floor, so the marker
    walked, auto-follow dragged the map after it, and the track recorded the walk.
  */
  reset();
  const { setGpsFix } = useEngineStore.getState();
  setGpsFix({ latitude: 13.7563, longitude: 100.5018, heading: 90, hdop: 4 });

  for (let i = 1; i <= 30; i++) {
    setGpsFix({
      latitude: 13.7563 + (i % 2 ? 1 : -1) * ONE_METRE_LAT * 12,
      longitude: 100.5018,
      heading: (i * 53) % 360,
      hdop: 4,
    });
  }

  const st = useEngineStore.getState();
  assert.equal(st.acceptedLatitude, 13.7563, 'the marker drifted on a poor fix');
  assert.equal(st.acceptedHeading, 90, 'the heading followed the noise');
  // And the raw fix still reports what the receiver said, including its quality.
  assert.equal(st.hdop, 4);
  assert.notEqual(st.latitude, 13.7563);
});

test('the same scatter on a good fix is still movement', () => {
  /*
    The floor must not simply be raised. 12 m at HDOP 1 is further than that fix's
    own error, so it is travel and refusing it would be the opposite defect --
    a tool that cannot follow a vehicle because it over-corrected for noise.
  */
  reset();
  const { setGpsFix } = useEngineStore.getState();
  setGpsFix({ latitude: 13.7563, longitude: 100.5018, hdop: 1 });
  setGpsFix({ latitude: 13.7563 + ONE_METRE_LAT * 12, longitude: 100.5018, hdop: 1 });

  assert.ok(
    useEngineStore.getState().acceptedLatitude > 13.7563,
    'a real 12 m step on a good fix was rejected'
  );
});

test('the quality of the fix in hand decides, not the one before it', () => {
  /*
    Fix quality changes during a survey -- under a bridge, between buildings. The
    floor is taken from the fix being judged, so a receiver that recovers starts
    tracking again immediately rather than staying stuck behind the floor its
    worst fix deserved.
  */
  reset();
  const { setGpsFix } = useEngineStore.getState();
  setGpsFix({ latitude: 13.7563, longitude: 100.5018, hdop: 5 });
  // 8 m under HDOP 5 is noise: the floor is 25 m.
  setGpsFix({ latitude: 13.7563 + ONE_METRE_LAT * 8, longitude: 100.5018, hdop: 5 });
  assert.equal(useEngineStore.getState().acceptedLatitude, 13.7563);

  // The same 8 m once the fix recovers is movement.
  setGpsFix({ latitude: 13.7563 + ONE_METRE_LAT * 8, longitude: 100.5018, hdop: 1 });
  assert.ok(useEngineStore.getState().acceptedLatitude > 13.7563);
});
