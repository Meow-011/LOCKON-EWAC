/**
 * Bundle entry for the GPS acceptance gate.
 *
 * The store holds the gate and `localization.ts` holds the rule it applies, and
 * the tests have to reach both: asserting that a parked receiver does not drift
 * needs the store, and asserting that the floor is derived from the fix's own
 * HDOP rather than from a constant needs the function that derives it.
 *
 * Re-exported together rather than bundled separately so the test sees the same
 * `gpsStepFloorM` the store calls, instead of a second copy that could agree with
 * the test while disagreeing with the application.
 */
export { useEngineStore } from '../../src/stores/engineStore';
export { gpsStepFloorM, GPS_STEP_M, GPS_UERE_M } from '../../src/lib/localization';
