/** LOCKON EWAC — Mission & Scan Data State */
import { create } from 'zustand';
import { useEngineStore } from './engineStore';
import type { Mission, AccessPoint, ScanLog } from '../types/models';

/**
 * Location estimation lives in src/lib/localization.ts.
 *
 * It was moved out of this store because it is numerical code that needed
 * testing against known ground truth — and when it was tested, the weighted
 * centroid turned out to be mathematically unable to leave the surveyed road,
 * the trilateration solver was stopping at two thirds of its correction, and
 * part of every trilaterated coordinate was derived from a hash of the BSSID.
 * A state container is the wrong place for that to hide.
 *
 * Re-exported here so existing importers keep working.
 */
export type { Observation, LocationEstimate, LocationMethod } from '../lib/localization';
export {
  estimateLocation,
  estimateBayesian,
  estimateTrilateration,
  estimateTrackPosition,
  estimatePeak,
  assessGeometry,
  mergeObservation,
  selectDiverse,
  radiusToConfidence,
} from '../lib/localization';

import {
  estimateLocation,
  mergeObservation,
  type Observation,
  type LocationEstimate,
  type LocationMethod,
} from '../lib/localization';

/**
 * Sightings retained per AP during a live sweep.
 *
 * Raised from 20. The old cap also selected the wrong points — strongest first,
 * which discards the distant weak readings that tell the model how far away the
 * transmitter is. Measured effect at a cap of 20 with that rule: the retained
 * signal range collapsed from 23 dB to 9 dB and the error nearly doubled.
 * selectDiverse now keeps the spread, so a larger cap costs little.
 */
const LIVE_HISTORY_CAP = 60;

/** How often the expensive estimators may re-run for one AP, in milliseconds. */
const REESTIMATE_INTERVAL_MS = 2000;
/** ...or immediately once this many new sightings have accumulated. */
const REESTIMATE_EVERY_N_OBSERVATIONS = 8;

/**
 * Milliseconds of estimation allowed per second of live scanning.
 *
 * A per-AP time throttle is not enough on its own: the cost scales with how many
 * access points are in range, and a dense city block is exactly where the rig
 * is busiest. Measured at 6 ms per grid search, 200 access points refreshed
 * every 2 s would take half a core continuously, on the same thread that draws
 * the map.
 *
 * A budget bounds the work no matter how many APs are in range. When it runs
 * out, the remaining access points keep the position they already had and get
 * refreshed on a later batch — their true position is not moving.
 */
const ESTIMATE_BUDGET_MS_PER_SECOND = 60;

let budgetWindowStart = 0;
let budgetSpentMs = 0;

function takeEstimateBudget(): boolean {
  const now = Date.now();
  if (now - budgetWindowStart >= 1000) {
    budgetWindowStart = now;
    budgetSpentMs = 0;
  }
  return budgetSpentMs < ESTIMATE_BUDGET_MS_PER_SECOND;
}

function chargeEstimateBudget(ms: number) {
  budgetSpentMs += ms;
}

/**
 * Throttle the costly estimators.
 *
 * The grid search runs a few thousand likelihood evaluations. Re-running it for
 * every access point on every scan batch is what made the dashboard stutter
 * with a busy spectrum; the position barely moves between consecutive sightings
 * anyway. Cheap estimators are never throttled.
 */
function shouldReestimate(
  method: LocationMethod,
  historyLength: number,
  lastCount: number,
  lastAt: number
): boolean {
  if (method !== 'bayesian_grid' && method !== 'trilateration') return true;
  if (lastAt === 0) return true;                       // never estimated
  if (historyLength <= 6) return true;                 // cheap at this size
  if (!takeEstimateBudget()) return false;             // out of budget this second
  if (historyLength - lastCount >= REESTIMATE_EVERY_N_OBSERVATIONS) return true;
  return Date.now() - lastAt >= REESTIMATE_INTERVAL_MS;
}

/** Run an estimate and charge what it cost against the budget. */
function runEstimate(history: Observation[], method: LocationMethod): LocationEstimate {
  const started = performance.now();
  const estimate = estimateLocation(history, method);
  chargeEstimateBudget(performance.now() - started);
  return estimate;
}

/**
 * The signal reading on this record, or null when there is not one.
 *
 * This replaces `ap.rssi ?? -100`, which put a fabricated -100 dBm into the
 * sighting history — and the history is exactly what the estimators work from.
 * An access point with no signal reading therefore still produced a coordinate,
 * an error radius and a confidence percentage, all of which the report prints as
 * measured values. A sighting with no signal is not a sighting the localizer can
 * use, so it is not recorded as one.
 */
function readingOf(ap: any): number | null {
  return typeof ap?.rssi === 'number' && Number.isFinite(ap.rssi) ? ap.rssi : null;
}

/** Latest non-empty value wins; otherwise keep what we had. */
function freshest<T>(incoming: T | null | undefined, existing: T | null | undefined): T | null {
  if (incoming === null || incoming === undefined) return existing ?? null;
  if (typeof incoming === 'string' && incoming === '') return existing ?? null;
  return incoming;
}

/** Sticky flag: once true for this AP it stays true, matching the DB's MAX(). */
function sticky(incoming: unknown, existing: unknown): boolean {
  return !!existing || !!incoming;
}

/**
 * Merge one engine-supplied access point record onto the one already in the map.
 *
 * Both callers (`addAccessPoint` and `addAccessPoints`) used to inline this, and
 * both listed only ten fields to re-apply: ssid, vendor, encryption,
 * is_vulnerable, first_seen, last_seen, channel, rssi, latitude, longitude.
 * Everything else on the *incoming* record was dropped, because the spread was
 * `...existing` and nothing re-applied it — including `rogue_verdict`,
 * `rogue_score`, `rogue_indicators`, `is_evil_twin`, `rssi_trend`, `cipher`,
 * `auth_type`, `radio_type`, `connected_stations`, `channel_utilization_pct`,
 * `band` and `frequency`.
 *
 * That interacted badly with how the engine is deliberately built. Rogue scoring
 * runs over the whole session cache rather than the current batch, because "a
 * twin is only visible relative to its peers, so a per-batch view would miss
 * pairs split across scans" (engine/ipc/handler.py). The verdict therefore
 * *upgrades* on a later cycle than first sighting — exactly the update that was
 * being discarded. An AP first seen as CLEAR stayed CLEAR forever.
 *
 * The archive is built from this store, while `wardrivingDB.logAccessPoint`
 * writes the raw engine record to SQLite and keeps the highest-scoring verdict.
 * So the database held the correct verdict and the exported report did not, and
 * the report was the one that was wrong.
 *
 * The rules below deliberately mirror that table's ON CONFLICT clause, so the
 * two can no longer disagree:
 *
 *   - a better-informed rogue verdict wins, decided by score, never by recency
 *     (a later scan that happened to see fewer peers must not erase it);
 *   - `is_evil_twin` and `is_vulnerable` are sticky, like the DB's MAX();
 *   - `simulated` is cleared by a real sighting, like the DB's MIN();
 *   - everything else takes the freshest non-empty value.
 *
 * Position fields are NOT handled here: they are computed from the sighting
 * history by the caller.
 */
function mergeEngineFields(existing: any, ap: any): Record<string, unknown> {
  // A later verdict is only better if the engine had at least as much to go on,
  // which its score is the proxy for. Ties go to the incoming record.
  const existingScore = typeof existing?.rogue_score === 'number' ? existing.rogue_score : -1;
  const incomingScore = typeof ap?.rogue_score === 'number' ? ap.rogue_score : -1;
  const takeIncomingRogue = incomingScore >= existingScore;

  return {
    ssid: ap.ssid || existing.ssid,
    vendor: ap.vendor || existing.vendor,
    encryption: ap.encryption || existing.encryption,
    cipher: freshest(ap.cipher, existing.cipher),
    auth_type: freshest(ap.auth_type, existing.auth_type),
    radio_type: freshest(ap.radio_type, existing.radio_type),
    band: freshest(ap.band, existing.band),
    frequency: freshest(ap.frequency, existing.frequency),
    channel: ap.channel ?? existing.channel,
    connected_stations: freshest(ap.connected_stations, existing.connected_stations),
    channel_utilization_pct: freshest(ap.channel_utilization_pct, existing.channel_utilization_pct),
    rssi_trend: freshest(ap.rssi_trend, existing.rssi_trend),
    first_seen: existing.first_seen || ap.first_seen,
    last_seen: ap.last_seen || existing.last_seen,
    rssi: ap.rssi,

    // Sticky: the worst state observed for this AP is the one that belongs in a
    // report, and it is what the database already keeps.
    is_vulnerable: sticky(ap.is_vulnerable, existing.is_vulnerable),
    is_evil_twin: sticky(ap.is_evil_twin, existing.is_evil_twin),

    // The three rogue fields move together or not at all — a verdict without its
    // own score and indicators cannot be explained to a reader.
    rogue_verdict: takeIncomingRogue
      ? freshest(ap.rogue_verdict, existing.rogue_verdict)
      : existing.rogue_verdict,
    rogue_score: Math.max(existingScore, incomingScore) >= 0
      ? Math.max(existingScore, incomingScore)
      : undefined,
    rogue_indicators: takeIncomingRogue
      ? freshest(ap.rogue_indicators, existing.rogue_indicators)
      : existing.rogue_indicators,

    // A real sighting clears a simulated-only record; a simulated one never
    // downgrades an AP that has been seen for real.
    simulated: existing.simulated === false || ap.simulated === false
      ? false
      : sticky(ap.simulated, existing.simulated),
  };
}

interface MissionState {
  activeMission: Mission | null;
  /** Survives stopMission, so an archive taken afterwards can still be tied to
   *  its mission for coverage reporting. */
  lastMissionId: string | null;
  accessPoints: Map<string, AccessPoint>;
  recentLogs: ScanLog[];
  totalAPs: number;
  highRiskCount: number;
  openNetworks: number;
  evilTwinCount: number;
  elapsedSeconds: number;
  pathCoords: [number, number][];
  viewingMissionId: string | null;

  // Actions
  startMission: (mission: Mission) => void;
  stopMission: () => void;
  addAccessPoint: (ap: AccessPoint) => void;
  addAccessPoints: (aps: AccessPoint[]) => void;
  /**
   * Apply the result of a WPS scan to the access points already in the map.
   *
   * WPS does not arrive with `aps_batch`; it comes from a separate `scan_wps`
   * run that parses beacon information elements. Only access points whose
   * beacon was parsed are touched, and each gets `wps_scanned_at` — without
   * that timestamp a `wps_enabled: false` cannot be told apart from an access
   * point the scan never covered, which is exactly the confusion that had the
   * report describing a beacon parse that never ran.
   */
  applyWpsMeasurements: (
    measurements: { bssid: string; wps_enabled: boolean; wps_locked: boolean; wps_version?: string | null }[],
    measuredAt: string
  ) => void;
  addScanLog: (log: ScanLog) => void;
  incrementElapsed: () => void;
  appendPathCoord: (coord: [number, number]) => void;
  loadArchive: (missionId: string, aps: AccessPoint[], path: [number, number][]) => void;
  clearArchive: () => void;
  reset: () => void;
}

const MAX_RECENT_LOGS = 50;

const initialState = {
  activeMission: null as Mission | null,
  lastMissionId: null as string | null,
  accessPoints: new Map<string, AccessPoint>(),
  recentLogs: [] as ScanLog[],
  totalAPs: 0,
  highRiskCount: 0,
  openNetworks: 0,
  evilTwinCount: 0,
  elapsedSeconds: 0,
  pathCoords: [] as [number, number][],
  viewingMissionId: null as string | null,
};

export const useMissionStore = create<MissionState>((set) => ({
  ...initialState,

  startMission: (mission) => set({
    activeMission: mission,
    lastMissionId: mission.id,
    accessPoints: new Map(),
    recentLogs: [],
    totalAPs: 0,
    highRiskCount: 0,
    openNetworks: 0,
    evilTwinCount: 0,
    elapsedSeconds: 0,
    pathCoords: [],
    viewingMissionId: null,
  }),

  // The collected APs deliberately survive stopMission so the operator can still
  // archive after ending a run. Keep the id too: survey coverage is keyed on it,
  // and the Archive button only appears once there is no active mission — so
  // reading activeMission at archive time would always have found null.
  stopMission: () => set((state) => ({
    activeMission: null,
    lastMissionId: state.activeMission?.id ?? state.lastMissionId,
  })),

  addAccessPoint: (ap) => set((state) => {
    const newMap = new Map(state.accessPoints);
    const existing = newMap.get(ap.bssid);

    if (!existing) {
      // First sighting. The running power-weighted sums this used to keep are
      // gone: they implemented the centroid that could never leave the driven
      // path, and the estimators now work from the sighting history directly.
      const hasGps = ap.latitude != null && ap.longitude != null;
      // No reading, no observation. See readingOf.
      const reading = readingOf(ap);
      newMap.set(ap.bssid, {
        ...ap,
        _peakRssi: reading,
        _history: hasGps && reading !== null
          ? [{ lat: ap.latitude!, lon: ap.longitude!, rssi: reading, frequency: ap.frequency ?? null }]
          : [],
        _lastEstimateAt: 0,
        _lastEstimateCount: 0,
        _estimate: null,
      } as any);
    } else {
      const incomingHasLocation = ap.latitude != null && ap.longitude != null;
      const existingHasLocation = existing.latitude != null && existing.longitude != null;
      // @ts-ignore  null until this AP has produced a real reading.
      const peakRssi: number | null = existing._peakRssi ?? null;
      const reading = readingOf(ap);
      const method = useEngineStore.getState().config.locationMethod;

      // @ts-ignore
      let history: Observation[] = existing._history || [];
      // @ts-ignore
      const lastEstimateAt: number = existing._lastEstimateAt ?? 0;
      // @ts-ignore
      const lastEstimateCount: number = existing._lastEstimateCount ?? 0;

      // A position needs a signal to be estimated from, so a sighting without a
      // reading is not added to the history at all.
      if (incomingHasLocation && reading !== null) {
        history = mergeObservation(
          history,
          { lat: ap.latitude!, lon: ap.longitude!, rssi: reading, frequency: ap.frequency ?? null },
          LIVE_HISTORY_CAP
        );
      }

      let newLat = existing.latitude;
      let newLon = existing.longitude;
      let newPeak = peakRssi;
      // @ts-ignore
      let estimate: LocationEstimate | null = existing._estimate ?? null;
      let estimatedAt = lastEstimateAt;
      let estimatedCount = lastEstimateCount;

      if (reading !== null && (peakRssi === null || reading > peakRssi)) newPeak = reading;

      if (history.length === 0) {
        // Nothing positioned yet; leave whatever we had.
      } else if (shouldReestimate(method, history.length, lastEstimateCount, lastEstimateAt)) {
        estimate = runEstimate(history, method);
        estimatedAt = Date.now();
        estimatedCount = history.length;
        newLat = estimate.lat;
        newLon = estimate.lon;
      } else if (estimate) {
        newLat = estimate.lat;
        newLon = estimate.lon;
      } else if (
        incomingHasLocation && reading !== null
        && (!existingHasLocation || peakRssi === null || reading >= peakRssi)
      ) {
        newLat = ap.latitude!;
        newLon = ap.longitude!;
      }

      newMap.set(ap.bssid, {
        ...existing,
        ...mergeEngineFields(existing, ap),
        latitude: newLat,
        longitude: newLon,
        // @ts-ignore
        _estimate: estimate,
        // @ts-ignore
        _lastEstimateAt: estimatedAt,
        // @ts-ignore
        _lastEstimateCount: estimatedCount,
        location_method: estimate?.method ?? undefined,
        // False only when the geometry could not constrain a position at all.
        // The map draws those differently rather than letting an unconstrained
        // guess sit among measured positions looking identical to them.
        location_resolved: estimate ? estimate.resolved !== false : true,
        location_confidence: estimate?.confidence ?? null,
        location_error_m: estimate?.errorRadiusM ?? null,
        location_mode_error_m: estimate?.modeRadiusM ?? null,
        geometry_ambiguous: estimate?.geometry.mirrorAmbiguous ? 1 : 0,
        location_mirror_lat: estimate?.mirrorCandidate?.lat ?? null,
        location_mirror_lon: estimate?.mirrorCandidate?.lon ?? null,
        location_mirror_distance_m: estimate?.mirrorDistanceM ?? null,
        // @ts-ignore
        _peakRssi: newPeak,
        // @ts-ignore
        _history: history,
      } as any);
    }

    let highRiskCount = 0;
    let openNetworks = 0;
    for (const a of newMap.values()) {
      if (a.is_vulnerable) highRiskCount++;
      if (a.encryption === 'OPEN') openNetworks++;
    }

    return {
      accessPoints: newMap,
      totalAPs: newMap.size,
      highRiskCount,
      openNetworks,
      evilTwinCount: state.evilTwinCount,
    };
  }),

  applyWpsMeasurements: (measurements, measuredAt) => set((state) => {
    if (!measurements?.length) return state;
    const newMap = new Map(state.accessPoints);
    let touched = 0;
    for (const m of measurements) {
      const bssid = String(m?.bssid ?? '').trim().toUpperCase();
      if (!bssid) continue;
      const existing = newMap.get(bssid) ?? newMap.get(bssid.toLowerCase());
      // An access point the survey never saw has no row to attach a measurement
      // to. Creating one here would put an AP in the archive that was never
      // surveyed, with no position, vendor or encryption behind it.
      if (!existing) continue;
      newMap.set(existing.bssid, {
        ...existing,
        wps_enabled: !!m.wps_enabled,
        wps_locked: !!m.wps_locked,
        wps_version: m.wps_version ?? (existing as any).wps_version ?? null,
        wps_scanned_at: measuredAt,
      } as any);
      touched++;
    }
    return touched > 0 ? { accessPoints: newMap } : state;
  }),

  addAccessPoints: (aps) => set((state) => {
    const newMap = new Map(state.accessPoints);
    let newHighRisk = 0;
    let newOpen = 0;
    
    // Ensure aps is an iterable array (in case Python returns None/null)
    if (!Array.isArray(aps)) return state;

    for (const ap of aps) {
      if (!ap || !ap.bssid) continue;
      
      const existing = newMap.get(ap.bssid);
      
      if (!existing) {
        // First sighting in a batch.
        const hasGps = ap.latitude != null && ap.longitude != null;
        // No reading, no observation. See readingOf.
        const reading = readingOf(ap);
        newMap.set(ap.bssid, {
          ...ap,
          _peakRssi: reading,
          _history: hasGps && reading !== null
            ? [{ lat: ap.latitude!, lon: ap.longitude!, rssi: reading, frequency: ap.frequency ?? null }]
            : [],
          _lastEstimateAt: 0,
          _lastEstimateCount: 0,
          _estimate: null,
        } as any);
        if (ap.is_vulnerable) newHighRisk++;
        if (ap.encryption === 'OPEN') newOpen++;
      } else {
        const incomingHasLocation = ap.latitude != null && ap.longitude != null;
        const existingHasLocation = existing.latitude != null && existing.longitude != null;
        // @ts-ignore  null until this AP has produced a real reading.
        const peakRssi: number | null = existing._peakRssi ?? null;
        const reading = readingOf(ap);

        // Read location method from engine config
        const method = useEngineStore.getState().config.locationMethod;

        // @ts-ignore
        let history: Observation[] = existing._history || [];
        // @ts-ignore
        const lastEstimateAt: number = existing._lastEstimateAt ?? 0;
        // @ts-ignore
        const lastEstimateCount: number = existing._lastEstimateCount ?? 0;

        // A position needs a signal to be estimated from, so a sighting without
        // a reading is not added to the history at all.
        if (incomingHasLocation && reading !== null) {
          history = mergeObservation(
            history,
            { lat: ap.latitude!, lon: ap.longitude!, rssi: reading, frequency: ap.frequency ?? null },
            LIVE_HISTORY_CAP
          );
        }

        // Compute location using the shared estimators, throttled for the
        // expensive ones. See shouldReestimate above.
        let newLat = existing.latitude;
        let newLon = existing.longitude;
        let newPeak = peakRssi;
        // @ts-ignore
        let estimate: LocationEstimate | null = existing._estimate ?? null;
        let estimatedAt = lastEstimateAt;
        let estimatedCount = lastEstimateCount;

        if (reading !== null && (peakRssi === null || reading > peakRssi)) newPeak = reading;

        if (history.length === 0) {
          // Nothing positioned yet; keep whatever we had.
        } else if (shouldReestimate(method, history.length, lastEstimateCount, lastEstimateAt)) {
          estimate = runEstimate(history, method);
          estimatedAt = Date.now();
          estimatedCount = history.length;
          newLat = estimate.lat;
          newLon = estimate.lon;
        } else if (estimate) {
          newLat = estimate.lat;
          newLon = estimate.lon;
        } else if (
          incomingHasLocation && reading !== null
          && (!existingHasLocation || peakRssi === null || reading >= peakRssi)
        ) {
          newLat = ap.latitude!;
          newLon = ap.longitude!;
        }

        newMap.set(ap.bssid, {
          ...existing,
          ...mergeEngineFields(existing, ap),
          latitude: newLat,
          longitude: newLon,
          // @ts-ignore
          _estimate: estimate,
          // @ts-ignore
          _lastEstimateAt: estimatedAt,
          // @ts-ignore
          _lastEstimateCount: estimatedCount,
          location_method: estimate?.method ?? undefined,
          location_confidence: estimate?.confidence ?? null,
          location_error_m: estimate?.errorRadiusM ?? null,
          /*
            The two columns the estimator fills and the store used to drop.

            `wardrivingDB` writes both, so a mission replayed from SQLite printed
            the per-mode spread and the separation between the two candidates; a
            live survey exported from memory printed `n/r` for each. The same
            mission, read two ways, produced two different documents — the defect
            immediately below this, in a second place.

            What a reader saw: "AMBIGUOUS - 1 of 2 candidates, n/r apart" on the
            map and in the KML, and `n/r` down the whole Per-mode column of the
            position-quality table, under a heading explaining what the column
            means. The numbers existed; nothing carried them here.
          */
          location_mode_error_m: estimate?.modeRadiusM ?? null,
          geometry_ambiguous: estimate?.geometry.mirrorAmbiguous ? 1 : 0,
          location_mirror_lat: estimate?.mirrorCandidate?.lat ?? null,
          location_mirror_lon: estimate?.mirrorCandidate?.lon ?? null,
          location_mirror_distance_m: estimate?.mirrorDistanceM ?? null,
          /*
            Written here as well as in `addAccessPoint`.

            Six fields were taken off the same `estimate` and this was not one of
            them, and that mattered more than it looks: the engine has no
            `ap_found` emitter at all — `handler.py` only ever sends `aps_batch` —
            so `addAccessPoint` is dead code and this is the path every live
            survey takes. `isUnresolved` in `report/archive.ts` reads
            `location_resolved === false`, which was therefore permanently false
            for a live archive.

            The consequence was a document that overstated itself: an access point
            the receiver never moved far enough to place was drawn on the survey
            map as an ordinary measured fix, indistinguishable from a constrained
            one. A mission *replayed* from SQLite showed the caveat correctly,
            because `wardrivingDB` sets the field — so one mission produced two
            different documents depending on which way it was read.
          */
          location_resolved: estimate ? estimate.resolved !== false : true,
          // @ts-ignore
          _peakRssi: newPeak,
          // @ts-ignore
          _history: history,
        } as any);
      }
    }

    /**
     * Rogue-AP verdicts come from the engine (engine/scanner/evil_twin.py) and
     * are not recomputed here.
     *
     * This used to hold its own heuristic — "same SSID seen with two encryption
     * types, flag every AP in the group" — which overwrote whatever the engine
     * said. It had three problems: WPA2/WPA3 transition mode is a correct modern
     * configuration and would have been reported as an evil twin in every
     * organisation mid-rollout; it accused the legitimate AP alongside the
     * impostor; and it could not detect a clone that matched the encryption and
     * differed only in hardware. The engine scores seven weighted indicators,
     * attributes them to the deviating AP, and only raises the flag at LIKELY or
     * above — and it carries the reasons, which is what makes the finding usable
     * in a report.
     */
    let evilTwinCount = 0;
    for (const ap of newMap.values()) {
      if (ap.is_evil_twin) evilTwinCount++;
    }

    // Dynamically compute KPIs to prevent state drift
    let highRiskCount = 0;
    let openNetworks = 0;
    for (const ap of newMap.values()) {
      if (ap.is_vulnerable) highRiskCount++;
      if (ap.encryption === 'OPEN') openNetworks++;
    }

    return {
      accessPoints: newMap,
      totalAPs: newMap.size,
      highRiskCount,
      openNetworks,
      evilTwinCount,
    };
  }),

  addScanLog: (log) => set((state) => ({
    recentLogs: [log, ...state.recentLogs].slice(0, MAX_RECENT_LOGS),
  })),

  incrementElapsed: () => set((state) => ({
    elapsedSeconds: state.elapsedSeconds + 1,
  })),

  appendPathCoord: (coord) => set((state) => ({
    pathCoords: [...state.pathCoords, coord],
  })),

  loadArchive: (missionId, aps, path) => set(() => {
    const newMap = new Map<string, AccessPoint>();
    let highRiskCount = 0;
    let openNetworks = 0;

    for (const ap of aps) {
      newMap.set(ap.bssid, ap);
    }

    for (const ap of newMap.values()) {
      if (ap.is_vulnerable) highRiskCount++;
      if (ap.encryption === 'OPEN') openNetworks++;
    }

    return {
      activeMission: null,
      viewingMissionId: missionId,
      accessPoints: newMap,
      totalAPs: newMap.size,
      highRiskCount,
      openNetworks,
      pathCoords: path,
      elapsedSeconds: 0,
      recentLogs: [],
    };
  }),

  clearArchive: () => set(() => ({
    ...initialState,
    accessPoints: new Map(),
    pathCoords: [],
    recentLogs: [],
  })),

  reset: () => set({
    ...initialState,
    accessPoints: new Map(),
    pathCoords: [],
    recentLogs: [],
  }),
}));
