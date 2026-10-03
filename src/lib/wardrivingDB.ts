import { getDb, reclaimFreePages } from './database';
import type { Mission, AccessPoint } from '../types/models';
import { estimateLocation, mergeObservation, type Observation } from './localization';

/**
 * Create a mission.
 *
 * `simulated` is recorded on the mission itself so a report built from it can
 * say so on its face. Note the single quotes around 'now': the double-quoted
 * form only worked by way of SQLite's double-quoted-string misfeature, and
 * would throw `no such column: now` on a build compiled with SQLITE_DQS=0.
 */
export async function createMission(name: string, simulated = false): Promise<string> {
  const db = await getDb();
  const id = crypto.randomUUID();
  await db.execute(
    "INSERT INTO missions (id, name, status, start_time, is_simulated) VALUES ($1, $2, $3, datetime('now'), $4)",
    [id, name, 'ACTIVE', simulated ? 1 : 0]
  );
  return id;
}

export async function completeMission(missionId: string): Promise<void> {
  const db = await getDb();
  await db.execute(
    "UPDATE missions SET status = $1, end_time = datetime('now') WHERE id = $2",
    ['COMPLETED', missionId]
  );
}

/** Flag a mission as simulated after the fact (e.g. simulator toggled mid-run). */
export async function markMissionSimulated(missionId: string): Promise<void> {
  const db = await getDb();
  await db.execute('UPDATE missions SET is_simulated = 1 WHERE id = $1', [missionId]);
}

export async function logGps(missionId: string, lat: number, lon: number, heading: number | null, speed: number | null): Promise<void> {
  const db = await getDb();
  // `heading || 0` and `speed || 0` recorded an unknown heading and speed as
  // "stationary, facing due north" — a measurement, not a gap. Both columns are
  // nullable (migration 003), so absence can be stored as absence. A receiver
  // that reports no course over ground is common at low speed, and coverage
  // reporting reads these rows back.
  const finite = (v: number | null | undefined) =>
    typeof v === 'number' && Number.isFinite(v) ? v : null;
  await db.execute(
    'INSERT INTO gps_logs (mission_id, latitude, longitude, heading, speed) VALUES ($1, $2, $3, $4, $5)',
    [missionId, lat, lon, finite(heading), finite(speed)]
  );
}

/**
 * Record what a WPS scan actually measured.
 *
 * Only access points whose beacon was parsed belong here. `wps_scanned_at`
 * (migration 013) is what makes the zero meaningful: without it, the schema's
 * `wps_enabled INTEGER NOT NULL DEFAULT 0` gave every access point ever seen a
 * confident "no WPS" that nobody had measured, and the report printed it as an
 * observation read from the beacon.
 *
 * Rows are only updated, never inserted. An access point that has never been
 * seen by the survey has no row to attach a WPS measurement to, and inventing
 * one would put an access point in the archive that was never surveyed.
 */
export async function recordWpsMeasurements(
  measurements: { bssid: string; wps_enabled: boolean; wps_locked: boolean; wps_version?: string | null }[],
  measuredAt: string
): Promise<void> {
  if (!measurements.length) return;
  const db = await getDb();
  for (const m of measurements) {
    const bssid = String(m.bssid ?? '').trim();
    if (!bssid) continue;
    await db.execute(
      `UPDATE access_points
          SET wps_enabled = $1, wps_locked = $2,
              wps_version = COALESCE($3, wps_version),
              wps_scanned_at = $4
        WHERE UPPER(bssid) = UPPER($5)`,
      [m.wps_enabled ? 1 : 0, m.wps_locked ? 1 : 0, m.wps_version ?? null, measuredAt, bssid]
    );
  }
}

/** GPS fix quality at the moment of a sighting. */
export interface FixQuality {
  hdop?: number | null;
  satellites?: number | null;
  altitude?: number | null;
  speed?: number | null;
}

export async function logAccessPoint(
  missionId: string,
  ap: AccessPoint,
  lat: number | null,
  lon: number | null,
  /**
   * Fix quality is persisted now. The engine has always reported HDOP and
   * satellite count, and the KPI tile showed them live, but nothing wrote them —
   * so after a drive there was no way to tell a genuinely empty area from one
   * surveyed on a bad fix. Coverage reporting depends on these columns.
   */
  fix: FixQuality = {}
): Promise<void> {
  const db = await getDb();

  // The engine stamps `simulated` on every AP it emits; treat a missing flag as
  // real only because older rows predate the field — never invent the opposite.
  const simulated = ap.simulated ? 1 : 0;

  // 1. Insert or update the Access Point in the master table.
  //    frequency/band/WPS/evil-twin are persisted now: the app already carried
  //    them in its types, but they were dropped on write, so a replayed mission
  //    could never match the map's EVIL_TWIN or WPS filters.
  await db.execute(`
    INSERT INTO access_points (
      bssid, ssid, vendor, encryption, cipher, auth_type, is_vulnerable, channel,
      frequency, band, is_evil_twin, wps_enabled, wps_locked, wps_version,
      is_simulated, rogue_verdict, rogue_score, rogue_indicators,
      radio_type, connected_stations, channel_utilization_pct, first_seen, last_seen
    )
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, datetime('now'), datetime('now'))
    ON CONFLICT(bssid) DO UPDATE SET
      last_seen = datetime('now'),
      ssid = CASE WHEN excluded.ssid IS NOT NULL THEN excluded.ssid ELSE access_points.ssid END,
      vendor = CASE WHEN excluded.vendor IS NOT NULL THEN excluded.vendor ELSE access_points.vendor END,
      channel = CASE WHEN excluded.channel IS NOT NULL THEN excluded.channel ELSE access_points.channel END,
      frequency = CASE WHEN excluded.frequency IS NOT NULL THEN excluded.frequency ELSE access_points.frequency END,
      band = CASE WHEN excluded.band IS NOT NULL THEN excluded.band ELSE access_points.band END,
      is_vulnerable = MAX(access_points.is_vulnerable, excluded.is_vulnerable),
      is_evil_twin = MAX(access_points.is_evil_twin, excluded.is_evil_twin),
      -- A survey sighting carries no WPS data, so excluded.wps_enabled is always
      -- 0 here and MAX() simply preserves whatever a WPS scan measured.
      -- wps_scanned_at is deliberately absent from this statement: only
      -- recordWpsMeasurements may set it, because only a scan that parsed the
      -- beacon has the right to claim WPS was measured. A survey sighting must
      -- never turn an unmeasured AP into a measured one.
      wps_enabled = MAX(access_points.wps_enabled, excluded.wps_enabled),
      wps_locked = MAX(access_points.wps_locked, excluded.wps_locked),
      wps_version = CASE WHEN excluded.wps_version IS NOT NULL THEN excluded.wps_version ELSE access_points.wps_version END,
      -- Once an AP has been seen for real, a later simulated sighting must not
      -- downgrade it, and a real sighting clears a simulated-only record.
      is_simulated = MIN(access_points.is_simulated, excluded.is_simulated),
      -- Keep the strongest rogue assessment seen for this AP. A twin is only
      -- visible relative to its peers, so a later scan that happened to see
      -- fewer of them must not erase an earlier, better-informed verdict.
      rogue_verdict = CASE WHEN excluded.rogue_score >= access_points.rogue_score
                           THEN excluded.rogue_verdict ELSE access_points.rogue_verdict END,
      rogue_indicators = CASE WHEN excluded.rogue_score >= access_points.rogue_score
                              THEN excluded.rogue_indicators ELSE access_points.rogue_indicators END,
      rogue_score = MAX(access_points.rogue_score, excluded.rogue_score),
      -- Freshest non-null wins. A sighting from an adapter that does not report
      -- BSS Load must not erase a reading from one that does, and NULL is the
      -- only honest value for "this adapter did not say".
      radio_type = CASE WHEN excluded.radio_type IS NOT NULL
                        THEN excluded.radio_type ELSE access_points.radio_type END,
      connected_stations = CASE WHEN excluded.connected_stations IS NOT NULL
                                THEN excluded.connected_stations
                                ELSE access_points.connected_stations END,
      channel_utilization_pct = CASE WHEN excluded.channel_utilization_pct IS NOT NULL
                                     THEN excluded.channel_utilization_pct
                                     ELSE access_points.channel_utilization_pct END
  `, [
    ap.bssid, ap.ssid || null, ap.vendor || null, ap.encryption, ap.cipher || null, ap.auth_type || null,
    ap.is_vulnerable ? 1 : 0, ap.channel ?? null,
    ap.frequency ?? null, ap.band || null, ap.is_evil_twin ? 1 : 0,
    // A survey sighting never carries WPS data — it comes from a separate
    // `scan_wps` run that parses beacon information elements. These two are
    // written here only because the columns are `NOT NULL` (migration 008); the
    // value that means anything is `wps_scanned_at`, which only
    // `recordWpsMeasurements` sets. Until a scan has run, `wps_scanned_at` is
    // NULL and the report reads these as "not measured" rather than as an
    // observation. See `wpsMeasured` in ReportsPage.
    ap.wps_enabled ? 1 : 0, ap.wps_locked ? 1 : 0, ap.wps_version || null,
    simulated,
    ap.rogue_verdict ?? null,
    Math.round(ap.rogue_score ?? 0),
    ap.rogue_indicators ? JSON.stringify(ap.rogue_indicators) : null,
    // Nullable on purpose. `connected_stations ?? 0` would say "measured, no
    // devices" for an adapter that never reported BSS Load at all, and those
    // are different findings about an open network.
    ap.radio_type || null,
    typeof ap.connected_stations === 'number' ? ap.connected_stations : null,
    typeof ap.channel_utilization_pct === 'number' ? ap.channel_utilization_pct : null
  ]);

  // 2. Add a scan log entry linked to the mission.
  //
  // A scan_logs row is a signal measurement at a position: `estimateLocation`
  // reads these rows back to place the access point on the map, and the report
  // prints the resulting coordinate and error radius.
  //
  // `rssi` used to be written as `ap.rssi ?? -90`, so a sighting that carried no
  // signal reading was stored as a hard -90 dBm, indistinguishable from an
  // observed -90. Those invented readings then fed the localizer and produced
  // coordinates and confidence figures with nothing behind them, and they also
  // made the telemetry column's correct 'n/r' branch unreachable.
  //
  // `scan_logs.rssi` is `INTEGER NOT NULL` (migration 001), so the column cannot
  // hold "not reported". The honest option left is not to claim a measurement
  // that does not exist: no reading, no row. The access point itself is still
  // recorded above, so the sighting is not lost — only the fabricated number is.
  //
  // Making this a nullable column would be better still, and would let the row
  // record "seen here, signal not reported". That needs a table rebuild, which
  // SQLite cannot do with ALTER.
  if (ap.rssi === null || ap.rssi === undefined || !Number.isFinite(ap.rssi)) {
    return;
  }

  await db.execute(`
    INSERT INTO scan_logs (mission_id, bssid, rssi, channel, frequency, latitude, longitude,
                           altitude, speed, hdop, satellites, is_simulated)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
  `, [
    missionId, ap.bssid, ap.rssi, ap.channel ?? null, ap.frequency ?? null, lat, lon,
    fix.altitude ?? null, fix.speed ?? null, fix.hdop ?? null, fix.satellites ?? null,
    simulated
  ]);
}

/**
 * Persist a refined location (e.g. the GPR post-processing result).
 *
 * This used to UPDATE latitude/longitude on access_points, which had no such
 * columns, so SQLite rejected every write and the .catch(console.error) around
 * it hid the failure. The columns exist as of migration 008.
 */
export interface LocationQuality {
  confidence?: number | null;
  errorRadiusM?: number | null;
  modeRadiusM?: number | null;
  mirrorLat?: number | null;
  mirrorLon?: number | null;
  mirrorDistanceM?: number | null;
  crossTrackM?: number | null;
  alongTrackM?: number | null;
  ambiguous?: boolean;
  notes?: string[];
}

export async function saveApLocation(
  bssid: string,
  lat: number,
  lon: number,
  method: string,
  quality: LocationQuality | number | null = null
): Promise<void> {
  const db = await getDb();
  // Accepts a bare confidence number for older callers.
  const q: LocationQuality = typeof quality === 'number' ? { confidence: quality } : (quality ?? {});
  const result = await db.execute(
    `UPDATE access_points
     SET latitude = $1, longitude = $2, location_method = $3, location_confidence = $4,
         location_error_m = $5, location_mode_error_m = $6,
         location_mirror_lat = $7, location_mirror_lon = $8, location_mirror_distance_m = $9,
         geometry_cross_track_m = $10, geometry_along_track_m = $11, geometry_ambiguous = $12,
         location_notes = $13
     WHERE UPPER(bssid) = UPPER($14)`,
    [
      lat, lon, method, q.confidence ?? null,
      q.errorRadiusM ?? null, q.modeRadiusM ?? null,
      q.mirrorLat ?? null, q.mirrorLon ?? null, q.mirrorDistanceM ?? null,
      q.crossTrackM ?? null, q.alongTrackM ?? null, q.ambiguous ? 1 : 0,
      q.notes ? JSON.stringify(q.notes) : null,
      bssid,
    ]
  );

  /*
    An UPDATE that matched nothing is a silent loss, and this is the most
    expensive thing in the app to lose: a GPR fix is minutes of computation the
    operator asked for explicitly.

    The match is now case-insensitive, as `recordWpsMeasurements` already was.
    The two disagreed — this one required an exact match — so a caller holding a
    lowercase BSSID (netsh and PyWiFi do not agree on case) updated zero rows
    and nothing anywhere said so. This function's own header records the last
    time a write here failed invisibly; that is the reason for the check rather
    than only the fix.
  */
  if (!result.rowsAffected) {
    console.warn(`[DB] saveApLocation matched no access point for BSSID ${bssid}; `
      + `the ${method} position was not stored.`);
  }
}

export async function getMissions(): Promise<Mission[]> {
  const db = await getDb();
  return await db.select<Mission[]>(`
    SELECT 
      m.*,
      COUNT(DISTINCT s.bssid) as total_aps,
      COUNT(DISTINCT CASE WHEN a.is_vulnerable = 1 OR a.encryption = 'OPEN' THEN s.bssid ELSE NULL END) as high_risk_aps
    FROM missions m
    LEFT JOIN scan_logs s ON m.id = s.mission_id
    LEFT JOIN access_points a ON s.bssid = a.bssid
    GROUP BY m.id
    ORDER BY m.start_time DESC
  `);
}

export async function deleteMission(missionId: string): Promise<void> {
  const db = await getDb();
  /*
    `gps_logs`, `scan_logs` and `mission_coverage` all declare
    `REFERENCES missions(id) ON DELETE CASCADE`, so the last statement would
    clear them on its own. They are still deleted explicitly because the cascade
    only fires when `PRAGMA foreign_keys` is on, which is a per-connection
    setting on a pooled connection nobody here controls.

    `findings` and `assessment_baselines` carry a plain `mission_id TEXT` with no
    foreign key, so nothing cascades to them. They were left behind: rows
    describing a mission that no longer exists, still counted by every query
    that does not filter by mission — which is how a deleted survey went on
    contributing to a headline risk figure. A finding is a statement about a
    mission's observations; deleting the mission deletes the grounds for it.

    `clients` and `evidence_files` were the same omission, found later and with a
    sharper edge: both hold third-party data. `clients` is the station inventory —
    MAC, vendor, probed SSIDs, associated BSSID — collected from devices belonging
    to people who are not the client, and `evidence_files` holds the filesystem
    paths and SHA-256 of captured handshakes. Deleting a survey from the archive
    hid them from every read, because every read filters by mission, while leaving
    them in the file. An operator who removes a survey has said what they want.
    `purgeCollectedData` already clears both, so only per-item deletion was
    affected.

    The pages are reclaimed afterwards for the same reason `crackingDB` does it:
    rows leave the index, not the file, and `evidence_files` rows name capture
    paths while `clients` rows are somebody's device inventory.
  */
  await db.execute('DELETE FROM gps_logs WHERE mission_id = $1', [missionId]);
  await db.execute('DELETE FROM scan_logs WHERE mission_id = $1', [missionId]);
  await db.execute('DELETE FROM mission_coverage WHERE mission_id = $1', [missionId]);
  await db.execute('DELETE FROM findings WHERE mission_id = $1', [missionId]);
  await db.execute('DELETE FROM assessment_baselines WHERE mission_id = $1', [missionId]);
  await db.execute('DELETE FROM clients WHERE mission_id = $1', [missionId]);
  await db.execute('DELETE FROM evidence_files WHERE mission_id = $1', [missionId]);
  await db.execute('DELETE FROM missions WHERE id = $1', [missionId]);
  await reclaimFreePages();
}

export interface MissionData {
  aps: AccessPoint[];
  gpsPath: [number, number][];
}

export async function getMissionData(missionId: string, locationMethod: 'bayesian_grid' | 'trilateration' | 'weighted_centroid' | 'peak_rssi' = 'bayesian_grid'): Promise<MissionData> {
  const db = await getDb();
  
  // 1. Get all unique APs for this mission
  const aps = await db.select<AccessPoint[]>(`
    SELECT a.* 
    FROM access_points a
    JOIN (SELECT DISTINCT bssid FROM scan_logs WHERE mission_id = $1) m ON a.bssid = m.bssid
  `, [missionId]);

  // 2. Fetch all scan logs for this mission to perform Post-Processing refinement
  // `frequency` is in this list because the code below reads it. It was not,
  // and the read was written as `(log as any).frequency` — so it was always
  // `undefined`, and every replayed sighting reached the localizer with no
  // frequency at all. The path-loss model then fell back to its default band
  // for a 5 GHz access point, which is a systematic distance error in the
  // position and the error radius the report prints. The column has been
  // written since migration 001; only the SELECT was missing it, and the `any`
  // cast is what stopped the compiler saying so.
  const logs = await db.select<{bssid: string, rssi: number, latitude: number,
                                longitude: number, frequency: number | null}[]>(`
    SELECT bssid, rssi, latitude, longitude, frequency
    FROM scan_logs
    WHERE mission_id = $1 AND latitude IS NOT NULL AND longitude IS NOT NULL
  `, [missionId]);

  // rogue_indicators is stored as JSON text; parse it back so a replayed archive
  // can print the reasons behind a verdict, not just the verdict.
  for (const ap of aps as any[]) {
    if (typeof ap.rogue_indicators === 'string') {
      try {
        ap.rogue_indicators = JSON.parse(ap.rogue_indicators);
      } catch {
        ap.rogue_indicators = [];
      }
    }
  }

  // 3. Re-aggregate sightings per BSSID.
  //    selectDiverse (inside mergeObservation) keeps the geometry and the full
  //    signal range rather than the strongest N, which is what the old
  //    "top 100 highest RSSI" rule did — and which discarded exactly the distant
  //    weak readings the estimators need to place a transmitter.
  const historyMap = new Map<string, Observation[]>();
  for (const log of logs) {
    const obs: Observation = {
      lat: log.latitude, lon: log.longitude, rssi: log.rssi,
      frequency: log.frequency ?? null,
    };
    historyMap.set(log.bssid, mergeObservation(historyMap.get(log.bssid) || [], obs, 100));
  }

  // 4. Apply the selected estimator.
  //
  //    Yielding to the event loop every few access points keeps the UI alive
  //    while this runs. The grid search costs about 6 ms per AP, so a 200-AP
  //    archive is roughly a second of work — long enough that doing it in one
  //    synchronous block visibly freezes the window while a mission opens.
  //    (It was 40 ms per AP, i.e. nine seconds, before the search was optimised.)
  const YIELD_EVERY = 12;
  let processed = 0;

  for (const ap of aps) {
    if (++processed % YIELD_EVERY === 0) {
      await new Promise<void>(resolve => setTimeout(resolve, 0));
    }
    const history = historyMap.get(ap.bssid) || [];

    // A stored GPR fix is the most expensive and most accurate estimate the tool
    // can produce, and the operator asked for it explicitly. Recomputing a
    // cheaper estimate over the top of it would throw that work away.
    const hasStoredGpr = ap.location_method === 'gpr'
      && ap.latitude != null && ap.longitude != null;
    if (hasStoredGpr) {
      const peak = history.length
        ? history.reduce((max, obs) => (obs.rssi > max.rssi ? obs : max), history[0])
        : null;
      if (peak) ap.rssi = peak.rssi;
      continue;
    }

    if (history.length > 0) {
      // Find peak for UI display
      const peak = history.reduce((max, obs) => obs.rssi > max.rssi ? obs : max, history[0]);
      ap.rssi = peak.rssi;

      // Refine the location, and keep everything the estimate says about how
      // much it is worth. Storing only the point is what let a coin-flip
      // position be presented as a fact.
      const estimate = estimateLocation(history, locationMethod);
      ap.latitude = estimate.lat;
      ap.longitude = estimate.lon;
      ap.location_method = estimate.method;
      // Carried into the archive, not just held in the live store. Without it
      // the report redraws an unresolved position as a resolved one: the notes
      // still say the receiver never moved, but every structured consumer --
      // the survey map, the position-quality table -- sees a coordinate like
      // any other. A caveat that only exists in prose is one a figure can
      // contradict.
      ap.location_resolved = estimate.resolved !== false;
      ap.location_confidence = estimate.confidence;
      ap.location_error_m = estimate.errorRadiusM;
      ap.location_mode_error_m = estimate.modeRadiusM ?? null;
      ap.location_mirror_lat = estimate.mirrorCandidate?.lat ?? null;
      ap.location_mirror_lon = estimate.mirrorCandidate?.lon ?? null;
      ap.location_mirror_distance_m = estimate.mirrorDistanceM ?? null;
      ap.geometry_cross_track_m = estimate.geometry.crossTrackM;
      ap.geometry_along_track_m = estimate.geometry.alongTrackM;
      ap.geometry_ambiguous = estimate.geometry.mirrorAmbiguous ? 1 : 0;
      ap.location_notes = JSON.stringify(estimate.notes);
    }
  }

  // Get the GPS path (ordered by time)
  const gpsRows = await db.select<{latitude: number, longitude: number}[]>(`
    SELECT latitude, longitude FROM gps_logs 
    WHERE mission_id = $1 
    ORDER BY timestamp ASC
  `, [missionId]);

  const gpsPath = gpsRows.map((r: any) => [r.longitude, r.latitude] as [number, number]);

  return { aps, gpsPath };
}

export async function getMissionRawLogs(missionId: string): Promise<{bssid: string, rssi: number, lat: number, lon: number}[]> {
  const db = await getDb();
  const logs = await db.select<{bssid: string, rssi: number, latitude: number, longitude: number}[]>(`
    SELECT bssid, rssi, latitude, longitude 
    FROM scan_logs 
    WHERE mission_id = $1 AND latitude IS NOT NULL AND longitude IS NOT NULL
  `, [missionId]);
  
  return logs.map(l => ({
    bssid: l.bssid,
    rssi: l.rssi,
    lat: l.latitude,
    lon: l.longitude
  }));
}
