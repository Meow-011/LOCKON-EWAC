/**
 * LOCKON EWAC — Survey coverage
 *
 * The report could say what was found but not where the operator actually went,
 * so "no vulnerable APs on the north side" was indistinguishable from "never
 * drove the north side". That is the first hole a sceptical reader finds.
 *
 * This computes coverage from the GPS track and scan log once, at archive time,
 * and freezes it: the underlying rows can be purged later while the report still
 * has to stand up.
 *
 * What it deliberately reports rather than hides:
 *  - GPS dropouts, as a count and the worst gap. A thin patch of results next to
 *    a 4-minute gap is a coverage limitation, not an absence of networks.
 *  - Fix quality (HDOP, satellites), so a coordinate's precision is auditable.
 *  - Per-band AP counts. Read alongside the adapter capability probe, this is
 *    what lets a reader tell "no 6 GHz networks here" from "this adapter cannot
 *    see 6 GHz".
 */
import { getDb } from './database';

/** A gap longer than this in the GPS track is treated as a dropout. */
export const GAP_THRESHOLD_SECONDS = 30;

export interface CoverageRow {
  mission_id: string;
  computed_at: string;
  duration_seconds: number | null;
  distance_metres: number | null;
  point_count: number | null;
  bbox_min_lat: number | null;
  bbox_min_lon: number | null;
  bbox_max_lat: number | null;
  bbox_max_lon: number | null;
  avg_hdop: number | null;
  worst_hdop: number | null;
  avg_satellites: number | null;
  gap_count: number | null;
  max_gap_seconds: number | null;
  gap_threshold_seconds: number;
  aps_2g: number;
  aps_5g: number;
  aps_6g: number;
  aps_unknown_band: number;
  channels_seen: string | null;
  notes: string | null;
}

/** Great-circle distance in metres. */
function haversine(lat1: number, lon1: number, lat2: number, lon2: number): number {
  const R = 6371000;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2
    + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

/**
 * Compute coverage for a mission and store it.
 *
 * Distance deliberately skips the leg across a dropout: a straight line drawn
 * over a 4-minute GPS outage is not distance that was surveyed, and counting it
 * would overstate coverage in the report.
 */
export async function computeAndStoreCoverage(missionId: string): Promise<CoverageRow | null> {
  const db = await getDb();

  const track = await db.select<{ latitude: number; longitude: number; timestamp: string }[]>(
    `SELECT latitude, longitude, timestamp FROM gps_logs
     WHERE mission_id = $1 AND latitude IS NOT NULL AND longitude IS NOT NULL
     ORDER BY timestamp ASC`,
    [missionId]
  );

  let distance = 0;
  let gapCount = 0;
  let maxGap = 0;
  let minLat: number | null = null, maxLat: number | null = null;
  let minLon: number | null = null, maxLon: number | null = null;

  for (let i = 0; i < track.length; i++) {
    const p = track[i];
    minLat = minLat === null ? p.latitude : Math.min(minLat, p.latitude);
    maxLat = maxLat === null ? p.latitude : Math.max(maxLat, p.latitude);
    minLon = minLon === null ? p.longitude : Math.min(minLon, p.longitude);
    maxLon = maxLon === null ? p.longitude : Math.max(maxLon, p.longitude);

    if (i === 0) continue;
    const prev = track[i - 1];
    const dt = (new Date(p.timestamp).getTime() - new Date(prev.timestamp).getTime()) / 1000;

    if (Number.isFinite(dt) && dt > GAP_THRESHOLD_SECONDS) {
      gapCount++;
      maxGap = Math.max(maxGap, Math.round(dt));
      continue; // do not count distance across a dropout
    }
    distance += haversine(prev.latitude, prev.longitude, p.latitude, p.longitude);
  }

  // Duration from the mission record, falling back to the track's own span.
  const mission = await db.select<{ start_time: string; end_time: string | null }[]>(
    `SELECT start_time, end_time FROM missions WHERE id = $1`, [missionId]);
  let duration: number | null = null;
  if (mission.length) {
    const start = new Date(mission[0].start_time).getTime();
    const end = mission[0].end_time
      ? new Date(mission[0].end_time).getTime()
      : (track.length ? new Date(track[track.length - 1].timestamp).getTime() : NaN);
    if (Number.isFinite(start) && Number.isFinite(end) && end >= start) {
      duration = Math.round((end - start) / 1000);
    }
  }

  // Fix quality, now that scan_logs actually stores it.
  const quality = await db.select<{ avg_hdop: number | null; worst_hdop: number | null; avg_sats: number | null }[]>(
    `SELECT AVG(hdop) as avg_hdop, MAX(hdop) as worst_hdop, AVG(satellites) as avg_sats
     FROM scan_logs WHERE mission_id = $1 AND hdop IS NOT NULL`,
    [missionId]
  );

  // Band breakdown over the distinct APs seen on this mission.
  const bands = await db.select<{ band: string | null; n: number }[]>(
    `SELECT a.band as band, COUNT(DISTINCT a.bssid) as n
     FROM access_points a
     JOIN (SELECT DISTINCT bssid FROM scan_logs WHERE mission_id = $1) m ON a.bssid = m.bssid
     GROUP BY a.band`,
    [missionId]
  );
  const bandCount = (name: string) => bands.find(b => (b.band || '') === name)?.n ?? 0;
  /*
    Everything that is not one of the three named bands, including NULL.

    This was `bands.filter(b => !b.band)`, which counted only NULL. The four
    stored counters are printed together as a breakdown of the access points
    seen, so a band string outside the vocabulary — one stored by an older
    build, or by an enrichment path that reported "5 GHz" rather than "5G" —
    appeared in none of them, and the four numbers quietly failed to add up to
    the access-point count beside them. Derived by subtraction so they always
    reconcile, whatever ends up in the column.
  */
  const totalAps = bands.reduce((a, b) => a + b.n, 0);
  const unknownBand = totalAps - bandCount('2.4G') - bandCount('5G') - bandCount('6G');

  const channels = await db.select<{ channel: number }[]>(
    `SELECT DISTINCT channel FROM scan_logs
     WHERE mission_id = $1 AND channel IS NOT NULL ORDER BY channel`,
    [missionId]
  );

  const notes: string[] = [];
  if (track.length === 0) notes.push('No GPS track was recorded for this mission; spatial coverage cannot be established.');
  if (gapCount > 0) notes.push(`${gapCount} GPS dropout(s) over ${GAP_THRESHOLD_SECONDS}s; the longest was ${maxGap}s. Distance across dropouts is excluded.`);
  if (!quality[0]?.avg_hdop) notes.push('No HDOP was recorded, so positional precision cannot be stated.');

  await db.execute(
    `INSERT INTO mission_coverage (
       mission_id, computed_at, duration_seconds, distance_metres, point_count,
       bbox_min_lat, bbox_min_lon, bbox_max_lat, bbox_max_lon,
       avg_hdop, worst_hdop, avg_satellites,
       gap_count, max_gap_seconds, gap_threshold_seconds,
       aps_2g, aps_5g, aps_6g, aps_unknown_band, channels_seen, notes
     ) VALUES ($1,datetime('now'),$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
     ON CONFLICT(mission_id) DO UPDATE SET
       computed_at = datetime('now'),
       duration_seconds = excluded.duration_seconds,
       distance_metres = excluded.distance_metres,
       point_count = excluded.point_count,
       bbox_min_lat = excluded.bbox_min_lat, bbox_min_lon = excluded.bbox_min_lon,
       bbox_max_lat = excluded.bbox_max_lat, bbox_max_lon = excluded.bbox_max_lon,
       avg_hdop = excluded.avg_hdop, worst_hdop = excluded.worst_hdop,
       avg_satellites = excluded.avg_satellites,
       gap_count = excluded.gap_count, max_gap_seconds = excluded.max_gap_seconds,
       aps_2g = excluded.aps_2g, aps_5g = excluded.aps_5g, aps_6g = excluded.aps_6g,
       aps_unknown_band = excluded.aps_unknown_band,
       channels_seen = excluded.channels_seen, notes = excluded.notes`,
    [
      missionId, duration, Math.round(distance), track.length,
      minLat, minLon, maxLat, maxLon,
      quality[0]?.avg_hdop ?? null, quality[0]?.worst_hdop ?? null, quality[0]?.avg_sats ?? null,
      // `?? null`, not `|| null`: a longest-gap of 0 means the track had no
      // dropouts, which is the good result and the one worth recording. `||`
      // stored it as "not computed", so a clean track and an uncomputed one
      // read identically in the report's coverage table.
      gapCount, maxGap ?? null, GAP_THRESHOLD_SECONDS,
      bandCount('2.4G'), bandCount('5G'), bandCount('6G'), unknownBand,
      JSON.stringify(channels.map(c => c.channel)),
      notes.join(' ') || null,
    ]
  );

  return getCoverage(missionId);
}

export async function getCoverage(missionId: string): Promise<CoverageRow | null> {
  const db = await getDb();
  const rows = await db.select<CoverageRow[]>(
    `SELECT * FROM mission_coverage WHERE mission_id = $1`, [missionId]);
  return rows[0] ?? null;
}

/** Human-readable coverage lines for the report. Honest about what is missing. */
export function formatCoverage(c: CoverageRow | null): string[] {
  if (!c) return ['No coverage data was recorded for this operation.'];

  const lines: string[] = [];
  if (c.distance_metres != null) {
    const km = c.distance_metres / 1000;
    lines.push(`Distance surveyed: ${km >= 1 ? `${km.toFixed(2)} km` : `${Math.round(c.distance_metres)} m`}`);
  }
  if (c.duration_seconds != null) {
    const h = Math.floor(c.duration_seconds / 3600);
    const m = Math.floor((c.duration_seconds % 3600) / 60);
    lines.push(`Duration: ${h > 0 ? `${h}h ` : ''}${m}m`);
  }
  if (c.point_count != null) lines.push(`GPS fixes recorded: ${c.point_count}`);
  if (c.bbox_min_lat != null && c.bbox_max_lat != null) {
    lines.push(`Area surveyed: ${c.bbox_min_lat.toFixed(5)}, ${c.bbox_min_lon?.toFixed(5)} to ${c.bbox_max_lat.toFixed(5)}, ${c.bbox_max_lon?.toFixed(5)}`);
  }
  if (c.avg_hdop != null) {
    lines.push(`Positional quality: average HDOP ${c.avg_hdop.toFixed(2)}${c.worst_hdop != null ? `, worst ${c.worst_hdop.toFixed(2)}` : ''}`);
  } else {
    lines.push('Positional quality: not recorded');
  }
  if (c.avg_satellites != null) lines.push(`Average satellites: ${c.avg_satellites.toFixed(1)}`);

  if ((c.gap_count ?? 0) > 0) {
    lines.push(`GPS dropouts: ${c.gap_count} (longest ${c.max_gap_seconds}s) — areas covered during a dropout are not represented`);
  } else {
    lines.push('GPS dropouts: none');
  }

  lines.push(`Access points by band: ${c.aps_2g} on 2.4 GHz, ${c.aps_5g} on 5 GHz, ${c.aps_6g} on 6 GHz${c.aps_unknown_band ? `, ${c.aps_unknown_band} band unknown` : ''}`);

  try {
    const chans: number[] = JSON.parse(c.channels_seen || '[]');
    if (chans.length) lines.push(`Channels observed: ${chans.join(', ')}`);
  } catch { /* channels_seen malformed — omit rather than guess */ }

  if (c.notes) lines.push(`Coverage notes: ${c.notes}`);
  return lines;
}
