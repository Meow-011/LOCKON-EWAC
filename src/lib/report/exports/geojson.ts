/**
 * GeoJSON, for anything that speaks it rather than KML.
 *
 * Moved out of `ReportsPage` verbatim, and with one behaviour change recorded in
 * `apRows.ts`: it filtered positions on `typeof === 'number' && Number.isFinite`,
 * so it exported an access point at exactly `0, 0` -- the value a NULL column
 * decays into -- while the KML built from the same archive dropped it. Both read
 * `positionedRows` now.
 *
 * The collection carries the localization model constants in its properties, so a
 * consumer can weigh the radii without having the application to hand.
 */
import { describeLocalizationMethodology } from '../../localization';
import { describeMethodology } from '../../riskEngine';
import { apMirror, isMirrorAmbiguous, positionCaveats } from '../../position';
import { wpsLabel } from '../../apRisk';
import { finiteNumber } from '../../numbers';
import { positionedRows } from './apRows';
import type { Report as IntelReport } from '../../../stores/reportStore';

/**
 * Returns the collection, or null when the archive has nothing to place.
 *
 * Null rather than an empty `FeatureCollection`, for the same reason the KML
 * returns null: a document with no features reads as "nothing was there".
 */
export function buildGeoJson(report: IntelReport): Record<string, unknown> | null {
    const features = positionedRows(report)
      .map(({ ap, findings, worst, verdict }) => {
        const mirror = apMirror(ap);
        const ambiguous = isMirrorAmbiguous(ap);
        return {
        type: 'Feature' as const,
        geometry: { type: 'Point' as const, coordinates: [Number(ap.longitude), Number(ap.latitude)] },
        properties: {
          bssid: ap.bssid ?? null,
          ssid: ap.ssid ?? null,
          vendor: ap.vendor ?? null,
          encryption: ap.encryption ?? null,
          channel: ap.channel ?? null,
          frequency_mhz: ap.frequency ?? null,
          band: ap.band ?? null,
          rssi_dbm: ap.rssi ?? null,
          wps: wpsLabel(ap),
          rogue_verdict: verdict,
          severity: worst.severity,
          confidence: worst.confidence,
          risk_score: findings.length ? Math.max(...findings.map(f => f.risk_score)) : 0,
          findings: findings.map(f => ({ title: f.title, severity: f.severity, confidence: f.confidence, rationale: f.rationale })),
          location_method: ap.location_method ?? null,
          location_confidence: ap.location_confidence ?? null,
          location_confidence_note: 'A display figure derived from location_error_m. It is not a probability.',
          location_error_m: finiteNumber(ap.location_error_m),
          location_error_note: 'Radius in metres containing roughly 95% of the posterior. Null where the estimator could not produce one. Where geometry_ambiguous is 1 this radius is widened to cover both candidate positions and is large by design.',
          location_mode_error_m: finiteNumber(ap.location_mode_error_m),
          geometry_ambiguous: ambiguous ? 1 : 0,
          geometry_cross_track_m: finiteNumber(ap.geometry_cross_track_m),
          geometry_along_track_m: finiteNumber(ap.geometry_along_track_m),
          mirror_latitude: mirror ? mirror.lat : null,
          mirror_longitude: mirror ? mirror.lon : null,
          mirror_distance_m: mirror ? mirror.distanceM : null,
          position_notes: positionCaveats(ap),
          position_caveat: ambiguous
            ? 'TWO EQUALLY GOOD POSITIONS. The survey route past this access point was effectively straight, so the measurements fit a position on either side of it equally well; mirror_latitude/mirror_longitude hold the alternative. Which side is correct cannot be determined from this data. Re-driving with at least one turn in the route resolves it.'
            : 'Estimated from received-signal observations along the surveyed route; not a surveyed location.',
          first_seen: ap.first_seen ?? null,
          last_seen: ap.last_seen ?? null,
          data_source: report.simulated ? 'HARDWARE_SIMULATOR' : 'FIELD',
        },
        };
      });

  // Nothing to place. The caller decides how to say so.
  if (features.length === 0) return null;

    const collection = {
      type: 'FeatureCollection' as const,
      properties: {
        report_id: report.id,
        target: report.targetName,
        exported_at: new Date().toISOString(),
        methodology: `${describeMethodology().id}@${describeMethodology().version}`,
        // The model constants behind every coordinate below, so a consumer can
        // weigh the radii without having the application to hand.
        localization: describeLocalizationMethodology(),
        simulated: !!report.simulated,
      },
      features,
    };

  return collection;
}
