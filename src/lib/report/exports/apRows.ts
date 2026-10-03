/**
 * The rows every text export of a wireless archive is built from.
 *
 * Why this is shared rather than three similar loops.
 *
 * Severity, the rogue verdict and *whether the access point has a position at
 * all* were each decided separately by the CSV, the KML and the GeoJSON. The
 * first two happened to agree. The third did not:
 *
 *   - KML filtered on `coordinatePair`, which rejects exactly `0, 0` -- the value
 *     a NULL column decays into -- and anything out of range;
 *   - GeoJSON filtered on `typeof === 'number' && Number.isFinite`, so it
 *     exported an access point at `0, 0` and would have exported latitude 95;
 *   - CSV did not filter at all, printing `lat.toFixed(6)` whenever the field was
 *     a number.
 *
 * So one archive exported three ways put a radio in the Gulf of Guinea in two of
 * them and left it out of the third, which is the defect `coordinatePair`'s own
 * comment was written about -- fixed in the KML and in both maps, and never
 * carried to the other two exports.
 *
 * The position is resolved once, here, and the three formatters read `fix`.
 */
import { apsOf } from '../archive';
import { coordinatePair } from '../../numbers';
import { toApInput, worstOf, rogueVerdictOf } from '../../apRisk';
import { assessAccessPoint, type Finding, type Severity, type Confidence } from '../../riskEngine';
import type { Report as IntelReport } from '../../../stores/reportStore';

export interface ApExportRow {
  ap: any;
  findings: Finding[];
  worst: { severity: Severity; confidence: Confidence | null };
  verdict: string;
  /**
   * The access point's position, or null when it has none.
   *
   * One rule, shared with the live map, the report figure and the recorder:
   * `coordinatePair`. A row with `fix === null` is not a located transmitter and
   * no export may place it anywhere.
   */
  fix: { lat: number; lon: number } | null;
}

/** Base name for any file exported from one archive. */
export function exportBaseName(report: IntelReport): string {
  return `${report.targetName.replace(/[^A-Za-z0-9_-]+/g, '_')}_${report.id}`;
}

/**
 * Per-AP severity, rogue verdict and position for the geospatial and tabular
 * exports, from the same rule set the PDF uses.
 */
export function apExportRows(report: IntelReport): ApExportRow[] {
  const simulated = !!report.simulated;
  return apsOf(report).map(ap => {
    const findings = assessAccessPoint(toApInput(ap, simulated));
    const worst = worstOf(findings);
    const { verdict } = rogueVerdictOf(ap);
    return { ap, findings, worst, verdict: verdict ?? 'CLEAR', fix: coordinatePair(ap.latitude, ap.longitude) };
  });
}

/** Only the rows a geospatial export may draw. */
export function positionedRows(report: IntelReport): ApExportRow[] {
  return apExportRows(report).filter(r => r.fix !== null);
}
