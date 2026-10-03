/**
 * The CSV an operator opens in a spreadsheet.
 *
 * Moved out of `ReportsPage` verbatim. It is a pure function from an archive to a
 * string, and it was three hundred lines inside a React component where nothing
 * could assert against it -- `tests/csv.test.mjs` covered `csvRow`, the cell
 * escaper, and nothing covered which cells were written or what went in them.
 *
 * Two hazards at once, and both are `csvRow`'s job: RFC 4180 quoting, because an
 * SSID containing `"` used to shift every following column, and formula
 * injection, because an SSID is chosen by whoever owns the access point and a
 * cell beginning `=` is a program to a spreadsheet.
 */
import { csvRow } from '../../csv';
import { credentialsOf, hostsOf, isWirelessReport } from '../archive';
import { apMirror, formatLocationConfidence, isMirrorAmbiguous, positionCaveats } from '../../position';
import { toHostInput, worstOf, wpsLabel } from '../../apRisk';
import { assessHost } from '../../riskEngine';
import { finiteNumber } from '../../numbers';
import { apExportRows } from './apRows';
import type { Report as IntelReport } from '../../../stores/reportStore';

/** The archive as CSV text, without the byte-order mark the caller prepends. */
export function buildCsv(report: IntelReport): string {
    let csvContent = '';

    if (isWirelessReport(report)) {
      // The previous header carried no coordinates at all, which is the entire
      // point of a wardrive, and no WPS or rogue verdict either.
      // Every coordinate column is followed by the uncertainty that belongs to
      // it. A consumer that reads LATITUDE/LONGITUDE and ignores the rest has
      // at least been handed the mirror candidate and the ambiguity flag.
      // RADIO_TYPE / CONNECTED_STATIONS / CHANNEL_UTILIZATION_PCT come from the
      // `netsh wlan` parser and are persisted by migration 015. They reached
      // the live feed and the archive but no export, which is the gap that
      // migration named: an open network carrying a dozen devices is a
      // different finding from an open network with none, and only the first
      // one has anybody's traffic on it. An empty cell means the adapter
      // published no value — never zero, which would read as a measurement.
      csvContent += csvRow([
        'BSSID', 'SSID', 'VENDOR', 'ENCRYPTION', 'CHANNEL', 'FREQUENCY_MHZ', 'BAND', 'RADIO_TYPE',
        'RSSI_DBM', 'CONNECTED_STATIONS', 'CHANNEL_UTILIZATION_PCT',
        'LATITUDE', 'LONGITUDE', 'LOCATION_ERROR_M', 'LOCATION_MODE_ERROR_M', 'LOCATION_METHOD', 'LOCATION_CONFIDENCE',
        'GEOMETRY_AMBIGUOUS', 'MIRROR_LATITUDE', 'MIRROR_LONGITUDE', 'MIRROR_SEPARATION_M',
        'GEOMETRY_CROSS_TRACK_M', 'GEOMETRY_ALONG_TRACK_M', 'POSITION_NOTES',
        'WPS', 'ROGUE_VERDICT', 'SEVERITY', 'CONFIDENCE', 'RISK_SCORE',
        'FINDINGS', 'FIRST_SEEN', 'LAST_SEEN', 'DATA_SOURCE',
      ]);
      /*
        Every access point, positioned or not -- a CSV is an inventory and a
        radio that could not be placed still belongs in it. What changes is the
        coordinate columns: they are written from `fix`, so a row the geospatial
        exports refuse to draw leaves them blank here rather than printing
        `0.000000, 0.000000` as though it were a measurement.
      */
      for (const { ap, findings, worst, verdict, fix } of apExportRows(report)) {
        const mirror = apMirror(ap);
        const ambiguous = isMirrorAmbiguous(ap);
        csvContent += csvRow([
          ap.bssid ?? '',
          ap.ssid ?? '',
          ap.vendor ?? 'Unknown',
          ap.encryption ?? 'Unknown',
          ap.channel ?? '',
          ap.frequency ?? '',
          ap.band ?? '',
          ap.radio_type ?? '',
          ap.rssi ?? '',
          typeof ap.connected_stations === 'number' ? ap.connected_stations : '',
          typeof ap.channel_utilization_pct === 'number' ? ap.channel_utilization_pct : '',
          fix ? fix.lat.toFixed(6) : '',
          fix ? fix.lon.toFixed(6) : '',
          finiteNumber(ap.location_error_m) ?? '',
          finiteNumber(ap.location_mode_error_m) ?? '',
          ap.location_method ?? '',
          formatLocationConfidence(ap.location_confidence),
          ambiguous ? 1 : 0,
          mirror ? mirror.lat.toFixed(6) : '',
          mirror ? mirror.lon.toFixed(6) : '',
          mirror && mirror.distanceM !== null ? mirror.distanceM : '',
          finiteNumber(ap.geometry_cross_track_m) ?? '',
          finiteNumber(ap.geometry_along_track_m) ?? '',
          positionCaveats(ap).join(' | '),
          wpsLabel(ap),
          verdict,
          worst.severity,
          worst.confidence ?? '',
          findings.length ? Math.max(...findings.map(f => f.risk_score)) : 0,
          findings.map(f => f.title).join(' | '),
          ap.first_seen ?? '',
          ap.last_seen ?? '',
          report.simulated ? 'SIMULATED' : 'FIELD',
        ]);
      }
    } else {
      const creds = credentialsOf(report);
      csvContent += csvRow([
        'IP', 'HOSTNAME', 'OS', 'OPEN_PORTS', 'CVE_COUNT', 'SNMP_COMMUNITIES',
        'CREDENTIALS_RECOVERED', 'SEVERITY', 'CONFIDENCE', 'RISK_SCORE', 'FINDINGS', 'DATA_SOURCE',
      ]);
      for (const h of hostsOf(report)) {
        const findings = assessHost(toHostInput(h, creds, !!report.simulated));
        const worst = worstOf(findings);
        const ports = (h.open_ports || []).map((p: any) => p.port).join(';');
        const cveCount = (h.open_ports || [])
          .reduce((acc: number, p: any) => acc + (Array.isArray(p.cves) ? p.cves.length : 0), 0);
        csvContent += csvRow([
          h.ip ?? '',
          h.hostname ?? '',
          h.os ?? '',
          ports,
          cveCount,
          (h.snmp_communities || []).length,
          creds.some(c => c && String(c.target_ip) === String(h.ip)) ? 'YES' : 'NO',
          worst.severity,
          worst.confidence ?? '',
          findings.length ? Math.max(...findings.map(f => f.risk_score)) : 0,
          findings.map(f => f.title).join(' | '),
          report.simulated ? 'SIMULATED' : 'FIELD',
        ]);
      }
    }

  return csvContent;
}
