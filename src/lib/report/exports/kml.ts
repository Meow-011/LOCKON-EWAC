/**
 * The KML document a GIS analyst or Google Earth opens.
 *
 * Moved out of `ReportsPage` verbatim. It is a pure function from an archive to
 * an XML string, and it had no test at all: `tests/kmz.test.mjs` covers the zip
 * container it is packed into, using the literal `<kml>hello</kml>` as its
 * payload, so nothing had ever asserted a placemark, a coordinate, an escape or
 * the second candidate.
 *
 * Every value is XML-escaped. An SSID is text chosen by whoever owns the access
 * point and must never be able to close a tag.
 *
 * An ambiguous access point is drawn twice, hollow, joined by a line: the second
 * placemark is the same transmitter in the place the survey geometry cannot rule
 * out, and a document that draws only one of the two is asserting a coin flip.
 */
import { xmlEscape } from '../archive';
import { apMirror, formatCoord, formatErrorRadius, formatMetres, isMirrorAmbiguous, locationMethodLabel, positionCaveats } from '../../position';
import { formatLocationConfidence } from '../../position';
import { wpsLabel } from '../../apRisk';
import { type Severity } from '../../riskEngine';
import { SEVERITY_RGB } from '../../severityStyle';
import { finiteNumber } from '../../numbers';
import { positionedRows } from './apRows';
import type { Report as IntelReport } from '../../../stores/reportStore';

/**
 * Returns the document text, or null when the archive has nothing to place.
 *
 * Null rather than an empty document: a KML with no placemarks opens as an empty
 * map, which reads as "nothing was there" rather than "nothing could be located".
 * The caller says which.
 */
export function buildKml(report: IntelReport): string | null {
    const rows = positionedRows(report);

  // Nothing to place. The caller decides how to say so.
  if (rows.length === 0) return null;

    /*
      The icons travel inside the file.

      These hrefs pointed at Google's map-shape images over plain HTTP, which
      meant a client opening the assessment weeks later sent a cleartext
      request to a third party at that moment. KMZ is the format that exists
      for this: a zip carrying `doc.kml` beside the images it names, opened
      natively by every KML viewer and working with no network at all.

      The paths are relative to the archive root and must match the entry names
      in `kmz()` exactly. A viewer that cannot resolve one falls back to its
      default pin and says nothing, so `npm run check:kmz` compares the two
      sides rather than trusting them to stay in step.

      The artwork is drawn by `scripts/make-kml-icons.py` rather than taken
      from Google, because carrying someone else's map files inside a document
      handed to a client is a licence question with no good answer. Both are
      white: KML's `<color>` multiplies, so a white source takes the severity
      colour exactly and a tinted one would shift it.
    */
    const styles = (Object.keys(SEVERITY_RGB) as Severity[]).map(level => {
      const [r, g, b] = SEVERITY_RGB[level];
      // KML colours are aabbggrr, not rrggbb.
      const abgr = `ff${b.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${r.toString(16).padStart(2, '0')}`;
      return `  <Style id="sev-${level}">\n    <IconStyle><color>${abgr}</color><scale>1.1</scale>\n      <Icon><href>icons/placemark-circle.png</href></Icon>\n    </IconStyle>\n  </Style>`;
    }).join('\n');

    // The mirror candidate gets a visually distinct pin. Google Earth shows one
    // icon per Placemark and nothing else; if the alternative position looked
    // like a normal access point, or were omitted, whoever opened this file
    // would read a coin flip as a fix.
    const mirrorStyle = '  <Style id="mirror-candidate">\n'
      + '    <IconStyle><color>ff00d7ff</color><scale>1.0</scale>\n'
      + '      <Icon><href>icons/mirror-diamond.png</href></Icon>\n'
      + '    </IconStyle>\n'
      + '  </Style>\n'
      + '  <Style id="mirror-link">\n'
      + '    <LineStyle><color>ff00d7ff</color><width>2</width></LineStyle>\n'
      + '  </Style>';

    const ambiguousCount = rows.filter(({ ap }) => isMirrorAmbiguous(ap)).length;
    // Only the ones whose alternative was actually recorded can be drawn twice.
    const mirrorDrawnCount = rows.filter(({ ap }) => apMirror(ap) !== null).length;

    const placemarks = rows.map(({ ap, findings, worst, verdict }) => {
      const mirror = apMirror(ap);
      const ambiguous = isMirrorAmbiguous(ap);
      const caveats = positionCaveats(ap);
      const description = [
        `SSID: ${ap.ssid || '(hidden or blank)'}`,
        `BSSID: ${ap.bssid || 'unknown'}`,
        `Vendor: ${ap.vendor || 'Unknown'}`,
        `Encryption: ${ap.encryption || 'Unknown'}`,
        `Channel: ${ap.channel ?? 'n/r'}${ap.band ? ` (${ap.band})` : ''}`,
        `Strongest RSSI: ${ap.rssi ?? 'n/r'} dBm`,
        `WPS: ${wpsLabel(ap)}`,
        `Rogue-AP verdict: ${verdict}`,
        `Severity: ${worst.severity}${worst.confidence ? ` (confidence ${worst.confidence})` : ''}`,
        `Findings: ${findings.length ? findings.map(f => f.title).join('; ') : 'none above reporting threshold'}`,
        `Position method: ${locationMethodLabel(ap.location_method)} (confidence figure ${formatLocationConfidence(ap.location_confidence)}, which is derived from the radius below and is not a probability)`,
        `Position uncertainty: ${formatErrorRadius(ap.location_error_m)} (radius containing roughly 95% of the posterior)`,
        ...(finiteNumber(ap.location_mode_error_m) !== null
          ? [`Spread about this position alone: ${formatMetres(ap.location_mode_error_m)}`]
          : []),
        ambiguous
          ? `POSITION IS ONE OF TWO CANDIDATES: ${mirror
            ? `the other is ${formatCoord(mirror.lat, mirror.lon)}, about ${formatMetres(mirror.distanceM)} away, carried in this file as a separate placemark named "[CANDIDATE B OF 2 - MIRROR]"`
            : 'the other candidate was not recorded'}. The route was effectively straight, so which side of it the radio sits on cannot be determined.`
          : 'Route geometry was sufficient to determine which side of the route this access point sits on.',
        ...caveats.map(n => `Caveat: ${n}`),
        'This position is an estimate derived from signal observations along the survey route, not a surveyed location.',
        `First seen: ${ap.first_seen || 'n/r'}`,
        `Last seen: ${ap.last_seen || 'n/r'}`,
        `Data source: ${report.simulated ? 'HARDWARE SIMULATOR - NOT FIELD-VERIFIED' : 'live hardware'}`,
      ].join('\n');

      const primary = [
        '  <Placemark>',
        `    <name>${xmlEscape(`${ap.ssid || ap.bssid || 'unknown'}${ambiguous ? ' [CANDIDATE A OF 2]' : ''}`)}</name>`,
        `    <styleUrl>#sev-${worst.severity}</styleUrl>`,
        `    <description>${xmlEscape(description)}</description>`,
        // clampToGround is stated rather than left to the reader's viewer.
        // These are 2-D estimates from signal strength: the survey records no
        // height for an access point, and a viewer that read the trailing 0
        // as an absolute altitude would sink every pin to sea level.
        `    <Point><altitudeMode>clampToGround</altitudeMode><coordinates>${Number(ap.longitude).toFixed(6)},${Number(ap.latitude).toFixed(6)},0</coordinates></Point>`,
        '  </Placemark>',
      ].join('\n');

      if (!mirror) return primary;

      // The alternative candidate, as its own pin plus a line joining the two.
      // A single pin for a two-candidate position is a false claim in any map
      // viewer, and Google Earth carries no uncertainty of its own.
      const mirrorDescription = [
        `ALTERNATIVE POSITION for ${ap.ssid || '(hidden or blank)'} (${ap.bssid || 'unknown BSSID'}).`,
        `This point and ${formatCoord(ap.latitude, ap.longitude)} fit the measurements equally well; they are about ${formatMetres(mirror.distanceM)} apart.`,
        'The survey route past this access point was effectively a straight line, which makes the signal model symmetric about that line. Which side the radio is on cannot be determined from this data - it is not that this candidate is less likely.',
        'Re-driving the area with at least one turn in the route removes the ambiguity entirely.',
        `Position uncertainty of the pair: ${formatErrorRadius(ap.location_error_m)}`,
        `Position method: ${locationMethodLabel(ap.location_method)}`,
      ].join('\n');

      const mirrorPlacemark = [
        '  <Placemark>',
        `    <name>${xmlEscape(`${ap.ssid || ap.bssid || 'unknown'} [CANDIDATE B OF 2 - MIRROR]`)}</name>`,
        '    <styleUrl>#mirror-candidate</styleUrl>',
        `    <description>${xmlEscape(mirrorDescription)}</description>`,
        `    <Point><altitudeMode>clampToGround</altitudeMode><coordinates>${mirror.lon.toFixed(6)},${mirror.lat.toFixed(6)},0</coordinates></Point>`,
        '  </Placemark>',
        '  <Placemark>',
        `    <name>${xmlEscape(`${ap.ssid || ap.bssid || 'unknown'} - candidate separation`)}</name>`,
        '    <styleUrl>#mirror-link</styleUrl>',
        `    <description>${xmlEscape(`The two equally good positions for this access point, about ${formatMetres(mirror.distanceM)} apart.`)}</description>`,
        '    <LineString><tessellate>1</tessellate><altitudeMode>clampToGround</altitudeMode><coordinates>'
        + `${Number(ap.longitude).toFixed(6)},${Number(ap.latitude).toFixed(6)},0 `
        + `${mirror.lon.toFixed(6)},${mirror.lat.toFixed(6)},0`
        + '</coordinates></LineString>',
        '  </Placemark>',
      ].join('\n');

      return `${primary}\n${mirrorPlacemark}`;
    }).join('\n');

    const kml = [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<kml xmlns="http://www.opengis.net/kml/2.2">',
      '<Document>',
      `  <name>${xmlEscape(`LOCKON EWAC ${report.targetName}${report.simulated ? ' [SIMULATED]' : ''}`)}</name>`,
      `  <description>${xmlEscape(
        `${rows.length} positioned access point(s) from report ${report.id}, exported ${new Date().toISOString()}. `
        + 'Positions are estimates produced from received-signal observations along the surveyed route; they are not surveyed locations. '
        + 'Each placemark states the radius containing roughly 95% of the posterior for that position. '
        + (ambiguousCount > 0
          ? `${ambiguousCount} of them are mirror-ambiguous: the route past them was effectively straight, so a position on either side of it fits the measurements equally well. `
            + `${mirrorDrawnCount} of those appear TWICE in this file - a coloured pin named "[CANDIDATE A OF 2]" and an open diamond named "[CANDIDATE B OF 2 - MIRROR]", joined by a line. Neither candidate is the better one. `
            + (ambiguousCount > mirrorDrawnCount
              ? `The remaining ${ambiguousCount - mirrorDrawnCount} are flagged ambiguous but their alternative position was not recorded, so only one pin could be drawn for each; do not read those as fixes either. `
              : '')
            + 'Re-driving with at least one turn in the route resolves them. '
          : 'No access point in this file is mirror-ambiguous; the route geometry was sufficient to determine which side of it each radio sits on. ')
        + (report.simulated ? 'THIS DATA CAME FROM THE HARDWARE SIMULATOR AND IS NOT FIELD-VERIFIED.' : '')
      )}</description>`,
      styles,
      mirrorStyle,
      placemarks,
      '</Document>',
      '</kml>',
      '',
    ].join('\n');

  return kml;
}
