/**
 * LOCKON EWAC — how well the survey actually located what it found.
 *
 * A latitude and longitude in a report invite a reader to treat an estimate as a
 * surveyed position, so this section states the opposite where it applies: how
 * many access points were positioned at all, how wide the 95% radius was, and
 * how many sit on a stretch of road where the measurements fit a position on
 * either side equally well.
 *
 * That last one is not a defect to be tuned away. With collinear sightings the
 * likelihood really is symmetric about the driving line, and driving the same
 * street twice makes it worse rather than better. The honest output is both
 * candidates and a radius wide enough to cover them — never the narrower
 * per-mode spread, which would be a claim the data does not support.
 *
 * Moved out of `buildAndSavePDF` verbatim by script; `pdfdiff` confirmed the
 * document is unchanged.
 */
import autoTable from 'jspdf-autotable';
import {
  apMirror,
  apsOf,
  ascii,
  formatCoord,
  formatErrorRadius,
  formatMetres,
  isMirrorAmbiguous,
  isWirelessReport,
  locationMethodLabel,
  locationNotesOf,
  summarisePositions,
} from '../archive';
import { coordinatePair, finiteNumber } from '../../numbers';
import { type Report as IntelReport } from '../../../stores/reportStore';
import type { ReportData } from '../assemble';
import { TABLE_MARGIN } from '../geometry';
import type { PdfLayout } from '../layout';

export function renderPositionQuality(layout: PdfLayout, data: ReportData): void {
  const { doc, tocEntries, fit, sectionHeading, paragraph, callout } = layout;
  const { reportsArray } = data;

    // --- 9b. POSITION QUALITY ---
  // Every coordinate in this document is an inference, and the inferences are
  // not equally good. This section states how good they are before the reader
  // reaches a table full of decimal degrees. It is placed ahead of the per-
  // operation telemetry deliberately: a reader who sees the coordinates first
  // has already formed an impression by the time the caveats arrive.
  // Deduplicated by BSSID for the same reason as every other count in this
  // document: one physical access point surveyed in two archives is one
  // position to judge, not two. The better-constrained estimate is the one
  // reported, since a tighter radius is the more informative measurement.
  const positionAps: { report: IntelReport; ap: any }[] = [];
  const positionSeen = new Map<string, number>();
  for (const r of reportsArray) {
    if (!isWirelessReport(r)) continue;
    for (const ap of apsOf(r)) {
      const bssid = String(ap?.bssid ?? '').toUpperCase();
      const at = bssid ? positionSeen.get(bssid) : undefined;
      if (at === undefined) {
        if (bssid) positionSeen.set(bssid, positionAps.length);
        positionAps.push({ report: r, ap });
        continue;
      }
      const radiusOf = (a: any) => {
        const v = finiteNumber(a?.location_error_m);
        return v === null ? Number.POSITIVE_INFINITY : v;
      };
      if (radiusOf(ap) < radiusOf(positionAps[at].ap)) positionAps[at] = { report: r, ap };
    }
  }

  if (positionAps.length > 0) {
    doc.addPage();
    tocEntries.push({ title: 'POSITION QUALITY', page: (doc as any).internal.getNumberOfPages() });
    let posY = sectionHeading('POSITION QUALITY');

    const quality = summarisePositions(positionAps.map(e => e.ap));
    const ambiguousEntries = positionAps.filter(e =>
      coordinatePair(e.ap?.latitude, e.ap?.longitude) !== null && isMirrorAmbiguous(e.ap));

    posY = paragraph(
      'An access point is never observed directly. What is recorded is where the operator was and how strong the signal was there, and a position is inferred from that. Two things decide how much the resulting coordinate is worth: how tightly the measurements constrain it, stated below as a radius in metres, and whether the shape of the route allows more than one answer. Both are reported here for every position in this document.',
      posY, { size: 9.5 }
    );
    posY += 4;

    autoTable(doc, {
      startY: posY,
      head: [['Position quality', 'Count', 'What it means']],
      body: [
        [
          'Access points in this export',
          String(quality.total),
          'Every access point observed, positioned or not.',
        ],
        [
          'Carrying an estimated position',
          String(quality.positioned),
          `${quality.total - quality.positioned} were detected without a usable position and appear as "no fix". That is a gap in positioning, not in detection.`,
        ],
        [
          'Well constrained',
          String(quality.wellConstrained),
          'Positioned, and the route geometry was good enough to determine which side of it the radio sits on. The stated radius still applies.',
        ],
        [
          'Mirror-ambiguous',
          String(quality.ambiguous),
          'Positioned, but the route past them was effectively a straight line. Two positions, one on each side of that line, fit the measurements equally well. These are listed individually below.',
        ],
        [
          'Median 95% radius (all positioned)',
          quality.medianErrorM !== null ? formatMetres(quality.medianErrorM) : 'n/a',
          'Half the positioned access points have a tighter radius than this, half wider. Mirror-ambiguous radii are widened to cover both candidates and pull this figure up, which is correct.',
        ],
        [
          'Median 95% radius (well constrained only)',
          quality.medianWellConstrainedM !== null ? formatMetres(quality.medianWellConstrainedM) : 'n/a',
          'The same figure over the unambiguous positions alone.',
        ],
        [
          'Widest 95% radius',
          quality.worstErrorM !== null ? formatMetres(quality.worstErrorM) : 'n/a',
          'The least constrained position in this export.',
        ],
        [
          'No stated radius',
          String(quality.radiusMissing),
          'Positioned by an estimator that cannot produce an uncertainty figure. The coordinate cannot be weighed and should not be treated as better than the others.',
        ],
      ].map(row => row.map(cell => ascii(cell))),
      theme: 'grid',
      headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 8 },
      styles: { fontSize: 8, cellPadding: 2, overflow: 'linebreak', textColor: [0, 0, 0] },
      columnStyles: {
        0: { cellWidth: 52, fontStyle: 'bold' },
        1: { cellWidth: 18, halign: 'center', fontStyle: 'bold' },
        2: { cellWidth: 108, textColor: [80, 80, 80] },
      },
      margin: TABLE_MARGIN,
    });
    posY = (doc as any).lastAutoTable.finalY + 6;

    if (quality.methods.size > 0) {
      posY = paragraph(
        ascii('Estimators used: '
          + Array.from(quality.methods.entries())
            .map(([m, n]) => `${locationMethodLabel(m)} (${n})`).join(', ')
          + '. Each is described in the method appendix.'),
        posY, { size: 8, color: [80, 80, 80] }
      );
      posY += 3;
    }

    if (ambiguousEntries.length === 0) {
      posY = callout(
        posY,
        'NO MIRROR-AMBIGUOUS POSITION IN THIS EXPORT',
        ascii(
          'No position in this document sits on a route straight enough to leave the side undetermined. Every coordinate here is a single candidate, subject to the radius printed beside it. '
          + 'This is a statement about the geometry of the drive, not a claim of accuracy: a well constrained position can still be tens of metres out, which is what its radius says.'
        ),
        [240, 253, 244], [16, 185, 129], [13, 148, 136]
      );
    } else {
      posY = callout(
        posY,
        `${ambiguousEntries.length} POSITION(S) HAVE TWO EQUALLY GOOD ANSWERS - RESOLVABLE BY RE-DRIVING`,
        ascii(
          'When every sighting of an access point lies on one straight line, the signal model is symmetric about that line: a radio 40 m to the left and a radio 40 m to the right fit the measurements equally well, and noise alone picks the winner. Measured against known ground truth, a single straight pass put the estimate on the wrong side of the road in two runs out of five; driving the same street twice got it wrong five times out of five, because a second pass only reinforces the symmetry. '
          + 'The two candidates are typically on the order of 80 m apart, which is the difference between one building and another. '
          + 'THIS IS ACTIONABLE, NOT A DEAD END: the ambiguity comes from the shape of the route and nothing else. One turn - driving any route past these access points that is not a straight line - removes it entirely. Both candidates are given below so a follow-up pass can be planned around them.'
        ),
        [254, 252, 232], [234, 179, 8], [161, 98, 7]
      );

      autoTable(doc, {
        startY: posY,
        head: [['SSID', 'BSSID', 'Candidate A (reported)', 'Candidate B (mirror)', 'Apart', '95% radius', 'Per-mode']],
        body: ambiguousEntries.map(({ ap }) => {
          const mirror = apMirror(ap);
          return [
            ascii(ap.ssid || '<hidden>'),
            ascii(ap.bssid || 'unknown'),
            ascii(formatCoord(ap.latitude, ap.longitude)),
            ascii(mirror ? formatCoord(mirror.lat, mirror.lon) : 'not recorded'),
            ascii(mirror ? formatMetres(mirror.distanceM) : 'n/r'),
            ascii(formatErrorRadius(ap.location_error_m).replace('+/- ', '')),
            ascii(finiteNumber(ap.location_mode_error_m) !== null ? formatMetres(ap.location_mode_error_m) : 'n/r'),
          ];
        }),
        theme: 'grid',
        headStyles: { fillColor: [161, 98, 7], textColor: 255, fontSize: 7.5 },
        styles: { fontSize: 7.5, cellPadding: 1.8, overflow: 'linebreak', textColor: [0, 0, 0] },
        columnStyles: {
          0: { cellWidth: 30 },
          1: { cellWidth: 28, font: 'courier' },
          2: { cellWidth: 32, font: 'courier' },
          3: { cellWidth: 32, font: 'courier' },
          4: { cellWidth: 16, halign: 'center' },
          5: { cellWidth: 20, halign: 'center' },
          6: { cellWidth: 18, halign: 'center' },
        },
        margin: TABLE_MARGIN,
      });
      posY = (doc as any).lastAutoTable.finalY + 5;

      posY = paragraph(
        ascii(
          'Neither candidate is the better one. "Candidate A (reported)" is simply the one the estimator returned and the one that appears in the telemetry table, on the preview map and as the primary placemark in any KML export; the KML also carries candidate B as its own open-diamond placemark. "95% radius" is wide because it is widened to cover BOTH candidates - that is the honest figure for a two-answer position and it has not been narrowed. "Per-mode" is the spread about one candidate alone: it is tight, and quoting it on its own would claim a precision this data does not support.'
        ),
        posY, { size: 8, color: [80, 80, 80], lead: 3.6 }
      );
      posY += 4;

      /*
        Caveats: the shared explanation once, the per-access-point exceptions in full.

        This used to print `positionCaveats(ap)` for every ambiguous row. Measured
        on a real export that was **165 access points, 165 caveats, and all 165
        were the same MIRROR-AMBIGUOUS sentence** - 23,265 characters across 13 of
        the document's 57 pages, saying one thing. Everything that actually varied
        between them, the alternative position and the distance between
        candidates, was already in the table immediately above, in its own
        columns.

        The cost was not the paper. Repetition on that scale teaches a reader to
        skip the section, and the day an estimator records something genuinely
        different it is skipped with the rest. A warnings section that trains
        people not to read warnings is worse than no section.

        So the mirror warning - which this module generates, identically, from the
        same template - is stated once as what the flag means, with a count. An
        access point is listed individually only when the estimator wrote a note
        of its own, because that is the part that differs and the part a reader
        has to see.
      */
      const generatedMirrorOnly = ({ ap }: { ap: any }) =>
        locationNotesOf(ap).length === 0;
      const withOwnNotes = ambiguousEntries.filter(e => !generatedMirrorOnly(e));
      const mirrorCount = ambiguousEntries.length;

      if (mirrorCount > 0) {
        posY = fit(posY, 20);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(10);
        doc.setTextColor(0, 0, 0);
        doc.text('CAVEATS RECORDED AGAINST THESE POSITIONS', layout.left(), posY);
        posY += 6;

        posY = callout(
          posY,
          `MIRROR-AMBIGUOUS - ${mirrorCount} POSITION(S)`,
          ascii(
            'The route past these access points was effectively a straight line, so the '
            + 'measurements fit a position on either side of it equally well. Which side is '
            + 'correct cannot be determined from this data, and neither candidate is the '
            + 'better one. Re-driving the area with at least one turn in the route resolves '
            + 'it. Every affected access point is listed in the table above with its '
            + 'alternative position and the distance between the two candidates; where the '
            + 'alternative was not recorded, that column says so.'
          ),
          [254, 252, 232], [234, 179, 8], [161, 98, 7]
        );
      }

      if (withOwnNotes.length > 0) {
        posY = fit(posY, 16);
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(9.5);
        doc.setTextColor(0, 0, 0);
        doc.text(
          ascii(`NOTES RECORDED BY THE ESTIMATOR (${withOwnNotes.length})`),
          layout.left(), posY,
        );
        posY += 5;
        for (const { ap } of withOwnNotes) {
          posY = fit(posY, 12);
          posY = paragraph(
            ascii(`${ap.ssid || '<hidden>'}  (${ap.bssid || 'unknown BSSID'})`),
            posY, { size: 8.5, bold: true, color: [0, 0, 0] }
          );
          // The estimator's own words, not the template this module generates.
          for (const note of locationNotesOf(ap)) {
            posY = paragraph(ascii(`- ${note}`), posY, { size: 8, color: [80, 80, 80], lead: 3.4 });
          }
          posY += 2;
        }
      }
    }
  }
}
