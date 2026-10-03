/**
 * Section 8 of the report: the rogue access point and evil twin assessment.
 *
 * Moved out of `buildAndSavePDF` verbatim: the body below is the code that was
 * inline, unchanged. The only edits are the values it now takes as parameters
 * instead of reading them from the closure, and `npm run test:export` was run
 * before and after to confirm the document says exactly what it said.
 */
import autoTable from 'jspdf-autotable';
import { ascii } from '../archive';
import { formatCoord } from '../../position';
import { TABLE_MARGIN } from '../geometry';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export function renderRogueAssessment(layout: PdfLayout, data: ReportData): void {
  const { doc, tocEntries, fit, sectionHeading, paragraph, callout } = layout;
  const { rogueEntries, clientTotals, clientReadError } = data;
      // --- 8. ROGUE ACCESS POINT / EVIL TWIN ASSESSMENT ---
      doc.addPage();
      tocEntries.push({ title: 'ROGUE AP / EVIL TWIN ASSESSMENT', page: (doc as any).internal.getNumberOfPages() });
      let rogueY = sectionHeading('ROGUE AP / EVIL TWIN ASSESSMENT');

      rogueY = callout(
        rogueY,
        'HOW TO READ THIS SECTION - SUSPECTED IS NOT AN ACCUSATION',
        'A verdict of SUSPECTED means indicators were present but are not sufficient to assert that an access point is hostile. Legitimate causes are common: a WPA2/WPA3 transition deployment, a mixed-mode legacy network, a mesh node, a phone hotspot named after the office network, or a neighbouring tenant. Nothing in this section should be treated as an allegation against a person or an organisation. LIKELY and CONFIRMED mean more indicators aligned, and still call for physical verification before any action is taken. The correct next step for every row below is to locate the device and establish whether it is authorised.',
        [239, 246, 255], [37, 99, 235], [37, 99, 235]
      );

      if (rogueEntries.length === 0) {
        rogueY = callout(
          rogueY,
          'NO ROGUE-AP INDICATORS ABOVE THE REPORTING THRESHOLD',
          'No access point in this export scored above the reporting threshold for rogue/evil-twin indicators. This analysis is beacon-based: it compares the properties advertised by access points sharing an SSID. A competent clone that matches vendor, channel and signal profile can score below the threshold, and hidden or blank SSIDs are excluded from twin grouping altogether, so this is not proof that no rogue access point was present.',
          [240, 253, 244], [16, 185, 129], [13, 148, 136]
        );
      } else {
        rogueY = paragraph(
          ascii(`${rogueEntries.length} access point(s) carry rogue-AP indicators. Each is listed with its verdict, its indicator score, the specific reasons that produced it, and the stations observed associated with it.`),
          rogueY, { size: 9.5, bold: true, color: [0, 0, 0] }
        );
        rogueY += 4;

        autoTable(doc, {
          startY: rogueY,
          head: [['Verdict', 'Score', 'Severity', 'SSID', 'BSSID', 'Vendor', 'Security', 'CH', 'Position']],
          body: rogueEntries.map(e => [
            e.verdict,
            e.score === null ? 'n/r' : String(e.score),
            `${e.severity}${e.confidence ? ` / ${e.confidence}` : ''}`,
            ascii(e.ap.ssid || '<hidden>'),
            ascii(e.ap.bssid || 'unknown'),
            ascii(e.ap.vendor || 'Unknown'),
            ascii(e.ap.encryption || 'Unknown'),
            e.ap.channel ?? '-',
            formatCoord(e.ap.latitude, e.ap.longitude),
          ]),
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 7.5 },
          styles: { fontSize: 7.5, cellPadding: 1.8, overflow: 'linebreak', textColor: [0, 0, 0] },
          columnStyles: {
            0: { cellWidth: 20, halign: 'center', fontStyle: 'bold' },
            1: { cellWidth: 11, halign: 'center', font: 'courier' },
            2: { cellWidth: 27, halign: 'center', fontSize: 6.5 },
            3: { cellWidth: 24 },
            4: { cellWidth: 28, font: 'courier' },
            5: { cellWidth: 22 },
            6: { cellWidth: 18 },
            7: { cellWidth: 8, halign: 'center' },
            8: { cellWidth: 20, font: 'courier', fontSize: 6.5 },
          },
          margin: TABLE_MARGIN,
          didParseCell: (data) => {
            if (data.section !== 'body' || data.column.index !== 0) return;
            const verdict = data.cell.text[0];
            if (verdict === 'CONFIRMED') data.cell.styles.textColor = [153, 27, 27];
            else if (verdict === 'LIKELY') data.cell.styles.textColor = [220, 38, 38];
            else data.cell.styles.textColor = [217, 119, 6];
          }
        });
        rogueY = (doc as any).lastAutoTable.finalY + 8;

        // Per-AP indicator reasons and associated stations. The reasons are the
        // whole value of the detection: a verdict with no stated basis is not
        // evidence a reader can act on.
        for (const e of rogueEntries) {
          rogueY = fit(rogueY, 26);
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(10);
          doc.setTextColor(30, 41, 59);
          doc.text(ascii(`${e.verdict}  -  ${e.ap.ssid || '<hidden>'}  (${e.ap.bssid || 'unknown BSSID'})`), 14, rogueY);
          rogueY += 5;

          if (e.heuristicOnly) {
            rogueY = paragraph(
              'This archive predates per-indicator scoring, so the verdict below rests on the SSID/encryption-split heuristic alone and no indicator weights are available for it.',
              rogueY, { size: 8, bold: true, color: [161, 98, 7] }
            );
            rogueY += 1;
          }

          if (e.indicators.length === 0) {
            rogueY = paragraph(
              'No indicator detail was recorded for this access point, so the basis of the verdict cannot be reproduced here. Treat it as unsubstantiated until it is re-observed with a build that records indicator detail.',
              rogueY, { size: 8.5, color: [161, 98, 7] }
            );
            rogueY += 2;
          } else {
            autoTable(doc, {
              startY: rogueY,
              head: [['Indicator', 'Weight', 'What was observed']],
              body: e.indicators.map(i => [ascii(i.code), i.weight ? String(i.weight) : 'n/r', ascii(i.detail)]),
              theme: 'grid',
              headStyles: { fillColor: [71, 85, 105], textColor: 255, fontSize: 7.5 },
              styles: { fontSize: 7.5, cellPadding: 1.8, overflow: 'linebreak', textColor: [0, 0, 0] },
              columnStyles: {
                0: { cellWidth: 40, font: 'courier' },
                1: { cellWidth: 14, halign: 'center' },
                2: { cellWidth: 124 },
              },
              margin: TABLE_MARGIN,
            });
            rogueY = (doc as any).lastAutoTable.finalY + 4;
          }

          // Associated stations. "Probed" and "associated" are different claims and
          // are never merged: only an observed association means connected.
          const associated = e.clients;
          if (associated.length === 0) {
            rogueY = paragraph(
              'No station was observed associated with this access point during the survey. That does not mean none was: association is only visible when the adapter can see data frames, and a client can associate outside the observation window entirely.',
              rogueY, { size: 8.5, color: [80, 80, 80] }
            );
            rogueY += 3;
          } else {
            rogueY = fit(rogueY, 20);
            rogueY = paragraph(
              ascii(`${associated.length} station(s) were observed ASSOCIATED with this access point - that is, seen exchanging frames with it, not merely present nearby.`),
              rogueY, { size: 8.5, bold: true, color: [153, 27, 27] }
            );
            rogueY += 2;

            autoTable(doc, {
              startY: rogueY,
              head: [['Station MAC', 'Vendor', 'MAC type', 'Strongest RSSI', 'Probes seen', 'First seen', 'Last seen']],
              body: associated.map(c => [
                ascii(c.mac),
                ascii(c.vendor || 'Unknown'),
                c.is_randomized ? 'RANDOMISED' : 'global (OUI)',
                c.strongest_rssi === null ? 'n/r' : `${c.strongest_rssi} dBm`,
                String(c.probe_count ?? 0),
                ascii(c.first_seen),
                ascii(c.last_seen),
              ]),
              theme: 'grid',
              headStyles: { fillColor: [71, 85, 105], textColor: 255, fontSize: 7.5 },
              styles: { fontSize: 7, cellPadding: 1.6, overflow: 'linebreak', textColor: [0, 0, 0] },
              columnStyles: {
                0: { cellWidth: 30, font: 'courier' },
                1: { cellWidth: 26 },
                2: { cellWidth: 24, halign: 'center' },
                3: { cellWidth: 20, halign: 'center' },
                4: { cellWidth: 16, halign: 'center' },
                5: { cellWidth: 30, fontSize: 6.5 },
                6: { cellWidth: 30, fontSize: 6.5 },
              },
              margin: TABLE_MARGIN,
              didParseCell: (data) => {
                if (data.section === 'body' && data.column.index === 2 && data.cell.text[0] === 'RANDOMISED') {
                  data.cell.styles.textColor = [161, 98, 7];
                }
              }
            });
            rogueY = (doc as any).lastAutoTable.finalY + 4;

            if (associated.some(c => c.is_randomized)) {
              rogueY = paragraph(
                'A randomised MAC address is not a stable device identity. Modern phones and laptops rotate it per network and over time, so the same physical device can appear as several rows and a row cannot be attributed to a person or to a specific handset.',
                rogueY, { size: 8, color: [161, 98, 7] }
              );
              rogueY += 3;
            }
          }
          rogueY += 2;
        }

        if (clientTotals) {
          rogueY = fit(rogueY, 20);
          rogueY = paragraph(
            ascii(`Station observations across this rig, for context: ${clientTotals.total} station(s) recorded, of which ${clientTotals.associated} were seen ASSOCIATED with an access point and ${clientTotals.probe_only} were seen only PROBING (broadcasting requests without a visible association). ${clientTotals.randomized} used a randomised MAC address. Probing means present; it does not mean connected, and the two are never combined in this document.`),
            rogueY, { size: 8.5, color: [80, 80, 80] }
          );
          rogueY += 3;
        }
        if (clientReadError) {
          rogueY = paragraph(
            ascii(`Station records could not be fully read (${clientReadError}), so the association lists above may be incomplete.`),
            rogueY, { size: 8, color: [161, 98, 7] }
          );
        }
      }
}
