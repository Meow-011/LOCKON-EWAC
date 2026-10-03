/**
 * Section 9 of the report: WPS exposure.
 *
 * Moved out of `buildAndSavePDF` verbatim: the body below is the code that was
 * inline, unchanged. The only edits are the values it now takes as parameters
 * instead of reading them from the closure, and `npm run test:export` was run
 * before and after to confirm the document says exactly what it said.
 */
import autoTable from 'jspdf-autotable';
import { apsOf, ascii, dedupeApsByBssid, isWirelessReport } from '../archive';
import { wpsLabel, wpsMeasured } from '../../apRisk';
import { formatCoord } from '../../position';
import { type Severity } from '../../riskEngine';
import { SEVERITY_RGB } from '../../severityStyle';
import { TABLE_MARGIN } from '../geometry';
import { PAGE_BOTTOM } from '../layout';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export function renderWpsExposure(layout: PdfLayout, data: ReportData): void {
  const { doc, tocEntries, sectionHeading, paragraph, callout } = layout;
  const { reportsArray, wpsEntries } = data;
      // --- 9. WPS EXPOSURE ---
      doc.addPage();
      tocEntries.push({ title: 'WPS EXPOSURE', page: (doc as any).internal.getNumberOfPages() });
      let wpsY = sectionHeading('WPS EXPOSURE');

      wpsY = paragraph(
        'Wi-Fi Protected Setup lets a client join using an 8-digit PIN. The PIN is validated in two independent halves, which reduces the search space to roughly 11,000 attempts, and recovering it yields the WPA passphrase in full no matter how strong that passphrase is. An access point advertising WPS therefore undermines its own encryption, which is precisely why a verdict based on encryption alone was never sufficient.',
        wpsY, { size: 9.5 }
      );
      wpsY += 4;

      // Three states, not two. The count of access points a WPS scan actually
      // covered is the denominator this section needs: without it, "no WPS found"
      // and "WPS was never looked for" print identically.
      // The WPS denominator. `wpsEntries` is deduplicated in `assemble.ts`, so
      // leaving this one raw did not merely inflate a count — it halved the stated
      // coverage rate, which is the figure a reader acts on.
      const allAps = dedupeApsByBssid(reportsArray.filter(isWirelessReport).flatMap(r => apsOf(r)));
      const measuredAps = allAps.filter(wpsMeasured);
      const unmeasuredCount = allAps.length - measuredAps.length;

      if (measuredAps.length === 0) {
        // This used to read "NO WPS-ENABLED ACCESS POINT WAS OBSERVED ... WPS
        // presence is read from the beacon information element", in a green box.
        // No beacon information element had ever been parsed, because nothing in
        // the app sent `scan_wps`. The wording described a measurement that did
        // not happen and then hedged it, which made a fabricated negative read as
        // a careful one.
        wpsY = callout(
          wpsY,
          'WPS WAS NOT ASSESSED IN THIS EXPORT',
          ascii(`No WPS scan result is present for any of the ${allAps.length} access point(s) in this archive, so this report states nothing about WPS either way. WPS presence is read from the beacon information element by a dedicated scan that is separate from the survey, and it needs a monitor-mode adapter. Absence of a result here is absence of a measurement, not evidence that WPS is disabled. Run a WPS scan and re-export before treating this area as assessed.`),
          [254, 252, 232], [234, 179, 8], [161, 98, 7]
        );
      } else if (wpsEntries.length === 0) {
        // Genuinely measured, genuinely nothing found. This is the one case that
        // earns a green box — and it still states its denominator.
        wpsY = callout(
          wpsY,
          'NO WPS-ENABLED ACCESS POINT WAS OBSERVED',
          ascii(`${measuredAps.length} access point(s) had their beacon parsed by a WPS scan and none advertised WPS.` +
            (unmeasuredCount > 0
              ? ` The other ${unmeasuredCount} access point(s) in this archive were not covered by a WPS scan and nothing here applies to them.`
              : '') +
            ' An access point with WPS enabled but not advertised, or one whose beacon was not captured cleanly, would not appear here. This is an observation, not a guarantee.'),
          [240, 253, 244], [16, 185, 129], [13, 148, 136]
        );
      } else {
        const unlocked = wpsEntries.filter(e => !e.ap.wps_locked).length;
        wpsY = paragraph(
          ascii(`${wpsEntries.length} access point(s) advertise WPS; ${unlocked} of them without any lockout. A rate-limited access point is still exposed, because lockout behaviour varies between firmware versions and is often cleared by a reboot.`),
          wpsY, { size: 9.5, bold: true, color: [0, 0, 0] }
        );
        wpsY += 3;
        // Only a positive observation puts an access point in this table, so the
        // ones missing from it are unmeasured rather than cleared. Stating the
        // denominator is the difference between a list and a claim about a
        // population.
        wpsY = paragraph(
          ascii(`Only access points with a positive WPS observation appear above. Of the ${allAps.length} access point(s) in this archive, ${measuredAps.length} were covered by a WPS scan` +
            (unmeasuredCount > 0
              ? `, and the remaining ${unmeasuredCount} were not — those are unmeasured, not WPS-free.`
              : '.')),
          wpsY, { size: 8.5, color: [80, 80, 80] }
        );
        wpsY += 4;

        autoTable(doc, {
          startY: wpsY,
          head: [['SSID', 'BSSID', 'Vendor', 'Security', 'CH', 'WPS state', 'WPS ver', 'Severity', 'Position']],
          body: wpsEntries.map(e => [
            ascii(e.ap.ssid || '<hidden>'),
            ascii(e.ap.bssid || 'unknown'),
            ascii(e.ap.vendor || 'Unknown'),
            ascii(e.ap.encryption || 'Unknown'),
            e.ap.channel ?? '-',
            wpsLabel(e.ap),
            ascii(e.ap.wps_version || 'n/r'),
            e.severity,
            formatCoord(e.ap.latitude, e.ap.longitude),
          ]),
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 7.5 },
          styles: { fontSize: 7.5, cellPadding: 1.8, overflow: 'linebreak', textColor: [0, 0, 0] },
          columnStyles: {
            0: { cellWidth: 26 },
            1: { cellWidth: 28, font: 'courier' },
            2: { cellWidth: 22 },
            3: { cellWidth: 18 },
            4: { cellWidth: 8, halign: 'center' },
            5: { cellWidth: 26, halign: 'center', fontStyle: 'bold' },
            6: { cellWidth: 12, halign: 'center' },
            7: { cellWidth: 18, halign: 'center', fontStyle: 'bold' },
            8: { cellWidth: 20, font: 'courier', fontSize: 6.5 },
          },
          margin: TABLE_MARGIN,
          didParseCell: (data) => {
            if (data.section !== 'body') return;
            if (data.column.index === 7) {
              const level = data.cell.text[0] as Severity;
              if (SEVERITY_RGB[level]) data.cell.styles.textColor = SEVERITY_RGB[level];
            }
            if (data.column.index === 5 && /unlocked/i.test(data.cell.text.join(' '))) {
              data.cell.styles.textColor = [220, 38, 38];
            }
          }
        });
        wpsY = (doc as any).lastAutoTable.finalY + 6;

        if (wpsY < PAGE_BOTTOM) {
          paragraph(
            'Remediation is the same in every case: disable WPS on the access point. It provides no convenience that offsets handing out the passphrase.',
            wpsY, { size: 8.5, color: [80, 80, 80] }
          );
        }
      }
}
