/**
 * Section 12 of the report: the retest and remediation delta.
 *
 * Moved out of `buildAndSavePDF` verbatim: the body below is the code that was
 * inline, unchanged. The only edits are the values it now takes as parameters
 * instead of reading them from the closure, and `npm run test:export` was run
 * before and after to confirm the document says exactly what it said.
 */
import autoTable from 'jspdf-autotable';
import { ascii } from '../archive';
import { type Severity } from '../../riskEngine';
import { SEVERITY_RGB } from '../../severityStyle';
import { TABLE_MARGIN } from '../geometry';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export interface RetestDeltaOptions {
  /**
   * The baseline this export is being compared against, or null for none.
   *
   * A property of this export rather than of the archive: the operator chooses it
   * from the export menu, and `null` is a first-class choice shown as selected,
   * because they have to be able to see that the document claims nothing.
   */
  baselineId: number | null;
}

export function renderRetestDelta(
  layout: PdfLayout,
  data: ReportData,
  { baselineId }: RetestDeltaOptions,
): void {
  const { doc, tocEntries, fit, sectionHeading, paragraph, callout } = layout;
  const { retest, retestError } = data;
      // --- 12. RETEST / REMEDIATION DELTA ---
      // The "did the fixes work" answer. Only printed when a baseline was chosen,
      // because inventing a comparison point would be worse than omitting one.
      if (baselineId !== null) {
        doc.addPage();
        tocEntries.push({ title: 'RETEST / REMEDIATION DELTA', page: (doc as any).internal.getNumberOfPages() });
        let reY = sectionHeading('RETEST / REMEDIATION DELTA');

        if (retestError || !retest) {
          reY = callout(
            reY,
            'BASELINE COMPARISON COULD NOT BE MADE',
            ascii(`A retest baseline (#${baselineId}) was selected for this export but the comparison could not be produced${retestError ? `: ${retestError}` : '.'} No remediation progress is claimed in this document.`),
            [254, 242, 242], [220, 38, 38], [220, 38, 38]
          );
        } else {
          reY = paragraph(
            ascii(`Compared against baseline "${retest.baseline_label ?? `#${baselineId}`}", taken ${retest.baseline_at ?? 'at an unrecorded time'}. Findings are matched on a stable fingerprint of the subject and the issue, not on a score or a timestamp, so the same issue is recognised across visits rather than being reported as new each time.`),
            reY, { size: 9.5 }
          );
          reY += 4;

          autoTable(doc, {
            startY: reY,
            head: [['FIXED', 'REGRESSED', 'STILL OPEN', 'NEWLY FOUND']],
            body: [[
              String(retest.fixed.length), String(retest.regressed.length),
              String(retest.still_open.length), String(retest.newly_found.length),
            ]],
            theme: 'grid',
            margin: TABLE_MARGIN,
            headStyles: { fillColor: [15, 23, 42], textColor: 255, fontStyle: 'bold', halign: 'center', fontSize: 8.5 },
            bodyStyles: { font: 'courier', halign: 'center', fontSize: 18, fontStyle: 'bold', textColor: [0, 0, 0] },
            didParseCell: (data) => {
              if (data.section !== 'body') return;
              const n = parseInt(data.cell.text[0] || '0');
              if (data.column.index === 0 && n > 0) data.cell.styles.textColor = [13, 148, 136];
              if ((data.column.index === 1 || data.column.index === 3) && n > 0) data.cell.styles.textColor = [220, 38, 38];
              if (data.column.index === 2 && n > 0) data.cell.styles.textColor = [217, 119, 6];
            }
          });
          reY = (doc as any).lastAutoTable.finalY + 8;

          if (retest.regressed.length > 0) {
            reY = callout(
              reY,
              `${retest.regressed.length} REGRESSION(S) - PREVIOUSLY CLOSED, OBSERVED AGAIN`,
              'Each regressed finding had been recorded as fixed or accepted and has since been observed again. A regression usually means a configuration was reverted, a device was replaced with an unhardened one, or the original fix did not persist across a reboot. These warrant attention ahead of newly found issues of the same severity, because the control that was supposed to hold has already failed once.',
              [254, 242, 242], [220, 38, 38], [220, 38, 38]
            );
          }

          const deltaGroup = (
            y: number,
            title: string,
            rows: typeof retest.fixed,
            headFill: [number, number, number],
            emptyNote: string
          ) => {
            let cursor = fit(y, 22);
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(10.5);
            doc.setTextColor(headFill[0], headFill[1], headFill[2]);
            doc.text(ascii(`${title} (${rows.length})`), 14, cursor);
            cursor += 5;

            if (rows.length === 0) {
              return paragraph(emptyNote, cursor, { size: 8.5, color: [110, 110, 110] }) + 4;
            }

            autoTable(doc, {
              startY: cursor,
              head: [['Severity', 'Subject', 'Finding', 'First seen', 'Last seen', 'Status']],
              body: rows.slice(0, 60).map(f => [
                f.severity,
                ascii(f.subject_id),
                ascii(f.title),
                ascii(f.first_seen),
                ascii(f.last_seen),
                f.status,
              ]),
              theme: 'grid',
              headStyles: { fillColor: headFill, textColor: 255, fontSize: 7.5 },
              styles: { fontSize: 7, cellPadding: 1.6, overflow: 'linebreak', textColor: [0, 0, 0] },
              columnStyles: {
                0: { cellWidth: 18, halign: 'center', fontStyle: 'bold' },
                1: { cellWidth: 30, font: 'courier' },
                2: { cellWidth: 62 },
                3: { cellWidth: 24, fontSize: 6.5 },
                4: { cellWidth: 24, fontSize: 6.5 },
                5: { cellWidth: 20, halign: 'center' },
              },
              margin: TABLE_MARGIN,
              didParseCell: (data) => {
                if (data.section === 'body' && data.column.index === 0) {
                  const level = data.cell.text[0] as Severity;
                  if (SEVERITY_RGB[level]) data.cell.styles.textColor = SEVERITY_RGB[level];
                }
              }
            });
            let after = (doc as any).lastAutoTable.finalY + 4;
            if (rows.length > 60) {
              after = paragraph(
                ascii(`${rows.length - 60} further row(s) in this group are not printed; the complete set is held in the local findings database.`),
                after, { size: 7.5, color: [161, 98, 7] }
              ) + 3;
            }
            return after + 3;
          };

          reY = deltaGroup(reY, 'REGRESSED', retest.regressed, [153, 27, 27],
            'Nothing that had been closed has been observed again.');
          reY = deltaGroup(reY, 'STILL OPEN SINCE THE BASELINE', retest.still_open, [217, 119, 6],
            'Nothing recorded at the baseline is still open.');
          reY = deltaGroup(reY, 'FIXED SINCE THE BASELINE', retest.fixed, [13, 148, 136],
            'No finding has been recorded as fixed or accepted since the baseline. This means no closure was recorded, not that no work was done: a fix only appears here once its finding is marked FIXED.');
          reY = deltaGroup(reY, 'NEWLY FOUND SINCE THE BASELINE', retest.newly_found, [37, 99, 235],
            'No new finding has been raised since the baseline.');

          paragraph(
            'A finding is only counted as FIXED when it was explicitly marked so; this tool does not infer a fix from an absence of observation, because an access point that was switched off, out of range, or simply not surveyed this time would otherwise look remediated.',
            fit(reY, 12), { size: 8, color: [110, 110, 110] }
          );
        }
      }
}
