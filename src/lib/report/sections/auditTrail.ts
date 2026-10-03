/**
 * Section 5 of the report: the scope enforcement audit trail.
 *
 * Moved out of `buildAndSavePDF` verbatim: the body below is the code that was
 * inline, unchanged. The only edits are the values it now takes as parameters
 * instead of reading them from the closure, and `npm run test:export` was run
 * before and after to confirm the document says exactly what it said.
 */
import autoTable from 'jspdf-autotable';

import { TABLE_MARGIN } from '../geometry';
import { PAGE_BOTTOM } from '../layout';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export function renderAuditTrail(layout: PdfLayout, data: ReportData): void {
  const { doc, tocEntries, sectionHeading, paragraph, callout } = layout;
  const {
    activeScope, auditRows, auditTotal, auditAllowed, auditBlocked, auditGlobal,
    auditReadError, auditTruncated,
  } = data;
      // --- 5. SCOPE ENFORCEMENT AUDIT TRAIL ---
      doc.addPage();
      tocEntries.push({ title: 'SCOPE ENFORCEMENT AUDIT TRAIL', page: (doc as any).internal.getNumberOfPages() });
      let auditY = sectionHeading('SCOPE ENFORCEMENT AUDIT TRAIL');

      if (auditReadError) {
        auditY = callout(
          auditY,
          'AUDIT TRAIL COULD NOT BE READ',
          `The scope-enforcement audit log could not be read from the local database, so this export cannot show which targeted actions were allowed and which were refused. Error reported: ${auditReadError}.`,
          [254, 242, 242], [220, 38, 38], [220, 38, 38]
        );
      } else {
        const scopeLabel = activeScope
          ? `engagement "${activeScope.engagement_name}" (scope record #${activeScope.id})`
          : 'this archive (no engagement scope was active, so the whole recorded trail is shown)';

        auditY = paragraph(
          `Every targeted action submitted to the engine passes the scope gate first. ${auditAllowed} action(s) were ALLOWED and ${auditBlocked} were BLOCKED for ${scopeLabel}, out of ${auditTotal} recorded event(s).`,
          auditY, { size: 10.5, bold: true, color: [0, 0, 0] }
        );
        auditY += 4;

        // Allowed / blocked counters, styled like the summary metrics block.
        autoTable(doc, {
          startY: auditY,
          head: [['ACTIONS ALLOWED', 'ACTIONS BLOCKED BY SCOPE GATE', 'EVENTS RECORDED']],
          body: [[String(auditAllowed), String(auditBlocked), String(auditTotal)]],
          theme: 'grid',
          margin: TABLE_MARGIN,
          headStyles: { fillColor: [15, 23, 42], textColor: 255, fontStyle: 'bold', halign: 'center', fontSize: 8.5 },
          bodyStyles: { font: 'courier', halign: 'center', fontSize: 18, fontStyle: 'bold', textColor: [0, 0, 0] },
          didParseCell: (data) => {
            if (data.section !== 'body') return;
            if (data.column.index === 0) data.cell.styles.textColor = [16, 185, 129];
            if (data.column.index === 1 && auditBlocked > 0) data.cell.styles.textColor = [37, 99, 235];
          }
        });
        auditY = (doc as any).lastAutoTable.finalY + 10;

        auditY = callout(
          auditY,
          auditBlocked > 0 ? `${auditBlocked} REFUSED ACTION(S) - EVIDENCE OF CONTROL` : 'NO REFUSALS RECORDED',
          auditBlocked > 0
            ? 'Each BLOCKED row below is a command the operator issued that the rig declined to execute because the target was not covered by the authorization on the previous page. They are not errors and not noise: they are the record of the engagement staying inside its boundary, and of the gate working under real operator pressure. Read alongside the ALLOWED rows, they show that the target list in this report is the list the engine was permitted to touch.'
            : 'No command was refused on scope grounds. Either every targeted action the operator issued fell inside the authorization, or no targeted action was attempted. The ALLOWED rows below show which it was.',
          auditBlocked > 0 ? [239, 246, 255] : [240, 253, 244],
          auditBlocked > 0 ? [37, 99, 235] : [16, 185, 129],
          auditBlocked > 0 ? [37, 99, 235] : [16, 185, 129]
        );

        if (auditGlobal && activeScope && (auditGlobal.allowed !== auditAllowed || auditGlobal.blocked !== auditBlocked)) {
          auditY = paragraph(
            `Archive-wide totals, across every engagement ever recorded on this rig: ${auditGlobal.allowed} ALLOWED / ${auditGlobal.blocked} BLOCKED. The table below is scoped to this engagement only.`,
            auditY, { size: 8.5, color: [110, 110, 110] }
          );
          auditY += 3;
        }

        if (auditTruncated) {
          auditY = callout(
            auditY,
            'TABLE TRUNCATED - NOT ALL EVIDENCE IS SHOWN',
            `${auditTotal} audit events were recorded, which is more than a readable report can carry. The table below lists the ${auditRows.length} MOST RECENT events only; the remaining ${auditTotal - auditRows.length} event(s) are omitted from this document and remain intact in the local audit database. The complete trail is available as a CSV: use EXPORT AUDIT TRAIL on the Reports page of the application, which writes every recorded event with no cap.`,
            [254, 252, 232], [234, 179, 8], [161, 98, 7]
          );
        }

        if (auditRows.length === 0) {
          auditY = callout(
            auditY,
            'NO SCOPE-GATED ACTIONS RECORDED',
            activeScope
              ? 'No targeted action was submitted to the engine under this engagement, so the gate had nothing to allow or refuse. Passive observation is not gated and does not appear here. If offensive activity was expected for this engagement, the audit log does not corroborate it.'
              : 'The audit log holds no events. No targeted action was submitted to the engine on this rig, or the log has not yet recorded any. Passive observation is not gated and does not appear here.',
            [245, 245, 245], [150, 150, 150], [80, 80, 80]
          );
        } else {
          autoTable(doc, {
            startY: auditY,
            head: [['Timestamp (as recorded)', 'Command', 'Target', 'Kind', 'Decision', 'Reason']],
            body: auditRows.map(row => [
              row.ts,
              row.command,
              row.target || '-',
              row.target_kind || '-',
              row.decision,
              row.reason || '-',
            ]),
            theme: 'grid',
            headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 8 },
            styles: { fontSize: 7.5, cellPadding: 1.8, overflow: 'linebreak', textColor: [0, 0, 0] },
            columnStyles: {
              0: { cellWidth: 34, font: 'courier' },
              1: { cellWidth: 30 },
              2: { cellWidth: 32, font: 'courier' },
              3: { cellWidth: 13, halign: 'center' },
              4: { cellWidth: 18, halign: 'center', fontStyle: 'bold' },
              5: { cellWidth: 51 },
            },
            margin: TABLE_MARGIN,
            didParseCell: (data) => {
              if (data.section !== 'body') return;
              const decision = auditRows[data.row.index]?.decision;
              if (decision === 'BLOCKED') {
                if (data.column.index === 4) {
                  data.cell.styles.textColor = [37, 99, 235];
                }
                data.cell.styles.fillColor = [239, 246, 255];
              } else if (data.column.index === 4) {
                data.cell.styles.textColor = [13, 148, 136];
              }
            }
          });
          auditY = (doc as any).lastAutoTable.finalY + 8;

          if (auditY < PAGE_BOTTOM) {
            paragraph(
              'Blue rows are actions the scope gate refused. Timestamps are reproduced exactly as recorded by the engine.',
              auditY, { size: 8, color: [110, 110, 110] }
            );
          }
        }
      }

}
