/**
 * Section 4 of the report: the authorized engagement scope.
 *
 * Moved out of `buildAndSavePDF` verbatim: the body below is the code that was
 * inline, unchanged. The only edits are the values it now takes as parameters
 * instead of reading them from the closure, and `npm run test:export` was run
 * before and after to confirm the document says exactly what it said.
 */
import autoTable from 'jspdf-autotable';

import { ascii, TARGET_KIND_LABEL, TARGET_KIND_ORDER } from '../archive';
import { type TargetKind } from '../../scopeDB';
import { TABLE_MARGIN } from '../geometry';
import { PAGE_BOTTOM } from '../layout';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export function renderEngagementScope(layout: PdfLayout, data: ReportData): void {
  const { doc, tocEntries, sectionHeading, paragraph, callout } = layout;
  const { activeScope, scopeReadError, gatedCommands } = data;
      // --- 4. AUTHORIZED ENGAGEMENT SCOPE ---
      // The authorization record is what makes this report defensible, so it sits
      // immediately behind the executive summary — and it is printed even when the
      // record is missing, because a missing record is itself a finding.
      doc.addPage();
      tocEntries.push({ title: 'AUTHORIZED ENGAGEMENT SCOPE', page: (doc as any).internal.getNumberOfPages() });
      let scopeY = sectionHeading('AUTHORIZED ENGAGEMENT SCOPE');

      /**
       * What the gate actually covers, in words, taken from the engine.
       *
       * `ScopePolicy.describe()` publishes `gated_commands`, so this sentence is
       * generated from the running policy rather than written by hand. If the
       * gated set is ever widened or narrowed, this prose follows it — which is
       * the point: a hand-written claim about the boundary is a claim that can
       * silently stop being true.
       *
       * When the engine could not be reached the wording falls back to naming no
       * count, because asserting one we did not read would be the same defect in
       * a smaller form.
       */
      const gatedDescription = gatedCommands.length > 0
        ? `every one of the ${gatedCommands.length} scope-gated command(s) (${gatedCommands.join(', ')})`
        : 'every scope-gated command (the engine did not report which commands those are for this export)';

      if (scopeReadError) {
        scopeY = callout(
          scopeY,
          'ENGAGEMENT SCOPE COULD NOT BE READ',
          `The engagement scope record could not be read from the local database, so this export cannot state what the operator was authorized to touch. Error reported: ${scopeReadError}. Treat the authorization status of this work as UNVERIFIED until the record is recovered.`,
          [254, 242, 242], [220, 38, 38], [220, 38, 38]
        );
      } else if (!activeScope) {
        scopeY = callout(
          scopeY,
          'NO ENGAGEMENT SCOPE RECORDED FOR THIS EXPORT',
          ascii(`No active engagement scope existed when this report was generated, so there is no stored record of who authorized this work, against which targets, or for what period. With no scope loaded the engine denies ${gatedDescription} by default, so no scope-gated action was possible — but reconnaissance and capture commands are not gated and remain available with or without a scope record. This document therefore carries no authorization evidence of its own. Before it is relied on externally, the operator should record the engagement (name, authorizing party, reference, validity window and target allowlist) and re-export.`),
          [254, 252, 232], [234, 179, 8], [161, 98, 7]
        );
        scopeY = paragraph(
          'The scope-enforcement audit trail on the following page still lists every targeted action the engine was asked to perform, and whether it was allowed or refused.',
          scopeY, { size: 9 }
        );
      } else {
        const validUntilExpired = !!activeScope.valid_until && new Date(activeScope.valid_until).getTime() < Date.now();
        const validityWindow = activeScope.valid_until
          ? `${activeScope.valid_from}  ->  ${activeScope.valid_until}${validUntilExpired ? '   [EXPIRED AT EXPORT TIME]' : ''}`
          : `${activeScope.valid_from}  ->  no end date recorded (OPEN-ENDED)`;

        autoTable(doc, {
          startY: scopeY - 6,
          head: [['AUTHORIZATION RECORD', '']],
          body: [
            ['Engagement', activeScope.engagement_name],
            ['Authorized by', activeScope.authorized_by],
            ['Authorization reference', activeScope.reference || 'none recorded'],
            ['Scope mode', activeScope.mode === 'UNRESTRICTED' ? 'UNRESTRICTED - no allowlist enforced' : 'ALLOWLIST - only the targets below were permitted'],
            ['Validity window', validityWindow],
            ['Record status', activeScope.is_active === 1 ? 'ACTIVE at export time' : 'NOT ACTIVE at export time'],
            ['Record created', activeScope.created_at],
            ['Scope record id', `#${activeScope.id}`],
            ['Operator notes', activeScope.notes || 'none'],
          ],
          theme: 'grid',
          headStyles: { fillColor: [15, 23, 42], textColor: 255, fontStyle: 'bold' },
          styles: { fontSize: 9, cellPadding: 2.5, overflow: 'linebreak', textColor: [0, 0, 0] },
          columnStyles: { 0: { cellWidth: 48, fontStyle: 'bold' } },
          didParseCell: (data) => {
            if (data.section !== 'body' || data.column.index !== 1) return;
            const text = data.cell.text.join(' ');
            if (text.includes('UNRESTRICTED') || text.includes('EXPIRED') || text.includes('NOT ACTIVE')) {
              data.cell.styles.textColor = [220, 38, 38];
              data.cell.styles.fontStyle = 'bold';
            }
          }
        });
        scopeY = (doc as any).lastAutoTable.finalY + 10;

        if (validUntilExpired) {
          scopeY = callout(
            scopeY,
            'AUTHORIZATION WINDOW HAD ALREADY CLOSED',
            `The recorded authorization expired on ${activeScope.valid_until}, which is before this report was generated. Any activity carried out after that date was outside the recorded window and should be reconciled against the authorizing party before this report is relied on.`,
            [254, 242, 242], [220, 38, 38], [220, 38, 38]
          );
        }

        if (activeScope.mode === 'UNRESTRICTED') {
          scopeY = callout(
            scopeY,
            'UNRESTRICTED MODE - NO TARGET ALLOWLIST WAS IN FORCE',
            `This engagement was run in UNRESTRICTED mode. No allowlist constrained the engine: offensive commands were permitted against any target the operator supplied, and nothing was refused on scope grounds. The operator explicitly acknowledged this before the mode was accepted; the acknowledgement recorded is: "${activeScope.unrestricted_ack || '(no acknowledgement text stored)'}". A reader assessing this report should treat the target list as operator-asserted rather than authorization-bounded, and should verify separately that every target reached was in fact covered by ${activeScope.reference || 'the engagement authorization'}.`,
            [254, 242, 242], [220, 38, 38], [220, 38, 38]
          );

          if (activeScope.targets.length > 0) {
            scopeY = paragraph(
              `${activeScope.targets.length} target(s) were nonetheless listed on the record and are reproduced below for reference. They were NOT enforced as a boundary.`,
              scopeY, { size: 9, bold: true, color: [161, 98, 7] }
            );
            scopeY += 2;
          }
        } else {
          // The claim is generated from the engine's own gated-command list, not
          // asserted. It used to read "refused every targeted offensive command",
          // which is only true if every targeted command is gated — and the gated
          // set is deliberately narrower: it covers the commands that can disrupt
          // a network, authenticate against it or intercept its traffic, not every
          // command that emits a packet. A report that overstates the boundary is
          // worse than one that states a narrower boundary accurately, because the
          // first one is checkable and wrong.
          scopeY = paragraph(
            ascii(`AUTHORIZED TARGETS (${activeScope.targets.length}). The engine refused ${gatedDescription} against anything not listed here; the refusals are recorded on the audit trail page. Commands outside that set are not checked against this list — see the method appendix for which they are and why.`),
            scopeY, { size: 9.5, bold: true, color: [0, 0, 0] }
          );
          scopeY += 3;
        }

        if (activeScope.targets.length === 0) {
          scopeY = callout(
            scopeY,
            'NO TARGETS ON THE ALLOWLIST',
            ascii(`The scope record carries no authorized targets. In ALLOWLIST mode this means the engine would have refused ${gatedDescription}, so no scope-gated action was possible under this record. Commands outside the gated set were still available.`),
            [254, 252, 232], [234, 179, 8], [161, 98, 7]
          );
        } else {
          const kindsPresent = [
            ...TARGET_KIND_ORDER.filter(k => activeScope!.targets.some(t => t.kind === k)),
            ...Array.from(new Set(activeScope.targets.map(t => String(t.kind))))
              .filter(k => !TARGET_KIND_ORDER.includes(k as TargetKind)),
          ];

          for (const kind of kindsPresent) {
            const group = activeScope.targets.filter(t => String(t.kind) === String(kind));
            if (group.length === 0) continue;

            if (scopeY > PAGE_BOTTOM - 20) {
              doc.addPage();
              scopeY = 25;
            }
            doc.setFont('helvetica', 'bold');
            doc.setFontSize(10);
            doc.setTextColor(30, 41, 59);
            doc.text(`${TARGET_KIND_LABEL[String(kind)] || String(kind)}  -  ${group.length} authorized`, 14, scopeY);

            autoTable(doc, {
              startY: scopeY + 2,
              head: [['#', 'Authorized Target', 'Operator Note']],
              body: group.map((t, idx) => [String(idx + 1), t.value, t.note || '-']),
              theme: 'grid',
              headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 8.5 },
              styles: { fontSize: 9, cellPadding: 2.2, font: 'courier', overflow: 'linebreak', textColor: [0, 0, 0] },
              columnStyles: { 0: { cellWidth: 10, halign: 'center' }, 1: { cellWidth: 70 } },
              margin: TABLE_MARGIN,
            });
            scopeY = (doc as any).lastAutoTable.finalY + 9;
          }
        }
      }
}
