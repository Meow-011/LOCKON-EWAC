/**
 * Section 7 of the report: the prioritised findings table.
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
import { geometry, TABLE_MARGIN } from '../geometry';
import { PAGE_BOTTOM } from '../layout';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export function renderPrioritisedFindings(layout: PdfLayout, data: ReportData): void {
  const { doc, tocEntries, sectionHeading, paragraph, callout } = layout;
  const { allFindings, findingStatus, methodology } = data;

      // --- 7. PRIORITISED FINDINGS ---
      // Every severity in this document comes from here. One table, one rule set,
      // each row carrying its own reason.
      doc.addPage();
      tocEntries.push({ title: 'PRIORITISED FINDINGS', page: (doc as any).internal.getNumberOfPages() });
      let findY = sectionHeading('PRIORITISED FINDINGS');

      if (allFindings.length === 0) {
        findY = callout(
          findY,
          'NO FINDINGS WERE RAISED',
          'The rule set raised no finding against anything in this export. That is a statement about what was observed, not about the security of the environment: see the survey coverage section for where the survey went and the method appendix for what this hardware was able to test.',
          [240, 253, 244], [16, 185, 129], [13, 148, 136]
        );
      } else {
        findY = paragraph(
          ascii(`${allFindings.length} finding(s), highest first. SEVERITY is how serious the issue would be; CONFIDENCE is how sure this tool is that it is real. They are independent: a SUSPECTED rogue access point is a serious finding that has not been confirmed, and is reported as such rather than downgraded. STATUS is taken from the finding history where a previous run recorded one. WHY is a reference into the list of reasons printed after the table - findings raised by the same rule share a reason, so each one is written out once rather than repeated on every row.`),
          findY, { size: 9 }
        );
        findY += 3;

        /*
          The reason is printed once and referenced, not repeated per row.

          `rationale` is a fixed string belonging to the rule, not to the finding.
          Forty-two unencrypted networks produce forty-two findings carrying the
          *same* five-line paragraph, and the table was printing all forty-two of
          them: about eight rows fitted a page, so seventy findings ran to nine
          pages of which the overwhelming majority was one paragraph photocopied
          down the right-hand side.

          Repetition at that volume does not just waste paper, it actively hides
          the table. The columns a reader scans - severity, score, which radio -
          were squeezed into 114 mm so that a constant could have 64 mm, and the
          subject line wrapped to three lines because of it.

          So each distinct rationale gets a code, the codes are listed once below
          the table, and the column becomes the code. Nothing is removed: every
          finding still states its reason, and the count beside each reason makes
          the repetition legible as a fact about the survey ("42 findings share
          this") instead of something the reader has to infer by reading the same
          words over and over.
        */
        const rationaleCodes = new Map<string, { code: string; count: number }>();
        const findingRows = [...allFindings]
          .sort((a, b) => b.risk_score - a.risk_score)
          .map(f => {
            const text = ascii(f.rationale);
            // Assigned in the table's own order, so R1 is the reason for the
            // highest-scoring row and the list below reads top-down with it.
            let entry = rationaleCodes.get(text);
            if (!entry) {
              entry = { code: `R${rationaleCodes.size + 1}`, count: 0 };
              rationaleCodes.set(text, entry);
            }
            entry.count += 1;
            return [
              f.severity,
              String(f.risk_score),
              f.confidence,
              findingStatus.get(f.fingerprint) ?? 'NEW',
              ascii(f.title),
              entry.code,
            ];
          });

        autoTable(doc, {
          startY: findY,
          head: [['Severity', 'Score', 'Confidence', 'Status', 'Finding', 'Why']],
          body: findingRows,
          theme: 'grid',
          headStyles: { fillColor: [30, 41, 59], textColor: 255, fontSize: 8 },
          styles: { fontSize: 7.5, cellPadding: 1.8, overflow: 'linebreak', textColor: [0, 0, 0] },
          columnStyles: {
            /*
              178 mm, the portrait content column. The old set summed to exactly
              182, which fitted the former margins but left `Score` on 11 mm —
              narrower than the word "Score" itself, so the header wrapped to
              "Scor / e" on every findings page. A column has to hold its own
              heading before it holds anything else.
            */
            0: { cellWidth: 18, halign: 'center', fontStyle: 'bold' },
            1: { cellWidth: 13, halign: 'center', font: 'courier' },
            2: { cellWidth: 20, halign: 'center' },
            3: { cellWidth: 17, halign: 'center' },
            /*
              The 64 mm the constant used to hold goes here, where it does work.
              `Finding` carries the issue and the radio that has it - the one cell
              that differs on every row - and at 45 mm it wrapped to three lines.
            */
            4: { cellWidth: 94 },
            5: { cellWidth: 16, halign: 'center', font: 'courier' },
          },
          margin: TABLE_MARGIN,
          didParseCell: (data) => {
            if (data.section !== 'body') return;
            if (data.column.index === 0) {
              const level = data.cell.text[0] as Severity;
              if (SEVERITY_RGB[level]) {
                data.cell.styles.textColor = SEVERITY_RGB[level];
              }
            }
            if (data.column.index === 3 && data.cell.text[0] === 'REGRESSED') {
              data.cell.styles.textColor = [220, 38, 38];
              data.cell.styles.fontStyle = 'bold';
            }
          }
        });
        findY = (doc as any).lastAutoTable.finalY + 8;

        /*
          The reasons, once each, in the order the table first uses them.

          This is the other half of the `Why` column and it is not optional: a
          code with no key is worse than the repetition it replaced. It is kept on
          the same run of pages as the table rather than pushed to an appendix, so
          a reader resolving R3 does not have to leave the section.
        */
        const findGeo = geometry(doc);
        // Don't strand the heading at the foot of a page with its first entry
        // overleaf; a key that starts on the next page reads as a new section.
        if (findY > findGeo.bottom - 24) {
          doc.addPage();
          findY = findGeo.top;
        }
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(9);
        doc.setTextColor(30, 41, 59);
        doc.text('WHY THESE WERE ASSESSED THIS WAY', findGeo.left, findY);
        doc.setDrawColor(203, 213, 225);
        doc.setLineWidth(0.3);
        doc.line(findGeo.left, findY + 1.6, findGeo.right, findY + 1.6);
        findY += 6;

        for (const [text, { code, count }] of rationaleCodes) {
          if (findY > findGeo.bottom - 10) {
            doc.addPage();
            findY = findGeo.top;
          }
          doc.setFont('courier', 'bold');
          doc.setFontSize(8);
          doc.setTextColor(30, 41, 59);
          doc.text(code, findGeo.left, findY);
          doc.setFont('helvetica', 'normal');
          doc.setFontSize(7.5);
          doc.setTextColor(110, 110, 110);
          doc.text(`${count} finding(s)`, findGeo.left + 11, findY);
          findY = paragraph(text, findY + 4, { size: 8.5, color: [50, 50, 50], lead: 3.7 });
          findY += 3.5;
        }

        if (findY < PAGE_BOTTOM) {
          paragraph(
            ascii(`Scores are 0-100 and map to levels through the bands printed in the method appendix. Rule set: ${methodology.id} version ${methodology.version}. A status of REGRESSED means this issue had previously been recorded as fixed or accepted and has been observed again.`),
            findY, { size: 8, color: [110, 110, 110] }
          );
        }
  }
}
