/**
 * Section 6c of the report: the evidence register.
 *
 * Moved out of `buildAndSavePDF` verbatim: the body below is the code that was
 * inline, unchanged. The only edits are the values it now takes as parameters
 * instead of reading them from the closure, and `npm run test:export` was run
 * before and after to confirm the document says exactly what it said.
 */
import autoTable from 'jspdf-autotable';
import { ascii } from '../archive';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export function renderEvidenceRegister(layout: PdfLayout, data: ReportData): void {
  const { doc, tocEntries, sectionHeading, paragraph, callout } = layout;
  const { evidenceRows, evidenceReadError } = data;
      // --- 6c. EVIDENCE REGISTER ---
      //
      // What was captured, where it is, and the digest that proves it has not
      // changed. The appendix has always claimed captures are recorded as
      // evidence; this is the section that makes the claim checkable.
      if (evidenceRows.length > 0 || evidenceReadError) {
        doc.addPage();
        tocEntries.push({ title: 'EVIDENCE REGISTER', page: (doc as any).internal.getNumberOfPages() });
        let evY = sectionHeading('EVIDENCE REGISTER');

        if (evidenceReadError) {
          evY = callout(
            evY,
            'THE EVIDENCE REGISTER COULD NOT BE READ',
            ascii(`The evidence table could not be read from the local database, so this export cannot list the artifacts behind its findings. Error reported: ${evidenceReadError}. Any statement elsewhere in this document about a capture being recorded as evidence is unverified for this export.`),
            [254, 242, 242], [220, 38, 38], [220, 38, 38]
          );
        } else {
          evY = paragraph(
            'Each artifact below was hashed with SHA-256 at the moment it was written, before anything else touched it. A recipient can recompute the digest of the file they hold and compare it with the value printed here: if they match, the file is byte-for-byte what the tool produced. The VERIFIED column records the last time this installation re-hashed the artifact itself, which is a separate check from the one a recipient performs.',
            evY, { size: 9.5 }
          );
          evY += 4;

          autoTable(doc, {
            startY: evY,
            head: [['Kind', 'Filename', 'Subject', 'Size', 'SHA-256', 'Recorded', 'Verified']],
            body: evidenceRows.map(e => [
              ascii(String(e.kind ?? '')),
              ascii(String(e.filename ?? '')),
              ascii(e.ssid ? `${e.ssid} (${e.bssid ?? '?'})` : (e.bssid ?? 'n/r')),
              e.size_bytes === null || e.size_bytes === undefined ? 'n/r' : `${e.size_bytes} B`,
              // Full digest, not a prefix: a truncated hash cannot be used to
              // verify anything, which would make the column decorative.
              ascii(e.sha256 ?? 'NOT HASHED'),
              ascii(String(e.recorded_at ?? '')),
              e.verify_status
                ? ascii(`${e.verify_status}${e.last_verified_at ? ` ${e.last_verified_at}` : ''}`)
                : 'never re-checked',
            ]),
            theme: 'grid',
            styles: { fontSize: 6.5, cellPadding: 1.5, overflow: 'linebreak' },
            headStyles: { fillColor: [30, 41, 59], textColor: 255, fontStyle: 'bold', fontSize: 7 },
            columnStyles: { 4: { font: 'courier', fontSize: 5.5, cellWidth: 52 } },
            didParseCell: (data: any) => {
              if (data.section !== 'body') return;
              // An unhashed artifact proves nothing, and a MISMATCH is the single
              // most serious row this document can contain.
              const text = String(data.cell.raw ?? '');
              if (data.column.index === 4 && text === 'NOT HASHED') {
                data.cell.styles.textColor = [220, 38, 38];
                data.cell.styles.fontStyle = 'bold';
              }
              if (data.column.index === 6 && (text.startsWith('MISMATCH') || text.startsWith('MISSING'))) {
                data.cell.styles.textColor = [220, 38, 38];
                data.cell.styles.fontStyle = 'bold';
              }
            },
          });
          evY = (doc as any).lastAutoTable.finalY + 6;

          const unhashed = evidenceRows.filter(e => !e.sha256).length;
          const failed = evidenceRows.filter(
            e => e.verify_status === 'MISMATCH' || e.verify_status === 'MISSING'
          );
          if (failed.length > 0) {
            evY = callout(
              evY,
              'AN ARTIFACT FAILED VERIFICATION',
              ascii(`${failed.length} artifact(s) did not match the digest recorded when they were written, or could no longer be found: `
                + `${failed.map(e => `${e.filename} (${e.verify_status})`).join('; ')}. `
                + 'Any finding that rests on those artifacts should be treated as unsupported until they are recovered from a known-good copy.'),
              [254, 242, 242], [220, 38, 38], [220, 38, 38]
            );
            evY += 4;
          }
          if (unhashed > 0) {
            evY = callout(
              evY,
              ascii(`${unhashed} ARTIFACT(S) WERE NOT HASHED`),
              'These files were recorded without a digest, so nothing in this document establishes that they are unchanged since capture. They are listed for completeness, not as evidence.',
              [254, 252, 232], [234, 179, 8], [161, 98, 7]
            );
            evY += 4;
          }

          evY = paragraph(
            ascii('This register lists every artifact this installation has recorded, not only those belonging to the archives in this export — the evidence table carries no reliable link back to an archive. Treat it as the inventory of what exists, and match artifacts to findings by their subject.'),
            evY, { size: 8, color: [110, 110, 110] }
          );
        }
      }
}
