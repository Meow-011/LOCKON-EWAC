/**
 * Section 14 of the report: the footer stamped on every page.
 *
 * Moved out of `buildAndSavePDF` verbatim: the body below is the code that was
 * inline, unchanged. The only edits are the values it now takes as parameters
 * instead of reading them from the closure, and `npm run test:export` was run
 * before and after to confirm the document says exactly what it said.
 */
import { geometry } from '../geometry';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export interface PageFooterOptions {
  /** The document's own identifier, as the cover and the summary print it. */
  reportIdStr: string;
  /** Whether this export carries secrets in the clear. */
  discloseCredentials: boolean;
  /**
   * The page the cleartext credentials landed on, returned by section 11.
   *
   * A page carrying real secrets is stamped differently from the rest, and this
   * is the dependency between two sections a hundred lines apart that used to be
   * a `let` in the enclosing closure.
   */
  credentialsPageNum: number | null;
}

export function renderPageFooter(
  layout: PdfLayout,
  data: ReportData,
  { reportIdStr, discloseCredentials, credentialsPageNum }: PageFooterOptions,
): void {
  const { doc } = layout;
  const { allSimulated, isMixedProvenance } = data;
      // --- 14. FOOTER ON ALL PAGES ---
      // The simulated marker repeats on every page: a reader who opens the file at
      // page 4 must still be able to tell that these findings are not evidence.
      const simulatedFooterMarker = allSimulated
        ? 'SIMULATED DATA // NOT FIELD-VERIFIED'
        : isMixedProvenance
          ? 'CONTAINS SIMULATED DATA // NOT FIELD-VERIFIED'
          : null;

      const pageCount = (doc as any).internal.getNumberOfPages();
      for (let i = 2; i <= pageCount; i++) { // Skip cover page
        doc.setPage(i);


        /*
          Measured per page, because the telemetry annexe is landscape.

          These were hardcoded to the portrait edges (14 and 196) and the footer
          to 287/292. A landscape page is 297 mm wide and 210 tall, so the same
          numbers would have put the running head two thirds of the way across the
          sheet and the footer rule 77 mm below the paper.
        */
        const pg = geometry(doc);

        // Top header line
        doc.setDrawColor(200, 200, 200);
        doc.setLineWidth(0.5);
        doc.line(pg.left, pg.headerRuleY, pg.right, pg.headerRuleY);
        doc.setFontSize(8);
        doc.setFont('helvetica', 'italic');
        doc.setTextColor(150, 150, 150);
        doc.text(`LOCKON EWAC // ${reportIdStr}`, pg.left, pg.headerTextY);
        doc.text(new Date().toLocaleDateString(), pg.right, pg.headerTextY, { align: 'right' });

        // Per-page provenance marker, above the footer rule
        if (simulatedFooterMarker) {
          doc.setFont('helvetica', 'bold');
          doc.setFontSize(7.5);
          doc.setTextColor(161, 98, 7);
          doc.text(simulatedFooterMarker, pg.width / 2, pg.footerRuleY - 2.5, { align: 'center' });
        }

        // Bottom footer
        doc.setDrawColor(200, 200, 200);
        doc.setFont('helvetica', 'italic');
        doc.setFontSize(8);
        doc.setTextColor(150, 150, 150);
        doc.line(pg.left, pg.footerRuleY, pg.right, pg.footerRuleY);
        doc.text(`Page ${i} of ${pageCount}`, pg.right, pg.footerTextY, { align: 'right' });
        doc.setTextColor(220, 38, 38);
        doc.setFont('helvetica', 'bold');
        doc.text('CONFIDENTIAL / DO NOT DISTRIBUTE', pg.width / 2, pg.footerTextY, { align: 'center' });

        if (discloseCredentials && credentialsPageNum !== null && i === credentialsPageNum) {
          doc.setFontSize(7.5);
          doc.setTextColor(220, 38, 38);
          doc.text('CLEARTEXT CREDENTIALS ON THIS PAGE', pg.left, pg.footerTextY);
        }
      }
}
