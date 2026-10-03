/**
 * Section 15 of the report: the table of contents, written back into the page reserved for it.
 *
 * Moved out of `buildAndSavePDF` verbatim: the body below is the code that was
 * inline, unchanged. The only edits are the values it now takes as parameters
 * instead of reading them from the closure, and `npm run test:export` was run
 * before and after to confirm the document says exactly what it said.
 */
import { geometry } from '../geometry';
import type { ReportData } from '../assemble';
import type { PdfLayout } from '../layout';

export interface TableOfContentsOptions {
  /** The page reserved for the contents back on section 2. */
  tocPageNum: number;
  /** The document's own identifier, which the filename is built from. */
  reportIdStr: string;
  /** Whether this export carries secrets in the clear. */
  discloseCredentials: boolean;
}

/**
 * Returns the filename the document will be saved under.
 *
 * Built here because it is assembled from the same parts as the contents page --
 * the identifier, the provenance and whether credentials are disclosed -- and it
 * was a `const` in the enclosing closure read by the save, the evidence note and
 * the notification. Returning it keeps those three reading one value.
 */
export function renderTableOfContents(
  layout: PdfLayout,
  data: ReportData,
  { tocPageNum, reportIdStr, discloseCredentials }: TableOfContentsOptions,
): string {
  const { doc, tocEntries } = layout;
  const { reportsArray, isMulti, allSimulated, isMixedProvenance, allCredentials } = data;
      // --- 15. POPULATE TOC PAGE ---
      doc.setPage(tocPageNum);
      // The contents page is portrait, but read it from the page rather than
      // assuming: the link rectangles have to land on the rows they underline.
      const tocGeo = geometry(doc);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(22);
      doc.setTextColor(0, 0, 0);
      doc.text('TABLE OF CONTENTS', tocGeo.left, 25);

      doc.setDrawColor(220, 38, 38);
      doc.setLineWidth(1);
      doc.line(geometry(doc).left, 28.5, geometry(doc).right, 28.5);

      // Two extra sections (scope + audit) plus one row per target means the
      // contents list can now outgrow its page, so tighten the leading and state
      // it plainly if anything still will not fit.
      const tocLead = tocEntries.length > 22 ? 7 : 10;
      const tocFontSize = tocEntries.length > 22 ? 9.5 : 12;
      doc.setFont('courier', 'bold');
      doc.setFontSize(tocFontSize);
      doc.setTextColor(50, 50, 50);

      let tocY = 45;
      let tocOverflow = 0;
      tocEntries.forEach((entry, idx) => {
        if (tocY > 268) { tocOverflow += 1; return; }
        const itemStr = `[${(idx + 1).toString().padStart(2, '0')}] ${entry.title}`;

        // Make TOC text a deeper, professional blue for readability on white background
        doc.setTextColor(37, 99, 235); // blue-600
        doc.text(itemStr, tocGeo.left, tocY);
        doc.setTextColor(50, 50, 50);
        doc.text(entry.page.toString().padStart(2, '0'), tocGeo.right, tocY, { align: 'right' });

        doc.setDrawColor(200, 200, 200);
        doc.setLineWidth(0.1);
        doc.line(tocGeo.left + 2 + doc.getTextWidth(itemStr), tocY - 1, tocGeo.right - 6, tocY - 1);

        // Make the entire row clickable (x, y, w, h, { pageNumber })
        // y in doc.text is the baseline. We shift up by ~4 units for the rectangle top.
        doc.link(tocGeo.left, tocY - 4, tocGeo.contentWidth, 6, { pageNumber: entry.page });

        tocY += tocLead;
      });

      if (tocOverflow > 0) {
        doc.setFont('helvetica', 'bold');
        doc.setFontSize(9);
        doc.setTextColor(161, 98, 7);
        doc.text(
          `+ ${tocOverflow} further section(s) are present in this document but did not fit on this contents page. They follow in order after the last entry listed above.`,
          14, tocY + 2
        );
      }

      const simTag = allSimulated ? 'SIMULATED_' : isMixedProvenance ? 'MIXED_' : '';
      const credTag = discloseCredentials && allCredentials.length > 0 ? '_CLEARTEXT' : '';
      /*
        The filename is sanitised, because `recordExport` below stores this exact
        string as the archive's durable record of the delivered document.

        It used to replace whitespace only. `targetName` is generated as
        `FIELD SCAN ${toLocaleTimeString()}` (TopBar), so on any locale that
        prints a time with colons — this one — every default archive name carries
        them. Windows cannot write a colon in a filename, so the OS dropped them
        on the way to disk: the delivered file was
        `LOCKON_FIELD_SCAN_2_29_49_PM_WIFI-1.pdf` while the archive recorded
        `LOCKON_FIELD_SCAN_2:29:49_PM_WIFI-1.pdf`. The digest was correct, so
        integrity still verified — the provenance row simply named a file that
        cannot exist. An operator-chosen title can carry / \ ? * " < > | and break
        the same way.

        Same character class as `exportBaseName`, which CSV, KML and GeoJSON
        already use. The PDF was the only export that built its own name, and the
        only one whose name is kept as evidence.

        Only the *filename* is sanitised. `targetName` is printed inside the
        document unchanged, and the digest covers the document rather than the
        name, so this leaves the PDF byte-identical and its SHA-256 unchanged.
      */
      const fileStem = isMulti
        // CONSOLIDATED, not COMPREHENSIVE: it says several surveys were merged,
        // which is true, rather than that coverage was complete, which the
        // method appendix explicitly denies. The filename is the first thing a
        // recipient reads and it travels further than the document does.
        ? `LOCKON_${simTag}CONSOLIDATED_${reportIdStr}${credTag}`
        : `LOCKON_${simTag}${reportsArray[0].targetName}_${reportsArray[0].id.substring(0, 6)}${credTag}`;
  const saveName = `${fileStem.replace(/[^A-Za-z0-9_-]+/g, '_')}.pdf`;
  return saveName;
}
