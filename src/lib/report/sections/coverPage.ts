/**
 * Section 1 of the report: the cover.
 *
 * Moved out of `buildAndSavePDF` verbatim. The body below is the code that was
 * inline, unchanged -- the only edits are the parameters it now takes instead of
 * reading them from the closure, and `scripts/export-smoke-test.mjs` was run
 * before and after to confirm the document says exactly what it said.
 *
 * It was the largest single block in a 2,700-line function and it is also the
 * most self-contained: it draws the artwork, paints out the supplied lettering
 * and writes the identification panel over it, and it touches nothing the rest
 * of the document builds up. That combination is why it went first.
 */
import type jsPDF from 'jspdf';

import { ascii } from '../archive';
import type { ReportData } from '../assemble';

export interface CoverPageOptions {
  doc: jsPDF;
  data: ReportData;
  /**
   * The document's own identifier, printed here and in every page header.
   *
   * Passed in rather than derived here because the header and the filename use
   * the same string, and a second derivation is a second chance to disagree.
   */
  reportIdStr: string;
  /**
   * Whether recovered credentials are being exported in the clear.
   *
   * A property of this export rather than of the data, which is why it is a
   * parameter and not a `ReportData` field: the same archive exports masked or
   * disclosed depending on what the operator chose, and the cover has to say
   * which one the reader is holding.
   */
  discloseCredentials: boolean;
}

export async function renderCoverPage(
  { doc, data, reportIdStr, discloseCredentials }: CoverPageOptions
): Promise<void> {
  const {
    reportsArray, isMulti, simulatedReports, anySimulated, allSimulated,
    isMixedProvenance, activeScope, allCredentials,
  } = data;
      // --- 1. COVER PAGE ---
      /*
        The cover is a supplied artwork with the document's own text drawn over it.

        `public/lockon-ewac-report.jpg` is exactly A4 (1414x2000, 0.7071), so it is
        placed edge to edge. Everything that varies per report — the title block and
        the identification panel — is drawn as real text on top rather than baked
        into the image. Three reasons: a reader can select and search it, it stays
        sharp when the document is printed, and `pdfdiff` can see it. A cover whose
        report id is a picture of a report id is not checkable by anything.

        Both regions were measured from the artwork rather than guessed:
          - the black title panel spans x 71.3..209.7mm, y 60.7..123.1mm, and its
            background is pure (0,0,0), so the supplied lettering is painted out
            with a matching rectangle and reset below;
          - the clear area at the foot of the page runs y 194..285mm with the left
            column free from x 8mm, which is where the identification panel goes.
      */
      /*
        The cover artwork, with a deadline.

        This awaited `onload` or `onerror` and nothing else, so a load that settles
        neither leaves the promise pending for ever -- and with it the whole export,
        which sits at RENDERING with no message and no way back. A browser fires
        `onerror` promptly for a missing local file, which is why this has never
        been seen in the field; but "the platform always calls one of my callbacks"
        is an assumption, and this one gates the only control the operator has.

        Five seconds is far beyond what a file in the application's own bundle
        takes, and the fallback is a path the export already supports: `coverOnArt`
        is false and the identification panel is drawn on a plain page. A document
        without its cover photograph is a complete document; an export that never
        finishes is not.
      */
      const coverArt = await new Promise<string | null>((resolve) => {
        const settle = (value: string | null) => { clearTimeout(deadline); resolve(value); };
        const deadline = setTimeout(() => settle(null), 5000);
        const img = new Image();
        img.crossOrigin = 'Anonymous';
        img.onload = () => {
          const canvas = document.createElement('canvas');
          canvas.width = img.naturalWidth || 1414;
          canvas.height = img.naturalHeight || 2000;
          const ctx = canvas.getContext('2d');
          if (!ctx) return settle(null);
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          // JPEG, not PNG: the artwork is a photograph and PNG would add several
          // megabytes to a document that is already 16 MB.
          settle(canvas.toDataURL('image/jpeg', 0.92));
        };
        img.onerror = () => settle(null);
        img.src = '/lockon-ewac-report.jpg';
      });

      /** Where the identification panel sits, and whether the page under it is dark. */
      const coverOnArt = !!coverArt;

      if (coverArt) {
        doc.addImage(coverArt, 'JPEG', 0, 0, 210, 297);
      } else {
        /*
          Fallback, for when the artwork cannot be read.

          The cover carries the classification, the provenance and the report id;
          a page that failed to draw is not an acceptable outcome for any of them.
          This is the previous cover, kept so the document is always complete.
        */
        doc.setFillColor(13, 16, 23);
        doc.rect(0, 0, 210, 297, 'F');
        doc.setFillColor(220, 38, 38);
        doc.rect(0, 20, 210, 4, 'F');
        doc.rect(20, 0, 4, 297, 'F');
      }

      /*
        The title is set in the artwork, not here.

        It was drawn in Helvetica over a black patch while the supplied cover still
        carried the previous wording. The artwork now carries "Field Survey" in its
        own display face, so drawing over it would replace a designed title with a
        substitute one. The trade is deliberate and worth stating: the title is no
        longer selectable or searchable in the PDF, and `pdfdiff` cannot see it.
        Everything that varies per report — the target, the timestamp, the report
        id, the operator and the provenance — is still real text below, which is
        the part that has to be checkable.
      */

      /*
        Identification panel.

        On the artwork this sits in the clear area at the foot of the page — the
        band measured at y 194..285mm with the left column free from x 8mm — so it
        has to be dark on light, the opposite of the old dark cover. `LABEL` and
        `VALUE` carry that, and the fallback cover keeps the original light-on-dark
        treatment, because a panel styled for the wrong background is unreadable
        rather than merely ugly.

        It is a left accent rule and type rather than a filled box: a panel drawn
        over supplied artwork should sit on it, not cut a hole in it.
      */
      /*
        Measured against the artwork rather than nudged by eye. The lower band is
        clear from y 207 to 259mm; below that the artwork sets its own strapline at
        263..271 and the classification line at 279, so the panel has 52mm to live
        in and starts far enough down to sit under the map rather than beside it.
      */
      const PANEL_X = 26;
      const PANEL_LABEL_X = 26;
      const PANEL_VALUE_X = 60;
      let panelY = coverOnArt ? 214 : 135;
      const LABEL: [number, number, number] = coverOnArt ? [100, 116, 139] : [156, 163, 175];
      const VALUE: [number, number, number] = coverOnArt ? [15, 23, 42] : [255, 255, 255];

      if (coverOnArt) {
        doc.setFillColor(220, 38, 38);
        doc.rect(PANEL_X - 5, panelY - 7, 1.6, 48, 'F');
      } else {
        doc.setDrawColor(220, 38, 38);
        doc.setFillColor(30, 41, 59);
        doc.rect(35, 120, 140, 60, 'FD');
      }

      doc.setFontSize(10);
      doc.setTextColor(LABEL[0], LABEL[1], LABEL[2]);
      doc.text(isMulti ? 'CLASSIFIED TARGETS:' : 'CLASSIFIED TARGET:', PANEL_LABEL_X, panelY);
      panelY += 10;
      doc.setFontSize(14);
      doc.setTextColor(VALUE[0], VALUE[1], VALUE[2]);
      doc.setFont('helvetica', 'bold');
      if (isMulti) {
        doc.text(`${reportsArray.length} NETWORKS CONSOLIDATED`, PANEL_LABEL_X, panelY);
      } else {
        doc.text(reportsArray[0].targetName.toUpperCase(), PANEL_LABEL_X, panelY);
      }
      panelY += 11;

      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(LABEL[0], LABEL[1], LABEL[2]);
      /*
        The span this report covers, not just the first archive's timestamp.

        This printed `reportsArray[0].timestamp` with no indication that it was
        only one archive's, so a consolidated report spanning three weeks looked
        like a single afternoon's work. The range is the honest label for a
        multi-archive export, and a reader comparing it against the operations
        listed in the executive summary needs it to match.
      */
      const stamps = reportsArray.map(r => r.timestamp).filter(t => typeof t === 'number');
      const earliest = stamps.length ? Math.min(...stamps) : Date.now();
      const latest = stamps.length ? Math.max(...stamps) : Date.now();
      const sameDay = new Date(earliest).toDateString() === new Date(latest).toDateString();
      const timestampLabel = stamps.length <= 1 || earliest === latest
        ? new Date(earliest).toLocaleString()
        : sameDay
          ? `${new Date(earliest).toLocaleString()} - ${new Date(latest).toLocaleTimeString()}`
          : `${new Date(earliest).toLocaleString()} - ${new Date(latest).toLocaleString()}`;

      doc.text(stamps.length > 1 && earliest !== latest ? 'COVERS:' : 'TIMESTAMP:', PANEL_LABEL_X, panelY);
      doc.setTextColor(VALUE[0], VALUE[1], VALUE[2]);
      doc.text(ascii(timestampLabel).slice(0, 46), PANEL_VALUE_X, panelY);
      panelY += 7;

      doc.setTextColor(LABEL[0], LABEL[1], LABEL[2]);
      doc.text('REPORT ID:', PANEL_LABEL_X, panelY);
      doc.setTextColor(VALUE[0], VALUE[1], VALUE[2]);
      /*
        A consolidated report's identifier is derived from what it contains, not
        invented at export time.

        This was `MULTI-${Date.now().toString().slice(-6)}`: a number recorded
        nowhere, which a recipient could not look up, and which differed between
        two exports of the same selection. It is printed in every page header and
        in the filename, so it reads exactly like a reference.

        Hashing the sorted archive ids makes it stable — the same selection always
        produces the same id, a different selection produces a different one — and
        the archive ids it is built from are listed in the executive summary, so it
        can actually be traced back.
      */
      doc.text(reportIdStr, PANEL_VALUE_X, panelY);
      panelY += 7;

      // The cover used to print a hardcoded `OP-LOCKON [AUTHORIZED]`, in green,
      // unconditionally: not read from any scope record and not conditioned on one
      // existing. A report with no recorded engagement therefore asserted
      // AUTHORIZED on its cover while page 4 stated "NO ENGAGEMENT SCOPE RECORDED
      // FOR THIS EXPORT", and a reader who noticed the contradiction had grounds
      // to reject the entire document.
      //
      // The cover now says only what the scope record supports, using the same
      // expiry and active-record checks as the authorization section on page 4, so
      // the two can no longer disagree.
      const operatorLabel = (() => {
        if (!activeScope) {
          return { text: 'NOT RECORDED - NO ENGAGEMENT SCOPE', color: [234, 179, 8] as [number, number, number] };
        }
        const who = activeScope.operator || 'operator not recorded';
        const expired = !!activeScope.valid_until
          && new Date(activeScope.valid_until).getTime() < Date.now();
        if (expired) return { text: `${who} [AUTHORIZATION EXPIRED]`, color: [234, 179, 8] as [number, number, number] };
        if (activeScope.is_active !== 1) return { text: `${who} [SCOPE RECORD NOT ACTIVE]`, color: [234, 179, 8] as [number, number, number] };
        return { text: `${who} [AUTHORIZED]`, color: [16, 185, 129] as [number, number, number] };
      })();

      doc.setTextColor(LABEL[0], LABEL[1], LABEL[2]);
      doc.text('OPERATOR:', PANEL_LABEL_X, panelY);
      doc.setTextColor(operatorLabel.color[0], operatorLabel.color[1], operatorLabel.color[2]);
      doc.setFont('courier', 'bold');
      // An operator name is free text, so it is transliterated like every other
      // string on this page and capped so it cannot run out of the cover box.
      doc.text(ascii(operatorLabel.text).slice(0, 44), PANEL_VALUE_X, panelY);
      panelY += 7;
      doc.setFont('helvetica', 'normal');

      // Provenance line inside the target box — the same slot the operator line
      // uses, so a reader scanning the cover cannot miss it.
      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(LABEL[0], LABEL[1], LABEL[2]);
      doc.text('DATA SOURCE:', PANEL_LABEL_X, panelY);
      doc.setFont('courier', 'bold');
      /*
        An imported archive is not field data, and "LIVE HARDWARE [FIELD DATA]" is
        the strongest provenance claim on this page.

        `origin` was written to the database and read only one report at a time by
        `getExportProvenance`, which this path never called — so an archive that
        arrived as a file printed here as though this rig had gathered it. Checked
        before the simulated branches because it is the broader statement: an
        imported file's contents cannot be vouched for at all, simulated or not.
      */
      const importedReports = reportsArray.filter(r => r.origin === 'IMPORTED');
      if (importedReports.length === reportsArray.length && reportsArray.length > 0) {
        doc.setTextColor(234, 179, 8); // amber
        doc.text('IMPORTED ARCHIVE [NOT FIELD DATA]', PANEL_VALUE_X, panelY);
      } else if (importedReports.length > 0) {
        doc.setTextColor(234, 179, 8);
        doc.text(ascii(`MIXED: ${importedReports.length} OF ${reportsArray.length} IMPORTED`), PANEL_VALUE_X, panelY);
      } else if (allSimulated) {
        doc.setTextColor(234, 179, 8);
        doc.text('HARDWARE SIMULATOR [SIMULATED]', PANEL_VALUE_X, panelY);
      } else if (isMixedProvenance) {
        doc.setTextColor(234, 179, 8);
        doc.text('MIXED: FIELD + SIMULATED', PANEL_VALUE_X, panelY);
      } else {
        doc.setTextColor(16, 185, 129);
        doc.text('LIVE HARDWARE [FIELD DATA]', PANEL_VALUE_X, panelY);
      }
      doc.setFont('helvetica', 'normal');

      // ── Cover banners: unmissable markers for anything that limits how this
      //    document may be relied on or handled. ──
      /*
        Below the identification panel, not at the old fixed 195mm — on the artwork
        the panel now occupies that band. These are the markers that limit how the
        document may be relied on, so they must not land underneath it.
      */
      let coverBannerY = coverOnArt ? panelY + 10 : 195;
      const coverBanner = (
        title: string,
        body: string,
        fill: [number, number, number],
        textColor: [number, number, number]
      ) => {
        doc.setFont('courier', 'bold');
        doc.setFontSize(7.5);
        const bodyLines = doc.splitTextToSize(body, 132);
        const height = 14 + bodyLines.length * 3.2;

        doc.setFillColor(fill[0], fill[1], fill[2]);
        doc.rect(16, coverBannerY, 178, height, 'F');
        doc.setDrawColor(255, 255, 255);
        doc.setLineWidth(0.6);
        doc.rect(16, coverBannerY, 178, height, 'S');

        doc.setFont('helvetica', 'bold');
        doc.setFontSize(13);
        doc.setTextColor(textColor[0], textColor[1], textColor[2]);
        doc.text(title, 105, coverBannerY + 9, { align: 'center' });

        doc.setFont('courier', 'bold');
        doc.setFontSize(7.5);
        doc.text(bodyLines, 105, coverBannerY + 15, { align: 'center' });

        coverBannerY += height + 6;
        doc.setFont('helvetica', 'normal');
        doc.setLineWidth(0.5);
      };

      // Imported data gets its own banner, and it comes first.
      //
      // A simulated archive at least came from this rig's own simulator, whose
      // behaviour is known. An imported one is a file: nothing in this document
      // can vouch for how it was produced, by what, or by whom. That is the
      // broadest limitation on the page, so it leads.
      if (importedReports.length > 0) {
        coverBanner(
          importedReports.length === reportsArray.length
            ? '!! IMPORTED DATA - NOT GATHERED BY THIS RIG !!'
            : '!! CONTAINS IMPORTED DATA !!',
          importedReports.length === reportsArray.length
            ? 'EVERY ARCHIVE IN THIS REPORT WAS IMPORTED FROM A FILE. NOTHING HERE WAS OBSERVED BY THIS INSTALLATION, AND ITS PROVENANCE CANNOT BE ESTABLISHED FROM THIS DOCUMENT.'
            : ascii(`${importedReports.length} OF ${reportsArray.length} ARCHIVES WERE IMPORTED FROM A FILE RATHER THAN OBSERVED BY THIS INSTALLATION. THEIR PROVENANCE CANNOT BE ESTABLISHED FROM THIS DOCUMENT.`),
          [234, 179, 8],
          [13, 16, 23]
        );
      }

      if (allSimulated) {
        coverBanner(
          '!! SIMULATED DATA !!',
          'EVERY OPERATION IN THIS REPORT WAS PRODUCED BY THE HARDWARE SIMULATOR. THESE FINDINGS ARE NOT FIELD-VERIFIED AND ARE NOT EVIDENCE OF REAL EXPOSURE.',
          [234, 179, 8],
          [13, 16, 23]
        );
      } else if (isMixedProvenance) {
        coverBanner(
          '!! CONTAINS SIMULATED DATA !!',
          `${simulatedReports.length} OF ${reportsArray.length} OPERATIONS CAME FROM THE HARDWARE SIMULATOR AND ARE NOT FIELD-VERIFIED. SEE THE EXECUTIVE SUMMARY FOR WHICH IS WHICH.`,
          [234, 179, 8],
          [13, 16, 23]
        );
      }

      if (discloseCredentials && allCredentials.length > 0) {
        coverBanner(
          '!! CLEARTEXT CREDENTIALS ENCLOSED !!',
          `FULL-DISCLOSURE EXPORT: ${allCredentials.length} RECOVERED PASSWORD(S) APPEAR IN CLEARTEXT. HANDLE THIS FILE AS A LIVE CREDENTIAL STORE.`,
          [220, 38, 38],
          [255, 255, 255]
        );
      }

      /*
        Classification footer.

        Drawn only on the fallback cover. The artwork sets it at the foot of the
        page itself, and printing a second one over it would double the line — the
        one marking on this page that must be unambiguous.
      */
      if (!coverOnArt) {
        doc.setFontSize(12);
        doc.setTextColor(220, 38, 38);
        doc.setFont('helvetica', 'bold');
        doc.text('CONFIDENTIAL // DO NOT DISTRIBUTE', 105, 280, { align: 'center' });
      }
      if (anySimulated) {
        doc.setFontSize(10);
        doc.setTextColor(234, 179, 8);
        doc.text(
          allSimulated ? 'SIMULATED DATA // NOT FIELD-VERIFIED' : 'CONTAINS SIMULATED DATA // NOT FIELD-VERIFIED',
          105, 288, { align: 'center' }
        );
      }
}
