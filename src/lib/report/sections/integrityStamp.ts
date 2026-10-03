/**
 * Section 16 of the report: the integrity stamp.
 *
 * Moved out of `buildAndSavePDF` verbatim. Only the stamping is here; what
 * followed it in the same block -- saving the file, hashing what was written and
 * recording it -- is the export itself rather than a page of the document, and it
 * stayed with the builder.
 *
 * Returns the pre-stamp digest, or the reason there is none, because the archive
 * records both and the notification says which. A digest cannot appear inside the
 * bytes it measures, so the document carries two values and states exactly what
 * each one covers.
 */
import type jsPDF from 'jspdf';

export interface IntegrityStamp {
  /** SHA-256 of the document as built, before this stamp was written into it. */
  interimDigest: string | null;
  /** Why there is no digest, when there is none. */
  digestError: string | null;
}

export async function renderIntegrityStamp(
  doc: jsPDF,
  sha256Hex: (buf: ArrayBuffer) => Promise<string>,
  errText: (err: unknown) => string,
): Promise<IntegrityStamp> {
      // --- 16. EXPORT INTEGRITY ---
      //
      // A report someone acts on has to be shown to be the one this tool produced.
      // A digest cannot appear inside the bytes it measures, so two values exist and
      // the document says exactly what each one covers: the short digest stamped
      // below is of the document as built, and the digest of the delivered file is
      // computed after stamping and recorded in the archive.
      let interimDigest: string | null = null;
      let digestError: string | null = null;
      try {
        interimDigest = await sha256Hex((doc as any).output('arraybuffer') as ArrayBuffer);
      } catch (err) {
        digestError = errText(err);
      }

      const digestLabel = interimDigest
        ? `PRE-STAMP SHA-256 ${interimDigest.slice(0, 16).toUpperCase()}`
        : 'PRE-STAMP SHA-256 UNAVAILABLE';

      const stampPages = (doc as any).internal.getNumberOfPages() as number;
      for (let i = 1; i <= stampPages; i++) {
        doc.setPage(i);
        doc.setFont('courier', 'bold');
        doc.setFontSize(6.5);
        if (i === 1) {
          // The cover is dark, so the stamp has to be light.
          doc.setTextColor(147, 197, 253);
          doc.text(digestLabel, 35, 292);
        } else {
          doc.setTextColor(150, 150, 150);
          doc.text(digestLabel, 14, 283.5);
        }
      }
      doc.setFont('helvetica', 'normal');

  return { interimDigest, digestError };
}
