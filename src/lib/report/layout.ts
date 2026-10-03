/**
 * LOCKON EWAC — page furniture for the PDF report.
 *
 * Four helpers and one constant that every body section in the document used,
 * defined once inside `buildAndSavePDF`'s closure and therefore reachable from
 * nowhere else. They are here so a section can be a module rather than another
 * 300 lines of the same function.
 *
 * **The one rule that governs all of them: nothing may run off the edge of a
 * page.** Each helper takes the current vertical cursor in millimetres and
 * returns the new one, breaking to a fresh page when what it is about to write
 * would not fit. A section that tracks its own `y` and writes past the content
 * bottom produces text underneath the footer rule, or off the paper entirely —
 * and the failure is invisible until somebody prints it.
 *
 * The cursor is passed and returned rather than held as state on purpose: a
 * section can compute a height, ask for the page break, and then draw, which is
 * what `callout` and the table sections need.
 *
 * Every horizontal number now comes from `geometry()`, which measures the page
 * being drawn. That is what lets the telemetry annexe be landscape without a
 * second set of constants to keep in step — and it is why the margins could be
 * widened in one place rather than in four files.
 */
import type jsPDF from 'jspdf';
import { geometry, CONTENT_TOP } from './geometry';
import { drawSectionIcon } from './icons';

/**
 * Last baseline that still clears the footer rule on a *portrait* page.
 *
 * Kept as a constant because sections import it directly. Prefer
 * `layout.bottom()`, which is correct on a landscape page too; this is the
 * portrait answer and nothing more.
 */
export const PAGE_BOTTOM = 297 - 25;

/** Top margin on a page this module opened. */
export const PAGE_TOP = CONTENT_TOP;

export interface ParagraphOptions {
  size?: number;
  color?: [number, number, number];
  bold?: boolean;
  width?: number;
  lead?: number;
}

export interface PdfLayout {
  doc: jsPDF;
  /**
   * Contents entries, in the order the sections claimed them.
   *
   * Filled while the body is written and rendered afterwards onto the page
   * reserved for it, because a table of contents cannot know its own page
   * numbers until the pages exist.
   */
  tocEntries: { title: string; page: number }[];
  /** The page number of the current page. */
  pageNumber(): number;
  /** Left edge of the content column on the current page. */
  left(): number;
  /** Right edge of the content column on the current page. */
  right(): number;
  /** Usable width between the margins on the current page. */
  contentWidth(): number;
  /** Last baseline that still clears the footer on the current page. */
  bottom(): number;
  /** Break to a fresh page when `needed` mm would not fit, and report the new cursor. */
  fit(y: number, needed: number): number;
  /** Open a titled section on the current page and return the first body cursor. */
  sectionHeading(title: string): number;
  /** Write a paragraph, breaking to a new page rather than running off this one. */
  paragraph(text: string, y: number, opts?: ParagraphOptions): number;
  /** Bordered callout box, auto-sized to its body text. */
  callout(
    y: number,
    title: string,
    body: string,
    fill: [number, number, number],
    stroke: [number, number, number],
    titleColor: [number, number, number],
  ): number;
}

/**
 * Bind the page helpers to one document.
 *
 * `tocEntries` belongs to the returned object rather than to the caller so that
 * a section cannot be handed the helpers without also being able to register
 * itself in the contents — a section that draws pages and never appears in the
 * contents is the kind of omission nobody notices in a 48-page document.
 */
export function createLayout(doc: jsPDF): PdfLayout {
  const tocEntries: { title: string; page: number }[] = [];

  const g = () => geometry(doc);
  const pageNumber = () => (doc as any).internal.getNumberOfPages() as number;
  const left = () => g().left;
  const right = () => g().right;
  const contentWidth = () => g().contentWidth;
  const bottom = () => g().bottom;

  const fit = (y: number, needed: number) => {
    if (y + needed <= g().bottom) return y;
    doc.addPage();
    return g().top;
  };

  /**
   * A section title, its rule, and the icon that marks it.
   *
   * The icon is drawn from `icons.ts` as line art in the rule's own colour, so
   * the two read as one object and a palette change cannot leave them
   * disagreeing. It sits in the left margin gutter — outside the text column —
   * which is what keeps every heading's text aligned with the body beneath it
   * whether or not its glyph happens to be wide.
   */
  const sectionHeading = (title: string) => {
    const geo = g();
    const ICON = 7;
    const RULE: [number, number, number] = [220, 38, 38];

    // Cap height of a 16pt heading is a shade under 6mm; the glyph box is
    // aligned to it rather than to the baseline so the two optically match.
    drawSectionIcon(doc, title, geo.left, 19.5, ICON, RULE);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(16);
    doc.setTextColor(0, 0, 0);
    doc.text(title, geo.left + ICON + 3.5, 25);

    doc.setDrawColor(RULE[0], RULE[1], RULE[2]);
    doc.setLineWidth(1);
    doc.line(geo.left, 28.5, geo.right, 28.5);
    doc.setLineWidth(0.5);
    return 38;
  };

  const paragraph = (text: string, y: number, opts?: ParagraphOptions) => {
    const size = opts?.size ?? 10;
    const lead = opts?.lead ?? size * 0.52;
    const color = opts?.color ?? [50, 50, 50];
    doc.setFont('helvetica', opts?.bold ? 'bold' : 'normal');
    doc.setFontSize(size);
    doc.setTextColor(color[0], color[1], color[2]);
    const lines = doc.splitTextToSize(text, opts?.width ?? g().contentWidth);
    let cursor = y;
    for (const line of lines) {
      if (cursor > g().bottom) {
        doc.addPage();
        cursor = g().top;
        // The font has to be re-set after a page break: jsPDF does not carry
        // the current style across one, so the rest of a paragraph that
        // happened to wrap would come out in whatever the last caller left.
        doc.setFont('helvetica', opts?.bold ? 'bold' : 'normal');
        doc.setFontSize(size);
        doc.setTextColor(color[0], color[1], color[2]);
      }
      doc.text(line, g().left, cursor);
      cursor += lead;
    }
    return cursor;
  };

  const callout = (
    y: number,
    title: string,
    body: string,
    fill: [number, number, number],
    stroke: [number, number, number],
    titleColor: [number, number, number],
  ) => {
    const geo = g();
    const PAD = 5;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    const lines = doc.splitTextToSize(body, geo.contentWidth - PAD * 2);
    const height = lines.length * 4.6 + 13;
    let top = y;
    // Measured before it is drawn, so a callout is never split across a page
    // boundary — half a warning box reads as a rendering fault and invites the
    // reader to discount the warning.
    if (top + height > geo.bottom) {
      doc.addPage();
      top = g().top;
    }
    doc.setFillColor(fill[0], fill[1], fill[2]);
    doc.setDrawColor(stroke[0], stroke[1], stroke[2]);
    doc.setLineWidth(0.8);
    doc.rect(geo.left, top, geo.contentWidth, height, 'FD');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10.5);
    doc.setTextColor(titleColor[0], titleColor[1], titleColor[2]);
    doc.text(title, geo.left + PAD, top + 7.5);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9);
    doc.setTextColor(50, 50, 50);
    doc.text(lines, geo.left + PAD, top + 13.5);
    doc.setLineWidth(0.5);
    return top + height + 8;
  };

  return {
    doc, tocEntries, pageNumber,
    left, right, contentWidth, bottom,
    fit, sectionHeading, paragraph, callout,
  };
}
