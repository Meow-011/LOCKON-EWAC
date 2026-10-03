/**
 * LOCKON EWAC — one definition of where things sit on a report page.
 *
 * Why this exists.
 *
 * The same numbers were written out by hand in four files: `14` for the left
 * margin, `196` for the right edge, `182` for a table or a text wrap, `287` and
 * `292` for the footer rule and its text, `25` for the first body line. Nothing
 * connected them, so they drifted — and the drift is exactly what a reader sees
 * as "this document was not designed". Worse, a table could be given column
 * widths that summed past the paper and nothing would object: the WiFi telemetry
 * table was 202 mm of columns on a 210 mm page, so its last column began at
 * 198.1 mm and was drawn **entirely off the sheet**. 372 rectangles across 11
 * pages fell outside the printable area before this module existed.
 *
 * So the geometry is derived, not repeated. Everything here comes from the page
 * size jsPDF reports for the page being drawn *right now*, which is what makes a
 * landscape annexe possible without a second set of constants to keep in step.
 *
 * Millimetres throughout, matching jsPDF's default unit for this document.
 */
import type jsPDF from 'jspdf';

/**
 * Side margin.
 *
 * Was 14 mm, which is tight for a document that gets printed and handed over —
 * the text ran closer to the edge than the eye expects and left no room for a
 * binding or a thumb. 16 mm is the compromise: visibly more generous, while
 * costing the dense tables only 4 mm of column width.
 */
export const MARGIN_X = 16;

/** Header: the running title's baseline, and the rule under it. */
export const HEADER_TEXT_Y = 12;
export const HEADER_RULE_Y = 15;

/** Footer: the rule, and the baseline of the text under it. */
export const FOOTER_GAP_FROM_BOTTOM = 17;
export const FOOTER_TEXT_GAP_FROM_BOTTOM = 11;

/** First body baseline on a fresh page, clear of the header rule. */
export const CONTENT_TOP = 30;

/**
 * Clearance between the last body line and the footer rule.
 *
 * The rule this whole module serves: nothing may run off the bottom of a page.
 * A section that writes past this produces text underneath the footer, or off
 * the paper, and the failure is invisible until somebody prints it.
 */
export const CONTENT_BOTTOM_GAP = 25;

/**
 * Margins handed to every `autoTable` call.
 *
 * jspdf-autotable defaults its side margins to 14 mm, which is where the whole
 * document used to sit. Leaving that default while the text column moved to 16
 * would have put every table 2 mm to the left of every paragraph above it —
 * the exact kind of near-miss that reads as "nobody laid this out".
 *
 * `top` applies to continuation pages, so it has to clear the header rule.
 */
export const TABLE_MARGIN = { top: CONTENT_TOP, left: MARGIN_X, right: MARGIN_X };

export interface PageGeometry {
  /** Page width in mm, as jsPDF reports it for the current page. */
  width: number;
  /** Page height in mm. */
  height: number;
  /** Left edge of the content column. */
  left: number;
  /** Right edge of the content column. */
  right: number;
  /** Usable width between the margins — what a table or a wrap must fit in. */
  contentWidth: number;
  /** First body baseline on a fresh page. */
  top: number;
  /** Last body baseline that still clears the footer rule. */
  bottom: number;
  headerTextY: number;
  headerRuleY: number;
  footerRuleY: number;
  footerTextY: number;
  /** True when this page is wider than it is tall. */
  landscape: boolean;
}

/**
 * Measure the page currently being drawn.
 *
 * Read per call rather than cached, because the document mixes orientations: the
 * telemetry annexe is landscape so an eleven-column table can be read, and the
 * header, footer and every wrap width have to follow the page they are on.
 */
export function geometry(doc: jsPDF): PageGeometry {
  const size = (doc as any).internal.pageSize;
  const width = typeof size.getWidth === 'function' ? size.getWidth() : size.width;
  const height = typeof size.getHeight === 'function' ? size.getHeight() : size.height;
  return {
    width,
    height,
    left: MARGIN_X,
    right: width - MARGIN_X,
    contentWidth: width - MARGIN_X * 2,
    top: CONTENT_TOP,
    bottom: height - CONTENT_BOTTOM_GAP,
    headerTextY: HEADER_TEXT_Y,
    headerRuleY: HEADER_RULE_Y,
    footerRuleY: height - FOOTER_GAP_FROM_BOTTOM,
    footerTextY: height - FOOTER_TEXT_GAP_FROM_BOTTOM,
    landscape: width > height,
  };
}

/**
 * Scale a set of column widths to fit the content column.
 *
 * Column widths are written as the proportions a table wants, and this makes
 * them fit whatever page they land on. It only ever shrinks: a table given less
 * than it asked for is cramped, which is a design problem, while one given more
 * than the paper has is a correctness problem — it silently loses its right-hand
 * columns, which is how the severity verdict disappeared off the telemetry
 * table for eleven pages.
 */
export function fitColumns(widths: number[], available: number): number[] {
  const total = widths.reduce((a, b) => a + b, 0);
  if (total <= available) return widths;
  const scale = available / total;
  return widths.map(w => w * scale);
}
