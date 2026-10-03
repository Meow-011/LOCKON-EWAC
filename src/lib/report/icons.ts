/**
 * LOCKON EWAC — section icons for the PDF report.
 *
 * Drawn as vectors rather than embedded images. Three reasons, and the third is
 * the one that decided it: a line-art glyph costs a few hundred bytes against a
 * PNG's tens of kilobytes in a document that is already 17 MB; it stays crisp at
 * any zoom and on paper, where a 16 px raster icon does not; and it takes the
 * section's own colour, so the icon cannot drift out of step with the palette
 * the way a baked-in image would.
 *
 * Each glyph is drawn inside a 1x1 box and scaled by the caller, so adding one
 * means thinking about shape and nothing else. Strokes only — no fills — so a
 * glyph reads the same against the white page as it would against a tint.
 */
import type jsPDF from 'jspdf';

/** Draws one glyph into the unit box at (x, y) with side `s`, in millimetres. */
type Glyph = (doc: jsPDF, x: number, y: number, s: number) => void;

const line = (doc: jsPDF, x1: number, y1: number, x2: number, y2: number) =>
  doc.line(x1, y1, x2, y2);

/** A rounded speech of concentric arcs — signal, broadcast, a radio. */
const signal: Glyph = (doc, x, y, s) => {
  doc.circle(x + s * 0.5, y + s * 0.78, s * 0.08, 'F');
  for (const r of [0.28, 0.46]) {
    // Two arcs, approximated with short chords: jsPDF has no arc primitive.
    const steps = 8;
    for (let i = 0; i < steps; i++) {
      const a0 = Math.PI * (1.15 + (0.7 * i) / steps);
      const a1 = Math.PI * (1.15 + (0.7 * (i + 1)) / steps);
      line(doc,
        x + s * 0.5 + Math.cos(a0) * s * r, y + s * 0.78 + Math.sin(a0) * s * r,
        x + s * 0.5 + Math.cos(a1) * s * r, y + s * 0.78 + Math.sin(a1) * s * r);
    }
  }
};

/** A shield — scope, authorisation, anything about permission. */
const shield: Glyph = (doc, x, y, s) => {
  const cx = x + s * 0.5;
  line(doc, cx, y + s * 0.08, x + s * 0.88, y + s * 0.26);
  line(doc, x + s * 0.88, y + s * 0.26, x + s * 0.88, y + s * 0.55);
  line(doc, x + s * 0.88, y + s * 0.55, cx, y + s * 0.94);
  line(doc, cx, y + s * 0.94, x + s * 0.12, y + s * 0.55);
  line(doc, x + s * 0.12, y + s * 0.55, x + s * 0.12, y + s * 0.26);
  line(doc, x + s * 0.12, y + s * 0.26, cx, y + s * 0.08);
};

/** A warning triangle — findings, risk, anything the reader must act on. */
const alert: Glyph = (doc, x, y, s) => {
  const cx = x + s * 0.5;
  line(doc, cx, y + s * 0.1, x + s * 0.94, y + s * 0.86);
  line(doc, x + s * 0.94, y + s * 0.86, x + s * 0.06, y + s * 0.86);
  line(doc, x + s * 0.06, y + s * 0.86, cx, y + s * 0.1);
  line(doc, cx, y + s * 0.38, cx, y + s * 0.62);
  doc.circle(cx, y + s * 0.74, s * 0.045, 'F');
};

/** A map pin — coverage, position, anything spatial. */
const pin: Glyph = (doc, x, y, s) => {
  const cx = x + s * 0.5;
  const cy = y + s * 0.38;
  doc.circle(cx, cy, s * 0.3);
  doc.circle(cx, cy, s * 0.1, 'F');
  line(doc, cx - s * 0.21, cy + s * 0.22, cx, y + s * 0.94);
  line(doc, cx + s * 0.21, cy + s * 0.22, cx, y + s * 0.94);
};

/** Stacked rows — a table, a register, an inventory. */
const rows: Glyph = (doc, x, y, s) => {
  doc.rect(x + s * 0.08, y + s * 0.12, s * 0.84, s * 0.76);
  line(doc, x + s * 0.08, y + s * 0.36, x + s * 0.92, y + s * 0.36);
  line(doc, x + s * 0.08, y + s * 0.58, x + s * 0.92, y + s * 0.58);
  line(doc, x + s * 0.34, y + s * 0.12, x + s * 0.34, y + s * 0.88);
};

/** A padlock — credentials, encryption, exposure. */
const lock: Glyph = (doc, x, y, s) => {
  doc.rect(x + s * 0.18, y + s * 0.44, s * 0.64, s * 0.46);
  const steps = 6;
  for (let i = 0; i < steps; i++) {
    const a0 = Math.PI * (1 + i / steps);
    const a1 = Math.PI * (1 + (i + 1) / steps);
    line(doc,
      x + s * 0.5 + Math.cos(a0) * s * 0.22, y + s * 0.44 + Math.sin(a0) * s * 0.22,
      x + s * 0.5 + Math.cos(a1) * s * 0.22, y + s * 0.44 + Math.sin(a1) * s * 0.22);
  }
};

/** A document with a folded corner — summary, appendix, methodology. */
const doc_: Glyph = (doc, x, y, s) => {
  line(doc, x + s * 0.2, y + s * 0.08, x + s * 0.64, y + s * 0.08);
  line(doc, x + s * 0.64, y + s * 0.08, x + s * 0.82, y + s * 0.28);
  line(doc, x + s * 0.82, y + s * 0.28, x + s * 0.82, y + s * 0.92);
  line(doc, x + s * 0.82, y + s * 0.92, x + s * 0.2, y + s * 0.92);
  line(doc, x + s * 0.2, y + s * 0.92, x + s * 0.2, y + s * 0.08);
  line(doc, x + s * 0.64, y + s * 0.08, x + s * 0.64, y + s * 0.28);
  line(doc, x + s * 0.64, y + s * 0.28, x + s * 0.82, y + s * 0.28);
  line(doc, x + s * 0.32, y + s * 0.5, x + s * 0.7, y + s * 0.5);
  line(doc, x + s * 0.32, y + s * 0.66, x + s * 0.7, y + s * 0.66);
};

/** A magnifier — audit, inspection, anything examined after the fact. */
const search: Glyph = (doc, x, y, s) => {
  doc.circle(x + s * 0.42, y + s * 0.42, s * 0.3);
  line(doc, x + s * 0.63, y + s * 0.63, x + s * 0.9, y + s * 0.9);
};

/** A clock — history, vintage, anything whose age matters. */
const clock: Glyph = (doc, x, y, s) => {
  doc.circle(x + s * 0.5, y + s * 0.5, s * 0.42);
  line(doc, x + s * 0.5, y + s * 0.5, x + s * 0.5, y + s * 0.26);
  line(doc, x + s * 0.5, y + s * 0.5, x + s * 0.68, y + s * 0.58);
};

/**
 * Which glyph belongs to which section.
 *
 * Matched on a substring of the heading, longest first, so a section can be
 * renamed slightly without losing its icon. Anything unmatched gets the document
 * glyph rather than nothing: a heading with no icon beside headings that have
 * one reads as a missing asset, not as a deliberate choice.
 */
const BY_TITLE: [string, Glyph][] = [
  ['EXECUTIVE SUMMARY', doc_],
  ['AUTHORIZED ENGAGEMENT SCOPE', shield],
  ['SCOPE ENFORCEMENT AUDIT TRAIL', search],
  ['SURVEY COVERAGE', pin],
  ['EVIDENCE REGISTER', rows],
  ['PRIORITISED FINDINGS', alert],
  ['ROGUE AP', signal],
  ['EVIL TWIN', signal],
  ['WPS EXPOSURE', lock],
  ['TELEMETRY', rows],
  ['POSITION QUALITY', pin],
  ['SUBNET SWEEP', pin],
  ['CREDENTIAL', lock],
  ['METHOD', doc_],
  ['APPENDIX', doc_],
  ['CVE', clock],
  ['RETEST', clock],
  ['REMEDIATION', clock],
];

export function glyphFor(title: string): Glyph {
  const upper = title.toUpperCase();
  let best: [string, Glyph] | null = null;
  for (const entry of BY_TITLE) {
    if (upper.includes(entry[0]) && (!best || entry[0].length > best[0].length)) best = entry;
  }
  return best ? best[1] : doc_;
}

/**
 * Draw the icon for a section heading.
 *
 * `size` is the box side in mm and `y` its top, so the caller positions it
 * against the heading's cap height rather than its baseline. The stroke weight
 * is set here and restored by the caller's next `setLineWidth`.
 */
export function drawSectionIcon(
  doc: jsPDF,
  title: string,
  x: number,
  y: number,
  size: number,
  color: [number, number, number],
) {
  doc.setDrawColor(color[0], color[1], color[2]);
  doc.setFillColor(color[0], color[1], color[2]);
  doc.setLineWidth(size * 0.075);
  glyphFor(title)(doc, x, y, size);
}
