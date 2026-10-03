/**
 * LOCKON EWAC — nothing in the report may be drawn off the page.
 *
 *     node scripts/check-report-margins.mjs <report.pdf>
 *     npm run check:margins          # against every PDF in scripts/baselines/
 *
 * Why this exists.
 *
 * The WiFi telemetry table was given eleven columns summing to 202 mm on a
 * 178 mm content column. Nothing objected. The table was drawn to 216.1 mm on a
 * 210 mm sheet, so its last column — the one carrying the severity verdict —
 * began at 198.1 mm and was printed **entirely off the paper**. 372 rectangles
 * across 11 pages fell outside the printable area, and the only way anyone found
 * out was by looking at a screenshot of page 35.
 *
 * A column width is a number somebody types. It is checkable, and until this
 * script it was not checked.
 *
 * Tables draw their cell fills and borders as `re` operators carrying an exact
 * x and width, so an overflowing table is provable from the file. Text start
 * positions come from `Td`/`TD`/`Tm`; a start beyond the margin is reported too,
 * since nothing legitimate begins there.
 *
 * What it cannot see: a line of text that *starts* inside the margin and runs
 * past it. jsPDF has already wrapped by then and the file records no width, so
 * catching that would need font metrics. `layout.paragraph` wraps to the content
 * column, which is the control that covers it.
 */
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { inflateSync } from 'node:zlib';

const MM = 72 / 25.4;
/** Must match MARGIN_X in src/lib/report/geometry.ts. */
const MARGIN_MM = 16;
/** Half a millimetre of slack for rounding in the PDF's own numbers. */
const SLACK_MM = 0.5;

/*
  -- Every pinned shape, not one file --------------------------------------

  This defaulted to `scripts/baseline-report.pdf`, which is the single-baseline
  file the export harness stopped writing when it moved to one baseline per
  archive shape. The file stayed on disk, so this check went on **passing** while
  measuring a frozen PDF that no build could ever change -- a check reading a
  stale artifact reports on the day that artifact was made, not on the code, and
  from the outside it is indistinguishable from a real pass.

  Reading the pins instead fixes the staleness and closes a gap that predates it:
  the wireless report was the only shape ever measured. The LAN document draws
  subnet coverage and host tables the wireless one does not, and a column width
  typed into one of those tables had nothing looking at it.
*/
const BASELINE_DIR = 'scripts/baselines';
const BASELINE_INDEX = join(BASELINE_DIR, 'index.json');

/** The pinned PDFs, named by the index so a stray file cannot pad the count. */
function pinnedBaselines() {
  if (existsSync(BASELINE_INDEX)) {
    try {
      const { reports } = JSON.parse(readFileSync(BASELINE_INDEX, 'utf8'));
      if (Array.isArray(reports) && reports.length) {
        return reports.map(id => ({ id, path: join(BASELINE_DIR, `${id}.pdf`) }));
      }
    } catch { /* fall through to the directory */ }
  }
  if (!existsSync(BASELINE_DIR)) return [];
  return readdirSync(BASELINE_DIR)
    .filter(f => f.endsWith('.pdf'))
    .map(f => ({ id: f.slice(0, -4), path: join(BASELINE_DIR, f) }));
}

const argPath = process.argv[2];
const targets = argPath ? [{ id: argPath, path: argPath }] : pinnedBaselines();

if (targets.length === 0) {
  console.error('[margins] no report to measure. Run `npm run test:export:release -- --write-baseline` first.');
  process.exit(2);
}

/*
  A pin whose PDF is absent is not a pass, for the same reason it is not one in
  the export harness: exit 0 for a measurement that never happened is the single
  outcome a release script cannot recover from.
*/
const absent = targets.filter(t => !existsSync(t.path));
if (absent.length) {
  for (const t of absent) console.error(`[margins] ${t.path} does not exist`);
  console.error('[margins] Run `npm run test:export:release -- --write-baseline` to record it.');
  process.exit(2);
}

/** Page boxes, in order, so each content stream can be measured against its own page. */
function pageSizes(hay) {
  const boxes = [];
  for (const m of hay.matchAll(/\/MediaBox\s*\[\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*\]/g)) {
    boxes.push({ w: parseFloat(m[3]) / MM, h: parseFloat(m[4]) / MM });
  }
  return boxes;
}

function contentStreams(buf, hay) {
  const out = [];
  const re = /stream\r?\n?/g;
  let m;
  while ((m = re.exec(hay)) !== null) {
    const start = m.index + m[0].length;
    const end = hay.indexOf('endstream', start);
    if (end === -1) continue;
    const raw = buf.subarray(start, end);
    const dict = hay.slice(Math.max(0, m.index - 400), m.index);
    let text;
    if (/\/FlateDecode/.test(dict)) {
      try { text = inflateSync(raw).toString('latin1'); } catch { re.lastIndex = end; continue; }
    } else {
      text = raw.toString('latin1');
    }
    out.push(text);
    re.lastIndex = end;
  }
  return out;
}

const N = String.raw`(-?\d+(?:\.\d+)?)`;

/** Measures one document. Reports what was looked at as well as what was wrong. */
function measure(path) {
const buf = readFileSync(path);
const hay = buf.toString('latin1');
const boxes = pageSizes(hay);
const streams = contentStreams(buf, hay);

const problems = [];
let widest = { mm: 0, page: 0, limit: 0 };
let landscapePages = 0;

streams.forEach((s, i) => {
  const page = i + 1;
  // Pages and content streams are emitted in step by jsPDF; fall back to the
  // first box rather than guessing when a document has fewer boxes than streams.
  const box = boxes[i] ?? boxes[0] ?? { w: 210, h: 297 };
  if (box.w > box.h) landscapePages++;
  const limit = box.w - MARGIN_MM;

  for (const r of s.matchAll(new RegExp(`${N} ${N} ${N} ${N} re`, 'g'))) {
    const x = parseFloat(r[1]);
    const w = parseFloat(r[3]);
    const rightMm = (x + w) / MM;
    if (rightMm > widest.mm) widest = { mm: rightMm, page, limit };
    if (rightMm > limit + SLACK_MM) {
      problems.push({ page, kind: 'table/box', rightMm, limit, detail: `x=${(x / MM).toFixed(1)}mm w=${(w / MM).toFixed(1)}mm` });
    }
    if ((x / MM) < MARGIN_MM - SLACK_MM) {
      problems.push({ page, kind: 'table/box', rightMm: x / MM, limit: MARGIN_MM, detail: `starts left of the margin at ${(x / MM).toFixed(1)}mm` });
    }
  }

  const starts = [
    ...s.matchAll(new RegExp(`${N} ${N} (?:Td|TD)`, 'g'))].map(t => parseFloat(t[1]));
  for (const t of s.matchAll(new RegExp(`${N} ${N} ${N} ${N} ${N} ${N} Tm`, 'g'))) {
    starts.push(parseFloat(t[5]));
  }
  for (const x of starts) {
    const mm = x / MM;
    if (mm > limit + SLACK_MM) {
      problems.push({ page, kind: 'text start', rightMm: mm, limit, detail: 'text begins past the right margin' });
    }
  }
});

  return { problems, streams: streams.length, landscapePages, widest };
}

let failed = 0;
let measuredPages = 0;

for (const target of targets) {
  const { problems, streams, landscapePages, widest } = measure(target.path);
  measuredPages += streams;

  console.log(`[margins] ${target.path}`);
  console.log(`[margins]   ${streams} content stream(s), ${landscapePages} landscape page(s), margin ${MARGIN_MM}mm`);
  console.log(`[margins]   widest drawn edge: ${widest.mm.toFixed(1)}mm (page ${widest.page}, limit ${widest.limit.toFixed(0)}mm)`);

  /*
    An empty document would otherwise be the quietest pass available: no streams,
    no rectangles, nothing outside anything. The shortest report this builder
    produces runs to several pages.
  */
  if (streams === 0) {
    console.log('[margins]   FAIL — no content streams; there is nothing here to measure.');
    failed++;
    continue;
  }
  if (problems.length === 0) continue;

  failed++;
  const byPage = new Map();
  for (const p of problems) {
    if (!byPage.has(p.page)) byPage.set(p.page, []);
    byPage.get(p.page).push(p);
  }
  console.log(`[margins]   FAIL — ${problems.length} item(s) outside the margins on ${byPage.size} page(s):`);
  let shown = 0;
  for (const [page, list] of [...byPage.entries()].sort((a, b) => a[0] - b[0])) {
    if (shown >= 12) { console.log(`    ... and ${byPage.size - shown} more page(s)`); break; }
    const worst = list.reduce((a, b) => (b.rightMm > a.rightMm ? b : a));
    console.log(`    page ${page}: ${list.length} item(s), worst ${worst.rightMm.toFixed(1)}mm vs limit ${worst.limit.toFixed(0)}mm — ${worst.detail}`);
    shown++;
  }
}

if (failed === 0) {
  console.log(`[margins] PASS — nothing is drawn outside the printable area, across `
    + `${targets.length} document(s) and ${measuredPages} page(s).`);
  process.exit(0);
}
// "draw outside the printable area" is one of the two ways to fail here; an
// empty document is the other, and it draws nothing at all.
console.log(`[margins] FAIL — ${failed} of ${targets.length} document(s) did not measure clean.`);
console.log('[margins] A column width is a number somebody typed. Narrow the table, or turn the page.');
process.exit(1);
