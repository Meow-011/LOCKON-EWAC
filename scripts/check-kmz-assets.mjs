#!/usr/bin/env node
/**
 * Every icon the KML names is one the archive actually carries.
 *
 *     npm run check:kmz
 *
 * Why this exists.
 *
 * A KMZ names its icons by a path relative to the archive root, and a viewer
 * that cannot resolve one draws its default pin and reports nothing. That is the
 * same silent failure the hrefs had before they were brought inside the file —
 * the export still succeeds, the document still opens, and the only sign is pin
 * artwork nobody compares against anything.
 *
 * Three names have to agree and they live in three places: the `<href>` in
 * `ReportsPage.tsx`, the entry name the exporter passes to `kmz()`, and the file
 * on disk that Vite emits. Nothing makes them agree; a rename touches one.
 *
 * The mirror-candidate pin matters more than decoration. Its placemark means
 * "this position is one of two that fit the measurements equally well", and the
 * whole reason it is a different shape is that a reader must not mistake it for
 * a fix. The description says so in words as well, which is what keeps this from
 * being a correctness bug — but the shape is the part read at a glance.
 */
import { readFileSync, existsSync } from 'node:fs';

/*
  Two files, because the export is in two halves.

  `exports/kml.ts` writes the `<Icon><href>` into each style; `ReportsPage.tsx`
  still owns the half that reads the image bytes and hands them to `kmz()`, since
  that part needs the bundler's asset URLs. The check is about those two halves
  agreeing, so it reads both and looks at them as one document -- naming only the
  page, as it used to, made it report that the styles had lost their pins on the
  day the builder moved.
*/
const SOURCES = [
  'src/lib/report/exports/kml.ts',
  'src/pages/ReportsPage.tsx',
];
const ASSET_DIR = 'src/assets/kml';
const problems = [];

const source = SOURCES.map(f => readFileSync(f, 'utf8')).join(String.fromCharCode(10));

// ── 1. What the document asks for ──────────────────────────────────────────
const hrefs = [...source.matchAll(/<Icon><href>([^<]+)<\/href><\/Icon>/g)].map(m => m[1]);
if (hrefs.length === 0) problems.push(`${SOURCES.join(' + ')} declare no <Icon><href>, so the styles lost their pins`);

for (const href of hrefs) {
  if (/^[a-z]+:/i.test(href)) {
    problems.push(`${href} is an absolute URL — an icon fetched at open time is a record of when the client read the report`);
    continue;
  }
  if (href.startsWith('/')) {
    problems.push(`${href} is absolute within the archive; KMZ paths are relative to its root`);
  }
}

// ── 2. What the exporter puts in the archive ───────────────────────────────
// The literal object list handed to `kmz()`, which is the only place the entry
// names are written.
const entries = [...source.matchAll(/path:\s*'(icons\/[^']+)'/g)].map(m => m[1]);

for (const href of hrefs) {
  if (!entries.includes(href)) {
    problems.push(`the document names "${href}" but no entry of that name is added to the archive — the viewer will fall back to a default pin`);
  }
}
for (const entry of entries) {
  if (!hrefs.includes(entry)) {
    problems.push(`"${entry}" is packed into every archive and no style references it`);
  }
}

// ── 3. What is on disk ─────────────────────────────────────────────────────
// Each entry is imported from `src/assets/kml/` by basename; a missing file is a
// build error rather than a silent one, but naming it here says which.
for (const entry of entries) {
  const file = `${ASSET_DIR}/${entry.split('/').pop()}`;
  if (!existsSync(file)) {
    problems.push(`${file} does not exist, so "${entry}" has nothing behind it (run \`python scripts/make-kml-icons.py\`)`);
  }
}

if (problems.length > 0) {
  console.error('[kmz] FAIL');
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}

console.log(`[kmz] ${hrefs.length} icon reference(s), each packed and present on disk`);
console.log('[kmz] PASS');
