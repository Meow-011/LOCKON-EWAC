#!/usr/bin/env node
/**
 * Fetch the map label glyphs the offline basemap needs.
 *
 *     npm run basemap:glyphs
 *
 * Needs a network connection, like `fonts:refresh`, and for the same reason: the
 * files it writes are committed, so a clone builds and a field rig runs with no
 * network at all.
 *
 * What glyphs are, and why they are not the interface fonts.
 *
 * MapLibre does not render map labels with a webfont. It requests pre-rendered
 * signed-distance-field glyphs in blocks of 256 code points — `{fontstack}/{range}.pbf`
 * — and composites them onto the tiles. The `src/assets/fonts/` woff2 files are
 * for the interface chrome and are no use here; these are for the map.
 *
 * Which ranges, and the honest limit.
 *
 * Latin (0-255), Latin Extended (256-511), Thai (3584-3839) and general
 * punctuation (8192-8447), for three fontstacks the Protomaps theme asks for.
 * About a megabyte in total.
 *
 * A label whose characters fall outside those ranges is **dropped by MapLibre**,
 * with a console warning and no mark on the map. That is a real limit with a
 * real consequence — a basemap of a region written in Cyrillic, Arabic or CJK
 * would lose its place names — and it is stated in the gaps list rather than
 * left to be discovered. The ranges are a line in this file; adding one is a
 * re-run and a commit.
 *
 * Thai is included because this tool is used in Thailand and a map of Bangkok
 * with no place names is a map of nowhere.
 */
import { writeFileSync, mkdirSync, existsSync, readdirSync, rmSync } from 'node:fs';
import layersFor from 'protomaps-themes-base';

const BASE = 'https://protomaps.github.io/basemaps-assets/fonts';
const OUT = 'public/basemap-glyphs';

/*
  The fontstacks are read out of the theme, not listed here.

  A hand-written list drifted immediately: it had `Noto Sans Medium`, which the
  theme never asks for, and lacked `Noto Sans Devanagari Regular v1`, which it
  does. `test:basemap` caught that, and a list that has to be caught by a test is
  a list that should not be written by hand -- the theme is the only thing that
  knows which fonts its own layers name.

  They are pulled from the serialised layers rather than from a documented
  export, because `text-font` appears both as a literal array and inside
  expressions, and a future layer could put one somewhere neither this nor the
  test anticipates. Walking the whole document is the only form that cannot miss
  one.
*/
function fontstacksInTheme() {
  const layers = layersFor('protomaps', 'black', { lang: 'en' });
  const names = new Set();
  const walk = (node) => {
    if (Array.isArray(node)) return node.forEach(walk);
    if (node && typeof node === 'object') return Object.values(node).forEach(walk);
    if (typeof node === 'string' && /^Noto Sans /.test(node)) names.add(node);
  };
  walk(layers);
  return [...names].sort();
}

const FONTSTACKS = fontstacksInTheme();

const RANGES = [
  '0-255',       // Basic Latin and Latin-1
  '256-511',     // Latin Extended-A and -B
  '2304-2559',   // Devanagari, which the theme names a dedicated fontstack for
  '3584-3839',   // Thai
  '8192-8447',   // General punctuation, which labels use for dashes and quotes
];

let total = 0;
let written = 0;
/** Combinations upstream has no glyphs for, reported rather than hidden. */
const empty = [];

// Cleared first so a fontstack or range removed from the lists above does not
// leave files behind that nothing requests and `check:basemap` would report.
if (existsSync(OUT)) {
  for (const dir of readdirSync(OUT)) rmSync(`${OUT}/${dir}`, { recursive: true, force: true });
}

for (const stack of FONTSTACKS) {
  const dir = `${OUT}/${stack}`;
  mkdirSync(dir, { recursive: true });
  for (const range of RANGES) {
    const url = `${BASE}/${encodeURIComponent(stack)}/${range}.pbf`;
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${stack} ${range}: ${res.status} ${res.statusText}`);
    const buf = Buffer.from(await res.arrayBuffer());
    /*
      An empty block is a real answer, not a failure.

      There is no Thai italic, and upstream says so with a valid 26-byte PBF
      containing no glyphs rather than a 404. Writing it is correct and quieter
      than leaving the file out, which would make MapLibre request it and log an
      error on every tile. Refusing the whole run over it, which the first
      version of this script did, would have meant shipping no glyphs at all
      because one combination legitimately has none.

      What is still refused is a body too small to be a PBF at all -- an error
      page committed as a glyph block means every label in that range silently
      missing, which is the failure worth being loud about.
    */
    if (buf.length < 16) throw new Error(`${stack} ${range} came back as ${buf.length} bytes, which is not a glyph block`);
    if (buf.length < 500) empty.push(`${stack} ${range}`);
    writeFileSync(`${dir}/${range}.pbf`, buf);
    total += buf.length;
    written++;
  }
}

console.log(`[glyphs] ${written} file(s) across ${FONTSTACKS.length} fontstack(s), ${(total / 1024).toFixed(0)} KB`);
if (empty.length > 0) {
  console.log(`[glyphs] ${empty.length} block(s) are empty upstream, which is an answer rather than a fault: ${empty.join(', ')}`);
}
console.log(`[glyphs] wrote ${OUT} — commit these, and \`npm run check:basemap\` resolves them`);
