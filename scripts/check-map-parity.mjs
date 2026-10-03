#!/usr/bin/env node
/**
 * The two maps draw the same things the same way.
 *
 *     npm run check:map
 *
 * Why this exists.
 *
 * There are two MapLibre maps in this application — the live tactical map in
 * `MapView.tsx` and the interactive survey map inside `ReportsPage.tsx` — and
 * they share most of their layers by name while being two separate
 * implementations three thousand lines apart. That is a shape in which a fix
 * reaches one and not the other, silently, and it has now done so twice:
 *
 *   * The heatmap weighted an access point with **no reading** at the top of its
 *     scale, because `interpolate` clamps outside its domain and `['get','rssi']`
 *     yields null. A radio whose signal was never recorded was the brightest
 *     thing on a map of signal strength. Fixed on the live map; the report's map
 *     kept the defect, in the figure that goes into the document.
 *   * The same heatmap was inserted *over* the uncertainty rings rather than
 *     under them, so switching it on erased the overlay. Same fix, same gap.
 *
 * And one drifted while it was being edited: the track line is `line-opacity`
 * 0.9 on one map and was 0.8 on the other, because a single change touched both
 * by hand.
 *
 * The track, the dots, the heatmap and the terrain now live in
 * `src/lib/map/surveyLayers.ts` and are identical by construction, which is what
 * this check was written to push towards. It still runs, for three reasons: a
 * layer can be added inline to one page again, the shared module can be bypassed,
 * and the `ALLOWED` list below is where the claim "these two maps answer
 * different questions here" has to be written down rather than assumed.
 *
 * It compares every layer the two files still define under the same id, with
 * comments and whitespace normalised away — one file wraps every expression and
 * the other does not — and fails on any difference not declared with a reason.
 * It also reports how many of the shared module's layers a page is still
 * defining for itself, which is 0 and should stay there.
 */
import { readFileSync } from 'node:fs';

const LIVE = 'src/components/dashboard/MapView.tsx';
/*
  `ReportMap` moved out of `ReportsPage.tsx` into its own file, and this constant
  had to move with it. It did not, for one run: the check read a page with no map
  layers in it, found nothing to compare, and passed. A check that is satisfied by
  its subject disappearing is worse than one that fails, so the file is asserted
  to contain a map before anything is compared.
*/
const REPORT = 'src/components/reports/ReportMap.tsx';

/*
  Layers that are allowed to differ, each with the reason.

  An entry here is a claim that the two maps are answering different questions,
  not that nobody has got round to it. `ap-uncertainty-*` is the clearest case:
  the live map has every ring on screen at once and leaves the widest out, while
  the report has an OFF / HOVER / ALL control and draws a fill — both reasonable,
  and `uncertaintyFeatures` already builds the geometry for both.
*/
const ALLOWED = {
  'ap-uncertainty-ring': 'live-only: outline, no fill, limited by RING_LIMIT_M',
  'ap-uncertainty-link': 'live-only: the report uses its own ap-mirror source',
  'ap-uncertainty-mirror': 'live-only: the report uses ap-mirror-point',
  'ap-uncertainty-fill': 'report-only: the OFF/HOVER/ALL control makes a fill readable',
  'ap-uncertainty-outline': 'report-only: paired with the fill above',
  'ap-mirror-link': 'report-only: a separate source so the ring control can filter it',
  'ap-mirror-point': 'report-only: paired with the link above',
};

/** Every `map.addLayer({ id: 'x', ... })` body in a file, keyed by id. */
function layersOf(source) {
  const out = new Map();
  const re = /addLayer\(\{([\s\S]*?)\n\s*\}(?:,\s*'[a-z-]+')?\);/g;
  for (const m of source.matchAll(re)) {
    const body = m[1];
    const id = body.match(/id:\s*'([a-z-]+)'/)?.[1];
    if (id) out.set(id, body);
  }
  return out;
}

/*
  Comments and layout carry no behaviour, and the two files are written in
  different styles — one wraps every expression, the other keeps them on a line.
  Comparing those would report a difference on every layer and the check would be
  ignored within a day.
*/
function normalise(body) {
  return body
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/[^\n]*/g, '')
    .replace(/\s+/g, ' ')
    // Also next to brackets and braces: one file wraps every expression and the
    // other keeps them on a line, so `[ 'interpolate'` and `['interpolate'` are
    // the same expression written two ways.
    .replace(/([[{(])\s+/g, '$1')
    .replace(/\s+([\]})])/g, '$1')
    .replace(/,\s*([\]}])/g, '$1')
    .replace(/\s*:\s*/g, ':')
    .replace(/\s*,\s*/g, ',')
    .trim();
}

/*
  A layer defined in the shared module is identical in both maps by construction,
  which is the point of the module and the end state this check exists to push
  towards. It is reported as progress rather than compared.
*/
const SHARED = 'src/lib/map/surveyLayers.ts';
const shared_ids = [...layersOf(readFileSync(SHARED, 'utf8')).keys()];

const live = layersOf(readFileSync(LIVE, 'utf8'));
const report = layersOf(readFileSync(REPORT, 'utf8'));

for (const [file, found] of [[LIVE, live], [REPORT, report]]) {
  if (found.size === 0) {
    console.error('[map] FAIL');
    console.error(`  - ${file} defines no map layers at all.`);
    console.error('      Either the map moved and this script was not told, or it lost its layers.');
    console.error('      Comparing nothing is not a pass.');
    process.exit(1);
  }
}

const shared = [...live.keys()].filter(id => report.has(id));
const problems = [];

for (const id of shared) {
  if (ALLOWED[id]) continue;
  const a = normalise(live.get(id));
  const b = normalise(report.get(id));
  if (a === b) continue;

  // Report the first property that differs rather than the whole body: the
  // difference is almost always one line, and printing two paint blocks makes
  // the reader find it themselves.
  const props = s => (s.match(/'[a-z-]+':\s*(\[[^\]]*\]|[^,}]+)/g) ?? []).map(x => x.trim());
  const pa = props(a), pb = props(b);
  const onlyLive = pa.filter(x => !pb.includes(x));
  const onlyReport = pb.filter(x => !pa.includes(x));
  const filterA = /filter:/.test(a), filterB = /filter:/.test(b);

  problems.push({ id, onlyLive, onlyReport, filterA, filterB });
}

for (const id of [...live.keys()]) {
  if (!report.has(id) && !ALLOWED[id] && !shared_ids.includes(id)) {
    problems.push({ id, missing: REPORT });
  }
}
for (const id of [...report.keys()]) {
  if (!live.has(id) && !ALLOWED[id] && !shared_ids.includes(id)) {
    problems.push({ id, missing: LIVE });
  }
}

if (problems.length > 0) {
  console.error('[map] FAIL');
  for (const p of problems) {
    if (p.missing) {
      console.error(`  - '${p.id}' is defined in only one map and is not declared as deliberate`);
      console.error(`      missing from ${p.missing}`);
      continue;
    }
    console.error(`  - '${p.id}' differs between the two maps`);
    if (p.filterA !== p.filterB) {
      console.error(`      one has a \`filter\` and the other does not — ` +
        `${p.filterA ? 'the live map' : 'the report map'} filters, the other draws everything`);
    }
    for (const x of p.onlyLive.slice(0, 3)) console.error(`      live only  : ${x.slice(0, 80)}`);
    for (const x of p.onlyReport.slice(0, 3)) console.error(`      report only: ${x.slice(0, 80)}`);
  }
  console.error('\n  Either make them agree, or add the id to ALLOWED with the reason they differ.');
  process.exit(1);
}

/*
  Layers the shared module owns that a page *also* still defines inline.

  The first version of this counted the intersection of the two pages, which read
  0 the moment one of them was rewired and the other had not been -- a progress
  number that says "done" half way through is worse than none.
*/
const stillInline = shared_ids.filter(id => live.has(id) || report.has(id));
console.log(`[map] ${shared_ids.length} layer(s) in ${SHARED}, ` +
  `${stillInline.length} still defined in both pages, ` +
  `${Object.keys(ALLOWED).length} declared different`);
if (stillInline.length > 0) {
  // Not a failure. They agree today; the module is what keeps them agreeing.
  console.log(`[map] still duplicated: ${stillInline.join(', ')}`);
}
console.log('[map] PASS');
