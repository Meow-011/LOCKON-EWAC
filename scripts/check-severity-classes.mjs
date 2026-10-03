/**
 * LOCKON EWAC — does the built stylesheet actually contain every severity class?
 *
 *     npm run build && npm run check:severity-css
 *
 * Why this exists.
 *
 * Tailwind builds its stylesheet by scanning source files for complete class
 * strings. A class assembled at run time — `` `text-${token}` `` — produces the
 * right string in the DOM and no rule in the CSS, so the element renders with no
 * colour at all. Not the wrong colour: none. It reads as a rendering glitch
 * rather than as a severity, which is the worst way for a risk label to fail.
 *
 * `severityStyle.ts` shipped exactly that for one commit. `.text-risk-medium`
 * was absent from the built CSS, so every MEDIUM finding lost its colour, and
 * `tsc`, the unit tests and the CSP smoke test all passed — the page rendered
 * fine, just colourless. The unit test now asserts each class appears verbatim
 * in that module's source, which catches the cause; this checks the effect, in
 * the artifact that actually ships.
 *
 * Kept out of `npm test` because it needs a build. Run it after one.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const CSS_DIR = 'dist/assets';
const SOURCES = ['src/lib/severityStyle.ts', 'src/lib/signalStyle.ts'];

function newestStylesheet() {
  let found = null;
  for (const name of readdirSync(CSS_DIR)) {
    if (!name.startsWith('index-') || !name.endsWith('.css')) continue;
    const path = join(CSS_DIR, name);
    const mtime = statSync(path).mtimeMs;
    if (!found || mtime > found.mtime) found = { path, mtime };
  }
  return found?.path ?? null;
}

const cssPath = newestStylesheet();
if (!cssPath) {
  console.error(`[severity-css] no built stylesheet in ${CSS_DIR}. Run \`npm run build\` first.`);
  process.exit(2);
}

const css = readFileSync(cssPath, 'utf8');

/*
  Both palettes, because both had the same bug waiting in them and the risk one
  fired. `severityStyle` answers "how bad is this", `signalStyle` answers "how
  well was it received" — different questions, deliberately different colours,
  and each one invisible in exactly the same way if a class is built at run time.
*/
const needed = new Set();
for (const path of SOURCES) {
  const source = readFileSync(path, 'utf8');
  const before = needed.size;
  for (const m of source.matchAll(/'((?:text|bg|border)-(?:risk|signal)-[a-z]+(?:\/\d+)?)'/g)) {
    needed.add(m[1]);
  }
  for (const [, chip] of source.matchAll(/chip: '([^']+)'/g)) {
    for (const cls of chip.split(' ')) needed.add(cls);
  }
  if (needed.size === before) {
    console.error(`[severity-css] found no classes in ${path}. Did its shape change?`);
    process.exit(2);
  }
}

// Tailwind escapes '/' as '\/' inside a selector.
const missing = [...needed].sort().filter(cls => !css.includes(`.${cls.replace('/', '\\/')}`));

console.log(`[severity-css] stylesheet: ${cssPath}`);
console.log(`[severity-css] classes named by ${SOURCES.join(' + ')}: ${needed.size}`);
console.log(`[severity-css] present in the stylesheet:  ${needed.size - missing.length}`);
for (const cls of missing) console.error(`  MISSING: ${cls}`);

if (missing.length) {
  console.error(
    '\n[severity-css] FAIL — those classes are named in the source but have no rule in the\n'
    + '               stylesheet, so the elements using them will render with no colour.\n'
    + '               Write the class out in full rather than building it from a variable.',
  );
  process.exit(1);
}
console.log('[severity-css] PASS — every severity class has a rule.');
