#!/usr/bin/env node
/**
 * Re-fetch the self-hosted webfonts and regenerate `src/fonts.css`.
 *
 *     npm run fonts:refresh
 *
 * Needs a network connection, and is the only thing in this repository that
 * does. It is a maintenance command, not part of the build: the files it writes
 * are committed, so a clone builds and runs with no network at all, which is the
 * whole point of having them.
 *
 * Two details that are easy to get wrong and silent when you do.
 *
 * The User-Agent has to look like a browser. Google's css2 endpoint serves a
 * different stylesheet per client, and to anything it does not recognise it
 * serves TrueType — so a fetch with curl's own agent returns a CSS with zero
 * woff2 URLs and reads exactly like a network failure. That is not a
 * hypothetical: it is why this repository carried a note saying self-hosting was
 * impossible here.
 *
 * Only the `latin` and `latin-ext` subsets are kept. The stylesheet also offers
 * Cyrillic, Greek, Vietnamese and Devanagari, which the browser was already
 * declining to download because no glyph in this interface falls in those
 * ranges; taking them would quadruple the size for faces nothing renders. Text
 * outside those ranges — an SSID in Thai, say — is drawn by a system font, which
 * is what happened before this was self-hosted too.
 */
import { writeFileSync, mkdirSync, readdirSync, rmSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
  + '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';

// The exact families and weights the interface asks for, as `src/index.css`
// names them in --font-sans, --font-mono, --font-tactical and --font-tech.
const HREF = 'https://fonts.googleapis.com/css2'
  + '?family=Inter:wght@300;400;500;600;700'
  + '&family=JetBrains+Mono:wght@400;500'
  + '&family=Rajdhani:wght@500;600;700'
  + '&family=Share+Tech+Mono'
  + '&display=swap';

const KEEP = new Set(['latin', 'latin-ext']);
const OUT_DIR = 'src/assets/fonts';
const OUT_CSS = 'src/fonts.css';

const res = await fetch(HREF, { headers: { 'User-Agent': UA } });
if (!res.ok) throw new Error(`the stylesheet request failed: ${res.status} ${res.statusText}`);
const css = await res.text();

const blocks = [...css.matchAll(/\/\*\s*([a-z0-9\-[\]]+)\s*\*\/\s*(@font-face\s*\{[^}]*\})/g)];
if (blocks.length === 0) {
  throw new Error(
    'no @font-face blocks came back. The usual cause is a User-Agent the endpoint '
    + 'did not recognise, which makes it serve TrueType with no subset comments.'
  );
}

mkdirSync(OUT_DIR, { recursive: true });
// Cleared first, so a face dropped from the list above does not leave its file
// behind for `check-fonts` to report as an orphan on the next run.
if (existsSync(OUT_DIR)) {
  for (const f of readdirSync(OUT_DIR).filter(n => n.endsWith('.woff2'))) rmSync(`${OUT_DIR}/${f}`);
}

/*
  Downloaded first, named second.

  Google serves these as variable fonts, so one file covers every weight of a
  family within a subset: all five Inter weights pointed at byte-identical
  content, as did both JetBrains Mono weights. Naming by weight before knowing
  that committed ten duplicate binaries, which Vite then deduplicated back to
  eleven in the build — so the waste never reached a user and sat in the
  repository instead.

  A file is therefore named for its family and subset when the whole group
  shares one body, and only gains the weight when the group genuinely differs.
*/
const downloaded = [];
let bytes = 0;
for (const [, subset, block] of blocks) {
  if (!KEEP.has(subset)) continue;
  const family = block.match(/font-family:\s*'([^']+)'/)[1];
  const weight = block.match(/font-weight:\s*([^;]+);/)[1].trim();
  const style = block.match(/font-style:\s*([^;]+);/)[1].trim();
  const range = block.match(/unicode-range:\s*([^;]+);/)[1].trim();
  const url = block.match(/url\((https:[^)]+\.woff2)\)/)[1];

  const file = await fetch(url, { headers: { 'User-Agent': UA } });
  if (!file.ok) throw new Error(`${family} ${weight} ${subset}: ${file.status} ${file.statusText}`);
  const buf = Buffer.from(await file.arrayBuffer());
  // A short body here is an error page, not a font, and would be committed as
  // one — a face that silently falls back on every machine.
  if (buf.length < 1000) throw new Error(`${family} ${weight} ${subset} came back as ${buf.length} bytes, which is not a font`);
  downloaded.push({ family, weight, style, subset, range, buf, hash: createHash('sha256').update(buf).digest('hex') });
}

const slug = (s) => s.toLowerCase().replace(/ /g, '-');
const groupKey = (f) => `${f.family}|${f.subset}`;
const groups = new Map();
for (const f of downloaded) {
  const g = groups.get(groupKey(f)) ?? [];
  g.push(f);
  groups.set(groupKey(f), g);
}

const faces = [];
const written = new Map();   // hash -> filename, so one body is written once
for (const [, group] of groups) {
  const shared = new Set(group.map(f => f.hash)).size === 1;
  for (const f of group) {
    let name = written.get(f.hash);
    if (!name) {
      name = shared
        ? `${slug(f.family)}-${f.subset}.woff2`
        : `${slug(f.family)}-${f.weight}-${f.subset}.woff2`;
      writeFileSync(`${OUT_DIR}/${name}`, f.buf);
      written.set(f.hash, name);
      bytes += f.buf.length;
    }
    faces.push({ family: f.family, weight: f.weight, style: f.style, name, range: f.range, subset: f.subset });
  }
}

faces.sort((a, b) => a.family.localeCompare(b.family) || Number(a.weight) - Number(b.weight) || a.subset.localeCompare(b.subset));

const header = readHeader();
writeFileSync(OUT_CSS, header + faces.map(f =>
  `@font-face {\n`
  + `  font-family: '${f.family}';\n`
  + `  font-style: ${f.style};\n`
  + `  font-weight: ${f.weight};\n`
  + `  font-display: swap;\n`
  + `  src: url('./assets/fonts/${f.name}') format('woff2');\n`
  + `  unicode-range: ${f.range};\n`
  + `}\n`
).join('\n'), 'utf8');

console.log(`[fonts] ${faces.length} faces over ${written.size} file(s), ${(bytes / 1024).toFixed(0)} KB`);
console.log(`[fonts] wrote ${OUT_CSS} and ${OUT_DIR}`);
console.log('[fonts] run `npm run check:fonts` to confirm, and commit the .woff2 files');

/** The explanatory header, kept out of the generated list so regenerating does not lose it. */
function readHeader() {
  return `/**
 * The interface fonts, carried in the build instead of fetched from Google.
 *
 * GENERATED by \`npm run fonts:refresh\`. Edit that script, not this file.
 *
 * Why this is here rather than two <link> tags in \`index.html\`.
 *
 * This is an offline-first tool. The engineering log says so about the CVE
 * snapshot in as many words — "this rig is offline in the field and opened
 * occasionally" — and the one thing still fetched at runtime was the typeface.
 * Measured inside the built app's own WebView2: online, all four families
 * resolved and were used; offline the stack fell through to Segoe UI, Cascadia
 * Mono and Bahnschrift Condensed. The tool looked like one application on a desk
 * and a different one in the field, and the field is where it is used.
 *
 * The second reason is the stronger one. A security assessment tool that opens a
 * connection to a third party every time it starts is making a request somebody
 * will eventually have to explain — in an air-gapped assessment it is a policy
 * breach, and on any engagement it is an outbound record of when the tool ran.
 * Nothing about rendering a heading needs that. With these files local, \`csp\`
 * names no font host at all, so the policy refuses the request rather than the
 * network merely happening not to answer it.
 *
 * What was taken: the \`latin\` and \`latin-ext\` subsets, which is exactly the set
 * the browser was already choosing to download from the same stylesheet. Text
 * outside those ranges is drawn by a system font, as it was before.
 *
 * \`unicode-range\` is preserved per face. Without it the browser loads every face
 * before it knows which it needs, which for 21 files is the opposite of the
 * reason they are split.
 */

`;
}
