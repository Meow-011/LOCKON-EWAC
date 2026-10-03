#!/usr/bin/env node
/**
 * Every declared font face has a file, and nothing fetches a font at runtime.
 *
 *     npm run check:fonts
 *
 * Why this exists.
 *
 * The fonts used to come from Google at startup, and the one thing that went
 * wrong with that arrangement was invisible: `index.html` loaded the stylesheet
 * `media="print"` and flipped it to `"all"` with an inline `onload`, which the
 * shipped `script-src-attr` refuses — so in a built copy the flip never ran and
 * the interface silently rendered on its fallback stack. Nothing failed. The app
 * simply looked slightly different, in a way nobody had a reason to look for.
 *
 * Self-hosting removes that failure and introduces two of its own, both equally
 * quiet. A face declared in `fonts.css` whose `.woff2` was never committed falls
 * back exactly as before and says nothing. And a `<link>` to a font CDN
 * reintroduced later would work on the developer's desk and fail in the field,
 * which is the environment this tool is actually for — and would put an outbound
 * request back into a security tool that is supposed to make none.
 *
 * So: resolve every `url()` against the filesystem, and refuse any reference to
 * a font host in the application's own sources or in the policy. The CSP is
 * checked too, because dropping the grant is what turns "we happen not to
 * request it" into "the policy refuses it".
 */
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, resolve, relative } from 'node:path';

const CSS = 'src/fonts.css';
const FONT_DIR = 'src/assets/fonts';
const FONT_HOST = /fonts\.(googleapis|gstatic)\.com/;
const SEPARATOR = String.fromCharCode(92); // a literal backslash, as Windows paths use
const problems = [];

if (!existsSync(CSS)) {
  console.error(`[fonts] FAIL — ${CSS} is missing`);
  process.exit(1);
}
const css = readFileSync(CSS, 'utf8');

// Comments are stripped before the host search, so the explanation of why the
// CDN was dropped does not read as the CDN coming back.
const stripComments = (text) => text
  .replace(/<!--[\s\S]*?-->/g, '')
  .replace(/\/\*[\s\S]*?\*\//g, '');

// ── 1. Every face resolves to a file ───────────────────────────────────────
const faces = css.match(/@font-face\s*\{[^}]*\}/g) || [];
if (faces.length === 0) problems.push(`${CSS} declares no @font-face rules`);

const referenced = new Set();
for (const face of faces) {
  const family = (face.match(/font-family:\s*'([^']+)'/) || [])[1] ?? '(unnamed)';
  const weight = (face.match(/font-weight:\s*([^;]+);/) || [])[1]?.trim() ?? '?';
  const url = (face.match(/url\(['"]?([^'")]+)['"]?\)/) || [])[1];
  if (!url) { problems.push(`${family} ${weight}: no url()`); continue; }
  if (/^https?:/i.test(url)) { problems.push(`${family} ${weight}: still points at ${url}`); continue; }

  const file = resolve(dirname(CSS), url);
  referenced.add(relative('.', file).split(SEPARATOR).join('/'));
  if (!existsSync(file)) {
    problems.push(`${family} ${weight}: ${url} has no file — this face falls back silently`);
  }
  // A unicode-range per face is why 21 files is cheaper than four rather than
  // more expensive: without it the browser fetches every face before it knows
  // which one it needs.
  if (!/unicode-range:/.test(face)) {
    problems.push(`${family} ${weight}: no unicode-range, so every face loads regardless of need`);
  }
}

// ── 2. No orphans ──────────────────────────────────────────────────────────
// A committed file nothing declares is dead weight in every installer, and
// usually the trace of a face that was renamed rather than removed.
if (existsSync(FONT_DIR)) {
  for (const f of readdirSync(FONT_DIR).filter(n => n.endsWith('.woff2'))) {
    const path = `${FONT_DIR}/${f}`;
    if (!referenced.has(path)) problems.push(`${path} is committed but no @font-face names it`);
  }
}

// ── 2b. No two files hold the same bytes ────────────────────────────
// These are variable fonts: one body covers every weight of a family within a
// subset. Naming the files by weight committed ten duplicate binaries, which
// Vite then deduplicated back down in the build -- so the waste never reached a
// user and sat in the repository instead, which is the kind of thing that is
// only ever noticed by looking.
if (existsSync(FONT_DIR)) {
  const byHash = new Map();
  for (const f of readdirSync(FONT_DIR).filter(n => n.endsWith('.woff2'))) {
    const hash = createHash('sha256').update(readFileSync(`${FONT_DIR}/${f}`)).digest('hex');
    const first = byHash.get(hash);
    if (first) problems.push(`${f} is byte-identical to ${first} — one of them is a duplicate the build will collapse anyway`);
    else byHash.set(hash, f);
  }
}

// ── 3. Nothing reaches for a font host ─────────────────────────────────────
for (const file of ['index.html', 'src/main.tsx', 'src/index.css', CSS]) {
  if (existsSync(file) && FONT_HOST.test(stripComments(readFileSync(file, 'utf8')))) {
    problems.push(`${file} references a font CDN outside a comment — it would work here and fail in the field`);
  }
}

const conf = JSON.parse(readFileSync('src-tauri/tauri.conf.json', 'utf8'));
for (const key of ['csp', 'devCsp']) {
  const policy = conf.app?.security?.[key] ?? '';
  if (FONT_HOST.test(policy)) {
    problems.push(`${key} still grants a font host — the policy should refuse the request, not merely not make it`);
  }
}

if (problems.length > 0) {
  console.error('[fonts] FAIL');
  for (const p of problems) console.error(`  - ${p}`);
  console.error(`${SEPARATOR}n  \`npm run fonts:refresh\` re-fetches the files this stylesheet names.`);
  process.exit(1);
}

console.log(`[fonts] ${faces.length} faces, ${referenced.size} files, no font host in sources or policy`);
console.log('[fonts] PASS');
