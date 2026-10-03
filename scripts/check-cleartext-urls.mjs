#!/usr/bin/env node
/**
 * Nothing this tool ships points at a third party over plain HTTP.
 *
 *     npm run check:cleartext
 *
 * Why this exists.
 *
 * The KML exporter embedded two `IconStyle` hrefs to Google's map-shape images
 * over cleartext. The gaps list had them recorded, accurately as far as it went,
 * as a cosmetic problem: an offline viewer falls back to default pins and the
 * data is unaffected. What it had not noticed was the scheme.
 *
 * A KML is a deliverable. It is handed to a client, who opens it weeks later on
 * their own machine — and each of those hrefs meant a cleartext request left that
 * machine for a third party at the moment somebody read the assessment. That is
 * an outbound record of when a security report was opened, sent in the clear,
 * from a file this tool produced. Nothing about a pin shape needs it.
 *
 * What this does NOT check, and why the first version of it was wrong.
 *
 * It was written to flag plain HTTP anywhere, and it flagged two dozen lines
 * that were all correct. This is a network scanner: `lan.py` probes a target's
 * own web service, `cve_db.py` carries proof-of-concept URLs with a literal
 * TARGET placeholder, and the engine tests use RFC 1918 fixtures. Forcing https
 * on any of those would break the scanner or rewrite a published PoC. A blanket
 * rule is not merely noisy here, it is incoherent.
 *
 * The rule that survives is narrow: a **literal** cleartext URL whose host is a
 * **public DNS name**. A template (`{ip}`, `${port}`), a bare word with no dot
 * (`TARGET`, `tauri`), an IP literal and anything on localhost are all left
 * alone, because none of them is this tool reaching out to somebody else's
 * server. XML namespace URIs are listed exactly, because they are identifiers
 * compared as strings and rewriting one produces a document that no longer
 * validates.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOTS = ['src', 'scripts', 'engine', 'index.html'];
const EXTENSIONS = /\.(ts|tsx|mjs|js|py|html|css)$/;
const SKIP_DIRS = new Set(['node_modules', '__pycache__', 'dist', 'build', '.venv', 'target', 'fonts']);

/** Identifiers, not addresses. Compared in full, so a real URL to the same host still fails. */
const NAMESPACE_URIS = new Set([
  'http://www.w3.org/2000/svg',
  'http://www.w3.org/1999/xhtml',
  'http://www.w3.org/2000/xmlns/',
  'http://www.opengis.net/kml/2.2',
  'http://www.google.com/kml/ext/2.2',
]);

const SCHEME = 'http' + '://';
const URL_RE = new RegExp(SCHEME + '[^\\s\'"`)>\\\\]+', 'g');
const findings = [];

/**
 * True when the host is a fixed public DNS name this tool would really contact.
 *
 * Everything else is a target, a template or a loopback, and this project speaks
 * plain HTTP to all three by design.
 */
function isThirdPartyHost(url) {
  const host = url.slice(SCHEME.length).split(/[/:?#]/)[0];
  if (!host) return false;
  if (/[{}$<>…*]/.test(host)) return false;              // a template or prose ellipsis
  if (!host.includes('.')) return false;                       // TARGET, tauri, localhost
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return false;      // an IP literal, incl. fixtures
  if (/^(localhost|ipc\.localhost)$/i.test(host)) return false;
  return true;
}

function scan(file) {
  const lines = readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, i) => {
    for (const match of line.match(URL_RE) || []) {
      const url = match.replace(/[.,;:]+$/, '');              // trailing prose punctuation
      if (NAMESPACE_URIS.has(url)) continue;
      if (!isThirdPartyHost(url)) continue;
      findings.push({ file: file.replace(/\\/g, '/'), line: i + 1, url });
    }
  });
}

function walk(dir) {
  for (const entry of readdirSync(dir)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) walk(full);
    else if (EXTENSIONS.test(entry)) scan(full);
  }
}

for (const root of ROOTS) {
  try {
    if (statSync(root).isDirectory()) walk(root);
    else scan(root);
  } catch { /* a root that is not present is not a failure */ }
}

if (findings.length > 0) {
  console.error('[cleartext] FAIL — a third-party host over plain HTTP:');
  for (const f of findings) console.error(`  - ${f.file}:${f.line}  ${f.url}`);
  console.error('\n  Use https. A URL embedded in an exported file is fetched on the');
  console.error('  recipient\'s machine, which makes it a record of when they opened it.');
  console.error('  If it is an XML namespace, add the exact URI to NAMESPACE_URIS here.');
  process.exit(1);
}

console.log('[cleartext] no third-party host reached over plain HTTP');
console.log('[cleartext] PASS');
