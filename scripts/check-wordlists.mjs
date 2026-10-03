/**
 * LOCKON EWAC — every shipped wordlist is documented, and a WPA list is one.
 *
 *     npm run check:wordlists
 *
 * Two rules, both from a pre-publication audit.
 *
 * ── 1. A file in the directory has a row in THIRD-PARTY-NOTICES.md ─────────
 *
 * That document used to say, of these eight files, that "their provenance is not
 * currently documented per file" and that redistribution should be treated as
 * unestablished. It said so accurately, and it said so for months, because prose
 * describing an outstanding job does not do the job.
 *
 * It is documented now. This keeps it documented: a list added to the directory
 * without a row fails here rather than quietly shipping inside the installer with
 * nothing recorded about where it came from.
 *
 * ── 2. A list named for WPA contains only passphrases WPA can have ─────────
 *
 * IEEE 802.11i fixes a WPA/WPA2 passphrase at 8 to 63 characters. A shorter
 * candidate cannot be the answer, so trying it is time spent on a known negative.
 *
 * `rockyou-wpa-optimized.txt` shipped with **7,914 of its 10,000 entries shorter
 * than eight characters** — 79% of a list whose name claims it was optimised for
 * WPA, and every one of them a guess that could not succeed. The two other
 * passphrase lists were filtered correctly, which is what made the outlier
 * visible. Nothing measured it, because nothing had been asked to.
 */
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const DIR = 'engine/wordlists';
const NOTICES = 'THIRD-PARTY-NOTICES.md';
const problems = [];

if (!existsSync(DIR)) {
  console.error(`[wordlists] ${DIR} is missing`);
  process.exit(2);
}

const files = readdirSync(DIR).filter(f => f.endsWith('.txt')).sort();
if (files.length === 0) {
  console.error('[wordlists] no wordlists found, so nothing was checked');
  process.exit(2);
}

// ── 1. Documented ──────────────────────────────────────────────────────────
const notices = existsSync(NOTICES) ? readFileSync(NOTICES, 'utf8') : '';
for (const f of files) {
  if (!notices.includes(`\`${f}\``)) {
    problems.push(`${f} ships in the installer and has no row in ${NOTICES}`);
  }
}

/*
  And the other direction: a row for a file that is no longer there describes
  something the installer does not carry, which misleads in the opposite way.
*/
for (const m of notices.matchAll(/\|\s*`([a-z0-9._-]+\.txt)`\s*\|/gi)) {
  if (!files.includes(m[1])) {
    problems.push(`${NOTICES} documents ${m[1]}, which is not in ${DIR}`);
  }
}

// ── 2. A WPA list holds WPA passphrases ────────────────────────────────────
const MIN = 8;   // IEEE 802.11i
const MAX = 63;
let checkedWpa = 0;
for (const f of files) {
  if (!/wpa/i.test(f)) continue;
  checkedWpa++;
  const entries = readFileSync(join(DIR, f), 'utf8')
    .split(String.fromCharCode(10))
    .map(l => l.replace(/\r$/, ''))
    .filter(l => l.length > 0);
  const bad = entries.filter(e => e.length < MIN || e.length > MAX);
  if (bad.length) {
    const pct = ((bad.length / entries.length) * 100).toFixed(1);
    problems.push(
      `${f} is named for WPA and ${bad.length} of its ${entries.length} entries (${pct}%) `
      + `are outside ${MIN}-${MAX} characters, so they cannot be a WPA passphrase. `
      + `Shortest: "${bad.sort((a, b) => a.length - b.length)[0]}"`);
  }
}

if (problems.length) {
  console.log('[wordlists] FAIL');
  for (const p of problems) console.log(`  - ${p}`);
  process.exit(1);
}

const total = files.reduce((n, f) =>
  n + readFileSync(join(DIR, f), 'utf8').split(String.fromCharCode(10)).filter(l => l.trim()).length, 0);
console.log(`[wordlists] ${files.length} list(s), ${total.toLocaleString()} entries, each documented; `
  + `${checkedWpa} WPA list(s) hold only ${MIN}-${MAX} character candidates`);
console.log('[wordlists] PASS');
