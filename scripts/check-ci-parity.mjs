/**
 * LOCKON EWAC — what CI checks out must be what this machine compiles.
 *
 *     npm run check:ci
 *
 * Both rules here come from one CI run that failed on two unrelated things, and
 * both share a shape: a check that passes locally because the local shell and the
 * local working tree are not the ones CI uses.
 *
 * ── 1. No source file is invisible to git ──────────────────────────────────
 *
 * `.gitignore` carried `exports/`. A gitignore pattern containing no slash
 * matches at **every depth**, so that meant "any directory named exports,
 * anywhere" rather than the top-level output directory it was written for. It
 * swallowed `src/lib/report/exports/` — four TypeScript modules the Reports page
 * imports — and every signal said the repository was fine:
 *
 *   * `git add -A` skipped them silently, because adding an ignored file is not
 *     an error.
 *   * `git status` was clean, because an ignored file is not untracked.
 *   * `npx tsc --noEmit` passed here, because the files are on disk.
 *
 * CI checked out a tree without them and failed with four `TS2307`s naming
 * modules that exist in every working copy. The only place the truth was visible
 * was `git check-ignore`, which nobody runs.
 *
 * ── 2. No `$?` that `-e` will never let you read ───────────────────────────
 *
 * GitHub runs `shell: bash` as `bash --noprofile --norc -eo pipefail {0}`. A step
 * that writes
 *
 *     python -m pyflakes engine > pyflakes.txt
 *     status=$?
 *
 * never reaches the second line when the command exits non-zero: `-e` aborts the
 * step first. The pyflakes step had four careful branches below that assignment
 * distinguishing "pyflakes crashed" from "pyflakes found style issues" from
 * "pyflakes found undefined names", and **none of them had ever executed**. It
 * failed the build on 39 unused imports while reporting undefined names, of which
 * there were none.
 *
 * A command whose non-zero exit is meaningful has to be written `|| status=$?`.
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';

const problems = [];

// ── 1. Ignored source ──────────────────────────────────────────────────────
/** Directories whose contents are the project rather than its output. */
const SOURCE_DIRS = ['src', 'src-tauri/src', 'engine', 'scripts', 'tests', 'installer'];
const SOURCE_EXT = /\.(ts|tsx|js|mjs|cjs|py|rs|css|iss|toml|json|md)$/i;

/*
  Generated files that are ignored on purpose. Each is written by a build step
  and named here rather than matched by a pattern, so adding one is a decision
  somebody makes in this file instead of a rule quietly widening.
*/
const DELIBERATELY_IGNORED = [
  'engine/_build_info.py',   // written by the PyInstaller spec on every build
];
const IGNORED_DIRS = [
  'engine/build/',           // PyInstaller work directory
  'engine/dist/',
  'scripts/baselines/',      // PDF regression baselines; survey data
  '__pycache__/',
  'node_modules/',
];

let ignoredSource = [];
try {
  const out = execFileSync('git', ['ls-files', '--others', '--ignored', '--exclude-standard'],
    { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  ignoredSource = out.split(String.fromCharCode(10))
    .map(l => l.trim())
    .filter(Boolean)
    .filter(f => SOURCE_DIRS.some(d => f.startsWith(`${d}/`)))
    .filter(f => SOURCE_EXT.test(f))
    .filter(f => !DELIBERATELY_IGNORED.includes(f))
    .filter(f => !IGNORED_DIRS.some(d => f.includes(d)));
} catch (e) {
  problems.push(`git could not list ignored files, so nothing was checked: ${e.message}`);
}

if (ignoredSource.length) {
  problems.push(
    `${ignoredSource.length} source file(s) are ignored by git and will not exist in a fresh clone:`);
  for (const f of ignoredSource.slice(0, 15)) {
    let why = '';
    try {
      why = execFileSync('git', ['check-ignore', '-v', f], { encoding: 'utf8' }).trim();
    } catch { /* check-ignore exits 1 when nothing matches */ }
    problems.push(`    ${f}${why ? `  <- ${why.split('\t')[0]}` : ''}`);
  }
  if (ignoredSource.length > 15) problems.push(`    ... and ${ignoredSource.length - 15} more`);
}

// ── 2. `$?` under `-e` ─────────────────────────────────────────────────────
const WORKFLOW_DIR = '.github/workflows';
let safeCaptures = 0;
if (existsSync(WORKFLOW_DIR)) {
  for (const file of readdirSync(WORKFLOW_DIR).filter(f => /\.ya?ml$/.test(f))) {
    const path = join(WORKFLOW_DIR, file);
    const lines = readFileSync(path, 'utf8').split(String.fromCharCode(10));

    let sawSetPlusE = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*set\s+\+e\b/.test(line)) sawSetPlusE = true;
      // A new step resets the shell, so `set +e` does not carry across one.
      if (/^\s*-\s+name:/.test(line)) sawSetPlusE = false;

      /*
        Counted as well as flagged, so a pass says what was looked at. A rule
        reporting "0 captures checked" has not established anything, and this one
        would have read exactly that on the day the defect was live, because the
        broken form and the safe form are different shapes.
      */
      if (/\|\|\s*\w+=\$\?/.test(line)) { safeCaptures++; continue; }

      const assign = line.match(/^\s*(\w+)=\$\?\s*$/);
      if (!assign) continue;
      if (sawSetPlusE) { safeCaptures++; continue; }

      // The command whose status is being read: the previous line that is not
      // blank and not a comment.
      let j = i - 1;
      while (j >= 0 && (lines[j].trim() === '' || lines[j].trim().startsWith('#'))) j--;
      const prev = j >= 0 ? lines[j].trim() : '';

      if (!/\|\|/.test(prev)) {
        problems.push(
          `${path}:${i + 1}: \`${assign[1]}=$?\` cannot run — GitHub's bash has \`-e\`, so`);
        problems.push(`    the previous command aborts the step on a non-zero exit:`);
        problems.push(`      ${prev}`);
        problems.push(`    write it as \`${prev} || ${assign[1]}=$?\`, or \`set +e\` first.`);
      }
    }
  }
}

if (problems.length) {
  console.log('[ci] FAIL');
  for (const p of problems) console.log(`  - ${p}`);
  process.exit(1);
}

console.log('[ci] no source file is hidden from a fresh clone; '
  + `${safeCaptures} exit-code capture(s) in the workflows survive \`-e\``);
console.log('[ci] PASS');
