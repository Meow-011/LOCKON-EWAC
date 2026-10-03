/**
 * LOCKON EWAC — do the docs still describe this repository?
 *
 *     npm run check:docs
 *
 * Why this exists.
 *
 * The README is the longest document in the project and it makes checkable
 * claims: that a file exists, that a suite has N tests, that a command can be
 * run, that a function is gone. Those are exactly the claims that rot, and they
 * rot silently — a stale line in a README reads the same as a true one.
 *
 * It had rotted. The test counts were two rounds of work behind (313 and 413
 * against 520 and 445), the project tree was missing a dozen modules including
 * every one added in the same week, and `docs/PLAYBOOK.md` still described
 * `getPortIntel` — a frontend CVE table that had been deleted — as the thing
 * that decides whether EternalBlue is flagged.
 *
 * This checks only what can be checked mechanically. Prose has to be read; a
 * number, a path and an identifier do not.
 */
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { spawnSync } from 'node:child_process';

/*
  Every document, not just the README.

  The README was split into topic files so a reader after one thing does not
  scroll past the other nine — which means the claims moved too, and a check
  that only reads the front page would now pass over all of them.
*/
const DOCS = [
  'README.md',
  'docs/INSTALL.md',
  'docs/ARCHITECTURE.md',
  'docs/TESTING.md',
  'docs/TROUBLESHOOTING.md',
  'docs/ENGINEERING_LOG.md',
  'docs/PLAYBOOK.md',
  'docs/AP_LOCATION_METHODS.md',
  'docs/GPS_AND_SURVEY.md',
  // Root documents are checked too. CONTRIBUTING names npm scripts and source
  // paths, SECURITY names where data lives, and both rot exactly as quietly as
  // the rest — a contributor following a command that no longer exists has been
  // misled by this repository, whichever file it was written in.
  'CONTRIBUTING.md',
  'SECURITY.md',
  'THIRD-PARTY-NOTICES.md',
];
const problems = [];

const ok = (label, pass, detail = '') => {
  console.log(`  ${pass ? 'OK  ' : 'FAIL'}  ${label}${!pass && detail ? ` — ${detail}` : ''}`);
  if (!pass) problems.push(label);
};

const docs = Object.fromEntries(
  DOCS.filter(existsSync).map(d => [d, readFileSync(d, 'utf8')]),
);
const all = Object.values(docs).join('\n');
const readme = docs['README.md'] ?? '';
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));

/*
  1. Identifiers the code no longer has must not be described as live.

  A mention is allowed — the docs explain what things replaced, and that history
  is worth keeping. What is not allowed is presenting one as current, so the
  check is: if the identifier is absent from `src/`, no doc may mention it
  outside a sentence that marks it as past.
*/
const srcText = (function read(dir) {
  let out = '';
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = `${dir}/${entry.name}`;
    if (entry.isDirectory()) out += read(path);
    else if (/\.tsx?$/.test(entry.name)) out += readFileSync(path, 'utf8');
  }
  return out;
})('src');

const PAST_TENSE =
  /used to|no longer|has been|was a|were a|replaced|deleted|removed|is gone|that had been|stopped|held a|moved (?:in)?to|any more/i;
for (const gone of ['getPortIntel', 'RISK_THRESHOLDS', 'SIGNAL_THRESHOLDS']) {
  /*
    A *declaration*, not a mention. The source comments these identifiers by
    name to explain what replaced them, so a plain `includes` matched every one
    of them and skipped the check entirely — it passed while proving nothing.
  */
  /*
    `String.raw`, because this is a template literal.

    Written as a plain template, `\s` collapses to `s` and `\b` becomes U+0008, so the
    compiled pattern was `(?:const|…|export function)s+getPortIntel\x08` — which matches
    nothing. Confirmed in node: it returns false even for
    `export const getPortIntel = () => {}`. So `if (declared) continue` could never
    fire, and the intent documented just above it was inverted: reintroducing any of
    these identifiers would not relax the check, it would make the check demand
    past-tense prose around every mention of a name that is live again, and fail.
  */
  const declared = new RegExp(
    String.raw`(?:const|let|function|class|export const|export function)\s+${gone}\b`,
  ).test(srcText);
  if (declared) continue;
  const bad = [];
  for (const [name, text] of Object.entries(docs)) {
    for (const m of text.matchAll(new RegExp(`\`${gone}\``, 'g'))) {
      const around = text.slice(Math.max(0, m.index - 400), m.index + 400);
      if (!PAST_TENSE.test(around)) bad.push(`${name}:${text.slice(0, m.index).split('\n').length}`);
    }
  }
  ok(`${gone} is not described as live code`, bad.length === 0, bad.join(', '));
}

// 2. Every test file the docs name, with a count, exists.
// Digits belong in both patterns. `test_[a-z_]+` silently skipped
// `test_smb2_wire_format.py`, so the coverage check above counted 31 of 32 engine
// files and the total it summed was short by that file's tests -- a checker blind
// to a name is worse than no checker, because it reports OK.
/*
  The component suites joined this when they were documented individually.

  They were described collectively for a long time -- "76 across eleven files" --
  so their per-file counts were prose nothing checked, and two of them were wrong
  within an hour of being written (a pair of figures transposed). The pattern
  accepts a bare `name.test.tsx` as well as a full path, because the table names
  several of them on one row after the first.
*/
const named = [...all.matchAll(/`((?:tests\/(?:components\/)?)?[A-Za-z0-9]+\.test\.(?:mjs|tsx)|test_[a-z0-9_]+\.py)`\s*\((\d+)\)/g)]
  .reduce((acc, m) => {
    const file = m[1].includes('/') || m[1].endsWith('.py')
      ? m[1]
      : `tests/components/${m[1]}`;
    return { ...acc, [file]: Number(m[2]) };
  }, {});
const missing = Object.keys(named)
  .filter(n => !existsSync(n) && !existsSync(`engine/tests/${n}`));
ok('every test file named in the docs exists', missing.length === 0, missing.join(', '));

/*
  The counts written beside a command a contributor is told to run.

  CONTRIBUTING's "before you open a pull request" block said `npm test` was
  15 suites and `run_all.py` was 26 files. They were 23 and 32. Nothing caught it,
  because the existing suite rule checks that every suite is *named* somewhere, and
  a number in a trailing comment is not a name.

  A stale count there is worse than a stale count in a reference document: it is
  the first thing a new contributor runs, and a number that does not match what
  scrolls past teaches them on their first day that this repository's numbers are
  approximate.
*/
const runCounts = [
  {
    file: 'CONTRIBUTING.md',
    pattern: /npm test\s+#\s*(\d+)\s*suites/,
    actual: () => [...pkg.scripts.test.matchAll(/npm run test:[a-z-]+/g)].length,
    what: 'suites in `npm test`',
  },
  {
    file: 'CONTRIBUTING.md',
    pattern: /run_all\.py\s+#\s*(\d+)\s*files/,
    actual: () => readdirSync('engine/tests').filter(f => /^test_.*\.py$/.test(f)).length,
    what: 'engine test files',
  },
  {
    file: 'CONTRIBUTING.md',
    pattern: /npm run test:components\s+#\s*(\d+)\s*files/,
    actual: () => readdirSync('tests/components').filter(f => /\.test\.tsx?$/.test(f)).length,
    what: 'component test files',
  },
];

for (const r of runCounts) {
  if (!existsSync(r.file)) continue;
  const m = readFileSync(r.file, 'utf8').match(r.pattern);
  const actual = r.actual();
  if (!m) {
    problems.push(`${r.file} no longer states how many ${r.what} there are`);
    continue;
  }
  ok(`${r.file} states the right number of ${r.what}`,
    Number(m[1]) === actual, `says ${m[1]}, there are ${actual}`);
}

// 3. The docs cover every suite that actually runs.
const suites = [...pkg.scripts.test.matchAll(/npm run (test:[a-z-]+)/g)].map(m => m[1]);
const engineFiles = readdirSync('engine/tests').filter(f => /^test_.*\.py$/.test(f));
/*
  Three populations, not two.

  `frontendNamed` meant "everything under tests/" until the component suites were
  documented per file, at which point they were counted as node suites and summed
  into the node total -- reporting 43 suites against 23 scripts and a total of 832
  against a real 679. They run under a different runner, are listed by a different
  command, and have their own total.
*/
const componentNamed = Object.keys(named).filter(n => n.startsWith('tests/components/'));
const frontendNamed = Object.keys(named)
  .filter(n => n.startsWith('tests/') && !n.startsWith('tests/components/'));
const engineNamed = Object.keys(named).filter(n => n.startsWith('test_'));
ok(`docs describe all ${suites.length} frontend suites`, frontendNamed.length === suites.length,
  `docs have ${frontendNamed.length}`);
ok(`docs describe all ${engineFiles.length} engine test files`, engineNamed.length === engineFiles.length,
  `docs have ${engineNamed.length}`);

/*
  4. Every per-file count is the number of tests in that file.

  This used to compare the documented counts against *each other*: the per-file
  numbers were parsed out of the prose, the only thing checked about the file was
  `existsSync`, and the headline total was then verified with
  `all.includes(String(total))` -- a bare substring over all twelve concatenated
  documents, so a stale total still passed if those digits appeared anywhere, in a line
  count or a port number or a byte size. The project's advertised test figure certified
  itself, and so did every number feeding it.

  Counted statically rather than by running the suites, which keeps this check fast
  enough to stay in the pre-commit path. Static counting is only trustworthy because
  `engine/tests/run_all.py` now fails a file that executes nothing -- that pairing is
  what closes the gap between "defined" and "ran", and one without the other is how
  seven GPS tests sat un-executed behind an exactly-correct documented count.
*/
const countTests = (file) => {
  const path = existsSync(file) ? file : `engine/tests/${file}`;
  const body = readFileSync(path, 'utf8');
  return file.endsWith('.py')
    // Module-level `def test_...`. Indented ones are methods on a helper class, which
    // pytest does not collect and `_main()` does not either.
    ? (body.match(/^def test_\w+\s*\(/gm) || []).length
    // `test('name', ...)` at the start of a line, which is how every node suite is
    // written. A nested or conditionally-registered test would be missed, and none is.
    // The component suites group theirs under `describe`, so those are indented --
    // hence the optional leading whitespace, which the node suites never have.
    : (body.match(/^\s*test\(/gm) || []).length;
};

const countMismatches = [];
for (const [file, claimed] of Object.entries(named)) {
  if (!existsSync(file) && !existsSync(`engine/tests/${file}`)) continue;
  const actual = countTests(file);
  if (actual !== claimed) countMismatches.push(`${file} says ${claimed}, has ${actual}`);
}
ok(`all ${Object.keys(named).length} per-file test counts match the file`,
   countMismatches.length === 0, countMismatches.join('; '));

/*
  5. The headline totals agree with the files, and are stated as totals.

  Matched against the sentence that states the figure rather than against the whole
  corpus, so a number that merely happens to appear somewhere cannot satisfy it.
*/
const sum = keys => keys.reduce((n, k) => n + countTests(k), 0);
const totals = [
  // The suite count is read, not hardcoded. It was `/16 frontend suites/`, so
  // adding a seventeenth suite stopped the sentence matching at all and the
  // check reported "no sentence states it" -- a failure whose message points
  // away from the cause. The count itself is verified separately above.
  [sum(frontendNamed), 'frontend', /(\d[\d,]*)\s+tests\)/g, [/\d+ frontend suites \((\d[\d,]*) tests\)/]],
  [sum(componentNamed), 'component', /(\d[\d,]*)\s+tests\)/g, [/\d+ files, (\d[\d,]*) tests\): vitest/, /jsdom \(\d+ files, (\d[\d,]*) tests\)/]],
  /*
    Each total may be stated in more than one place, and every place has to agree.

    This matched one sentence and stopped, which let two numbers rot in plain
    sight. `ARCHITECTURE.md` carried "15 frontend suites (525 tests)" against a
    real 608, and its engine tree comment said "26 files, 488 tests" against 683 —
    both invisible, because the patterns were anchored on the wording of a
    different sentence in a different file.

    Widening one pattern to any "N files, M tests" then matched the component
    suite as well, which is a different number and correctly so. The answer is
    not a cleverer regex but several explicit ones: a total lists the forms it is
    allowed to appear in, and all of them must agree with the count.
  */
  [sum(engineNamed), 'engine', /(\d[\d,]*)\s+tests\)/g, [
    /engine suite \(\d+ files, (\d[\d,]*) tests\)/,
    /(\d[\d,]*) tests; no third-party/,
  ]],
];
/*
  Every sentence that states the total, not just the first one.

  This matched once and stopped. `ARCHITECTURE.md` carried "15 frontend suites
  (525 tests)" against a real 596, and the check had never looked at it: the
  pattern was anchored on a hardcoded "16 frontend suites", so the one sentence
  with a different count was the one sentence it could not see. A stale figure in
  a second document is the same defect as a stale figure in the first, and the
  only reason to check one would be that it was easier.
*/
for (const [total, what, , sentences] of totals) {
  const found = [];
  for (const sentence of sentences) {
    for (const m of all.matchAll(new RegExp(sentence.source, 'g'))) {
      found.push(Number(m[1].replace(/,/g, '')));
    }
  }
  const wrong = found.filter(n => n !== total);
  ok(`the ${what} total is stated as ${total}`,
     found.length > 0 && wrong.length === 0,
     found.length === 0 ? 'no sentence states it' : `the docs also say ${[...new Set(wrong)].join(', ')}`);
}

/*
  5. Every npm script the docs tell a reader to run exists.

  `npm run test:<name>` is a placeholder, not a script — the docs use it to say
  "any of the above individually" — so angle brackets are skipped rather than
  reported as a missing script.
*/
const documentedScripts = new Set(
  [...all.matchAll(/npm run ([a-z][a-z:-]*)/g)].map(x => x[1]).filter(m => !m.endsWith(':'))
);

/*
  And the other direction: every `check:` script is written down somewhere.

  The forward check catches a doc naming a script that does not exist. The
  reverse catches the commoner thing — a check added to `package.json` and to CI
  and never mentioned to anyone, which is how five of them accumulated. A check
  nobody knows to run before a release is a check that does not exist on the day
  it matters.

  Only `check:` scripts, because the per-suite `test:` ones are covered
  collectively by the docs saying each is runnable as `npm run test:<name>`, and
  listing twenty of them individually would be noise rather than information.
*/
const undocumented = Object.keys(pkg.scripts)
  .filter(k => k.startsWith('check:'))
  .filter(k => !documentedScripts.has(k));
ok('every check: script is documented', undocumented.length === 0,
   `not mentioned anywhere: ${undocumented.join(', ')}`);

for (const m of documentedScripts) {
  ok(`npm script exists: ${m}`, m in pkg.scripts);
}

// 6. Every file named in the README's project tree exists somewhere sensible.
/*
  Find the tree by its own shape, not by the repository's name appearing
  somewhere in the file.

  This used to be `.find(t => t.includes('LOCKON-EWAC/'))`, which matches any URL
  carrying the repo name -- and adding a CI badge, whose URL is
  `.../LOCKON-EWAC/actions/workflows/ci.yml`, silently moved the match to the
  README. The checker then sliced from the badge and scanned ordinary prose as
  though it were a directory listing, reporting two test files as missing that
  have been present all along.

  The real tree is a line that is *only* `LOCKON-EWAC/`, inside a fenced block.
*/
const TREE_START = /^LOCKON-EWAC\/\s*$/m;
const treeDoc = Object.values(docs).find(t => TREE_START.test(t));
if (treeDoc) {
  const block = treeDoc.slice(treeDoc.search(TREE_START)).split('```')[0];
  // `engine/tests/` was absent, which is why the false alarm above could land:
  // the two files it named do exist, just not under any root this list knew.
  // `src/lib/map/` and `src/lib/report/exports/` joined the list when the maps
  // and the text exports were split out; a tree entry under a directory this
  // does not know is reported as a missing file, which is the right failure but
  // a confusing message.
  const roots = ['', 'src/', 'src/lib/', 'src/lib/map/', 'src/lib/report/',
    'src/lib/report/sections/', 'src/lib/report/exports/', 'src/stores/', 'src/pages/', 'engine/',
    'engine/scanner/', 'engine/offensive/', 'engine/gps/', 'engine/ipc/', 'engine/tests/',
    'src-tauri/', 'scripts/', 'docs/', 'tests/', 'tests/entries/', 'tests/components/',
    'tests/components/stubs/'];
  const files = new Set([...block.matchAll(/([A-Za-z_][\w.-]*\.(?:ts|tsx|py|mjs|json|md))/g)].map(m => m[1]));
  const absent = [...files].filter(f => !roots.some(r => existsSync(r + f)));
  ok('every file named in the project tree exists', absent.length === 0, absent.join(', '));
}

/*
  7. Every link between documents resolves, and every #anchor exists.

  The README was split into eight files, which turned a dozen in-page jumps into
  cross-file ones overnight. A link to a missing file is at least visible; a
  link to a heading that was reworded lands the reader at the top of the right
  document and looks like it worked, which is worse.
*/
const slugs = text =>
  new Set([...text.matchAll(/^#{1,6}\s+(.+?)\s*$/gm)].map(m =>
    m[1].toLowerCase()
      /*
        Strip a markdown link's URL, not every parenthesis.

        This used to be `\(.*?\)`, which eats ordinary parenthesised words out
        of a heading: "### 3. The GPS Receiver (For Wardriving)" slugged to
        `3-the-gps-receiver`, while GitHub keeps the words and serves
        `#3-the-gps-receiver-for-wardriving`. So a correct link was reported as
        broken, and 61 headings across these documents carry parentheses.
        Only a `](...)` is a link URL.
      */
      .replace(/\]\([^)]*\)/g, '')
      .replace(/`|\*|\[|\]/g, '')
      .replace(/[^\w\s-]/g, '')
      .trim()
      .replace(/\s+/g, '-')));

const anchorsOf = Object.fromEntries(Object.entries(docs).map(([d, t]) => [d, slugs(t)]));
const brokenLinks = [];
let linkCount = 0;
for (const [doc, text] of Object.entries(docs)) {
  const base = doc.includes('/') ? doc.slice(0, doc.lastIndexOf('/')) : '';
  for (const m of text.matchAll(/\[[^\]]*\]\(([^)\s]+)\)/g)) {
    const target = m[1];
    if (/^(https?:|mailto:)/.test(target)) continue;
    linkCount++;
    const [file, frag] = target.split('#');
    let resolved = doc;
    if (file) {
      resolved = (base ? `${base}/${file}` : file)
        .replace(/[^/]+\/\.\.\//g, '')   // collapse "docs/../README.md"
        .replace(/^\.\//, '');
      if (!existsSync(resolved)) {
        brokenLinks.push(`${doc} -> ${target} (no such file)`);
        continue;
      }
    }
    if (frag && anchorsOf[resolved] && !anchorsOf[resolved].has(frag.toLowerCase())) {
      brokenLinks.push(`${doc} -> ${target} (no such heading)`);
    }
  }
}
ok(`all ${linkCount} cross-document links resolve`, brokenLinks.length === 0,
   brokenLinks.join('; '));

/*
  Every <img> points at a file that exists.

  The screenshots are written as raw HTML rather than Markdown, so the check
  above never saw them: its regex wants `[alt](target)` and an `<img src="...">`
  has no brackets. That blind spot shipped a broken image. `docs/INSTALL.md`
  carried `src="img/for-install/..."`, copied from the README — correct there,
  because the README sits at the repository root, and wrong one directory down,
  where it resolves to the `docs/img/` that does not exist. The whole check
  suite passed, and the only symptom was a broken-image icon on GitHub.

  Filenames here contain spaces and are written `%20`, so the path is decoded
  before it is resolved. An `src` that forgot the encoding would otherwise be
  reported as missing with its name cut at the first space, which sends the
  reader looking for the wrong fault.
*/
const brokenImages = [];
let imageCount = 0;
for (const [doc, text] of Object.entries(docs)) {
  const base = doc.includes('/') ? doc.slice(0, doc.lastIndexOf('/')) : '';
  for (const m of text.matchAll(/<img\b[^>]*?\ssrc\s*=\s*["']([^"']+)["']/gi)) {
    const target = m[1];
    if (/^(https?:|data:)/.test(target)) continue;
    imageCount++;
    let decoded = target;
    try { decoded = decodeURIComponent(target); } catch { /* leave it as written */ }
    const resolved = (base ? `${base}/${decoded}` : decoded)
      .replace(/[^/]+\/\.\.\//g, '')   // collapse "docs/../img/x.jpg"
      .replace(/^\.\//, '');
    if (!existsSync(resolved)) {
      brokenImages.push(`${doc} -> ${target} (no such file: ${resolved})`);
    }
  }
}
ok(`all ${imageCount} <img> sources exist`, brokenImages.length === 0,
   brokenImages.join('; '));

/*
  Every "<path> (N lines)" claim counts the file it names.

  This class of drift was corrected by hand ten times in one sitting:
  `engineRouter.ts` stated 1,051 against 1,113, `report/archive.ts` 791 against 840,
  `buildAndSavePDF` 2,236 against 2,689. None of it is dangerous on its own — but a
  document whose checkable numbers are stale teaches a reader to discount the ones that
  matter, and this project's argument is that its numbers can be trusted.

  Only the "<backticked path> (N lines" form is checked, because that is the one that
  names its own subject. Prose counts like "position quality (293)" carry no path and
  are left to a human.

  Tolerance is zero: these are `wc -l`, not estimates.
*/
const LINE_CLAIM_RE = /`([\w./-]+\.(?:ts|tsx|mjs|js|py|rs|sql))`\s*\((\d[\d,]*)\s+lines/g;

/*
  And the "N exports" half of the same claim.

  The line count beside it was checked from the day this script was written; the
  export count next to it was not, and it had drifted by one without anyone
  noticing -- `report/archive.ts` was documented as 52 exports while holding 53.
  A number sitting inside a parenthesis that is half-verified is worse than one
  that is not verified at all, because the verified half lends it credit.

  `^export ` only, matching the line count's bluntness: a re-exported symbol or
  one exported from inside a block is not what this claim is counting, and a
  checker that tried to be clever about that would need a parser to stay honest.
*/
const EXPORT_CLAIM_RE = /`([\w./-]+\.(?:ts|tsx|mjs|js))`\s*\(\d[\d,]*\s+lines,\s*(\d+)\s+exports/g;
const exportClaims = [];
const badExportClaims = [];
for (const [doc, text] of Object.entries(docs)) {
  for (const m of text.matchAll(EXPORT_CLAIM_RE)) {
    const [, file, countText] = m;
    if (!existsSync(file)) continue;
    const actual = (readFileSync(file, 'utf8').match(/^export /gm) || []).length;
    const claimed = Number(countText);
    exportClaims.push(file);
    if (claimed !== actual) {
      badExportClaims.push(`${doc}: ${file} says ${claimed} exports, has ${actual}`);
    }
  }
}
ok(`all ${exportClaims.length} "(N exports)" claims match the file`,
   badExportClaims.length === 0, badExportClaims);
const lineClaims = [];
const badLineClaims = [];
for (const [doc, text] of Object.entries(docs)) {
  for (const m of text.matchAll(LINE_CLAIM_RE)) {
    const [, file, countText] = m;
    if (!existsSync(file)) continue;   // the path check below owns that failure
    const body = readFileSync(file, 'utf8');
    const actual = body.split('\n').length - (body.endsWith('\n') ? 1 : 0);
    const claimed = Number(countText.replace(/,/g, ''));
    lineClaims.push(file);
    if (claimed !== actual) {
      badLineClaims.push(`${doc}: ${file} says ${claimed} lines, is ${actual}`);
    }
  }
}
ok(`all ${lineClaims.length} "(N lines)" claims match the file`,
   badLineClaims.length === 0, badLineClaims.join('; '));

/*
  8. Every backticked path that looks like a file is one.

  Two exceptions, both deliberate and both checked here rather than by weakening
  the pattern, because a weaker pattern would also stop catching real rot:
  a deleted file may be named by the sentence recording its deletion, and
  `/config.json` is a URL the web-secrets scanner probes, not a file in the repo.
*/
const NOT_REPO_FILES = new Set([
  'src/pages/MissionsPage.tsx',  // deleted; the engineering log records that it was
  '/config.json',                // a URL the web-secrets probe requests
]);
const PATHISH = /`([A-Za-z0-9_./-]+\.(?:ts|tsx|mjs|js|py|json|sql|iss|spec|md|toml|rs|css|html|txt))`/g;
let badPaths = [];
let pathCount = 0;
for (const [doc, text] of Object.entries(docs)) {
  for (const m of text.matchAll(PATHISH)) {
    const cand = m[1];
    if (!cand.includes('/')) continue;          // a bare name is prose, not a path
    if (NOT_REPO_FILES.has(cand)) continue;
    pathCount++;
    if (!existsSync(cand)) badPaths.push({ doc, cand });
  }
}

/*
  A path the repository deliberately does not carry is not documentation drift.

  This check used to be "does the file exist", which gives a different answer on
  a developer's machine than in a fresh clone --- and that is exactly how it
  failed: the export harness's baseline index is written on its first run and is
  gitignored, so it existed locally, did not exist in CI, and the check passed
  here and went red on the first push.

  Documenting a generated artifact is correct and should stay possible. So an
  absent path is only drift when git would also have tracked it; if a .gitignore
  rule covers it, the documentation is describing something that appears when
  you run something, which is a different and legitimate thing to write down.

  One `git check-ignore` call for the whole batch, and a missing or failed git
  is treated as "not ignored" so the check stays strict rather than silently
  passing everything.
*/
if (badPaths.length) {
  const probe = spawnSync('git', ['check-ignore', '--stdin'], {
    input: badPaths.map(b => b.cand).join('\n'),
    encoding: 'utf8',
  });
  const ignored = new Set(
    (probe.stdout || '').split(/\r?\n/).map(l => l.trim()).filter(Boolean)
  );
  badPaths = badPaths.filter(b => !ignored.has(b.cand));
}

ok(`all ${pathCount} backticked paths exist`, badPaths.length === 0,
  badPaths.map(b => `${b.doc}: ${b.cand}`).join(', '));

/*
  9. Every backticked identifier appears in some source file.

  This is the check that found four engine events the docs had invented:
  `wordlist_list` for `wordlists_list`, `smb_enum_result` for
  `smb_enum_completed`, `vlan_result` for `vlan_scan_completed`, and
  `passive_probe`, which named no event at all — the 802.11 work it described
  lives in a different module and emits `probe_detected`.

  Someone reading a playbook to wire something up copies these names verbatim,
  and a wrong one fails as silence: the listener simply never fires.

  The allowlist is browser APIs and package names. They are legitimately absent
  from `src/`, and several are mentioned precisely because the project does NOT
  use them.
*/
const NOT_OUR_CODE = new Set([
  'LICENSE',                                            // a file, named in prose
  'QuotaExceededError', 'contentEditable',              // browser APIs
  'dangerouslySetInnerHTML', 'sessionStorage',          // named as things src/ avoids
  'html2canvas', 'purify',                              // reach us through jspdf
  'recharts',                                           // stated as NOT a dependency
  'ATTACH',                                             // a SQLite keyword, cited as a risk
  'passive_probe',                                      // never existed; the docs say so
  'TRACKED_PRODUCTS',                                   // deleted; the log entry records that it was
  'SignTool',                                           // an Inno Setup directive we do not use (unsigned)
]);
const codeText = [
  srcText,
  (function read(dir) {
    let out = '';
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.name === '.venv' || e.name === '__pycache__' || e.name === 'node_modules') continue;
      const full = `${dir}/${e.name}`;
      if (e.isDirectory()) out += read(full);
      else if (/\.(py|rs|sql|mjs|iss|json)$/.test(e.name)) out += readFileSync(full, 'utf8');
    }
    return out;
  })('engine') ,
  readFileSync('package.json', 'utf8'),
  existsSync('installer/lockon-ewac.iss') ? readFileSync('installer/lockon-ewac.iss', 'utf8') : '',
  readdirSync('src-tauri/migrations').map(f => readFileSync(`src-tauri/migrations/${f}`, 'utf8')).join(''),
  readdirSync('tests').filter(f => f.endsWith('.mjs')).map(f => readFileSync(`tests/${f}`, 'utf8')).join(''),
  // The component tests and their harness, which the docs reference by name --
  // `objectUrls` lives in `tests/components/setup.ts` and read as a missing
  // identifier only because this corpus stopped at `tests/*.mjs`.
  existsSync('tests/components')
    ? readdirSync('tests/components')
        .filter(f => /\.(ts|tsx)$/.test(f))
        .map(f => readFileSync(`tests/components/${f}`, 'utf8')).join('')
    : '',
  existsSync('tests/entries')
    ? readdirSync('tests/entries').map(f => readFileSync(`tests/entries/${f}`, 'utf8')).join('')
    : '',
  readdirSync('scripts')
    .filter(f => f.endsWith('.mjs') && f !== 'check-docs.mjs')
    .map(f => readFileSync(`scripts/${f}`, 'utf8')).join(''),
].join('');

const idents = new Set();
for (const text of Object.values(docs)) {
  for (const m of text.matchAll(/`([a-z_][a-zA-Z0-9_]{5,}\(?\)?|[A-Z][A-Za-z0-9_]{5,})`/g)) {
    idents.add(m[1].replace(/\(\)$/, ''));
  }
}
const invented = [...idents].filter(i => !NOT_OUR_CODE.has(i) && !codeText.includes(i));
ok(`all ${idents.size} backticked identifiers exist in the source`, invented.length === 0,
   invented.join(', '));

console.log();
if (problems.length) {
  console.error(`FAIL — ${problems.length} claim(s) the repository does not support:`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log('PASS — every checkable claim in the docs matches the repository.');
