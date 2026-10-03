#!/usr/bin/env node
/**
 * The Inno installer ships the same application the Tauri bundlers do.
 *
 *     npm run check:installer
 *
 * Why this exists.
 *
 * There are three installers for one product — MSI and NSIS from `tauri build`,
 * and `installer/lockon-ewac.iss` from Inno Setup, which exists for the one thing
 * the Tauri bundlers do not do: a page telling the operator what this machine is
 * missing before they find out mid-survey. `INSTALL.md` says so deliberately.
 *
 * The cost of that choice is a second file list. Tauri computes its payload from
 * `bundle.externalBin` and `bundle.resources`; the `.iss` repeats it by hand. Add
 * a resource and the MSI carries it, the Inno build succeeds, and the installed
 * application is missing a file — with no error anywhere, because Inno only fails
 * on a `Source:` it cannot find, never on one nobody wrote.
 *
 * The version is the same shape of problem with a smaller blast radius: the `.iss`
 * hardcodes it, so a release where `package.json` moved and the installer did not
 * produces a Programs-and-Features entry, a setup file's properties and an
 * `AppVersion` that disagree with the application they install.
 *
 * And the uninstall prompt names directories. It asks the operator to confirm
 * deleting them, so the names have to be the ones the code actually writes to, or
 * the prompt is describing a set that is not the set being removed.
 */
import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';

const ISS = 'installer/lockon-ewac.iss';
const problems = [];

if (!existsSync(ISS)) {
  console.error(`[installer] FAIL — ${ISS} is missing`);
  process.exit(1);
}

const iss = readFileSync(ISS, 'utf8');
const conf = JSON.parse(readFileSync('src-tauri/tauri.conf.json', 'utf8'));
const pkg = JSON.parse(readFileSync('package.json', 'utf8'));

const defines = Object.fromEntries(
  [...iss.matchAll(/#define\s+(\w+)\s+"([^"]*)"/g)].map(m => [m[1], m[2]])
);
/** A `Source:` with its `{#Define}`s substituted, which is what Inno actually installs. */
const expand = (v) => v.replace(/\{#(\w+)\}/g, (_, k) => defines[k] ?? `{#${k}}`);

// ── 1. One version, stated in four places ──────────────────────────────────
const cargo = (readFileSync('src-tauri/Cargo.toml', 'utf8').match(/^version\s*=\s*"([^"]+)"/m) || [])[1];
const versions = {
  [ISS]: defines.AppVersion,
  'package.json': pkg.version,
  'tauri.conf.json': conf.version,
  'Cargo.toml': cargo,
};
const distinct = [...new Set(Object.values(versions))];
if (distinct.length !== 1 || !distinct[0]) {
  problems.push(
    'the version disagrees across files: '
    + Object.entries(versions).map(([f, v]) => `${f}=${v ?? '(unreadable)'}`).join(', ')
  );
}

/*
  ── 1b. One Inno Setup version, stated in four places ──────────────────────

  The documented toolchain version drifted once already: the `.iss` header and
  INSTALL.md both said Inno Setup 7 while what is installed, and what the script
  was verified against, is 6. Those two were corrected and **the README was
  missed**, so it went on telling every reader the wrong one for nine phases --
  found by reading, which is the method this check exists to replace.

  It is a documentation claim rather than a build input, which is exactly why it
  rots quietly: nothing fails, the installer still compiles, and the only cost is
  somebody installing the wrong toolchain and finding out at `ISCC.exe`.
*/
const INNO_SOURCES = ['README.md', 'docs/INSTALL.md', ISS];

/*
  A line that *narrates* the old version is not a claim about the current one.

  The first version of this flagged the `.iss` for disagreeing with itself,
  correctly reading both numbers in "this file was documented as needing Inno
  Setup 7, which is not what was installed". That sentence is the record of the
  mistake and is worth keeping; a check that forces it out would be deleting the
  explanation to make itself pass.

  So lines marked as history are skipped, and the marker is explicit rather than
  clever -- a heuristic that guessed at tense would fail in whichever direction
  nobody tested.
*/
const HISTORICAL = /documented as|was documented|not what was installed|used to say/i;

/*
  The product name may be a markdown link, which is how the fourth claim hid.

  This rule shipped reading `Inno Setup (\d+)` and reported agreement across
  three files while INSTALL.md's own prerequisites paragraph -- forty lines above
  the build command it checked -- still said 6, because there it is written
  `[Inno Setup](https://jrsoftware.org/isinfo.php) 6` and the digits are no longer
  adjacent to the name. The check was looking for one spelling of a claim that
  prose is free to spell several ways, which is the same shape of mistake as
  counting a mention as a declaration: it passed, and the thing it exists to
  prevent was sitting in one of the three files it had just read.
*/
const INNO_NAME = /Inno Setup(?:\]\([^)]*\))? (\d+)/g;

const innoVersions = {};
for (const file of INNO_SOURCES) {
  if (!existsSync(file)) continue;
  const found = readFileSync(file, 'utf8')
    .split(String.fromCharCode(10))
    .filter(line => !HISTORICAL.test(line))
    .flatMap(line => [...line.matchAll(INNO_NAME)].map(m => m[1]));
  if (found.length) innoVersions[file] = [...new Set(found)].join('/');
}
const innoDistinct = [...new Set(Object.values(innoVersions))];
if (innoDistinct.length > 1) {
  problems.push(
    'the Inno Setup version disagrees across files: '
    + Object.entries(innoVersions).map(([f, v]) => `${f}=${v}`).join(', ')
  );
}

/*
  ── 1c. No control characters in the script ────────────────────────────────

  The readiness page's basemap probe shipped reading

      {userappdata}\com.lockon.ewac<0x08>asemap.pmtiles

  -- a literal backspace byte where the path separator belongs, from a `\b`
  escape that an editing pass interpreted rather than wrote. Every tool in the
  chain was content: Inno compiled it, because a control character inside a string
  literal is a valid string; `tsc` never sees this file; and reading it finds
  nothing, because a terminal *performs* the backspace and renders exactly the path
  the author meant. The defect was invisible by construction and could only ever
  return False, so the wizard reported "No offline basemap" on a machine holding
  one.

  Three bytes, in the probe and in two comments. There is no legitimate use for any
  of these in an Inno script, so the rule is a flat refusal rather than a judgement:
  tab, CR and LF are the only control characters a text file here needs.
*/
const CONTROL_BYTES = [0x00, 0x07, 0x08, 0x0b, 0x0c, 0x1b];
const CONTROL_NAMES = { 0x00: 'NUL', 0x07: 'BEL (\a)', 0x08: 'BS (\b)', 0x0b: 'VT (\v)', 0x0c: 'FF (\f)', 0x1b: 'ESC' };
for (let i = 0; i < iss.length; i++) {
  const code = iss.charCodeAt(i);
  if (!CONTROL_BYTES.includes(code)) continue;
  const line = iss.slice(0, i).split(String.fromCharCode(10)).length;
  const around = iss.slice(Math.max(0, i - 30), i).replace(/\s+/g, ' ');
  problems.push(`line ${line}: a ${CONTROL_NAMES[code]} control character in the script, after "...${around}"`);
}

/*
  ── 1d. The basemap the wizard probes is the basemap the app reads ──────────

  Both sides of this are derived, not transcribed: the directory is Tauri's
  `app_data_dir()`, which on Windows is %APPDATA% plus the identifier from
  tauri.conf.json, and the file name is whatever `basemap.rs` joins onto it. So the
  one path in the installer is checked against the two things that decide it, and a
  renamed archive or a changed identifier fails here rather than in a wizard that
  quietly reports every machine as having no basemap.
*/
const BASEMAP_RS = 'src-tauri/src/basemap.rs';
if (existsSync(BASEMAP_RS)) {
  const rs = readFileSync(BASEMAP_RS, 'utf8');
  const joined = (rs.match(/\.join\("([^"]+\.pmtiles)"\)/) || [])[1];

  /*
    The Pascal expression is normalised rather than matched, so reformatting the
    concatenation is not a failure and only the path it builds is compared.
  */
  const body = (iss.match(/function BasemapPath\(\)[\s\S]{0,300}?Result\s*:=\s*([^;]+);/) || [])[1];
  const built = body
    ? body.replace(/ExpandConstant\s*\(/g, '').replace(/[')(+]/g, '').replace(/\s+/g, '')
    : null;
  const wanted = `{userappdata}@${conf.identifier}@${joined}`.replace(/@/g, String.fromCharCode(92));

  if (!joined) {
    problems.push(`${BASEMAP_RS} no longer joins a .pmtiles file name; this check cannot verify the installer's path`);
  } else if (!built) {
    problems.push(`${ISS} has no BasemapPath() returning a path; the readiness page's basemap probe cannot be checked`);
  } else if (built !== wanted) {
    problems.push(
      'the installer and basemap.rs disagree about where the offline basemap lives: '
      + `basemap.rs says ${wanted}, the script builds ${built}`
    );
  }
}

/*
  ── 1e. The digest in the documentation is the digest of the file ──────────

  `docs/INSTALL.md` tells a reader to check the installer's SHA-256 before running
  it, and prints the expected value. That instruction is worth less than nothing if
  the printed value is stale: a reader who follows it, gets a mismatch on a
  perfectly good download and is told "do not run it" learns to ignore the step,
  which is the one habit this project cannot afford to teach --- the binary is a
  Wi-Fi scanner with a password-recovery front end and it is not code-signed.

  The digest changes whenever the application, the sidecar or the wordlists change,
  which is every release. So it is compared rather than trusted.

  `dist-installer/` is gitignored, so on a fresh clone and in CI there is nothing to
  compare against. That is reported as what it is --- not checked --- rather than
  counted as a pass, and the rule does its work on the machine that cuts the
  release, which is the only machine where it can.
*/
const SETUP = 'dist-installer/lockon-ewac-setup.exe';
const installMd = existsSync('docs/INSTALL.md') ? readFileSync('docs/INSTALL.md', 'utf8') : '';
const documentedSha = (installMd.match(/\|\s*SHA-256\s*\|\s*`([0-9a-f]{64})`/) || [])[1];
const documentedSize = (() => {
  const m = installMd.match(/\|\s*Size\s*\|\s*([\d,]+)\s*bytes/);
  return m ? Number(m[1].replace(/,/g, '')) : null;
})();

let shaNote = 'no digest documented';
if (documentedSha || documentedSize !== null) {
  if (!existsSync(SETUP)) {
    shaNote = `digest NOT CHECKED (${SETUP} is not built here)`;
  } else {
    const bytes = readFileSync(SETUP);
    const actualSha = createHash('sha256').update(bytes).digest('hex');
    if (documentedSize !== null && documentedSize !== bytes.length) {
      problems.push(
        `docs/INSTALL.md says the installer is ${documentedSize.toLocaleString()} bytes; `
        + `${SETUP} is ${bytes.length.toLocaleString()}`);
    }
    if (documentedSha && documentedSha !== actualSha) {
      problems.push(
        `docs/INSTALL.md publishes a SHA-256 that is not this installer's. `
        + `Documented ${documentedSha.slice(0, 16)}..., built ${actualSha.slice(0, 16)}... `
        + '— rebuild the documentation or re-upload the release asset, but do not ship both.');
    }
    if (documentedSha === actualSha) shaNote = `digest matches ${SETUP}`;
  }
}

// ── 2. Everything Tauri bundles, the .iss also installs ────────────────────
/*
  Compared on the last path segment, because the two sides spell the same file
  differently on purpose: Tauri's `binaries/ewac-engine/_internal` is the `.iss`'s
  `{#EngineDir}\_internal\*`, and the engine executable is renamed on the way in
  because Tauri strips the target triple when it bundles. Comparing whole paths
  would report differences that are all correct.
*/
const sources = [...iss.matchAll(/^Source:\s*"([^"]+)"/gm)].map(m => expand(m[1]));
const leafOf = (p) => p.replace(/[\\/]\*$/, '').split(/[\\/]/).pop().toLowerCase();
const issLeaves = new Set(sources.map(leafOf));

const required = [
  ...(conf.bundle?.externalBin ?? []).map(path => ({ what: 'externalBin', path })),
  ...Object.keys(conf.bundle?.resources ?? {}).map(path => ({ what: 'resource', path })),
];

for (const { what, path } of required) {
  const leaf = leafOf(path);
  // The sidecar is `ewac-engine` in tauri.conf and
  // `ewac-engine-x86_64-pc-windows-msvc.exe` in the .iss, so a prefix match on a
  // separator covers the rename without matching something unrelated.
  const covered = [...issLeaves].some(l => l === leaf || l.startsWith(`${leaf}-`) || l.startsWith(`${leaf}.`));
  if (!covered) {
    problems.push(`${what} "${path}" is bundled by Tauri and not installed by ${ISS}`);
  }
}

/*
  ── 3. Every source the .iss names exists ──────────────────────────────────

  Two populations, and conflating them broke this.

  Most `[Files]` entries are build output --- the Tauri binary, the PyInstaller
  sidecar, the synced wordlists --- and none of it exists in a fresh clone. So the
  rule skipped itself when the tree had not been built, which is right: a check
  that only works after a twenty-minute build is a check nobody runs, and CI does
  not build the app.

  It detected "not built" by asking whether *any* `[Files]` path resolved. That
  held exactly as long as every entry was build output. Adding `LICENSE` and
  `THIRD-PARTY-NOTICES.md` --- committed files, present in every clone --- made the
  answer two instead of zero, the skip stopped firing, and CI failed demanding
  binaries it had never been asked to produce. The signal was a proxy for the
  question rather than the question.

  Asked directly now: a repository file must always be there, and build output is
  resolved only when there is a build. Each is reported, so a run says which of the
  two it actually did.
*/
const resolved = sources.map(s => s.replace(/\\/g, '/').replace(/^\.\.\//, ''));
const onDisk = (p) => existsSync(p.replace(/\/\*$/, ''));

/** Written by a build step, so absent from a clone. Everything else is committed. */
const GENERATED_PREFIXES = ['src-tauri/target/', 'src-tauri/binaries/'];
const isGenerated = (p) => GENERATED_PREFIXES.some(d => p.startsWith(d));

const fromRepo = resolved.filter(p => !isGenerated(p));
const fromBuild = resolved.filter(isGenerated);
const built = existsSync('src-tauri/target/release') && fromBuild.some(onDisk);

for (const p of fromRepo) {
  if (!onDisk(p)) {
    problems.push(`${p} is listed in [Files] and is not in this repository`);
  }
}

let sourcesNote = `${fromRepo.length} committed file(s) installed`;
if (!built) {
  sourcesNote += `; ${fromBuild.length} build path(s) NOT RESOLVED (nothing built here)`;
} else {
  sourcesNote += `; ${fromBuild.length} build path(s) resolved`;
  for (const p of fromBuild) {
    if (!onDisk(p)) problems.push(`${p} is listed in [Files] and is not in this tree`);
  }
}

// ── 4. The uninstall prompt names every directory it deletes ───────────────
const engineDirs = new Set();
for (const file of ['engine/evidence.py', 'engine/cve_feed.py', 'engine/logging_setup.py', 'engine/wordlists_path.py']) {
  if (!existsSync(file)) continue;
  const body = readFileSync(file, 'utf8');
  for (const m of body.matchAll(/"LOCKON-EWAC",\s*"(\w+)"/g)) engineDirs.add(m[1]);
  /*
    And the constant form, which the first version of this missed entirely.

    `wordlists_path.py` writes `os.path.join(base, "LOCKON-EWAC", _WORDLIST_SUBDIR)`,
    so a literal-only search found three of the four directories and reported the
    prompt complete. A check that is satisfied by how a path happens to be spelled
    is the same class of mistake as the prompt it is checking.
  */
  for (const m of body.matchAll(/"LOCKON-EWAC",\s*([A-Za-z_]\w*)\s*\)/g)) {
    const value = body.match(new RegExp(`^${m[1]}\\s*=\\s*"([^"]+)"`, 'm'));
    if (value) engineDirs.add(value[1]);
  }
}

/*
  Scoped to the sentence that describes that directory, not to the whole file.

  Searching the `.iss` for the word was the first attempt, and it passed while the
  prompt was wrong: "evidence" appears in the *other* paragraph, describing the
  evidence register inside the database — so the check agreed the operator had
  been told about a directory of captured artifacts that nobody had mentioned. A
  word in the wrong sentence is not a disclosure.

  `DelTree` takes the parent, so everything under it goes whether the message
  listed it or not. That is exactly why the message has to list it.
*/
const promptBlock = (() => {
  const at = iss.indexOf("+ '    ' + DataDir + #13#10");
  if (at === -1) return null;
  const end = iss.indexOf('#13#10 #13#10', at + 30);
  return end === -1 ? null : iss.slice(at, end);
})();

if (!promptBlock) {
  problems.push('the uninstall prompt no longer describes the local data directory in a form this check can read');
} else {
  for (const dir of engineDirs) {
    if (!new RegExp(`\\b${dir}\\b`, 'i').test(promptBlock)) {
      problems.push(
        `the uninstaller offers to delete %LOCALAPPDATA%\\LOCKON-EWAC, and the sentence describing `
        + `it never mentions "${dir}" — which the engine writes to, so the operator is asked to `
        + 'confirm removing something they were not told was there'
      );
    }
  }
}

// ── 5. No brace comment in [Code] contains a brace ──────────────────────
/*
  The trap that stopped this script compiling at all.

  A Pascal brace comment ends at the FIRST closing brace, so an Inno constant
  written inside one -- `{%USERPROFILE}`, `{app}`, `{localappdata}` -- terminates
  the comment early and everything after it is parsed as code. The file warns
  about this in one of its own comments and then did it anyway, in the hashcat
  probe, which is why `installer/lockon-ewac.iss` had never produced a setup
  executable: `Error on line 242: Syntax error. Compile aborted.`

  Nothing caught it because nothing compiled it. Inno Setup is not on a GitHub
  runner, so CI cannot; this is the static half, and it is the specific half that
  bit. Scanned over `[Code]` only, because a brace in `[Setup]` is an AppId or a
  path constant and entirely correct there.
*/
/*
  The section *header*, not the first mention of it.

  This was `indexOf('[Code]')`, which found the words inside a comment at the top
  of the script the moment that comment came to mention the section -- and then
  scanned `[Setup]` as if it were Pascal, flagging `AppId={{...}` where a doubled
  brace is Inno's own escape for a literal one. A check that cannot tell a
  declaration from a mention is the same mistake as the Inno version rule above,
  found the same way: by writing prose and watching the check fail on it.
*/
const codeHeader = iss.match(/^\[Code\]\s*$/m);
const codeAt = codeHeader ? codeHeader.index : -1;
if (codeAt === -1) {
  problems.push('the script has no [Code] section, which this check expects');
} else {
  const code = iss.slice(codeAt);
  let i = 0;
  while (i < code.length) {
    const open = code.indexOf('{', i);
    if (open === -1) break;
    const close = code.indexOf('}', open + 1);
    if (close === -1) break;
    const inner = code.indexOf('{', open + 1);
    if (inner !== -1 && inner < close) {
      const line = iss.slice(0, codeAt + inner).split(String.fromCharCode(10)).length;
      problems.push(
        `line ${line}: a brace comment in [Code] contains "${code.slice(inner, Math.min(inner + 24, close))}" — `
        + 'a Pascal comment ends at the first closing brace, so this terminates it early '
        + 'and the rest is parsed as code'
      );
      break;
    }
    i = close + 1;
  }
}

if (problems.length > 0) {
  console.error('[installer] FAIL');
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}

console.log(
  `[installer] version ${distinct[0]} agrees across 4 files; `
  // printed on a pass, not only on a failure: the version this names is what a
  // reader will go and install, and the last two times it was wrong the cost was
  // that nobody ever saw it stated.
  + `Inno Setup ${innoDistinct[0] ?? '(unstated)'} across `
  + `${Object.keys(innoVersions).length} file(s); `
  + `${required.length} bundled path(s) installed; `
  + `${engineDirs.size} data director(ies) named in the uninstall prompt; `
  + sourcesNote + '; '
  + shaNote
);
console.log('[installer] PASS');
