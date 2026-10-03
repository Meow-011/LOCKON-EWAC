/**
 * LOCKON EWAC — the frozen engine must start, and the bundle must be what was built.
 *
 *     node scripts/check-sidecar-resources.mjs
 *     npm run check:sidecar
 *
 * Why this exists.
 *
 * Nothing else in this project runs the **frozen** engine. `python
 * engine/tests/run_all.py` imports source inside a virtualenv, where a missing
 * dependency is a clean `ImportError` the code already handles and a
 * half-collected package cannot exist at all. The only symptom of a bad freeze
 * is an engine that refuses to start after an install, and the app reports that
 * as "engine offline" without saying why.
 *
 * The defect that prompted this. `tauri build` copies the sidecar into
 * `src-tauri/target/release/_internal` **without clearing it**, so a file from a
 * previous sidecar build stays behind and ships. One rebuild left 244 orphans,
 * including `_internal/yaml/` holding exactly one file — `_yaml.cp313-win_amd64.pyd`,
 * PyYAML's optional C accelerator — and no `__init__.py`, left from before
 * PyYAML was removed from the virtualenv.
 *
 * A directory without an `__init__.py` is a **namespace package**. So
 * `import yaml` *succeeded* and returned an empty module; paramiko guards that
 * import with `except ImportError`, the guard never fired, and the engine died
 * on `AttributeError: module 'yaml' has no attribute 'error'`. The orphan did
 * not break something that worked — it converted an absence the code handled
 * into a crash it could not.
 *
 * And deleting the stale directory is **not** a sufficient fix, which is the
 * second thing this learned: Tauri does not re-copy resources when its build
 * script is fingerprint-clean, so a plain rebuild after deleting them leaves
 * `target/release` with no engine at all.
 *
 * **What that directory is and is not.** It is the staging copy used when
 * `target/release/lockon-ewac.exe` is run *directly* — which is exactly what
 * `test:csp:release` and `test:export:release` do, and how the crash surfaced.
 * It is also what `installer/lockon-ewac.iss` used to source from. Tauri's own
 * MSI and NSIS bundles do **not** use it: `tauri.conf.json` names
 * `binaries/ewac-engine/_internal` as a resource, so those bundles read the
 * sidecar from its build output and were never affected. Measured rather than
 * assumed — a build with this directory absent still produced a 124 MB MSI,
 * within 8 KB of the build that had it.
 *
 * The installer now sources from `src-tauri/binaries/ewac-engine/` too, so it no
 * longer depends on that copy existing or being current. The tree comparison
 * below guards what remains: the release binary when run directly, which is
 * every release-mode harness in this project.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, relative, resolve, sep } from 'node:path';
import { spawn } from 'node:child_process';

/** Where PyInstaller writes the sidecar. This is what the installer ships. */
const SIDECAR_DIR = 'src-tauri/binaries/ewac-engine';
const SIDECAR = `${SIDECAR_DIR}/_internal`;
const SIDECAR_EXE = `${SIDECAR_DIR}/ewac-engine-x86_64-pc-windows-msvc.exe`;
/** Tauri's copy, used only by its own MSI/NSIS bundles. May legitimately be absent. */
const BUNDLED = 'src-tauri/target/release/_internal';

function walk(root) {
  const out = new Set();
  if (!existsSync(root)) return out;
  const stack = [root];
  while (stack.length) {
    const dir = stack.pop();
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) stack.push(full);
      else out.add(relative(root, full).split(sep).join('/'));
    }
  }
  return out;
}

/** Group by top-level directory, which is how an orphaned package reads. */
function summarise(list) {
  const byTop = new Map();
  for (const f of list) {
    const top = f.includes('/') ? f.slice(0, f.indexOf('/')) : '(root)';
    byTop.set(top, (byTop.get(top) ?? 0) + 1);
  }
  return [...byTop.entries()].sort((a, b) => b[1] - a[1]);
}

if (!existsSync(SIDECAR_EXE)) {
  console.error(`[sidecar] ${SIDECAR_EXE} does not exist. Build the sidecar first:`);
  console.error('[sidecar]   cd engine && .venv\\Scripts\\pyinstaller.exe ewac-engine-x86_64-pc-windows-msvc.spec --distpath ..\\src-tauri\\binaries --noconfirm');
  process.exit(2);
}

let failed = false;

// ── 1. The engine the installer ships must actually start ──────────────────
/*
  The `ready` event carries the build stamp, so a successful import is proved
  rather than inferred from "it did not exit immediately". It is launched from
  its own directory, because that is where a stale sibling would shadow a
  module and it is how the application launches it.
*/
const startCode = await new Promise((done) => {
  const child = spawn(resolve(SIDECAR_EXE), [], { cwd: resolve(SIDECAR_DIR) });
  let out = '';
  let err = '';
  const finish = (status, why) => {
    clearTimeout(timer);
    try { child.kill(); } catch { /* already gone */ }
    if (why) console.log(why);
    done(status);
  };
  const timer = setTimeout(
    () => finish(1, '[sidecar] FAIL — the engine produced no `ready` event within 40s.'),
    40000,
  );

  child.stdout.on('data', (b) => {
    out += b.toString();
    const line = out.split('\n').find(l => l.includes('"event"') && l.includes('"ready"'));
    if (!line) return;
    let stamp = null;
    try { stamp = JSON.parse(line).data?.build ?? null; } catch { /* printed raw below */ }
    console.log('[sidecar] engine starts: ' + (stamp
      ? `v${stamp.version}, built ${stamp.built_at}, ${stamp.git_describe}, python ${stamp.python}`
      : line.slice(0, 160)));
    finish(0, null);
  });
  child.stderr.on('data', (b) => { err += b.toString(); });
  child.on('error', (e) => finish(2, `[sidecar] could not launch the engine: ${e.message}`));
  child.on('exit', (c) => {
    if (out.includes('"ready"')) return;
    const trace = err.trim().split('\n').slice(-8).join('\n  ');
    finish(1, `[sidecar] FAIL — the engine exited (code ${c}) without starting.\n  ${trace || '(no stderr)'}`);
  });
});

if (startCode === 2) process.exit(2);
if (startCode !== 0) failed = true;

// ── 2. Tauri's bundle copy, when there is one ──────────────────────────────
if (!existsSync(BUNDLED)) {
  console.log(`[sidecar] note: ${BUNDLED} is absent, so running the release binary`);
  console.log('[sidecar]       directly has no engine — every release-mode harness');
  console.log('[sidecar]       (test:csp:release, test:export:release) will show it offline.');
  console.log(`[sidecar]       The Inno installer and Tauri's MSI/NSIS are unaffected: both`);
  console.log(`[sidecar]       read the sidecar from ${SIDECAR_DIR}.`);
  console.log('[sidecar]       To restore it, copy the sidecar there — a plain rebuild is');
  console.log('[sidecar]       fingerprint-clean and skips the copy.');
} else {
  const sidecar = walk(SIDECAR);
  const bundled = walk(BUNDLED);
  const orphans = [...bundled].filter(f => !sidecar.has(f)).sort();
  const missing = [...sidecar].filter(f => !bundled.has(f)).sort();

  console.log(`[sidecar] built ${sidecar.size} file(s), bundled ${bundled.size}`);

  if (orphans.length) {
    failed = true;
    console.log(`[sidecar] FAIL — ${orphans.length} file(s) in the bundle the sidecar did not build:`);
    for (const [top, n] of summarise(orphans).slice(0, 12)) {
      console.log(`  ${String(n).padStart(5)}  ${top}`);
    }
    for (const [top] of summarise(orphans)) {
      if (top === '(root)') continue;
      const stillBuilt = [...sidecar].some(f => f.startsWith(`${top}/`));
      const hasInit = orphans.some(f => f === `${top}/__init__.py`);
      if (!stillBuilt && !hasInit) {
        console.log(`  note: '${top}' is orphaned entirely and has no __init__.py, so Python`);
        console.log('        reads it as a namespace package and it will shadow the real module.');
      }
    }
  }
  if (missing.length) {
    failed = true;
    console.log(`[sidecar] FAIL — ${missing.length} file(s) the sidecar built that did not reach the bundle:`);
    for (const [top, n] of summarise(missing).slice(0, 12)) {
      console.log(`  ${String(n).padStart(5)}  ${top}`);
    }
  }
  /*
    "Exactly" meant "the same file names", which is not the same claim.

    `walk` returns relative paths, so the comparison above proves that nothing is
    orphaned and nothing is missing, and says nothing whatever about the bytes. A
    stale copy has precisely the same file names as a fresh one -- that is the only
    way for it to be stale. Tauri's build script does not refresh the staging copy
    when it is fingerprint-clean, so rebuilding the sidecar without rebuilding the
    app leaves two directories agreeing on every name and differing in every file
    that changed. That is the state this ran in when the wording was noticed, and
    it printed a match.

    It matters for the release harnesses rather than for the installers -- the Inno
    script and Tauri's own bundlers both read the sidecar from its build output, on
    purpose -- but "matches exactly" is read as "these are the same engine", and a
    harness driving the release binary against a month-old engine while this prints
    a match is how a fixed bug goes on being reported from the field.

    Content now, by digest, and the executable as well as `_internal`: the exe is
    the one file whose staleness changes behaviour on its own, and it was outside
    the comparison entirely.
  */
  const digest = f => createHash('sha256').update(readFileSync(f)).digest('hex');
  if (!orphans.length && !missing.length) {
    const differing = [];
    for (const rel of sidecar) {
      if (digest(join(SIDECAR, rel)) !== digest(join(BUNDLED, rel))) differing.push(rel);
    }
    const bundledExe = 'src-tauri/target/release/ewac-engine.exe';
    const exeStale = existsSync(bundledExe) && digest(SIDECAR_EXE) !== digest(bundledExe);

    if (differing.length || exeStale) {
      failed = true;
      if (exeStale) {
        console.log('[sidecar] FAIL — the engine executable in the staging copy is not the one');
        console.log(`[sidecar]        that was built. ${bundledExe}`);
      }
      if (differing.length) {
        console.log(`[sidecar] FAIL — ${differing.length} of ${sidecar.size} file(s) share a name across both`);
        console.log('[sidecar]        copies and differ in content. The staging copy is stale:');
        for (const [top, n] of summarise(differing).slice(0, 12)) {
          console.log(`  ${String(n).padStart(5)}  ${top}`);
        }
      }
    } else {
      console.log(`[sidecar] Tauri's bundle copy is byte-identical to the sidecar: `
        + `${sidecar.size} file(s) and the executable.`);
    }
  }
}

if (failed) {
  console.log('[sidecar] To restore the staging copy cleanly:');
  console.log('[sidecar]   rm -rf src-tauri/target/release/_internal src-tauri/target/release/ewac-engine.exe');
  console.log('[sidecar]   cp -r src-tauri/binaries/ewac-engine/_internal src-tauri/target/release/_internal');
  console.log('[sidecar]   cp src-tauri/binaries/ewac-engine/ewac-engine-x86_64-pc-windows-msvc.exe src-tauri/target/release/ewac-engine.exe');
  process.exit(1);
}

console.log('[sidecar] PASS');
process.exit(0);
