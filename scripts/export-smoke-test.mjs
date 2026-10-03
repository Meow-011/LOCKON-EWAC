/**
 * LOCKON EWAC — report export smoke test, and the PDF regression net.
 *
 *     node scripts/export-smoke-test.mjs                       # compare every pinned archive
 *     node scripts/export-smoke-test.mjs --write-baseline      # re-record them all
 *     node scripts/export-smoke-test.mjs --write-baseline --report <id>   # pin another
 *
 * Why this exists.
 *
 * `buildAndSavePDF` is the one product path `npm test` cannot reach. `tsc`
 * passes over it, every unit suite stops short of it, and the report is the
 * thing this whole project exists to produce — so a change to it was, for three
 * days, verified by nothing at all. A rewrite of `ReportsPage.tsx` landed with
 * ~2,700 insertions while the newest PDF the app had actually produced was two
 * days older than the code that would produce the next one.
 *
 * This drives the real app to a real exported file and compares what the
 * document *says* against a baseline, through `pdfdiff.mjs`.
 *
 * Four things each cost a round of debugging the first time, and each is now
 * handled here rather than rediscovered:
 *
 *   * **`Browser.setDownloadBehavior` is mandatory.** `doc.save()` is an
 *     `<a download>` click. Without an allowed download path WebView2 drops it
 *     and the harness sees a clean pass with no file — the worst outcome for a
 *     test whose job is to notice an absence.
 *   * **Wait for "Engine: ONLINE".** The frozen sidecar takes 7-23 seconds to
 *     emit `ready`, longer under `tauri dev`. Exporting before then produces a
 *     document that correctly reports the engine as unreachable, with no CVE
 *     vintage and no capability probe — one page shorter, and a diff that looks
 *     like a code change when the invariant was working.
 *   * **Poll in short evaluates.** One long `awaitPromise` evaluate outlives the
 *     CDP send timeout and dies as "Runtime.evaluate timed out".
 *   * **A report has to be selected first**, via `data-report-row`, and the
 *     archive has to contain one. An empty archive is reported as a *failure to
 *     test*, not as a pass.
 */
import { existsSync, mkdirSync, readdirSync, copyFileSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  refuseIfAppAlreadyRunning, waitForDebugger, launchApp, connect, pollFor, shutdownApp,
  Session, RELEASE_EXE,
} from './cdp.mjs';
import { extract, compare } from './pdfdiff.mjs';

const PORT = 9224;              // not the CSP harness's port, so both can exist
/*
  One baseline per archive *shape*, not one baseline.

  A wireless survey and a LAN sweep draw different halves of the document: the
  survey figure, the rogue assessment, WPS exposure and position quality render
  only for the first, the subnet sweep coverage and the host tables only for the
  second. A single pinned archive therefore checks about half the builder.

  That was not theoretical. Eleven PDF sections were extracted against a pinned
  `INTRUSION` report, so six of them were compared against a document that did not
  contain them -- `tsc` was the only thing holding those moves. Closing it needed
  a second baseline captured by hand, which is a step that gets forgotten, and had
  been forgotten once already.

  So the set is a list, every member is exported in one app launch (the launch is
  the expensive part, not the export), and a difference in any of them fails.
*/
const BASELINE_DIR = 'scripts/baselines';
const baselinePdf = id => join(BASELINE_DIR, `${id}.pdf`);
/*
  Which report the baseline was taken from.

  The harness used to export "the first archived report", which is only stable
  while the archive is. It is not: run a scan and a newer row goes to the top, so
  the next run exported a *different survey* and the comparison reported dozens
  of differences that had nothing to do with the code. A regression net that
  cannot tell "the build changed the document" from "a different document" is
  worse than none, because every real diff after that gets read as noise.

  So the baseline records its report id and later runs select that exact row.
*/
const BASELINE_INDEX = join(BASELINE_DIR, 'index.json');

/** The pinned archive ids, in the order they will be exported. */
function readPins() {
  if (!existsSync(BASELINE_INDEX)) return [];
  try {
    const parsed = JSON.parse(readFileSync(BASELINE_INDEX, 'utf8'));
    return Array.isArray(parsed?.reports) ? parsed.reports.filter(x => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function writePins(ids) {
  mkdirSync(BASELINE_DIR, { recursive: true });
  writeFileSync(BASELINE_INDEX, JSON.stringify({ reports: ids }, null, 2));
}
const PROGRESS_LOG = join(tmpdir(), 'lockon-export-progress.log');

const WRITE_BASELINE = process.argv.includes('--write-baseline');
/*
  Re-pinning the baseline to a different survey has to be asked for.

  `--write-baseline` alone means "the document changed on purpose, re-record it for the
  same report". `--report <id>` is what changes *which* report, and without it an
  existing pin is kept — otherwise accepting a change would quietly re-pin to whatever
  sits at the top of the archive, and every later comparison would be against a
  different survey.
*/
const REPIN = process.argv.includes('--report');
const REPIN_ID = REPIN ? (process.argv[process.argv.indexOf('--report') + 1] ?? null) : null;

/*
  `--release` drives the built binary instead of `npm run tauri dev`.

  Worth preferring for the same reason the CSP harness has it: the report is the
  product, and the build is what produces the operator's copy of it. It is also
  far cheaper — the dev path needs `src-tauri/target/debug`, which is 13 GB and
  is the first thing to delete when the disk fills, after which the next dev run
  pays a full Rust rebuild before the harness can even start.
*/
const RELEASE = process.argv.includes('--release');

const log = (...a) => {
  const line = `[export] ${a.join(' ')}`;
  console.log(line);
  try { writeFileSync(PROGRESS_LOG, line + '\n', { flag: 'a' }); } catch { /* not fatal */ }
};

class ExportSession extends Session {
  constructor(ws) {
    super(ws);
    this.consoleErrors = [];
  }

  onEvent(msg) {
    if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
      this.consoleErrors.push(`${msg.params.entry.source}: ${msg.params.entry.text}`);
    }
    if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
      this.consoleErrors.push((msg.params.args || [])
        .map(a => a.value ?? a.description ?? '').join(' '));
    }
  }
}

/** Click an element found by a DOM expression, failing loudly if it is absent. */
async function click(session, label, finder) {
  const ok = await session.evaluate(`(() => {
    const el = ${finder};
    if (!el) return false;
    el.click();
    return true;
  })()`);
  if (!ok) throw new Error(`could not find ${label} to click`);
  log(`clicked ${label}`);
}

/**
 * The newest PDF in `dir` that this run has not already claimed.
 *
 * `seen` matters once there is more than one archive to export: taking the
 * newest would hand the second comparison the *first* document whenever the
 * second had not been written yet, which reports a difference against the wrong
 * archive -- a worse outcome than timing out.
 */
function newestPdf(dir, seen = new Set()) {
  if (!existsSync(dir)) return null;
  const files = readdirSync(dir)
    .filter(f => f.toLowerCase().endsWith('.pdf') && !seen.has(f))
    .map(f => ({ f, path: join(dir, f), t: statSync(join(dir, f)).mtimeMs }))
    .sort((a, b) => b.t - a.t);
  return files.length ? files[0] : null;
}

async function main() {
  await refuseIfAppAlreadyRunning(PORT, 'export');

  const downloads = join(tmpdir(), `lockon-export-${Date.now()}`);
  mkdirSync(downloads, { recursive: true });
  try { writeFileSync(PROGRESS_LOG, ''); } catch { /* not fatal */ }
  log(`progress log: ${PROGRESS_LOG}`);
  log(`download dir: ${downloads}`);
  if (RELEASE && !existsSync(RELEASE_EXE)) {
    console.error(`[export] ${RELEASE_EXE} does not exist. Run \`npm run tauri build\` first.`);
    process.exit(2);
  }
  log(RELEASE
    ? `launching the BUILT app with remote debugging on :${PORT}`
    : `launching the dev app with remote debugging on :${PORT}`);

  const { app, output } = launchApp(PORT, RELEASE ? 'release' : 'dev');
  let session;
  let exitCode = 1;

  try {
    // The first run compiles the Rust side, which is minutes, not seconds.
    const page = await waitForDebugger(PORT, 15 * 60 * 1000);
    log(`attached to ${page.url}`);
    session = await connect(page, ExportSession);

    await session.send('Log.enable');
    await session.send('Runtime.enable');
    await session.send('Page.enable');

    // Mandatory. Without it `doc.save()` is silently dropped — see the header.
    await session.send('Browser.setDownloadBehavior', {
      behavior: 'allow', downloadPath: downloads,
    });
    log('download behaviour set to allow');

    // The sidecar is slow and load-dependent; exporting early changes the
    // document rather than failing, which is why this waits rather than sleeps.
    log('waiting for the engine to come online (up to 3 minutes)');
    await pollFor(session, '"Engine: ONLINE"',
      `(() => (document.body?.innerText || '').includes('ONLINE'))()`,
      3 * 60 * 1000, log);
    log('engine is online');

    await click(session, 'the Reports nav link',
      `[...document.querySelectorAll('a')].find(a => /report/i.test(a.textContent || ''))`);
    await pollFor(session, 'the Reports screen',
      `(() => !!document.querySelector('[data-report-row]')
          || /no .{0,20}report/i.test(document.body?.innerText || ''))()`,
      30000, log);

    const rows = await session.evaluate(
      `document.querySelectorAll('[data-report-row]').length`);
    if (!rows) {
      throw new Error(
        'the report archive is empty, so there is nothing to export. Run a scan '
        + 'and archive a report first — an empty archive is a failure to test, '
        + 'not a passing test.');
    }
    log(`${rows} archived report(s) available`);

    /*
      Which archives to export.

      Pinned ids, in order, exported in a single app launch -- the launch and the
      sidecar wait are the expensive parts, not the export, so adding a second
      shape costs about a minute rather than doubling the run.

      With no pins at all (a fresh clone), the first archive in the list is taken
      and recorded, which is the old single-baseline behaviour and keeps a first
      run useful. `--report <id>` adds or re-records one, and is the only way the
      compared set changes -- accepting an intended change must not silently swap
      which survey the net watches.
    */
    let pins = readPins();
    if (REPIN_ID) {
      if (!WRITE_BASELINE) {
        throw new Error('--report only means anything with --write-baseline: it pins a '
          + 'new archive. Without it, every pinned archive is compared.');
      }
      pins = pins.includes(REPIN_ID) ? pins : [...pins, REPIN_ID];
    }
    if (pins.length === 0) {
      const first = await session.evaluate(
        `document.querySelector('[data-report-row]')?.getAttribute('data-report-row') ?? null`);
      if (!first) throw new Error('no archived report could be selected.');
      pins = [first];
      log(`no baseline pinned yet; adopting ${first}`);
    }

    log(`${pins.length} archive(s) to export: ${pins.join(', ')}`);

    /** PDFs already in the download directory, so each export waits for its own. */
    const seen = new Set();
    const results = [];

    for (const id of pins) {
      log(`--- ${id} ---`);

      /*
        Back to the list between archives.

        Selecting a report opens its detail view, and the next `[data-report-row]`
        click has to happen on the list again. Re-clicking the nav link is the
        cheapest way to get there that does not depend on which view is showing.
      */
      await click(session, 'the Reports nav link',
        `[...document.querySelectorAll('a')].find(a => /report/i.test(a.textContent || ''))`);
      await pollFor(session, 'the Reports screen',
        `(() => !!document.querySelector('[data-report-row]'))()`, 30000, log);

      const found = await session.evaluate(
        `!!document.querySelector('[data-report-row="${id}"]')`);
      if (!found) {
        throw new Error(
          `the pinned archive ${id} is no longer present. Re-pin with --write-baseline `
          + '--report <id>; comparing a different survey would report differences that '
          + 'are not code changes.');
      }
      await click(session, `archived report ${id}`,
        `document.querySelector('[data-report-row="${id}"]')`);

      await click(session, 'the export menu',
        `document.querySelector('[aria-haspopup="menu"]')`);
      await click(session, 'PDF REPORT',
        `[...document.querySelectorAll('button')]`
        + `.find(b => (b.textContent || '').trim().startsWith('PDF REPORT'))`);

      log('waiting for the PDF to be written (up to 5 minutes)');
      const deadline = Date.now() + 5 * 60 * 1000;
      let produced = null;
      while (Date.now() < deadline) {
        /*
          A *new* file, not the newest one. With several exports in a run, taking
          the newest would hand the second comparison the first document whenever
          the second had not been written yet -- a difference reported against the
          wrong archive, which is worse than a timeout.
        */
        const candidate = newestPdf(downloads, seen);
        if (candidate) {
          const first = statSync(candidate.path).size;
          await new Promise(r => setTimeout(r, 2000));
          if (statSync(candidate.path).size === first && first > 0) {
            produced = candidate;
            break;
          }
        }
        await new Promise(r => setTimeout(r, 2000));
      }
      if (!produced) {
        throw new Error(`no PDF appeared for ${id}. If the export reported success, `
          + 'check Browser.setDownloadBehavior.');
      }
      seen.add(produced.f);

      const sizeMb = (statSync(produced.path).size / 1024 / 1024).toFixed(2);
      log(`produced ${produced.f} (${sizeMb} MB)`);

      const got = extract(produced.path);
      log(`extracted ${got.streams.length} text streams, ${got.strings} strings`);
      if (got.strings === 0) {
        throw new Error(`the PDF for ${id} yielded no text, so a comparison would always `
          + 'report IDENTICAL. Treating that as a failure.');
      }
      results.push({ id, produced, got });
    }

    mkdirSync(BASELINE_DIR, { recursive: true });

    if (WRITE_BASELINE) {
      for (const { id, produced } of results) copyFileSync(produced.path, baselinePdf(id));
      writePins(pins);
      log(`baseline(s) updated: ${pins.map(baselinePdf).join(', ')}`);
      log('RESULT: BASELINE WRITTEN — re-run without --write-baseline to compare.');
      /*
        Its own exit code, so a release script cannot read it as a pass. "Nothing
        to compare against" and "identical" are different answers.
      */
      exitCode = 3;
    } else {
      let differed = 0;
      let missing = 0;

      for (const { id, produced, got } of results) {
        const base = baselinePdf(id);
        if (!existsSync(base)) {
          /*
            A pin with no baseline file is not a pass. It happened the moment the
            set grew: the index listed two archives and only one had ever been
            recorded, and reporting that as IDENTICAL would have been the single
            worst outcome available to this harness.
          */
          log(`${id}: NO BASELINE RECORDED — run --write-baseline`);
          missing += 1;
          continue;
        }
        const diffs = compare(extract(base), got);
        if (diffs.length === 0) {
          log(`${id}: IDENTICAL`);
          continue;
        }
        differed += 1;
        const kept = `scripts/candidate-${id}.pdf`;
        try {
          copyFileSync(produced.path, kept);
          log(`${id}: candidate kept for inspection: ${kept}`);
          log(`  compare with: node scripts/pdfdiff.mjs ${base} ${kept}`);
        } catch (e) {
          log(`${id}: could not keep the candidate: ${e.message}`);
        }
        log(`${id}: ${diffs.length} DIFFERENCE(S) from the baseline:`);
        for (const d of diffs.slice(0, 20)) console.log('  ' + d);
      }

      if (missing > 0) {
        log(`RESULT: ${missing} pinned archive(s) have no baseline. Nothing was compared for them.`);
        exitCode = 3;
      } else if (differed > 0) {
        log(`RESULT: ${differed} of ${results.length} archive(s) differ from the baseline.`);
        log('If this change was intended, re-run with --write-baseline.');
        exitCode = 1;
      } else {
        log(`RESULT: IDENTICAL — all ${results.length} document(s) say exactly what their baselines say.`);
        exitCode = 0;
      }
    }


    if (session.consoleErrors.length) {
      log(`${session.consoleErrors.length} console error(s) during the export:`);
      for (const e of session.consoleErrors.slice(0, 10)) console.log('  ' + e);
      exitCode = 1;
    } else {
      log('0 console errors');
    }
  } catch (err) {
    log(`harness failed: ${err.message}`);
    console.error('\n[export] harness failed:', err.message);
    const tail = output.join('').split('\n').slice(-30).join('\n');
    if (tail.trim()) console.error('\n--- last app output ---\n' + tail);
  } finally {
    if (session) try { session.ws.close(); } catch { /* already gone */ }
    await shutdownApp(app);
    try { rmSync(downloads, { recursive: true, force: true }); } catch { /* leave it */ }
    process.exit(exitCode);
  }
}

main();
