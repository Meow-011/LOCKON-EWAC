/**
 * LOCKON EWAC — what this costs a machine, measured rather than guessed.
 *
 *     node scripts/benchmark.mjs                   # drives the built app
 *     node scripts/benchmark.mjs --dev             # drives `npm run tauri dev`
 *     node scripts/benchmark.mjs --report <id>     # a specific archive
 *     node scripts/benchmark.mjs --json out.json
 *
 * Why this exists.
 *
 * `docs/INSTALL.md` is read by somebody deciding whether their laptop will run
 * this before they install it, and until now it said nothing about memory at all.
 * A requirement invented from a feeling ("8 GB should be fine") is the same class
 * of claim this project refuses everywhere else: a number stated without being
 * measured. So the numbers in that document now come from here.
 *
 * What is measured.
 *
 * The whole process set, because the application is not one process. Tauri's
 * window hosts WebView2, which runs its own browser, GPU and renderer processes
 * under `msedgewebview2.exe`, and the Python sidecar is a separate
 * `ewac-engine.exe` holding scipy, numpy and scikit-learn resident. Reading the
 * working set of `lockon-ewac.exe` alone reports roughly a tenth of the truth.
 *
 * **By descent from this app's own process, never by process name.** The first
 * version of this matched `msedgewebview2` by name and summed every one of them
 * on the machine. WebView2 is the Windows web runtime -- Office, Teams, Widgets
 * and a dozen ordinary applications each run their own -- so on the machine this
 * was written on, thirty of them were already running before the benchmark
 * started, holding about 1,042 MB between them. That went straight into the
 * figure, and the answer to "how much memory does LOCKON EWAC need" came out
 * roughly twice the truth with nothing in the output to suggest it.
 *
 * So each tick asks Windows for the parent of every candidate process and keeps
 * only those descending from the `lockon-ewac.exe` this harness launched. A
 * process that cannot be traced to that root is somebody else's.
 *
 * Two memory figures, because one of them alone would mislead.
 *
 * **Working set** is what Task Manager shows, so it is what an operator will
 * compare against -- but summing it across processes counts shared pages once per
 * process that maps them, and WebView2 runs four or five processes sharing a large
 * browser runtime. The sum therefore overstates what the machine has to find.
 *
 * **Private bytes** (commit) is memory that belongs to one process and nothing
 * else, so summing it across the set is sound. It is the better answer to "how
 * much RAM do I need" and the smaller of the two.
 *
 * Both are reported. A minimum written from the working-set sum would be too
 * cautious; one written from private bytes alone would not survive somebody
 * opening Task Manager and seeing a bigger number.
 *
 * What is NOT measured, and the document says so too: a live scan. That needs
 * radio hardware, Npcap and somewhere to drive to. Every phase here replays
 * recorded survey data from the archive, which exercises the rendering, the map
 * and the report builder honestly and the capture path not at all.
 */
import { existsSync, writeFileSync, statSync, readdirSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { join } from 'node:path';
import {
  refuseIfAppAlreadyRunning, waitForDebugger, launchApp, connect, pollFor,
  shutdownApp, Session, RELEASE_EXE,
} from './cdp.mjs';

const DEV = process.argv.includes('--dev');
const PORT = 9223;
const jsonAt = (() => {
  const i = process.argv.indexOf('--json');
  return i === -1 ? null : process.argv[i + 1];
})();

/*
  Which archive to open and export.

  The default takes the newest wireless survey, which is whatever was scanned
  last and says nothing about how heavy it is. A minimum specification wants the
  *worst* case somebody will actually hit, so the archive is selectable and the
  figures published in docs/INSTALL.md come from the largest one on this machine
  rather than the most recent.
*/
const wantReport = (() => {
  const i = process.argv.indexOf('--report');
  return i === -1 ? null : process.argv[i + 1];
})();

const log = (...a) => console.log('[bench]', ...a);

/* ── The sampler ───────────────────────────────────────────────────────────
   One long-lived PowerShell loop rather than a `Get-Process` per sample: a
   PowerShell start-up is a few hundred milliseconds and would both coarsen the
   interval and show up in the CPU figure it is supposed to be measuring.

   `CPU` on a Process object is cumulative processor-seconds, so a phase's cost is
   the difference across it rather than any single reading.                     */
const PROCESS_NAMES = ['lockon-ewac.exe', 'msedgewebview2.exe', 'ewac-engine.exe'];

function startSampler() {
  const filter = PROCESS_NAMES.map(n => `Name='${n}'`).join(' OR ');
  /*
    `Win32_Process` rather than `Get-Process`, because it is the one that carries
    `ParentProcessId`. Times are in 100-nanosecond units and memory in bytes;
    `PrivatePageCount` is the commit charge, the counterpart of
    `PrivateMemorySize64`.
  */
  const script = `
$ErrorActionPreference='SilentlyContinue'
while ($true) {
  $t = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  foreach ($p in Get-CimInstance Win32_Process -Filter "${filter}") {
    Write-Output ("$t," + $p.Name + "," + $p.ProcessId + "," + $p.ParentProcessId + "," + $p.WorkingSetSize + "," + $p.PrivatePageCount + "," + ($p.KernelModeTime + $p.UserModeTime))
  }
  Write-Output "$t,--mark--,0,0,0,0,0"
  Start-Sleep -Milliseconds 500
}`;
  const ps = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', script],
    { stdio: ['ignore', 'pipe', 'ignore'] });

  const raw = [];
  let buf = '';
  ps.stdout.on('data', chunk => {
    buf += chunk.toString('utf8');
    const lines = buf.split(/\r?\n/);
    buf = lines.pop() ?? '';
    for (const line of lines) {
      const [t, name, pid, ppid, ws, priv, time100ns] = line.trim().split(',');
      if (!t || !name || name === '--mark--') continue;
      raw.push({
        t: Number(t),
        name: name.replace(/\.exe$/i, ''),
        pid: Number(pid),
        ppid: Number(ppid),
        ws: Number(ws),
        priv: Number(priv),
        cpu: Number(time100ns) / 1e7,
      });
    }
  });
  return { ps, raw };
}

/*
  Keep only what descends from the app this harness launched.

  Done per tick rather than once, because WebView2 spawns and retires renderer
  and utility processes while the app runs; a PID set captured at launch would
  miss the GPU process that appears when the map first draws.
*/
function ownedByApp(raw) {
  const byTick = new Map();
  for (const r of raw) {
    if (!byTick.has(r.t)) byTick.set(r.t, []);
    byTick.get(r.t).push(r);
  }

  const kept = [];
  let rootPid = null;
  for (const [, list] of [...byTick.entries()].sort((a, b) => a[0] - b[0])) {
    const root = list.find(r => r.name === 'lockon-ewac');
    if (root) rootPid = root.pid;
    if (rootPid === null) continue;

    // Walk down from the root: a child joins the set once its parent is in it,
    // so repeated passes settle the whole tree however deep WebView2 nests.
    const owned = new Set([rootPid]);
    let grew = true;
    while (grew) {
      grew = false;
      for (const r of list) {
        if (!owned.has(r.pid) && owned.has(r.ppid)) { owned.add(r.pid); grew = true; }
      }
    }
    for (const r of list) if (owned.has(r.pid)) kept.push(r);
  }
  return kept;
}

/* ── Phases ────────────────────────────────────────────────────────────────
   Wall-clock windows the samples are later bucketed into. Recorded as timestamps
   instead of sampling inside each step so that a step which takes longer than
   expected does not silently truncate its own measurement.                     */
const phases = [];
let current = null;
function phase(name) {
  if (current) current.end = Date.now();
  current = { name, start: Date.now(), end: null };
  phases.push(current);
  log(`--- ${name}`);
}

const sleep = ms => new Promise(r => setTimeout(r, ms));

/*
  `Session.send` gives every call 30 seconds, which is the right default for a
  harness that is checking whether something rendered. It is the wrong one here,
  because a blocked main thread is a thing this is *trying to measure*: the first
  run died on "Runtime.evaluate timed out" at the Reports screen, which is not a
  harness fault but the measurement arriving as an exception.

  A CDP evaluate cannot run while the renderer's JS thread is busy, so the reply
  comes back when the thread frees up -- and how long that takes is the number
  worth having.
*/
class PatientSession extends Session {
  send(method, params = {}, timeoutMs = 180000) {
    const id = ++this.id;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`${method} timed out after ${timeoutMs}ms`));
      }, timeoutMs);
    });
  }
}

/** How long an evaluate actually took to come back, which is main-thread latency. */
const blocked = [];
async function timedEvaluate(session, label, expression) {
  const t0 = Date.now();
  const value = await session.evaluate(expression);
  const ms = Date.now() - t0;
  if (ms > 1000) {
    blocked.push({ label, ms });
    log(`  main thread was busy ${(ms / 1000).toFixed(1)}s before "${label}" could run`);
  }
  return value;
}

async function click(session, what, selectorExpr) {
  const ok = await timedEvaluate(session, what,
    `(() => { const el = ${selectorExpr}; if (!el) return false; el.click(); return true; })()`);
  if (!ok) throw new Error(`could not click ${what}`);
  await sleep(400);
}

/* ── Reporting ─────────────────────────────────────────────────────────────
   Per phase: the peak of the *summed* working set across the process set, since
   that is what the machine has to find at once, plus the same figure broken down
   by process so a reader can see where it goes. CPU is the processor-seconds the
   set consumed during the phase, divided by its wall-clock duration -- so "1.0
   core" means one core saturated for the whole phase, whatever the core count. */
function summarise(samples, cores) {
  // Group samples into ticks by timestamp, so working sets are summed across
  // processes that existed at the same moment.
  const ticks = new Map();
  for (const s of samples) {
    if (s.name === '--mark--') continue;
    if (!ticks.has(s.t)) ticks.set(s.t, []);
    ticks.get(s.t).push(s);
  }

  const rows = [];
  for (const p of phases) {
    const end = p.end ?? Date.now();
    const inPhase = [...ticks.entries()].filter(([t]) => t >= p.start && t <= end);
    if (inPhase.length === 0) { rows.push({ name: p.name, empty: true }); continue; }

    let peakTotal = 0, peakAt = null, sumTotal = 0;
    let peakPriv = 0, sumPriv = 0;
    const perName = new Map();
    for (const [, list] of inPhase) {
      const total = list.reduce((a, s) => a + s.ws, 0);
      const privTotal = list.reduce((a, s) => a + s.priv, 0);
      sumTotal += total;
      sumPriv += privTotal;
      if (privTotal > peakPriv) peakPriv = privTotal;
      if (total > peakTotal) { peakTotal = total; peakAt = list; }
      for (const s of list) {
        const e = perName.get(s.name) ?? { peak: 0, procs: 0 };
        e.peak = Math.max(e.peak, s.ws);
        perName.set(s.name, e);
      }
    }
    // Peak per process NAME means the sum across that name's processes at the
    // peak moment: WebView2 runs several and reporting the largest single one
    // would understate it.
    const breakdown = new Map();
    if (peakAt) {
      for (const s of peakAt) {
        breakdown.set(s.name, (breakdown.get(s.name) ?? 0) + s.ws);
      }
    }

    // CPU: last reading minus first, summed over pids seen in the phase.
    const firstCpu = new Map(), lastCpu = new Map();
    for (const [, list] of inPhase) {
      for (const s of list) {
        if (!firstCpu.has(s.pid)) firstCpu.set(s.pid, s.cpu);
        lastCpu.set(s.pid, s.cpu);
      }
    }
    let cpuSeconds = 0;
    for (const [pid, last] of lastCpu) cpuSeconds += Math.max(0, last - (firstCpu.get(pid) ?? 0));
    const wall = (end - p.start) / 1000;

    rows.push({
      name: p.name,
      seconds: wall,
      peakMb: peakTotal / 1048576,
      meanMb: (sumTotal / inPhase.length) / 1048576,
      peakPrivMb: peakPriv / 1048576,
      meanPrivMb: (sumPriv / inPhase.length) / 1048576,
      breakdown: [...breakdown.entries()].map(([n, b]) => [n, b / 1048576]),
      cpuSeconds,
      cores: wall > 0 ? cpuSeconds / wall : 0,
      coresPct: wall > 0 ? (cpuSeconds / wall / cores) * 100 : 0,
      samples: inPhase.length,
    });
  }
  return rows;
}

// ── Run ───────────────────────────────────────────────────────────────────
async function main() {
  if (!DEV && !existsSync(RELEASE_EXE)) {
    console.error(`[bench] ${RELEASE_EXE} does not exist. Run \`npm run tauri build\` first.`);
    process.exit(2);
  }
  await refuseIfAppAlreadyRunning(PORT, 'bench');

  const cores = (await import('node:os')).cpus().length;
  const { ps, raw } = startSampler();
  let app = null;
  let failure = null;

  try {
    phase('launch');
    log(`launching the ${DEV ? 'dev' : 'BUILT'} app on :${PORT}`);
    const launched = launchApp(PORT, DEV ? 'dev' : 'release');
    app = launched.app;

    const page = await waitForDebugger(PORT, 120000);
    const session = await connect(page, PatientSession);
    await session.send('Runtime.enable');

    await pollFor(session, 'the window to render',
      `(() => !!document.querySelector('body') && document.body.innerText.length > 50)()`,
      120000, log);

    /*
      `/ONLINE|READY/` matched the scan button, which reads READY before the
      sidecar has connected -- so the first run of this attributed two seconds to
      "launch" and the engine's real start-up to the idle phase that followed. The
      status line is specific; the button is not.
    */
    log('waiting for the engine to report ONLINE (up to 120s)');
    await pollFor(session, 'engine ONLINE',
      `(() => /Engine:\\s*ONLINE/i.test(document.body.innerText || ''))()`, 120000, log);
    const readyAt = Date.now();
    log(`engine ONLINE ${((readyAt - phases[0].start) / 1000).toFixed(1)}s after launch`);

    phase('idle');
    await sleep(25000);

    phase('archive list');
    await click(session, 'the Reports nav link',
      `[...document.querySelectorAll('a')].find(a => /report/i.test(a.textContent || ''))`);
    await pollFor(session, 'the Reports screen',
      `(() => !!document.querySelector('[data-report-row]'))()`, 60000, log);
    const ids = await session.evaluate(
      `[...document.querySelectorAll('[data-report-row]')].map(e => e.getAttribute('data-report-row'))`);
    log(`${ids.length} archive(s) present`);
    await sleep(8000);

    const target = wantReport ?? ids.find(i => i.startsWith('WIFI')) ?? ids[0];
    if (!target) throw new Error('no archived report to open');
    if (wantReport && !ids.includes(wantReport)) {
      throw new Error(`archive ${wantReport} is not in the list; it holds: ${ids.join(', ')}`);
    }

    /*
      How big the thing being measured is, so the numbers can be read against
      something. A peak of N MB means nothing without the size of the document
      that produced it.
    */
    const size = await timedEvaluate(session, 'the row summary',
      `(() => { const el = document.querySelector('[data-report-row="${target}"]');`
      + ` return el ? (el.innerText || '').replace(/\\s+/g, ' ').slice(0, 120) : null; })()`);
    log(`archive under test: ${target}`);
    if (size) log(`  ${size}`);

    phase('open report');
    log(`opening ${target}`);
    await click(session, `archived report ${target}`,
      `document.querySelector('[data-report-row="${target}"]')`);
    await sleep(12000);

    phase('tactical map');
    const gotMap = await session.evaluate(
      `(() => { const b = [...document.querySelectorAll('button')]`
      + `.find(x => /TACTICAL MAP/i.test(x.textContent || '')); if (!b) return false; b.click(); return true; })()`);
    if (gotMap) { log('map tab opened'); await sleep(20000); }
    else log('no TACTICAL MAP tab found; skipping');

    phase('pdf export');
    await click(session, 'the export menu',
      `document.querySelector('[aria-haspopup="menu"]')`);
    await click(session, 'PDF REPORT',
      `[...document.querySelectorAll('button')]`
      + `.find(b => (b.textContent || '').trim().startsWith('PDF REPORT'))`);
    log('exporting (up to 5 minutes)');
    const downloads = join(process.env.USERPROFILE ?? '.', 'Downloads');
    const before = new Set(readdirSync(downloads).filter(f => f.endsWith('.pdf')));
    const deadline = Date.now() + 5 * 60 * 1000;
    let produced = null;
    while (Date.now() < deadline) {
      const now = readdirSync(downloads).filter(f => f.endsWith('.pdf') && !before.has(f));
      if (now.length) {
        const p = join(downloads, now[0]);
        const a = statSync(p).size;
        await sleep(2000);
        if (statSync(p).size === a && a > 0) { produced = { f: now[0], size: a }; break; }
      }
      await sleep(1500);
    }
    if (produced) log(`produced ${produced.f} (${(produced.size / 1048576).toFixed(2)} MB)`);
    else log('WARNING: no PDF appeared; the export phase measures an attempt, not a completion');

    phase('settle after export');
    await sleep(15000);
    if (current) current.end = Date.now();
  } catch (e) {
    /*
      A phase that fails has still been measured up to the point it failed, and
      throwing away everything collected because the last step did not finish is
      how a benchmark ends up never producing a number. The failure is reported
      with the table rather than instead of it.
    */
    failure = e;
    if (current && !current.end) current.end = Date.now();
  } finally {
    ps.kill();
    if (app) await shutdownApp(app).catch(() => {});
  }

  const samples = ownedByApp(raw);

  /*
    Stated rather than silently dropped: if a large amount of WebView2 was
    excluded, the reader should know this machine had other web-hosting
    applications running, because that is the condition the naive version of this
    harness got wrong.
  */
  const foreignPeak = (() => {
    const byTick = new Map();
    for (const r of raw) {
      if (r.name !== 'msedgewebview2') continue;
      byTick.set(r.t, (byTick.get(r.t) ?? 0) + r.ws);
    }
    const ourByTick = new Map();
    for (const r of samples) {
      if (r.name !== 'msedgewebview2') continue;
      ourByTick.set(r.t, (ourByTick.get(r.t) ?? 0) + r.ws);
    }
    let worst = 0;
    for (const [t, all] of byTick) worst = Math.max(worst, all - (ourByTick.get(t) ?? 0));
    return worst / 1048576;
  })();

  const rows = summarise(samples, cores);

  console.log('');
  console.log('[bench] peak is the sum across lockon-ewac.exe + msedgewebview2.exe + ewac-engine.exe');
  console.log('');
  console.log('                           ---- working set ----   --- private bytes ---');
  console.log('  phase                secs    peak MB    mean MB    peak MB    mean MB   cores');
  console.log('  ' + '-'.repeat(76));
  for (const r of rows) {
    if (r.empty) { console.log(`  ${r.name.padEnd(18)}  (no samples)`); continue; }
    console.log(
      `  ${r.name.padEnd(18)} ${r.seconds.toFixed(0).padStart(5)} `
      + `${r.peakMb.toFixed(0).padStart(10)} ${r.meanMb.toFixed(0).padStart(10)} `
      + `${r.peakPrivMb.toFixed(0).padStart(10)} ${r.meanPrivMb.toFixed(0).padStart(10)} `
      + `${r.cores.toFixed(2).padStart(7)}`);
  }
  console.log('');
  for (const r of rows) {
    if (r.empty || !r.breakdown?.length) continue;
    const parts = r.breakdown.sort((a, b) => b[1] - a[1])
      .map(([n, mb]) => `${n} ${mb.toFixed(0)}`).join(' / ');
    console.log(`  at ${r.name} peak: ${parts}  (MB)`);
  }

  const live = rows.filter(r => !r.empty);
  const overallPeak = Math.max(...live.map(r => r.peakMb));
  const overallPriv = Math.max(...live.map(r => r.peakPrivMb));
  console.log('');
  console.log(`[bench] peak across the whole run: ${overallPeak.toFixed(0)} MB working set, `
    + `${overallPriv.toFixed(0)} MB private`);
  console.log(`[bench] machine: ${cores} logical core(s)`);
  console.log(`[bench] excluded ${foreignPeak.toFixed(0)} MB of WebView2 belonging to other `
    + 'applications on this machine (counted by name, this would have been added in)');

  if (blocked.length) {
    console.log('');
    console.log('[bench] the renderer could not answer immediately:');
    for (const b of blocked.sort((x, y) => y.ms - x.ms)) {
      console.log(`  ${(b.ms / 1000).toFixed(1).padStart(6)}s before "${b.label}"`);
    }
  }

  if (jsonAt) {
    writeFileSync(jsonAt, JSON.stringify({ cores, rows, phases, blocked, foreignPeak }, null, 2));
    log(`wrote ${jsonAt}`);
  }

  if (failure) {
    console.log('');
    console.error(`[bench] the run did not finish: ${failure.message}`);
    console.error('[bench] the phases above completed; anything after them did not run.');
    process.exit(1);
  }
}

main().catch(e => { console.error('[bench] FAILED —', e.message); process.exit(1); });
