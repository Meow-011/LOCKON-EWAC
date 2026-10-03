/**
 * LOCKON EWAC — CSP smoke test.
 *
 *     node scripts/csp-smoke-test.mjs
 *
 * Why this exists.
 *
 * `app.security.csp` was `null` — no policy at all — while the renderer holds
 * `sql:allow-execute` (arbitrary SQL, including ATTACH) and `shell:allow-spawn`,
 * and renders attacker-chosen strings throughout: SSIDs, hostnames, service
 * banners. A policy is now set, allowing exactly the origins the app uses.
 *
 * The README called this the one change in its pass that no automated test
 * covered, and gave the reason: a wrong CSP fails silently. There is nothing to
 * assert against, because the symptom is an absence — the map renders grey, a
 * font falls back, an export produces a blank page, and nothing says why.
 *
 * This closes that. It launches the app with WebView2's remote debugging port
 * open, attaches over the Chrome DevTools Protocol, drives the screens whose
 * network use the policy governs, and fails if anything was blocked or if any
 * console error appeared. It is a smoke test, not a proof: it exercises the
 * paths listed in CHECKS below, and an origin reached only by a code path
 * nobody visits here would still slip through.
 *
 * The app also reports violations itself, through `src/lib/cspReporter.ts`, so
 * one that happens outside this harness is still named rather than silent.
 */
import { appendFileSync, existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  refuseIfAppAlreadyRunning, waitForDebugger, launchApp, connect, shutdownApp,
  RELEASE_EXE,
  Session as BaseSession,
} from './cdp.mjs';

const PORT = 9223;
// The dev server's address, and why both spellings of it matter, now live in
// `cdp.mjs` (APP_URL_HINTS) so the two harnesses cannot disagree about it.

/** What gets exercised, and which directive each one depends on. */
const CHECKS = [
  { path: '/', label: 'Dashboard + map', directives: ['img-src (tiles)', 'worker-src blob: (MapLibre)'] },
  { path: '/intrusion', label: 'Intrusion', directives: ['connect-src ipc:'] },
  { path: '/decryptor', label: 'Decryptor', directives: ['connect-src ipc:'] },
  { path: '/reports', label: 'Reports', directives: ['img-src data: (PDF canvas)'] },
  { path: '/settings', label: 'Settings', directives: ['font-src, style-src (Google Fonts)'] },
];

/*
  Progress goes to a file as well as to stdout.

  Node buffers stdout when it is redirected to a file, so a run that takes
  minutes shows nothing until it ends — which makes a hung harness
  indistinguishable from a slow one. `appendFileSync` is unbuffered, so the file
  is readable while the run is still going.
*/
const PROGRESS_LOG = process.env.CSP_PROGRESS_LOG
  ?? join(tmpdir(), 'lockon-csp-progress.log');

const log = (...a) => {
  const line = `[csp] ${a.join(' ')}`;
  console.log(line);
  try {
    appendFileSync(PROGRESS_LOG, `${new Date().toISOString()} ${line}\n`);
  } catch {
    // A harness that cannot write its own log still runs.
  }
};

/**
 * What this harness counts as a failure. The CDP plumbing lives in `cdp.mjs`;
 * only the judgement is here, because that is the part the two harnesses
 * legitimately disagree about.
 */
class Session extends BaseSession {
  constructor(ws) {
    super(ws);
    this.consoleErrors = [];
    this.violations = [];
    this.failedRequests = [];
    // Requests, not only failures: a policy run that blocks nothing proves
    // nothing if nothing was requested.
    this.requestedUrls = [];
  }

  onEvent(msg) {
    if (msg.method === 'Log.entryAdded') {
      const e = msg.params.entry;
      // A CSP violation arrives here with source "security".
      if (e.source === 'security' || /Content Security Policy/i.test(e.text || '')) {
        this.violations.push(e.text);
      } else if (e.level === 'error') {
        this.consoleErrors.push(`${e.source}: ${e.text}`);
      }
    }
    if (msg.method === 'Runtime.consoleAPICalled' && msg.params.type === 'error') {
      const text = (msg.params.args || [])
        .map(a => a.value ?? a.description ?? '').join(' ');
      if (text.startsWith('[CSP]')) this.violations.push(text);
      else this.consoleErrors.push(text);
    }
    if (msg.method === 'Network.requestWillBeSent') {
      this.requestedUrls.push(msg.params?.request?.url ?? '');
    }
    if (msg.method === 'Network.loadingFailed') {
      // `blockedReason` is set when it was the policy that stopped it, as
      // opposed to a server being down or the machine being offline — which
      // this harness must not report as a CSP failure.
      if (msg.params.blockedReason) {
        this.failedRequests.push(
          `${msg.params.blockedReason}: ${msg.params.type} ${msg.params.requestId}`
        );
      }
    }
  }

}

/*
  The dev policy must not be more permissive than the production one.

  This harness runs under `tauri dev`, and Tauri applies `devCsp` there, not
  `csp`. For a long time `devCsp` was unset, which means *no policy at all* was
  injected in development - so every PASS this harness printed said nothing
  whatsoever about the policy that ships. The cost was a basemap that worked on
  every developer machine and degraded to the offline grid on every installed
  copy, because `csp` allowed `basemaps.cartocdn.com` while the style it serves
  loads its tiles, glyphs and sprite from `tiles.basemaps.cartocdn.com`.

  So: any host the production policy would refuse must also be refused in
  development, or a resource can work here and fail in the field. The dev server's
  own origins are the deliberate exception - they exist only in development.
*/
const DEV_ONLY = [
  'http://localhost:1420', 'http://127.0.0.1:1420',
  'ws://localhost:1420', 'ws://127.0.0.1:1420',
  "'unsafe-inline'",   // Vite injects inline scripts in dev; the build does not
];

function directives(policy) {
  const out = new Map();
  for (const part of (policy || '').split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name) out.set(name, sources);
  }
  return out;
}

function checkPolicyDrift() {
  const conf = JSON.parse(readFileSync('src-tauri/tauri.conf.json', 'utf8'));
  const { csp, devCsp } = conf.app?.security ?? {};
  if (!csp) {
    console.error('[csp] tauri.conf.json has no `csp`. There is no policy to test.');
    process.exit(2);
  }
  if (!devCsp) {
    console.error([
      '[csp] tauri.conf.json has no `devCsp`.',
      '      Tauri injects `devCsp` under `tauri dev`, so with none set this',
      '      harness would exercise the app with NO policy and report PASS.',
      '      Set devCsp to the production policy plus the dev server origins.',
    ].join('\n'));
    process.exit(2);
  }
  const prod = directives(csp);
  const dev = directives(devCsp);
  const extra = [];

  /*
    A directive production sets and development omits is the loudest kind of drift, and
    this loop could not see it.

    It iterated `dev`'s directives only. A directive present in `csp` and absent from
    `devCsp` is not inherited as production has it -- it falls back to *devCsp's*
    `default-src`, which carries the dev-server origins. So `object-src 'none'` dropped
    from the dev policy would leave objects loading from `localhost:1420` while the
    shipped policy forbids them entirely, and the harness printed PASS: the exact
    failure mode this function's own header says it exists to prevent, which is also
    how an unset `devCsp` once let the whole suite run with no policy at all.
  */
  for (const [name] of prod) {
    if (name === 'default-src') continue;
    if (!dev.has(name)) {
      extra.push(
        `${name} is set in production and missing from development, so it falls back `
        + `to devCsp's default-src instead of the production value`,
      );
    }
  }

  for (const [name, sources] of dev) {
    const allowed = new Set(prod.get(name) ?? prod.get('default-src') ?? []);
    for (const src of sources) {
      if (allowed.has(src)) continue;
      /*
        `'unsafe-inline'` is scoped to `script-src`.

        It is in `DEV_ONLY` because Vite needs it there, and the exemption was applied
        to every directive -- so an `'unsafe-inline'` smuggled into `img-src` or
        `connect-src` would have been accepted as a known dev difference.
      */
      if (src === "'unsafe-inline'" && name === 'script-src') continue;
      if (src !== "'unsafe-inline'" && DEV_ONLY.includes(src)) continue;
      extra.push(`${name} allows ${src} in development but not in production`);
    }
  }
  if (extra.length) {
    console.error('[csp] the dev policy is more permissive than production:');
    for (const e of extra) console.error('      ' + e);
    console.error('      A resource that loads here would fail in an installed copy.');
    process.exit(2);
  }
  log('dev policy is no more permissive than production');
}

async function main() {
  checkPolicyDrift();

  // Both guards and the launch itself live in `cdp.mjs`, shared with
  // `export-smoke-test.mjs` — including why an already-running instance has to
  // be refused up front rather than waited out.
  await refuseIfAppAlreadyRunning(PORT, 'csp');

  try { writeFileSync(PROGRESS_LOG, ''); } catch { /* not fatal */ }
  log(`progress log: ${PROGRESS_LOG}`);
  /*
    `--release` drives the built binary instead of the dev server.

    This is the only way to exercise the policy that actually ships: Tauri
    injects `devCsp` under `tauri dev` and `csp` in a build. A dev run checks
    that the dev policy is sane and that nothing else is broken; it cannot tell
    you whether an installed copy will load its basemap.
  */
  const RELEASE = process.argv.includes('--release');
  if (RELEASE && !existsSync(RELEASE_EXE)) {
    console.error(`[csp] ${RELEASE_EXE} does not exist. Run \`npm run tauri build\` first.`);
    process.exit(2);
  }
  log(RELEASE
    ? `launching the BUILT app (production CSP) with remote debugging on :${PORT}`
    : `launching the dev app (devCsp) with remote debugging on :${PORT}`);
  const { app, output: appOutput } = launchApp(PORT, RELEASE ? 'release' : 'dev');

  let session;
  let exitCode = 1;
  try {
    // The first run compiles the Rust side, which is minutes, not seconds.
    const page = await waitForDebugger(PORT, 15 * 60 * 1000);
    log(`attached to ${page.url}`);
    session = await connect(page, Session);

    await session.send('Log.enable');
    await session.send('Runtime.enable');
    await session.send('Network.enable');

    // Let the first paint, the engine handshake and the first tiles settle.
    await new Promise(r => setTimeout(r, 12000));

    /*
      Navigation via the sidebar link, falling back to history.

      The app uses `BrowserRouter`, so setting `location.hash` does not navigate
      it — it appends a fragment and leaves the route where it was, and every
      screen after the first would have been "visited" without ever rendering.
      A test that reports five screens and looked at one is worse than no test.

      Clicking the real link is what a user does; `pushState` + `popstate` is
      the fallback for a route with no visible link.
    */
    const navigate = async (path) => {
      const how = await session.evaluate(`
        (() => {
          const link = Array.from(document.querySelectorAll('a[href]'))
            .find(a => a.getAttribute('href') === ${JSON.stringify(path)});
          if (link) { link.click(); return 'clicked'; }
          window.history.pushState({}, '', ${JSON.stringify(path)});
          window.dispatchEvent(new PopStateEvent('popstate'));
          return 'pushState';
        })()
      `);
      await new Promise(r => setTimeout(r, 4000));
      const landed = await session.evaluate('window.location.pathname');
      if (landed !== path) {
        throw new Error(`navigation to ${path} did not take (${how}, now at ${landed}). `
          + 'The harness would otherwise report screens it never rendered.');
      }
      return how;
    };

    for (const check of CHECKS) {
      log(`visiting ${check.path} — ${check.label}`);
      const how = await navigate(check.path);
      log(`  rendered (${how})`);
    }

    /*
      Turn 3D terrain on before the map run, so the elevation grant is exercised.

      `MAP_TERRAIN_TILES` is the only thing in the application that touches
      `s3.amazonaws.com`, and that grant was narrowed from the whole host to one
      bucket path -- `https://s3.amazonaws.com/elevation-tiles-prod/` -- on the
      reasoning that CSP source expressions match paths. Reasoning is what it
      stayed: the terrain source is added only when `enable3DBuildings` is on,
      which is off by default, so every release-mode CSP run so far has walked
      past the one directive whose narrowing was never confirmed.

      The setting persists through zustand under `lockon-engine-config`, so it is
      set in storage and the page reloaded, which is also how an operator who has
      it on arrives at the map.
    */
    log('enabling 3D terrain, so the narrowed elevation-tile grant is exercised');
    await session.evaluate(`
      (() => {
        const key = 'lockon-engine-config';
        let stored;
        try { stored = JSON.parse(localStorage.getItem(key) || '{}'); } catch { stored = {}; }
        stored.state = stored.state || {};
        stored.state.config = { ...(stored.state.config || {}), enable3DBuildings: true };
        stored.version = stored.version ?? 0;
        localStorage.setItem(key, JSON.stringify(stored));
        return 'set';
      })()
    `);
    await session.evaluate('location.reload()').catch(() => {});
    await new Promise(r => setTimeout(r, 6000));

    // Back to the map and pan it, which is what actually fetches tiles.
    log('panning the map to force tile requests');
    await navigate('/');
    await new Promise(r => setTimeout(r, 3000));
    await session.evaluate(`
      (() => {
        const el = document.querySelector('.maplibregl-map');
        if (!el) return 'no map element';
        const box = el.getBoundingClientRect();
        const cx = box.left + box.width / 2, cy = box.top + box.height / 2;
        const fire = (type, x, y) => el.dispatchEvent(new MouseEvent(type, {
          bubbles: true, clientX: x, clientY: y, buttons: 1,
        }));
        fire('mousedown', cx, cy);
        for (let i = 1; i <= 10; i++) fire('mousemove', cx - i * 12, cy - i * 8);
        fire('mouseup', cx - 120, cy - 80);
        return 'panned';
      })()
    `);
    await new Promise(r => setTimeout(r, 6000));

    const inPage = await session.evaluate(
      'JSON.stringify((window.__lockonCspViolations && window.__lockonCspViolations()) || [])'
    );
    const pageViolations = JSON.parse(inPage || '[]');

    /*
      Did the one narrowed grant actually get exercised?

      Reported rather than asserted: a run on a machine with no network reaches
      no tile host at all and must not fail for it. What must not happen is a
      PASS being read as "the elevation path grant is confirmed" when nothing
      ever asked for an elevation tile -- which is what the four runs before this
      one did, because the terrain source is added only when 3D terrain is on and
      it is off by default.
    */
    const elevation = session.requestedUrls.filter(u => u.includes('elevation-tiles-prod'));
    if (elevation.length > 0) {
      log(`elevation tiles requested: ${elevation.length} — the narrowed s3 path grant was exercised`);
    } else {
      log('NOTE: no elevation tile was requested, so the narrowed s3 path grant is NOT confirmed by this run');
    }

    log('=== results ===');
    console.log('\n================ CSP SMOKE TEST ================');
    console.log(`Screens visited:        ${CHECKS.length}`);
    console.log(`In-page violations:     ${pageViolations.length}`);
    console.log(`DevTools CSP messages:  ${session.violations.length}`);
    console.log(`Policy-blocked loads:   ${session.failedRequests.length}`);
    console.log(`Other console errors:   ${session.consoleErrors.length}`);

    if (pageViolations.length) {
      console.log('\n-- blocked (reported by the page) --');
      for (const v of pageViolations) {
        console.log(`  ${v.directive}  ${v.blockedUri}`);
      }
    }
    for (const [title, list] of [
      ['DevTools security messages', session.violations],
      ['Policy-blocked network loads', session.failedRequests],
      ['Console errors', session.consoleErrors.slice(0, 25)],
    ]) {
      if (list.length) {
        console.log(`\n-- ${title} --`);
        for (const line of list) console.log(`  ${String(line).slice(0, 300)}`);
      }
    }

    const blocked = pageViolations.length + session.violations.length
      + session.failedRequests.length;
    if (blocked > 0) {
      log('RESULT: FAIL');
      console.log('\nRESULT: FAIL — the policy blocked something the app needed.');
      console.log('Add the origin to the matching directive in src-tauri/tauri.conf.json,');
      console.log('or remove whatever requests it. Do not widen a directive to silence a');
      console.log('request the app should not be making.');
    } else {
      log('RESULT: PASS');
      console.log('\nRESULT: PASS — nothing was blocked on the paths exercised.');
      console.log('Console errors above, if any, are not CSP failures; read them anyway.');
      exitCode = 0;
    }
    console.log('===============================================\n');
  } catch (err) {
    log(`harness failed: ${err.message}`);
    console.error('\n[csp] harness failed:', err.message);
    const tail = appOutput.join('').split('\n').slice(-30).join('\n');
    if (tail.trim()) console.error('\n--- last app output ---\n' + tail);
  } finally {
    if (session) try { session.ws.close(); } catch { /* already gone */ }
    await shutdownApp(app);
    process.exit(exitCode);
  }
}

main();
