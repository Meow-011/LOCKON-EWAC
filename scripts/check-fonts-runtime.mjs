#!/usr/bin/env node
/**
 * The shipped app renders in the intended fonts, and asks nobody for them.
 *
 *     npm run check:fonts:runtime        (needs a release build)
 *
 * Why this is separate from `check:fonts`.
 *
 * That one reads files. This one is the only way to answer the question that
 * actually matters, which is what the font stack resolves to *inside the
 * WebView2 that ships* — and the two can disagree in both directions.
 *
 * They disagreed here. A PowerShell font enumeration reported `Segoe UI Variable`
 * as absent and `Bahnschrift Condensed` as present; GDI+ truncates family names
 * at 31 characters and does not expose the typographic families DirectWrite
 * does, so neither answer could be trusted. Measured in the app, `Segoe UI
 * Variable` genuinely does not resolve — Windows registers `Segoe UI Variable
 * Display`, `Text` and `Small`, never the bare name — so that entry in
 * `--font-sans` has never once been used and the stack has always fallen
 * through it to `Segoe UI`.
 *
 * The measurement is width comparison, not `document.fonts.check`, which
 * answers a different question and returns true for a system family whether or
 * not it resolves. Rendering the same string in the candidate stacked in front
 * of a generic and comparing advance widths against that generic alone says
 * whether the candidate was really used. Three generics are tried and two must
 * differ, because a candidate can coincide with one of them by accident.
 *
 * The second half records every request the app makes while it starts and fails
 * if any reaches a font host. The CSP forbids it, and this is the check that the
 * CSP is the reason rather than the network merely happening not to answer.
 */
import { waitForDebugger, launchApp, shutdownApp, connect, cdp, APP_URL_HINTS } from './cdp.mjs';

const PORT = 9226;
const FONT_HOST = /fonts\.(googleapis|gstatic)\.com/;

/** The first name in each stack that must be the one in use. */
const EXPECTED = {
  '--font-sans': 'Inter',
  '--font-mono': 'JetBrains Mono',
  '--font-tactical': 'Rajdhani',
  '--font-tech': 'Share Tech Mono',
};

const PROBE = `(() => {
  const SAMPLE = 'LOCKON EWAC 0123456789 mmmmiiiiwwww';
  const c = document.createElement('canvas').getContext('2d');
  const widthIn = (family) => { c.font = '32px ' + family; return c.measureText(SAMPLE).width; };
  const generics = { serif: widthIn('serif'), 'sans-serif': widthIn('sans-serif'), monospace: widthIn('monospace') };
  const resolves = (name) => {
    let differing = 0;
    for (const [g, w] of Object.entries(generics)) {
      if (Math.abs(widthIn('"' + name + '",' + g) - w) > 0.5) differing++;
    }
    return differing >= 2;
  };
  const read = (v) => getComputedStyle(document.body).getPropertyValue(v).trim();
  const out = {};
  for (const key of ['--font-sans', '--font-mono', '--font-tactical', '--font-tech']) {
    const names = read(key).split(',').map(s => s.trim().replace(/^['"]|['"]$/g, ''));
    out[key] = names.map(n => ({
      name: n,
      resolves: /^(system-ui|sans-serif|serif|monospace|-apple-system)$/.test(n) ? 'generic' : resolves(n),
    }));
  }
  return JSON.stringify(out);
})()`;

const log = (m) => console.log(`[fonts:runtime] ${m}`);
const problems = [];

const app = launchApp(PORT, 'release');
try {
  await waitForDebugger(PORT, 120000);
  const pages = await cdp(PORT, '/json/list');
  const page = pages.find(p => p.type === 'page' && APP_URL_HINTS.some(h => (p.url || '').includes(h)))
    ?? pages.find(p => p.type === 'page');
  if (!page) throw new Error('no page to attach to');
  const session = await connect(page);

  // Requests are recorded from before the reload, so the stylesheet fetch a
  // startup would make is inside the window rather than before it.
  const requests = [];
  // `onEvent` is the hook each harness overrides; `cdp.mjs` uses the browser
  // WebSocket API, which has no EventEmitter `.on()`.
  session.onEvent = (msg) => {
    if (msg.method === 'Network.requestWillBeSent') requests.push(msg.params?.request?.url ?? '');
  };
  await session.send('Network.enable', {});
  await session.evaluate('location.reload()').catch(() => {});
  // The fonts are applied from a stylesheet in the bundle, so they are in place
  // as soon as the document has styled itself; a short settle is enough and the
  // assertion below is what decides, not the wait.
  await new Promise(r => setTimeout(r, 4000));

  const result = JSON.parse(await session.evaluate(PROBE));
  for (const [key, expected] of Object.entries(EXPECTED)) {
    const names = result[key] ?? [];
    const used = names.find(n => n.resolves === true || n.resolves === 'generic');
    log(`${key.padEnd(16)} ${used ? used.name : '(nothing resolved)'}`);
    if (!used || used.name !== expected) {
      problems.push(`${key} renders in ${used ? used.name : 'nothing'}, not ${expected} — the self-hosted face did not load`);
    }
  }

  const reached = requests.filter(u => FONT_HOST.test(u));
  log(`${requests.length} request(s) recorded, ${reached.length} to a font host`);
  for (const u of reached) problems.push(`the app requested ${u}`);
} finally {
  await shutdownApp(app);
}

if (problems.length > 0) {
  console.error('[fonts:runtime] FAIL');
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
log('PASS — the intended faces are in use and no font host was contacted');
