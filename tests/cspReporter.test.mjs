/**
 * Tests for the thing that makes a blocked request say so.
 *
 *     npm run test:csp-reporter
 *
 * Why this exists.
 *
 * A wrong Content-Security-Policy fails silently: the browser blocks the
 * request, the feature it belonged to does not work, and nothing says why — the
 * map renders grey, a font falls back, an export produces a blank page. This
 * module converts that absence into a named failure, and `scripts/csp-smoke-test.mjs`
 * asks it, through `window.__lockonCspViolations()`, whether anything was
 * blocked while it drove the app.
 *
 * So two things have to hold, and neither was covered. **The record has to be
 * complete enough to be worth asking** — if the dedup or the cap dropped the
 * wrong thing, the smoke test would report a clean run over a broken policy,
 * which is the worst possible outcome for a check whose whole job is to notice
 * an absence. And **the console must stay readable**: a policy that blocks a
 * tile server blocks one request per tile, and a line each would bury
 * everything else in the log during a drive.
 */

import test, { beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

/*
  The smallest DOM this module needs: it listens on `document` and, in dev only,
  dispatches a toast on `window`. Both are shimmed before the import so the real
  `installCspReporter` runs unmodified.
*/
const listeners = new Map();
globalThis.document = {
  addEventListener: (type, handler) => {
    const arr = listeners.get(type) ?? [];
    arr.push(handler);
    listeners.set(type, arr);
  },
  removeEventListener: (type, handler) => {
    listeners.set(type, (listeners.get(type) ?? []).filter(h => h !== handler));
  },
};
globalThis.window = globalThis.window ?? {};
globalThis.window.dispatchEvent = () => true;
globalThis.CustomEvent = class { constructor(type, init) { this.type = type; Object.assign(this, init); } };

const { cspViolations, installCspReporter } = await import('../.test-build/cspReporter.mjs');

/** Fire a `securitypolicyviolation` the way the platform would. */
function violate(over = {}) {
  const event = {
    effectiveDirective: 'img-src',
    violatedDirective: 'img-src',
    blockedURI: 'https://tiles.example/1/2/3.png',
    documentURI: 'http://localhost:1420/',
    sourceFile: null,
    lineNumber: 0,
    sample: null,
    ...over,
  };
  for (const h of listeners.get('securitypolicyviolation') ?? []) h(event);
}

let uninstall = null;
let errors = [];
const realError = console.error;

beforeEach(() => {
  errors = [];
  console.error = (...a) => errors.push(a.join(' '));
  uninstall = installCspReporter();
});

afterEach(() => {
  console.error = realError;
  uninstall?.();
});

test('a blocked request is recorded with the directive and the URI that was blocked', () => {
  const before = cspViolations().length;
  violate({ blockedURI: 'https://tiles.example/1/2/3.png' });
  const v = cspViolations().at(-1);
  assert.equal(cspViolations().length, before + 1);
  assert.equal(v.directive, 'img-src');
  assert.equal(v.blockedUri, 'https://tiles.example/1/2/3.png');
  assert.ok(v.at, 'a violation with no timestamp cannot be correlated with anything');
});

test('the console line names the directive, the URI and how to fix it', () => {
  // The whole value of this module is that one line. "The basemap is broken" and
  // "img-src blocked https://tiles.example/..." cost the same to log.
  violate({ blockedURI: 'https://fonts.example/x.woff2', effectiveDirective: 'font-src' });
  const line = errors.at(-1);
  assert.match(line, /\[CSP\]/);
  assert.match(line, /font-src/);
  assert.match(line, /https:\/\/fonts\.example\/x\.woff2/);
  assert.match(line, /tauri\.conf\.json/, 'a message with no remedy is half a message');
});

test('one bad origin logs once, however many requests it blocks', () => {
  /*
    A blocked tile server blocks one request per tile. Without the dedup a single
    misconfigured origin produces hundreds of identical console lines during a
    drive and buries every other message — including the next, different
    violation.

    A distinct origin per test, because `reported` and `seen` are module-level and
    are never reset — deliberately, since one page load is one session. Reusing an
    origin another test already tripped makes this assert 0 and blames the dedup
    for working.
  */
  const before = errors.length;
  for (let i = 0; i < 40; i++) {
    violate({ blockedURI: `https://dedup-origin.example/${i}/${i}/${i}.png` });
  }
  assert.equal(errors.length - before, 1, 'the same directive+origin must log once');
});

test('a different origin under the same directive is still reported', () => {
  // The dedup key is directive+origin, not directive alone — otherwise the first
  // blocked origin would silence every other one.
  const before = errors.length;
  violate({ blockedURI: 'https://a.example/x.png' });
  violate({ blockedURI: 'https://b.example/y.png' });
  assert.equal(errors.length - before, 2);
});

test('a different directive for the same origin is still reported', () => {
  const before = errors.length;
  violate({ blockedURI: 'https://c.example/x', effectiveDirective: 'img-src' });
  violate({ blockedURI: 'https://c.example/x', effectiveDirective: 'connect-src' });
  assert.equal(errors.length - before, 2);
});

test('every blocked request is still recorded even when only one is logged', () => {
  // Deduplication is about the console, not about the record. The smoke test
  // counts the record, and a policy blocking 40 tiles did block 40 requests.
  const before = cspViolations().length;
  for (let i = 0; i < 10; i++) violate({ blockedURI: `https://many.example/${i}.png` });
  assert.equal(cspViolations().length - before, 10);
});

test('an inline violation has a name rather than an empty URI', () => {
  // `blockedURI` is empty for inline script and style. An empty string in the
  // console reads as a truncated message.
  violate({ blockedURI: '', effectiveDirective: 'script-src' });
  assert.equal(cspViolations().at(-1).blockedUri, '(inline)');
});

test('a URI that is not a URL does not break the dedup', () => {
  // `eval`, `inline` and `data` all arrive here, and `new URL()` throws on them.
  assert.doesNotThrow(() => violate({ blockedURI: 'eval', effectiveDirective: 'script-src' }));
  assert.equal(cspViolations().at(-1).blockedUri, 'eval');
});

test('a missing directive is reported as unknown rather than as empty', () => {
  violate({ effectiveDirective: '', violatedDirective: '' });
  assert.equal(cspViolations().at(-1).directive, 'unknown');
});

test('the source location is kept when there is one and null when there is not', () => {
  violate({ sourceFile: 'http://localhost:1420/src/main.tsx', lineNumber: 42 });
  let v = cspViolations().at(-1);
  assert.equal(v.sourceFile, 'http://localhost:1420/src/main.tsx');
  assert.equal(v.line, 42);

  // Line 0 is the platform's "no line", not the first line of the file.
  violate({ sourceFile: null, lineNumber: 0, blockedURI: 'https://noline.example/x' });
  v = cspViolations().at(-1);
  assert.equal(v.sourceFile, null);
  assert.equal(v.line, null);
});

test('the record is a copy, so a reader cannot corrupt it', () => {
  // `window.__lockonCspViolations()` is handed to a smoke test and to anyone at
  // the console. Neither should be able to edit the evidence.
  violate({ blockedURI: 'https://copy.example/x' });
  const first = cspViolations();
  first.push({ directive: 'fabricated' });
  first.length = 0;
  assert.ok(cspViolations().some(v => v.blockedUri === 'https://copy.example/x'));
  assert.ok(!cspViolations().some(v => v.directive === 'fabricated'));
});

test('the record is capped, so a long drive cannot grow it without bound', () => {
  // One violation per blocked tile, for as long as the survey lasts.
  for (let i = 0; i < 250; i++) violate({ blockedURI: `https://flood.example/${i}.png` });
  assert.ok(cspViolations().length <= 100, `recorded ${cspViolations().length}`);
});

test('uninstalling stops the listener', () => {
  // `installCspReporter` returns a cleanup; a listener that survives it would
  // double-count on a remount.
  uninstall();
  uninstall = null;
  const before = cspViolations().length;
  violate({ blockedURI: 'https://after-uninstall.example/x' });
  assert.equal(cspViolations().length, before);
});
