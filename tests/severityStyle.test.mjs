/**
 * Tests for the one colour per severity.
 *
 *     npm run test:severity
 *
 * Why this exists.
 *
 * Six places decided a severity's colour independently, and the disagreements
 * were the kind a reader acts on. The archive telemetry tables drew HIGH in
 * CRITICAL's red at a lighter opacity, so two levels the rule set separates on
 * purpose were one hue apart in the view where a reader scans a long list
 * fastest. The CVE chips tested for CRITICAL and painted everything else as
 * HIGH, so a MEDIUM CVE carried HIGH's border next to its own MEDIUM label.
 *
 * The test that matters most here is the one asserting **no two levels share a
 * colour.** That is the regression, stated directly: a five-level scale the
 * document spends a page explaining is worth nothing if two of the levels look
 * the same. Everything else in this file is about not inventing a severity that
 * was never assessed.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  SEVERITY_CLASSES,
  SEVERITY_LEVELS,
  SEVERITY_RGB,
  UNASSESSED_CLASSES,
  encryptionBadgeClasses,
  encryptionBadgeTitle,
  encryptionTextClass,
  severityClasses,
  severityForEncryption,
  severityRgb,
} from '../.test-build/severityStyle.mjs';

test('the five levels of the rule set all have a colour, on screen and on paper', () => {
  assert.deepEqual(SEVERITY_LEVELS, ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']);
  for (const level of SEVERITY_LEVELS) {
    const c = SEVERITY_CLASSES[level];
    for (const part of ['text', 'bg', 'border', 'dot', 'chip']) {
      assert.equal(typeof c[part], 'string', `${level}.${part}`);
      assert.ok(c[part].length > 0, `${level}.${part} is empty`);
    }
    assert.ok(Array.isArray(SEVERITY_RGB[level]), `${level} has no print colour`);
  }
});

test('no two severities share a screen colour', () => {
  // The regression, stated as an assertion. HIGH used to be CRITICAL's red at a
  // lower opacity in the archive tables, which collapses two levels into one for
  // anybody reading quickly.
  const seen = new Map();
  for (const level of SEVERITY_LEVELS) {
    const text = SEVERITY_CLASSES[level].text;
    assert.ok(!seen.has(text), `${level} and ${seen.get(text)} are both ${text}`);
    seen.set(text, level);
  }
});

test('no two severities share a print colour', () => {
  const seen = new Map();
  for (const level of SEVERITY_LEVELS) {
    const key = SEVERITY_RGB[level].join(',');
    assert.ok(!seen.has(key), `${level} and ${seen.get(key)} print identically`);
    seen.set(key, level);
  }
});

test('print colours are valid RGB, because jsPDF will not complain', () => {
  // An out-of-range component is silently clamped or ignored by jsPDF, so a
  // typo here reaches paper rather than a stack trace.
  for (const level of SEVERITY_LEVELS) {
    const rgb = SEVERITY_RGB[level];
    assert.equal(rgb.length, 3, level);
    assert.ok(rgb.every(c => Number.isInteger(c) && c >= 0 && c <= 255), `${level}: ${rgb}`);
  }
});

test('an unrecognised level falls back to INFO, never to a warning colour', () => {
  /*
    A value this module does not know is an unknown, and painting an unknown red
    asserts a finding the rule set did not make. This is the same rule the risk
    engine follows for an unrecognised security mode: report it as unassessed,
    not as dangerous and not as safe.
  */
  for (const junk of [null, undefined, '', 'SEVERE', 'critical!', 0, false, [], {}, NaN]) {
    assert.deepEqual(severityClasses(junk), SEVERITY_CLASSES.INFO,
      `${JSON.stringify(junk)} must fall back to INFO`);
    assert.deepEqual(severityRgb(junk), SEVERITY_RGB.INFO,
      `${JSON.stringify(junk)} must print as INFO`);
  }
});

test('a level is matched regardless of case', () => {
  // Severities reach the UI from the engine, from SQLite and from imported
  // archives. A lowercase one losing its colour would read as INFO.
  assert.deepEqual(severityClasses('critical'), SEVERITY_CLASSES.CRITICAL);
  assert.deepEqual(severityClasses('Medium'), SEVERITY_CLASSES.MEDIUM);
  assert.deepEqual(severityRgb('high'), SEVERITY_RGB.HIGH);
});

test('every class is written out in the source, where Tailwind can find it', () => {
  /*
    The test that would have caught the bug this file's first version shipped.

    Tailwind builds its stylesheet by scanning source files for complete class
    strings. The first version of `severityStyle.ts` generated them from a token
    — `` text-${token} `` — which produces the correct string at run time and puts
    nothing in the CSS. `.text-risk-medium` was absent from the built stylesheet,
    so every MEDIUM finding rendered with no colour: not the wrong colour, no
    colour, which reads as a rendering glitch rather than as a severity.

    `tsc` passed. The unit tests passed, because they checked the shape of the
    run-time string. The CSP smoke test passed, because the page rendered fine —
    just colourless. The only thing that showed it was grepping the built CSS.

    So this asserts the property that actually matters: each class exists
    verbatim in the module's own source, which is what the scanner reads.
  */
  const source = readFileSync(
    new URL('../src/lib/severityStyle.ts', import.meta.url), 'utf8',
  );
  const shape = /^[a-z-]+-risk-(critical|high|medium|low|info)(\/\d{1,3})?$/;

  for (const level of SEVERITY_LEVELS) {
    const c = SEVERITY_CLASSES[level];
    for (const part of ['text', 'bg', 'border', 'dot']) {
      assert.match(c[part], shape, `${level}.${part}`);
      assert.ok(source.includes(`'${c[part]}'`),
        `${level}.${part} = "${c[part]}" must appear as a literal in severityStyle.ts, `
        + 'or Tailwind will not emit a rule for it');
    }
    assert.equal(c.chip.split(' ').length, 3, `${level}.chip should be bg + text + border`);
    for (const cls of c.chip.split(' ')) assert.match(cls, shape, `${level}.chip`);
    assert.ok(source.includes(`'${c.chip}'`), `${level}.chip must be a literal too`);
  }

  assert.doesNotMatch(source, /['"`][a-z-]*-\$\{/,
    'a class assembled with interpolation is invisible to the Tailwind scanner');
});

test('the chip is exactly the bg, text and border of the same level', () => {
  // A chip built from a different level's parts is how the two systems drifted
  // in the first place.
  for (const level of SEVERITY_LEVELS) {
    const c = SEVERITY_CLASSES[level];
    assert.deepEqual(c.chip.split(' ').sort(), [c.bg, c.text, c.border].sort(), level);
  }
});

test('CRITICAL prints darker than HIGH, which is the convention on paper', () => {
  /*
    Deliberate, and the opposite of the screen palette where CRITICAL is the
    brighter red. On white paper a dark red reads as more serious than a vivid
    one, and the two stay distinguishable after a photocopy — this document gets
    printed and handed over. If the screen palette is ever copied over the print
    table this test fails, which is the intent.
  */
  const luminance = ([r, g, b]) => 0.2126 * r + 0.7152 * g + 0.0722 * b;
  assert.ok(luminance(SEVERITY_RGB.CRITICAL) < luminance(SEVERITY_RGB.HIGH),
    'CRITICAL must be the darker of the two reds in print');
});

// ── Security-mode badges must not be a second risk judgement ────────────────

test('the badge severity for every mode is the one the rule set assigns', () => {
  /*
    Three screens kept their own encryption table and all three disagreed with
    the rules. This asserts the agreement directly, mode by mode, using the
    scores in `ENCRYPTION_RULES`: OPEN 95 and WEP 92 are both CRITICAL, WPA1 is
    72 and therefore HIGH, WPA2 (10) and WPA3 (0) are both INFO — nothing to
    report, which is what "no finding" means.
  */
  assert.equal(severityForEncryption('OPEN'), 'CRITICAL');
  assert.equal(severityForEncryption('WEP'), 'CRITICAL', 'WEP scores 92; it was drawn as HIGH');
  assert.equal(severityForEncryption('WPA'), 'HIGH');
  assert.equal(severityForEncryption('WPA-PSK'), 'HIGH');
  assert.equal(severityForEncryption('WPA2'), 'INFO');
  assert.equal(severityForEncryption('WPA3'), 'INFO');
  assert.equal(severityForEncryption('WPA3-SAE'), 'INFO');
});

test('WPA1 is never drawn in the colour of a healthy network', () => {
  /*
    The regression, named. `TargetDrawer` — in a panel headed THREAT ASSESSMENT —
    painted everything that was not OPEN or WEP green, so a WPA1 network read as
    safe on screen while the report built from the same row called it HIGH. That
    is the pair of statements this project exists to stop producing.
  */
  const wpa1 = encryptionTextClass('WPA');
  assert.equal(wpa1, SEVERITY_CLASSES.HIGH.text);
  assert.notEqual(wpa1, SEVERITY_CLASSES.LOW.text);
  assert.notEqual(wpa1, UNASSESSED_CLASSES.text, 'grey would read as "not assessed"');
  assert.match(encryptionBadgeClasses('WPA'), /risk-high/);
});

test('an unreported security mode is grey, not green and not red', () => {
  /*
    The third state. Every one of the old tables ended in an `else`, and what
    landed there was whatever that screen happened to use — green in one of them.
    "The adapter did not say" is not "this network is fine", and it is not a
    finding either.
  */
  for (const unknown of [null, undefined, '', '   ', 'UNKNOWN', 'unknown']) {
    assert.equal(severityForEncryption(unknown), null, `${JSON.stringify(unknown)}`);
    assert.equal(encryptionTextClass(unknown), UNASSESSED_CLASSES.text);
    assert.equal(encryptionBadgeClasses(unknown), UNASSESSED_CLASSES.chip);
    assert.doesNotMatch(encryptionBadgeClasses(unknown), /risk-/,
      'an unassessed mode must not borrow a severity colour');
  }
});

test('a mode the rules do not recognise is surfaced, not treated as safe', () => {
  // `assessAccessPoint` reports an unrecognised mode at 20 / SUSPECTED rather
  // than dropping it, so the badge has to match that rather than go neutral.
  assert.equal(severityForEncryption('WPA4-QUANTUM'), 'LOW');
  assert.match(encryptionTextClass('WPA4-QUANTUM'), /risk-low/);
});

test('the badge tooltip states the level and where it came from', () => {
  // A colour is an assertion with no stated basis. One hover is the cheapest
  // place to say which rule set produced it.
  assert.match(encryptionBadgeTitle('OPEN'), /CRITICAL/);
  assert.match(encryptionBadgeTitle('OPEN'), /risk rule set/);
  assert.match(encryptionBadgeTitle(null), /not been assessed/);
  assert.match(encryptionBadgeTitle(null), /not a statement that the network is secure/);
});

test('the unassessed style is a literal Tailwind can find, like the rest', () => {
  const source = readFileSync(new URL('../src/lib/severityStyle.ts', import.meta.url), 'utf8');
  for (const cls of [UNASSESSED_CLASSES.text, UNASSESSED_CLASSES.bg]) {
    assert.ok(source.includes(`'${cls}'`), `${cls} must be a literal`);
  }
  assert.ok(source.includes(`'${UNASSESSED_CLASSES.chip}'`));
});
