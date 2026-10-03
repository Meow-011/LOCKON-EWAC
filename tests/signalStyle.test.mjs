/**
 * Tests for the one set of signal-strength bands.
 *
 *     npm run test:signal
 *
 * Why this exists.
 *
 * Five surfaces banded RSSI independently and no two agreed. The two that
 * mattered most were offset by a whole band, so an access point at -65 dBm was
 * "fair" in the live feed and "good" in the archive table built from the same
 * reading — one measurement, two descriptions, on screens an operator compares.
 * A third drew signal strength in the **risk** palette, so -75 dBm came out the
 * colour of a warning when it only means the access point was far from the car.
 *
 * Two invariants are worth more than the thresholds themselves, and both have a
 * test here: **a reading that does not exist is not the bottom of the scale**,
 * and **reception is not risk**. The second one is why this module may never
 * reference `risk-*`: a weak access point is not a safer one.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  SIGNAL_BANDS,
  SIGNAL_UNMEASURED,
  signalBand,
  signalBarClass,
  signalBars,
  signalHex,
  signalLabel,
  signalTextClass,
} from '../.test-build/signalStyle.mjs';

test('the bands cover the whole scale with no gap and no overlap', () => {
  // A reading that falls through every band would return undefined and render
  // as no colour, which is the failure mode this project keeps meeting.
  assert.equal(SIGNAL_BANDS.length, 5);
  for (let i = 1; i < SIGNAL_BANDS.length; i++) {
    assert.ok(SIGNAL_BANDS[i].minDbm < SIGNAL_BANDS[i - 1].minDbm,
      'bands must descend, because lookup takes the first match');
  }
  assert.equal(SIGNAL_BANDS[SIGNAL_BANDS.length - 1].minDbm, -Infinity,
    'the last band must be open-ended so nothing falls through');
});

test('the conventional Wi-Fi boundaries land in the band they name', () => {
  const key = rssi => signalBand(rssi).key;
  assert.equal(key(-30), 'STRONG');
  assert.equal(key(-50), 'STRONG');
  assert.equal(key(-51), 'GOOD');
  assert.equal(key(-60), 'GOOD');
  assert.equal(key(-61), 'FAIR');
  assert.equal(key(-70), 'FAIR');
  assert.equal(key(-71), 'WEAK');
  assert.equal(key(-80), 'WEAK');
  assert.equal(key(-81), 'DEAD');
  assert.equal(key(-120), 'DEAD');
});

test('-65 dBm gets one answer, which is the whole point of this module', () => {
  // The exact reading that used to come out "fair" on one screen and "good" on
  // another. There is now one answer, whichever surface asks.
  assert.equal(signalBand(-65).key, 'FAIR');
  assert.equal(signalTextClass(-65), 'text-signal-fair');
  assert.equal(signalBarClass(-65), 'bg-signal-fair');
  assert.equal(signalHex(-65), '#eab308');
  assert.equal(signalBars(-65), 2);
});

test('no reading is unmeasured, not the weakest band', () => {
  /*
    `scan_logs.rssi` used to be written as `ap.rssi ?? -90`, which stored an
    invented reading indistinguishable from an observed -90 and then fed it to
    the localizer. That was fixed on the write side; the display side has to hold
    the same line, or a sighting with no signal reading comes out looking like a
    measurement of an extremely weak one.
  */
  for (const missing of [null, undefined, NaN, Infinity, -Infinity, '-65', '', false, [], {}]) {
    assert.equal(signalBand(missing), null, `${JSON.stringify(missing)} is not a reading`);
    assert.equal(signalTextClass(missing), SIGNAL_UNMEASURED.text);
    assert.equal(signalBarClass(missing), SIGNAL_UNMEASURED.bar);
    assert.equal(signalHex(missing), SIGNAL_UNMEASURED.hex);
  }
  assert.notEqual(SIGNAL_UNMEASURED.text, SIGNAL_BANDS[4].text,
    'unmeasured must not look like the DEAD band');
});

test('zero bars means either the weakest band or no reading, and the colour tells them apart', () => {
  // The bar count collides by necessity — there is no fifth bar to spend — so the
  // colour has to carry the distinction.
  assert.equal(signalBars(-95), 0);
  assert.equal(signalBars(null), 0);
  assert.notEqual(signalBarClass(-95), signalBarClass(null));
});

test('reception is never described with the risk palette', () => {
  /*
    The category error, asserted. Signal strength was drawn in `risk-*` in the
    map popup, so -75 dBm was amber — a warning colour — for being far away. The
    same popup prints the actual severity two elements later in that palette,
    meaning something else. A weak access point is not a safer one, and this
    module must never be able to imply otherwise.
  */
  const source = readFileSync(new URL('../src/lib/signalStyle.ts', import.meta.url), 'utf8');
  const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  assert.doesNotMatch(code, /risk-(critical|high|medium|low|info)/,
    'signalStyle must not reference the risk palette');
  for (const band of SIGNAL_BANDS) {
    assert.doesNotMatch(band.text, /risk-/);
    assert.doesNotMatch(band.bar, /risk-/);
  }
});

test('every band is distinguishable from every other, in class and in hex', () => {
  const texts = new Set(SIGNAL_BANDS.map(b => b.text));
  const hexes = new Set(SIGNAL_BANDS.map(b => b.hex));
  const bars = new Set(SIGNAL_BANDS.map(b => b.bars));
  assert.equal(texts.size, SIGNAL_BANDS.length, 'two bands share a text class');
  assert.equal(hexes.size, SIGNAL_BANDS.length, 'two bands share a hex');
  assert.equal(bars.size, SIGNAL_BANDS.length, 'two bands show the same number of bars');
});

test('every class is written out where Tailwind can find it', () => {
  // Same guard as severityStyle: a class assembled from the band key would put
  // nothing in the stylesheet and render with no colour at all.
  const source = readFileSync(new URL('../src/lib/signalStyle.ts', import.meta.url), 'utf8');
  for (const band of SIGNAL_BANDS) {
    for (const cls of [band.text, band.bar]) {
      assert.match(cls, /^(text|bg)-signal-(strong|good|fair|weak|dead)$/, cls);
      assert.ok(source.includes(`'${cls}'`), `${cls} must appear as a literal`);
    }
    assert.match(band.hex, /^#[0-9a-f]{6}$/, band.hex);
  }
  assert.ok(source.includes(`'${SIGNAL_UNMEASURED.text}'`));
  assert.ok(source.includes(`'${SIGNAL_UNMEASURED.bar}'`));
});

test('the tooltip says what the number means and what it does not', () => {
  // "Weak" invites a reader to treat reception as a property of the network
  // rather than of where it was measured from.
  assert.match(signalLabel(-65), /-65 dBm/);
  assert.match(signalLabel(-65), /Fair/);
  assert.match(signalLabel(-65), /not how secure/);
  assert.match(signalLabel(null), /No signal reading was recorded/);
  assert.match(signalLabel(null), /not a reading of zero/);
});
