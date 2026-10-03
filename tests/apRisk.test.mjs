/**
 * One question, one answer: is this access point the one to look at first?
 *
 *     npm run test:aprisk
 *
 * Why this exists.
 *
 * A red dot on a map is an answer to that question, and there were two of them.
 *
 * The report's map derived it from the rule set -- `assessAccessPoint` then
 * `worstOf`, HIGH or above -- under a comment saying "so a marker's colour and
 * its row's severity cannot disagree". The live map asked
 * `is_vulnerable || encryption === 'OPEN'`. Those are not the same question, and
 * the gap between them is not a corner case: it is every access point the rule
 * set judges on evidence the engine never set a boolean for.
 *
 * So one mission produced two pictures again. The dot was green on the screen the
 * operator surveys from and red in the document made from the same data, and MAP
 * FILTER -> RISK kept different sets on the two maps.
 *
 * These tests are mostly about the rows where the two definitions disagree,
 * because a test built from rows where they agree would have passed throughout.
 */
import test from 'node:test';
import assert from 'node:assert/strict';

import {
  isHighRiskAp,
  toApInput,
  worstOf,
  assessAccessPoint,
  SEVERITY_ORDER,
} from '../.test-build/apRisk.mjs';

/** What the live map used to ask. Kept so the disagreement can be asserted. */
const theOldWay = (ap) => Boolean(ap.is_vulnerable) || ap.encryption === 'OPEN';

const ap = (over = {}) => ({ bssid: 'AA:BB:CC:DD:EE:01', ssid: 'TEST', encryption: 'WPA2', ...over });

test('an open network is high risk under both, which is why this went unnoticed', () => {
  const open = ap({ encryption: 'OPEN' });
  assert.equal(isHighRiskAp(open), true);
  assert.equal(theOldWay(open), true);
});

test('WEP is high risk although no boolean says so', () => {
  /*
    The shape of the defect. WEP is broken and the rule set says so on the
    encryption alone; `is_vulnerable` is a field the engine sets from its own
    checks and need not be set here at all. Under the old test this was a green
    dot on the live map and a red one in the report.
  */
  const wep = ap({ encryption: 'WEP' });
  assert.equal(isHighRiskAp(wep), true, 'the rule set does not call WEP high risk');
  assert.equal(theOldWay(wep), false, 'the fixture no longer models the disagreement');
});

test('the two definitions are not merely different, they disagree on real rows', () => {
  /*
    Driven over a spread of records rather than one, because the point is not that
    a particular access point was mis-coloured -- it is that the live map was
    answering a question of its own on every row, and nothing compared them.
  */
  const rows = [
    ap({ encryption: 'WEP' }),
    ap({ encryption: 'OPEN', is_vulnerable: false }),
    ap({ encryption: 'WPA2', is_vulnerable: true }),
    ap({ encryption: 'WPA3' }),
    ap({ encryption: 'WPA2', wps_enabled: 1, wps_scanned_at: '2026-01-01T00:00:00Z' }),
    ap({ encryption: 'WPA2', rogue_verdict: 'CONFIRMED', rogue_score: 90 }),
    ap({ encryption: 'WPA', is_evil_twin: true }),
  ];
  const disagreements = rows.filter(r => isHighRiskAp(r) !== theOldWay(r));
  assert.ok(
    disagreements.length > 0,
    'no row distinguishes the two definitions, so this file proves nothing'
  );
});

test('the answer is the rule set\'s, not a second opinion about it', () => {
  // Stated as the identity it is, so a future shortcut here fails rather than
  // quietly reintroducing a parallel threshold.
  for (const row of [
    ap({ encryption: 'WEP' }),
    ap({ encryption: 'OPEN' }),
    ap({ encryption: 'WPA3' }),
    ap({ encryption: 'WPA2', rogue_verdict: 'CONFIRMED', rogue_score: 90 }),
  ]) {
    const expected =
      SEVERITY_ORDER[worstOf(assessAccessPoint(toApInput(row, false))).severity]
      >= SEVERITY_ORDER.HIGH;
    assert.equal(isHighRiskAp(row), expected, row.encryption);
  }
});

test('a simulated sighting is still assessed, and says it was simulated', () => {
  /*
    `simulated` is passed rather than read off the record because a live sighting
    carries it per-row while an archived one inherits it from the report. It must
    not change the verdict -- a rehearsal of a WEP network is still a WEP network
    -- only the provenance the findings carry.
  */
  const wep = ap({ encryption: 'WEP' });
  assert.equal(isHighRiskAp(wep, true), isHighRiskAp(wep, false));
  const findings = assessAccessPoint(toApInput(wep, true));
  assert.ok(findings.length > 0);
  assert.ok(findings.every(f => f.is_simulated === true), 'provenance was dropped');
});

test('a record with nothing in it is not high risk, and does not throw', () => {
  // The live map calls this on every row of every batch, including the first
  // sighting of an access point the engine has barely described.
  for (const thin of [{}, { bssid: '' }, ap({ encryption: undefined })]) {
    assert.equal(typeof isHighRiskAp(thin), 'boolean');
  }
});
