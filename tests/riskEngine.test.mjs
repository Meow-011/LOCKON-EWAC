/**
 * Tests for the one rule set that decides every severity in every report.
 *
 *     npm run test:risk
 *
 * Why this exists.
 *
 * `riskEngine.ts` is 440 lines with no test coverage, and it is the single
 * origin of every severity label, every risk score and every headline count the
 * tool prints. README defers the published methodology to it. An audit of this
 * repository found that the modules carrying tests were essentially clean while
 * every defect found sat in an untested one — this file closes the most
 * expensive gap in that list.
 *
 * What these tests are for: the next round of work deliberately changes numbers
 * that come out of this module (CVE matching, rogue verdicts, deduplication,
 * fabricated defaults). Without a recorded baseline there is no way to tell an
 * intended change from a regression.
 *
 * So this file records CURRENT behaviour, which is not the same as endorsing it.
 * Where the recorded behaviour is arguably wrong, the test says so in a comment
 * and still asserts what the code does today. Changing one of those is a
 * deliberate act that should show up as a failing test and a methodology
 * version bump, not as a silent drift in a document someone already signed.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  assessAccessPoint,
  assessHost,
  assessServiceObservations,
  summarise,
  severityForSubject,
  scoreToSeverity,
  describeMethodology,
  SEVERITY_BANDS,
  SEVERITY_ORDER,
  METHODOLOGY_ID,
  METHODOLOGY_VERSION,
  smbObservations,
  tlsObservations,
  dirbusterObservations,
  hostOfUrl,
} from '../.test-build/riskEngine.mjs';

const ap = (over = {}) => ({ bssid: 'AA:BB:CC:DD:EE:FF', ...over });
const host = (over = {}) => ({ ip: '10.0.0.5', ...over });
const only = (findings, category) => findings.filter(f => f.category === category);
const one = (findings, category) => {
  const hits = only(findings, category);
  assert.equal(hits.length, 1, `expected exactly one '${category}' finding, got ${hits.length}`);
  return hits[0];
};

// ── The score → level scale ─────────────────────────────────────────────────

test('every band boundary lands on the level the report prints', () => {
  // Inclusive lower bounds. An off-by-one here silently relabels a whole class
  // of finding in every document.
  assert.equal(scoreToSeverity(100), 'CRITICAL');
  assert.equal(scoreToSeverity(90), 'CRITICAL');
  assert.equal(scoreToSeverity(89), 'HIGH');
  assert.equal(scoreToSeverity(70), 'HIGH');
  assert.equal(scoreToSeverity(69), 'MEDIUM');
  assert.equal(scoreToSeverity(40), 'MEDIUM');
  assert.equal(scoreToSeverity(39), 'LOW');
  assert.equal(scoreToSeverity(15), 'LOW');
  assert.equal(scoreToSeverity(14), 'INFO');
  assert.equal(scoreToSeverity(0), 'INFO');
});

test('a score outside 0-100 is clamped rather than falling through the bands', () => {
  assert.equal(scoreToSeverity(1000), 'CRITICAL');
  assert.equal(scoreToSeverity(-50), 'INFO');
});

test('a fractional score rounds before it is banded', () => {
  assert.equal(scoreToSeverity(89.5), 'CRITICAL'); // rounds to 90
  assert.equal(scoreToSeverity(89.4), 'HIGH');
  assert.equal(scoreToSeverity(14.5), 'LOW');      // rounds to 15
});

test('the bands are ordered high to low, which is what find() relies on', () => {
  for (let i = 1; i < SEVERITY_BANDS.length; i++) {
    assert.ok(
      SEVERITY_BANDS[i - 1].min > SEVERITY_BANDS[i].min,
      'SEVERITY_BANDS must descend, or scoreToSeverity returns the wrong level'
    );
  }
});

// ── The contradiction this module was written to end ────────────────────────

test('WPA1 is HIGH, not LOW — the exact disagreement that produced a self-contradicting PDF', () => {
  // The headline counted WPA1 as vulnerable while the per-row rule
  // (`encryption === 'WEP' || 'OPEN'`) printed the same network as LOW on the
  // same page. One rule set now answers both.
  const f = one(assessAccessPoint(ap({ encryption: 'WPA' })), 'encryption');
  assert.equal(f.risk_score, 72);
  assert.equal(f.severity, 'HIGH');
  assert.equal(f.confidence, 'CONFIRMED');
});

test('the headline count and the per-row label come from the same finding', () => {
  const findings = assessAccessPoint(ap({ encryption: 'WPA' }));
  const summary = summarise(findings);
  assert.equal(summary.worst, 'HIGH');
  assert.equal(summary.significant, 1, 'a HIGH finding must reach the headline figure');
  assert.equal(severityForSubject(findings, 'AA:BB:CC:DD:EE:FF'), 'HIGH');
});

test('open and WEP outrank deprecated WPA1, and all three are reportable', () => {
  const score = enc => one(assessAccessPoint(ap({ encryption: enc })), 'encryption').risk_score;
  assert.equal(score('OPEN'), 95);
  assert.equal(score('WEP'), 92);
  assert.ok(score('OPEN') > score('WEP'), 'no encryption is worse than broken encryption');
  assert.ok(score('WEP') > score('WPA'), 'broken is worse than deprecated');
  assert.equal(scoreToSeverity(score('OPEN')), 'CRITICAL');
  assert.equal(scoreToSeverity(score('WEP')), 'CRITICAL');
});

// ── Encryption strings arrive in several shapes ─────────────────────────────

test('separators and case do not change which rule fires', () => {
  const variants = ['WPA2PSK', 'WPA2-PSK', 'wpa2_psk', 'WPA2 PSK', 'wpa2-PSK'];
  const fingerprints = new Set();
  for (const v of variants) {
    // WPA2 scores below the reporting threshold, so nothing is emitted; the
    // point is that every spelling resolves to the same rule rather than
    // falling through to "unrecognised".
    assert.equal(
      only(assessAccessPoint(ap({ encryption: v })), 'encryption').length, 0,
      `'${v}' should resolve to the WPA2-PSK rule, not be treated as unknown`
    );
  }
  // And for a spelling that IS reportable, the fingerprint is stable across forms.
  for (const v of ['WPAPSK', 'WPA-PSK', 'wpa_psk']) {
    fingerprints.add(one(assessAccessPoint(ap({ encryption: v })), 'encryption').fingerprint);
  }
  assert.equal(fingerprints.size, 1, 'one issue on one AP must have one fingerprint');
});

// ── Station counts as exposure evidence ─────────────────────────────────────
//
// Every OPEN network scores 95 and lands on CRITICAL, so a survey produces a
// page of identical CRITICAL rows — 72 of them at score 95 in one real archive
// on this rig — and the findings table sorts by score, which cannot separate
// them. The BSS Load station count is the observation that can, so it is
// appended to the rationale. These tests exist to keep it evidence rather than
// letting it become a claim.

test('an open network with devices on it says so, and says how many', () => {
  const f = one(assessAccessPoint(ap({ encryption: 'OPEN', connected_stations: 12 })), 'encryption');
  assert.match(f.rationale, /12 devices were associated with it during the survey/);
  assert.match(f.rationale, /exposure\s+in use/, 'the reader needs the conclusion, not only the number');
});

test('one device is not "1 devices"', () => {
  // A report goes to somebody outside the team; the grammar is part of whether
  // it reads as a measurement or as output.
  const f = one(assessAccessPoint(ap({ encryption: 'OPEN', connected_stations: 1 })), 'encryption');
  assert.match(f.rationale, /1 device was associated/);
});

test('a measured zero is reported, and explicitly is not evidence the network is unused', () => {
  // This is the branch that demotes 58 of 72 open networks in a real archive, so
  // it has to be honest about what a short pass can show. Claiming disuse from a
  // 45-second drive-by would be the tool overstating its own observation.
  const f = one(assessAccessPoint(ap({ encryption: 'OPEN', connected_stations: 0 })), 'encryption');
  assert.match(f.rationale, /No device was associated/);
  assert.match(f.rationale, /not evidence the network is unused/);
});

test('an absent station count is not reported as zero devices', () => {
  // "This AP does not publish a count" and "no devices are on this AP" are
  // different observations. Most adapters do not publish the element at all, so
  // this is the common case, not the edge one.
  const silent = one(assessAccessPoint(ap({ encryption: 'OPEN' })), 'encryption');
  assert.doesNotMatch(silent.rationale, /device/i,
    'saying nothing is the only honest option when nothing was measured');

  for (const junk of [null, undefined, '', '3', NaN, Infinity, -1, false, []]) {
    const f = one(assessAccessPoint(ap({ encryption: 'OPEN', connected_stations: junk })), 'encryption');
    assert.equal(f.rationale, silent.rationale,
      `a station count of ${JSON.stringify(junk)} must be treated as unmeasured, not coerced`);
  }
});

test('the station count never moves the score, the severity or the fingerprint', () => {
  // An unlocked network is equally misconfigured whether or not anyone is on it.
  // Scoring a busy one higher would mean scoring a quiet one lower, and would
  // change the severity of an existing finding without the rule set changing —
  // which is what the methodology version is for. The count changes what a
  // reader does first, not what the tool asserts.
  const base = one(assessAccessPoint(ap({ encryption: 'OPEN' })), 'encryption');
  for (const n of [0, 1, 12, 500]) {
    const f = one(assessAccessPoint(ap({ encryption: 'OPEN', connected_stations: n })), 'encryption');
    assert.equal(f.risk_score, base.risk_score);
    assert.equal(f.severity, base.severity);
    assert.equal(f.confidence, base.confidence);
    assert.equal(f.fingerprint, base.fingerprint,
      'a retest must match the same row, so the count cannot be part of identity');
    assert.equal(f.remediation, base.remediation);
  }
});

test('WEP carries the evidence too — its traffic is readable as well', () => {
  const f = one(assessAccessPoint(ap({ encryption: 'WEP', connected_stations: 3 })), 'encryption');
  assert.match(f.rationale, /3 devices were associated/);
});

test('a WPA finding is not padded with a station count', () => {
  // WPA/WPA2 findings are about key strength and offline attack on a captured
  // handshake. Who is associated does not change what to do about them, and
  // printing "no device was associated" under every row would be noise in a
  // document that has to stay readable.
  for (const enc of ['WPA', 'WPA-PSK']) {
    for (const n of [0, 7, undefined]) {
      const f = one(assessAccessPoint(ap({ encryption: enc, connected_stations: n })), 'encryption');
      assert.doesNotMatch(f.rationale, /associated/,
        `${enc} must not carry exposure evidence`);
    }
  }
});

test('the published methodology states what a station count is and is not', () => {
  // The invariant: the appendix a reader audits has to describe the code that
  // ran. The rationale gained a sentence, so the methodology has to account for
  // it — otherwise the document asserts something its own method section does
  // not cover.
  const m = describeMethodology();
  const text = m.limitations.join(' ');
  assert.match(text, /BSS Load/);
  assert.match(text, /does not affect the score/);
  assert.match(text, /reported without one rather than as having none/);
});

// ── An acceptable configuration must not manufacture a finding ──────────────

test('WPA3 raises nothing, because there is nothing to report', () => {
  assert.deepEqual(assessAccessPoint(ap({ encryption: 'WPA3' })), []);
  assert.deepEqual(assessAccessPoint(ap({ encryption: 'WPA3-SAE' })), []);
});

test('WPA2 raises nothing — it scores below the reporting threshold', () => {
  assert.deepEqual(assessAccessPoint(ap({ encryption: 'WPA2' })), []);
  assert.equal(scoreToSeverity(10), 'INFO');
});

test('an absent encryption field is not a finding, and not a clean bill of health either', () => {
  // The engine reports nothing when it could not read the security mode. The
  // rule set must stay silent rather than invent either verdict; saying
  // "no findings" about an unread AP is the report layer's job to caveat.
  assert.deepEqual(assessAccessPoint(ap()), []);
  assert.deepEqual(assessAccessPoint(ap({ encryption: '' })), []);
  assert.deepEqual(assessAccessPoint(ap({ encryption: 'UNKNOWN' })), []);
  assert.deepEqual(assessAccessPoint(ap({ encryption: 'unknown' })), []);
});

test('a security mode with no rule is surfaced as unassessed, not as safe', () => {
  const f = one(assessAccessPoint(ap({ encryption: 'WPA4-QUANTUM' })), 'encryption');
  assert.equal(f.risk_score, 20);
  assert.equal(f.severity, 'LOW');
  assert.equal(f.confidence, 'SUSPECTED');
  assert.match(f.rationale, /does not have a rule for/);
  assert.match(f.rationale, /WPA4-QUANTUM/, 'the unrecognised value itself must be quoted for the reader');
});

// ── WPS ─────────────────────────────────────────────────────────────────────

test('an unknown WPS state raises nothing, so no report may claim WPS was measured', () => {
  // `wps_enabled` is only ever populated by the `scan_wps` command. This module
  // correctly stays silent when it is absent. Any "no WPS observed" wording
  // downstream is therefore a claim this rule set never made.
  assert.equal(only(assessAccessPoint(ap({ encryption: 'WPA2' })), 'wps').length, 0);
  assert.equal(only(assessAccessPoint(ap({ wps_enabled: undefined })), 'wps').length, 0);
  assert.equal(only(assessAccessPoint(ap({ wps_enabled: false })), 'wps').length, 0);
});

test('unlocked WPS is HIGH and defeats an otherwise sound WPA2 setup', () => {
  const findings = assessAccessPoint(ap({ encryption: 'WPA2', wps_enabled: true }));
  const f = one(findings, 'wps');
  assert.equal(f.risk_score, 75);
  assert.equal(f.severity, 'HIGH');
  assert.equal(f.confidence, 'CONFIRMED');
  // The whole reason a binary encryption verdict was not enough.
  assert.equal(summarise(findings).significant, 1);
  assert.equal(only(findings, 'encryption').length, 0, 'WPA2 itself is still not a finding');
});

test('rate-limited WPS drops two bands, from HIGH to LOW', () => {
  // 35 sits below the MEDIUM floor of 40, so a locked WPS AP is reported at
  // LOW. Worth knowing when reading a report: the same feature is HIGH or LOW
  // depending only on whether the firmware rate-limits, with nothing in
  // between, and `describeMethodology` publishes both numbers.
  const f = one(assessAccessPoint(ap({ wps_enabled: true, wps_locked: true })), 'wps');
  assert.equal(f.risk_score, 35);
  assert.equal(f.severity, 'LOW');
  assert.match(f.rationale, /rate-limiting/);
  assert.match(f.title, /rate-limited/);
});

// ── Rogue AP: severity and confidence are separate axes ─────────────────────

test('a CLEAR or absent verdict raises no rogue finding', () => {
  assert.equal(only(assessAccessPoint(ap({ rogue_verdict: 'CLEAR' })), 'rogue_ap').length, 0);
  assert.equal(only(assessAccessPoint(ap({ rogue_verdict: '' })), 'rogue_ap').length, 0);
  assert.equal(only(assessAccessPoint(ap()), 'rogue_ap').length, 0);
});

test('each rogue verdict maps to its own score and its own confidence', () => {
  const at = verdict => one(assessAccessPoint(ap({ rogue_verdict: verdict })), 'rogue_ap');

  const confirmed = at('CONFIRMED');
  assert.equal(confirmed.risk_score, 90);
  assert.equal(confirmed.severity, 'CRITICAL');
  assert.equal(confirmed.confidence, 'CONFIRMED');

  const likely = at('LIKELY');
  assert.equal(likely.risk_score, 75);
  assert.equal(likely.severity, 'HIGH');
  assert.equal(likely.confidence, 'LIKELY');

  const suspected = at('SUSPECTED');
  assert.equal(suspected.confidence, 'SUSPECTED');
  // The rogue rule is the one place where verdict strength scales severity too,
  // and that is now stated as an exception in the module docstring and in the
  // report prose rather than contradicted by both. The reason it stays: the
  // headline figure is severity-only, so without this ladder every unconfirmed
  // suspicion would inflate the number a manager reads first.
  assert.equal(suspected.risk_score, 45);
  assert.equal(suspected.severity, 'MEDIUM');
});

test('the rogue ladder is monotonic in the verdict, which is what keeps it defensible', () => {
  const score = v => one(assessAccessPoint(ap({ rogue_verdict: v })), 'rogue_ap').risk_score;
  assert.ok(score('CONFIRMED') > score('LIKELY'), 'a confirmed rogue must outrank a likely one');
  assert.ok(score('LIKELY') > score('SUSPECTED'), 'a likely rogue must outrank a suspected one');
});

test('a low confidence never raises a severity, on any rule', () => {
  // The weaker half of the claim the report makes, and the half that is true:
  // uncertainty may hold a score down but never pushes one up.
  const confirmed = one(assessAccessPoint(ap({ rogue_verdict: 'CONFIRMED' })), 'rogue_ap');
  for (const v of ['LIKELY', 'SUSPECTED']) {
    const weaker = one(assessAccessPoint(ap({ rogue_verdict: v })), 'rogue_ap');
    assert.ok(weaker.risk_score <= confirmed.risk_score, `${v} must not outrank CONFIRMED`);
  }
});

test('a lowercase verdict from the engine is still honoured', () => {
  const f = one(assessAccessPoint(ap({ rogue_verdict: 'confirmed' })), 'rogue_ap');
  assert.equal(f.severity, 'CRITICAL');
});

test('a suspected rogue is never reduced to INFO, whatever its confidence', () => {
  for (const v of ['SUSPECTED', 'LIKELY', 'CONFIRMED']) {
    const f = one(assessAccessPoint(ap({ rogue_verdict: v })), 'rogue_ap');
    assert.ok(SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER.MEDIUM, `${v} must stay reportable`);
  }
});

test('the indicators the engine scored are quoted as the reason', () => {
  const f = one(assessAccessPoint(ap({
    rogue_verdict: 'LIKELY',
    rogue_indicators: [
      { code: 'ssid_encryption_split', weight: 3, detail: 'Same SSID advertised with two encryption types.' },
      { code: 'vendor_mismatch', weight: 2, detail: 'BSSID vendor differs from its peers.' },
    ],
  })), 'rogue_ap');
  assert.match(f.rationale, /Same SSID advertised with two encryption types\./);
  assert.match(f.rationale, /BSSID vendor differs from its peers\./);
});

test('a verdict with no indicators still states why it was raised', () => {
  const f = one(assessAccessPoint(ap({ rogue_verdict: 'LIKELY' })), 'rogue_ap');
  assert.ok(f.rationale.length > 0, 'rationale is never empty — a label a reader cannot audit is not evidence');
  assert.match(f.rationale, /above the reporting threshold/);
});

// ── Every finding carries what makes it auditable ───────────────────────────

test('no finding ever ships without a rationale, a methodology tag and a fingerprint', () => {
  const findings = [
    ...assessAccessPoint(ap({ encryption: 'OPEN', wps_enabled: true, rogue_verdict: 'LIKELY' })),
    ...assessAccessPoint(ap({ encryption: 'MYSTERY-MODE' })),
    ...assessHost(host({
      default_creds: { username: 'admin', password: 'admin' },
      snmp_communities: ['public'],
      open_ports: [{ port: 23, service: 'telnet', cves: [{ cve: 'CVE-2020-1', severity: 'HIGH' }] }],
    })),
  ];
  assert.ok(findings.length >= 7, 'sanity: the fixture should produce a spread of findings');
  for (const f of findings) {
    assert.ok(f.rationale && f.rationale.trim().length > 0, `${f.category} has no rationale`);
    assert.equal(f.methodology.startsWith(`${METHODOLOGY_ID}@${METHODOLOGY_VERSION}/`), true, f.methodology);
    assert.ok(f.fingerprint && f.fingerprint.length > 0, `${f.category} has no fingerprint`);
    assert.equal(f.severity, scoreToSeverity(f.risk_score), `${f.category}: label disagrees with its own score`);
    assert.ok(['SUSPECTED', 'LIKELY', 'CONFIRMED'].includes(f.confidence), f.confidence);
  }
});

test('a fingerprint is stable across runs, so a retest recognises the same issue', () => {
  const input = ap({ encryption: 'OPEN', wps_enabled: true, rogue_verdict: 'LIKELY' });
  const a = assessAccessPoint(input).map(f => f.fingerprint);
  const b = assessAccessPoint(input).map(f => f.fingerprint);
  assert.deepEqual(a, b);
});

test('a fingerprint ignores BSSID letter case, so one device is not two rows', () => {
  const upper = assessAccessPoint(ap({ bssid: 'AA:BB:CC:DD:EE:FF', encryption: 'OPEN' }))[0].fingerprint;
  const lower = assessAccessPoint(ap({ bssid: 'aa:bb:cc:dd:ee:ff', encryption: 'OPEN' }))[0].fingerprint;
  assert.equal(upper, lower);
});

test('different issues on one device get different fingerprints', () => {
  const findings = assessAccessPoint(ap({ encryption: 'OPEN', wps_enabled: true, rogue_verdict: 'LIKELY' }));
  const prints = findings.map(f => f.fingerprint);
  assert.equal(new Set(prints).size, prints.length, 'three issues must not collapse into one row');
});

test('the fingerprint does not move when the score does', () => {
  // Identity is subject + issue, never a score or a timestamp. If this breaks,
  // every retest reports every finding as newly discovered.
  const locked = assessAccessPoint(ap({ wps_enabled: true, wps_locked: true }))[0];
  const unlocked = assessAccessPoint(ap({ wps_enabled: true, wps_locked: false }))[0];
  assert.notEqual(locked.risk_score, unlocked.risk_score);
  assert.equal(locked.fingerprint, unlocked.fingerprint);
});

test('the simulated flag travels with the finding in both spellings', () => {
  assert.equal(assessAccessPoint(ap({ encryption: 'OPEN', simulated: true }))[0].is_simulated, true);
  assert.equal(assessAccessPoint(ap({ encryption: 'OPEN', is_simulated: 1 }))[0].is_simulated, true);
  assert.equal(assessAccessPoint(ap({ encryption: 'OPEN' }))[0].is_simulated, false);
});

// ── Hosts ───────────────────────────────────────────────────────────────────

test('an empty host produces no findings at all', () => {
  assert.deepEqual(assessHost(host()), []);
  assert.deepEqual(assessHost(host({ open_ports: [] })), []);
});

test('a recovered credential is the one finding scored at the ceiling', () => {
  const f = one(assessHost(host({ default_creds: { username: 'admin', password: 'admin' } })), 'credentials');
  assert.equal(f.risk_score, 100);
  assert.equal(f.severity, 'CRITICAL');
  assert.equal(f.confidence, 'CONFIRMED');
  assert.match(f.rationale, /demonstrated access, not a theoretical weakness/);
  assert.match(f.rationale, /admin/);
});

test('credentials with no username are not a finding', () => {
  assert.equal(only(assessHost(host({ default_creds: { username: '' } })), 'credentials').length, 0);
});

test('a CVE from a banner is LIKELY and says it was not exploited', () => {
  const f = one(assessHost(host({
    open_ports: [{ port: 6379, service: 'redis', cves: [{ cve: 'CVE-2022-0543', severity: 'CRITICAL', description: 'Lua sandbox escape.' }] }],
  })), 'service_cve');
  assert.equal(f.risk_score, 95);
  assert.equal(f.severity, 'CRITICAL');
  // A banner match is never CONFIRMED, however severe the CVE.
  assert.equal(f.confidence, 'LIKELY');
  assert.match(f.rationale, /not exploited during this assessment/);
  assert.match(f.rationale, /port 6379/);
});

test('a CVE whose severity was never established is scored 40 and prints MEDIUM', () => {
  // RECORDED, NOT ENDORSED. `cve_feed.py` emits severity "UNKNOWN" whenever the
  // record carries no CVSS metric, and an unknown severity becomes a MEDIUM
  // with nothing marking that it was never established.
  const noSeverity = one(assessHost(host({
    open_ports: [{ port: 80, cves: [{ cve: 'CVE-2024-0001' }] }],
  })), 'service_cve');
  assert.equal(noSeverity.risk_score, 40);
  assert.equal(noSeverity.severity, 'MEDIUM');

  const explicitUnknown = one(assessHost(host({
    open_ports: [{ port: 80, cves: [{ cve: 'CVE-2024-0002', severity: 'UNKNOWN' }] }],
  })), 'service_cve');
  assert.equal(explicitUnknown.risk_score, 40);

  const nonsense = one(assessHost(host({
    open_ports: [{ port: 80, cves: [{ cve: 'CVE-2024-0003', severity: 'WOBBLY' }] }],
  })), 'service_cve');
  assert.equal(nonsense.risk_score, 40, 'an unrecognised severity must not throw or score 0');
});

test('one CVE per port per id, each with its own fingerprint', () => {
  const findings = only(assessHost(host({
    open_ports: [
      { port: 80, cves: [{ cve: 'CVE-1', severity: 'HIGH' }, { cve: 'CVE-2', severity: 'LOW' }] },
      { port: 443, cves: [{ cve: 'CVE-1', severity: 'HIGH' }] },
    ],
  })), 'service_cve');
  assert.equal(findings.length, 3);
  assert.equal(new Set(findings.map(f => f.fingerprint)).size, 3, 'the same CVE on two ports is two findings');
});

test('an exposed service is CONFIRMED, because reachability was observed', () => {
  const f = one(assessHost(host({ open_ports: [{ port: 23, service: 'telnet' }] })), 'exposed_service');
  assert.equal(f.risk_score, 85);
  assert.equal(f.severity, 'HIGH');
  assert.equal(f.confidence, 'CONFIRMED');
  assert.match(f.rationale, /Confirmed reachable/);
});

test('a port with no exposure rule contributes nothing', () => {
  assert.deepEqual(assessHost(host({ open_ports: [{ port: 8081 }, { port: 49152 }] })), []);
});

test('cleartext protocols outrank database exposure, which outranks nothing at all', () => {
  const score = port => one(assessHost(host({ open_ports: [{ port }] })), 'exposed_service').risk_score;
  assert.ok(score(23) > score(21), 'telnet is worse than FTP');
  assert.ok(score(6379) > score(3306), 'an unauthenticated Redis is worse than a reachable MySQL');
  assert.equal(scoreToSeverity(score(23)), 'HIGH');
});

test('a default SNMP community is a confirmed disclosure and counts what answered', () => {
  const f = one(assessHost(host({ snmp_communities: ['public', 'private'] })), 'snmp');
  assert.equal(f.risk_score, 70);
  assert.equal(f.severity, 'HIGH');
  assert.equal(f.confidence, 'CONFIRMED');
  assert.match(f.rationale, /2 well-known community string/);
});

test('an empty SNMP list is not a finding', () => {
  assert.equal(only(assessHost(host({ snmp_communities: [] })), 'snmp').length, 0);
});

test('a hostname is used in the label when present, and the IP alone when not', () => {
  const named = assessHost(host({ hostname: 'nas01', open_ports: [{ port: 23 }] }))[0];
  assert.match(named.title, /nas01 \(10\.0\.0\.5\)/);
  const bare = assessHost(host({ open_ports: [{ port: 23 }] }))[0];
  assert.match(bare.title, /10\.0\.0\.5/);
  assert.doesNotMatch(bare.title, /undefined/, 'a missing hostname must never print as "undefined"');
});

test('an AP label never prints undefined when the SSID is hidden', () => {
  const f = assessAccessPoint(ap({ encryption: 'OPEN' }))[0];
  assert.doesNotMatch(f.title, /undefined/);
  assert.match(f.title, /AA:BB:CC:DD:EE:FF/);
});

// ── Service observations from the deep inspection modules ──────────────────

test('a service observation becomes a finding this report can carry', () => {
  // These reached no further than React state before: `findings` was written
  // from two places only, so an unauthenticated Redis appeared on screen at
  // CRITICAL while the PDF raised nothing for that host.
  const f = assessServiceObservations('10.0.0.5', [
    { code: 'redis_no_auth', port: 6379, description: 'Redis answered INFO without auth.' },
  ]);
  assert.equal(f.length, 1);
  assert.equal(f[0].subject_type, 'HOST');
  assert.equal(f[0].subject_id, '10.0.0.5');
  assert.equal(f[0].category, 'service_config');
  assert.equal(f[0].severity, 'CRITICAL');
  assert.equal(f[0].confidence, 'CONFIRMED');
});

test('the severity comes from this rule set, never from the engine label', () => {
  // `vuln_engine.py` hardcodes its own severity per check and its `cve` field
  // carries CWE ids and the literal string "N/A". Neither may reach a document
  // that claims one rule set decides every severity.
  const f = assessServiceObservations('10.0.0.5', [
    { code: 'mysql_exposed', port: 3306, severity: 'CRITICAL', cve: 'N/A' },
  ]);
  assert.equal(f[0].risk_score, 55, 'the engine said CRITICAL; the rule set decides');
  assert.equal(f[0].severity, 'MEDIUM');
  assert.ok(!('cve' in f[0]), 'a CWE id must not travel as a CVE');
});

test('a demonstrated weakness is CONFIRMED and a banner reading is not', () => {
  const demonstrated = assessServiceObservations('10.0.0.5', [{ code: 'ftp_anonymous', port: 21 }]);
  assert.equal(demonstrated[0].confidence, 'CONFIRMED');
  assert.match(demonstrated[0].rationale, /not an inference from a banner/);

  const inferred = assessServiceObservations('10.0.0.5', [{ code: 'ssh_openssh_outdated', port: 22 }]);
  assert.equal(inferred[0].confidence, 'SUSPECTED');
  assert.match(inferred[0].rationale, /banner reading only/);
  assert.match(inferred[0].rationale, /backport/, 'the reader must be told why a banner can mislead');
});

test('an unrecognised observation is reported, but never at an assessed severity', () => {
  // Dropping it would hide a real observation; trusting the engine's label would
  // put a number in the report that no rule set produced.
  const f = assessServiceObservations('10.0.0.5', [
    { code: 'some_future_check', port: 1234, vuln: 'Mystery Finding', severity: 'CRITICAL' },
  ]);
  assert.equal(f.length, 1);
  assert.equal(f[0].risk_score, 20);
  assert.equal(f[0].severity, 'LOW');
  assert.equal(f[0].confidence, 'SUSPECTED');
  assert.match(f[0].rationale, /no severity was independently assessed/);
  assert.match(f[0].rationale, /Mystery Finding/, 'the original label must survive for the reader');
  assert.equal(summarise(f).significant, 0, 'an unassessed observation must not reach the headline figure');
});

test('an observation with no target is dropped rather than attributed to nothing', () => {
  assert.deepEqual(assessServiceObservations('', [{ code: 'ftp_anonymous' }]), []);
  assert.deepEqual(assessServiceObservations('   ', [{ code: 'ftp_anonymous' }]), []);
});

test('an empty or missing observation list produces nothing', () => {
  assert.deepEqual(assessServiceObservations('10.0.0.5', []), []);
  assert.deepEqual(assessServiceObservations('10.0.0.5', undefined), []);
});

test('two findings on one host keep separate fingerprints, and repeat scans match', () => {
  const obs = [
    { code: 'ftp_anonymous', port: 21 },
    { code: 'telnet_cleartext', port: 23 },
  ];
  const first = assessServiceObservations('10.0.0.5', obs);
  const second = assessServiceObservations('10.0.0.5', obs);
  assert.equal(new Set(first.map(f => f.fingerprint)).size, 2);
  assert.deepEqual(first.map(f => f.fingerprint), second.map(f => f.fingerprint));
});

test('the same check on two ports is two findings', () => {
  const f = assessServiceObservations('10.0.0.5', [
    { code: 'http_server_version', port: 80 },
    { code: 'http_server_version', port: 8080 },
  ]);
  assert.equal(f.length, 2);
  assert.equal(new Set(f.map(x => x.fingerprint)).size, 2);
});

test('every service finding carries the auditable fields', () => {
  const codes = Object.keys(describeMethodology().rules.service_config);
  assert.ok(codes.length >= 10, 'the published rule table should cover the engine checks');
  for (const code of codes) {
    const f = assessServiceObservations('10.0.0.5', [{ code, port: 80 }])[0];
    assert.ok(f.rationale.trim().length > 0, `${code} has no rationale`);
    assert.ok(f.remediation && f.remediation.trim().length > 0, `${code} has no remediation`);
    assert.equal(f.severity, scoreToSeverity(f.risk_score), `${code}: label disagrees with score`);
    assert.match(f.methodology, /service_config\//);
  }
});

test('the published service scores are the scores the assessor applies', () => {
  const published = describeMethodology().rules.service_config;
  for (const [code, rule] of Object.entries(published)) {
    const f = assessServiceObservations('10.0.0.5', [{ code, port: 80 }])[0];
    assert.equal(f.risk_score, rule.score, `published score for ${code} is not the one applied`);
    assert.equal(f.confidence, rule.confidence, `published confidence for ${code} is not the one applied`);
    assert.equal(rule.level, scoreToSeverity(rule.score));
  }
});

test('the engine detail is preserved in the rationale, not replaced by it', () => {
  const f = assessServiceObservations('10.0.0.5', [
    { code: 'ftp_anonymous', port: 21, description: 'Banner said vsFTPd 3.0.3.' },
  ])[0];
  assert.match(f.rationale, /Banner said vsFTPd 3\.0\.3\./);
  assert.match(f.rationale, /accepted an anonymous login/, 'the rule set rationale must still lead');
});

test('the methodology tells the reader what a service finding is based on', () => {
  const limitations = describeMethodology().limitations;
  assert.ok(
    limitations.some(l => /Service-configuration findings/.test(l)),
    'the report must explain that some service findings are demonstrated and some are banner-read'
  );
});

// ── Aggregation ─────────────────────────────────────────────────────────────

test('the headline figure is CRITICAL plus HIGH, and nothing else', () => {
  const findings = [
    ...assessAccessPoint(ap({ bssid: '00:00:00:00:00:01', encryption: 'OPEN' })),   // 95 CRITICAL
    ...assessAccessPoint(ap({ bssid: '00:00:00:00:00:02', encryption: 'WPA' })),    // 72 HIGH
    ...assessAccessPoint(ap({ bssid: '00:00:00:00:00:03', rogue_verdict: 'SUSPECTED' })), // 45 MEDIUM
    ...assessAccessPoint(ap({ bssid: '00:00:00:00:00:04', encryption: 'ODD-MODE' })),     // 20 LOW
  ];
  const s = summarise(findings);
  assert.equal(s.total, 4);
  assert.equal(s.bySeverity.CRITICAL, 1);
  assert.equal(s.bySeverity.HIGH, 1);
  assert.equal(s.bySeverity.MEDIUM, 1);
  assert.equal(s.bySeverity.LOW, 1);
  assert.equal(s.bySeverity.INFO, 0);
  assert.equal(s.significant, 2);
  assert.equal(s.worst, 'CRITICAL');
});

test('confidence is counted separately from severity', () => {
  const findings = [
    ...assessAccessPoint(ap({ bssid: '00:00:00:00:00:01', encryption: 'OPEN' })),        // CONFIRMED
    ...assessAccessPoint(ap({ bssid: '00:00:00:00:00:02', rogue_verdict: 'SUSPECTED' })), // SUSPECTED
    ...assessHost(host({ open_ports: [{ port: 80, cves: [{ cve: 'CVE-X', severity: 'HIGH' }] }] })), // LIKELY
  ];
  const s = summarise(findings);
  assert.equal(s.byConfidence.CONFIRMED, 1);
  assert.equal(s.byConfidence.SUSPECTED, 1);
  assert.equal(s.byConfidence.LIKELY, 1);
  assert.equal(s.total, 3);
});

test('an empty finding set has no worst severity, rather than an INFO verdict', () => {
  // `worst` was 'INFO' here, which the report printed as "Highest severity
  // present: INFO" for an archive containing no access points at all — a verdict
  // where none was possible, and indistinguishable from a real assessment whose
  // worst finding was informational. Same class of defect as reading an absent
  // numeric column as a hard zero, so it is null now and the caller must choose
  // which sentence to print.
  const s = summarise([]);
  assert.equal(s.total, 0);
  assert.equal(s.significant, 0);
  assert.equal(s.worst, null);
  assert.deepEqual(s.bySeverity, { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 });
});

test('a genuine INFO finding is still distinguishable from no findings at all', () => {
  // The distinction only means something if a real INFO result still reads as
  // INFO. No current rule emits one (everything below 15 is suppressed), so this
  // asserts the aggregation rather than the rules.
  const info = {
    subject_type: 'AP', subject_id: 'AA:BB:CC:DD:EE:FF', category: 'test',
    title: 'informational', severity: 'INFO', risk_score: 5,
    confidence: 'CONFIRMED', rationale: 'x', methodology: 'test', fingerprint: 'x',
  };
  const s = summarise([info]);
  assert.equal(s.worst, 'INFO');
  assert.equal(s.total, 1);
  assert.notEqual(s.worst, summarise([]).worst, 'an INFO result must not look like an empty one');
});

test('summarise does not mutate or reorder what it is given', () => {
  const findings = assessAccessPoint(ap({ encryption: 'OPEN', wps_enabled: true }));
  const before = JSON.stringify(findings);
  summarise(findings);
  assert.equal(JSON.stringify(findings), before);
});

test('a per-subject label ignores every other subject, whatever the case', () => {
  const findings = [
    ...assessAccessPoint(ap({ bssid: 'AA:AA:AA:AA:AA:AA', encryption: 'OPEN' })), // CRITICAL
    ...assessAccessPoint(ap({ bssid: 'BB:BB:BB:BB:BB:BB', encryption: 'ODD' })),  // LOW
  ];
  assert.equal(severityForSubject(findings, 'BB:BB:BB:BB:BB:BB'), 'LOW');
  assert.equal(severityForSubject(findings, 'bb:bb:bb:bb:bb:bb'), 'LOW');
  assert.equal(severityForSubject(findings, 'AA:AA:AA:AA:AA:AA'), 'CRITICAL');
});

test('a subject with no findings has no severity, so a table row cannot imply one', () => {
  assert.equal(severityForSubject([], 'AA:AA:AA:AA:AA:AA'), null);
  // And a subject absent from a non-empty set is equally unranked.
  const others = assessAccessPoint(ap({ bssid: 'AA:AA:AA:AA:AA:AA', encryption: 'OPEN' }));
  assert.equal(severityForSubject(others, 'FF:FF:FF:FF:FF:FF'), null);
});

// ── The published methodology must not drift from the code ──────────────────

test('every encryption level the methodology prints matches the banding of its own score', () => {
  const m = describeMethodology();
  for (const [key, rule] of Object.entries(m.rules.encryption)) {
    assert.equal(rule.level, scoreToSeverity(rule.score), `printed level for ${key} disagrees with its score`);
  }
});

test('the methodology block states the same encryption scores the assessor applies', () => {
  const m = describeMethodology();
  for (const [key, rule] of Object.entries(m.rules.encryption)) {
    const findings = only(assessAccessPoint(ap({ encryption: key })), 'encryption');
    if (rule.score >= 15) {
      assert.equal(findings.length, 1, `${key} is published as reportable but raises nothing`);
      assert.equal(findings[0].risk_score, rule.score, `${key}: published score is not the score used`);
    } else {
      assert.equal(findings.length, 0, `${key} scores below the threshold but still raised a finding`);
    }
  }
});

test('the published WPS scores are the scores the assessor uses', () => {
  const m = describeMethodology();
  assert.equal(
    one(assessAccessPoint(ap({ wps_enabled: true })), 'wps').risk_score,
    m.rules.wps.enabled_unlocked
  );
  assert.equal(
    one(assessAccessPoint(ap({ wps_enabled: true, wps_locked: true })), 'wps').risk_score,
    m.rules.wps.enabled_locked
  );
});

test('the published rogue-AP scores are the scores the assessor uses', () => {
  const m = describeMethodology();
  for (const verdict of ['CONFIRMED', 'LIKELY', 'SUSPECTED']) {
    assert.equal(
      one(assessAccessPoint(ap({ rogue_verdict: verdict })), 'rogue_ap').risk_score,
      m.rules.rogue_ap[verdict],
      `published rogue score for ${verdict} is not the one applied`
    );
  }
});

test('every published exposed-service score is the score the assessor uses', () => {
  const m = describeMethodology();
  for (const [portStr, rule] of Object.entries(m.rules.exposed_service)) {
    const f = one(assessHost(host({ open_ports: [{ port: Number(portStr) }] })), 'exposed_service');
    assert.equal(f.risk_score, rule.score, `published score for port ${portStr} is not the one applied`);
    assert.match(f.title, new RegExp(rule.name), `published name for port ${portStr} is not the one printed`);
  }
});

test('every published CVE severity score is the score the assessor uses', () => {
  const m = describeMethodology();
  for (const [severity, score] of Object.entries(m.rules.service_cve)) {
    const f = one(assessHost(host({
      open_ports: [{ port: 80, cves: [{ cve: 'CVE-TEST', severity }] }],
    })), 'service_cve');
    assert.equal(f.risk_score, score, `published score for ${severity} is not the one applied`);
  }
});

test('the published credential and SNMP scores are the ones applied', () => {
  const m = describeMethodology();
  assert.equal(
    one(assessHost(host({ default_creds: { username: 'root' } })), 'credentials').risk_score,
    m.rules.credentials.recovered
  );
  assert.equal(
    one(assessHost(host({ snmp_communities: ['public'] })), 'snmp').risk_score,
    m.rules.snmp.default_community
  );
});

test('the methodology publishes the same bands the banding function uses', () => {
  assert.deepEqual(describeMethodology().bands, SEVERITY_BANDS);
});

test('the methodology names a confidence meaning for every confidence a finding can carry', () => {
  const m = describeMethodology();
  for (const level of ['CONFIRMED', 'LIKELY', 'SUSPECTED']) {
    assert.ok(m.confidence_meaning[level], `no published meaning for ${level}`);
  }
});

test('the methodology states its limitations, including that absence is not proof', () => {
  const m = describeMethodology();
  assert.ok(Array.isArray(m.limitations) && m.limitations.length >= 3);
  assert.ok(
    m.limitations.some(l => /Absence of a finding is not proof/.test(l)),
    'the report must keep carrying the statement that a clean result is not a guarantee'
  );
  assert.ok(
    m.limitations.some(l => /banner/.test(l)),
    'the report must keep stating that CVE findings come from banners and were not exploited'
  );
});

test('the methodology identifies itself, so a label in a document can be traced to a version', () => {
  const m = describeMethodology();
  assert.equal(m.id, METHODOLOGY_ID);
  assert.equal(m.version, METHODOLOGY_VERSION);
  assert.equal(typeof m.version, 'number');
  // A findings row records the tag; the report prints the version. They must agree.
  const f = assessAccessPoint(ap({ encryption: 'OPEN' }))[0];
  assert.equal(f.methodology, `${m.id}@${m.version}/encryption`);
});

// ── Deep-inspection adapters ────────────────────────────────────────────────
//
// These convert an engine payload into observations the rule set can score.
// They are the boundary where the engine's honest tri-state answers used to be
// flattened, so each of the three states gets an explicit test.

test('SMBv1 enabled becomes a CONFIRMED HIGH finding against the host', () => {
  const obs = smbObservations({ target: '10.0.0.7', smbv1_enabled: true, signing_required: true });
  assert.equal(obs.length, 1);
  assert.equal(obs[0].code, 'smb_v1_enabled');
  const [f] = assessServiceObservations('10.0.0.7', obs);
  assert.equal(f.subject_id, '10.0.0.7');
  // CONFIRMED because the protocol was negotiated, not inferred from a banner.
  assert.equal(f.confidence, 'CONFIRMED');
  // HIGH, not CRITICAL, and deliberately so: 85 sits below the CRITICAL floor
  // because the dialect being reachable is a configuration weakness, not a
  // demonstrated compromise of the host. Nothing was exploited to learn this.
  assert.equal(f.risk_score, 85);
  assert.equal(f.severity, 'HIGH');
});

test('a check that could not answer is not a finding — and not a clean result either', () => {
  // The engine sends null for a check that never reached the host. If null were
  // read as false this would report "signing not required" for a machine that
  // was merely firewalled; if it were read as true the report would assert a
  // security control nobody observed. Neither: it produces no observation, and
  // the engine's `inconclusive` list is what tells the reader it was not asked.
  assert.deepEqual(smbObservations({ target: '10.0.0.7', smbv1_enabled: null, signing_required: null }), []);
});

test('SMB signing present is silence, not a finding', () => {
  const obs = smbObservations({ target: '10.0.0.7', smbv1_enabled: false, signing_required: true });
  assert.deepEqual(obs, []);
});

test('SMB signing absent is a finding; SMBv1 absent is not', () => {
  const obs = smbObservations({ target: '10.0.0.7', smbv1_enabled: false, signing_required: false });
  assert.equal(obs.length, 1);
  assert.equal(obs[0].code, 'smb_signing');
});

test('the host detail the engine reported travels into the rationale', () => {
  const [f] = assessServiceObservations(
    '10.0.0.7',
    smbObservations({ target: '10.0.0.7', smbv1_enabled: true, computer_name: 'FILESRV01', os_version: 'Windows Server 2008 R2' })
  );
  assert.match(f.rationale, /FILESRV01/);
  assert.match(f.rationale, /2008 R2/);
});

test('"Unknown" is not host detail and must not be printed as if it were', () => {
  const [f] = assessServiceObservations(
    '10.0.0.7',
    smbObservations({ target: '10.0.0.7', smbv1_enabled: true, computer_name: 'Unknown', os_version: 'Unknown' })
  );
  assert.doesNotMatch(f.rationale, /Unknown/);
});

test('each responding path is its own finding, under one host', () => {
  // The defect this pins: the fingerprint is built from (subject, category,
  // port, code), so without the path as a discriminator twenty hits on one
  // server collapse into a single row and nineteen findings vanish on upsert.
  const hits = [
    { path: '/admin', status: 200, size: 4096 },
    { path: '/backup', status: 403, size: 0 },
    { path: '/.git', status: 200, size: 120 },
  ];
  const findings = assessServiceObservations('10.0.0.9', dirbusterObservations(hits));
  assert.equal(findings.length, 3);
  assert.equal(new Set(findings.map(f => f.fingerprint)).size, 3, 'each path needs its own fingerprint');
  assert.equal(new Set(findings.map(f => f.subject_id)).size, 1, 'and they all belong to one host');
  assert.equal(findings[0].subject_id, '10.0.0.9');
});

test('the same path assessed twice keeps the same fingerprint, so a retest can match it', () => {
  const a = assessServiceObservations('10.0.0.9', dirbusterObservations([{ path: '/admin', status: 200, size: 4096 }]));
  // Size changed between scans; it is detail, not identity.
  const b = assessServiceObservations('10.0.0.9', dirbusterObservations([{ path: '/admin', status: 200, size: 8192 }]));
  assert.equal(a[0].fingerprint, b[0].fingerprint);
});

test('an enumerated path is SUSPECTED and low — it is a thing to look at, not a breach', () => {
  const [f] = assessServiceObservations('10.0.0.9', dirbusterObservations([{ path: '/admin', status: 200 }]));
  assert.equal(f.confidence, 'SUSPECTED');
  assert.equal(f.severity, 'LOW');
  // The status code must survive: a 200 and a 403 need different follow-up.
  assert.match(f.rationale, /HTTP 200/);
});

test('a hit with no path is dropped rather than filed as an unnamed one', () => {
  assert.deepEqual(dirbusterObservations([{ status: 200 }, null, undefined]), []);
  assert.deepEqual(dirbusterObservations(null), []);
});

test('the host of a dirbuster hit is derived one way only', () => {
  // Both the live listener and the archive reader call this. If they disagreed
  // the retest delta would report every path as simultaneously fixed and new.
  assert.equal(hostOfUrl('http://10.0.0.9:8080/admin'), '10.0.0.9:8080');
  assert.equal(hostOfUrl('https://10.0.0.9:443/x'), '10.0.0.9');
  assert.equal(hostOfUrl('not a url'), null);
  assert.equal(hostOfUrl(''), null);
  assert.equal(hostOfUrl(undefined), null);
  assert.equal(hostOfUrl(12345), null);
});

// ── Two kinds of CVE claim, and the confidence that separates them ──────────

test('a banner-matched CVE is LIKELY, and says it was matched from the banner', () => {
  const f = one(assessHost(host({
    open_ports: [{ port: 80, service: 'http', cves: [{ cve: 'CVE-2021-41773', severity: 'CRITICAL', description: 'Path traversal.' }] }],
  })), 'service_cve');
  assert.equal(f.severity, 'CRITICAL');
  assert.equal(f.confidence, 'LIKELY');
  assert.match(f.rationale, /Matched from the service banner/);
  assert.match(f.rationale, /not exploited/);
});

test('an OS-inferred CVE is SUSPECTED, never LIKELY', () => {
  /*
    SMB and RDP do not publish a patch level, so EternalBlue and BlueKeep can
    only be inferred from an operating-system fingerprint plus an open port. A
    fully patched host looks identical. Reporting that at LIKELY would put a
    CRITICAL into the headline count on the strength of a fingerprint.

    The severity is the same either way — the flaw is as bad as it is. Only the
    confidence differs, which is why this rule set keeps them as separate fields.
  */
  const f = one(assessHost(host({
    open_ports: [{
      port: 445, service: 'smb',
      cves: [{
        cve: 'CVE-2017-0144', severity: 'CRITICAL', description: 'EternalBlue.',
        inferred: true, basis: 'SMB does not publish a patch level, so this is inferred from the OS fingerprint.',
      }],
    }],
  })), 'service_cve');
  assert.equal(f.severity, 'CRITICAL', 'the flaw is as serious as it is');
  assert.equal(f.confidence, 'SUSPECTED');
  assert.doesNotMatch(f.rationale, /Matched from the service banner/,
    'an inference must not claim a banner match');
});

test('an inferred finding carries its basis and admits what it cannot tell apart', () => {
  const f = one(assessHost(host({
    open_ports: [{
      port: 3389,
      cves: [{
        cve: 'CVE-2019-0708', severity: 'CRITICAL', description: 'BlueKeep.',
        inferred: true, basis: 'RDP does not publish a patch level.',
      }],
    }],
  })), 'service_cve');
  assert.match(f.rationale, /RDP does not publish a patch level/);
  assert.match(f.rationale, /patched host cannot be told apart/);
  assert.match(f.remediation, /Verify by hand/);
});

test('only an explicit inferred:true downgrades the confidence', () => {
  // A truthy-ish value arriving from an archive must not silently weaken a real
  // banner match, and a missing flag is a banner match.
  for (const flag of [undefined, null, false, 0, '', 'true', 1]) {
    const f = one(assessHost(host({
      open_ports: [{ port: 80, cves: [{ cve: 'CVE-2021-41773', severity: 'HIGH', inferred: flag }] }],
    })), 'service_cve');
    assert.equal(f.confidence, 'LIKELY', `inferred: ${JSON.stringify(flag)}`);
  }
});

test('an inferred and a matched advisory on one host stay distinguishable', () => {
  const findings = only(assessHost(host({
    open_ports: [
      { port: 80, cves: [{ cve: 'CVE-2021-41773', severity: 'CRITICAL' }] },
      { port: 445, cves: [{ cve: 'CVE-2017-0144', severity: 'CRITICAL', inferred: true }] },
    ],
  })), 'service_cve');
  assert.equal(findings.length, 2);
  const byId = Object.fromEntries(findings.map(f => [f.title.match(/CVE-[\d-]+/)[0], f]));
  assert.equal(byId['CVE-2021-41773'].confidence, 'LIKELY');
  assert.equal(byId['CVE-2017-0144'].confidence, 'SUSPECTED');
  assert.notEqual(byId['CVE-2021-41773'].fingerprint, byId['CVE-2017-0144'].fingerprint);
});

test('the methodology appendix covers advisories that cannot be banner-matched', () => {
  // The invariant: the appendix a reader audits has to describe the code that
  // ran. A SUSPECTED CRITICAL with no explanation in the method section is the
  // kind of row that gets the whole document questioned.
  const text = describeMethodology().limitations.join(' ');
  assert.match(text, /does not publish a patch level/);
  assert.match(text, /SUSPECTED confidence/);
  assert.match(text, /absence is not evidence that a host is patched/);
});

// ── TLS inspection observations ──────────────────────────────────────────────
//
// `deep_ssl_scan` produced these measurements long before anything consumed
// them: `start_deep_ssl_scan` had no caller in the application, so no payload it
// returned ever reached a rule. These tests cover the boundary where it does now.
//
// The same tri-state discipline as SMB applies, and for a sharper reason: a TLS
// check that could not complete looks exactly like one that found nothing wrong,
// and the thing being certified is whether a service is safe to trust.

test('an expired certificate becomes a CONFIRMED finding carrying its port', () => {
  const obs = tlsObservations({ target: '10.0.0.8', port: 8443, expired: true, cn: 'intranet.local', expires: '2024-01-01' });
  assert.equal(obs.length, 1);
  assert.equal(obs[0].code, 'tls_certificate_expired');
  // The port from the payload, not 443. A host can serve TLS on several and the
  // findings have to be distinguishable.
  assert.equal(obs[0].port, 8443);
  const [f] = assessServiceObservations('10.0.0.8', obs);
  assert.equal(f.confidence, 'CONFIRMED');
  assert.equal(f.risk_score, 60);
});

test('null expiry and null self-signed raise nothing at all', () => {
  // `check_certificate` seeds both as None and only fills them once it has
  // parsed far enough to know. Reading either as false would certify a
  // certificate that nobody managed to read.
  assert.deepEqual(tlsObservations({ target: '10.0.0.8', expired: null, self_signed: null }), []);
});

test('a valid certificate is silence, not a finding', () => {
  assert.deepEqual(
    tlsObservations({ target: '10.0.0.8', expired: false, self_signed: false, hsts: { enabled: true } }),
    []
  );
});

test('HSTS unreachable is not HSTS missing', () => {
  /*
    The defect this guards, which `ssl_check.py` records having already fixed
    once on the engine side: "any failure to reach the server used to produce the
    MEDIUM finding above". If `enabled: null` raised `tls_no_hsts`, every
    firewalled host would acquire a finding for a header nobody asked it for.
  */
  assert.deepEqual(tlsObservations({ target: '10.0.0.8', hsts: { enabled: null, error: 'timed out' } }), []);
  const present = tlsObservations({ target: '10.0.0.8', hsts: { enabled: false } });
  assert.equal(present.length, 1);
  assert.equal(present[0].code, 'tls_no_hsts');
});

test('several deprecated versions on one port are one finding, not three', () => {
  // Three rows would inflate the count the report leads with without adding an
  // action: it is one change window either way.
  const obs = tlsObservations({
    target: '10.0.0.8',
    deprecated_tls: { accepted: [{ version: 'TLSv1' }, { version: 'TLSv1.1' }] },
  });
  assert.equal(obs.length, 1);
  assert.equal(obs[0].code, 'tls_deprecated_version');
  // Both versions are named, because "deprecated TLS accepted" without saying
  // which is not something an administrator can act on.
  assert.match(obs[0].description, /TLSv1/);
  assert.match(obs[0].description, /TLSv1\.1/);
});

test('an empty accepted list is not a deprecated-TLS finding', () => {
  // `check_deprecated_tls` returns `accepted: []` with the versions it could not
  // test listed under `untested`. An empty list means none were accepted among
  // those tried — not that the check failed, and not that a finding exists.
  assert.deepEqual(
    tlsObservations({ target: '10.0.0.8', deprecated_tls: { accepted: [], untested: [{ version: 'TLSv1' }] } }),
    []
  );
});

test('a weak cipher finding carries the caveat that bounds it', () => {
  /*
    `check_weak_ciphers` sets `caveat` when it could only observe the suite that
    was actually negotiated. The finding then means "this suite is weak", not
    "these are the only weak suites accepted", and a reader who treats a short
    list as the complete one will under-scope the fix.
  */
  const obs = tlsObservations({
    target: '10.0.0.8',
    cipher_audit: { weak: [{ name: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA' }], caveat: 'only the negotiated suite was observed' },
  });
  assert.equal(obs.length, 1);
  assert.equal(obs[0].code, 'tls_weak_cipher');
  assert.match(obs[0].description, /3DES/);
  assert.match(obs[0].description, /only the negotiated suite was observed/);
});

test('observations are read from fields, not from the engine\'s finding text', () => {
  /*
    The whole payload minus the structured fields, plus findings worded exactly
    as the engine words them. If any rule matched on that text this would produce
    findings; it must produce none.

    This is the test that keeps the rule set from depending on wording. The
    engine writes those sentences for the operator's screen and is free to
    reword them, and a rule set reading them would stop raising findings the day
    somebody fixed a typo — with every other test here still green.
  */
  const obs = tlsObservations({
    target: '10.0.0.8',
    findings: [
      { severity: 'HIGH', finding: 'Deprecated TLSv1 accepted', detail: 'PCI-DSS and NIST require TLS 1.2 as a minimum.' },
      { severity: 'MEDIUM', finding: 'HSTS not enabled', detail: 'a client can be downgraded to plain HTTP' },
    ],
  });
  assert.deepEqual(obs, []);
});

test('a host with several TLS faults raises one finding per fault', () => {
  const obs = tlsObservations({
    target: '10.0.0.8', port: 443,
    expired: true, self_signed: true,
    deprecated_tls: { accepted: [{ version: 'TLSv1' }] },
    cipher_audit: { weak: [{ name: 'RC4-SHA' }] },
    hsts: { enabled: false },
  });
  assert.deepEqual(obs.map(o => o.code).sort(), [
    'tls_certificate_expired',
    'tls_certificate_self_signed',
    'tls_deprecated_version',
    'tls_no_hsts',
    'tls_weak_cipher',
  ]);
  const findings = assessServiceObservations('10.0.0.8', obs);
  assert.equal(findings.length, 5);
  // Every one of them is attributed to the host the payload named.
  assert.ok(findings.every(f => f.subject_id === '10.0.0.8'));
});
