/**
 * LOCKON EWAC — Risk assessment: one rule set, stated reasons
 *
 * This replaces five separate, disagreeing rule sets:
 *
 *   1. `engine/scanner/wifi.py` set a binary `is_vulnerable` (WPA1 = vulnerable).
 *   2. `missionStore` passed that straight through as `highRiskCount`, which
 *      became the report's headline "VULNERABLE APs" number.
 *   3. The PDF's per-AP table recomputed severity as
 *      `encryption === 'WEP' || encryption === 'OPEN'`, so a WPA1 network was
 *      counted in the headline figure and printed as `[LOW]` in the table on the
 *      same page.
 *   4. The PDF's per-host severity string-matched its own note text.
 *   5. `IntrusionPage.getPortIntel` had yet another port/CVE scale that never
 *      reached the PDF at all.
 *
 * Plus `vulnerability_results`, `RISK_THRESHOLDS` and `risk_score` all existed
 * and were never written, so the Reports page's LAN "vulnerable" count filtered
 * on a column that is always null and was therefore permanently zero.
 *
 * The contract here:
 *   - One function decides severity, for every subject type.
 *   - Every finding carries a `rationale` a reader can audit and a `methodology`
 *     id + version, so a label in a document can always be traced to a rule.
 *   - Findings carry a stable `fingerprint`, so a retest recognises the same
 *     issue rather than reporting it as new.
 *   - `confidence` is reported beside `severity`, never folded into it, so a
 *     reader gets both facts. For most rules severity is genuinely independent
 *     of confidence: an exposed Telnet port is scored the same whether it was
 *     found by one probe or ten.
 *
 *     The rogue-AP rule is the documented exception. Its verdict
 *     (SUSPECTED/LIKELY/CONFIRMED) comes from indicator scoring in
 *     `engine/scanner/evil_twin.py` and it scales the score as well as the
 *     confidence, so a SUSPECTED rogue lands at MEDIUM and a CONFIRMED one at
 *     CRITICAL. That is deliberate rather than an oversight: `summarise()`
 *     builds the headline figure from severity alone (`CRITICAL + HIGH`), so
 *     without the ladder every unconfirmed suspicion would inflate the number a
 *     manager reads first — and one false accusation costs more credibility
 *     than the finding is worth. If the headline is ever made
 *     confidence-aware, the ladder should be removed at the same time and the
 *     severity held constant across verdicts.
 *
 *     Both the ladder and the bands are published by `describeMethodology()`
 *     and printed in the report's method appendix, so a reader can audit this
 *     rather than take it on trust.
 *
 * Scores are 0-100 and map to levels through SEVERITY_BANDS. The bands are
 * exported so the report can print the scale it used.
 */

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type Confidence = 'SUSPECTED' | 'LIKELY' | 'CONFIRMED';
export type SubjectType = 'AP' | 'HOST' | 'CLIENT' | 'NETWORK';

export const METHODOLOGY_ID = 'lockon-risk';

/**
 * Bump this whenever a change here would make the same archive produce a
 * different label, score or count.
 *
 * The report prints this version as the rule set in force, and every finding
 * records it in `methodology`. Two documents that disagree while claiming the
 * same version are worse than the defect that caused the disagreement, so the
 * number has to move with the behaviour. `fingerprint()` deliberately excludes
 * it, so a retest still matches findings recorded under an earlier version.
 *
 * Version history:
 *
 *  1. Initial single rule set, replacing five disagreeing ones.
 *  2. `summarise()` returns `worst: null` for an empty finding set instead of
 *     `'INFO'`. An archive with nothing to assess printed "Highest severity
 *     present: INFO" — a verdict where none was possible, indistinguishable from
 *     a real assessment whose worst finding was informational.
 *     `severityForSubject()` is nullable for the same reason. No score, band or
 *     rule changed, so a non-empty archive produces identical labels to v1.
 *
 *     Shipped alongside three report-side corrections that do not affect this
 *     rule set but do change the document: WPS is reported as "not measured"
 *     rather than "not advertised" (the scan that produces it is unreachable, so
 *     the old wording asserted an observation that never happened); the cover no
 *     longer prints a hardcoded `OP-LOCKON [AUTHORIZED]`; and localization
 *     confidence is no longer rescaled, which had printed the least certain
 *     estimate the tool can produce as "100%".
 *  3. Counts are deduplicated, and two sources of findings changed. No band,
 *     rule or score in this file moved, but the same archives now produce
 *     different totals, so the version has to move with them:
 *
 *       - Findings, access-point and host totals, the WPS and rogue-AP tables and
 *         POSITION QUALITY are deduplicated by `fingerprint` / BSSID / IP across
 *         the archives in one export. A multi-archive export previously counted a
 *         device once per archive, so two surveys of one estate doubled the
 *         headline risk figure.
 *       - CVE matching no longer accepts a substring of a version string, and
 *         entries can declare the release that fixed them, so a patched host in a
 *         keyed line is no longer asserted vulnerable. Expect fewer, better
 *         founded CRITICAL and HIGH findings.
 *       - Rogue-AP verdicts now survive into the archive instead of being
 *         discarded after first sighting, so rogue findings that were previously
 *         missing appear. Expect more of them.
 *  4. A `service_config` category, so the deep inspection modules reach the
 *     document at all. Their results previously lived in component state and
 *     were never written to `findings` or into an archive, so an operator could
 *     watch an unauthenticated Redis appear on screen at CRITICAL while the PDF
 *     for that host raised nothing.
 *
 *     Severity for these is decided here rather than taken from the engine,
 *     which hardcodes its own per check and puts CWE identifiers and the string
 *     "N/A" in a field named `cve`. Checks that demonstrate access are
 *     CONFIRMED; checks that read a version banner are SUSPECTED and say so. An
 *     observation this rule set does not recognise is still reported, at the
 *     lowest reportable score with its severity explicitly unassessed, so it can
 *     never reach the headline figure on a label nothing here produced.
 *
 *     Extended in the same pass to cover SMB and directory enumeration:
 *     `smb_v1_enabled` (85, CONFIRMED — the dialect was negotiated, so it is
 *     observed rather than inferred, but it is a reachable configuration and not
 *     a demonstrated compromise, which is why it sits below the CRITICAL floor)
 *     and `http_enumerated_path` (20, SUSPECTED — an image directory and an
 *     unauthenticated admin console look identical from here).
 *
 *     `ServiceObservation.detail` also joins the fingerprint, so one rule can
 *     fire more than once against the same host and port. Only directory
 *     enumeration uses it; no fingerprint produced by an earlier version
 *     changes, because no earlier observation carried a detail.
 */
export const METHODOLOGY_VERSION = 4;

/** Score -> level. Printed in the report so a severity label can be checked. */
export const SEVERITY_BANDS: { min: number; level: Severity }[] = [
  { min: 90, level: 'CRITICAL' },
  { min: 70, level: 'HIGH' },
  { min: 40, level: 'MEDIUM' },
  { min: 15, level: 'LOW' },
  { min: 0, level: 'INFO' },
];

export function scoreToSeverity(score: number): Severity {
  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  return (SEVERITY_BANDS.find(b => clamped >= b.min)?.level) ?? 'INFO';
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0,
};

export interface Finding {
  subject_type: SubjectType;
  subject_id: string;
  category: string;
  title: string;
  severity: Severity;
  risk_score: number;
  confidence: Confidence;
  /** Why this was assessed the way it was. Never empty. */
  rationale: string;
  methodology: string;
  remediation?: string;
  fingerprint: string;
  is_simulated?: boolean;
}

function fingerprint(subjectType: SubjectType, subjectId: string, category: string, key = ''): string {
  // Stable across runs: identity is the subject plus what the issue is, never a
  // timestamp or a score, so a retest matches the same row.
  return [subjectType, subjectId.toUpperCase(), category, key].filter(Boolean).join('|');
}

function methodologyTag(rule: string) {
  return `${METHODOLOGY_ID}@${METHODOLOGY_VERSION}/${rule}`;
}

// ── Access points ───────────────────────────────────────────────────────────

/**
 * Encryption scoring. Single source for both the headline count and the per-row
 * severity, which is what stops the PDF contradicting itself.
 */
const ENCRYPTION_RULES: Record<string, { score: number; title: string; rationale: string; remediation: string }> = {
  OPEN: {
    score: 95,
    title: 'Unencrypted network',
    rationale: 'The network broadcasts with no encryption, so all traffic is readable by anyone in radio range and no credential is needed to join.',
    remediation: 'Enable WPA2-Enterprise or WPA3. If an open network is required for guests, isolate it from internal networks and force a captive portal with client isolation.',
  },
  WEP: {
    score: 92,
    title: 'WEP encryption (broken)',
    rationale: 'WEP is cryptographically broken; the key can be recovered from passively captured traffic in minutes regardless of its length or complexity.',
    remediation: 'Replace with WPA2-AES or WPA3 immediately. WEP-only hardware should be retired.',
  },
  WPA: {
    score: 72,
    title: 'WPA1/TKIP encryption (deprecated)',
    rationale: 'WPA1 with TKIP is deprecated and has known practical attacks. It is materially weaker than WPA2-AES and is no longer considered adequate.',
    remediation: 'Reconfigure for WPA2-AES at minimum; prefer WPA3 where the hardware supports it.',
  },
  WPAPSK: {
    score: 72,
    title: 'WPA1/TKIP encryption (deprecated)',
    rationale: 'WPA1 with TKIP is deprecated and has known practical attacks. It is materially weaker than WPA2-AES.',
    remediation: 'Reconfigure for WPA2-AES at minimum; prefer WPA3 where supported.',
  },
  WPA2: {
    score: 10,
    title: 'WPA2 encryption',
    rationale: 'WPA2-AES is currently acceptable. It remains exposed to offline dictionary attack on a captured handshake, so passphrase strength is what carries the risk.',
    remediation: 'Ensure a long random passphrase, or move to WPA3 / WPA2-Enterprise to remove the offline-cracking exposure.',
  },
  WPA2PSK: {
    score: 10,
    title: 'WPA2-PSK encryption',
    rationale: 'WPA2-AES is currently acceptable. A pre-shared key remains exposed to offline dictionary attack on a captured handshake.',
    remediation: 'Ensure a long random passphrase, or move to WPA3 / WPA2-Enterprise.',
  },
  WPA3: {
    score: 0,
    title: 'WPA3 encryption',
    rationale: 'WPA3 with SAE is the current standard and is not vulnerable to offline dictionary attack on a captured handshake.',
    remediation: 'No action required.',
  },
  WPA3SAE: {
    score: 0,
    title: 'WPA3-SAE encryption',
    rationale: 'WPA3 with SAE is the current standard and resists offline dictionary attack.',
    remediation: 'No action required.',
  },
};

function normEnc(value?: string): string {
  return (value || '').toUpperCase().replace(/[-_\s]/g, '');
}

/**
 * The severity this rule set gives a security mode, for a badge on screen.
 *
 * The UI used to keep its own encryption table, and it disagreed with this one.
 * `ScanFeed` drew WEP in HIGH's orange while the rules score it 92 — CRITICAL —
 * and gave WPA1 the same neutral grey as WPA2, though it scores 72 and is
 * reported as HIGH. `TargetDrawer`, in a panel headed THREAT ASSESSMENT, painted
 * everything that was not OPEN or WEP green, so a WPA1 network read as safe on
 * screen and as HIGH in the report built from the same row.
 *
 * That is the defect this module was consolidated to end: five rule sets that
 * agreed on severity and disagreed on everything else, one of which produced a
 * PDF calling a WPA1 network vulnerable in its headline and LOW in its table.
 * A second table in the UI is the same mistake in a different surface, so there
 * is no second table — the badge asks the rules.
 *
 * Returns **null when the mode could not be read or is not recognised**, which
 * the caller must render as "not assessed" rather than as safe. An adapter that
 * reported nothing and a network that is genuinely fine are different findings,
 * and green is a claim.
 */
export function severityForEncryption(value?: string | null): Severity | null {
  const enc = normEnc(value ?? undefined);
  if (!enc || enc === 'UNKNOWN') return null;
  const rule = ENCRYPTION_RULES[enc];
  if (rule) return scoreToSeverity(rule.score);
  // An unrecognised mode is reported by `assessAccessPoint` at 20 / SUSPECTED
  // rather than dropped, and the badge has to match that rather than fall
  // through to a neutral colour.
  return scoreToSeverity(20);
}

export interface ApInput {
  bssid: string;
  ssid?: string;
  encryption?: string;
  vendor?: string;
  channel?: number;
  band?: string;
  wps_enabled?: boolean;
  wps_locked?: boolean;
  is_evil_twin?: boolean;
  /** From the engine's rogue-AP scoring: CLEAR | SUSPECTED | LIKELY | CONFIRMED */
  rogue_verdict?: string;
  rogue_score?: number;
  rogue_indicators?: { code: string; weight: number; detail: string }[];
  /**
   * Stations associated with this AP, from the BSS Load information element.
   *
   * `undefined` means the adapter published no count, which is not the same as
   * zero and must never be reported as one. Most adapters and most scans do not
   * report it at all.
   */
  connected_stations?: number;
  simulated?: boolean;
  is_simulated?: number;
}

/**
 * Exposure evidence for a network whose traffic is readable: whether anything
 * was actually on it.
 *
 * Why this is here rather than in the report layer. Every OPEN network scores 95
 * and lands on CRITICAL, so a survey of a campus produces a page of identical
 * CRITICAL rows — measured on this rig, 72 of them in one archive, all at score
 * 95 — and the findings table sorts by score, which cannot separate them. A
 * reader is handed a list and no order to work in. Whether devices were
 * associated is the one observation that distinguishes "a door is unlocked" from
 * "a door is unlocked and people are walking through it", so it belongs in the
 * rationale, which is the field a reader audits.
 *
 * **It deliberately does not change the score.** An unlocked network is equally
 * misconfigured whether or not anyone is on it, and scoring a busy one higher
 * would mean scoring a quiet one lower — which is not true, and would move the
 * severity of an existing finding without the rule set changing. It changes what
 * a reader does first, not what the tool asserts.
 *
 * Returns '' when no count was published. "This AP does not report a station
 * count" and "no devices are on this AP" are different observations, and
 * stating the second from the first is exactly the class of untruth this rule
 * set exists to prevent.
 */
function exposureEvidence(stations?: number): string {
  if (typeof stations !== 'number' || !Number.isFinite(stations) || stations < 0) return '';
  if (stations === 0) {
    return ' No device was associated with it while the survey was within radio range.'
      + ' A survey is a short pass, so this is not evidence the network is unused —'
      + ' it does mean nobody was observed relying on it at the time.';
  }
  const devices = stations === 1 ? '1 device was' : `${stations} devices were`;
  return ` ${devices} associated with it during the survey, so this is an exposure`
    + ' in use rather than a latent misconfiguration.';
}

export function assessAccessPoint(ap: ApInput): Finding[] {
  const findings: Finding[] = [];
  const simulated = !!(ap.simulated || ap.is_simulated);
  const label = ap.ssid ? `${ap.ssid} (${ap.bssid})` : ap.bssid;

  // 1. Encryption
  const enc = normEnc(ap.encryption);
  const rule = ENCRYPTION_RULES[enc];
  if (rule) {
    if (rule.score >= 15) {
      /*
        Station counts are appended only where the risk *is* traffic exposure.

        For OPEN and WEP the traffic is readable, so who is on the network
        changes how urgent the finding is. For WPA/WPA2 the finding is about key
        strength and offline attack on a captured handshake; a client count does
        not change what to do about it, and printing "no device was associated"
        under every WPA2 row would be noise in a document that has to stay
        readable.
      */
      const exposesTraffic = enc === 'OPEN' || enc === 'WEP';
      findings.push({
        subject_type: 'AP', subject_id: ap.bssid,
        category: 'encryption',
        title: `${rule.title} — ${label}`,
        risk_score: rule.score,
        severity: scoreToSeverity(rule.score),
        confidence: 'CONFIRMED',
        rationale: rule.rationale
          + (exposesTraffic ? exposureEvidence(ap.connected_stations) : ''),
        methodology: methodologyTag('encryption'),
        remediation: rule.remediation,
        fingerprint: fingerprint('AP', ap.bssid, 'encryption', enc),
        is_simulated: simulated,
      });
    }
  } else if (enc && enc !== 'UNKNOWN') {
    findings.push({
      subject_type: 'AP', subject_id: ap.bssid,
      category: 'encryption',
      title: `Unrecognised security configuration — ${label}`,
      risk_score: 20, severity: scoreToSeverity(20), confidence: 'SUSPECTED',
      rationale: `The adapter reported a security mode ('${ap.encryption}') this tool does not have a rule for, so it could not be assessed. Verify manually.`,
      methodology: methodologyTag('encryption'),
      remediation: 'Confirm the AP configuration by hand.',
      fingerprint: fingerprint('AP', ap.bssid, 'encryption', enc),
      is_simulated: simulated,
    });
  }

  // 2. WPS — an unlocked WPS PIN undermines an otherwise sound WPA2 setup, which
  //    is exactly why a binary encryption-only verdict was not enough.
  if (ap.wps_enabled) {
    const locked = !!ap.wps_locked;
    const score = locked ? 35 : 75;
    findings.push({
      subject_type: 'AP', subject_id: ap.bssid,
      category: 'wps',
      title: `WPS enabled${locked ? ' (rate-limited)' : ''} — ${label}`,
      risk_score: score,
      severity: scoreToSeverity(score),
      confidence: 'CONFIRMED',
      rationale: locked
        ? 'WPS is enabled but the AP is rate-limiting PIN attempts. The attack surface remains present and lockout behaviour varies between firmware versions.'
        : 'WPS is enabled without lockout. The 8-digit PIN is effectively recoverable, which yields the WPA passphrase regardless of how strong that passphrase is.',
      methodology: methodologyTag('wps'),
      remediation: 'Disable WPS on the access point. It provides no benefit that offsets this exposure.',
      fingerprint: fingerprint('AP', ap.bssid, 'wps'),
      is_simulated: simulated,
    });
  }

  // 3. Rogue AP / evil twin. Severity stays high while confidence carries the
  //    uncertainty — a suspected rogue is not a low-risk finding, it is an
  //    unconfirmed high-risk one, and a reader needs both facts.
  const verdict = (ap.rogue_verdict || '').toUpperCase();
  if (verdict === 'SUSPECTED' || verdict === 'LIKELY' || verdict === 'CONFIRMED') {
    const confidence: Confidence = verdict === 'CONFIRMED' ? 'CONFIRMED'
      : verdict === 'LIKELY' ? 'LIKELY' : 'SUSPECTED';
    const score = verdict === 'CONFIRMED' ? 90 : verdict === 'LIKELY' ? 75 : 45;
    const reasons = (ap.rogue_indicators || []).map(i => i.detail).join(' ');
    findings.push({
      subject_type: 'AP', subject_id: ap.bssid,
      category: 'rogue_ap',
      title: `Possible rogue access point (${verdict}) — ${label}`,
      risk_score: score,
      severity: scoreToSeverity(score),
      confidence,
      rationale: reasons
        ? `Indicators observed: ${reasons}`
        : 'Rogue-AP indicators were scored above the reporting threshold.',
      methodology: methodologyTag('rogue_ap'),
      remediation: 'Physically locate the device and confirm whether it is authorised. If it is not, remove it and review how it was able to broadcast this SSID.',
      fingerprint: fingerprint('AP', ap.bssid, 'rogue_ap'),
      is_simulated: simulated,
    });
  }

  return findings;
}

// ── Hosts ───────────────────────────────────────────────────────────────────

export interface HostPort {
  port: number;
  service?: string;
  banner?: string;
  cves?: {
    cve: string;
    severity?: string;
    description?: string;
    /**
     * True when the advisory follows from the host's operating system rather
     * than from a version the service reported about itself.
     *
     * SMB and RDP do not publish a patch level, so EternalBlue and BlueKeep can
     * only be inferred from an OS fingerprint plus an open port. A patched host
     * looks identical, so the finding is reported at SUSPECTED, not LIKELY.
     */
    inferred?: boolean;
    /** What the inference rests on, printed as the rationale when set. */
    basis?: string;
  }[];
}

export interface HostInput {
  ip: string;
  hostname?: string;
  os?: string;
  open_ports?: HostPort[];
  default_creds?: { username: string; password?: string };
  snmp_communities?: unknown[];
  simulated?: boolean;
}

/** Services whose exposure is itself the finding, with why. */
const EXPOSED_SERVICE_RULES: Record<number, { score: number; name: string; rationale: string; remediation: string }> = {
  23: { score: 85, name: 'Telnet', rationale: 'Telnet transmits credentials and session data in cleartext and has no integrity protection.', remediation: 'Disable Telnet and use SSH.' },
  21: { score: 60, name: 'FTP', rationale: 'FTP transmits credentials in cleartext unless explicitly wrapped in TLS.', remediation: 'Replace with SFTP/FTPS, or restrict to an isolated segment.' },
  445: { score: 65, name: 'SMB', rationale: 'SMB exposed on the network is a primary lateral-movement path and a frequent target for relay and remote-execution attacks.', remediation: 'Restrict SMB to required hosts, enforce signing, and disable SMBv1.' },
  3389: { score: 65, name: 'RDP', rationale: 'Exposed RDP is routinely brute-forced and is a common initial-access vector.', remediation: 'Place RDP behind a VPN or gateway, enforce NLA and MFA.' },
  5900: { score: 70, name: 'VNC', rationale: 'VNC often ships with weak or absent authentication and no transport encryption.', remediation: 'Disable VNC or tunnel it over SSH/VPN with strong authentication.' },
  1433: { score: 55, name: 'MSSQL', rationale: 'A database engine reachable from the general network broadens its attack surface well beyond its application tier.', remediation: 'Bind to the application subnet only and require TLS.' },
  3306: { score: 55, name: 'MySQL', rationale: 'A database engine reachable from the general network broadens its attack surface well beyond its application tier.', remediation: 'Bind to localhost or the application subnet and require TLS.' },
  6379: { score: 80, name: 'Redis', rationale: 'Redis historically defaults to no authentication, and an unauthenticated instance commonly permits arbitrary file write.', remediation: 'Enable requirepass, bind to localhost, and enable protected-mode.' },
  27017: { score: 75, name: 'MongoDB', rationale: 'MongoDB exposed without authentication permits full read/write access to every database.', remediation: 'Enable authentication and bind to the application subnet.' },
  9200: { score: 70, name: 'Elasticsearch', rationale: 'Elasticsearch exposed without authentication permits reading and deleting every index.', remediation: 'Enable security features and restrict network access.' },
};

const CVE_SEVERITY_SCORE: Record<string, number> = {
  CRITICAL: 95, HIGH: 80, MEDIUM: 50, LOW: 25, UNKNOWN: 40,
};

export function assessHost(host: HostInput): Finding[] {
  const findings: Finding[] = [];
  const simulated = !!host.simulated;
  const label = host.hostname ? `${host.hostname} (${host.ip})` : host.ip;

  // 1. Recovered credentials — the strongest possible demonstration of impact.
  if (host.default_creds?.username) {
    findings.push({
      subject_type: 'HOST', subject_id: host.ip,
      category: 'credentials',
      title: `Valid credentials recovered — ${label}`,
      risk_score: 100, severity: 'CRITICAL', confidence: 'CONFIRMED',
      rationale: `A working credential was recovered for account '${host.default_creds.username}'. This is demonstrated access, not a theoretical weakness.`,
      methodology: methodologyTag('credentials'),
      remediation: 'Rotate the credential immediately, review access logs for prior use, and enforce a password policy plus MFA on this service.',
      fingerprint: fingerprint('HOST', host.ip, 'credentials', host.default_creds.username),
      is_simulated: simulated,
    });
  }

  // 2. CVEs, scored from the severity the CVE itself carries.
  for (const port of host.open_ports || []) {
    for (const cve of port.cves || []) {
      const sev = (cve.severity || 'UNKNOWN').toUpperCase();
      const score = CVE_SEVERITY_SCORE[sev] ?? 40;
      /*
        Two kinds of claim, kept apart because a reader acts on them differently.

        A banner match is evidence about *this* service: the version it reported
        falls inside a known-vulnerable range. An OS-inferred advisory is evidence
        about the era of the operating system and nothing more — SMB and RDP do
        not publish a patch level, so a fully patched host is indistinguishable
        from an unpatched one. Reporting the second at LIKELY would put a
        CRITICAL in the headline count on the strength of a fingerprint.

        The severity is the same either way, because the flaw is as bad as it is;
        the confidence is what differs. They are separate fields in this rule set
        precisely so that this case does not have to be fudged into one number.
      */
      const inferred = cve.inferred === true;
      findings.push({
        subject_type: 'HOST', subject_id: host.ip,
        category: 'service_cve',
        title: `${cve.cve} on port ${port.port} — ${label}`,
        risk_score: score, severity: scoreToSeverity(score),
        confidence: inferred ? 'SUSPECTED' : 'LIKELY',
        rationale: inferred
          ? `${cve.description || 'No description available.'} ${cve.basis || 'Inferred from the operating system fingerprint rather than from a version the service reported.'} Not exploited during this assessment, and a patched host cannot be told apart from an unpatched one by this check.`
          : `${cve.description || 'No description available.'} Matched from the service banner on port ${port.port}${port.service ? ` (${port.service})` : ''}; not exploited during this assessment.`,
        methodology: methodologyTag('service_cve'),
        remediation: inferred
          ? 'Confirm the host has the vendor patch for this advisory, and restrict the port to the networks that need it. Verify by hand before treating this as a live vulnerability.'
          : 'Patch the affected service to a version outside the vulnerable range, and confirm the banner no longer matches.',
        fingerprint: fingerprint('HOST', host.ip, 'service_cve', `${port.port}:${cve.cve}`),
        is_simulated: simulated,
      });
    }
  }

  // 3. Exposed services.
  for (const port of host.open_ports || []) {
    const rule = EXPOSED_SERVICE_RULES[port.port];
    if (!rule) continue;
    findings.push({
      subject_type: 'HOST', subject_id: host.ip,
      category: 'exposed_service',
      title: `${rule.name} exposed on port ${port.port} — ${label}`,
      risk_score: rule.score, severity: scoreToSeverity(rule.score),
      confidence: 'CONFIRMED',
      rationale: `${rule.rationale} Confirmed reachable during this assessment.`,
      methodology: methodologyTag('exposed_service'),
      remediation: rule.remediation,
      fingerprint: fingerprint('HOST', host.ip, 'exposed_service', String(port.port)),
      is_simulated: simulated,
    });
  }

  // 4. SNMP with a guessable community string.
  if (host.snmp_communities?.length) {
    findings.push({
      subject_type: 'HOST', subject_id: host.ip,
      category: 'snmp',
      title: `SNMP responds to a default community string — ${label}`,
      risk_score: 70, severity: scoreToSeverity(70), confidence: 'CONFIRMED',
      rationale: `The host answered SNMP queries using ${host.snmp_communities.length} well-known community string(s), disclosing device and network configuration to any unauthenticated caller.`,
      methodology: methodologyTag('snmp'),
      remediation: 'Change the community strings, or move to SNMPv3 with authentication and encryption.',
      fingerprint: fingerprint('HOST', host.ip, 'snmp'),
      is_simulated: simulated,
    });
  }

  return findings;
}

// ── Service-level observations from the deep inspection modules ─────────────

/**
 * One observation as `engine/scanner/vuln_engine.py` emits it.
 *
 * `severity` and `cve` are deliberately absent from this interface even though
 * the engine sends them. The engine hardcodes a severity per check, and its
 * `cve` field carries CWE identifiers and the literal string "N/A" — neither is
 * a CVE and neither went through any rule set. Letting those into the document
 * would reintroduce exactly the problem this module was written to end: two
 * severity scales disagreeing inside one report.
 *
 * `code` is what this rule set keys on. It is a stable identifier added to each
 * check for this purpose, rather than the `vuln` label, which is an f-string
 * with a banner interpolated into it.
 */
export interface ServiceObservation {
  code?: string;
  vuln?: string;
  port?: number;
  description?: string;
  /**
   * What this observation is *about* within the host, when one rule can fire
   * more than once against the same host and port.
   *
   * The fingerprint is what makes a finding the same finding across two scans,
   * and it is built from (subject, category, port, code). For most rules that
   * is already unique — a host either accepts anonymous FTP or it does not.
   * Directory enumeration is the exception: twenty responding paths on one web
   * server are twenty separate things to look at, and without a discriminator
   * they all collapse into a single row, each upsert overwriting the last.
   *
   * The alternative — making the URL the subject — was worse: it puts a URL in
   * a column labelled "host", and then the same server appears as twenty hosts
   * in every count the report prints.
   */
  detail?: string;
}

/**
 * Scores for what the service checks actually observe.
 *
 * Assigned here, not by the engine. Where a check demonstrates access
 * (anonymous FTP, an unauthenticated database) the score reflects that; where it
 * observes a configuration weakness inferred from a banner, the confidence is
 * lower and the score is not allowed to imply a demonstration.
 */
const SERVICE_RULES: Record<string, {
  score: number;
  confidence: Confidence;
  title: string;
  rationale: string;
  remediation: string;
}> = {
  ftp_anonymous: {
    score: 85, confidence: 'CONFIRMED',
    title: 'Anonymous FTP login accepted',
    rationale: 'The FTP service accepted an anonymous login during this assessment. This is demonstrated unauthenticated access to the file service, not an inference from a banner.',
    remediation: 'Disable the anonymous account, or restrict it to a read-only directory that holds nothing sensitive and cannot be written to.',
  },
  redis_no_auth: {
    score: 95, confidence: 'CONFIRMED',
    title: 'Redis accepts unauthenticated commands',
    rationale: 'The Redis instance answered an INFO command without authentication. An unauthenticated Redis commonly permits arbitrary file write, which on many deployments is a direct path to code execution.',
    remediation: 'Set requirepass, bind the service to localhost or the application subnet, and enable protected-mode.',
  },
  ssh_protocol_v1: {
    score: 88, confidence: 'CONFIRMED',
    title: 'SSH protocol version 1 offered',
    rationale: 'The SSH service advertised protocol version 1, which has structural weaknesses in its integrity checking and is not repairable by configuration.',
    remediation: 'Restrict the daemon to protocol 2 only.',
  },
  telnet_cleartext: {
    score: 85, confidence: 'CONFIRMED',
    title: 'Telnet service reachable',
    rationale: 'A Telnet service answered. Telnet carries credentials and session content in cleartext with no integrity protection, so anyone able to observe the path can read both.',
    remediation: 'Disable Telnet and use SSH.',
  },
  /*
    TLS inspection rules.

    `deep_ssl_scan` has produced these measurements since before this rule set
    existed, and nothing consumed them: the command had no caller, so the
    question of what its findings were worth had never come up.

    Every one of these reads a structured field rather than the engine's own
    finding text. The engine writes a sentence for the operator's screen; parsing
    that sentence here would make the report's findings depend on wording, and a
    reworded string would silently stop raising a finding with every test still
    green.
  */
  tls_certificate_expired: {
    score: 60, confidence: 'CONFIRMED',
    title: 'TLS certificate has expired',
    rationale: 'The certificate presented by this service is past its notAfter date. Clients that check expiry refuse the connection, and the usual response in the field is for people to click through the warning — which trains them past the one signal that would show them an interception.',
    remediation: 'Reissue and deploy a current certificate, and put renewal on a timer rather than a calendar reminder.',
  },
  tls_certificate_self_signed: {
    score: 45, confidence: 'CONFIRMED',
    title: 'TLS certificate is self-signed',
    rationale: 'Issuer and subject are the same, so the certificate vouches only for itself. It encrypts the channel but establishes nothing about who is at the other end, which is the half that stops an interception.',
    remediation: 'Issue the certificate from a CA the clients already trust — an internal CA is enough, provided its root is actually distributed.',
  },
  tls_deprecated_version: {
    score: 65, confidence: 'CONFIRMED',
    title: 'Deprecated TLS version accepted',
    rationale: 'The service completed a handshake using a TLS version that is no longer considered sound. PCI-DSS and NIST both require TLS 1.2 as a minimum, and the weaknesses here are structural rather than configuration faults.',
    remediation: 'Disable TLS 1.0 and 1.1 at the server and confirm no client still depends on them before the change window closes.',
  },
  tls_weak_cipher: {
    score: 60, confidence: 'CONFIRMED',
    title: 'Weak cipher suite accepted',
    rationale: 'The service negotiated a cipher suite from the weak set — in practice RC4, 3DES, NULL, EXPORT or anonymous key exchange. The protocol version alone does not protect a session that then agrees on one of these.',
    remediation: 'Restrict the cipher list to AEAD suites with forward secrecy, and verify by re-running this check rather than by reading the configuration.',
  },
  tls_no_hsts: {
    score: 25, confidence: 'CONFIRMED',
    title: 'HSTS not enabled',
    rationale: 'The service answered without a Strict-Transport-Security header, so a client that first arrives over plain HTTP can be held there and never redirected. The TLS configuration below this is irrelevant to a session that never reaches it.',
    remediation: 'Send Strict-Transport-Security with a max-age of at least six months once the certificate chain is known good on every hostname served.',
  },
  smb_signing: {
    score: 65, confidence: 'CONFIRMED',
    title: 'SMB signing not required',
    rationale: 'The SMB service does not require message signing, which is what makes relay attacks against it practical.',
    remediation: 'Require SMB signing on both servers and clients.',
  },
  http_exposed_secret: {
    score: 80, confidence: 'LIKELY',
    title: 'Sensitive file served by the web server',
    rationale: 'A request for a path that normally holds configuration or credentials returned a success response. The content was not retrieved or inspected, so confirm what is actually served before treating the secret as disclosed.',
    remediation: 'Block the path at the web server and rotate anything it may have exposed.',
  },
  ssh_openssh_outdated: {
    score: 45, confidence: 'SUSPECTED',
    title: 'OpenSSH banner reports an outdated version',
    rationale: 'The version in the SSH banner falls below the threshold this tool treats as current. This is a banner reading only: no vulnerability was tested, the banner may be inaccurate or deliberately altered, and distributions routinely backport fixes without changing it.',
    remediation: 'Confirm the running version and its patch level against the vendor advisory before acting on this.',
  },
  ssh_openssh_aging: {
    score: 25, confidence: 'SUSPECTED',
    title: 'OpenSSH banner reports an ageing version',
    rationale: 'The SSH banner reports a version that is no longer current. Nothing was tested against it; this is a maintenance observation rather than a demonstrated weakness.',
    remediation: 'Bring the service onto a supported version as part of normal patching.',
  },
  ssh_dropbear: {
    score: 20, confidence: 'SUSPECTED',
    title: 'Dropbear SSH in use',
    rationale: 'Dropbear is typical of embedded and appliance devices, which as a class are more likely to carry vendor default credentials. That is a reason to check this device, not a finding about it.',
    remediation: 'Confirm the device is inventoried and that its credentials were changed from the vendor default.',
  },
  mysql_exposed: {
    score: 55, confidence: 'CONFIRMED',
    title: 'MySQL reachable from the network',
    rationale: 'The database answered its handshake on the network. Reachability alone broadens the attack surface well past the application tier; no authentication attempt was made.',
    remediation: 'Bind to localhost or the application subnet and require TLS.',
  },
  http_server_version: {
    score: 15, confidence: 'CONFIRMED',
    title: 'Web server discloses its version',
    rationale: 'The Server header names the software and its version. On its own this is an information leak that assists an attacker in selecting an exploit; it is not itself a weakness.',
    remediation: 'Suppress the version in the Server header.',
  },
  http_powered_by: {
    score: 15, confidence: 'CONFIRMED',
    title: 'X-Powered-By header discloses the application stack',
    rationale: 'The response names the application framework and often its version. An information leak rather than a weakness.',
    remediation: 'Remove the X-Powered-By header.',
  },
  smb_v1_enabled: {
    score: 85, confidence: 'CONFIRMED',
    title: 'SMBv1 is enabled',
    rationale: 'The host accepted an SMBv1 dialect negotiation. SMBv1 has no pre-authentication integrity, is the protocol the large 2017 worm families spread over, and is deprecated by its vendor. This was measured, not inferred from a version string.',
    remediation: 'Disable SMBv1 on this host. Windows exposes it as an optional feature; on a NAS or an appliance it is usually a single setting.',
  },
  http_enumerated_path: {
    // Deliberately low. Directory enumeration finds paths; whether a path
    // matters depends entirely on what is behind it, and this tool does not
    // look. Scoring it higher would fill the headline figure with results that
    // need triage before they mean anything.
    score: 20, confidence: 'SUSPECTED',
    title: 'Path responded to directory enumeration',
    rationale: 'A request for this path returned a response rather than a 404, so something is served there. The content was not retrieved or examined, so this is a lead to follow rather than a finding in itself — an image directory and an unauthenticated admin console look identical from here.',
    remediation: 'Look at what the path actually serves. If it should not be reachable, block it at the web server.',
  },
  http_missing_frame_options: {
    score: 20, confidence: 'CONFIRMED',
    title: 'No clickjacking protection sent',
    rationale: 'The response carries neither X-Frame-Options nor a frame-ancestors directive, so the page can be framed by a third-party site.',
    remediation: 'Send Content-Security-Policy with frame-ancestors, or X-Frame-Options, on HTML responses.',
  },
};

/**
 * Turn the deep inspection modules' output into findings this report can carry.
 *
 * These results used to reach no further than React component state. `findings`
 * was written from two places only — access-point assessment and host discovery
 * — so an operator could watch an unauthenticated Redis appear on screen at
 * CRITICAL while the exported PDF printed "no findings were raised" for that
 * host. Every `vuln_engine` result was invisible to the deliverable.
 *
 * An observation whose `code` this rule set does not recognise is still
 * reported, at a score that cannot reach the headline figure and at SUSPECTED
 * confidence, and its rationale says plainly that the severity was not
 * independently assessed. Dropping it would hide a real observation; trusting
 * the engine's own severity label would put a number in the report that no rule
 * set produced.
 */
export function assessServiceObservations(
  target: string,
  observations: ServiceObservation[],
  opts: { simulated?: boolean } = {}
): Finding[] {
  const findings: Finding[] = [];
  const simulated = !!opts.simulated;
  const subject = String(target ?? '').trim();
  if (!subject) return findings;

  for (const obs of observations || []) {
    const code = String(obs?.code ?? '').trim();
    const port = typeof obs?.port === 'number' ? obs.port : null;
    const portSuffix = port === null ? '' : ` on port ${port}`;
    const detail = String(obs?.detail ?? '').trim();
    const rule = code ? SERVICE_RULES[code] : undefined;

    if (rule) {
      findings.push({
        subject_type: 'HOST', subject_id: subject,
        category: 'service_config',
        title: `${rule.title}${detail ? ` (${detail})` : ''}${portSuffix} — ${subject}`,
        risk_score: rule.score,
        severity: scoreToSeverity(rule.score),
        confidence: rule.confidence,
        rationale: obs.description
          ? `${rule.rationale} Engine detail: ${obs.description}`
          : rule.rationale,
        methodology: methodologyTag(`service_config/${code}`),
        remediation: rule.remediation,
        fingerprint: fingerprint('HOST', subject, 'service_config', `${port ?? '-'}:${code}${detail ? `:${detail}` : ''}`),
        is_simulated: simulated,
      });
      continue;
    }

    // Unrecognised check. Reported, but never allowed to carry a severity this
    // rule set did not decide.
    const label = String(obs?.vuln ?? code ?? 'unnamed service observation');
    findings.push({
      subject_type: 'HOST', subject_id: subject,
      category: 'service_config',
      title: `Unassessed service observation${portSuffix} — ${subject}`,
      risk_score: 20,
      severity: scoreToSeverity(20),
      confidence: 'SUSPECTED',
      rationale: `The service inspection reported "${label}"${obs.description ? `: ${obs.description}` : ''}. This rule set has no entry for it, so no severity was independently assessed and it is recorded at the lowest reportable score. Verify it by hand before relying on it or dismissing it.`,
      methodology: methodologyTag('service_config/unassessed'),
      remediation: 'Verify the observation manually and, if it matters, add a rule for it so it can be scored consistently.',
      fingerprint: fingerprint('HOST', subject, 'service_config', `${port ?? '-'}:${code || label}${detail ? `:${detail}` : ''}`),
      is_simulated: simulated,
    });
  }

  return findings;
}

/**
 * An `smb_enum_completed` payload as a set of service observations.
 *
 * The engine reports three states per check — true, false, and `None` for
 * "could not answer" — and only the first is a finding. `signing_required`
 * false is a finding; `signing_required` null means the check never reached the
 * host, and treating that as "signing is required" would report a clean
 * security posture for a machine that was merely firewalled. That was the bug
 * the tri-state was introduced to fix, so this must not undo it at the next
 * boundary.
 */
/**
 * `deep_ssl_scan_completed` payloads as service observations.
 *
 * Read from the structured fields, never from the engine's finding text. The
 * engine writes those sentences for the operator's screen and is free to reword
 * them; a rule set that matched on them would stop raising findings the day
 * somebody fixed a typo, with every test still green.
 *
 * Three-state fields are treated as three-state. `expired` and `self_signed` are
 * `null` when the certificate could not be parsed far enough to tell, and
 * `hsts.enabled` is `null` when the HTTPS request did not complete at all --
 * which is precisely the case `ssl_check.py` built its `inconclusive` list for:
 * "a check that did not run produces an entry in `inconclusive`, never a
 * finding". A `null` here must raise nothing, and the report says separately
 * that it could not be established.
 *
 * The port travels with each observation because a host can serve TLS on several
 * and the findings have to be distinguishable. It falls back to 443 only when
 * the payload carries no port at all.
 */
export function tlsObservations(payload: Record<string, any>): ServiceObservation[] {
  const out: ServiceObservation[] = [];
  const port = typeof payload?.port === 'number' ? payload.port : 443;
  const subject = typeof payload?.cn === 'string' && payload.cn ? `Certificate subject: ${payload.cn}.` : undefined;

  if (payload?.expired === true) {
    out.push({
      code: 'tls_certificate_expired', port,
      description: [subject, typeof payload?.expires === 'string' ? `Expired ${payload.expires}.` : undefined]
        .filter(Boolean).join(' ') || undefined,
    });
  }
  if (payload?.self_signed === true) {
    out.push({ code: 'tls_certificate_self_signed', port, description: subject });
  }

  // One finding, not one per version. Three deprecated versions on one port is
  // one thing to fix and one change window; three rows would inflate the count
  // the report leads with without adding an action.
  const accepted = Array.isArray(payload?.deprecated_tls?.accepted) ? payload.deprecated_tls.accepted : [];
  const versions = accepted
    .map((a: any) => (typeof a?.version === 'string' ? a.version : null))
    .filter((v: string | null): v is string => !!v);
  if (versions.length > 0) {
    out.push({
      code: 'tls_deprecated_version', port,
      description: `Accepted: ${versions.join(', ')}.`,
    });
  }

  const weak = Array.isArray(payload?.cipher_audit?.weak) ? payload.cipher_audit.weak : [];
  const weakNames = weak
    .map((w: any) => (typeof w?.name === 'string' ? w.name : typeof w === 'string' ? w : null))
    .filter((v: string | null): v is string => !!v);
  if (weakNames.length > 0) {
    out.push({
      code: 'tls_weak_cipher', port,
      // The caveat is carried into the finding because it changes what the
      // finding means: when only the negotiated suite could be observed, these
      // are the suites seen, not the complete set the server would accept.
      description: [
        `Weak suite(s): ${weakNames.join(', ')}.`,
        typeof payload?.cipher_audit?.caveat === 'string' ? payload.cipher_audit.caveat : undefined,
      ].filter(Boolean).join(' '),
    });
  }

  if (payload?.hsts?.enabled === false) {
    out.push({ code: 'tls_no_hsts', port });
  }

  return out;
}

export function smbObservations(payload: Record<string, any>): ServiceObservation[] {
  const out: ServiceObservation[] = [];
  const detail = [payload?.computer_name, payload?.os_version]
    .filter(v => v && v !== 'Unknown').join(', ');

  if (payload?.smbv1_enabled === true) {
    out.push({
      code: 'smb_v1_enabled', port: 445,
      description: detail ? `Host reported: ${detail}.` : undefined,
    });
  }
  if (payload?.signing_required === false) {
    out.push({
      code: 'smb_signing', port: 445,
      description: detail ? `Host reported: ${detail}.` : undefined,
    });
  }
  return out;
}

/**
 * `dirbuster_finding` events as service observations.
 *
 * One per responding path. The status code travels in the rationale because it
 * is what tells a reader whether to look: a 200 and a 403 are both "something
 * is there", but they need different follow-up.
 */
/**
 * Host part of a URL, or `null` when it cannot be read.
 *
 * Lives here, beside the rule that consumes it, because it decides the
 * `subject_id` a dirbuster finding is filed under. Two call sites deriving the
 * host by slightly different means would file the live scan and the archived
 * one under different subjects, and the retest delta would then report every
 * path as both fixed and new.
 */
export function hostOfUrl(url: unknown): string | null {
  if (typeof url !== 'string' || !url.trim()) return null;
  try {
    return new URL(url).host || null;
  } catch {
    return null;
  }
}

export function dirbusterObservations(
  findings: { path?: string; status?: number; size?: number }[]
): ServiceObservation[] {
  return (findings || [])
    .filter(f => f && f.path)
    .map(f => ({
      code: 'http_enumerated_path',
      // The path is the discriminator, not part of the subject: one web server
      // with twenty responding paths is one host with twenty observations.
      detail: f.path,
      description: `Path ${f.path} returned HTTP ${f.status ?? '?'}`
        + (typeof f.size === 'number' ? ` (${f.size} bytes)` : '')
        + '.',
    }));
}

// ── Aggregation ─────────────────────────────────────────────────────────────

export interface RiskSummary {
  total: number;
  bySeverity: Record<Severity, number>;
  byConfidence: Record<Confidence, number>;
  /**
   * Highest severity present, or `null` when there is nothing to rank.
   *
   * This used to be `'INFO'` for an empty set, which is a verdict where none was
   * possible: the report printed "Highest severity present: INFO" for an archive
   * that contained no access points at all, and a reader could not tell that
   * from "we assessed this and the worst thing present was informational".
   *
   * Same class of defect as reading an absent numeric column as a hard zero.
   * `null` forces the caller to say which of the two it is.
   */
  worst: Severity | null;
  /** Count at HIGH or above — the honest definition of the headline number. */
  significant: number;
}

export function summarise(findings: Finding[]): RiskSummary {
  const bySeverity: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const byConfidence: Record<Confidence, number> = { CONFIRMED: 0, LIKELY: 0, SUSPECTED: 0 };
  let worst: Severity | null = null;

  for (const f of findings) {
    bySeverity[f.severity]++;
    byConfidence[f.confidence]++;
    if (worst === null || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[worst]) worst = f.severity;
  }

  return {
    total: findings.length,
    bySeverity,
    byConfidence,
    worst,
    significant: bySeverity.CRITICAL + bySeverity.HIGH,
  };
}

/**
 * Worst severity for one subject — used for a per-row label in a table.
 *
 * `null` when this subject raised no findings, which is not the same as having
 * been assessed and found informational.
 */
export function severityForSubject(findings: Finding[], subjectId: string): Severity | null {
  const mine = findings.filter(f => f.subject_id.toUpperCase() === subjectId.toUpperCase());
  return summarise(mine).worst;
}

/**
 * The methodology block the report prints. A severity a reader cannot audit is
 * not evidence, so the scale and the rules travel with the document.
 */
export function describeMethodology() {
  return {
    id: METHODOLOGY_ID,
    version: METHODOLOGY_VERSION,
    bands: SEVERITY_BANDS,
    rules: {
      encryption: Object.fromEntries(
        Object.entries(ENCRYPTION_RULES).map(([k, v]) => [k, { score: v.score, level: scoreToSeverity(v.score) }])
      ),
      wps: { enabled_unlocked: 75, enabled_locked: 35 },
      rogue_ap: { CONFIRMED: 90, LIKELY: 75, SUSPECTED: 45 },
      exposed_service: Object.fromEntries(
        Object.entries(EXPOSED_SERVICE_RULES).map(([k, v]) => [k, { name: v.name, score: v.score }])
      ),
      service_cve: CVE_SEVERITY_SCORE,
      credentials: { recovered: 100 },
      snmp: { default_community: 70 },
      service_config: Object.fromEntries(
        Object.entries(SERVICE_RULES).map(([k, v]) => [k, {
          score: v.score, level: scoreToSeverity(v.score), confidence: v.confidence,
        }])
      ),
      service_config_unassessed: { score: 20, level: scoreToSeverity(20), confidence: 'SUSPECTED' },
    },
    confidence_meaning: {
      CONFIRMED: 'Directly observed by this tool during the assessment.',
      LIKELY: 'Inferred from strong evidence such as a version banner, but not exercised.',
      SUSPECTED: 'Indicators present but insufficient to assert. Requires manual verification.',
    },
    limitations: [
      'Severity is assessed from network-observable properties only; it does not account for the business value of the asset or compensating controls that are not visible over the network.',
      'CVE findings are matched from service banners and were not exploited. A banner can be inaccurate or deliberately altered.',
      'A small number of advisories cannot be matched from a banner at all, because the service does not publish a patch level — SMB and RDP are the cases here. Those are inferred from the operating system fingerprint together with the open port, are reported at SUSPECTED confidence with the basis stated in the finding, and must be confirmed by hand: a patched host is indistinguishable from an unpatched one by this method, and their absence is not evidence that a host is patched.',
      'Service-configuration findings state their own basis in each rationale. Some are demonstrated (an anonymous login that was accepted, a database that answered without authentication); others are read from a banner and are recorded at SUSPECTED confidence because no vulnerability was tested. An observation the rule set does not recognise is reported at the lowest reportable score with its severity explicitly unassessed, rather than being dropped or given the scanning module\'s own label.',
      'Absence of a finding is not proof of security: coverage depends on adapter capability, scan duration and the engagement scope.',
      'Where an access point published a station count in its BSS Load element, the rationale for an open or WEP network states how many devices were associated. That count is a snapshot taken while the survey was in radio range, not a measure of how much the network is used, and it does not affect the score: an unlocked network is equally misconfigured whether or not anyone is on it. Most adapters do not publish the element at all, and a network whose count is absent is reported without one rather than as having none.',
    ],
  };
}
