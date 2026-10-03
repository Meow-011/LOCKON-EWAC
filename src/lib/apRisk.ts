/**
 * Between a stored record and the one risk rule set.
 *
 * Why this is its own module.
 *
 * These helpers turn a row -- an archived access point, a LAN host, a live
 * sighting -- into the input `riskEngine` expects, and read its output back. That
 * is not "reading an archive and wording it for a document", which is what
 * `report/archive.ts` is for and where they used to live. The difference stopped
 * being academic when the live map needed one of them: `archive.ts` reaches
 * `engineIPC` and `scopeDB`, so asking it whether an access point is high risk
 * pulled the sidecar bridge and the SQL plugin into the dashboard.
 *
 * Nothing here touches Tauri, MapLibre, jsPDF or the DOM. That is the property
 * worth keeping: it is what lets the live map, the report and the exports answer
 * the same question the same way.
 *
 * `archive.ts` re-exports every name below, so the move changed no call site and
 * the compiler verified it.
 */
import {
  assessAccessPoint,
  SEVERITY_ORDER,
  type ApInput,
  type HostInput,
  type Finding,
  type Severity,
  type Confidence,
} from './riskEngine';

export interface RogueIndicator { code: string; weight: number; detail: string }

/**
 * Whether a WPS scan actually covered this access point.
 *
 * `access_points.wps_enabled` is `INTEGER NOT NULL DEFAULT 0` (migration 008),
 * so a zero there is ambiguous on its own: it is the column default for every
 * access point ever inserted. The report used to read it as an observation and
 * print a callout saying no access point advertised WPS "in its beacon",
 * describing a beacon parse that had never run — a positive measurement claim
 * with no measurement behind it, wrapped in hedging that made it read as rigour.
 *
 * `wps_scanned_at` (migration 013) is what disambiguates it. Present means a
 * `scan_wps` run parsed this access point's beacon, and `wps_enabled` is then a
 * real result *including when it is false*. Absent means no WPS scan has ever
 * covered it.
 *
 * A positive `wps_enabled` is also accepted on its own, for archives written
 * before migration 013: a true there could only have come from a real scan.
 */
export function wpsMeasured(ap: any): boolean {
  const at = ap?.wps_scanned_at;
  if (typeof at === 'string' && at.trim()) return true;
  return ap?.wps_enabled === true || ap?.wps_enabled === 1;
}

/** Whether this record carries a positive WPS observation. */
export function wpsObserved(ap: any): boolean {
  return wpsMeasured(ap) && (ap?.wps_enabled === true || ap?.wps_enabled === 1);
}

/** WPS exposure, stated the way the report has to state it. Three states. */
export function wpsLabel(ap: any): string {
  if (!wpsMeasured(ap)) return 'not measured';
  if (!wpsObserved(ap)) return 'not advertised';
  return ap?.wps_locked ? 'ENABLED (rate-limited)' : 'ENABLED (unlocked)';
}

export function rogueIndicatorsOf(ap: any): RogueIndicator[] {
  const raw = Array.isArray(ap?.rogue_indicators) ? ap.rogue_indicators : [];
  return raw
    .filter((i: any) => i && typeof i.detail === 'string')
    .map((i: any) => ({
      code: String(i.code ?? 'indicator'),
      weight: Number(i.weight ?? 0),
      detail: String(i.detail),
    }));
}

/**
 * The engine's rogue scorer emits `{verdict, score, indicators}` per AP. Older
 * archives carry only the boolean `is_evil_twin` produced by the
 * SSID/encryption-split heuristic. A bare boolean is not a verdict, so it is
 * mapped to SUSPECTED with the reason spelled out rather than presented as a
 * confirmed rogue access point.
 */
export const HEURISTIC_ONLY_INDICATOR: RogueIndicator = {
  code: 'ssid_encryption_split',
  weight: 0,
  detail: 'This SSID was observed broadcasting under more than one security configuration. That is the pattern an evil twin produces, and it is equally the pattern of a legitimate mixed-mode or WPA2/WPA3 transition deployment, so it is reported as suspected only and no per-indicator score is available for this archive.',
};

export function rogueVerdictOf(ap: any): { verdict: string | undefined; indicators: RogueIndicator[]; heuristicOnly: boolean } {
  const stated = typeof ap?.rogue_verdict === 'string' && ap.rogue_verdict.trim()
    ? String(ap.rogue_verdict).toUpperCase()
    : undefined;
  if (stated) return { verdict: stated, indicators: rogueIndicatorsOf(ap), heuristicOnly: false };
  if (ap?.is_evil_twin) return { verdict: 'SUSPECTED', indicators: [HEURISTIC_ONLY_INDICATOR], heuristicOnly: true };
  return { verdict: undefined, indicators: [], heuristicOnly: false };
}

/** Archived AP row -> the one risk rule set's input. */
export function toApInput(ap: any, reportSimulated: boolean): ApInput {
  const { verdict, indicators } = rogueVerdictOf(ap);
  return {
    bssid: String(ap?.bssid ?? ''),
    ssid: ap?.ssid || undefined,
    encryption: ap?.encryption || undefined,
    vendor: ap?.vendor || undefined,
    channel: typeof ap?.channel === 'number' ? ap.channel : undefined,
    band: ap?.band || undefined,
    // Only a positive observation reaches the rule set. `!!ap?.wps_enabled` on a
    // NOT NULL DEFAULT 0 column turned "never measured" into a confident false,
    // which the risk engine is right to treat as "no WPS finding" but which the
    // report then printed as an observation. See `wpsObserved`.
    wps_enabled: wpsObserved(ap),
    wps_locked: ap?.wps_locked === true || ap?.wps_locked === 1,
    is_evil_twin: !!ap?.is_evil_twin,
    rogue_verdict: verdict,
    rogue_score: typeof ap?.rogue_score === 'number' ? ap.rogue_score : undefined,
    rogue_indicators: indicators,
    // `typeof`, not `?? undefined`: 0 is a measurement ("the AP published a
    // count and it was zero") and has to survive, while a missing element must
    // stay undefined so the rule set says nothing about it.
    connected_stations: typeof ap?.connected_stations === 'number' ? ap.connected_stations : undefined,
    simulated: !!ap?.simulated || reportSimulated,
  };
}

/** Archived LAN host row -> the one risk rule set's input. */
export function toHostInput(host: any, credentials: any[], reportSimulated: boolean): HostInput {
  const cred = credentials.find(c => c && String(c.target_ip) === String(host?.ip));
  return {
    ip: String(host?.ip ?? ''),
    hostname: host?.hostname || undefined,
    os: host?.os || undefined,
    open_ports: (host?.open_ports || [])
      .filter((p: any) => p && p.port !== undefined && p.port !== null)
      .map((p: any) => ({
        port: Number(p.port),
        service: p.service || undefined,
        banner: p.banner || undefined,
        cves: Array.isArray(p.cves) ? p.cves : [],
      })),
    /*
      The vault snapshot first, then the host record's own field.

      `engine/scanner/lan.py` runs a quick credential check during a DEEP sweep
      and puts the result on the host as `default_creds`. This helper only ever
      read the credentials array, so a credential the sweep itself demonstrated
      was dropped unless it also happened to be in the vault snapshot — and
      `credentials.recovered` is the top of the scale at 100. A demonstrated
      login is the strongest finding this tool can make; it must not depend on
      which subsystem happened to record it.
    */
    default_creds: cred && cred.username
      ? { username: String(cred.username), password: cred.password }
      : host?.default_creds?.username
        ? { username: String(host.default_creds.username), password: host.default_creds.password }
        : undefined,
    snmp_communities: Array.isArray(host?.snmp_communities) ? host.snmp_communities : [],
    simulated: !!host?.simulated || reportSimulated,
  };
}

/**
 * Worst severity across a set of findings, and the confidence attached to it.
 *
 * The one rule. There used to be three implementations of this in this file and
 * they did not agree:
 *
 *   * this one, tie-breaking equal severities by `risk_score` — used by the
 *     CSV, KML and GeoJSON exports;
 *   * `severityBySubject`, which kept the *first* finding at the maximum
 *     severity — used on screen;
 *   * `subjectWorst`/`worstFor`, which did the same — used by the PDF.
 *
 * Severity always agreed, because the score-to-severity map is monotone. The
 * **confidence label** did not. An access point with WPS-locked (35, LOW,
 * CONFIRMED) and rogue-SUSPECTED (45, MEDIUM, SUSPECTED) came out MEDIUM /
 * CONFIRMED in the PDF and MEDIUM / SUSPECTED in the CSV — and confidence is
 * the axis this document spends a page insisting matters.
 *
 * Tie-breaking on `risk_score` is the deterministic choice: it does not depend
 * on the order findings happen to arrive in.
 */
export function worstOf(findings: Finding[]): { severity: Severity; confidence: Confidence | null } {
  let best: Finding | null = null;
  for (const f of findings) {
    if (!best || SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[best.severity] ||
      (SEVERITY_ORDER[f.severity] === SEVERITY_ORDER[best.severity] && f.risk_score > best.risk_score)) {
      best = f;
    }
  }
  return best ? { severity: best.severity, confidence: best.confidence } : { severity: 'INFO', confidence: null };
}

/**
 * Whether this access point is one the operator should look at first.
 *
 * The question a red dot on a map is answering, and it had two answers.
 *
 * The report's map derived it from the rule set -- `assessAccessPoint` then
 * `worstOf`, HIGH or above -- under a comment saying "so a marker's colour and
 * its row's severity cannot disagree". The live map asked
 * `is_vulnerable || encryption === 'OPEN'`, which is not the same question: a
 * WPA2 network that the rule set raises a HIGH finding against without the
 * engine having set `is_vulnerable` was **green on screen and red in the
 * report**, and the MAP FILTER's RISK button filtered the two maps differently.
 *
 * The report map was fixed and the live map was never brought along, which is
 * what happens when the rule lives at the call site. It lives here now.
 *
 * `simulated` is passed rather than read off the record because a live sighting
 * carries it per-row while an archived one inherits it from the report.
 */
export function isHighRiskAp(ap: any, simulated = false): boolean {
  const { severity } = worstOf(assessAccessPoint(toApInput(ap, simulated)));
  return SEVERITY_ORDER[severity] >= SEVERITY_ORDER.HIGH;
}
