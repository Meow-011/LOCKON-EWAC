/**
 * LOCKON EWAC — Reading an archive, and turning it into report values.
 *
 * These lived at the top of `ReportsPage.tsx`, which had grown to 6,558 lines
 * with a 3,500-line PDF builder inside the component's closure. None of this is
 * page logic: it is how an archive is read (`apsOf`, `hostsOf`, `credentialsOf`
 * and friends), how it is assessed (`assessReport`, `worstBySubject`), and how
 * the results are worded for a document (`formatMetres`, `positionCaveats`,
 * `wpsLabel`).
 *
 * Moved verbatim rather than rewritten, so the compiler could verify the move
 * and nothing about the output changed. Two things follow from it being here:
 * the page shrinks to the thing it is named after, and these functions become
 * reachable from a test — most of them are pure, and several encode judgments
 * the report depends on ("not measured" is not "not present", an absent radius
 * is not a radius of zero) that were previously untestable.
 */
import { type Report as IntelReport } from '../../stores/reportStore';
import { finiteNumber, coordinatePair } from '../../lib/numbers';
import { type TargetKind } from '../../lib/scopeDB';
import {
  assessAccessPoint,
  assessHost,
  assessServiceObservations,
  smbObservations,
  tlsObservations,
  dirbusterObservations,
  hostOfUrl,
  type Finding,
  type Severity,
  type Confidence,
} from '../../lib/riskEngine';
import { engineIPC } from '../../lib/ipc';

/**
 * Hard cap on audit rows rendered into a PDF. The trail can grow without bound;
 * a report that tries to print all of it becomes unusable. When we trim, the
 * page says so and states the true total — evidence is never silently dropped.
 */
export const AUDIT_ROWS_IN_PDF = 300;

/** Order the authorized-target table groups so the PDF always reads the same. */
export const TARGET_KIND_ORDER: TargetKind[] = ['BSSID', 'SSID', 'IP', 'CIDR'];

export const TARGET_KIND_LABEL: Record<string, string> = {
  BSSID: 'BSSID (specific radio)',
  SSID: 'SSID (named network)',
  IP: 'IP ADDRESS (single host)',
  CIDR: 'CIDR (subnet range)',
};

/**
 * Mask a recovered secret so the report proves recovery without redistributing
 * the credential. Short secrets reveal length only — first/last on a 2-char
 * password is the whole password.
 */
export function maskSecret(raw: unknown): string {
  const s = raw === null || raw === undefined ? '' : String(raw);
  if (s.length === 0) return '(empty) (len 0)';
  if (s.length <= 3) return `${'*'.repeat(s.length)} (len ${s.length})`;
  const middle = '*'.repeat(Math.min(s.length - 2, 10));
  return `${s[0]}${middle}${s[s.length - 1]} (len ${s.length})`;
}

export function errText(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

/**
 * jsPDF's standard fonts are WinAnsi-encoded, so anything outside that set is
 * silently dropped or mangled in the output. Every string that reaches the
 * document goes through here, which also means field-captured data (an SSID
 * with a smart quote, a CVE description with an em dash) cannot corrupt a page.
 */
export function ascii(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value);
  return s
    .replace(/[‘’‚‛]/g, "'")
    .replace(/[“”„]/g, '"')
    .replace(/[‐-―]/g, '-')
    .replace(/[•·●▪]/g, '-')
    .replace(/…/g, '...')
    .replace(/[   ]/g, ' ')
    .replace(/→/g, '->')
    .replace(/[^\t\n\x20-\x7e]/g, '?');
}

// csvCell / csvRow moved to src/lib/csv.ts so they can be tested: they also
// neutralise spreadsheet formula injection now, and an SSID is a string the
// owner of the access point chooses.

/** XML text/attribute escaping for KML. Control characters are illegal in XML 1.0. */
export function xmlEscape(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value);
  return s
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/*
  Print colour per severity level.

  Defined in `src/lib/severityStyle.ts`, which owns the screen palette beside
  this one so the two cannot drift apart unnoticed. Re-exported here because
  every PDF section already imports its formatting from this module.
*/
export { SEVERITY_RGB, severityRgb } from '../severityStyle';

/*
  Position formatting and geometry moved to `src/lib/position.ts`.

  Which estimator produced a coordinate, the radius it is entitled to, whether
  a second position fits equally well and the ring that says so are not
  archive-reading -- and by the end the live map, the target drawer and the
  uncertainty overlay all needed them, which meant importing a module that
  reaches `engineIPC` and `scopeDB` to format a number.

  Re-exported here so the move itself changed no call site.
*/
export {
  LOCATION_METHOD_LABEL,
  LOCATION_METHOD_NOTE,
  locationMethodLabel,
  locationMethodNote,
  formatCoord,
  formatLocationConfidence,
  formatErrorRadius,
  formatMetres,
  apMirror,
  isMirrorAmbiguous,
  isUnresolved,
  locationNotesOf,
  positionCaveats,
  AMBIGUOUS_FLAG,
  circlePolygon,
} from '../position';
// Bound here as well as re-exported above: a bare `export ... from` re-exports
// without binding the names in this module's own scope, and these are called
// by functions that stayed.
import { isMirrorAmbiguous } from '../position';

/** Median of a numeric set. Returns null for an empty set rather than 0. */
export function medianOf(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

export interface PositionQuality {
  total: number;
  positioned: number;
  ambiguous: number;
  wellConstrained: number;
  radiusStated: number;
  radiusMissing: number;
  medianErrorM: number | null;
  medianWellConstrainedM: number | null;
  worstErrorM: number | null;
  ambiguousAps: any[];
  methods: Map<string, number>;
}

/**
 * Position quality across a set of access point rows.
 *
 * "Well constrained" means positioned and not mirror-ambiguous. It does not mean
 * accurate: it means the geometry of the drive was good enough to pick one side
 * of the road, and the stated radius still applies.
 */
export function summarisePositions(aps: any[]): PositionQuality {
  // Checked as a pair and range-checked: a row with no fix must not be counted
  // as positioned, and 0, 0 is a legal coordinate no survey here will produce.
  const positionedAps = aps.filter(ap => coordinatePair(ap?.latitude, ap?.longitude) !== null);
  const ambiguousAps = positionedAps.filter(isMirrorAmbiguous);
  const radii = positionedAps
    .map(ap => finiteNumber(ap?.location_error_m))
    .filter((v): v is number => v !== null && v >= 0);
  const wellConstrainedRadii = positionedAps
    .filter(ap => !isMirrorAmbiguous(ap))
    .map(ap => finiteNumber(ap?.location_error_m))
    .filter((v): v is number => v !== null && v >= 0);
  const methods = new Map<string, number>();
  for (const ap of positionedAps) {
    const key = typeof ap?.location_method === 'string' && ap.location_method ? ap.location_method : 'not recorded';
    methods.set(key, (methods.get(key) ?? 0) + 1);
  }
  return {
    total: aps.length,
    positioned: positionedAps.length,
    ambiguous: ambiguousAps.length,
    wellConstrained: positionedAps.length - ambiguousAps.length,
    radiusStated: radii.length,
    radiusMissing: positionedAps.length - radii.length,
    medianErrorM: medianOf(radii),
    medianWellConstrainedM: medianOf(wellConstrainedRadii),
    worstErrorM: radii.length ? Math.max(...radii) : null,
    ambiguousAps,
    methods,
  };
}

/*
  The record-to-rule-set bridge moved to `src/lib/apRisk.ts`.

  It was always a different subject from this file -- turning a row into the risk
  engine's input is not wording an archive for a document -- and the difference
  became load-bearing when the live map needed `isHighRiskAp`. This file reaches
  `engineIPC` and `scopeDB`, so importing it from the dashboard pulled the sidecar
  bridge and the SQL plugin along; `apRisk.ts` depends on nothing but the rule set.

  Re-exported rather than relocated at every call site, so the move itself changed
  no behaviour and `tsc` checked it.
*/
// Bound here as well as re-exported below: a bare `export ... from` re-exports
// without binding the names in this module's own scope, and three of them are
// called by functions that stayed.
import { toApInput, toHostInput, worstOf } from '../apRisk';

export {
  wpsMeasured,
  wpsObserved,
  wpsLabel,
  rogueIndicatorsOf,
  rogueVerdictOf,
  toApInput,
  toHostInput,
  worstOf,
  isHighRiskAp,
  HEURISTIC_ONLY_INDICATOR,
  type RogueIndicator,
} from '../apRisk';

/**
 * A stable identifier for a set of archives.
 *
 * Deterministic: the same selection always yields the same id, and any change
 * to the selection yields a different one. That is what makes it usable as a
 * reference — the previous `MULTI-${Date.now()}` was a fresh number on every
 * export of the same content, recorded nowhere.
 *
 * FNV-1a, because this needs to be reproducible and short, not cryptographic:
 * the document's integrity is established by the SHA-256 digests recorded for
 * the file, not by its name.
 */
export function stableSelectionId(ids: string[]): string {
  const joined = [...ids].sort().join('|');
  let hash = 0x811c9dc5;
  for (let i = 0; i < joined.length; i++) {
    hash ^= joined.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).toUpperCase().padStart(8, '0');
}

/**
 * `worstOf` applied per subject, so every view and every export label a row the
 * same way.
 *
 * Returns a lookup rather than a Map so the callers read identically.
 */
export function worstBySubject(findings: Finding[]): (id: unknown) => { severity: Severity; confidence: Confidence | null } {
  const grouped = new Map<string, Finding[]>();
  for (const f of findings) {
    const key = f.subject_id.toUpperCase();
    const bucket = grouped.get(key);
    if (bucket) bucket.push(f);
    else grouped.set(key, [f]);
  }
  const resolved = new Map<string, { severity: Severity; confidence: Confidence | null }>();
  for (const [key, group] of grouped) resolved.set(key, worstOf(group));
  return (id: unknown) =>
    resolved.get(String(id ?? '').toUpperCase()) ?? { severity: 'INFO' as Severity, confidence: null };
}

/**
 * Every archive that is not a LAN intrusion sweep is a wireless survey. The page
 * used to test for `WIFI_WARDRIVE` exactly, so a `WIFI_SCAN` archive was rendered
 * and exported through the LAN-host path and came out empty.
 */
export function isWirelessReport(report: IntelReport): boolean {
  return report.type !== 'INTRUSION';
}

/** Every AP row an archive might carry, under either key the engine has used. */
export function apsOf(report: IntelReport): any[] {
  const raw = report.rawData?.accessPoints ?? report.rawData?.aps ?? [];
  return Array.isArray(raw) ? raw : [];
}

/**
 * One entry per physical radio, by BSSID, keeping the first sighting of each.
 *
 * Every population figure in the document is deduplicated this way, because two
 * archives of one estate are still one estate: `totalAPs` in `assemble.ts` sets the
 * rule, and `allFindings`, `wpsEntries`, `rogueEntries` and POSITION QUALITY all
 * follow it, each with a comment saying why.
 *
 * Two places did not. The WPS denominator and the survey map's AP set were plain
 * `flatMap`s, so a merged export of two archives covering the same 50 radios printed
 * "Of the 100 access point(s) in this archive" beside an ACCESS POINTS tile reading
 * 50 — and halved the apparent WPS coverage rate, because `wpsEntries` *was*
 * deduplicated and only the denominator doubled. The map drew every radio twice and
 * double-counted it in the figure's own census.
 *
 * An AP with no BSSID cannot be deduplicated, so it is kept as its own entry rather
 * than silently collapsed with every other blank one — the same choice `totalAPs`
 * makes, for the same reason.
 */
export function dedupeApsByBssid(aps: any[]): any[] {
  const seen = new Set<string>();
  const out: any[] = [];
  for (const ap of aps) {
    const id = String(ap?.bssid ?? '').toUpperCase();
    if (!id) { out.push(ap); continue; }
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(ap);
  }
  return out;
}

export function hostsOf(report: IntelReport): any[] {
  const raw = report.rawData?.hosts ?? [];
  return Array.isArray(raw) ? raw : [];
}

export function credentialsOf(report: IntelReport): any[] {
  const raw = report.rawData?.credentials ?? [];
  return Array.isArray(raw) ? raw : [];
}

/**
 * Per-subnet sweep coverage carried by an intrusion archive.
 *
 * Empty for archives written before this was recorded, which is why the report
 * distinguishes "no coverage figures were recorded" from "the sweep was
 * complete" rather than assuming the latter.
 */
export function sweepScopesOf(report: IntelReport): any[] {
  const raw = (report.rawData as any)?.sweepScopes ?? [];
  return Array.isArray(raw) ? raw : [];
}

/**
 * Mission id, if the archive carries one. Coverage is computed per mission, so
 * an archive without one cannot have a coverage section — and the report says so
 * rather than dropping the section silently.
 */
export function missionIdOf(report: IntelReport): string | null {
  const raw = report.rawData ?? {};
  const candidate = raw.missionId ?? raw.mission_id ?? raw.mission?.id ?? null;
  return typeof candidate === 'string' && candidate.trim() ? candidate : null;
}

/**
 * Service-inspection results carried by an intrusion archive.
 *
 * Absent from archives written before these were recorded, which is why the
 * report says the inspection was not recorded rather than that it found nothing.
 */
export function serviceObservationsOf(report: IntelReport): any[] {
  const raw = (report.rawData as any)?.serviceObservations ?? [];
  return Array.isArray(raw) ? raw : [];
}

/**
 * SMB enumeration result carried by an intrusion archive, if any.
 *
 * One host per archive: the enumeration is launched from a selected host, so
 * only the last one enumerated before the archive was written is present. The
 * payload names its own target, so a result is never attributed to whichever
 * host happened to be selected at archive time.
 */
export function smbEnumOf(report: IntelReport): Record<string, any> | null {
  const raw = (report.rawData as any)?.smbEnum;
  return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : null;
}

/**
 * Network segmentation result carried by an intrusion archive.
 *
 * Context, not findings -- the same treatment as the traceroute path and for a
 * sharper reason. Every field in the map except `gateway_alive` is derived from
 * a CIDR string: the VLAN id is the third octet, the gateway is the first usable
 * address by convention. The engine ships `vlan_id_basis` and `gateway_basis`
 * alongside them so a consumer cannot render a guess as a measurement, and
 * nothing here is routed through the risk rule set, because a findings count is
 * a number management acts on and an inferred topology has no business inflating
 * it.
 */
export function segmentationOf(report: IntelReport): Record<string, any> | null {
  const raw = (report.rawData as any)?.segmentation;
  return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : null;
}

/**
 * TLS inspection result carried by an intrusion archive.
 *
 * One per archive, like the SMB result and for the same reason: the drawer holds
 * the most recent scan, so an archive written after inspecting several hosts
 * carries only the last. The payload names its own target and its own port, so a
 * result is never attributed to whichever host was selected at archive time, and
 * never to the wrong port on the right host.
 */
export function tlsInspectionOf(report: IntelReport): Record<string, any> | null {
  const raw = (report.rawData as any)?.tlsInspection;
  return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : null;
}

/**
 * Directory-enumeration result carried by an intrusion archive.
 *
 * The host comes from each hit's own URL rather than from the archive, for the
 * same reason as above.
 *
 * `complete` is `null` when the archive does not record it, which is not the
 * same as `false`. Only an exhausted wordlist licenses a statement about the
 * paths that did *not* respond, so the three states stay distinct all the way
 * to the page.
 */
export function dirbusterOf(report: IntelReport): { hits: any[]; complete: boolean | null } {
  const raw = (report.rawData as any)?.dirbuster;
  if (!raw) return { hits: [], complete: null };
  const hits = Array.isArray(raw?.hits) ? raw.hits : [];
  return { hits, complete: typeof raw?.complete === 'boolean' ? raw.complete : null };
}

/**
 * Traceroute path carried by an intrusion archive.
 *
 * Deliberately *not* turned into findings. "NAT boundary detected at hop 4" and
 * "possible firewall between hop 6 and the target" describe the shape of the
 * path, not a weakness in it; running them through the rule set would pad the
 * findings table — and therefore the headline count a manager reads — with rows
 * that are not vulnerabilities. It gets its own context section instead.
 */
export function traceroutePathOf(report: IntelReport): { target?: string; hops?: any[]; analysis?: any[] } | null {
  const raw = (report.rawData as any)?.traceroutePath;
  return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : null;
}

/** Findings for one archive, from the single rule set. Pure; no database. */
export function assessReport(report: IntelReport): Finding[] {
  const simulated = !!report.simulated;
  if (report.type === 'INTRUSION') {
    const creds = credentialsOf(report);
    const hostFindings = hostsOf(report).flatMap(h => assessHost(toHostInput(h, creds, simulated)));
    // Deep-inspection results are assessed by the same rule set as everything
    // else, so an unauthenticated Redis reaches the document through the same
    // path — and with the same severity scale — as an exposed port.
    const serviceFindings = serviceObservationsOf(report).flatMap((entry: any) =>
      assessServiceObservations(
        String(entry?.target ?? ''),
        Array.isArray(entry?.findings) ? entry.findings : [],
        { simulated }
      )
    );

    // SMB enumeration. Only `true`/`false` answers become findings — the engine
    // sends `null` for a check that could not complete, and a missing answer
    // must never read as "signing is required".
    const smb = smbEnumOf(report);
    const smbFindings = smb
      ? assessServiceObservations(String(smb.target ?? ''), smbObservations(smb), { simulated })
      : [];

    // Directory enumeration, grouped by the host each hit's URL names.
    const hitsByHost = new Map<string, any[]>();
    for (const hit of dirbusterOf(report).hits) {
      const host = hostOfUrl(hit?.url);
      if (!host) continue;
      const bucket = hitsByHost.get(host);
      if (bucket) bucket.push(hit);
      else hitsByHost.set(host, [hit]);
    }
    const dirbusterFindings = [...hitsByHost.entries()].flatMap(([host, hits]) =>
      assessServiceObservations(host, dirbusterObservations(hits), { simulated })
    );

    // TLS inspection. Same rule as SMB above: only a `true` answer becomes a
    // finding. `expired`, `self_signed` and `hsts.enabled` are all null when the
    // check could not establish an answer, and a null that read as "valid" would
    // certify a certificate nobody managed to parse.
    const tls = tlsInspectionOf(report);
    const tlsFindings = tls
      ? assessServiceObservations(String(tls.target ?? ''), tlsObservations(tls), { simulated })
      : [];

    return [...hostFindings, ...serviceFindings, ...smbFindings, ...dirbusterFindings, ...tlsFindings];
  }
  return apsOf(report).flatMap(ap => assessAccessPoint(toApInput(ap, simulated)));
}

/** Hand a generated file to the browser's download handler. Throws on failure. */
export function downloadBlob(blob: Blob, fileName: string): void {
  const objectUrl = URL.createObjectURL(blob);
  try {
    const link = document.createElement('a');
    link.href = objectUrl;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  } catch (err) {
    URL.revokeObjectURL(objectUrl);
    throw err;
  }
  setTimeout(() => URL.revokeObjectURL(objectUrl), 60000);
}

/**
 * The engine's `methodology` payload, best-effort.
 *
 * The method appendix is what makes a severity auditable, so it is worth asking
 * the engine directly for its own version, CVE vintage, evil-twin rules and
 * capability probe. When the engine is not running the appendix still prints,
 * from the store's last known values, and says which parts are missing.
 */
export interface EngineMethodology {
  engine_version?: string;
  platform?: string;
  cve_data?: {
    origin?: string; source?: string; generated_at?: string | null; age_days?: number | null;
    stale?: boolean; entry_count?: number; coverage_note?: string;
  };
  evil_twin?: {
    name?: string; version?: number;
    weights?: Record<string, number>;
    thresholds?: Record<string, number>;
    reported_as_evil_twin_at?: string;
    legitimate_encryption_pairs?: string[][];
    limitations?: string[];
  };
  capabilities?: Record<string, any>;
  /**
   * The engine's own view of the scope at export time, from
   * `ScopePolicy.describe()`. `gated_commands` is the authoritative list of
   * commands the gate actually covers.
   *
   * The report must generate its claim about refusals from this list rather
   * than asserting a blanket one. It previously printed "the engine refused
   * every targeted offensive command against anything not listed here", which
   * is only true if every targeted command is gated — and the gated set is
   * deliberately narrower than that, covering the commands that can disrupt,
   * authenticate or intercept rather than every command that emits a packet.
   */
  scope?: {
    loaded?: boolean;
    mode?: string;
    gated_commands?: string[];
  };
}

export function fetchEngineMethodology(timeoutMs = 2500): Promise<EngineMethodology | null> {
  if (!engineIPC.connected) return Promise.resolve(null);
  return new Promise(resolve => {
    let settled = false;
    const finish = (value: EngineMethodology | null) => {
      if (settled) return;
      settled = true;
      unsubscribe();
      clearTimeout(timer);
      resolve(value);
    };
    const unsubscribe = engineIPC.on('methodology', msg => {
      finish((msg.data ?? null) as EngineMethodology | null);
    });
    const timer = setTimeout(() => finish(null), timeoutMs);
    engineIPC.send('get_methodology').catch(() => finish(null));
  });
}

