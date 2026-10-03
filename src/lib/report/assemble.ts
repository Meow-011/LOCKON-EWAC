/**
 * LOCKON EWAC — everything a report says, gathered before anything is drawn.
 *
 * This was the first third of `buildAndSavePDF`, a 2,900-line function inside
 * `ReportsPage`'s closure. The split is along a line that was already there in
 * the comments: the function opened with seven labelled blocks that read the
 * database and reconcile the numbers, and only then started emitting pages.
 * Nothing above the cover page touched `doc`.
 *
 * Why it matters that this half is out here. Every figure a manager reads is
 * decided in this file — the headline counts, the deduplication that stops one
 * access point surveyed twice from doubling the risk figure, which rogue verdict
 * wins when two archives disagree, whether a coverage row is the archive's own
 * frozen copy or a recomputed one. All of it was unreachable from a test because
 * it lived in a component closure, and the defects this project has actually
 * shipped were all of that shape: a number that was right in one place and wrong
 * in another, in a document nobody could assert against.
 *
 * Moved verbatim. The compiler verified the move and `pdfdiff` verified the
 * output: same 101 text streams, same 16,129 strings, page for page.
 *
 * **Every read here is allowed to fail without taking the export down.** A
 * report that cannot be produced because the audit table is locked is worse than
 * one that prints "the audit trail could not be read" — so each block records
 * its own error string and the document states it. Do not turn these into
 * throws; the section that renders each one knows how to say "unavailable", and
 * silence would be the only unacceptable outcome.
 */
import { type Report as IntelReport } from '../../stores/reportStore';
import { useEngineStore } from '../../stores/engineStore';
import { revealArchivedCredentials } from '../credentialDB';
import {
  getActiveScope,
  getAuditCount,
  getAuditLog,
  getAuditLogForScope,
  getAuditSummary,
  type AuditRow,
  type EngagementScopeWithTargets,
} from '../scopeDB';
import {
  assessAccessPoint,
  describeMethodology,
  summarise,
  SEVERITY_ORDER,
  type Confidence,
  type Finding,
  type Severity,
} from '../riskEngine';
import {
  compareToBaseline,
  getClientSummary,
  getClientsForBssid,
  getEvidence,
  getFindings,
  type ClientRow,
  type EvidenceRow,
  type RetestDelta,
} from '../findingsDB';
import { computeAndStoreCoverage, getCoverage, type CoverageRow } from '../coverageDB';
import {
  AUDIT_ROWS_IN_PDF,
  apsOf,
  assessReport,
  credentialsOf,
  errText,
  fetchEngineMethodology,
  hostsOf,
  isWirelessReport,
  missionIdOf,
  rogueVerdictOf,
  toApInput,
  worstBySubject,
  wpsObserved,
  type EngineMethodology,
  type RogueIndicator,
} from './archive';

/** One rogue/evil-twin access point, with the clients seen on it. */
export interface RogueEntry {
  report: IntelReport;
  ap: any;
  verdict: string;
  score: number | null;
  heuristicOnly: boolean;
  indicators: RogueIndicator[];
  severity: Severity;
  confidence: Confidence | null;
  clients: ClientRow[];
}

export interface WpsEntry {
  report: IntelReport;
  ap: any;
  severity: Severity;
}

export interface CoverageSection {
  report: IntelReport;
  missionId: string | null;
  row: CoverageRow | null;
  error: string | null;
}

/** The two values the page owns rather than the database. */
export interface AssembleOptions {
  /** The archive chosen as the retest baseline, or null for no comparison. */
  baselineId: number | null;
  /** A delta the page has already computed for that baseline, if it has one. */
  baselineDelta: RetestDelta | null;
}

/** Everything the document is built from. Read-only from here on. */
export interface ReportData {
  /** The archives this export covers, in the order the operator selected them. */
  reportsArray: IntelReport[];
  isMulti: boolean;

  // Provenance
  simulatedReports: IntelReport[];
  fieldReports: IntelReport[];
  anySimulated: boolean;
  allSimulated: boolean;
  isMixedProvenance: boolean;

  // Authorization and the scope gate's trail
  activeScope: EngagementScopeWithTargets | null;
  scopeReadError: string | null;
  auditRows: AuditRow[];
  auditTotal: number;
  auditAllowed: number;
  auditBlocked: number;
  auditGlobal: { allowed: number; blocked: number } | null;
  auditReadError: string | null;
  auditTruncated: boolean;

  // One rule set, one set of numbers
  assessed: { report: IntelReport; findings: Finding[]; summary: ReturnType<typeof summarise> }[];
  allFindings: Finding[];
  overall: ReturnType<typeof summarise>;
  totalAPs: number;
  totalNodes: number;
  allCredentials: any[];
  worstFor: ReturnType<typeof worstBySubject>;
  findingStatus: Map<string, string>;
  findingsDbError: string | null;

  // Rogue / WPS / clients
  rogueEntries: RogueEntry[];
  wpsEntries: WpsEntry[];
  clientTotals: { total: number; randomized: number; associated: number; probe_only: number } | null;
  clientReadError: string | null;

  // Evidence register
  evidenceRows: EvidenceRow[];
  evidenceReadError: string | null;

  // Survey coverage
  coverageSections: CoverageSection[];

  // Method appendix
  methodology: ReturnType<typeof describeMethodology>;
  /*
    The engine's own answer to `get_methodology`, kept whole.

    Two sections read fields off it that nothing else needs — the engine's
    platform string, and `scope.gated_commands`, which is the authoritative list
    of commands the gate actually covers. The report has to generate its claim
    about refusals from that list rather than asserting a blanket one: the gated
    set is deliberately narrower than "every command that emits a packet", and
    the document used to overstate it.

    `null` when the engine did not answer, which the sections say out loud.
  */
  engineMethodology: EngineMethodology | null;
  /*
    The commands the scope gate actually covers, as the engine reports them.

    Read by two sections — the authorization record and the method appendix —
    and they have to agree, because one states the claim and the other states
    the basis for it. Empty when the engine did not answer, and both sections
    say so rather than asserting a blanket refusal the gate does not make.
  */
  gatedCommands: string[];
  cveData: EngineMethodology['cve_data'] | null;
  capabilities: Record<string, any> | null;
  evilTwinMethod: NonNullable<EngineMethodology['evil_twin']> | null;
  appVersion: string | undefined;
  engineVersion: string | null;

  // Retest
  retest: RetestDelta | null;
  retestError: string | null;
}

export async function assembleReportData(
  reportsArray: IntelReport[],
  { baselineId, baselineDelta }: AssembleOptions,
): Promise<ReportData> {
  const isMulti = reportsArray.length > 1;

  // ── Provenance: which of these operations came from the hardware simulator ──
  const simulatedReports = reportsArray.filter(r => r.simulated);
  const fieldReports = reportsArray.filter(r => !r.simulated);
  const anySimulated = simulatedReports.length > 0;
  const allSimulated = anySimulated && fieldReports.length === 0;
  const isMixedProvenance = anySimulated && fieldReports.length > 0;

  // ── Authorization record + scope-gate audit trail ──
  let activeScope: EngagementScopeWithTargets | null = null;
  let scopeReadError: string | null = null;
  try {
    activeScope = await getActiveScope();
  } catch (err) {
    scopeReadError = errText(err);
  }

  let auditRows: AuditRow[] = [];
  let auditTotal = 0;
  let auditAllowed = 0;
  let auditBlocked = 0;
  let auditGlobal: { allowed: number; blocked: number } | null = null;
  let auditReadError: string | null = null;
  try {
    // Scope-specific when an authorization record exists, otherwise the most
    // recent archive-wide events so an unscoped export still shows its trail.
    const all = activeScope
      ? await getAuditLogForScope(activeScope.id)
      : await getAuditLog(5000);
    auditTotal = all.length;
    auditAllowed = all.filter(r => r.decision === 'ALLOWED').length;
    auditBlocked = all.filter(r => r.decision === 'BLOCKED').length;
    auditRows = [...all]
      .sort((a, b) => (a.ts === b.ts ? b.id - a.id : (a.ts < b.ts ? 1 : -1)))
      .slice(0, AUDIT_ROWS_IN_PDF);
    auditGlobal = await getAuditSummary();
    // Both fetches are capped, so the stated total comes from a COUNT() — a
    // truncation notice that understates the true total is worse than none.
    auditTotal = await getAuditCount(activeScope?.id);
    if (!activeScope) {
      auditAllowed = auditGlobal.allowed;
      auditBlocked = auditGlobal.blocked;
    }
  } catch (err) {
    auditReadError = errText(err);
  }
  const auditTruncated = auditTotal > auditRows.length;

  // ── One rule set, one set of numbers ──────────────────────────────────────
  //
  // Everything severity-shaped in this document is derived here and nowhere
  // else. Previously the headline "VULNERABLE APs" figure came from the
  // engine's binary `is_vulnerable` flag while the per-AP table recomputed
  // `WEP || OPEN` on the same page, so a WPA1 network was counted in the
  // headline and printed as [LOW] in the table below it.
  let totalAPs = 0;
  let totalNodes = 0;
  const allCredentials: any[] = [];
  /** Per-archive assessment, reused by every section below. */
  const assessed = reportsArray.map(r => {
    const findings = assessReport(r);
    return { report: r, findings, summary: summarise(findings) };
  });
  /**
   * One row per real-world issue, across every archive in this export.
   *
   * A multi-archive export is the normal way a manager-facing report is
   * produced, and this used to be a plain `flatMap`. An access point present in
   * two archives — the same physical device, surveyed twice — was therefore
   * counted twice in the ACCESS POINTS tile, FINDINGS RAISED, the CRITICAL +
   * HIGH headline, the severity and confidence tables, the WPS and rogue-AP
   * counts, POSITION QUALITY, and PRIORITISED FINDINGS, which printed the
   * identical row twice. Two archives of one estate doubled the headline risk
   * figure.
   *
   * `fingerprint` is exactly the right key and it already existed:
   * subject + category, with no timestamp, score or archive component, which is
   * what `upsertFindings` upserts on. The database was already deduplicating
   * while the document it produced was not.
   *
   * The worst instance wins, so a later survey that saw an AP under better
   * conditions is the one that gets reported, and `occurrences` keeps the fact
   * that it was seen more than once from being lost.
   */
  const dedupedFindings: Finding[] = (() => {
    const best = new Map<string, Finding & { occurrences?: number }>();
    for (const f of assessed.flatMap(a => a.findings)) {
      const key = f.fingerprint || `${f.subject_type}|${f.subject_id}|${f.category}`;
      const seen = best.get(key);
      if (!seen) {
        best.set(key, { ...f, occurrences: 1 });
        continue;
      }
      const occurrences = (seen.occurrences ?? 1) + 1;
      if (f.risk_score > seen.risk_score) best.set(key, { ...f, occurrences });
      else seen.occurrences = occurrences;
    }
    return [...best.values()];
  })();
  const allFindings: Finding[] = dedupedFindings;
  const overall = summarise(allFindings);

  // Subjects are counted the same way, and for the same reason: one physical
  // access point seen in two archives is one access point.
  const seenBssids = new Set<string>();
  const seenHostIps = new Set<string>();
  reportsArray.forEach(r => {
    if (isWirelessReport(r)) {
      for (const ap of apsOf(r)) {
        const id = String(ap?.bssid ?? '').toUpperCase();
        // An AP with no BSSID cannot be deduplicated, so it is counted as its
        // own row rather than silently collapsed with every other blank one.
        if (!id) { totalAPs++; continue; }
        if (seenBssids.has(id)) continue;
        seenBssids.add(id);
        totalAPs++;
      }
    } else {
      for (const h of hostsOf(r)) {
        const id = String(h?.ip ?? '');
        if (!id) { totalNodes++; continue; }
        if (seenHostIps.has(id)) continue;
        seenHostIps.add(id);
        totalNodes++;
      }
      allCredentials.push(...credentialsOf(r));
    }
  });

  // Snapshots carry secrets sealed, so they are decrypted here — once, at
  // export, under the key the operator unlocked. An archive written before the
  // vault existed carries cleartext and passes straight through.
  const revealedCredentials = await revealArchivedCredentials(allCredentials);
  allCredentials.length = 0;
  allCredentials.push(...revealedCredentials);

  /**
   * Worst severity per subject id, for the per-row label in the telemetry
   * tables — the same rule the on-screen table and the CSV/KML/GeoJSON
   * exports use, so a row cannot carry one confidence label in the PDF and a
   * different one in the CSV.
   */
  const worstFor = worstBySubject(allFindings);

  /**
   * Persisted status per fingerprint. A finding a previous run closed should
   * not read as brand new, and a REGRESSED one has to be called that.
   */
  const findingStatus = new Map<string, string>();
  let findingsDbError: string | null = null;
  try {
    for (const row of await getFindings({ limit: 4000 })) {
      if (row.fingerprint) findingStatus.set(row.fingerprint, row.status);
    }
  } catch (err) {
    findingsDbError = errText(err);
  }

  // ── Rogue / evil twin, WPS and their associated stations ─────────────────
  const rogueEntries: RogueEntry[] = [];
  const wpsEntries: WpsEntry[] = [];
  let clientReadError: string | null = null;

  // One device, one row. Both of these tables state a count in prose — "N
  // access point(s) advertise WPS", "N access point(s) carry rogue-AP
  // indicators" — so an access point present in two archives was inflating a
  // sentence a reader takes as a population figure. Keyed on BSSID, keeping the
  // more severe sighting.
  const wpsSeen = new Map<string, number>();
  const rogueSeen = new Map<string, number>();

  for (const r of reportsArray) {
    if (!isWirelessReport(r)) continue;
    for (const ap of apsOf(r)) {
      const bssid = String(ap?.bssid ?? '').toUpperCase();
      const findings = assessAccessPoint(toApInput(ap, !!r.simulated));
      if (wpsObserved(ap)) {
        const wpsFinding = findings.find(f => f.category === 'wps');
        const entry = { report: r, ap, severity: wpsFinding?.severity ?? 'INFO' as Severity };
        const at = bssid ? wpsSeen.get(bssid) : undefined;
        if (at === undefined) {
          if (bssid) wpsSeen.set(bssid, wpsEntries.length);
          wpsEntries.push(entry);
        } else if (SEVERITY_ORDER[entry.severity] > SEVERITY_ORDER[wpsEntries[at].severity]) {
          wpsEntries[at] = entry;
        }
      }
      const { verdict, indicators, heuristicOnly } = rogueVerdictOf(ap);
      if (!verdict || verdict === 'CLEAR') continue;
      const rogueFinding = findings.find(f => f.category === 'rogue_ap');
      let clients: ClientRow[] = [];
      try {
        // Scoped to this archive's own mission. Unscoped, a re-survey of the same
        // estate put a later engagement's stations into this one's report.
        clients = await getClientsForBssid(String(ap.bssid ?? ''), missionIdOf(r));
      } catch (err) {
        clientReadError = errText(err);
      }
      const entry: RogueEntry = {
        report: r, ap, verdict, indicators, heuristicOnly,
        score: typeof ap.rogue_score === 'number' ? ap.rogue_score : null,
        severity: rogueFinding?.severity ?? 'INFO',
        confidence: rogueFinding?.confidence ?? null,
        clients,
      };
      const at = bssid ? rogueSeen.get(bssid) : undefined;
      if (at === undefined) {
        if (bssid) rogueSeen.set(bssid, rogueEntries.length);
        rogueEntries.push(entry);
      } else if ((entry.score ?? -1) > (rogueEntries[at].score ?? -1)) {
        // Better-informed verdict wins, decided by the engine's own score
        // rather than by which archive happened to be exported first.
        rogueEntries[at] = entry;
      }
    }
  }
  rogueEntries.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);

  let clientTotals: { total: number; randomized: number; associated: number; probe_only: number } | null = null;
  try {
    clientTotals = await getClientSummary();
  } catch (err) {
    clientReadError = clientReadError ?? errText(err);
  }

  /*
    The evidence register.

    `evidence_files` was written on every capture and read by nothing:
    `getEvidence`, `getEvidenceForBssid` and `markEvidenceVerified` had no
    callers anywhere in `src/`, and the PDF had no evidence section at all —
    no artifact filename, no SHA-256, no verification status. Meanwhile the
    appendix asserted that "where a handshake or PMKID was captured, that is
    recorded as evidence". The record existed in the database and was absent
    from the document that made the claim, which is the same defect class as
    every other one in this file: a true statement about the code that the
    output did not support.

    The digest is the point. `engine/evidence.py` hashes each artifact at the
    moment it is written, and `test_evidence_and_cve.py` proves the digest and
    the tamper detection are correct — so the only thing missing was printing
    it where a recipient can use it.
  */
  let evidenceRows: EvidenceRow[] = [];
  let evidenceReadError: string | null = null;
  try {
    /*
      Scoped to the missions in this export.

      `getEvidence` used to take only a limit and return every row in the table, and
      the PDF prints the result under the heading EVIDENCE REGISTER, introduced as
      "the artifacts behind its findings". So exporting engagement A's archive listed
      B's and C's captures — filename, filesystem path, SSID, BSSID, SHA-256 — as
      evidence for A.
    */
    const missionIds = reportsArray.map(missionIdOf).filter((id): id is string => !!id);
    evidenceRows = await getEvidence(missionIds, 500);
  } catch (err) {
    evidenceReadError = errText(err);
  }

  // ── Survey coverage, computed at export time and then frozen ─────────────
  const coverageSections: CoverageSection[] = [];
  for (const r of reportsArray) {
    if (!isWirelessReport(r)) continue;
    const missionId = missionIdOf(r);
    if (!missionId) {
      coverageSections.push({ report: r, missionId: null, row: null, error: null });
      continue;
    }
    // The archive's own frozen copy wins.
    //
    // `mission_coverage` cascades away when its mission is deleted, so the
    // table cannot be relied on to still hold what this archive was surveyed
    // over — which is the opposite of why migration 009 freezes it. Archives
    // written before the snapshot existed fall through to the table.
    const frozen = (r.rawData as any)?.coverage;
    if (frozen && typeof frozen === 'object') {
      coverageSections.push({ report: r, missionId, row: frozen as CoverageRow, error: null });
      continue;
    }
    try {
      let row = await getCoverage(missionId);
      if (!row) row = await computeAndStoreCoverage(missionId);
      coverageSections.push({ report: r, missionId, row, error: null });
    } catch (err) {
      coverageSections.push({ report: r, missionId, row: null, error: errText(err) });
    }
  }

  // ── Method appendix inputs ──────────────────────────────────────────────
  const methodology = describeMethodology();
  const engineState = useEngineStore.getState();
  const engineMethodology = await fetchEngineMethodology();
  const cveData = engineMethodology?.cve_data ?? engineState.cveInfo ?? null;
  const capabilities = engineMethodology?.capabilities ?? engineState.capabilities ?? null;
  const evilTwinMethod = engineMethodology?.evil_twin ?? null;
  const gatedCommands = engineMethodology?.scope?.gated_commands ?? [];
  const appVersion = (import.meta as any).env?.VITE_APP_VERSION as string | undefined;
  /*
    The engine identity recorded against an exported document.

    `engineState.engineVersion` was the only fallback and it was never written
    — the store declared the field and nothing set it — so a document produced
    with no `get_methodology` answer recorded no engine at all. The build stamp
    is the identity that actually distinguishes one sidecar from another: a
    severity traced to a rule set is auditable only if the software that
    applied it can be named, and "0.1.0" names every build ever made.
  */
  const build = engineState.engineBuild;
  const buildIdentity = build
    ? [build.version,
       build.git_describe ?? null,
       build.built_at ? `built ${build.built_at}` : null,
       build.frozen ? null : 'from source']
      .filter(Boolean).join(' · ')
    : null;
  const engineVersion = engineMethodology?.engine_version ?? buildIdentity
    ?? engineState.engineVersion ?? null;

  // ── Retest delta against the selected baseline ──────────────────────────
  let retest: RetestDelta | null = baselineDelta;
  let retestError: string | null = null;
  if (baselineId !== null && !retest) {
    try {
      retest = await compareToBaseline(baselineId);
    } catch (err) {
      retestError = errText(err);
    }
  }

  return {
    reportsArray,
    isMulti,
    simulatedReports, fieldReports, anySimulated, allSimulated, isMixedProvenance,
    activeScope, scopeReadError,
    auditRows, auditTotal, auditAllowed, auditBlocked, auditGlobal, auditReadError, auditTruncated,
    assessed, allFindings, overall, totalAPs, totalNodes, allCredentials,
    worstFor, findingStatus, findingsDbError,
    rogueEntries, wpsEntries, clientTotals, clientReadError,
    evidenceRows, evidenceReadError,
    coverageSections,
    methodology, engineMethodology, gatedCommands, cveData, capabilities, evilTwinMethod, appVersion, engineVersion,
    retest, retestError,
  };
}
