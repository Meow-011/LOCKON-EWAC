/**
 * LOCKON EWAC — Findings, evidence, clients, coverage
 *
 * These are the records that make the report defensible:
 *
 *  - `findings` stores each assessed risk with the reason and the rule that
 *    produced it, so the PDF reads severities from one place instead of
 *    recomputing them per view (which is how one document ended up calling a
 *    network vulnerable in its headline and LOW in its table).
 *  - `evidence_files` ties an artifact (a pcap, a .hc22000) to its SHA-256, so a
 *    "handshake captured" claim points at a file that can be shown unaltered.
 *  - `clients` answers "who was connected to that AP", keeping probe-only
 *    sightings separate from observed associations.
 *  - `mission_coverage` records what was actually surveyed, so "no findings
 *    here" can be told apart from "never went here".
 */
import { getDb } from './database';
import type { Finding, Severity, Confidence } from './riskEngine';

// ── Findings ────────────────────────────────────────────────────────────────

export interface FindingRow extends Finding {
  id: number;
  mission_id: string | null;
  session_id: string | null;
  evidence_refs: string | null;
  status: 'OPEN' | 'FIXED' | 'ACCEPTED' | 'REGRESSED' | 'FALSE_POSITIVE';
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
}

/**
 * Insert or refresh findings.
 *
 * Upserts on `fingerprint` so a retest updates the existing row rather than
 * creating a duplicate — that is what lets the tool say "this is the same issue
 * we reported last time" instead of reporting everything as new every run.
 *
 * A finding that had been marked FIXED and is seen again becomes REGRESSED,
 * which is a more useful thing to hand a manager than a fresh OPEN row.
 */
export async function upsertFindings(
  findings: Finding[],
  context: { mission_id?: string | null; session_id?: string | null } = {}
): Promise<void> {
  if (findings.length === 0) return;
  const db = await getDb();

  for (const f of findings) {
    await db.execute(
      `INSERT INTO findings (
         subject_type, subject_id, mission_id, session_id, category, title,
         severity, risk_score, confidence, rationale, methodology, remediation,
         status, first_seen, last_seen, is_simulated, fingerprint
       )
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'OPEN',datetime('now'),datetime('now'),$13,$14)
       ON CONFLICT(fingerprint) DO UPDATE SET
         last_seen   = datetime('now'),
         severity    = excluded.severity,
         risk_score  = excluded.risk_score,
         confidence  = excluded.confidence,
         rationale   = excluded.rationale,
         methodology = excluded.methodology,
         remediation = excluded.remediation,
         title       = excluded.title,
         mission_id  = COALESCE(excluded.mission_id, findings.mission_id),
         session_id  = COALESCE(excluded.session_id, findings.session_id),
         -- Seen again after being closed: that is a regression, not a new issue.
         status      = CASE WHEN findings.status IN ('FIXED','ACCEPTED') THEN 'REGRESSED' ELSE findings.status END,
         resolved_at = CASE WHEN findings.status IN ('FIXED','ACCEPTED') THEN NULL ELSE findings.resolved_at END,
         is_simulated = MIN(findings.is_simulated, excluded.is_simulated)`,
      [
        f.subject_type, f.subject_id, context.mission_id ?? null, context.session_id ?? null,
        f.category, f.title, f.severity, Math.max(0, Math.min(100, Math.round(f.risk_score))),
        f.confidence, f.rationale, f.methodology, f.remediation ?? null,
        f.is_simulated ? 1 : 0, f.fingerprint,
      ]
    );
  }

  await linkEvidenceToFindings(findings);
}

/**
 * Point each finding at the evidence artifacts for its subject.
 *
 * `findings.evidence_refs` is declared in migration 009 as "JSON array of
 * evidence_files.id", it is typed on `FindingRow`, and it was never written —
 * so it was NULL on every row and no finding could be traced to the capture
 * that backs it. That link is the whole reason migration 009 created the
 * evidence table alongside the findings table.
 *
 * Matching is by subject: an access-point finding gets the evidence recorded
 * against that BSSID. That is the only association the data actually supports —
 * a handshake capture is evidence about an access point, not about one
 * particular finding on it — and claiming anything narrower would be inventing
 * a relationship.
 *
 * Runs after the upserts so the rows exist, and is deliberately not fatal: a
 * finding without its evidence link is still a finding worth recording, and
 * failing the whole assessment write over a cross-reference would lose real
 * data to protect a convenience.
 */
async function linkEvidenceToFindings(findings: Finding[]): Promise<void> {
  const bssids = [...new Set(
    findings
      .filter(f => f.subject_type === 'AP' && f.subject_id)
      .map(f => f.subject_id.toUpperCase())
  )];
  if (bssids.length === 0) return;

  const db = await getDb();
  for (const bssid of bssids) {
    try {
      const rows = await db.select<{ id: number }[]>(
        // `UPPER($1)`, matching the otherwise identical query in
        // `getEvidenceForBssid`. The caller happens to upper-case the value before
        // calling, so comparing against the raw parameter worked -- and left the two
        // queries one refactor apart from `linkEvidenceToFindings` silently linking
        // nothing, which would make every finding's `evidence_refs` NULL again without
        // an error anywhere.
        `SELECT id FROM evidence_files WHERE UPPER(bssid) = UPPER($1) ORDER BY id`,
        [bssid]
      );
      if (rows.length === 0) continue;
      await db.execute(
        `UPDATE findings
            SET evidence_refs = $1
          WHERE subject_type = 'AP' AND UPPER(subject_id) = UPPER($2)`,
        [JSON.stringify(rows.map(r => r.id)), bssid]
      );
    } catch (err) {
      console.error('[DB] linkEvidenceToFindings failed for', bssid, err);
    }
  }
}

export async function getFindings(options: {
  mission_id?: string;
  session_id?: string;
  subject_id?: string;
  status?: string;
  limit?: number;
} = {}): Promise<FindingRow[]> {
  const db = await getDb();
  const where: string[] = [];
  const params: unknown[] = [];

  if (options.mission_id) { params.push(options.mission_id); where.push(`mission_id = $${params.length}`); }
  if (options.session_id) { params.push(options.session_id); where.push(`session_id = $${params.length}`); }
  if (options.subject_id) { params.push(options.subject_id); where.push(`subject_id = $${params.length}`); }
  if (options.status) { params.push(options.status); where.push(`status = $${params.length}`); }

  params.push(options.limit ?? 2000);
  return db.select<FindingRow[]>(
    `SELECT * FROM findings
     ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
     ORDER BY risk_score DESC, last_seen DESC
     LIMIT $${params.length}`,
    params
  );
}

export async function setFindingStatus(
  id: number,
  status: FindingRow['status'],
  note?: string
): Promise<void> {
  const db = await getDb();
  const closing = status === 'FIXED' || status === 'ACCEPTED' || status === 'FALSE_POSITIVE';
  await db.execute(
    `UPDATE findings
     SET status = $1,
         resolved_at = CASE WHEN $2 = 1 THEN datetime('now') ELSE NULL END,
         rationale = CASE WHEN $3 IS NOT NULL THEN rationale || char(10) || '[' || $1 || '] ' || $3 ELSE rationale END
     WHERE id = $4`,
    [status, closing ? 1 : 0, note ?? null, id]
  );
}

export interface FindingsSummary {
  total: number;
  bySeverity: Record<Severity, number>;
  byStatus: Record<string, number>;
  byConfidence: Record<Confidence, number>;
  significant: number;
}

export async function getFindingsSummary(missionId?: string): Promise<FindingsSummary> {
  const db = await getDb();
  const params = missionId ? [missionId] : [];
  const scope = missionId ? 'WHERE mission_id = $1' : '';

  const sev = await db.select<{ severity: Severity; n: number }[]>(
    `SELECT severity, COUNT(*) as n FROM findings ${scope} GROUP BY severity`, params);
  const st = await db.select<{ status: string; n: number }[]>(
    `SELECT status, COUNT(*) as n FROM findings ${scope} GROUP BY status`, params);
  const conf = await db.select<{ confidence: Confidence; n: number }[]>(
    `SELECT confidence, COUNT(*) as n FROM findings ${scope} GROUP BY confidence`, params);

  const bySeverity: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  sev.forEach(r => { bySeverity[r.severity] = r.n; });
  const byConfidence: Record<Confidence, number> = { CONFIRMED: 0, LIKELY: 0, SUSPECTED: 0 };
  conf.forEach(r => { byConfidence[r.confidence] = r.n; });
  const byStatus: Record<string, number> = {};
  st.forEach(r => { byStatus[r.status] = r.n; });

  return {
    total: sev.reduce((a, r) => a + r.n, 0),
    bySeverity, byStatus, byConfidence,
    significant: bySeverity.CRITICAL + bySeverity.HIGH,
  };
}

// ── Retest / baseline comparison ────────────────────────────────────────────

export interface RetestDelta {
  fixed: FindingRow[];
  regressed: FindingRow[];
  still_open: FindingRow[];
  newly_found: FindingRow[];
  baseline_label: string | null;
  baseline_at: string | null;
}

export async function createBaseline(label: string, context: {
  mission_id?: string | null; session_id?: string | null; scope_id?: number | null; notes?: string;
} = {}): Promise<number> {
  const db = await getDb();
  // Count what this baseline is actually a baseline *of*.
  //
  // It counted every OPEN finding on the installation and then stored that
  // number against the named mission, so a baseline for a ten-finding
  // engagement could record eighty. `finding_count` is what the retest section
  // prints as the starting position, so a wrong number there misstates the
  // denominator of every percentage derived from it. Scoped the same way
  // `compareToBaseline` scopes its groups, so the two agree.
  const countScope: string[] = [];
  const countArgs: unknown[] = [];
  if (context.mission_id) {
    countScope.push(`mission_id = $${countArgs.length + 1}`);
    countArgs.push(context.mission_id);
  }
  if (context.session_id) {
    countScope.push(`session_id = $${countArgs.length + 1}`);
    countArgs.push(context.session_id);
  }
  const counted = await db.select<{ n: number }[]>(
    `SELECT COUNT(*) as n FROM findings WHERE status = 'OPEN'`
    + (countScope.length ? ` AND (${countScope.join(' OR ')})` : ''),
    countArgs
  );
  await db.execute(
    `INSERT INTO assessment_baselines (label, mission_id, session_id, scope_id, finding_count, notes)
     VALUES ($1,$2,$3,$4,$5,$6)`,
    [label, context.mission_id ?? null, context.session_id ?? null,
     context.scope_id ?? null, counted[0]?.n ?? 0, context.notes ?? null]
  );
  const [{ id }] = await db.select<{ id: number }[]>(`SELECT id FROM assessment_baselines ORDER BY id DESC LIMIT 1`);
  return id;
}

export async function listBaselines(): Promise<{ id: number; label: string; created_at: string; finding_count: number }[]> {
  const db = await getDb();
  return db.select(`SELECT id, label, created_at, finding_count FROM assessment_baselines ORDER BY created_at DESC`);
}

/**
 * Compare the current findings against a baseline.
 *
 * This is the "did the fixes work" answer, which the tool previously could not
 * give at all: the only comparison anywhere was an in-memory, IP-only new-device
 * diff whose "disappeared" half the UI discarded.
 */
export async function compareToBaseline(baselineId: number): Promise<RetestDelta> {
  const db = await getDb();
  const base = await db.select<{
    label: string; created_at: string;
    mission_id: string | null; session_id: string | null;
  }[]>(
    `SELECT label, created_at, mission_id, session_id
       FROM assessment_baselines WHERE id = $1`, [baselineId]);
  if (base.length === 0) throw new Error(`Baseline ${baselineId} not found`);
  const at = base[0].created_at;

  /*
    Scope the comparison to what the baseline was taken over.

    `assessment_baselines` records `mission_id` and `session_id` and neither was
    ever used, so every group below was a query across the whole database. A
    retest of engagement A reported engagement B's remediation as its own
    progress — and "FIXED SINCE THE BASELINE" is a number a client reads as
    work delivered.

    A baseline with neither recorded is a deliberate rig-wide baseline, and
    compares rig-wide, which is why this is built rather than mandatory.
  */
  const scope: string[] = [];
  const scopeArgs: unknown[] = [];
  if (base[0].mission_id) {
    scope.push(`mission_id = $${scopeArgs.length + 2}`);
    scopeArgs.push(base[0].mission_id);
  }
  if (base[0].session_id) {
    scope.push(`session_id = $${scopeArgs.length + 2}`);
    scopeArgs.push(base[0].session_id);
  }
  const scoped = scope.length ? ` AND (${scope.join(' OR ')})` : '';

  /*
    "Fixed since the baseline" has to mean closed *after* it.

    The predicate was `first_seen <= baseline AND status IN ('FIXED','ACCEPTED')`,
    which counts a finding that was already closed months before the baseline
    was taken. Those rows padded the green FIXED tile and the
    "FIXED SINCE THE BASELINE (n)" heading with work that predates the retest
    entirely. `resolved_at` is set by `setFindingStatus` when a finding is
    closed, so it is the field that answers the question the heading asks.
  */
  const fixed = await db.select<FindingRow[]>(
    `SELECT * FROM findings
      WHERE first_seen <= $1
        AND status IN ('FIXED','ACCEPTED')
        AND resolved_at IS NOT NULL
        AND resolved_at > $1${scoped}
      ORDER BY risk_score DESC`, [at, ...scopeArgs]);

  /*
    A regression belongs to this retest only if it was observed after the
    baseline.

    This had no baseline predicate at all — `WHERE status = 'REGRESSED'` — so
    every regression ever recorded on this installation was attributed to
    whichever retest happened to be running. `markAsRegressed` does not stamp a
    time of its own, but it only fires when a closed finding is seen again, and
    that sighting updates `last_seen`. So `last_seen > baseline` is what
    distinguishes "came back during this retest" from "came back last year".
  */
  const regressed = await db.select<FindingRow[]>(
    `SELECT * FROM findings
      WHERE status = 'REGRESSED'
        AND last_seen > $1${scoped}
      ORDER BY risk_score DESC`, [at, ...scopeArgs]);

  const stillOpen = await db.select<FindingRow[]>(
    `SELECT * FROM findings
      WHERE first_seen <= $1 AND status = 'OPEN'${scoped}
      ORDER BY risk_score DESC`, [at, ...scopeArgs]);

  const newlyFound = await db.select<FindingRow[]>(
    `SELECT * FROM findings
      WHERE first_seen > $1 AND status = 'OPEN'${scoped}
      ORDER BY risk_score DESC`, [at, ...scopeArgs]);

  return {
    fixed, regressed, still_open: stillOpen, newly_found: newlyFound,
    baseline_label: base[0].label, baseline_at: at,
  };
}

// ── Evidence files ──────────────────────────────────────────────────────────

export interface EvidenceRow {
  id: number;
  kind: string;
  path: string;
  filename: string;
  sha256: string | null;
  size_bytes: number | null;
  bssid: string | null;
  ssid: string | null;
  mission_id: string | null;
  session_id: string | null;
  recorded_at: string;
  last_verified_at: string | null;
  verify_status: 'MATCH' | 'MISMATCH' | 'MISSING' | null;
  notes: string | null;
  error: string | null;
}

/** Persist an `evidence_recorded` event from the engine. */
export async function recordEvidence(event: Record<string, any>): Promise<void> {
  const db = await getDb();
  await db.execute(
    `INSERT INTO evidence_files (kind, path, filename, sha256, size_bytes, bssid, ssid, mission_id, session_id, recorded_at, error)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [
      event.kind ?? 'unknown', event.path ?? '', event.filename ?? '',
      event.sha256 ?? null, event.size_bytes ?? null,
      event.bssid ?? null, event.ssid ?? null,
      event.mission_id ?? null, event.session_id ?? null,
      event.recorded_at ?? new Date().toISOString(),
      event.error ?? null,
    ]
  );
}

/**
 * Re-hash every recorded artifact and store the result.
 *
 * This closes the loop that `evidence_files` existed for and never had:
 * `engine/evidence.py` hashes each artifact as it is written, the digest is
 * stored, `verify_evidence` was implemented in the engine — and nothing in the
 * app ever sent that command, so `verify_status` was NULL on every row and the
 * report could only say "never re-checked". A digest nobody can check is a
 * digest that proves nothing.
 *
 * Verification is per artifact, sequential, and each answer is written as it
 * arrives, so a run interrupted halfway still records what it established.
 * Artifacts with no stored digest are skipped: there is nothing to compare
 * against, and marking them MISSING would say the file is gone when the truth
 * is that it was never hashed.
 *
 * Returns the tally the operator needs to see, including how many could not be
 * asked about at all.
 */
export async function verifyAllEvidence(
  send: (cmd: 'verify_evidence', payload: Record<string, unknown>) => Promise<unknown>,
  awaitResult: (id: number, timeoutMs?: number) => Promise<{
    matches?: boolean; exists?: boolean; error?: string | null;
  }>,
): Promise<{ checked: number; matched: number; mismatched: number; missing: number; unhashed: number; failed: number }> {
  // Installation-wide, deliberately: this re-hashes every artifact this rig holds,
  // which is a different job from listing one engagement's register. The scoped
  // read above is for the document.
  const rows = await getAllEvidenceForVerification(1000);
  const tally = { checked: 0, matched: 0, mismatched: 0, missing: 0, unhashed: 0, failed: 0 };

  for (const row of rows) {
    if (!row.sha256) {
      tally.unhashed += 1;
      continue;
    }
    try {
      await send('verify_evidence', { id: row.id, path: row.path, sha256: row.sha256 });
      const result = await awaitResult(row.id);
      tally.checked += 1;
      if (result.matches) {
        await markEvidenceVerified(row.id, 'MATCH');
        tally.matched += 1;
      } else if (result.exists === false) {
        await markEvidenceVerified(row.id, 'MISSING');
        tally.missing += 1;
      } else {
        await markEvidenceVerified(row.id, 'MISMATCH');
        tally.mismatched += 1;
      }
    } catch (err) {
      // An artifact we could not ask about is not an artifact that failed.
      // Left unmarked so the report still says "never re-checked" rather than
      // asserting a verdict this run did not reach.
      console.error('[Evidence] verification failed for', row.filename, err);
      tally.failed += 1;
    }
  }

  return tally;
}

/**
 * Evidence artifacts, scoped to the missions named in `missionIds`.
 *
 * This took only a limit and returned every row in the table. The PDF prints the
 * result as the EVIDENCE REGISTER, introduced as "the artifacts behind its
 * findings" — so exporting one engagement's archive listed another engagement's
 * captures, by filename, filesystem path, SSID, BSSID and SHA-256, as evidence for
 * this one. `mission_id` and `session_id` have been on the table since migration
 * 009.
 *
 * An empty `missionIds` returns nothing rather than everything. The register's own
 * text says it lists the artifacts behind *these* findings, and a document that
 * omits an artifact understates itself, while one that attributes a stranger's
 * capture to this engagement cannot be corrected after it has been delivered.
 */
export async function getEvidence(
  missionIds: readonly string[],
  limit = 500,
): Promise<EvidenceRow[]> {
  const ids = [...new Set(missionIds.filter(Boolean))];
  if (ids.length === 0) return [];
  const db = await getDb();
  const placeholders = ids.map((_, i) => `$${i + 1}`).join(', ');
  return db.select<EvidenceRow[]>(
    `SELECT * FROM evidence_files
      WHERE mission_id IN (${placeholders})
      ORDER BY recorded_at DESC
      LIMIT $${ids.length + 1}`,
    [...ids, limit]);
}

/**
 * Every artifact this installation holds, for the re-hash sweep.
 *
 * Deliberately unscoped, and named so that cannot be mistaken for the register's
 * read. `verifyAllEvidence` checks files on this machine's disk against the hashes
 * recorded when they were captured, which is a property of the installation rather
 * than of any one engagement.
 */
/**
 * What the evidence register holds, as four numbers.
 *
 * The Settings card had no state at all before a verification run: a paragraph
 * and a button, next to two cards that each show their condition in a badge. It
 * could not answer the first question an operator has, which is whether this
 * installation holds any artifacts to verify.
 *
 * Counted in one query rather than by reading the rows, because the card is
 * rendered on every visit to the page and the register can hold thousands.
 *
 * `unhashed` is separate from `neverChecked` deliberately. A file recorded
 * without a digest can never be verified -- there is nothing to compare against
 * -- so it is not waiting for a run, and counting it among the un-checked would
 * promise the operator that a verification will clear it.
 */
export async function getEvidenceSummary(): Promise<{
  total: number; unhashed: number; neverChecked: number; failed: number;
}> {
  const db = await getDb();
  const rows = await db.select<{
    total: number; unhashed: number; never_checked: number; failed: number;
  }[]>(
    `SELECT COUNT(*) AS total,
            SUM(CASE WHEN sha256 IS NULL OR sha256 = '' THEN 1 ELSE 0 END) AS unhashed,
            SUM(CASE WHEN sha256 IS NOT NULL AND sha256 <> '' AND verify_status IS NULL THEN 1 ELSE 0 END) AS never_checked,
            SUM(CASE WHEN verify_status IN ('MISMATCH', 'MISSING') THEN 1 ELSE 0 END) AS failed
     FROM evidence_files`
  );
  const r = rows[0];
  // SUM over no rows is NULL, not 0, which would render as "null artifacts".
  return {
    total: r?.total ?? 0,
    unhashed: r?.unhashed ?? 0,
    neverChecked: r?.never_checked ?? 0,
    failed: r?.failed ?? 0,
  };
}

export async function getAllEvidenceForVerification(limit = 1000): Promise<EvidenceRow[]> {
  const db = await getDb();
  return db.select<EvidenceRow[]>(
    `SELECT * FROM evidence_files ORDER BY recorded_at DESC LIMIT $1`, [limit]);
}

export async function getEvidenceForBssid(bssid: string): Promise<EvidenceRow[]> {
  const db = await getDb();
  return db.select<EvidenceRow[]>(
    `SELECT * FROM evidence_files WHERE UPPER(bssid) = UPPER($1) ORDER BY recorded_at DESC`, [bssid]);
}

export async function markEvidenceVerified(
  id: number,
  status: 'MATCH' | 'MISMATCH' | 'MISSING'
): Promise<void> {
  const db = await getDb();
  await db.execute(
    `UPDATE evidence_files SET last_verified_at = datetime('now'), verify_status = $1 WHERE id = $2`,
    [status, id]
  );
}

// ── Clients ─────────────────────────────────────────────────────────────────

export interface ClientRow {
  mac: string;
  vendor: string | null;
  is_randomized: number;
  probe_count: number;
  probed_ssids: string | null;
  associated_bssid: string | null;
  associated_ssid: string | null;
  strongest_rssi: number | null;
  sources: string | null;
  mission_id: string | null;
  first_seen: string;
  last_seen: string;
  is_simulated: number;
}

/** Persist a `client_observed` event. Upserts, keeping the earliest first_seen. */
/*
  Two unknowns stay unknown.

  The `strongest_rssi` upsert below was
  `MAX(COALESCE(clients.strongest_rssi, -127), COALESCE(excluded.strongest_rssi, -127))`,
  which turns "neither side has a reading" into a hard -127: a fabricated measurement,
  stored indistinguishably from one a radio actually took. Same defect class as the
  `scan_logs.rssi ?? -90` write that `wardrivingDB` records against itself.

  It was reached on nearly every station. The only producer of client rows is
  `probe_monitor.py`, whose `observe_probe` call passes no rssi at all, while
  `probe_count` increments on every probe — so the second probe from any station took
  the conflict path and wrote -127.

  Each side falls back to the other before the comparison, which gives the three
  answers separately: two readings compare, one reading survives alone, and two
  unknowns stay NULL.

  Written that way because SQLite's *scalar* `max(a, b)` returns NULL when either
  argument is NULL — the opposite of the aggregate `max()`, and the trap a first
  attempt at this fix fell into: it stopped inventing -127 and started erasing real
  measurements instead. The database suite caught it.

  `ReportsPage` already has the `null -> 'n/r'` branch waiting for the NULL.
*/
export async function recordClient(event: Record<string, any>, missionId?: string | null): Promise<void> {
  const db = await getDb();
  await db.execute(
    `INSERT INTO clients (mac, vendor, is_randomized, probe_count, probed_ssids,
                          associated_bssid, associated_ssid, strongest_rssi, sources,
                          mission_id, first_seen, last_seen, is_simulated)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
     ON CONFLICT(mac) DO UPDATE SET
       vendor           = COALESCE(excluded.vendor, clients.vendor),
       probe_count      = MAX(clients.probe_count, excluded.probe_count),
       probed_ssids     = excluded.probed_ssids,
       -- An observed association must never be overwritten by a later
       -- probe-only sighting: "connected" is a stronger claim than "present".
       associated_bssid = COALESCE(excluded.associated_bssid, clients.associated_bssid),
       associated_ssid  = COALESCE(excluded.associated_ssid, clients.associated_ssid),
       strongest_rssi   = MAX(COALESCE(clients.strongest_rssi, excluded.strongest_rssi),
                              COALESCE(excluded.strongest_rssi, clients.strongest_rssi)),
       sources          = excluded.sources,
       mission_id       = COALESCE(excluded.mission_id, clients.mission_id),
       last_seen        = excluded.last_seen,
       is_simulated     = MIN(clients.is_simulated, excluded.is_simulated)`,
    [
      event.mac, event.vendor ?? null, event.randomized ? 1 : 0,
      event.probe_count ?? 0, JSON.stringify(event.probed_ssids ?? []),
      event.associated_bssid ?? null, event.associated_ssid ?? null,
      event.strongest_rssi ?? null, JSON.stringify(event.sources ?? []),
      missionId ?? null,
      event.first_seen ?? new Date().toISOString(),
      event.last_seen ?? new Date().toISOString(),
      event.simulated ? 1 : 0,
    ]
  );
}

export async function getClients(limit = 1000): Promise<ClientRow[]> {
  const db = await getDb();
  return db.select<ClientRow[]>(
    `SELECT * FROM clients ORDER BY last_seen DESC LIMIT $1`, [limit]);
}

/** Stations observed associated with one AP — the rogue-AP follow-up question. */
/**
 * Stations observed associated with `bssid` during `missionId`.
 *
 * The mission filter was missing, and the report prints the result as "N station(s)
 * were observed ASSOCIATED with this access point" under a heading that says
 * "during the survey". Re-survey the same estate for a different client and Monday's
 * archive listed Wednesday's stations, with Wednesday's timestamps, as having been
 * seen during Monday's work.
 *
 * `mission_id` and `idx_clients_mission` have been on the table since migration 009.
 * A null `missionId` returns nothing: the figure is a per-survey claim, and there is
 * no honest way to make it without knowing which survey.
 */
export async function getClientsForBssid(
  bssid: string,
  missionId: string | null,
): Promise<ClientRow[]> {
  if (!missionId) return [];
  const db = await getDb();
  return db.select<ClientRow[]>(
    `SELECT * FROM clients
      WHERE UPPER(associated_bssid) = UPPER($1) AND mission_id = $2
      ORDER BY last_seen DESC`, [bssid, missionId]);
}

export async function getClientSummary(): Promise<{
  total: number; randomized: number; associated: number; probe_only: number;
}> {
  const db = await getDb();
  const rows = await db.select<{ total: number; randomized: number; associated: number }[]>(
    `SELECT COUNT(*) as total,
            SUM(is_randomized) as randomized,
            SUM(CASE WHEN associated_bssid IS NOT NULL THEN 1 ELSE 0 END) as associated
     FROM clients`
  );
  const r = rows[0] || { total: 0, randomized: 0, associated: 0 };
  return {
    total: r.total ?? 0,
    randomized: r.randomized ?? 0,
    associated: r.associated ?? 0,
    probe_only: (r.total ?? 0) - (r.associated ?? 0),
  };
}
