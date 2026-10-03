/**
 * LOCKON EWAC — Engagement Scope & Audit Trail
 *
 * The scope is the list of BSSIDs, SSIDs, IPs and subnets the operator was
 * authorized to touch. The engine refuses every offensive command against
 * anything outside it, and records both the allows and the blocks here so the
 * report can show that the work stayed inside its authorization.
 */
import { getDb } from './database';
import { csvRow } from './csv';

export type ScopeMode = 'ALLOWLIST' | 'UNRESTRICTED';
export type TargetKind = 'BSSID' | 'SSID' | 'IP' | 'CIDR';
export type AuditDecision = 'ALLOWED' | 'BLOCKED';

export interface ScopeTarget {
  id?: number;
  kind: TargetKind;
  value: string;
  note?: string | null;
}

export interface EngagementScope {
  id: number;
  engagement_name: string;
  authorized_by: string;
  /** Who ran the engagement; stamped onto every audit row. */
  operator: string | null;
  reference: string | null;
  mode: ScopeMode;
  unrestricted_ack: string | null;
  valid_from: string;
  valid_until: string | null;
  is_active: number;
  notes: string | null;
  created_at: string;
}

export interface EngagementScopeWithTargets extends EngagementScope {
  targets: ScopeTarget[];
}

export interface AuditRow {
  id: number;
  ts: string;
  scope_id: number | null;
  engagement_name: string | null;
  command: string;
  target: string | null;
  target_kind: string | null;
  decision: AuditDecision;
  reason: string | null;
  operator: string | null;
  mission_id: string | null;
  session_id: string | null;
  details: string | null;
}

/** Payload shape the engine's `set_scope` command expects. */
export interface ScopePayload {
  scope_id: number | null;
  engagement_name: string | null;
  authorized_by: string | null;
  operator: string | null;
  reference: string | null;
  mode: ScopeMode;
  valid_until: string | null;
  targets: { kind: TargetKind; value: string }[];
}

export async function listScopes(): Promise<EngagementScope[]> {
  const db = await getDb();
  return db.select<EngagementScope[]>(
    `SELECT * FROM engagement_scope ORDER BY is_active DESC, created_at DESC`
  );
}

export async function getScopeTargets(scopeId: number): Promise<ScopeTarget[]> {
  const db = await getDb();
  return db.select<ScopeTarget[]>(
    `SELECT id, kind, value, note FROM engagement_targets WHERE scope_id = $1 ORDER BY kind, value`,
    [scopeId]
  );
}

export async function getActiveScope(): Promise<EngagementScopeWithTargets | null> {
  const db = await getDb();
  const rows = await db.select<EngagementScope[]>(
    `SELECT * FROM engagement_scope WHERE is_active = 1 ORDER BY created_at DESC LIMIT 1`
  );
  if (rows.length === 0) return null;
  const targets = await getScopeTargets(rows[0].id);
  return { ...rows[0], targets };
}

export interface CreateScopeInput {
  engagement_name: string;
  authorized_by: string;
  operator?: string | null;
  reference?: string | null;
  mode?: ScopeMode;
  /** Required when mode is UNRESTRICTED — the operator types this to confirm. */
  unrestricted_ack?: string | null;
  valid_until?: string | null;
  notes?: string | null;
  targets: ScopeTarget[];
}

export async function createScope(input: CreateScopeInput): Promise<number> {
  const db = await getDb();
  const mode: ScopeMode = input.mode === 'UNRESTRICTED' ? 'UNRESTRICTED' : 'ALLOWLIST';

  if (mode === 'UNRESTRICTED' && !input.unrestricted_ack) {
    throw new Error('Unrestricted mode requires a typed acknowledgement.');
  }
  if (mode === 'ALLOWLIST' && input.targets.length === 0) {
    throw new Error('An allowlist engagement needs at least one target.');
  }

  await db.execute(
    `INSERT INTO engagement_scope
       (engagement_name, authorized_by, operator, reference, mode, unrestricted_ack, valid_until, notes, is_active)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 0)`,
    [
      input.engagement_name,
      input.authorized_by,
      input.operator ?? null,
      input.reference ?? null,
      mode,
      input.unrestricted_ack ?? null,
      input.valid_until ?? null,
      input.notes ?? null,
    ]
  );

  const [{ id }] = await db.select<{ id: number }[]>(
    `SELECT id FROM engagement_scope ORDER BY id DESC LIMIT 1`
  );

  for (const target of input.targets) {
    await db.execute(
      `INSERT INTO engagement_targets (scope_id, kind, value, note) VALUES ($1, $2, $3, $4)`,
      [id, target.kind, target.value.trim(), target.note ?? null]
    );
  }

  return id;
}

/** Make one scope active; exactly one row may hold is_active = 1. */
/**
 * Make one scope the active engagement.
 *
 * The clear comes before the set, and the order is load-bearing: migration 019 adds
 * `UNIQUE INDEX ... ON engagement_scope(is_active) WHERE is_active = 1`, so setting
 * before clearing would be refused by the database.
 *
 * That index exists because 008 declared the invariant in a comment and left it to this
 * function, on the stated grounds that "SQLite has no clean partial-unique constraint
 * for it across all supported versions" — which is not so, and has not been since 3.8.0
 * in 2013. The active scope is the authorization record every offensive command is
 * gated against and every refusal in the report is written from; two active at once
 * would make "which authorization covered this command?" unanswerable, and that
 * question is the reason the record is kept at all. 008's file text cannot be corrected
 * — sqlx checksums each migration over its whole contents — so the correction lives
 * here and in 019.
 *
 * Not in a transaction, deliberately: a failure between the two statements leaves zero
 * active scopes, and with no active scope the engine is sent a *cleared* allowlist and
 * refuses every gated command. Failing closed is the right direction for this one.
 */
export async function activateScope(scopeId: number): Promise<void> {
  const db = await getDb();
  await db.execute(`UPDATE engagement_scope SET is_active = 0 WHERE is_active = 1`);
  await db.execute(`UPDATE engagement_scope SET is_active = 1 WHERE id = $1`, [scopeId]);
}

export async function deactivateAllScopes(): Promise<void> {
  const db = await getDb();
  await db.execute(`UPDATE engagement_scope SET is_active = 0 WHERE is_active = 1`);
}

export async function deleteScope(scopeId: number): Promise<void> {
  const db = await getDb();
  await db.execute(`DELETE FROM engagement_targets WHERE scope_id = $1`, [scopeId]);
  await db.execute(`DELETE FROM engagement_scope WHERE id = $1`, [scopeId]);
}

export async function addTarget(scopeId: number, target: ScopeTarget): Promise<void> {
  const db = await getDb();
  await db.execute(
    `INSERT INTO engagement_targets (scope_id, kind, value, note) VALUES ($1, $2, $3, $4)`,
    [scopeId, target.kind, target.value.trim(), target.note ?? null]
  );
}

export async function removeTarget(targetId: number): Promise<void> {
  const db = await getDb();
  await db.execute(`DELETE FROM engagement_targets WHERE id = $1`, [targetId]);
}

/**
 * Build the payload for the engine's `set_scope`.
 * Returns a cleared payload when no scope is active, which puts the engine back
 * into its deny-everything default rather than leaving a stale scope loaded.
 */
export async function buildScopePayload(operator?: string | null): Promise<ScopePayload> {
  const active = await getActiveScope();
  if (!active) {
    return {
      scope_id: null,
      engagement_name: null,
      authorized_by: null,
      operator: operator ?? null,
      reference: null,
      mode: 'ALLOWLIST',
      valid_until: null,
      targets: [],
    };
  }
  return {
    scope_id: active.id,
    engagement_name: active.engagement_name,
    authorized_by: active.authorized_by,
    // Prefer the caller's operator (the person at the keyboard right now), and
    // fall back to the one recorded on the engagement.
    operator: operator ?? active.operator ?? null,
    reference: active.reference,
    mode: active.mode,
    valid_until: active.valid_until,
    targets: active.targets.map(t => ({ kind: t.kind, value: t.value })),
  };
}

// ── Audit trail ─────────────────────────────────────────────────────────────

/** Persist one `audit_event` emitted by the engine. */
export async function recordAuditEvent(event: Partial<AuditRow>): Promise<void> {
  const db = await getDb();
  await db.execute(
    `INSERT INTO audit_log
       (ts, scope_id, engagement_name, command, target, target_kind, decision, reason, operator, mission_id, session_id, details)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
    [
      event.ts ?? new Date().toISOString(),
      event.scope_id ?? null,
      event.engagement_name ?? null,
      event.command ?? 'unknown',
      event.target ?? null,
      event.target_kind ?? null,
      event.decision === 'BLOCKED' ? 'BLOCKED' : 'ALLOWED',
      event.reason ?? null,
      event.operator ?? null,
      event.mission_id ?? null,
      event.session_id ?? null,
      event.details ?? null,
    ]
  );
}

export async function getAuditLog(limit = 500): Promise<AuditRow[]> {
  const db = await getDb();
  return db.select<AuditRow[]>(
    `SELECT * FROM audit_log ORDER BY ts DESC, id DESC LIMIT $1`,
    [limit]
  );
}

export async function getAuditLogForScope(scopeId: number): Promise<AuditRow[]> {
  const db = await getDb();
  return db.select<AuditRow[]>(
    `SELECT * FROM audit_log WHERE scope_id = $1 ORDER BY ts ASC, id ASC`,
    [scopeId]
  );
}

/** Total audit rows, so a truncated table in the PDF can state the real total. */
export async function getAuditCount(scopeId?: number): Promise<number> {
  const db = await getDb();
  // `!= null` for the same reason as in the export below: scope 0 is a scope.
  const rows = scopeId != null
    ? await db.select<{ n: number }[]>(`SELECT COUNT(*) as n FROM audit_log WHERE scope_id = $1`, [scopeId])
    : await db.select<{ n: number }[]>(`SELECT COUNT(*) as n FROM audit_log`);
  return rows[0]?.n ?? 0;
}

/**
 * The complete audit trail as CSV.
 *
 * The PDF tells the reader to "request the full audit export if the complete
 * trail is needed" — which was an honest disclosure of a truncated table, but
 * pointed at a capability that did not exist. This is that export.
 *
 * Streamed in pages so a long engagement does not build one enormous string,
 * and BOM-prefixed so non-ASCII values survive Excel.
 *
 * Cells go through `csvRow` from `csv.ts` rather than a local escaper. The
 * local one doubled quotes and stopped there, which covers a malformed file but
 * not the hazard that module exists for: a cell opening with `=`, `+`, `-` or
 * `@` is evaluated as a formula by Excel, LibreOffice and Sheets, and quoting
 * does not prevent it. That matters here specifically because `audit_log.target`
 * holds **SSIDs** — a string chosen by whoever owns the access point, including
 * the one under investigation. Naming a network `=HYPERLINK("http://…")` is
 * free, and this export is the file handed to management. `csv.ts` already says
 * "every attacker-influenced string in the export is affected"; this export was
 * not using it.
 */
export async function exportAuditTrailCsv(scopeId?: number): Promise<{ csv: string; rows: number }> {
  const db = await getDb();
  const pageSize = 1000;
  // CRLF, because `csvRow` terminates its records that way per RFC 4180 and a
  // file that mixes the two is a file some parsers read as one long row.
  const header = 'Timestamp,Engagement,Command,Target,Target Kind,Decision,Reason,Operator,Mission,Session,Details\r\n';
  const parts: string[] = ['﻿', header];
  let offset = 0;
  let total = 0;
  // `!= null`, not truthiness: a scope id of 0 would otherwise export the whole
  // installation's trail while the caller believed it had asked for one scope.
  const scoped = scopeId != null;

  for (;;) {
    const page = scoped
      ? await db.select<AuditRow[]>(
          `SELECT * FROM audit_log WHERE scope_id = $1 ORDER BY ts ASC, id ASC LIMIT $2 OFFSET $3`,
          [scopeId, pageSize, offset])
      : await db.select<AuditRow[]>(
          `SELECT * FROM audit_log ORDER BY ts ASC, id ASC LIMIT $1 OFFSET $2`,
          [pageSize, offset]);

    if (page.length === 0) break;
    for (const r of page) {
      parts.push(csvRow([
        r.ts, r.engagement_name, r.command, r.target,
        r.target_kind, r.decision, r.reason, r.operator,
        r.mission_id, r.session_id, r.details,
      ]));
    }
    total += page.length;
    offset += pageSize;
    if (page.length < pageSize) break;
  }

  return { csv: parts.join(''), rows: total };
}

export async function getAuditSummary(): Promise<{ allowed: number; blocked: number }> {
  const db = await getDb();
  const rows = await db.select<{ decision: AuditDecision; n: number }[]>(
    `SELECT decision, COUNT(*) as n FROM audit_log GROUP BY decision`
  );
  return {
    allowed: rows.find(r => r.decision === 'ALLOWED')?.n ?? 0,
    blocked: rows.find(r => r.decision === 'BLOCKED')?.n ?? 0,
  };
}
