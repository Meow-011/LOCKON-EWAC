/** LOCKON EWAC — Intrusion Database Access Layer */
import { getDb, reclaimFreePages } from './database';

/*
  One connection layer for the whole app.

  This module opened its own `Database.load('sqlite:ewac.db')` with the database
  name written out as a literal, in a second place, with its own module-level
  cache. Two things followed. The setup `getDb()` performs — enabling WAL, which
  is what stops a read during a scan hitting SQLITE_BUSY — did not run on this
  path unless some other module happened to open first. And the name was
  duplicated: changing `DB_NAME` in `constants.ts` would have left this module
  reading a different file, silently, and the symptom would have been history
  that had simply vanished.
*/
const getDB = getDb;

// ─── Session Management ───

export async function createSession(
  id: string,
  subnet: string,
  scanMode: string,
  /**
   * Whether this sweep came from the simulator.
   *
   * `scan_sessions.is_simulated` has existed since migration 008 and was the
   * only one of that migration's six provenance flags with no writer, so every
   * sweep recorded as real. Low risk while `simulator.py` produces only access
   * points and GPS, but a provenance column that silently says "field data" is
   * the wrong thing to leave in place for the day a host simulator lands.
   */
  simulated = false,
) {
  const conn = await getDB();
  await conn.execute(
    'INSERT INTO scan_sessions (id, subnet, scan_mode, is_simulated) VALUES ($1, $2, $3, $4)',
    [id, subnet, scanMode, simulated ? 1 : 0]
  );
}

export async function completeSession(id: string, hostCount: number) {
  const conn = await getDB();
  await conn.execute(
    "UPDATE scan_sessions SET completed_at = datetime('now'), host_count = $1 WHERE id = $2",
    [hostCount, id]
  );
}

export async function updateSessionSubnet(id: string, subnet: string) {
  const conn = await getDB();
  await conn.execute(
    "UPDATE scan_sessions SET subnet = $1 WHERE id = $2",
    [subnet, id]
  );
}

// ─── Host Persistence ───

export async function saveHost(
  sessionId: string,
  host: { ip: string; hostname: string; os: string; mac?: string; vendor?: string; isGateway: boolean; open_ports: { port: number; service: string; banner?: string }[] }
): Promise<number> {
  const conn = await getDB();

  const result = await conn.execute(
    /*
      `intrusion_hosts.risk_score`, `.risk_level` and `.last_status` are
      declared by migration 009 and are deliberately left unwritten.

      009's stated purpose for them — "let a host's assessment be queried and
      compared between runs" — is met, but through `findings`: `assessHost`
      writes a row per finding with a stable fingerprint, which is what the
      retest comparison reads. Filling these columns as well would put a second
      risk number in the database for the same host, and five disagreeing risk
      scales is precisely the problem `riskEngine.ts` was written to end.

      Note what "unwritten" actually looks like in the file: `risk_level` and
      `last_status` are NULL, but `risk_score` is declared
      `INTEGER NOT NULL DEFAULT 0`, so it reads back as a confident **0** — the
      same shape as `wps_enabled NOT NULL DEFAULT 0`, which gave every access
      point a "no WPS" nobody had measured. Nothing reads this column today (the
      dashboard tile that filtered `risk_score >= 7.0` on it was permanently
      zero and has been replaced by the findings query), and anything that
      starts reading it must not take that 0 for an assessment.

      SQLite cannot drop a column without rebuilding the table, so they stay.
    */
    'INSERT INTO intrusion_hosts (session_id, ip, hostname, os, mac, vendor, is_gateway) VALUES ($1, $2, $3, $4, $5, $6, $7)',
    [sessionId, host.ip, host.hostname, host.os, host.mac || null, host.vendor || null, host.isGateway ? 1 : 0]
  );

  const hostId = result.lastInsertId;

  // Save ports
  for (const p of host.open_ports) {
    await conn.execute(
      'INSERT INTO intrusion_ports (host_id, port, service, banner) VALUES ($1, $2, $3, $4)',
      [hostId, p.port, p.service, p.banner || null]
    );
  }

  return hostId as number;
}

// ─── Query Functions ───

export interface ScanSession {
  id: string;
  subnet: string;
  scan_mode: string;
  host_count: number;
  started_at: string;
  completed_at: string | null;
}

export interface HistoryHost {
  id: number;
  ip: string;
  hostname: string | null;
  os: string | null;
  mac: string | null;
  vendor: string | null;
  is_gateway: number;
  discovered_at: string;
  ports: { port: number; service: string; banner: string | null }[];
}

export async function getSessions(limit = 50): Promise<ScanSession[]> {
  const conn = await getDB();
  return await conn.select<ScanSession[]>(
    'SELECT * FROM scan_sessions ORDER BY started_at DESC LIMIT $1',
    [limit]
  );
}

export async function getSessionHosts(sessionId: string): Promise<HistoryHost[]> {
  const conn = await getDB();
  const hosts = await conn.select<(HistoryHost & { ports?: any })[]>(
    'SELECT * FROM intrusion_hosts WHERE session_id = $1 ORDER BY ip',
    [sessionId]
  );

  // Fetch ports for each host
  for (const host of hosts) {
    host.ports = await conn.select(
      'SELECT port, service, banner FROM intrusion_ports WHERE host_id = $1',
      [host.id]
    );
  }

  return hosts;
}

export interface DeviceHistoryEntry {
  session_id: string;
  ip: string;
  os: string;
  discovered_at: string;
  started_at: string;
  subnet: string;
}

/**
 * Every time this MAC has been seen, across all sweeps.
 *
 * Useful for two questions a report gets asked: "is this device new here?" and
 * "has it moved?" — a MAC that appears under several IPs or subnets over time is
 * either roaming or being re-addressed, and that distinction matters when the
 * finding is about an unexpected host.
 *
 * Matching is case-insensitive because MAC formatting is inconsistent between
 * the ARP table and the scanner.
 */
export async function getDeviceHistory(mac: string): Promise<DeviceHistoryEntry[]> {
  const conn = await getDB();
  return await conn.select(
    `SELECT h.session_id, h.ip, h.os, h.discovered_at, s.started_at, s.subnet
     FROM intrusion_hosts h
     JOIN scan_sessions s ON h.session_id = s.id
     WHERE UPPER(REPLACE(h.mac, '-', ':')) = UPPER(REPLACE($1, '-', ':'))
     ORDER BY h.discovered_at DESC`,
    [mac]
  );
}

/** Distinct IPs this MAC has held, newest first — the "has it moved" answer. */
export async function getDeviceAddressChanges(mac: string): Promise<{ ip: string; first: string; last: string; sightings: number }[]> {
  const conn = await getDB();
  return await conn.select(
    `SELECT h.ip as ip,
            MIN(h.discovered_at) as first,
            MAX(h.discovered_at) as last,
            COUNT(*) as sightings
     FROM intrusion_hosts h
     WHERE UPPER(REPLACE(h.mac, '-', ':')) = UPPER(REPLACE($1, '-', ':'))
     GROUP BY h.ip
     ORDER BY last DESC`,
    [mac]
  );
}

/**
 * Delete one sweep and everything that described it.
 *
 * `intrusion_hosts` and `intrusion_ports` cascade from `scan_sessions`, so the
 * last statement would clear them on its own — but only while
 * `PRAGMA foreign_keys` is on, which is a per-connection setting on a pooled
 * connection nobody here controls. Deleted explicitly for the same reason
 * `deleteMission` does.
 *
 * `findings` carries a plain `session_id TEXT` with no foreign key, so nothing
 * cascades to it. Those rows were left behind, still counted by every query
 * that does not filter by session — a deleted sweep went on contributing to the
 * headline risk figure. A finding is a statement about a sweep's observations;
 * deleting the sweep deletes the grounds for it.
 */
export async function deleteSession(id: string) {
  const conn = await getDB();
  const hosts = await conn.select<{ id: number }[]>(
    'SELECT id FROM intrusion_hosts WHERE session_id = $1', [id]);
  for (const host of hosts) {
    await conn.execute('DELETE FROM intrusion_ports WHERE host_id = $1', [host.id]);
  }
  await conn.execute('DELETE FROM intrusion_hosts WHERE session_id = $1', [id]);
  await conn.execute('DELETE FROM findings WHERE session_id = $1', [id]);
  await conn.execute('DELETE FROM assessment_baselines WHERE session_id = $1', [id]);
  /*
    The two session-scoped tables that were left behind.

    `credentials` and `evidence_files` carry `session_id` with no foreign key, so
    nothing cascades to them, and every read filters by session — so deleting a sweep
    hid them from the interface while leaving them in the file. Both hold the most
    sensitive rows this application stores: recovered passwords, and the paths and
    SHA-256 of captured handshakes. `purgeCollectedData` clears them, so only
    per-sweep deletion was affected.

    Pages are reclaimed afterwards, like `crackingDB.deleteCrackingRecord`: a deleted
    credential leaves the index and not the file, and for a legacy `enc_version = 0`
    row what stays behind is cleartext.
  */
  await conn.execute('DELETE FROM credentials WHERE session_id = $1', [id]);
  await conn.execute('DELETE FROM evidence_files WHERE session_id = $1', [id]);
  await conn.execute('DELETE FROM scan_sessions WHERE id = $1', [id]);
  await reclaimFreePages();
}

export async function deleteAllSessions() {
  const conn = await getDB();
  // Ports before hosts before sessions, and the session-scoped findings with
  // them. `session_id IS NOT NULL` so a finding from a wardriving mission —
  // which has a mission_id and no session — is not caught by this.
  await conn.execute('DELETE FROM intrusion_ports');
  await conn.execute('DELETE FROM intrusion_hosts');
  await conn.execute('DELETE FROM findings WHERE session_id IS NOT NULL');
  await conn.execute('DELETE FROM assessment_baselines WHERE session_id IS NOT NULL');
  await conn.execute('DELETE FROM scan_sessions');
}
