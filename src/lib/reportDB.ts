/**
 * LOCKON EWAC — Intel Reports Database Layer
 */
import { getDb } from './database';
import type { Report } from '../stores/reportStore';

/**
 * Save a report.
 *
 * Throws on a duplicate id instead of swallowing the constraint error — an
 * import that silently did nothing was indistinguishable from one that worked.
 */
export async function saveReport(report: Report): Promise<void> {
  const db = await getDb();
  await db.execute(
    `INSERT INTO intel_reports (id, type, target_name, timestamp, total_nodes, critical_nodes, total_aps, vulnerable_aps, raw_data, is_simulated)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
    [
      report.id,
      report.type,
      report.targetName,
      report.timestamp,
      /*
        `?? null`, not `|| null`.

        `||` treats a genuine zero as absent, so "we surveyed this area and
        found no access points" and "no count was recorded" were stored
        identically — erasing a real result at the storage layer, which is the
        same defect as reading an absent column back as a hard zero. Zero
        vulnerable access points is the single most valuable number a
        remediation report can carry, and it was the one guaranteed not to
        survive.

        `??` keeps a zero and still stores NULL when the field really is absent,
        which is what the nullable columns are for.
      */
      report.summary.totalNodes ?? null,
      report.summary.criticalNodes ?? null,
      report.summary.totalAPs ?? null,
      report.summary.vulnerableAPs ?? null,
      JSON.stringify(report.rawData),
      report.simulated ? 1 : 0
    ]
  );
}

export async function reportExists(id: string): Promise<boolean> {
  const db = await getDb();
  const rows = await db.select<{ n: number }[]>(
    'SELECT COUNT(*) as n FROM intel_reports WHERE id = $1',
    [id]
  );
  return (rows[0]?.n ?? 0) > 0;
}

/**
 * One archive's `raw_data`, or a marker that it could not be read.
 *
 * `JSON.parse` was called inline in the map below, so a single unreadable
 * `raw_data` — a half-written import, a row from a session that died mid-write —
 * threw out of `getAllReports()`. That is the function the Reports page calls to
 * list everything, so one bad row emptied the whole archive list with no
 * indication of which report was at fault or that any existed.
 *
 * The row is kept and marked instead. An archive whose contents cannot be read
 * is still a fact about the engagement, and the operator needs to see that it is
 * there and broken rather than that it is gone.
 */
function parseRawData(id: string, raw: unknown): any {
  if (typeof raw !== 'string' || raw.length === 0) {
    return { unreadable: true, reason: 'This archive stored no data.' };
  }
  try {
    const parsed = JSON.parse(raw);
    // `JSON.parse('null')` and `JSON.parse('7')` both succeed and neither is an
    // archive. Everything downstream reads properties off this object.
    if (parsed === null || typeof parsed !== 'object') {
      return { unreadable: true, reason: 'This archive\'s stored data is not an object.' };
    }
    return parsed;
  } catch (err) {
    console.error(`[DB] report ${id} has unreadable raw_data:`, err);
    return {
      unreadable: true,
      reason: `This archive's stored data could not be parsed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

export async function getAllReports(): Promise<Report[]> {
  const db = await getDb();
  const rows: any[] = await db.select('SELECT * FROM intel_reports ORDER BY timestamp DESC');

  return rows.map(r => ({
    id: r.id,
    type: r.type,
    targetName: r.target_name,
    timestamp: r.timestamp,
    simulated: r.is_simulated === 1,
    summary: {
      totalNodes: r.total_nodes,
      criticalNodes: r.critical_nodes,
      totalAPs: r.total_aps,
      vulnerableAPs: r.vulnerable_aps,
    },
    rawData: parseRawData(r.id, r.raw_data),
    // Carried through so the PDF cover can state where an archive came from.
    // This column was written, and read only by `getExportProvenance` for one
    // report at a time — the export path never saw it, so an imported archive
    // printed as "LIVE HARDWARE [FIELD DATA]".
    origin: r.origin ?? 'LOCAL',
  }));
}

export async function removeReport(id: string): Promise<void> {
  const db = await getDb();
  await db.execute('DELETE FROM intel_reports WHERE id = $1', [id]);
}

export async function updateReportName(id: string, newName: string): Promise<void> {
  const db = await getDb();
  await db.execute('UPDATE intel_reports SET target_name = $1 WHERE id = $2', [newName, id]);
}

export async function clearAllReports(): Promise<void> {
  const db = await getDb();
  await db.execute('DELETE FROM intel_reports');
}

// ── Export integrity ────────────────────────────────────────────────────────

/**
 * SHA-256 of an exported artifact, computed in the browser via WebCrypto.
 *
 * A report someone acts on has to be shown to be the one the tool produced.
 * Recording the digest at export time means the holder of a PDF can verify it
 * was not altered afterwards, and the document can print its own fingerprint.
 */
export async function sha256Hex(data: ArrayBuffer | Uint8Array | Blob): Promise<string> {
  let buffer: ArrayBuffer;
  if (data instanceof Blob) {
    buffer = await data.arrayBuffer();
  } else if (data instanceof Uint8Array) {
    buffer = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
  } else {
    buffer = data;
  }
  const digest = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(digest))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export interface ExportProvenance {
  sha256: string;
  filename: string;
  exported_by?: string | null;
  app_version?: string | null;
  engine_version?: string | null;
  cve_data_date?: string | null;
  /** JSON snapshot of the rules that produced the severities in this document. */
  methodology?: unknown;
}

/** Record what was exported, when, by whom, and under which rule set. */
export async function recordExport(reportId: string, p: ExportProvenance): Promise<void> {
  const db = await getDb();
  await db.execute(
    `UPDATE intel_reports
     SET sha256 = $1, exported_at = datetime('now'), exported_by = $2,
         export_filename = $3, app_version = $4, engine_version = $5,
         cve_data_date = $6, methodology = $7
     WHERE id = $8`,
    [
      p.sha256, p.exported_by ?? null, p.filename,
      p.app_version ?? null, p.engine_version ?? null, p.cve_data_date ?? null,
      p.methodology ? JSON.stringify(p.methodology) : null,
      reportId,
    ]
  );
}

export async function getExportProvenance(reportId: string): Promise<{
  sha256: string | null; exported_at: string | null; exported_by: string | null;
  export_filename: string | null; app_version: string | null;
  engine_version: string | null; cve_data_date: string | null;
  methodology: string | null; origin: string;
} | null> {
  const db = await getDb();
  const rows = await db.select<any[]>(
    `SELECT sha256, exported_at, exported_by, export_filename, app_version,
            engine_version, cve_data_date, methodology, origin
     FROM intel_reports WHERE id = $1`,
    [reportId]
  );
  return rows[0] ?? null;
}

/** Mark a report as imported rather than produced locally. */
export async function markImported(reportId: string): Promise<void> {
  const db = await getDb();
  await db.execute(`UPDATE intel_reports SET origin = 'IMPORTED' WHERE id = $1`, [reportId]);
}
