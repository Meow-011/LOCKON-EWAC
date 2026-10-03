/** LOCKON EWAC — Antenna Benchmark Database Layer */
import { getDb } from './database';

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

// ─── Types ───

export interface BenchmarkResult {
  id: number;
  label: string;
  interface_name: string;
  total_aps: number;
  aps_2g: number;
  aps_5g: number;
  aps_6g: number;
  min_rssi: number | null;
  max_rssi: number | null;
  avg_rssi: number | null;
  band_excellent: number;
  band_good: number;
  band_fair: number;
  band_weak: number;
  scan_duration_ms: number | null;
  notes: string | null;
  created_at: string;
}

// ─── CRUD ───

export async function saveBenchmark(result: Omit<BenchmarkResult, 'id' | 'created_at'>): Promise<number> {
  const conn = await getDB();
  const res = await conn.execute(
    `INSERT INTO antenna_benchmarks (label, interface_name, total_aps, aps_2g, aps_5g, aps_6g, min_rssi, max_rssi, avg_rssi, band_excellent, band_good, band_fair, band_weak, scan_duration_ms, notes)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
    [
      result.label,
      result.interface_name,
      result.total_aps,
      result.aps_2g,
      result.aps_5g,
      result.aps_6g,
      result.min_rssi,
      result.max_rssi,
      result.avg_rssi,
      result.band_excellent,
      result.band_good,
      result.band_fair,
      result.band_weak,
      result.scan_duration_ms,
      result.notes
    ]
  );
  return res.lastInsertId as number;
}

export async function getBenchmarks(limit = 20): Promise<BenchmarkResult[]> {
  const conn = await getDB();
  return await conn.select<BenchmarkResult[]>(
    'SELECT * FROM antenna_benchmarks ORDER BY created_at DESC LIMIT $1',
    [limit]
  );
}

export async function deleteBenchmark(id: number) {
  const conn = await getDB();
  await conn.execute('DELETE FROM antenna_benchmarks WHERE id = $1', [id]);
}
