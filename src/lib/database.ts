/** LOCKON EWAC — Database Operations Wrapper */
import Database from '@tauri-apps/plugin-sql';
import { DB_NAME } from './constants';

let db: Database | null = null;

export async function getDb(): Promise<Database> {
  if (!db) {
    db = await Database.load(DB_NAME);

    /*
      Turn on WAL, from here rather than from a migration.

      Migration 001 contains `PRAGMA journal_mode = WAL` and it has never done
      anything. sqlx applies every migration inside a transaction, and SQLite
      silently refuses a journal-mode change while a write transaction is open —
      it returns the current mode and changes nothing. Verified by applying all
      migrations to a fresh database exactly as sqlx does: `journal_mode` comes
      out as `delete`. sqlx also does not set it on connect, so nothing else
      recovered it.

      Two things followed. Readers and writers blocked each other, so a `select`
      for the map or the archive while a scan was inserting hit SQLITE_BUSY and
      surfaced as "database is locked" or a stalled UI. And with a rollback
      journal `synchronous` stays FULL, making every one of the app's many
      single-row inserts its own fsync'd transaction — the hot paths here are
      un-batched loops, one row per sighting and one per open port.

      Unlike `secure_delete`, this works from a single connection: WAL is
      recorded in the database file header, so setting it once is permanent and
      applies to every connection in the pool from then on. That difference is
      the whole reason this one can be fixed here and that one could not.
    */
    try {
      const rows = await db.select<{ journal_mode: string }[]>('PRAGMA journal_mode = WAL');
      const mode = rows?.[0]?.journal_mode?.toLowerCase();
      if (mode && mode !== 'wal') {
        // A network share or a read-only file cannot hold a WAL. Worth knowing
        // about rather than silently running slowly.
        console.warn(`[DB] WAL could not be enabled; journal_mode is '${mode}'. `
          + 'Expect "database is locked" under concurrent access.');
      }
    } catch (err) {
      console.warn('[DB] could not set journal_mode=WAL:', err);
    }

    // Best-effort only — see reclaimFreePages() for the guarantee.
    //
    // SQLite's secure_delete is per *connection*, and `tauri-plugin-sql` hands
    // out an sqlx pool (10 connections by default), so this pragma lands on
    // whichever connection happened to serve it and the others keep the default
    // of off. It is set anyway because it costs nothing and narrows the window,
    // but nothing may be built on top of it.
    try {
      await db.execute('PRAGMA secure_delete = ON');
    } catch {
      // A pragma that will not apply is not a reason to fail to open the app.
    }
  }
  return db;
}

/**
 * Rewrite the database file so that freed pages no longer contain their old
 * contents.
 *
 * This is the load-bearing part of the vault's promise, and it was missing.
 *
 * SQLite marks deleted pages free **with the bytes still in them** —
 * `secure_delete` defaults to off, verified on this machine. Migration 012
 * copies the cleartext `password` column into a new table and then
 * `DROP TABLE credentials`, and `sealLegacyCredentials()` nulls the column per
 * row. Neither reclaims anything, and there was no `VACUUM` anywhere in the
 * project.
 *
 * Measured on a seeded vault of 300 credentials: after running migration 012
 * and then sealing, **every one of the 300 passwords was still recoverable as
 * raw bytes from the .db file** (310 byte-matches, because the INSERT…SELECT
 * leaves a second copy behind). After a VACUUM: zero.
 *
 * So the operator would set a passphrase, seal the vault, watch the banner
 * report no unprotected rows, and carry a laptop off the engagement with every
 * recovered credential still readable by `strings ewac.db` — which is the exact
 * scenario migration 012's own header says it exists to prevent.
 *
 * VACUUM cannot run inside a transaction, which is why this is not part of the
 * migration.
 */
export async function reclaimFreePages(): Promise<void> {
  const database = await getDb();
  await database.execute('VACUUM');
}

/** Generic query helper */
export async function query<T>(sql: string, bindValues?: unknown[]): Promise<T[]> {
  const database = await getDb();
  return database.select<T[]>(sql, bindValues);
}

/** Generic execute helper (INSERT/UPDATE/DELETE) */
export async function execute(sql: string, bindValues?: unknown[]) {
  const database = await getDb();
  return database.execute(sql, bindValues);
}

/**
 * Tables the PURGE action clears, in dependency order (children first) so the
 * deletes work whether or not foreign keys are enforced.
 *
 * engagement_scope / engagement_targets are deliberately absent: an engagement
 * is the operator's authorization record, not collected data, and wiping the
 * scope silently would disarm the tool. audit_log is absent for the same reason
 * — an audit trail you can erase with one button is not an audit trail.
 */
const PURGEABLE_TABLES = [
  'intrusion_ports',
  'intrusion_hosts',
  'scan_sessions',
  'vulnerability_results',
  'scan_logs',
  'gps_logs',
  /*
    The five below were missing, and they do not cascade: `findings`,
    `evidence_files` and `clients` carry `mission_id` as plain TEXT with no
    foreign key to `missions`, so deleting missions left every one of their rows
    behind.

    `clients` is the one that matters most. It holds the MAC addresses, vendors
    and probed-SSID history of third-party devices seen in passive monitoring —
    people who were not the subject of the engagement. For a tool that gets
    carried off-site, that is the table an operator would most expect
    "PURGE DATABASE" to clear, and it was the one table it never touched.

    The others left dangling references: `findings` and `evidence_files` kept
    pointing at BSSIDs and mission ids whose rows were gone, so the Findings
    view listed findings about access points the archive no longer contained.

    `engagement_scope`, `engagement_targets` and `audit_log` remain deliberately
    absent, for the reason given above.
  */
  'findings',
  'evidence_files',
  'clients',
  'mission_coverage',
  'assessment_baselines',
  'access_points',
  'missions',
  'credentials',
  'intel_reports',
  'cracking_history',
  'antenna_benchmarks',
] as const;

export interface PurgeResult {
  table: string;
  rowsAffected: number;
}

/**
 * Actually delete collected data.
 *
 * The Settings button used to be labelled "PURGE DATABASE" while only clearing
 * the engine's in-memory dicts and a Zustand store, so every row survived. This
 * does what the label says and reports what it removed, so the operator can see
 * the wipe happened rather than trusting a toast.
 */
export async function purgeCollectedData(): Promise<PurgeResult[]> {
  const database = await getDb();
  const results: PurgeResult[] = [];
  for (const table of PURGEABLE_TABLES) {
    const res = await database.execute(`DELETE FROM ${table}`);
    results.push({ table, rowsAffected: res.rowsAffected ?? 0 });
  }

  // A DELETE that leaves the rows legible in the file is not what this button
  // says it does. `credentials` is in the list above, so a purge without this
  // left every recovered password readable by `strings ewac.db` — and a purge is
  // the single most likely moment for an operator to believe the data is gone.
  //
  // It also reclaims the space, which a survey database badly needs after a
  // purge. Reported as its own row so a failure is visible rather than leaving
  // the operator with a false assurance.
  try {
    await database.execute('VACUUM');
    results.push({ table: 'VACUUM (file rewritten, freed pages overwritten)', rowsAffected: 0 });
  } catch (err) {
    results.push({
      table: `VACUUM FAILED — deleted rows may still be readable in the file: ${String(err)}`,
      rowsAffected: -1,
    });
  }
  return results;
}

/** Row counts per purgeable table, for the confirmation dialog. */
export async function getDataFootprint(): Promise<PurgeResult[]> {
  const database = await getDb();
  const results: PurgeResult[] = [];
  for (const table of PURGEABLE_TABLES) {
    const rows = await database.select<{ n: number }[]>(`SELECT COUNT(*) as n FROM ${table}`);
    results.push({ table, rowsAffected: rows[0]?.n ?? 0 });
  }
  return results;
}
