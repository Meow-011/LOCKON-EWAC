#!/usr/bin/env node
/**
 * Carry data forward from a database on the older schema line.
 *
 *     node scripts/migrate-legacy-db.mjs <legacy.db> <fresh.db> [--apply]
 *
 * Why this exists.
 *
 * This project's migrations 8 and 9 were once `raw_gps` and `bluetooth_schema`.
 * They are now `create_integrity_and_scope` and `create_findings_and_evidence`:
 * different migrations occupying the same two version numbers. sqlx identifies a
 * migration by its number, so a database carrying the old pair cannot be opened
 * by a build carrying the new one, and no checksum repair can change that -- the
 * two schemas genuinely diverged. The startup dialog's advice, to move the file
 * aside and start fresh, is correct about the file and wrong about the data: on
 * the database that prompted this, every table had a home in the current schema,
 * and starting fresh would have discarded 1,833 access points, 29,963 GPS fixes
 * and 394,584 scan-log rows of real field survey.
 *
 * So: let the current build create a fresh database -- it writes its own sqlx
 * bookkeeping, which is the part that must not be forged by hand -- and copy the
 * rows into it.
 *
 * What it will and will not do.
 *
 * Only columns present in BOTH schemas are copied, by name, never by position.
 * A column the current schema added is left at its default, which is what "this
 * was never measured" looks like in this project: an old survey genuinely has no
 * value for a field that did not exist when it was recorded, and inventing one
 * would be the exact failure this tool exists to avoid. A column only the old
 * schema had is dropped and named in the report, so the loss is stated rather
 * than discovered later.
 *
 * It refuses to write into a table that already holds rows. Merging two
 * populated databases means deciding what to do about colliding primary keys,
 * and silently picking one is how evidence gets attributed to the wrong survey.
 *
 * It is a dry run unless `--apply` is passed, and `--apply` runs in one
 * transaction: either every table lands or none does. Back up the legacy file
 * first regardless; this opens it read-only, but a backup costs nothing.
 */
import { DatabaseSync } from 'node:sqlite';
import { existsSync } from 'node:fs';

const [, , legacyPath, freshPath, ...flags] = process.argv;
const apply = flags.includes('--apply');

if (!legacyPath || !freshPath) {
  console.error('usage: node scripts/migrate-legacy-db.mjs <legacy.db> <fresh.db> [--apply]');
  process.exit(2);
}
for (const p of [legacyPath, freshPath]) {
  if (!existsSync(p)) { console.error(`[migrate] no such file: ${p}`); process.exit(2); }
}

const legacy = new DatabaseSync(legacyPath, { readOnly: true });
const fresh = new DatabaseSync(freshPath);

const tablesOf = (db) => db
  .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
  .all()
  .map(r => r.name)
  // sqlx's own bookkeeping is the one thing that must stay as the app wrote it,
  // and sqlite_sequence maintains itself as rows are inserted.
  .filter(n => !n.startsWith('sqlite_') && n !== '_sqlx_migrations');

const colsOf = (db, t) => db.prepare(`PRAGMA table_info(${t})`).all().map(r => r.name);
const countOf = (db, t) => db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n;

const legacyTables = tablesOf(legacy);
const freshTables = new Set(tablesOf(fresh));

const plan = [];
const skipped = [];

for (const t of legacyTables) {
  const rows = countOf(legacy, t);
  if (!freshTables.has(t)) { skipped.push({ t, rows, why: 'no table of this name in the current schema' }); continue; }
  if (rows === 0) { skipped.push({ t, rows, why: 'empty' }); continue; }

  const existing = countOf(fresh, t);
  if (existing > 0) { skipped.push({ t, rows, why: `the destination already holds ${existing} row(s)` }); continue; }

  const from = colsOf(legacy, t);
  const to = new Set(colsOf(fresh, t));
  const shared = from.filter(c => to.has(c));
  const dropped = from.filter(c => !to.has(c));
  const added = colsOf(fresh, t).filter(c => !from.includes(c));

  if (shared.length === 0) { skipped.push({ t, rows, why: 'no columns in common' }); continue; }
  plan.push({ t, rows, shared, dropped, added });
}

console.log(`[migrate] ${legacyPath}`);
console.log(`[migrate] -> ${freshPath}`);
console.log(`[migrate] ${apply ? 'APPLYING' : 'DRY RUN (pass --apply to write)'}\n`);

let total = 0;
for (const p of plan) {
  total += p.rows;
  console.log(`  ${p.t.padEnd(22)} ${String(p.rows).padStart(7)} rows   ${p.shared.length} columns carried`);
  if (p.dropped.length) console.log(`      DROPPED (not in the current schema): ${p.dropped.join(', ')}`);
  if (p.added.length) console.log(`      left at default (added since): ${p.added.join(', ')}`);
}
if (skipped.length) {
  console.log('\n  not copied:');
  for (const s of skipped) console.log(`    ${s.t.padEnd(22)} ${String(s.rows).padStart(7)} rows   ${s.why}`);
}

if (!apply) {
  console.log(`\n[migrate] would copy ${total} row(s) across ${plan.length} table(s). Nothing was written.`);
  process.exit(0);
}

// Foreign keys stay off for the copy, which is SQLite's default for a new
// connection. Tables are copied in whatever order sqlite_master lists them, so a
// child can land before its parent; enforcing references row by row would reject
// rows that are perfectly consistent once the whole copy is done. The check is
// run at the end instead, and a violation fails the transaction.
fresh.exec('PRAGMA foreign_keys = OFF');
fresh.exec('BEGIN');
try {
  for (const p of plan) {
    const cols = p.shared.map(c => `"${c}"`).join(', ');
    const read = legacy.prepare(`SELECT ${cols} FROM "${p.t}"`);
    const write = fresh.prepare(
      `INSERT INTO "${p.t}" (${cols}) VALUES (${p.shared.map(() => '?').join(', ')})`
    );
    let n = 0;
    for (const row of read.all()) {
      write.run(...p.shared.map(c => row[c]));
      n++;
    }
    const landed = countOf(fresh, p.t);
    if (landed !== p.rows) throw new Error(`${p.t}: read ${p.rows}, wrote ${n}, destination holds ${landed}`);
    console.log(`  ${p.t.padEnd(22)} ${String(landed).padStart(7)} rows copied`);
  }

  const violations = fresh.prepare('PRAGMA foreign_key_check').all();
  if (violations.length > 0) {
    throw new Error(`${violations.length} foreign-key violation(s) after the copy, first in table "${violations[0].table}"`);
  }

  fresh.exec('COMMIT');
} catch (e) {
  fresh.exec('ROLLBACK');
  console.error(`\n[migrate] FAILED, nothing written — ${e.message}`);
  process.exit(1);
}

console.log(`\n[migrate] ${total} row(s) copied across ${plan.length} table(s).`);
console.log('[migrate] The legacy file was opened read-only and is unchanged.');
