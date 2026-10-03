/**
 * A real SQLite standing in for @tauri-apps/plugin-sql.
 *
 * Why this and not a mock.
 *
 * Every `src/lib/*DB.ts` module was untested, and the reason was the database:
 * mocking `select`/`execute` proves only that the code calls them, which is
 * never where the bugs are. The bugs in this project's SQL were a backtick
 * inside a SQL comment that silently terminated a template literal, a JOIN that
 * counted rows from other engagements, and an index the planner never chose.
 * A mock cannot see any of those. `node:sqlite` can, and it runs the project's
 * actual migrations, so the schema under test is the schema that ships.
 *
 * What it is faithful about:
 *   - `$1`-style placeholders, bound positionally from the array, exactly as
 *     tauri-plugin-sql does for its sqlx/SQLite backend.
 *   - `execute()` returning `{ rowsAffected, lastInsertId }`.
 *   - `select()` returning plain row objects.
 *   - Foreign keys ON, which sqlx enables and which is what makes
 *     `ON DELETE CASCADE` in the migrations mean anything.
 *
 * Where it differs, and it matters:
 *   - One connection, not a pool. Anything that depends on *which* connection
 *     served a statement — `PRAGMA secure_delete` is the live example — cannot
 *     be tested here, and a test that seems to prove it works is lying.
 *   - `:memory:` cannot hold a WAL, so `journal_mode` comes back `memory`. Real
 *     WAL behaviour is not observable from here.
 */
import { DatabaseSync } from 'node:sqlite';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/*
  Found by walking up, not by a relative path from this file.

  The alias that installs this stub makes esbuild inline it into the test
  bundle, so `import.meta.url` at run time is `.test-build/db.mjs` and a
  hardcoded `../../src-tauri/migrations` resolves one directory too high. That
  failed as ENOENT inside a `beforeEach`, which node:test reports as every test
  failing at once — a confusing symptom for a path bug.
*/
function findMigrationsDir() {
  const starts = [dirname(fileURLToPath(import.meta.url)), process.cwd()];
  for (const start of starts) {
    let dir = resolve(start);
    for (let up = 0; up < 6; up++) {
      const candidate = join(dir, 'src-tauri', 'migrations');
      if (existsSync(candidate)) return candidate;
      const parent = dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
  }
  throw new Error('could not locate src-tauri/migrations from ' + starts.join(' or '));
}

const MIGRATIONS_DIR = findMigrationsDir();

/** Every migration file, in the order sqlx would apply them. */
export function migrationFiles() {
  return readdirSync(MIGRATIONS_DIR)
    .filter(f => f.endsWith('.sql'))
    .sort();
}

/**
 * Bind an array the way the plugin does: `$1` is `values[0]`.
 *
 * Only the placeholders the statement actually contains are bound. SQLite
 * rejects a named parameter it has never heard of, and callers in this codebase
 * routinely pass a longer array than a given branch of the SQL uses.
 */
function bindingsFor(sql, values) {
  if (!values || values.length === 0) return undefined;
  const used = new Set();
  for (const match of String(sql).matchAll(/\$(\d+)/g)) used.add(Number(match[1]));
  if (used.size === 0) return undefined;
  const out = {};
  for (const index of used) {
    const value = values[index - 1];
    // SQLite has no boolean and node:sqlite refuses one outright rather than
    // coercing; the plugin's Rust side converts, so this must too or every
    // `is_simulated` write would throw only in tests.
    out[`$${index}`] = typeof value === 'boolean' ? (value ? 1 : 0)
      : value === undefined ? null
      : value;
  }
  return out;
}

class FakeDatabase {
  constructor(path) {
    this.path = path;
    this.raw = new DatabaseSync(path);
    this.raw.exec('PRAGMA foreign_keys = ON');
    this.statementLog = [];
  }

  applyMigrations() {
    for (const file of migrationFiles()) {
      const sql = readFileSync(join(MIGRATIONS_DIR, file), 'utf8');
      try {
        this.raw.exec(sql);
      } catch (err) {
        throw new Error(`migration ${file} failed: ${err.message}`);
      }
    }
  }

  async execute(sql, values) {
    this.statementLog.push(sql);
    const bindings = bindingsFor(sql, values);
    const statement = this.raw.prepare(sql);
    const result = bindings ? statement.run(bindings) : statement.run();
    return {
      rowsAffected: Number(result.changes ?? 0),
      lastInsertId: Number(result.lastInsertRowid ?? 0),
    };
  }

  async select(sql, values) {
    this.statementLog.push(sql);
    const bindings = bindingsFor(sql, values);
    const statement = this.raw.prepare(sql);
    const rows = bindings ? statement.all(bindings) : statement.all();
    // node:sqlite hands back null-prototype objects. Real rows come over IPC as
    // JSON, so anything reached with `Object.hasOwn`, spread or `in` behaves
    // differently on one than the other. Normalised here so a test cannot pass
    // for a reason production does not share.
    return rows.map(row => ({ ...row }));
  }

  async close() {
    this.raw.close();
    return true;
  }
}

let current = null;

/** The database the test is currently running against. */
export function currentDatabase() {
  return current;
}

/**
 * Throw away the open database so the next `load()` builds a fresh one.
 *
 * Called between tests: `src/lib/database.ts` caches its connection in module
 * state, so without this every test would share one database and the order they
 * ran in would decide whether they passed.
 */
export function resetDatabase() {
  if (current) {
    try { current.raw.close(); } catch { /* already closed */ }
  }
  current = null;
}

export default {
  async load(path) {
    if (!current) {
      current = new FakeDatabase(':memory:');
      current.declaredPath = path;
      current.applyMigrations();
    }
    return current;
  },
};
