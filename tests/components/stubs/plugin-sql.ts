/**
 * The Tauri SQL plugin, for component tests.
 *
 * Modelled on `tests/stubs/plugin-sql.mjs` and for the same reason: a component test
 * that silently succeeds against a fake database proves nothing about the queries, and
 * the database suites already cover those against real SQLite with the real migrations.
 *
 * So this records what was asked and answers from a script the test sets up. A query
 * nobody scripted throws, rather than returning `[]` — because `[]` is a *result* in
 * this application ("no shares", "no credentials", "no findings"), and a stub that
 * hands one back would let a test pass while asserting on a fabricated clean answer.
 * That is the exact defect class this project keeps finding.
 */
type Row = Record<string, unknown>;

interface Scripted {
  /** Matched against the SQL with `includes`, first match wins. */
  match: string;
  rows?: Row[];
  /** For `execute`. */
  result?: { rowsAffected: number; lastInsertId?: number };
  throws?: string;
}

const script: Scripted[] = [];
export const sqlCalls: { kind: 'select' | 'execute'; sql: string; args: unknown[] }[] = [];

/** Script a response. Call from a test before rendering. */
export function whenSql(entry: Scripted) {
  script.push(entry);
}

export function resetSqlStub() {
  script.length = 0;
  sqlCalls.length = 0;
}

function answer(kind: 'select' | 'execute', sql: string, args: unknown[]) {
  sqlCalls.push({ kind, sql, args });
  const hit = script.find(s => sql.includes(s.match));
  if (!hit) {
    throw new Error(
      `plugin-sql stub: nothing scripted for this ${kind}:\n  ${sql.trim().slice(0, 160)}\n`
      + 'Script it with `whenSql({ match, rows })`. An unscripted query must not return '
      + 'an empty result, because an empty result is a finding in this application.',
    );
  }
  if (hit.throws) throw new Error(hit.throws);
  return kind === 'select'
    ? (hit.rows ?? [])
    : (hit.result ?? { rowsAffected: 0 });
}

class FakeDatabase {
  async select<T>(sql: string, args: unknown[] = []): Promise<T> {
    return answer('select', sql, args) as T;
  }

  async execute(sql: string, args: unknown[] = []) {
    return answer('execute', sql, args) as { rowsAffected: number };
  }

  async close() {
    return true;
  }
}

export default {
  async load(_path: string) {
    return new FakeDatabase();
  },
};
