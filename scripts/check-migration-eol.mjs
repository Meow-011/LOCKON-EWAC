#!/usr/bin/env node
/**
 * Migration files must be LF, and every migration file must be registered.
 *
 *     npm run check:migrations
 *
 * Why this exists.
 *
 * A user's installed app refused to start with:
 *
 *     failed to initialize plugin `sql`: migration 1 was previously applied
 *     but has been modified
 *
 * Migration 1 had not been modified. It has one commit in its entire history.
 * What differed was its line endings: `lib.rs` embeds each migration with
 * `include_str!`, which copies the working tree's bytes verbatim; sqlx hashes
 * that text with SHA-384 to decide whether a migration changed since it was
 * applied; and with `core.autocrlf=true` -- the Windows default -- git stores
 * these files as LF and checks them out as CRLF. So the same commit produced one
 * checksum on CI and a different one on a Windows checkout, and a database
 * created by either build was rejected by the other.
 *
 * That is a defect with no symptom until a release reaches someone, and it
 * cannot be caught by a test that reads the file through a text API, because
 * every text API hides exactly the bytes that matter. So this reads them as
 * bytes.
 *
 * `.gitattributes` pins `*.sql` to LF, which governs a fresh checkout. It does
 * not convert a file already sitting in a working tree with CRLF, and it does
 * nothing for an editor configured to write CRLF. This check does not care how
 * the bytes got there.
 *
 * The second rule is unrelated in mechanism and identical in consequence: a
 * migration file that is never registered in `lib.rs` is a schema change that
 * silently does not happen. The numbers also have to be contiguous and unique --
 * a database records a migration by its *number*, so two different migrations
 * sharing one number cannot both be applied, and the second installation to meet
 * it gets the same unexplainable startup failure. That is not hypothetical: the
 * failure above turned out to sit on a database whose migrations 8 and 9 were
 * `raw_gps` and `bluetooth_schema`, from an older line of this project, against
 * a build whose 8 and 9 are different migrations entirely.
 */
import { readFileSync, readdirSync } from 'node:fs';

const DIR = 'src-tauri/migrations';
const LIB = 'src-tauri/src/lib.rs';
const problems = [];

const files = readdirSync(DIR).filter(f => f.endsWith('.sql')).sort();
if (files.length === 0) problems.push(`${DIR} contains no .sql files — is the path right?`);

// ── 1. Bytes ───────────────────────────────────────────────────────────────
// Read as a Buffer, deliberately. Every text read in Node normalises nothing but
// also reveals nothing: '\r\n' survives as characters, but a single CR that an
// editor left behind is just as invisible to a line-based diff as it is to a
// reviewer. The checksum sees all of it.
for (const f of files) {
  const buf = readFileSync(`${DIR}/${f}`);
  const crlf = buf.indexOf('\r\n') !== -1;
  // A lone CR (old Mac line ending, or a half-converted file) is equally fatal
  // and far harder to spot by eye.
  let loneCr = false;
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0x0d && buf[i + 1] !== 0x0a) { loneCr = true; break; }
  }
  if (crlf) problems.push(`${f} has CRLF line endings — its checksum will not match a build made from a LF checkout`);
  else if (loneCr) problems.push(`${f} contains a bare CR`);
}

// ── 2. Registration ────────────────────────────────────────────────────────
const lib = readFileSync(LIB, 'utf8');
const seen = new Map();
for (const f of files) {
  const n = Number(f.slice(0, 3));
  if (!Number.isInteger(n)) { problems.push(`${f} does not start with a three-digit number`); continue; }
  if (seen.has(n)) problems.push(`migrations ${seen.get(n)} and ${f} share version ${n} — a database records a migration by its number, so only one of them can ever be applied`);
  else seen.set(n, f);
  // The path as `include_str!` writes it. Matching on the filename alone would
  // pass for a file merely mentioned in a comment.
  if (!lib.includes(`include_str!("../migrations/${f}")`)) {
    problems.push(`${f} is not registered in ${LIB} — it will never run`);
  }
}

const numbers = [...seen.keys()].sort((a, b) => a - b);
for (let i = 0; i < numbers.length; i++) {
  if (numbers[i] !== i + 1) {
    problems.push(`migration numbering jumps from ${numbers[i - 1] ?? '(start)'} to ${numbers[i]} — sqlx applies them in order and a gap usually means a file was renamed or lost`);
    break;
  }
}

// A migration registered in lib.rs whose file is gone fails to compile, so that
// direction needs no check here; `cargo check` is the stricter test.

if (problems.length > 0) {
  console.error('[migrations] FAIL');
  for (const p of problems) console.error(`  - ${p}`);
  console.error('\n  CRLF can be fixed in place; .gitattributes keeps it fixed for the next checkout.');
  process.exit(1);
}

console.log(`[migrations] ${files.length} files, all LF, all registered, numbered 1..${numbers.length}`);
console.log('[migrations] PASS');
