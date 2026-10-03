/**
 * LOCKON EWAC — keep the sidecar's wordlist directory in step with the source.
 *
 * `engine/wordlists/` is the source of truth that a plain `python -m engine.main`
 * run reads. The frozen sidecar reads `src-tauri/binaries/wordlists/` instead
 * (see engine/wordlists_path.py), so the two have to hold the same files.
 *
 * That copy was maintained by hand, and it drifted: `common-dirs.txt` was added
 * for DIRBUSTER and never copied, so `get_wordlists` in a packaged build never
 * listed it and the attack could only ever answer "Wordlist not found". This
 * runs from `predev`/`prebuild` so the drift cannot come back silently.
 *
 * Copy-only, never delete: operator-uploaded lists land in the sidecar's
 * directory (upload_wordlist writes to whatever get_wordlists_dir() resolves to)
 * and must survive a sync.
 */
import { readdirSync, readFileSync, writeFileSync, mkdirSync, existsSync, statSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const src = join(root, 'engine', 'wordlists');
const dst = join(root, 'src-tauri', 'binaries', 'wordlists');

if (!existsSync(src)) {
  console.error(`[wordlists] source directory is missing: ${src}`);
  process.exit(1);
}
mkdirSync(dst, { recursive: true });

const copied = [];
for (const name of readdirSync(src)) {
  const from = join(src, name);
  if (!statSync(from).isFile() || !name.endsWith('.txt')) continue;
  const to = join(dst, name);
  const body = readFileSync(from);
  // Compare contents, not mtimes: a fresh checkout has arbitrary timestamps.
  if (existsSync(to) && readFileSync(to).equals(body)) continue;
  writeFileSync(to, body);
  copied.push(name);
}

/*
  A wordlist removed from `engine/wordlists/` is named, not silently kept.

  This copies and never deletes, which is the safe default -- but the Inno installer's
  `[Files]` section installs `src-tauri/binaries/wordlists` wholesale, so a list deleted
  from the source directory went on shipping to every operator from a stale copy nobody
  was looking at. For a directory that holds credential and password lists, "still
  shipping" is a decision somebody should make on purpose.

  Reported rather than deleted: this runs from `predev` and `prebuild`, and a build step
  that removes files without being asked is the wrong kind of helpful. `--prune` does
  the removal when that is what is wanted.
*/
const PRUNE = process.argv.includes('--prune');
const stale = readdirSync(dst)
  .filter(name => name.endsWith('.txt') && !existsSync(join(src, name)));
if (stale.length) {
  if (PRUNE) {
    for (const name of stale) rmSync(join(dst, name));
    console.log(`[wordlists] pruned ${stale.length} stale file(s): ${stale.join(', ')}`);
  } else {
    console.warn(
      `[wordlists] ${stale.length} file(s) in the sidecar are no longer in `
      + `engine/wordlists and will still ship: ${stale.join(', ')}
`
      + '[wordlists] run `npm run sync:wordlists -- --prune` to remove them.',
    );
  }
}

console.log(copied.length
  ? `[wordlists] synced ${copied.length} file(s) to the sidecar: ${copied.join(', ')}`
  : '[wordlists] sidecar already in step with engine/wordlists');
