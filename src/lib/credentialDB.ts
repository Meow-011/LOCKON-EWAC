/**
 * LOCKON EWAC — Credential Vault Database Layer
 *
 * Secrets are encrypted at rest (AES-256-GCM, key from an operator passphrase —
 * see vaultCrypto.ts). Three rules this layer exists to keep:
 *
 *   1. **A locked vault returns `password: null`, never a guess and never a
 *      blank that reads like an empty password.** `locked` says why, so the UI
 *      and the report can state it instead of showing nothing and letting the
 *      reader assume the vault was empty.
 *   2. **Writing requires the vault to be unlocked.** A discovered credential is
 *      never silently written in the clear as a fallback — that is the defect
 *      this replaced. It throws, and the caller tells the operator the
 *      credential was not stored.
 *   3. **Rows written before encryption existed are reported, not hidden.**
 *      `enc_version = 0` means cleartext on disk. The vault counts them and
 *      offers to seal them; pretending the whole store is encrypted when part of
 *      it is not would be the same class of untruth as an unflagged simulation.
 */
import { getDb, reclaimFreePages } from './database';
// The other table holding a recovered secret. Imported here so one call seals
// the whole database rather than one table of it.
import {
  countUnprotectedCrackedPasswords,
  sealLegacyCrackingHistory,
} from './crackingDB';
import {
  VaultLockedError,
  createVaultParams,
  isUnlocked,
  lockVault,
  openSecret,
  sealSecret,
  unlockVault,
  type VaultParams,
} from './vaultCrypto';

export { VaultLockedError, WrongPassphraseError, lockVault, isUnlocked, onVaultLockChange } from './vaultCrypto';

/** AES-256-GCM. 0 is a legacy row whose password is still cleartext on disk. */
export const ENC_VERSION_AES_GCM = 1;

export interface StoredCredential {
  id: number;
  target_ip: string;
  port: number;
  service: string;
  username: string;
  /**
   * The recovered password, or null when it could not be produced.
   * `locked` and `decrypt_error` say which — never treat null as an empty
   * password.
   */
  password: string | null;
  /** True when the row holds a secret this session cannot read. */
  locked: boolean;
  /** Set when the ciphertext failed authentication, i.e. the row was altered. */
  decrypt_error?: string;
  /** 0 = cleartext on disk (pre-encryption row), 1 = AES-256-GCM. */
  enc_version: number;
  source: 'bruteforce' | 'default_check' | 'spray' | 'manual';
  session_id: string | null;
  hostname: string | null;
  notes: string | null;
  discovered_at: string;
}

/** Raw shape as the table stores it. */
interface CredentialRow {
  id: number;
  target_ip: string;
  port: number;
  service: string;
  username: string;
  password: string | null;
  password_cipher: string | null;
  password_iv: string | null;
  enc_version: number;
  source: StoredCredential['source'];
  session_id: string | null;
  hostname: string | null;
  notes: string | null;
  discovered_at: string;
}

export interface VaultStatus {
  /** Whether a passphrase has ever been set for this database. */
  exists: boolean;
  /** Whether this session holds the key. */
  unlocked: boolean;
  /** Total credentials stored. */
  total: number;
  /**
   * How many secrets still hold cleartext on disk (enc_version = 0), across
   * **every** table that stores one.
   *
   * This counted `credentials` alone, and `cracking_history.cracked_password`
   * holds the same kind of secret — the WPA passphrase hashcat recovered. So
   * the banner could report "no unprotected rows" while every cracked
   * passphrase sat in the file in cleartext, which is the exact claim migration
   * 012 exists to make true rather than merely display.
   */
  unprotected: number;
  /** The `credentials` half of `unprotected`. */
  unprotectedCredentials: number;
  /** The `cracking_history` half of `unprotected` (migration 017). */
  unprotectedCrackedPasswords: number;
  /** When pre-existing cleartext rows were sealed, if they have been. */
  legacySealedAt: string | null;
}

// ── Vault lifecycle ─────────────────────────────────────────────────────────

async function readParams(): Promise<VaultParams | null> {
  const db = await getDb();
  const rows = await db.select<VaultParams[]>(
    'SELECT kdf, iterations, salt, verifier_cipher, verifier_iv FROM vault_meta WHERE id = 1'
  );
  return rows[0] ?? null;
}

export async function getVaultStatus(): Promise<VaultStatus> {
  const db = await getDb();
  const params = await readParams();
  const counts = await db.select<[{ total: number; unprotected: number }]>(
    `SELECT COUNT(*) AS total,
            SUM(CASE WHEN enc_version = 0 THEN 1 ELSE 0 END) AS unprotected
       FROM credentials`
  );
  const sealed = await db.select<[{ legacy_sealed_at: string | null }]>(
    'SELECT legacy_sealed_at FROM vault_meta WHERE id = 1'
  );
  const crackedUnprotected = await countUnprotectedCrackedPasswords();
  const credentialsUnprotected = counts[0]?.unprotected ?? 0;
  return {
    exists: params !== null,
    unlocked: isUnlocked(),
    total: counts[0]?.total ?? 0,
    unprotected: credentialsUnprotected + crackedUnprotected,
    unprotectedCredentials: credentialsUnprotected,
    unprotectedCrackedPasswords: crackedUnprotected,
    legacySealedAt: sealed[0]?.legacy_sealed_at ?? null,
  };
}

/**
 * Set the vault passphrase for the first time and leave it unlocked.
 *
 * Refuses if one already exists: silently replacing the parameters would strand
 * every encrypted row with a key nothing can derive again.
 */
export async function createVault(passphrase: string): Promise<void> {
  if (!passphrase) throw new Error('A vault passphrase cannot be empty.');
  const db = await getDb();
  if (await readParams()) {
    throw new Error('This vault already has a passphrase. Unlock it instead.');
  }
  const params = await createVaultParams(passphrase);
  try {
    await db.execute(
      `INSERT INTO vault_meta (id, kdf, iterations, salt, verifier_cipher, verifier_iv)
       VALUES (1, $1, $2, $3, $4, $5)`,
      [params.kdf, params.iterations, params.salt, params.verifier_cipher, params.verifier_iv]
    );
  } catch (e) {
    // createVaultParams() already unlocked the vault with the new key. If the
    // parameters did not reach the database, that key cannot be derived again
    // next session — so anything sealed under it now would be unrecoverable.
    // Drop it and fail rather than leaving a vault that works exactly once.
    lockVault();
    throw e;
  }
}

/**
 * Show the operator a message, if there is anywhere to show it.
 *
 * A toast is a convenience and must never be able to fail the operation it is
 * describing. `window.dispatchEvent` was called bare inside `openVault`, once
 * in the try and once in the catch — so anything wrong with the dispatch turned
 * an unlock into a thrown error *through the handler written to report the
 * problem*. The vault is usable either way; losing access to the credentials
 * over an undelivered notification is not a trade worth making.
 */
function notify(message: string, type: 'warning' | 'error'): void {
  try {
    if (typeof window === 'undefined') return;
    window.dispatchEvent(new CustomEvent('lockon:toast', { detail: { message, type } }));
  } catch (err) {
    console.error('[Vault] could not surface a notice:', err, message);
  }
}

/** Derive and verify the key for this session. Throws WrongPassphraseError. */
export async function openVault(passphrase: string): Promise<void> {
  const params = await readParams();
  if (!params) throw new Error('No vault has been created on this database yet.');
  await unlockVault(passphrase, params);

  // Catch up a database that was sealed before the page reclaim existed. Done
  // here because it is the one moment the operator is present, waiting, and
  // thinking about the vault — and because it must happen before they next take
  // the laptop anywhere. `reclaimVaultPagesIfNeeded` is a no-op after the first
  // time.
  //
  // A failure does not fail the unlock: the vault is usable either way, and the
  // operator is told separately rather than being locked out of their own
  // credentials over a maintenance step.
  try {
    if (await reclaimVaultPagesIfNeeded()) {
      notify(
        'Vault storage reclaimed: cleartext left in freed database pages by an earlier '
        + 'version has been overwritten. If this database left the premises before now, '
        + 'treat the credentials in it as exposed.',
        'warning'
      );
    }
  } catch (err) {
    console.error('[Vault] page reclaim failed:', err);
    notify(
      'Vault unlocked, but the database file could not be compacted. Freed pages may '
      + 'still contain cleartext from before encryption was enabled.',
      'error'
    );
  }
}

/**
 * Encrypt every row still holding cleartext.
 *
 * Runs one row at a time and only clears `password` after the ciphertext is
 * written for that row, so an interruption leaves a readable credential rather
 * than losing it. Returns how many were sealed.
 */
export async function sealLegacyCredentials(): Promise<number> {
  if (!isUnlocked()) throw new VaultLockedError('Unlock the vault before sealing it.');
  const db = await getDb();
  const legacy = await db.select<{ id: number; password: string | null }[]>(
    'SELECT id, password FROM credentials WHERE enc_version = 0'
  );
  let sealedCount = 0;
  for (const row of legacy) {
    // An empty password is encrypted like any other, not special-cased away. A
    // blank service password is a real finding, and marking the row sealed
    // without a ciphertext would turn it into "no password recorded" — losing
    // the finding rather than protecting it. Only a genuinely absent value is
    // skipped, which the pre-encryption schema could not even produce.
    if (row.password === null) {
      await db.execute(
        'UPDATE credentials SET enc_version = $1 WHERE id = $2',
        [ENC_VERSION_AES_GCM, row.id]
      );
      continue;
    }
    const sealed = await sealSecret(row.password);
    await db.execute(
      `UPDATE credentials
          SET password_cipher = $1, password_iv = $2, enc_version = $3, password = NULL
        WHERE id = $4`,
      [sealed.cipher, sealed.iv, ENC_VERSION_AES_GCM, row.id]
    );
    sealedCount += 1;
  }
  if (legacy.length > 0) {
    await db.execute(
      "UPDATE vault_meta SET legacy_sealed_at = datetime('now') WHERE id = 1"
    );
  }

  // Nulling the column is not erasing it.
  //
  // Sealing every row and then telling the operator the vault is protected was
  // false while the cleartext was still sitting in the file's free pages —
  // measured at 300 of 300 recoverable. This is the step that makes the banner
  // true, so it runs whenever anything was sealed, and a failure here is
  // reported rather than swallowed: the operator has to know the difference
  // between "sealed" and "sealed and reclaimed" before the laptop leaves.
  // The other table that stores a recovered secret. Sealed in the same pass,
  // because an operator who clicks "seal the vault" is not choosing to protect
  // one table — and a banner that goes green while cracked passphrases stay in
  // cleartext is worse than one that never went green at all.
  const crackedSealed = await sealLegacyCrackingHistory();

  if (legacy.length > 0 || crackedSealed > 0) {
    await reclaimVaultPages();
  }

  return sealedCount + crackedSealed;
}

/**
 * Rewrite the file so the vault's freed pages no longer hold cleartext, and
 * record that it happened.
 *
 * Separate from `reclaimFreePages()` because of the installs that sealed before
 * the reclaim existed: their cleartext is still in the free pages, and there
 * are no `enc_version = 0` rows left to trigger a re-seal, so nothing would
 * ever clean them. `pages_reclaimed_at` (migration 014) is what
 * `reclaimVaultPagesIfNeeded()` keys off.
 *
 * Safe to call repeatedly; VACUUM is idempotent.
 */
export async function reclaimVaultPages(): Promise<void> {
  const db = await getDb();
  await reclaimFreePages();
  await db.execute(
    "UPDATE vault_meta SET pages_reclaimed_at = datetime('now') WHERE id = 1"
  );
}

/**
 * The one-time catch-up for a database sealed before the reclaim existed.
 *
 * Runs at most once per database. Deliberately does nothing when no vault has
 * been created: without a vault there was never a sealing step to leave
 * cleartext behind, and a VACUUM on a large survey database is not free.
 *
 * Returns true when it reclaimed, so the caller can tell the operator. This is
 * not a silent repair — the fact that the file needed cleaning is exactly what
 * an operator who already shipped a report needs to know.
 */
export async function reclaimVaultPagesIfNeeded(): Promise<boolean> {
  const db = await getDb();
  const rows = await db.select<{ legacy_sealed_at: string | null; pages_reclaimed_at: string | null }[]>(
    'SELECT legacy_sealed_at, pages_reclaimed_at FROM vault_meta WHERE id = 1'
  );
  const meta = rows[0];
  if (!meta) return false;                      // no vault on this database
  if (meta.pages_reclaimed_at) return false;    // already done
  await reclaimVaultPages();
  return true;
}

// ── Writing ─────────────────────────────────────────────────────────────────

async function insertEncrypted(
  db: Awaited<ReturnType<typeof getDb>>,
  cred: {
    target_ip: string; port: number; service: string; username: string;
    password: string; source: StoredCredential['source'];
    session_id?: string | null; hostname?: string | null; notes?: string | null;
  }
): Promise<void> {
  const sealed = await sealSecret(cred.password);
  await db.execute(
    `INSERT INTO credentials
       (target_ip, port, service, username, password, password_cipher, password_iv,
        enc_version, source, session_id, hostname, notes)
     VALUES ($1, $2, $3, $4, NULL, $5, $6, $7, $8, $9, $10, $11)`,
    [
      cred.target_ip, cred.port, cred.service, cred.username,
      sealed.cipher, sealed.iv, ENC_VERSION_AES_GCM,
      cred.source, cred.session_id ?? null, cred.hostname ?? null, cred.notes ?? null,
    ]
  );
}

/**
 * Save a discovered credential.
 *
 * Throws VaultLockedError when the vault is locked or has never been created.
 * There is deliberately no cleartext fallback: storing the secret unprotected
 * "just this once" is the behaviour this module was written to remove.
 */
export async function saveCredential(
  targetIp: string,
  port: number,
  service: string,
  username: string,
  password: string,
  source: StoredCredential['source'],
  sessionId?: string,
  hostname?: string,
  notes?: string
): Promise<void> {
  if (!isUnlocked()) {
    throw new VaultLockedError(
      'The credential vault is locked, so this credential was not stored. '
      + 'Unlock the vault and re-run to record it.'
    );
  }
  const db = await getDb();
  await insertEncrypted(db, {
    target_ip: targetIp, port, service, username, password, source,
    session_id: sessionId ?? null, hostname: hostname ?? null, notes: notes ?? null,
  });
}

/** Save several at once (from a default-credential batch). */
export async function saveCredentialBatch(
  credentials: Array<{
    target_ip: string;
    port: number;
    service: string;
    username: string;
    password: string;
    source: StoredCredential['source'];
    session_id?: string;
    hostname?: string;
  }>
): Promise<void> {
  if (!isUnlocked()) {
    throw new VaultLockedError(
      `The credential vault is locked, so ${credentials.length} credential(s) were not stored.`
    );
  }
  const db = await getDb();
  for (const cred of credentials) {
    await insertEncrypted(db, cred);
  }
}

// ── Reading ─────────────────────────────────────────────────────────────────

async function hydrate(rows: CredentialRow[]): Promise<StoredCredential[]> {
  const unlocked = isUnlocked();
  const out: StoredCredential[] = [];
  for (const row of rows) {
    const base = {
      id: row.id,
      target_ip: row.target_ip,
      port: row.port,
      service: row.service,
      username: row.username,
      enc_version: row.enc_version,
      source: row.source,
      session_id: row.session_id,
      hostname: row.hostname,
      notes: row.notes,
      discovered_at: row.discovered_at,
    };

    // A legacy row is readable with no key at all. That is the point of counting
    // them: the vault has to show what is still exposed.
    if (row.enc_version === 0) {
      out.push({ ...base, password: row.password, locked: false });
      continue;
    }
    if (!row.password_cipher || !row.password_iv) {
      // Sealed rows with no ciphertext hold nothing; say so rather than
      // reporting an empty password.
      out.push({ ...base, password: null, locked: false });
      continue;
    }
    if (!unlocked) {
      out.push({ ...base, password: null, locked: true });
      continue;
    }
    try {
      const password = await openSecret({ cipher: row.password_cipher, iv: row.password_iv });
      out.push({ ...base, password, locked: false });
    } catch (e) {
      // GCM authentication failed: the row was altered. One bad row must not
      // take the whole vault listing down with it.
      out.push({
        ...base,
        password: null,
        locked: true,
        decrypt_error: e instanceof Error ? e.message : String(e),
      });
    }
  }
  return out;
}

const SELECT_COLUMNS =
  `id, target_ip, port, service, username, password, password_cipher, password_iv,
   enc_version, source, session_id, hostname, notes, discovered_at`;

/** Retrieve all stored credentials, most recent first. */
export async function getAllCredentials(): Promise<StoredCredential[]> {
  const db = await getDb();
  const rows = await db.select<CredentialRow[]>(
    `SELECT ${SELECT_COLUMNS} FROM credentials ORDER BY discovered_at DESC`
  );
  return hydrate(rows);
}

/**
 * Credentials as the table stores them, secrets still sealed.
 *
 * This is what goes into a report snapshot. `getAllCredentials()` must never be
 * used for that: it decrypts, and the result was being written into
 * `intel_reports.raw_data` as JSON — putting every recovered password back into
 * the same database file in cleartext and undoing the encryption entirely.
 *
 * Embedding the ciphertext instead keeps a snapshot exactly as readable as the
 * vault it came from, and no more.
 */
/**
 * Credentials in the vault that belong to no session, so no archive can carry them.
 *
 * Rows written before the writers began stamping `session_id` — and any written while
 * no sweep was active — cannot be attributed to a survey. The scoped snapshot
 * therefore leaves them out, which is right: attaching an unattributable credential to
 * whichever archive shares its IP is the cross-engagement defect the scoping fixed.
 *
 * But silently omitting evidence is its own failure. The count is surfaced at archive
 * time so the operator is told that N recovered credentials exist and are not in this
 * document, rather than reading an empty section as "none were recovered".
 */
export async function countUnattributedCredentials(): Promise<number> {
  const db = await getDb();
  const rows = await db.select<{ count: number }[]>(
    'SELECT COUNT(*) as count FROM credentials WHERE session_id IS NULL',
  );
  return rows[0]?.count ?? 0;
}

export async function getCredentialsForArchive(
  sessionId: string | null | undefined,
): Promise<Record<string, unknown>[]> {
  const db = await getDb();

  /*
    Scoped to one sweep. This used to be every row in the table.

    `toHostInput` in `report/archive.ts` attaches a credential to a host on
    `target_ip === host.ip` and nothing else, so an unscoped snapshot meant any
    credential ever recovered at an address was attached to any host that later
    answered at the same address. RFC1918 gateways collide across virtually every
    engagement: `admin/admin` found on 192.168.1.1 at one client reappeared, weeks
    later, as a finding against a different client's 192.168.1.1 — scored 100,
    CRITICAL, CONFIRMED, over the words "A working credential was recovered ...
    This is demonstrated access, not a theoretical weakness." About a host nothing
    had ever been tried against.

    `session_id` and its index have been on this table since migration 005; the
    query simply never used them.

    With no session there is nothing to scope by, and an unscoped snapshot is the
    defect. Returning none is the safe failure: a report that omits a credential
    understates what was found, which is recoverable, while one that invents a
    demonstrated login about a stranger's host is not.
  */
  if (!sessionId) {
    console.warn(
      '[Vault] No session id for this archive, so no credentials were included. ' +
      'An unscoped snapshot would attach other engagements\' credentials to any ' +
      'host sharing an address.',
    );
    return [];
  }

  const rows = await db.select<CredentialRow[]>(
    `SELECT ${SELECT_COLUMNS} FROM credentials
      WHERE session_id = $1
      ORDER BY discovered_at DESC`,
    [sessionId],
  );
  return rows as unknown as Record<string, unknown>[];
}

/**
 * Decrypt credentials carried in a report snapshot, at export time.
 *
 * Tolerates archives written before encryption existed: those rows carry
 * cleartext in `password` with `enc_version` absent, and are passed through as
 * readable so an old report still exports the way it always did.
 */
export async function revealArchivedCredentials(
  entries: unknown[]
): Promise<StoredCredential[]> {
  const rows = (entries ?? []).map((raw) => {
    const e = (raw ?? {}) as Record<string, unknown>;
    return {
      id: Number(e.id ?? 0),
      target_ip: String(e.target_ip ?? ''),
      port: Number(e.port ?? 0),
      service: String(e.service ?? 'unknown'),
      username: String(e.username ?? ''),
      password: (e.password ?? null) as string | null,
      password_cipher: (e.password_cipher ?? null) as string | null,
      password_iv: (e.password_iv ?? null) as string | null,
      // An archive with no enc_version predates encryption, so its secret is
      // cleartext: treating a missing field as "encrypted" would report every
      // old report's credentials as unreadable.
      enc_version: Number(e.enc_version ?? 0),
      source: (e.source ?? 'manual') as StoredCredential['source'],
      session_id: (e.session_id ?? null) as string | null,
      hostname: (e.hostname ?? null) as string | null,
      notes: (e.notes ?? null) as string | null,
      discovered_at: String(e.discovered_at ?? ''),
    } satisfies CredentialRow;
  });
  return hydrate(rows);
}

/** Retrieve credentials for a specific target IP. */
export async function getCredentialsByTarget(targetIp: string): Promise<StoredCredential[]> {
  const db = await getDb();
  const rows = await db.select<CredentialRow[]>(
    `SELECT ${SELECT_COLUMNS} FROM credentials WHERE target_ip = $1 ORDER BY discovered_at DESC`,
    [targetIp]
  );
  return hydrate(rows);
}

/** Retrieve credentials discovered during a specific session. */
export async function getCredentialsBySession(sessionId: string): Promise<StoredCredential[]> {
  const db = await getDb();
  const rows = await db.select<CredentialRow[]>(
    `SELECT ${SELECT_COLUMNS} FROM credentials WHERE session_id = $1 ORDER BY discovered_at DESC`,
    [sessionId]
  );
  return hydrate(rows);
}

/**
 * Delete a credential by ID, and reclaim the pages it was in.
 *
 * The row leaves the index; its bytes do not leave the file. `secure_delete` is off
 * by default and is per-connection on tauri-plugin-sql's ten-connection pool, which
 * `database.ts` already records as something nothing may be built on top of. So a
 * deleted credential's ciphertext — and, for a legacy `enc_version = 0` row, its
 * cleartext password — stayed readable in the freed pages until something happened to
 * rewrite them. `strings ewac.db` was enough.
 *
 * `crackingDB.deleteCrackingRecord` does reclaim, for the same class of secret, and
 * says why: deleting a recovered password is precisely the moment an operator expects
 * it to be gone. This is the same moment.
 */
export async function deleteCredential(id: number): Promise<void> {
  const db = await getDb();
  await db.execute('DELETE FROM credentials WHERE id = $1', [id]);
  await reclaimFreePages();
}

/** Clear all credentials from the vault, and reclaim their pages. */
export async function clearAllCredentials(): Promise<void> {
  const db = await getDb();
  await db.execute('DELETE FROM credentials');
  // Especially here: this is the operator clearing the vault, which is the strongest
  // statement of intent the UI offers about wanting the secrets gone.
  await reclaimFreePages();
}

/** Get credential count for dashboard stats. Needs no key. */
export async function getCredentialCount(): Promise<number> {
  const db = await getDb();
  const result = await db.select<[{ count: number }]>(
    'SELECT COUNT(*) as count FROM credentials'
  );
  return result[0]?.count || 0;
}
