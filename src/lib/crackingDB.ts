/**
 * LOCKON EWAC — Cracking History Database Access Layer
 *
 * A recovered WPA passphrase is a credential, and it lives behind the same
 * vault as everything in `credentials`.
 *
 * It did not. `cracked_password` was written in cleartext, displayed in the
 * Decryptor's history table, and untouched by sealing the vault — so the
 * vault's own banner ("no unprotected rows") was true of one table and false of
 * the database. An operator could set a passphrase, seal the vault, watch the
 * banner go green, and carry a laptop off the engagement with every cracked
 * passphrase still readable by `strings ewac.db`. That is the exact scenario
 * migration 012's header says it exists to prevent; this closes the second half
 * of it (migration 017).
 */
import { getDb as getDB, reclaimFreePages } from './database';
import { sealSecret, openSecret, isUnlocked, VaultLockedError } from './vaultCrypto';

/** AES-256-GCM, matching `credentials.enc_version` so one meaning applies. */
export const ENC_VERSION_AES_GCM = 1;

export interface CrackingRecord {
  id: number;
  pcap_file: string;
  ssid: string | null;
  bssid: string | null;
  encryption: string | null;
  wordlist: string;
  mangling_keywords: string | null;
  result: 'SUCCESS' | 'FAILED' | 'ABORTED';
  /**
   * Cleartext, and only ever set on a row written before migration 017.
   *
   * A reader wanting the passphrase calls `revealCrackedPassword`, which
   * returns null while the vault is locked rather than an empty string — the
   * two mean different things and the history table prints them differently.
   */
  cracked_password: string | null;
  password_cipher?: string | null;
  password_iv?: string | null;
  /** 0 = cleartext in `cracked_password`; 1 = sealed. */
  enc_version?: number;
  passwords_tested: number;
  passwords_total: number;
  duration_seconds: number;
  created_at: string;
  /**
   * 1 only if the run did not come from real hashcat output. The page used to
   * write fabricated BSSIDs and hash rates here from a mock cracker; nothing
   * should reach this table now unless hashcat actually produced it.
   */
  is_simulated?: number;
}

export async function saveCrackingRecord(
  record: Omit<CrackingRecord, 'id' | 'created_at'>
): Promise<number> {
  const conn = await getDB();
  const secret = record.cracked_password;
  const hasSecret = typeof secret === 'string' && secret.length > 0;

  /*
    The vault is required only when there is something to protect.

    A FAILED or ABORTED run carries no passphrase, and refusing to record it
    would lose the most useful negative result the tool produces — "this
    wordlist was exhausted against this handshake and did not crack it" is a
    finding. A SUCCESS is different: there is no cleartext fallback, for the
    same reason `saveCredential` has none. Storing it unprotected "just this
    once" is the behaviour the vault was built to remove.
  */
  if (hasSecret && !isUnlocked()) {
    throw new VaultLockedError(
      'The credential vault is locked, so the recovered passphrase was not stored. '
      + 'Unlock the vault and record this run again.'
    );
  }

  const sealed = hasSecret ? await sealSecret(secret as string) : null;

  const result = await conn.execute(
    `INSERT INTO cracking_history
      (pcap_file, ssid, bssid, encryption, wordlist, mangling_keywords, result,
       cracked_password, password_cipher, password_iv, enc_version,
       passwords_tested, passwords_total, duration_seconds, is_simulated)
     VALUES ($1, $2, $3, $4, $5, $6, $7, NULL, $8, $9, $10, $11, $12, $13, $14)`,
    [
      record.pcap_file,
      record.ssid,
      record.bssid,
      record.encryption,
      record.wordlist,
      record.mangling_keywords,
      record.result,
      sealed?.cipher ?? null,
      sealed?.iv ?? null,
      // A run with no passphrase is marked sealed: there is nothing
      // unprotected about it, and counting it would make the vault banner
      // permanently alarming for the normal case.
      ENC_VERSION_AES_GCM,
      record.passwords_tested,
      record.passwords_total,
      record.duration_seconds,
      record.is_simulated ? 1 : 0
    ]
  );
  return result.lastInsertId as number;
}

export async function getCrackingHistory(limit = 20): Promise<CrackingRecord[]> {
  const conn = await getDB();
  return await conn.select<CrackingRecord[]>(
    'SELECT * FROM cracking_history ORDER BY created_at DESC LIMIT $1',
    [limit]
  );
}

/**
 * The passphrase for one run, decrypted — or null.
 *
 * Null covers three different situations and the caller must not collapse
 * them: the run recovered nothing, the vault is locked, or the ciphertext
 * failed to open. `reason` says which, because "no password was found" and
 * "the vault is locked" are opposite statements about the same network and the
 * history table has to print them differently.
 */
export async function revealCrackedPassword(
  record: Pick<CrackingRecord, 'cracked_password' | 'password_cipher' | 'password_iv' | 'enc_version'>
): Promise<{ password: string | null; reason: 'ok' | 'none' | 'locked' | 'undecryptable' }> {
  // A row written before migration 017 still holds its cleartext.
  if (record.enc_version === 0) {
    return record.cracked_password
      ? { password: record.cracked_password, reason: 'ok' }
      : { password: null, reason: 'none' };
  }
  if (!record.password_cipher || !record.password_iv) {
    return { password: null, reason: 'none' };
  }
  if (!isUnlocked()) {
    return { password: null, reason: 'locked' };
  }
  try {
    return {
      password: await openSecret({ cipher: record.password_cipher, iv: record.password_iv }),
      reason: 'ok',
    };
  } catch {
    // Authentication failure means the stored bytes are not what this key
    // sealed. Reported, never rendered as an empty password.
    return { password: null, reason: 'undecryptable' };
  }
}

/** How many cracking runs still hold a passphrase in cleartext on disk. */
export async function countUnprotectedCrackedPasswords(): Promise<number> {
  const conn = await getDB();
  const rows = await conn.select<{ n: number }[]>(
    `SELECT COUNT(*) AS n FROM cracking_history
      WHERE enc_version = 0 AND cracked_password IS NOT NULL AND cracked_password <> ''`
  );
  return rows[0]?.n ?? 0;
}

/**
 * Encrypt every cracking run still holding a cleartext passphrase.
 *
 * The counterpart to `sealLegacyCredentials`, and it follows the same order:
 * write the ciphertext for a row before clearing its cleartext, so an
 * interruption leaves a readable passphrase rather than losing one. Returns how
 * many were sealed.
 *
 * Runs a VACUUM afterwards when anything was sealed. Nulling the column is not
 * erasing it — SQLite leaves freed pages with their contents intact — and a
 * banner that says "protected" while the bytes are still in the file is the
 * defect this whole mechanism exists to prevent.
 */
export async function sealLegacyCrackingHistory(): Promise<number> {
  if (!isUnlocked()) throw new VaultLockedError('Unlock the vault before sealing it.');
  const conn = await getDB();
  const legacy = await conn.select<{ id: number; cracked_password: string | null }[]>(
    'SELECT id, cracked_password FROM cracking_history WHERE enc_version = 0'
  );

  let sealedCount = 0;
  for (const row of legacy) {
    if (!row.cracked_password) {
      // Nothing to protect; mark it so it stops being counted as unprotected.
      await conn.execute(
        'UPDATE cracking_history SET enc_version = $1 WHERE id = $2',
        [ENC_VERSION_AES_GCM, row.id]
      );
      continue;
    }
    const sealed = await sealSecret(row.cracked_password);
    await conn.execute(
      `UPDATE cracking_history
          SET password_cipher = $1, password_iv = $2, enc_version = $3, cracked_password = NULL
        WHERE id = $4`,
      [sealed.cipher, sealed.iv, ENC_VERSION_AES_GCM, row.id]
    );
    sealedCount += 1;
  }

  if (sealedCount > 0) await reclaimFreePages();
  return sealedCount;
}

export async function deleteCrackingRecord(id: number): Promise<void> {
  const conn = await getDB();
  await conn.execute('DELETE FROM cracking_history WHERE id = $1', [id]);
  /*
    The row is gone from the index; its bytes are not gone from the file.

    `secure_delete` is off by default and is per-connection on a pool, so a
    deleted row's ciphertext — and, for a legacy row, its cleartext passphrase —
    stays in the freed pages until something rewrites the file. Deleting a
    cracked passphrase is precisely the moment an operator expects it to be
    gone, so the reclaim happens here rather than at some later convenience.
  */
  await reclaimFreePages();
}
