/**
 * LOCKON EWAC — Credential vault cryptography
 *
 * Recovered passwords were stored in cleartext in the SQLite file. The PDF
 * masked them by default, which protected the report but not the database: a
 * laptop that left the engagement carried every credential the audit recovered
 * in a file anyone could open with `sqlite3`.
 *
 * Scheme: AES-256-GCM per row, key derived from an operator passphrase with
 * PBKDF2-HMAC-SHA256. GCM is used because a credential store needs integrity as
 * much as secrecy — a tampered ciphertext must fail loudly rather than decrypt
 * to a different password that then gets reported as recovered.
 *
 * What this does and does not protect:
 *
 *   - Protects a stolen or leaked `.db` file, a copied backup, and anything that
 *     reads the file while the vault is locked.
 *   - Does NOT protect against something reading this process's memory while the
 *     vault is unlocked. The key lives in memory for exactly that window, which
 *     is why `lockVault()` exists and why it is called on an explicit lock.
 *
 * The key is never written anywhere. There is no recovery path: a forgotten
 * passphrase means the credentials are gone, which is the correct trade for a
 * store whose whole purpose is to be unreadable without the operator.
 */

/** Iterations for PBKDF2-HMAC-SHA256. OWASP's floor for this KDF is 600k. */
export const PBKDF2_ITERATIONS = 600_000;
export const KDF_NAME = 'PBKDF2-SHA256';

const SALT_BYTES = 16;
/** GCM nonce. 96 bits is the size the mode is defined for. */
const IV_BYTES = 12;

/**
 * Encrypted under the derived key when a vault is created and checked on unlock.
 *
 * Without it a wrong passphrase produces an authentication failure on the first
 * credential the operator happens to open, and the honest reading of that is
 * ambiguous: mistyped passphrase, or a corrupted row? The verifier makes "wrong
 * passphrase" a distinguishable answer.
 */
const VERIFIER_PLAINTEXT = 'LOCKON-EWAC-VAULT-v1';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Thrown when an operation needs the key and the vault is locked. */
export class VaultLockedError extends Error {
  constructor(message = 'The credential vault is locked.') {
    super(message);
    this.name = 'VaultLockedError';
  }
}

/** Thrown when the supplied passphrase does not match the stored verifier. */
export class WrongPassphraseError extends Error {
  constructor(message = 'That passphrase does not match this vault.') {
    super(message);
    this.name = 'WrongPassphraseError';
  }
}

export interface VaultParams {
  kdf: string;
  iterations: number;
  /** base64 */
  salt: string;
  /** base64 */
  verifier_cipher: string;
  /** base64 */
  verifier_iv: string;
}

export interface SealedSecret {
  /** base64(ciphertext || tag) */
  cipher: string;
  /** base64 nonce */
  iv: string;
}

// ── base64 ──────────────────────────────────────────────────────────────────

export function toBase64(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) out += String.fromCharCode(bytes[i]);
  return btoa(out);
}

export function fromBase64(value: string): Uint8Array {
  const raw = atob(value);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

// ── Session key ─────────────────────────────────────────────────────────────

/**
 * The derived key, held only in memory.
 *
 * Module-level rather than in a store because the persisted stores serialise to
 * localStorage, and a key that can be serialised is a key that ends up on disk.
 */
let sessionKey: CryptoKey | null = null;
const listeners = new Set<(unlocked: boolean) => void>();

function announce() {
  for (const fn of listeners) fn(sessionKey !== null);
}

/** Subscribe to lock/unlock, so the UI never shows a stale padlock. */
export function onVaultLockChange(fn: (unlocked: boolean) => void): () => void {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

export function isUnlocked(): boolean {
  return sessionKey !== null;
}

export function lockVault(): void {
  sessionKey = null;
  announce();
}

function requireKey(): CryptoKey {
  if (!sessionKey) throw new VaultLockedError();
  return sessionKey;
}

// ── Key derivation ──────────────────────────────────────────────────────────

function subtle(): SubtleCrypto {
  // A non-secure context has no crypto.subtle. Tauri's webview is a secure
  // context, so this is a clear failure rather than a case to work around.
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error(
      'Web Crypto is unavailable, so the vault cannot be encrypted. This build '
      + 'is not running in a secure context.'
    );
  }
  return crypto.subtle;
}

async function deriveKey(
  passphrase: string, salt: Uint8Array, iterations: number
): Promise<CryptoKey> {
  const base = await subtle().importKey(
    'raw', encoder.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return subtle().deriveKey(
    { name: 'PBKDF2', salt: salt as unknown as BufferSource, iterations, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    // Not extractable: nothing in the app has a reason to read the key back, and
    // a key that cannot be exported cannot be exported by accident either.
    false,
    ['encrypt', 'decrypt']
  );
}

async function sealWith(key: CryptoKey, plaintext: string): Promise<SealedSecret> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const cipher = await subtle().encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    key,
    encoder.encode(plaintext)
  );
  return { cipher: toBase64(new Uint8Array(cipher)), iv: toBase64(iv) };
}

async function openWith(key: CryptoKey, sealed: SealedSecret): Promise<string> {
  const plain = await subtle().decrypt(
    { name: 'AES-GCM', iv: fromBase64(sealed.iv) as unknown as BufferSource },
    key,
    fromBase64(sealed.cipher) as unknown as BufferSource
  );
  return decoder.decode(plain);
}

// ── Vault lifecycle ─────────────────────────────────────────────────────────

/**
 * Derive the parameters for a brand-new vault. Does not touch the database —
 * the caller persists these and then the vault is usable.
 *
 * The key is left unlocked on success, because the operator just proved they
 * know the passphrase by choosing it.
 */
export async function createVaultParams(passphrase: string): Promise<VaultParams> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const key = await deriveKey(passphrase, salt, PBKDF2_ITERATIONS);
  const verifier = await sealWith(key, VERIFIER_PLAINTEXT);
  sessionKey = key;
  announce();
  return {
    kdf: KDF_NAME,
    iterations: PBKDF2_ITERATIONS,
    salt: toBase64(salt),
    verifier_cipher: verifier.cipher,
    verifier_iv: verifier.iv,
  };
}

/**
 * Derive the key for an existing vault and check it against the verifier.
 *
 * Throws WrongPassphraseError on a mismatch so the caller can say so plainly.
 * The KDF cost comes from the stored parameters, not from the constant above,
 * so raising PBKDF2_ITERATIONS later cannot lock the operator out of a vault
 * created under the old cost.
 */
export async function unlockVault(passphrase: string, params: VaultParams): Promise<void> {
  const key = await deriveKey(
    passphrase, fromBase64(params.salt), params.iterations || PBKDF2_ITERATIONS
  );
  let verified: string;
  try {
    verified = await openWith(key, {
      cipher: params.verifier_cipher, iv: params.verifier_iv,
    });
  } catch {
    // GCM authentication failed: the key is wrong.
    throw new WrongPassphraseError();
  }
  if (verified !== VERIFIER_PLAINTEXT) throw new WrongPassphraseError();
  sessionKey = key;
  announce();
}

// ── Per-secret operations ───────────────────────────────────────────────────

export async function sealSecret(plaintext: string): Promise<SealedSecret> {
  return sealWith(requireKey(), plaintext);
}

export async function openSecret(sealed: SealedSecret): Promise<string> {
  return openWith(requireKey(), sealed);
}
