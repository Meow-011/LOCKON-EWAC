/**
 * Tests for the credential vault's cryptography.
 *
 *     npm run test:vault
 *
 * The vault exists because recovered passwords were stored in cleartext in the
 * SQLite file: the PDF masked them, but a laptop that left the engagement
 * carried every credential the audit recovered in a file anyone could open.
 *
 * These tests lock the properties that make the replacement worth trusting. Each
 * one is here because getting it wrong fails quietly rather than loudly:
 *
 *   - **A wrong passphrase must be distinguishable from a corrupted row.** Without
 *     the verifier, mistyping produces an authentication failure on whichever
 *     credential the operator happens to open first, and the honest reading of
 *     that is ambiguous.
 *   - **A tampered ciphertext must fail, not decrypt.** A credential store needs
 *     integrity as much as secrecy: silently returning a different password than
 *     the one recovered would put a false credential in a report.
 *   - **Nonces must never repeat.** AES-GCM loses its integrity guarantee
 *     entirely if a nonce is reused under the same key, and nonce reuse is
 *     invisible in testing unless something checks for it.
 *   - **Locking must actually drop the key.** A padlock that shows locked while
 *     the key is still in memory protects nothing.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  PBKDF2_ITERATIONS,
  KDF_NAME,
  createVaultParams,
  unlockVault,
  lockVault,
  isUnlocked,
  sealSecret,
  openSecret,
  toBase64,
  fromBase64,
  onVaultLockChange,
  VaultLockedError,
  WrongPassphraseError,
  revealArchivedCredentials,
} from '../.test-build/vault.mjs';

const PASSPHRASE = 'correct horse battery staple';

/** Every test starts from a locked, keyless state. */
function reset() {
  lockVault();
}

test('a secret round-trips through seal and open', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const secret = 'Tr0ub4dor&3';
  const sealed = await sealSecret(secret);
  assert.notEqual(sealed.cipher, secret, 'ciphertext must not contain the plaintext');
  assert.equal(await openSecret(sealed), secret);
});

test('a vault can be unlocked with the passphrase that created it', async () => {
  reset();
  const params = await createVaultParams(PASSPHRASE);
  const sealed = await sealSecret('admin123');
  lockVault();
  assert.equal(isUnlocked(), false);
  await unlockVault(PASSPHRASE, params);
  assert.equal(await openSecret(sealed), 'admin123');
});

test('a wrong passphrase is reported as wrong, not as a corrupt vault', async () => {
  reset();
  const params = await createVaultParams(PASSPHRASE);
  lockVault();
  await assert.rejects(
    () => unlockVault('not the passphrase', params),
    (err) => err instanceof WrongPassphraseError
  );
  // A failed unlock must not leave the vault half-open.
  assert.equal(isUnlocked(), false);
});

test('a locked vault refuses to seal or open rather than returning nothing', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const sealed = await sealSecret('secret');
  lockVault();
  await assert.rejects(() => sealSecret('another'), (e) => e instanceof VaultLockedError);
  await assert.rejects(() => openSecret(sealed), (e) => e instanceof VaultLockedError);
});

test('a tampered ciphertext fails authentication instead of decrypting', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const sealed = await sealSecret('P@ssw0rd!');
  const bytes = fromBase64(sealed.cipher);
  bytes[0] ^= 0xff;             // flip a byte of ciphertext
  await assert.rejects(() => openSecret({ cipher: toBase64(bytes), iv: sealed.iv }));
});

test('a tampered nonce fails authentication', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const sealed = await sealSecret('P@ssw0rd!');
  const iv = fromBase64(sealed.iv);
  iv[0] ^= 0xff;
  await assert.rejects(() => openSecret({ cipher: sealed.cipher, iv: toBase64(iv) }));
});

test('every secret gets a fresh nonce', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const seen = new Set();
  for (let i = 0; i < 200; i += 1) {
    // The same plaintext every time: identical input must not produce identical
    // output, or the vault leaks which accounts share a password.
    const sealed = await sealSecret('same password');
    assert.equal(seen.has(sealed.iv), false, 'nonce reused under one key');
    seen.add(sealed.iv);
  }
  assert.equal(seen.size, 200);
});

test('the same plaintext encrypts to different ciphertext each time', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const a = await sealSecret('shared-password');
  const b = await sealSecret('shared-password');
  assert.notEqual(a.cipher, b.cipher);
});

test('two vaults built from the same passphrase get different salts', async () => {
  reset();
  const first = await createVaultParams(PASSPHRASE);
  const second = await createVaultParams(PASSPHRASE);
  assert.notEqual(first.salt, second.salt, 'salt must be random per vault');
  assert.notEqual(first.verifier_cipher, second.verifier_cipher);
});

test('a secret sealed by one vault cannot be opened by another', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const sealed = await sealSecret('leak me');
  const other = await createVaultParams(PASSPHRASE);   // different salt
  lockVault();
  await unlockVault(PASSPHRASE, other);
  await assert.rejects(() => openSecret(sealed));
});

test('the stored iteration count is what unlock uses', async () => {
  reset();
  const params = await createVaultParams(PASSPHRASE);
  assert.equal(params.iterations, PBKDF2_ITERATIONS);
  assert.equal(params.kdf, KDF_NAME);
  lockVault();
  // Raising the constant later must not lock the operator out of an existing
  // vault, so unlock has to honour the parameters stored with it.
  await unlockVault(PASSPHRASE, { ...params, iterations: params.iterations });
  assert.equal(isUnlocked(), true);
  // A different cost derives a different key, which the verifier must catch.
  lockVault();
  await assert.rejects(
    () => unlockVault(PASSPHRASE, { ...params, iterations: 1000 }),
    (e) => e instanceof WrongPassphraseError
  );
});

test('the KDF cost is not weakened below the current guidance', () => {
  assert.ok(
    PBKDF2_ITERATIONS >= 600_000,
    `PBKDF2 iterations dropped to ${PBKDF2_ITERATIONS}; OWASP's floor for SHA-256 is 600k`
  );
});

test('non-ASCII passphrases and passwords survive the round trip', async () => {
  reset();
  const thai = 'รหัสผ่านที่ปลอดภัยมาก';
  const params = await createVaultParams(thai);
  const secret = 'ผ่าน-123-🔐';
  const sealed = await sealSecret(secret);
  lockVault();
  await unlockVault(thai, params);
  assert.equal(await openSecret(sealed), secret);
});

test('an empty password is preserved as empty, not lost', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  // Blank service passwords are a real finding; the vault must store one
  // faithfully rather than turning it into "no password recorded".
  const sealed = await sealSecret('');
  assert.equal(await openSecret(sealed), '');
});

test('a long password is not truncated', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const long = 'x'.repeat(4096);
  assert.equal(await openSecret(await sealSecret(long)), long);
});

test('locking drops the key and subscribers are told', async () => {
  reset();
  const seen = [];
  const stop = onVaultLockChange((unlocked) => seen.push(unlocked));
  await createVaultParams(PASSPHRASE);
  assert.equal(isUnlocked(), true);
  lockVault();
  assert.equal(isUnlocked(), false);
  stop();
  assert.deepEqual(seen, [true, false]);
  // After unsubscribing, no further notifications.
  lockVault();
  assert.deepEqual(seen, [true, false]);
});

test('base64 helpers round-trip arbitrary bytes', () => {
  const bytes = new Uint8Array(256);
  for (let i = 0; i < 256; i += 1) bytes[i] = i;
  assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
});

// ── Report snapshots ────────────────────────────────────────────────────────
//
// A report archive is stored as JSON in the same SQLite file as the vault.
// Archiving used to call getAllCredentials(), which decrypts, and wrote the
// result straight into `intel_reports.raw_data` — putting every recovered
// password back on disk in cleartext and undoing the encryption completely.
// Snapshots now carry the ciphertext, and these tests cover the read side.

/** A snapshot row as the archive stores it: sealed, with metadata in the clear. */
function archivedRow(sealed, extra = {}) {
  return {
    id: 7,
    target_ip: '10.0.0.5',
    port: 22,
    service: 'ssh',
    username: 'root',
    password: null,
    password_cipher: sealed.cipher,
    password_iv: sealed.iv,
    enc_version: 1,
    source: 'bruteforce',
    session_id: 'S-1',
    hostname: 'fileserver',
    notes: null,
    discovered_at: '2026-09-27 10:00:00',
    ...extra,
  };
}

test('an archived credential is readable when the vault is unlocked', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const sealed = await sealSecret('toor');
  const [revealed] = await revealArchivedCredentials([archivedRow(sealed)]);
  assert.equal(revealed.password, 'toor');
  assert.equal(revealed.locked, false);
  assert.equal(revealed.username, 'root');
  assert.equal(revealed.hostname, 'fileserver');
});

test('an archived credential stays withheld while the vault is locked', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const row = archivedRow(await sealSecret('toor'));
  lockVault();
  const [revealed] = await revealArchivedCredentials([row]);
  // null, not '' — the report must not render this as an empty password.
  assert.equal(revealed.password, null);
  assert.equal(revealed.locked, true);
  // The finding itself survives: the account and host are still reportable.
  assert.equal(revealed.username, 'root');
  assert.equal(revealed.target_ip, '10.0.0.5');
});

test('an archive sealed under another vault reports failure, not a password', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const row = archivedRow(await sealSecret('toor'));
  // A report imported from another machine: different salt, different key.
  await createVaultParams(PASSPHRASE);
  const [revealed] = await revealArchivedCredentials([row]);
  assert.equal(revealed.password, null);
  assert.ok(revealed.decrypt_error, 'the failure must be reported, not swallowed');
});

test('an archive written before encryption existed still exports', async () => {
  reset();
  // No enc_version and a cleartext password: treating a missing field as
  // "encrypted" would make every historical report unreadable.
  const legacy = {
    id: 1, target_ip: '10.0.0.9', port: 21, service: 'ftp', username: 'admin',
    password: 'admin', source: 'default_check', discovered_at: '2026-01-01 00:00:00',
  };
  const [revealed] = await revealArchivedCredentials([legacy]);
  assert.equal(revealed.password, 'admin');
  assert.equal(revealed.enc_version, 0, 'must be reported as cleartext on disk');
  assert.equal(revealed.locked, false);
});

test('one unreadable row does not take the rest of the archive down', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const good = archivedRow(await sealSecret('good-one'), { id: 1 });
  const broken = archivedRow(await sealSecret('bad-one'), { id: 2 });
  const bytes = fromBase64(broken.password_cipher);
  bytes[0] ^= 0xff;
  broken.password_cipher = toBase64(bytes);
  const out = await revealArchivedCredentials([good, broken]);
  assert.equal(out.length, 2);
  assert.equal(out[0].password, 'good-one');
  assert.equal(out[1].password, null);
  assert.ok(out[1].decrypt_error);
});

test('an empty archived password survives as empty, not as withheld', async () => {
  reset();
  await createVaultParams(PASSPHRASE);
  const row = archivedRow(await sealSecret(''));
  const [revealed] = await revealArchivedCredentials([row]);
  // A blank service password is a real finding. It must not become null, which
  // the report renders as "vault locked".
  assert.equal(revealed.password, '');
  assert.equal(revealed.locked, false);
});

test('an empty archive list is handled', async () => {
  reset();
  assert.deepEqual(await revealArchivedCredentials([]), []);
});
