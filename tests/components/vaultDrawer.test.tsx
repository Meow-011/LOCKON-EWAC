/**
 * The credential vault, and the four different reasons a password is not shown.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * This drawer is the one surface in the application that handles recovered
 * credentials, and being wrong here is the most expensive kind of wrong available
 * to it. Its careful distinctions are all of the same family:
 *
 *   * **"the vault is locked" and "nothing was recovered" are opposite statements
 *     about the same network**, and both render as an empty password cell;
 *   * a row whose ciphertext fails to authenticate has been *altered*, which is
 *     not the same as one that was never stored;
 *   * a vault that looked uniformly encrypted while some rows were still
 *     cleartext on disk would be, in the drawer's own words, "the same kind of
 *     untruth as an unflagged simulation".
 *
 * None of that had a test. The component is 614 lines of state and this file does
 * not try to cover it; it covers the claims, which is where the harm is.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';

import { VaultDrawer } from '../../src/components/intrusion/VaultDrawer';
import { whenSql, resetSqlStub } from './stubs/plugin-sql';
import { createVaultParams, lockVault, sealSecret, unlockVault } from '../../src/lib/vaultCrypto';

/**
 * A credentials **row**, as the table stores it.
 *
 * Rows rather than hydrated credentials on purpose. `hydrate` in `credentialDB`
 * is what decides whether a password is readable, locked, absent or altered --
 * from `enc_version`, the presence of ciphertext and whether the key is in
 * memory -- and that decision is the subject here. Handing the drawer a
 * pre-decided `password: null, locked: true` would assert that the drawer renders
 * what it is given, which nobody doubts.
 */
const ROW = (over: Record<string, unknown> = {}) => ({
  id: 1,
  target_ip: '192.168.1.10',
  port: 22,
  service: 'ssh',
  username: 'root',
  password: null,
  password_cipher: null,
  password_iv: null,
  enc_version: 1,
  source: 'spray',
  session_id: null,
  hostname: null,
  notes: null,
  discovered_at: '2026-01-01T00:00:00Z',
  ...over,
});

/** A row written before the vault was encrypted: readable with no key at all. */
const LEGACY = (password = 'hunter2') => ROW({ enc_version: 0, password });

/** A sealed row. With the vault locked, its secret is not readable. */
const SEALED = () => ROW({ password_cipher: 'Y2lwaGVy', password_iv: 'aXY=' });

/**
 * Open the drawer with a given vault state and credential list.
 *
 * The SQL stub answers both reads the drawer makes on mount. `sealed` is what
 * `getVaultStatus` reports; the rows are what `getAllCredentials` returns, after
 * the decryption layer has already decided what each `password` is.
 */
function mount(rows: Record<string, unknown>[], vault: Record<string, unknown> = {}) {
  whenSql({ match: 'FROM credentials', rows });
  whenSql({ match: 'SELECT', rows: [{ total: rows.length, encrypted: rows.length, cleartext: 0, ...vault }] });
  whenSql({ match: 'UPDATE', rows: [] });
  whenSql({ match: 'INSERT', rows: [] });
  whenSql({ match: 'PRAGMA', rows: [] });
  return render(<VaultDrawer isOpen onClose={() => {}} />);
}

beforeEach(() => {
  resetSqlStub();
  // Every test starts from a locked vault; the ones that need it unlock
  // explicitly, so no test inherits another's key.
  lockVault();
});

/**
 * Unlock the vault with real key derivation.
 *
 * Not stubbed. The states this file is about -- readable, locked, never stored,
 * altered -- are decided by `hydrate` from whether the key is in memory and
 * whether the ciphertext authenticates, so a stubbed crypto layer would decide
 * the answers the test is checking. PBKDF2 at 600k iterations costs a few hundred
 * milliseconds once, which is the right price for that.
 */
async function unlock(passphrase = 'correct horse battery staple') {
  const params = await createVaultParams(passphrase);
  await unlockVault(passphrase, params);
}

describe('why a password is not shown', () => {
  test('a locked row says locked, not that nothing was recovered', async () => {
    /*
      The distinction this drawer exists to make. An empty cell for a network
      whose passphrase *was* cracked, shown to an operator who reads it as "this
      one held", is the worst outcome available here.
    */
    mount([SEALED()]);
    expect(await screen.findByText('locked')).toBeTruthy();
    expect(screen.queryByText('not stored')).toBeNull();
  });

  test('a row that was never stored says so', async () => {
    mount([ROW()]);
    expect(await screen.findByText('not stored')).toBeTruthy();
    expect(screen.queryByText('locked')).toBeNull();
  });

  test('ciphertext that fails authentication is reported as altered, not blank', async () => {
    /*
      A failed authentication tag means the stored bytes are not the bytes that
      were written. Rendering that as an empty cell would hide tampering behind
      the same appearance as an absence — and "altered" and "never stored" lead a
      reader to opposite conclusions about the same row.

      The vault has to be unlocked for this: a locked one reports `locked` and
      never attempts the decryption, which is a different state with its own test
      above. The ciphertext here is real and simply not the one that was sealed.
    */
    await unlock();
    const sealed = await sealSecret('hunter2');
    mount([ROW({ password_cipher: sealed.cipher, password_iv: 'AAAAAAAAAAAAAAAA' })]);

    expect(await screen.findByText('unreadable')).toBeTruthy();
    expect(screen.getByText(/ALTERED/)).toBeTruthy();
  });

  test('an intact sealed row is readable once the vault is open', async () => {
    // The inverse, so the test above is not passing because decryption never
    // works in this environment.
    await unlock();
    const sealed = await sealSecret('hunter2');
    mount([ROW({ password_cipher: sealed.cipher, password_iv: sealed.iv })]);

    expect(await screen.findByText('••••••••')).toBeTruthy();
    expect(screen.queryByText(/ALTERED/)).toBeNull();
  });

  test('a readable password is masked until it is asked for', async () => {
    mount([LEGACY('hunter2')]);
    expect(await screen.findByText('••••••••')).toBeTruthy();
    expect(screen.queryByText('hunter2')).toBeNull();
  });
});

describe('what the vault claims about itself', () => {
  test('a row still in cleartext on disk is flagged as such', async () => {
    /*
      `enc_version === 0` is a row written before the vault was encrypted. A
      drawer that looked uniformly protected while some rows were cleartext would
      be making a claim about the database file that is not true of it.
    */
    mount([LEGACY()]);
    expect(await screen.findByText(/CLEARTEXT ON DISK/)).toBeTruthy();
  });

  test('an encrypted row is not flagged', async () => {
    // The inverse, so the flag means something when it appears.
    mount([SEALED()]);
    await screen.findByText('locked');
    expect(screen.queryByText(/CLEARTEXT ON DISK/)).toBeNull();
  });
});

describe('the controls follow what is actually readable', () => {
  test('reveal and copy are withheld for a row with no readable password', async () => {
    /*
      Not cosmetic: a copy button that silently puts an empty string on the
      clipboard, for a credential the operator believes they copied, is a way to
      lose a finding between the tool and the report.
    */
    mount([SEALED()]);
    await screen.findByText('locked');

    const disabled = screen.getAllByRole('button')
      .filter(b => (b as HTMLButtonElement).disabled);
    expect(disabled.length).toBeGreaterThanOrEqual(2);
  });

  test('they are offered for a row that has one', async () => {
    mount([LEGACY('hunter2')]);
    await screen.findByText('••••••••');

    const reveal = screen.getByTitle(/Toggle Visibility/i);
    expect((reveal as HTMLButtonElement).disabled).toBe(false);
  });
});
