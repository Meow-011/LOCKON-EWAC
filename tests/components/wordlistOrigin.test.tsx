/**
 * A list that ships with the application must look like one, and resist deletion.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * The engine sends `origin` on every wordlist, the state type declares it and
 * the store preserves it — and the projection in `SettingsPage` dropped it on the
 * way through, while `wordlists` prefers that copy over the store's. The page
 * issues `get_wordlists` on mount, so the stripped list arrived almost
 * immediately and `file.origin` was `undefined` from then on.
 *
 * Two things depended on it. The BUNDLED badge never rendered, so a list that
 * ships with the tool was indistinguishable from one the operator uploaded. And
 * `disabled={file.origin === 'bundled'}` on DELETE was always false — so the
 * control was offered, the operator pressed it, and the engine refused with
 * "ships with the application". A button that is enabled and then refuses is
 * exactly the "reads as a broken feature" outcome the comment beside it says it
 * exists to prevent.
 *
 * Nothing here is caught by `tsc`: dropping a field while building a new object
 * is type-correct, because the field is optional. What makes it visible is
 * rendering the list and looking at what an operator would see.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';

import { SettingsPage } from '../../src/pages/SettingsPage';
import { engineIPC } from '../../src/lib/ipc';
import { whenSql, resetSqlStub } from './stubs/plugin-sql';

function emit(event: string, data: Record<string, unknown>) {
  const listeners = (engineIPC as unknown as {
    listeners: Map<string, ((m: unknown) => void)[]>;
  }).listeners;
  for (const h of [...(listeners.get(event) ?? [])]) h({ event, data, ts: 'test' });
}

function scriptSql() {
  whenSql({ match: 'journal_mode', rows: [{ journal_mode: 'wal' }] });
  whenSql({ match: 'engagement_scope', rows: [] });
  whenSql({ match: 'scope_targets', rows: [] });
  whenSql({ match: 'audit_log', rows: [] });
  whenSql({ match: 'FROM evidence_files', rows: [] });
  whenSql({ match: 'antenna_benchmarks', rows: [] });
  whenSql({ match: 'SELECT', rows: [] });
  whenSql({ match: 'UPDATE', rows: [] });
  whenSql({ match: 'INSERT', rows: [] });
  whenSql({ match: 'DELETE', rows: [] });
  whenSql({ match: 'PRAGMA', rows: [] });
}

/** The engine's reply to `get_wordlists`. */
const LISTS = {
  lists: [
    { name: 'rockyou-top-10k.txt', size: 85000, origin: 'bundled' },
    { name: 'client-site-guesses.txt', size: 2048, origin: 'user' },
  ],
};

/** The delete control inside the row for a given list. */
function deleteButtonFor(name: string): HTMLButtonElement {
  const label = screen.getByText(name);
  let node: HTMLElement | null = label;
  while (node) {
    const button = [...node.querySelectorAll('button')].find(
      b => /delete|remove/i.test(b.getAttribute('title') || b.getAttribute('aria-label') || '')
        || b.querySelector('svg polyline[points="3 6 5 6 21 6"]')
    ) as HTMLButtonElement | undefined;
    if (button) return button;
    node = node.parentElement;
  }
  throw new Error(`no delete control in the row for ${name}`);
}

beforeEach(() => {
  resetSqlStub();
  scriptSql();
  (engineIPC as unknown as { send: unknown }).send = async () => undefined;
});

describe('a bundled wordlist', () => {
  test('is badged, so it is distinguishable from an uploaded one', async () => {
    render(<SettingsPage />);
    emit('wordlists_list', LISTS);

    expect(await screen.findByText('rockyou-top-10k.txt')).toBeTruthy();
    expect(await screen.findByText('BUNDLED')).toBeTruthy();
  });

  test('exactly the bundled one is badged', async () => {
    // A badge on everything is the same as a badge on nothing.
    render(<SettingsPage />);
    emit('wordlists_list', LISTS);

    await screen.findByText('client-site-guesses.txt');
    expect(screen.getAllByText('BUNDLED')).toHaveLength(1);
  });

  test('its delete control is disabled rather than offered and refused', async () => {
    /*
      The engine refuses this deletion with "ships with the application". An
      enabled button that then refuses teaches the operator the feature is
      broken; a disabled one says the answer before they ask.
    */
    render(<SettingsPage />);
    emit('wordlists_list', LISTS);
    await screen.findByText('rockyou-top-10k.txt');

    await waitFor(() => {
      expect(deleteButtonFor('rockyou-top-10k.txt').disabled).toBe(true);
    });
  });

  test('a list the operator uploaded can still be deleted', async () => {
    // The guard has to be about origin, not about disabling deletion generally.
    render(<SettingsPage />);
    emit('wordlists_list', LISTS);
    await screen.findByText('client-site-guesses.txt');

    expect(deleteButtonFor('client-site-guesses.txt').disabled).toBe(false);
  });

  test('an engine that sends no origin badges nothing and blocks nothing', async () => {
    /*
      Absent is not "bundled". An older sidecar, or one that could not read the
      directory, sends the list without the field — and inventing a BUNDLED badge
      for it would claim the file ships with the tool when nobody knows that.
      Leaving delete enabled is the right failure: the engine still refuses if it
      is in fact bundled, which is a worse message than a disabled button but a
      better outcome than refusing to delete a file the operator owns.
    */
    render(<SettingsPage />);
    emit('wordlists_list', { lists: [{ name: 'unknown-origin.txt', size: 100 }] });

    await screen.findByText('unknown-origin.txt');
    expect(screen.queryByText('BUNDLED')).toBeNull();
    expect(deleteButtonFor('unknown-origin.txt').disabled).toBe(false);
  });

  test('an unrecognised origin is treated as unknown, not as bundled', async () => {
    // The projection keeps `'bundled'` and `'user'` and discards anything else,
    // so a future value cannot acquire the protections of one it is not.
    render(<SettingsPage />);
    emit('wordlists_list', { lists: [{ name: 'odd.txt', size: 100, origin: 'vendor-supplied' }] });

    await screen.findByText('odd.txt');
    expect(screen.queryByText('BUNDLED')).toBeNull();
  });
});
