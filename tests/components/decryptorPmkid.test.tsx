/**
 * The PMKID button must not claim to be listening after the capture has failed.
 *
 * Why this exists.
 *
 * `DecryptorPage` had listeners for `pmkid_captured`, `pmkid_timeout` and
 * `pmkid_eapol_seen` and none for `pmkid_error` or `pmkid_aborted`, and no other engine
 * event cleared `pmkidListening`. The terminal case that reaches this is
 * `capture.py`'s `_pmkid_worker` raising — a scapy, Npcap or monitor-mode failure — which
 * emits `pmkid_error` and no timeout. The button then read "LISTENING — CLICK TO STOP"
 * indefinitely for a capture that had already stopped, and clicking it logged "STOPPED
 * BY OPERATOR" about something that was never running.
 *
 * `engineRouter` raises a toast for `pmkid_error`, which is why this was easy to miss:
 * the operator saw an error *and* a button still claiming to listen.
 */
import { describe, expect, test } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';

import { DecryptorPage } from '../../src/pages/DecryptorPage';
import { engineIPC } from '../../src/lib/ipc';
import { whenSql } from './stubs/plugin-sql';

/** Deliver an engine event to every registered handler, as `ipc.ts` dispatch would. */
function emit(event: string, data: Record<string, unknown>) {
  const listeners = (engineIPC as unknown as {
    listeners: Map<string, ((m: unknown) => void)[]>;
  }).listeners;
  for (const h of [...(listeners.get(event) ?? [])]) {
    h({ event, data, ts: 'test' });
  }
}

function renderPage() {
  // The cracking history is read on mount.
  whenSql({ match: 'journal_mode', rows: [{ journal_mode: 'wal' }] });
  whenSql({ match: 'FROM cracking_history', rows: [] });
  whenSql({ match: 'cracking_history', rows: [] });
  return render(
    <MemoryRouter>
      <DecryptorPage />
    </MemoryRouter>,
  );
}

/**
 * Put the button into LISTENING, the way an operator does.
 *
 * This matters more than it looks. The first version of the two tests below asserted
 * that an error *releases* the button without ever putting it into the listening state —
 * so `queryByText` was null either way and both passed with the listeners deleted. A
 * test that cannot fail is worse than no test, and this harness exists to catch exactly
 * that class of thing.
 */
async function startListening() {
  (engineIPC as unknown as { send: unknown }).send = async () => undefined;
  const input = screen.getByPlaceholderText('AA:BB:CC:DD:EE:FF');
  await userEvent.type(input, 'AA:BB:CC:DD:EE:01');
  await userEvent.click(screen.getByRole('button', { name: /PMKID CAPTURE/i }));
  // Confirmed, so a failure to start is not mistaken for the behaviour under test.
  expect(await screen.findByRole('button', { name: /LISTENING/i })).toBeTruthy();
}

describe('the PMKID listener', () => {
  test('the page renders without a database or a sidecar', () => {
    // The harness check: if this fails, nothing below means anything. Asserted on the
    // log pane rather than on the word PMKID, which appears in several places.
    renderPage();
    expect(screen.getAllByText(/PMKID/i).length).toBeGreaterThan(0);
  });

  test('a capture error releases the button', async () => {
    renderPage();
    await startListening();
    emit('pmkid_error', { bssid: 'AA:BB:CC:DD:EE:01', message: 'monitor mode unavailable' });

    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /LISTENING/i })).toBeNull();
    });
    expect(screen.getByRole('button', { name: /PMKID CAPTURE/i })).toBeTruthy();
  });

  test('a capture error is written to the log with its reason', async () => {
    renderPage();
    emit('pmkid_error', { bssid: 'AA:BB:CC:DD:EE:01', message: 'monitor mode unavailable' });
    expect(await screen.findByText(/monitor mode unavailable/i)).toBeTruthy();
  });

  test('an aborted capture releases the button too', async () => {
    // `capture.py` emits `pmkid_aborted` when a capture never started — an enum already
    // in progress, for instance. Self-correcting in practice, and it was still unhandled.
    renderPage();
    await startListening();
    emit('pmkid_aborted', { bssid: 'AA:BB:CC:DD:EE:01', message: 'already in progress' });
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: /LISTENING/i })).toBeNull();
    });
  });

  test('a timeout still releases the button', async () => {
    // The path that already worked. Asserted so the new listeners cannot be added in a
    // way that breaks it.
    renderPage();
    emit('pmkid_timeout', { bssid: 'AA:BB:CC:DD:EE:01', message: 'no PMKID observed' });
    expect(await screen.findByText(/no PMKID observed/i)).toBeTruthy();
  });
});
