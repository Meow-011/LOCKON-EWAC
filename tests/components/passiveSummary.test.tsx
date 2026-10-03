/**
 * The probe count on screen must be the engine's, not the last event's.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * `probe_monitor.py` emits `probe_detected` only when `is_new_client or
 * is_new_ssid`. A device that probes five hundred times for one network emits
 * once, and the `probe_count` carried by that one event is its value at the
 * first sighting — so the panel showed "1 PROBES" for a client that had probed
 * five hundred times. `passive_host` is rate limited per host for the same
 * reason, and `get_feed_stats` exists, in its own words, "so a quiet feed is
 * never read as a quiet network".
 *
 * Both summaries are pull-only commands the engine has always offered and
 * nothing ever sent. This project's own gaps list recorded them as redundant —
 * "a second source for a number the UI already has" — which was wrong in both
 * cases, and wrong in the direction this tool exists not to be wrong in: a
 * figure in front of an operator that understates what was measured.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { PassiveSigintView } from '../../src/components/intrusion/PassiveSigintView';
import { engineIPC } from '../../src/lib/ipc';
import { usePassiveSigintStore } from '../../src/stores/passiveSigintStore';
import { useEngineStore } from '../../src/stores/engineStore';

function emit(event: string, data: Record<string, unknown>) {
  const listeners = (engineIPC as unknown as {
    listeners: Map<string, ((m: unknown) => void)[]>;
  }).listeners;
  for (const h of [...(listeners.get(event) ?? [])]) h({ event, data, ts: 'test' });
}

const sent: string[] = [];
function engineRecords() {
  sent.length = 0;
  (engineIPC as unknown as { send: unknown }).send = async (cmd: string) => { sent.push(cmd); };
}

const CLIENT = 'AA:BB:CC:DD:EE:FF';

beforeEach(() => {
  usePassiveSigintStore.getState().reset?.();
  useEngineStore.setState({ config: { ...useEngineStore.getState().config, interfaceName: 'Wi-Fi' } });
  engineRecords();
});

/** Start the capture, which is what begins the polling. */
async function start() {
  await userEvent.click(screen.getByRole('button', { name: /INITIATE SIGINT/i }));
  await screen.findByRole('button', { name: /CEASE MONITORING/i });
}

describe('the authoritative counts are requested at all', () => {
  test('both summaries are asked for once the capture is running', async () => {
    render(<PassiveSigintView />);
    await start();
    await waitFor(() => {
      expect(sent).toContain('get_probe_summary');
      expect(sent).toContain('get_passive_summary');
    });
  });

  test('nothing is asked for while the panel is idle', async () => {
    // Polling a capture that is not running would be noise, and a reply would
    // correct figures that belong to a previous run.
    render(<PassiveSigintView />);
    await new Promise(r => setTimeout(r, 50));
    expect(sent).not.toContain('get_probe_summary');
  });

  test('they are asked for one last time when the operator stops', async () => {
    // Before the stop, so the final figures left on screen are the engine's and
    // not whatever the last event happened to carry.
    render(<PassiveSigintView />);
    await start();
    sent.length = 0;
    await userEvent.click(screen.getByRole('button', { name: /CEASE MONITORING/i }));

    expect(sent.indexOf('get_probe_summary')).toBeGreaterThan(-1);
    expect(sent.indexOf('get_probe_summary')).toBeLessThan(sent.indexOf('stop_passive'));
  });
});

describe('what the summary corrects', () => {
  test('a stale probe count is replaced by the live one', async () => {
    /*
      The defect as an operator meets it: one event said 1, the device has since
      probed 500 times, and the screen still says 1.
    */
    render(<PassiveSigintView />);
    await start();
    emit('probe_detected', {
      client_mac: CLIENT, ssid: 'CORP-WIFI', is_new_client: true,
      total_ssids: 1, probe_count: 1, timestamp: '2026-10-03T00:00:00Z',
    });
    expect(await screen.findByText(/1 PROBES/)).toBeTruthy();

    emit('probe_summary', {
      clients: [{ client_mac: CLIENT, ssids: ['CORP-WIFI', 'GUEST'], probe_count: 500 }],
      total: 1,
    });

    expect(await screen.findByText(/500 PROBES/)).toBeTruthy();
    expect(screen.queryByText(/^1 PROBES/)).toBeNull();
    // The SSID count is corrected from the same answer.
    expect(screen.getByText(/2 SSIDS SEEN/)).toBeTruthy();
  });

  test('a client in the summary with no row is not invented', async () => {
    /*
      Its probes were suppressed as repeats of a sighting already on screen under
      another SSID. Adding a row would show a probe event that never happened;
      the corrected counts on the existing rows are what say the activity was
      higher.
    */
    render(<PassiveSigintView />);
    await start();
    emit('probe_detected', {
      client_mac: CLIENT, ssid: 'CORP-WIFI', is_new_client: true,
      total_ssids: 1, probe_count: 1, timestamp: '2026-10-03T00:00:00Z',
    });
    await screen.findByText(/1 PROBES/);

    emit('probe_summary', {
      clients: [
        { client_mac: CLIENT, ssids: ['CORP-WIFI'], probe_count: 9 },
        { client_mac: '11:22:33:44:55:66', ssids: ['OTHER'], probe_count: 40 },
      ],
      total: 2,
    });

    await screen.findByText(/9 PROBES/);
    expect(screen.queryByText(/11:22:33:44:55:66/i)).toBeNull();
    expect(screen.queryByText(/40 PROBES/)).toBeNull();
  });

  test('the ssid of a row is never rewritten by the summary', async () => {
    // The summary is per client and carries every SSID that client asked for.
    // Writing one of them onto an existing row would relabel a sighting that was
    // about a different network.
    render(<PassiveSigintView />);
    await start();
    emit('probe_detected', {
      client_mac: CLIENT, ssid: 'CORP-WIFI', is_new_client: true,
      total_ssids: 1, probe_count: 1, timestamp: '2026-10-03T00:00:00Z',
    });
    await screen.findByText(/CORP-WIFI/);

    emit('probe_summary', { clients: [{ client_mac: CLIENT, ssids: ['GUEST', 'CORP-WIFI'], probe_count: 7 }], total: 1 });

    await screen.findByText(/7 PROBES/);
    expect(screen.getByText('CORP-WIFI')).toBeTruthy();
  });
});

describe('a quiet feed is not reported as a quiet network', () => {
  test('the suppressed count is stated, with what it does and does not mean', async () => {
    render(<PassiveSigintView />);
    await start();
    emit('passive_summary', {
      hosts: [], total: 0,
      feed: { suppressed_repeat_events: 1234, min_interval_seconds: 5 },
    });

    const note = await screen.findByText(/held back by the/i);
    expect(note.textContent).toMatch(/1,234/);
    // Both halves of the claim: the list is complete, the traffic is not.
    expect(note.textContent).toMatch(/already listed here/i);
    expect(note.textContent).toMatch(/heavier than it looks/i);
  });

  test('nothing is claimed when nothing was suppressed', async () => {
    // A banner reading "0 repeat sightings held back" is noise that teaches the
    // operator to skip the line for the run where it says 1,234.
    render(<PassiveSigintView />);
    await start();
    emit('passive_summary', { hosts: [], total: 0, feed: { suppressed_repeat_events: 0, min_interval_seconds: 5 } });

    await waitFor(() => expect(screen.queryByText(/held back by the/i)).toBeNull());
  });

  test('an engine that sends no feed stats produces no claim', async () => {
    // An older sidecar, or one that could not read them. Absent is not zero.
    render(<PassiveSigintView />);
    await start();
    emit('passive_summary', { hosts: [], total: 0 });

    await waitFor(() => expect(screen.queryByText(/held back by the/i)).toBeNull());
  });
});
