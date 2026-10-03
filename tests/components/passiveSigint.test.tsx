/**
 * Passive SIGINT: the panel must not say it is recording when nothing is.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * `toggleSigint` sent `start_passive` and `start_probe_monitor` with `.catch(console.error)`
 * and then ran `setActive(true)` unconditionally. `engineIPC.send` rejects when the
 * sidecar is not attached — `throw new Error('Engine not connected')` when `child` is
 * null, which is the state during the reconnect backoff — so the panel showed ACTIVE,
 * started its mission timer and displayed "Awaiting Broadcast Traffic…" while nothing
 * reached the engine and nothing on the engine side could ever emit `passive_stopped`
 * to undo it. `setErrorMsg(null)` had already cleared the one row that might have said
 * so.
 *
 * This is the first test in the project that renders a component, and it is this one
 * because the fix is a state transition with no database and no map behind it: the whole
 * claim is "ACTIVE only if the engine took the command", which is exactly what a render
 * can check and `tsc` cannot.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { PassiveSigintView } from '../../src/components/intrusion/PassiveSigintView';
import { engineIPC } from '../../src/lib/ipc';
import { usePassiveSigintStore } from '../../src/stores/passiveSigintStore';
import { useEngineStore } from '../../src/stores/engineStore';

/** The engine's answer to a `send`, controlled per test. */
function engineAccepts() {
  // The real `send` writes to the sidecar's stdin. Replacing it here keeps the test
  // about the component's state machine rather than about the IPC layer, which
  // `tests/ipc.test.mjs` already covers against a stub child process.
  (engineIPC as unknown as { send: unknown }).send = async () => undefined;
}

function engineRefuses(message = 'Engine not connected') {
  (engineIPC as unknown as { send: unknown }).send = async () => {
    throw new Error(message);
  };
}

const sent: { cmd: string; data?: Record<string, unknown> }[] = [];
function engineRecords() {
  sent.length = 0;
  // The payload is recorded as well as the name, because the test below is named
  // for the interface and asserted only the names — so the defect it exists for,
  // the interface omitted entirely while the header claimed to show it, would
  // have gone straight past it.
  (engineIPC as unknown as { send: unknown }).send = async (cmd: string, data?: Record<string, unknown>) => {
    sent.push({ cmd, data });
  };
}

beforeEach(() => {
  usePassiveSigintStore.getState().reset?.();
  useEngineStore.setState({ config: { ...useEngineStore.getState().config, interfaceName: 'Wi-Fi' } });
});

describe('the SIGINT control', () => {
  test('starts as idle and offers to initiate', () => {
    render(<PassiveSigintView />);
    expect(screen.getByRole('button', { name: /INITIATE SIGINT/i })).toBeTruthy();
  });

  test('goes ACTIVE when the engine accepts both commands', async () => {
    engineAccepts();
    render(<PassiveSigintView />);
    await userEvent.click(screen.getByRole('button', { name: /INITIATE SIGINT/i }));
    expect(await screen.findByRole('button', { name: /CEASE MONITORING/i })).toBeTruthy();
  });

  test('stays idle when the engine refuses the command', async () => {
    /*
      The defect. A rejected `send` went to `console.error` and the panel went ACTIVE
      anyway — with a running timer and "Awaiting Broadcast Traffic…" over a capture
      that did not exist, and no engine-side event able to correct it.
    */
    engineRefuses();
    render(<PassiveSigintView />);
    await userEvent.click(screen.getByRole('button', { name: /INITIATE SIGINT/i }));

    expect(screen.getByRole('button', { name: /INITIATE SIGINT/i })).toBeTruthy();
    expect(screen.queryByRole('button', { name: /CEASE MONITORING/i })).toBeNull();
  });

  test('says why it did not start', async () => {
    // Silence here is the worst outcome: the operator believes a capture is running.
    engineRefuses('Engine not connected');
    render(<PassiveSigintView />);
    await userEvent.click(screen.getByRole('button', { name: /INITIATE SIGINT/i }));

    const message = await screen.findByText(/Could not start passive capture/i);
    expect(message.textContent).toMatch(/Nothing is being recorded/i);
  });

  test('a refusal of the second command does not leave it ACTIVE either', async () => {
    /*
      `start_passive` can be accepted and `start_probe_monitor` refused — they are two
      writes to the same pipe, and the second can fail on its own. Both are awaited, so
      either rejection keeps the panel idle.
    */
    let call = 0;
    (engineIPC as unknown as { send: unknown }).send = async () => {
      call += 1;
      if (call === 2) throw new Error('stdin closed');
    };
    render(<PassiveSigintView />);
    await userEvent.click(screen.getByRole('button', { name: /INITIATE SIGINT/i }));

    expect(screen.queryByRole('button', { name: /CEASE MONITORING/i })).toBeNull();
    expect(await screen.findByText(/Could not start passive capture/i)).toBeTruthy();
  });

  test('both engine commands are sent, with the selected interface', async () => {
    engineRecords();
    render(<PassiveSigintView />);
    await userEvent.click(screen.getByRole('button', { name: /INITIATE SIGINT/i }));

    /*
      The two start commands, in order, each carrying the interface.

      This asserted `sent` equalled exactly those two names. That made it brittle
      to any other command the panel might send — it broke the moment the
      authoritative summaries began being polled — and, more to the point, it
      never looked at the interface at all despite being named for it. The defect
      it guards is the interface being omitted, so that is what it checks now.
    */
    const starts = sent.filter(c => c.cmd === 'start_passive' || c.cmd === 'start_probe_monitor');
    expect(starts.map(c => c.cmd)).toEqual(['start_passive', 'start_probe_monitor']);
    for (const call of starts) {
      expect(call.data?.interface).toBe('Wi-Fi');
    }
  });
});
