/**
 * A deep-scan result must render under the host it came from.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * The four completion listeners wrote their payload into flat component state, and the
 * drawer rendered it under whichever host happened to be selected. Scan host A, close
 * the drawer, open host B, and B's drawer showed A's CRITICAL finding under the header
 * "TARGET ACQUIRED <B>", with the button reading SCAN COMPLETED. The same for SMB,
 * dirbuster and traceroute, and none of that state was reset when the selection changed.
 *
 * The engine ships the subject in every one of those payloads specifically to prevent
 * it — `engine/scanner/smb_enum.py` says so: "The payload names its own subject. Without
 * this the frontend had to guess the target from whichever host happened to be selected
 * when the result arrived, which mislabels the evidence." The listeners never read it.
 *
 * The archive path was always correct, because it takes the host from the payload. So
 * this was screen-only — and the screen is what an operator reads and writes down, which
 * is why it is worth a test that actually renders the drawer.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { IntrusionPage } from '../../src/pages/IntrusionPage';
import { engineIPC } from '../../src/lib/ipc';
import { useIntrusionStore } from '../../src/stores/intrusionStore';
import { readFileSync } from 'node:fs';
import { whenSql } from './stubs/plugin-sql';

/** Deliver an engine event to every registered handler, as dispatch would. */
function emit(event: string, data: Record<string, unknown>) {
  const listeners = (engineIPC as unknown as {
    listeners: Map<string, ((m: unknown) => void)[]>;
  }).listeners;
  for (const h of [...(listeners.get(event) ?? [])]) {
    h({ event, data, ts: 'test' });
  }
}

const HOST_A = '10.0.0.11';
const HOST_B = '10.0.0.22';

function host(ip: string) {
  return {
    ip,
    hostname: `host-${ip}`,
    mac: null,
    vendor: null,
    os: null,
    open_ports: [{ port: 6379, service: 'redis', banner: null }],
    status: 'up' as const,
  };
}

function renderPage() {
  whenSql({ match: 'journal_mode', rows: [{ journal_mode: 'wal' }] });
  whenSql({ match: 'FROM scan_sessions', rows: [] });
  whenSql({ match: 'scan_sessions', rows: [] });
  whenSql({ match: 'FROM intel_reports', rows: [] });
  whenSql({ match: 'intel_reports', rows: [] });
  (engineIPC as unknown as { send: unknown }).send = async () => undefined;
  return render(<IntrusionPage />);
}

/**
 * Open a host's drawer from the inventory.
 *
 * Via that host's own ANALYZE NODE button rather than by clicking the address: the
 * address is a heading inside the card and is not the control. Scoped to the card that
 * contains the address, because every card has a button with the same label and picking
 * the first would quietly test one host twice.
 */
async function openHost(ip: string) {
  const address = await screen.findByText(ip);
  // Walk up until an ancestor holds this host's own ANALYZE NODE button. Every card has
  // one with the same label, so taking the first in the document would quietly test one
  // host twice; and guessing at the class structure is brittle in a way this is not.
  let node: HTMLElement | null = address;
  let button: HTMLButtonElement | undefined;
  while (node && !button) {
    button = [...node.querySelectorAll('button')]
      .find(b => /analyze node/i.test(b.textContent ?? '')) as HTMLButtonElement | undefined;
    node = node.parentElement;
  }
  if (!button) throw new Error(`no ANALYZE NODE button in the card for ${ip}`);
  await userEvent.click(button);
}

beforeEach(() => {
  // `hosts` is a `Record<string, DiscoveredHost>` keyed by address, not an array.
  //
  // The first version of this fixture used an array. `Object.values` still produced the
  // inventory, so the list rendered and the test looked healthy — but
  // `hosts[selectedHostIp]` on an array keyed by '10.0.0.11' is undefined, so the drawer
  // never opened and every assertion failed for a reason that had nothing to do with the
  // code under test. A fixture shaped unlike what the application produces is the same
  // trap that hid the `same_adapter` defect in `net_context`.
  useIntrusionStore.setState({
    hosts: { [HOST_A]: host(HOST_A), [HOST_B]: host(HOST_B) },
    currentSessionId: 'S-TEST',
  });
});

describe('a vulnerability scan result', () => {
  test('both hosts are listed, so the drawer can be opened for either', async () => {
    // The harness check for this file.
    renderPage();
    expect(await screen.findByText(HOST_A)).toBeTruthy();
    expect(await screen.findByText(HOST_B)).toBeTruthy();
  });

  test('renders under the host the engine named', async () => {
    renderPage();
    await openHost(HOST_A);
    emit('vuln_scan_completed', {
      target: HOST_A,
      findings: [{ vuln: 'Unauthenticated Redis', severity: 'CRITICAL', port: 6379,
                   description: 'no password', code: 'redis_noauth' }],
    });
    expect(await screen.findByText(/Unauthenticated Redis/i)).toBeTruthy();
  });

  test('does not render under a different host', async () => {
    /*
      The defect, as an operator meets it: scan A, then open B and read A's finding
      under B's header.
    */
    renderPage();
    await openHost(HOST_A);
    emit('vuln_scan_completed', {
      target: HOST_A,
      findings: [{ vuln: 'Unauthenticated Redis', severity: 'CRITICAL', port: 6379,
                   description: 'no password', code: 'redis_noauth' }],
    });
    expect(await screen.findByText(/Unauthenticated Redis/i)).toBeTruthy();

    await openHost(HOST_B);
    await waitFor(() => {
      expect(screen.queryByText(/Unauthenticated Redis/i)).toBeNull();
    });
  });

  test('reappears when the host it belongs to is reopened', async () => {
    // The gate withholds a result from the wrong host; it must not discard it.
    renderPage();
    await openHost(HOST_A);
    emit('vuln_scan_completed', {
      target: HOST_A,
      findings: [{ vuln: 'Unauthenticated Redis', severity: 'CRITICAL', port: 6379,
                   description: 'no password', code: 'redis_noauth' }],
    });
    await screen.findByText(/Unauthenticated Redis/i);

    await openHost(HOST_B);
    await waitFor(() => expect(screen.queryByText(/Unauthenticated Redis/i)).toBeNull());

    await openHost(HOST_A);
    expect(await screen.findByText(/Unauthenticated Redis/i)).toBeTruthy();
  });
});

describe('every deep-scan listener records an owner', () => {
  /*
    Read from the source, and said plainly to be a mirror.

    The gate itself is `ownsResult`, and the tests above exercise it end to end through
    the vulnerability panel — one function, one behaviour, proven once. What differs per
    listener is whether it records an owner at all, and a fifth listener added later
    without one would reintroduce the whole defect while every test above still passed.

    The SMB, dirbuster and traceroute panels sit behind their own disclosure controls, and
    driving those adds no guarantee about the gate that the vulnerability tests do not
    already give. This covers the part they cannot: that all four kinds are claimed, and
    claimed at the *start* of a scan rather than only on completion — which was its own
    defect, hiding a running trace on a newly selected host for the length of the run.
  */
  const source = readFileSync('src/pages/IntrusionPage.tsx', 'utf8');

  test('all five kinds are recorded', () => {
    // 'ssl' joined the other four when the TLS panel was wired up. It is in this
    // list rather than in a test of its own precisely because the risk a fifth
    // listener carries is that it forgets to claim an owner at all -- which is
    // what this list exists to catch.
    for (const kind of ['vuln', 'smb', 'dirbuster', 'traceroute', 'ssl']) {
      expect(source).toContain(`setResultOwner(prev => ({ ...prev, ${kind}:`);
    }
  });

  test('each panel is gated on ownership', () => {
    for (const kind of ['vuln', 'smb', 'dirbuster', 'traceroute', 'ssl']) {
      expect(source).toContain(`ownsResult('${kind}', selectedHost.ip)`);
    }
  });

  test('the owner is claimed when a scan starts, not only when it completes', () => {
    // `resultOwner.traceroute` was written only by `traceroute_completed`, so tracing a
    // newly selected host hid the ROUTE TRACE panel — spinner, streaming hops and all —
    // for the whole run, because the owner was still the previous host.
    const beforeStart = source.indexOf("setResultOwner(prev => ({ ...prev, traceroute: selectedHost.ip }))");
    const startCall = source.indexOf("engineIPC.send('start_traceroute'");
    expect(beforeStart).toBeGreaterThan(-1);
    expect(beforeStart).toBeLessThan(startCall);
  });

  test('an unknown owner does not withhold a result', () => {
    // `ownsResult` returns true when no owner was recorded. A result from an engine that
    // sent no subject, or from a build before this existed, is shown rather than hidden:
    // withholding a real finding is the worse of the two failures.
    expect(source).toContain('if (!owner || !ip) return true;');
  });
});
