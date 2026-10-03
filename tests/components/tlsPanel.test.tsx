/**
 * The TLS panel must never let an absence read as a pass.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * `deep_ssl_scan` is built around one rule, stated in its own docstring: "a check
 * that did not run produces an entry in `inconclusive`, never a finding. Every
 * finding here is supposed to become a remediation task for somebody, and a task
 * invented from a failed measurement costs real time and real credibility."
 *
 * That rule only survives as far as the thing that renders it. The engine can
 * separate "nothing was wrong" from "nothing was established" perfectly and it
 * buys nothing if the panel draws an empty findings list for both — and an empty
 * findings list is exactly what a scan that reached nothing produces.
 *
 * So these tests drive the panel rather than the adapter. `riskEngine.test.mjs`
 * already proves `tlsObservations` raises no finding from a null; what it cannot
 * prove is that an operator looking at the screen can tell which happened.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { IntrusionPage } from '../../src/pages/IntrusionPage';
import { engineIPC } from '../../src/lib/ipc';
import { useIntrusionStore } from '../../src/stores/intrusionStore';
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

const HOST = '10.0.0.44';

function renderPage() {
  whenSql({ match: 'journal_mode', rows: [{ journal_mode: 'wal' }] });
  whenSql({ match: 'FROM scan_sessions', rows: [] });
  whenSql({ match: 'scan_sessions', rows: [] });
  whenSql({ match: 'FROM intel_reports', rows: [] });
  whenSql({ match: 'intel_reports', rows: [] });
  (engineIPC as unknown as { send: unknown }).send = async () => undefined;
  return render(<IntrusionPage />);
}

/** Open the host drawer via its own ANALYZE NODE button. */
async function openHost(ip: string) {
  const address = await screen.findByText(ip);
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

/**
 * Expand the drawer's deep-scan section.
 *
 * The TLS, SMB, dirbuster and traceroute controls sit behind this disclosure;
 * only the vulnerability scan is offered directly. A test that skipped it would
 * fail looking for a button that is present in the tree and merely not rendered,
 * which is a confusing way to be told the right thing.
 */
async function openModules() {
  await userEvent.click(await screen.findByRole('button', { name: /OFFENSIVE MODULES & ACTIONS/i }));
}

async function startTlsScan() {
  await openModules();
  await userEvent.click(await screen.findByRole('button', { name: /TLS \/ CERTIFICATE INSPECTION/i }));
}

beforeEach(() => {
  useIntrusionStore.setState({
    hosts: {
      [HOST]: {
        ip: HOST, hostname: 'web-01', mac: null, vendor: null, os: null,
        // 8443 and not 443, deliberately. The button has to offer itself for a
        // TLS service wherever the port scan found one, and the scan has to go
        // to the port that was actually open rather than to a default.
        open_ports: [{ port: 8443, service: 'https-alt', banner: null }],
        status: 'up' as const,
      },
    },
    currentSessionId: 'S-TLS',
  });
});

describe('the TLS inspection control', () => {
  test('is offered for an implicit-TLS port that is not 443', async () => {
    renderPage();
    await openHost(HOST);
    await openModules();
    expect(await screen.findByRole('button', { name: /TLS \/ CERTIFICATE INSPECTION/i })).toBeTruthy();
  });

  test('scans the port that was found open, not 443', async () => {
    // Scanning a closed 443 on a host whose TLS service is on 8443 would fail,
    // and that failure would be reported as this host's posture.
    const sent: { cmd: string; data: Record<string, unknown> }[] = [];
    renderPage();
    (engineIPC as unknown as { send: unknown }).send = async (cmd: string, data: Record<string, unknown>) => {
      sent.push({ cmd, data });
    };
    await openHost(HOST);
    await startTlsScan();
    const call = sent.find(s => s.cmd === 'start_deep_ssl_scan');
    expect(call).toBeTruthy();
    expect(call!.data.port).toBe(8443);
    expect(call!.data.target_ip).toBe(HOST);
  });

  test('stays idle when the engine refuses the command', async () => {
    /*
      The passive-SIGINT panel shipped the other way round — it set ACTIVE and
      then sent — and showed a capture running against a sidecar that was not
      attached. SCANNING here is entered only after `send` resolves.
    */
    renderPage();
    (engineIPC as unknown as { send: unknown }).send = async () => {
      throw new Error('Engine not connected');
    };
    await openHost(HOST);
    await startTlsScan();

    expect(screen.queryByText(/NEGOTIATING TLS/i)).toBeNull();
    expect(await screen.findByText(/could not be started/i)).toBeTruthy();
  });
});

describe('what the panel does with an answer it did not get', () => {
  test('renders the inconclusive checks, and says their absence is not a pass', async () => {
    /*
      The defect this guards against is a panel that shows an empty findings
      list. A scan that reached nothing produces exactly that, and so does a
      service with nothing wrong.
    */
    renderPage();
    await openHost(HOST);
    await startTlsScan();
    emit('deep_ssl_scan_completed', {
      target: HOST, port: 8443,
      cn: 'web-01.local', issuer: 'Internal CA', expires: '2027-01-01',
      findings: [],
      inconclusive: [
        { check: 'hsts', reason: 'the HTTPS request did not complete' },
        { check: 'deprecated_tls/TLSv1', reason: 'connection refused' },
      ],
    });

    expect(await screen.findByText(/NOT ESTABLISHED \(2\)/i)).toBeTruthy();
    expect(screen.getByText(/the HTTPS request did not complete/i)).toBeTruthy();
    expect(screen.getByText(/absence from the findings above is not a pass/i)).toBeTruthy();
    // And it must not also claim the clean result.
    expect(screen.queryByText(/none of them raised anything/i)).toBeNull();
  });

  test('a genuinely clean scan says so, and only then', async () => {
    renderPage();
    await openHost(HOST);
    await startTlsScan();
    emit('deep_ssl_scan_completed', {
      target: HOST, port: 8443, cn: 'web-01.local',
      findings: [], inconclusive: [],
    });

    expect(await screen.findByText(/none of them raised anything/i)).toBeTruthy();
    expect(screen.queryByText(/NOT ESTABLISHED/i)).toBeNull();
  });

  test('an engine-side failure is not a clean result either', async () => {
    renderPage();
    await openHost(HOST);
    await startTlsScan();
    emit('ssl_scan_error', {
      target: HOST, port: 8443,
      message: 'The TLS inspection could not complete: TimeoutError: timed out',
    });

    expect(await screen.findByText(/could not complete/i)).toBeTruthy();
    expect(screen.getByText(/only that it could not be examined/i)).toBeTruthy();
    expect(screen.queryByText(/none of them raised anything/i)).toBeNull();
  });

  test('a finding is rendered with its severity and its detail', async () => {
    renderPage();
    await openHost(HOST);
    await startTlsScan();
    emit('deep_ssl_scan_completed', {
      target: HOST, port: 8443, expired: true, expires: '2024-01-01',
      findings: [{ severity: 'HIGH', finding: 'Deprecated TLSv1 accepted', detail: 'PCI-DSS and NIST require TLS 1.2 as a minimum.' }],
      inconclusive: [],
    });

    expect(await screen.findByText(/Deprecated TLSv1 accepted/i)).toBeTruthy();
    expect(screen.getByText(/PCI-DSS and NIST/i)).toBeTruthy();
    // The expiry is shown as expired rather than as a date the reader must check.
    expect(screen.getByText(/EXPIRED/i)).toBeTruthy();
  });
});

describe('a result belongs to the host it names', () => {
  test('a result for another host does not render here', async () => {
    const OTHER = '10.0.0.99';
    useIntrusionStore.setState({
      hosts: {
        [HOST]: {
          ip: HOST, hostname: 'web-01', mac: null, vendor: null, os: null,
          open_ports: [{ port: 8443, service: 'https-alt', banner: null }], status: 'up' as const,
        },
        [OTHER]: {
          ip: OTHER, hostname: 'web-02', mac: null, vendor: null, os: null,
          open_ports: [{ port: 443, service: 'https', banner: null }], status: 'up' as const,
        },
      },
      currentSessionId: 'S-TLS',
    });

    renderPage();
    await openHost(HOST);
    await startTlsScan();
    // The engine names OTHER as the subject — a scan the operator started
    // earlier, landing after they moved on.
    emit('deep_ssl_scan_completed', {
      target: OTHER, port: 443,
      findings: [{ severity: 'HIGH', finding: 'Deprecated TLSv1 accepted', detail: 'x' }],
      inconclusive: [],
    });

    await waitFor(() => {
      expect(screen.queryByText(/Deprecated TLSv1 accepted/i)).toBeNull();
    });
  });
});
