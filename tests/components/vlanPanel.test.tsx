/**
 * The segmentation panel must not cost the host list its viewport — and must not
 * buy that back by dropping what makes its numbers honest.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * The first version put every subnet on two lines and wrote "(basis not stated)"
 * out once per value — eight times for four subnets — and came to roughly 470px.
 * It never overlapped the host cards: it is an ordinary block, and they sit in a
 * `flex-1 overflow-y-auto` sibling inside a fixed-height column. But every pixel
 * it took came out of their scroll viewport, so a four-subnet result left the
 * operator looking at the bottom edge of two cards. Squeezing looks exactly like
 * covering, and the screenshot that reported it could not tell them apart.
 *
 * Collapsing it is easy and the risk is obvious: the qualifications are what stop
 * an inferred VLAN id being read as a measured one, and "make it smaller" is
 * exactly the pressure that removes them. So these tests pin both halves — that
 * the detail is not on screen until it is asked for, and that when it is asked
 * for, every value that was inferred still says so.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { IntrusionPage } from '../../src/pages/IntrusionPage';
import { engineIPC } from '../../src/lib/ipc';
import { useIntrusionStore } from '../../src/stores/intrusionStore';
import { whenSql, resetSqlStub } from './stubs/plugin-sql';

function emit(event: string, data: Record<string, unknown>) {
  const listeners = (engineIPC as unknown as {
    listeners: Map<string, ((m: unknown) => void)[]>;
  }).listeners;
  for (const h of [...(listeners.get(event) ?? [])]) h({ event, data, ts: 'test' });
}

/** The engine's answer, shaped as `vlan_detect.py` emits it. */
const REPORT = {
  subnets_analyzed: 4,
  vlan_map: [
    { subnet: '10.20.0.0/24', vlan_id: 2, vlan_id_basis: 'inferred from the third octet',
      gateway: '10.20.0.1', gateway_basis: 'assumed: first usable address in the prefix',
      network_class: 'Class A Private', gateway_alive: false, prefix_length: 24 },
    { subnet: '192.168.31.0/24', vlan_id: 31, vlan_id_basis: 'inferred from the third octet',
      gateway: '192.168.31.1', gateway_basis: 'assumed: first usable address in the prefix',
      network_class: 'Class C Private', gateway_alive: true, prefix_length: 24 },
    { subnet: '10.0.0.0/31', vlan_id: null, vlan_id_basis: null,
      gateway: null, gateway_basis: null,
      network_class: 'Class A Private', gateway_alive: null, prefix_length: 31 },
    { subnet: 'garbage', error: 'not a valid CIDR', vlan_id: null, gateway: null, gateway_alive: null },
  ],
  findings: [
    { type: 'inter_vlan', severity: 'INFO', message: 'This host reached the assumed gateway of another subnet.' },
    { type: 'rogue_dhcp', severity: 'HIGH', message: 'Two DHCP servers answered one discover.' },
  ],
};

function renderPage() {
  whenSql({ match: 'journal_mode', rows: [{ journal_mode: 'wal' }] });
  whenSql({ match: 'scan_sessions', rows: [] });
  whenSql({ match: 'intel_reports', rows: [] });
  (engineIPC as unknown as { send: unknown }).send = async () => undefined;
  return render(<IntrusionPage />);
}

/** Run the analysis and land on a completed report. */
async function analyse(report: Record<string, unknown> = REPORT) {
  await userEvent.click(await screen.findByRole('button', { name: /ANALYSE NETWORK SEGMENTATION/i }));
  emit('vlan_scan_completed', report);
}

beforeEach(() => {
  resetSqlStub();
  useIntrusionStore.setState({
    hosts: {
      '10.0.0.5': {
        ip: '10.0.0.5', hostname: 'nas', mac: null, vendor: null, os: null,
        open_ports: [{ port: 445, service: 'smb', banner: null }], status: 'up' as const,
      },
    },
    currentSessionId: 'S-VLAN',
  });
});

describe('the summary line', () => {
  test('answers the question without opening anything', async () => {
    /*
      How many subnets, how many gateways answered, and whether anything routes
      between them. That is what the operator pressed the button for; the table
      is the evidence behind it.
    */
    renderPage();
    await analyse();

    const line = await screen.findByText(/subnet\(s\) ·/i);
    expect(line.textContent).toMatch(/4 subnet\(s\)/);
    expect(line.textContent).toMatch(/1 gateway\(s\) answered/);
    expect(line.textContent).toMatch(/inter-VLAN routing/i);
  });

  test('the table is not on screen until it is asked for', async () => {
    // The whole point: 470px of detail is not taken out of the host list's
    // viewport for a result most runs read in one line.
    renderPage();
    await analyse();
    await screen.findByText(/4 subnet\(s\)/);

    expect(screen.queryByText('192.168.31.0/24')).toBeNull();
    expect(screen.queryByText(/not read from any switch/i)).toBeNull();
  });

  test('a HIGH finding is surfaced in the collapsed line', async () => {
    // A rogue DHCP server is the one measured result this check produces, and it
    // must not be something you have to expand a table to discover.
    renderPage();
    await analyse();

    const line = await screen.findByText(/subnet\(s\) ·/i);
    expect(line.textContent).toMatch(/Two DHCP servers answered/i);
  });
});

describe('the table, once opened', () => {
  async function open() {
    await userEvent.click(await screen.findByRole('button', { name: /SEGMENTATION/i }));
  }

  test('every inferred column is marked, and the basis is stated once', async () => {
    /*
      The defect this guards is the one that made the panel 470px in the first
      place, arriving from the other direction: making it compact by dropping the
      qualification. A VLAN id here is the third octet of a range. Rendered
      without a mark it is indistinguishable from something a switch was asked.
    */
    renderPage();
    await analyse();
    await open();

    expect(await screen.findByText('192.168.31.0/24')).toBeTruthy();

    const footnote = screen.getByText(/not read from any switch/i);
    expect(footnote.textContent).toMatch(/inferred from the third octet/);
    expect(footnote.textContent).toMatch(/assumed: first usable address in the prefix/);
    // Said once, not once per value: the repetition was the largest thing on
    // screen and it was not information.
    expect(screen.queryAllByText(/inferred from the third octet/)).toHaveLength(1);
  });

  test('the footnote is built from what the engine sent', async () => {
    // Not written in the page. A column whose derivation changes must not keep a
    // footnote describing the old one.
    renderPage();
    await analyse({
      ...REPORT,
      vlan_map: REPORT.vlan_map.map(v => (v.vlan_id_basis ? { ...v, vlan_id_basis: 'read from LLDP' } : v)),
    });
    await open();

    const footnote = await screen.findByText(/not read from any switch/i);
    expect(footnote.textContent).toMatch(/read from LLDP/);
    expect(footnote.textContent).not.toMatch(/third octet/);
  });

  test('gateway reachability has three states, and the third is not "no"', async () => {
    /*
      A /31 is a point-to-point link with no first usable host, so nothing was
      pinged. Printing "no reply" for it would report a gateway that failed to
      answer, which is a measurement nobody took.
    */
    renderPage();
    await analyse();
    await open();

    expect(await screen.findByText('answered')).toBeTruthy();
    expect(screen.getByText('no reply')).toBeTruthy();
    expect(screen.getByText('not probed')).toBeTruthy();
  });

  test('a subnet that could not be parsed stays in the table', async () => {
    // Dropped, it would read as a network with fewer segments than it has.
    renderPage();
    await analyse();
    await open();

    expect(await screen.findByText('garbage')).toBeTruthy();
    expect(screen.getByText(/could not be read: not a valid CIDR/i)).toBeTruthy();
  });

  test('it closes again', async () => {
    renderPage();
    await analyse();
    await open();
    await screen.findByText('192.168.31.0/24');

    await open();
    await waitFor(() => expect(screen.queryByText('192.168.31.0/24')).toBeNull());
  });
});

describe('a failure', () => {
  test('is not reported as a flat network', async () => {
    // "Could not be analysed" and "nothing is segmented" are opposite findings.
    renderPage();
    (engineIPC as unknown as { send: unknown }).send = async () => {
      throw new Error('Engine not connected');
    };
    await userEvent.click(await screen.findByRole('button', { name: /ANALYSE NETWORK SEGMENTATION/i }));

    expect(await screen.findByText(/could not be analysed/i)).toBeTruthy();
    await userEvent.click(screen.getByRole('button', { name: /SEGMENTATION/i }));
    expect(await screen.findByText(/only that it was not analysed/i)).toBeTruthy();
  });
});

describe('the host count per range', () => {
  /*
    The question this answers — "how many machines are in that VLAN" — has a trap
    in it, and the trap is the number zero.

    A sweep covers one subnet at a time, so the segmentation map routinely lists
    three ranges nothing has ever probed. Printing `0 found` for those would read
    as "we looked and the VLAN is empty", which is a claim about somebody's
    network made from no measurement at all. A range with no sweep scope has to
    say that instead.
  */
  async function open() {
    await userEvent.click(await screen.findByRole('button', { name: /SEGMENTATION/i }));
  }

  function withHostsAndScope() {
    useIntrusionStore.setState({
      hosts: {
        '192.168.31.10': { ip: '192.168.31.10', hostname: 'a', mac: null, vendor: null, os: null, open_ports: [], status: 'up' as const },
        '192.168.31.11': { ip: '192.168.31.11', hostname: 'b', mac: null, vendor: null, os: null, open_ports: [], status: 'up' as const },
        // In a different range entirely, so a sloppy match would count it twice.
        '10.20.0.9': { ip: '10.20.0.9', hostname: 'c', mac: null, vendor: null, os: null, open_ports: [], status: 'up' as const },
      },
      sweepScopes: {
        '192.168.31.0/24': {
          subnet: '192.168.31.0/24', addressesInRange: 254, addressesProbed: 254,
          skippedByArpFilter: 0, addressesNeverSwept: 0,
        },
      },
      currentSessionId: 'S-VLAN',
    });
  }

  test('a swept range reports what was found and how much was probed', async () => {
    // "2 found" means very different things out of 254 probed and out of 6, so
    // the denominator travels with the count.
    withHostsAndScope();
    renderPage();
    await analyse();
    await open();

    const row = (await screen.findByText('192.168.31.0/24')).closest('tr')!;
    expect(row.textContent).toMatch(/2 found/);
    expect(row.textContent).toMatch(/254 probed/);
  });

  test('a range nothing has swept says so instead of showing zero', async () => {
    /*
      The defect this exists for. 10.20.0.0/24 holds a discovered host in this
      fixture and still has no sweep scope — so even a count that happens to be
      non-zero must not be presented as a survey of that range.
    */
    withHostsAndScope();
    renderPage();
    await analyse();
    await open();

    const row = (await screen.findByText('10.20.0.0/24')).closest('tr')!;
    expect(row.textContent).toMatch(/not swept/);
    expect(row.textContent).not.toMatch(/found/);
  });

  test('a host is counted into one range only', async () => {
    // `192.168.31.10` and `10.20.0.9` share no prefix, but the rule that used to
    // decide this compared three octets as text, which merges a /25 pair and
    // splits a /16. The count is the first consumer routinely handed a prefix
    // that is not 24.
    withHostsAndScope();
    renderPage();
    await analyse();
    await open();

    const row = (await screen.findByText('192.168.31.0/24')).closest('tr')!;
    expect(row.textContent).toMatch(/2 found/);
    expect(row.textContent).not.toMatch(/3 found/);
  });

  test('the footnote says what the column counted', async () => {
    withHostsAndScope();
    renderPage();
    await analyse();
    await open();

    const footnote = await screen.findByText(/not read from any switch/i);
    expect(footnote.textContent).toMatch(/HOSTS counts what this sweep found/i);
    expect(footnote.textContent).toMatch(/rather than showing zero/i);
  });
});
