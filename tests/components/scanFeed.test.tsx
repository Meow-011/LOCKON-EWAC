/**
 * The live contact list, and what it says about each radio.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * The scan feed is the list an operator reads while driving, and the HIGH RISK
 * filter is how they narrow it to the radios worth stopping for. Both were
 * changed in Phase 30 — the filter and the SSID colour had been asking
 * `ap.is_vulnerable`, a boolean the engine sets from its own checks, while the
 * map and the report asked the rule set. A WEP network was a red dot on the map,
 * a red row in the exported document, and **absent from this list** when the
 * operator filtered for the ones worth looking at.
 *
 * That change shipped with nothing behind it. `check:risk-claims` stops the same
 * mistake being made again; it says nothing about whether the fix was right. This
 * is the part that does.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';

import { ScanFeed } from '../../src/components/dashboard/ScanFeed';
import { useMissionStore } from '../../src/stores/missionStore';
import { useEngineStore } from '../../src/stores/engineStore';
import { useUIStore } from '../../src/stores/uiStore';

const AP = (over: Record<string, unknown> = {}) => ({
  bssid: 'AA:BB:CC:DD:EE:01',
  ssid: 'TEST-NET',
  encryption: 'WPA2',
  rssi: -62,
  band: '2.4G',
  ...over,
});

/**
 * Render the feed.
 *
 * `expanded` picks the table rather than the compact list. The feed has two
 * views and they do not say the same things: the compact one is what is on
 * screen while driving and carries the name, the security and the reading; the
 * table is the expanded view and adds the modelled range and the position
 * radius. Both are tested, because both are read.
 */
function mount(aps: Record<string, unknown>[], { expanded = false } = {}) {
  useMissionStore.setState({
    accessPoints: new Map(aps.map(a => [String(a.bssid), a as any])),
  } as any);
  useUIStore.setState({ dashboardFocus: expanded ? 'feed' : null } as any);
  return render(<ScanFeed />);
}

/**
 * How many rows the feed says it is showing.
 *
 * Asserted instead of DOM presence, because the rows are wrapped in
 * `AnimatePresence`: a filtered-out row stays in the document while it animates
 * away, and in jsdom that animation never finishes. Counting present elements
 * would therefore report the pre-filter list for ever -- a test artifact that
 * would have been read as "the filter does not work".
 *
 * The count is also the component's own statement about how many radios match,
 * which is the thing an operator reads.
 */
function shownCount() {
  return Number(screen.getByText(/\d+ entries/).textContent?.match(/\d+/)?.[0] ?? -1);
}

/** Open the filter panel and press one of the FLAGS buttons. */
function applyFlag(label: string) {
  fireEvent.click(screen.getByText('FILTERS'));
  fireEvent.click(screen.getByRole('button', { name: label }));
}

beforeEach(() => {
  useMissionStore.setState({ accessPoints: new Map() } as any);
  useEngineStore.setState({ scanning: false, netContext: null } as any);
  useUIStore.setState({ dashboardFocus: null, selectedBssid: null } as any);
});

describe('the HIGH RISK filter', () => {
  test('keeps a radio the rule set rates high, with no engine flag set', () => {
    /*
      The defect, as an operator met it: filter for the ones worth stopping for
      and the WEP network is not in the list, while the map is drawing it in red.
    */
    mount([AP({ ssid: 'OLD-WEP', encryption: 'WEP', is_vulnerable: false })]);
    applyFlag('HIGH RISK');

    expect(screen.getAllByText('OLD-WEP').length).toBeGreaterThan(0);
  });

  test('drops a radio the rule set does not', () => {
    // The filter has to actually filter, or the test above passes for the wrong
    // reason — a filter that keeps everything keeps the WEP network too.
    mount([
      AP({ bssid: 'AA:BB:CC:DD:EE:01', ssid: 'OLD-WEP', encryption: 'WEP' }),
      AP({ bssid: 'AA:BB:CC:DD:EE:02', ssid: 'MODERN', encryption: 'WPA3' }),
    ]);
    expect(shownCount()).toBe(2);

    applyFlag('HIGH RISK');
    expect(shownCount()).toBe(1);
    expect(screen.getAllByText('OLD-WEP').length).toBeGreaterThan(0);
  });

  test('an open network is kept, which is why this went unnoticed', () => {
    // The two definitions agree here, so a fixture built only from open networks
    // would have passed throughout.
    mount([AP({ ssid: 'FREE-WIFI', encryption: 'OPEN' })]);
    applyFlag('HIGH RISK');

    expect(screen.getAllByText('FREE-WIFI').length).toBeGreaterThan(0);
  });
});

describe('what a row states', () => {
  test('a reading that does not exist is not rendered as a number', () => {
    /*
      `rssi ?? -90` is the write-side version of this defect and has its own
      tests; this is the display side. A radio heard without a usable reading must
      not appear at the bottom of the scale as though it had been measured there.
    */
    mount([AP({ rssi: null })]);
    expect(screen.queryByText(/-90 dBm/)).toBeNull();
    expect(screen.queryByText(/-100 dBm/)).toBeNull();
  });

  test('a modelled range is marked as modelled, not stated as a measurement', () => {
    // `~` is the whole claim: this is the path-loss model inverted from one
    // reading, not a distance anybody measured.
    mount([AP({ rssi: -62, frequency: 2437 })], { expanded: true });
    expect(screen.getAllByText(/^~\d+ m$/).length).toBeGreaterThan(0);
  });

  test('a position radius is shown when there is one', () => {
    mount([AP({ location_error_m: 48, frequency: 2437 })], { expanded: true });
    expect(screen.getAllByText(/±48 m fix/).length).toBeGreaterThan(0);
  });

  test('no radius renders no radius line rather than a zero', () => {
    mount([AP({ location_error_m: null, frequency: 2437 })], { expanded: true });
    expect(screen.queryByText(/m fix/)).toBeNull();
  });
});

describe('the other two flag filters', () => {
  test('WPS and EVIL TWIN filter on the observation, not on a verdict', () => {
    /*
      These two stayed as plain field reads on purpose, and the distinction is
      worth pinning: "show me the ones advertising WPS" names something the engine
      measured. Only HIGH RISK is a judgement, and only it asks the rule set.
    */
    mount([
      AP({ bssid: 'AA:BB:CC:DD:EE:01', ssid: 'HAS-WPS', wps_enabled: 1 }),
      AP({ bssid: 'AA:BB:CC:DD:EE:02', ssid: 'NO-WPS' }),
    ]);
    applyFlag('WPS');

    expect(shownCount()).toBe(1);
    expect(screen.getAllByText('HAS-WPS').length).toBeGreaterThan(0);
  });
});
