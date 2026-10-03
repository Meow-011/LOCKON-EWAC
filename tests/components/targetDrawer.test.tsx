/**
 * The drawer an operator opens before walking towards a radio.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * The DIRECTION dial is the most actionable thing in this application: it is read
 * by someone deciding which way to walk. Two of its claims were corrected without
 * any test behind them.
 *
 * Phase 22 found that for an access point no estimator could place, `ap.latitude`
 * is the *receiver's* own position — so the dial pointed at the operator's feet,
 * steadily, with a crisp bearing and nothing saying so. For a mirror-ambiguous
 * one it points at whichever of two equally good candidates the estimator
 * reported, and walking the wrong way is the entire cost of that ambiguity.
 *
 * Phase 30 found that the status dot, the warning paragraph and the **AUDIT
 * button** were gated on `ap.is_vulnerable` while the rest of the application
 * asked the rule set: the drawer refused to act on a radio the map was drawing in
 * red.
 *
 * Both fixes shipped with nothing checking them. This is that.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

import { TargetDrawer } from '../../src/components/dashboard/TargetDrawer';
import { useMissionStore } from '../../src/stores/missionStore';
import { useEngineStore } from '../../src/stores/engineStore';
import { useUIStore } from '../../src/stores/uiStore';

const BSSID = 'AA:BB:CC:DD:EE:01';

const AP = (over: Record<string, unknown> = {}) => ({
  bssid: BSSID,
  ssid: 'TEST-NET',
  encryption: 'WPA2',
  rssi: -62,
  latitude: 13.7563,
  longitude: 100.5018,
  location_resolved: true,
  ...over,
});

/** Open the drawer on one access point, with the receiver at a given fix. */
function mount(ap: Record<string, unknown>, ego: { lat: number | null; lon: number | null } = { lat: 13.7500, lon: 100.5000 }) {
  useMissionStore.setState({ accessPoints: new Map([[BSSID, ap as any]]) } as any);
  useEngineStore.setState({
    acceptedLatitude: ego.lat, acceptedLongitude: ego.lon, acceptedHeading: 0,
  } as any);
  useUIStore.setState({ selectedBssid: BSSID } as any);
  /*
    Inside a router, because the AUDIT control navigates to the intrusion page.
    That is the one thing this drawer does besides describe a radio, and a test
    that stubbed `useNavigate` away would stop covering the button it is here for.
  */
  return render(<MemoryRouter><TargetDrawer /></MemoryRouter>);
}

beforeEach(() => {
  useMissionStore.setState({ accessPoints: new Map() } as any);
  useUIStore.setState({ selectedBssid: null } as any);
});

describe('the DIRECTION dial', () => {
  test('an unresolved radio is told to the operator as not a bearing', () => {
    /*
      `ap.latitude` for an unresolved access point is the receiver's own
      position, so the arrow points at the operator's feet. It did that silently.
    */
    mount(AP({ location_resolved: false }));

    expect(screen.getByText(/NOT A BEARING/)).toBeTruthy();
    expect(screen.getByText(/points at\s+where it was heard from/)).toBeTruthy();
  });

  test('an ambiguous radio says the dial is one of two directions', () => {
    mount(AP({
      geometry_ambiguous: 1,
      location_mirror_lat: 13.7571,
      location_mirror_lon: 100.5018,
      location_mirror_distance_m: 89,
    }));

    expect(screen.getByText(/1 OF 2 DIRECTIONS/)).toBeTruthy();
    expect(screen.getByText(/89 m away/)).toBeTruthy();
  });

  test('a resolved, unambiguous radio is not qualified at all', () => {
    // The caveats have to be absent when they do not apply, or they stop being
    // read when they do.
    mount(AP({ location_error_m: 30 }));

    expect(screen.queryByText(/NOT A BEARING/)).toBeNull();
    expect(screen.queryByText(/1 OF 2 DIRECTIONS/)).toBeNull();
  });

  test('a missing receiver fix and a missing radio position are different problems', () => {
    /*
      One is solved by waiting for satellites and the other by driving, and both
      were shown as "NO GPS FIX" until Phase 22.
    */
    const { unmount } = mount(AP(), { lat: null, lon: null });
    expect(screen.getByText('NO GPS FIX')).toBeTruthy();
    unmount();

    mount(AP({ latitude: null, longitude: null }));
    expect(screen.getByText('NO POSITION FOR THIS RADIO')).toBeTruthy();
  });

  test('the equator is a place, not a missing fix', () => {
    // `!latitude || !longitude` hid the dial on the equator and the prime
    // meridian; `coordinatePair` is the one rule, and only exactly 0, 0 is absent.
    mount(AP({ latitude: 0, longitude: 100.5018 }), { lat: 0, lon: 100.49 });

    expect(screen.queryByText('NO GPS FIX')).toBeNull();
    expect(screen.queryByText('NO POSITION FOR THIS RADIO')).toBeNull();
  });
});

describe('the AUDIT control', () => {
  test('it is offered for a radio the rule set rates high, with no engine flag', () => {
    /*
      The defect, as it reached an operator: the map draws the WEP network in red,
      the drawer shows a green dot and the button that would act on it is
      disabled.
    */
    mount(AP({ encryption: 'WEP', is_vulnerable: false }));

    const button = screen.getByRole('button', { name: /LAN AUDIT/i });
    expect((button as HTMLButtonElement).disabled).toBe(false);
  });

  test('it is withheld for a radio the rule set does not, and says SECURE', () => {
    /*
      The label changes with the verdict, so this asserts both. A button reading
      SECURE is a claim about the radio, and it was being made from a boolean the
      engine happened to set rather than from the rule set that produces every
      other severity in the document.
    */
    mount(AP({ encryption: 'WPA3' }));

    const button = screen.getByRole('button', { name: /SECURE/i });
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(screen.queryByText(/LAN AUDIT/)).toBeNull();
  });

  test('a WEP radio is not labelled SECURE', () => {
    // The inverse of the above, and the one that was actually wrong: the drawer
    // called a WEP network secure because `is_vulnerable` had not been set.
    mount(AP({ encryption: 'WEP', is_vulnerable: false }));
    expect(screen.queryByText(/SECURE/)).toBeNull();
  });
});
