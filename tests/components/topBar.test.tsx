/**
 * The bar that says where the rig is and what it is doing.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * It holds the coordinate readout, which Phase 22 found printing
 * `${latitude.toFixed(4)}°N ${longitude.toFixed(4)}°E` with the hemisphere
 * letters written in — so a fix south of the equator or west of Greenwich read as
 * **"-13.7563°N"**, a minus sign and a letter saying opposite things, in the
 * figure an operator checks most often. The offline-basemap card had been fixed
 * for exactly that and the fix did not travel, because each surface had its own
 * formatter.
 *
 * `degreesWithHemisphere` is covered by `tests/numbers.test.mjs`. What was not
 * covered is that this bar uses it, and the distinction matters: the defect was
 * never in the formatting, it was in a surface not calling one.
 *
 * The scan controls are here too. They send commands to the sidecar, and the
 * thing worth pinning is which command — stopping a scan and starting one are not
 * recoverable from each other by an operator watching a progress bar.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

import { TopBar } from '../../src/components/layout/TopBar';
import { useEngineStore } from '../../src/stores/engineStore';
import { useMissionStore } from '../../src/stores/missionStore';
import { engineIPC } from '../../src/lib/ipc';

/** Commands sent to the sidecar during one test. */
let sent: { cmd: string; data?: unknown }[] = [];

/**
 * Render the bar.
 *
 * `mission` matters: the scan controls and the WPS button live inside
 * `{activeMission ? ...}`, so without one the bar offers only "Start Scan" and
 * the archive. That is the component's own rule -- those controls belong to a
 * mission -- and encoding it here keeps the tests from asserting against a state
 * the application never shows.
 */
function mount(engine: Record<string, unknown> = {}, mission: unknown = null) {
  useEngineStore.setState({
    connected: true, scanning: false, gpsLocked: false,
    latitude: null, longitude: null,
    ...engine,
  } as any);
  useMissionStore.setState({ activeMission: mission, elapsedSeconds: 0, totalAPs: 0 } as any);
  return render(<MemoryRouter><TopBar /></MemoryRouter>);
}

const MISSION = { id: 1, name: 'TEST MISSION' };

beforeEach(() => {
  sent = [];
  (engineIPC as unknown as { send: unknown }).send = async (cmd: string, data?: unknown) => {
    sent.push({ cmd, data });
  };
  useMissionStore.setState({ activeMission: null, elapsedSeconds: 0, totalAPs: 0 } as any);
});

describe('the coordinate readout', () => {
  test('a southern, western fix is not printed with N and E', () => {
    /*
      The defect exactly: `-13.7563°N` is a minus sign and a hemisphere letter
      contradicting each other. Sydney and New York are the two cases that catch
      each axis.
    */
    mount({ gpsLocked: true, latitude: -33.8688, longitude: 151.2093 });
    expect(screen.getByText(/33\.8688°S/)).toBeTruthy();
    expect(screen.queryByText(/-33/)).toBeNull();
  });

  test('a western longitude is W, not a negative E', () => {
    mount({ gpsLocked: true, latitude: 40.7128, longitude: -74.006 });
    expect(screen.getByText(/74\.0060°W/)).toBeTruthy();
    expect(screen.queryByText(/-74/)).toBeNull();
  });

  test('the readout is absent until there is a fix', () => {
    // Not a zero, not a placeholder: "we do not know yet" shown as nothing.
    mount({ gpsLocked: true, latitude: null, longitude: null });
    expect(screen.queryByText(/°[NSEW]/)).toBeNull();
  });

  test('exactly 0, 0 is an absent fix and the equator is not', () => {
    /*
      `coordinatePair` decides, through `formatFix`, so this bar and the map agree
      about which pairs are positions.
    */
    const { unmount } = mount({ gpsLocked: true, latitude: 0, longitude: 0 });
    expect(screen.queryByText(/°[NSEW]/)).toBeNull();
    unmount();

    mount({ gpsLocked: true, latitude: 0, longitude: 100.5018 });
    expect(screen.getByText(/0\.0000°N/)).toBeTruthy();
  });
});

describe('the engine state', () => {
  test('each of the three states is named', () => {
    const cases: [Record<string, unknown>, string][] = [
      [{ connected: true, scanning: true }, 'SCANNING'],
      [{ connected: true, scanning: false }, 'READY'],
      [{ connected: false }, 'OFFLINE'],
    ];
    for (const [state, label] of cases) {
      const { unmount } = mount(state);
      expect(screen.getByText(label), label).toBeTruthy();
      unmount();
    }
  });
});

describe('the scan controls', () => {
  test('pausing a running scan sends stop_scan, and not a fresh start', () => {
    /*
      The two are not recoverable from each other by an operator watching the
      screen: a pause that silently started a new scan would overwrite the mission
      they were about to archive.
    */
    mount({ scanning: true }, MISSION);
    fireEvent.click(screen.getByRole('button', { name: /Pause/i }));

    expect(sent.map(s => s.cmd)).toContain('stop_scan');
    expect(sent.map(s => s.cmd)).not.toContain('start_scan');
  });

  test('resuming sends start_scan, and not a stop', () => {
    mount({ scanning: false }, MISSION);
    fireEvent.click(screen.getByRole('button', { name: /Resume/i }));

    expect(sent.map(s => s.cmd)).toContain('start_scan');
    expect(sent.map(s => s.cmd)).not.toContain('stop_scan');
  });

  test('the WPS scan is offered with what it cannot do stated', () => {
    /*
      WPS is read from the beacon information element, which needs monitor mode.
      Without it the engine reports the scan **inconclusive** rather than "no WPS
      found", and the control says so before it is pressed — an absence reported
      as a clean result is the one thing this project refuses.

      It is also the control that was missing entirely: `scan_wps` sat in the
      engine and in the command union with nothing sending it, which is why
      `wps_enabled` was never populated and the report described a beacon parse
      that had never run.
    */
    mount({ scanning: false }, MISSION);
    const wps = screen.getByRole('button', { name: /Scan WPS/i });
    expect(wps.getAttribute('title')).toMatch(/monitor-mode adapter/i);
    expect(wps.getAttribute('title')).toMatch(/inconclusive/i);
  });

  test('the controls belong to a mission, and are absent without one', () => {
    // Not an oversight: there is nothing to pause and nothing to record a WPS
    // result against until a mission is running.
    mount({ scanning: false }, null);
    expect(screen.queryByRole('button', { name: /Scan WPS/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /Pause/i })).toBeNull();
  });
});
