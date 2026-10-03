/**
 * What the map does when the basemap does not arrive.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * Four paths lead to a degraded basemap and none of them had a test: a start with
 * no network, a style-level failure, a source-level failure with a grace period,
 * and a watchdog for a request that hangs instead of failing. They are the paths
 * taken in exactly the conditions this tool is built for — a rig in a dead spot,
 * a captive portal, no connection at all — and they were verified by opening the
 * application somewhere with bad signal.
 *
 * They were untestable because they are driven by MapLibre events that never
 * arrive in jsdom and by timers. With a stub that records calls and lets a test
 * fire `error` by hand, and vitest's fake clock, they are ordinary assertions.
 *
 * The property that matters most is the one in the banner's second line:
 * **a degraded basemap must never imply the scan has failed.** The map is the
 * only thing that broke; the contacts, the track and the recording are untouched.
 * An operator who reads "BASEMAP DEGRADED" and stops surveying has been misled by
 * this application, which is the specific harm these paths exist to avoid.
 */
import { describe, expect, test, beforeEach, afterEach, vi } from 'vitest';
import { act, render, screen } from '@testing-library/react';

import { MapView } from '../../src/components/dashboard/MapView';
import { useMissionStore } from '../../src/stores/missionStore';
import { instances, resetMapStub } from './stubs/maplibre-gl';
import { whenInvoke } from './stubs/api-core';

function mount() {
  render(<MapView />);
  return instances[0];
}

/** The style the map is currently showing, as the stub recorded it. */
const currentStyle = (map: any) => map.record.styles[map.record.styles.length - 1];

beforeEach(() => {
  resetMapStub();
  whenInvoke('basemap_status', () => ({ installed: false, path: 'x', size_bytes: 0 }));
  useMissionStore.setState({ accessPoints: new Map(), pathCoords: [] } as any);
  // `navigator.onLine` is a hint the component reads for its starting choice.
  Object.defineProperty(window.navigator, 'onLine', { value: true, configurable: true });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('a style that will never load', () => {
  test('an error with no sourceId falls back immediately', () => {
    /*
      No `sourceId` means the failure is the style document, the sprite or the
      glyphs — the style will never load, so `load` will never fire, so waiting
      achieves nothing. This is the one path that must not be given a grace
      period: the operator would stare at a blank panel for it.
    */
    const map = mount();
    const before = map.record.styles.length;
    act(() => { map.emit('error', { error: new Error('style 404') }); });

    expect(map.record.styles.length).toBeGreaterThan(before);
    expect(screen.getByText(/BASEMAP DEGRADED/)).toBeTruthy();
  });

  test('the banner states that the survey is unaffected', () => {
    // The whole point of the banner. A degraded basemap is a broken picture, not
    // a broken scan, and an operator who stops surveying has been misled.
    const map = mount();
    act(() => { map.emit('error', { error: new Error('style 404') }); });

    expect(screen.getByText(/Scanning, GPS logging and recording are UNAFFECTED/)).toBeTruthy();
  });

  test('the data layers are registered onto the replacement style', () => {
    /*
      The reason the registration lives in a named function rather than inside a
      `load` handler: a style swap drops every source the application owns, and
      the failed style never fired `load` in the first place. Trapping it in
      `load` left the operator with a working grid and no track or contacts on it.
    */
    const map = mount();
    act(() => { map.emit('error', { error: new Error('style 404') }); });
    act(() => { map.emit('styledata'); });

    expect(map.record.sources.has('aps-data')).toBe(true);
    expect(map.record.sources.has('gps-path')).toBe(true);
  });
});

describe('a source that fails', () => {
  test('one bad tile does not drop a working basemap', () => {
    /*
      A source-level error before the layers exist gets 1.5 seconds, because a
      single unreachable tile is not a reason to abandon a basemap that is
      otherwise fine.
    */
    vi.useFakeTimers();
    const map = mount();
    const before = map.record.styles.length;

    act(() => { map.emit('error', { sourceId: 'carto', error: new Error('tile 503') }); });
    act(() => { vi.advanceTimersByTime(1000); });
    expect(map.record.styles.length).toBe(before);

    // And if the style comes good inside the grace period, nothing is swapped.
    act(() => { map.emit('load'); });
    act(() => { vi.advanceTimersByTime(2000); });
    expect(map.record.styles.length).toBe(before);
  });

  test('a source that is still failing after the grace period is given up on', () => {
    vi.useFakeTimers();
    const map = mount();
    const before = map.record.styles.length;

    act(() => { map.emit('error', { sourceId: 'carto', error: new Error('tile 503') }); });
    act(() => { vi.advanceTimersByTime(2000); });

    expect(map.record.styles.length).toBeGreaterThan(before);
  });
});

describe('a request that hangs', () => {
  test('the watchdog fires when nothing fails and nothing loads', () => {
    /*
      A captive portal answers the request and never completes it, so no `error`
      arrives and `load` never fires. Without the watchdog the panel stays blank
      for ever, which looks like the application has crashed.
    */
    vi.useFakeTimers();
    const map = mount();
    const before = map.record.styles.length;

    act(() => { vi.advanceTimersByTime(9000); });

    expect(map.record.styles.length).toBeGreaterThan(before);
    expect(screen.getByText(/BASEMAP DEGRADED/)).toBeTruthy();
  });

  test('a map that loaded in time is not taken away from the operator', () => {
    vi.useFakeTimers();
    const map = mount();
    act(() => { map.emit('load'); });
    const after = map.record.styles.length;

    act(() => { vi.advanceTimersByTime(9000); });

    expect(map.record.styles.length).toBe(after);
    expect(screen.queryByText(/BASEMAP DEGRADED/)).toBeNull();
  });
});

describe('once the layers exist', () => {
  test('a later tile error is reported without swapping the style', () => {
    /*
      After registration, a tile error means patchy imagery over a basemap that is
      otherwise working. Swapping to the offline grid at that point would take a
      better map away from the operator to tell them about a worse problem.
    */
    const map = mount();
    act(() => { map.emit('load'); });
    const after = map.record.styles.length;

    act(() => { map.emit('error', { sourceId: 'carto', error: new Error('tile 503') }); });

    expect(map.record.styles.length).toBe(after);
    expect(screen.getByText(/imagery may be incomplete/i)).toBeTruthy();
  });
});
