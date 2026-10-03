/**
 * What a popup on either map tells the operator.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * There are six popup builders across the two maps and until now **none of them
 * had a single assertion**. The only mention of `setHTML` anywhere in `tests/`
 * was a sentence in a comment. They were untestable for one reason: the real
 * MapLibre needs WebGL, jsdom has none, so the pages holding a map could not be
 * rendered at all — which is why this is the first file to use the stub.
 *
 * A popup is where this application makes its most specific claims to an
 * operator: this radio is here, to within this radius, and there is or is not a
 * second position that fits equally well. Two defects were found in these
 * builders this session by reading them, which is not a method that scales.
 *
 * What the stub can and cannot say.
 *
 * It records the HTML each popup was given. So these tests assert what the
 * component *said*, which is the part that can be wrong in a way that matters.
 * Whether it then appears, where, and in a readable colour is not knowable in
 * jsdom and is not claimed here.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { act, render } from '@testing-library/react';

import { MapView } from '../../src/components/dashboard/MapView';
import { useMissionStore } from '../../src/stores/missionStore';
import { instances, popups, resetMapStub } from './stubs/maplibre-gl';
import { whenInvoke } from './stubs/api-core';

const AP = (over: Record<string, unknown> = {}) => ({
  bssid: 'AA:BB:CC:DD:EE:01',
  ssid: 'TEST-NET',
  encryption: 'WPA2',
  vendor: 'Acme',
  rssi: -62,
  latitude: 13.7563,
  longitude: 100.5018,
  location_resolved: true,
  ...over,
});

/**
 * Render the live map with one access point in the store.
 *
 * `load` has to be fired by hand. The component draws nothing until the style is
 * ready -- deliberately, because MapLibre does not fire `load` when the style
 * request fails and the map is written around that -- so in jsdom, where no
 * network and no renderer exist, nothing is ever registered unless the test says
 * the style arrived. That is the stub earning its place rather than a limitation:
 * the same handle lets the fallback tests say the style *failed*.
 */
function mountWith(ap: Record<string, unknown>) {
  useMissionStore.setState({ accessPoints: new Map([[String(ap.bssid), ap as any]]) } as any);
  render(<MapView />);
  const map = instances[0];
  act(() => { map.emit('load'); });
  return map;
}

/**
 * Hover a plotted mark.
 *
 * The handler reads `e.features[0]`, which is what MapLibre hands it, so the
 * feature is taken from what the component actually pushed into the source
 * rather than invented here — a hand-written feature would test the test.
 */
function hoverFirstMark(map: any) {
  const data = map.record.data.get('aps-data');
  expect(data, 'nothing was pushed into aps-data').toBeTruthy();
  const feature = data.features[0];
  expect(feature, 'no access point reached the map').toBeTruthy();
  map.emit('mouseenter:aps-low-risk', { features: [feature], lngLat: { lng: 100.5, lat: 13.75 } });
  map.emit('mouseenter:aps-high-risk', { features: [feature], lngLat: { lng: 100.5, lat: 13.75 } });
  return popups[popups.length - 1];
}

beforeEach(() => {
  resetMapStub();
  whenInvoke('basemap_status', () => ({ installed: false, path: 'x', size_bytes: 0 }));
  useMissionStore.setState({ accessPoints: new Map(), pathCoords: [] } as any);
});

describe('the live map popup', () => {
  test('a reading that does not exist is n/r, never a number', async () => {
    /*
      `escapeHtml` maps null to the empty string, so an unguarded
      `${escapeHtml(props.rssi)} dBm` renders " dBm" — a blank where a
      measurement goes. The report's map had exactly that until this session.
    */
    const map = mountWith(AP({ rssi: null }));
    const popup = hoverFirstMark(map);
    expect(popup.html).toContain('n/r');
    expect(popup.html).not.toMatch(/>\s*dBm/);
  });

  test('a position with no stated radius says so rather than leaving a gap', () => {
    const map = mountWith(AP({ location_error_m: null }));
    const popup = hoverFirstMark(map);
    expect(popup.html).toContain('no stated radius');
  });

  test('a radius is printed with the estimator that produced it', () => {
    const map = mountWith(AP({ location_error_m: 42, location_method: 'bayesian_grid' }));
    const popup = hoverFirstMark(map);
    expect(popup.html).toMatch(/42 m/);
    expect(popup.html).toMatch(/Bayesian/i);
  });

  test('an ambiguous position says it is one of two, and how far apart', () => {
    /*
      The number that tells a reader what the ambiguity costs. Saying there are
      two candidates without saying they are ninety metres apart is the version
      the report's popup shipped with.
    */
    const map = mountWith(AP({
      location_error_m: 95,
      geometry_ambiguous: 1,
      location_mirror_lat: 13.7571,
      location_mirror_lon: 100.5018,
      location_mirror_distance_m: 89,
    }));
    const popup = hoverFirstMark(map);
    expect(popup.html).toMatch(/1 of 2/);
    expect(popup.html).toMatch(/89 m apart/);
  });

  test('an SSID cannot close a tag', () => {
    // MapLibre's `setHTML` assigns to `innerHTML`, and an SSID is chosen by
    // whoever owns the access point.
    const map = mountWith(AP({ ssid: '</div><script>x</script>' }));
    const popup = hoverFirstMark(map);
    expect(popup.html).not.toContain('<script>');
    expect(popup.html).toContain('&lt;script&gt;');
  });
});

describe('what reaches the map at all', () => {
  test('an unresolved access point is not plotted as a position', () => {
    /*
      It is grouped into a counted marker instead, because every unresolved
      estimate lands on the receiver and drawing them individually stacks them
      into one pile that still reads as N separate places.
    */
    const map = mountWith(AP({ location_resolved: false }));
    const data = map.record.data.get('aps-data');
    expect(data.features).toHaveLength(0);
  });

  test('the dot carries the rule set\'s verdict, not the engine\'s boolean', () => {
    /*
      A WEP network is CRITICAL to the rule set whether or not `is_vulnerable` was
      set. This map asked the boolean until Phase 24, so the mark was green here
      and red in the document made from the same survey.
    */
    const map = mountWith(AP({ encryption: 'WEP', is_vulnerable: false }));
    const feature = map.record.data.get('aps-data').features[0];
    expect(feature.properties.isHighRisk).toBe(true);
  });

  test('an access point with no reading is kept out of the heatmap', () => {
    // `interpolate` clamps outside its domain, so a null rssi would be weighted
    // at the *top* of the scale — the brightest thing on a map of signal strength.
    const map = mountWith(AP({ rssi: null }));
    const feature = map.record.data.get('aps-data').features[0];
    expect(feature.properties.hasReading).toBe(false);
  });

  test('a coordinate of exactly 0, 0 is an absent column, not the Atlantic', () => {
    const map = mountWith(AP({ latitude: 0, longitude: 0 }));
    const uncertainty = map.record.data.get('ap-uncertainty');
    expect(uncertainty?.features ?? []).toHaveLength(0);
  });
});
