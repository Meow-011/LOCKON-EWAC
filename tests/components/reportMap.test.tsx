/**
 * The survey map in the Reports page.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * This is the other map, and it has carried defects the live one had already been
 * fixed for — twice. The heatmap weighted an access point with **no reading** at
 * the top of its scale, and the same heatmap was drawn *over* the uncertainty
 * rings so switching it on erased them. Both were corrected on the live map and
 * neither reached here for six phases, because the two were separate
 * implementations and nothing compared them.
 *
 * `check:map` now holds their layer definitions to each other. What it cannot see
 * is the data: which access points reach the source, with what properties, under
 * which filter. That is what this covers.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { act, render } from '@testing-library/react';

import { ReportMap } from '../../src/components/reports/ReportMap';
import { instances, resetMapStub } from './stubs/maplibre-gl';

const AP = (over: Record<string, unknown> = {}) => ({
  bssid: 'AA:BB:CC:DD:EE:01',
  ssid: 'TEST-NET',
  encryption: 'WPA2',
  rssi: -62,
  latitude: 13.7563,
  longitude: 100.5018,
  ...over,
});

const report = (aps: Record<string, unknown>[]) => ({
  id: 'WIFI-1',
  targetName: 'Test Survey',
  type: 'WIFI_WARDRIVE',
  timestamp: '2026-01-01T00:00:00Z',
  simulated: false,
  rawData: { accessPoints: aps, pathCoords: [[100.5, 13.75], [100.51, 13.76]] },
}) as any;

function mount(aps: Record<string, unknown>[], focusBssid: string | null = null) {
  render(<ReportMap report={report(aps)} focusBssid={focusBssid} />);
  const map = instances[0];
  // The component registers nothing until the style is ready, which in jsdom
  // only happens because the test says so.
  act(() => { map.emit('load'); });
  return map;
}

const apFeatures = (map: any) => map.record.data.get('aps-data')?.features ?? [];
const overlay = (map: any) => map.record.data.get('ap-uncertainty')?.features ?? [];
const mirrors = (map: any) => map.record.data.get('ap-mirror')?.features ?? [];

beforeEach(() => {
  resetMapStub();
});

describe('what reaches the map', () => {
  test('a mark carries the rule set\'s verdict, not the engine\'s boolean', () => {
    /*
      The report map was fixed for this first, under a comment reading "so a
      marker's colour and its row's severity cannot disagree". The assertion is
      here so that it stays true of this map too, not only of the live one.
    */
    const map = mount([AP({ encryption: 'WEP', is_vulnerable: false })]);
    expect(apFeatures(map)[0].properties.isHighRisk).toBe(true);
  });

  test('an access point with no reading is kept out of the heatmap', () => {
    // `interpolate` clamps outside its domain, so a null rssi would be weighted
    // at the *top* of the scale. This map carried that defect for six phases
    // after the live one was fixed.
    const map = mount([AP({ rssi: null })]);
    expect(apFeatures(map)[0].properties.hasReading).toBe(false);
  });

  test('a coordinate of exactly 0, 0 is an absent column, not the Atlantic', () => {
    const map = mount([AP({ latitude: 0, longitude: 0 })]);
    expect(apFeatures(map)).toHaveLength(0);
  });

  test('the equator is still a place', () => {
    const map = mount([AP({ latitude: 0, longitude: 100.5018 })]);
    expect(apFeatures(map)).toHaveLength(1);
  });
});

describe('the uncertainty overlay', () => {
  test('a stated radius becomes a ring', () => {
    const map = mount([AP({ location_error_m: 40 })]);
    const rings = overlay(map).filter((f: any) => f.properties.kind === 'ring');
    expect(rings).toHaveLength(1);
    expect(rings[0].geometry.type).toBe('Polygon');
  });

  test('this map draws every radius, however wide', () => {
    /*
      The one place the two maps legitimately differ, and the reason
      `uncertaintyFeatures` takes the limit as a parameter: the live map has every
      ring on screen at once and leaves the widest out, while this one has an
      OFF / HOVER / ALL control and can afford to draw them all.
    */
    const map = mount([AP({ location_error_m: 4000 })]);
    const rings = overlay(map).filter((f: any) => f.properties.kind === 'ring');
    expect(rings).toHaveLength(1);
  });

  test('an ambiguous access point gets a second candidate and a line, in their own source', () => {
    /*
      Separate from the rings so the ring control can filter one without the
      other. The line and the point are tagged by `kind`, which is what lets the
      circle layer avoid drawing a ring at every vertex of the line — a defect
      that existed while this map had its own inline builder with no such tag.
    */
    const map = mount([AP({
      location_error_m: 90,
      geometry_ambiguous: 1,
      location_mirror_lat: 13.7571,
      location_mirror_lon: 100.5018,
      location_mirror_distance_m: 89,
    })]);

    const kinds = mirrors(map).map((f: any) => f.properties.kind).sort();
    expect(kinds).toEqual(['link', 'mirror']);
    expect(overlay(map).every((f: any) => f.properties.kind === 'ring')).toBe(true);
  });

  test('a mirror flag with no stored coordinates draws no second candidate', () => {
    // The flag and the coordinates are independent columns; a flag on its own is
    // not a second position and must not become one.
    const map = mount([AP({ location_error_m: 90, geometry_ambiguous: 1 })]);
    expect(mirrors(map)).toHaveLength(0);
  });
});

describe('the track', () => {
  test('the route is drawn from the archive it belongs to', () => {
    const map = mount([AP()]);
    const path = map.record.data.get('gps-path');
    expect(path.geometry.coordinates).toHaveLength(2);
  });
});
