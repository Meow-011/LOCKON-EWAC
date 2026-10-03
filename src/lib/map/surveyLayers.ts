/**
 * The layers both maps draw, defined once.
 *
 * Why this exists.
 *
 * There are two MapLibre maps in this application: the live tactical map on the
 * dashboard and the interactive survey map in the Reports page. They draw the
 * same track, the same access-point dots and the same heatmap from sources with
 * the same names, and until now they did it with two sets of definitions three
 * thousand lines apart.
 *
 * That cost something three times, and `npm run check:map` exists because of it:
 *
 *   * the heatmap weighted an access point with **no reading** at the top of its
 *     scale, because `interpolate` clamps outside its domain and `['get','rssi']`
 *     yields null for a radio whose signal was never recorded. Fixed on the live
 *     map; the report's map kept it for six phases, in the figure that goes into
 *     the document;
 *   * the same heatmap was inserted *over* the uncertainty rings rather than
 *     under them, so switching it on erased the overlay. Same fix, same gap;
 *   * the track line drifted to `line-opacity` 0.9 on one map and 0.8 on the
 *     other **inside a single change**, because one edit touched both files by
 *     hand.
 *
 * What is here and what is not.
 *
 * This owns the sources and layers that are genuinely the same question: the
 * track, the access-point dots, the heatmap and the terrain. It does not own the
 * uncertainty overlay, which is the one place the two maps legitimately differ --
 * the live map has every ring on screen at once and leaves the widest out, while
 * the report has an OFF / HOVER / ALL control and can afford a fill. Nor does it
 * own interaction: filters, auto-follow, the vehicle, fitBounds and the popups
 * belong to whichever map has them.
 *
 * Every call is idempotent. A style swap silently drops every source a map owns,
 * both maps re-register on `styledata`, and `addSource` re-fires it -- so these
 * are written to be safe to call again rather than guarded at each call site,
 * which is how one of the two maps ended up with `if (!map.getSource(...))` on
 * every line and the other with none.
 */
import type maplibregl from 'maplibre-gl';

import { MAP_TERRAIN_TILES } from '../constants';

/** Where the dots sit relative to everything else, by layer id. */
export const AP_LAYERS = ['aps-low-risk', 'aps-high-risk'] as const;

/**
 * The track the receiver actually travelled.
 *
 * One line. There was a 4px line with a 12px blurred copy beneath it at 0.2
 * opacity, which on a dark basemap spread the route into a soft band several
 * times its own width -- a width that means nothing, on a map whose entire
 * subject is where things are.
 */
export function addTrackLayers(map: maplibregl.Map): void {
  if (!map.getSource('gps-path')) {
    map.addSource('gps-path', {
      type: 'geojson',
      data: {
        type: 'Feature',
        properties: {},
        geometry: { type: 'LineString', coordinates: [] },
      },
    });
  }
  if (!map.getLayer('gps-path-line')) {
    map.addLayer({
      id: 'gps-path-line',
      type: 'line',
      source: 'gps-path',
      layout: { 'line-join': 'round', 'line-cap': 'round' },
      paint: {
        'line-color': '#38bdf8',   // neon-400
        'line-width': 3,
        'line-opacity': 0.9,
      },
    });
  }
}

/** The access-point source. Separate because both maps fill it differently. */
export function addApSource(map: maplibregl.Map): void {
  if (!map.getSource('aps-data')) {
    map.addSource('aps-data', { type: 'geojson', data: { type: 'FeatureCollection', features: [] } });
  }
}

/**
 * The dots, which shrink out of the way when the heatmap is on.
 *
 * `beforeId` is how each map decides what the dots sit above: they are the last
 * thing registered on the live map and are inserted under the mirror layers on
 * the report's, and in both the dots must stay on top of their own rings.
 */
export function addApLayers(map: maplibregl.Map, { heatmap }: { heatmap: boolean }): void {
  if (!map.getLayer('aps-low-risk')) {
    map.addLayer({
      id: 'aps-low-risk',
      type: 'circle',
      source: 'aps-data',
      filter: ['!=', ['get', 'isHighRisk'], true],
      paint: {
        'circle-color': '#10b981',   // risk-low
        'circle-radius': heatmap ? 2 : 5,
        'circle-opacity': heatmap ? 0.2 : 0.6,
        'circle-stroke-width': heatmap ? 0 : 1,
        'circle-stroke-color': '#064e3b',
      },
    });
  }
  if (!map.getLayer('aps-high-risk')) {
    map.addLayer({
      id: 'aps-high-risk',
      type: 'circle',
      source: 'aps-data',
      filter: ['==', ['get', 'isHighRisk'], true],
      paint: {
        'circle-color': '#ef4444',   // risk-critical
        'circle-radius': heatmap ? 3 : 7,
        'circle-opacity': heatmap ? 0.4 : 0.9,
        'circle-stroke-width': heatmap ? 0 : 1.5,
        'circle-stroke-color': '#7f1d1d',
      },
    });
  }
}

/**
 * Density of estimated transmitter positions, shaded by their reading.
 *
 * Two things here are corrections rather than style, and both took six phases to
 * reach the second map:
 *
 * `filter` --- the weight interpolates `rssi` over -100..-40 dBm and
 * `interpolate` clamps outside its domain, so an access point with no reading was
 * clamped to the *top* of the scale and drawn as the brightest thing on a map of
 * signal strength. Filtered rather than coalesced to -100, because substituting
 * the floor is the same invention in the other direction: a density shaded by
 * reading strength has nothing to say about a sighting that carries no reading.
 *
 * `beforeId` --- it must sit below the uncertainty overlay and not merely below
 * the dots. At `heatmap-opacity: 0.8` anything above the rings erases them, and
 * the dots survive because they are drawn higher still, so the one thing left
 * visible is the confident mark.
 */
export function addHeatmapLayer(map: maplibregl.Map, beforeId: string): void {
  if (map.getLayer('aps-heatmap')) return;
  map.addLayer({
    id: 'aps-heatmap',
    type: 'heatmap',
    source: 'aps-data',
    maxzoom: 18,
    filter: ['==', ['get', 'hasReading'], true],
    paint: {
      'heatmap-weight': ['interpolate', ['linear'], ['get', 'rssi'], -100, 0, -40, 1],
      'heatmap-intensity': ['interpolate', ['linear'], ['zoom'], 11, 1, 15, 3],
      'heatmap-color': ['interpolate', ['linear'], ['heatmap-density'], 0, 'rgba(0, 0, 255, 0)', 0.2, 'royalblue', 0.4, 'cyan', 0.6, 'lime', 0.8, 'yellow', 1, 'red'],
      'heatmap-radius': ['interpolate', ['linear'], ['zoom'], 11, 15, 15, 30],
      'heatmap-opacity': 0.8,
    },
  }, map.getLayer(beforeId) ? beforeId : undefined);
}

/**
 * 3D terrain, and the symbol layers it forces off.
 *
 * Skipped entirely while the basemap is degraded: the terrain tiles are remote
 * too, so requesting them when the network is already known to be unavailable
 * only produces more failed requests.
 *
 * Hiding the symbol layers is not cosmetic -- MapLibre warns "Too many glyphs"
 * and drops labels unpredictably in 3D, so they are turned off deliberately
 * rather than left to fail.
 */
export function addTerrain(map: maplibregl.Map): void {
  if (!map.getSource('terrain')) {
    map.addSource('terrain', {
      type: 'raster-dem',
      tiles: [...MAP_TERRAIN_TILES],
      encoding: 'terrarium',
      tileSize: 256,
      maxzoom: 14,
    });
  }
  map.setTerrain({ source: 'terrain', exaggeration: 1.5 });

  const style = map.getStyle();
  if (style && style.layers) {
    for (const layer of style.layers) {
      if (layer.type !== 'symbol') continue;
      try {
        map.setLayoutProperty(layer.id, 'visibility', 'none');
      } catch {
        // Some internal layers refuse a layout property; losing one label is not
        // worth failing the whole registration for.
      }
    }
  }
}
