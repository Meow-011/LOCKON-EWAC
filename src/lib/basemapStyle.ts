/**
 * The MapLibre style for the offline basemap.
 *
 * Everything it names is inside the application: the tiles come from the
 * installed PMTiles archive through the `pmtiles://` protocol, and the label
 * glyphs from `public/basemap-glyphs/`, served same-origin and already allowed
 * by `default-src 'self'`. No host appears anywhere in it, so a rig with no
 * network draws the same map as one with.
 *
 * Why the layers are generated rather than written out.
 *
 * `protomaps-themes-base` publishes the 66 layer definitions that match the
 * Protomaps tile schema — which is the schema of every archive built by their
 * tooling, including whatever extract an operator installs. Hand-writing them
 * would mean maintaining a copy that drifts from the archives it has to read,
 * and getting that wrong is invisible: an unmatched source layer renders as
 * nothing, so the map simply has no roads and says nothing about why.
 *
 * The one thing deliberately dropped is the sprite. Exactly one of the 66 layers
 * uses `icon-image`, for point-of-interest symbols, and carrying a sprite sheet
 * for it would add an asset set for decoration that a survey map does not need.
 * The layer is removed rather than left to fail, because a layer referencing a
 * sprite that is not there logs an error for every tile.
 */
import layersFor from 'protomaps-themes-base';
import { degreesWithHemisphere } from './numbers';

/** The one archive, through the protocol registered in `basemap.ts`. */
export const BASEMAP_SOURCE = 'protomaps';

/**
 * Glyphs, as a same-origin path.
 *
 * The directory names contain spaces, exactly as the theme's `text-font` values
 * spell them; MapLibre percent-encodes `{fontstack}` when it builds the request,
 * so the files on disk keep the readable name.
 */
export const BASEMAP_GLYPHS = '/basemap-glyphs/{fontstack}/{range}.pbf';

/** Ranges shipped in `public/basemap-glyphs`, as `fetch-basemap-glyphs.mjs` writes them. */
export const GLYPH_RANGES = ['0-255', '256-511', '3584-3839', '8192-8447'] as const;

export interface BasemapStyleOptions {
  /** `black` suits the tactical palette; the themes also publish light variants. */
  theme?: string;
  /** Label language. `en` plus the local name is what a survey wants. */
  lang?: string;
}

/**
 * A complete MapLibre style for the installed archive.
 *
 * `maxzoom` on the source is deliberately not set here: it belongs to the
 * archive, and the caller reads it from the header. Guessing it caps detail on a
 * deep extract, or asks for tiles a shallow one does not have.
 */
export function offlineBasemapStyle(
  maxZoom: number,
  { theme = 'black', lang = 'en' }: BasemapStyleOptions = {}
) {
  const layers = (layersFor as unknown as (
    source: string, theme: string, options: { lang: string }
  ) => any[])(BASEMAP_SOURCE, theme, { lang })
    // The sprite-dependent layer, removed rather than left to log on every tile.
    .filter(layer => !JSON.stringify(layer).includes('icon-image'));

  return {
    version: 8 as const,
    glyphs: BASEMAP_GLYPHS,
    sources: {
      [BASEMAP_SOURCE]: {
        type: 'vector' as const,
        // The host part is ignored by the protocol handler; there is one archive.
        url: undefined,
        tiles: ['pmtiles://basemap/{z}/{x}/{y}'],
        minzoom: 0,
        maxzoom: maxZoom,
      },
    },
    layers: [
      // Under everything, so the area the archive does not cover reads as
      // deliberate background rather than as a map that failed to load.
      {
        id: 'basemap-background',
        type: 'background' as const,
        paint: { 'background-color': '#0b0f14' },
      },
      ...layers,
    ],
  };
}

/**
 * The archive's bounds, in words an operator can act on.
 *
 * The Settings card printed `11.22, 43.75, 11.29, 43.79` — four bare floats in
 * the order PMTiles stores them, with nothing saying which was which. Displayed
 * that way the figure is not information: the one question it exists to answer
 * is "does this cover where I am working", and a reader cannot get there from a
 * list of numbers whose meaning they have to look up.
 *
 * So: hemispheres rather than signs, and an approximate extent, because "about
 * 6 × 5 km" answers that question in the time it takes to read it while a
 * decimal degree does not.
 *
 * The extent is **approximate and says so**. It is the equirectangular
 * approximation — a degree of latitude is near enough 110.57 km, and a degree of
 * longitude is that scaled by the cosine of the latitude — which is wrong by a
 * fraction of a percent over a city and badly wrong over a continent-sized box.
 * That is acceptable for "is this the right extract" and is not a measurement,
 * which is why it is prefixed rather than stated flat.
 */
export function describeBounds(bounds: [number, number, number, number]): {
  lon: string; lat: string; extent: string | null;
} {
  const [minLon, minLat, maxLon, maxLat] = bounds;
  const ok = bounds.every(n => typeof n === 'number' && Number.isFinite(n));
  if (!ok) return { lon: 'not reported', lat: 'not reported', extent: null };

  /*
    The shared primitive, not a local copy.

    This had the only correct hemisphere formatter in the codebase while the live
    coordinate readout printed a hardcoded "°N °E" beside a minus sign. Two
    implementations of one rule is how that happened, so there is now one, and
    `?? ''` is unreachable here -- `bounds` was range-checked above.
  */
  const ew = (v: number) => degreesWithHemisphere(v, 'lon', 2) ?? 'not reported';
  const ns = (v: number) => degreesWithHemisphere(v, 'lat', 2) ?? 'not reported';

  const KM_PER_DEGREE_LAT = 110.57;
  const midLat = (minLat + maxLat) / 2;
  const widthKm = Math.abs(maxLon - minLon) * KM_PER_DEGREE_LAT * Math.cos(midLat * Math.PI / 180);
  const heightKm = Math.abs(maxLat - minLat) * KM_PER_DEGREE_LAT;

  // Rounded to whole kilometres above 10 and one decimal below, because an
  // extract of a city block and an extract of a country want different
  // precision and neither wants four decimal places.
  const km = (v: number) => (v >= 10 ? Math.round(v).toString() : v.toFixed(1));

  return {
    lon: `${ew(minLon)} to ${ew(maxLon)}`,
    lat: `${ns(minLat)} to ${ns(maxLat)}`,
    extent: widthKm > 0 && heightKm > 0 ? `about ${km(widthKm)} × ${km(heightKm)} km` : null,
  };
}
