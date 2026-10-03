/** LOCKON EWAC — Application Constants */

export const APP_NAME = 'LOCKON EWAC';
export const APP_VERSION = '1.0.0';
export const APP_DESCRIPTION = 'Early Warning and Control Suite';

/** Database */
export const DB_NAME = 'sqlite:ewac.db';

/** Map defaults — Bangkok, Thailand */
export const MAP_DEFAULT_CENTER: [number, number] = [100.5018, 13.7563];
export const MAP_DEFAULT_ZOOM = 12;

/**
 * Fully offline MapLibre style — NO remote sources, NO glyphs, NO sprite.
 * Used as the automatic fallback when a remote basemap cannot be reached
 * (basements, cellular dead spots, captive portals, air-gapped operation).
 *
 * The point is not cartography: it is that the map *initialises*, so the
 * `load` event fires and the GPS track + AP layers still render on a plain
 * tactical backdrop instead of leaving the operator a blank dead panel.
 */
export const MAP_OFFLINE_STYLE = {
  version: 8,
  name: 'LOCKON Offline Grid',
  sources: {},
  layers: [
    {
      id: 'offline-background',
      type: 'background',
      paint: {
        'background-color': '#05070d', // space-950 — matches the tactical shell
      },
    },
  ],
} as const;

/**
 * The basemap the *report figure* uses, which is not the one on screen.
 *
 * The application's map is dark, because the shell is. A printed page is white,
 * and three things follow from that. `SEVERITY_RGB` is tuned for paper — CRITICAL
 * is a deep [153,27,27] that reads as serious in ink and all but disappears on a
 * near-black map. A dark rectangle in an otherwise white document looks like it
 * came from somewhere else. And it costs a great deal of toner.
 *
 * So the figure uses a light basemap and the operator's style preference does not
 * apply to it. That is deliberate: the preference is about working at night in a
 * vehicle, not about how a report prints.
 */
export const REPORT_MAP_STYLE =
  'https://basemaps.cartocdn.com/gl/positron-gl-style/style.json';

/** Light counterpart to MAP_OFFLINE_STYLE, for when the figure's basemap fails. */
export const REPORT_MAP_OFFLINE_STYLE = {
  version: 8,
  name: 'LOCKON Offline Grid (print)',
  sources: {},
  layers: [
    {
      id: 'offline-background',
      type: 'background',
      paint: { 'background-color': '#f1f5f9' },
    },
  ],
} as const;

export const MAP_STYLES = {
  DARK: 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json',
  /** Offline fallback — see MAP_OFFLINE_STYLE. Not user-selectable in Settings. */
  OFFLINE: MAP_OFFLINE_STYLE,
  SATELLITE: {
    version: 8,
    sources: {
      'satellite': {
        type: 'raster',
        tiles: [
          'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}'
        ],
        tileSize: 256
      }
    },
    layers: [
      {
        id: 'satellite-layer',
        type: 'raster',
        source: 'satellite',
        minzoom: 0,
        maxzoom: 22
      }
    ]
  }
} as const;

/** Style keys that require network access (everything except OFFLINE). */
export const REMOTE_MAP_STYLES = ['DARK', 'SATELLITE'] as const;

export function isRemoteMapStyle(key: string): boolean {
  return (REMOTE_MAP_STYLES as readonly string[]).includes(key);
}

/** Remote raster-DEM used for 3D terrain. Skipped whenever the basemap is degraded. */
export const MAP_TERRAIN_TILES = [
  'https://s3.amazonaws.com/elevation-tiles-prod/terrarium/{z}/{x}/{y}.png',
] as const;

/*
  Risk and signal thresholds are deliberately NOT here.

  Two constants used to be: `RISK_THRESHOLDS` (CRITICAL 80, HIGH 60, MEDIUM 40,
  LOW 0) and `SIGNAL_THRESHOLDS` (STRONG -50 … DEAD -90). Neither was read by any
  code — `RISK_THRESHOLDS` survived only as a mention in a comment — and the
  first one **disagreed with the bands actually in force**, which are 90 / 70 / 40
  / 15 / 0 in `riskEngine.SEVERITY_BANDS`. A dead constant in a file called
  `constants.ts` is worse than no constant: it reads as the authority, and the
  next person to reach for "the risk thresholds" finds the wrong numbers.

  The owners are:
    - severity bands      -> `src/lib/riskEngine.ts`   (SEVERITY_BANDS)
    - severity colours    -> `src/lib/severityStyle.ts`
    - signal bands+colour -> `src/lib/signalStyle.ts`  (SIGNAL_BANDS)

  Each is the single source for its answer and each has tests. Do not mirror
  their numbers here.
*/

/** Navigation items */
export const NAV_ITEMS = [
  { id: 'dashboard', label: 'Dashboard', icon: 'radar', path: '/' },
  { id: 'intrusion', label: 'INTRUSION', icon: 'zap', path: '/intrusion' },
  { id: 'decryptor', label: 'DECRYPTOR', icon: 'unlock', path: '/decryptor' },
  { id: 'reports', label: 'Reports', icon: 'file-text', path: '/reports' },
  { id: 'settings', label: 'Settings', icon: 'settings', path: '/settings' },
] as const;
