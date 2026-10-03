/**
 * The offline basemap: a PMTiles archive read from local disk.
 *
 * Why this exists.
 *
 * With no network the map has been a flat grey background — `MAP_STYLES.OFFLINE`
 * is one `background` layer and nothing else. The markers and the track still
 * draw, so the tool works, but an operator looking at a survey has no coastline,
 * no roads and no place names to locate it against. This is a tool whose own log
 * says the rig "is offline in the field and opened occasionally", and the map is
 * the screen it is opened to.
 *
 * PMTiles is a single file holding every tile, addressed by byte range. There is
 * no tile server, no directory of millions of files, and nothing to install
 * besides the archive itself.
 *
 * How the bytes get here.
 *
 * `read_basemap_range` in the Rust host reads one fixed path and returns base64.
 * The renderer never supplies a path and cannot influence one, which is why this
 * is two narrow commands rather than a filesystem permission: this renderer holds
 * `sql:allow-execute` and spawns the sidecar, so a traversal in it would be worth
 * more than usual, and the project has been removing capabilities rather than
 * adding them.
 *
 * Base64 across the bridge because Tauri's IPC is JSON, where a `Vec<u8>` becomes
 * an array of numbers — about four times the bytes, hundreds of times per pan.
 */
import { invoke } from '@tauri-apps/api/core';
import { PMTiles, type Source, type RangeResponse } from 'pmtiles';

/** What the host reports about the installed archive. */
export interface BasemapStatus {
  installed: boolean;
  /** Always present, so the operator can be told where to put a file. */
  path: string;
  size_bytes: number | null;
}

export async function basemapStatus(): Promise<BasemapStatus> {
  return invoke<BasemapStatus>('basemap_status');
}

/** base64 -> bytes, without a fetch and therefore without a CSP question. */
function decode(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out.buffer;
}

/**
 * A PMTiles `Source` backed by the Rust host.
 *
 * The library's own `FetchSource` issues HTTP range requests, which would mean
 * exposing the file over a protocol and allowing that origin in `connect-src`.
 * This reads it directly instead: no server, no origin, no policy change.
 */
export class TauriPMTilesSource implements Source {
  getKey(): string {
    // One archive per installation, so the key is constant. The library uses it
    // to namespace its caches; a changing key would defeat them.
    return 'lockon-basemap';
  }

  async getBytes(offset: number, length: number): Promise<RangeResponse> {
    const base64 = await invoke<string>('read_basemap_range', { offset, length });
    return { data: decode(base64) };
  }
}

/**
 * Teach MapLibre to resolve `pmtiles://` URLs.
 *
 * Registered once and idempotently: MapLibre throws if a protocol is added
 * twice, and the map component remounts on every navigation back to the
 * dashboard.
 */
let registered: PMTiles | null = null;

export function registerBasemapProtocol(
  addProtocol: (name: string, handler: (params: { url: string }, abort?: AbortController) => Promise<{ data: ArrayBuffer | null }>) => void
): PMTiles {
  if (registered) return registered;

  const archive = new PMTiles(new TauriPMTilesSource());
  registered = archive;

  addProtocol('pmtiles', async (params) => {
    // `pmtiles://basemap/{z}/{x}/{y}` — the host part is ignored because there
    // is only ever one archive; the path is what matters.
    const match = /pmtiles:\/\/[^/]*\/(\d+)\/(\d+)\/(\d+)/.exec(params.url);
    if (!match) throw new Error(`not a pmtiles tile URL: ${params.url}`);
    const [, z, x, y] = match;
    const tile = await archive.getZxy(Number(z), Number(x), Number(y));
    // `null`, not an empty buffer. A tile that does not exist is a real answer —
    // the archive covers a bounded area — and MapLibre draws nothing for it,
    // where an empty ArrayBuffer is a parse error on every blank tile.
    return { data: tile ? tile.data : null };
  });

  return archive;
}

/** Reset, for tests. The protocol registration itself is MapLibre's to undo. */
export function resetBasemapProtocol() {
  registered = null;
}

/**
 * The archive's own bounds and zoom range, or null when nothing is installed.
 *
 * Read from the header rather than assumed. An operator who installs an extract
 * of one city gets a map of that city and grey everywhere else, and the UI has
 * to be able to say which — "the basemap is installed" and "the basemap covers
 * where you are standing" are different claims.
 */
export async function basemapCoverage(archive: PMTiles): Promise<{
  minZoom: number; maxZoom: number;
  bounds: [number, number, number, number];
} | null> {
  try {
    const h = await archive.getHeader();
    return {
      minZoom: h.minZoom,
      maxZoom: h.maxZoom,
      bounds: [h.minLon, h.minLat, h.maxLon, h.maxLat],
    };
  } catch {
    return null;
  }
}

/**
 * The style to use when there is no network: the installed archive if there is
 * one, and the flat grid if there is not.
 *
 * Resolved once and cached, because the map component remounts on every
 * navigation back to the dashboard and re-reading the header each time would
 * re-issue the range reads behind it.
 *
 * `null` while it is still being decided. The caller starts on the flat grid and
 * swaps when this settles, rather than blocking the first paint on a disk read —
 * launching to a blank window because a file is being measured is the failure
 * the non-blocking webfont load was written to avoid, repeated.
 */
let offlineStyle: unknown | null = null;
let offlineStyleWork: Promise<unknown | null> | null = null;

export function offlineStyleIfReady(): unknown | null {
  return offlineStyle;
}

export async function resolveOfflineStyle(
  addProtocol: Parameters<typeof registerBasemapProtocol>[0]
): Promise<unknown | null> {
  if (offlineStyle) return offlineStyle;
  if (offlineStyleWork) return offlineStyleWork;

  offlineStyleWork = (async () => {
    /*
      Each outcome says which it was.

      Returning `null` for "no archive", "the host refused" and "the header would
      not parse" is right -- all three mean the flat grid -- but three causes
      sharing one silent answer is how a feature becomes undiagnosable. The first
      run of `test:basemap:runtime` hit exactly that: the map fell back, nothing
      followed, and nothing anywhere said why.
    */
    let status;
    try {
      status = await basemapStatus();
    } catch (e) {
      console.warn('[basemap] the host could not be asked about an archive:', e);
      return null;
    }
    if (!status.installed) {
      console.info(`[basemap] no archive at ${status.path}; the offline map is the flat grid`);
      return null;
    }

    const archive = registerBasemapProtocol(addProtocol);
    const coverage = await basemapCoverage(archive);
    // An archive whose header will not parse is worse than none: the protocol is
    // registered and every tile request fails. Treated as not installed, and the
    // settings card is where the operator is told why.
    if (!coverage) {
      console.warn(`[basemap] ${status.path} is present but its header did not parse; falling back to the flat grid`);
      return null;
    }
    console.info(`[basemap] archive ready: z${coverage.minZoom}-z${coverage.maxZoom}`);

    const { offlineBasemapStyle } = await import('./basemapStyle');
    offlineStyle = offlineBasemapStyle(coverage.maxZoom);
    return offlineStyle;
  })();

  return offlineStyleWork;
}

/** Forget the cached style. For tests, and after an archive is installed or removed. */
export function resetOfflineStyle() {
  offlineStyle = null;
  offlineStyleWork = null;
  registered = null;
}
