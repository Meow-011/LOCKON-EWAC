/**
 * LOCKON EWAC — the survey map, rendered for the report.
 *
 * Why an offscreen map rather than a screenshot of the one on the page.
 *
 * The preview map is wherever the operator last panned it, at whatever zoom, in
 * whatever view mode. Capturing that would make the figure in a delivered
 * document depend on how somebody was holding the UI a moment earlier — not
 * reproducible, not determined by the data, and a guaranteed false positive for
 * `pdfdiff` on every export. This builds its own map, fits it to the survey, and
 * throws it away.
 *
 * It is also deliberately a *simpler* view than the interactive one. No popups,
 * no 3D: a printed figure cannot be clicked.
 *
 * **What colour means here, and why it changed.** The first version spent hue on
 * positional certainty — amber for mirror-ambiguous, blue for resolved. On the
 * real survey that made the figure almost entirely amber, because 165 of 172
 * positions are ambiguous. A channel that is nearly constant carries nearly no
 * information, and it was spending the most legible channel on paper to carry
 * it, while severity — the thing a reader opens this figure to find — was not
 * shown at all. So hue is severity now, from `SEVERITY_RGB`, the same table the
 * tables and chips use.
 *
 * Certainty did not get dropped; it moved to shape, which suits it better. An
 * ambiguous position already draws two marks — the estimate and its mirror — so
 * the uncertainty is drawn as what it actually is: a filled dot with a hollow
 * twin, one radio with two candidate positions. That reads without a key, and
 * it cannot be confused with two radios the way two filled dots could.
 *
 * **`preserveDrawingBuffer` is the whole trick.** MapLibre draws through WebGL,
 * which clears its buffer after every frame, so `getCanvas().toDataURL()` on a
 * normally-configured map returns a blank image — and returns it *successfully*,
 * with no error anywhere. A silent blank figure in an evidence document is worse
 * than no figure, so the flag is set here and the result is checked before it is
 * handed back.
 */
import maplibregl from 'maplibre-gl';
import { REPORT_MAP_STYLE, REPORT_MAP_OFFLINE_STYLE } from '../constants';
import { severityRgb } from '../severityStyle';
import { SEVERITY_LEVELS } from '../severityStyle';
import { circlePolygon, isMirrorAmbiguous, isUnresolved, apMirror } from './archive';
import { coordinatePair, finiteNumber } from '../numbers';

export interface SurveyMapResult {
  /** JPEG data URL, or null when a usable image could not be produced. */
  image: string | null;
  /** Width/height of the captured bitmap, for placing it without distortion. */
  width: number;
  height: number;
  /** How many access points were drawn. */
  plotted: number;
  /** How many of those are mirror-ambiguous and drawn as such. */
  ambiguous: number;
  /** How many had no position derived at all, because the receiver never moved. */
  unresolved: number;
  /**
   * How many mirror twins were actually drawn.
   *
   * Lower than `ambiguous` whenever an AP was flagged ambiguous without usable
   * mirror coordinates, which the schema allows: the flag column and the coordinate
   * columns are independent. The caption states this number rather than `ambiguous`,
   * so a reader counting dots on the figure finds the text agrees with it.
   */
  mirrorsDrawn: number;
  /** Radii too large to draw at this scale; stated so the omission is visible. */
  ringsOmitted: number;
  /**
   * Whether a route was recorded *and the receiver actually went anywhere*.
   *
   * Not the same as "there are coordinates". See `MIN_ROUTE_SPAN_M`.
   */
  hasRoute: boolean;
  /** How far the recorded track spans end to end, in metres. */
  routeSpanM: number;
  /** How many fixes were recorded, however little ground they covered. */
  routeFixes: number;
  /**
   * What the reader is actually looking at underneath the data.
   *
   * The basemap is a network resource. When it cannot load, MapLibre falls back
   * to a plain grid, and a grid that is not labelled as one reads as "there is
   * nothing there" rather than "we could not fetch the cartography".
   */
  basemap: 'cartography' | 'offline-grid';
  /** How many plotted access points sit at each severity, for the legend. */
  counts: Record<string, number>;
  /** Why there is no image, when there is none. */
  reason?: string;
}

const EMPTY: SurveyMapResult = {
  image: null, width: 0, height: 0, plotted: 0, ambiguous: 0, ringsOmitted: 0,
  hasRoute: false, routeSpanM: 0, routeFixes: 0, basemap: 'offline-grid', counts: {},
  unresolved: 0, mirrorsDrawn: 0,
};

/** Build the figure's features from a report, independent of any live map. */
// `RING_LIMIT_M` is a fact about drawing an uncertainty ring rather than about
// this figure, and the live map needs it too -- importing it from here dragged
// MapLibre's stylesheet into the dashboard's overlay module.
export { RING_LIMIT_M } from '../position';
import { RING_LIMIT_M } from '../position';

/**
 * How far the receiver has to have travelled before a track counts as a route.
 *
 * The first version asked `route.length > 1`, which counts *fixes*, not ground.
 * The survey this was built against recorded **280 fixes spanning 7.6 metres**:
 * a receiver sitting still, logging its own GPS jitter. On that evidence the
 * report printed "the route shown is the recorded GPS track" and drew a line
 * too short to see, which is a claim the data does not support.
 *
 * It matters well beyond the figure. Every position here is trilaterated from
 * signal strength measured along the route, and resolving which side of a line
 * a transmitter sits on requires the receiver to have moved across a baseline.
 * A stationary survey cannot do it --- which is the direct cause of 165 of 172
 * positions coming back mirror-ambiguous. A reader looking at that number
 * deserves the explanation, not a figure implying a drive took place.
 *
 * 25 m is a conservative floor: consumer GPS jitter sits well under it, and
 * anything above it is movement a vehicle or a walk actually made.
 */
const MIN_ROUTE_SPAN_M = 25;

/** Metres between two WGS-84 points. */
function metresBetween(lon1: number, lat1: number, lon2: number, lat2: number): number {
  const R = 6371000;
  const rad = Math.PI / 180;
  const dLat = (lat2 - lat1) * rad;
  const dLon = (lon2 - lon1) * rad;
  const a = Math.sin(dLat / 2) ** 2
    + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.min(1, Math.sqrt(a)));
}

/**
 * End-to-end extent of a track, as the diagonal of its bounding box.
 *
 * Deliberately not path length. A receiver standing still for an hour
 * accumulates hundreds of metres of path length out of noise alone, so summing
 * segments would report exactly the movement that is not there. The bounding
 * box asks the only question that matters for a baseline: how far apart are the
 * two most distant places this receiver ever was?
 */
function routeSpan(route: number[][]): number {
  if (route.length < 2) return 0;
  let minLon = Infinity, maxLon = -Infinity, minLat = Infinity, maxLat = -Infinity;
  for (const [lon, lat] of route) {
    if (lon < minLon) minLon = lon;
    if (lon > maxLon) maxLon = lon;
    if (lat < minLat) minLat = lat;
    if (lat > maxLat) maxLat = lat;
  }
  return metresBetween(minLon, minLat, maxLon, maxLat);
}

/*
  Exported for its own tests.

  Everything below it needs a canvas and a MapLibre instance, so the figure's
  arithmetic was unreachable from a test — and that arithmetic is where the KEY
  disagreed with the "N plotted" sentence printed under it. The counting invariant is
  worth more coverage than the drawing is.
*/
/**
 * How many marks on the figure stand for an access point.
 *
 * Exported so a test can hold the real rule rather than a copy of it. The rule used
 * to be written inline as `points.filter(p => !p.properties.mirror)`, and `mirror`
 * was overloaded — it meant "draw this hollow" and also "this is a second answer for
 * a radio already plotted". An unresolved access point carried it for the paint, so
 * it was excluded here while `counts[sev]` had already included it: the KEY summed
 * higher than the "N plotted" sentence printed beneath it, for dots that are on the
 * map.
 *
 * Only a mirror twin is excluded now, because that is the one mark which is not its
 * own radio.
 */
export function plottedCount(points: any[]): number {
  return points.filter(p => !p?.properties?.twin).length;
}

export function featuresFor(
  aps: any[],
  pathCoords: any[],
  severityFor: (ap: any) => string,
) {
  const points: any[] = [];
  const rings: any[] = [];
  let ambiguous = 0;
  let ringsOmitted = 0;
  let unresolvedCount = 0;
  /*
    How many second dots were actually drawn.

    `ambiguous` counts the APs the estimator flagged, and `isMirrorAmbiguous` returns
    true on `geometry_ambiguous === 1` alone — while a twin is only pushed when the
    mirror coordinates are both present and finite. The two columns are independent,
    which is why `isMirrorAmbiguous` ORs them. So the caption's claim that every
    ambiguous AP "is drawn twice" was higher than the number of double dots on the
    map, and a reader counting them found the figure wrong.
  */
  let mirrorsDrawn = 0;
  const counts: Record<string, number> = {};

  for (const ap of aps) {
    const pair = coordinatePair(ap.latitude, ap.longitude);
    if (!pair) continue;
    const { lat, lon } = pair;
    const amb = isMirrorAmbiguous(ap);
    if (amb) ambiguous += 1;
    // The same verdict the findings table prints for this radio — resolved by
    // the caller from `worstBySubject`, so the figure cannot disagree with the
    // table about how bad something is.
    const sev = severityFor(ap);
    counts[sev] = (counts[sev] ?? 0) + 1;

    // Unresolved is drawn like a mirror candidate - hollow - because it is the
    // same kind of statement: this mark is not a measured transmitter position.
    // Ambiguous means two places fit; unresolved means none was derived at all.
    const unresolved = isUnresolved(ap);
    if (unresolved) unresolvedCount += 1;

    points.push({
      type: 'Feature',
      /*
        `mirror` is the paint flag — draw this hollow — and `twin` says whether the
        mark is a second answer for a radio already plotted.

        They were one property. An unresolved AP got `mirror: true` so it would be
        drawn hollow, and `plotted` was `points.filter(p => !p.properties.mirror)`,
        so it was excluded from the count of plotted marks while `counts[sev]` above
        had already included it. The figure's KEY therefore summed to more than the
        "N access point(s) plotted" sentence printed directly beneath it, for marks
        that are on the map — and the caption then separately said N "are drawn
        hollow", describing the same dots it had just left out of the total.
      */
      properties: { ambiguous: amb, sev, mirror: unresolved, twin: false },
      geometry: { type: 'Point', coordinates: [lon, lat] },
    });

    /*
      The stated radius — but only where drawing it says something.

      Drawing all of them was tried and produced a solid orange disc with the
      city underneath it. The radii in a real survey run to hundreds and
      thousands of metres, and 165 circles centred within a few streets of each
      other overlap hundreds deep: at 3.5% fill that reaches 99.9% opacity, so no
      opacity is low enough. The fill is gone and the large ones are left out,
      because a ring wider than the area surveyed conveys nothing except that the
      figure is unreadable.

      What is omitted is counted and said in the caption, and every radius is in
      the position-quality table regardless. Omitting silently would be the one
      unacceptable version of this.
    */
    const radius = finiteNumber(ap.location_error_m);
    if (radius !== null && radius > 0) {
      if (radius <= RING_LIMIT_M) {
        rings.push({
          type: 'Feature',
          properties: { ambiguous: amb, sev },
          geometry: { type: 'Polygon', coordinates: [circlePolygon(lon, lat, radius)] },
        });
      } else {
        ringsOmitted += 1;
      }
    }

    // A mirror candidate is a second answer, not a second access point: drawn
    // hollow so it cannot be counted as another radio on the street.
    if (amb) {
      const mirror = apMirror(ap);
      if (mirror && finiteNumber(mirror.lat) !== null && finiteNumber(mirror.lon) !== null) {
        mirrorsDrawn += 1;
        points.push({
          type: 'Feature',
          properties: { ambiguous: true, mirror: true, sev, twin: true },
          geometry: { type: 'Point', coordinates: [mirror.lon, mirror.lat] },
        });
      }
    }
  }

  const route = (pathCoords || [])
    .map((c: any) => (Array.isArray(c) ? c : [c?.lon ?? c?.lng, c?.lat]))
    .filter((c: any[]) => finiteNumber(c[0]) !== null && finiteNumber(c[1]) !== null);

  return { points, rings, route, ambiguous, ringsOmitted, counts, unresolvedCount, mirrorsDrawn };
}

/**
 * The hex form of a severity, for MapLibre, taken from the one print table.
 *
 * Not a second palette. `SEVERITY_RGB` is already tuned for ink on white and
 * this figure now prints on white, so the figure and the tables beside it name
 * a given severity with the same colour.
 */
function sevHex(level: string): string {
  const [r, g, b] = severityRgb(level);
  return `#${[r, g, b].map(n => n.toString(16).padStart(2, '0')).join('')}`;
}

/**
 * `match` input for a per-severity paint property.
 *
 * 'NONE' is included as a case of its own rather than left to the fallback: a
 * radio that raised no finding has to be visibly distinct from one this tool
 * assessed as INFO, and relying on the fallback would make that distinction
 * depend on nothing else ever reaching it.
 */
function bySeverity(fallback: string): any {
  const levels = [...SEVERITY_LEVELS, 'NONE'];
  return ['match', ['get', 'sev'], ...levels.flatMap(l => [l, sevHex(l)]), fallback];
}

/**
 * Render the survey to a bitmap.
 *
 * The basemap is `REPORT_MAP_STYLE` and the operator's own map preference does
 * not apply — see the note on that constant for why a report figure is light
 * when the application is dark. The offline grid is used if it does not load,
 * and the result says which one the reader got.
 *
 * `severityFor` resolves a radio to the verdict already printed for it; pass the
 * report's own resolver so the figure and the tables cannot disagree.
 */
export async function captureSurveyMap(
  aps: any[],
  pathCoords: any[],
  opts?: {
    severityFor?: (ap: any) => string;
    width?: number; height?: number; timeoutMs?: number;
  },
): Promise<SurveyMapResult> {
  const W = opts?.width ?? 1600;
  const H = opts?.height ?? 1100;
  const TIMEOUT = opts?.timeoutMs ?? 20000;

  const severityFor = opts?.severityFor ?? (() => 'INFO');
  const { points, rings, route, ambiguous, ringsOmitted, counts, unresolvedCount, mirrorsDrawn } =
    featuresFor(aps, pathCoords, severityFor);
  const span = routeSpan(route);
  if (points.length === 0 && route.length === 0) {
    return { ...EMPTY, reason: 'no positioned access points and no recorded route' };
  }

  const host = document.createElement('div');
  host.style.cssText =
    `position:fixed;left:-10000px;top:0;width:${W}px;height:${H}px;pointer-events:none;`;
  document.body.appendChild(host);

  let map: maplibregl.Map | null = null;
  let fellBack = false;

  const cleanup = () => {
    try { map?.remove(); } catch { /* already gone */ }
    try { host.remove(); } catch { /* already gone */ }
  };

  try {
    map = new maplibregl.Map({
      container: host,
      style: REPORT_MAP_STYLE as any,
      center: [0, 0],
      zoom: 2,
      attributionControl: false,
      interactive: false,
      /*
        Without this the capture is silently blank — see the header.

        Note it is nested under `canvasContextAttributes` in this version of
        MapLibre, not a top-level option. Passing it at the top level type-checks
        as an excess property and is dropped, which produces exactly the blank
        image this is here to prevent; `tsc` caught that on the way in.
      */
      canvasContextAttributes: { preserveDrawingBuffer: true },
      fadeDuration: 0,
    });

    // A style that will not load is a fallback, not a failure — but the caller
    // has to be told which one the reader is looking at.
    const styleReady = await new Promise<boolean>((resolve) => {
      const done = (ok: boolean) => { clearTimeout(timer); resolve(ok); };
      const timer = setTimeout(() => done(false), Math.min(TIMEOUT, 12000));
      map!.once('load', () => done(true));
      map!.once('error', () => done(false));
    });

    if (!styleReady) {
      fellBack = true;
      await new Promise<void>((resolve) => {
        map!.once('load', () => resolve());
        map!.once('error', () => resolve());
        map!.setStyle(REPORT_MAP_OFFLINE_STYLE as any);
        setTimeout(resolve, 4000);
      });
    }

    map.addSource('survey-rings', { type: 'geojson', data: { type: 'FeatureCollection', features: rings } as any });
    map.addSource('survey-route', {
      type: 'geojson',
      data: { type: 'Feature', properties: {}, geometry: { type: 'LineString', coordinates: route } } as any,
    });
    map.addSource('survey-aps', { type: 'geojson', data: { type: 'FeatureCollection', features: points } as any });

    /*
      Outlines only. A filled ring cannot work here at any opacity — see the
      comment on RING_LIMIT_M — so the radius is carried by its edge.
    */
    map.addLayer({
      id: 'survey-rings-line', type: 'line', source: 'survey-rings',
      paint: {
        'line-color': bySeverity('#64748b'),
        'line-width': 0.8, 'line-opacity': 0.3, 'line-dasharray': [2, 2],
      },
    });
    /*
      Dark green, not the screen's `#22c55e`.

      The route is drawn under the dots on a light basemap now. At green-500 it
      washed out against pale road fill to the point where the track was hard to
      follow; green-700 holds its line, and it is the same hue the application's
      own route uses.
    */
    map.addLayer({
      id: 'survey-route-line', type: 'line', source: 'survey-route',
      paint: { 'line-color': '#15803d', 'line-width': 2.2, 'line-opacity': 0.85 },
    });
    map.addLayer({
      id: 'survey-aps-dot', type: 'circle', source: 'survey-aps',
      paint: {
        'circle-radius': 3.4,
        'circle-color': bySeverity('#64748b'),
        /*
          Hollow means "this is the same radio's other candidate position".

          Shape carries certainty and hue carries severity, so the two never
          compete for the same channel. The mirror keeps its severity colour in
          the outline, which is what ties the pair together visually without
          needing a line drawn between them.
        */
        'circle-opacity': ['case', ['==', ['get', 'mirror'], true], 0, 0.92],
        'circle-stroke-width': ['case', ['==', ['get', 'mirror'], true], 1.2, 0.9],
        // White around a filled dot so dense clusters still separate; the
        // mirror outlines itself in its own severity instead.
        'circle-stroke-color': [
          'case', ['==', ['get', 'mirror'], true], bySeverity('#64748b'), '#ffffff',
        ],
      },
    });

    // Framed by the data, never by the UI.
    const bounds = new maplibregl.LngLatBounds();
    for (const f of points) bounds.extend(f.geometry.coordinates as [number, number]);
    for (const c of route) bounds.extend(c as [number, number]);
    if (!bounds.isEmpty()) {
      /*
        maxZoom 18, not 17. At 17 a survey confined to a few streets - which is
        what a stationary or short survey produces - sat in the middle of the
        frame with most of the page given to cartography nobody drove through.
      */
      map.fitBounds(bounds, { padding: 50, duration: 0, maxZoom: 18 });
    }

    // `idle` means every tile and layer for the current view has finished.
    await new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, TIMEOUT);
      map!.once('idle', () => { clearTimeout(timer); resolve(); });
    });
    // One more frame, because `idle` can fire fractionally before the last paint.
    await new Promise(r => requestAnimationFrame(() => setTimeout(r, 250)));

    const canvas = map.getCanvas();
    const image = canvas.toDataURL('image/jpeg', 0.85);

    // Verified rather than assumed: a blank capture is the failure this whole
    // module is arranged to avoid, and it does not announce itself.
    if (!image || image.length < 5000) {
      return { ...EMPTY, reason: 'the map produced an empty image', plotted: plottedCount(points) };
    }

    return {
      image,
      width: canvas.width,
      height: canvas.height,
      plotted: plottedCount(points),
      ambiguous,
      ringsOmitted,
      unresolved: unresolvedCount,
      mirrorsDrawn,
      hasRoute: span >= MIN_ROUTE_SPAN_M,
      routeSpanM: span,
      routeFixes: route.length,
      basemap: fellBack ? 'offline-grid' : 'cartography',
      counts,
    };
  } catch (err: any) {
    return { ...EMPTY, reason: `map capture failed: ${err?.message ?? err}` };
  } finally {
    cleanup();
  }
}
