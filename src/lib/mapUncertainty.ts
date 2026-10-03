/**
 * What the live map was not saying about the positions it drew.
 *
 * Why this exists.
 *
 * Every access point on the tactical map was a 5 or 7 pixel dot, and a dot is an
 * assertion. The estimators have published an uncertainty radius and, on a
 * straight pass, a second equally good position on the other side of the road
 * since `011_location_uncertainty.sql`; the exported PDF, CSV and KML all print
 * both. The live map read neither. `location_error_m`, `geometry_ambiguous` and
 * `location_mirror_lat`/`lon` reached `MapView` on every feature and were never
 * looked at.
 *
 * So one mission produced two different pictures. On screen, during the survey —
 * when the operator is deciding where to drive next, and whether they have enough
 * geometry — a transmitter whose position was known to ±90 m and could equally
 * well be across the street looked exactly like one pinned to five metres. In the
 * report afterwards, the same radio carried a 90 m ring, an AMBIGUOUS flag and a
 * twin. The screen was the confident one, and the screen is the one that decides
 * what gets surveyed.
 *
 * What this module does and does not decide.
 *
 * It builds the geometry and counts what it left out. It does not decide how the
 * rings are painted, and it deliberately shares `circlePolygon`, `apMirror` and
 * `isMirrorAmbiguous` with the report rather than reimplementing them, so the two
 * cannot drift into disagreeing about the same mission again.
 *
 * `RING_LIMIT_M` is shared for the same reason, and it is not an aesthetic
 * choice. Drawing every radius was tried for the report figure and produced a
 * solid disc with the city underneath it: real radii run to hundreds of metres,
 * and a hundred and sixty of them centred within a few streets overlap hundreds
 * deep, at which point no fill opacity is low enough. A ring wider than the area
 * surveyed says nothing except that the map is unreadable.
 *
 * Omitting silently would be the one unacceptable version of this, so the count
 * comes back with the features and the map states it.
 */
import {
  apMirror,
  circlePolygon,
  isMirrorAmbiguous,
  locationMethodLabel,
  RING_LIMIT_M,
} from './position';
import { coordinatePair, finiteNumber } from './numbers';

export { RING_LIMIT_M };

/** One of the three things this module draws, as a paint discriminator. */
export type UncertaintyKind = 'ring' | 'mirror' | 'link';

export interface UncertaintyFeatures {
  /** Ring polygons, mirror points and the lines joining a pair, in one source. */
  features: any[];
  /** Radii left out because they were wider than `RING_LIMIT_M`. */
  ringsOmitted: number;
  /** Access points the estimator flagged as mirror-ambiguous. */
  ambiguous: number;
  /** Second candidates actually drawn — not the same number as `ambiguous`. */
  mirrorsDrawn: number;
  /**
   * Plotted access points carrying no radius at all.
   *
   * Counted because the absence is the claim that needs stating. A dot with no
   * ring is indistinguishable from a dot whose ring is too small to see, and on a
   * map where most dots have rings the bare ones read as the precise ones — the
   * exact inversion of what is true.
   */
  noRadius: number;
  /**
   * The estimator behind every position that carries no radius, when there is
   * only one of them.
   *
   * Because "47 with no stated radius" is the wrong sentence when the operator
   * has selected TRACK POSITION, which publishes no radius for anything --
   * `estimateTrackPosition` returns `errorRadiusM: null` by construction, since a
   * convex combination of the sighting positions has no uncertainty model behind
   * it. Phrased as a loss, the line reads as though the data were damaged, on
   * every survey, which is how a caveat becomes wallpaper.
   *
   * Null when the plotted set mixes estimators, because then the absence really
   * is per-position and naming one method would be wrong.
   */
  noRadiusMethod: string | null;
  /** Same, for access points flagged ambiguous with no second candidate stored. */
  noCandidateMethod: string | null;
}

/**
 * The one estimator shared by every row in a set, or null.
 *
 * `null` for an empty set as well as for a mixed one: "they all agree" is not a
 * statement about nothing. Also null when any row does not say which estimator
 * produced it, because "all of them came from the same place" cannot be claimed
 * about a row that does not name one -- and attributing the absence to "not
 * recorded" would turn a missing field into an explanation of itself.
 */
function soleMethod(methods: Set<string | null>): string | null {
  if (methods.size !== 1) return null;
  return [...methods][0];
}

export interface UncertaintyOptions {
  /**
   * Widest radius still drawn, in metres.
   *
   * `RING_LIMIT_M` on the live map, where every ring is on screen at once and a
   * hundred and sixty of them overlap into one mass. `Infinity` in the report,
   * which solves the same problem with a control instead -- OFF / HOVER / ALL --
   * so a reader can ask for one ring at a time and nothing has to be left out.
   *
   * Two surfaces, two reasonable answers, one implementation. It is a parameter
   * rather than a constant precisely because the second map was written as a
   * second copy over this disagreement.
   */
  ringLimitM?: number;
}

/**
 * Build the uncertainty overlay for the access points currently plotted.
 *
 * `aps` must already be filtered the way the dots are: pass the same list, or
 * the rings outlive the marks they belong to and annotate the wrong street.
 */
export function uncertaintyFeatures(
  aps: any[],
  { ringLimitM = RING_LIMIT_M }: UncertaintyOptions = {},
): UncertaintyFeatures {
  const features: any[] = [];
  let ringsOmitted = 0;
  let ambiguous = 0;
  let mirrorsDrawn = 0;
  let noRadius = 0;
  const noRadiusMethods = new Set<string | null>();
  const noCandidateMethods = new Set<string | null>();

  for (const ap of aps ?? []) {
    const pair = coordinatePair(ap?.latitude, ap?.longitude);
    if (!pair) continue;
    const { lat, lon } = pair;

    /*
      Both columns, ORed, because they are independent.

      `geometry_ambiguous` is the estimator's verdict on the route; a stored
      mirror pair means it produced a second candidate. A row that has one and
      not the other is still ambiguous, and treating it as a confident fix
      because the flag column happened to be null is the failure the shared
      helper exists to prevent.
    */
    const amb = isMirrorAmbiguous(ap);
    if (amb) ambiguous += 1;

    const radius = finiteNumber(ap?.location_error_m);
    if (radius === null || radius <= 0) {
      noRadius += 1;
      noRadiusMethods.add(methodOf(ap));
    } else if (radius <= ringLimitM) {
      features.push({
        type: 'Feature',
        properties: {
          kind: 'ring' as UncertaintyKind,
          ambiguous: amb,
          radiusM: radius,
          bssid: ap?.bssid ?? null,
        },
        geometry: { type: 'Polygon', coordinates: [circlePolygon(lon, lat, radius)] },
      });
    } else {
      ringsOmitted += 1;
    }

    /*
      The second candidate, and the line that says the two belong together.

      Without the line a hollow ring 80 m away is read as another radio on the
      next street, which is the opposite of what it means: it is the same
      transmitter, and the survey geometry cannot say which of the two places it
      is in. The KML has drawn this connector since it learned the same lesson.
    */
    if (amb) {
      const mirror = apMirror(ap);
      const mirrorPair = mirror ? coordinatePair(mirror.lat, mirror.lon) : null;
      if (!mirror || !mirrorPair) {
        noCandidateMethods.add(methodOf(ap));
      }
      if (mirror && mirrorPair) {
        mirrorsDrawn += 1;
        const props = {
          ambiguous: true,
          bssid: ap?.bssid ?? null,
          ssid: ap?.ssid ?? null,
          distanceM: mirror.distanceM,
        };
        features.push({
          type: 'Feature',
          properties: { ...props, kind: 'link' as UncertaintyKind },
          geometry: {
            type: 'LineString',
            coordinates: [[lon, lat], [mirrorPair.lon, mirrorPair.lat]],
          },
        });
        features.push({
          type: 'Feature',
          properties: {
            ...props,
            kind: 'mirror' as UncertaintyKind,
            /*
              Where the first candidate is, carried on the second one.

              A popup opened on the mirror has to be able to name the pin it is
              the twin of, and it has only this feature to read. Raw degrees
              rather than a formatted string: formatting is each surface's job,
              and a geometry module that returns prose is a module two callers
              will disagree about.
            */
            primaryLat: lat,
            primaryLon: lon,
          },
          geometry: { type: 'Point', coordinates: [mirrorPair.lon, mirrorPair.lat] },
        });
      }
    }
  }

  return {
    features, ringsOmitted, ambiguous, mirrorsDrawn, noRadius,
    noRadiusMethod: soleMethod(noRadiusMethods),
    noCandidateMethod: soleMethod(noCandidateMethods),
  };
}

/**
 * The estimator named on a row, as the report labels it, or null if it says none.
 *
 * Null rather than "not recorded": the point of collecting these is to decide
 * whether one estimator explains an absence, and a row that does not name one
 * explains nothing.
 */
function methodOf(ap: any): string | null {
  return typeof ap?.location_method === 'string' && ap.location_method
    ? locationMethodLabel(ap.location_method)
    : null;
}

/**
 * The one-line statement of what the overlay is not showing.
 *
 * Returns null when there is nothing to qualify, so the caller renders nothing
 * rather than a reassuring "0 omitted" that the operator learns to ignore.
 */
export function uncertaintyCaveat(u: UncertaintyFeatures): string | null {
  const parts: string[] = [];
  if (u.ringsOmitted > 0) {
    parts.push(`${u.ringsOmitted} radius over ${RING_LIMIT_M} m not drawn`);
  }
  /* Nothing is omitted when the caller passes no limit, so a surface with an
     OFF/HOVER/ALL control never reaches this line. */
  if (u.noRadius > 0) {
    /*
      Named when one estimator accounts for all of them, because the two cases
      need different sentences. TRACK POSITION publishes no radius for anything,
      so on a survey using it this count is every access point on the map and
      "with no stated radius" describes the method, not a loss of data.
    */
    parts.push(u.noRadiusMethod
      ? `${u.noRadius} from ${u.noRadiusMethod}, which states no radius`
      : `${u.noRadius} with no stated radius`);
  }
  /*
    An ambiguous access point whose second candidate was never stored. The flag
    says two places fit and the coordinates to draw the other one are absent, so
    the map can only show one of the two — and must say which case it is in,
    because a single dot otherwise reads as a resolved position.
  */
  const flaggedWithoutTwin = u.ambiguous - u.mirrorsDrawn;
  if (flaggedWithoutTwin > 0) {
    /*
      Also named, and for the same reason. TRACK POSITION never produces a second
      candidate either -- `assessGeometry` still reports a straight route as
      ambiguous, which is true of the route, but the estimator has no mirror to
      offer -- so on a straight survey using it this is every access point again.
    */
    parts.push(u.noCandidateMethod
      ? `${flaggedWithoutTwin} from ${u.noCandidateMethod}, which offers no second candidate`
      : `${flaggedWithoutTwin} ambiguous with no second candidate recorded`);
  }
  return parts.length > 0 ? parts.join(' · ') : null;
}
