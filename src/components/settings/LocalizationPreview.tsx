/**
 * LOCKON EWAC — a live demonstration of the three AP location estimators.
 *
 * Why this runs the real code.
 *
 * The three methods differ in ways that are hard to say and obvious to see: one
 * cannot leave the road it drove, one needs the route to have shape before it
 * beats guessing, and one searches positions and can place a transmitter inside
 * a building. A hand-drawn illustration of that would be a marketing asset —
 * accurate the day it was drawn, and free to drift from the code forever after.
 * This project has already been bitten by a document that kept a formula after
 * the function changed.
 *
 * So nothing here is drawn from imagination. A synthetic drive is generated
 * from the same path-loss model the estimators invert, and the estimate on
 * screen is whatever `estimateBayesian`, `estimateTrilateration` or
 * `estimateTrackPosition` actually returns for those sightings. If an estimator
 * regresses, this panel shows the regression.
 *
 * The straight-versus-turn toggle is the point of the whole panel: it is the
 * one control that makes mirror ambiguity visible rather than a paragraph.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { signalHex } from '../../lib/signalStyle';
import {
  assessGeometry,
  estimateBayesian,
  estimateTrackPosition,
  estimateTrilateration,
  makeProjection,
  referencePowerDbm,
  PATH_LOSS_EXPONENT,
  SHADOWING_SIGMA_DB,
  type LocationEstimate,
  type Observation,
} from '../../lib/localization';

type Method = 'bayesian_grid' | 'weighted_centroid' | 'trilateration';
type RouteId = 'STRAIGHT' | 'TURN';

/** Origin is arbitrary; everything is worked in metres and projected through it. */
const ORIGIN_LAT = 13.7563;
const ORIGIN_LON = 100.5018;
const FREQUENCY_MHZ = 2437;

/** The transmitter, in metres from the origin. Off the road, as they always are. */
const TRUE_X = 46;
const TRUE_Y = 30;

/** Below this a managed-mode adapter would not report the AP at all. */
const NOISE_FLOOR = -95;

const ROUTES: Record<RouteId, { label: string; hint: string; points: [number, number][] }> = {
  STRAIGHT: {
    label: 'ONE STRAIGHT PASS',
    hint: 'Every sighting on one line. The fit is symmetric about it.',
    points: [[-40, 0], [150, 0]],
  },
  TURN: {
    label: 'ROUTE WITH ONE TURN',
    hint: 'One leg that leaves the line is worth more than another pass along it.',
    points: [[-40, 0], [120, 0], [120, 50]],
  },
};

const METHOD_RUNNER: Record<Method, (h: Observation[]) => LocationEstimate> = {
  bayesian_grid: (h) => estimateBayesian(h),
  trilateration: (h) => estimateTrilateration(h),
  weighted_centroid: (h) => estimateTrackPosition(h),
};

const METHOD_LABEL: Record<Method, string> = {
  bayesian_grid: 'LIKELIHOOD GRID',
  trilateration: 'MULTILATERATION',
  weighted_centroid: 'TRACK POSITION',
};

/** Deterministic noise, so the same panel always tells the same story. */
function mulberry32(seed: number) {
  let a = seed;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function gauss(rng: () => number, sd: number) {
  const u = Math.max(1e-9, rng());
  const v = rng();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v) * sd;
}

interface Frame {
  /** Where the vehicle is, in metres. */
  car: { x: number; y: number };
  /** Sightings collected so far, in metres, for drawing. */
  seen: { x: number; y: number; rssi: number }[];
  estimate: LocationEstimate | null;
  /** Estimate position in metres, and how far it is from the truth. */
  fix: { x: number; y: number; errorM: number } | null;
  mirror: { x: number; y: number } | null;
}

const STEPS = 34;

/**
 * Walk the route, sample the radio model, and run the real estimator as the
 * history grows. Precomputed once per (method, route) so the animation is just
 * playback — re-running a grid search every frame would stutter the panel.
 */
function buildFrames(method: Method, routeId: RouteId): Frame[] {
  const proj = makeProjection(ORIGIN_LAT, ORIGIN_LON);
  const rng = mulberry32(7);
  const route = ROUTES[routeId].points;

  // Total length, so steps are evenly spaced along the whole polyline.
  const legs: { from: [number, number]; to: [number, number]; len: number }[] = [];
  for (let i = 0; i < route.length - 1; i += 1) {
    const from = route[i];
    const to = route[i + 1];
    legs.push({ from, to, len: Math.hypot(to[0] - from[0], to[1] - from[1]) });
  }
  const total = legs.reduce((a, l) => a + l.len, 0);

  const pointAt = (distance: number): { x: number; y: number } => {
    let walked = 0;
    for (const leg of legs) {
      if (walked + leg.len >= distance) {
        const t = leg.len === 0 ? 0 : (distance - walked) / leg.len;
        return {
          x: leg.from[0] + (leg.to[0] - leg.from[0]) * t,
          y: leg.from[1] + (leg.to[1] - leg.from[1]) * t,
        };
      }
      walked += leg.len;
    }
    const last = route[route.length - 1];
    return { x: last[0], y: last[1] };
  };

  const history: Observation[] = [];
  const seen: { x: number; y: number; rssi: number }[] = [];
  const frames: Frame[] = [];
  const run = METHOD_RUNNER[method];

  for (let step = 0; step < STEPS; step += 1) {
    const car = pointAt((step / (STEPS - 1)) * total);

    // The same model the estimators invert, plus log-normal shadowing.
    const distance = Math.max(1, Math.hypot(TRUE_X - car.x, TRUE_Y - car.y));
    const clean = referencePowerDbm(FREQUENCY_MHZ)
      - 10 * PATH_LOSS_EXPONENT * Math.log10(distance);
    const rssi = Math.round(clean + gauss(rng, SHADOWING_SIGMA_DB));

    if (rssi >= NOISE_FLOOR) {
      const { lat, lon } = proj.toDegrees(car.x, car.y);
      history.push({ lat, lon, rssi, frequency: FREQUENCY_MHZ });
      seen.push({ x: car.x, y: car.y, rssi });
    }

    let estimate: LocationEstimate | null = null;
    let fix: Frame['fix'] = null;
    let mirror: Frame['mirror'] = null;

    // Three sightings is the floor the estimators themselves work to.
    if (history.length >= 3) {
      estimate = run(history);
      const p = proj.toMetres(estimate.lat, estimate.lon);
      fix = {
        x: p.x,
        y: p.y,
        errorM: Math.hypot(p.x - TRUE_X, p.y - TRUE_Y),
      };
      if (estimate.mirrorCandidate) {
        const m = proj.toMetres(estimate.mirrorCandidate.lat, estimate.mirrorCandidate.lon);
        mirror = { x: m.x, y: m.y };
      }
    }

    frames.push({ car, seen: seen.slice(), estimate, fix, mirror });
  }

  return frames;
}

// ── Drawing ─────────────────────────────────────────────────────────────────

/**
 * Viewport.
 *
 * Two constraints pull against each other and both matter:
 *
 *  - **One metre must be one metre on either axis.** With independent x and y
 *    scales the uncertainty ring was drawn as a circle in pixels while standing
 *    for an ellipse in metres — 2.2x too tall for the distance it claimed. A
 *    panel about how far to trust a position cannot misdraw the uncertainty.
 *  - **It has to fill the panel.** Capping the height and letting the SVG
 *    letterbox squeezed the drawing into the middle third of the width with
 *    black bars either side, which is worse than a tall panel.
 *
 * Both are satisfied by choosing the metre window to match the viewport's own
 * aspect, then sizing the scenario to fit that window rather than the reverse.
 */
const VIEW_W = 700;
const VIEW_H = 248;
const SPAN_X: [number, number] = [-70, 190];
const SPAN_M_X = SPAN_X[1] - SPAN_X[0];
/** Height in metres follows from the width, so the scales cannot diverge. */
const SPAN_M_Y = (SPAN_M_X * VIEW_H) / VIEW_W;
/**
 * Anchored below the road: the mirrored candidate sits about as far south of it
 * as the transmitter is north, and it needs to be on screen to make the point.
 */
const SPAN_Y: [number, number] = [-40, -40 + SPAN_M_Y];

const sx = (x: number) => ((x - SPAN_X[0]) / SPAN_M_X) * VIEW_W;
// SVG y grows downward; metres grow north.
const sy = (y: number) => VIEW_H - ((y - SPAN_Y[0]) / SPAN_M_Y) * VIEW_H;
/** One metre in viewport units. Identical on both axes, by construction. */
const scaleM = VIEW_W / SPAN_M_X;

/*
  The preview draws to SVG, so it needs hex rather than a class — but the bands
  are the app's, not its own. These used to be four hardcoded hexes on their own
  thresholds, which happened to duplicate three of the palette's values while
  cutting the scale in different places.
*/
const rssiColour = signalHex;

export function LocalizationPreview({ method }: { method: Method }) {
  const [routeId, setRouteId] = useState<RouteId>('STRAIGHT');
  const [step, setStep] = useState(STEPS - 1);
  const [playing, setPlaying] = useState(true);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const frames = useMemo(() => buildFrames(method, routeId), [method, routeId]);

  // Restart the drive whenever the scenario changes, so the panel always shows
  // the new method from the beginning rather than mid-route.
  useEffect(() => {
    setStep(0);
    setPlaying(true);
  }, [method, routeId]);

  useEffect(() => {
    if (!playing) return undefined;
    timer.current = setInterval(() => {
      setStep((s) => {
        if (s >= STEPS - 1) {
          setPlaying(false);
          return s;
        }
        return s + 1;
      });
    }, 110);
    return () => {
      if (timer.current) clearInterval(timer.current);
      timer.current = null;
    };
  }, [playing]);

  const frame = frames[Math.min(step, frames.length - 1)];
  const route = ROUTES[routeId];
  const geometry = frame.estimate?.geometry
    ?? assessGeometry([]);

  const routePath = route.points
    .map(([x, y], i) => `${i === 0 ? 'M' : 'L'} ${sx(x).toFixed(1)} ${sy(y).toFixed(1)}`)
    .join(' ');

  return (
    <div className="mt-4 rounded border border-space-500/30 bg-space-950 overflow-hidden">
      <div className="flex items-center justify-between px-3 py-2 border-b border-space-500/20 bg-space-900/50">
        <div className="flex items-center gap-2">
          <span className="text-[9px] font-tactical tracking-widest text-gray-400">
            LIVE PREVIEW — {METHOD_LABEL[method]}
          </span>
          <span className="text-[9px] font-mono text-gray-600">
            running the real estimator, not an illustration
          </span>
        </div>
        <div className="flex items-center gap-1">
          {(Object.keys(ROUTES) as RouteId[]).map((id) => (
            <button
              key={id}
              onClick={() => setRouteId(id)}
              className={`text-[9px] font-tactical tracking-wider px-2 py-1 rounded border transition-colors ${
                routeId === id
                  ? 'bg-space-700 border-space-400 text-white'
                  : 'bg-space-900 border-space-500/30 text-gray-500 hover:text-gray-300'
              }`}
            >
              {ROUTES[id].label}
            </button>
          ))}
          <button
            onClick={() => (step >= STEPS - 1 ? (setStep(0), setPlaying(true)) : setPlaying((p) => !p))}
            className="text-[9px] font-tactical tracking-wider px-2 py-1 rounded border border-neon-500/40 text-neon-400 hover:bg-neon-500/10"
          >
            {step >= STEPS - 1 ? 'REPLAY' : playing ? 'PAUSE' : 'PLAY'}
          </button>
        </div>
      </div>

      <svg viewBox={`0 0 ${VIEW_W} ${VIEW_H}`} className="w-full h-auto block" role="img"
           aria-label={`Simulated drive showing how ${METHOD_LABEL[method]} estimates a transmitter position`}>
        <defs>
          <pattern id="lp-grid" width="34" height="34" patternUnits="userSpaceOnUse">
            <path d="M 34 0 L 0 0 0 34" fill="none" stroke="#1e293b" strokeWidth="1" />
          </pattern>
          <clipPath id="lp-clip">
            <rect x="0" y="0" width={VIEW_W} height={VIEW_H} />
          </clipPath>
        </defs>
        <rect width={VIEW_W} height={VIEW_H} fill="#020617" />
        <rect width={VIEW_W} height={VIEW_H} fill="url(#lp-grid)" />

        {/* The road that was driven */}
        <path d={routePath} fill="none" stroke="#334155" strokeWidth="10" strokeLinecap="round" />
        <path d={routePath} fill="none" stroke="#475569" strokeWidth="1.5"
              strokeDasharray="6 8" strokeLinecap="round" />

        {/* Error radius, to scale and clipped to the plot. On a straight pass
            this is genuinely larger than the view — which is the point. */}
        {frame.fix && frame.estimate?.errorRadiusM != null && (
          <g clipPath="url(#lp-clip)">
            <circle cx={sx(frame.fix.x)} cy={sy(frame.fix.y)}
                    r={Math.max(2, frame.estimate.errorRadiusM * scaleM)}
                    fill="rgba(168,85,247,0.07)" stroke="rgba(168,85,247,0.40)"
                    strokeWidth="1" strokeDasharray="4 4" />
          </g>
        )}

        {/* Sightings so far */}
        {frame.seen.map((s, i) => (
          <circle key={i} cx={sx(s.x)} cy={sy(s.y)} r="2.6"
                  fill={rssiColour(s.rssi)} opacity="0.85" />
        ))}

        {/* The mirrored candidate: an equally good answer, never a lesser one */}
        {frame.mirror && frame.fix && (
          <>
            <line x1={sx(frame.fix.x)} y1={sy(frame.fix.y)}
                  x2={sx(frame.mirror.x)} y2={sy(frame.mirror.y)}
                  stroke="#f59e0b" strokeWidth="1" strokeDasharray="5 5" opacity="0.8" />
            <circle cx={sx(frame.mirror.x)} cy={sy(frame.mirror.y)} r="7"
                    fill="none" stroke="#f59e0b" strokeWidth="2" />
            <text x={sx(frame.mirror.x) + 11} y={sy(frame.mirror.y) + 4}
                  fill="#f59e0b" fontSize="9" fontFamily="monospace">
              equally good
            </text>
          </>
        )}

        {/* Where the transmitter really is */}
        <g>
          <circle cx={sx(TRUE_X)} cy={sy(TRUE_Y)} r="5" fill="#ef4444" />
          <circle cx={sx(TRUE_X)} cy={sy(TRUE_Y)} r="11" fill="none"
                  stroke="#ef4444" strokeWidth="1" opacity="0.5" />
          <text x={sx(TRUE_X) + 15} y={sy(TRUE_Y) - 6} fill="#ef4444"
                fontSize="9" fontFamily="monospace">actual transmitter</text>
        </g>

        {/* The estimate */}
        {frame.fix && (
          <g>
            <line x1={sx(frame.fix.x) - 7} y1={sy(frame.fix.y)}
                  x2={sx(frame.fix.x) + 7} y2={sy(frame.fix.y)}
                  stroke="#a855f7" strokeWidth="2" />
            <line x1={sx(frame.fix.x)} y1={sy(frame.fix.y) - 7}
                  x2={sx(frame.fix.x)} y2={sy(frame.fix.y) + 7}
                  stroke="#a855f7" strokeWidth="2" />
            <text x={sx(frame.fix.x) + 11}
                  y={sy(frame.fix.y) + (sy(frame.fix.y) > VIEW_H - 30 ? -12 : 16)}
                  fill="#a855f7" fontSize="9" fontFamily="monospace">
              estimate
            </text>
          </g>
        )}

        {/* The vehicle */}
        <circle cx={sx(frame.car.x)} cy={sy(frame.car.y)} r="5" fill="#38bdf8" />
        <circle cx={sx(frame.car.x)} cy={sy(frame.car.y)} r="10" fill="none"
                stroke="#38bdf8" strokeWidth="1" opacity="0.45" />
      </svg>

      {/* Live readout. Every number here comes from the estimate object. */}
      <div className="px-3 py-2 border-t border-space-500/20 bg-space-900/40 flex flex-wrap items-center gap-x-5 gap-y-1">
        <Readout label="ERROR" value={frame.fix ? `${frame.fix.errorM.toFixed(0)} m` : '—'}
                 tone={!frame.fix ? 'dim' : frame.fix.errorM <= 20 ? 'good' : frame.fix.errorM <= 40 ? 'warn' : 'bad'} />
        <Readout label="STATED RADIUS"
                 value={frame.estimate?.errorRadiusM != null ? `±${frame.estimate.errorRadiusM.toFixed(0)} m` : 'none'}
                 tone={frame.estimate?.errorRadiusM == null ? 'dim' : 'plain'} />
        <Readout label="SIGHTINGS" value={String(frame.seen.length)} tone="plain" />
        {frame.estimate?.mirrorDistanceM != null && (
          <Readout label="CANDIDATES" value={`2, ${frame.estimate.mirrorDistanceM.toFixed(0)} m apart`} tone="warn" />
        )}
        <Readout
          label="GEOMETRY"
          value={geometry.count === 0 ? 'no data'
            : geometry.insufficientBaseline ? 'stationary'
            : geometry.mirrorAmbiguous ? 'straight — side unknown'
            : 'shaped'}
          tone={geometry.count === 0 ? 'dim' : geometry.mirrorAmbiguous ? 'warn' : 'good'}
        />
      </div>

      <p className="px-3 pb-2 text-[9px] font-mono text-gray-600 leading-relaxed">
        {/*
          One drive, one noise seed. The per-method figures in README and
          docs/AP_LOCATION_METHODS.md are medians over five seeds, so a single
          run here can land well above or below them — especially on a straight
          route, where the side of the road is a coin flip roughly two times in
          five. Saying so keeps the panel from reading as a contradiction.
        */}
        This is one drive with one noise seed, not the median of five that the docs quote.{' '}
        {route.hint}{' '}
        {frame.mirror
          ? 'The hollow amber ring is the other position that fits these measurements just as well — not a worse guess.'
          : frame.estimate?.errorRadiusM == null
            ? 'This method states no radius, so the report cannot say how far out it might be.'
            : 'The dashed ring is the radius containing roughly 95% of the estimate.'}
      </p>
    </div>
  );
}

function Readout({ label, value, tone }: {
  label: string;
  value: string;
  tone: 'good' | 'warn' | 'bad' | 'dim' | 'plain';
}) {
  const colour = {
    good: 'text-signal-strong',
    warn: 'text-risk-high',
    bad: 'text-risk-critical',
    dim: 'text-gray-600',
    plain: 'text-gray-300',
  }[tone];
  return (
    <div className="flex items-baseline gap-1.5">
      <span className="text-[8px] font-tactical tracking-widest text-gray-600">{label}</span>
      <span className={`text-[11px] font-mono ${colour}`}>{value}</span>
    </div>
  );
}
