import { useEffect, useRef, useState, type ReactNode } from 'react';
import maplibregl from 'maplibre-gl';
import 'maplibre-gl/dist/maplibre-gl.css';
import { MAP_DEFAULT_CENTER, MAP_DEFAULT_ZOOM, MAP_STYLES } from '../../lib/constants';
import { addApLayers, addApSource, addHeatmapLayer, addTerrain, addTrackLayers } from '../../lib/map/surveyLayers';
import { offlineStyleIfReady, resolveOfflineStyle } from '../../lib/basemap';
import { escapeHtml, HIDDEN_SSID_LABEL } from '../../lib/html';
import { RING_LIMIT_M, uncertaintyCaveat, uncertaintyFeatures, type UncertaintyFeatures } from '../../lib/mapUncertainty';
import { apMirror, formatErrorRadius, formatMetres, isMirrorAmbiguous, locationMethodLabel } from '../../lib/position';
import { coordinatePair, finiteNumber } from '../../lib/numbers';
import { isHighRiskAp } from '../../lib/apRisk';
import { useEngineStore } from '../../stores/engineStore';
import { useMissionStore } from '../../stores/missionStore';
import { useUIStore } from '../../stores/uiStore';

// Jitter removed as per user request to show exact real locations

/**
 * How much a mark on the map is actually claiming.
 *
 * The popup named the radio and its signal and said nothing about the position,
 * while the report printed a radius and an AMBIGUOUS flag for the same row.
 * During a survey this is the more useful of the two: it is what tells the
 * operator the geometry is not yet good enough and they should turn a corner
 * rather than drive the same street again.
 *
 * At module scope rather than inside the map effect because *two* popups describe
 * the same access point -- one on hover, one when a target is selected from the
 * scan feed -- and they said different things about it. One function, so they
 * cannot drift apart again.
 *
 * A missing radius is printed as such. `formatErrorRadius` returns "no stated
 * radius" for null, which is the one thing that must not be quietly rendered as a
 * tight number or omitted into blank space.
 */
function positionQualifier(props: {
  locationMethod?: unknown;
  locationErrorM?: unknown;
  ambiguous?: unknown;
  mirrorDistanceM?: unknown;
  resolved?: unknown;
}): string {
  const method = props.locationMethod
    ? `<span class="text-gray-500">${escapeHtml(locationMethodLabel(String(props.locationMethod)))}</span>`
    : '<span class="text-gray-500">estimator not recorded</span>';
  const radiusM = typeof props.locationErrorM === 'number' ? props.locationErrorM : null;
  const radius = escapeHtml(formatErrorRadius(radiusM));
  // MapLibre serialises feature properties through the style, so a boolean can
  // arrive as the string "true". Both forms are accepted rather than one of them
  // silently reading as false.
  const ambiguous = props.ambiguous === true || props.ambiguous === 'true';

  /*
    An access point no estimator could place.

    Selecting one from the scan feed flew the camera to its stored coordinate --
    which is the receiver's own position -- and opened a popup that looked exactly
    like a located transmitter. There is not even a dot there: unresolved marks are
    grouped into counted markers instead. So the popup was the only thing on screen
    at that coordinate, and it asserted a position the tool had explicitly refused
    to state.
  */
  if (props.resolved === false) {
    return `
      <div class="mt-1.5 pt-1.5 border-t border-space-500/30 text-[9px] font-mono leading-snug">
        <div class="text-amber-400/90">POSITION UNRESOLVED</div>
        <div class="text-gray-400 mt-0.5">
          The receiver did not travel far enough for any estimator to run. This mark is
          where it was heard from, not where it is. Drive or walk past it to resolve.
        </div>
      </div>
    `;
  }

  return `
    <div class="mt-1.5 pt-1.5 border-t border-space-500/30 text-[9px] font-mono leading-snug">
      <div class="flex items-center justify-between gap-2">
        ${method}
        <span class="${radiusM !== null ? 'text-gray-300' : 'text-amber-400/90'}">${radius}</span>
      </div>
      ${ambiguous ? `<div class="text-amber-400/90 mt-0.5">1 of 2 positions that fit${
        typeof props.mirrorDistanceM === 'number'
          ? `, ${escapeHtml(formatMetres(props.mirrorDistanceM))} apart`
          : ''
      }</div>` : ''}
    </div>
  `;
}

/**
 * One row of the map key per thing the map actually draws.
 *
 * At module scope so the swatches are not rebuilt on every render, and so the
 * list sits next to `positionQualifier` -- the two are the same subject said two
 * ways, one in a panel and one in a popup.
 *
 * The colours and dash patterns are the layer paint values repeated literally. A
 * swatch that only approximates the mark it describes is worse than none: the
 * operator would be matching the wrong shape.
 */
const MAP_KEY_ROWS: { swatch: ReactNode; label: string; note: string }[] = [
  {
    swatch: <span className="block w-3 h-3 rounded-full" style={{ background: '#10b981', border: '1px solid #064e3b' }} />,
    label: 'Estimated position',
    note: 'no finding raised',
  },
  {
    swatch: <span className="block w-3.5 h-3.5 rounded-full" style={{ background: '#ef4444', border: '1.5px solid #7f1d1d' }} />,
    label: 'Estimated position',
    note: 'open, or a finding raised',
  },
  {
    swatch: <span className="block w-3.5 h-3.5 rounded-full" style={{ border: '1px dashed #94a3b8' }} />,
    label: '95% radius',
    note: 'the dot is an inference with a width',
  },
  {
    swatch: <span className="block w-3.5 h-3.5 rounded-full" style={{ border: '1px dashed #f59e0b' }} />,
    label: 'Radius, side undetermined',
    note: 'widened to cover both candidates',
  },
  {
    swatch: (
      <svg viewBox="0 0 16 16" className="w-4 h-4" aria-hidden="true">
        <line x1="0" y1="14" x2="7" y2="7" stroke="#f59e0b" strokeWidth="1" strokeDasharray="1 2" />
        <circle cx="10" cy="5" r="4" fill="none" stroke="#f59e0b" strokeWidth="1.5" />
      </svg>
    ),
    label: 'Second candidate',
    note: 'the same transmitter, not another one',
  },
  {
    swatch: (
      <span className="flex items-center justify-center w-4 h-4 rounded-full border border-dashed border-gray-400 text-[7px] font-tactical text-gray-300">
        3
      </span>
    ),
    label: 'Heard here, not located',
    note: 'the receiver never moved far enough',
  },
  {
    swatch: <span className="block w-4 h-0.5 rounded" style={{ background: '#38bdf8' }} />,
    label: 'Track driven',
    note: 'accepted fixes only, not raw GPS',
  },
];

/**
 * The key, as a panel.
 *
 * Its own component so the control cluster reads as a cluster of controls, and so
 * the panel can be given its own row in that column -- it is wider and far taller
 * than any button beside it, and nesting it in a cell put it across its
 * neighbours.
 */
function MapKeyPanel({ onClose }: { onClose: () => void }) {
  return (
    <div className="pointer-events-auto w-[252px] rounded border border-space-500/40 bg-space-950/92 backdrop-blur-sm shadow-xl overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 border-b border-space-500/25">
        <span className="text-[9px] font-tactical tracking-widest text-gray-400">MAP KEY</span>
        <button
          onClick={onClose}
          className="text-gray-500 hover:text-gray-200 transition-colors"
          title="Close the key"
        >
          <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><path d="M18 6 6 18M6 6l12 12" /></svg>
        </button>
      </div>
      <div className="px-3 py-2 space-y-1.5">
        {MAP_KEY_ROWS.map(row => (
          <div key={row.label + row.note} className="flex items-start gap-2.5">
            <span className="shrink-0 w-4 flex items-center justify-center pt-0.5">{row.swatch}</span>
            <span className="min-w-0 leading-tight">
              <span className="block text-[10px] font-mono text-gray-300">{row.label}</span>
              <span className="block text-[9px] font-mono text-gray-600">{row.note}</span>
            </span>
          </div>
        ))}
      </div>
      {/*
          The undrawn radii are stated here as well as in the caveat line, because a
          reader counting rings has to know that some are missing by design rather
          than by failure.
      */}
      <div className="px-3 pb-2 pt-1 border-t border-space-500/20">
        <p className="text-[9px] font-mono text-gray-600 leading-snug">
          Radii wider than {RING_LIMIT_M} m are left undrawn &mdash; at survey density they
          overlap into one unreadable mass. Every radius is in the exported report, and
          the number omitted is stated bottom-left.
        </p>
      </div>
    </div>
  );
}

export function MapView() {
  const mapContainer = useRef<HTMLDivElement>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const egoMarkerRef = useRef<maplibregl.Marker | null>(null);
  /*
    Markers for access points no estimator could place.

    DOM markers rather than a MapLibre symbol layer, because a symbol layer with
    text needs `glyphs` and the offline style deliberately has none -- the count
    would vanish in exactly the degraded conditions where it matters most.
  */
  const unresolvedMarkersRef = useRef<maplibregl.Marker[]>([]);
  const egoPulseRef = useRef<HTMLDivElement | null>(null);
  const egoVehicleNodeRef = useRef<HTMLDivElement | null>(null);
  const popupRef = useRef<maplibregl.Popup | null>(null);
  /** One-shot: force a remote basemap attempt on the next map build. */
  const forceRemoteRef = useRef(false);

  const [autoFollow, setAutoFollow] = useState(true);
  const [mapFilter, setMapFilter] = useState<'ALL' | 'HIGH_RISK' | 'OPEN' | 'EVIL_TWIN'>('ALL');

  /**
   * Bumped every time the GPS / AP sources + layers are (re)registered on the
   * style. The data effects depend on it, so a style / 3D / heatmap rebuild —
   * or an automatic offline fallback — re-applies the existing track and
   * contacts instead of leaving the operator with an empty map until the next
   * scan batch arrives (which, on an archived mission, never happens).
   */
  const [layersReady, setLayersReady] = useState(0);

  /*
    What the uncertainty overlay is not showing, in words.

    The rings and the second candidates are drawn from the same columns the report
    prints, but a ring wider than the area surveyed cannot be drawn without making
    the map unreadable (see `RING_LIMIT_M`), and some positions carry no radius at
    all. Both are absences, and an absence on a map reads as a clean result unless
    something says otherwise.
  */
  const [uncertaintyNote, setUncertaintyNote] = useState<string | null>(null);

  /*
    The key, collapsed by default.

    There was none at all, which was already a gap -- a filled dot, a hollow
    dashed circle with a number in it and a blue line are three different kinds of
    statement -- and adding the uncertainty overlay made it three symbols worse.
    The report's figure has carried a KEY since it was written; the live map, which
    is what the operator actually acts on, explained nothing.

    Collapsed because the map is the content and a permanent panel costs the corner
    of a view that is often fullscreen. Open on a click, and kept for the session
    only: it is a reference, not a preference.
  */
  const [showKey, setShowKey] = useState(false);

  /** Basemap health. `null` message == healthy. */
  const [basemapFault, setBasemapFault] = useState<string | null>(null);
  const [basemapRetry, setBasemapRetry] = useState(0);
  const [isOnline, setIsOnline] = useState(
    () => typeof navigator === 'undefined' || navigator.onLine !== false
  );

  const scanning = useEngineStore(s => s.scanning);
  const gpsLocked = useEngineStore(s => s.gpsLocked);
  /*
    The accepted fix, not the raw one.

    The vehicle marker was drawn from `latitude`/`longitude` straight off the
    receiver, so parked it crawled around the map, span on the spot — course over
    ground is the direction of the receiver's own noise at zero speed — and with
    auto-follow on it dragged the whole map with it. The track already refused to
    record that as travel; the marker had no such rule, and the troubleshooting
    note saying this was fixed in v1.0.0 was describing the track.

    The raw pair is still what the readouts use, because satellite count and HDOP
    are facts about the fix. Where the operator *is* is a different claim, and it
    does not change until a fix is GPS_STEP_M away from the last one accepted.
  */
  const latitude = useEngineStore(s => s.acceptedLatitude);
  const longitude = useEngineStore(s => s.acceptedLongitude);
  const heading = useEngineStore(s => s.acceptedHeading);
  
  const mapStyle = useEngineStore(s => s.config.mapStyle) || 'DARK';
  const enable3DBuildings = useEngineStore(s => s.config.enable3DBuildings);
  const enableHeatmap = useEngineStore(s => s.config.enableHeatmap);
  
  const accessPoints = useMissionStore(s => s.accessPoints);
  const pathCoords = useMissionStore(s => s.pathCoords);
  const viewingMissionId = useMissionStore(s => s.viewingMissionId);
  
  const selectedBssid = useUIStore(s => s.selectedBssid);
  const egoVehicle = useUIStore(s => s.egoVehicle);
  const mapFullscreen = useUIStore(s => s.dashboardFocus === 'map');
  const toggleDashboardFocus = useUIStore(s => s.toggleDashboardFocus);

  useEffect(() => {
    if (!mapContainer.current) return;
    
    // Clean up previous map instance if re-initializing due to style change
    const prevZoom = mapRef.current?.getZoom() ?? MAP_DEFAULT_ZOOM;
    if (mapRef.current) {
      mapRef.current.remove();
      mapRef.current = null;
    }

    // navigator.onLine is only a HINT — a captive portal still reports "online",
    // and a stale "offline" can follow a reconnect. It therefore only decides
    // where we START; the actual decision is made by the map.on('error') handler.
    // An explicit operator RETRY always attempts the remote basemap, even if
    // navigator.onLine still claims we are offline (it lags behind reality).
    const forceRemote = forceRemoteRef.current;
    forceRemoteRef.current = false;
    const startOffline =
      !forceRemote && typeof navigator !== 'undefined' && navigator.onLine === false;

    /*
      Start reading the archive now, whether or not it is needed yet.

      The expensive moment is the first tile error on a rig that has just lost
      its connection -- the operator is already looking at a broken map. Reading
      the header at mount means the style is usually resolved by then, and the
      swap is immediate. It costs a handful of range reads against a local file
      on a path that does nothing otherwise, and it is a no-op when no archive is
      installed.
    */
    void resolveOfflineStyle((name, handler) => maplibregl.addProtocol(name, handler as any))
      .catch(() => { /* reported by the Settings card, not by a map toast */ });
    let offlineFallbackActive = startOffline;
    let disposed = false;

    setBasemapFault(
      startOffline
        ? 'No network detected at startup — offline grid basemap in use.'
        : null
    );

    const map = new maplibregl.Map({
      container: mapContainer.current,
      style: (startOffline ? (offlineStyleIfReady() ?? MAP_STYLES.OFFLINE) : MAP_STYLES[mapStyle]) as any,
      // `coordinatePair`, not `lat && lon`. A truthiness test treats latitude 0 or
      // longitude 0 as no fix, and this project already has one rule for that:
      // the equator and the prime meridian are real places, only exactly 0, 0 is
      // the absent value, and an out-of-range pair is not a position either.
      center: (() => {
        const fix = coordinatePair(latitude, longitude);
        return fix ? [fix.lon, fix.lat] as [number, number] : MAP_DEFAULT_CENTER;
      })(),
      zoom: prevZoom,
      attributionControl: false,
      interactive: true,
      pitch: enable3DBuildings ? 60 : 0, // Tilt map for 3D effect
    });

    map.addControl(new maplibregl.NavigationControl({ showCompass: true, visualizePitch: true }), 'top-right');
    map.addControl(new maplibregl.ScaleControl({ maxWidth: 200 }), 'bottom-left');

    const container = document.createElement('div');
    container.className = 'relative w-16 h-16 flex items-center justify-center';

    /*
      The scanning indicator, as a ring rather than a pulse.

      It was `animate-ping`: a filled disc expanding out of the vehicle twice a
      second, the largest moving thing on the map, sitting on exactly the ground
      the operator is reading. A static ring says the same thing -- a scan is
      running -- without animating over the data, and the top bar says it in words.
    */
    const pulse = document.createElement('div');
    pulse.className = 'absolute inset-2 rounded-full border border-neon-400/70 transition-opacity duration-300 opacity-0';
    egoPulseRef.current = pulse;
    container.appendChild(pulse);

    const car = document.createElement('div');
    car.className = 'absolute w-10 h-10 z-10 bg-contain bg-center bg-no-repeat transition-all duration-500';
    egoVehicleNodeRef.current = car;
    container.appendChild(car);

    /*
      Created hidden, and at the map's centre only because a Marker must be
      given some coordinate to exist.

      It used to be placed at MAP_DEFAULT_CENTER and left visible, which draws a
      vehicle in central Bangkok on a survey anywhere else in the country. There
      is nothing on screen to say it is a placeholder: it looks exactly like a
      position, so the first thing the operator sees is the rig somewhere it has
      never been. Hidden until a fix arrives, "we do not know yet" is shown as
      nothing at all, which is what it is.
    */
    container.style.visibility = 'hidden';
    const egoMarker = new maplibregl.Marker({ element: container, rotationAlignment: 'map' })
      .setLngLat(MAP_DEFAULT_CENTER)
      .addTo(map);

    egoMarkerRef.current = egoMarker;
    mapRef.current = map;

    // Initialize global hover popup
    popupRef.current = new maplibregl.Popup({
      closeButton: false,
      closeOnClick: false,
      offset: 15,
      className: 'tactical-popup'
    });

    // --- Sources + layers live in a NAMED function so they can be registered
    // --- on `load` AND again after an automatic fallback / style swap. They must
    // --- never be trapped inside a closure only `load` can reach: MapLibre does
    // --- not fire `load` when the style request fails, which used to leave the
    // --- operator with a blank panel and no track or contacts at all.
    const registerDataLayers = () => {
      addTrackLayers(map);

      addApSource(map);

      /*
        The uncertainty overlay, under the dots.

        Registered before `aps-low-risk` so the marks stay legible on top of their
        own rings; MapLibre draws in insertion order and a 90 m ring over a 5 px
        dot would hide the thing it qualifies.

        No fill on the rings. The report figure tried one and found that real
        surveys put a hundred and sixty radii within a few streets of each other,
        overlapping hundreds deep — at 3.5% fill that reaches 99.9% opacity, so no
        opacity is low enough. The edge carries the radius.
      */
      map.addSource('ap-uncertainty', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] }
      });

      map.addLayer({
        id: 'ap-uncertainty-ring',
        type: 'line',
        source: 'ap-uncertainty',
        filter: ['==', ['get', 'kind'], 'ring'],
        paint: {
          // Amber where which side of the road is undetermined, grey where the
          // position is single-valued and only imprecise. Two different
          // statements, and painting them alike would collapse them into one.
          'line-color': ['case', ['get', 'ambiguous'], '#f59e0b', '#94a3b8'],
          'line-width': 1,
          'line-opacity': 0.45,
          'line-dasharray': [2, 2]
        }
      });

      map.addLayer({
        id: 'ap-uncertainty-link',
        type: 'line',
        source: 'ap-uncertainty',
        filter: ['==', ['get', 'kind'], 'link'],
        paint: {
          // The line is what stops the second candidate being read as another
          // radio on the next street. It is the same transmitter.
          'line-color': '#f59e0b',
          'line-width': 1,
          'line-opacity': 0.5,
          'line-dasharray': [1, 2]
        }
      });

      map.addLayer({
        id: 'ap-uncertainty-mirror',
        type: 'circle',
        source: 'ap-uncertainty',
        filter: ['==', ['get', 'kind'], 'mirror'],
        paint: {
          // Hollow, like the report draws it, because a filled dot of the same
          // size would be counted as a second access point.
          'circle-color': 'rgba(0,0,0,0)',
          'circle-radius': 5,
          'circle-stroke-width': 1.5,
          'circle-stroke-color': '#f59e0b',
          'circle-stroke-opacity': 0.9
        }
      });

      addApLayers(map, { heatmap: enableHeatmap });

      // 3D terrain, skipped while the basemap is degraded — the terrain tiles
      // are remote too, so asking for them when the network is already known to
      // be unavailable only produces more failed requests.
      if (enable3DBuildings && !offlineFallbackActive) addTerrain(map);

      if (enableHeatmap) addHeatmapLayer(map, 'ap-uncertainty-ring');

    };

    /**
     * Idempotent, re-entrancy safe wrapper. `addSource` re-fires `styledata`
     * synchronously, and a style swap silently drops every source we own, so
     * 'aps-data' is used as the sentinel for "our layers exist on this style".
     */
    let registering = false;
    let graceTimer: ReturnType<typeof setTimeout> | null = null;
    let watchdogTimer: ReturnType<typeof setTimeout> | null = null;
    const clearTimers = () => {
      if (graceTimer) clearTimeout(graceTimer);
      if (watchdogTimer) clearTimeout(watchdogTimer);
      graceTimer = null;
      watchdogTimer = null;
    };

    const ensureDataLayers = () => {
      if (disposed || registering) return;
      if (!map.isStyleLoaded()) return;
      if (map.getSource('aps-data')) return;
      registering = true;
      try {
        registerDataLayers();
        clearTimers();
        // Tell the data effects to re-apply the current track + contacts.
        setLayersReady(v => v + 1);
      } catch (err) {
        console.error('[MapView] Failed to register map data layers:', err);
      } finally {
        registering = false;
      }
    };

    /** Swap to the bundled offline style so the data layers still get a home. */
    const fallbackToOfflineStyle = (reason: string) => {
      if (disposed || offlineFallbackActive) return;
      offlineFallbackActive = true;
      clearTimers();
      setBasemapFault(reason);
      try {
        /*
          The installed archive if there is one, and the flat grid if not.

          Applied in two steps because reading the archive's header is a disk
          read and this path is reached from a tile error, where the map is
          already broken and the operator is already waiting. The grid goes up
          immediately so the markers and the track have a home, and the real
          basemap replaces it when the header has been read. If nothing is
          installed the second step never happens and the behaviour is exactly
          what it was.
        */
        const ready = offlineStyleIfReady();
        // The failed style never fired `load`; setStyle gives us a fresh chance,
        // and `styledata` below re-registers the sources onto the new style.
        map.setStyle((ready ?? MAP_STYLES.OFFLINE) as any, { diff: false });
        if (!ready) {
          void resolveOfflineStyle((name, handler) => maplibregl.addProtocol(name, handler as any))
            .then(style => {
              // `disposed` and the fallback flag are both re-checked: an
              // operator who pressed RETRY in the meantime is back on the remote
              // basemap, and swapping it out from under them would undo it.
              if (style && !disposed && offlineFallbackActive) {
                map.setStyle(style as any, { diff: false });
                setBasemapFault('No network — using the installed offline basemap.');
              }
            })
            .catch(err => console.error('[MapView] Offline basemap could not be loaded:', err));
        }
      } catch (err) {
        console.error('[MapView] Offline basemap fallback failed:', err);
      }
    };

    // Surface every MapLibre error — never swallow it.
    map.on('error', (e: any) => {
      const err = e?.error ?? e;
      console.error('[MapView] MapLibre error:', err?.message ?? err, e?.sourceId ?? '');
      if (disposed) return;

      if (map.getSource('aps-data')) {
        // Our layers are already registered, so this is a tile / sprite / glyph
        // failure: the basemap will be patchy but the tactical data is intact.
        if (!offlineFallbackActive) {
          setBasemapFault('Basemap tiles unavailable — imagery may be incomplete.');
        }
        return;
      }

      if (!e?.sourceId) {
        // No sourceId => style document / sprite / glyph level failure. The style
        // will never load, so `load` will never fire: fall back immediately.
        fallbackToOfflineStyle(
          `Basemap "${mapStyle}" could not be loaded${isOnline ? '' : ' (no network)'} — offline grid in use.`
        );
        return;
      }

      // A source-level failure before our layers exist (e.g. an unreachable
      // TileJSON) also blocks `load`. Give the style a brief grace period so a
      // single bad tile does not needlessly drop a working basemap.
      if (!graceTimer) {
        graceTimer = setTimeout(() => {
          graceTimer = null;
          if (!disposed && !map.getSource('aps-data')) {
            fallbackToOfflineStyle(
              `Basemap sources for "${mapStyle}" are unreachable — offline grid in use.`
            );
          }
        }, 1500);
      }
    });

    // Captive portals and dead spots can hang the request instead of failing it,
    // in which case no error ever arrives and `load` never fires.
    if (!startOffline) {
      watchdogTimer = setTimeout(() => {
        watchdogTimer = null;
        if (!disposed && !map.getSource('aps-data')) {
          fallbackToOfflineStyle(
            'Basemap request timed out (dead spot or captive portal) — offline grid in use.'
          );
        }
      }, 8000);
    }

    map.on('load', ensureDataLayers);
    map.on('styledata', ensureDataLayers);
    map.on('idle', ensureDataLayers);

    // --- GeoJSON Hover Interactions (registered once per map instance; MapLibre
    // --- tolerates layer-scoped listeners bound before the layer exists) ---
    const handleMouseEnter = (e: any) => {
      map.getCanvas().style.cursor = 'crosshair';
      if (!e.features || e.features.length === 0 || !popupRef.current) return;
      
      const props = e.features[0].properties;
      const coords = e.features[0].geometry.coordinates.slice();

      // If multiple points overlap, it's fine, we show the top one
      while (Math.abs(e.lngLat.lng - coords[0]) > 180) {
        coords[0] += e.lngLat.lng > coords[0] ? 360 : -360;
      }

      const isHighRisk = props.isHighRisk;
      /*
        RSSI prints "n/r" when there is no reading.

        It was interpolated as `props.rssi || -90`, so a reading that does not
        exist rendered as "-90 dBm" -- the display-side twin of the `rssi ?? -90`
        write bug the signal-band tests exist to hold: a reading that was never
        taken is not the bottom of the scale. `||` is worse than `??` here, since
        it discards a genuine 0 as well.
      */
      const content = `
        <div class="px-3 py-2 min-w-[160px] pointer-events-none">
          <div class="text-xs font-bold text-white mb-0.5 truncate max-w-[200px]">${escapeHtml(props.ssid || HIDDEN_SSID_LABEL)}</div>
          <div class="flex items-center justify-between mt-1.5 border-b border-space-500/30 pb-1.5">
            <span class="text-[10px] text-gray-400 font-mono">${escapeHtml(props.bssid)}</span>
            <span class="text-[11px] font-mono font-bold ${isHighRisk ? 'text-risk-critical' : 'text-signal-strong'}">${props.rssi === undefined || props.rssi === null ? 'n/r' : `${escapeHtml(props.rssi)} dBm`}</span>
          </div>
          <div class="flex items-center justify-between mt-1.5">
            <span class="text-[9px] text-gray-500 font-tactical uppercase tracking-wider">${escapeHtml(props.vendor || 'UNKNOWN')}</span>
            <span class="text-[9px] font-mono uppercase bg-space-800 px-1 rounded ${isHighRisk ? 'text-risk-high' : 'text-gray-400'}">${escapeHtml(props.encryption)}</span>
          </div>
          ${positionQualifier(props)}
        </div>
      `;

      popupRef.current.setLngLat(coords as [number, number]).setHTML(content).addTo(map);
    };

    const handleMouseLeave = () => {
      map.getCanvas().style.cursor = '';
      if (popupRef.current) popupRef.current.remove();
    };

    /*
      The hollow ring needs to be able to say what it is.

      Unlabelled, an amber circle 80 m from a dot is read as another access point
      — which is the opposite of the truth. It is the same transmitter, in the
      place the survey geometry cannot rule out.
    */
    const handleMirrorEnter = (e: any) => {
      map.getCanvas().style.cursor = 'help';
      if (!e.features || e.features.length === 0 || !popupRef.current) return;
      const props = e.features[0].properties;
      const coords = e.features[0].geometry.coordinates.slice();
      popupRef.current.setLngLat(coords as [number, number]).setHTML(`
        <div class="px-3 py-2 max-w-[240px] pointer-events-none">
          <div class="text-[10px] font-tactical tracking-widest text-amber-400">SECOND CANDIDATE</div>
          <div class="text-xs font-bold text-white mt-0.5 truncate">${escapeHtml(props.ssid || HIDDEN_SSID_LABEL)}</div>
          <div class="text-[10px] font-mono text-gray-400">${escapeHtml(props.bssid)}</div>
          <div class="text-[10px] font-mono text-gray-300 mt-1.5 leading-snug">
            The same transmitter. This position and the filled mark fit the
            measurements equally well${
              typeof props.distanceM === 'number'
                ? `, and they are ${escapeHtml(formatMetres(props.distanceM))} apart`
                : ''
            }. Drive a route with a turn in it to rule one out.
          </div>
        </div>
      `).addTo(map);
    };
    map.on('mouseenter', 'ap-uncertainty-mirror', handleMirrorEnter);
    map.on('mouseleave', 'ap-uncertainty-mirror', handleMouseLeave);

    map.on('mouseenter', 'aps-low-risk', handleMouseEnter);
    map.on('mouseleave', 'aps-low-risk', handleMouseLeave);
    map.on('mouseenter', 'aps-high-risk', handleMouseEnter);
    map.on('mouseleave', 'aps-high-risk', handleMouseLeave);

    // Detect user manual map interaction to break auto-follow
    map.on('dragstart', () => {
      setAutoFollow(false);
    });

    return () => {
      disposed = true;
      clearTimers();
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, [mapStyle, enable3DBuildings, enableHeatmap, basemapRetry]);

  // Handle Vehicle Skin Updates
  useEffect(() => {
    if (egoVehicleNodeRef.current) {
      const bgUrl = egoVehicle.includes('.') ? egoVehicle : `${egoVehicle}.png`;
      egoVehicleNodeRef.current.style.backgroundImage = `url('/cars/${bgUrl}')`;
    }
  }, [egoVehicle]);

  // Handle Pulse Animation state
  useEffect(() => {
    if (egoPulseRef.current) {
      if (scanning) {
        egoPulseRef.current.classList.remove('opacity-0');
        egoPulseRef.current.classList.add('opacity-100');
      } else {
        egoPulseRef.current.classList.add('opacity-0');
        egoPulseRef.current.classList.remove('opacity-100');
      }
    }
  }, [scanning]);

  // Handle GPS Ego Marker updates
  useEffect(() => {
    if (!mapRef.current || !egoMarkerRef.current) return;
    
    // Hide ego vehicle during archive viewing
    if (viewingMissionId) {
       egoMarkerRef.current.getElement().style.display = 'none';
       return;
    } else {
       egoMarkerRef.current.getElement().style.display = 'flex';
    }

    // One rule for what counts as a fix. `!latitude || !longitude` hid the vehicle
    // on the equator and on the prime meridian.
    const fix = coordinatePair(latitude, longitude);
    if (!fix) {
      // No fix, no vehicle. See the note where the marker is created.
      egoMarkerRef.current.getElement().style.visibility = 'hidden';
      return;
    }

    const lngLat: [number, number] = [fix.lon, fix.lat];
    egoMarkerRef.current.getElement().style.visibility = 'visible';
    egoMarkerRef.current.setLngLat(lngLat);
    egoMarkerRef.current.setRotation(heading || 0);
    if (gpsLocked && !selectedBssid && autoFollow) {
      mapRef.current.easeTo({ center: lngLat });
    }
    // `layersReady` included so the freshly-created ego marker is moved off
    // MAP_DEFAULT_CENTER immediately after a map rebuild, rather than waiting
    // for the next GPS tick (which never arrives in archive review).
  }, [latitude, longitude, heading, gpsLocked, selectedBssid, viewingMissionId, autoFollow, layersReady]);

  // Track connectivity — a HINT only, used for the initial style choice and to
  // explain the degraded state. The error handler remains the authority.
  useEffect(() => {
    const goOnline = () => setIsOnline(true);
    const goOffline = () => setIsOnline(false);
    window.addEventListener('online', goOnline);
    window.addEventListener('offline', goOffline);
    return () => {
      window.removeEventListener('online', goOnline);
      window.removeEventListener('offline', goOffline);
    };
  }, []);

  // Handle GPS Path line updates.
  // `layersReady` is a dependency so the trail is re-applied after any map
  // rebuild (style / 3D / heatmap toggle) or offline fallback, instead of
  // waiting for the next GPS fix — which never comes on an archived mission.
  useEffect(() => {
    if (!mapRef.current) return;
    const map = mapRef.current;

    const updateSource = () => {
      const source = map.getSource('gps-path') as maplibregl.GeoJSONSource;
      if (source && pathCoords.length > 1) {
        source.setData({
          type: 'Feature',
          properties: {},
          geometry: {
            type: 'LineString',
            coordinates: pathCoords
          }
        });
      } else if (source) {
        source.setData({
          type: 'Feature',
          properties: {},
          geometry: { type: 'LineString', coordinates: [] }
        });
      }
    };

    // No `map.once('load', ...)` here: the sources are guaranteed to exist by
    // the time `layersReady` bumps, and one-shot listeners piled up per effect
    // run while the map was unloaded.
    updateSource();
  }, [pathCoords, layersReady]);

  // Handle FitBounds when loading an archive (re-framed after a map rebuild too,
  // so switching to satellite view for a report screenshot keeps the framing)
  useEffect(() => {
    if (viewingMissionId && pathCoords.length > 1 && mapRef.current) {
      const bounds = new maplibregl.LngLatBounds();
      pathCoords.forEach(coord => bounds.extend(coord));
      mapRef.current.fitBounds(bounds, { padding: 50, duration: 2000 });
    }
  }, [viewingMissionId, layersReady]);

  // Handle Map AP Data updates (also re-applied on every `layersReady` bump)
  useEffect(() => {
    if (!mapRef.current) return;
    const map = mapRef.current;
    
    const updateAPSource = () => {
      const source = map.getSource('aps-data') as maplibregl.GeoJSONSource;
      if (!source) return;

      const features: any[] = [];
      /*
        The access points that survived the filter, kept so the uncertainty
        overlay is built from exactly the marks that are on the map. Built from a
        second pass over `accessPoints` and the rings would annotate radios the
        filter had just hidden.
      */
      const plotted: any[] = [];
      accessPoints.forEach(ap => {
        if (ap.latitude != null && ap.longitude != null) {
          const lat = Number(ap.latitude);
          const lon = Number(ap.longitude);
          if (isNaN(lat) || isNaN(lon)) return;

          // Unresolved positions are grouped below instead of plotted here. All
          // of them sit on the receiver -- measured at 1.6 m apart across twelve
          // transmitters 30 to 300 m away -- so drawing them individually stacks
          // them into one unreadable pile that still reads as N separate places.
          if (ap.location_resolved === false) return;

          let show = true;
          /*
            The rule set, not `is_vulnerable || OPEN`.

            The report's map derives this from `assessAccessPoint` + `worstOf`
            under a comment saying "so a marker's colour and its row's severity
            cannot disagree"; this map asked a different question, so a WPA2
            network the rule set raises a HIGH finding against without the engine
            having set `is_vulnerable` was green here and red in the document made
            from the same mission -- and the RISK filter kept different sets.
          */
          const isHighRisk = isHighRiskAp(ap, !!ap.simulated);
          
          if (mapFilter === 'HIGH_RISK' && !isHighRisk) show = false;
          if (mapFilter === 'OPEN' && ap.encryption !== 'OPEN') show = false;
          if (mapFilter === 'EVIL_TWIN' && !ap.is_evil_twin) show = false;

          if (show) {
            plotted.push(ap);
            features.push({
              type: 'Feature',
              properties: {
                bssid: ap.bssid,
                ssid: ap.ssid,
                rssi: ap.rssi,
                // Whether there is a reading at all, for the heatmap's filter.
                // `rssi` is nullable and the weight expression cannot say so.
                hasReading: finiteNumber(ap.rssi) !== null,
                vendor: ap.vendor,
                encryption: ap.encryption,
                isHighRisk,
                /*
                  Carried so the popup can qualify the dot it is describing.

                  A dot is an assertion, and these three columns are what the
                  report prints beside the same coordinate. Reaching `MapView` on
                  every feature and never being read is how the screen came to be
                  more confident than the document made from it.

                  `?? null` rather than omitted: MapLibre serialises feature
                  properties through the style, and an absent key and a null one
                  are not distinguishable on the way out, so the popup has to
                  treat null as "not stated" either way.
                */
                locationErrorM: finiteNumber(ap.location_error_m),
                ambiguous: isMirrorAmbiguous(ap),
                mirrorDistanceM: apMirror(ap)?.distanceM ?? null,
                locationMethod: ap.location_method ?? null,
                // Always true in this source -- unresolved access points returned
                // above and are grouped into counted markers instead. Stated
                // explicitly because the same qualifier serves the selection
                // popup, which reads the record directly and can see a false one.
                resolved: true,
              },
              geometry: {
                type: 'Point',
                coordinates: [lon, lat]
              }
            });
          }
        }
      });

      source.setData({
        type: 'FeatureCollection',
        features
      });

      /*
        The rings and the second candidates, from the same columns the report
        reads and through the same helpers, so the live map and the document
        cannot disagree about one mission again.
      */
      const uncertainty: UncertaintyFeatures = uncertaintyFeatures(plotted);
      const uncertaintySource = map.getSource('ap-uncertainty') as maplibregl.GeoJSONSource;
      if (uncertaintySource) {
        uncertaintySource.setData({
          type: 'FeatureCollection',
          features: uncertainty.features
        });
      }
      setUncertaintyNote(uncertaintyCaveat(uncertainty));
    };

    /*
      One marker per place the operator stood, not one per access point.

      A survey taken without moving cannot place anything: every estimate
      collapses onto the receiver, so N access points become N identical marks.
      Stacking them is unreadable and still implies N distinct positions;
      dropping them silently is worse, because an empty map reads as "nothing
      was there". Grouping says the true thing -- this many radios were heard
      from here, and none of them could be located.

      Grouped on a ~30 m grid rather than to a single centroid: an operator who
      stops twice has two stationary clusters hundreds of metres apart, and one
      averaged marker would sit between them, where nothing was ever measured.
    */
    const updateUnresolved = () => {
      for (const m of unresolvedMarkersRef.current) m.remove();
      unresolvedMarkersRef.current = [];

      const CELL_DEG = 30 / 111320;
      const groups = new Map<string, { lat: number; lon: number; n: number; risk: number }>();
      accessPoints.forEach(ap => {
        if (ap.location_resolved !== false) return;
        const lat = Number(ap.latitude);
        const lon = Number(ap.longitude);
        if (!Number.isFinite(lat) || !Number.isFinite(lon)) return;
        // The same rule as the plotted marks, so a grouped count and a dot
        // cannot disagree about which radios are the ones to look at.
        const isHighRisk = isHighRiskAp(ap, !!ap.simulated);
        if (mapFilter === 'HIGH_RISK' && !isHighRisk) return;
        if (mapFilter === 'OPEN' && ap.encryption !== 'OPEN') return;
        if (mapFilter === 'EVIL_TWIN' && !ap.is_evil_twin) return;
        const key = `${Math.round(lat / CELL_DEG)}:${Math.round(lon / CELL_DEG)}`;
        const g = groups.get(key);
        if (g) { g.lat += lat; g.lon += lon; g.n += 1; g.risk += isHighRisk ? 1 : 0; }
        else groups.set(key, { lat, lon, n: 1, risk: isHighRisk ? 1 : 0 });
      });

      for (const g of groups.values()) {
        const el = document.createElement('div');
        el.className = 'flex items-center justify-center rounded-full border-2 border-dashed '
          + 'text-[10px] font-tactical pointer-events-auto cursor-help '
          + (g.risk > 0 ? 'border-risk-critical text-risk-critical' : 'border-gray-400 text-gray-300');
        // Sized by count so a dense stop reads as dense, with a ceiling so one
        // busy location cannot swallow the view.
        const size = Math.min(64, 28 + Math.round(Math.sqrt(g.n) * 5));
        el.style.width = `${size}px`;
        el.style.height = `${size}px`;
        el.style.background = 'rgba(2,6,23,0.55)';
        el.textContent = String(g.n);
        el.title =
          `${g.n} access point(s) heard from here, none of them located.
`
          + `${g.risk} flagged high risk.

`
          + 'The receiver did not move far enough for any estimator to run, so '
          + 'there is no position to draw for them - only the fact that they '
          + 'were audible from this spot. Drive or walk past them to resolve.';
        unresolvedMarkersRef.current.push(
          new maplibregl.Marker({ element: el })
            .setLngLat([g.lon / g.n, g.lat / g.n])
            .addTo(map)
        );
      }
    };

    // Same as the GPS path: driven by `layersReady`, never by a one-shot
    // `load` listener (those accumulated one per effect run).
    updateAPSource();
    updateUnresolved();
    return () => {
      for (const m of unresolvedMarkersRef.current) m.remove();
      unresolvedMarkersRef.current = [];
    };
  }, [accessPoints, mapFilter, layersReady]);

  // Handle Target Selection FlyTo
  useEffect(() => {
    if (!mapRef.current || !selectedBssid) return;
    
    // Disable auto-follow when manually inspecting a target to prevent camera tug-of-war
    setAutoFollow(false);

    // Fetch the AP directly to avoid putting accessPoints in the dependency array
    const ap = useMissionStore.getState().accessPoints.get(selectedBssid);
    // The same coordinate rule as everywhere else, instead of `ap.latitude &&
    // ap.longitude` -- which also rejected the equator and the prime meridian.
    const target = ap ? coordinatePair(ap.latitude, ap.longitude) : null;
    if (ap && target) {
      // Fly map to the exact target location
      mapRef.current.flyTo({
        center: [target.lon, target.lat],
        zoom: 17,
        essential: true,
        duration: 1500
      });

      // Auto-open Popup to highlight selection
      if (popupRef.current) {
        const isHighRisk = isHighRiskAp(ap, !!ap.simulated);
        const content = `
          <div class="px-3 py-2 min-w-[160px] pointer-events-none">
            <div class="text-xs font-bold text-white mb-0.5 truncate max-w-[200px]">${escapeHtml(ap.ssid || HIDDEN_SSID_LABEL)}</div>
            <div class="flex items-center justify-between mt-1.5 border-b border-space-500/30 pb-1.5">
              <span class="text-[10px] text-gray-400 font-mono">${escapeHtml(selectedBssid)}</span>
              <span class="text-[11px] font-mono font-bold ${isHighRisk ? 'text-risk-critical' : 'text-signal-strong'}">${ap.rssi === undefined || ap.rssi === null ? 'n/r' : `${escapeHtml(ap.rssi)} dBm`}</span>
            </div>
            <div class="flex items-center justify-between mt-1.5">
              <span class="text-[9px] text-gray-500 font-tactical uppercase tracking-wider">${escapeHtml(ap.vendor || 'UNKNOWN')}</span>
              <span class="text-[9px] font-mono uppercase bg-space-800 px-1 rounded ${isHighRisk ? 'text-risk-high' : 'text-gray-400'}">${escapeHtml(ap.encryption)}</span>
            </div>
            ${/*
                The same qualifier the hover popup uses.

                These two popups describe the same access point and said different
                things about it: hovering the dot stated the estimator, the radius
                and the ambiguity, while selecting the row from the scan feed --
                which is how an operator usually arrives at a specific radio --
                showed none of it. And for an unresolved access point the selection
                popup was worse than incomplete: there is no dot at that coordinate
                at all, so the popup was the only thing on screen there, asserting a
                position the tool had refused to state.
              */ ''}
            ${positionQualifier({
              locationMethod: ap.location_method ?? null,
              locationErrorM: finiteNumber(ap.location_error_m),
              ambiguous: isMirrorAmbiguous(ap),
              mirrorDistanceM: apMirror(ap)?.distanceM ?? null,
              resolved: ap.location_resolved !== false,
            })}
          </div>
        `;
        popupRef.current.setLngLat([target.lon, target.lat]).setHTML(content).addTo(mapRef.current);
      }
    }
  }, [selectedBssid]);

  // HTML Marker logic has been removed. Using pure GeoJSON rendering for performance and exact location accuracy.

  return (
    <div className="relative glass-card overflow-hidden h-full scanline-overlay bg-space-950">
      {/* Map Header */}
      <div className="absolute top-0 left-0 right-0 z-10 flex items-center justify-between px-4 pr-12 py-2 bg-gradient-to-b from-space-900/90 to-transparent pointer-events-none">
        <div className="flex items-center gap-2">
          {gpsLocked ? (
             <div className="w-1.5 h-1.5 rounded-full bg-signal-strong animate-pulse-slow" />
          ) : scanning ? (
             <div className="w-1.5 h-1.5 rounded-full bg-risk-high animate-pulse" />
          ) : (
            <div className="w-1.5 h-1.5 rounded-full bg-gray-600" />
          )}
          <span className="text-xs text-tactical text-gray-300 tracking-wider">TACTICAL MAP</span>
        </div>

        {/* Fullscreen Toggle */}
        <button 
          onClick={() => toggleDashboardFocus('map')}
          className="text-gray-400 hover:text-white transition-colors p-1.5 z-20 pointer-events-auto bg-space-950/80 rounded border border-space-500/30 backdrop-blur-sm hover:bg-space-800 shadow-lg mt-1 mr-1"
          title={mapFullscreen ? "Collapse Map" : "Expand Map"}
        >
          {mapFullscreen ? (
            <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3"/></svg>
          ) : (
            <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>
          )}
        </button>
      </div>

      {/* Map Container */}
      <div ref={mapContainer} className={`w-full h-full min-h-[300px] transition-opacity duration-700 ${scanning && !gpsLocked ? 'opacity-30 mix-blend-luminosity' : 'opacity-100'}`} />

      {/* Degraded basemap indicator — the map itself is a plain grid, but the
          scan is untouched. Never implies the scan or recording has failed. */}
      {basemapFault && (
        <div className="absolute top-9 left-1/2 -translate-x-1/2 z-30 max-w-[92%] pointer-events-auto">
          <div className="flex items-start gap-2.5 px-3 py-2 rounded border border-signal-fair/50 bg-space-950/90 backdrop-blur-sm shadow-lg">
            <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 shrink-0 mt-0.5 text-signal-fair" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2 2 21h20L12 2z" />
              <line x1="12" y1="9" x2="12" y2="14" />
              <line x1="12" y1="17.5" x2="12" y2="17.5" />
            </svg>
            <div className="min-w-0">
              <div className="text-[11px] font-tactical tracking-widest text-signal-fair">
                BASEMAP DEGRADED{isOnline ? '' : ' — NO NETWORK'}
              </div>
              <div className="text-[10px] font-mono text-gray-300 mt-0.5 leading-snug">
                {basemapFault}
              </div>
              <div className="text-[10px] font-mono text-signal-strong mt-1 leading-snug">
                Scanning, GPS logging and recording are UNAFFECTED — contacts and
                track are shown on the offline grid.
              </div>
            </div>
            <button
              onClick={() => {
                forceRemoteRef.current = true;
                setBasemapRetry(v => v + 1);
              }}
              className="shrink-0 self-center px-2 py-1 text-[9px] font-tactical tracking-widest rounded border border-space-500/50 text-gray-300 hover:text-white hover:border-gray-400 transition-colors"
              title="Rebuild the map and retry the remote basemap"
            >
              RETRY
            </button>
          </div>
        </div>
      )}

      {/*
          What the overlay is not showing.

          Rendered only when there is something to qualify. A permanent line that
          usually reads "0 omitted" is a line the operator stops seeing, and the
          whole point of it is to be read on the one survey where it matters.

          Bottom-left but above the scale bar. MapLibre's ScaleControl is added
          to `bottom-left` and that container puts it at `bottom: 10px; left:
          10px` with a width up to 200px, so at `bottom-2` this sat directly on
          top of it -- amber text over a white scale bar. `bottom-12` clears it,
          and the block grows upward as the text wraps.

          `pointer-events-none` so it never intercepts a drag on the map.
      */}
      {uncertaintyNote && (
        <div className="absolute bottom-12 left-2 z-20 pointer-events-none max-w-[60%]">
          <div className="px-2 py-1 rounded bg-space-950/80 border border-space-500/40 backdrop-blur-sm">
            <div className="text-[9px] font-mono text-amber-400/90 leading-snug">
              Uncertainty not fully drawn: {uncertaintyNote}
            </div>
          </div>
        </div>
      )}

      {/* NO FIX Overlay */}
      {scanning && !gpsLocked && (
        <div className="absolute inset-0 pointer-events-none flex flex-col items-center justify-center bg-space-950/40 backdrop-blur-[2px] z-20">
           <svg className="w-12 h-12 text-risk-critical animate-spin-slow mb-4 opacity-80" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
             <circle cx="12" cy="12" r="10" strokeDasharray="16 16" />
             <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4" />
           </svg>
           <div className="text-risk-high font-tactical tracking-widest text-lg animate-pulse">ACQUIRING SATELLITE UPLINK</div>
           <div className="text-gray-400 font-mono text-xs mt-2">Searching for valid NMEA GPS stream...</div>
        </div>
      )}

      {/* Crosshair overlay */}
      <div className="absolute inset-0 pointer-events-none flex items-center justify-center z-10">
        <div className="relative w-8 h-8">
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-px h-2.5 bg-space-500/40" />
          <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-px h-2.5 bg-space-500/40" />
          <div className="absolute left-0 top-1/2 -translate-y-1/2 h-px w-2.5 bg-space-500/40" />
          <div className="absolute right-0 top-1/2 -translate-y-1/2 h-px w-2.5 bg-space-500/40" />
        </div>
      </div>

      {/*
          Map Controls Container.

          A column, not a row with the key panel inside one of its cells. The panel
          is 252px wide and about 200px tall and it opened upward from inside the
          left-hand cell, which put it across the MAP FILTER buttons sitting beside
          that cell -- the kind of overlap that depends on the panel's height and so
          survives a quick look at one viewport. Giving it its own row above the
          controls makes the collision impossible rather than unlikely.
      */}
      <div className="absolute bottom-4 right-4 z-20 flex flex-col items-end gap-2 pointer-events-none">
        {showKey && <MapKeyPanel onClose={() => setShowKey(false)} />}
        <div className="flex items-end gap-3">
        {/*
            What the marks mean.

            Every row describes one thing that is actually drawn, and each swatch is
            built from the same colours and dash pattern as the layer that draws it
            -- a key painted from memory is a second source of truth and would
            drift from the map it describes. The wording says what a mark *claims*
            rather than what it looks like, because that is the part an operator
            cannot infer from the screen.
        */}
        <button
            onClick={() => setShowKey(v => !v)}
            className={`pointer-events-auto px-2.5 py-1.5 text-[10px] font-tactical tracking-widest rounded border transition-colors shadow-lg backdrop-blur-sm ${
              showKey
                ? 'bg-space-700 border-space-500/50 text-white'
                : 'bg-space-900/90 border-space-500/30 text-gray-400 hover:text-gray-200'
            }`}
            title="What the marks on this map mean"
          >
            KEY
          </button>

        {/* Geospatial Map Filters */}
        <div className="flex flex-col items-end gap-1.5 pointer-events-auto">
          <div className="text-[10px] font-tactical text-gray-400 mb-1 mr-1 tracking-widest drop-shadow-md">MAP FILTER</div>
          <div className="flex bg-space-900/90 backdrop-blur-sm border border-space-500/30 rounded-lg p-1 shadow-lg w-max">
            <button 
              onClick={() => setMapFilter('ALL')} 
              className={`px-3 py-1.5 text-[10px] font-tactical rounded transition-colors ${mapFilter === 'ALL' ? 'bg-space-700 text-white shadow-sm' : 'text-gray-400 hover:text-gray-200'}`}
            >
              ALL
            </button>
            <button 
              onClick={() => setMapFilter('HIGH_RISK')} 
              className={`px-3 py-1.5 text-[10px] font-tactical rounded transition-colors ${mapFilter === 'HIGH_RISK' ? 'bg-risk-high/30 text-risk-high shadow-sm' : 'text-gray-400 hover:text-risk-high'}`}
            >
              RISK
            </button>
            <button 
              onClick={() => setMapFilter('OPEN')} 
              className={`px-3 py-1.5 text-[10px] font-tactical rounded transition-colors ${mapFilter === 'OPEN' ? 'bg-risk-critical/30 text-risk-critical shadow-sm' : 'text-gray-400 hover:text-risk-critical'}`}
            >
              OPEN
            </button>
            <button 
              onClick={() => setMapFilter('EVIL_TWIN')} 
              className={`px-3 py-1.5 text-[10px] font-tactical rounded transition-colors ${mapFilter === 'EVIL_TWIN' ? 'bg-neon-500/30 text-neon-400 shadow-sm' : 'text-gray-400 hover:text-neon-400'}`}
            >
              EVIL TWIN
            </button>
          </div>
        </div>

        {/* Auto-Follow / Recenter Button */}
        {gpsLocked && !viewingMissionId && (
          <button
            onClick={() => {
              setAutoFollow(true);
              const fix = coordinatePair(latitude, longitude);
              if (fix && mapRef.current) {
                mapRef.current.flyTo({ center: [fix.lon, fix.lat], zoom: 17, duration: 1000 });
              }
            }}
            className={`pointer-events-auto w-10 h-10 rounded-full flex shrink-0 items-center justify-center border transition-all duration-300 shadow-lg ${
              autoFollow 
                ? 'bg-space-900 border-signal-strong text-signal-strong' 
                : 'bg-space-900 border-space-500 text-gray-400 hover:text-white hover:border-gray-400'
            }`}
            title={autoFollow ? "Lock-on Active" : "Re-center on Vehicle"}
          >
            <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <circle cx="12" cy="12" r="3" />
              {autoFollow && (
                <>
                  <line x1="12" y1="2" x2="12" y2="6" />
                  <line x1="12" y1="18" x2="12" y2="22" />
                  <line x1="4.93" y1="4.93" x2="7.76" y2="7.76" />
                  <line x1="16.24" y1="16.24" x2="19.07" y2="19.07" />
                  <line x1="2" y1="12" x2="6" y2="12" />
                  <line x1="18" y1="12" x2="22" y2="12" />
                  <line x1="4.93" y1="19.07" x2="7.76" y2="16.24" />
                  <line x1="16.24" y1="7.76" x2="19.07" y2="4.93" />
                </>
              )}
            </svg>
          </button>
        )}
        </div>
      </div>


    </div>
  );
}
