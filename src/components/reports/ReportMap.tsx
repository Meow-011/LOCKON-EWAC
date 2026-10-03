/**
 * The interactive survey map on the Reports page.
 *
 * A move, not a merge: this is the component that was at the bottom of
 * `ReportsPage.tsx`, unchanged. The layers it shares with the live tactical map
 * went to `src/lib/map/surveyLayers.ts` in the phase before this one, and what is
 * left here is what makes this map the report's rather than the dashboard's --
 * framing the archive with `fitBounds`, flying to a selected access point, the
 * OFF / HOVER / ALL ring control, and the uncertainty paint that control makes
 * affordable.
 *
 * It is 620 lines, which is why it is a file. Inside `ReportsPage` it was the
 * last fifth of a page about exporting documents, and the two subjects had
 * nothing to say to each other.
 */
import { useEffect, useRef, useState } from 'react';
import maplibregl from 'maplibre-gl';

import { MAP_DEFAULT_CENTER, MAP_STYLES, isRemoteMapStyle } from '../../lib/constants';
import { escapeHtml, HIDDEN_SSID_LABEL } from '../../lib/html';
import { coordinatePair, finiteNumber } from '../../lib/numbers';
import { signalTextClass } from '../../lib/signalStyle';
import { assessAccessPoint } from '../../lib/riskEngine';
import { isHighRiskAp, toApInput, worstOf } from '../../lib/apRisk';
import {
  apMirror,
  formatCoord,
  formatErrorRadius,
  formatMetres,
  isMirrorAmbiguous,
} from '../../lib/position';
import { uncertaintyFeatures } from '../../lib/mapUncertainty';
import { apsOf, isWirelessReport } from '../../lib/report/archive';
import {
  addApLayers,
  addApSource,
  addHeatmapLayer,
  addTerrain,
  addTrackLayers,
} from '../../lib/map/surveyLayers';
import { useEngineStore } from '../../stores/engineStore';
import type { Report as IntelReport } from '../../stores/reportStore';

export function ReportMap({ report, focusBssid }: { report: IntelReport, focusBssid: string | null }) {
  const mapContainer = useRef<HTMLDivElement>(null);
  const mapRef = useRef<maplibregl.Map | null>(null);
  const popupRef = useRef<maplibregl.Popup | null>(null);
  const [mapFilter, setMapFilter] = useState<'ALL' | 'HIGH_RISK' | 'OPEN'>('ALL');
  /**
   * How much of the position uncertainty to draw.
   *
   * Every ring was drawn at once, at 8% fill. That is fine for a dozen access
   * points and mathematically doomed for a hundred: overlapping alpha compounds,
   * so 100 rings over one block reach 1 - 0.92^100 = 99.97% opacity. The result
   * was a solid orange disc that hid the markers underneath and communicated
   * nothing about any individual estimate.
   *
   * The radius itself is not hidden by this control — it is in every popup, in
   * the tables and in the PDF. This decides only whether the ring is painted,
   * and defaults to the one access point the cursor is actually on.
   */
  const [ringMode, setRingMode] = useState<'HOVER' | 'ALL' | 'OFF'>('HOVER');
  const [hoveredBssid, setHoveredBssid] = useState<string | null>(null);

  /**
   * Bumped whenever the map's layers are (re)registered, so the data effects
   * re-run and push the access points and the GPS track back onto a style that
   * has just been rebuilt. Without it a fallback to the offline style produced a
   * map with no markers at all.
   */
  const [layersEpoch, setLayersEpoch] = useState(0);
  /**
   * True once the remote basemap failed and the offline style was substituted.
   * The panel says so, because an operator screenshotting an empty-looking map
   * for a report has to be able to tell "no networks here" from "no basemap".
   */
  const [basemapDegraded, setBasemapDegraded] = useState(false);
  const degradedRef = useRef(false);
  /**
   * How many markers on this map have a second, equally good candidate position.
   * The map says so on its face: a viewer who screenshots it must not be able to
   * read a two-answer position as one pin.
   */
  const [ambiguousOnMap, setAmbiguousOnMap] = useState(0);

  const mapStyle = useEngineStore(s => s.config.mapStyle) || 'DARK';
  const enable3DBuildings = useEngineStore(s => s.config.enable3DBuildings);
  const enableHeatmap = useEngineStore(s => s.config.enableHeatmap);

  useEffect(() => {
    if (!mapContainer.current) return;

    // Clean up previous map instance if re-initializing due to style change
    if (mapRef.current) {
      mapRef.current.remove();
      mapRef.current = null;
    }

    degradedRef.current = false;
    setBasemapDegraded(false);

    const map = new maplibregl.Map({
      container: mapContainer.current,
      style: MAP_STYLES[mapStyle] as any,
      center: MAP_DEFAULT_CENTER,
      zoom: 15,
      attributionControl: false,
      interactive: true,
      pitch: enable3DBuildings ? 60 : 0,
    });
    map.addControl(new maplibregl.NavigationControl({ showCompass: true }), 'top-right');
    map.addControl(new maplibregl.FullscreenControl(), 'top-right');
    map.addControl(new maplibregl.ScaleControl({ maxWidth: 200 }), 'bottom-left');

    popupRef.current = new maplibregl.Popup({
      closeButton: false,
      closeOnClick: false,
      offset: 10,
      className: 'tactical-popup pointer-events-none'
    });

    /**
     * Register every source and layer this panel owns.
     *
     * Idempotent, and called from both `load` and `styledata`. MapLibre does not
     * fire `load` when the style request fails, and every source and layer used
     * to be registered inside that one handler — so with no network the operator
     * got a blank panel with no access points and no GPS track, and no error.
     * On a report page that is worse than a broken map: an empty map exported as
     * evidence reads as "nothing was found here".
     */
    const registerLayers = () => {
      if (!map.getStyle()) return;
      if (map.getSource('gps-path') && map.getSource('aps-data')) {
        // Already registered against the current style.
        setLayersEpoch(e => e + 1);
        return;
      }

      addTrackLayers(map);

      addApSource(map);

      // The uncertainty a marker cannot carry on its own. A dot is a claim of a
      // point; the ring is the radius that claim actually has. Added before the
      // marker layers so it always draws underneath them.
      if (!map.getSource('ap-uncertainty')) map.addSource('ap-uncertainty', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] }
      });
      if (!map.getLayer('ap-uncertainty-fill')) map.addLayer({
        id: 'ap-uncertainty-fill',
        type: 'fill',
        source: 'ap-uncertainty',
        paint: {
          'fill-color': ['case', ['==', ['get', 'ambiguous'], true], '#f59e0b', '#38bdf8'],
          'fill-opacity': 0.08
        }
      });
      if (!map.getLayer('ap-uncertainty-outline')) map.addLayer({
        id: 'ap-uncertainty-outline',
        type: 'line',
        source: 'ap-uncertainty',
        paint: {
          'line-color': ['case', ['==', ['get', 'ambiguous'], true], '#f59e0b', '#38bdf8'],
          'line-width': 1,
          'line-opacity': 0.55,
          'line-dasharray': [2, 2]
        }
      });

      addApLayers(map, { heatmap: enableHeatmap });

      if (!map.getSource('ap-mirror')) map.addSource('ap-mirror', {
        type: 'geojson',
        data: { type: 'FeatureCollection', features: [] }
      });
      /*
        Both layers read one source that holds the joining lines and the candidate
        points together, so each has to say which it draws.

        Without the filter the circle layer below rendered a ring at every vertex
        of every line -- MapLibre draws a circle layer at each vertex, not only at
        Point features -- which put a 7px hollow candidate ring on top of the
        *primary* pin of every ambiguous access point. The primary then looked like
        a candidate too, in the figure whose whole job is to distinguish them.

        It is fixable in a line because the shared builder tags every feature with
        its `kind`; the inline version this replaced carried no such tag, which is
        why the defect had nowhere to be caught.
      */
      if (!map.getLayer('ap-mirror-link')) map.addLayer({
        id: 'ap-mirror-link',
        type: 'line',
        source: 'ap-mirror',
        filter: ['==', ['get', 'kind'], 'link'],
        paint: {
          'line-color': '#f59e0b',
          'line-width': 1.5,
          'line-opacity': 0.7,
          'line-dasharray': [3, 2]
        }
      });
      if (!map.getLayer('ap-mirror-point')) map.addLayer({
        id: 'ap-mirror-point',
        type: 'circle',
        source: 'ap-mirror',
        filter: ['==', ['get', 'kind'], 'mirror'],
        paint: {
          'circle-color': 'rgba(0,0,0,0)',
          'circle-radius': 7,
          'circle-stroke-width': 2,
          'circle-stroke-color': '#f59e0b',
          'circle-stroke-opacity': 0.95
        }
      });

      // 3D terrain, skipped once the basemap has degraded: the terrain tiles are
      // remote too, so requesting them when the network is already known to be
      // unavailable only produces more failed requests.
      if (enable3DBuildings && !degradedRef.current) addTerrain(map);

      if (enableHeatmap) addHeatmapLayer(map, 'ap-uncertainty-fill');

      const handleMouseEnter = (e: any) => {
        map.getCanvas().style.cursor = 'crosshair';
        if (!e.features || e.features.length === 0 || !popupRef.current) return;

        const props = e.features[0].properties;
        // Drives the uncertainty ring in HOVER mode.
        setHoveredBssid(typeof props.bssid === 'string' ? props.bssid : null);
        const coords = e.features[0].geometry.coordinates.slice();

        while (Math.abs(e.lngLat.lng - coords[0]) > 180) {
          coords[0] += e.lngLat.lng > coords[0] ? 360 : -360;
        }

        const isHighRisk = props.isHighRisk;
        const content = `
          <div class="px-2 py-1 min-w-[150px]">
            <div class="text-[11px] font-tactical tracking-wider ${isHighRisk ? 'text-risk-critical' : 'text-risk-low'} mb-1">${escapeHtml(props.ssid || HIDDEN_SSID_LABEL)}</div>
            <div class="text-[10px] font-mono text-gray-500">${escapeHtml(props.bssid)}</div>
            <div class="flex items-center gap-2 mt-2 pt-2 border-t border-gray-700/50">
              <span class="text-[9px] px-1.5 py-0.5 bg-gray-800 rounded font-mono text-gray-300">${escapeHtml(props.encryption)}</span>
              <span class="text-[9px] font-mono ${signalTextClass(props.rssi)}">${
                props.rssi === undefined || props.rssi === null ? 'n/r' : `${escapeHtml(props.rssi)} dBm`
              }</span>
              <span class="text-[9px] font-tactical ${isHighRisk ? 'text-risk-critical' : 'text-gray-400'}">${escapeHtml(props.severity ?? 'INFO')}</span>
            </div>
            <div class="text-[9px] font-mono text-gray-400 mt-1">${escapeHtml(props.errorRadius ?? 'no stated radius')} (95%)</div>
            ${/*
                 Two corrections the live map's popup already had.

                 The reading printed as `${escapeHtml(props.rssi)} dBm`, and
                 `escapeHtml` maps null to the empty string -- so an access point
                 with no reading showed " dBm", a blank where a measurement goes.
                 It is `n/r` above now, as everywhere else in this project.

                 And the ambiguity said how many candidates there were without
                 saying how far apart they are, which is the number that tells a
                 reader what the ambiguity actually costs.
               */ ''}
            ${props.ambiguous === true || props.ambiguous === 'true'
            ? `<div class="text-[9px] font-tactical text-amber-300 mt-1">AMBIGUOUS - 1 of 2 candidates${
              typeof props.mirrorDistanceM === 'number'
                ? `, ${escapeHtml(formatMetres(props.mirrorDistanceM))} apart`
                : ''
            }</div>`
            : ''}
            <div class="text-[8px] font-mono text-gray-500 mt-1">estimated position, not a surveyed one</div>
          </div>
        `;

        popupRef.current.setLngLat(coords as [number, number]).setHTML(content).addTo(map);
      };

      const handleMouseLeave = () => {
        map.getCanvas().style.cursor = '';
        if (popupRef.current) popupRef.current.remove();
        setHoveredBssid(null);
      };

      /** The mirror pin explains itself, or it is just an unexplained circle. */
      const handleMirrorEnter = (e: any) => {
        map.getCanvas().style.cursor = 'crosshair';
        if (!e.features || e.features.length === 0 || !popupRef.current) return;
        const props = e.features[0].properties;
        const coords = e.features[0].geometry.coordinates.slice();
        const content = `
          <div class="px-2 py-1 min-w-[170px]">
            <div class="text-[11px] font-tactical tracking-wider text-amber-300 mb-1">ALTERNATIVE POSITION</div>
            <div class="text-[10px] font-mono text-gray-300">${escapeHtml(props.ssid || HIDDEN_SSID_LABEL)}</div>
            <div class="text-[10px] font-mono text-gray-500">${escapeHtml(props.bssid)}</div>
            <div class="text-[9px] font-mono text-gray-400 mt-2 pt-2 border-t border-gray-700/50 leading-snug">
              Fits the measurements as well as ${escapeHtml(
                typeof props.primaryLat === 'number' && typeof props.primaryLon === 'number'
                  ? formatCoord(props.primaryLat, props.primaryLon)
                  : 'the other pin'
              )}, about ${escapeHtml(formatMetres(props.distanceM))} away.
              The route here was effectively straight, so which side the radio is on cannot be determined. One turn in a re-drive resolves it.
            </div>
          </div>
        `;
        popupRef.current.setLngLat(coords as [number, number]).setHTML(content).addTo(map);
      };

      if (!hoverBound) {
        map.on('mouseenter', 'aps-low-risk', handleMouseEnter);
        map.on('mouseleave', 'aps-low-risk', handleMouseLeave);
        map.on('mouseenter', 'aps-high-risk', handleMouseEnter);
        map.on('mouseleave', 'aps-high-risk', handleMouseLeave);
        map.on('mouseenter', 'ap-mirror-point', handleMirrorEnter);
        map.on('mouseleave', 'ap-mirror-point', handleMouseLeave);
        hoverBound = true;
      }

      // Tell the data effects to push the report back onto the new style.
      setLayersEpoch(e => e + 1);
    };

    let hoverBound = false;

    map.on('load', registerLayers);
    // `styledata` covers every later style swap, including the offline fallback
    // below. Registration is idempotent, so running twice is harmless.
    map.on('styledata', registerLayers);

    /**
     * A style that never loads leaves MapLibre silent: no `load`, no layers, no
     * markers, no message. Fall back to the bundled offline style so the access
     * points and the GPS track still render on a plain backdrop, and say plainly
     * that the basemap is missing.
     */
    map.on('error', (e: any) => {
      console.error('[ReportMap] MapLibre error:', e?.error ?? e);
      if (degradedRef.current) return;
      if (!isRemoteMapStyle(mapStyle)) return;
      degradedRef.current = true;
      setBasemapDegraded(true);
      try {
        map.setStyle(MAP_STYLES.OFFLINE as any);
      } catch (err) {
        console.error('[ReportMap] offline style fallback failed:', err);
      }
    });

    mapRef.current = map;

    return () => {
      if (mapRef.current) {
        mapRef.current.remove();
        mapRef.current = null;
      }
    };
  }, [mapStyle, enable3DBuildings, enableHeatmap]);

  const updateMapData = () => {
    if (!mapRef.current || !report.rawData) return;
    const map = mapRef.current;
    // `loaded()` is false while a style is still settling, and was the second
    // reason a rebuilt map came back empty. The sources are what matter here.
    if (!map.getSource('aps-data') || !map.getSource('gps-path')) return;

    const bounds = new maplibregl.LngLatBounds();
    let hasPoints = false;
    const features: any[] = [];
    /*
      What survived the filter, for the shared overlay builder.

      The rings, the mirror candidates and the line joining each pair used to be
      assembled here, inline, in a local array that happened to be called
      `uncertaintyFeatures` -- while `src/lib/mapUncertainty.ts` held a second
      implementation of the same overlay for the live map, with different layer
      ids, different paint and a different answer to the overlapping-rings
      problem. Two maps, one subject, no shared code: the exact failure the live
      one's own header says it exists to prevent.

      One builder now. This map keeps its OFF / HOVER / ALL control and therefore
      asks for no radius limit; the live map has every ring on screen at once and
      keeps `RING_LIMIT_M`.
    */
    const plotted: any[] = [];

    if (isWirelessReport(report)) {
      apsOf(report).forEach((ap: any) => {
        // `coordinatePair` rather than a truthiness test followed by `isNaN`:
        // the pair it rejects is exactly the pair the rest of the project
        // rejects, and longitude 0 is a place rather than an absent column.
        const pair = coordinatePair(ap.latitude, ap.longitude);
        if (pair) {
          const lat = pair.lat;
          const lon = pair.lon;

          // Risk on this map comes from the same rule set as the tables and the
          // PDF, so a marker's colour and its row's severity cannot disagree.
          const severity = worstOf(assessAccessPoint(toApInput(ap, !!report.simulated))).severity;
          // The same call the live map makes, rather than the expression spelled
          // out again -- it was spelled out twice in this file alone.
          const isHighRisk = isHighRiskAp(ap, !!report.simulated);

          let show = true;
          if (mapFilter === 'HIGH_RISK' && !isHighRisk) show = false;
          if (mapFilter === 'OPEN' && ap.encryption !== 'OPEN') show = false;

          if (show) {
            hasPoints = true;
            bounds.extend([lon, lat]);

            const ambiguous = isMirrorAmbiguous(ap);
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
                encryption: ap.encryption,
                severity,
                isHighRisk,
                errorRadius: formatErrorRadius(ap.location_error_m),
                ambiguous,
                // So the popup can state what the ambiguity costs rather than
                // only that there is one.
                mirrorDistanceM: apMirror(ap)?.distanceM ?? null,
              },
              geometry: {
                type: 'Point',
                coordinates: [lon, lat]
              }
            });

            // The frame has to include the second candidate, which is as much
            // the answer as the first one is.
            const mirror = apMirror(ap);
            if (mirror) bounds.extend([mirror.lon, mirror.lat]);
          }
        }
      });
    }

    const apsSource = map.getSource('aps-data') as maplibregl.GeoJSONSource;
    if (apsSource) {
      apsSource.setData({
        type: 'FeatureCollection',
        features
      });
    }

    /*
      One builder, two sources.

      `ringLimitM: Infinity` because this map answers the overlap problem with the
      OFF / HOVER / ALL control beside it rather than by leaving the widest radii
      out. The live map has no such control and keeps the limit.
    */
    const overlay = uncertaintyFeatures(plotted, { ringLimitM: Infinity });

    const uncertaintySource = map.getSource('ap-uncertainty') as maplibregl.GeoJSONSource | undefined;
    if (uncertaintySource) {
      uncertaintySource.setData({
        type: 'FeatureCollection',
        features: overlay.features.filter((f: any) => f.properties.kind === 'ring'),
      } as any);
    }

    const mirrorSource = map.getSource('ap-mirror') as maplibregl.GeoJSONSource | undefined;
    if (mirrorSource) {
      mirrorSource.setData({
        type: 'FeatureCollection',
        features: overlay.features.filter((f: any) => f.properties.kind !== 'ring'),
      } as any);
    }
    // The count of second candidates actually drawn, which is not the count of
    // access points flagged ambiguous -- a flag can arrive without coordinates.
    setAmbiguousOnMap(overlay.mirrorsDrawn);

    const pathSource = map.getSource('gps-path') as maplibregl.GeoJSONSource;
    if (pathSource) {
      const coords = report.rawData?.pathCoords || [];
      if (coords.length > 0) {
        coords.forEach((c: any) => bounds.extend(c));
      }
      pathSource.setData({
        type: 'Feature',
        properties: {},
        geometry: {
          type: 'LineString',
          coordinates: coords
        }
      });
    }

    if (!bounds.isEmpty() && (hasPoints || (report.rawData?.pathCoords && report.rawData.pathCoords.length > 0))) {
      map.fitBounds(bounds, { padding: 50, maxZoom: 18 });
    }
  };

  /**
   * Paint only the rings the operator asked for.
   *
   * Done with a layer filter rather than by rebuilding the GeoJSON: the
   * geometry is unchanged, only its visibility is, and re-running the source
   * update on every hover would rebuild every polygon in the archive.
   */
  useEffect(() => {
    const map = mapRef.current;
    if (!map || !map.getLayer('ap-uncertainty-fill')) return;

    const visible = ringMode !== 'OFF';
    const filter = ringMode === 'ALL'
      ? null
      // An empty BSSID matches nothing, which is what HOVER means with no hover.
      : ['==', ['get', 'bssid'], hoveredBssid ?? '__none__'] as any;

    for (const id of ['ap-uncertainty-fill', 'ap-uncertainty-outline']) {
      if (!map.getLayer(id)) continue;
      map.setLayoutProperty(id, 'visibility', visible ? 'visible' : 'none');
      map.setFilter(id, visible ? filter : null);
    }
    // A single ring can afford to be legible; a hundred stacked cannot.
    if (map.getLayer('ap-uncertainty-fill')) {
      map.setPaintProperty('ap-uncertainty-fill', 'fill-opacity',
        ringMode === 'ALL' ? 0.04 : 0.14);
    }
    if (map.getLayer('ap-uncertainty-outline')) {
      map.setPaintProperty('ap-uncertainty-outline', 'line-opacity',
        ringMode === 'ALL' ? 0.35 : 0.9);
    }
  }, [ringMode, hoveredBssid, layersEpoch]);

  // `layersEpoch` is the dependency that makes the data survive a style rebuild.
  useEffect(() => {
    updateMapData();
    // updateMapData closes over `report` and `mapFilter`, both listed here.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [report, mapFilter, layersEpoch]);

  // Handle Target Selection FlyTo
  useEffect(() => {
    if (!mapRef.current || !focusBssid || !report.rawData) return;

    const ap = apsOf(report).find((a: any) => a.bssid === focusBssid);
    const focus = ap ? coordinatePair(ap.latitude, ap.longitude) : null;
    if (ap && focus) {
      mapRef.current.flyTo({
        center: [focus.lon, focus.lat],
        zoom: 18,
        essential: true,
        duration: 1500
      });

      if (popupRef.current) {
        const isHighRisk = isHighRiskAp(ap, !!report.simulated);
        const content = `
          <div class="px-2 py-1 min-w-[150px]">
            <div class="text-[11px] font-tactical tracking-wider ${isHighRisk ? 'text-risk-critical' : 'text-risk-low'} mb-1">${escapeHtml(ap.ssid || HIDDEN_SSID_LABEL)}</div>
            <div class="text-[10px] font-mono text-gray-500">${escapeHtml(ap.bssid)}</div>
            <div class="flex items-center gap-2 mt-2 pt-2 border-t border-gray-700/50">
              <span class="text-[9px] px-1.5 py-0.5 bg-gray-800 rounded font-mono text-gray-300">${escapeHtml(ap.encryption)}</span>
              <span class="text-[9px] font-mono ${signalTextClass(ap.rssi)}">${escapeHtml(ap.rssi)} dBm</span>
            </div>
            <div class="text-[9px] font-mono text-gray-400 mt-1">${formatErrorRadius(ap.location_error_m)} (95%)</div>
            ${isMirrorAmbiguous(ap)
            ? `<div class="text-[9px] font-tactical text-amber-300 mt-1">AMBIGUOUS - 1 of 2 candidates${apMirror(ap) ? `, ${formatMetres(apMirror(ap)!.distanceM)} apart` : ''}</div>`
            : ''}
          </div>
        `;
        popupRef.current.setLngLat([ap.longitude, ap.latitude]).setHTML(content).addTo(mapRef.current);
      }
    }
  }, [focusBssid, report, layersEpoch]);

  return (
    <div className="w-full h-full relative group bg-space-950">
      <div ref={mapContainer} className="w-full h-full" />

      {/* A degraded basemap must be stated on the panel itself. An operator who
          screenshots this view for a report would otherwise hand over an empty
          map that reads as "nothing was found in this area". */}
      {basemapDegraded && (
        <div className="absolute top-3 left-3 z-20 max-w-[420px] bg-amber-400/15 border border-amber-400/50 rounded px-3 py-2 backdrop-blur-sm">
          <div className="text-[10px] font-tactical tracking-widest text-amber-300 mb-0.5">BASEMAP UNAVAILABLE - OFFLINE GRID</div>
          <div className="text-[10px] font-mono text-amber-200/90 leading-snug">
            The map tiles could not be fetched, so a plain offline backdrop is shown. The access point markers and the GPS track below are complete and unaffected. Do not read the missing streets as missing coverage, and do not use this view as a coverage screenshot.
          </div>
        </div>
      )}

      {/* A dashed ring is the radius the marker at its centre is entitled to, and
          a hollow amber circle is a second position that fits the measurements
          just as well as the pin it is joined to. Neither means anything to a
          viewer who is not told, and a screenshot carries no tooltips. */}
      <div className={`absolute z-20 max-w-[420px] rounded px-3 py-2 backdrop-blur-sm border ${basemapDegraded ? 'top-[92px]' : 'top-3'} left-3 ${ambiguousOnMap > 0 ? 'bg-amber-400/15 border-amber-400/50' : 'bg-space-900/80 border-space-500/40'}`}>
        <div className={`text-[10px] font-tactical tracking-widest mb-0.5 ${ambiguousOnMap > 0 ? 'text-amber-300' : 'text-gray-400'}`}>
          POSITION UNCERTAINTY
        </div>
        <div className={`text-[10px] font-mono leading-snug ${ambiguousOnMap > 0 ? 'text-amber-200/90' : 'text-gray-400'}`}>
          Hovering a marker draws the radius containing roughly 95% of that estimate; the figure is in the popup either way, and UNCERTAINTY RING switches between the hovered one, all of them, and none. Markers are estimates from signal measurements, not surveyed locations.
          {ambiguousOnMap > 0 && (
            <> {' '}<span className="text-amber-300">{ambiguousOnMap} access point{ambiguousOnMap === 1 ? ' has' : 's have'} TWO equally good positions</span> - the hollow amber circle joined to a pin by a dashed line is the alternative, not a separate network. The route past them was straight, so which side the radio is on cannot be determined. One turn in a re-drive resolves it.</>
          )}
        </div>
      </div>

      {/* Map Controls Container */}
      <div className="absolute bottom-4 right-4 z-20 flex items-end gap-3">
        {/*
          Uncertainty rings. Drawn for the hovered access point by default:
          painting all of them at once turned a dense block into one solid disc
          that hid the markers and said nothing about any single estimate.
          The radius stays in the popup, the tables and the PDF regardless.
        */}
        <div className="flex flex-col items-end gap-1.5">
          <div className="text-[10px] font-tactical text-gray-400 mb-1 mr-1 tracking-widest drop-shadow-md">UNCERTAINTY RING</div>
          <div className="flex bg-space-900/90 backdrop-blur-sm border border-space-500/30 rounded-lg p-1 shadow-lg w-max">
            {([['HOVER', 'ON HOVER'], ['ALL', 'ALL'], ['OFF', 'OFF']] as const).map(([mode, label]) => (
              <button
                key={mode}
                onClick={() => setRingMode(mode)}
                title={
                  mode === 'HOVER' ? 'Draw the radius only for the access point under the cursor'
                  : mode === 'ALL' ? 'Draw every radius at once — unreadable where access points are dense'
                  : 'Hide the rings. The radius is still stated in the popup and the report.'
                }
                className={`px-3 py-1.5 text-[10px] font-tactical rounded transition-colors ${ringMode === mode ? 'bg-space-700 text-white shadow-sm' : 'text-gray-400 hover:text-gray-200'}`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>

        {/* Geospatial Map Filters */}
        <div className="flex flex-col items-end gap-1.5">
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
          </div>
        </div>
      </div>
    </div>
  );
}
