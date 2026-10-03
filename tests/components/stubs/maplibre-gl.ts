/**
 * A MapLibre that records what it was told, and draws nothing.
 *
 * Why this is allowed here.
 *
 * `vitest.config.ts` states the rule: the only things a component test may stand
 * in for are the ones a browser cannot provide. WebGL is one of them — jsdom has
 * no canvas context and no layout engine, so the real MapLibre throws on
 * construction and every page that holds a map was untestable for that reason
 * alone. The risk rule set, the archive readers and the palettes stay real.
 *
 * What this is, and what it deliberately is not.
 *
 * It **records calls**. It does not simulate behaviour: no tiles, no projection,
 * no layer ordering semantics, no hit testing. A stub that pretends to render
 * gives confidence in the stub rather than in the application, and this project
 * has already been bitten once by a check that passed because its subject had
 * disappeared.
 *
 * So the tests built on it assert *what the component told the map to draw* —
 * which sources were filled with which features, which popup was given which
 * HTML, which style was swapped in when the network failed. Whether the result
 * appears correctly on a screen is not knowable here and is not claimed; see the
 * engineering log's gaps section.
 *
 * Handlers registered through `on` are kept so a test can fire `error`, `load`,
 * `styledata` and `idle` by hand. That is the whole point for the basemap
 * fallback: it is a state machine driven by events that never arrive in jsdom.
 */

type Handler = (e?: any) => void;

/*
  The real `Map`, captured before this module exports one of its own.

  `export const Map = FakeMap` shadows the global inside this file, so a plain
  `new Map()` in the recorder below constructed a FakeMap, which constructed a
  FakeMap, until the stack ran out. It took a stack trace to see, because the
  error points at the field initialiser rather than at the name.
*/
const NativeMap = globalThis.Map;

/** Everything one map instance was asked to do, for assertions. */
export interface MapRecord {
  styles: any[];
  sources: InstanceType<typeof NativeMap>;
  layers: { id: string; def: any; beforeId?: string }[];
  data: InstanceType<typeof NativeMap>;
  filters: { id: string; filter: any }[];
  paint: { id: string; prop: string; value: any }[];
  layout: { id: string; prop: string; value: any }[];
  terrain: any[];
  eased: any[];
  flown: any[];
  fitted: any[];
  removed: boolean;
}

export class FakeMap {
  readonly record: MapRecord = {
    styles: [], sources: new NativeMap(), layers: [], data: new NativeMap(),
    filters: [], paint: [], layout: [], terrain: [],
    eased: [], flown: [], fitted: [], removed: false,
  };
  private handlers = new NativeMap<string, Handler[]>();
  private styleLoaded = true;
  private canvas = { style: {} as Record<string, string> };

  constructor(opts: any) {
    this.record.styles.push(opts?.style);
    instances.push(this);
  }

  /** Fire an event the way MapLibre would. The reason this stub exists. */
  emit(event: string, payload?: any) {
    for (const h of [...(this.handlers.get(event) ?? [])]) h(payload);
  }

  on(event: string, a?: any, b?: any) {
    // `on(event, layerId, handler)` and `on(event, handler)` both occur. The
    // layer-scoped form is keyed by layer so a test can hover one specific mark.
    const [key, handler] = typeof a === 'string' ? [`${event}:${a}`, b] : [event, a];
    if (!this.handlers.has(key)) this.handlers.set(key, []);
    this.handlers.get(key)!.push(handler);
    return this;
  }
  once(event: string, handler: Handler) { return this.on(event, handler); }

  addControl() { return this; }
  getCanvas() { return this.canvas; }
  getStyle() { return { layers: [] }; }
  isStyleLoaded() { return this.styleLoaded; }

  setStyle(style: any) {
    this.record.styles.push(style);
    /*
      A real style swap drops every source and layer the application owns, which
      is the fact both maps are written around — they re-register on `styledata`.
      Modelled because a stub that kept them would make the re-registration look
      unnecessary.
    */
    this.record.sources.clear();
    this.record.layers.length = 0;
    return this;
  }

  addSource(id: string, def: any) {
    this.record.sources.set(id, def);
    return this;
  }
  getSource(id: string) {
    if (!this.record.sources.has(id)) return undefined;
    return { setData: (d: any) => { this.record.data.set(id, d); } };
  }

  addLayer(def: any, beforeId?: string) {
    this.record.layers.push({ id: def.id, def, beforeId });
    return this;
  }
  getLayer(id: string) { return this.record.layers.find(l => l.id === id); }

  setFilter(id: string, filter: any) { this.record.filters.push({ id, filter }); return this; }
  setPaintProperty(id: string, prop: string, value: any) { this.record.paint.push({ id, prop, value }); return this; }
  setLayoutProperty(id: string, prop: string, value: any) { this.record.layout.push({ id, prop, value }); return this; }
  setTerrain(t: any) { this.record.terrain.push(t); return this; }

  easeTo(o: any) { this.record.eased.push(o); return this; }
  flyTo(o: any) { this.record.flown.push(o); return this; }
  fitBounds(b: any, o?: any) { this.record.fitted.push({ bounds: b, options: o }); return this; }
  getZoom() { return 14; }
  remove() { this.record.removed = true; }
}

/** Every popup this test rendered, newest last. */
export interface PopupRecord { html: string; lngLat: any; added: boolean }
export const popups: PopupRecord[] = [];

export class FakePopup {
  private rec: PopupRecord = { html: '', lngLat: null, added: false };
  constructor(_opts?: any) { popups.push(this.rec); }
  setLngLat(ll: any) { this.rec.lngLat = ll; return this; }
  setHTML(html: string) { this.rec.html = html; return this; }
  addTo() { this.rec.added = true; return this; }
  remove() { this.rec.added = false; return this; }
}

export interface MarkerRecord { element: HTMLElement | null; lngLat: any; rotation: number; added: boolean }
export const markers: MarkerRecord[] = [];

export class FakeMarker {
  private rec: MarkerRecord;
  constructor(opts?: any) {
    this.rec = { element: opts?.element ?? null, lngLat: null, rotation: 0, added: false };
    markers.push(this.rec);
  }
  setLngLat(ll: any) { this.rec.lngLat = ll; return this; }
  setRotation(r: number) { this.rec.rotation = r; return this; }
  addTo() { this.rec.added = true; return this; }
  getElement() { return this.rec.element ?? document.createElement('div'); }
  remove() { this.rec.added = false; return this; }
}

class FakeLngLatBounds {
  readonly points: any[] = [];
  extend(p: any) { this.points.push(p); return this; }
  /*
    `isEmpty` is modelled rather than left off, because the report map asks it
    before framing: an archive with nothing positioned must not be fitted to an
    empty box. Leaving it out made the component throw, which the first run of
    `reportMap.test.tsx` reported as nine failures with one cause.
  */
  isEmpty() { return this.points.length === 0; }
}

/** Map instances created since the last reset, oldest first. */
export const instances: FakeMap[] = [];

export function resetMapStub() {
  instances.length = 0;
  popups.length = 0;
  markers.length = 0;
  protocols.length = 0;
}

export const protocols: string[] = [];

const api = {
  Map: FakeMap,
  Popup: FakePopup,
  Marker: FakeMarker,
  LngLatBounds: FakeLngLatBounds,
  NavigationControl: class { },
  ScaleControl: class { },
  FullscreenControl: class { },
  addProtocol: (name: string) => { protocols.push(name); },
  removeProtocol: () => { },
};

export const Map = FakeMap;
export const Popup = FakePopup;
export const Marker = FakeMarker;
export const LngLatBounds = FakeLngLatBounds;
export const NavigationControl = api.NavigationControl;
export const ScaleControl = api.ScaleControl;
export const FullscreenControl = api.FullscreenControl;
export const addProtocol = api.addProtocol;
export const removeProtocol = api.removeProtocol;
export default api;
