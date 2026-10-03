import { useState, useCallback, useRef, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { APP_VERSION } from '../lib/constants';
import { useEngineStore } from '../stores/engineStore';
import { useMissionStore } from '../stores/missionStore';
import { useUIStore } from '../stores/uiStore';
import { engineIPC } from '../lib/ipc';
import { saveBenchmark, getBenchmarks, deleteBenchmark, type BenchmarkResult } from '../lib/benchmarkDB';
import type { EngineMessage, ScopeStatus } from '../types/engine';
import { ConfirmModal } from '../components/common/ConfirmModal';
import { LocalizationPreview } from '../components/settings/LocalizationPreview';
import { getDataFootprint, purgeCollectedData, type PurgeResult } from '../lib/database';
import {
  listScopes,
  getActiveScope,
  getScopeTargets,
  createScope,
  activateScope,
  deactivateAllScopes,
  deleteScope,
  addTarget,
  removeTarget,
  type EngagementScope,
  type EngagementScopeWithTargets,
  type ScopeTarget,
  type TargetKind,
  type ScopeMode
} from '../lib/scopeDB';
import { verifyAllEvidence } from '../lib/findingsDB';
import { basemapStatus, basemapCoverage, registerBasemapProtocol, type BasemapStatus } from '../lib/basemap';
import { describeBounds } from '../lib/basemapStyle';
import { getEvidenceSummary } from '../lib/findingsDB';
import { DataRow, RowNote, RowCallout } from '../components/settings/DataRow';
import maplibregl from 'maplibre-gl';
import { pushScopeToEngine, requestScopeStatus } from '../lib/scopeSync';
import { assessGeometry } from '../lib/localization';

const VEHICLES = [
  { id: 'arrow.svg', name: 'NAVIGATION ARROW' },
  { id: 'car1.svg', name: 'PATROL SEDAN' },
  { id: 'car2.svg', name: 'TACTICAL SUV' },
  { id: 'car3.svg', name: 'HATCHBACK' },
  { id: 'car4.svg', name: 'WHITE SEDAN' },
  { id: 'car5.svg', name: 'COVERT VAN' }
];

/**
 * Measured localization error by route shape.
 *
 * Simulation: AP 40 m off a road, 300 m of driving, five noise seeds per route.
 * "Wrong side" counts the runs that placed the AP on the opposite side of the
 * road from the truth. Driving the same street twice is worse than driving it
 * once because a second pass only reinforces the symmetry about the line of
 * travel; a single turn breaks it.
 */
const GEOMETRY_TRIALS: { route: string; error: string; wrongSide: string; good: boolean }[] = [
  { route: 'Single straight pass', error: '31 m', wrongSide: '2 of 5', good: false },
  { route: 'Same street driven twice', error: '25 m', wrongSide: '5 of 5', good: false },
  { route: 'Two parallel streets', error: '13 m', wrongSide: '0 of 5', good: true },
  { route: 'Route with one turn', error: '5 m', wrongSide: '0 of 5', good: true },
  { route: 'Loop around the block', error: '14 m', wrongSide: '0 of 5', good: true }
];

/** Typed verbatim before an UNRESTRICTED engagement can be saved. */
const UNRESTRICTED_PHRASE = 'I HAVE WRITTEN AUTHORIZATION FOR EVERY REACHABLE TARGET';
/** Typed verbatim before collected data is deleted. */
const PURGE_PHRASE = 'PURGE';

const TARGET_KINDS: { kind: TargetKind; label: string; placeholder: string; hint: string }[] = [
  { kind: 'BSSID', label: 'BSSID', placeholder: 'AA:BB:CC:DD:EE:FF', hint: 'One access point, matched by MAC (separators and case ignored).' },
  { kind: 'SSID', label: 'SSID', placeholder: 'CORP-GUEST', hint: 'Every AP broadcasting this exact name — one entry covers a whole estate, however many radios it has. Exact match: CORP-WIFI does not cover CORP-WIFI-GUEST.' },
  { kind: 'IP', label: 'IP', placeholder: '192.168.10.25', hint: 'A single IPv4 or IPv6 host.' },
  { kind: 'CIDR', label: 'CIDR', placeholder: '192.168.10.0/24', hint: 'A subnet. Requested ranges must fit fully inside it.' }
];

const isIPv4 = (value: string): boolean => {
  const parts = value.split('.');
  return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255);
};

const isIPv6 = (value: string): boolean => {
  if (!value.includes(':')) return false;
  if (/[^0-9A-Fa-f:.]/.test(value)) return false;
  const halves = value.split('::');
  if (halves.length > 2) return false;
  const split = (s: string) => (s === '' ? [] : s.split(':'));
  const head = split(halves[0]);
  const tail = halves.length === 2 ? split(halves[1]) : [];
  const groups = [...head, ...tail];
  if (groups.length === 0) return halves.length === 2; // "::"
  const last = groups[groups.length - 1];
  const hasV4Tail = last.includes('.');
  if (hasV4Tail && !isIPv4(last)) return false;
  const hexGroups = hasV4Tail ? groups.slice(0, -1) : groups;
  if (hexGroups.some(g => !/^[0-9A-Fa-f]{1,4}$/.test(g))) return false;
  const slots = hexGroups.length + (hasV4Tail ? 2 : 0);
  return halves.length === 2 ? slots <= 7 : slots === 8;
};

/**
 * Client-side gate for a single scope entry. Returns null when the value is
 * usable, otherwise the reason — the engine silently drops malformed IP/CIDR
 * entries (it only emits `scope_warning`), so a typo caught here is the
 * difference between an allowlist that covers the target and one that does not.
 */
const validateTarget = (kind: TargetKind, raw: string): string | null => {
  const value = raw.trim();
  if (!value) return 'Value is empty.';

  if (kind === 'BSSID') {
    const hex = value.replace(/[:\-.\s]/g, '');
    if (!/^[0-9A-Fa-f]{12}$/.test(hex)) return 'Not a MAC address — expected 6 hex pairs, e.g. AA:BB:CC:DD:EE:FF.';
    return null;
  }

  if (kind === 'SSID') {
    if (value.length > 32) return 'An SSID cannot be longer than 32 characters.';
    return null;
  }

  if (kind === 'IP') {
    if (value.includes('/')) return 'That is a subnet — use kind CIDR instead.';
    if (!isIPv4(value) && !isIPv6(value)) return 'Not a valid IPv4 or IPv6 address.';
    return null;
  }

  // CIDR
  const parts = value.split('/');
  if (parts.length !== 2 || parts[1] === '') return 'Expected address/prefix, e.g. 192.168.1.0/24 or 2001:db8::/32.';
  if (!/^\d{1,3}$/.test(parts[1])) return 'Prefix length must be a number.';
  const prefix = Number(parts[1]);
  if (isIPv4(parts[0])) return prefix <= 32 ? null : 'An IPv4 prefix length must be 0-32.';
  if (isIPv6(parts[0])) return prefix <= 128 ? null : 'An IPv6 prefix length must be 0-128.';
  return 'The network part is not a valid IPv4 or IPv6 address.';
};

const errText = (err: unknown): string =>
  err instanceof Error ? err.message : typeof err === 'string' ? err : JSON.stringify(err);

const fmtDate = (value: string | null | undefined): string => {
  if (!value) return '—';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString('en-GB', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
};

const KIND_COLOR: Record<TargetKind, string> = {
  BSSID: 'text-neon-400 border-neon-500/40 bg-neon-500/10',
  SSID: 'text-signal-strong border-signal-strong/40 bg-signal-strong/10',
  IP: 'text-risk-high border-risk-high/40 bg-risk-high/10',
  CIDR: 'text-[#ff00ff] border-[#ff00ff]/40 bg-[#ff00ff]/10'
};

interface DraftTarget extends ScopeTarget {
  /** Local key so a row can be flagged as the bad one without relying on index. */
  key: number;
}

export function SettingsPage() {
  // Narrow selectors: this page is large and the status poll writes engine state
  // every 2s, so subscribing to the whole store re-rendered all of it each tick.
  const config = useEngineStore(s => s.config);
  const setConfig = useEngineStore(s => s.setConfig);
  const connected = useEngineStore(s => s.connected);
  // What the running sidecar is, so a stale build cannot hide behind a
  // version string that never changes.
  const engineBuild = useEngineStore(s => s.engineBuild);
  const wifiReady = useEngineStore(s => s.wifiReady);
  const gpsLocked = useEngineStore(s => s.gpsLocked);
  const wifiInterfaces = useEngineStore(s => s.wifiInterfaces);
  const comPorts = useEngineStore(s => s.comPorts);
  const storeWordlists = useEngineStore(s => s.wordlists);
  const egoVehicle = useUIStore(s => s.egoVehicle);
  const setEgoVehicle = useUIStore(s => s.setEgoVehicle);

  // Live survey geometry. The driven path is what determines whether the side of
  // the road can be resolved at all, so the route itself is assessed rather than
  // any one target's sightings — assessGeometry only reads positions. pathCoords
  // is stored GeoJSON-style, [lon, lat].
  const pathCoords = useMissionStore(s => s.pathCoords);
  const routeGeometry = useMemo(
    () =>
      pathCoords.length < 3
        ? null
        : assessGeometry(pathCoords.map(([lon, lat]) => ({ lat, lon, rssi: 0 }))),
    [pathCoords]
  );

  const [saveStatus, setSaveStatus] = useState<'IDLE' | 'SAVING' | 'SAVED'>('IDLE');
  const saveTimeout = useRef<number | null>(null);

  const [isTesting, setIsTesting] = useState(false);
  const [diagnosticLogs, setDiagnosticLogs] = useState<string[]>([]);
  const logEndRef = useRef<HTMLDivElement>(null);

  // Hardware capability and CVE provenance come from the engine, so the UI shows
  // what is actually true of this rig rather than what it hopes is true.
  const caps = useEngineStore(s => s.capabilities);
  const simulation = useEngineStore(s => s.simulation);
  const cveInfo = useEngineStore(s => s.cveInfo);
  const [cveUpdating, setCveUpdating] = useState(false);
  const [cveUpdateProgress, setCveUpdateProgress] = useState<string | null>(null);
  const [cveMessage, setCveMessage] = useState<string | null>(null);
  const [engineLog, setEngineLog] = useState<{ path: string; lines: string[] } | null>(null);

  /*
    Evidence verification state. `null` tally means "not run in this session",
    which is distinct from a run that found nothing -- the card says which.
  */
  /*
    Offline basemap state.

    Coverage is read separately from installation because they are different
    claims: an extract of one city satisfies "installed" everywhere and "covers
    where you are standing" almost nowhere.
  */
  const [basemap, setBasemap] = useState<BasemapStatus | null>(null);
  const [basemapCoverageInfo, setBasemapCoverageInfo] = useState<{ minZoom: number; maxZoom: number; bounds: [number, number, number, number] } | null>(null);
  const [basemapError, setBasemapError] = useState<string | null>(null);

  const [evidenceVerifying, setEvidenceVerifying] = useState(false);
  const [evidenceTally, setEvidenceTally] = useState<Awaited<ReturnType<typeof verifyAllEvidence>> | null>(null);
  const [evidenceMessage, setEvidenceMessage] = useState<string | null>(null);

  /*
    What the register holds, before anything is verified.

    This card had no state at all until a run: a paragraph and a button, beside
    two cards that each show their condition in a badge. It could not answer the
    first question an operator has, which is whether this installation holds any
    artifacts to verify — so "never re-checked" read as a warning about nothing
    when the register was empty, and as a warning about a great deal when it was
    not, with no way to tell which.
  */
  const [evidenceSummary, setEvidenceSummary] = useState<Awaited<ReturnType<typeof getEvidenceSummary>> | null>(null);

  const refreshEvidenceSummary = useCallback(async () => {
    try { setEvidenceSummary(await getEvidenceSummary()); } catch { setEvidenceSummary(null); }
  }, []);

  useEffect(() => { void refreshEvidenceSummary(); }, [refreshEvidenceSummary]);

  // Benchmark state
  const [isBenchmarking, setIsBenchmarking] = useState(false);
  const [benchmarkLabel, setBenchmarkLabel] = useState('');
  const [benchmarkNotes, setBenchmarkNotes] = useState('');
  const [benchmarkInterface, setBenchmarkInterface] = useState<string | null>(null);
  const [benchmarkProgress, setBenchmarkProgress] = useState(0);
  const [benchmarkHistory, setBenchmarkHistory] = useState<BenchmarkResult[]>([]);
  const [lastBenchmark, setLastBenchmark] = useState<BenchmarkResult | null>(null);
  const [benchmarkExpanded, setBenchmarkExpanded] = useState(false);
  const [deleteConfirmId, setDeleteConfirmId] = useState<number | null>(null);
  const [compareIds, setCompareIds] = useState<number[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Wordlist Arsenal state
  type UploadPhase = 'SENDING' | 'FINALIZING' | 'SAVED' | 'FAILED';
  const [uploadProgress, setUploadProgress] = useState<{ filename: string; progress: number; phase: UploadPhase; message?: string } | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [wordlistNotice, setWordlistNotice] = useState<string | null>(null);
  /**
   * The engine's `wordlists_list` payload is `{wordlists, total}`; it used to be
   * a bare array. Held locally so this page renders the real list even while
   * another consumer of the event has not caught up with the new shape.
   */
  const [engineWordlists, setEngineWordlists] = useState<
    { name: string; size: number; origin?: 'bundled' | 'user' }[] | null>(null);
  const wordlists = engineWordlists ?? (Array.isArray(storeWordlists) ? storeWordlists : []);

  // ── Engagement scope state ────────────────────────────────────────────────
  const [scopes, setScopes] = useState<EngagementScope[]>([]);
  const [activeScope, setActiveScope] = useState<EngagementScopeWithTargets | null>(null);
  const [engineScope, setEngineScope] = useState<ScopeStatus | null>(null);
  const [scopeWarnings, setScopeWarnings] = useState<string[]>([]);
  const [scopeBusy, setScopeBusy] = useState(false);
  const [scopeError, setScopeError] = useState<string | null>(null);
  const [scopeSyncError, setScopeSyncError] = useState<string | null>(null);
  const [scopeNotice, setScopeNotice] = useState<string | null>(null);
  const [scopeLoaded, setScopeLoaded] = useState(false);
  const [operator, setOperator] = useState<string>(() => {
    try { return localStorage.getItem('lockon-operator') ?? ''; } catch { return ''; }
  });
  const operatorRef = useRef(operator);
  operatorRef.current = operator;

  // Scope creation form
  const [showScopeForm, setShowScopeForm] = useState(false);
  const [formName, setFormName] = useState('');
  const [formAuthorizedBy, setFormAuthorizedBy] = useState('');
  const [formReference, setFormReference] = useState('');
  const [formValidUntil, setFormValidUntil] = useState('');
  const [formNotes, setFormNotes] = useState('');
  const [formMode, setFormMode] = useState<ScopeMode>('ALLOWLIST');
  const [formAck, setFormAck] = useState('');
  const [draftTargets, setDraftTargets] = useState<DraftTarget[]>([]);
  const [draftKind, setDraftKind] = useState<TargetKind>('BSSID');
  const [draftValue, setDraftValue] = useState('');
  const [draftError, setDraftError] = useState<string | null>(null);
  const [badDraftKeys, setBadDraftKeys] = useState<number[]>([]);
  const draftKeyRef = useRef(1);

  // Add-target-to-active-scope row
  const [liveKind, setLiveKind] = useState<TargetKind>('BSSID');
  const [liveValue, setLiveValue] = useState('');
  const [liveError, setLiveError] = useState<string | null>(null);

  // Per-scope target inspector (non-active scopes)
  const [inspectedScopeId, setInspectedScopeId] = useState<number | null>(null);
  const [inspectedTargets, setInspectedTargets] = useState<ScopeTarget[]>([]);
  const [confirmDeleteScope, setConfirmDeleteScope] = useState<EngagementScope | null>(null);
  const [confirmLabScope, setConfirmLabScope] = useState(false);

  // ── Purge state ───────────────────────────────────────────────────────────
  const [purgeStage, setPurgeStage] = useState<'IDLE' | 'REVIEW' | 'RUNNING' | 'DONE'>('IDLE');
  const [footprint, setFootprint] = useState<PurgeResult[] | null>(null);
  const [purgeConfirmText, setPurgeConfirmText] = useState('');
  const [purgeResult, setPurgeResult] = useState<PurgeResult[] | null>(null);
  const [purgeError, setPurgeError] = useState<string | null>(null);

  /** Why a long-running panel cleared itself, when it was not a clean finish. */
  const [runtimeNotice, setRuntimeNotice] = useState<string | null>(null);

  // Refs to capture latest form values inside event handler closures
  const benchmarkLabelRef = useRef(benchmarkLabel);
  const benchmarkNotesRef = useRef(benchmarkNotes);
  const benchmarkInterfaceRef = useRef(benchmarkInterface);
  // `config` needs the same treatment: the handlers below are registered once
  // with []-deps, so reading config directly captured the first render's value
  // and a benchmark recorded "Unknown" whenever the interface was auto-selected
  // after mount.
  const configRef = useRef(config);
  const uploadRef = useRef<{ filename: string } | null>(null);
  const isTestingRef = useRef(isTesting);
  const isBenchmarkingRef = useRef(isBenchmarking);
  isTestingRef.current = isTesting;
  isBenchmarkingRef.current = isBenchmarking;
  benchmarkLabelRef.current = benchmarkLabel;
  benchmarkNotesRef.current = benchmarkNotes;
  benchmarkInterfaceRef.current = benchmarkInterface;
  configRef.current = config;

  // Watchdogs so a dead engine does not leave a panel spinning forever.
  const testTimeout = useRef<number | null>(null);
  const benchTimeout = useRef<number | null>(null);
  const clearTestWatchdog = () => { if (testTimeout.current) { window.clearTimeout(testTimeout.current); testTimeout.current = null; } };
  const clearBenchWatchdog = () => { if (benchTimeout.current) { window.clearTimeout(benchTimeout.current); benchTimeout.current = null; } };

  useEffect(() => {
    if (logEndRef.current) {
      logEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [diagnosticLogs]);

  useEffect(() => {
    // CVE refresh lifecycle. A failed update must say so and name the data that
    // remains in force — leaving the operator unsure which vintage they are on
    // is worse than the staleness itself.
    const unsubCveStart = engineIPC.on('cve_update_started', () => {
      setCveUpdating(true);
      setCveMessage(null);
      setCveUpdateProgress('Contacting NVD…');
    });
    const unsubCveProgress = engineIPC.on('cve_update_progress', (msg: EngineMessage) => {
      const d = msg.data as any;
      setCveUpdateProgress(`Fetching ${d.product} (${d.current}/${d.total})…`);
    });
    const unsubCveDone = engineIPC.on('cve_update_complete', (msg: EngineMessage) => {
      const info = msg.data as any;
      setCveUpdating(false);
      setCveUpdateProgress(null);
      useEngineStore.setState({ cveInfo: info });
      setCveMessage(`Updated: ${info.entry_count} entries across ${info.product_count} products.`);
    });
    const unsubCveError = engineIPC.on('cve_update_error', (msg: EngineMessage) => {
      const d = msg.data as any;
      setCveUpdating(false);
      setCveUpdateProgress(null);
      const kept = d.retained?.generated_at
        ? ` Still using data generated ${new Date(d.retained.generated_at).toLocaleDateString()}.`
        : '';
      setCveMessage(`Update failed: ${d.message}.${kept}`);
    });

    const unsubEngineLog = engineIPC.on('engine_log', (msg: EngineMessage) => {
      const d = msg.data as any;
      setEngineLog({ path: d.path, lines: d.lines || [] });
    });

    const unsubLog = engineIPC.on('diagnostic_log', (msg: EngineMessage) => {
      const data = msg.data as { message: string };
      setDiagnosticLogs(prev => [...prev, `[${new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}] ${data.message}`]);
    });

    const unsubComplete = engineIPC.on('diagnostic_complete', () => {
      clearTestWatchdog();
      setIsTesting(false);
    });

    // Benchmark events
    const unsubBenchmarkResult = engineIPC.on('benchmark_result', async (msg: EngineMessage) => {
      const data = msg.data as any;
      const rssiValues: number[] = data.rssi_values || [];
      const channels: number[] = data.channels || [];

      // Categorize by frequency band.
      //
      // The engine sends `freq_to_channel(...)`, which returns None by design
      // when the frequency is unknown — "returns None rather than a guess". That
      // null arrived here typed as `number`, failed both range tests, and fell
      // into the final `else`, so every access point whose channel could not be
      // derived was counted as a 6 GHz one. The engine went out of its way not
      // to invent a channel and this loop invented a band from it.
      //
      // Unknowns are now counted separately rather than assigned to a band.
      let aps2g = 0, aps5g = 0, aps6g = 0, apsUnknownBand = 0;
      channels.forEach((ch: number | null) => {
        if (typeof ch !== 'number' || !Number.isFinite(ch)) { apsUnknownBand++; return; }
        if (ch >= 1 && ch <= 14) aps2g++;
        else if (ch >= 36 && ch <= 177) aps5g++;
        else if (ch >= 1) aps6g++;
        else apsUnknownBand++;
      });

      // Categorize by signal strength bands
      let excellent = 0, good = 0, fair = 0, weak = 0;
      rssiValues.forEach((rssi: number) => {
        if (rssi >= -50) excellent++;
        else if (rssi >= -60) good++;
        else if (rssi >= -70) fair++;
        else weak++;
      });

      const minRssi = rssiValues.length > 0 ? Math.min(...rssiValues) : null;
      const maxRssi = rssiValues.length > 0 ? Math.max(...rssiValues) : null;
      const avgRssi = rssiValues.length > 0 ? rssiValues.reduce((a: number, b: number) => a + b, 0) / rssiValues.length : null;

      const result: Omit<BenchmarkResult, 'id' | 'created_at'> = {
        label: benchmarkLabelRef.current || `Benchmark ${new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short' })}`,
        interface_name: benchmarkInterfaceRef.current || configRef.current.interfaceName || 'Unknown',
        total_aps: data.total_aps || rssiValues.length,
        aps_2g: aps2g,
        aps_5g: aps5g,
        aps_6g: aps6g,
        min_rssi: minRssi,
        max_rssi: maxRssi,
        avg_rssi: avgRssi ? parseFloat(avgRssi.toFixed(1)) : null,
        band_excellent: excellent,
        band_good: good,
        band_fair: fair,
        band_weak: weak,
        scan_duration_ms: data.duration_ms || null,
        notes: benchmarkNotesRef.current || null
      };

      try {
        const id = await saveBenchmark(result);
        const saved = { ...result, id, created_at: new Date().toISOString() } as BenchmarkResult;
        setLastBenchmark(saved);
        setBenchmarkHistory(prev => [saved, ...prev]);
      } catch (err) {
        console.error('[DB] saveBenchmark error:', err);
      }

      clearBenchWatchdog();
      setIsBenchmarking(false);
      setBenchmarkLabel('');
      setBenchmarkNotes('');
      setBenchmarkProgress(0);
    });

    const unsubBenchmarkProgress = engineIPC.on('benchmark_progress', (msg: EngineMessage) => {
      const data = msg.data as any;
      setBenchmarkProgress(data.aps_found || 0);
    });

    const unsubBenchmarkError = engineIPC.on('benchmark_error', (msg: EngineMessage) => {
      const message = (msg.data as any)?.message || 'Benchmark failed.';
      console.error('[Benchmark] Error:', message);
      clearBenchWatchdog();
      setIsBenchmarking(false);
      setRuntimeNotice(`BENCHMARK FAILED — ${message}`);
    });

    /**
     * A run used to be cleared only by its own completion event, so an engine
     * that died mid-run left the panel spinning with no way back. These are the
     * generic failure paths.
     */
    const abortRuns = (reason: string) => {
      if (!isTestingRef.current && !isBenchmarkingRef.current) return;
      clearTestWatchdog();
      clearBenchWatchdog();
      setIsTesting(false);
      setIsBenchmarking(false);
      setRuntimeNotice(reason);
    };

    const unsubScanError = engineIPC.on('scan_error', (msg: EngineMessage) => {
      abortRuns(`ENGINE REPORTED A SCAN ERROR — ${(msg.data as any)?.message || 'no detail given'}`);
    });
    const unsubGenericError = engineIPC.on('error', (msg: EngineMessage) => {
      abortRuns(`ENGINE ERROR — ${(msg.data as any)?.message || 'no detail given'}`);
    });
    const unsubDisconnected = engineIPC.on('disconnected', () => {
      abortRuns('ENGINE UPLINK LOST — the run was abandoned. Reconnect and try again.');
      setEngineScope(null);
    });

    // ── Wordlists ───────────────────────────────────────────────────────────
    const unsubWordlists = engineIPC.on('wordlists_list', (msg: EngineMessage) => {
      const data = msg.data as any;
      // Current shape: {wordlists, total}. Older builds sent a bare array (which
      // arrived as {} when the folder was empty, because emit() coerces falsy
      // payloads) — both are accepted rather than trusted.
      const list = Array.isArray(data?.wordlists)
        ? data.wordlists
        : Array.isArray(data)
          ? data
          : Array.isArray(data?.lists)
            ? data.lists
            : [];
      setEngineWordlists(
        list
          .filter((f: any) => f && typeof f.name === 'string')
          /*
            `origin` is carried through.

            The engine sends it, the state type above declares it, and the store
            preserves it — but this projection dropped it, and `wordlists` prefers
            this copy over the store's. The page issues `get_wordlists` on mount, so
            the stripped list arrived almost immediately and `file.origin` was
            `undefined` from then on.

            Two things depended on it: the BUNDLED badge, which therefore never
            rendered, and `disabled={file.origin === 'bundled'}` on the delete button,
            which was always false. So the operator got an enabled DELETE on a list
            that ships with the application, and the engine refused it with "ships
            with the application" — which is exactly the "reads as a broken feature"
            outcome the comment beside that button says it exists to prevent.
          */
          .map((f: any) => ({
            name: f.name,
            size: typeof f.size === 'number' ? f.size : 0,
            origin: f.origin === 'bundled' || f.origin === 'user' ? f.origin : undefined,
          }))
      );
    });

    const unsubWordlistSaved = engineIPC.on('wordlist_saved', (msg: EngineMessage) => {
      const name = (msg.data as any)?.name as string | undefined;
      const pending = uploadRef.current;
      if (!pending || (name && name !== pending.filename)) return;
      uploadRef.current = null;
      setUploadProgress({ filename: pending.filename, progress: 100, phase: 'SAVED' });
      setWordlistNotice(null);
      window.setTimeout(() => setUploadProgress(null), 2000);
    });

    const unsubWordlistError = engineIPC.on('wordlist_error', (msg: EngineMessage) => {
      const data = msg.data as any;
      const message = data?.message || 'The engine refused the wordlist.';
      const name = data?.name as string | undefined;
      const pending = uploadRef.current;
      if (pending && (!name || name === pending.filename)) {
        uploadRef.current = null;
        setUploadProgress({ filename: pending.filename, progress: 100, phase: 'FAILED', message });
        window.setTimeout(() => setUploadProgress(prev => (prev?.phase === 'FAILED' ? null : prev)), 8000);
      }
      setWordlistNotice(name ? `${name}: ${message}` : message);
    });

    // ── Engagement scope (engine-side view) ─────────────────────────────────
    const applyScopeStatus = (msg: EngineMessage) => {
      setEngineScope(msg.data as unknown as ScopeStatus);
    };
    const unsubScopeStatus = engineIPC.on('scope_status', applyScopeStatus);
    const unsubScopeUpdated = engineIPC.on('scope_updated', applyScopeStatus);
    // A fresh engine starts with no scope loaded, so re-ask on every (re)connect
    // rather than leaving the panel showing whatever the last session reported.
    const refreshOnConnect = () => {
      engineIPC.send('get_wordlists').catch(() => { /* not fatal */ });
      requestScopeStatus().catch(() => { /* not fatal */ });
    };
    const unsubReady = engineIPC.on('ready', refreshOnConnect);
    const unsubReconnected = engineIPC.on('reconnected', refreshOnConnect);

    const unsubScopeWarning = engineIPC.on('scope_warning', (msg: EngineMessage) => {
      const message = (msg.data as any)?.message || 'The engine ignored a malformed scope entry.';
      setScopeWarnings(prev => (prev.includes(message) ? prev : [...prev.slice(-4), message]));
    });

    // Load benchmark history on mount
    getBenchmarks().then(setBenchmarkHistory).catch(console.error);
    // Ask the engine for the current truth rather than waiting for a change.
    engineIPC.send('get_wordlists').catch(() => { /* engine offline — store value stands */ });
    requestScopeStatus().catch(() => { /* engine offline — shown as UNKNOWN below */ });

    return () => {
      clearTestWatchdog();
      clearBenchWatchdog();
      unsubLog();
      unsubCveStart();
      unsubCveProgress();
      unsubCveDone();
      unsubCveError();
      unsubEngineLog();
      unsubComplete();
      unsubBenchmarkResult();
      unsubBenchmarkProgress();
      unsubBenchmarkError();
      unsubScanError();
      unsubGenericError();
      unsubDisconnected();
      unsubWordlists();
      unsubWordlistSaved();
      unsubWordlistError();
      unsubScopeStatus();
      unsubScopeUpdated();
      unsubScopeWarning();
      unsubReady();
      unsubReconnected();
    };
  }, []);

  const updateConfig = useCallback((changes: Partial<typeof config>) => {
    setConfig(changes);
    setSaveStatus('SAVING');
    if (saveTimeout.current) window.clearTimeout(saveTimeout.current);

    saveTimeout.current = window.setTimeout(() => {
      setSaveStatus('SAVED');
      setTimeout(() => setSaveStatus('IDLE'), 2000);
    }, 500);
  }, [setConfig]);

  const handleTestHardware = () => {
    setDiagnosticLogs([]);
    setRuntimeNotice(null);
    setIsTesting(true);
    clearTestWatchdog();
    testTimeout.current = window.setTimeout(() => {
      testTimeout.current = null;
      setIsTesting(false);
      setRuntimeNotice('DIAGNOSTICS TIMED OUT — no completion from the engine within 90s. The result below may be incomplete.');
    }, 90_000);
    engineIPC.send('test_hardware', {
      com_port: config.comPort,
      baud_rate: config.baudRate,
      interface_name: config.interfaceName
    }).catch((e) => {
      console.error(e);
      clearTestWatchdog();
      setIsTesting(false);
      setRuntimeNotice(`COULD NOT START DIAGNOSTICS — ${errText(e)}`);
    });
  };

  const handleRunBenchmark = () => {
    setRuntimeNotice(null);
    setIsBenchmarking(true);
    setLastBenchmark(null);
    setBenchmarkProgress(0);
    clearBenchWatchdog();
    benchTimeout.current = window.setTimeout(() => {
      benchTimeout.current = null;
      setIsBenchmarking(false);
      setRuntimeNotice('BENCHMARK TIMED OUT — no result from the engine within 5 minutes. Nothing was recorded.');
    }, 300_000);
    const targetInterface = benchmarkInterface || config.interfaceName;
    engineIPC.send('run_benchmark', {
      interface_name: targetInterface
    }).catch((e) => {
      console.error(e);
      clearBenchWatchdog();
      setIsBenchmarking(false);
      setRuntimeNotice(`COULD NOT START BENCHMARK — ${errText(e)}`);
    });
  };

  // ──────────────────── Evidence integrity ────────────────────

  /**
   * Re-hash the whole evidence register and record what came back.
   *
   * The two closures handed to `verifyAllEvidence` are the whole reason it takes
   * them as parameters: it is unit-tested against stubs, and the IPC it needs did
   * not exist on the real path. `awaitKeyed` matches each `evidence_verified`
   * reply to the row id the engine echoes back, so a register of many artifacts
   * cannot cross answers between them.
   *
   * The tally from a partial run is still shown. `verifyAllEvidence` writes each
   * answer as it arrives, so a run that dies halfway has still established
   * something about the rows it reached, and discarding the count would hide
   * that. Only a failure before the register could be read at all leaves the
   * tally null, and then the message says so instead of showing zeros -- six
   * zeros would read as "nothing is wrong", which is the opposite of what an
   * unreadable register means.
   */


  const refreshBasemap = useCallback(async () => {
    setBasemapError(null);
    try {
      const status = await basemapStatus();
      setBasemap(status);
      if (!status.installed) { setBasemapCoverageInfo(null); return; }
      const archive = registerBasemapProtocol((name, handler) => {
        // Registering twice throws, and this page can be opened repeatedly.
        try { maplibregl.addProtocol(name, handler as never); } catch { /* already registered */ }
      });
      setBasemapCoverageInfo(await basemapCoverage(archive));
    } catch (e) {
      setBasemap(null);
      setBasemapCoverageInfo(null);
      setBasemapError(`The offline basemap could not be checked — ${errText(e)}.`);
    }
  }, []);

  useEffect(() => { void refreshBasemap(); }, [refreshBasemap]);  const runEvidenceVerification = useCallback(async () => {
    setEvidenceVerifying(true);
    setEvidenceMessage(null);
    try {
      const tally = await verifyAllEvidence(
        (cmd, payload) => engineIPC.send(cmd, payload),
        // The shape named here rather than inferred: `awaitKeyed` only
        // guarantees the id it matched on, and the three fields the verifier
        // reads are the engine's, documented in `_handle_verify_evidence`.
        (id, timeoutMs) => engineIPC.awaitKeyed<{
          id?: unknown; matches?: boolean; exists?: boolean; error?: string | null;
        }>('evidence_verified', id, timeoutMs),
      );
      setEvidenceTally(tally);
      void refreshEvidenceSummary();
    } catch (e) {
      setEvidenceTally(null);
      setEvidenceMessage(
        `The evidence register could not be verified — ${errText(e)}. `
        + 'No row was changed by this attempt, so the report still states what it stated before.'
      );
    } finally {
      setEvidenceVerifying(false);
    }
  }, []);

  // ── Engagement scope actions ─────────────────────────────────────────────

  const reloadScopes = useCallback(async () => {
    const [list, active] = await Promise.all([listScopes(), getActiveScope()]);
    setScopes(list);
    setActiveScope(active);
    setScopeLoaded(true);
  }, []);

  useEffect(() => {
    reloadScopes().catch(err => {
      setScopeLoaded(true);
      setScopeError(`Could not read the engagement scope table: ${errText(err)}`);
    });
  }, [reloadScopes]);

  useEffect(() => {
    try { localStorage.setItem('lockon-operator', operator); } catch { /* non-fatal */ }
  }, [operator]);

  /**
   * Push the database's idea of the scope to the engine. Every caller that
   * changed what is authorized must run this: a scope saved locally but never
   * pushed means the engine is still gating on the previous allowlist, which is
   * exactly the mismatch the operator cannot see.
   */
  const syncScope = useCallback(async (label: string): Promise<boolean> => {
    try {
      const payload = await pushScopeToEngine(operatorRef.current || null);
      setScopeSyncError(null);
      setScopeNotice(
        payload.scope_id === null
          ? `${label} — engine scope CLEARED. Offensive modules are blocked again.`
          : `${label} — engine now gating on "${payload.engagement_name}" (${payload.mode}, ${payload.targets.length} target${payload.targets.length === 1 ? '' : 's'}).`
      );
      requestScopeStatus().catch(() => { /* status strip stays stale, banner already shown */ });
      return true;
    } catch (err) {
      setScopeNotice(null);
      setScopeSyncError(
        `${label} was saved to the database but the engine did NOT receive it (${errText(err)}). ` +
        `The engine is still gating on whatever it loaded last — press RESYNC ENGINE before running any offensive module.`
      );
      return false;
    }
  }, []);

  /** Returns false when the database write itself failed, so callers can keep the form open. */
  const runScopeAction = useCallback(async (label: string, action: () => Promise<void>): Promise<boolean> => {
    setScopeBusy(true);
    setScopeError(null);
    setScopeNotice(null);
    try {
      await action();
      await reloadScopes();
      await syncScope(label);
      return true;
    } catch (err) {
      setScopeError(`${label} failed: ${errText(err)}`);
      return false;
    } finally {
      setScopeBusy(false);
    }
  }, [reloadScopes, syncScope]);

  const resetScopeForm = () => {
    setFormName('');
    setFormAuthorizedBy('');
    setFormReference('');
    setFormValidUntil('');
    setFormNotes('');
    setFormMode('ALLOWLIST');
    setFormAck('');
    setDraftTargets([]);
    setDraftValue('');
    setDraftError(null);
    setBadDraftKeys([]);
  };

  const handleAddDraftTarget = () => {
    const problem = validateTarget(draftKind, draftValue);
    if (problem) {
      setDraftError(problem);
      return;
    }
    const value = draftValue.trim();
    if (draftTargets.some(t => t.kind === draftKind && t.value.toLowerCase() === value.toLowerCase())) {
      setDraftError('That entry is already on the list.');
      return;
    }
    setDraftTargets(prev => [...prev, { key: draftKeyRef.current++, kind: draftKind, value }]);
    setDraftValue('');
    setDraftError(null);
    setBadDraftKeys([]);
  };

  const handleCreateScope = async () => {
    setScopeError(null);
    setScopeNotice(null);

    if (!formName.trim()) { setScopeError('The engagement needs a name — it goes on the report and every audit row.'); return; }
    if (!formAuthorizedBy.trim()) { setScopeError('Record who authorized this engagement.'); return; }

    // Re-validate every row so a value pasted in before a kind change cannot slip through.
    const bad = draftTargets.filter(t => validateTarget(t.kind, t.value) !== null);
    if (bad.length > 0) {
      setBadDraftKeys(bad.map(t => t.key));
      setScopeError(
        `${bad.length} target${bad.length === 1 ? '' : 's'} below ${bad.length === 1 ? 'is' : 'are'} not valid and ${bad.length === 1 ? 'is' : 'are'} highlighted: ` +
        bad.map(t => `${t.kind} "${t.value}" — ${validateTarget(t.kind, t.value)}`).join('; ')
      );
      return;
    }
    setBadDraftKeys([]);

    if (formMode === 'ALLOWLIST' && draftTargets.length === 0) {
      setScopeError('An allowlist engagement needs at least one target, otherwise nothing is authorized.');
      return;
    }
    if (formMode === 'UNRESTRICTED' && formAck.trim() !== UNRESTRICTED_PHRASE) {
      setScopeError('Type the acknowledgement phrase exactly as shown to save an UNRESTRICTED engagement.');
      return;
    }
    if (formValidUntil) {
      const until = new Date(formValidUntil);
      if (Number.isNaN(until.getTime())) { setScopeError('The validity date could not be read.'); return; }
    }

    const ok = await runScopeAction('Engagement created and activated', async () => {
      const id = await createScope({
        engagement_name: formName.trim(),
        authorized_by: formAuthorizedBy.trim(),
        reference: formReference.trim() || null,
        mode: formMode,
        unrestricted_ack: formMode === 'UNRESTRICTED' ? formAck.trim() : null,
        // A date-only input means "authorized through the end of that day"; the
        // engine fails closed on an expiry it has passed, so anchor to 23:59:59.
        valid_until: formValidUntil ? new Date(`${formValidUntil}T23:59:59`).toISOString() : null,
        notes: formNotes.trim() || null,
        targets: draftTargets.map(t => ({ kind: t.kind, value: t.value }))
      });
      await activateScope(id);
    });
    // Keep the form (and everything typed into it) open if the write failed.
    if (ok) {
      setShowScopeForm(false);
      resetScopeForm();
    }
  };

  /**
   * One-click UNRESTRICTED engagement for your own equipment.
   *
   * The scope gate exists to stop the offensive modules touching something you
   * were not authorized to touch, and nothing here weakens that: this still
   * creates a real engagement, it still runs in UNRESTRICTED mode with that
   * stated plainly on the report, and every gated command is still written to
   * the audit trail with the engagement name attached.
   *
   * What it removes is the typing, not the decision. The acknowledgement phrase
   * is a speed bump meant to make the operator state the claim consciously — so
   * this still asks once, in a dialog that says what is being claimed, rather
   * than filling the phrase in silently behind a single click.
   *
   * No expiry: a lab engagement that lapses mid-session would re-block every
   * module for the exact reason the operator pressed this button to avoid.
   */
  const handleLabEngagement = async () => {
    setConfirmLabScope(false);
    const today = new Date().toISOString().slice(0, 10);
    const ok = await runScopeAction('Lab engagement created and activated', async () => {
      const id = await createScope({
        engagement_name: `Lab / own network — ${today}`,
        authorized_by: operator.trim() || 'Self (own equipment)',
        reference: null,
        mode: 'UNRESTRICTED',
        unrestricted_ack: UNRESTRICTED_PHRASE,
        valid_until: null,
        notes:
          'Created with the LAB / MY OWN NETWORK shortcut. No allowlist is in '
          + 'force: the operator asserted that every reachable target is their '
          + 'own equipment or is covered by authorization they already hold.',
        targets: [],
      });
      await activateScope(id);
    });
    if (ok) setShowScopeForm(false);
  };

  const handleAddLiveTarget = async () => {
    if (!activeScope) return;
    const problem = validateTarget(liveKind, liveValue);
    if (problem) { setLiveError(problem); return; }
    setLiveError(null);
    const value = liveValue.trim();
    const ok = await runScopeAction(`Target ${liveKind} ${value} added`, () => addTarget(activeScope.id, { kind: liveKind, value }));
    if (ok) setLiveValue('');
  };

  const handleInspectScope = async (scopeId: number) => {
    if (inspectedScopeId === scopeId) {
      setInspectedScopeId(null);
      setInspectedTargets([]);
      return;
    }
    setInspectedScopeId(scopeId);
    try {
      setInspectedTargets(await getScopeTargets(scopeId));
    } catch (err) {
      setInspectedTargets([]);
      setScopeError(`Could not read the targets of that engagement: ${errText(err)}`);
    }
  };

  // ── Purge actions ────────────────────────────────────────────────────────

  const openPurgeReview = async () => {
    setPurgeError(null);
    setPurgeResult(null);
    setPurgeConfirmText('');
    setFootprint(null);
    setPurgeStage('REVIEW');
    try {
      setFootprint(await getDataFootprint());
    } catch (err) {
      setPurgeError(`Could not read the current data footprint: ${errText(err)}`);
    }
  };

  const cancelPurge = () => {
    setPurgeStage('IDLE');
    setFootprint(null);
    setPurgeConfirmText('');
    setPurgeError(null);
  };

  const executePurge = async () => {
    if (purgeConfirmText.trim().toUpperCase() !== PURGE_PHRASE) return;
    setPurgeStage('RUNNING');
    setPurgeError(null);
    try {
      const deleted = await purgeCollectedData();
      setPurgeResult(deleted);
      // The engine keeps its own in-memory dicts; clearing the tables alone
      // would leave the live view populated from RAM.
      try {
        await engineIPC.send('purge_data');
      } catch (err) {
        setPurgeError(`Database rows were deleted, but the engine's in-memory state was not cleared (${errText(err)}). Restart the engine to be sure.`);
      }
      useMissionStore.getState().reset();
      setPurgeStage('DONE');
    } catch (err) {
      setPurgeError(`Purge failed: ${errText(err)}. Nothing is guaranteed to have been deleted — re-check the footprint.`);
      setPurgeStage('REVIEW');
    } finally {
      setPurgeConfirmText('');
    }
  };

  const footprintTotal = footprint?.reduce((sum, r) => sum + r.rowsAffected, 0) ?? 0;
  const purgedTotal = purgeResult?.reduce((sum, r) => sum + r.rowsAffected, 0) ?? 0;

  // ── Derived scope view ───────────────────────────────────────────────────

  const dbCounts = { bssid: 0, ssid: 0, ip: 0, cidr: 0 };
  (activeScope?.targets ?? []).forEach(t => {
    const key = t.kind.toLowerCase() as keyof typeof dbCounts;
    if (key in dbCounts) dbCounts[key] += 1;
  });

  const dbScopeId = activeScope?.id ?? null;
  const engineScopeId = engineScope?.loaded ? engineScope.scope_id : null;
  const dbExpired = !!(activeScope?.valid_until && new Date(activeScope.valid_until).getTime() < Date.now());
  const identityMismatch = engineScope !== null && engineScopeId !== dbScopeId;
  const countMismatch =
    !identityMismatch && !!engineScope?.loaded &&
    (engineScope.counts.bssid !== dbCounts.bssid ||
      engineScope.counts.ssid !== dbCounts.ssid ||
      engineScope.counts.ip !== dbCounts.ip ||
      engineScope.counts.cidr !== dbCounts.cidr);
  const modeMismatch = !identityMismatch && !!engineScope?.loaded && !!activeScope && engineScope.mode !== activeScope.mode;
  const scopeMismatch = identityMismatch || countMismatch || modeMismatch;
  const offensiveBlocked = !engineScope || !engineScope.loaded || engineScope.expired;

  const handleDeleteBenchmark = async (id: number) => {
    try {
      await deleteBenchmark(id);
      setBenchmarkHistory(prev => prev.filter(b => b.id !== id));
      if (lastBenchmark?.id === id) setLastBenchmark(null);
      setCompareIds(prev => prev.filter(cid => cid !== id));
      setDeleteConfirmId(null);
    } catch (err) {
      console.error('[DB] deleteBenchmark error:', err);
    }
  };

  const toggleCompare = (id: number) => {
    setCompareIds(prev => {
      if (prev.includes(id)) return prev.filter(cid => cid !== id);
      if (prev.length >= 2) return [prev[1], id];
      return [...prev, id];
    });
  };

  const compareA = benchmarkHistory.find(b => b.id === compareIds[0]);
  const compareB = benchmarkHistory.find(b => b.id === compareIds[1]);

  /** Calculate a 0-100 benchmark score based on key metrics */
  const getBenchmarkScore = (b: BenchmarkResult): number => {
    if (b.total_aps === 0) return 0;
    // Weight: 40% AP count, 30% avg RSSI, 20% sensitivity, 10% excellent ratio
    const apScore = Math.min(b.total_aps / 50, 1) * 40;
    const avgScore = b.avg_rssi ? Math.max(0, Math.min(1, (b.avg_rssi + 90) / 40)) * 30 : 0;
    const sensScore = b.min_rssi ? Math.max(0, Math.min(1, (Math.abs(b.min_rssi) - 50) / 50)) * 20 : 0;
    const excellentRatio = b.total_aps > 0 ? (b.band_excellent + b.band_good) / b.total_aps : 0;
    const qualityScore = excellentRatio * 10;
    return Math.round(Math.min(100, apScore + avgScore + sensScore + qualityScore));
  };

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const [confirmDelete, setConfirmDelete] = useState<{ open: boolean; filename: string }>({ open: false, filename: '' });

  const handleDeleteWordlist = (filename: string) => {
    setConfirmDelete({ open: true, filename });
  };

  const executeDeleteWordlist = () => {
    engineIPC.send('delete_wordlist', { filename: confirmDelete.filename }).catch(console.error);
    setConfirmDelete({ open: false, filename: '' });
  };

  /**
   * Chunked upload. The bar used to walk to 100% and clear itself as soon as the
   * last chunk had been *written to stdin*, so a file the engine failed to save
   * still looked like a success. The final state now comes from the engine's own
   * `wordlist_saved` / `wordlist_error`, and progress stops at 99% until it does.
   */
  const handleFileUpload = (file: File) => {
    if (!file.name.endsWith('.txt')) {
      setWordlistNotice(`${file.name} was rejected — only .txt wordlists are supported.`);
      return;
    }

    const CHUNK_SIZE = 512 * 1024; // 512KB chunks
    let offset = 0;
    setWordlistNotice(null);
    uploadRef.current = { filename: file.name };
    setUploadProgress({ filename: file.name, progress: 0, phase: 'SENDING' });

    const fail = (message: string) => {
      console.error('[SYS] Upload failed:', message);
      uploadRef.current = null;
      setUploadProgress({ filename: file.name, progress: 0, phase: 'FAILED', message });
      setWordlistNotice(`${file.name}: ${message}`);
    };

    /*
      One decoder for the whole file, carrying partial characters across chunks.

      Each slice is a cut at an arbitrary *byte* offset, and `readAsText` decoded each
      one independently — so a multi-byte UTF-8 sequence straddling byte 524288 lost
      its tail in chunk N and had its orphaned continuation bytes in chunk N+1, each
      decoding to U+FFFD. One candidate corrupted per boundary, silently, in exactly
      the lists this tool ships for: the Thai password and mobile-number wordlists, and
      any list with accented Latin, Cyrillic or CJK. The engine opens with
      `errors='replace'`, so the damage was unrecoverable on the far side too.

      `TextDecoder` with `stream: true` holds an incomplete sequence back and prepends
      it to the next chunk, which is what it exists for. The final chunk is decoded
      with `stream: false` so anything still buffered is flushed rather than dropped.
    */
    const decoder = new TextDecoder('utf-8');

    const readNextChunk = () => {
      const slice = file.slice(offset, offset + CHUNK_SIZE);
      const reader = new FileReader();
      reader.onerror = () => fail('Could not read the file from disk.');
      reader.onload = async (event) => {
        const buffer = event.target?.result;
        if (!(buffer instanceof ArrayBuffer)) {
          fail('The file could not be read as bytes.');
          return;
        }
        const isFirst = offset === 0;
        offset += CHUNK_SIZE;
        const isFinal = offset >= file.size;
        const content = decoder.decode(new Uint8Array(buffer), { stream: !isFinal });

        try {
          await engineIPC.send('upload_wordlist', {
            filename: file.name,
            content: content,
            append: !isFirst,
            is_final: isFinal
          });
        } catch (err) {
          fail(errText(err));
          return;
        }

        // Cap at 99: the engine has not confirmed the write yet.
        const percentage = Math.min(99, Math.round((offset / file.size) * 100));
        if (!isFinal) {
          setUploadProgress({ filename: file.name, progress: percentage, phase: 'SENDING' });
          readNextChunk();
        } else {
          setUploadProgress({ filename: file.name, progress: 99, phase: 'FINALIZING' });
          // If the engine never answers either way, say so instead of implying success.
          window.setTimeout(() => {
            if (uploadRef.current?.filename === file.name) {
              uploadRef.current = null;
              setUploadProgress({
                filename: file.name,
                progress: 99,
                phase: 'FAILED',
                message: 'The engine never confirmed the write. Check the arsenal list before relying on this wordlist.'
              });
            }
          }, 20_000);
        }
      };
      reader.readAsArrayBuffer(slice);
    };

    readNextChunk();
  };

  return (
    <div
      className="w-full py-6 px-6 pb-20 relative h-full overflow-y-auto no-scrollbar select-none"
      style={{ WebkitTapHighlightColor: 'transparent' }}
    >
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold text-white text-tactical tracking-wider">COMMAND & CONTROL</h2>

          {/* Feedback Loop Indicator */}
          <div className="h-6 flex items-center justify-end w-32">
            <AnimatePresence mode="wait">
              {saveStatus === 'SAVING' && (
                <motion.span key="saving" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="text-xs font-mono text-gray-400 flex items-center gap-2">
                  <div className="w-1.5 h-1.5 rounded-full bg-gray-400 animate-pulse" /> SAVING...
                </motion.span>
              )}
              {saveStatus === 'SAVED' && (
                <motion.span key="saved" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="text-xs font-mono text-signal-strong flex items-center gap-2">
                  <div className="w-1.5 h-1.5 rounded-full bg-signal-strong" /> CONFIG SAVED
                </motion.span>
              )}
            </AnimatePresence>
          </div>
        </div>

        {/* About System Hero */}
        <div className="glass-card mb-6 p-8 flex flex-col md:flex-row items-center md:items-start gap-10 bg-gradient-to-r from-space-900/80 to-space-900/20 border-l-4 border-l-neon-500">
          <div className="flex-shrink-0 flex flex-col items-center group mt-2">
            <img src="/LOCKON_logo.svg" alt="Lockon Mascot" className="w-32 h-32 object-contain group-hover:scale-105 transition-transform duration-500" />
            <div className="mt-4 bg-space-900/80 px-3 py-1 rounded-sm text-[10px] font-mono text-neon-400 border border-neon-500/30 tracking-widest">v{APP_VERSION}</div>
          </div>

          <div className="flex-grow flex flex-col items-center md:items-start text-center md:text-left">
            <h2 className="text-3xl font-bold text-white text-tactical tracking-widest mb-1">LOCKON EWAC</h2>
            <div className="text-[11px] font-mono text-gray-400 mb-5 uppercase tracking-wider">Early Warning & Control - Active Reconnaissance</div>

            <div className="flex flex-wrap items-center justify-center md:justify-start gap-2 mb-6">
              <span className="px-2 py-1 bg-risk-critical/10 border border-risk-critical/30 rounded text-[9px] font-tactical text-risk-critical tracking-widest">CORE: RUST / TAURI</span>
              <span className="px-2 py-1 bg-neon-500/10 border border-neon-500/30 rounded text-[9px] font-tactical text-neon-400 tracking-widest">UI: VITE / REACT</span>
              {/*
                The engine badge says which build, not just which language.

                It read "ENGINE: PYTHON 3" while the engine reported a hardcoded
                "0.1.0", so a sidecar compiled days earlier looked identical to a
                fresh one — and a decoding bug already fixed in the source went
                on being reported from the field, because nothing anywhere said
                the running .exe predated the fix. A build older than the source
                is called out rather than merely displayed.
              */}
              {(() => {
                const build = engineBuild;
                if (!build) {
                  return (
                    <span
                      className="px-2 py-1 bg-space-700/40 border border-space-500/40 rounded text-[9px] font-tactical text-gray-400 tracking-widest"
                      title="The engine has not reported its build. Either it is not connected, or it predates the build stamp — in which case it is at least this old."
                    >ENGINE: BUILD UNKNOWN</span>
                  );
                }
                const stamp = build.built_at ? build.built_at.replace('T', ' ').replace('+00:00', 'Z') : 'unknown';
                const rev = build.git_describe ?? 'no revision';
                const dirty = build.git_describe?.includes('dirty');
                return (
                  <span
                    className={`px-2 py-1 rounded text-[9px] font-tactical tracking-widest ${
                      dirty
                        ? 'bg-amber-500/10 border border-amber-500/30 text-amber-300'
                        : 'bg-signal-strong/10 border border-signal-strong/30 text-signal-strong'
                    }`}
                    title={`Python ${build.python} · ${build.frozen ? 'compiled sidecar' : 'running from source'}`
                      + `\nBuilt: ${stamp}`
                      + `\nRevision: ${rev}`
                      + (dirty ? '\n\nBuilt from a working tree with uncommitted changes, so the revision does not identify it exactly.' : '')
                      + (build.frozen ? '\n\nIf this is older than your last change to engine/, rebuild the sidecar — the running code is not the code you edited.' : '')}
                  >
                    ENGINE: {build.frozen ? 'BUILD' : 'SOURCE'} {stamp.slice(0, 16)}
                  </span>
                );
              })()}
              <span className="px-2 py-1 bg-risk-high/10 border border-risk-high/30 rounded text-[9px] font-tactical text-risk-high tracking-widest">GIS: MAPLIBRE-GL</span>
            </div>

            <div className="text-[11px] text-gray-400 font-mono leading-relaxed border-t border-space-500/20 pt-5 w-full space-y-3">
              <p>
                <strong className="text-neon-400 font-tactical tracking-wide">LOCKON EWAC</strong> is an advanced agentic network warfare and threat intelligence platform designed for deep reconnaissance and tactical auditing.
              </p>
              <p>
                Operating strictly off-grid, it provides high-fidelity, real-time spatial awareness across <strong>2.4GHz, 5GHz, and 6GHz</strong> 802.11 environments. The system incorporates an autonomous offensive kill-chain—featuring WPS auditing, PMKID capture, and offline Hashcat integration—engineered for advanced red team operations.
              </p>
              <p className="text-risk-high text-[10px] mt-2 border-l-2 border-risk-high pl-2">
                AUTHORIZED USE ONLY. OPERATOR DISCRETION IS STRICTLY ADVISED.
              </p>
            </div>
          </div>
        </div>

        {/* ───────────────────────── ENGAGEMENT SCOPE ───────────────────────── */}
        <div className={`glass-card mb-6 p-6 border-l-4 ${offensiveBlocked ? 'border-l-risk-high bg-risk-high/[0.03]' : activeScope?.mode === 'UNRESTRICTED' ? 'border-l-risk-critical bg-risk-critical/[0.04]' : 'border-l-signal-strong bg-signal-strong/[0.03]'}`}>
          <div className="flex flex-wrap items-center justify-between gap-3 mb-4 border-b border-space-500/20 pb-3">
            <h3 className="text-xs font-semibold text-white text-tactical tracking-wider uppercase flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className={`w-4 h-4 ${offensiveBlocked ? 'text-risk-high' : 'text-signal-strong'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              Engagement Scope
            </h3>
            <div className="flex items-center gap-2">
              <span className={`px-2 py-1 rounded text-[9px] font-tactical tracking-widest border ${offensiveBlocked ? 'bg-risk-high/10 border-risk-high/40 text-risk-high' : 'bg-signal-strong/10 border-signal-strong/40 text-signal-strong'}`}>
                {offensiveBlocked ? 'OFFENSIVE MODULES BLOCKED' : 'OFFENSIVE MODULES ARMED'}
              </span>
              <button
                onClick={() => { setScopeBusy(true); syncScope('Resync').finally(() => setScopeBusy(false)); }}
                disabled={scopeBusy}
                className="px-3 py-1.5 text-[10px] font-tactical tracking-widest text-gray-300 border border-space-500/30 rounded hover:bg-space-800 hover:text-white transition-colors disabled:opacity-40"
              >
                RESYNC ENGINE
              </button>
            </div>
          </div>

          {/* Deny-by-default guidance — a normal starting state, not a fault */}
          {!activeScope && scopeLoaded && (
            <div className="mb-5 rounded border border-risk-high/40 bg-risk-high/10 p-4">
              <div className="flex items-start gap-3">
                <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-risk-high shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>
                <div>
                  <div className="text-sm font-tactical tracking-wider text-risk-high mb-1">NO ACTIVE ENGAGEMENT — EVERY OFFENSIVE MODULE IS BLOCKED</div>
                  <p className="text-[11px] text-gray-300 font-mono leading-relaxed">
                    This is the intended resting state, not an error. The engine denies by default, so capture, brute-force, spray,
                    MITM, dirbuster, SMB enumeration, vulnerability scanning and the auto-attack chain will all refuse to run until you
                    state what you were authorized to touch. Passive listening and read-only local queries are unaffected.
                  </p>
                  <p className="text-[11px] text-gray-400 font-mono mt-2">
                    Define an engagement below with the authorization you actually hold, then activate it.
                  </p>
                </div>
              </div>
            </div>
          )}

          {/* Side-by-side: what the database holds vs what the engine is gating on */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            {/* DATABASE-SIDE CONFIG */}
            <div className="bg-space-950/60 border border-space-500/20 rounded p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="text-[10px] font-tactical tracking-widest text-gray-400">THIS DEVICE (DATABASE)</div>
                {activeScope && (
                  <span className={`px-2 py-0.5 rounded text-[9px] font-tactical tracking-wider border ${activeScope.mode === 'UNRESTRICTED' ? 'bg-risk-critical/15 border-risk-critical/50 text-risk-critical' : 'bg-signal-strong/10 border-signal-strong/40 text-signal-strong'}`}>
                    {activeScope.mode}
                  </span>
                )}
              </div>
              {activeScope ? (
                <div className="space-y-2 text-[11px] font-mono">
                  <div className="text-sm font-tactical tracking-wider text-white">{activeScope.engagement_name}</div>
                  <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
                    <div><span className="text-gray-600">AUTHORIZED BY</span><div className="text-gray-200">{activeScope.authorized_by}</div></div>
                    <div><span className="text-gray-600">REFERENCE</span><div className="text-gray-200">{activeScope.reference || '—'}</div></div>
                    <div><span className="text-gray-600">VALID FROM</span><div className="text-gray-200">{fmtDate(activeScope.valid_from)}</div></div>
                    <div>
                      <span className="text-gray-600">VALID UNTIL</span>
                      <div className={dbExpired ? 'text-risk-critical' : 'text-gray-200'}>
                        {activeScope.valid_until ? fmtDate(activeScope.valid_until) : 'No expiry set'}
                        {dbExpired && ' — EXPIRED'}
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2 pt-1">
                    {(['BSSID', 'SSID', 'IP', 'CIDR'] as TargetKind[]).map(k => (
                      <span key={k} className={`px-2 py-0.5 rounded border text-[9px] font-mono ${KIND_COLOR[k]}`}>
                        {k} {dbCounts[k.toLowerCase() as keyof typeof dbCounts]}
                      </span>
                    ))}
                  </div>
                  {activeScope.notes && (
                    <div className="text-[10px] text-gray-500 border-t border-space-500/10 pt-2">NOTE: {activeScope.notes}</div>
                  )}
                </div>
              ) : (
                <div className="text-[11px] font-mono text-gray-500">{scopeLoaded ? 'No engagement is active.' : 'Reading engagement table...'}</div>
              )}
            </div>

            {/* ENGINE-SIDE TRUTH */}
            <div className={`bg-space-950/60 border rounded p-4 ${scopeMismatch ? 'border-risk-critical/50' : 'border-space-500/20'}`}>
              <div className="flex items-center justify-between mb-3">
                <div className="text-[10px] font-tactical tracking-widest text-gray-400">ENGINE (GATE IN FORCE)</div>
                {engineScope && (
                  <span className={`px-2 py-0.5 rounded text-[9px] font-tactical tracking-wider border ${!engineScope.loaded || engineScope.expired ? 'bg-risk-high/10 border-risk-high/40 text-risk-high' : engineScope.mode === 'UNRESTRICTED' ? 'bg-risk-critical/15 border-risk-critical/50 text-risk-critical' : 'bg-signal-strong/10 border-signal-strong/40 text-signal-strong'}`}>
                    {!engineScope.loaded ? 'DENY ALL' : engineScope.expired ? 'EXPIRED' : engineScope.mode}
                  </span>
                )}
              </div>
              {!engineScope ? (
                <div className="text-[11px] font-mono text-gray-500">
                  The engine has not reported a scope{connected ? ' yet' : ' (uplink offline)'}. Until it does, treat the gate as unknown and
                  press RESYNC ENGINE before running anything offensive.
                </div>
              ) : !engineScope.loaded ? (
                <div className="text-[11px] font-mono text-risk-high">
                  No scope loaded in the engine. It is denying every gated command.
                </div>
              ) : (
                <div className="space-y-2 text-[11px] font-mono">
                  <div className="text-sm font-tactical tracking-wider text-white">{engineScope.engagement_name}</div>
                  <div className="grid grid-cols-2 gap-x-3 gap-y-1.5">
                    <div><span className="text-gray-600">AUTHORIZED BY</span><div className="text-gray-200">{engineScope.authorized_by || '—'}</div></div>
                    <div><span className="text-gray-600">OPERATOR</span><div className="text-gray-200">{engineScope.operator || '—'}</div></div>
                    <div><span className="text-gray-600">REFERENCE</span><div className="text-gray-200">{engineScope.reference || '—'}</div></div>
                    <div>
                      <span className="text-gray-600">VALID UNTIL</span>
                      <div className={engineScope.expired ? 'text-risk-critical' : 'text-gray-200'}>
                        {engineScope.valid_until ? fmtDate(engineScope.valid_until) : 'No expiry'}
                        {engineScope.expired && ' — EXPIRED'}
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2 pt-1">
                    {(['bssid', 'ssid', 'ip', 'cidr'] as const).map(k => (
                      <span key={k} className={`px-2 py-0.5 rounded border text-[9px] font-mono ${KIND_COLOR[k.toUpperCase() as TargetKind]}`}>
                        {k.toUpperCase()} {engineScope.counts?.[k] ?? 0}
                      </span>
                    ))}
                  </div>
                  <div className="text-[10px] text-gray-500 border-t border-space-500/10 pt-2">
                    GATED COMMANDS ({engineScope.gated_commands?.length ?? 0}): {(engineScope.gated_commands ?? []).join(', ') || '—'}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Mismatch / sync / warning banners */}
          {scopeMismatch && (
            <div className="mb-3 rounded border border-risk-critical/50 bg-risk-critical/10 p-3 text-[11px] font-mono text-risk-critical">
              <strong className="font-tactical tracking-wider">SCOPE MISMATCH.</strong>{' '}
              {identityMismatch
                ? 'The engine is gating on a different engagement than the one active on this device.'
                : modeMismatch
                  ? 'The engine is running a different mode than the active engagement.'
                  : 'The engine is holding a different number of targets than the active engagement.'}{' '}
              The engine decides what runs, so press RESYNC ENGINE and confirm both panels agree before proceeding.
            </div>
          )}
          {scopeSyncError && (
            <div className="mb-3 rounded border border-risk-critical/50 bg-risk-critical/10 p-3 text-[11px] font-mono text-risk-critical">{scopeSyncError}</div>
          )}
          {scopeError && (
            <div className="mb-3 rounded border border-risk-high/50 bg-risk-high/10 p-3 text-[11px] font-mono text-risk-high">{scopeError}</div>
          )}
          {scopeNotice && !scopeSyncError && (
            <div className="mb-3 rounded border border-signal-strong/40 bg-signal-strong/10 p-3 text-[11px] font-mono text-signal-strong">{scopeNotice}</div>
          )}
          {scopeWarnings.length > 0 && (
            <div className="mb-3 rounded border border-risk-high/40 bg-risk-high/5 p-3">
              <div className="flex items-center justify-between mb-1">
                <span className="text-[10px] font-tactical tracking-widest text-risk-high">ENGINE IGNORED SCOPE ENTRIES</span>
                <button onClick={() => setScopeWarnings([])} className="text-[9px] font-tactical text-gray-500 hover:text-gray-300">DISMISS</button>
              </div>
              {scopeWarnings.map((w, i) => (
                <div key={i} className="text-[10px] font-mono text-gray-300">• {w}</div>
              ))}
              <div className="text-[10px] font-mono text-gray-500 mt-1">Those entries authorize nothing. Fix or remove them.</div>
            </div>
          )}

          {/* Operator signature */}
          <div className="mb-4">
            <label className="block text-[10px] text-gray-500 font-mono mb-1.5">OPERATOR (SIGNS EVERY AUDIT ROW)</label>
            <input
              type="text"
              value={operator}
              onChange={(e) => setOperator(e.target.value)}
              placeholder="Your name or callsign"
              className="w-full sm:w-2/3 bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 text-sm font-mono placeholder-gray-600 focus:outline-none focus:border-space-500/50 transition-colors"
            />
            <p className="text-[10px] text-gray-600 font-mono mt-1">Sent with the scope on the next push. Blank leaves the audit trail unsigned.</p>
          </div>

          {/* Targets of the active engagement */}
          {activeScope && (
            <div className="mb-4 bg-space-950/40 border border-space-500/20 rounded p-4">
              <div className="flex items-center justify-between mb-3">
                <div className="text-[10px] font-tactical tracking-widest text-gray-400">
                  AUTHORIZED TARGETS ({activeScope.targets.length})
                </div>
                {activeScope.mode === 'UNRESTRICTED' && (
                  <span className="text-[9px] font-mono text-risk-critical">Not consulted in UNRESTRICTED mode.</span>
                )}
              </div>

              {activeScope.targets.length === 0 ? (
                <div className="text-[11px] font-mono text-gray-500 mb-3">
                  {activeScope.mode === 'UNRESTRICTED'
                    ? 'No allowlist entries — none are required in this mode.'
                    : 'No targets on this engagement, so nothing is authorized. Add at least one below.'}
                </div>
              ) : (
                <div className="flex flex-wrap gap-2 mb-3">
                  {activeScope.targets.map(t => (
                    <span key={t.id} className={`group flex items-center gap-2 px-2 py-1 rounded border text-[10px] font-mono ${KIND_COLOR[t.kind]}`}>
                      <span className="opacity-70">{t.kind}</span>
                      <span className="text-white">{t.value}</span>
                      <button
                        onClick={() => t.id !== undefined && runScopeAction(`Target ${t.kind} ${t.value} removed`, () => removeTarget(t.id as number))}
                        disabled={scopeBusy}
                        title="Remove from scope"
                        className="text-gray-500 hover:text-risk-critical transition-colors disabled:opacity-30"
                      >
                        ✕
                      </button>
                    </span>
                  ))}
                </div>
              )}

              {/* Add target to the live engagement */}
              <div className="flex flex-col sm:flex-row gap-2">
                <div className="relative sm:w-32">
                  <select
                    value={liveKind}
                    onChange={(e) => { setLiveKind(e.target.value as TargetKind); setLiveError(null); }}
                    className="appearance-none bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 pr-8 text-xs font-mono w-full focus:outline-none focus:border-space-500/50"
                  >
                    {TARGET_KINDS.map(k => <option key={k.kind} value={k.kind}>{k.label}</option>)}
                  </select>
                  <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-space-400">
                    <svg className="fill-current h-3 w-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" /></svg>
                  </div>
                </div>
                <input
                  type="text"
                  value={liveValue}
                  onChange={(e) => { setLiveValue(e.target.value); setLiveError(null); }}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleAddLiveTarget(); } }}
                  placeholder={TARGET_KINDS.find(k => k.kind === liveKind)?.placeholder}
                  className={`flex-1 bg-space-900 border text-white rounded px-3 py-2 text-xs font-mono placeholder-gray-600 focus:outline-none ${liveError ? 'border-risk-critical' : 'border-space-500/30 focus:border-space-500/50'}`}
                />
                <button
                  onClick={handleAddLiveTarget}
                  disabled={scopeBusy}
                  className="px-4 py-2 text-[10px] font-tactical tracking-widest border border-signal-strong/50 text-signal-strong bg-signal-strong/10 rounded hover:bg-signal-strong/20 transition-colors disabled:opacity-40"
                >
                  ADD TARGET
                </button>
              </div>
              {liveError && <div className="text-[10px] font-mono text-risk-critical mt-1.5">{liveError}</div>}
              <p className="text-[10px] text-gray-600 font-mono mt-1.5">{TARGET_KINDS.find(k => k.kind === liveKind)?.hint}</p>
            </div>
          )}

          {/* Engagement list */}
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-[10px] font-tactical tracking-widest text-gray-400">RECORDED ENGAGEMENTS ({scopes.length})</div>
              {activeScope && (
                <button
                  onClick={() => runScopeAction('Engagement deactivated', () => deactivateAllScopes())}
                  disabled={scopeBusy}
                  className="px-3 py-1.5 text-[10px] font-tactical tracking-widest text-risk-high border border-risk-high/40 rounded hover:bg-risk-high/10 transition-colors disabled:opacity-40"
                >
                  DEACTIVATE (BLOCK EVERYTHING)
                </button>
              )}
            </div>

            {scopes.length === 0 ? (
              <div className="text-[11px] font-mono text-gray-500 bg-space-950/40 border border-space-500/10 rounded p-4 text-center">
                No engagements recorded yet.
              </div>
            ) : (
              <div className="space-y-2">
                {scopes.map(s => (
                  <div key={s.id} className={`rounded border p-3 ${s.is_active ? 'border-signal-strong/40 bg-signal-strong/5' : 'border-space-500/20 bg-space-950/40'}`}>
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2">
                          {s.is_active === 1 && <span className="w-1.5 h-1.5 rounded-full bg-signal-strong" />}
                          <span className="text-sm font-tactical tracking-wide text-white truncate">{s.engagement_name}</span>
                          <span className={`px-1.5 py-0.5 rounded text-[8px] font-tactical tracking-wider border ${s.mode === 'UNRESTRICTED' ? 'bg-risk-critical/15 border-risk-critical/50 text-risk-critical' : 'bg-space-800 border-space-500/30 text-gray-400'}`}>
                            {s.mode}
                          </span>
                        </div>
                        <div className="text-[10px] font-mono text-gray-500 mt-0.5">
                          {s.authorized_by}{s.reference ? ` · ${s.reference}` : ''} · created {fmtDate(s.created_at)}
                          {s.valid_until ? ` · until ${fmtDate(s.valid_until)}` : ''}
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <button
                          onClick={() => handleInspectScope(s.id)}
                          className="px-2 py-1 text-[9px] font-tactical tracking-widest text-gray-400 border border-space-500/30 rounded hover:text-white hover:bg-space-800 transition-colors"
                        >
                          {inspectedScopeId === s.id ? 'HIDE TARGETS' : 'VIEW TARGETS'}
                        </button>
                        {s.is_active !== 1 && (
                          <button
                            onClick={() => runScopeAction(`Engagement "${s.engagement_name}" activated`, () => activateScope(s.id))}
                            disabled={scopeBusy}
                            className="px-2 py-1 text-[9px] font-tactical tracking-widest text-signal-strong border border-signal-strong/40 rounded hover:bg-signal-strong/10 transition-colors disabled:opacity-40"
                          >
                            ACTIVATE
                          </button>
                        )}
                        <button
                          onClick={() => setConfirmDeleteScope(s)}
                          disabled={scopeBusy}
                          className="px-2 py-1 text-[9px] font-tactical tracking-widest text-gray-500 border border-space-500/30 rounded hover:text-risk-critical hover:border-risk-critical/40 transition-colors disabled:opacity-40"
                        >
                          DELETE
                        </button>
                      </div>
                    </div>

                    {inspectedScopeId === s.id && (
                      <div className="mt-3 pt-3 border-t border-space-500/10">
                        {inspectedTargets.length === 0 ? (
                          <div className="text-[10px] font-mono text-gray-500">No targets recorded on this engagement.</div>
                        ) : (
                          <div className="flex flex-wrap gap-2">
                            {inspectedTargets.map(t => (
                              <span key={t.id} className={`px-2 py-0.5 rounded border text-[10px] font-mono ${KIND_COLOR[t.kind]}`}>
                                <span className="opacity-70">{t.kind}</span> <span className="text-white">{t.value}</span>
                              </span>
                            ))}
                          </div>
                        )}
                        {s.notes && <div className="text-[10px] font-mono text-gray-500 mt-2">NOTE: {s.notes}</div>}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* New engagement */}
          {!showScopeForm ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <button
                onClick={() => { resetScopeForm(); setScopeError(null); setShowScopeForm(true); }}
                className="w-full py-3 text-xs font-tactical tracking-widest rounded border border-neon-500/40 bg-neon-500/10 text-neon-400 hover:bg-neon-500/20 transition-colors flex items-center justify-center gap-2"
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
                DEFINE NEW ENGAGEMENT
              </button>

              {/*
                The shortcut for testing your own kit. It is a real engagement,
                audited like any other — it just skips a form that says nothing
                useful when the answer to "who authorized this" is "I own it".
              */}
              <button
                onClick={() => { setScopeError(null); setConfirmLabScope(true); }}
                className="w-full py-3 text-xs font-tactical tracking-widest rounded border border-space-500/40 bg-space-800/50 text-gray-300 hover:bg-space-700 hover:text-white transition-colors flex items-center justify-center gap-2"
              >
                <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 3h6v6l4 9a2 2 0 0 1-1.8 3H6.8A2 2 0 0 1 5 18l4-9V3Z"/><path d="M9 3h6"/></svg>
                LAB / MY OWN NETWORK
              </button>
            </div>
          ) : (
            <div className="bg-space-950/60 border border-neon-500/30 rounded p-4">
              <div className="flex items-center justify-between mb-4">
                <div className="text-[10px] font-tactical tracking-widest text-neon-400">NEW ENGAGEMENT</div>
                <button onClick={() => { setShowScopeForm(false); resetScopeForm(); }} className="text-[9px] font-tactical text-gray-500 hover:text-gray-300">CANCEL</button>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mb-3">
                <div>
                  <label className="block text-[10px] text-gray-500 font-mono mb-1">ENGAGEMENT NAME *</label>
                  <input type="text" value={formName} onChange={(e) => setFormName(e.target.value)} placeholder="Acme HQ wireless audit"
                    className="w-full bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 text-xs font-mono placeholder-gray-600 focus:outline-none focus:border-space-500/50" />
                </div>
                <div>
                  <label className="block text-[10px] text-gray-500 font-mono mb-1">AUTHORIZED BY *</label>
                  <input type="text" value={formAuthorizedBy} onChange={(e) => setFormAuthorizedBy(e.target.value)} placeholder="Name and role of the signatory"
                    className="w-full bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 text-xs font-mono placeholder-gray-600 focus:outline-none focus:border-space-500/50" />
                </div>
                <div>
                  <label className="block text-[10px] text-gray-500 font-mono mb-1">REFERENCE (TICKET / DOCUMENT)</label>
                  <input type="text" value={formReference} onChange={(e) => setFormReference(e.target.value)} placeholder="SOW-2026-114 / JIRA-8821"
                    className="w-full bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 text-xs font-mono placeholder-gray-600 focus:outline-none focus:border-space-500/50" />
                </div>
                <div>
                  <label className="block text-[10px] text-gray-500 font-mono mb-1">VALID UNTIL (OPTIONAL)</label>
                  <input type="date" value={formValidUntil} onChange={(e) => setFormValidUntil(e.target.value)}
                    className="w-full bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 text-xs font-mono focus:outline-none focus:border-space-500/50" />
                  <p className="text-[9px] text-gray-600 font-mono mt-1">The engine refuses everything once this date has passed.</p>
                </div>
              </div>

              <div className="mb-4">
                <label className="block text-[10px] text-gray-500 font-mono mb-1">NOTES (OPTIONAL)</label>
                <textarea value={formNotes} onChange={(e) => setFormNotes(e.target.value)} rows={2} placeholder="Constraints, agreed windows, contacts..."
                  className="w-full bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 text-xs font-mono placeholder-gray-600 focus:outline-none focus:border-space-500/50 resize-none" />
              </div>

              {/* Targets builder */}
              <div className={`mb-4 rounded border p-3 ${formMode === 'UNRESTRICTED' ? 'border-space-500/20 opacity-50' : 'border-space-500/20'}`}>
                <div className="text-[10px] font-tactical tracking-widest text-gray-400 mb-2">
                  AUTHORIZED TARGETS ({draftTargets.length}){formMode === 'ALLOWLIST' ? ' *' : ' — unused in UNRESTRICTED mode'}
                </div>
                <div className="flex flex-col sm:flex-row gap-2">
                  <div className="relative sm:w-32">
                    <select
                      value={draftKind}
                      onChange={(e) => { setDraftKind(e.target.value as TargetKind); setDraftError(null); }}
                      className="appearance-none bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 pr-8 text-xs font-mono w-full focus:outline-none focus:border-space-500/50"
                    >
                      {TARGET_KINDS.map(k => <option key={k.kind} value={k.kind}>{k.label}</option>)}
                    </select>
                    <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-space-400">
                      <svg className="fill-current h-3 w-3" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" /></svg>
                    </div>
                  </div>
                  <input
                    type="text"
                    value={draftValue}
                    onChange={(e) => { setDraftValue(e.target.value); setDraftError(null); }}
                    onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); handleAddDraftTarget(); } }}
                    placeholder={TARGET_KINDS.find(k => k.kind === draftKind)?.placeholder}
                    className={`flex-1 bg-space-900 border text-white rounded px-3 py-2 text-xs font-mono placeholder-gray-600 focus:outline-none ${draftError ? 'border-risk-critical' : 'border-space-500/30 focus:border-space-500/50'}`}
                  />
                  <button
                    onClick={handleAddDraftTarget}
                    className="px-4 py-2 text-[10px] font-tactical tracking-widest border border-space-500/30 text-gray-300 rounded hover:bg-space-800 hover:text-white transition-colors"
                  >
                    ADD
                  </button>
                </div>
                {draftError && <div className="text-[10px] font-mono text-risk-critical mt-1.5">{draftError}</div>}
                <p className="text-[10px] text-gray-600 font-mono mt-1.5">{TARGET_KINDS.find(k => k.kind === draftKind)?.hint}</p>

                {draftTargets.length > 0 && (
                  <div className="flex flex-wrap gap-2 mt-3">
                    {draftTargets.map(t => {
                      const flagged = badDraftKeys.includes(t.key);
                      return (
                        <span key={t.key} className={`flex items-center gap-2 px-2 py-1 rounded border text-[10px] font-mono ${flagged ? 'border-risk-critical bg-risk-critical/15 text-risk-critical' : KIND_COLOR[t.kind]}`}>
                          <span className="opacity-70">{t.kind}</span>
                          <span className={flagged ? '' : 'text-white'}>{t.value}</span>
                          {flagged && <span title={validateTarget(t.kind, t.value) ?? ''}>⚠</span>}
                          <button onClick={() => { setDraftTargets(prev => prev.filter(d => d.key !== t.key)); setBadDraftKeys(prev => prev.filter(k => k !== t.key)); }} className="text-gray-500 hover:text-risk-critical transition-colors">✕</button>
                        </span>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Mode */}
              <div className="mb-4">
                <div className="text-[10px] font-tactical tracking-widest text-gray-400 mb-2">MODE</div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <button
                    onClick={() => { setFormMode('ALLOWLIST'); setFormAck(''); }}
                    className={`p-3 rounded border text-left transition-all ${formMode === 'ALLOWLIST' ? 'bg-space-800 border-signal-strong' : 'bg-space-900 border-space-500/30 hover:border-space-500/50'}`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <div className={`w-2 h-2 rounded-full ${formMode === 'ALLOWLIST' ? 'bg-signal-strong' : 'bg-gray-600'}`} />
                      <span className={`text-xs font-tactical tracking-wider ${formMode === 'ALLOWLIST' ? 'text-signal-strong' : 'text-gray-400'}`}>ALLOWLIST (RECOMMENDED)</span>
                    </div>
                    <p className="text-[10px] text-gray-500 font-mono leading-relaxed">A target must match an entry above. Everything else is refused and recorded as blocked.</p>
                  </button>

                  <button
                    onClick={() => setFormMode('UNRESTRICTED')}
                    className={`p-3 rounded border text-left transition-all ${formMode === 'UNRESTRICTED' ? 'bg-risk-critical/10 border-risk-critical' : 'bg-space-900 border-space-500/30 hover:border-risk-critical/40'}`}
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <div className={`w-2 h-2 rounded-full ${formMode === 'UNRESTRICTED' ? 'bg-risk-critical animate-pulse' : 'bg-gray-600'}`} />
                      <span className={`text-xs font-tactical tracking-wider ${formMode === 'UNRESTRICTED' ? 'text-risk-critical' : 'text-gray-400'}`}>UNRESTRICTED — LAB / OWN NETWORK</span>
                    </div>
                    <p className="text-[10px] text-gray-500 font-mono leading-relaxed">
                      No allowlist in force — every reachable target is permitted. Still recorded in the audit trail, and the report states plainly that no allowlist applied.
                    </p>
                  </button>
                </div>
              </div>

              {formMode === 'UNRESTRICTED' && (
                <div className="mb-4 rounded border border-risk-critical/50 bg-risk-critical/10 p-3">
                  <div className="text-[10px] font-tactical tracking-widest text-risk-critical mb-2">ACKNOWLEDGEMENT REQUIRED</div>
                  <p className="text-[11px] font-mono text-gray-300 leading-relaxed mb-2">
                    In this mode nothing is checked against an allowlist: anything the rig can reach can be attacked, including
                    neighbours you did not intend to touch. Use it only on a lab or a network you own. Type the phrase below exactly
                    to confirm — it is stored with the engagement and appears in the audit record.
                  </p>
                  <div className="text-[11px] font-mono text-risk-critical bg-space-950/70 border border-risk-critical/30 rounded px-2 py-1.5 mb-2 select-text">
                    {UNRESTRICTED_PHRASE}
                  </div>
                  <input
                    type="text"
                    value={formAck}
                    onChange={(e) => setFormAck(e.target.value)}
                    placeholder="Type the phrase above"
                    className={`w-full bg-space-900 border text-white rounded px-3 py-2 text-xs font-mono placeholder-gray-600 focus:outline-none ${formAck.trim() === UNRESTRICTED_PHRASE ? 'border-signal-strong' : 'border-risk-critical/50'}`}
                  />
                </div>
              )}

              <button
                onClick={handleCreateScope}
                disabled={scopeBusy || (formMode === 'UNRESTRICTED' && formAck.trim() !== UNRESTRICTED_PHRASE)}
                className={`w-full py-3 text-xs font-tactical tracking-widest rounded border transition-colors ${scopeBusy || (formMode === 'UNRESTRICTED' && formAck.trim() !== UNRESTRICTED_PHRASE)
                  ? 'bg-space-800 border-space-500/20 text-gray-600 cursor-not-allowed'
                  : formMode === 'UNRESTRICTED'
                    ? 'bg-risk-critical/15 border-risk-critical/60 text-risk-critical hover:bg-risk-critical/25'
                    : 'bg-signal-strong/10 border-signal-strong/50 text-signal-strong hover:bg-signal-strong/20'}`}
              >
                {scopeBusy ? 'SAVING...' : 'SAVE, ACTIVATE & PUSH TO ENGINE'}
              </button>
            </div>
          )}
        </div>

        {/* ─────────────────────── HARDWARE READINESS ───────────────────────
            The most consequential panel on this page. A handshake capture on an
            adapter that cannot enter monitor mode returns nothing, and "nothing"
            is indistinguishable from "the target is secure" — that is how this
            tool could produce a confidently wrong report. So what the hardware
            cannot do is stated up front, per feature, with the reason. */}
        <div className={`glass-card p-6 mb-6 border-l-2 ${
          !caps ? 'border-l-space-500'
            : caps.unavailable_features.length === 0 ? 'border-l-signal-strong'
            : 'border-l-risk-high'
        }`}>
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-gray-300 text-tactical tracking-wider uppercase flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0" /><path d="M1.42 9a16 16 0 0 1 21.16 0" /><path d="M8.53 16.11a6 6 0 0 1 6.95 0" /><line x1="12" y1="20" x2="12.01" y2="20" /></svg>
              Hardware Readiness (802.11)
            </h3>
            <div className="flex items-center gap-2">
              {caps && (
                <span className={`px-2 py-0.5 rounded text-[9px] font-tactical tracking-wider border ${
                  caps.unavailable_features.length === 0
                    ? 'bg-signal-strong/10 border-signal-strong/40 text-signal-strong'
                    : 'bg-risk-high/10 border-risk-high/40 text-risk-high'
                }`}>
                  {caps.unavailable_features.length === 0 ? 'ALL AVAILABLE' : `${caps.unavailable_features.length} BLOCKED`}
                </span>
              )}
              <button
                onClick={() => engineIPC.send('check_capabilities', {
                  interface_name: config.interfaceName || null,
                }).catch(console.error)}
                disabled={!connected}
                className="text-[10px] px-2 py-1 rounded bg-space-800 text-gray-300 hover:bg-space-700 border border-space-500/30 font-tactical uppercase disabled:opacity-40"
              >
                Re-probe
              </button>
            </div>
          </div>

          {!caps ? (
            <div className="text-xs font-mono text-gray-500">
              {connected ? 'Probing hardware capability…' : 'Engine offline — capability is unknown.'}
            </div>
          ) : (
            <>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
                {[
                  { label: 'NPCAP DRIVER', ok: caps.npcap.available, detail: caps.npcap.available === null ? caps.npcap.note : (caps.npcap.available ? (caps.npcap.service_state || 'present') : 'not installed') },
                  { label: 'RAW L2 SOCKET', ok: caps.raw_socket.available, detail: caps.raw_socket.available ? 'available' : (caps.raw_socket.error || 'unavailable') },
                  { label: 'ELEVATED', ok: caps.elevated, detail: caps.elevated ? 'administrator' : 'standard user' },
                  { label: 'MONITOR MODE', ok: caps.monitor_mode.supported, detail: caps.monitor_mode.supported === null ? 'cannot be confirmed' : (caps.monitor_mode.supported ? 'supported' : (caps.monitor_mode.reason || 'unsupported')) },
                ].map(item => (
                  <div key={item.label} className="p-3 bg-space-800/50 rounded border border-space-500/10">
                    <div className="text-[10px] text-gray-500 font-mono mb-1">{item.label}</div>
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full shrink-0 ${
                        item.ok === true ? 'bg-signal-strong'
                          : item.ok === false ? 'bg-risk-critical'
                          : 'bg-risk-high'
                      }`} />
                      <span className={`text-[10px] font-tactical ${
                        item.ok === true ? 'text-signal-strong' : item.ok === false ? 'text-risk-critical' : 'text-risk-high'
                      }`}>
                        {item.ok === true ? 'YES' : item.ok === false ? 'NO' : 'UNKNOWN'}
                      </span>
                    </div>
                    <div className="text-[9px] font-mono text-gray-600 mt-1 leading-tight">{item.detail}</div>
                  </div>
                ))}
              </div>

              {/* Monitor mode is reported as unknown rather than guessed at, and
                  the reason is spelled out — a confident wrong answer here is the
                  whole problem this panel exists to prevent. */}
              {caps.monitor_mode.note && (
                <div className="text-[10px] font-mono text-risk-high bg-risk-high/10 border border-risk-high/30 rounded px-3 py-2 mb-4 leading-relaxed">
                  {caps.monitor_mode.note}
                </div>
              )}

              <div className="space-y-1.5">
                {Object.entries(caps.features).map(([name, f]) => (
                  <div key={name} className={`flex items-start gap-3 px-3 py-2 rounded border text-[10px] font-mono ${
                    f.ready ? 'bg-space-900/50 border-space-500/20' : 'bg-risk-critical/5 border-risk-critical/30'
                  }`}>
                    <span className={`shrink-0 w-14 font-tactical tracking-wider ${f.ready ? 'text-signal-strong' : 'text-risk-critical'}`}>
                      {f.ready ? 'READY' : 'BLOCKED'}
                    </span>
                    <span className="shrink-0 w-40 text-gray-300 uppercase">{name.replace(/_/g, ' ')}</span>
                    <span className="text-gray-600 flex-1 leading-tight">
                      Requires {f.requires}.
                      {!f.ready && f.caveat && <span className="text-risk-high"> {f.caveat}</span>}
                      {f.ready && f.caveat && <span className="text-risk-high/70"> {f.caveat}</span>}
                      {f.note && <span className="text-gray-500"> {f.note}</span>}
                    </span>
                  </div>
                ))}
              </div>

              {caps.npcap.hint && (
                <div className="text-[10px] font-mono text-gray-400 mt-3 px-3 py-2 bg-space-800/50 rounded border border-space-500/20">
                  {caps.npcap.hint}
                </div>
              )}
            </>
          )}
        </div>

        {/* ─────────────────────────── LOCAL DATA ───────────────────────────
            Three things this machine carries offline, and how current each is.

            They were three full-width cards, each about 400px tall for four to
            six short facts. The page has no width constraint, so on a 1920px
            display that is a slab nearly 1900px wide holding a two-character
            entry count, and the three together came to roughly 1,200px of mostly
            nothing. Constraining the content to a reading column — the first
            attempt — made it worse: the values lined up and the emptiness beside
            them became the obvious thing on the screen. The container was wrong.

            They are also one subject. "What does this rig hold, how old is it,
            and what can I do about it" is a single question, and a row answers it
            in the shape a wide viewport is actually good for.

            Every qualification the three cards carried is still here, under the
            row it belongs to. The rewrite was about the container; what each one
            is allowed to claim is unchanged. */}
        <div className="glass-card p-6 mb-6">
          <div className="flex items-center justify-between mb-2 border-b border-space-500/20 pb-3">
            <h3 className="text-xs font-semibold text-gray-300 text-tactical tracking-wider uppercase flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-neon-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M3 5v14a9 3 0 0 0 18 0V5" /><path d="M3 12a9 3 0 0 0 18 0" />
              </svg>
              Local Data
            </h3>
            <span className="text-[10px] font-mono text-gray-600">carried on this machine, used with no network</span>
          </div>

          {/* ── CVE snapshot ── */}
          <DataRow
            name="CVE intelligence"
            badge={cveInfo ? (cveInfo.age_days != null ? `${cveInfo.age_days} DAYS OLD` : 'AGE UNKNOWN') : null}
            tone={cveInfo?.stale ? 'warn' : cveInfo ? 'ok' : 'idle'}
            facts={!cveInfo ? (connected ? 'Reading provenance…' : 'Engine offline.') : (
              <>
                {cveInfo.entry_count} entries · {
                  /*
                    Three origins, not two. A downloaded snapshot is merged *over*
                    the seed rather than replacing it, so `snapshot+seed` is the
                    normal state after an update — testing only for 'snapshot'
                    reported that as "built-in seed" and hid the update entirely.
                  */
                  cveInfo.origin === 'snapshot+seed' ? 'snapshot + built-in seed'
                    : cveInfo.origin === 'snapshot' ? 'downloaded snapshot'
                      : 'built-in seed'
                }
                <span className="text-gray-600"> · generated {cveInfo.generated_at ? new Date(cveInfo.generated_at).toLocaleDateString() : 'unknown'}</span>
              </>
            )}
            action={
              <button
                onClick={() => {
                  setCveUpdating(true);
                  engineIPC.send('update_cve_db').catch(err => {
                    setCveUpdating(false);
                    setCveMessage(`Update could not start: ${err}`);
                  });
                }}
                disabled={!connected || cveUpdating}
                className="text-[10px] px-2 py-1 rounded bg-neon-600/20 text-neon-400 hover:bg-neon-600/40 border border-neon-500/30 font-tactical uppercase disabled:opacity-40"
              >
                {cveUpdating ? 'Updating…' : 'Update now'}
              </button>
            }
          >
            {cveInfo?.stale && (
              <RowCallout tone="warn">
                This data is older than {cveInfo.stale_after_days ?? 30} days. Findings still reflect
                real issues, but only ones known as of the date above. The report states this age so a
                reader can judge it — update before going out if you have a connection.
              </RowCallout>
            )}
            {cveInfo && <RowNote>{cveInfo.coverage_note}</RowNote>}
            {cveUpdateProgress && <p className="text-[10px] font-mono text-neon-400">{cveUpdateProgress}</p>}
            {cveMessage && <p className="text-[10px] font-mono text-gray-300">{cveMessage}</p>}
          </DataRow>

          {/* ── Offline basemap ── */}
          <DataRow
            name="Offline basemap"
            badge={basemapError ? 'UNREADABLE'
              : !basemap ? null
                : basemap.installed ? `${((basemap.size_bytes ?? 0) / 1048576).toFixed(0)} MB`
                  : 'NOT INSTALLED'}
            tone={basemapError ? 'bad' : basemap?.installed ? (basemapCoverageInfo ? 'ok' : 'warn') : 'idle'}
            facts={basemapError ? basemapError : !basemap ? 'Reading…' : (() => {
              if (!basemap.installed) return 'no archive — the offline map is a flat grid';
              if (!basemapCoverageInfo) return 'present, but its header did not parse';
              /*
                The bounds in words rather than in storage order. This printed
                `11.22, 43.75, 11.29, 43.79` — four bare floats with nothing
                saying which was which, for a figure whose only job is to answer
                "does this cover where I am working".
              */
              const box = describeBounds(basemapCoverageInfo.bounds);
              return (
                <>
                  z{basemapCoverageInfo.minZoom}–z{basemapCoverageInfo.maxZoom}
                  {box.extent && <> · {box.extent}</>}
                  <span className="text-gray-600"> · {box.lon}, {box.lat}</span>
                </>
              );
            })()}
            action={
              <button
                onClick={() => { void refreshBasemap(); }}
                className="text-[10px] px-2 py-1 rounded bg-space-800 text-gray-300 hover:bg-space-700 border border-space-500/30 font-tactical uppercase"
              >
                Re-check
              </button>
            }
          >
            {basemap && <RowNote title={basemap.path}><span className="break-all">{basemap.path}</span></RowNote>}
            {basemap?.installed && !basemapCoverageInfo && !basemapError && (
              <RowCallout tone="warn">
                A file is present but its header could not be read, so it is not being used. An archive
                whose header will not parse is worse than none — every tile request would fail — so the
                flat grid is shown instead. Check that the file is a PMTiles v3 archive and was copied whole.
              </RowCallout>
            )}
            {basemap && !basemap.installed && (
              <RowNote>
                Put a PMTiles v3 archive at the path above and press Re-check. An extract of the area you
                work in is a few megabytes; the whole planet is tens of gigabytes. See docs/INSTALL.md for
                how to produce one.
              </RowNote>
            )}
            {basemap?.installed && basemapCoverageInfo && (
              <RowNote>
                Used automatically whenever the remote basemap is unreachable. The area outside those
                bounds is drawn as plain background, which is the edge of the data rather than a map that
                failed to load.
              </RowNote>
            )}
          </DataRow>

          {/* ── Evidence register ── */}
          <DataRow
            name="Evidence register"
            badge={!evidenceSummary ? null
              : evidenceSummary.failed > 0 ? `${evidenceSummary.failed} FAILED`
                : evidenceSummary.total === 0 ? 'NO ARTIFACTS'
                  : evidenceSummary.neverChecked > 0 ? `${evidenceSummary.neverChecked} NEVER RE-CHECKED`
                    : `${evidenceSummary.total} VERIFIED`}
            tone={!evidenceSummary ? 'idle'
              : evidenceSummary.failed > 0 ? 'bad'
                : evidenceSummary.total === 0 ? 'idle'
                  : evidenceSummary.neverChecked > 0 ? 'warn' : 'ok'}
            facts={!evidenceSummary ? 'Reading…' : evidenceSummary.total === 0
              ? 'nothing recorded yet'
              : (
                <>
                  {evidenceSummary.total} artifact(s)
                  {evidenceSummary.unhashed > 0 && (
                    <span className="text-risk-high"> · {evidenceSummary.unhashed} with no digest</span>
                  )}
                </>
              )}
            action={
              <button
                onClick={runEvidenceVerification}
                disabled={!connected || evidenceVerifying}
                title={connected
                  ? 'Re-hash every artifact this installation has recorded and compare each against the digest stored when it was written.'
                  : 'The engine is not attached, so no file can be hashed.'}
                className="text-[10px] px-2 py-1 rounded bg-neon-600/20 text-neon-400 hover:bg-neon-600/40 border border-neon-500/30 font-tactical uppercase disabled:opacity-40"
              >
                {evidenceVerifying ? 'Verifying…' : 'Verify now'}
              </button>
            }
          >
            {evidenceMessage && (
              <p className="max-w-4xl text-[10px] font-mono text-risk-high leading-relaxed">{evidenceMessage}</p>
            )}

            {evidenceTally && (
              <>
                <p className="text-[10px] font-mono text-gray-400">
                  Last run: {evidenceTally.checked} checked
                  <span className="text-signal-strong"> · {evidenceTally.matched} matched</span>
                  {evidenceTally.mismatched > 0 && <span className="text-risk-critical"> · {evidenceTally.mismatched} mismatched</span>}
                  {evidenceTally.missing > 0 && <span className="text-risk-critical"> · {evidenceTally.missing} missing</span>}
                  {evidenceTally.unhashed > 0 && <span className="text-risk-high"> · {evidenceTally.unhashed} not hashed</span>}
                  {evidenceTally.failed > 0 && <span className="text-risk-high"> · {evidenceTally.failed} could not ask</span>}
                </p>

                {/* Each non-clean outcome says what it means for the document,
                    because the number on its own does not. */}
                {(evidenceTally.mismatched > 0 || evidenceTally.missing > 0) && (
                  <RowCallout tone="bad">
                    {evidenceTally.mismatched + evidenceTally.missing} artifact(s) no longer match the digest
                    recorded at capture, or could no longer be found. Any finding resting on them is
                    unsupported until they are recovered from a known-good copy. The exported report marks
                    these rows.
                  </RowCallout>
                )}
                {evidenceTally.unhashed > 0 && (
                  <RowCallout tone="warn">
                    {evidenceTally.unhashed} artifact(s) were recorded without a digest, so there is nothing
                    to compare them against. They were skipped rather than marked MISSING: a file that was
                    never hashed is not the same as a file that is gone.
                  </RowCallout>
                )}
                {evidenceTally.failed > 0 && (
                  <RowCallout tone="warn">
                    {evidenceTally.failed} artifact(s) could not be asked about at all — the engine did not
                    answer within the timeout. Those rows are left unchanged rather than cleared: an
                    artifact that was never checked must not be recorded as one that was.
                  </RowCallout>
                )}
              </>
            )}

            {!evidenceTally && !evidenceMessage && (
              <RowNote>
                Re-hashes every artifact this installation holds and compares it against the digest stored
                when it was written, then records the answer in the evidence register the report prints.
                Until this is run, the report can only state that an artifact was never re-checked.
              </RowNote>
            )}
          </DataRow>
        </div>

        {/* ─────────────────────────── ENGINE LOG ─────────────────────────── */}
        <div className="glass-card p-6 mb-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xs font-semibold text-gray-300 text-tactical tracking-wider uppercase flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></svg>
              Engine Log
            </h3>
            <button
              onClick={() => engineIPC.send('get_engine_log', { lines: 300 }).catch(console.error)}
              disabled={!connected}
              className="text-[10px] px-2 py-1 rounded bg-space-800 text-gray-300 hover:bg-space-700 border border-space-500/30 font-tactical uppercase disabled:opacity-40"
            >
              Load log
            </button>
          </div>
          {engineLog ? (
            <>
              <div className="text-[9px] font-mono text-gray-600 mb-2 break-all">{engineLog.path}</div>
              <div className="bg-space-950 border border-space-500/20 rounded p-3 max-h-64 overflow-y-auto font-mono text-[9px] leading-relaxed">
                {engineLog.lines.length === 0
                  ? <span className="text-gray-600">Log file is empty.</span>
                  : engineLog.lines.map((line, i) => (
                      <div key={i} className={
                        line.includes('CRITICAL') || line.includes('ERROR') ? 'text-risk-critical'
                          : line.includes('WARNING') ? 'text-risk-high'
                          : 'text-gray-400'
                      }>{line}</div>
                    ))}
              </div>
            </>
          ) : (
            <div className="text-xs font-mono text-gray-500">
              The engine now writes a rotating log file. Load it here when something went wrong in the
              field — previously failures left no artifact at all.
            </div>
          )}
        </div>

        {/* Live Diagnostics */}
        <div className="glass-card p-6 mb-6 border-l-2 border-l-neon-500">
          <h3 className="text-xs font-semibold text-neon-400 text-tactical tracking-wider mb-4 uppercase flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-neon-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
              Live System Diagnostics
            </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-3 bg-space-800/50 rounded border border-space-500/10">
              <div className="text-[10px] text-gray-500 font-mono mb-1">ENGINE UPLINK</div>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${connected ? 'bg-signal-strong' : 'bg-risk-critical animate-pulse'}`} />
                <span className={`text-sm font-mono ${connected ? 'text-white' : 'text-risk-critical'}`}>{connected ? 'ONLINE' : 'OFFLINE'}</span>
              </div>
            </div>

            <div className="p-3 bg-space-800/50 rounded border border-space-500/10">
              <div className="text-[10px] text-gray-500 font-mono mb-1">WI-FI ADAPTER</div>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${wifiReady ? 'bg-signal-strong' : 'bg-risk-high animate-pulse'}`} />
                <span className={`text-sm font-mono ${wifiReady ? 'text-white' : 'text-risk-high'}`}>{wifiReady ? 'READY' : 'SEARCHING'}</span>
              </div>
            </div>

            <div className="p-3 bg-space-800/50 rounded border border-space-500/10">
              <div className="text-[10px] text-gray-500 font-mono mb-1">SATELLITE FIX</div>
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${gpsLocked ? 'bg-signal-strong' : 'bg-gray-600'}`} />
                <span className="text-sm text-white font-mono">{gpsLocked ? 'LOCKED' : 'NO FIX'}</span>
              </div>
            </div>

            <div className="p-3 bg-space-800/50 rounded border border-space-500/10">
              <div className="text-[10px] text-gray-500 font-mono mb-1">FIRMWARE</div>
              <div className="flex items-center gap-2">
                <span className="text-sm text-gray-300 font-mono">v{APP_VERSION}</span>
              </div>
            </div>
          </div>

          {runtimeNotice && (
            <div className="mt-4 flex items-start justify-between gap-3 rounded border border-risk-high/40 bg-risk-high/10 p-3">
              <div className="text-[11px] font-mono text-risk-high leading-relaxed">{runtimeNotice}</div>
              <button onClick={() => setRuntimeNotice(null)} className="text-[9px] font-tactical text-gray-500 hover:text-gray-300 shrink-0">DISMISS</button>
            </div>
          )}
        </div>

        {/* Hardware Configuration */}
        <div className="glass-card p-6 mb-6">
          <h3 className="text-xs font-semibold text-gray-300 text-tactical tracking-wider mb-5 uppercase border-b border-space-500/20 pb-2 flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="4" y="4" width="16" height="16" rx="2" /><rect x="9" y="9" width="6" height="6" /><line x1="9" y1="1" x2="9" y2="4" /><line x1="15" y1="1" x2="15" y2="4" /><line x1="9" y1="20" x2="9" y2="23" /><line x1="15" y1="20" x2="15" y2="23" /><line x1="20" y1="9" x2="23" y2="9" /><line x1="20" y1="14" x2="23" y2="14" /><line x1="1" y1="9" x2="4" y2="9" /><line x1="1" y1="14" x2="4" y2="14" /></svg>
              Hardware Interfaces
            </h3>

          <div className="space-y-6">
            {/* Wi-Fi Adapter Selection */}
            <div>
              <label className="block text-xs text-neon-400 font-mono mb-2">TARGET NETWORK INTERFACE</label>
              <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                <div className="relative w-full sm:w-2/3">
                  <select
                    value={config.interfaceName || ''}
                    onChange={(e) => updateConfig({ interfaceName: e.target.value })}
                    className="appearance-none bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 pr-10 text-sm font-mono w-full focus:outline-none focus:border-space-500/50 transition-colors"
                  >
                    <option value="" disabled>Select Capture Interface...</option>
                    {wifiInterfaces.map(iface => (
                      <option key={iface} value={iface}>{iface}</option>
                    ))}
                    {wifiInterfaces.length === 0 && <option value="" disabled>No interfaces detected</option>}
                  </select>
                  <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-space-400">
                    <svg className="fill-current h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" /></svg>
                  </div>
                </div>
                <button
                  onClick={() => engineIPC.send('get_interfaces').catch(console.error)}
                  className="px-3 py-2 text-xs font-tactical text-gray-400 border border-space-500/20 rounded hover:bg-space-800 hover:text-white transition-colors"
                >
                  SCAN PORTS
                </button>
              </div>
              <p className="text-[10px] text-gray-500 font-mono mt-1.5">Select the physical Wi-Fi card used for managed packet injection/discovery.</p>
            </div>

            {/* GPS COM Port */}
            <div>
              <label className="block text-xs text-neon-400 font-mono mb-2">NMEA GPS RECEIVER (COM PORT)</label>
              <div className="flex flex-col sm:flex-row sm:items-center gap-3">
                <div className="relative w-full sm:w-2/3">
                  <select
                    value={config.comPort}
                    onChange={(e) => updateConfig({ comPort: e.target.value })}
                    className="appearance-none bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 pr-10 text-sm font-mono w-full focus:outline-none focus:border-space-500/50 transition-colors"
                  >
                    <option value="COM3" disabled>Select Serial Port...</option>
                    {comPorts.map(port => (
                      <option key={port.device} value={port.device}>{port.device} - {port.description}</option>
                    ))}
                    {comPorts.length === 0 && <option value={config.comPort}>{config.comPort} (Manual Entry)</option>}
                  </select>
                  <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-space-400">
                    <svg className="fill-current h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" /></svg>
                  </div>
                </div>

                <div className="relative w-full sm:w-1/3">
                  <select
                    value={config.baudRate || 9600}
                    onChange={(e) => updateConfig({ baudRate: parseInt(e.target.value, 10) })}
                    className="appearance-none bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 pr-10 text-sm font-mono w-full focus:outline-none focus:border-space-500/50 transition-colors"
                  >
                    <option value={4800}>4800 bps</option>
                    <option value={9600}>9600 bps</option>
                    <option value={19200}>19200 bps</option>
                    <option value={38400}>38400 bps</option>
                    <option value={57600}>57600 bps</option>
                    <option value={115200}>115200 bps</option>
                  </select>
                  <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-space-400">
                    <svg className="fill-current h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" /></svg>
                  </div>
                </div>
              </div>
              <p className="text-[10px] text-gray-500 font-mono mt-1.5 mb-3">Specify active serial port for GPS tracking data (Click SCAN PORTS above to detect).</p>

              {/* Test Hardware Button & Terminal */}
              <div className="mt-4">
                <button
                  onClick={handleTestHardware}
                  disabled={isTesting}
                  className={`px-4 py-2 text-xs font-tactical tracking-widest border rounded transition-all flex items-center gap-2 ${isTesting ? 'bg-space-800 border-space-500/30 text-gray-400 cursor-not-allowed' : 'bg-space-800/80 border-neon-500/50 text-neon-400 hover:bg-neon-900/30 hover:border-neon-400'}`}
                >
                  {isTesting ? (
                    <><div className="w-2 h-2 rounded-full bg-neon-500 animate-pulse" /> TESTING DIAGNOSTICS...</>
                  ) : (
                    <><svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" /></svg> TEST HARDWARE</>
                  )}
                </button>

                <AnimatePresence>
                  {(isTesting || diagnosticLogs.length > 0) && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      exit={{ opacity: 0, height: 0 }}
                      className="mt-3 bg-black/60 border border-space-500/30 rounded p-3 h-48 overflow-y-auto font-mono text-[10px] text-gray-300 relative"
                    >
                      {diagnosticLogs.map((log, i) => (
                        <div key={i} className={`${log.includes('SUCCESS') ? 'text-signal-strong' : log.includes('ERROR') || log.includes('WARNING') ? 'text-risk-high' : log.includes('RAW') ? 'text-space-400' : 'text-neon-400'} mb-1`}>
                          {log}
                        </div>
                      ))}
                      <div ref={logEndRef} />
                      {isTesting && (
                        <div className="text-gray-500 animate-pulse mt-2 flex items-center gap-2">
                          <div className="w-1.5 h-1.5 rounded-full bg-neon-500" /> Awaiting sensor data...
                        </div>
                      )}
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </div>

            {/* Simulation Mode Toggle */}
            <div className="flex items-center justify-between pt-4 border-t border-space-500/10">
              <div>
                <label className="block text-sm text-gray-200 font-medium font-tactical tracking-wide">SIMULATION OVERRIDE</label>
                <span className="text-[10px] text-gray-500 font-mono">Drive a scenario instead of the radio: {simulation ? simulation.ap_count : 11} access points along a route, so a report can be rehearsed before the field.</span>
              </div>
              <button
                onClick={() => updateConfig({ emulateHardware: !config.emulateHardware })}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none border border-space-500/20 ${config.emulateHardware ? 'bg-neon-600 border-neon-500' : 'bg-space-800'}`}
              >
                <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${config.emulateHardware ? 'translate-x-6' : 'translate-x-1'}`} />
              </button>
            </div>

            {/*
              What the running scenario actually contains. Shown so the operator
              knows what to expect in the rehearsal report — and so a scenario
              that lost its turn is visible rather than silently degrading the
              localization they are reviewing.
            */}
            {simulation && (
              <div className="mt-3 p-3 rounded border border-amber-500/40 bg-amber-500/5">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-tactical tracking-widest text-amber-400">
                    SIMULATED SURVEY RUNNING — NOT FIELD EVIDENCE
                  </span>
                  <span className="text-[9px] font-mono text-gray-500">
                    {Math.round(simulation.route_length_m)} m @ {simulation.speed_kmh} km/h
                    {simulation.route_has_turn
                      ? ' · route turns'
                      : ' · STRAIGHT ROUTE: sides of the road are ambiguous'}
                  </span>
                </div>
                <div className="max-h-40 overflow-y-auto no-scrollbar space-y-1">
                  {simulation.aps.map(ap => (
                    <div key={ap.bssid} className="flex items-baseline gap-2 text-[9px] font-mono">
                      <span className="text-gray-500 w-[132px] shrink-0">{ap.bssid}</span>
                      <span className="text-gray-300 w-[112px] shrink-0 truncate">{ap.ssid || '<hidden>'}</span>
                      <span className={`w-[42px] shrink-0 ${ap.encryption === 'OPEN' || ap.encryption === 'WEP' ? 'text-risk-critical' : 'text-gray-400'}`}>
                        {ap.encryption}
                      </span>
                      <span className="text-gray-600 truncate">{ap.note}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Visual Preferences */}
        <div className="glass-card p-6 mb-6">
          <h3 className="text-xs font-semibold text-gray-300 text-tactical tracking-wider mb-5 uppercase border-b border-space-500/20 pb-2 flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="13.5" cy="6.5" r=".5" /><circle cx="17.5" cy="10.5" r=".5" /><circle cx="8.5" cy="7.5" r=".5" /><circle cx="6.5" cy="12.5" r=".5" /><path d="M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10c.926 0 1.648-.746 1.648-1.688 0-.437-.18-.835-.437-1.125-.29-.289-.438-.652-.438-1.125a1.64 1.64 0 0 1 1.668-1.668h1.996c3.051 0 5.555-2.503 5.555-5.554C21.965 6.012 17.461 2 12 2z" /></svg>
              Visual Preferences
            </h3>

          <div>
            <label className="block text-xs text-neon-400 font-mono mb-3">EGO VEHICLE (MAP AVATAR)</label>
            <div className="flex gap-4 overflow-x-auto no-scrollbar pb-2">
              {VEHICLES.map(v => (
                <button
                  key={v.id}
                  onClick={() => setEgoVehicle(v.id)}
                  className={`flex flex-col items-center flex-shrink-0 p-3 w-32 rounded border transition-all ${egoVehicle === v.id ? 'bg-space-800 border-neon-500' : 'bg-space-900 border-space-500/30 hover:bg-space-800/80 hover:border-space-500/50'}`}
                >
                  <div className="w-12 h-12 bg-space-950 rounded mb-3 border border-space-500/10 flex items-center justify-center p-2">
                    <img
                      src={`/cars/${v.id}`}
                      alt={v.name}
                      onError={(e) => {
                        // Fallback placeholder logic
                        (e.target as HTMLImageElement).src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2"><path d="M5 21l3-11h8l3 11M3 21h18M12 10v11"/></svg>';
                      }}
                      className="w-full h-full object-contain"
                      style={{ filter: egoVehicle === v.id ? 'none' : 'grayscale(100%) opacity(40%)' }}
                    />
                  </div>
                  <span className={`text-[10px] font-tactical tracking-wider break-words text-center ${egoVehicle === v.id ? 'text-neon-400' : 'text-gray-500'}`}>{v.name}</span>
                </button>
              ))}
            </div>
            <p className="text-[10px] text-gray-500 font-mono mt-2">Select the tactical indicator shown on the war-driving map.</p>
          </div>
        </div>

        {/* Geospatial & Map Configuration */}
        <div className="glass-card p-6 mb-6 border-l-2 border-l-neon-500">
          <h3 className="text-xs font-semibold text-gray-300 text-tactical tracking-wider mb-5 uppercase border-b border-space-500/20 pb-2 flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z" /><circle cx="12" cy="10" r="3" /></svg>
              Geospatial Configuration
            </h3>

          <div className="space-y-6">
            {/* Map Style */}
            <div>
              <label className="block text-xs text-neon-400 font-mono mb-3">TACTICAL MAP STYLE</label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <button
                  onClick={() => updateConfig({ mapStyle: 'DARK' })}
                  className={`relative p-4 rounded border text-left transition-all duration-300 overflow-hidden group ${config.mapStyle === 'DARK' ? 'bg-space-800 border-neon-500' : 'bg-space-900 border-space-500/30 hover:border-space-500/60 hover:-translate-y-1'}`}
                >
                  {/* Active Indicator */}
                  {config.mapStyle === 'DARK' && (
                    <div className="absolute top-3 right-3 flex items-center gap-1.5 z-20">
                      <div className="w-1.5 h-1.5 rounded-full bg-neon-400 animate-pulse" />
                      <span className="text-[9px] font-tactical text-neon-400 tracking-widest">ACTIVE</span>
                    </div>
                  )}

                  <div className="relative z-10 flex items-center gap-3 mb-2">
                    <svg xmlns="http://www.w3.org/2000/svg" className={`w-5 h-5 ${config.mapStyle === 'DARK' ? 'text-neon-400' : 'text-gray-400'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                    <div className={`text-sm font-tactical tracking-wider ${config.mapStyle === 'DARK' ? 'text-white' : 'text-gray-300'}`}>DARK MATTER</div>
                  </div>
                  <div className="relative z-10 text-[10px] text-gray-500 font-mono">High-contrast tactical dark mode. Optimal for night ops and low-light field conditions.</div>
                </button>

                <button
                  onClick={() => updateConfig({ mapStyle: 'SATELLITE', enable3DBuildings: false })}
                  className={`relative p-4 rounded border text-left transition-all duration-300 overflow-hidden group ${config.mapStyle === 'SATELLITE' ? 'bg-space-800 border-neon-500' : 'bg-space-900 border-space-500/30 hover:border-space-500/60 hover:-translate-y-1'}`}
                >
                  {/* Active Indicator */}
                  {config.mapStyle === 'SATELLITE' && (
                    <div className="absolute top-3 right-3 flex items-center gap-1.5 z-20">
                      <div className="w-1.5 h-1.5 rounded-full bg-neon-400 animate-pulse" />
                      <span className="text-[9px] font-tactical text-neon-400 tracking-widest">ACTIVE</span>
                    </div>
                  )}

                  <div className="relative z-10 flex items-center gap-3 mb-2">
                    <svg xmlns="http://www.w3.org/2000/svg" className={`w-5 h-5 ${config.mapStyle === 'SATELLITE' ? 'text-neon-400' : 'text-gray-400'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><line x1="2" y1="12" x2="22" y2="12" /><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" /></svg>
                    <div className={`text-sm font-tactical tracking-wider ${config.mapStyle === 'SATELLITE' ? 'text-white' : 'text-gray-300'}`}>ORBITAL IMAGERY</div>
                  </div>
                  <div className="relative z-10 text-[10px] text-gray-500 font-mono">High-resolution satellite view. Essential for physical target recon and structure identification.</div>
                </button>
              </div>

              {/* Live Preview Pane */}
              <div className="mt-4 rounded border border-space-500/30 overflow-hidden bg-space-950 relative">
                <img
                  src={`/geo/${config.mapStyle === 'SATELLITE' ? 'obital_imagery.svg' : (config.enable3DBuildings ? 'dark_matter-3D.svg' : 'dark_matter.svg')}`}
                  alt="Map Preview"
                  className="w-full h-auto object-contain transition-opacity duration-500"
                />
                <div className="absolute top-2 left-2 px-2 py-1 bg-space-900/80 backdrop-blur text-[9px] font-tactical text-gray-400 rounded tracking-widest border border-space-500/20">
                  LIVE PREVIEW
                </div>
              </div>

              <div className="mt-5 flex items-start gap-2 text-space-400 px-1">
                <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5 mt-0.5 shrink-0 text-neon-500/70" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>
                <div className="text-[10px] font-mono leading-relaxed">
                  <span className="text-neon-400 font-tactical mr-1">ENGINE OPTIMIZATION NOTE:</span>
                  This preview is a visual representation. The active MapLibre rendering engine employs custom tile pruning, dynamic label filtering, and texture optimization to ensure maximum WebGL performance and UI responsiveness during operations.
                </div>
              </div>
            </div>

            {/* Map Toggles */}
            <div className="flex flex-col gap-5 pt-6 border-t border-space-500/10">
              <div className={`flex items-center justify-between group transition-opacity ${config.mapStyle === 'SATELLITE' ? 'opacity-50 pointer-events-none' : ''}`}>
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded mt-0.5 transition-colors ${config.enable3DBuildings ? 'bg-neon-500/20 text-neon-400' : 'bg-space-800 text-gray-500 group-hover:text-gray-400'}`}>
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                  </div>
                  <div>
                    <label className={`block text-sm font-medium font-tactical tracking-wide transition-colors ${config.enable3DBuildings ? 'text-white' : 'text-gray-400'}`}>3D TERRAIN & BUILDINGS</label>
                    <span className="text-[10px] text-gray-500 font-mono">
                      {config.mapStyle === 'SATELLITE' ? 'Not available in Orbital Imagery mode.' : 'Extrude 3D building geometry when zooming in.'}
                    </span>
                  </div>
                </div>

                {/* Tactical Segmented Switch */}
                <button
                  disabled={config.mapStyle === 'SATELLITE'}
                  onClick={() => updateConfig({ enable3DBuildings: !config.enable3DBuildings })}
                  className="flex rounded overflow-hidden border border-space-500/30 text-[10px] font-tactical tracking-widest shrink-0"
                >
                  <div className={`px-4 py-1.5 transition-colors ${!config.enable3DBuildings ? 'bg-space-700 text-gray-300' : 'bg-space-900 text-gray-600 hover:text-gray-400'}`}>OFF</div>
                  <div className={`px-4 py-1.5 transition-all ${config.enable3DBuildings ? 'bg-neon-600 text-space-950' : 'bg-space-900 text-gray-600 hover:text-gray-400'}`}>ON</div>
                </button>
              </div>

              <div className="flex items-center justify-between group">
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded mt-0.5 transition-colors ${config.enableHeatmap ? 'bg-risk-high/20 text-risk-high' : 'bg-space-800 text-gray-500 group-hover:text-gray-400'}`}>
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.38-.5-2-1-3-1.072-2.143-.224-4.054 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.153.433-2.294 1-3a2.5 2.5 0 0 0 2.5 2.5z"></path></svg>
                  </div>
                  <div>
                    <label className={`block text-sm font-medium font-tactical tracking-wide transition-colors ${config.enableHeatmap ? 'text-white' : 'text-gray-400'}`}>HEATMAP RENDERER</label>
                    <span className="text-[10px] text-gray-500 font-mono">Density of <span className="text-gray-400">estimated transmitter positions</span>, shaded by their latest reading — not signal measured along the route. Shrinks the markers and hides the uncertainty rings beneath it.</span>
                  </div>
                </div>

                {/* Tactical Segmented Switch */}
                <button
                  onClick={() => updateConfig({ enableHeatmap: !config.enableHeatmap })}
                  className="flex rounded overflow-hidden border border-space-500/30 text-[10px] font-tactical tracking-widest shrink-0"
                >
                  <div className={`px-4 py-1.5 transition-colors ${!config.enableHeatmap ? 'bg-space-700 text-gray-300' : 'bg-space-900 text-gray-600 hover:text-gray-400'}`}>OFF</div>
                  <div className={`px-4 py-1.5 transition-all ${config.enableHeatmap ? 'bg-risk-high text-space-950' : 'bg-space-900 text-gray-600 hover:text-gray-400'}`}>ON</div>
                </button>
              </div>

              {/* Auto-Attack Chain Toggle */}
              <div className="flex items-center justify-between group pt-5 border-t border-space-500/10">
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded mt-0.5 transition-colors ${config.enableAutoAttack ? 'bg-risk-critical/20 text-risk-critical animate-pulse' : 'bg-space-800 text-gray-500 group-hover:text-gray-400'}`}>
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 1v6M12 17v6M4.22 4.22l4.24 4.24M15.54 15.54l4.24 4.24M1 12h6M17 12h6M4.22 19.78l4.24-4.24M15.54 8.46l4.24-4.24"/></svg>
                  </div>
                  <div>
                    <label className={`block text-sm font-medium font-tactical tracking-wide transition-colors ${config.enableAutoAttack ? 'text-risk-critical' : 'text-gray-400'}`}>AUTO-ATTACK CHAIN</label>
                    <span className="text-[10px] text-gray-500 font-mono">
                      {config.enableAutoAttack
                        ? '⚡ ARMED — Auto PMKID capture on WPA/WPA2 targets with RSSI ≥ -75 dBm'
                        : 'Automatically chain WPS scan → PMKID capture → Hashcat export on discovered targets.'
                      }
                    </span>
                  </div>
                </div>

                <button
                  onClick={() => {
                    const newVal = !config.enableAutoAttack;
                    updateConfig({ enableAutoAttack: newVal });
                    engineIPC.send('set_auto_attack', { enabled: newVal }).catch(console.error);
                  }}
                  className="flex rounded overflow-hidden border border-space-500/30 text-[10px] font-tactical tracking-widest shrink-0"
                >
                  <div className={`px-4 py-1.5 transition-colors ${!config.enableAutoAttack ? 'bg-space-700 text-gray-300' : 'bg-space-900 text-gray-600 hover:text-gray-400'}`}>SAFE</div>
                  <div className={`px-4 py-1.5 transition-all ${config.enableAutoAttack ? 'bg-risk-critical text-white' : 'bg-space-900 text-gray-600 hover:text-gray-400'}`}>ARMED</div>
                </button>
              </div>

              {/*
                Clear the chain's memory of what it has already tried.

                `auto_attack.reset()` clears `_attacked_bssids`, the set the chain
                filters against so it does not re-attack a target it has already
                attempted. `reset_auto_attack` has been in the engine's command
                table and in `EngineCommand` the whole time with nothing able to
                send it, so the only way to retry a target was to restart the
                engine -- which is a real operational dead end, because the usual
                reason to retry is that the first attempt was made from a worse
                position and the operator has since moved.

                Offered whether the chain is armed or not: the history outlives a
                disarm, so clearing it while safe is the careful order to do it in.
                It arms nothing by itself, which is why it is a quiet control and
                not a red one.
              */}
              <div className="flex items-center justify-between pt-4">
                <span className="text-[10px] text-gray-500 font-mono leading-relaxed max-w-[70%]">
                  The chain skips targets it has already attempted. Clearing that history lets it try
                  them again &mdash; useful after moving to a position with better signal, and nothing
                  else about it changes.
                </span>
                <button
                  onClick={() => {
                    engineIPC.send('reset_auto_attack')
                      .then(() => setRuntimeNotice('AUTO-ATTACK TARGET HISTORY CLEARED — previously attempted targets are eligible again.'))
                      .catch(e => setRuntimeNotice(`COULD NOT CLEAR TARGET HISTORY — ${errText(e)}. The chain will still skip what it has already tried.`));
                  }}
                  disabled={!connected}
                  title={connected
                    ? 'Clears the set of BSSIDs the auto-attack chain has already attempted, so they become eligible again.'
                    : 'The engine is not attached, so there is nothing holding the history to clear.'}
                  className="text-[10px] px-2 py-1 rounded bg-space-800 text-gray-300 hover:bg-space-700 border border-space-500/30 font-tactical uppercase tracking-wider disabled:opacity-40 shrink-0"
                >
                  Clear target history
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* RF Tuning */}
        <div className="glass-card p-6 mb-6">
          <h3 className="text-xs font-semibold text-gray-300 text-tactical tracking-wider mb-5 uppercase border-b border-space-500/20 pb-2 flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="4" y1="21" x2="4" y2="14" /><line x1="4" y1="10" x2="4" y2="3" /><line x1="12" y1="21" x2="12" y2="12" /><line x1="12" y1="8" x2="12" y2="3" /><line x1="20" y1="21" x2="20" y2="16" /><line x1="20" y1="12" x2="20" y2="3" /><line x1="1" y1="14" x2="7" y2="14" /><line x1="9" y1="8" x2="15" y2="8" /><line x1="17" y1="16" x2="23" y2="16" /></svg>
              RF Tuning
            </h3>

          <div>
            <div className="flex justify-between items-end mb-2">
              <label className="block text-xs text-neon-400 font-mono">SCAN INTERVAL LATENCY</label>
              <span className="text-xs font-mono text-white bg-space-800 px-2 py-0.5 rounded border border-space-500/20">
                {config.scanInterval.toFixed(1)}s
              </span>
            </div>
            <input
              type="range"
              min="1.0" max="10.0" step="0.5"
              value={config.scanInterval}
              onChange={(e) => updateConfig({ scanInterval: parseFloat(e.target.value) })}
              className="w-full accent-neon-500 h-1.5 bg-space-800 rounded-lg appearance-none cursor-pointer"
            />
            <div className="flex justify-between text-[10px] text-gray-600 font-mono mt-1.5">
              <span>More Aggressive (1s)</span>
              <span>More Stealthy (10s)</span>
            </div>
          </div>

          {/* AP Location Method */}
          <div className="pt-5 border-t border-space-500/10">
            <label className="block text-xs text-neon-400 font-mono mb-3">AP LOCATION METHOD</label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <button
                onClick={() => updateConfig({ locationMethod: 'bayesian_grid' })}
                className={`p-4 rounded border text-left transition-all relative overflow-hidden ${config.locationMethod === 'bayesian_grid'
                  ? 'bg-space-800 border-risk-high'
                  : 'bg-space-900 border-space-500/30 hover:border-space-500/50'
                  }`}
              >
                <div className="absolute top-0 right-0 px-2 py-0.5 bg-signal-strong/20 text-[8px] font-tactical text-signal-strong border-b border-l border-signal-strong/50 rounded-bl tracking-wider">RECOMMENDED</div>
                <div className="flex items-center gap-2 mb-2">
                  <div className={`w-2 h-2 rounded-full ${config.locationMethod === 'bayesian_grid' ? 'bg-risk-high animate-pulse' : 'bg-gray-600'}`} />
                  <span className={`text-xs font-tactical tracking-wider ${config.locationMethod === 'bayesian_grid' ? 'text-risk-high' : 'text-gray-400'}`}>LIKELIHOOD GRID</span>
                </div>
                <p className="text-[10px] text-gray-500 font-mono leading-relaxed">
                  Searches a grid for the position that best explains every RSSI reading, so it can place a transmitter <span className="text-gray-300">off</span> the surveyed path. Most accurate of the three on every route measured, and the only one that still works from a single straight pass. Reports an error radius in metres, and flags a mirrored candidate when the route cannot rule one out.
                </p>
              </button>

              <button
                onClick={() => updateConfig({ locationMethod: 'weighted_centroid' })}
                className={`p-4 rounded border text-left transition-all ${config.locationMethod === 'weighted_centroid'
                  ? 'bg-space-800 border-signal-strong'
                  : 'bg-space-900 border-space-500/30 hover:border-space-500/50'
                  }`}
              >
                <div className="flex items-center gap-2 mb-2">
                  <div className={`w-2 h-2 rounded-full ${config.locationMethod === 'weighted_centroid' ? 'bg-signal-strong' : 'bg-gray-600'}`} />
                  <span className={`text-xs font-tactical tracking-wider ${config.locationMethod === 'weighted_centroid' ? 'text-signal-strong' : 'text-gray-400'}`}>TRACK POSITION</span>
                </div>
                <p className="text-[10px] text-gray-500 font-mono leading-relaxed">
                  Average of the sighting positions, weighted by <span className="text-gray-300">inverse modelled range</span>. The result is a blend of points you drove through, so it <span className="text-gray-300">cannot leave the path</span> — measured off-track displacement is 0 m. It states <span className="text-gray-300">no uncertainty radius and no second candidate</span>, so the map will say so for every access point while this is selected. Use it as a sanity baseline, not as a transmitter fix.
                </p>
              </button>

              <button
                onClick={() => updateConfig({ locationMethod: 'trilateration' })}
                className={`p-4 rounded border text-left transition-all ${config.locationMethod === 'trilateration'
                  ? 'bg-space-800 border-[#ff00ff]'
                  : 'bg-space-900 border-space-500/30 hover:border-space-500/50'
                  }`}
              >
                <div className="flex items-center gap-2 mb-2">
                  <div className={`w-2 h-2 rounded-full ${config.locationMethod === 'trilateration' ? 'bg-[#ff00ff]' : 'bg-gray-600'}`} />
                  <span className={`text-xs font-tactical tracking-wider ${config.locationMethod === 'trilateration' ? 'text-[#ff00ff]' : 'text-gray-400'}`}>MULTILATERATION</span>
                </div>
                <p className="text-[10px] text-gray-500 font-mono leading-relaxed">
                  Least-squares fit of the ranges implied by the path loss model, solved to convergence. Can leave the path, but it is the hungriest option: it needs more sightings than the others and a route with real shape before it beats the grid. Reports an error radius, and on a straight pass <span className="text-gray-300">both candidate positions and the distance between them</span> — the radius is widened to reach the second one, so expect a large number there rather than a tight one.
                </p>
              </button>
            </div>

            {/*
              The selected method, demonstrated rather than described. It runs
              the real estimator over a synthetic drive, so the panel cannot
              drift away from the code the way a drawn illustration would.
            */}
            <LocalizationPreview method={config.locationMethod} />

            {/* Survey geometry: what the route shape does to the answer. */}
            <div className="mt-5 p-4 rounded border border-space-500/30 bg-space-900/60">
              <div className="flex items-center gap-2 mb-2">
                <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5 text-neon-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 18 9 6l6 12 6-12" /></svg>
                <span className="text-xs font-tactical tracking-wider text-neon-400">SURVEY GEOMETRY</span>
              </div>

              <p className="text-[10px] text-gray-500 font-mono leading-relaxed mb-3">
                With every sighting on one straight line, the fit is symmetric about that line: an AP 40 m left and an AP 40 m right explain the measurements equally well, and <span className="text-gray-300">no algorithm can tell which side it is on</span>. Driving the same street again makes it worse, not better — a second pass only reinforces the symmetry. One turn resolves it.
              </p>

              <div className="border border-space-500/20 rounded overflow-hidden mb-3">
                <div className="grid grid-cols-[1fr_auto_auto] gap-x-4 px-3 py-1.5 bg-space-800/70 text-[9px] font-tactical tracking-wider text-gray-500">
                  <span>ROUTE DRIVEN</span>
                  <span className="text-right">MEDIAN ERR</span>
                  <span className="text-right">WRONG SIDE</span>
                </div>
                {GEOMETRY_TRIALS.map(trial => (
                  <div
                    key={trial.route}
                    className="grid grid-cols-[1fr_auto_auto] gap-x-4 px-3 py-1.5 text-[10px] font-mono border-t border-space-500/10"
                  >
                    <span className={trial.good ? 'text-gray-300' : 'text-gray-500'}>{trial.route}</span>
                    <span className="text-right text-gray-400">{trial.error}</span>
                    <span className={`text-right ${trial.good ? 'text-signal-strong' : 'text-risk-high'}`}>{trial.wrongSide}</span>
                  </div>
                ))}
              </div>

              <p className="text-[10px] text-gray-500 font-mono leading-relaxed mb-3">
                <span className="text-gray-300 font-tactical tracking-wider mr-2">SO:</span>
                Turn a corner, run a parallel street, or loop the block. Any leg that leaves the line is worth more than another pass along it. Figures are from a simulated AP 40 m off a 300 m road, five noise seeds per route.
              </p>

              {/* Live read on the current route, from the recorded GPS path. */}
              <div className="pt-3 border-t border-space-500/10 flex gap-2 items-start">
                <div className={`w-2 h-2 rounded-full shrink-0 mt-1 ${!routeGeometry ? 'bg-gray-600' : routeGeometry.mirrorAmbiguous ? 'bg-risk-high' : 'bg-signal-strong'}`} />
                <p className="text-[10px] font-mono leading-relaxed">
                  <span className={`font-tactical tracking-wider mr-2 ${!routeGeometry ? 'text-gray-500' : routeGeometry.mirrorAmbiguous ? 'text-risk-high' : 'text-signal-strong'}`}>
                    {/*
                      Three states, not two. "Parked" and "drove in a straight
                      line" are both ambiguous but need opposite advice, and the
                      old two-state version showed a stationary rig's GPS
                      scatter as CURRENT ROUTE: SHAPED — a near-circular blob
                      scores a perfect cross/along ratio.
                    */}
                    {!routeGeometry
                      ? 'CURRENT ROUTE: NO DATA'
                      : routeGeometry.insufficientBaseline
                        ? 'CURRENT ROUTE: STATIONARY'
                        : routeGeometry.mirrorAmbiguous
                          ? 'CURRENT ROUTE: STILL A LINE'
                          : 'CURRENT ROUTE: SHAPED'}
                  </span>
                  <span className="text-gray-500">
                    {!routeGeometry
                      ? 'Not enough recorded GPS path yet to assess the survey geometry.'
                      : routeGeometry.note}
                  </span>
                </p>
              </div>
            </div>

            <div className="mt-5 pt-4 border-t border-space-500/10 flex gap-3 items-start">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5 text-gray-500 shrink-0 mt-0.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><path d="M12 16v-4" /><path d="M12 8h.01" /></svg>
              <p className="text-[10px] text-gray-500 font-mono leading-relaxed">
                <span className="text-gray-300 font-tactical tracking-wider mr-2">ARCHIVE POST-PROCESSING:</span>
                The method above runs live during a sweep on a capped set of sighting points. Archiving a mission re-runs it without that cap, and additionally fits a <strong className="text-gray-400 font-normal">Gaussian Process Regression</strong> surface over the recorded signal field. GPR smooths the measurements and returns the peak of that smoothed field — so its answer lies on or near the path you drove, by construction. Read it as a de-noised "where was the signal strongest", not as a transmitter fix. It now reports an error radius in metres alongside the position.
              </p>
            </div>
          </div>
        </div>

        {/* Antenna Benchmark */}
        <div className="glass-card p-6 mb-6 border-l-2 border-l-signal-strong">
          <div className="flex items-center justify-between mb-5 border-b border-space-500/20 pb-2">
            <h3 className="text-xs font-semibold text-gray-300 text-tactical tracking-wider uppercase flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-signal-strong" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 20h.01" /><path d="M7 20v-4" /><path d="M12 20v-8" /><path d="M17 20V8" /><path d="M22 4v16" /></svg>
              Antenna Benchmark
            </h3>
            {benchmarkHistory.length > 0 && (
              <button
                onClick={() => setBenchmarkExpanded(!benchmarkExpanded)}
                className="text-[10px] font-tactical text-gray-500 hover:text-gray-300 transition-colors flex items-center gap-1"
              >
                {benchmarkExpanded ? 'COLLAPSE' : `VIEW HISTORY (${benchmarkHistory.length})`}
                <svg xmlns="http://www.w3.org/2000/svg" className={`w-3 h-3 transition-transform ${benchmarkExpanded ? 'rotate-180' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9" /></svg>
              </button>
            )}
          </div>

          <p className="text-[10px] text-gray-500 font-mono mb-4">Run a full Wi-Fi environment scan to measure your adapter's reception capability. Compare results across different antennas and cards.</p>

          {/* Run Controls */}
          <div className="space-y-3 mb-5">
            {/* Interface Selector */}
            <div>
              <label className="block text-[10px] text-gray-500 font-mono mb-1.5">BENCHMARK INTERFACE</label>
              <div className="relative">
                <select
                  value={benchmarkInterface || config.interfaceName || ''}
                  onChange={(e) => setBenchmarkInterface(e.target.value)}
                  className="appearance-none bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 pr-10 text-sm font-mono w-full focus:outline-none focus:border-space-500/50 transition-colors"
                >
                  {wifiInterfaces.map(iface => (
                    <option key={iface} value={iface}>{iface}</option>
                  ))}
                  {wifiInterfaces.length === 0 && <option value="" disabled>No interfaces detected — click SCAN PORTS above</option>}
                </select>
                <div className="pointer-events-none absolute inset-y-0 right-0 flex items-center px-2 text-space-400">
                  <svg className="fill-current h-4 w-4" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20"><path d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" /></svg>
                </div>
              </div>
              <p className="text-[10px] text-gray-600 font-mono mt-1">Select the Wi-Fi adapter to benchmark. You can test with your built-in card or an external antenna.</p>
            </div>

            {/* Label + Notes */}
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                type="text"
                value={benchmarkLabel}
                onChange={(e) => setBenchmarkLabel(e.target.value)}
                placeholder="Label (e.g. TP-Link 722N, Stock Antenna)"
                className="flex-1 bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 text-sm font-mono placeholder-gray-600 focus:outline-none focus:border-space-500/50 transition-colors"
              />
              <input
                type="text"
                value={benchmarkNotes}
                onChange={(e) => setBenchmarkNotes(e.target.value)}
                placeholder="Notes (e.g. 3rd floor, outdoor, rainy)"
                className="flex-1 bg-space-900 border border-space-500/30 text-white rounded px-3 py-2 text-sm font-mono placeholder-gray-600 focus:outline-none focus:border-space-500/50 transition-colors"
              />
            </div>

            {/* Run Button + Live Progress */}
            <div className="flex items-center gap-3">
              <button
                onClick={handleRunBenchmark}
                disabled={isBenchmarking || (!benchmarkInterface && !config.interfaceName)}
                className={`px-5 py-2 text-xs font-tactical tracking-widest border rounded transition-all flex items-center gap-2 shrink-0 ${isBenchmarking
                  ? 'bg-space-800 border-space-500/30 text-gray-400 cursor-not-allowed'
                  : (!benchmarkInterface && !config.interfaceName)
                    ? 'bg-space-800 border-space-500/20 text-gray-600 cursor-not-allowed'
                    : 'bg-signal-strong/10 border-signal-strong/50 text-signal-strong hover:bg-signal-strong/20'
                  }`}
              >
                {isBenchmarking ? (
                  <><div className="w-2 h-2 rounded-full bg-signal-strong animate-pulse" /> SCANNING AIRSPACE...</>
                ) : (
                  <><svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M2 20h.01" /><path d="M7 20v-4" /><path d="M12 20v-8" /><path d="M17 20V8" /><path d="M22 4v16" /></svg> RUN BENCHMARK</>
                )}
              </button>
              {isBenchmarking && (
                <div className="flex items-center gap-2 text-sm font-mono text-signal-strong">
                  <div className="w-1.5 h-1.5 rounded-full bg-signal-strong animate-pulse" />
                  {benchmarkProgress} APs found
                </div>
              )}
            </div>
          </div>

          {/* Last Result Card */}
          <AnimatePresence>
            {lastBenchmark && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="bg-space-950/50 border border-signal-strong/30 rounded-lg p-5 mb-5"
              >
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <div className="text-[10px] font-mono text-signal-strong mb-1">LATEST BENCHMARK RESULT</div>
                    <div className="text-sm font-tactical text-white tracking-wider">{lastBenchmark.label}</div>
                    <div className="text-[10px] font-mono text-gray-500 mt-0.5">{lastBenchmark.interface_name}</div>
                  </div>
                  <div className="flex items-center gap-6">
                    <div className="text-right">
                      <div className={`text-3xl font-mono font-bold ${getBenchmarkScore(lastBenchmark) >= 70 ? 'text-signal-strong' : getBenchmarkScore(lastBenchmark) >= 40 ? 'text-risk-high' : 'text-risk-critical'}`}>{getBenchmarkScore(lastBenchmark)}</div>
                      <div className="text-[10px] font-tactical text-gray-400">SCORE</div>
                    </div>
                    <div className="text-right">
                      <div className="text-3xl font-mono font-bold text-white">{lastBenchmark.total_aps}</div>
                      <div className="text-[10px] font-tactical text-gray-400">APs DETECTED</div>
                    </div>
                  </div>
                </div>

                {/* Stats Grid */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
                  <div className="bg-space-900/80 rounded p-3 border border-space-500/10">
                    <div className="text-[10px] font-mono text-gray-500 mb-1">STRONGEST</div>
                    <div className="text-sm font-mono text-signal-strong">{lastBenchmark.max_rssi ?? '—'} dBm</div>
                  </div>
                  <div className="bg-space-900/80 rounded p-3 border border-space-500/10">
                    <div className="text-[10px] font-mono text-gray-500 mb-1">WEAKEST</div>
                    <div className="text-sm font-mono text-risk-high">{lastBenchmark.min_rssi ?? '—'} dBm</div>
                  </div>
                  <div className="bg-space-900/80 rounded p-3 border border-space-500/10">
                    <div className="text-[10px] font-mono text-gray-500 mb-1">AVERAGE</div>
                    <div className="text-sm font-mono text-neon-400">{lastBenchmark.avg_rssi ?? '—'} dBm</div>
                  </div>
                  <div className="bg-space-900/80 rounded p-3 border border-space-500/10">
                    <div className="text-[10px] font-mono text-gray-500 mb-1">DURATION</div>
                    <div className="text-sm font-mono text-gray-300">{lastBenchmark.scan_duration_ms ? `${(lastBenchmark.scan_duration_ms / 1000).toFixed(1)}s` : '—'}</div>
                  </div>
                </div>

                {/* Signal Distribution Bar */}
                <div className="mb-3">
                  <div className="text-[10px] font-mono text-gray-500 mb-2">SIGNAL DISTRIBUTION</div>
                  <div className="flex h-5 rounded overflow-hidden border border-space-500/20">
                    {lastBenchmark.total_aps > 0 && (
                      <>
                        {lastBenchmark.band_excellent > 0 && (
                          <div className="bg-signal-strong flex items-center justify-center" style={{ width: `${(lastBenchmark.band_excellent / lastBenchmark.total_aps) * 100}%` }}>
                            <span className="text-[8px] font-mono text-white">{lastBenchmark.band_excellent}</span>
                          </div>
                        )}
                        {lastBenchmark.band_good > 0 && (
                          <div className="bg-neon-500 flex items-center justify-center" style={{ width: `${(lastBenchmark.band_good / lastBenchmark.total_aps) * 100}%` }}>
                            <span className="text-[8px] font-mono text-white">{lastBenchmark.band_good}</span>
                          </div>
                        )}
                        {lastBenchmark.band_fair > 0 && (
                          <div className="bg-risk-high flex items-center justify-center" style={{ width: `${(lastBenchmark.band_fair / lastBenchmark.total_aps) * 100}%` }}>
                            <span className="text-[8px] font-mono text-white">{lastBenchmark.band_fair}</span>
                          </div>
                        )}
                        {lastBenchmark.band_weak > 0 && (
                          <div className="bg-risk-critical flex items-center justify-center" style={{ width: `${(lastBenchmark.band_weak / lastBenchmark.total_aps) * 100}%` }}>
                            <span className="text-[8px] font-mono text-white">{lastBenchmark.band_weak}</span>
                          </div>
                        )}
                      </>
                    )}
                  </div>
                  <div className="flex gap-4 mt-2 text-[9px] font-mono">
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-signal-strong" />Excellent (≥ -50)</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-neon-500" />Good (-51 to -60)</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-risk-high" />Fair (-61 to -70)</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-risk-critical" />Weak (&lt; -70)</span>
                  </div>
                </div>

                {/* Band Breakdown */}
                {/*
                  Access points whose channel the driver never reported are no
                  longer counted as 6 GHz, so the three band figures can now sum
                  to less than the total. That remainder is shown rather than
                  left as an unexplained gap — it is the difference between "this
                  adapter saw no 6 GHz networks" and "this adapter could not tell
                  us", which is the whole reason the benchmark exists.
                */}
                <div className="flex flex-wrap gap-3 text-[10px] font-mono">
                  <span className="px-2 py-1 bg-space-900 rounded border border-space-500/20 text-gray-300">2.4 GHz: <strong className="text-white">{lastBenchmark.aps_2g}</strong></span>
                  <span className="px-2 py-1 bg-space-900 rounded border border-space-500/20 text-gray-300">5 GHz: <strong className="text-white">{lastBenchmark.aps_5g}</strong></span>
                  {lastBenchmark.aps_6g > 0 && (
                    <span className="px-2 py-1 bg-space-900 rounded border border-space-500/20 text-gray-300">6 GHz: <strong className="text-white">{lastBenchmark.aps_6g}</strong></span>
                  )}
                  {(() => {
                    const banded = lastBenchmark.aps_2g + lastBenchmark.aps_5g + lastBenchmark.aps_6g;
                    const unknown = lastBenchmark.total_aps - banded;
                    if (unknown <= 0) return null;
                    return (
                      <span
                        title="The driver reported no frequency for these access points, so their band could not be derived. They are not counted in any band above."
                        className="px-2 py-1 bg-space-900 rounded border border-amber-400/30 text-amber-300"
                      >
                        band not reported: <strong>{unknown}</strong>
                      </span>
                    );
                  })()}
                </div>

                {/* Notes */}
                {lastBenchmark.notes && (
                  <div className="mt-3 text-[10px] font-mono text-gray-500 border-t border-space-500/10 pt-2">
                    <span className="text-gray-600">NOTE:</span> {lastBenchmark.notes}
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>

          {/* Benchmark History Table */}
          <AnimatePresence>
            {benchmarkExpanded && benchmarkHistory.length > 0 && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="overflow-hidden"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="text-[10px] font-mono text-gray-500 uppercase tracking-wider">Comparison History</div>
                  {compareIds.length > 0 && (
                    <button onClick={() => setCompareIds([])} className="text-[9px] font-tactical text-gray-600 hover:text-gray-300 transition-colors">CLEAR SELECTION</button>
                  )}
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-[10px] font-mono">
                    <thead>
                      <tr className="text-gray-500 border-b border-space-500/20">
                        <th className="text-left py-2 pr-2 w-8">VS</th>
                        <th className="text-left py-2 pr-3">LABEL</th>
                        <th className="text-left py-2 pr-3">INTERFACE</th>
                        <th className="text-right py-2 pr-3">APs</th>
                        <th className="text-right py-2 pr-3">AVG dBm</th>
                        <th className="text-right py-2 pr-3">MIN dBm</th>
                        <th className="text-right py-2 pr-3">DATE</th>
                        <th className="text-right py-2"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {benchmarkHistory.map((b) => (
                        <tr key={b.id} className={`border-b border-space-500/10 hover:bg-space-800/30 transition-colors ${compareIds.includes(b.id) ? 'bg-signal-strong/5' : ''}`}>
                          <td className="py-2 pr-2">
                            <button
                              onClick={() => toggleCompare(b.id)}
                              className={`w-4 h-4 rounded border flex items-center justify-center transition-colors ${compareIds.includes(b.id) ? 'bg-signal-strong border-signal-strong text-white' : 'border-space-500/40 hover:border-signal-strong/50'}`}
                            >
                              {compareIds.includes(b.id) && <span className="text-[8px]">✓</span>}
                            </button>
                          </td>
                          <td className="py-2 pr-3">
                            <div className="text-white">{b.label}</div>
                            {b.notes && <div className="text-[9px] text-gray-600 mt-0.5 truncate max-w-[160px]">{b.notes}</div>}
                          </td>
                          <td className="py-2 pr-3 text-gray-400 max-w-[120px] truncate">{b.interface_name}</td>
                          <td className="py-2 pr-3 text-right text-signal-strong font-bold">{b.total_aps}</td>
                          <td className="py-2 pr-3 text-right text-neon-400">{b.avg_rssi ?? '—'}</td>
                          <td className="py-2 pr-3 text-right text-risk-high">{b.min_rssi ?? '—'}</td>
                          <td className="py-2 pr-3 text-right text-gray-500">{new Date(b.created_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: '2-digit' })}</td>
                          <td className="py-2 text-right">
                            <button
                              onClick={() => deleteConfirmId === b.id ? handleDeleteBenchmark(b.id) : setDeleteConfirmId(b.id)}
                              className={`text-[9px] px-2 py-0.5 rounded transition-colors ${deleteConfirmId === b.id ? 'bg-risk-critical text-white' : 'text-gray-600 hover:text-risk-critical'}`}
                            >
                              {deleteConfirmId === b.id ? 'CONFIRM' : '✕'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                {/* Side-by-Side Comparison Card */}
                {compareA && compareB && (
                  <div className="mt-4 bg-space-950/60 border border-neon-500/30 rounded-lg p-5">
                    <div className="text-[10px] font-tactical text-neon-400 mb-4 tracking-wider">SIDE-BY-SIDE COMPARISON</div>
                    <div className="grid grid-cols-3 gap-2 text-[10px] font-mono">
                      {/* Header */}
                      <div className="text-gray-600 py-1">METRIC</div>
                      <div className="text-center text-white font-bold py-1 bg-space-800/50 rounded">{compareA.label}</div>
                      <div className="text-center text-white font-bold py-1 bg-space-800/50 rounded">{compareB.label}</div>
                      {/* Total APs */}
                      <div className="text-gray-500 py-1.5">Total APs</div>
                      <div className={`text-center py-1.5 font-bold ${compareA.total_aps >= compareB.total_aps ? 'text-signal-strong' : 'text-gray-400'}`}>{compareA.total_aps}</div>
                      <div className={`text-center py-1.5 font-bold ${compareB.total_aps >= compareA.total_aps ? 'text-signal-strong' : 'text-gray-400'}`}>{compareB.total_aps}</div>
                      {/* Avg RSSI */}
                      <div className="text-gray-500 py-1.5">Avg RSSI</div>
                      <div className={`text-center py-1.5 ${(compareA.avg_rssi ?? -100) >= (compareB.avg_rssi ?? -100) ? 'text-signal-strong' : 'text-gray-400'}`}>{compareA.avg_rssi ?? '—'} dBm</div>
                      <div className={`text-center py-1.5 ${(compareB.avg_rssi ?? -100) >= (compareA.avg_rssi ?? -100) ? 'text-signal-strong' : 'text-gray-400'}`}>{compareB.avg_rssi ?? '—'} dBm</div>
                      {/* Min RSSI (sensitivity) */}
                      <div className="text-gray-500 py-1.5">Weakest Detected</div>
                      <div className={`text-center py-1.5 ${(compareA.min_rssi ?? -100) <= (compareB.min_rssi ?? -100) ? 'text-signal-strong' : 'text-gray-400'}`}>{compareA.min_rssi ?? '—'} dBm</div>
                      <div className={`text-center py-1.5 ${(compareB.min_rssi ?? -100) <= (compareA.min_rssi ?? -100) ? 'text-signal-strong' : 'text-gray-400'}`}>{compareB.min_rssi ?? '—'} dBm</div>
                      {/* 2.4G */}
                      <div className="text-gray-500 py-1.5">2.4 GHz</div>
                      <div className={`text-center py-1.5 ${compareA.aps_2g >= compareB.aps_2g ? 'text-signal-strong' : 'text-gray-400'}`}>{compareA.aps_2g}</div>
                      <div className={`text-center py-1.5 ${compareB.aps_2g >= compareA.aps_2g ? 'text-signal-strong' : 'text-gray-400'}`}>{compareB.aps_2g}</div>
                      {/* 5G */}
                      <div className="text-gray-500 py-1.5">5 GHz</div>
                      <div className={`text-center py-1.5 ${compareA.aps_5g >= compareB.aps_5g ? 'text-signal-strong' : 'text-gray-400'}`}>{compareA.aps_5g}</div>
                      <div className={`text-center py-1.5 ${compareB.aps_5g >= compareA.aps_5g ? 'text-signal-strong' : 'text-gray-400'}`}>{compareB.aps_5g}</div>
                      {/* Excellent Band */}
                      <div className="text-gray-500 py-1.5">Excellent Signal</div>
                      <div className={`text-center py-1.5 ${compareA.band_excellent >= compareB.band_excellent ? 'text-signal-strong' : 'text-gray-400'}`}>{compareA.band_excellent}</div>
                      <div className={`text-center py-1.5 ${compareB.band_excellent >= compareA.band_excellent ? 'text-signal-strong' : 'text-gray-400'}`}>{compareB.band_excellent}</div>
                    </div>
                  </div>
                )}
              </motion.div>
            )}
          </AnimatePresence>

          {benchmarkHistory.length === 0 && !isBenchmarking && (
            <div className="text-center py-6 text-gray-600 font-mono text-xs">
              No benchmark records yet. Run your first benchmark to start comparing adapters.
            </div>
          )}
          {benchmarkExpanded && benchmarkHistory.length > 0 && compareIds.length < 2 && (
            <div className="text-center py-2 text-gray-600 font-mono text-[10px]">
              Select 2 results from the table above to compare side-by-side.
            </div>
          )}
        </div>

        {/* Dictionary Arsenal */}
        <div
          className={`glass-card p-6 mb-6 border-l-2 border-l-neon-500 transition-colors ${isDragging ? 'bg-neon-500/10 border-neon-500 ring-2 ring-neon-500/50' : ''}`}
          onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
          onDragLeave={(e) => { e.preventDefault(); setIsDragging(false); }}
          onDrop={(e) => {
            e.preventDefault();
            setIsDragging(false);
            if (uploadProgress?.phase === 'SENDING' || uploadProgress?.phase === 'FINALIZING') return;
            const file = e.dataTransfer.files?.[0];
            if (file) handleFileUpload(file);
          }}
        >
          <div className="flex items-center justify-between mb-5 border-b border-space-500/20 pb-2">
            <h3 className="text-xs font-semibold text-gray-300 text-tactical tracking-wider uppercase flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-neon-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 19.5v-15A2.5 2.5 0 0 1 6.5 2H20v20H6.5a2.5 2.5 0 0 1 0-5H20"></path></svg>
              Dictionary Arsenal
            </h3>
            <span className="text-[10px] font-mono text-gray-500 bg-space-800 px-2 py-0.5 rounded border border-space-500/20">
              {wordlists.length} FILES LOADED
            </span>
          </div>

          <p className="text-[10px] text-gray-500 font-mono mb-4">
            Manage your offensive wordlists for brute-forcing and WPA decryption. Drag and drop a `.txt` file anywhere in this box to upload.
          </p>

          {wordlistNotice && (
            <div className="mb-4 flex items-start justify-between gap-3 rounded border border-risk-critical/40 bg-risk-critical/10 p-3">
              <div className="text-[11px] font-mono text-risk-critical leading-relaxed">{wordlistNotice}</div>
              <button onClick={() => setWordlistNotice(null)} className="text-[9px] font-tactical text-gray-500 hover:text-gray-300 shrink-0">DISMISS</button>
            </div>
          )}

          <div className="space-y-2 mb-4 max-h-[250px] overflow-y-auto no-scrollbar pr-2">
            {wordlists.length === 0 ? (
              <div className="text-center py-6 text-gray-600 font-mono text-xs bg-space-950/50 rounded border border-space-500/10">
                No wordlists found, in either the bundled directory or your upload directory.
              </div>
            ) : (
              wordlists.map((file, idx) => (
                <div key={idx} className="flex justify-between items-center p-3 bg-space-900 border border-space-500/20 rounded hover:border-space-500/50 transition-colors group relative overflow-hidden">
                  <div className="flex items-center gap-3">
                    <svg xmlns="http://www.w3.org/2000/svg" className={`w-4 h-4 transition-colors ${file.size > 50 * 1024 * 1024 ? 'text-risk-high' : 'text-gray-500 group-hover:text-neon-400'}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                    <div className="flex items-center gap-2">
                      <div className="text-sm font-mono text-gray-300 group-hover:text-white transition-colors">{file.name}</div>
                      {file.size > 50 * 1024 * 1024 && (
                        <span className="text-[8px] bg-risk-high/20 text-risk-high border border-risk-high/50 px-1 rounded font-tactical tracking-wider">HEAVY</span>
                      )}
                      {file.origin === 'bundled' && (
                        <span className="text-[8px] bg-space-500/20 text-gray-400 border border-space-500/50 px-1 rounded font-tactical tracking-wider">BUNDLED</span>
                      )}
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <div className="text-[10px] font-mono text-gray-500 bg-space-950 px-2 py-1 rounded">
                      {formatBytes(file.size)}
                    </div>
                    {/*
                      Delete Action (Shows on Hover).
                      Disabled for a bundled list: it is part of the installation
                      and lives under %ProgramFiles% on an installed copy, so the
                      engine refuses it. Offering a button that always fails reads
                      as a broken feature rather than as a deliberate refusal.
                    */}
                    <button
                      onClick={() => handleDeleteWordlist(file.name)}
                      disabled={file.origin === 'bundled'}
                      className="opacity-0 group-hover:opacity-100 transition-opacity p-1.5 text-gray-500 hover:text-risk-high hover:bg-risk-high/10 rounded disabled:cursor-not-allowed disabled:hover:text-gray-500 disabled:hover:bg-transparent"
                      title={file.origin === 'bundled'
                        ? 'Ships with the application — cannot be deleted'
                        : 'Delete Wordlist'}
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>

          <input
            type="file"
            accept=".txt"
            ref={fileInputRef}
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) handleFileUpload(file);
              // Reset input
              e.target.value = '';
            }}
          />

          {(() => {
            const inFlight = uploadProgress?.phase === 'SENDING' || uploadProgress?.phase === 'FINALIZING';
            return (
              <button
                onClick={() => !inFlight && fileInputRef.current?.click()}
                disabled={inFlight}
                className={`w-full py-3 text-xs font-tactical tracking-widest rounded transition-all border flex items-center justify-center gap-2 relative overflow-hidden
              ${inFlight
                    ? 'bg-space-900 border-neon-500/30 text-neon-400 cursor-wait'
                    : uploadProgress?.phase === 'SAVED'
                      ? 'bg-space-900 border-signal-strong/50 text-signal-strong'
                      : uploadProgress?.phase === 'FAILED'
                        ? 'bg-space-900 border-risk-critical/50 text-risk-critical'
                        : 'bg-space-800 hover:bg-space-700 text-gray-300 border-space-500/30'}
            `}
              >
                {/* Progress Bar Background */}
                {uploadProgress && (
                  <div
                    className={`absolute left-0 top-0 bottom-0 transition-all duration-300 ${uploadProgress.phase === 'FAILED' ? 'bg-risk-critical/10' : uploadProgress.phase === 'SAVED' ? 'bg-signal-strong/10' : 'bg-neon-500/10'}`}
                    style={{ width: `${uploadProgress.progress}%` }}
                  />
                )}

                {uploadProgress?.phase === 'SENDING' ? (
                  <>
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line><line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line><line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line><line x1="16.24" y1="4.93" x2="19.07" y2="7.76"></line></svg>
                    SENDING {uploadProgress.filename}... {uploadProgress.progress}%
                  </>
                ) : uploadProgress?.phase === 'FINALIZING' ? (
                  <>
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="2" x2="12" y2="6"></line><line x1="12" y1="18" x2="12" y2="22"></line><line x1="2" y1="12" x2="6" y2="12"></line><line x1="18" y1="12" x2="22" y2="12"></line></svg>
                    AWAITING ENGINE CONFIRMATION FOR {uploadProgress.filename}...
                  </>
                ) : uploadProgress?.phase === 'SAVED' ? (
                  <>
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
                    {uploadProgress.filename} WRITTEN BY ENGINE
                  </>
                ) : uploadProgress?.phase === 'FAILED' ? (
                  <>
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10" /><line x1="15" y1="9" x2="9" y2="15" /><line x1="9" y1="9" x2="15" y2="15" /></svg>
                    UPLOAD FAILED — {uploadProgress.filename} NOT SAVED
                  </>
                ) : (
                  <>
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="17 8 12 3 7 8"></polyline><line x1="12" y1="3" x2="12" y2="15"></line></svg>
                    UPLOAD CUSTOM WORDLIST
                  </>
                )}
              </button>
            );
          })()}
        </div>

        {/* Danger Zone */}
        <div className="glass-card p-6 border border-risk-critical/30 bg-risk-critical/5">
          <h3 className="text-xs font-semibold text-risk-critical text-tactical tracking-wider mb-2 uppercase flex items-center gap-2">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-risk-critical" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></svg>
              Danger Zone
            </h3>
          <p className="text-xs text-gray-400 font-mono mb-4">Destructive actions cannot be reversed. Proceed with extreme caution.</p>

          <div className="p-4 bg-space-950/50 rounded border border-risk-critical/20">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="text-sm font-medium text-white">Purge Collected Data</div>
                <div className="text-[10px] text-gray-500 font-mono mt-0.5">
                  Deletes every row of collected intelligence from the local database and clears the engine's in-memory state.
                </div>
              </div>

              {purgeStage === 'IDLE' && (
                <button
                  onClick={openPurgeReview}
                  className="px-4 py-2 rounded text-xs font-tactical uppercase transition-all bg-space-800 border border-risk-critical/30 text-risk-critical hover:bg-risk-critical/20"
                >
                  REVIEW & PURGE
                </button>
              )}
            </div>

            {/* What is NOT purgeable — stated up front, not discovered afterwards */}
            <div className="mt-4 flex items-start gap-2 rounded border border-space-500/20 bg-space-900/60 p-3">
              <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5 mt-0.5 shrink-0 text-neon-500/70" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              <p className="text-[10px] text-gray-400 font-mono leading-relaxed">
                <span className="text-gray-200 font-tactical tracking-wider mr-1">KEPT ON PURPOSE:</span>
                the engagement scope, its targets and the audit log are never touched by this button. They are the record of what you
                were authorized to do and what the engine allowed or blocked — not collected data. Wiping them would disarm the tool
                and erase the evidence that the work stayed inside its authorization. Remove an engagement from the Engagement Scope
                section above if that is what you actually want.
              </p>
            </div>

            {/* Step 1 — real footprint */}
            {(purgeStage === 'REVIEW' || purgeStage === 'RUNNING') && (
              <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} className="mt-4 rounded border border-risk-critical/40 bg-space-900/80 p-4">
                <div className="text-[10px] font-tactical tracking-widest text-risk-critical mb-3">STEP 1 — WHAT WILL BE DELETED</div>

                {!footprint ? (
                  <div className="text-[11px] font-mono text-gray-500">Counting rows...</div>
                ) : footprintTotal === 0 ? (
                  <div className="text-[11px] font-mono text-gray-400">
                    All purgeable tables are already empty. There is nothing to delete.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-[10px] font-mono">
                      <thead>
                        <tr className="text-gray-500 border-b border-space-500/20">
                          <th className="text-left py-1.5 pr-3">TABLE</th>
                          <th className="text-right py-1.5">ROWS</th>
                        </tr>
                      </thead>
                      <tbody>
                        {footprint.filter(r => r.rowsAffected > 0).map(r => (
                          <tr key={r.table} className="border-b border-space-500/10">
                            <td className="py-1.5 pr-3 text-gray-300">{r.table}</td>
                            <td className="py-1.5 text-right text-risk-critical font-bold">{r.rowsAffected.toLocaleString()}</td>
                          </tr>
                        ))}
                        <tr>
                          <td className="py-2 pr-3 text-gray-200 font-tactical tracking-wider">TOTAL</td>
                          <td className="py-2 text-right text-white font-bold">{footprintTotal.toLocaleString()}</td>
                        </tr>
                      </tbody>
                    </table>
                    <div className="text-[10px] font-mono text-gray-600 mt-1">
                      {footprint.filter(r => r.rowsAffected === 0).length} further purgeable table(s) are already empty.
                    </div>
                  </div>
                )}

                {/* Step 2 — explicit confirmation */}
                <div className="mt-4 pt-4 border-t border-space-500/20">
                  <div className="text-[10px] font-tactical tracking-widest text-risk-critical mb-2">STEP 2 — CONFIRM</div>
                  <p className="text-[11px] font-mono text-gray-300 mb-2">
                    Type <span className="text-risk-critical font-bold">{PURGE_PHRASE}</span> to delete the {footprintTotal.toLocaleString()} row(s) above. This cannot be undone.
                  </p>
                  <div className="flex flex-col sm:flex-row gap-2">
                    <input
                      type="text"
                      value={purgeConfirmText}
                      onChange={(e) => setPurgeConfirmText(e.target.value)}
                      placeholder={PURGE_PHRASE}
                      disabled={purgeStage === 'RUNNING'}
                      className={`flex-1 bg-space-900 border text-white rounded px-3 py-2 text-xs font-mono placeholder-gray-600 focus:outline-none ${purgeConfirmText.trim().toUpperCase() === PURGE_PHRASE ? 'border-risk-critical' : 'border-space-500/30'}`}
                    />
                    <button
                      onClick={executePurge}
                      disabled={purgeStage === 'RUNNING' || purgeConfirmText.trim().toUpperCase() !== PURGE_PHRASE || footprintTotal === 0}
                      className={`px-4 py-2 rounded text-xs font-tactical uppercase tracking-widest transition-all ${purgeStage === 'RUNNING'
                        ? 'bg-space-800 border border-space-500/30 text-gray-400 cursor-wait'
                        : purgeConfirmText.trim().toUpperCase() === PURGE_PHRASE && footprintTotal > 0
                          ? 'bg-risk-critical text-white'
                          : 'bg-space-800 border border-space-500/20 text-gray-600 cursor-not-allowed'}`}
                    >
                      {purgeStage === 'RUNNING' ? 'PURGING...' : 'EXECUTE PURGE'}
                    </button>
                    <button
                      onClick={cancelPurge}
                      disabled={purgeStage === 'RUNNING'}
                      className="px-4 py-2 rounded text-xs font-tactical uppercase tracking-widest text-gray-400 border border-space-500/30 hover:bg-space-800 hover:text-white transition-colors disabled:opacity-40"
                    >
                      CANCEL
                    </button>
                  </div>
                </div>
              </motion.div>
            )}

            {/* Step 3 — what was actually removed */}
            {purgeStage === 'DONE' && purgeResult && (
              <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }} className="mt-4 rounded border border-signal-strong/40 bg-signal-strong/5 p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="text-[10px] font-tactical tracking-widest text-signal-strong">PURGE COMPLETE — {purgedTotal.toLocaleString()} ROW(S) DELETED</div>
                  <button onClick={cancelPurge} className="text-[9px] font-tactical text-gray-500 hover:text-gray-300">CLOSE</button>
                </div>
                {purgedTotal === 0 ? (
                  <div className="text-[11px] font-mono text-gray-400">The database reported no rows removed. Nothing was there to delete.</div>
                ) : (
                  <div className="flex flex-wrap gap-2">
                    {purgeResult.filter(r => r.rowsAffected > 0).map(r => (
                      <span key={r.table} className="px-2 py-1 rounded border border-space-500/20 bg-space-900 text-[10px] font-mono text-gray-300">
                        {r.table} <strong className="text-signal-strong">−{r.rowsAffected.toLocaleString()}</strong>
                      </span>
                    ))}
                  </div>
                )}
                <div className="text-[10px] font-mono text-gray-500 mt-3">
                  Counts are what the database reported deleting, not an assumption. The engine's in-memory state and the live mission
                  view were reset as well.
                </div>
              </motion.div>
            )}

            {purgeError && (
              <div className="mt-4 rounded border border-risk-critical/50 bg-risk-critical/10 p-3 text-[11px] font-mono text-risk-critical">{purgeError}</div>
            )}
          </div>
        </div>

      </motion.div>

      <ConfirmModal
        isOpen={confirmDelete.open}
        title="DELETE WORDLIST"
        message={`Are you sure you want to delete "${confirmDelete.filename}"? This action cannot be undone.`}
        confirmLabel="DELETE"
        variant="danger"
        onConfirm={executeDeleteWordlist}
        onCancel={() => setConfirmDelete({ open: false, filename: '' })}
      />

      <ConfirmModal
        isOpen={confirmLabScope}
        title="LAB / MY OWN NETWORK"
        message={
          'This activates an UNRESTRICTED engagement: every offensive module — deauth, handshake '
          + 'capture, brute force, spraying, MITM, dirbuster, SMB enumeration and the auto-attack '
          + 'chain — becomes available against anything the radio or the subnet can reach, with no '
          + 'allowlist to stop it.' + '\n\n'
          + 'By continuing you are stating that every reachable target is your own equipment, or is '
          + 'covered by authorization you already hold. That statement is recorded with the '
          + 'engagement and every report generated from it says plainly that no allowlist was in '
          + 'force.' + '\n\n'
          + 'Every gated command is still written to the audit trail. If you are working on someone '
          + "else's network, cancel and define the engagement properly instead."
        }
        confirmLabel="I OWN OR AM AUTHORIZED FOR EVERYTHING IN RANGE"
        variant="warning"
        onConfirm={handleLabEngagement}
        onCancel={() => setConfirmLabScope(false)}
      />

      <ConfirmModal
        isOpen={confirmDeleteScope !== null}
        title="DELETE ENGAGEMENT"
        message={
          confirmDeleteScope
            ? `Delete "${confirmDeleteScope.engagement_name}" and its targets? ${confirmDeleteScope.is_active === 1
              ? 'It is the ACTIVE engagement — deleting it leaves the engine with no scope, so every offensive module will be blocked until another one is activated. '
              : ''}The audit rows it produced are kept.`
            : ''
        }
        confirmLabel="DELETE"
        variant="danger"
        onConfirm={() => {
          const target = confirmDeleteScope;
          if (!target) return;
          runScopeAction(`Engagement "${target.engagement_name}" deleted`, async () => {
            await deleteScope(target.id);
            if (inspectedScopeId === target.id) {
              setInspectedScopeId(null);
              setInspectedTargets([]);
            }
          });
        }}
        onCancel={() => setConfirmDeleteScope(null)}
      />
    </div>
  );
}
