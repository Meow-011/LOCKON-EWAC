/** LOCKON EWAC — Passive SIGINT State (session-persistent across navigation) */
import { create } from 'zustand';

/**
 * Mirrors what the engine emits on `passive_host` / `probe_detected`.
 *
 * The previous shape invented `vendor`, `os` and `protocol`. None are sent, so
 * every vendor cell read "Unknown", the protocol column was blank and vendor
 * search matched nothing — while the engine's real `source` and `detail` were
 * never shown. `timestamp` is an ISO string, not epoch millis.
 */
export interface PassiveHost {
  ip: string;
  mac: string;
  hostname: string | null;
  source: string;
  detail?: string | null;
  is_new?: boolean;
  timestamp: string;
}

export interface ProbeRequest {
  client_mac: string;
  ssid: string;
  is_new_client?: boolean;
  total_ssids?: number;
  probe_count?: number;
  timestamp: string;
}

/**
 * What the live feed could not tell us, from the engine's own summaries.
 *
 * Both `get_passive_summary` and `get_probe_summary` existed with no caller, and
 * this project's gaps list recorded them as redundant -- "a second source for a
 * number the UI already has". That was wrong in both cases, and the engine says
 * so in its own words. `passive.get_summary` is documented as "the authoritative
 * record: the feed is rate limited per host, so `event_count` here can exceed the
 * number of lines that reached the UI", and `probe_monitor` only emits
 * `probe_detected` when `is_new_client or is_new_ssid` -- so a client that probes
 * five hundred times for one SSID emits once, and the `probe_count` frozen on
 * screen is its value at that first sighting.
 *
 * The consequence is the one failure this tool exists not to commit: a number in
 * front of an operator that understates what was actually measured.
 */
export interface FeedStats {
  suppressed_repeat_events: number;
  min_interval_seconds: number;
}

interface PassiveSigintState {
  isActive: boolean;
  passiveHosts: PassiveHost[];
  probeRequests: ProbeRequest[];
  startTime: number | null;
  feedStats: FeedStats | null;
  /** When the authoritative counts were last read, so the panel can say. */
  lastSummaryAt: number | null;

  // Actions
  setActive: (v: boolean) => void;
  addPassiveHost: (host: PassiveHost) => void;
  addProbeRequest: (probe: ProbeRequest) => void;
  clearHosts: () => void;
  clearProbes: () => void;
  setStartTime: (t: number | null) => void;
  applyProbeSummary: (rows: { client_mac: string; ssids?: string[]; probe_count?: number }[]) => void;
  applyPassiveSummary: (feed: FeedStats | null) => void;
  reset: () => void;
}

export const usePassiveSigintStore = create<PassiveSigintState>((set) => ({
  isActive: false,
  passiveHosts: [],
  probeRequests: [],
  startTime: null,

  setActive: (isActive) => set({ isActive }),
  addPassiveHost: (host) => set((state) => {
    const exists = state.passiveHosts.findIndex(p => p.mac === host.mac && p.ip === host.ip);
    if (exists >= 0) {
      const next = [...state.passiveHosts];
      // Keep the engine's own timestamp rather than overwriting it with the
      // moment the UI happened to process the message.
      next[exists] = { ...next[exists], ...host };
      return { passiveHosts: next };
    }
    return { passiveHosts: [host, ...state.passiveHosts].slice(0, 50) };
  }),
  addProbeRequest: (probe) => set((state) => ({
    probeRequests: [probe, ...state.probeRequests].slice(0, 100)
  })),
  clearHosts: () => set({ passiveHosts: [] }),
  clearProbes: () => set({ probeRequests: [] }),
  setStartTime: (startTime) => set({ startTime }),

  /*
    Correct the displayed counts from the authoritative list.

    Matched on `client_mac`, and only the counts are replaced: the rest of each
    row is what the engine sent at the moment of sighting, including the SSID
    that row is about, and overwriting that would merge distinct probes into one.

    A client in the summary with no row on screen is not added. Its probes were
    suppressed as repeats of a sighting that is already here under another SSID,
    so inventing a row for it would show a probe event that never happened; the
    corrected count on the existing rows is what says the activity was higher.
  */
  applyProbeSummary: (rows) => set((state) => {
    if (!Array.isArray(rows) || rows.length === 0) return {};
    const byMac = new Map(rows.map(r => [String(r.client_mac).toUpperCase(), r]));
    return {
      probeRequests: state.probeRequests.map(p => {
        const live = byMac.get(String(p.client_mac).toUpperCase());
        if (!live) return p;
        return {
          ...p,
          probe_count: typeof live.probe_count === 'number' ? live.probe_count : p.probe_count,
          total_ssids: Array.isArray(live.ssids) ? live.ssids.length : p.total_ssids,
        };
      }),
      lastSummaryAt: Date.now(),
    };
  }),

  applyPassiveSummary: (feedStats) => set({ feedStats, lastSummaryAt: Date.now() }),

  feedStats: null,
  lastSummaryAt: null,
  reset: () => set({ isActive: false, passiveHosts: [], probeRequests: [], startTime: null, feedStats: null, lastSummaryAt: null }),
}));
