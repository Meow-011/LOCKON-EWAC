import { create } from 'zustand';

export interface DiscoveredHost {
  ip: string;
  hostname: string;
  os: string;
  mac?: string;
  vendor?: string;
  open_ports: { 
    port: number; 
    protocol?: string; // 'UDP' | 'TCP'
    service: string; 
    banner?: string;
    server_header?: string;
    service_name?: string;
    service_version?: string;
    cves?: { cve: string, severity: string, description: string }[];
  }[];
  timestamp: number;
  isGateway: boolean;
  ssl_cert?: any;
  snmp_communities?: any[];
  default_creds?: { username: string; password?: string };
}

/**
 * How much of a subnet a sweep actually put a probe on.
 *
 * The engine has always emitted this as `intrusion_scope`, carrying the caveat
 * "absence here is not evidence that nothing is there" — and nothing in the app
 * subscribed to it, so the one thing that separates "swept the subnet and found
 * six hosts" from "probed the six addresses that answered ARP within half a
 * second" was dropped on the floor.
 *
 * The ARP pre-filter routinely reduces a /24 to a handful of addresses, and it
 * also comes back empty when the ARP read *failed* rather than the network being
 * quiet. Without these numbers a narrow sweep is indistinguishable from a clean
 * one in the UI and in the report.
 */
export interface SweepScope {
  subnet: string;
  addressesInRange: number;
  addressesProbed: number;
  skippedByArpFilter: number;
  /**
   * Addresses the ARP-populating sweep never contacted at all.
   *
   * Distinct from `skippedByArpFilter`, and the distinction matters: an address
   * that was asked and stayed silent is a (weak) observation, while one that was
   * never asked is not an observation of anything. The sweep is capped per
   * subnet to avoid flooding the segment with ARP broadcasts, so on a range
   * larger than that cap this is where the uncovered addresses are counted.
   */
  addressesNeverSwept: number;
  /**
   * Why the ARP table could not be read, when it could not.
   *
   * The pre-filter that decides which addresses get probed is built from that
   * table, so a failed read narrows the sweep to a fallback sample of two
   * addresses while the run completes normally. Without this the report cannot
   * tell a quiet subnet from one it never really looked at.
   */
  arpReadError: string | null;
  scanMode: string;
  discovery: string;
  caveat: string;
}

interface IntrusionState {
  isActive: boolean;
  progress: number;
  scannedCount: number;
  totalCount: number;
  /** Per-subnet sweep coverage, keyed by subnet. */
  sweepScopes: Record<string, SweepScope>;
  targetSubnet: string | null;
  activeSsid: string | null;
  currentSessionId: string | null;
  currentScanMode: string;
  hosts: Record<string, DiscoveredHost>;
  subnets: string[];
  newDevices: string[];
  /**
   * Hosts that responded in a previous sweep and no longer do. The engine has
   * always reported these; the UI used to drop them. On a retest they are how you
   * show something was taken off the network.
   */
  disappearedDevices: string[];
  hasScanned: boolean;

  // Actions
  startIntrusion: (subnet?: string, scanMode?: string) => void;
  stopIntrusion: () => void;
  setProgress: (progress: number, scanned: number, total: number) => void;
  recordSweepScope: (scope: SweepScope) => void;
  addHost: (host: DiscoveredHost) => void;
  setSubnets: (subnets: string[]) => void;
  setNewDevices: (devices: string[]) => void;
  setDisappearedDevices: (devices: string[]) => void;
  reset: () => void;
}

export const useIntrusionStore = create<IntrusionState>((set) => ({
  isActive: false,
  progress: 0,
  scannedCount: 0,
  totalCount: 0,
  sweepScopes: {},
  targetSubnet: null,
  activeSsid: null,
  currentSessionId: null,
  currentScanMode: 'QUICK',
  hosts: {},
  subnets: [],
  newDevices: [],
  disappearedDevices: [],
  hasScanned: false,

  startIntrusion: (subnet, scanMode) => set((state) => {
    const shouldClear = state.targetSubnet && subnet && state.targetSubnet !== subnet;
    return {
      isActive: true,
      progress: 0,
      scannedCount: 0,
      totalCount: 0,
      // Coverage belongs to one run; a previous run's figures must never be
      // read as describing this one.
      sweepScopes: {},
      targetSubnet: subnet || state.targetSubnet,
      currentSessionId: `SCAN-${Date.now()}`,
      currentScanMode: scanMode || 'QUICK',
      hosts: shouldClear ? {} : state.hosts,
      hasScanned: true
    };
  }),
  stopIntrusion: () => set({ isActive: false }),
  setProgress: (progress, scanned, total) => set({ progress, scannedCount: scanned, totalCount: total }),
  recordSweepScope: (scope) => set((state) => ({
    sweepScopes: { ...state.sweepScopes, [scope.subnet]: scope },
  })),
  addHost: (host) => set((state) => ({ 
    hosts: { ...state.hosts, [host.ip]: host } 
  })),
  setSubnets: (subnets) => set({ subnets }),
  setNewDevices: (devices) => set((state) => ({
    newDevices: [...new Set([...state.newDevices, ...devices])]
  })),
  setDisappearedDevices: (devices) => set((state) => ({
    disappearedDevices: [...new Set([...state.disappearedDevices, ...devices])]
  })),
  reset: () => set({
    isActive: false,
    progress: 0,
    scannedCount: 0,
    totalCount: 0,
    sweepScopes: {},
    targetSubnet: null,
    currentSessionId: null,
    currentScanMode: 'QUICK',
    hosts: {},
    subnets: [],
    newDevices: [],
    disappearedDevices: [],
    hasScanned: false
  })
}));
