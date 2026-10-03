/** Engine IPC message types */

export interface EngineConfig {
  emulateHardware: boolean;
  comPort: string;
  baudRate: number;
  interfaceName: string | null;
  scanInterval: number;
}

export interface EngineMessage {
  event: string;
  data: Record<string, unknown>;
  ts: string;
}

export type EngineCommand = 
  // Core
  | 'ping'
  | 'start_scan'
  | 'stop_scan'
  | 'get_status'
  | 'get_interfaces'
  | 'purge_data'
  // Intrusion
  | 'start_intrusion'
  | 'stop_intrusion'
  // Strike
  | 'start_strike'
  | 'stop_strike'
  | 'stop_all_strikes'
  // Capture & Brute Force
  | 'start_capture'
  | 'start_bruteforce'
  | 'stop_bruteforce'
  | 'start_spray'
  | 'stop_spray'
  // Decryptor
  | 'start_decrypt'
  | 'stop_decrypt'
  // MITM
  | 'start_mitm'
  | 'stop_mitm'
  // Offensive Recon
  | 'start_dirbuster'
  | 'stop_dirbuster'
  | 'start_smb_enum'
  | 'start_vuln_scan'
  // Wordlists
  | 'get_wordlists'
  | 'upload_wordlist'
  | 'delete_wordlist'
  // Hardware
  | 'test_hardware'
  | 'run_benchmark'
  // Passive Intelligence
  | 'start_probe_monitor'
  | 'stop_probe_monitor'
  | 'get_probe_summary'
  | 'start_passive'
  | 'stop_passive'
  | 'get_passive_summary'
  // Advanced Recon
  | 'start_traceroute'
  | 'stop_traceroute'
  | 'start_vlan_detect'
  | 'start_deep_ssl_scan'
  | 'run_gpr'
  // WiFi Attack Enhancement
  | 'scan_wps'
  | 'stop_wps'
  | 'export_hashcat'
  | 'check_hashcat'
  | 'start_pmkid_capture'
  | 'stop_pmkid'
  // Auto-Attack & Band
  | 'set_auto_attack'
  | 'reset_auto_attack'
  // Engagement scope & audit
  | 'set_scope'
  | 'get_scope'
  // Capability, provenance, diagnostics, evidence
  | 'check_capabilities'
  | 'get_net_context'
  | 'get_cve_info'
  | 'update_cve_db'
  | 'get_engine_log'
  | 'verify_evidence'
  | 'get_client_summary'
  | 'get_methodology';

export interface EngineStatus {
  scanning: boolean;
  gpsLocked: boolean;
  wifiReady: boolean;
}

/**
 * Raw `status` payload as the engine sends it.
 *
 * The engine speaks snake_case on the wire; the store uses camelCase. These
 * were spread into each other directly, so `wifiReady` was never set by
 * anything and the UI showed "WIFI ADAPTER: SEARCHING" forever. Convert with
 * `mapEngineStatus` instead of spreading.
 */
export interface RawEngineStatus {
  scanning?: boolean;
  gps_locked?: boolean;
  wifi_ready?: boolean;
}

export function mapEngineStatus(raw: RawEngineStatus): Partial<EngineStatus> {
  const mapped: Partial<EngineStatus> = {};
  if (typeof raw.scanning === 'boolean') mapped.scanning = raw.scanning;
  if (typeof raw.gps_locked === 'boolean') mapped.gpsLocked = raw.gps_locked;
  if (typeof raw.wifi_ready === 'boolean') mapped.wifiReady = raw.wifi_ready;
  return mapped;
}

/** Engine-side view of the engagement scope (`scope_status` / `scope_updated`). */
export interface ScopeStatus {
  loaded: boolean;
  scope_id: number | null;
  engagement_name: string | null;
  authorized_by: string | null;
  operator: string | null;
  reference: string | null;
  mode: 'ALLOWLIST' | 'UNRESTRICTED';
  valid_until: string | null;
  expired: boolean;
  counts: { bssid: number; ssid: number; ip: number; cidr: number };
  gated_commands: string[];
}

/**
 * What this rig can actually do (`capabilities` event).
 *
 * `monitor_mode.supported` is deliberately nullable: on Windows it cannot be
 * determined without switching the adapter, so the engine reports "unknown"
 * rather than guessing. A confident wrong answer here is what makes a failed
 * capture look like a secure target.
 */
export interface FeatureCapability {
  ready: boolean;
  requires: string;
  note?: string;
  caveat?: string;
}

export interface EngineCapabilities {
  platform: string;
  platform_release?: string;
  python?: string;
  elevated: boolean;
  scapy: { available: boolean; version?: string; error?: string; hint?: string };
  npcap: {
    available: boolean | null;
    driver_files?: string[];
    service_present?: boolean;
    service_state?: string | null;
    hint?: string;
    note?: string;
  };
  raw_socket: { available: boolean; error?: string; hint?: string };
  monitor_mode: { supported: boolean | null; determinable: boolean; reason?: string; note?: string };
  interfaces: { name: string; description?: string | null; mac?: string | null }[];
  features: Record<string, FeatureCapability>;
  unavailable_features: string[];
  summary: string;
}

/**
 * The scenario behind a simulated survey (`simulation_started` event).
 *
 * `route_has_turn` is here because it decides whether the rehearsal is worth
 * anything: a straight route is mirror-ambiguous, so the localizer cannot tell
 * which side of the road an access point is on, and a scenario that lost its
 * turn would quietly rehearse the estimator at its worst.
 */
export interface SimulationScenario {
  simulated: true;
  origin: { latitude: number; longitude: number };
  route_m: [number, number][];
  route_length_m: number;
  route_has_turn: boolean;
  speed_kmh: number;
  ap_count: number;
  radio_model: {
    reference_dbm_at_1m: number;
    reference_frequency_mhz: number;
    path_loss_exponent: number;
    shadowing_sigma_db: number;
    note: string;
  };
  aps: { bssid: string; ssid: string; encryption: string; frequency: number; note: string }[];
}

/**
 * Which network this machine is actually on (`net_context` event).
 *
 * This is the only place an IP can honestly be attached to an access point. A
 * beacon frame is layer 2 and carries no address, so for every AP except the
 * associated one there is nothing to show.
 *
 * `gateway_is_ap` is deliberately nullable and has three meanings:
 *   true  — the gateway answers on the BSSID we are associated with, so this
 *           access point *is* the gateway.
 *   false — we reach the gateway through this AP, but it answers on a different
 *           MAC. Normal for a bridged router or an enterprise deployment.
 *   null  — it could not be determined; nothing is claimed.
 */
export interface NetContext {
  connected: boolean;
  ssid: string | null;
  bssid: string | null;
  auth_type: string | null;
  cipher: string | null;
  radio_type: string | null;
  channel: number | null;
  rssi: number | null;
  rx_mbps: string | null;
  tx_mbps: string | null;
  interface: string | null;
  local_ip: string | null;
  subnet: string | null;
  gateway_ip: string | null;
  gateway_mac: string | null;
  gateway_is_ap: boolean | null;
  note: string;
  error?: string;
}

/** Provenance and age of the CVE data (`cve_info` / `cve_update_complete`). */
export interface CveInfo {
  /**
   * `snapshot+seed` is the normal state after an update: a downloaded snapshot is
   * merged *over* the built-in seed rather than replacing it, because replacing
   * it dropped 14 of the seed's 23 entries — Heartbleed among them — while
   * reporting the data as current.
   */
  origin: 'snapshot+seed' | 'snapshot' | 'builtin';
  source: string;
  generated_at: string | null;
  age_days: number | null;
  stale: boolean;
  entry_count: number;
  product_count?: number;
  tracked_products?: string[];
  stale_after_days?: number;
  /**
   * What the update could not establish. A product that came back empty is
   * indistinguishable, from the matrix alone, from one with nothing known
   * against it — so these are stated rather than inferred, and `coverage_note`
   * names them.
   */
  empty_products?: string[];
  truncated_cpes?: string[];
  unmapped_products?: string[];
  coverage_note: string;
}

/** `scope_denied` — a command the engine refused because the target was out of scope. */
export interface ScopeDenied {
  command: string;
  target: string | null;
  target_kind: string | null;
  reason: string;
  engagement_name: string | null;
  mode: string | null;
}

export interface ComPort {
  device: string;
  description: string;
}
