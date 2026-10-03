/** Database model types — mirrors SQLite schema */

export interface Mission {
  id: string;
  name: string;
  description?: string;
  start_time: string;
  end_time?: string;
  status: 'ACTIVE' | 'COMPLETED' | 'SYNCED';
  operator?: string;
  vehicle_id?: string;
  created_at: string;
  total_aps?: number;
  high_risk_aps?: number;
  /** 1 when the mission was run against the hardware simulator. */
  is_simulated?: number;
}

export interface AccessPoint {
  bssid: string;
  ssid?: string;
  vendor?: string;
  encryption: string;
  /**
   * Pairwise cipher (CCMP, TKIP, None) and the full authentication string
   * (e.g. "WPA3-Personal").
   *
   * Both were declared here, in the database and in the engine schema while
   * nothing ever populated them: PyWiFi's Windows backend reports cipher as
   * NONE for every network. They are now filled from `netsh wlan show
   * networks`, which is also why encryption finally distinguishes WPA3 from
   * WPA2 — PyWiFi reported a WPA3-Personal AP as WPA2.
   */
  cipher?: string;
  auth_type?: string;
  is_vulnerable: boolean;
  /**
   * Set from the engine's rogue-AP scoring, which only raises it at LIKELY or
   * above. Do not recompute this on the frontend — a weaker local heuristic
   * overwriting the engine's verdict is how a legitimate WPA3 transition
   * deployment used to get labelled an evil twin.
   */
  is_evil_twin?: boolean;
  /** CLEAR | SUSPECTED | LIKELY | CONFIRMED */
  rogue_verdict?: 'CLEAR' | 'SUSPECTED' | 'LIKELY' | 'CONFIRMED';
  rogue_score?: number;
  /** The reasons behind the verdict. This is what makes the finding actionable. */
  rogue_indicators?: { code: string; weight: number; detail: string }[];
  /**
   * WPS is a three-state field, and `wps_scanned_at` is what makes it one.
   *
   * `wps_enabled` is stored as `INTEGER NOT NULL DEFAULT 0`, so a false there is
   * the column default for every access point ever inserted and means nothing on
   * its own. Only when `wps_scanned_at` is set has a `scan_wps` run parsed this
   * access point's beacon, and only then is `wps_enabled` an observation —
   * including when it is false. Absent means no WPS scan has ever covered it.
   */
  wps_enabled?: boolean;
  wps_locked?: boolean;
  wps_version?: string | null;
  /** ISO-8601 time a WPS scan parsed this AP's beacon. Absent = never measured. */
  wps_scanned_at?: string | null;
  channel?: number;
  frequency?: number;
  band?: '2.4G' | '5G' | '6G';
  rssi?: number;
  /** NEW | RISING | PEAK | STABLE | FALLING — which way the signal is moving. */
  rssi_trend?: 'NEW' | 'RISING' | 'PEAK' | 'STABLE' | 'FALLING';
  /**
   * 802.11 generation as the driver reports it (802.11ac, 802.11ax, ...).
   * From `netsh wlan show networks`; absent off Windows.
   */
  radio_type?: string;
  /**
   * Stations currently associated, when the AP advertises BSS Load. Absent is
   * NOT zero: "no clients" and "this AP does not publish a client count" are
   * different findings, so only a real number is ever shown.
   */
  connected_stations?: number | null;
  /** Airtime the channel is using, percent, from the same BSS Load element. */
  channel_utilization_pct?: number | null;
  latitude?: number;
  longitude?: number;
  /** Which estimator produced latitude/longitude — 'gpr' wins over recomputation. */
  location_method?: 'gpr' | 'bayesian_grid' | 'trilateration' | 'weighted_centroid' | 'peak_rssi';
  /**
   * Display figure derived from location_error_m, not a probability. The
   * mapping is documented in localization.ts and printed in the report.
   */
  location_confidence?: number | null;
  /**
   * False when no estimator could run because the receiver never moved far
   * enough, and the coordinate marks where it stood rather than where the
   * transmitter is. Absent or true means a position was actually estimated.
   */
  location_resolved?: boolean;
  /** Radius in metres containing roughly 95% of the posterior mass. */
  location_error_m?: number | null;
  /**
   * Spread about the chosen position alone. When the route was straight the
   * posterior is bimodal — tight around each of two positions far apart — and a
   * single number cannot describe that honestly, so both are kept.
   */
  location_mode_error_m?: number | null;
  /** The equally good position on the other side of the line of travel. */
  location_mirror_lat?: number | null;
  location_mirror_lon?: number | null;
  location_mirror_distance_m?: number | null;
  /** Route geometry at the time of the estimate. */
  geometry_cross_track_m?: number | null;
  geometry_along_track_m?: number | null;
  /** 1 when the route was too straight to tell which side the AP is on. */
  geometry_ambiguous?: number | null;
  /** JSON array of caveats attached to this estimate. */
  location_notes?: string | null;
  /**
   * True when this sighting came from the hardware simulator rather than a real
   * radio. Set by the engine, persisted as access_points.is_simulated, and
   * stamped onto any report built from it.
   */
  simulated?: boolean;
  is_simulated?: number;
  first_seen: string;
  last_seen: string;
}

export interface ScanLog {
  id: number;
  mission_id: string;
  bssid: string;
  timestamp: string;
  rssi: number;
  channel?: number;
  frequency?: number;
  latitude?: number;
  longitude?: number;
  altitude?: number;
  speed?: number;
  hdop?: number;
  satellites?: number;
  is_simulated?: number;
}

export interface VulnerabilityResult {
  id: number;
  bssid: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  summary?: string;
  created_at: string;
}

export type RiskLevel = VulnerabilityResult['risk_level'];
