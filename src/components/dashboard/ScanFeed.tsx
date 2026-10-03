import { useState } from 'react';
import { encryptionBadgeClasses, encryptionBadgeTitle } from '../../lib/severityStyle';
import { motion, AnimatePresence } from 'framer-motion';
import { StatusBadge } from '../common/StatusBadge';
import type { AccessPoint } from '../../types/models';
import { useMissionStore } from '../../stores/missionStore';
import { useEngineStore } from '../../stores/engineStore';
import { useUIStore } from '../../stores/uiStore';
import { rssiToDistanceM } from '../../lib/localization';
import { signalBars, signalTextClass } from '../../lib/signalStyle';
import { isHighRiskAp } from '../../lib/apRisk';
import { finiteNumber } from '../../lib/numbers';

/*
  The bands live in `src/lib/signalStyle.ts`. They used to be defined here and in
  four other places with three different threshold sets, so the same -65 dBm
  reading was "fair" on this screen and "good" in the archive table.
*/
const getSignalColor = signalTextClass;
const getSignalBars = signalBars;

function SignalIcon({ rssi }: { rssi: number }) {
  const bars = getSignalBars(rssi);
  const color = getSignalColor(rssi);
  return (
    <div className={`flex items-end gap-px h-4 ${color}`}>
      {[1, 2, 3, 4].map((i) => (
        <div
          key={i}
          className={`w-1 rounded-full transition-all ${
            i <= bars ? 'bg-current' : 'bg-space-600'
          }`}
          style={{ height: `${i * 25}%` }}
        />
      ))}
    </div>
  );
}

interface FeedEntry {
  ap: AccessPoint;
  /**
   * The reading, or null when there is not one.
   *
   * It was `ap.rssi || -90`, which put a fabricated -90 dBm on every row for a
   * radio heard without a usable reading -- and `||` is worse than `??` here,
   * because it discards a genuine 0 as well. The same substitution was fixed in
   * the map popup, where its comment calls it "the display-side twin of the
   * `rssi ?? -90` write bug the signal-band tests exist to hold"; the feed kept
   * it, and the feed is the list an operator actually reads.
   *
   * It is not only a label. This value sorts the list, so an unmeasured radio was
   * ranked among the weakest signals rather than held apart from them.
   */
  rssi: number | null;
  timestamp: string;
}


/** BSSIDs arrive from PyWiFi with a trailing colon; netsh's do not. */
function sameBssid(a?: string | null, b?: string | null): boolean {
  const clean = (v?: string | null) =>
    (v || '').toUpperCase().replace(/[^0-9A-F]/g, '');
  const ca = clean(a);
  return ca.length === 12 && ca === clean(b);
}

/** Compact "how long ago", for the first/last-seen column. */
function ago(iso?: string): string {
  if (!iso) return '—';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '—';
  const secs = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h`;
  return `${Math.round(secs / 86400)}d`;
}

const TREND_STYLE: Record<string, { glyph: string; className: string }> = {
  RISING: { glyph: '▲', className: 'text-signal-good' },
  PEAK: { glyph: '◆', className: 'text-signal-strong' },
  FALLING: { glyph: '▼', className: 'text-signal-weak' },
  STABLE: { glyph: '■', className: 'text-gray-600' },
  NEW: { glyph: '＋', className: 'text-neon-400' },
};

export function ScanFeed() {
  const accessPoints = useMissionStore((s) => s.accessPoints);
  const scanning = useEngineStore((s) => s.scanning);
  const selectedBssid = useUIStore((s) => s.selectedBssid);
  const setSelectedBssid = useUIStore((s) => s.setSelectedBssid);
  const feedFullscreen = useUIStore((s) => s.dashboardFocus === 'feed');
  const toggleDashboardFocus = useUIStore((s) => s.toggleDashboardFocus);
  const netContext = useEngineStore((s) => s.netContext);
  
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState({
    bands: [] as string[],
    security: [] as string[],
    flags: [] as string[]
  });

  const activeFilterCount = filters.bands.length + filters.security.length + filters.flags.length;

  const toggleFilter = (category: keyof typeof filters, value: string) => {
    setFilters(prev => {
      const current = prev[category];
      if (current.includes(value)) {
        return { ...prev, [category]: current.filter(v => v !== value) };
      } else {
        return { ...prev, [category]: [...current, value] };
      }
    });
  };

  const clearFilters = () => setFilters({ bands: [], security: [], flags: [] });

  const rawEntries: FeedEntry[] = Array.from(accessPoints.values()).map((ap) => ({
    ap,
    rssi: finiteNumber(ap.rssi),
    timestamp: ap.last_seen,
  }));

  const entries = rawEntries.filter(entry => {
    if (filters.bands.length > 0 && !filters.bands.includes(entry.ap.band || '2.4G')) return false;
    if (filters.security.length > 0 && !filters.security.includes(entry.ap.encryption || 'OPEN')) return false;
    /*
      The rule set decides what HIGH RISK means, not this filter.

      It asked `is_vulnerable`, a boolean the engine sets from its own checks, and
      that is a different question from the one the map and the report answer. A
      WEP network the rule set rates CRITICAL without the engine having set that
      flag was a red dot on the map, a red row in the document, and **not in this
      list** when the operator filtered for the radios worth looking at.

      `wps_enabled` and `is_evil_twin` below stay as they are: those filters name
      an observation ("show me the ones advertising WPS"), not a judgement.
    */
    if (filters.flags.includes('HIGH RISK') && !isHighRiskAp(entry.ap, !!entry.ap.simulated)) return false;
    if (filters.flags.includes('WPS') && !entry.ap.wps_enabled) return false;
    if (filters.flags.includes('EVIL TWIN') && !entry.ap.is_evil_twin) return false;
    return true;
  }).sort((a, b) => {
    /*
      Strongest first, and the ones with no reading last rather than sorted as
      though they were the weakest. "Not measured" is not a position on the scale.
    */
    if (a.rssi === null && b.rssi === null) return 0;
    if (a.rssi === null) return 1;
    if (b.rssi === null) return -1;
    return b.rssi - a.rssi;
  });


  return (
    <div className="glass-card overflow-hidden flex flex-col h-full bg-space-900 border-space-500/20">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-space-500/20 bg-space-800/30">
        <div className="flex items-center gap-2">
          {scanning ? (
            <div className="w-1.5 h-1.5 rounded-full bg-neon-500 animate-pulse-slow" />
          ) : (
            <div className="w-1.5 h-1.5 rounded-full bg-gray-600" />
          )}
          <h3 className="text-sm font-semibold text-white text-tactical tracking-wider">SCAN FEED</h3>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-gray-500 font-mono hidden sm:inline-block">{entries.length} entries</span>

          {/*
            Expand, mirroring the map's control. The feed is the panel an
            operator reads line by line during a drive — with 150+ entries the
            third of a screen it normally gets is the wrong shape for it, and
            the map already had this while the feed did not.
          */}
          <button
            onClick={() => toggleDashboardFocus('feed')}
            className="text-gray-400 hover:text-white transition-colors p-1.5 bg-space-950/80 rounded border border-space-500/30 backdrop-blur-sm hover:bg-space-800 shadow-lg"
            title={feedFullscreen ? 'Collapse Feed' : 'Expand Feed'}
          >
            {feedFullscreen ? (
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3"/></svg>
            ) : (
              <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/></svg>
            )}
          </button>

          <button 
            onClick={() => setShowFilters(!showFilters)}
            className={`group relative flex items-center gap-2 px-3 py-1.5 rounded-md border text-[10px] font-tactical tracking-widest transition-all duration-300 ${
              showFilters
                ? 'bg-space-700 border-space-400 text-white shadow-inner'
                : activeFilterCount > 0 
                  ? 'bg-neon-500/10 text-neon-400 border-neon-500/30 hover:bg-neon-500/20 hover:border-neon-500/50' 
                  : 'bg-space-800/50 text-gray-400 border-space-500/20 hover:bg-space-700 hover:text-gray-200 hover:border-space-500/40'
            }`}
          >
            {showFilters && (
              <span className="absolute -inset-px bg-gradient-to-r from-transparent via-space-400/20 to-transparent opacity-50 rounded-md pointer-events-none" />
            )}
            <svg 
              className={`w-3.5 h-3.5 transition-transform duration-300 ${showFilters ? 'rotate-90 text-neon-400' : ''}`} 
              fill="none" 
              viewBox="0 0 24 24" 
              stroke="currentColor"
            >
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 6V4m0 2a2 2 0 100 4m0-4a2 2 0 110 4m-6 8a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4m6 6v10m6-2a2 2 0 100-4m0 4a2 2 0 110-4m0 4v2m0-6V4" />
            </svg>
            <span className="relative z-10">FILTERS</span>
            {activeFilterCount > 0 && (
              <span className="relative z-10 flex items-center justify-center min-w-[16px] h-[16px] px-1 rounded-full bg-neon-500 text-space-900 font-bold text-[9px]">
                {activeFilterCount}
              </span>
            )}
          </button>
        </div>
      </div>

      {/* Filter Popover */}
      <AnimatePresence>
        {showFilters && (
          <motion.div 
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="border-b border-space-500/20 bg-space-800/80 overflow-hidden backdrop-blur-sm z-10 relative"
          >
            <div className="p-4 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-gray-500 font-tactical tracking-widest">FILTER CONFIGURATION</span>
                {activeFilterCount > 0 && (
                  <button onClick={clearFilters} className="text-[10px] text-risk-high hover:text-risk-critical font-tactical tracking-wider transition-colors">
                    CLEAR ALL
                  </button>
                )}
              </div>
              
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-5">
                {/* Band */}
                <div className="space-y-2">
                  <div className="text-[10px] text-gray-400 font-mono flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-purple-500"></span>BAND</div>
                  <div className="flex flex-wrap gap-2">
                    {['2.4G', '5G', '6G'].map(b => (
                      <button key={b} onClick={() => toggleFilter('bands', b)}
                        className={`px-2 py-1 rounded border text-[10px] font-mono transition-colors ${
                          filters.bands.includes(b) ? 'bg-purple-500/20 text-purple-300 border-purple-500/50' : 'bg-space-700/50 text-gray-500 border-space-500/30 hover:bg-space-600'
                        }`}
                      >
                        {b}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Security */}
                <div className="space-y-2">
                  <div className="text-[10px] text-gray-400 font-mono flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-neon-500"></span>SECURITY</div>
                  <div className="flex flex-wrap gap-2">
                    {['OPEN', 'WEP', 'WPA', 'WPA2', 'WPA3'].map(s => (
                      <button key={s} onClick={() => toggleFilter('security', s)}
                        className={`px-2 py-1 rounded border text-[10px] font-mono transition-colors ${
                          filters.security.includes(s) ? 'bg-neon-500/20 text-neon-300 border-neon-500/50' : 'bg-space-700/50 text-gray-500 border-space-500/30 hover:bg-space-600'
                        }`}
                      >
                        {s}
                      </button>
                    ))}
                  </div>
                </div>

                {/* Flags */}
                <div className="space-y-2">
                  <div className="text-[10px] text-gray-400 font-mono flex items-center gap-1.5"><span className="w-1.5 h-1.5 rounded-full bg-risk-high"></span>FLAGS</div>
                  <div className="flex flex-wrap gap-2">
                    {['WPS', 'HIGH RISK', 'EVIL TWIN'].map(f => (
                      <button key={f} onClick={() => toggleFilter('flags', f)}
                        className={`px-2 py-1 rounded border text-[10px] font-tactical tracking-wider transition-colors ${
                          filters.flags.includes(f) ? 'bg-risk-high/20 text-risk-high border-risk-high/50' : 'bg-space-700/50 text-gray-500 border-space-500/30 hover:bg-space-600'
                        }`}
                      >
                        {f}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Feed List */}
      <div className="flex-1 overflow-y-auto">
        {entries.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center opacity-50 p-6 text-center">
            {scanning ? (
              <>
                <svg className="w-10 h-10 text-neon-500 animate-spin-slow mb-4 opacity-50" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1">
                  <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
                </svg>
                <div className="text-sm text-neon-400 font-tactical tracking-widest animate-pulse">AWAITING SIGNALS...</div>
                <div className="text-xs text-gray-500 mt-2 font-mono">Listening for 802.11 beacon frames</div>
              </>
            ) : (
              <>
                <img src="/cat-feed.svg" alt="System Idle" className="w-16 h-16 opacity-40 mb-4" />
                <div className="text-sm text-gray-400 font-tactical tracking-wider">SYSTEM IDLE</div>
                <div className="text-xs text-gray-600 mt-2 font-mono">Start mission to discover networks</div>
              </>
            )}
          </div>
        ) : feedFullscreen ? (
          /*
            Expanded view. The compact card beside the map is the right shape
            for a glance while driving; with the whole window it can show what
            the scan already collected and used to throw away on screen —
            cipher, the 802.11 generation, how many stations are on the AP, how
            far away it is estimated to be, how long it has been up, and WHY an
            access point is flagged rather than just that it is.
          */
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 z-10 bg-space-900">
                <tr className="text-[9px] font-tactical tracking-widest text-gray-500 border-b border-space-500/30">
                  <th className="py-2 px-3 font-normal">SIGNAL</th>
                  <th className="py-2 px-3 font-normal">NETWORK</th>
                  <th className="py-2 px-3 font-normal">BSSID / VENDOR</th>
                  <th className="py-2 px-3 font-normal">SECURITY</th>
                  <th className="py-2 px-3 font-normal">RADIO</th>
                  <th className="py-2 px-3 font-normal text-right">CLIENTS</th>
                  <th className="py-2 px-3 font-normal text-right">DISTANCE</th>
                  <th className="py-2 px-3 font-normal text-right">SEEN</th>
                  <th className="py-2 px-3 font-normal">ADDRESS</th>
                  <th className="py-2 px-3 font-normal">ASSESSMENT</th>
                </tr>
              </thead>
              <tbody>
                {entries.slice(0, 300).map((entry) => {
                  const ap = entry.ap;
                  const trend = TREND_STYLE[ap.rssi_trend || ''] ?? null;
                  const isConnected = sameBssid(ap.bssid, netContext?.bssid);
                  // Distance from the path-loss model the localizer inverts.
                  // Rounded hard: this is a rule of thumb from one reading, not
                  // a measurement, and decimals would imply precision it has not
                  // got. The tolerance comes from the position estimate when one exists.
                  const distance = ap.rssi != null
                    ? Math.round(rssiToDistanceM(ap.rssi, ap.frequency))
                    : null;
                  return (
                    <tr
                      key={ap.bssid}
                      onClick={() => setSelectedBssid(ap.bssid)}
                      className={`border-b border-space-500/10 cursor-pointer align-top transition-colors ${
                        selectedBssid === ap.bssid ? 'bg-space-600/40' : 'hover:bg-space-700/25'
                      }`}
                    >
                      <td className="py-2 px-3">
                        <div className="flex items-center gap-2">
                          <SignalIcon rssi={entry.rssi ?? -100} />
                          <span className={`font-mono text-xs ${entry.rssi === null ? 'text-gray-600' : getSignalColor(entry.rssi)}`}>
                            {entry.rssi === null ? 'n/r' : entry.rssi}
                          </span>
                          {trend && (
                            <span className={`text-[10px] ${trend.className}`} title={ap.rssi_trend}>
                              {trend.glyph}
                            </span>
                          )}
                        </div>
                      </td>

                      <td className="py-2 px-3">
                        <div className="flex items-center gap-2">
                          <span className={`text-xs font-semibold truncate max-w-[180px] ${isHighRiskAp(ap, !!ap.simulated) ? 'text-risk-high' : 'text-gray-200'}`}>
                            {ap.ssid || '(Hidden)'}
                          </span>
                          {ap.simulated && (
                            <span className="px-1 py-0.5 rounded bg-amber-500/15 text-amber-400 border border-amber-500/40 text-[8px] font-tactical">SIM</span>
                          )}
                          {isConnected && (
                            <span className="px-1 py-0.5 rounded bg-signal-strong/15 text-signal-strong border border-signal-strong/40 text-[8px] font-tactical">JOINED</span>
                          )}
                        </div>
                      </td>

                      <td className="py-2 px-3">
                        <div className="text-[10px] font-mono text-gray-400">{ap.bssid}</div>
                        <div className="text-[10px] text-gray-600 truncate max-w-[170px]">{ap.vendor || '—'}</div>
                      </td>

                      <td className="py-2 px-3">
                        <div className="flex items-center gap-1.5">
                          <span
                            title={encryptionBadgeTitle(ap.encryption)}
                            className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${encryptionBadgeClasses(ap.encryption)}`}
                          >
                            {ap.encryption}
                          </span>
                          {ap.wps_enabled && (
                            <span className={`text-[8px] font-tactical px-1 py-0.5 rounded border ${
                              ap.wps_locked
                                ? 'bg-space-700 text-gray-400 border-space-500/40'
                                : 'bg-risk-high/15 text-risk-high border-risk-high/40'
                            }`}>
                              {ap.wps_locked ? 'WPS LOCKED' : 'WPS'}
                            </span>
                          )}
                        </div>
                        <div className="text-[10px] text-gray-600 mt-0.5 truncate max-w-[170px]">
                          {ap.auth_type || '—'}{ap.cipher ? ` / ${ap.cipher}` : ''}
                        </div>
                      </td>

                      <td className="py-2 px-3">
                        <div className="text-[10px] font-mono text-gray-400">
                          {ap.band || '—'}{ap.channel != null ? ` · ch ${ap.channel}` : ''}
                        </div>
                        <div className="text-[10px] text-gray-600">{ap.radio_type || '—'}</div>
                      </td>

                      <td className="py-2 px-3 text-right">
                        {/* Absent is not zero: an AP that does not advertise BSS
                            Load has no client count, which is not the same
                            finding as an AP with nobody on it. */}
                        <div className="text-xs font-mono text-gray-300">
                          {ap.connected_stations != null ? ap.connected_stations : '—'}
                        </div>
                        {ap.channel_utilization_pct != null && (
                          <div className="text-[9px] font-mono text-gray-600">{ap.channel_utilization_pct}% air</div>
                        )}
                      </td>

                      <td className="py-2 px-3 text-right">
                        <div className="text-xs font-mono text-gray-300">
                          {distance != null ? `~${distance} m` : '—'}
                        </div>
                        {ap.location_error_m != null && (
                          <div className="text-[9px] font-mono text-gray-600">±{Math.round(ap.location_error_m)} m fix</div>
                        )}
                      </td>

                      <td className="py-2 px-3 text-right">
                        <div className="text-[10px] font-mono text-gray-400">{ago(ap.last_seen)} ago</div>
                        <div className="text-[9px] font-mono text-gray-600">first {ago(ap.first_seen)}</div>
                      </td>

                      <td className="py-2 px-3">
                        {/*
                          The only access point an IP can honestly be attached
                          to is the one this machine is associated with. A beacon
                          frame is layer 2 and carries no address, so every other
                          row says so instead of showing a blank that reads like
                          missing data.
                        */}
                        {isConnected && netContext ? (
                          <>
                            <div className="text-[10px] font-mono text-signal-strong">
                              {netContext.gateway_ip ? `gw ${netContext.gateway_ip}` : 'no default route'}
                            </div>
                            <div className="text-[9px] font-mono text-gray-600">
                              {netContext.subnet || '—'}
                              {netContext.gateway_is_ap === true && ' · this AP'}
                              {netContext.gateway_is_ap === false && ' · via this AP'}
                            </div>
                          </>
                        ) : (
                          <span className="text-[10px] font-mono text-gray-700" title="A Wi-Fi scan reads layer 2 beacons, which carry no IP address. Only the network this machine has joined has one.">
                            not on this network
                          </span>
                        )}
                      </td>

                      <td className="py-2 px-3">
                        <div className="flex items-center gap-2">
                          {ap.is_evil_twin && (
                            <span className="px-1.5 py-0.5 bg-risk-critical/20 text-risk-critical border border-risk-critical/50 text-[9px] font-tactical rounded">EVIL TWIN</span>
                          )}
                          {ap.rogue_verdict && ap.rogue_verdict !== 'CLEAR' && !ap.is_evil_twin && (
                            <span className="px-1.5 py-0.5 bg-risk-high/15 text-risk-high border border-risk-high/40 text-[9px] font-tactical rounded">
                              {ap.rogue_verdict}
                            </span>
                          )}
                          {isHighRiskAp(ap, !!ap.simulated) && !ap.is_evil_twin && <StatusBadge level="HIGH" label="RISK" />}
                          {ap.rogue_score != null && ap.rogue_score > 0 && (
                            <span className="text-[9px] font-mono text-gray-600">score {ap.rogue_score}</span>
                          )}
                        </div>
                        {/*
                          The reasons, not just the verdict. The engine already
                          computes these; the compact view could only show an
                          orange chip, which tells the operator something is
                          wrong but nothing they can act on or write down.
                        */}
                        {ap.rogue_indicators && ap.rogue_indicators.length > 0 && (
                          <div className="text-[9px] font-mono text-gray-500 mt-0.5 leading-snug max-w-[340px]">
                            {ap.rogue_indicators.map(i => i.code.replace(/_/g, ' ')).join(' · ')}
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {entries.slice(0, 100).map((entry) => (
            <motion.div
              key={entry.ap.bssid}
              onClick={() => setSelectedBssid(entry.ap.bssid)}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -20 }}
              transition={{ duration: 0.2 }}
              className={`flex items-center gap-3 px-4 py-2.5 border-b border-space-500/10 cursor-pointer transition-colors ${
                selectedBssid === entry.ap.bssid ? 'bg-space-600/50' : 'hover:bg-space-700/30'
              }`}
            >
              {/* The icon has no "unknown" state, so an absent reading is drawn at the
                  floor -- but the figure beside it says `n/r` rather than a number,
                  which is where the claim is made. */}
              <SignalIcon rssi={entry.rssi ?? -100} />

              {/* AP Info */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className={`font-semibold truncate text-sm sm:text-base ${isHighRiskAp(entry.ap, !!entry.ap.simulated) ? 'text-risk-high' : 'text-gray-200'}`}>
                    {entry.ap.ssid || '(Hidden)'}
                  </span>
                  {entry.ap.is_evil_twin && (
                    <span className="px-2 py-0.5 bg-risk-critical/20 text-risk-critical border border-risk-critical/50 text-[10px] font-tactical rounded animate-pulse">EVIL TWIN</span>
                  )}
                  {isHighRiskAp(entry.ap, !!entry.ap.simulated) && !entry.ap.is_evil_twin && (
                    <StatusBadge level="HIGH" label="RISK" />
                  )}
                </div>
                <div className="flex items-center gap-2 mt-0.5">
                  <span className="text-[11px] text-gray-500 font-mono">{entry.ap.bssid}</span>
                  {entry.ap.vendor && (
                    <>
                      <span className="text-[11px] text-gray-600">•</span>
                      <span className="text-[11px] text-gray-500 truncate max-w-[120px] sm:max-w-none">{entry.ap.vendor}</span>
                    </>
                  )}
                </div>
              </div>

              {/* Right Side Info Group */}
              <div className="flex flex-col items-end gap-1 shrink-0 ml-2">
                <div className="flex items-center gap-1.5">
                  {/* Encryption Badge */}
                  <span
                    title={encryptionBadgeTitle(entry.ap.encryption)}
                    className={`text-[10px] sm:text-xs font-mono px-2 py-0.5 rounded ${encryptionBadgeClasses(entry.ap.encryption)}`}
                  >
                    {entry.ap.encryption}
                  </span>

                  {/* WPS Badge */}
                  {entry.ap.wps_enabled && (
                    <span className={`text-[9px] font-tactical tracking-wider px-1.5 py-0.5 rounded border ${
                      entry.ap.wps_locked
                        ? 'bg-risk-high/15 text-risk-high border-risk-high/30'
                        : 'bg-signal-strong/15 text-signal-strong border-signal-strong/30 animate-pulse'
                    }`}>
                      WPS{entry.ap.wps_locked ? ' 🔒' : ''}
                    </span>
                  )}

                  {/* Band Badge */}
                  {entry.ap.band && (
                    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border ${
                      entry.ap.band === '5G' ? 'bg-purple-500/15 text-purple-400 border-purple-500/30'
                      : entry.ap.band === '6G' ? 'bg-pink-500/15 text-pink-400 border-pink-500/30'
                      : 'bg-space-600/30 text-gray-500 border-space-500/20'
                    }`}>
                      {entry.ap.band}
                    </span>
                  )}
                </div>

                {/* RSSI */}
                <div className={`text-sm font-tech tabular-nums tracking-wider ${
                  entry.rssi === null ? 'text-gray-600' : getSignalColor(entry.rssi)
                }`}>
                  {entry.rssi === null ? 'n/r' : `${entry.rssi} dBm`}
                </div>
              </div>
            </motion.div>
          ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}
