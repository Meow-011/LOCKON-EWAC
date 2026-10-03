import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { engineIPC } from '../../lib/ipc';
import { useEngineStore } from '../../stores/engineStore';
import { usePassiveSigintStore } from '../../stores/passiveSigintStore';

/**
 * Shapes as the engine actually emits them.
 *
 * These used to declare `vendor`, `os` and `protocol`, none of which the engine
 * sends — so the vendor column read "Unknown" for every host, the protocol cell
 * rendered empty, and vendor search never matched anything. The engine's own
 * field is `source` (ARP / DHCP / DNS), which is what "protocol" meant, plus a
 * `detail` string that was never displayed at all.
 */
interface PassiveHost {
  ip: string;
  mac: string;
  hostname: string | null;
  source: string;
  detail?: string | null;
  is_new?: boolean;
  /** ISO string from the engine, not a number. */
  timestamp: string;
}

interface ProbeRequest {
  client_mac: string;
  ssid: string;
  is_new_client?: boolean;
  total_ssids?: number;
  probe_count?: number;
  timestamp: string;
}

export function PassiveSigintView() {
  // Persistent state (survives navigation)
  const isActive = usePassiveSigintStore(s => s.isActive);
  const passiveHosts = usePassiveSigintStore(s => s.passiveHosts);
  const probeRequests = usePassiveSigintStore(s => s.probeRequests);
  const startTime = usePassiveSigintStore(s => s.startTime);
  const feedStats = usePassiveSigintStore(s => s.feedStats);
  const applyProbeSummary = usePassiveSigintStore(s => s.applyProbeSummary);
  const applyPassiveSummary = usePassiveSigintStore(s => s.applyPassiveSummary);
  const setActive = usePassiveSigintStore(s => s.setActive);
  const addPassiveHost = usePassiveSigintStore(s => s.addPassiveHost);
  const addProbeRequest = usePassiveSigintStore(s => s.addProbeRequest);
  const clearHosts = usePassiveSigintStore(s => s.clearHosts);
  const clearProbes = usePassiveSigintStore(s => s.clearProbes);
  const setStartTime = usePassiveSigintStore(s => s.setStartTime);

  // Local-only UI state
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  // Selector rather than the whole store: this component re-rendered on every
  // 2s status poll and every GPS tick otherwise.
  const config = useEngineStore(s => s.config);
  
  // UX State
  const [probeViewMode, setProbeViewMode] = useState<'RAW' | 'GROUPED'>('RAW');
  const [hostPps, setHostPps] = useState<number[]>(new Array(20).fill(0));
  const [probePps, setProbePps] = useState<number[]>(new Array(20).fill(0));
  
  // Search & Time States
  const [hostSearch, setHostSearch] = useState('');
  const [probeSearch, setProbeSearch] = useState('');
  const [durationMs, setDurationMs] = useState(0);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  
  const ppsRefs = useRef({ hosts: 0, probes: 0 });

  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // Passive Host Events
    const unsubPassiveHost = engineIPC.on('passive_host', (msg) => {
      if (msg.data) {
        ppsRefs.current.hosts++;
        const host = msg.data as unknown as PassiveHost;
        addPassiveHost(host);
      }
    });

    // Probe Request Events
    const unsubProbe = engineIPC.on('probe_detected', (msg) => {
      if (msg.data) {
        ppsRefs.current.probes++;
        const probe = msg.data as unknown as ProbeRequest;
        addProbeRequest(probe);
      }
    });

    // Sparkline Updater.
    // This used to read `isActive` from the first render's closure ([] deps), so
    // the guard was permanently false and both sparklines stayed flat no matter
    // how much traffic arrived. Read the live value from the store instead.
    const ppsTimer = setInterval(() => {
      if (usePassiveSigintStore.getState().isActive) {
        setHostPps(prev => [...prev.slice(1), ppsRefs.current.hosts]);
        setProbePps(prev => [...prev.slice(1), ppsRefs.current.probes]);
      }
      ppsRefs.current = { hosts: 0, probes: 0 };
    }, 1000);

    // The engine emits `passive_error`, not `passive_monitor_error`. The old name
    // matched nothing, so a missing Npcap or a failed sniff never reached the UI
    // and this panel stayed "ACTIVE" with a running timer forever.
    const unsubErrorP = engineIPC.on('passive_error', (msg: any) => {
      setErrorMsg(`Passive Error: ${msg.data?.message ?? 'unknown'}`);
    });

    const unsubErrorW = engineIPC.on('probe_monitor_error', (msg: any) => {
      setErrorMsg(`Probe Error: ${msg.data?.message ?? 'unknown'}`);
    });

    // The engine guarantees a terminal *_stopped event on every exit path, so
    // clearing the active flag there covers errors, timeouts and cancellation
    // alike — no local timeout needed.
    /*
      The authoritative counts.

      `probe_detected` fires only when a client or an SSID is new, so a device
      probing five hundred times for one network emits once and the PROBES figure
      on screen stays at whatever it was then. `passive_host` is rate limited per
      host for the same reason. Both summaries are pull-only commands the engine
      has always offered and nothing ever sent.
    */
    const unsubProbeSummary = engineIPC.on('probe_summary', (msg) => {
      const d = msg.data as any;
      applyProbeSummary(Array.isArray(d?.clients) ? d.clients : []);
    });
    const unsubPassiveSummary = engineIPC.on('passive_summary', (msg) => {
      const d = msg.data as any;
      const feed = d?.feed;
      applyPassiveSummary(
        feed && typeof feed.suppressed_repeat_events === 'number'
          ? { suppressed_repeat_events: feed.suppressed_repeat_events,
              min_interval_seconds: Number(feed.min_interval_seconds) || 0 }
          : null
      );
    });

    const unsubPassiveStopped = engineIPC.on('passive_stopped', () => setActive(false));
    const unsubProbeStopped = engineIPC.on('probe_monitor_stopped', () => setActive(false));

    return () => {
      clearInterval(ppsTimer);
      unsubPassiveHost();
      unsubProbe();
      unsubErrorP();
      unsubErrorW();
      unsubProbeSummary();
      unsubPassiveSummary();
      unsubPassiveStopped();
      unsubProbeStopped();
    };
  }, [addPassiveHost, addProbeRequest, setActive, applyProbeSummary, applyPassiveSummary]);

  /*
    Ask for the authoritative counts while the capture runs, and once after it
    stops.

    Every 15 seconds: the engine's own per-host rate limit is the interval these
    counts drift against, so polling much faster would ask for an answer that has
    not changed, and much slower would leave an understated figure on screen for
    longer than the operator takes to read it.

    A failure is deliberately silent. This is a correction to numbers that are
    already displayed, not a measurement of its own, and a toast every fifteen
    seconds because the sidecar is reconnecting would train the operator to
    ignore the toasts that matter.
  */
  useEffect(() => {
    if (!isActive) return;
    const ask = () => {
      engineIPC.send('get_probe_summary').catch(() => {});
      engineIPC.send('get_passive_summary').catch(() => {});
    };
    ask();
    const t = setInterval(ask, 15000);
    return () => clearInterval(t);
  }, [isActive]);

  // Timer Effect
  useEffect(() => {
    let interval: ReturnType<typeof setInterval>;
    if (isActive && startTime) {
      interval = setInterval(() => {
        setDurationMs(Date.now() - startTime);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [isActive, startTime]);

  const formatTime = (ms: number) => {
    const totalSeconds = Math.floor(ms / 1000);
    const h = Math.floor(totalSeconds / 3600).toString().padStart(2, '0');
    const m = Math.floor((totalSeconds % 3600) / 60).toString().padStart(2, '0');
    const s = (totalSeconds % 60).toString().padStart(2, '0');
    return `${h}:${m}:${s}`;
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const toggleSigint = async () => {
    if (isActive) {
      // Asked before the stop, so the final figures on screen are the engine's
      // and not whatever the last event happened to carry.
      engineIPC.send('get_probe_summary').catch(() => {});
      engineIPC.send('get_passive_summary').catch(() => {});
      engineIPC.send('stop_passive').catch(console.error);
      engineIPC.send('stop_probe_monitor').catch(console.error);
      setActive(false);
    } else {
      setErrorMsg(null);
      clearHosts();
      clearProbes();
      setHostPps(new Array(20).fill(0));
      setProbePps(new Array(20).fill(0));
      setStartTime(Date.now());
      setDurationMs(0);
      // The interface was never sent, so the engine picked a default adapter
      // even though the operator had selected one — on a multi-adapter rig that
      // silently listened on the wrong NIC. The header already claims to show
      // which interface is in use.
      const iface = config.interfaceName || undefined;
      /*
        ACTIVE only if the engine actually took the command.

        `send` rejects when the sidecar is not attached — `throw new Error('Engine not
        connected')` when `child` is null — which is the state during the reconnect
        backoff. Both rejections went to `console.error` and `setActive(true)` ran
        anyway, so the panel showed ACTIVE, ran the mission timer and displayed
        "Awaiting Broadcast Traffic..." while nothing was recording and nothing on the
        engine side could ever emit `passive_stopped` to undo it. `setErrorMsg(null)`
        above had already cleared the one row that might have said so.
      */
      try {
        await engineIPC.send('start_passive', { duration: null, interface: iface });
        await engineIPC.send('start_probe_monitor', { interface: iface });
      } catch (err) {
        console.error('[Passive SIGINT] start failed:', err);
        setErrorMsg(
          `Could not start passive capture: ${err instanceof Error ? err.message : String(err)}. `
          + 'Nothing is being recorded.'
        );
        setStartTime(null);
        return;
      }
      setActive(true);
    }
  };

  const HIGH_VALUE_SSIDS = ['truewifi', 'ais', 'dtac', 'guest', 'free', 'airport', 'hotel', 'public', 'starbucks', 'cafe'];
  const isHighValue = (ssid: string) => HIGH_VALUE_SSIDS.some(h => ssid.toLowerCase().includes(h));

  /**
   * Icon for how a host was discovered.
   *
   * This used to be a vendor/OS icon fed from fields the engine never sends, so
   * it always fell through to the generic box. The discovery source is real
   * information the engine does provide, so show that instead of guessing at a
   * device type we have no data for.
   */
  const getSourceIcon = (source: string) => {
    const s = (source || '').toLowerCase();
    if (s.includes('arp')) {
      // Link-layer presence
      return <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 shrink-0 text-neon-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12h14M5 12l4-4M5 12l4 4M19 12l-4-4M19 12l-4 4"/></svg>;
    }
    if (s.includes('dhcp')) {
      return <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 shrink-0 text-risk-high" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M4 7h16M4 12h16M4 17h10"/></svg>;
    }
    if (s.includes('dns') || s.includes('mdns')) {
      return <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 shrink-0 text-blue-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 3 2.5 15 0 18M12 3c-2.5 3-2.5 15 0 18"/></svg>;
    }
    return <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 shrink-0 opacity-50" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="4" y="4" width="16" height="16" rx="2" ry="2"/><rect x="9" y="9" width="6" height="6"/></svg>;
  };


  // Search covers what the engine actually sends: address, name, and the
  // discovery source (ARP / DHCP / DNS) plus its detail string.
  const filteredHosts = passiveHosts.filter(h =>
    h.ip.includes(hostSearch) ||
    h.mac.toLowerCase().includes(hostSearch.toLowerCase()) ||
    (h.source || '').toLowerCase().includes(hostSearch.toLowerCase()) ||
    (h.detail || '').toLowerCase().includes(hostSearch.toLowerCase()) ||
    (h.hostname || '').toLowerCase().includes(hostSearch.toLowerCase())
  );

  const filteredProbes = probeRequests.filter(p =>
    p.client_mac.toLowerCase().includes(probeSearch.toLowerCase()) ||
    (p.ssid || '').toLowerCase().includes(probeSearch.toLowerCase())
  );

  const groupedProbes = filteredProbes.reduce((acc, probe) => {
    const existing = acc.find(p => p.client_mac === probe.client_mac);
    if (existing) {
      if (!existing.ssids.includes(probe.ssid) && probe.ssid) {
        existing.ssids.push(probe.ssid);
      }
      // ISO strings compare correctly lexicographically, so keep the later one.
      if (probe.timestamp > existing.timestamp) existing.timestamp = probe.timestamp;
    } else {
      acc.push({ ...probe, ssids: probe.ssid ? [probe.ssid] : [] });
    }
    return acc;
  }, [] as (ProbeRequest & { ssids: string[] })[]);

  return (
    <div className="h-full flex flex-col min-h-0 bg-space-950/20 rounded-xl border border-space-500/20 overflow-hidden relative">
      {/* Radar Overlay Effect */}
      {isActive && (
        <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-20">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] rounded-full border border-neon-500/30"></div>
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full border border-neon-500/20"></div>
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[400px] h-[400px] rounded-full border border-neon-500/10 animate-[spin_4s_linear_infinite] border-t-neon-500"></div>
        </div>
      )}

      {/* Header Controls */}
      <div className="flex-none p-4 border-b border-space-500/20 bg-space-900/50 flex justify-between items-center z-10 relative">
        <div>
          <h2 className="text-sm font-tactical tracking-widest flex items-center gap-2">
            <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-neon-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M4 22h14a2 2 0 0 0 2-2V7.5L14.5 2H6a2 2 0 0 0-2 2v4"/><polyline points="14 2 14 8 20 8"/><path d="M2 15h10"/><path d="m9 18 3-3-3-3"/></svg>
            <span className="text-white">SIGNALS INTELLIGENCE</span>
            <span className="text-neon-500">_PASSIVE RADAR</span>
            {isActive && (
              <>
                <span className="ml-3 px-2 py-0.5 border border-space-500/30 bg-space-800 text-[9px] font-mono text-gray-400 rounded">
                  IFACE: {config.interfaceName || 'ALL'}
                </span>
                <span className="ml-2 px-2 py-0.5 border border-neon-500/30 bg-neon-500/10 text-[9px] font-mono text-neon-400 rounded flex items-center gap-1">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                  {formatTime(durationMs)}
                </span>
              </>
            )}
          </h2>
          <p className="text-[10px] text-gray-500 font-mono mt-1">Listening for ARP, DHCP, mDNS, and 802.11 Probe Requests</p>
        </div>
        
        <div className="flex items-center gap-4">
          {errorMsg && (
            <div className="text-[10px] font-mono text-risk-critical animate-pulse bg-risk-critical/10 px-2 py-1 rounded border border-risk-critical/30">
              {errorMsg}
            </div>
          )}
          <button
            onClick={toggleSigint}
            className={`px-6 py-2 rounded text-xs font-tactical uppercase tracking-wider transition-all border flex items-center gap-2 ${isActive
              ? 'bg-space-800 border-space-500/50 text-white hover:bg-space-700'
              : 'bg-space-900 border-space-500/50 text-gray-400 hover:bg-space-800 hover:text-white'
              }`}
          >
            {isActive ? (
              <>
                <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5 animate-spin text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0 1 18.8-4.3M22 12.5a10 10 0 0 1-18.8 4.2"/></svg>
                CEASE MONITORING
              </>
            ) : (
              <>
                <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                INITIATE SIGINT
              </>
            )}
          </button>
        </div>
      </div>

      {/* Grid Layout for Content */}
      <div className="flex-1 min-h-0 grid grid-cols-1 lg:grid-cols-2 gap-4 p-4 z-10 relative">
        
        {/* Passive Hosts Panel */}
        <div className="flex flex-col min-h-0 bg-space-950/60 border border-space-500/20 rounded-lg overflow-hidden relative">
          <div className="flex-none p-2 border-b border-space-500/20 bg-space-900/50 flex flex-col gap-2 relative">
            <div className="flex justify-between items-center">
              <h3 className="text-[10px] font-tactical text-gray-400 tracking-wider shrink-0">PASSIVE HOST DISCOVERY</h3>
              <div className="flex items-center gap-3">
                <div className="flex items-end gap-0.5 h-3 hidden sm:flex">
                  {hostPps.map((val, i) => (
                    <div key={i} className="w-1 bg-neon-500/60" style={{ height: `${Math.max(10, Math.min(100, (val / 10) * 100))}%` }} />
                  ))}
                </div>
                <span className="text-[10px] font-mono text-neon-400 bg-neon-500/10 px-1.5 py-0.5 rounded">{filteredHosts.length} DETECTED</span>
                <button onClick={() => clearHosts()} className="text-gray-500 hover:text-red-400 transition-colors p-0.5" title="Clear Stream">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                </button>
              </div>
            </div>
            <input 
              type="text" 
              value={hostSearch}
              onChange={(e) => setHostSearch(e.target.value)}
              placeholder="Filter IP, MAC, Vendor..." 
              className="bg-space-950/50 border border-space-500/20 rounded px-2 py-1 text-[10px] font-mono text-white focus:outline-none focus:border-neon-500/50 w-full"
            />
          </div>
          {/*
            How much of the feed the rate limit held back.

            `passive.get_feed_stats` exists for one stated reason -- "so a quiet
            feed is never read as a quiet network" -- and nothing asked for it.
            Every suppressed event was a repeat sighting of a host already listed,
            so no host is missing from the rows below; what was missing was any
            sense of how busy the segment is. On a link where the same dozen hosts
            chatter constantly, a still list and a dead network looked the same.
          */}
          {feedStats && feedStats.suppressed_repeat_events > 0 && (
            <div className="px-2 pb-1 text-[9px] font-mono text-gray-500 leading-relaxed">
              {feedStats.suppressed_repeat_events.toLocaleString()} repeat sighting(s) held back by the
              {feedStats.min_interval_seconds ? ` ${feedStats.min_interval_seconds}s` : ''} per-host feed
              limit. Every one was a host already listed here — the list is complete, the traffic is
              heavier than it looks.
            </div>
          )}

          <div className="flex-1 overflow-y-auto p-2 space-y-2 no-scrollbar" ref={containerRef}>
            <AnimatePresence initial={false}>
              {filteredHosts.length === 0 && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col justify-center items-center h-full text-center p-6 opacity-50">
                  <svg xmlns="http://www.w3.org/2000/svg" className={`w-10 h-10 text-gray-500 mb-4 ${isActive ? 'animate-pulse' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>
                  <div className="text-gray-300 font-tactical text-sm uppercase tracking-widest mb-1">{isActive ? 'Awaiting Broadcast Traffic...' : 'Radar Dormant'}</div>
                  <div className="text-gray-500 font-mono text-[9px] max-w-[250px] leading-relaxed">
                    Zero-Emission Reconnaissance. Captures unencrypted ARP, DHCP, and mDNS broadcasts to map active hosts completely stealthily without transmitting any packets.
                  </div>
                </motion.div>
              )}
              {filteredHosts.map((host, i) => (
                <motion.div
                  key={`${host.mac}-${i}`}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="bg-space-900 border border-space-500/20 p-2.5 rounded flex items-center justify-between"
                >
                  <div className="flex items-center gap-3">
                    <div className="text-gray-400" title={`Discovered via ${host.source || 'unknown source'}`}>
                      {getSourceIcon(host.source)}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span 
                          onClick={() => copyToClipboard(host.ip)}
                          className="text-sm font-bold text-white font-mono cursor-pointer hover:text-neon-400 transition-colors relative"
                          title="Copy IP"
                        >
                          {host.ip}
                          {copiedText === host.ip && <span className="absolute -top-4 left-0 text-[8px] text-neon-400 bg-space-900 px-1 rounded border border-neon-500/30 z-10">COPIED</span>}
                        </span>
                        <span className="text-[9px] px-1 bg-space-800 text-gray-400 rounded border border-space-500/30">
                          {host.source || '—'}
                        </span>
                        {host.is_new && (
                          <span className="text-[9px] px-1 bg-neon-500/20 text-neon-400 rounded border border-neon-500/30">NEW</span>
                        )}
                      </div>
                    <div className="text-[10px] font-mono text-gray-500 mt-1">
                      <span onClick={() => copyToClipboard(host.mac)} className="cursor-pointer hover:text-white transition-colors relative" title="Copy MAC">
                        {host.mac.toUpperCase()}
                        {copiedText === host.mac && <span className="absolute -top-4 left-0 text-[8px] text-neon-400 bg-space-900 px-1 rounded border border-neon-500/30 z-10">COPIED</span>}
                      </span>
                      {host.detail && <> — {host.detail}</>}
                    </div>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-gray-300 font-tactical truncate max-w-[120px]">{host.hostname || '—'}</div>
                    <div className="text-[9px] text-gray-600 font-mono mt-1">
                      {new Date(host.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>

        {/* Probe Requests Panel */}
        <div className="flex flex-col min-h-0 bg-space-950/60 border border-space-500/20 rounded-lg overflow-hidden relative">
          <div className="flex-none p-2 border-b border-space-500/20 bg-space-900/50 flex flex-col gap-2 relative">
            <div className="flex justify-between items-center">
              <h3 className="text-[10px] font-tactical text-gray-400 tracking-wider shrink-0">PROBE REQUESTS</h3>
              <div className="flex items-center gap-3">
                <div className="flex items-end gap-0.5 h-3 hidden sm:flex">
                  {probePps.map((val, i) => (
                    <div key={i} className="w-1 bg-amber-500/60" style={{ height: `${Math.max(10, Math.min(100, (val / 10) * 100))}%` }} />
                  ))}
                </div>
                <span className="text-[10px] font-mono text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded">{filteredProbes.length} CAPTURED</span>
                <button onClick={() => clearProbes()} className="text-gray-500 hover:text-red-400 transition-colors p-0.5" title="Clear Stream">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></svg>
                </button>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <input 
                type="text" 
                value={probeSearch}
                onChange={(e) => setProbeSearch(e.target.value)}
                placeholder="Filter MAC, SSID..." 
                className="bg-space-950/50 border border-space-500/20 rounded px-2 py-1 text-[10px] font-mono text-white focus:outline-none focus:border-amber-500/50 flex-1"
              />
              <div className="flex bg-space-950 rounded border border-space-500/30 p-0.5 shrink-0">
                <button onClick={() => setProbeViewMode('GROUPED')} className={`px-2 py-0.5 text-[9px] font-tactical rounded transition-colors ${probeViewMode === 'GROUPED' ? 'bg-space-700 text-white' : 'text-gray-500 hover:text-gray-300'}`}>GROUPED</button>
                <button onClick={() => setProbeViewMode('RAW')} className={`px-2 py-0.5 text-[9px] font-tactical rounded transition-colors ${probeViewMode === 'RAW' ? 'bg-space-700 text-white' : 'text-gray-500 hover:text-gray-300'}`}>RAW STREAM</button>
              </div>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto p-2 space-y-2 no-scrollbar">
            <AnimatePresence initial={false}>
              {filteredProbes.length === 0 && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col justify-center items-center h-full text-center p-6 opacity-50">
                  <svg xmlns="http://www.w3.org/2000/svg" className={`w-10 h-10 text-gray-500 mb-4 ${isActive ? 'animate-pulse' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round"><path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242"/><path d="M12 12v9"/><path d="m8 17 4 4 4-4"/></svg>
                  <div className="text-gray-300 font-tactical text-sm uppercase tracking-widest mb-1">{isActive ? 'Scanning for Probe Requests...' : 'Radar Dormant'}</div>
                  <div className="text-gray-500 font-mono text-[9px] max-w-[250px] leading-relaxed">
                    802.11 Client Tracking. Intercepts probe requests from nearby devices seeking past networks, exposing historical connections and physical proximity.
                  </div>
                </motion.div>
              )}
              {probeViewMode === 'RAW' ? filteredProbes.map((probe, i) => (
                <motion.div
                  key={`raw-${probe.client_mac}-${probe.timestamp}-${i}`}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className={`bg-space-900 border p-2.5 rounded ${isHighValue(probe.ssid || '') ? 'border-risk-critical' : 'border-space-500/20'}`}
                >
                  <div className="flex justify-between items-start mb-1">
                    <span 
                      onClick={() => copyToClipboard(probe.client_mac)} 
                      className="text-[10px] font-mono text-gray-400 cursor-pointer hover:text-white transition-colors relative" 
                      title="Copy MAC"
                    >
                      {probe.client_mac.toUpperCase()}
                      {copiedText === probe.client_mac && <span className="absolute -top-4 left-0 text-[8px] text-neon-400 bg-space-900 px-1 rounded border border-neon-500/30 z-10">COPIED</span>}
                    </span>
                    <span className="text-[9px] text-gray-600 font-mono">
                      {new Date(probe.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-500 shrink-0">Looking for:</span>
                    <span className={`text-sm font-bold font-mono truncate ${isHighValue(probe.ssid || '') ? 'text-risk-critical animate-pulse' : 'text-amber-400'}`}>
                      {probe.ssid || '<HIDDEN NETWORK>'}
                    </span>
                    {isHighValue(probe.ssid || '') && (
                      <span className="text-[8px] bg-risk-critical/20 text-risk-critical border border-risk-critical px-1 rounded font-tactical tracking-wider">HIGH VALUE TARGET</span>
                    )}
                  </div>
                  {/* The engine does not resolve a vendor for probe frames, so
                      there is nothing to show here but what it does report. */}
                  <div className="text-[9px] font-tactical text-gray-600 mt-1 uppercase">
                    {probe.is_new_client ? 'NEW CLIENT · ' : ''}
                    {probe.probe_count != null ? `${probe.probe_count} PROBES` : ''}
                    {probe.total_ssids != null ? ` · ${probe.total_ssids} SSIDS SEEN` : ''}
                  </div>
                </motion.div>
              )) : groupedProbes.map((probe, i) => (
                <motion.div
                  key={`grp-${probe.client_mac}-${i}`}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="bg-space-900 border border-space-500/20 p-2.5 rounded"
                >
                  <div className="flex justify-between items-start mb-1">
                    <div className="flex items-center gap-2">
                      <div className="text-gray-400">{getSourceIcon('probe')}</div>
                      <span 
                        onClick={() => copyToClipboard(probe.client_mac)} 
                        className="text-sm font-mono text-white cursor-pointer hover:text-amber-400 transition-colors relative" 
                        title="Copy MAC"
                      >
                        {probe.client_mac.toUpperCase()}
                        {copiedText === probe.client_mac && <span className="absolute -top-4 left-0 text-[8px] text-amber-400 bg-space-900 px-1 rounded border border-amber-500/30 z-10">COPIED</span>}
                      </span>
                    </div>
                    <span className="text-[9px] text-gray-600 font-mono">
                      {probe.ssids.length} NETWORKS
                    </span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {probe.ssids.map((ssid, j) => (
                      <span key={j} className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${isHighValue(ssid) ? 'bg-risk-critical/10 border-risk-critical/50 text-risk-critical' : 'bg-space-800 border-space-500/30 text-amber-400'}`}>
                        {ssid}
                      </span>
                    ))}
                  </div>
                  <div className="text-[9px] font-tactical text-gray-600 mt-2 uppercase">
                    LAST SEEN {new Date(probe.timestamp).toLocaleTimeString()}
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>

      </div>
    </div>
  );
}
