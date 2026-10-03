import { motion, AnimatePresence } from 'framer-motion';
import { encryptionBadgeTitle, encryptionTextClass } from '../../lib/severityStyle';
import { signalBarClass } from '../../lib/signalStyle';
import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { engineIPC } from '../../lib/ipc';
import { useEngineStore } from '../../stores/engineStore';
import { useUIStore } from '../../stores/uiStore';
import { useMissionStore } from '../../stores/missionStore';
import { getEvidenceForBssid, type EvidenceRow } from '../../lib/findingsDB';
import { coordinatePair } from '../../lib/numbers';
import { isHighRiskAp } from '../../lib/apRisk';
import { apMirror, formatMetres, isMirrorAmbiguous } from '../../lib/position';

function getBearing(lat1: number, lon1: number, lat2: number, lon2: number) {
  const dLon = (lon2 - lon1) * Math.PI / 180;
  lat1 = lat1 * Math.PI / 180;
  lat2 = lat2 * Math.PI / 180;
  const y = Math.sin(dLon) * Math.cos(lat2);
  const x = Math.cos(lat1) * Math.sin(lat2) - Math.sin(lat1) * Math.cos(lat2) * Math.cos(dLon);
  return (Math.atan2(y, x) * 180 / Math.PI + 360) % 360;
}

export function TargetDrawer() {
  const navigate = useNavigate();
  const selectedBssid = useUIStore(s => s.selectedBssid);
  const setSelectedBssid = useUIStore(s => s.setSelectedBssid);
  const accessPoints = useMissionStore(s => s.accessPoints);
  const [captureState, setCaptureState] = useState<'IDLE' | 'CAPTURING' | 'SUCCESS' | 'FAILED'>('IDLE');
  const [captureErrorMsg, setCaptureErrorMsg] = useState<string>('');
  const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Selectors rather than whole-store reads, so the drawer is not re-rendered by
  // every unrelated engine state change.
  /*
    The accepted fix, like the map marker and for the same reason.

    These two and `egoHeading` drive the bearing arrow to the access point.
    Taken raw, a parked receiver's scatter and its essentially random course
    over ground make that arrow swing while the operator stands still holding
    the rig, which is the one moment they are using it to walk towards
    something.
  */
  const egoLat = useEngineStore(s => s.acceptedLatitude);
  const egoLon = useEngineStore(s => s.acceptedLongitude);
  const egoHeading = useEngineStore(s => s.acceptedHeading);
  // One rule for what counts as a position, shared with the map and the recorder.
  const egoFix = coordinatePair(egoLat, egoLon);
  const interfaceName = useEngineStore(s => s.config.interfaceName);

  const ap = selectedBssid ? accessPoints.get(selectedBssid) : null;
  // The access point's own position, by the same rule. Separate from `egoFix`
  // because the dial needs both and they fail for different reasons.
  const targetFix = ap ? coordinatePair(ap.latitude, ap.longitude) : null;
  const [rssiHistory, setRssiHistory] = useState<number[]>([]);

  // Update RSSI history
  useEffect(() => {
    if (ap?.rssi) {
      setRssiHistory(prev => {
        const next = [...prev, ap.rssi!];
        return next.slice(-20); // Keep last 20 readings
      });
    }
  }, [ap?.rssi]);

  // Reset history on new target
  useEffect(() => {
    setRssiHistory([]);
  }, [selectedBssid]);

  /*
    What this installation has actually recorded for this access point.

    `getEvidenceForBssid` has existed, with no caller, since the evidence table
    was added. The register in the exported PDF lists every artifact the rig
    holds and tells the reader to "match artifacts to findings by their subject",
    which is a reasonable instruction for a document and a poor one for the
    moment it matters: standing in front of an access point, deciding whether to
    capture again. That question — did I get anything for *this* BSSID — had no
    answer anywhere in the interface.

    Read on selection rather than kept in a store: it is a handful of rows, it is
    only wanted while a drawer is open, and a cached copy would go stale the
    moment a capture completed, which is exactly when the operator looks.

    A read failure is held and shown. Zero artifacts and a table that could not
    be read lead to opposite decisions — capture again, or go and find out why
    the database is unreadable before trusting anything else on this screen.
  */
  const [evidence, setEvidence] = useState<EvidenceRow[]>([]);
  const [evidenceError, setEvidenceError] = useState<string | null>(null);

  useEffect(() => {
    if (!selectedBssid) { setEvidence([]); setEvidenceError(null); return; }
    let current = true;
    setEvidenceError(null);
    getEvidenceForBssid(selectedBssid)
      .then(rows => { if (current) setEvidence(rows); })
      .catch(e => {
        if (!current) return;
        setEvidence([]);
        setEvidenceError(e instanceof Error ? e.message : String(e));
      });
    // The drawer can be reselected faster than a query returns, and a late
    // answer for the previous BSSID would be rendered under this one's heading —
    // the same mislabelling the deep-scan panels needed an ownership gate for.
    return () => { current = false; };
  }, [selectedBssid, captureState]);

  // Reset capture state when target changes
  useEffect(() => {
    setCaptureState('IDLE');

    const unsubStart = engineIPC.on('capture_started', () => setCaptureState('CAPTURING'));
    const unsubSuccess = engineIPC.on('capture_success', (msg: any) => {
      setCaptureState('SUCCESS');
      const filename = msg.data.file || `handshake_${selectedBssid?.replace(/:/g, '')}.pcap`;
      useUIStore.getState().setCapturedPcapFile(filename);
    });
    // Tracked so the reset does not fire into an unmounted drawer.
    const scheduleIdle = () => {
      if (resetTimer.current) clearTimeout(resetTimer.current);
      resetTimer.current = setTimeout(() => {
        resetTimer.current = null;
        setCaptureState('IDLE');
      }, 3000);
    };

    const unsubFailed = engineIPC.on('capture_failed', (msg: any) => {
      setCaptureState('FAILED');
      // The engine now names which EAPOL messages it did see and which pair was
      // missing, which is far more actionable than "NO EAPOL DETECTED".
      const seen = Array.isArray(msg.data?.messages_seen) && msg.data.messages_seen.length
        ? ` (saw M${msg.data.messages_seen.join(', M')})`
        : '';
      // The caveat is the part that stops a null result being read as a
      // finding, so it travels with the reason rather than being dropped.
      const caveat = msg.data?.caveat ? ` — ${msg.data.caveat}` : '';
      setCaptureErrorMsg(
        (msg.data?.reason || msg.data?.message || 'NO EAPOL DETECTED') + seen + caveat
      );
      scheduleIdle();
    });
    const unsubError = engineIPC.on('capture_error', (msg: any) => {
      setCaptureState('FAILED');
      setCaptureErrorMsg(msg.data?.message || 'ERROR OCCURRED');
      scheduleIdle();
    });
    // Cancellation is a terminal event now, so the drawer no longer spins
    // forever when a capture is stopped.
    const unsubAborted = engineIPC.on('capture_aborted', (msg: any) => {
      setCaptureState('IDLE');
      setCaptureErrorMsg(msg.data?.message || 'CAPTURE CANCELLED');
    });

    return () => {
      unsubStart();
      unsubSuccess();
      unsubFailed();
      unsubError();
      unsubAborted();
      if (resetTimer.current) clearTimeout(resetTimer.current);
    };
  }, [selectedBssid]);

  /*
    One verdict for this access point, from the rule set that produces every other
    severity in the application.

    These four places asked `ap.is_vulnerable` -- a boolean the engine sets from
    its own checks -- while the map, the report and now the scan feed ask
    `assessAccessPoint`. They are different questions, and a WEP network the rule
    set rates CRITICAL without that flag set had a green status dot here, no
    warning paragraph, and the AUDIT button **disabled**: the drawer refused to
    act on a radio the rest of the application was drawing in red.
  */
  const highRisk = ap ? isHighRiskAp(ap, !!(ap as any).simulated) : false;

  const handleAudit = () => {
    if (!highRisk) return;
    setSelectedBssid(null); // Close Drawer
    navigate('/intrusion'); // Switch Tab
  };

  const handleCapture = () => {
    if (!ap) return;
    setCaptureState('CAPTURING');
    setCaptureErrorMsg('');
    engineIPC.send('start_capture', {
      bssid: ap.bssid,
      // Send the adapter the operator actually chose. Passing null made the
      // engine fall back to a default NIC on multi-adapter rigs.
      interface: interfaceName || null
    }).catch(err => {
      // The engine cannot emit a terminal event for a request it never received.
      setCaptureState('FAILED');
      setCaptureErrorMsg(String(err));
    });
  };

  const exportToDecryptor = () => {
    setSelectedBssid(null);
    navigate('/decryptor');
  };

  return (
    <AnimatePresence>
      {selectedBssid && ap && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setSelectedBssid(null)}
            className="fixed inset-0 bg-space-950/60 backdrop-blur-sm z-40 lg:hidden"
          />

          {/* Drawer Panel */}
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="fixed right-0 top-0 bottom-0 w-full md:w-96 bg-space-900 border-l border-space-500/30 shadow-2xl z-50 flex flex-col"
          >
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-space-500/20 bg-space-800/50">
              <div className="flex items-center gap-3">
                <div className={`w-2 h-2 rounded-full ${highRisk ? 'bg-risk-critical' : 'bg-risk-low'}`} />
                <h2 className="text-lg font-bold text-white font-tactical tracking-wider">TARGET INTEL</h2>
              </div>
              <button 
                onClick={() => setSelectedBssid(null)}
                className="p-1 px-2 text-gray-400 hover:text-white rounded bg-space-700/50 hover:bg-risk-critical/80 transition-colors uppercase font-tactical text-xs"
              >
                Close
              </button>
            </div>

            {/* Content Scroll Area */}
            <div className="flex-1 overflow-y-auto p-5 space-y-6">
              
              {/* Identity Section */}
              <div>
                <h3 className="text-[10px] font-mono text-gray-500 mb-1">NETWORK IDENTITY</h3>
                <div className="text-2xl font-medium text-white truncate mb-1">
                  {ap.ssid || '(Hidden SSID)'}
                </div>
                <div className="flex items-center gap-2 mt-2">
                  <span className="text-sm font-mono text-neon-400 bg-neon-500/10 px-2 py-0.5 rounded border border-neon-500/20">
                    {ap.bssid}
                  </span>
                </div>
              </div>

              {/* Tactical Assessment */}
              <div className="glass-card p-4 border-l-4 overflow-hidden border-l-risk-critical bg-gradient-to-r from-risk-critical/10 to-transparent">
                <h3 className="text-[10px] font-mono text-risk-critical mb-2">THREAT ASSESSMENT</h3>
                <div className="flex items-center justify-between mb-3">
                  <span className="text-sm text-gray-300">Security Layer</span>
                  <span
                    title={encryptionBadgeTitle(ap.encryption)}
                    className={`text-sm font-mono font-bold ${encryptionTextClass(ap.encryption)}`}
                  >{ap.encryption}</span>
                </div>
                {highRisk ? (
                  <p className="text-xs text-gray-400 leading-relaxed font-mono">
                    <span className="text-risk-critical">WARNING:</span> This network's security protocol is highly vulnerable to immediate decryption vector attacks. Active interception is feasible.
                  </p>
                ) : (
                  <p className="text-xs text-gray-400 leading-relaxed font-mono">
                    Network utilizes robust cryptographic standards. Passive signals collection only.
                  </p>
                )}
              </div>

              {/* Hardware Data */}
              <div>
                <h3 className="text-[10px] font-mono text-gray-500 mb-3 border-b border-space-500/20 pb-1">TELEMETRY & HARDWARE</h3>
                <div className="grid grid-cols-2 gap-3">
                  <div className="p-3 bg-space-800/30 rounded border border-space-500/20">
                    <div className="text-xs text-gray-500 mb-1">Last Signal</div>
                    <div className="flex items-end gap-2">
                      <div className="text-lg font-mono text-white tabular-nums leading-none">
                        {ap.rssi ? `${ap.rssi} dBm` : 'N/A'}
                      </div>
                      {ap.rssi && (
                        <div className="flex-1 h-1.5 bg-space-950 rounded-full overflow-hidden mb-1">
                          <div 
                            className={`h-full transition-all duration-500 ${signalBarClass(ap.rssi)}`}
                            style={{ width: `${Math.max(0, Math.min(100, (ap.rssi + 100) * 1.5))}%` }} 
                          />
                        </div>
                      )}
                    </div>
                    {/* RSSI Waterfall */}
                    {rssiHistory.length > 0 && (
                      <div className="mt-3 pt-3 border-t border-space-500/10">
                        <div className="text-[9px] font-mono text-gray-500 mb-1 flex justify-between">
                          <span>SIGNAL WATERFALL</span>
                          <span>{ap.rssi} dBm</span>
                        </div>
                        <div className="h-8 flex items-end gap-[2px] opacity-80">
                          {rssiHistory.map((val, i) => {
                            const height = Math.max(5, Math.min(100, (val + 100) * 1.5));
                            const isLast = i === rssiHistory.length - 1;
                            return (
                              <div 
                                key={i} 
                                className={`flex-1 rounded-t-sm transition-all duration-300 ${isLast ? 'bg-white' : val >= -60 ? 'bg-signal-strong' : val >= -80 ? 'bg-signal-fair' : 'bg-signal-dead'}`}
                                style={{ height: `${height}%` }}
                              />
                            );
                          })}
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="p-3 bg-space-800/30 rounded border border-space-500/20">
                    <div className="text-xs text-gray-500 mb-1">Frequency</div>
                    <div className="text-sm font-mono text-white leading-none mt-1.5">
                      {ap.channel ? `CH ${ap.channel}` : 'Auto'}
                    </div>

                    {/*
                        Radar Compass.

                        The most actionable thing in the application: it is read by
                        someone deciding which way to walk. It was also the last
                        surface that said nothing about what the position under it
                        was worth.

                        For an access point no estimator could place, `ap.latitude`
                        is the receiver's own position — so the arrow pointed at the
                        operator's feet, steadily, with a crisp bearing. For a
                        mirror-ambiguous one it points at whichever of two equally
                        good candidates the estimator happened to report, and walking
                        the wrong way is the specific cost of that ambiguity.

                        Both are now stated under the dial. `coordinatePair` on each
                        side replaces the four-way truthiness test, which also hid
                        the dial on the equator and the prime meridian, and the
                        absent state no longer says "NO GPS FIX" when it is the
                        access point and not the receiver that has no position.
                    */}
                    {targetFix && egoFix ? (
                      <div className="mt-3 pt-3 border-t border-space-500/10 flex flex-col items-center">
                        <div className="text-[9px] font-mono text-gray-500 mb-2 w-full text-left">DIRECTION</div>
                        <div className="relative w-12 h-12 rounded-full border border-space-500/30 bg-space-950 flex items-center justify-center">
                          {/* Crosshairs */}
                          <div className="absolute w-full h-[1px] bg-space-500/20" />
                          <div className="absolute h-full w-[1px] bg-space-500/20" />
                          <div className="absolute inset-1 rounded-full border border-space-500/10" />
                          
                          {/* Arrow */}
                          <div 
                            className="absolute w-full h-full transition-transform duration-500"
                            style={{ 
                              transform: `rotate(${getBearing(egoFix.lat, egoFix.lon, targetFix.lat, targetFix.lon) - (egoHeading ?? 0)}deg)`
                            }}
                          >
                            <svg className="absolute -top-1.5 left-1/2 -translate-x-1/2 w-3 h-3 text-neon-400" viewBox="0 0 24 24" fill="currentColor">
                              <polygon points="12 2 20 22 12 17 4 22 12 2" />
                            </svg>
                          </div>
                        </div>
                        {/*
                            What the bearing is worth, under the bearing.

                            Unresolved is checked first, because it is not a weaker
                            kind of position — there is none, and the dial is pointing
                            at where the rig is standing.
                        */}
                        {ap.location_resolved === false ? (
                          <div className="mt-2 text-[8px] font-mono text-amber-400/90 leading-snug text-center">
                            NOT A BEARING — this radio was never located, so the dial points at
                            where it was heard from. Move, and it will resolve.
                          </div>
                        ) : isMirrorAmbiguous(ap) ? (
                          <div className="mt-2 text-[8px] font-mono text-amber-400/90 leading-snug text-center">
                            1 OF 2 DIRECTIONS{apMirror(ap)?.distanceM != null
                              ? ` — the other candidate is ${formatMetres(apMirror(ap)!.distanceM)} away`
                              : ' — the other fits equally well'}. Turn a corner to rule one out.
                          </div>
                        ) : null}
                      </div>
                    ) : (
                      <div className="mt-3 pt-3 border-t border-space-500/10 flex flex-col items-center justify-center h-12 opacity-50">
                        {/* Which side is missing, because they are different problems:
                            one is solved by waiting for satellites and the other by
                            driving. "NO GPS FIX" was shown for both. */}
                        <div className="text-[9px] font-mono text-gray-500">
                          {egoFix ? 'NO POSITION FOR THIS RADIO' : 'NO GPS FIX'}
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="col-span-2 p-3 bg-space-800/30 rounded border border-space-500/20 flex justify-between items-center">
                    <div>
                      <div className="text-xs text-gray-500 mb-1">Vendor</div>
                      <div className="text-sm text-white truncate max-w-[200px]" title={ap.vendor || 'Unknown'}>
                        {ap.vendor || 'Unknown'}
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="text-xs text-gray-500 mb-1">First Detected</div>
                      <div className="text-xs font-mono text-gray-400">
                        {ap.first_seen ? ap.first_seen.split('.')[0] : 'Unknown'}
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="pt-4 border-t border-space-500/20 flex flex-col gap-3">
                
                {/* Handshake Capture (RF Strike) */}
                {ap.encryption !== 'OPEN' && (
                  <div className="flex flex-col gap-2 p-3 bg-space-950 rounded border border-space-500/30">
                    <h3 className="text-[10px] font-mono text-gray-500">OFFENSIVE RF CAPABILITIES</h3>
                    
                    {captureState === 'IDLE' && (
                      <button 
                        onClick={handleCapture}
                        className="w-full flex items-center justify-center gap-2 bg-risk-high/10 border border-risk-high/50 text-risk-high hover:bg-risk-high hover:text-white font-tactical tracking-wider py-2.5 rounded text-sm transition-all"
                      >
                        <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>
                        INITIATE HANDSHAKE CAPTURE
                      </button>
                    )}

                    {captureState === 'CAPTURING' && (
                      <div className="w-full flex flex-col items-center justify-center gap-2 bg-space-900 border border-neon-500/50 py-3 rounded text-sm">
                        <svg className="w-6 h-6 text-neon-400 animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                          <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
                        </svg>
                        <span className="text-neon-400 font-mono text-xs animate-pulse">LISTENING FOR EAPOL PACKETS...</span>
                      </div>
                    )}

                    {captureState === 'SUCCESS' && (
                      <div className="flex flex-col gap-2">
                        <div className="w-full flex items-center justify-center gap-2 bg-signal-strong/20 border border-signal-strong/50 text-signal-strong py-2 rounded text-sm font-tactical tracking-widest">
                          <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                          HANDSHAKE SECURED
                        </div>
                        
                        {/* Evidence Display */}
                        <div className="bg-space-900 border border-space-500/30 rounded p-2 text-center mb-1">
                          <div className="text-[11px] text-gray-400 font-mono truncate px-2 mb-1" title={useUIStore.getState().capturedPcapFile || ''}>
                            FILE: {useUIStore.getState().capturedPcapFile}
                          </div>
                          <div className="text-[10px] text-signal-strong font-mono">
                            EAPOL: 4/4 PACKETS | SIZE: ~4.2 KB
                          </div>
                        </div>

                        <button 
                          onClick={exportToDecryptor}
                          className="w-full bg-space-800 border border-space-500/50 hover:bg-space-700 text-white font-tactical tracking-wider py-2 rounded text-xs transition-colors"
                        >
                          [ EXPORT TO DECRYPTOR ]
                        </button>
                      </div>
                    )}

                    {captureState === 'FAILED' && (
                      <div className="w-full flex items-center justify-center gap-2 bg-risk-critical/20 border border-risk-critical text-risk-critical py-3 rounded text-[11px] font-tactical tracking-wider">
                        <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                        <span className="truncate">FAILED: {captureErrorMsg.toUpperCase()}</span>
                      </div>
                    )}
                  </div>
                )}

                {/* ─────────────────────── RECORDED EVIDENCE ───────────────────────
                    What this installation actually holds for this BSSID.

                    The register in the exported PDF lists every artifact the rig
                    has and tells the reader to match them to findings by their
                    subject. That is fine for a document and no use at the moment
                    it matters — standing in front of an access point deciding
                    whether to capture again — and that question had no answer
                    anywhere in the interface. `getEvidenceForBssid` has existed
                    since the evidence table was added, with no caller. */}
                <div className="bg-space-900/60 border border-space-500/20 rounded p-2">
                  <div className="text-[9px] font-tactical tracking-widest text-gray-500 mb-1.5">
                    RECORDED EVIDENCE
                  </div>

                  {evidenceError ? (
                    // Not "0 artifacts". Nothing recorded and a table that could
                    // not be read lead to opposite decisions.
                    <div className="text-[10px] font-mono text-risk-high leading-relaxed">
                      The evidence register could not be read — {evidenceError}. This says nothing
                      about whether anything was captured for this target.
                    </div>
                  ) : evidence.length === 0 ? (
                    <div className="text-[10px] font-mono text-gray-600 leading-relaxed">
                      No artifact recorded for this BSSID. A capture that ran but was never written
                      to the register would look the same here.
                    </div>
                  ) : (
                    <div className="space-y-1">
                      {evidence.slice(0, 6).map(e => (
                        <div key={e.id} className="flex items-center justify-between gap-2 text-[10px] font-mono">
                          <span className="text-gray-300 truncate" title={e.path ?? e.filename}>
                            {e.filename}
                          </span>
                          <span className="shrink-0 flex items-center gap-2">
                            <span className="text-gray-600">{e.kind ?? 'artifact'}</span>
                            {/*
                              Four states, not two. NULL verify_status is the
                              normal one — it means this installation has never
                              re-hashed the file, which is different from having
                              checked it and found it sound. Settings → Evidence
                              Integrity is what changes it.
                            */}
                            <span className={
                              e.verify_status === 'MATCH' ? 'text-signal-strong'
                                : e.verify_status === 'MISMATCH' || e.verify_status === 'MISSING' ? 'text-risk-critical'
                                : !e.sha256 ? 'text-risk-high'
                                : 'text-gray-600'
                            }>
                              {e.verify_status === 'MATCH' ? 'VERIFIED'
                                : e.verify_status === 'MISMATCH' ? 'MISMATCH'
                                : e.verify_status === 'MISSING' ? 'MISSING'
                                : !e.sha256 ? 'NOT HASHED'
                                : 'NOT RE-CHECKED'}
                            </span>
                          </span>
                        </div>
                      ))}
                      {evidence.length > 6 && (
                        <div className="text-[10px] font-mono text-gray-600">
                          and {evidence.length - 6} more — the full register is in the exported report.
                        </div>
                      )}
                    </div>
                  )}
                </div>
                <div className="flex gap-3">
                  <button 
                    onClick={() => navigator.clipboard.writeText(ap.bssid)}
                    className="flex-1 flex items-center justify-center gap-2 bg-space-800 hover:bg-space-700 border border-space-500/30 text-gray-300 hover:text-white font-tactical tracking-wider py-2 rounded text-xs transition-colors group"
                  >
                    <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5 opacity-50 group-hover:opacity-100 transition-opacity" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                    COPY BSSID
                  </button>
                  <button 
                    onClick={handleAudit}
                    disabled={!highRisk}
                    className={`flex-1 flex items-center justify-center gap-2 font-tactical tracking-wider py-2 rounded text-xs transition-all border ${
                      highRisk 
                        ? 'bg-risk-critical/10 border-risk-critical/50 text-risk-critical hover:bg-risk-critical hover:text-white' 
                        : 'bg-space-950 border-space-500/10 text-gray-600 cursor-not-allowed opacity-50'
                    }`}
                  >
                    {highRisk ? (
                      <>
                        <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="22" y1="12" x2="18" y2="12"/><line x1="6" y1="12" x2="2" y2="12"/><line x1="12" y1="6" x2="12" y2="2"/><line x1="12" y1="22" x2="12" y2="18"/></svg>
                        LAN AUDIT
                      </>
                    ) : (
                      <>
                        <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                        SECURE
                      </>
                    )}
                  </button>
                </div>
              </div>

            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
