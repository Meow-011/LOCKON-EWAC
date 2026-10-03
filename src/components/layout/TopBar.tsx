/** TopBar — Mission info, timer, and quick actions */
import { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useEngineStore } from '../../stores/engineStore';
import { useMissionStore } from '../../stores/missionStore';
import { useUIStore } from '../../stores/uiStore';
import { formatFix } from '../../lib/numbers';
import { useStrikeStore } from '../../stores/strikeStore';
import { StatusBadge } from '../common/StatusBadge';
import { engineIPC } from '../../lib/ipc';
import { createMission, completeMission } from '../../lib/wardrivingDB';
import type { Mission } from '../../types/models';

function formatTime(seconds: number): string {
  const h = Math.floor(seconds / 3600).toString().padStart(2, '0');
  const m = Math.floor((seconds % 3600) / 60).toString().padStart(2, '0');
  const s = (seconds % 60).toString().padStart(2, '0');
  return `${h}:${m}:${s}`;
}

export function TopBar() {
  const connected = useEngineStore(s => s.connected);
  const scanning = useEngineStore(s => s.scanning);
  const gpsLocked = useEngineStore(s => s.gpsLocked);
  const latitude = useEngineStore(s => s.latitude);
  const longitude = useEngineStore(s => s.longitude);

  const activeMission = useMissionStore(s => s.activeMission);
  const elapsedSeconds = useMissionStore(s => s.elapsedSeconds);
  const totalAPs = useMissionStore(s => s.totalAPs);
  const incrementElapsed = useMissionStore(s => s.incrementElapsed);

  const activeStrikes = useStrikeStore(s => s.activeStrikes);
  const isStrikeActive = Object.values(activeStrikes).some(s => s.status === 'ACTIVE');

  // Timer Tick
  useEffect(() => {
    let interval: number;
    if (activeMission || scanning) {
      interval = window.setInterval(() => {
        incrementElapsed();
      }, 1000);
    }
    return () => window.clearInterval(interval);
  }, [activeMission, scanning, incrementElapsed]);

  // System Vitals Polling
  const [vitals, setVitals] = useState<{cpu_usage: number, ram_usage: number, ram_total: number} | null>(null);

  // Archive button feedback, held in React state rather than written into the
  // DOM, and cleared on unmount.
  const [archiveState, setArchiveState] = useState<'idle' | 'saving' | 'saved' | 'error'>('idle');
  const [wpsScanning, setWpsScanning] = useState(false);
  const archiveTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => {
    if (archiveTimer.current) clearTimeout(archiveTimer.current);
  }, []);

  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        const data = await invoke('get_system_vitals');
        setVitals(data as any);
      } catch (err) {
        // Silently ignore if not ready
      }
    }, 2000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="flex items-center justify-between h-12 px-4 bg-space-900/80 backdrop-blur-sm border-b border-space-500/20">
      {/* Left — Mission Info */}
      <div className="flex items-center gap-4">
        {activeMission ? (
          <div className="flex items-center gap-3">
            <StatusBadge level={scanning ? "ACTIVE" : "PAUSED"} label={activeMission?.name || "ACTIVE SCAN"} pulse={scanning} />
            <span className="text-sm text-neon-400 font-tech tracking-wider font-medium tabular-nums">
              {formatTime(elapsedSeconds)}
            </span>
            {/*
              WPS measurement. `scan_wps` has been implemented in the engine and
              present in the EngineCommand union all along with nothing ever
              sending it, which is why `wps_enabled` was never populated and the
              report described a beacon parse that never ran.

              It needs monitor mode: the engine reports the scan inconclusive
              rather than empty when no beacon arrives, and nothing is written in
              that case.
            */}
            <button
              onClick={() => {
                if (wpsScanning) {
                  // `stop_wps` was implemented and never sent, so a 12-second
                  // sniff could only be waited out.
                  engineIPC.send('stop_wps').catch(console.error);
                  setWpsScanning(false);
                  return;
                }
                const { config } = useEngineStore.getState();
                setWpsScanning(true);
                engineIPC.send('scan_wps', {
                  interface: config.interfaceName,
                  duration: 12,
                }).catch(err => {
                  console.error(err);
                  setWpsScanning(false);
                });
                // The engine's terminal event clears this; the timer is a
                // fallback so the button cannot stick on if that never arrives.
                window.setTimeout(() => setWpsScanning(false), 20000);
              }}
              title="Read WPS from beacon information elements. Requires a monitor-mode adapter; without one the scan reports inconclusive rather than 'no WPS found'."
              className="text-xs px-2.5 py-1 rounded bg-space-800 text-gray-300 hover:bg-space-700 border border-space-500/30 transition-colors uppercase font-tactical disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {wpsScanning ? 'WPS… STOP' : 'Scan WPS'}
            </button>
            {scanning ? (
              <button
                onClick={() => {
                  engineIPC.send('stop_scan').catch(console.error);
                  // Optimistically update to avoid jitter
                  useEngineStore.getState().setScanning(false);
                }}
                className="text-xs px-2.5 py-1 rounded bg-risk-high/20 text-risk-high hover:bg-risk-high/40 transition-colors uppercase font-tactical"
              >
                Pause
              </button>
            ) : (
              <div className="flex gap-2">
                <button 
                  onClick={() => {
                    const { config } = useEngineStore.getState();
                    engineIPC.send('start_scan', { 
                      simulate: config.emulateHardware,
                      com_port: config.comPort,
                      baud_rate: config.baudRate,
                      interface_name: config.interfaceName,
                      scan_interval: config.scanInterval
                    }).catch(console.error);
                    useEngineStore.getState().setScanning(true);
                  }}
                  className="text-xs px-3 py-1 rounded bg-neon-600/20 text-neon-400 hover:bg-neon-600/40 border border-neon-500/30 transition-colors uppercase font-tactical"
                >
                  Resume
                </button>
                <button 
                  onClick={() => {
                    const { stopMission } = useMissionStore.getState();
                    if (activeMission) {
                      completeMission(activeMission.id).catch(err => console.error('[DB] completeMission error:', err));
                    }
                    stopMission();
                  }}
                  className="text-xs px-2.5 py-1 rounded bg-risk-critical/20 text-risk-critical hover:bg-risk-critical/40 transition-colors uppercase font-tactical"
                >
                  End Mission
                </button>
              </div>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-2">
            {totalAPs > 0 && (
              <button 
                onClick={async () => {
                  // The label used to be set to "SAVED" by writing innerHTML on a
                  // React-managed node, before the insert had even been attempted.
                  // It is React state now, and it only says SAVED once the write
                  // resolved.
                  if (archiveState === 'saving') return;
                  setArchiveState('saving');

                  const { accessPoints, highRiskCount, pathCoords } = useMissionStore.getState();
                  const { addReport } = (await import('../../stores/reportStore')).useReportStore.getState();

                  const aps = Array.from(accessPoints.values());
                  const report = {
                    id: `WIFI-${Date.now()}-${Math.floor(Math.random() * 1000)}`,
                    type: 'WIFI_WARDRIVE' as const,
                    targetName: `FIELD SCAN ${new Date().toLocaleTimeString()}`,
                    timestamp: Date.now(),
                    // Carried onto the report so the PDF can mark it. An archive
                    // of a simulator run must never read as field evidence.
                    simulated: aps.some(ap => ap.simulated) || useEngineStore.getState().config.emulateHardware,
                    summary: {
                      totalAPs: accessPoints.size,
                      vulnerableAPs: highRiskCount,
                    },
                    rawData: {
                      // The mission id has to travel with the archive: survey
                      // coverage (distance, duration, GPS dropouts, per-band
                      // counts) is keyed on it, and without it the report can
                      // only say it could not establish what was surveyed.
                      missionId: useMissionStore.getState().activeMission?.id
                                 ?? useMissionStore.getState().lastMissionId,
                      accessPoints: aps,
                      pathCoords: pathCoords,
                      /*
                        Survey coverage, frozen into the archive.

                        `mission_coverage` is declared `REFERENCES missions(id)
                        ON DELETE CASCADE`, so deleting a mission destroys the
                        coverage record — which defeats the reason migration 009
                        gives for computing and freezing it: "because the source
                        rows can be purged while the report must remain
                        defensible". The report then cannot say what was
                        surveyed, and "no vulnerable networks on the north side"
                        becomes indistinguishable from "never drove the north
                        side" again.

                        Carrying a copy here means the archive holds its own
                        answer. The export prefers this and falls back to the
                        table, so an archive written before this still works.
                      */
                      coverage: await (async () => {
                        const missionId = useMissionStore.getState().activeMission?.id
                                       ?? useMissionStore.getState().lastMissionId;
                        if (!missionId) return null;
                        try {
                          const { computeAndStoreCoverage } = await import('../../lib/coverageDB');
                          return await computeAndStoreCoverage(missionId);
                        } catch (err) {
                          console.error('[Archive] coverage snapshot failed:', err);
                          return null;
                        }
                      })(),
                    }
                  };

                  try {
                    await addReport(report);
                    setArchiveState('saved');
                    window.dispatchEvent(new CustomEvent('lockon:toast', {
                      detail: { message: `Archived ${aps.length} AP(s) to Intel Reports`, type: 'success' }
                    }));
                  } catch (err) {
                    console.error('[DB] archive error:', err);
                    setArchiveState('error');
                    window.dispatchEvent(new CustomEvent('lockon:toast', {
                      detail: { message: `Archive failed: ${err}`, type: 'error' }
                    }));
                  }

                  if (archiveTimer.current) clearTimeout(archiveTimer.current);
                  archiveTimer.current = setTimeout(() => {
                    archiveTimer.current = null;
                    setArchiveState('idle');
                  }, 2500);
                }}
                disabled={archiveState === 'saving'}
                className="text-xs px-3 py-1 rounded bg-space-800 text-gray-300 hover:bg-space-700 border border-space-500/30 transition-colors uppercase font-tactical shadow-sm disabled:opacity-60"
              >
                {archiveState === 'saving' ? 'Saving…'
                  : archiveState === 'saved' ? 'Saved'
                  : archiveState === 'error' ? 'Failed'
                  : 'Archive'}
              </button>
            )}
            
            <button
              onClick={() => {
                useUIStore.getState().setShowMissionArchive(true);
              }}
              className="text-xs px-3 py-1 rounded bg-space-800 text-gray-300 hover:bg-space-700 hover:text-white border border-space-500/30 transition-colors uppercase font-tactical flex items-center gap-2"
            >
              <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
              Mission Archive
            </button>

            <button 
              onClick={async () => {
                const { config } = useEngineStore.getState();
                const { startMission } = useMissionStore.getState();
                
                try {
                  const missionName = `WARDESK-${new Date().toISOString().split('T')[0]}`;
                  const missionId = await createMission(missionName, config.emulateHardware);
                  const mission: Mission = {
                    id: missionId,
                    name: missionName,
                    status: 'ACTIVE',
                    start_time: new Date().toISOString(),
                    created_at: new Date().toISOString(),
                    is_simulated: config.emulateHardware ? 1 : 0
                  };
                  startMission(mission);

                  await engineIPC.send('start_scan', {
                    mission_id: missionId,
                    simulate: config.emulateHardware,
                    com_port: config.comPort,
                    baud_rate: config.baudRate,
                    interface_name: config.interfaceName,
                    scan_interval: config.scanInterval
                  });
                  // The resume path set this; the new-mission path did not, so the
                  // button showed the wrong label until the 2s status poll caught up.
                  useEngineStore.getState().setScanning(true);
                } catch (err) {
                  // Previously only a console.error: if createMission rejected, the
                  // start_scan call never ran and "Start Scan" appeared to do nothing.
                  console.error('[Scan] start failed:', err);
                  window.dispatchEvent(new CustomEvent('lockon:toast', {
                    detail: { message: `Could not start scan: ${err}`, type: 'error' }
                  }));
                }
              }}
              className="text-xs px-3 py-1 rounded bg-neon-600/20 text-neon-400 hover:bg-neon-600/40 border border-neon-500/30 transition-colors uppercase font-tactical"
            >
              Start Scan
            </button>
          </div>
        )}
      </div>

      {/* Right — Status Indicators */}
      <div className="flex items-center gap-3">
        {/* Active Strike Indicator */}
        {isStrikeActive && (
          <div className="flex items-center gap-2 px-3 py-1 rounded bg-risk-critical text-white border border-risk-critical/50 mr-2 animate-pulse font-tactical">
            <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
            <span className="text-xs tracking-wider">STRIKE ACTIVE</span>
          </div>
        )}

        {/* Lat/Lon Coordinates - Only show when we have a fix */}
        {/*
            The hemisphere comes from the sign.

            This printed `${latitude.toFixed(4)}°N ${longitude.toFixed(4)}°E` with
            the letters written in, so a fix south of the equator or west of
            Greenwich read as "-13.7563°N" -- a minus sign and a hemisphere letter
            contradicting each other, in the readout checked most often. The
            offline-basemap card was fixed for this exact thing; this was not,
            because each had its own formatter.

            `formatFix` also decides what counts as a fix, instead of the truthiness
            test that hid the readout on the equator and the prime meridian.
        */}
        {gpsLocked && formatFix(latitude, longitude) && (
          <div className="hidden sm:flex items-center px-2.5 py-1 rounded-md bg-risk-low/10 border border-risk-low/30">
            <span className="text-xs font-tech text-risk-low tracking-tight">
              {formatFix(latitude, longitude)}
            </span>
          </div>
        )}

        {/* AP Count */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-space-800/60 border border-space-500/20">
          <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5 text-neon-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/>
            <circle cx="12" cy="20" r="1"/>
          </svg>
          <span className="text-sm font-tech text-gray-300">{totalAPs}</span>
        </div>

        {/* GPS */}
        <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border ${
          gpsLocked 
            ? 'bg-risk-low/10 border-risk-low/30 text-risk-low' 
            : 'bg-space-800/60 border-space-500/20 text-gray-500'
        }`}>
          <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M20 10c0 4.993-5.539 10.193-7.399 11.799a1 1 0 0 1-1.202 0C9.539 20.193 4 14.993 4 10a8 8 0 0 1 16 0"/>
            <circle cx="12" cy="10" r="3"/>
          </svg>
          <span className="text-xs font-mono">{gpsLocked ? 'FIX' : 'NO FIX'}</span>
        </div>

        {/* System Vitals */}
        {vitals && (
          <div className="hidden lg:flex items-center gap-3 px-3 py-1 rounded-md bg-space-800/60 border border-space-500/20 font-mono text-[10px] text-gray-400 tracking-wider">
            <div className="flex items-center gap-1" title="System-wide CPU Usage">
              <span className="text-gray-500">SYS CPU</span>
              <span className={vitals.cpu_usage > 80 ? 'text-risk-critical' : 'text-neon-400'}>
                {Math.round(vitals.cpu_usage)}%
              </span>
            </div>
            <div className="w-px h-3 bg-space-500/50"></div>
            <div className="flex items-center gap-1" title="System-wide RAM Usage">
              <span className="text-gray-500">SYS RAM</span>
              <span className={(vitals.ram_usage / vitals.ram_total) > 0.8 ? 'text-risk-critical' : 'text-risk-info'}>
                {vitals.ram_usage.toFixed(1)}GB
              </span>
            </div>
          </div>
        )}

        {/*
            Engine state, carried by the border rather than by a halo.

            Scanning used to be a two-second `boxShadow` pulse breathing around
            this pill. The state it was signalling is also in the dot colour, the
            text colour and the word itself, so removing the glow removes nothing
            from the reader -- but the border was `/30` in all three states, which
            left the glow doing real work at a glance. It is `/70` while scanning
            now, so the pill still stands out across the bar without lighting up.
        */}
        <div
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border ${
            connected
              ? scanning
                ? 'bg-neon-500/10 border-neon-500/70'
                : 'bg-risk-low/10 border-risk-low/30'
              : 'bg-risk-critical/10 border-risk-critical/30'
          }`}
        >
          <div className={`w-1.5 h-1.5 rounded-full ${
            connected ? scanning ? 'bg-neon-500' : 'bg-risk-low' : 'bg-risk-critical'
          }`} />
          <span className={`text-xs font-mono ${
            connected ? scanning ? 'text-neon-400' : 'text-risk-low' : 'text-risk-critical'
          }`}>
            {connected ? scanning ? 'SCANNING' : 'READY' : 'OFFLINE'}
          </span>
        </div>
      </div>
    </header>
  );
}
