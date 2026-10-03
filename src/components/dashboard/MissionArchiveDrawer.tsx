import { motion, AnimatePresence } from 'framer-motion';
import { useEffect, useState } from 'react';
import { useUIStore } from '../../stores/uiStore';
import { useMissionStore } from '../../stores/missionStore';
import { getMissions, getMissionData, deleteMission, getMissionRawLogs } from '../../lib/wardrivingDB';
import { engineIPC } from '../../lib/ipc';
import type { Mission } from '../../types/models';

export function MissionArchiveDrawer() {
  const { showMissionArchive, setShowMissionArchive } = useUIStore();
  const { loadArchive, viewingMissionId } = useMissionStore();
  const [missions, setMissions] = useState<Mission[]>([]);
  const [loading, setLoading] = useState(false);
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);

  useEffect(() => {
    if (showMissionArchive) {
      refreshMissions();
    } else {
      setConfirmDeleteId(null);
    }
  }, [showMissionArchive]);

  const refreshMissions = () => {
    setLoading(true);
    getMissions()
      .then(setMissions)
      .catch(console.error)
      .finally(() => setLoading(false));
  };

  const handleLoadMission = async (missionId: string) => {
    if (viewingMissionId === missionId) {
      setShowMissionArchive(false);
      return;
    }
    try {
      setLoading(true);
      const data = await getMissionData(missionId);
      loadArchive(missionId, data.aps, data.gpsPath);
      setShowMissionArchive(false);
    } catch (err) {
      console.error('Failed to load mission', err);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (missionId: string) => {
    if (confirmDeleteId === missionId) {
      try {
        setLoading(true);
        await deleteMission(missionId);
        setConfirmDeleteId(null);
        refreshMissions();
      } catch (err) {
        console.error('Failed to delete mission', err);
        setLoading(false);
      }
    } else {
      setConfirmDeleteId(missionId);
    }
  };

  const formatTacticalDate = (isoString: string) => {
    const d = new Date(isoString);
    const day = d.getDate().toString().padStart(2, '0');
    const mon = d.toLocaleString('en-US', { month: 'short' }).toUpperCase();
    const yr = d.getFullYear();
    const hr = d.getHours().toString().padStart(2, '0');
    const min = d.getMinutes().toString().padStart(2, '0');
    return `${day} ${mon} ${yr} // ${hr}:${min} HRS`;
  };

  return (
    <AnimatePresence>
      {showMissionArchive && (
        <>
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setShowMissionArchive(false)}
            className="fixed inset-0 bg-space-950/60 backdrop-blur-sm z-40"
          />

          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="fixed right-0 top-0 bottom-0 w-full md:w-96 bg-space-900 border-l border-space-500/30 shadow-2xl z-50 flex flex-col"
          >
            <div className="flex items-center justify-between p-4 border-b border-space-500/20 bg-space-800/50">
              <div className="flex items-center gap-3">
                <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-neon-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>
                <h2 className="text-lg font-bold text-white font-tactical tracking-wider">MISSION ARCHIVE</h2>
              </div>
              <button 
                onClick={() => setShowMissionArchive(false)}
                className="p-1 px-2 text-gray-400 hover:text-white rounded bg-space-700/50 transition-colors uppercase font-tactical text-xs"
              >
                Close
              </button>
            </div>

            <div className="flex-1 overflow-y-auto p-4 space-y-3">
              {loading && missions.length === 0 ? (
                <div className="text-center py-8 text-gray-400 font-mono text-sm">LOADING SECURE ARCHIVES...</div>
              ) : missions.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full py-16 text-center opacity-50 hover:opacity-100 transition-opacity">
                  <img src="/cat-archive-empty-mission.svg" alt="Archive Empty" className="w-24 h-24 mb-4 opacity-80" />
                  <div className="text-gray-400 font-tactical text-sm mb-2 tracking-widest uppercase">Archive Empty</div>
                  <div className="text-gray-500 font-mono text-[10px] mb-6 max-w-[200px] leading-relaxed">
                    No field missions recorded. Initiate a wardriving sweep to begin gathering RF intelligence.
                  </div>
                  <button
                    onClick={() => setShowMissionArchive(false)}
                    className="px-4 py-2 bg-space-800 text-gray-300 border border-space-500/30 hover:bg-space-700 hover:text-white rounded text-xs font-tactical tracking-widest transition-colors"
                  >
                    RETURN TO DASHBOARD
                  </button>
                </div>
              ) : (
                missions.map(m => {
                  const isActive = viewingMissionId === m.id;
                  
                  return (
                    <div 
                      key={m.id} 
                      className={`glass-card p-4 transition-colors group relative overflow-hidden ${
                        isActive ? 'border-neon-500/80 bg-neon-900/10' : 'border-space-500/30 hover:border-space-400'
                      }`}
                    >
                      {isActive && (
                        <div className="absolute top-0 left-0 w-1 h-full bg-neon-500" />
                      )}
                      
                      <div className="flex justify-between items-start mb-2">
                        <div className="font-bold text-white tracking-wider text-sm flex items-center gap-2">
                          {m.name}
                          {isActive && <span className="flex w-2 h-2 rounded-full bg-neon-400 animate-pulse"></span>}
                        </div>
                        <div className="flex gap-2">
                          <button 
                            onClick={() => handleDelete(m.id)}
                            className={`p-1 rounded transition-colors text-xs ${
                              confirmDeleteId === m.id 
                                ? 'bg-risk-critical text-white px-2 font-tactical tracking-wider' 
                                : 'text-gray-500 hover:text-risk-critical hover:bg-risk-critical/20'
                            }`}
                          >
                            {confirmDeleteId === m.id ? 'CONFIRM' : (
                              <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
                            )}
                          </button>
                        </div>
                      </div>
                      
                      <div className="text-[10px] text-gray-400 font-mono mb-3 bg-space-800/50 px-2 py-1 rounded inline-block border border-space-500/20">
                        {formatTacticalDate(m.start_time)}
                      </div>
                      
                      <div className="grid grid-cols-2 gap-2 mb-4">
                        <div className="bg-space-800/40 border border-space-500/20 rounded p-2 flex flex-col justify-center items-center">
                          <span className="text-[10px] text-gray-500 font-mono mb-0.5">TOTAL APs</span>
                          <span className="text-sm font-bold text-gray-300 tabular-nums">{m.total_aps || 0}</span>
                        </div>
                        <div className={`bg-space-800/40 border rounded p-2 flex flex-col justify-center items-center ${
                          (m.high_risk_aps || 0) > 0 ? 'border-risk-critical/30' : 'border-space-500/20'
                        }`}>
                          <span className="text-[10px] text-gray-500 font-mono mb-0.5">HIGH RISK</span>
                          <span className={`text-sm font-bold tabular-nums ${
                            (m.high_risk_aps || 0) > 0 ? 'text-risk-critical' : 'text-gray-300'
                          }`}>{m.high_risk_aps || 0}</span>
                        </div>
                      </div>
                      
                      <div className="flex flex-col gap-2">
                        <button 
                          onClick={() => handleLoadMission(m.id)}
                          disabled={loading}
                          className={`w-full py-2 text-xs font-tactical tracking-widest rounded border transition-all flex items-center justify-center gap-2 ${
                            isActive 
                              ? 'bg-neon-600/20 text-neon-400 border-neon-500/50 hover:bg-neon-600/30' 
                              : 'bg-space-700/50 hover:bg-neon-600/20 text-gray-300 hover:text-neon-400 border-space-500/30'
                          }`}
                        >
                          {isActive ? (
                            <>
                              <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect></svg>
                              EXIT PLAYBACK
                            </>
                          ) : (
                            <>
                              <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg>
                              REPLAY MISSION
                            </>
                          )}
                        </button>
                        
                        <button 
                          onClick={async (e) => {
                            e.stopPropagation();
                            window.dispatchEvent(new CustomEvent('lockon:toast', {
                              detail: { message: 'EXTRACTING MISSION DATA FOR GPR...', type: 'info' }
                            }));
                            
                            try {
                              // 1. Fetch raw logs
                              const rawLogs = await getMissionRawLogs(m.id);
                              
                              // 2. Group by BSSID
                              const grouped = new Map<string, typeof rawLogs>();
                              for (const log of rawLogs) {
                                if (!grouped.has(log.bssid)) grouped.set(log.bssid, []);
                                grouped.get(log.bssid)!.push(log);
                              }

                              // 3. Filter APs with enough data (min 3 points)
                              const validAps = Array.from(grouped.entries())
                                .filter(([_, logs]) => logs.length >= 3)
                                .sort((a, b) => b[1].length - a[1].length); // Sort by most data points

                              // 4. Limit to top 20 to avoid melting the CPU
                              const topAps = validAps.slice(0, 20);

                              if (topAps.length === 0) {
                                window.dispatchEvent(new CustomEvent('lockon:toast', {
                                  detail: { message: 'GPR FAILED: INSUFFICIENT DATA POINTS', type: 'error' }
                                }));
                                return;
                              }

                              window.dispatchEvent(new CustomEvent('lockon:toast', {
                                detail: { message: `INITIALIZING GPR MATRIX FOR ${topAps.length} TARGETS...`, type: 'warning' }
                              }));

                              // 5. Pipe to Python Engine
                              for (const [bssid, measurements] of topAps) {
                                engineIPC.send('run_gpr', { 
                                  bssid, 
                                  measurements,
                                  grid_resolution: 50 // Lower resolution for batch processing
                                }).catch(console.error);
                              }
                            } catch (err) {
                              console.error('GPR Extraction Error:', err);
                            }
                          }}
                          disabled={loading}
                          className="w-full py-1.5 text-[10px] font-tactical tracking-widest rounded bg-space-800/80 text-neon-400 hover:bg-neon-900/40 border border-neon-500/20 hover:border-neon-500/50 transition-colors flex items-center justify-center gap-1.5"
                        >
                          <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"></path></svg>
                          DEEP GPR ANALYSIS
                        </button>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
