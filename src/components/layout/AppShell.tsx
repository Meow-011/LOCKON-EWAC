/** AppShell — Main layout wrapper with sidebar + content */
import { useCallback, useEffect, useRef, useState } from 'react';
import { Outlet } from 'react-router-dom';
import { engineIPC } from '../../lib/ipc';
import { registerEngineHandlers, type ToastType } from '../../lib/engineRouter';
import { useUIStore } from '../../stores/uiStore';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { useKeyboardShortcuts } from '../../hooks/useKeyboardShortcuts';


let audioCtx: AudioContext | null = null;
function playSonarPing(isHighRisk: boolean) {
  try {
    if (!audioCtx) {
      audioCtx = new (window.AudioContext || (window as any).webkitAudioContext)();
    }
    if (audioCtx.state === 'suspended') {
      audioCtx.resume().catch(() => {});
    }
    
    const osc = audioCtx.createOscillator();
    const gain = audioCtx.createGain();
    
    osc.connect(gain);
    gain.connect(audioCtx.destination);
    
    if (isHighRisk) {
       osc.type = 'square';
       osc.frequency.setValueAtTime(880, audioCtx.currentTime); 
       osc.frequency.exponentialRampToValueAtTime(440, audioCtx.currentTime + 0.2);
       gain.gain.setValueAtTime(0.05, audioCtx.currentTime);
       gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.2);
       osc.start();
       osc.stop(audioCtx.currentTime + 0.2);
    } else {
       osc.type = 'sine';
       osc.frequency.setValueAtTime(600, audioCtx.currentTime);
       gain.gain.setValueAtTime(0.02, audioCtx.currentTime);
       gain.gain.exponentialRampToValueAtTime(0.001, audioCtx.currentTime + 0.1);
       osc.start();
       osc.stop(audioCtx.currentTime + 0.1);
    }
  } catch (e) {
    // Sliently fail audio on strict browsers
  }
}

export function AppShell() {
  useKeyboardShortcuts();


  // Intrusion Actions

  const [connError, setConnError] = useState<string | null>(null);
  const [engineToast, setEngineToast] = useState<{ show: boolean; message: string; type: ToastType }>({ show: false, message: '', type: 'info' });
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Tracked so it can be cleared on unmount — the old version left a dangling
  // timer that called setState after the component was gone.
  const showEngineToast = useCallback((message: string, type: ToastType = 'error', duration = 5000) => {
    if (toastTimer.current) clearTimeout(toastTimer.current);
    setEngineToast({ show: true, message, type });
    toastTimer.current = setTimeout(() => {
      toastTimer.current = null;
      setEngineToast(prev => ({ ...prev, show: false }));
    }, duration);
  }, []);

  useEffect(() => {
    /**
     * The app dispatches `lockon:toast` from 16 places (GPR, WPS, hashcat,
     * PMKID, auto-attack, archive actions) and nothing ever listened, so every
     * one of those messages was discarded. This is that listener.
     */
    const onAppToast = (e: Event) => {
      const detail = (e as CustomEvent).detail as { message?: string; type?: string } | undefined;
      if (!detail?.message) return;
      const raw = detail.type;
      const type: ToastType =
        raw === 'error' ? 'error' :
        raw === 'warning' ? 'warning' :
        raw === 'success' ? 'success' : 'info';
      showEngineToast(detail.message, type, type === 'error' ? 6000 : 4000);
    };
    window.addEventListener('lockon:toast', onAppToast);
    return () => window.removeEventListener('lockon:toast', onAppToast);
  }, [showEngineToast]);

  useEffect(() => {
    /**
     * `lockon:escape` was dispatched by the keyboard shortcut hook with a
     * "close drawers/modals" comment and no listener. These are the dismissible
     * overlays the UI stores actually track.
     */
    const onEscape = () => {
      const ui = useUIStore.getState();
      if (ui.showMissionArchive) ui.setShowMissionArchive(false);
      else if (ui.selectedBssid) ui.setSelectedBssid(null);
      else if (ui.dashboardFocus) ui.clearDashboardFocus();
    };
    window.addEventListener('lockon:escape', onEscape);
    return () => window.removeEventListener('lockon:escape', onEscape);
  }, []);

  /*
    The engine's whole event surface lives in `src/lib/engineRouter.ts`.

    Sixty-one handlers used to sit in this effect. Forty-eight were pure
    routing — event in, store or SQLite row out — and none of them was
    reachable from a test while they lived in a component closure. What is left
    here is the three things that are actually visible: the toast, the offline
    banner and the sonar ping.
  */
  useEffect(() => {
    const stopRouting = registerEngineHandlers({
      showToast: showEngineToast,
      setConnError,
      sonarPing: playSonarPing,
    });
    return () => {
      stopRouting();
      if (toastTimer.current) clearTimeout(toastTimer.current);
    };
  }, [showEngineToast]);

  useEffect(() => {
    // Stop the sidecar when the window actually goes away, so a closed app does
    // not leave an orphaned engine process behind.
    const shutdown = () => { engineIPC.disconnect().catch(() => {}); };
    window.addEventListener('beforeunload', shutdown);
    return () => window.removeEventListener('beforeunload', shutdown);
  }, []);

  return (
    <div className="flex h-screen bg-space-950 overflow-hidden relative">
      {connError && (
        <div className="absolute top-16 left-1/2 -translate-x-1/2 z-50 bg-risk-critical/90 text-white px-4 py-2 rounded-lg font-mono text-sm border border-risk-critical animate-pulse flex items-center gap-2">
          <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          {connError}
        </div>
      )}
      <Sidebar />
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar />
        <main className="flex-1 overflow-hidden p-4">
          <Outlet />
        </main>
      </div>

      {/* Global Engine Toast */}
      {engineToast.show && (
        <div className={`fixed bottom-6 left-1/2 -translate-x-1/2 z-[200] max-w-[min(90vw,720px)] px-5 py-3 rounded-lg border backdrop-blur-md shadow-2xl text-xs font-tactical tracking-wider flex items-start gap-2 animate-in fade-in slide-in-from-bottom-4 duration-300 ${
          engineToast.type === 'error' ? 'bg-risk-critical/20 border-risk-critical/40 text-risk-critical' :
          engineToast.type === 'warning' ? 'bg-risk-high/20 border-risk-high/40 text-risk-high' :
          'bg-neon-500/20 border-neon-500/40 text-neon-400'
        }`}>
          <span className="shrink-0">
            {engineToast.type === 'error' ? '✗' : engineToast.type === 'warning' ? '⚠' : '✓'}
          </span>
          <span className="break-words">{engineToast.message}</span>
        </div>
      )}
    </div>
  );
}
