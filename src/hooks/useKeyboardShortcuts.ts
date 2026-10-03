/** LOCKON EWAC — Global Keyboard Shortcuts */
import { useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useUIStore } from '../stores/uiStore';
import { useEngineStore } from '../stores/engineStore';
import { useMissionStore } from '../stores/missionStore';
import { engineIPC } from '../lib/ipc';
import { createMission } from '../lib/wardrivingDB';
import type { Mission } from '../types/models';

const NAV_KEYS: Record<string, string> = {
  '1': '/',
  '2': '/intrusion',
  '3': '/decryptor',
  '4': '/reports',
  '5': '/settings',
};

export function useKeyboardShortcuts() {
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      // Ignore when typing in input/textarea/contenteditable
      const target = e.target as HTMLElement;
      if (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.isContentEditable
      ) {
        return;
      }

      // ── Ctrl+1 through Ctrl+5 — Quick navigation ──
      if (e.ctrlKey && !e.shiftKey && !e.altKey && NAV_KEYS[e.key]) {
        e.preventDefault();
        const path = NAV_KEYS[e.key];
        if (location.pathname !== path) {
          navigate(path);
        }
        return;
      }

      // ── Ctrl+B — Toggle sidebar ──
      if (e.ctrlKey && !e.shiftKey && !e.altKey && e.key === 'b') {
        e.preventDefault();
        useUIStore.getState().toggleSidebar();
        return;
      }

      // ── Ctrl+S — Toggle wardriving scan ──
      if (e.ctrlKey && !e.shiftKey && !e.altKey && e.key === 's') {
        e.preventDefault();
        const { connected, scanning, config } = useEngineStore.getState();
        if (!connected) return;

        if (scanning) {
          // Stop scan
          engineIPC.send('stop_scan').catch(console.error);
          useEngineStore.getState().setScanning(false);
        } else {
          // Start scan — create mission if needed
          const { activeMission, startMission } = useMissionStore.getState();
          if (activeMission) {
            // Resume existing mission
            engineIPC.send('start_scan', {
              simulate: config.emulateHardware,
              com_port: config.comPort,
              baud_rate: config.baudRate,
              interface_name: config.interfaceName,
              scan_interval: config.scanInterval,
            }).catch(console.error);
            useEngineStore.getState().setScanning(true);
          } else {
            // Create new mission
            const missionName = `WARDESK-${new Date().toISOString().split('T')[0]}`;
            createMission(missionName, config.emulateHardware).then((missionId) => {
              const mission: Mission = {
                id: missionId,
                name: missionName,
                status: 'ACTIVE',
                start_time: new Date().toISOString(),
                created_at: new Date().toISOString(),
                is_simulated: config.emulateHardware ? 1 : 0,
              };
              startMission(mission);
              return engineIPC.send('start_scan', {
                mission_id: missionId,
                simulate: config.emulateHardware,
                com_port: config.comPort,
                baud_rate: config.baudRate,
                interface_name: config.interfaceName,
                scan_interval: config.scanInterval,
              }).then(() => {
                useEngineStore.getState().setScanning(true);
              });
            }).catch((err) => {
              // Ctrl+S used to fail completely silently here.
              console.error('[Scan] start failed:', err);
              window.dispatchEvent(new CustomEvent('lockon:toast', {
                detail: { message: `Could not start scan: ${err}`, type: 'error' },
              }));
            });
          }
        }
        return;
      }

      // ── Ctrl+, — Jump to Settings ──
      if (e.ctrlKey && !e.shiftKey && !e.altKey && e.key === ',') {
        e.preventDefault();
        if (location.pathname !== '/settings') {
          navigate('/settings');
        }
        return;
      }

      // ── F11 — Toggle fullscreen ──
      if (e.key === 'F11') {
        e.preventDefault();
        import('@tauri-apps/api/window').then(({ getCurrentWindow }) => {
          const win = getCurrentWindow();
          win.isFullscreen().then((isFs) => {
            win.setFullscreen(!isFs);
          });
        }).catch(console.error);
        return;
      }

      /*
        ── Ctrl+Shift+X — stop every deauthentication at once ──

        `stop_all_strikes` existed in the engine and nothing ever sent it, so
        the only way to stop a deauth was one MAC at a time from the host
        drawer. Deauthentication is the most disruptive thing this tool does and
        the one most likely to be aimed at the wrong device, so a single
        unconditional stop is worth a shortcut.

        Deliberately fired without confirmation: a confirmation dialog on a
        panic stop is a dialog between the operator and stopping.
      */
      if (e.ctrlKey && e.shiftKey && (e.key === 'X' || e.key === 'x')) {
        e.preventDefault();
        import('../lib/ipc').then(({ engineIPC }) => {
          engineIPC.send('stop_all_strikes').catch(console.error);
        }).catch(console.error);
        window.dispatchEvent(new CustomEvent('lockon:toast', {
          detail: { message: 'PANIC STOP: every active deauthentication was told to cease.', type: 'warning' },
        }));
        return;
      }

      // ── Escape — Close drawers/modals ──
      if (e.key === 'Escape') {
        window.dispatchEvent(new CustomEvent('lockon:escape'));
        return;
      }
    };

    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [navigate, location.pathname]);
}
