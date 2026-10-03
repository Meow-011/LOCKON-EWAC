/** Sidebar — Tactical navigation sidebar with engine status */
import type { ReactNode } from 'react';
import { NavLink } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { useEngineStore } from '../../stores/engineStore';
import { useUIStore } from '../../stores/uiStore';
import { NAV_ITEMS, APP_VERSION } from '../../lib/constants';

const ICONS: Record<string, ReactNode> = {
  radar: (
    <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M19.07 4.93A10 10 0 0 0 6.99 3.34" />
      <path d="M4 6h.01" />
      <path d="M2.29 9.62A10 10 0 1 0 21.31 8.35" />
      <path d="M16.24 7.76A6 6 0 1 0 8.23 16.67" />
      <path d="M12 18H12.01" />
      <path d="M17.99 11.66A6 6 0 0 1 15.77 16.67" />
      <circle cx="12" cy="12" r="2" />
      <path d="m13.41 10.59 5.66-5.66" />
    </svg>
  ),
  target: (
    <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><circle cx="12" cy="12" r="6" /><circle cx="12" cy="12" r="2" />
    </svg>
  ),
  map: (
    <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14.106 5.553a2 2 0 0 0 1.788 0l3.659-1.83A1 1 0 0 1 21 4.619v12.764a1 1 0 0 1-.553.894l-4.553 2.277a2 2 0 0 1-1.788 0l-4.212-2.106a2 2 0 0 0-1.788 0l-3.659 1.83A1 1 0 0 1 3 19.381V6.618a1 1 0 0 1 .553-.894l4.553-2.277a2 2 0 0 1 1.788 0z" />
      <path d="M15 5.764v15" /><path d="M9 3.236v15" />
    </svg>
  ),
  'file-text': (
    <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M15 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7Z" />
      <path d="M14 2v4a2 2 0 0 0 2 2h4" /><path d="M10 9H8" /><path d="M16 13H8" /><path d="M16 17H8" />
    </svg>
  ),
  zap: (
    <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  ),
  unlock: (
    <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 9.9-1" />
    </svg>
  ),
  settings: (
    <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  ),
};

export function Sidebar() {
  const connected = useEngineStore(s => s.connected);
  const scanning = useEngineStore(s => s.scanning);
  const sidebarCollapsed = useUIStore(s => s.sidebarCollapsed);
  const toggleSidebar = useUIStore(s => s.toggleSidebar);

  return (
    <motion.aside
      className="flex flex-col h-screen bg-space-900 border-r border-space-500/20"
      animate={{ width: sidebarCollapsed ? 64 : 220 }}
      transition={{ duration: 0.2, ease: 'easeInOut' }}
    >
      {/* ── Logo ── */}
      <div className="flex items-center gap-3 px-4 h-16 border-b border-space-500/20">
        <div className="relative flex-shrink-0">
          <div className="w-8 h-8 flex items-center justify-center">
            <img src="/LOCKON_logo.svg" alt="LOCKON Logo" className="w-full h-full object-contain" />
          </div>
          {scanning && (
            <motion.div
              className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-risk-low rounded-full"
              animate={{ scale: [1, 1.3, 1], opacity: [1, 0.7, 1] }}
              transition={{ duration: 1, repeat: Infinity }}
            />
          )}
        </div>
        <AnimatePresence>
          {!sidebarCollapsed && (
            <motion.div
              initial={{ opacity: 0, width: 0 }}
              animate={{ opacity: 1, width: 'auto' }}
              exit={{ opacity: 0, width: 0 }}
              className="overflow-hidden whitespace-nowrap"
            >
              <h1 className="text-sm font-bold text-tactical text-white tracking-widest">LOCKON</h1>
              <p className="text-[10px] text-neon-400 font-mono -mt-0.5">EWAC v{APP_VERSION}</p>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* ── Navigation ── */}
      <nav className="flex-1 py-3 px-2 space-y-1 overflow-y-auto">
        {NAV_ITEMS.map((item) => (
          <NavLink
            key={item.id}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm transition-all duration-150 outline-none focus:outline-none
               ${isActive
                ? 'bg-neon-600/15 text-neon-400 border border-neon-500/20'
                : 'text-gray-400 hover:text-gray-200 hover:bg-space-700/50'
              }
               ${sidebarCollapsed ? 'justify-center' : ''}`
            }
          >
            {ICONS[item.icon]}
            <AnimatePresence>
              {!sidebarCollapsed && (
                <motion.span
                  initial={{ opacity: 0, width: 0 }}
                  animate={{ opacity: 1, width: 'auto' }}
                  exit={{ opacity: 0, width: 0 }}
                  className="overflow-hidden whitespace-nowrap font-medium"
                >
                  {item.label}
                </motion.span>
              )}
            </AnimatePresence>
          </NavLink>
        ))}
      </nav>

      {/* ── Shortcut Hints ── */}
      <AnimatePresence>
        {!sidebarCollapsed && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="mx-3 mb-3 mt-auto px-2.5"
          >
            <div className="text-[9px] font-tactical text-gray-600 tracking-widest mb-1.5 uppercase">Navigate</div>
            <div className="space-y-1">
              {NAV_ITEMS.map((item, i) => (
                <div key={item.id} className="flex items-center justify-between">
                  <span className="text-[10px] text-gray-500 font-mono truncate">{item.label}</span>
                  <kbd className="text-[9px] text-gray-600 bg-space-700/60 border border-space-500/20 rounded px-1 py-0.5 font-mono leading-none">
                    Ctrl+{i + 1}
                  </kbd>
                </div>
              ))}
            </div>
            <div className="text-[9px] font-tactical text-gray-600 tracking-widest mt-2.5 mb-1.5 uppercase">Actions</div>
            <div className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-gray-500 font-mono">Scan toggle</span>
                <kbd className="text-[9px] text-gray-600 bg-space-700/60 border border-space-500/20 rounded px-1 py-0.5 font-mono leading-none">Ctrl+S</kbd>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-gray-500 font-mono">Sidebar</span>
                <kbd className="text-[9px] text-gray-600 bg-space-700/60 border border-space-500/20 rounded px-1 py-0.5 font-mono leading-none">Ctrl+B</kbd>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-gray-500 font-mono">Fullscreen</span>
                <kbd className="text-[9px] text-gray-600 bg-space-700/60 border border-space-500/20 rounded px-1 py-0.5 font-mono leading-none">F11</kbd>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-[10px] text-gray-500 font-mono">Close panel</span>
                <kbd className="text-[9px] text-gray-600 bg-space-700/60 border border-space-500/20 rounded px-1 py-0.5 font-mono leading-none">Esc</kbd>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* ── Engine Status ── */}
      <div className="px-3 py-3 border-t border-space-500/20">
        <div className={`flex items-center gap-2 ${sidebarCollapsed ? 'justify-center' : ''}`}>
          <div className={`w-2 h-2 rounded-full ${connected ? 'bg-risk-low' : 'bg-risk-critical'}`} />
          <AnimatePresence>
            {!sidebarCollapsed && (
              <motion.span
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="text-xs text-gray-500 font-mono"
              >
                Engine: {connected ? 'ONLINE' : 'OFFLINE'}
              </motion.span>
            )}
          </AnimatePresence>
        </div>
      </div>

      {/* ── Collapse Toggle ── */}
      <button
        onClick={toggleSidebar}
        className="flex items-center justify-center h-10 border-t border-space-500/20 text-gray-500 hover:text-gray-300 hover:bg-space-800 transition-colors"
      >
        <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
          style={{ transform: sidebarCollapsed ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}
        >
          <path d="m11 17-5-5 5-5" /><path d="m18 17-5-5 5-5" />
        </svg>
      </button>
    </motion.aside>
  );
}
