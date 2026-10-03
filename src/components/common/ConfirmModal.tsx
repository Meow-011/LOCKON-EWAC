/** LOCKON EWAC — Tactical Confirm Modal */
import { motion, AnimatePresence } from 'framer-motion';

interface ConfirmModalProps {
  isOpen: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  variant?: 'danger' | 'warning' | 'info';
  onConfirm: () => void;
  onCancel: () => void;
}

export function ConfirmModal({
  isOpen,
  title,
  message,
  confirmLabel = 'CONFIRM',
  cancelLabel = 'CANCEL',
  variant = 'danger',
  onConfirm,
  onCancel,
}: ConfirmModalProps) {
  const variantStyles = {
    danger: {
      icon: '⚠',
      border: 'border-risk-critical/40',
      bg: 'bg-risk-critical/10',
      btnBg: 'bg-risk-critical hover:bg-risk-critical/80',
      text: 'text-risk-critical',
    },
    warning: {
      icon: '⚡',
      border: 'border-risk-high/40',
      bg: 'bg-risk-high/10',
      btnBg: 'bg-risk-high hover:bg-risk-high/80',
      text: 'text-risk-high',
    },
    info: {
      icon: 'ℹ',
      border: 'border-neon-500/40',
      bg: 'bg-neon-500/10',
      btnBg: 'bg-neon-600 hover:bg-neon-500',
      text: 'text-neon-400',
    },
  };

  const s = variantStyles[variant];

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onCancel}
            className="fixed inset-0 z-[300] bg-space-950/70 backdrop-blur-sm"
          />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 20 }}
            transition={{ type: 'spring', damping: 25, stiffness: 300 }}
            className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-[301] w-full max-w-md"
          >
            <div className={`bg-space-900 border ${s.border} rounded-xl shadow-2xl overflow-hidden`}>
              {/* Header */}
              <div className={`px-6 pt-6 pb-4 ${s.bg} border-b border-space-500/20`}>
                <div className="flex items-center gap-3">
                  <span className={`text-2xl ${s.text}`}>{s.icon}</span>
                  <h3 className="text-lg font-bold text-white font-tactical tracking-wider">{title}</h3>
                </div>
              </div>

              {/* Body */}
              <div className="px-6 py-5">
                {/* pre-line so a multi-paragraph message keeps its breaks;
                    without it every newline collapsed into one wall of text. */}
                <p className="text-sm text-gray-300 font-mono leading-relaxed whitespace-pre-line">{message}</p>
              </div>

              {/* Actions */}
              <div className="px-6 pb-5 flex items-center justify-end gap-3">
                <button
                  onClick={onCancel}
                  className="px-5 py-2.5 text-xs font-tactical tracking-widest uppercase text-gray-400 hover:text-white bg-space-800 hover:bg-space-700 border border-space-500/30 rounded-lg transition-colors"
                >
                  {cancelLabel}
                </button>
                <button
                  onClick={() => { onConfirm(); onCancel(); }}
                  className={`px-5 py-2.5 text-xs font-tactical tracking-widest uppercase text-white ${s.btnBg} rounded-lg transition-colors shadow-lg`}
                >
                  {confirmLabel}
                </button>
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
