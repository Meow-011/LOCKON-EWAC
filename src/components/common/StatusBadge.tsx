/** StatusBadge — Risk level & status badges with tactical styling */
import { motion } from 'framer-motion';
import { severityClasses } from '../../lib/severityStyle';
import type { Severity } from '../../lib/riskEngine';

interface StatusBadgeProps {
  level: Severity | 'ACTIVE' | 'SYNCED' | 'PAUSED';
  label?: string;
  pulse?: boolean;
}

/*
  The five severities come from `severityStyle`, which the PDF and every table
  also read. The three states below are not severities — they describe what the
  application is doing, not how bad something is — so they keep their own
  styling here rather than being forced into the risk palette.
*/
const STATE_STYLES: Record<string, { bg: string; text: string; dot: string }> = {
  ACTIVE: { bg: 'bg-neon-500/15',  text: 'text-neon-400',  dot: 'bg-neon-500' },
  SYNCED: { bg: 'bg-risk-info/15', text: 'text-risk-info', dot: 'bg-risk-info' },
  PAUSED: { bg: 'bg-gray-500/15',  text: 'text-gray-400',  dot: 'bg-gray-500' },
};

export function StatusBadge({ level, label, pulse = false }: StatusBadgeProps) {
  const style = STATE_STYLES[level] ?? severityClasses(level);
  const displayLabel = label || level;

  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium ${style.bg} ${style.text}`}>
      <motion.span
        className={`w-1.5 h-1.5 rounded-full ${style.dot}`}
        animate={pulse ? { scale: [1, 1.5, 1], opacity: [1, 0.5, 1] } : {}}
        transition={{ duration: 1.5, repeat: Infinity }}
      />
      {displayLabel}
    </span>
  );
}
