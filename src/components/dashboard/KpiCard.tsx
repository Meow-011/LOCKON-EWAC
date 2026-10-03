/** KpiCard — Glassmorphism stat card with animated counter */
import { motion, useMotionValue, useTransform, animate } from 'framer-motion';
import { useEffect } from 'react';

interface KpiCardProps {
  label: string;
  value: number;
  icon: React.ReactNode;
  accentColor?: string;
  suffix?: string;
  trend?: 'up' | 'down' | 'neutral';
}

export function KpiCard({ label, value, icon, accentColor = 'neon', suffix = '', trend }: KpiCardProps) {
  const count = useMotionValue(0);
  const rounded = useTransform(count, (v) => Math.round(v));

  useEffect(() => {
    const controls = animate(count, value, {
      duration: 1.2,
      ease: 'easeOut',
    });
    return controls.stop;
  }, [value, count]);

  const accentMap: Record<string, string> = {
    neon: 'from-neon-500/25 to-transparent border-neon-500/30',
    red: 'from-risk-critical/30 to-transparent border-risk-critical/30',
    green: 'from-risk-low/25 to-transparent border-risk-low/30',
    blue: 'from-risk-info/25 to-transparent border-risk-info/30',
    orange: 'from-risk-high/30 to-transparent border-risk-high/30',
  };

  const iconColorMap: Record<string, string> = {
    neon: 'text-neon-400',
    red: 'text-risk-critical',
    green: 'text-risk-low',
    blue: 'text-risk-info',
    orange: 'text-risk-high',
  };

  return (
    <motion.div
      className={`relative overflow-hidden rounded-xl bg-gradient-to-br ${accentMap[accentColor]} bg-space-800/50 border backdrop-blur-sm p-4`}
      whileHover={{ scale: 1.02, y: -2 }}
      transition={{ duration: 0.15 }}
    >
      {/* Background decoration */}
      <div className="absolute top-0 right-0 w-20 h-20 opacity-5">
        <div className="w-full h-full scale-[2] translate-x-4 -translate-y-4">
          {icon}
        </div>
      </div>

      <div className="relative z-10">
        <div className="flex items-center justify-between mb-3">
          <span className={`${iconColorMap[accentColor]} opacity-80`}>{icon}</span>
          {trend && (
            <span className={`text-xs font-mono ${trend === 'up' ? 'text-risk-low' : trend === 'down' ? 'text-risk-critical' : 'text-gray-500'}`}>
              {trend === 'up' ? '▲' : trend === 'down' ? '▼' : '—'}
            </span>
          )}
        </div>
        <div className="flex items-baseline gap-1">
          <motion.span className="text-3xl font-bold text-white font-tech tabular-nums tracking-wider">
            {rounded}
          </motion.span>
          {suffix && <span className="text-xs text-gray-500 font-mono">{suffix}</span>}
        </div>
        <p className="text-xs text-gray-400 mt-1 text-tactical tracking-wider">{label}</p>
      </div>
    </motion.div>
  );
}
