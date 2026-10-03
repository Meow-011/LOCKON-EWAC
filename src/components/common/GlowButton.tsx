/** GlowButton — Tactical neon-glow action button */
import { motion } from 'framer-motion';

interface GlowButtonProps {
  children: React.ReactNode;
  onClick?: () => void;
  variant?: 'primary' | 'danger' | 'ghost';
  size?: 'sm' | 'md' | 'lg';
  disabled?: boolean;
  className?: string;
}

const VARIANTS = {
  primary: {
    base: 'bg-neon-600 hover:bg-neon-500 text-white',
    glow: '',
  },
  danger: {
    base: 'bg-risk-critical/20 hover:bg-risk-critical/30 text-risk-critical border border-risk-critical/40',
    glow: '',
  },
  ghost: {
    base: 'bg-space-700/50 hover:bg-space-600 text-gray-300 border border-space-500/30',
    glow: '',
  },
};

const SIZES = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-6 py-3 text-base',
};

export function GlowButton({
  children,
  onClick,
  variant = 'primary',
  size = 'md',
  disabled = false,
  className = '',
}: GlowButtonProps) {
  const v = VARIANTS[variant];
  const s = SIZES[size];

  return (
    <motion.button
      onClick={onClick}
      disabled={disabled}
      className={`
        inline-flex items-center justify-center gap-2
        rounded-lg font-medium
        transition-all duration-200
        ${v.base} ${v.glow} ${s}
        disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none
        ${className}
      `}
      whileHover={disabled ? {} : { scale: 1.02 }}
      whileTap={disabled ? {} : { scale: 0.98 }}
    >
      {children}
    </motion.button>
  );
}
