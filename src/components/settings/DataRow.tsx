/**
 * One asset this installation carries, as a row.
 *
 * Why a row and not a card.
 *
 * The CVE snapshot, the offline basemap and the evidence register were three
 * full-width cards, each about 400px tall to show four to six short facts. The
 * Settings page has no width constraint, so on a 1920px display that is a slab
 * nearly 1900px wide holding a two-character entry count — and three of them
 * stacked came to roughly 1,200px of mostly nothing.
 *
 * Constraining the *content* to a reading column, which was the first attempt,
 * made it worse rather than better: the values lined up but the emptiness to
 * their right became the obvious thing on the screen. The container was wrong,
 * not the contents.
 *
 * A row is the shape that uses a wide viewport, and these three are one subject:
 * data this machine holds offline, and how current it is. Together they are a
 * card of about 320px that answers "what do I have, how old is it, and what can
 * I do about it" in one glance.
 *
 * What does not change is what each one is allowed to claim. Every qualification
 * the three cards carried is still here, rendered under the row it belongs to —
 * the point of the rewrite was the container.
 */
import type { ReactNode } from 'react';

export type RowTone = 'ok' | 'warn' | 'bad' | 'idle';

const BADGE: Record<RowTone, string> = {
  ok: 'bg-signal-strong/10 border-signal-strong/40 text-signal-strong',
  warn: 'bg-risk-high/10 border-risk-high/40 text-risk-high',
  bad: 'bg-risk-critical/10 border-risk-critical/40 text-risk-critical',
  // Not a colour: "nothing here yet" is a state, not a problem, and painting it
  // amber would train the operator to ignore the amber that means something.
  idle: 'bg-space-800 border-space-500/40 text-gray-500',
};

export function DataRow({
  name,
  badge,
  tone = 'idle',
  facts,
  action,
  children,
}: {
  name: string;
  /** The one-word condition, in the same place on every row so it can be scanned. */
  badge?: string | null;
  tone?: RowTone;
  /** The facts worth seeing without opening anything. */
  facts?: ReactNode;
  action?: ReactNode;
  /** Warnings, tallies and qualifications, under the row they belong to. */
  children?: ReactNode;
}) {
  return (
    <div className="py-3 border-t border-space-500/15 first:border-t-0">
      <div className="flex items-start gap-4">
        <div className="w-40 shrink-0 text-[11px] font-tactical tracking-wider text-gray-300 uppercase pt-0.5">
          {name}
        </div>
        <div className="w-40 shrink-0">
          {badge && (
            <span className={`inline-block px-2 py-0.5 rounded text-[9px] font-tactical tracking-wider border ${BADGE[tone]}`}>
              {badge}
            </span>
          )}
        </div>
        {/* `min-w-0` so a long path truncates here instead of pushing the action
            button off the end of the card. */}
        <div className="flex-1 min-w-0 text-[11px] font-mono text-gray-400 leading-relaxed">
          {facts}
        </div>
        <div className="shrink-0">{action}</div>
      </div>
      {children && (
        // Indented to the facts column, so a warning reads as belonging to the
        // row above it rather than to the card.
        <div className="mt-2 ml-44 space-y-2">{children}</div>
      )}
    </div>
  );
}

/** A qualification under a row: quieter than the facts, not small enough to skip. */
export function RowNote({ children, title }: { children: ReactNode; title?: string }) {
  // `title` for a value that has to be truncated on screen and readable on
  // hover — a file path, which is the only one so far.
  return (
    <p className="max-w-4xl text-[10px] font-mono text-gray-600 leading-relaxed" title={title}>{children}</p>
  );
}

/** A warning that belongs to one row, in the tone of what it is warning about. */
export function RowCallout({ tone, children }: { tone: Exclude<RowTone, 'idle'>; children: ReactNode }) {
  const style = tone === 'bad'
    ? 'bg-risk-critical/10 border-risk-critical/30 text-risk-critical'
    : tone === 'warn'
      ? 'bg-risk-high/10 border-risk-high/30 text-risk-high'
      : 'bg-signal-strong/10 border-signal-strong/30 text-signal-strong';
  return (
    <div className={`max-w-4xl text-[10px] font-mono leading-relaxed rounded border px-3 py-2 ${style}`}>
      {children}
    </div>
  );
}
