/**
 * LOCKON EWAC — The archive's export menu.
 *
 * Eight buttons sat in one row: a credential-disclosure toggle, five export
 * formats, a clipboard copy, and PURGE. They shared a size, a font and a
 * border, so nothing about the row told the eye that one of them deletes the
 * archive and another decides whether recovered passwords leave the building in
 * cleartext. This collapses the six that merely produce a file into one menu,
 * grouped by what the reader of that file is going to do with it.
 *
 * Two controls are deliberately **not** in here, and the reasons are different:
 *
 *   * **The credential toggle** is a mode, not an action, and it changes what
 *     the PDF contains. Hidden behind a menu, its state would be invisible at
 *     the moment the operator clicks Export — which is the only moment it
 *     matters. It stays on the surface, and the state is repeated on the PDF
 *     row here so it is impossible to export without seeing it.
 *   * **PURGE** is irreversible. A destructive action one row below "JSON to
 *     clipboard" in a list of exports is how somebody deletes an engagement
 *     they meant to send to a client.
 *
 * Items that cannot work for this archive are shown disabled with the reason,
 * rather than accepting the click and answering with a toast. A KML export of a
 * LAN sweep was never going to produce anything: there are no coordinates in it.
 */
import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';

export interface ExportItem {
  /** Stable key, also used for the "done" flash. */
  id: string;
  label: string;
  /** One line under the label — what the file is and who opens it. */
  hint?: string;
  onSelect: () => void;
  /** Set when the item cannot work here; the text says why. */
  disabledReason?: string | null;
  /** Shown in place of the label after a successful action. */
  doneLabel?: string;
  done?: boolean;
  busy?: boolean;
  /** A short state note rendered on the right, e.g. the credential mode. */
  note?: string;
  noteTone?: 'normal' | 'warning';
  /**
   * Marks the current choice in a group of alternatives.
   *
   * Used by the retest baseline, which is a setting rather than an action:
   * picking one decides what the *next* PDF contains, so the menu has to show
   * which one is in force rather than only offering the list.
   */
  selected?: boolean;
  /** Leave the menu open after choosing — for a setting, not an action. */
  keepOpen?: boolean;
}

export interface ExportGroup {
  title: string;
  /** One line explaining what the group is for, when the titles are not enough. */
  items: ExportItem[];
}

interface Props {
  groups: ExportGroup[];
  /** Disables the trigger, e.g. while a PDF is rendering. */
  busy?: boolean;
  busyLabel?: string;
}

/** Menu width in pixels. Needed here because the panel is positioned by hand. */
const MENU_WIDTH = 304;
/** Keep this much clear of the viewport edge when flipping the panel upward. */
const VIEWPORT_MARGIN = 12;

export function ExportMenu({ groups, busy = false, busyLabel = 'EXPORTING' }: Props) {
  const [open, setOpen] = useState(false);
  const [placement, setPlacement] = useState<{ left: number; top: number; maxHeight: number } | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);

  /*
    The panel is rendered into `document.body` and positioned by hand, rather
    than absolutely inside this component.

    The card this menu sits in is `overflow-hidden` — it has to be, for the
    rounded corners and the scrolling table below. An absolutely positioned
    dropdown inside it is clipped at the card's edge, and how much of the menu
    survives depends on the window height. It would have looked right on this
    screen and lost its last group on a laptop, which is the kind of bug that
    only shows up in front of somebody else.
  */
  const place = useCallback(() => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const rect = trigger.getBoundingClientRect();
    const spaceBelow = window.innerHeight - rect.bottom - VIEWPORT_MARGIN;
    const spaceAbove = rect.top - VIEWPORT_MARGIN;
    // Open upward when there is materially more room there, so the menu is not
    // squeezed into a scrolling stub near the bottom of the window.
    const above = spaceBelow < 260 && spaceAbove > spaceBelow;
    const height = panelRef.current?.offsetHeight ?? 0;

    setPlacement({
      // Right-aligned to the trigger, then pulled back inside the viewport.
      left: Math.max(
        VIEWPORT_MARGIN,
        Math.min(rect.right - MENU_WIDTH, window.innerWidth - MENU_WIDTH - VIEWPORT_MARGIN),
      ),
      top: above
        ? Math.max(VIEWPORT_MARGIN, rect.top - 8 - (height || Math.min(spaceAbove, 420)))
        : rect.bottom + 8,
      maxHeight: above ? spaceAbove - 8 : spaceBelow - 8,
    });
  }, []);

  useLayoutEffect(() => {
    if (!open) {
      setPlacement(null);
      return;
    }
    place();
    // A scroll or resize while the menu is open would leave it floating where
    // the button used to be: it is no longer a child of anything that moves
    // with the page.
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
    return () => {
      window.removeEventListener('scroll', place, true);
      window.removeEventListener('resize', place);
    };
  }, [open, place]);

  /*
    Close on anything that means "not this".

    `pointerdown` rather than `click`: a click that starts inside the menu and
    ends outside it (a drag, or a mis-aimed press) should not be treated as a
    dismissal, and pointerdown is where the intent actually is.

    Escape also returns focus to the trigger, so a keyboard operator is not
    dropped at the top of the document.
  */
  useEffect(() => {
    if (!open) return;

    const onPointerDown = (event: PointerEvent) => {
      const target = event.target as Node;
      // Both, because the panel is portaled to `document.body` and is
      // therefore not a descendant of the trigger's container. Checking only
      // the container would dismiss the menu on the way to clicking an item.
      const inside = containerRef.current?.contains(target)
        || panelRef.current?.contains(target);
      if (!inside) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    // The app's global Escape handler closes drawers; this listens first so
    // Escape closes the menu rather than whatever is behind it.
    document.addEventListener('pointerdown', onPointerDown, true);
    document.addEventListener('keydown', onKeyDown, true);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown, true);
      document.removeEventListener('keydown', onKeyDown, true);
    };
  }, [open]);

  const choose = (item: ExportItem) => {
    if (item.disabledReason || item.busy) return;
    // A setting leaves the menu open so the operator can see the choice take
    // effect — and, for the baseline, see it reflected on the PDF row above.
    if (!item.keepOpen) setOpen(false);
    item.onSelect();
  };

  return (
    <div className="relative" ref={containerRef}>
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen(v => !v)}
        disabled={busy}
        aria-haspopup="menu"
        aria-expanded={open}
        className={`px-4 py-2 border rounded text-xs font-tactical tracking-wider transition-colors
          flex items-center justify-center gap-2 min-w-[120px] ${
          busy
            ? 'bg-space-800 border-space-500/50 text-gray-400 cursor-not-allowed'
            : 'bg-space-800 hover:bg-space-700 border-space-500/30 text-white'
        }`}
      >
        {busy ? (
          <>
            <svg className="w-4 h-4 animate-spin text-gray-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
            </svg>
            {busyLabel}
          </>
        ) : (
          <>
            <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4 text-gray-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            EXPORT
            <svg xmlns="http://www.w3.org/2000/svg" className={`w-3 h-3 text-gray-500 transition-transform ${open ? 'rotate-180' : ''}`} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="6 9 12 15 18 9" />
            </svg>
          </>
        )}
      </button>

      {open && createPortal(
        <div
          role="menu"
          ref={panelRef}
          style={{
            position: 'fixed',
            left: placement?.left ?? -9999,
            top: placement?.top ?? -9999,
            width: MENU_WIDTH,
            maxHeight: placement ? Math.max(180, placement.maxHeight) : undefined,
            // Hidden until measured, so the first paint is not at the wrong
            // place followed by a visible jump.
            visibility: placement ? 'visible' : 'hidden',
          }}
          className="z-[60] rounded-lg border border-space-500/40 bg-space-900/98 backdrop-blur
                     shadow-2xl shadow-black/60 overflow-y-auto overscroll-contain"
        >
          {groups.map((group, groupIndex) => (
            <div key={group.title} className={groupIndex > 0 ? 'border-t border-space-500/20' : ''}>
              <div className="px-3 pt-2.5 pb-1 text-[9px] font-tactical tracking-[0.2em] text-gray-500">
                {group.title}
              </div>
              {group.items.map(item => {
                const disabled = !!item.disabledReason || !!item.busy;
                return (
                  <button
                    key={item.id}
                    role="menuitem"
                    type="button"
                    onClick={() => choose(item)}
                    disabled={disabled}
                    /*
                      The reason travels in the tooltip as well as on the row.
                      A disabled control that does not say why is a dead end,
                      and this one is disabled for a reason the operator can
                      act on — export from the other archive.
                    */
                    title={item.disabledReason ?? item.hint ?? undefined}
                    className={`w-full text-left px-3 py-2 flex items-start gap-3 transition-colors ${
                      disabled
                        ? 'opacity-45 cursor-not-allowed'
                        : 'hover:bg-space-700/70 focus:bg-space-700/70 focus:outline-none'
                    }`}
                  >
                    {/* A fixed-width gutter, so labels line up whether or not
                        the group is a set of alternatives. */}
                    {typeof item.selected === 'boolean' && (
                      <span className={`mt-1 w-1.5 h-1.5 rounded-full shrink-0 ${
                        item.selected ? 'bg-neon-400' : 'bg-space-600'
                      }`} />
                    )}
                    <div className="min-w-0 flex-1">
                      <div className={`text-xs font-tactical tracking-wider ${
                        item.done ? 'text-signal-strong'
                          : item.selected ? 'text-neon-300'
                          : disabled ? 'text-gray-400' : 'text-white'
                      }`}>
                        {item.done && item.doneLabel ? item.doneLabel : item.label}
                      </div>
                      {(item.disabledReason || item.hint) && (
                        <div className="text-[10px] font-mono text-gray-500 leading-snug mt-0.5">
                          {item.disabledReason ?? item.hint}
                        </div>
                      )}
                    </div>
                    {item.note && (
                      <span
                        className={`shrink-0 mt-0.5 px-1.5 py-0.5 rounded text-[9px] font-mono ${
                          item.noteTone === 'warning'
                            ? 'bg-risk-critical/20 text-risk-critical border border-risk-critical/40'
                            : 'bg-space-800 text-gray-400 border border-space-500/30'
                        }`}
                      >
                        {item.note}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </div>,
        document.body,
      )}
    </div>
  );
}
