/**
 * LOCKON EWAC — one colour per severity, for the screen and for paper.
 *
 * Six places decided this independently and they did not agree. The
 * disagreements were not cosmetic:
 *
 *   * The archive telemetry tables drew **HIGH in CRITICAL's red**, at a lighter
 *     opacity. Two levels the rule set separates deliberately — and that the
 *     document spends a page explaining — were one hue apart in the only view
 *     where a reader scans a long list quickly.
 *   * The CVE chips on the intrusion screen tested `severity === 'CRITICAL'`
 *     and painted **everything else as HIGH**, so a MEDIUM CVE carried HIGH's
 *     border while its own label said MEDIUM. Elsewhere on the same screen every
 *     level below HIGH was amber, which made a LOW finding the colour of a
 *     warning.
 *   * LOW was styled from the *signal strength* palette (`signal-strong`). That
 *     one is invisible — `--color-signal-strong` and `--color-risk-low` are both
 *     `#22c55e` — but it means a change to either palette silently changes the
 *     other's meaning.
 *
 * This is the same failure the risk rule set was consolidated for: a severity
 * that reads one way in one place and another way somewhere else. `riskEngine`
 * fixed which level a finding gets; this fixes what that level looks like.
 *
 * **Screen and print are deliberately different colours and that is not a bug.**
 * The screen palette (`--color-risk-*` in `index.css`) is tuned for light text
 * on a near-black background. The print triples are darker, because the same
 * hues on white paper are thin and several of them do not survive a monochrome
 * printer or a photocopy — and this document gets printed and handed over.
 * Keep the two tables next to each other so a change to one prompts the
 * question about the other.
 */
import { severityForEncryption, type Severity } from './riskEngine';
export { severityForEncryption };

/** Worst first. The order findings are listed and summarised in. */
export const SEVERITY_LEVELS: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export interface SeverityClasses {
  /** Foreground, for the level's own text. */
  text: string;
  /** Tinted background for a badge or chip. */
  bg: string;
  /** Border for a chip or a card edge. */
  border: string;
  /** Solid fill, for a status dot. */
  dot: string;
  /** `bg` + `text` + `border` together, which is how most chips use it. */
  chip: string;
}

/*
  Every class written out in full, and never assembled from a variable.

  Tailwind finds classes by scanning the source for complete strings. A helper
  like `` text-${token} `` produces the right string at run time and puts nothing
  in the stylesheet, so the class resolves to no rule at all — a severity chip
  with no colour, which reads as a rendering glitch rather than as a finding.

  This is not hypothetical: the first version of this file did exactly that, and
  `.text-risk-medium` was absent from the built CSS, so every MEDIUM finding lost
  its colour. `tsc`, the unit tests and the CSP smoke test all passed. Only
  grepping the built stylesheet showed it, which is why the test for this reads
  this file's own source and asserts each class appears here verbatim.

  So: if a new opacity or utility is needed, write the whole class out.
*/
export const SEVERITY_CLASSES: Record<Severity, SeverityClasses> = {
  CRITICAL: {
    text: 'text-risk-critical',
    bg: 'bg-risk-critical/15',
    border: 'border-risk-critical/50',
    dot: 'bg-risk-critical',
    chip: 'bg-risk-critical/15 text-risk-critical border-risk-critical/50',
  },
  HIGH: {
    text: 'text-risk-high',
    bg: 'bg-risk-high/15',
    border: 'border-risk-high/50',
    dot: 'bg-risk-high',
    chip: 'bg-risk-high/15 text-risk-high border-risk-high/50',
  },
  MEDIUM: {
    text: 'text-risk-medium',
    bg: 'bg-risk-medium/15',
    border: 'border-risk-medium/50',
    dot: 'bg-risk-medium',
    chip: 'bg-risk-medium/15 text-risk-medium border-risk-medium/50',
  },
  LOW: {
    text: 'text-risk-low',
    bg: 'bg-risk-low/15',
    border: 'border-risk-low/50',
    dot: 'bg-risk-low',
    chip: 'bg-risk-low/15 text-risk-low border-risk-low/50',
  },
  INFO: {
    text: 'text-risk-info',
    bg: 'bg-risk-info/15',
    border: 'border-risk-info/50',
    dot: 'bg-risk-info',
    chip: 'bg-risk-info/15 text-risk-info border-risk-info/50',
  },
};

/**
 * Screen styling for a severity, falling back to INFO.
 *
 * The fallback is INFO and never CRITICAL: a value this module does not
 * recognise is an unknown, and painting an unknown red states a finding the
 * rule set did not make.
 */
export function severityClasses(level: unknown): SeverityClasses {
  const key = String(level ?? '').toUpperCase() as Severity;
  return SEVERITY_CLASSES[key] ?? SEVERITY_CLASSES.INFO;
}

/**
 * Print colour per severity, for jsPDF.
 *
 * Darker than the screen palette on purpose — see the note at the top of this
 * file. CRITICAL is the deepest red rather than the brightest: on paper a dark
 * red reads as more serious than a vivid one, and it stays distinguishable from
 * HIGH after a photocopy.
 */
export const SEVERITY_RGB: Record<Severity, [number, number, number]> = {
  CRITICAL: [153, 27, 27],
  HIGH: [220, 38, 38],
  MEDIUM: [217, 119, 6],
  /*
    Green, and specifically green-700 rather than the screen's green-500.

    The scale has to read at a glance as safe-to-dangerous, and it did not: the
    screen palette has LOW at `#22c55e` (green) while this table had it at teal
    `[13,148,136]`. The same level was green in the app and blue-green on paper,
    which is the exact class of disagreement this file exists to remove.

    It is not simply the screen value copied across. `#22c55e` on white is thin
    and goes pale under a monochrome printer; green-700 is the same hue carried
    down to a weight that survives both. See the note above on why the two
    tables differ at all.
  */
  LOW: [21, 128, 61],
  /*
    INFO stays neutral on purpose. It is not the safe end of the scale — it is
    the absence of a judgment, and painting it green would state a conclusion
    the rule set did not reach.
  */
  INFO: [100, 116, 139],
};

/**
 * Print colour for "nothing was raised against this subject".
 *
 * Not a severity, and deliberately not green. A subject with no finding is one
 * this tool had no opinion about, which is not the same as one it cleared --- a
 * distinction the method appendix states outright and that a green dot on a map
 * would quietly contradict. Lighter than INFO so the two read as different
 * marks where both appear.
 */
export const NO_FINDING_RGB: [number, number, number] = [148, 163, 184];

/** Print colour for a severity, falling back to INFO for the same reason. */
export function severityRgb(level: unknown): [number, number, number] {
  const key = String(level ?? '').toUpperCase();
  if (key === 'NONE') return NO_FINDING_RGB;
  return SEVERITY_RGB[key as Severity] ?? SEVERITY_RGB.INFO;
}

/*
  ── Security-mode badges ──────────────────────────────────────────────────────

  A security mode's colour is not a separate judgment; it is the rule set's
  severity for that mode, looked up. Three screens used to keep their own
  encryption table and all three disagreed with the rules — see
  `severityForEncryption` for what each one got wrong.

  The neutral style below is the third state, and the reason these live here
  rather than being written inline: "the adapter did not report a security mode"
  has to look different from both "this is fine" and "this is dangerous". Every
  one of the old tables had an `else` branch, and in `TargetDrawer` that branch
  was green.
*/

/** Grey, for a mode that could not be read. Never green — green is a claim. */
export const UNASSESSED_CLASSES = {
  text: 'text-gray-400',
  bg: 'bg-space-600/50',
  chip: 'bg-space-600/50 text-gray-400',
} as const;

/** Chip classes for a security-mode badge: `bg` + `text`, no border. */
export function encryptionBadgeClasses(encryption?: string | null): string {
  const level = severityForEncryption(encryption);
  if (!level) return UNASSESSED_CLASSES.chip;
  const c = SEVERITY_CLASSES[level];
  return `${c.bg} ${c.text}`;
}

/** Text colour alone, for a mode rendered as plain text rather than a chip. */
export function encryptionTextClass(encryption?: string | null): string {
  const level = severityForEncryption(encryption);
  return level ? SEVERITY_CLASSES[level].text : UNASSESSED_CLASSES.text;
}

/**
 * Tooltip naming the level and where it came from.
 *
 * The colour alone is an assertion with no stated basis, and this tool's whole
 * argument is that a severity a reader cannot trace to a rule is not evidence.
 * One hover is the cheapest place to state it.
 */
export function encryptionBadgeTitle(encryption?: string | null): string {
  const level = severityForEncryption(encryption);
  if (!level) {
    return 'The security mode was not reported for this network, so it has not been assessed. '
      + 'This is not a statement that the network is secure.';
  }
  return `${level} — the severity this build's risk rule set assigns to ${encryption}. `
    + 'The same rule set produces the findings in the report.';
}
