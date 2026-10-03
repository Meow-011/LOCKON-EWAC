/**
 * LOCKON EWAC — Make a Content-Security-Policy violation visible.
 *
 * Why this exists.
 *
 * A wrong CSP fails silently. The browser blocks the request, the feature it
 * belonged to simply does not work, and nothing in the app says why — the map
 * renders grey, a font falls back, an export produces a blank page. The README
 * called this out as the one change in its pass that no automated test could
 * cover, because there is nothing to assert against: the symptom is an absence.
 *
 * `securitypolicyviolation` is the event the platform already fires for exactly
 * this. Listening to it converts the silent failure into a named one, with the
 * directive that blocked it and the URI it blocked — which is all anyone needs
 * to fix the policy. It costs one listener and it is the difference between
 * "the basemap is broken" and "img-src blocked https://tiles.example/1/2/3.png".
 *
 * Deliberately not a toast in production. An operator mid-survey cannot act on
 * a CSP directive, and a popup over the map during a drive is worse than the
 * console line. It is loud in development, where someone can fix it, and
 * recorded in production, where someone can read it back out of the console.
 */

export interface CspViolation {
  directive: string;
  blockedUri: string;
  documentUri: string;
  sourceFile: string | null;
  line: number | null;
  sample: string | null;
  at: string;
}

/**
 * Violations seen this session, newest last.
 *
 * Kept so a smoke test — or an operator reading the console — can ask "did
 * anything get blocked?" rather than having to have been watching. Capped: a
 * policy that blocks a map tile blocks one per tile, and an unbounded array
 * would grow for as long as the drive lasts.
 */
const seen: CspViolation[] = [];
const MAX_RECORDED = 100;

/** Directive+URI pairs already reported, so one bad origin logs once. */
const reported = new Set<string>();

export function cspViolations(): CspViolation[] {
  return [...seen];
}

export function installCspReporter(): () => void {
  const handler = (event: SecurityPolicyViolationEvent) => {
    const violation: CspViolation = {
      directive: event.effectiveDirective || event.violatedDirective || 'unknown',
      blockedUri: event.blockedURI || '(inline)',
      documentUri: event.documentURI || '',
      sourceFile: event.sourceFile || null,
      line: typeof event.lineNumber === 'number' && event.lineNumber > 0 ? event.lineNumber : null,
      sample: event.sample || null,
      at: new Date().toISOString(),
    };

    if (seen.length < MAX_RECORDED) seen.push(violation);

    // One line per distinct directive+origin. A blocked tile server would
    // otherwise produce a line per tile and bury everything else.
    const origin = (() => {
      try {
        return new URL(violation.blockedUri).origin;
      } catch {
        return violation.blockedUri;
      }
    })();
    const key = `${violation.directive} ${origin}`;
    if (reported.has(key)) return;
    reported.add(key);

    console.error(
      `[CSP] Blocked by ${violation.directive}: ${violation.blockedUri}`
      + (violation.sourceFile ? ` (from ${violation.sourceFile}:${violation.line ?? '?'})` : '')
      + '. The feature that needed it will not work. Add this origin to '
      + `\`${violation.directive}\` in src-tauri/tauri.conf.json, or remove whatever requests it.`
    );

    // In development the person who can fix it is at the keyboard.
    if (import.meta.env.DEV) {
      window.dispatchEvent(new CustomEvent('lockon:toast', {
        detail: {
          message: `CSP blocked ${origin} (${violation.directive}). See the console.`,
          type: 'error',
        },
      }));
    }
  };

  document.addEventListener('securitypolicyviolation', handler);
  return () => document.removeEventListener('securitypolicyviolation', handler);
}
