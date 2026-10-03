/**
 * Escaping for the one place this application builds HTML from strings.
 *
 * MapLibre popups take markup, not nodes: `Popup.setHTML(s)` assigns to
 * `innerHTML` internally. Five popup builders — three on the report map, two on
 * the live dashboard — interpolated an access point's SSID, BSSID, vendor and
 * encryption straight into a template and handed the result to it.
 *
 * An SSID is a string chosen by whoever owns the access point, which on a survey
 * includes the access point under investigation. Every other consumer in this
 * project already treats it that way and says why: KML goes through `xmlEscape`,
 * CSV through the formula neutralisation in `csv.ts`, the PDF through `ascii()`.
 * The popups were the exception.
 *
 * The floor on the damage is a report-grade falsehood rather than code
 * execution: an access point named `</div><div hidden>` can suppress or rewrite
 * the BSSID, encryption, severity and error-radius lines of its own popup, and
 * that popup is what gets screenshotted into a document. Script execution is a
 * separate question and is currently refused by the shipped CSP, but relying on
 * that is relying on one control to cover for a missing one.
 *
 * Kept in its own module rather than imported from `report/archive.ts`, which is
 * where `xmlEscape` lives: the dashboard map would then pull the whole archive
 * layer into its chunk for one function.
 */

/**
 * `value` as HTML text, safe to interpolate into markup or a quoted attribute.
 *
 * Escapes the five significant characters. `&` first, or the ampersands
 * introduced by the later replacements would be escaped a second time and the
 * SSID `a<b` would render as `a&lt;b`.
 *
 * Control characters are stripped rather than escaped, matching `xmlEscape`: an
 * SSID is 32 arbitrary bytes and nothing is gained by rendering a C0 control.
 * Null and undefined become the empty string, so a missing field cannot print
 * the word "undefined" into a document.
 */
export function escapeHtml(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value);
  return s
    .replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    // `&#39;` rather than `&apos;`: both are valid HTML5, the numeric form is
    // also valid in the HTML4 and XML contexts this string may be pasted into.
    .replace(/'/g, '&#39;');
}

/**
 * The label for a network that broadcasts no SSID.
 *
 * A constant because the literal was written as `'<Hidden SSID>'` inside a
 * template. With no space after the `<`, an HTML parser reads that as a tag
 * named `hidden` carrying an attribute `ssid` — so it rendered as nothing at
 * all, and a hidden network's popup had a blank title where the fallback was
 * supposed to be. Escaped at the point of use like any other text.
 */
export const HIDDEN_SSID_LABEL = '<Hidden SSID>';
