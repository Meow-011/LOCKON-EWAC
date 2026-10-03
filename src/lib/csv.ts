/**
 * LOCKON EWAC — CSV cells that survive both a parser and a spreadsheet.
 *
 * These lived inside `ReportsPage.tsx`, which is 5,500 lines and has no tests.
 * They are pure functions on strings and they decide what a manager sees when
 * they double-click the export, so they belong somewhere a test can reach them.
 *
 * Two separate hazards, both already demonstrated in this project:
 *
 *  1. **Parser corruption.** The original exporter wrapped values in quotes
 *     without doubling the internal ones, so a single SSID containing `"`
 *     shifted every following column on that row and corrupted the file for any
 *     parser. RFC 4180 doubling fixes that.
 *
 *  2. **Formula injection.** A cell that opens with `=`, `+`, `-`, `@`, a tab or
 *     a carriage return is evaluated as a formula by Excel, LibreOffice and
 *     Google Sheets. Quoting does not help: the spreadsheet strips the quotes
 *     and then evaluates what is inside.
 *
 * The second one matters here more than in most reporting tools, because of
 * where this tool's strings come from. An SSID is chosen by whoever owns the
 * access point — including the one being investigated, and including a rogue.
 * Naming a network `=HYPERLINK("http://…","Click")` is free, and the survey
 * dutifully records it, writes it into the CSV, and hands the file to
 * management. The tool would be the delivery mechanism.
 *
 * Every attacker-influenced string in the export is affected, not only SSIDs:
 * vendor strings, service banners, hostnames, and the finding titles built from
 * them.
 */

/**
 * True when a spreadsheet would treat this text as a formula rather than data.
 *
 * Exported so a test can state the threat model directly rather than inferring
 * it from quoting behaviour.
 */
export function looksLikeSpreadsheetFormula(s: string): boolean {
  if (!/^[=+\-@\t\r]/.test(s)) return false;
  // A genuinely negative number is not a formula, and this export carries
  // plenty of them — RSSI, longitude, latitude. Prefixing those would turn a
  // numeric column into text and break the analysis the CSV exists for, so a
  // value that is a plain finite number is left alone.
  if (s.trim() !== '' && Number.isFinite(Number(s))) return false;
  return true;
}

/**
 * One RFC 4180 cell, neutralised against formula evaluation.
 *
 * A leading apostrophe is the conventional escape: spreadsheets consume it and
 * display the original text, and every CSV parser sees it as part of the value.
 * That last part is the trade-off — a machine consumer reading this column gets
 * `'=foo` rather than `=foo`. That is the intended outcome: the literal text is
 * preserved and marked, rather than silently executing on open.
 */
export function csvCell(value: unknown): string {
  const raw = value === null || value === undefined ? '' : String(value);
  const s = looksLikeSpreadsheetFormula(raw) ? `'${raw}` : raw;
  return `"${s.replace(/"/g, '""')}"`;
}

/** One CSV record, CRLF-terminated per RFC 4180. */
export function csvRow(values: unknown[]): string {
  return values.map(csvCell).join(',') + '\r\n';
}
