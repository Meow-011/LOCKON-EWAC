/**
 * Tests for the escaping that stands between an SSID and a map popup.
 *
 *     npm run test:html
 *
 * Why this exists.
 *
 * MapLibre's `Popup.setHTML` assigns to `innerHTML`. Five popup builders -- three
 * on the report map, two on the live dashboard -- interpolated an access point's
 * SSID, BSSID, vendor and encryption straight into a template and handed the
 * result to it.
 *
 * An SSID is 32 bytes chosen by whoever owns the access point, which on a survey
 * includes the access point being investigated. Every other consumer in this
 * project already treats it as hostile and says why: KML through `xmlEscape`, CSV
 * through the formula neutralisation in `csv.ts`, the PDF through `ascii()`. The
 * popups were the exception, and the engineering log's claim that there was no
 * `innerHTML` anywhere in `src/` was no longer true because of them.
 *
 * The floor on the damage is not script execution -- the shipped CSP refuses that
 * -- it is a report-grade falsehood. An access point named `</div><div hidden>`
 * can suppress or rewrite the BSSID, encryption, severity and error-radius lines
 * of its own popup, and that popup is what gets screenshotted into a document.
 * A control that is only correct because a second control is working is the thing
 * this file is here to stop being true.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { escapeHtml, HIDDEN_SSID_LABEL } from '../.test-build/html.mjs';

test('the five significant characters are all escaped', () => {
  assert.equal(escapeHtml('&<>"\''), '&amp;&lt;&gt;&quot;&#39;');
});

test('an ampersand is escaped once, not twice', () => {
  // `&` has to be replaced first. Done last, it would re-escape the ampersands
  // the other replacements introduce, and `a<b` would render as `a&lt;b`.
  assert.equal(escapeHtml('a<b'), 'a&lt;b');
  assert.equal(escapeHtml('Tom & Jerry'), 'Tom &amp; Jerry');
  assert.equal(escapeHtml('&amp;'), '&amp;amp;');
});

test('an SSID cannot close the element it is rendered in', () => {
  const ssid = '</div><div hidden>';
  const out = escapeHtml(ssid);
  assert.ok(!out.includes('<'), out);
  assert.ok(!out.includes('>'), out);
});

test('an SSID cannot introduce an event handler', () => {
  const out = escapeHtml('<img src=x onerror=alert(1)>');
  assert.ok(!out.includes('<img'), out);
  assert.equal(out, '&lt;img src=x onerror=alert(1)&gt;');
});

test('an SSID cannot break out of a quoted attribute', () => {
  // These strings are also interpolated into `class="..."` positions.
  assert.ok(!escapeHtml('" onload="alert(1)').includes('"'));
  assert.ok(!escapeHtml("' onload='alert(1)").includes("'"));
});

test('control characters are stripped rather than rendered', () => {
  assert.equal(escapeHtml('a\x00b\x07c'), 'abc');
});

test('a newline and a tab are kept', () => {
  // Stripping these would silently alter a legitimate value; they are harmless
  // in HTML text and the range in the regex deliberately excludes them.
  assert.equal(escapeHtml('a\nb\tc'), 'a\nb\tc');
});

test('null and undefined render as nothing, never as the word', () => {
  // A missing field printing "undefined" into a document is its own small lie.
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
});

test('a number survives unchanged', () => {
  // RSSI and channel go through the same path.
  assert.equal(escapeHtml(-72), '-72');
  assert.equal(escapeHtml(0), '0');
});

test('a plain SSID is returned unchanged', () => {
  // The common case must not be mangled: this is what the operator reads.
  assert.equal(escapeHtml('CAFE-GUEST-5G'), 'CAFE-GUEST-5G');
  assert.equal(escapeHtml('บ้านคุณสมชาย'), 'บ้านคุณสมชาย');
});

test('the hidden-SSID label is plain text, not markup', () => {
  /*
    It was written inline as `'<Hidden SSID>'`. With no space after the `<`, an
    HTML parser reads that as a tag named `hidden` with an attribute `ssid`, so it
    rendered as nothing at all: a hidden network's popup had a blank title where
    the fallback was meant to be. It is a constant now, and escaped like any other
    text, so it renders as the characters it is written with.
  */
  assert.equal(escapeHtml(HIDDEN_SSID_LABEL), '&lt;Hidden SSID&gt;');
  assert.ok(HIDDEN_SSID_LABEL.includes('<'), 'the label is meant to read as <...>');
});

test('escaping is idempotent in the sense that matters', () => {
  // Not literally idempotent -- `&` is re-escaped, which is correct -- but a
  // value that has already been escaped can never produce live markup.
  const once = escapeHtml('</div>');
  const twice = escapeHtml(once);
  assert.ok(!twice.includes('<') && !twice.includes('>'));
});
