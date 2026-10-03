/**
 * The archive this tool hands to a client has to be one other software can open.
 *
 *     npm run test:kmz
 *
 * Why this exists, and why Python opens the files.
 *
 * `src/lib/report/kmz.ts` is a zip writer written for this repository rather
 * than taken as a dependency. That is the right trade for a tool whose supply
 * chain is part of what it assesses, and it moves the risk somewhere specific: a
 * ZIP that this project's own code can read proves nothing at all, because the
 * bug and the check would share an assumption. A KMZ that Google Earth cannot
 * open is a deliverable that fails in front of a client.
 *
 * So the decisive assertions here hand the bytes to Python's `zipfile`, which is
 * an entirely separate implementation that verifies every CRC on read. If it
 * reports the archive as valid and returns the contents unchanged, the writer
 * agrees with somebody else's reading of the specification.
 *
 * Python is already a hard dependency of this project — the engine is written in
 * it — so this adds no new requirement.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { zip, kmz, assetBytes } from '../.test-build/kmz.mjs';

/**
 * Open the archive with Python and return what it found.
 *
 * `testzip()` walks every entry and recomputes its CRC, so a header this writer
 * got wrong surfaces as a named bad file rather than as silently wrong bytes.
 */
async function openWithPython(blob) {
  const dir = mkdtempSync(join(tmpdir(), 'ewac-kmz-'));
  const file = join(dir, 'a.kmz');
  writeFileSync(file, Buffer.from(await blob.arrayBuffer()));
  try {
    const out = execFileSync('python', ['-c', `
import json, sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    bad = z.testzip()
    print(json.dumps({
        "bad": bad,
        "names": z.namelist(),
        "contents": {n: z.read(n).decode("utf-8", "replace") for n in z.namelist() if n.endswith(".kml")},
        "sizes": {n: z.getinfo(n).file_size for n in z.namelist()},
        "methods": {n: z.getinfo(n).compress_type for n in z.namelist()},
    }))
`, file], { encoding: 'utf8' });
    return JSON.parse(out);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const bytes = (s) => new TextEncoder().encode(s);

test('a one-entry archive is valid, and holds exactly what went in', async () => {
  const blob = await zip([{ name: 'doc.kml', data: bytes('<kml>hello</kml>') }]);
  const got = await openWithPython(blob);

  // null from testzip() means every CRC matched.
  assert.equal(got.bad, null);
  assert.deepEqual(got.names, ['doc.kml']);
  assert.equal(got.contents['doc.kml'], '<kml>hello</kml>');
});

test('text is deflated and binary marked stored, and both read back whole', async () => {
  // A PNG gains nothing from deflate, so `store` skips it. The point of the
  // assertion is that a stored entry is still readable by a different reader —
  // method 0 and method 8 are different code paths in every unzip.
  const png = new Uint8Array(Array.from({ length: 512 }, (_, i) => (i * 37) % 256));
  const doc = '<kml>' + 'x'.repeat(5000) + '</kml>';
  const blob = await zip([
    { name: 'doc.kml', data: bytes(doc) },
    { name: 'icons/a.png', data: png, store: true },
  ]);
  const got = await openWithPython(blob);

  assert.equal(got.bad, null);
  assert.equal(got.methods['icons/a.png'], 0, 'the image should be stored');
  assert.equal(got.sizes['icons/a.png'], 512);
  assert.equal(got.contents['doc.kml'], doc);
  assert.equal(got.sizes['doc.kml'], doc.length);
});

test('a document that deflate cannot shrink is stored rather than grown', async () => {
  // Deflate expands incompressible input. Storing it is both smaller and valid,
  // and an export that grew its own output would be a strange thing to ship.
  const noise = new Uint8Array(4096);
  for (let i = 0; i < noise.length; i++) noise[i] = (i * 2654435761) % 251;
  const blob = await zip([{ name: 'doc.kml', data: bytes('x') }, { name: 'n.bin', data: noise }]);
  const got = await openWithPython(blob);

  assert.equal(got.bad, null);
  assert.equal(got.sizes['n.bin'], 4096);
});

test('non-ASCII in the document survives the round trip', async () => {
  /*
    An SSID is attacker-controlled text and routinely is not ASCII. The writer
    encodes the document as UTF-8 and records the uncompressed length in bytes,
    not characters — getting that wrong produces an archive whose header
    disagrees with its contents, which is exactly what a CRC check catches.
  */
  const doc = '<kml><name>เครือข่าย — café 📡</name></kml>';
  const got = await openWithPython(await zip([{ name: 'doc.kml', data: bytes(doc) }]));

  assert.equal(got.bad, null);
  assert.equal(got.contents['doc.kml'], doc);
  assert.equal(got.sizes['doc.kml'], bytes(doc).length);
});

test('kmz() puts the document first and names the icons as given', async () => {
  // Some readers take the first .kml in the archive as the document regardless
  // of its name, so the order is part of the format rather than a tidiness.
  const blob = await kmz('<kml/>', [
    { path: 'icons/placemark-circle.png', data: new Uint8Array([1, 2, 3, 4]) },
    { path: 'icons/mirror-diamond.png', data: new Uint8Array([5, 6, 7, 8]) },
  ]);
  const got = await openWithPython(blob);

  assert.equal(got.bad, null);
  assert.deepEqual(got.names, ['doc.kml', 'icons/placemark-circle.png', 'icons/mirror-diamond.png']);
});

test('the same input produces the same bytes twice', async () => {
  /*
    `test:export:release` compares a produced document against a committed
    baseline. A ZIP records an MS-DOS timestamp per entry, and taking it from the
    clock would make every export differ from every other for no reason that
    concerns a reader — so it is fixed at the epoch of that format, and the
    document carries its real generation date in text instead.
  */
  const build = () => zip([{ name: 'doc.kml', data: bytes('<kml>same</kml>') }]);
  const a = Buffer.from(await (await build()).arrayBuffer());
  const b = Buffer.from(await (await build()).arrayBuffer());
  assert.deepEqual(a, b);
});

test('an empty archive is refused rather than written', async () => {
  // A zero-entry KMZ opens as an empty document, which reads as "the survey
  // found nothing" rather than "something went wrong building this".
  await assert.rejects(() => zip([]), /at least one entry/);
});

test('the local header agrees with the central directory', async () => {
  /*
    A ZIP records each entry's CRC and both sizes twice: once in the local header
    before the data, and once in the central directory at the end. A reader that
    seeks to the directory — which is every ordinary unzip, including Python's —
    never looks at the local copy, so the two can disagree and every test above
    still passes. That was not hypothetical: corrupting the local size by one
    byte left all seven green, and only corrupting the directory copy turned them
    red.

    A streaming reader does use the local header, and so does anything that
    repairs a truncated archive. The two copies have to agree, and this is the
    only assertion that can say so.
  */
  const doc = '<kml>' + 'y'.repeat(3000) + '</kml>';
  const buf = Buffer.from(await (await zip([{ name: 'doc.kml', data: bytes(doc) }])).arrayBuffer());

  // Local header: signature, then CRC at +14, compressed at +18, uncompressed at +22.
  assert.equal(buf.readUInt32LE(0), 0x04034b50, 'local file header signature');
  const local = {
    crc: buf.readUInt32LE(14),
    compressed: buf.readUInt32LE(18),
    uncompressed: buf.readUInt32LE(22),
  };

  // Central directory: found by its own signature, with the same three fields
  // at +16, +20 and +24.
  const at = buf.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02]));
  assert.ok(at > 0, 'central directory header is present');
  const central = {
    crc: buf.readUInt32LE(at + 16),
    compressed: buf.readUInt32LE(at + 20),
    uncompressed: buf.readUInt32LE(at + 24),
  };

  assert.deepEqual(local, central);
  assert.equal(local.uncompressed, bytes(doc).length);
});

// ── assetBytes ─────────────────────────────────────────────────────────────
//
// Vite inlines an asset below `assetsInlineLimit` as a `data:` URI and emits a
// larger one as a file. The two need different handling for a reason that is not
// visible in either: `fetch()` of a `data:` URI is governed by `connect-src`, and
// the shipped policy lists `'self' ipc:` and three tile hosts, not `data:`.
//
// The first version of the KMZ export fetched both icons. Both were under the
// limit, so both were inlined, so both would have been refused by the policy in
// the built application — while working perfectly under `tauri dev`, where the
// dev policy is wider. The CSP smoke test would not have caught it either: it
// visits screens, and this fails only when somebody exports a map.

test('a base64 data URI is decoded without a request', async () => {
  /*
    `fetch` is made to throw for the length of this test, which is what makes it
    an assertion rather than a coincidence.

    Node's `fetch` accepts `data:` URLs, so removing the decode branch and
    falling through to `fetch` produces the same bytes here and a blocked request
    in the shipped application, where `connect-src` does not list `data:`. A test
    that only compared the bytes passed either way — it did, when it was written,
    and the branch it was meant to pin could have been deleted without a word.
  */
  const original = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x00, 0xff, 0x7f]);
  const b64 = Buffer.from(original).toString('base64');
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () => { throw new Error('a request was made for an inlined asset'); };
  try {
    const got = await assetBytes(`data:image/png;base64,${b64}`);
    assert.deepEqual([...got], [...original]);
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('a data URI that is not base64 is refused rather than guessed at', async () => {
  // Percent-encoded is a different bundler or a different asset type. Guessing
  // produces a corrupt PNG, which a viewer renders as a missing pin — the exact
  // silent failure this whole change removes.
  await assert.rejects(
    () => assetBytes('data:image/png,%89PNG'),
    /not base64/
  );
});

test('a malformed data URI is refused', async () => {
  await assert.rejects(() => assetBytes('data:image/png;base64'), /malformed/);
});

test('a file URL is fetched and its status is checked', async () => {
  const realFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url) => {
      assert.equal(url, '/assets/icon.png');
      return { ok: true, arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer };
    };
    assert.deepEqual([...await assetBytes('/assets/icon.png')], [1, 2, 3]);

    globalThis.fetch = async () => ({ ok: false, status: 404 });
    // Not an empty icon. An archive carrying a zero-byte PNG is one whose pins
    // silently do not render, which is what the hrefs did before.
    await assert.rejects(() => assetBytes('/assets/icon.png'), /404/);
  } finally {
    globalThis.fetch = realFetch;
  }
});
