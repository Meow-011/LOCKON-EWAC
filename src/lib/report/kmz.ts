/**
 * A minimal ZIP writer, for producing KMZ.
 *
 * Why there is a zip writer in this repository.
 *
 * The KML export referenced its placemark icons by URL, which made a document
 * handed to a client reach out to a third party at the moment they opened it.
 * KMZ is the format that exists for this: a zip carrying `doc.kml` beside the
 * images it names, which every KML viewer opens natively and which works with no
 * network at all.
 *
 * Why not a zip library.
 *
 * `fflate` is 8 KB and `jszip` is far more, and both would be a dependency added
 * for one export path in a tool whose supply chain is part of what it is
 * assessing. What a KMZ needs is the oldest and smallest corner of the ZIP
 * specification: a handful of fixed-layout records, no encryption, no
 * multi-disk, no Zip64. That is this file.
 *
 * Deflate comes from the platform. `CompressionStream('deflate-raw')` is in
 * every Chromium since 103 and in Node since 18, which covers WebView2 and the
 * test runner; when it is missing the entry is stored instead, which is a larger
 * file rather than a failed export. A KMZ of stored entries is still a valid
 * KMZ.
 *
 * What this deliberately does not implement: Zip64. An archive above 4 GB, or
 * one with more than 65,535 entries, would silently produce a corrupt file — so
 * `zip()` refuses rather than writing one. A KMZ of a survey is a few megabytes
 * and three entries, so the limit is unreachable in practice and checked anyway,
 * because "unreachable in practice" is how a truncated deliverable gets written.
 */

/** One file in the archive. */
export interface ZipEntry {
  /** Path inside the archive, forward slashes, no leading slash. */
  name: string;
  data: Uint8Array;
  /**
   * Skip compression. Set for data that is already compressed — a PNG gains
   * nothing from deflate and costs the time twice.
   */
  store?: boolean;
}

const ZIP_MAX_ENTRIES = 0xffff;
const ZIP_MAX_BYTES = 0xffffffff;

/**
 * CRC-32, as ZIP defines it.
 *
 * The table is built once on first use rather than held as a literal: 256
 * entries of hex in a source file is a thing nobody can review, and this is four
 * lines that can be read against the polynomial.
 */
let CRC_TABLE: Uint32Array | null = null;
function crc32(data: Uint8Array): number {
  if (!CRC_TABLE) {
    CRC_TABLE = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
      let c = i;
      // 0xEDB88320 is the reversed representation of the CRC-32 polynomial.
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC_TABLE[i] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < data.length; i++) {
    crc = CRC_TABLE[(crc ^ data[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/** Raw deflate, or the input unchanged when the platform cannot deflate. */
async function deflate(data: Uint8Array): Promise<{ body: Uint8Array; method: number }> {
  const CS = (globalThis as { CompressionStream?: typeof CompressionStream }).CompressionStream;
  if (!CS) return { body: data, method: 0 };
  try {
    const stream = new Blob([data as BlobPart]).stream().pipeThrough(new CS('deflate-raw'));
    const body = new Uint8Array(await new Response(stream).arrayBuffer());
    // Deflate can grow incompressible input. Storing is then both smaller and
    // faster to read, and the format allows either.
    return body.length < data.length ? { body, method: 8 } : { body: data, method: 0 };
  } catch {
    return { body: data, method: 0 };
  }
}

/**
 * MS-DOS date and time, which is what ZIP records.
 *
 * Fixed to 1980-01-01, the epoch of that format, rather than the moment of
 * export. Two exports of the same archive should differ only where the data
 * differs — `test:export:release` compares a produced document against a
 * baseline, and a timestamp would make every run differ for no reason. The
 * document itself carries the date it was generated, in text a reader sees.
 */
const DOS_TIME = 0;
const DOS_DATE = (1 << 5) | 1; // month 1, day 1, year 1980 (0 years since epoch)

function u16(v: number): number[] { return [v & 0xff, (v >>> 8) & 0xff]; }
function u32(v: number): number[] { return [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff]; }

/**
 * Build a ZIP archive.
 *
 * Entries are written in the order given, which for a KMZ matters: the KML
 * document is expected first, and some readers take the first `.kml` in the
 * archive as the document regardless of its name.
 */
export async function zip(entries: ZipEntry[]): Promise<Blob> {
  if (entries.length === 0) throw new Error('an archive needs at least one entry');
  if (entries.length > ZIP_MAX_ENTRIES) {
    throw new Error(`${entries.length} entries exceeds what a non-Zip64 archive can record`);
  }

  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [];
  const central: number[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBytes = encoder.encode(entry.name);
    const { body, method } = entry.store
      ? { body: entry.data, method: 0 }
      : await deflate(entry.data);
    const crc = crc32(entry.data);

    const local = [
      ...u32(0x04034b50),       // local file header signature
      ...u16(20),               // version needed: 2.0, which is deflate
      ...u16(0),                // flags: none. No data descriptor, sizes are known here.
      ...u16(method),
      ...u16(DOS_TIME), ...u16(DOS_DATE),
      ...u32(crc),
      ...u32(body.length),      // compressed size
      ...u32(entry.data.length),// uncompressed size
      ...u16(nameBytes.length),
      ...u16(0),                // extra field length
    ];

    central.push(
      ...u32(0x02014b50),       // central directory header signature
      ...u16(20),               // version made by
      ...u16(20),               // version needed
      ...u16(0),
      ...u16(method),
      ...u16(DOS_TIME), ...u16(DOS_DATE),
      ...u32(crc),
      ...u32(body.length),
      ...u32(entry.data.length),
      ...u16(nameBytes.length),
      ...u16(0),                // extra
      ...u16(0),                // comment
      ...u16(0),                // disk number start
      ...u16(0),                // internal attributes
      ...u32(0),                // external attributes
      ...u32(offset),           // offset of the local header
      ...Array.from(nameBytes),
    );

    chunks.push(new Uint8Array(local), nameBytes, body);
    offset += local.length + nameBytes.length + body.length;
    if (offset > ZIP_MAX_BYTES) {
      throw new Error('the archive exceeds 4 GB, which this writer cannot record without Zip64');
    }
  }

  const centralBytes = new Uint8Array(central);
  const end = new Uint8Array([
    ...u32(0x06054b50),         // end of central directory signature
    ...u16(0), ...u16(0),       // this disk, and the disk the directory starts on
    ...u16(entries.length), ...u16(entries.length),
    ...u32(centralBytes.length),
    ...u32(offset),             // offset of the central directory
    ...u16(0),                  // comment length
  ]);

  return new Blob([...chunks, centralBytes, end] as BlobPart[], {
    type: 'application/vnd.google-earth.kmz',
  });
}

/**
 * The bytes behind an asset import, however the bundler chose to express it.
 *
 * Vite inlines an asset below `assetsInlineLimit` as a `data:` URI and emits
 * anything larger as a file — and the two need different handling for a reason
 * that is not obvious. `fetch()` of a `data:` URI is governed by `connect-src`,
 * and the shipped policy lists `'self' ipc:` and three tile hosts, not `data:`.
 * So fetching the inlined form is refused by the policy in a built copy while
 * working perfectly under `tauri dev`, where the dev policy is wider.
 *
 * That is not hypothetical: the first version of the KMZ export fetched both
 * icons, both were under the limit, and both would have been blocked in the
 * shipped application — reported as "icon could not be read", which is at least
 * loud, but it would have been loud in front of whoever first exported a map.
 *
 * Decoding the data URI here needs no request and therefore no policy. A file
 * URL is fetched, which is same-origin and already allowed. Neither path widens
 * the policy, which is the point: the icons were brought into the archive to
 * stop the document reaching outside itself, and an export that reaches outside
 * itself to assemble it would be a strange way to achieve that.
 */
export async function assetBytes(url: string): Promise<Uint8Array> {
  if (url.startsWith('data:')) {
    const comma = url.indexOf(',');
    if (comma === -1) throw new Error('malformed data URI');
    const payload = url.slice(comma + 1);
    if (!/;base64/i.test(url.slice(0, comma))) {
      // Vite emits base64 for binary. A percent-encoded data URI would be a
      // different bundler or a different asset type, and guessing at it would
      // produce a corrupt PNG rather than an error.
      throw new Error('data URI is not base64; refusing to guess at its encoding');
    }
    const binary = atob(payload);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} could not be read (${res.status})`);
  return new Uint8Array(await res.arrayBuffer());
}

/**
 * A KMZ: the document, plus whatever it references.
 *
 * `doc.kml` is the conventional name and goes first. Icon paths inside the KML
 * must be relative to the archive root and match these keys exactly — a viewer
 * that cannot resolve one falls back to its default pin and says nothing, which
 * is the failure this whole change exists to remove, so `check-kmz.mjs` compares
 * the two sides rather than trusting them to stay in step.
 */
export async function kmz(doc: string, assets: { path: string; data: Uint8Array }[]): Promise<Blob> {
  return zip([
    { name: 'doc.kml', data: new TextEncoder().encode(doc) },
    // Already-compressed images; deflating a PNG spends time to grow it.
    ...assets.map(a => ({ name: a.path, data: a.data, store: true })),
  ]);
}
