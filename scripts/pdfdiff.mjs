/**
 * LOCKON EWAC — PDF text comparator.
 *
 *     node scripts/pdfdiff.mjs <baseline.pdf> <candidate.pdf>
 *     node scripts/pdfdiff.mjs --self-test [any.pdf]   # defaults to a pinned baseline
 *
 * Why this exists.
 *
 * The report is the product, and `buildAndSavePDF` is the one path `npm test`
 * cannot reach. During the refactor that split it up, this comparator is what
 * made each move safe: every step was checked to produce a byte-for-byte
 * equivalent document before the next one started.
 *
 * A hash or byte comparison is useless here. The document carries its own
 * creation date and two SHA-256 stamps, so two runs of identical code over
 * identical data differ in every one of those places. What has to be compared is
 * what the document *says*.
 *
 * So this extracts the literal strings from each content stream, in stream
 * order, blanks the values that are expected to change, and reports the first
 * difference per stream. jsPDF leaves its content streams uncompressed in this
 * app, but FlateDecode is handled anyway so a change to jsPDF's settings does
 * not silently turn every stream into "no text found".
 *
 * **Validate the comparator before trusting it.** `--self-test` does that: it
 * compares a file with itself, expects IDENTICAL, then flips one character in
 * one string and expects that to be caught. A diff tool that always says
 * IDENTICAL is worse than no diff tool, because it converts an unchecked change
 * into a checked one in the reader's mind. This script was originally written,
 * lost with its session scratchpad, and rewritten; the self-test is the part
 * that makes a rewrite trustworthy rather than merely present.
 */
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { inflateSync } from 'node:zlib';

/*
  Values that legitimately differ between two runs of the same code.

  Each one is replaced with a fixed token rather than deleted, so a *missing*
  timestamp still shows up as a difference — the length and position of the
  normalised text carries information too.
*/
/** Differences reported per stream before the rest are summarised. */
const PER_STREAM_REPORTS = 8;

const VOLATILE = [
  // The two SHA-256 stamps: the archive digest and the delivered-file digest.
  [/\b[0-9a-f]{64}\b/gi, '<sha256>'],
  // A shortened digest, as the evidence register prints it.
  [/\b[0-9a-f]{16,63}\b/gi, '<hexdigest>'],
  [/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?/g, '<isotime>'],
  [/\b\d{4}-\d{2}-\d{2}\b/g, '<date>'],
  [/\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/g, '<date>'],
  [/\b\d{1,2}:\d{2}(:\d{2})?\s?([AaPp]\.?[Mm]\.?)?/g, '<time>'],
  /*
    The CVE vintage advances on its own, without a code change. Both phrasings
    appear: the method appendix prints "0 day(s) old" and prose elsewhere says
    "1005 days old".

    This cannot fully suppress it. jsPDF wraps the paragraph before any of this
    runs, so an age that gains a digit re-wraps the whole callout and every line
    after it differs. Most days it does not — the width only changes at 9 -> 10
    and so on — and when it does, the operator re-baselines. Normalising the
    number still removes the common case, which is what keeps the net worth
    reading.
  */
  [/\b\d+\s+day\(s\)\s+old\b/gi, '<age> day(s) old'],
  [/\b\d+\s+days?\s+old\b/gi, '<age> old'],
];

/** Every `stream ... endstream` payload, in file order, decoded where possible. */
function contentStreams(buf) {
  const out = [];
  const haystack = buf.latin1Slice ? buf.latin1Slice(0) : buf.toString('latin1');
  const re = /stream\r?\n?/g;
  let m;
  while ((m = re.exec(haystack)) !== null) {
    const start = m.index + m[0].length;
    const end = haystack.indexOf('endstream', start);
    if (end === -1) continue;
    const raw = buf.subarray(start, end);
    // The dictionary immediately before the stream says whether it is deflated.
    const dict = haystack.slice(Math.max(0, m.index - 400), m.index);
    let text;
    if (/\/FlateDecode/.test(dict)) {
      try {
        text = inflateSync(raw).toString('latin1');
      } catch {
        continue;   // an image or a stream we cannot read is not text to compare
      }
    } else {
      text = raw.toString('latin1');
    }
    out.push(text);
    re.lastIndex = end;
  }
  return out;
}

/** Unescape a PDF literal string's body. */
function unescape(s) {
  return s.replace(/\\([nrtbf()\\]|[0-7]{1,3})/g, (_, esc) => {
    switch (esc) {
      case 'n': return '\n';
      case 'r': return '\r';
      case 't': return '\t';
      case 'b': return '\b';
      case 'f': return '\f';
      case '(': return '(';
      case ')': return ')';
      case '\\': return '\\';
      default: return String.fromCharCode(parseInt(esc, 8));
    }
  });
}

/*
  Literal strings in a content stream, in order.

  Every `(...)` in a content stream is a text string in practice, so the strings
  are taken directly rather than by pairing them with their `Tj`/`TJ` operator.
  That is deliberate: operator pairing has to handle `TJ` arrays, text matrices
  and nested forms, and getting it subtly wrong would drop text — which this tool
  would then report as IDENTICAL.
*/
function stringsIn(stream) {
  const out = [];
  const re = /\((?:\\[\s\S]|[^\\()])*\)/g;
  let m;
  while ((m = re.exec(stream)) !== null) {
    const body = unescape(m[0].slice(1, -1));
    if (body.trim()) out.push(body);
  }
  return out;
}

function normalise(s) {
  let out = s;
  for (const [re, token] of VOLATILE) out = out.replace(re, token);
  return out;
}

export function extract(path) {
  const buf = readFileSync(path);
  const streams = contentStreams(buf).map(stringsIn).filter(a => a.length > 0);
  return {
    streams,
    strings: streams.reduce((n, a) => n + a.length, 0),
  };
}

/** Compare two extractions. Returns a list of differences, empty when identical. */
export function compare(a, b) {
  const diffs = [];
  if (a.streams.length !== b.streams.length) {
    diffs.push(`stream count: baseline ${a.streams.length}, candidate ${b.streams.length}`);
  }
  const n = Math.min(a.streams.length, b.streams.length);
  for (let i = 0; i < n; i++) {
    const left = a.streams[i].map(normalise);
    const right = b.streams[i].map(normalise);
    if (left.length !== right.length) {
      diffs.push(`stream ${i + 1}: ${left.length} strings vs ${right.length}`);
      continue;
    }
    /*
      Several reports per stream, not one.

      This used to break after the first difference in a stream, to keep a
      wholesale change readable. That hid the rest: a legitimate change to the
      method appendix reported one line, and accepting it as a new baseline meant
      accepting whatever else in that stream had changed unseen. A review has to
      see what it is approving, so the cap is per stream and generous, and the
      count below says when it was hit.
    */
    let shown = 0;
    let more = 0;
    for (let j = 0; j < left.length; j++) {
      if (left[j] === right[j]) continue;
      if (shown < PER_STREAM_REPORTS) {
        diffs.push(
          `stream ${i + 1}, string ${j + 1}:\n`
          + `    baseline:  ${JSON.stringify(left[j])}\n`
          + `    candidate: ${JSON.stringify(right[j])}`
        );
        shown++;
      } else {
        more++;
      }
    }
    if (more) diffs.push(`stream ${i + 1}: and ${more} further difference(s)`);
  }
  return diffs;
}

/** Any pinned baseline will do as a self-test subject; returns null if there is none. */
function firstPinnedBaseline() {
  const dir = 'scripts/baselines';
  const index = `${dir}/index.json`;
  try {
    const { reports } = JSON.parse(readFileSync(index, 'utf8'));
    for (const id of reports ?? []) {
      const p = `${dir}/${id}.pdf`;
      if (existsSync(p)) return p;
    }
  } catch { /* no index, or unreadable */ }
  try {
    const f = readdirSync(dir).find(n => n.endsWith('.pdf'));
    return f ? `${dir}/${f}` : null;
  } catch { return null; }
}

function selfTest(path) {
  const a = extract(path);
  console.log(`[pdfdiff] self-test on ${path}`);
  console.log(`[pdfdiff]   ${a.streams.length} text streams, ${a.strings} strings`);
  if (a.strings === 0) {
    console.error('[pdfdiff] FAIL — no strings extracted, so a comparison would '
      + 'always report IDENTICAL. The extractor is broken, not the document.');
    return 1;
  }

  if (compare(a, extract(path)).length !== 0) {
    console.error('[pdfdiff] FAIL — a file differs from itself. Normalisation is '
      + 'not deterministic.');
    return 1;
  }
  console.log('[pdfdiff]   a file compared with itself: IDENTICAL (as it must be)');

  // Flip one character of one string, and require that it is caught. This is the
  // check that distinguishes a working comparator from one that cannot fail.
  const mutated = {
    streams: a.streams.map(s => s.slice()),
    strings: a.strings,
  };
  let target = -1;
  for (let i = 0; i < mutated.streams.length; i++) {
    const j = mutated.streams[i].findIndex(s => /[A-Za-z]{4}/.test(s));
    if (j !== -1) {
      const s = mutated.streams[i][j];
      const k = s.search(/[A-Za-z]/);
      mutated.streams[i][j] = s.slice(0, k)
        + (s[k] === 'x' ? 'y' : 'x') + s.slice(k + 1);
      target = i;
      console.log(`[pdfdiff]   mutating stream ${i + 1}: `
        + `${JSON.stringify(s)} -> ${JSON.stringify(mutated.streams[i][j])}`);
      break;
    }
  }
  if (target === -1) {
    console.error('[pdfdiff] FAIL — no alphabetic string to mutate; cannot prove '
      + 'the comparator detects a change.');
    return 1;
  }
  const caught = compare(a, mutated);
  if (caught.length === 0) {
    console.error('[pdfdiff] FAIL — a one-character change was NOT detected. '
      + 'Every IDENTICAL this tool has ever printed is worthless.');
    return 1;
  }
  console.log(`[pdfdiff]   the one-character change was caught: ${caught[0].split('\n')[0]}`);
  console.log('[pdfdiff] SELF-TEST PASS — the comparator can both agree and disagree.');
  return 0;
}

function main(argv) {
  if (argv[0] === '--self-test') {
    /*
      The path was fixed at `scripts/baseline-report.pdf` in package.json, which
      is the file the export harness stopped writing when baselines became one
      per archive shape. Any PDF will do for a self-test -- it mutates the file
      in memory and checks that the comparator notices -- so the subject is
      whichever baseline happens to be pinned rather than a name that can rot.
    */
    const subject = argv[1] ?? firstPinnedBaseline();
    if (!subject) {
      console.error('usage: node scripts/pdfdiff.mjs --self-test <any.pdf>');
      console.error('       (no pinned baseline found to use instead)');
      return 2;
    }
    return selfTest(subject);
  }
  const [baseline, candidate] = argv;
  if (!baseline || !candidate) {
    console.error('usage: node scripts/pdfdiff.mjs <baseline.pdf> <candidate.pdf>');
    console.error('       node scripts/pdfdiff.mjs --self-test <any.pdf>');
    return 2;
  }
  const a = extract(baseline);
  const b = extract(candidate);
  console.log(`[pdfdiff] baseline  ${a.streams.length} streams, ${a.strings} strings`);
  console.log(`[pdfdiff] candidate ${b.streams.length} streams, ${b.strings} strings`);

  if (a.strings === 0 || b.strings === 0) {
    console.error('[pdfdiff] REFUSING to compare: one file yielded no text. '
      + 'That would report IDENTICAL for two unrelated documents.');
    return 2;
  }

  const diffs = compare(a, b);
  if (diffs.length === 0) {
    console.log('[pdfdiff] IDENTICAL — every extracted string matches, '
      + 'ignoring timestamps and digests.');
    return 0;
  }
  console.log(`[pdfdiff] ${diffs.length} difference(s):`);
  for (const d of diffs.slice(0, 40)) console.log('  ' + d);
  if (diffs.length > 40) console.log(`  ... and ${diffs.length - 40} more`);
  return 1;
}

/*
  Run as a script, or stay quiet when imported.

  `process.argv[1]` is undefined under `node -e` and `node --eval`, and reading
  `.replace` off it threw before the module had finished loading — so importing
  this file to use `extract`/`compare` from another script crashed instead of
  working. `export-smoke-test.mjs` imports it, so this is load-bearing.
*/
const invokedAs = process.argv[1] ?? '';
if (invokedAs.endsWith('pdfdiff.mjs')) {
  process.exit(main(process.argv.slice(2)));
}
