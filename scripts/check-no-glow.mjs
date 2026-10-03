#!/usr/bin/env node
/**
 * No glow.
 *
 *     npm run check:glow
 *
 * Why this exists.
 *
 * Sixty-four zero-offset shadows had accumulated across thirteen files, plus
 * three CSS tokens, a keyframe animation, two blurred MapLibre line layers and a
 * `drop-shadow` filter on the vehicle. None of it arrived in one change. It is
 * what a dark tactical theme turns into when every new control is given a halo
 * because the control beside it has one, and nothing anywhere said whether that
 * was the convention or an accident.
 *
 * It is worth a check rather than a one-off sweep for the same reason the icon
 * one is: a glow renders correctly, type-checks, and looks deliberate on its own.
 * It is only wrong next to the ninety controls that do not have one — a
 * comparison nothing makes, because they are in different files.
 *
 * What is NOT flagged, deliberately:
 *
 *   * `shadow-lg`, `shadow-xl`, `shadow-md`, `drop-shadow-md` and friends. A
 *     shadow with an offset is depth — it lifts a panel off the one behind it,
 *     or keeps a label legible over a map. That was never the complaint.
 *   * `blur` and `backdrop-blur`. Frosted glass is not a halo.
 *
 * The discriminator is the zero offset: `0_0_` in a Tailwind arbitrary value, or
 * `0 0` in a CSS `box-shadow`, means the light is coming from the element itself
 * and spreading evenly in every direction. That is a glow.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const ROOTS = ['src'];

const RULES = [
  {
    // shadow-[0_0_15px_rgba(...)], hover:shadow-[0_0_...], drop-shadow-[0_0_...]
    pattern: /(?:[a-z-]+:)?(?:drop-)?shadow-\[0_0_[^\]]*\]/g,
    what: 'a zero-offset Tailwind shadow',
    fix: 'say it with the border or the text colour, which every one of these already changed too',
  },
  {
    pattern: /(?:[a-z-]+:)?shadow-neon(?:-lg)?\b/g,
    what: 'a neon shadow utility',
    fix: 'the --shadow-neon tokens were removed with the rest',
  },
  {
    pattern: /animate-(?:glow|ping)\b/g,
    what: 'a glow or ping animation',
    fix: 'a static ring says a scan is running without animating over the data',
  },
  {
    // The MapLibre equivalent: a wide, blurred, low-opacity line under a real one.
    pattern: /'line-blur'/g,
    what: 'a blurred map line',
    fix: 'the track is the line; a blurred copy under it spreads the route into a band that means nothing',
  },
  {
    // box-shadow: 0 0 ... in CSS, including inside a keyframe.
    pattern: /box-shadow:[^;}]*\b0 0 \d/g,
    what: 'a zero-offset CSS box-shadow',
    fix: 'keep offset shadows for depth; drop the halo',
  },
  {
    pattern: /filter\s*=\s*'drop-shadow\(0 0 /g,
    what: 'a zero-offset drop-shadow filter',
    fix: 'an element that needs separating from the map wants a border, not a halo',
  },
];

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) {
      yield* walk(path);
    } else if (/\.(tsx?|css)$/.test(name)) {
      yield path;
    }
  }
}

const problems = [];
let scanned = 0;

for (const root of ROOTS) {
  for (const file of walk(root)) {
    scanned++;
    const source = readFileSync(file, 'utf8');
    /*
      Only code is checked.

      The explanatory comments here quote what they removed -- that is most of
      their value -- so prose about `animate-ping` is not an `animate-ping`. The
      first version tested for a leading `*` or `//`, which missed every block
      comment in this codebase written without asterisk continuation lines, and
      the check failed on its own rationale. Block state is tracked instead.
    */
    const lines = source.split(/\r?\n/);
    let inBlock = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();

      const opened = line.lastIndexOf('/*');
      const closed = line.lastIndexOf('*/');
      const wasInBlock = inBlock;
      if (!inBlock && opened !== -1 && closed < opened) inBlock = true;
      else if (inBlock && closed !== -1) inBlock = false;
      // A line inside a block comment, or one that opens or closes one, is prose.
      if (wasInBlock || inBlock || (opened !== -1 && closed !== -1)) continue;

      if (trimmed.startsWith('*') || trimmed.startsWith('//')) continue;
      for (const rule of RULES) {
        rule.pattern.lastIndex = 0;
        const hit = rule.pattern.exec(line);
        if (hit) {
          problems.push({ file, line: i + 1, text: hit[0], what: rule.what, fix: rule.fix });
        }
      }
    }
  }
}

if (problems.length > 0) {
  console.error('[glow] FAIL');
  for (const p of problems) {
    console.error(`  - ${p.file.replace(/\\/g, '/')}:${p.line} — ${p.what}: ${p.text}`);
    console.error(`      ${p.fix}`);
  }
  console.error('\n  Offset shadows (shadow-lg, drop-shadow-md) are depth and are fine.');
  process.exit(1);
}

console.log(`[glow] ${scanned} source file(s), no zero-offset shadows`);
console.log('[glow] PASS');
