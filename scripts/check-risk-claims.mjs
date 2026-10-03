#!/usr/bin/env node
/**
 * Only the rule set decides how bad something is.
 *
 *     npm run check:risk-claims
 *
 * Why this exists.
 *
 * `access_points.is_vulnerable` is a boolean the engine sets from its own checks.
 * It is a *field on a record*, which means any call site can read it, and reading
 * it to decide whether something is high risk answers a different question from
 * the one `riskEngine` answers. The two disagree: a WEP network is CRITICAL to the
 * rule set whether or not the engine happened to set that flag.
 *
 * That divergence has now been fixed four separate times, in four phases:
 *
 *   * the report's survey map, under a comment reading "so a marker's colour and
 *     its row's severity cannot disagree";
 *   * the live tactical map, which was never brought along when the report was
 *     fixed — a WEP network was green on the screen the operator surveys from and
 *     red in the document made from the same data;
 *   * the scan feed, whose HIGH RISK filter *excluded* radios the map was drawing
 *     in red, and whose SSID colour disagreed with its own badge;
 *   * the target drawer, where the status dot was green, the warning paragraph was
 *     absent and the AUDIT button was **disabled** for a radio the rest of the
 *     application was treating as critical.
 *
 * Three of those four were found by measuring for a refactor rather than by anyone
 * noticing the screen was wrong, and the fourth was found in a file that had been
 * fixed ten minutes earlier and still had three more. Fixing instances does not
 * converge. This is what makes the next one a failed build instead of an audit.
 *
 * The rule, precisely.
 *
 * Reading these fields to *display* an observation is fine and common — "this
 * access point advertises WPS" is a fact the engine measured. Reading them to
 * decide **severity, risk, colour by risk, or whether an action is allowed** is
 * not: that is `isHighRiskAp` in `src/lib/apRisk.ts`, which asks the rule set.
 *
 * So this flags a risk-field read that lands in a conditional whose other side is
 * a risk colour, a severity level, a disabled control or a risk-named filter. It
 * is deliberately narrow: a check that flagged every mention would be turned off.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

/** Where the rule set and its one bridge live. These may read anything. */
const OWNERS = [
  'src/lib/riskEngine.ts',
  'src/lib/apRisk.ts',
  // Writes the columns rather than judging them.
  'src/lib/wardrivingDB.ts',
  'src/lib/engineRouter.ts',
  'src/stores/missionStore.ts',
  'src/types/models.ts',
];

/**
 * The fields that are observations, not verdicts.
 *
 * `rogue_verdict` and `rogue_score` were in this list and came out. The first run
 * flagged two uses of them and both were correct: the scan feed renders the
 * engine's own verdict as its badge text, which is reporting a measurement rather
 * than judging one, and `assemble.ts` carries the score into a struct whose
 * `severity` on the next line comes from the rule set.
 *
 * They are a different shape from these two. `is_vulnerable` and `wps_enabled` are
 * booleans that invite `flag ? red : grey`; a rogue verdict is a value the engine
 * computed and the document is supposed to print. All four of the real defects
 * were a boolean deciding an outcome, and widening past that produced only noise.
 */
const FIELDS = ['is_vulnerable', 'wps_enabled'];

/*
  What makes a read a *judgement* rather than a display.

  Each of these appeared in one of the four defects: a risk colour chosen from the
  flag, a severity level handed to a badge, a control disabled by it, or a filter
  named for risk gated on it.
*/
const VERDICT_MARKERS = [
  { re: /text-risk-|bg-risk-|border-risk-/, what: 'picks a risk colour' },
  { re: /level="(CRITICAL|HIGH)"|severity|SEVERITY_ORDER/, what: 'assigns a severity' },
  { re: /disabled=/, what: 'enables or disables a control' },
  { re: /HIGH RISK|highRisk|isHighRisk/i, what: 'answers "is this high risk"' },
];

function* walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name).replace(/\\/g, '/');
    if (statSync(path).isDirectory()) yield* walk(path);
    else if (/\.tsx?$/.test(name)) yield path;
  }
}

const problems = [];
let scanned = 0;

for (const file of walk('src')) {
  if (OWNERS.includes(file)) continue;
  scanned++;
  const lines = readFileSync(file, 'utf8').split(/\r?\n/);
  let inBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Comments explain these defects at length; prose about `is_vulnerable` is
    // not a read of it. Block state is tracked, as `check:glow` learned to.
    const opened = line.lastIndexOf('/*');
    const closed = line.lastIndexOf('*/');
    const wasInBlock = inBlock;
    if (!inBlock && opened !== -1 && closed < opened) inBlock = true;
    else if (inBlock && closed !== -1) inBlock = false;
    if (wasInBlock || inBlock || (opened !== -1 && closed !== -1)) continue;
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    const field = FIELDS.find(f => new RegExp(`\\.${f}\\b`).test(line));
    if (!field) continue;

    /*
      The same expression, not the next three lines.

      The window was three lines and it blamed `assemble.ts` for a `severity:` on
      the line *after* the one it read — a struct literal, where the next field is
      unrelated by construction. A conditional is continued only when the line
      ends with an operator, so that is what extends the window.
    */
    let window = line;
    for (let k = i; k < Math.min(i + 4, lines.length); k++) {
      if (!/(\?|&&|\|\||\(|=>|\+)\s*$/.test(lines[k])) break;
      window += ' ' + lines[k + 1];
    }
    const marker = VERDICT_MARKERS.find(m => m.re.test(window));
    if (!marker) continue;

    problems.push({ file, line: i + 1, field, what: marker.what, text: trimmed.slice(0, 90) });
  }
}

if (problems.length > 0) {
  console.error('[risk-claims] FAIL');
  for (const p of problems) {
    console.error(`  - ${p.file}:${p.line} reads \`${p.field}\` and ${p.what}`);
    console.error(`      ${p.text}`);
  }
  console.error('\n  Ask the rule set: `isHighRiskAp(ap, simulated)` from src/lib/apRisk.ts.');
  console.error('  Reading these fields to state an observation is fine; deciding severity with them is not.');
  process.exit(1);
}

console.log(`[risk-claims] ${scanned} file(s), no call site decides risk for itself`);
console.log('[risk-claims] PASS');
