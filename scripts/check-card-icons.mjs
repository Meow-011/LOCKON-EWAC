#!/usr/bin/env node
/**
 * Every card heading carries an icon.
 *
 *     npm run check:icons
 *
 * Why this exists.
 *
 * Three of the fourteen headings on the Settings page had one — Engagement
 * Scope, Antenna Benchmark, Dictionary Arsenal — and eleven did not. That is the
 * shape a convention takes when it is only a habit: the first few cards were
 * written with an icon, the next ten were written by somebody in a hurry, and
 * nothing anywhere said which was intended.
 *
 * It is worth a check rather than a one-off sweep because the failure is
 * invisible to everything else. A heading without an icon renders correctly,
 * passes type-checking, and reads fine on its own; it only looks wrong beside
 * the ones that have one, which is a comparison no test makes and no reviewer
 * makes either, because they are five hundred lines apart in the same file.
 *
 * The check is deliberately shallow: an `<h3>` with text in it has an `<svg>` in
 * it. It says nothing about whether the icon is a good one, which is not
 * something a script can know.
 */
import { readFileSync, existsSync } from 'node:fs';

/*
  Settings only, and that is a finding rather than a shortcut.

  The first version of this ran over every page and reported ten more headings,
  all of which were correct. "NO TARGETS DETECTED" is an empty state and already
  carries a 64px icon above it, where a 16px one inside the heading would be
  wrong. "Fingerprint Data" is a `text-[10px] font-mono` sub-section label inside
  a drawer, not a card title. "SAVED ARCHIVES" heads a list.

  So `<h3>` does not mean "card heading", and a check that assumed it did was
  inventing a convention for pages that have their own. What is real is the one
  on Settings: a `font-tactical` title inside a `glass-card`, where three of
  fourteen had an icon and eleven did not.
*/
const PAGE = 'src/pages/SettingsPage.tsx';

const problems = [];
let checked = 0;

if (existsSync(PAGE)) {
  const source = readFileSync(PAGE, 'utf8');

  for (const match of source.matchAll(/<h3[^>]*>([\s\S]*?)<\/h3>/g)) {
    const open = match[0].slice(0, match[0].indexOf('>') + 1);
    const body = match[1];

    // `font-tactical` is what distinguishes a card title from a field label.
    if (!open.includes('font-tactical') && !open.includes('text-tactical')) continue;

    // Visible text only. A heading that is nothing but an expression is a value,
    // not a title.
    const text = body.replace(/<[^>]+>/g, ' ').replace(/\{[^}]*\}/g, ' ').replace(/\s+/g, ' ').trim();
    if (!text) continue;

    checked++;
    if (!body.includes('<svg')) {
      const line = source.slice(0, match.index).split(String.fromCharCode(10)).length;
      problems.push(`${PAGE}:${line} — "${text.slice(0, 40)}" has no icon`);
    }
  }
}

if (problems.length > 0) {
  console.error('[icons] FAIL');
  for (const p of problems) console.error(`  - ${p}`);
  console.error('\n  The convention is an <svg class="w-4 h-4 text-..."> inside the <h3>,');
  console.error('  with `flex items-center gap-2` on the heading.');
  process.exit(1);
}

console.log(`[icons] ${checked} Settings card heading(s), each with an icon`);
console.log('[icons] PASS');
