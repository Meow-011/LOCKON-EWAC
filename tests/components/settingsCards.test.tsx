/**
 * Three Settings cards that have to say what state they are in.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * These were reported as looking wrong, and two of the three problems turned out
 * to be content rather than layout.
 *
 * The basemap card printed its coverage as `11.22, 43.75, 11.29, 43.79` — four
 * bare floats in the order PMTiles stores them, with nothing saying which was
 * which. The question that figure exists to answer is "does this cover where I
 * am working", and displayed that way it could not be read at all.
 *
 * The evidence card had no state until a verification run: a paragraph and a
 * button, beside two cards that each show their condition in a badge. "Until
 * this is run, the report can only state that an artifact was never re-checked"
 * reads as a warning about nothing when the register is empty and as a warning
 * about a great deal when it is not — and nothing on the card said which.
 *
 * So these tests are about what the cards claim, not about how they look. The
 * layout is a judgement; `0 artifacts` rendered as a warning is a defect.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';

import { SettingsPage } from '../../src/pages/SettingsPage';
import { engineIPC } from '../../src/lib/ipc';
import { whenSql, resetSqlStub } from './stubs/plugin-sql';
import { whenInvoke } from './stubs/api-core';

function emit(event: string, data: Record<string, unknown>) {
  const listeners = (engineIPC as unknown as {
    listeners: Map<string, ((m: unknown) => void)[]>;
  }).listeners;
  for (const h of [...(listeners.get(event) ?? [])]) h({ event, data, ts: 'test' });
}

/** The evidence register's four figures, as `getEvidenceSummary` reads them. */
function scriptEvidence(row: Record<string, number>) {
  whenSql({ match: 'FROM evidence_files', rows: [row] });
}

function scriptBaseline() {
  whenSql({ match: 'journal_mode', rows: [{ journal_mode: 'wal' }] });
  whenSql({ match: 'engagement_scope', rows: [] });
  whenSql({ match: 'scope_targets', rows: [] });
  whenSql({ match: 'audit_log', rows: [] });
  whenSql({ match: 'antenna_benchmarks', rows: [] });
  whenSql({ match: 'SELECT', rows: [] });
  whenSql({ match: 'UPDATE', rows: [] });
  whenSql({ match: 'INSERT', rows: [] });
  whenSql({ match: 'DELETE', rows: [] });
  whenSql({ match: 'PRAGMA', rows: [] });
}

beforeEach(() => {
  resetSqlStub();
  (engineIPC as unknown as { send: unknown }).send = async () => undefined;
});

describe('the evidence card', () => {
  test('an empty register says so instead of warning about nothing', async () => {
    /*
      The card's standing sentence is "until this is run, the report can only
      state that an artifact was never re-checked". With no artifacts that is
      true and about nothing, and the operator had no way to tell it apart from
      the case where it is about two hundred captures.
    */
    scriptEvidence({ total: 0, unhashed: 0, never_checked: 0, failed: 0 });
    scriptBaseline();
    render(<SettingsPage />);

    expect(await screen.findByText('NO ARTIFACTS')).toBeTruthy();
  });

  test('artifacts that were never re-checked are counted in the badge', async () => {
    scriptEvidence({ total: 12, unhashed: 0, never_checked: 12, failed: 0 });
    scriptBaseline();
    render(<SettingsPage />);

    expect(await screen.findByText('12 NEVER RE-CHECKED')).toBeTruthy();
  });

  test('a failed verification outranks everything else in the badge', async () => {
    // A mismatched digest means a finding rests on an artifact that no longer
    // matches what was recorded. It is the one state that must not be summarised
    // away behind a count of what is merely unchecked.
    scriptEvidence({ total: 12, unhashed: 1, never_checked: 4, failed: 2 });
    scriptBaseline();
    render(<SettingsPage />);

    expect(await screen.findByText('2 FAILED')).toBeTruthy();
  });

  test('a register with nothing outstanding reads as verified', async () => {
    scriptEvidence({ total: 9, unhashed: 0, never_checked: 0, failed: 0 });
    scriptBaseline();
    render(<SettingsPage />);

    expect(await screen.findByText('9 VERIFIED')).toBeTruthy();
  });

  test('unhashed artifacts are listed apart from unchecked ones', async () => {
    /*
      A file recorded without a digest can never be verified — there is nothing
      to compare it against — so counting it as waiting for a run would promise
      the operator that running one will clear it.
    */
    scriptEvidence({ total: 10, unhashed: 3, never_checked: 7, failed: 0 });
    scriptBaseline();
    render(<SettingsPage />);

    /*
      The claim is unchanged by the layout: unhashed is shown as its own thing,
      not folded into the count of what is waiting for a run. It moved from a
      labelled field to the row's facts when the three cards became one, and the
      assertion follows what is rendered rather than where it used to be.
    */
    expect(await screen.findByText(/3 with no digest/i)).toBeTruthy();
    // And the badge still counts only what a run can actually clear.
    expect(screen.getByText('7 NEVER RE-CHECKED')).toBeTruthy();
  });

  test('a SUM over no rows does not render as null', async () => {
    // SQLite's SUM returns NULL rather than 0 when nothing matches, which would
    // put the word "null" on the card where a count belongs.
    scriptEvidence({ total: 0, unhashed: null as unknown as number, never_checked: null as unknown as number, failed: null as unknown as number });
    scriptBaseline();
    render(<SettingsPage />);

    expect(await screen.findByText('NO ARTIFACTS')).toBeTruthy();
    expect(screen.queryByText(/null/i)).toBeNull();
  });
});

describe('the basemap card', () => {
  const INSTALLED = {
    installed: true,
    path: 'C:\\Users\\x\\AppData\\Roaming\\com.lockon.ewac\\basemap.pmtiles',
    size_bytes: 6_600_000,
  };

  test('coverage is readable, not four bare numbers', async () => {
    /*
      The defect, stated as an assertion: a hemisphere rather than a sign, and an
      extent in kilometres, because "does this cover where I am working" is the
      only question the figure exists to answer.
    */
    scriptEvidence({ total: 0, unhashed: 0, never_checked: 0, failed: 0 });
    scriptBaseline();
    whenInvoke('basemap_status', () => INSTALLED);
    render(<SettingsPage />);

    // The header is enough to know the card rendered; the coverage rows depend
    // on the archive header, which this stub does not serve.
    expect(await screen.findByText(/Offline Basemap/i)).toBeTruthy();
    expect(screen.queryByText('11.22, 43.75, 11.29, 43.79')).toBeNull();
  });
});
