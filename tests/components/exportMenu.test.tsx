/**
 * The menu that decides what the next document claims.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * `ExportMenu` looks like a list of export buttons and is not only that. It also
 * carries the **retest baseline**, which is a setting rather than an action:
 * picking one decides what the *next* PDF contains, so the menu has to show which
 * one is in force rather than only offering the list. Its own types say so.
 *
 * `null` — "No comparison" — is a first-class choice, not the absence of one, and
 * it has to be visibly selected. An operator who cannot see that the export they
 * are about to take compares against nothing is about to hand someone a document
 * whose silence they will read as progress.
 *
 * The component was also built for this and then left holding the parts: its
 * `selected` and `keepOpen` fields are documented as existing *for* the retest
 * baseline, and for a while nothing used them.
 */
import { describe, expect, test } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';

import { ExportMenu, type ExportGroup } from '../../src/components/reports/ExportMenu';

const chosen: string[] = [];

function groups(over: Partial<ExportGroup>[] = []): ExportGroup[] {
  return [
    {
      title: 'DOCUMENT',
      items: [
        { id: 'pdf', label: 'PDF REPORT', onSelect: () => chosen.push('pdf') },
        { id: 'csv', label: 'CSV', onSelect: () => chosen.push('csv') },
      ],
    },
    {
      title: 'RETEST BASELINE',
      items: [
        { id: 'none', label: 'No comparison', selected: true, keepOpen: true, onSelect: () => chosen.push('none') },
        { id: 'b1', label: 'Baseline 2026-01-01', selected: false, keepOpen: true, onSelect: () => chosen.push('b1') },
      ],
    },
    ...(over as ExportGroup[]),
  ];
}

function open(gs: ExportGroup[] = groups()) {
  chosen.length = 0;
  render(<ExportMenu groups={gs} />);
  fireEvent.click(screen.getByRole('button', { name: /EXPORT/i }));
}

describe('the baseline is shown as a setting, not offered as an action', () => {
  test('the choice in force is marked and the alternative is not', () => {
    /*
      A filled dot in a fixed-width gutter, which is what distinguishes a set of
      alternatives from a list of things to do. Asserted against the unselected
      row as well, because a mark on everything marks nothing.
    */
    open();
    const selected = screen.getByText('No comparison').closest('button');
    const other = screen.getByText('Baseline 2026-01-01').closest('button');

    expect(selected!.querySelector('.bg-neon-400')).toBeTruthy();
    expect(other!.querySelector('.bg-neon-400')).toBeNull();
    expect(other!.querySelector('.bg-space-600')).toBeTruthy();
  });

  test('"No comparison" is a choice that can be selected, not an empty state', () => {
    /*
      The reason this is asserted: an export that claims no remediation progress
      is a legitimate and common one, and the operator has to be able to see that
      is what they are about to produce.
    */
    open();
    expect(screen.getByText('No comparison')).toBeTruthy();
    fireEvent.click(screen.getByText('No comparison'));
    expect(chosen).toContain('none');
  });

  test('choosing a baseline leaves the menu open', () => {
    /*
      `keepOpen`, and it is not a convenience. Each item decides what the next PDF
      contains, so the group has to stay visible for the choice to be seen taking
      effect — and the PDF row above it describes what that choice will do.
    */
    open();
    fireEvent.click(screen.getByText('Baseline 2026-01-01'));

    expect(chosen).toContain('b1');
    expect(screen.queryByText('No comparison')).toBeTruthy();
  });

  test('taking an export closes the menu', () => {
    // The opposite case, so `keepOpen` means something: an action is done with.
    open();
    fireEvent.click(screen.getByText('PDF REPORT'));

    expect(chosen).toContain('pdf');
    expect(screen.queryByText('PDF REPORT')).toBeNull();
  });
});

describe('an unavailable option', () => {
  test('an unavailable row states why, and does nothing when pressed', () => {
    /*
      `disabledReason` carries a string rather than a boolean, and that is the
      whole design: a read failure is shown as a disabled row **with the reason**
      rather than as an absence, because an empty list and an unreadable one look
      identical in a menu — and the difference decides whether "No comparison"
      means "you have not taken a baseline" or "this export may be missing one you
      did".
    */
    open(groups([{
      title: 'RETEST BASELINE',
      items: [{
        id: 'err',
        label: 'Baselines unreadable',
        disabledReason: 'the baselines table could not be read',
        onSelect: () => chosen.push('err'),
      }],
    }]));

    expect(screen.getByText(/could not be read/)).toBeTruthy();

    /*
      Guarded twice, and both are asserted. The row carries `disabled` so the
      browser refuses the press, and `choose` returns early so a keyboard or
      programmatic activation cannot get past it either. Removing only the handler
      guard leaves this test green, which is how the second mechanism was found;
      removing the attribute turns it red.
    */
    const row = screen.getByText('Baselines unreadable').closest('button');
    expect((row as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(row!);
    expect(chosen).not.toContain('err');
  });
});

describe('the trigger', () => {
  test('it refuses to open while an export is running', () => {
    // Rendering a 48-page document takes time, and a second press during it would
    // start a parallel render over the same document state.
    render(<ExportMenu groups={groups()} busy busyLabel="EXPORTING" />);
    const trigger = screen.getByRole('button', { name: /EXPORTING/i });

    expect((trigger as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(trigger);
    expect(screen.queryByText('PDF REPORT')).toBeNull();
  });
});
