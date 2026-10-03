/**
 * An imported archive must be marked imported in the store, not only on disk.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * `markImported` writes `origin = 'IMPORTED'` to the database, and for a long
 * time that was the only half. The store received the parsed file verbatim —
 * whose `origin` is whatever the file carried, normally nothing — and
 * `loadReports()` has exactly one caller, at application start. So for the rest
 * of the session the in-memory record said nothing about where the archive came
 * from, and the PDF cover reads `r.origin === 'IMPORTED'` off the store: the
 * filter came back empty, the "IMPORTED DATA — NOT GATHERED BY THIS RIG" banner
 * was skipped, and the cover printed **LIVE HARDWARE [FIELD DATA]**, in green,
 * for a file that arrived over the network from somewhere unknown.
 *
 * It corrected itself after a restart, because the database was right. That is
 * what kept it hidden: anyone who imported, restarted and then exported saw a
 * correct document, and the one person who exported straight after importing did
 * not know they had not.
 *
 * This is the worst failure shape this tool has: not a missing finding, but a
 * confident provenance claim about data whose provenance is unknown. It is held
 * up by `tsc` and nothing else, which is why it is tested here through the file
 * input an operator actually uses.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ReportsPage } from '../../src/pages/ReportsPage';
import { useReportStore } from '../../src/stores/reportStore';
import { whenSql, resetSqlStub, sqlCalls } from './stubs/plugin-sql';

/** A file that passes the import validator: id, type, targetName, timestamp, summary, rawData. */
function archiveFile(overrides: Record<string, unknown> = {}) {
  const archive = {
    id: 'ARCHIVE-FROM-ELSEWHERE',
    type: 'WIRELESS',
    targetName: 'Someone Else Survey',
    timestamp: '2026-09-01T10:00:00.000Z',
    summary: { totalNodes: 3, criticalNodes: 1, totalAps: 3, vulnerableAps: 1 },
    rawData: { accessPoints: [] },
    ...overrides,
  };
  return new File([JSON.stringify(archive)], 'archive.json', { type: 'application/json' });
}

/** The page reads these at mount; the import path adds the three below them. */
function scriptBaseline() {
  whenSql({ match: 'journal_mode', rows: [{ journal_mode: 'wal' }] });
  whenSql({ match: 'FROM intel_reports WHERE id', rows: [{ n: 0 }] });   // reportExists -> no
  whenSql({ match: 'INSERT INTO intel_reports', rows: [] });             // addReport
  whenSql({ match: "SET origin = 'IMPORTED'", rows: [] });               // markImported
  whenSql({ match: 'FROM intel_reports', rows: [] });                    // the initial load
  whenSql({ match: 'intel_reports', rows: [] });
  whenSql({ match: 'FROM scan_sessions', rows: [] });
  whenSql({ match: 'scan_sessions', rows: [] });
  whenSql({ match: 'FROM evidence_files', rows: [] });
  whenSql({ match: 'FROM findings', rows: [] });
  whenSql({ match: 'FROM assessment_baselines', rows: [] });
  whenSql({ match: 'assessment_baselines', rows: [] });
  whenSql({ match: 'FROM clients', rows: [] });
  whenSql({ match: 'engagement_scope', rows: [] });
  whenSql({ match: 'audit_log', rows: [] });
}

/** The hidden file input the IMPORT control clicks. */
function fileInput(container: HTMLElement): HTMLInputElement {
  const input = container.querySelector('input[type="file"]') as HTMLInputElement | null;
  if (!input) throw new Error('the page has no file input to import through');
  return input;
}

beforeEach(() => {
  resetSqlStub();
  useReportStore.setState({ reports: [] });
});

describe('importing an archive', () => {
  test('stamps the in-memory record, not just the row on disk', async () => {
    /*
      The assertion is on the store, because the store is what the PDF cover
      reads. Asserting that `markImported` ran would re-test the half that was
      always right.
    */
    scriptBaseline();
    const { container } = render(<ReportsPage />);
    await userEvent.upload(fileInput(container), archiveFile());

    await waitFor(() => {
      const stored = useReportStore.getState().reports.find(r => r.id === 'ARCHIVE-FROM-ELSEWHERE');
      expect(stored).toBeTruthy();
      expect(stored!.origin).toBe('IMPORTED');
    });
  });

  test('a file carrying its own origin cannot talk its way out of the stamp', async () => {
    /*
      The archive is JSON from an untrusted source and `origin` is one of its
      fields. If the import spread the file over the stamp rather than under it,
      a file claiming `origin: "LIVE"` would be exported as field data — a way
      round the whole provenance chain through the one door that takes a file
      from outside.
    */
    scriptBaseline();
    const { container } = render(<ReportsPage />);
    await userEvent.upload(fileInput(container), archiveFile({ origin: 'LIVE', simulated: false }));

    await waitFor(() => {
      const stored = useReportStore.getState().reports.find(r => r.id === 'ARCHIVE-FROM-ELSEWHERE');
      expect(stored?.origin).toBe('IMPORTED');
    });
  });

  test('the database half still runs', async () => {
    // Both halves are needed: the store keeps this session honest and the row
    // keeps the next one honest.
    scriptBaseline();
    const { container } = render(<ReportsPage />);
    await userEvent.upload(fileInput(container), archiveFile());

    await waitFor(() => {
      expect(sqlCalls.some(c => c.sql.includes("SET origin = 'IMPORTED'"))).toBe(true);
    });
  });

  test('when the row cannot be written, it says so instead of claiming success', async () => {
    /*
      The in-memory stamp survives a failed UPDATE, so the session is still
      correct and a restart is not. Silence here would be the worst outcome: the
      operator would have an archive that exports correctly today and as LIVE
      HARDWARE tomorrow, with nothing having said which.
    */
    whenSql({ match: 'journal_mode', rows: [{ journal_mode: 'wal' }] });
    whenSql({ match: 'FROM intel_reports WHERE id', rows: [{ n: 0 }] });
    whenSql({ match: 'INSERT INTO intel_reports', rows: [] });
    whenSql({ match: "SET origin = 'IMPORTED'", throws: 'database is locked' });
    whenSql({ match: 'FROM intel_reports', rows: [] });
    whenSql({ match: 'intel_reports', rows: [] });
    whenSql({ match: 'scan_sessions', rows: [] });
    whenSql({ match: 'FROM evidence_files', rows: [] });
    whenSql({ match: 'FROM findings', rows: [] });
    whenSql({ match: 'assessment_baselines', rows: [] });
    whenSql({ match: 'FROM clients', rows: [] });
    whenSql({ match: 'engagement_scope', rows: [] });
    whenSql({ match: 'audit_log', rows: [] });

    const { container } = render(<ReportsPage />);
    await userEvent.upload(fileInput(container), archiveFile());

    const notice = await screen.findByText(/PROVENANCE WAS NOT SAVED/i, {}, { timeout: 4000 });
    expect(notice.textContent).toMatch(/after a restart it would export as LIVE HARDWARE/i);
    // And it is still marked for this session, which the message promises.
    expect(useReportStore.getState().reports.find(r => r.id === 'ARCHIVE-FROM-ELSEWHERE')?.origin).toBe('IMPORTED');
  });

  test('a file that is not an archive is refused rather than stored', async () => {
    scriptBaseline();
    const { container } = render(<ReportsPage />);
    await userEvent.upload(
      fileInput(container),
      new File([JSON.stringify({ hello: 'world' })], 'notes.json', { type: 'application/json' })
    );

    expect(await screen.findByText(/INVALID ARCHIVE/i)).toBeTruthy();
    expect(useReportStore.getState().reports).toHaveLength(0);
  });
});
