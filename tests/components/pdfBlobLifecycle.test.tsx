/**
 * Each export releases the previous export's blob, and the page releases the last.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * `URL.revokeObjectURL` appeared nowhere in `ReportsPage`. A blob URL was created
 * on every export — before the save was even attempted — and used only inside two
 * notification click handlers, so each export pinned its whole PDF in memory for
 * the document's lifetime. This is a single-page application that never reloads,
 * so that is the rest of the session: a report carrying the survey-map image is
 * several megabytes, and ten exports retained tens of megabytes with no way to
 * release them short of restarting the tool, on a rig that is often a laptop in a
 * vehicle.
 *
 * The fix has two halves that pull against each other, which is what makes it
 * worth a test rather than a review. The *previous* URL is revoked when a new one
 * is made, not the current one on close, because the notification that opens the
 * preview stays clickable for a while and a revoked URL opens a blank frame. And
 * the comparison is made against a ref rather than the state value, because
 * everything above that line is `await`-heavy: an operator who opens the previous
 * export's preview *while* this one assembles would otherwise have had its URL
 * revoked out from under the iframe, with the modal left open on nothing.
 *
 * A LAN sweep is exported rather than a wireless survey. `captureSurveyMap` runs
 * MapLibre, which needs a WebGL context jsdom does not have; `ReportsPage` skips
 * the map entirely when no wireless report is selected, so this exercises the
 * real PDF path without it.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { ReportsPage } from '../../src/pages/ReportsPage';
import { useReportStore } from '../../src/stores/reportStore';
import { objectUrls } from './setup';
import { whenSql, resetSqlStub } from './stubs/plugin-sql';

const REPORT = {
  id: 'LAN-SWEEP-1',
  // Not 'WIRELESS': `isWirelessReport` is `type !== 'INTRUSION'`, and an
  // intrusion archive is the one that carries no survey map.
  type: 'INTRUSION' as const,
  targetName: 'Branch Office LAN',
  timestamp: '2026-09-20T09:00:00.000Z',
  summary: { totalNodes: 2, criticalNodes: 0, totalAps: 0, vulnerableAps: 0 },
  origin: 'LIVE',
  rawData: {
    hosts: [
      { ip: '10.0.0.5', hostname: 'nas', mac: null, vendor: null, os: null, open_ports: [], status: 'up' },
    ],
    credentials: [],
    serviceObservations: [],
    sweepScopes: [],
  },
};

function scriptSql() {
  whenSql({ match: 'journal_mode', rows: [{ journal_mode: 'wal' }] });
  whenSql({ match: 'FROM evidence_files', rows: [] });
  whenSql({ match: 'evidence_files', rows: [] });
  whenSql({ match: 'FROM findings', rows: [] });
  whenSql({ match: 'findings', rows: [] });
  whenSql({ match: 'assessment_baselines', rows: [] });
  whenSql({ match: 'FROM clients', rows: [] });
  whenSql({ match: 'clients', rows: [] });
  whenSql({ match: 'engagement_scope', rows: [] });
  whenSql({ match: 'audit_log', rows: [] });
  whenSql({ match: 'mission_coverage', rows: [] });
  whenSql({ match: 'gps_logs', rows: [] });
  whenSql({ match: 'scan_sessions', rows: [] });
  whenSql({ match: 'intel_reports', rows: [] });
  whenSql({ match: 'SELECT', rows: [] });
  whenSql({ match: 'UPDATE', rows: [] });
  whenSql({ match: 'INSERT', rows: [] });
  whenSql({ match: 'PRAGMA', rows: [] });
}

/** Select the archive, open the export menu and render a PDF. */
async function exportPdf() {
  // The name appears twice once a report is selected -- in the list and in the
  // header -- so the first match is taken rather than asserting there is one.
  const [listed] = await screen.findAllByText('Branch Office LAN');
  await userEvent.click(listed);
  await userEvent.click(await screen.findByRole('button', { name: /EXPORT/i }));
  // Either label: the item flashes its done text for a while after a successful
  // export, and the second export in a test arrives inside that window. The
  // control is the same one and `onSelect` does not change with the label.
  await userEvent.click(await screen.findByText(/PDF (REPORT|EXPORTED)/i));
}

/** The export is await-heavy; wait until a new blob URL exists. */
async function waitForUrls(n: number, timeoutMs = 25000) {
  await waitFor(() => expect(objectUrls.created.length).toBeGreaterThanOrEqual(n), { timeout: timeoutMs });
}

beforeEach(() => {
  resetSqlStub();
  scriptSql();
  useReportStore.setState({ reports: [REPORT as never] });
});

describe('the preview blob', () => {
  test('one export creates a URL and revokes nothing', async () => {
    // There is nothing to supersede yet, and revoking the one just made would
    // leave the notification opening a blank frame.
    render(<ReportsPage />);
    await exportPdf();
    await waitForUrls(1);

    expect(objectUrls.revoked).toHaveLength(0);
  }, 60000);

  test('a second export releases the first', async () => {
    /*
      The defect, as memory: every export pinned its whole PDF for the life of
      the page, and the page is the life of the session.
    */
    render(<ReportsPage />);
    await exportPdf();
    await waitForUrls(1);
    const first = objectUrls.created[0];

    await exportPdf();
    await waitForUrls(2);

    await waitFor(() => expect(objectUrls.revoked).toContain(first));
    // And not the one that was just made, which the operator may be about to open.
    expect(objectUrls.revoked).not.toContain(objectUrls.created[objectUrls.created.length - 1]);
  }, 60000);

  test('leaving the page releases the last one', async () => {
    // Only the superseded URL is revoked during a session, so without this the
    // newest outlives the component that made it.
    const { unmount } = render(<ReportsPage />);
    await exportPdf();
    await waitForUrls(1);
    const last = objectUrls.created[objectUrls.created.length - 1];

    unmount();
    expect(objectUrls.revoked).toContain(last);
  }, 60000);

  test('nothing is revoked twice', async () => {
    /*
      Revoking an already-released URL is harmless in a browser and a sign of
      confused ownership here: it would mean the unmount path and the supersede
      path both believe they hold the same blob.
    */
    const { unmount } = render(<ReportsPage />);
    await exportPdf();
    await waitForUrls(1);
    await exportPdf();
    await waitForUrls(2);
    unmount();

    expect(new Set(objectUrls.revoked).size).toBe(objectUrls.revoked.length);
  }, 60000);
});
