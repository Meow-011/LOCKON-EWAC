/**
 * A wordlist must arrive at the engine byte-for-byte as it left the disk.
 *
 *     npm run test:components
 *
 * Why this exists.
 *
 * The upload reads the file in 512 KB slices and used `readAsText` on each one.
 * A slice is a cut at an arbitrary *byte* offset, so a multi-byte UTF-8 sequence
 * straddling byte 524288 lost its tail in chunk N and had its orphaned
 * continuation bytes in chunk N+1 — each decoding to U+FFFD. One candidate
 * corrupted per boundary, silently, in exactly the lists this tool ships for:
 * the Thai password and mobile-number wordlists, and any list with accented
 * Latin, Cyrillic or CJK. The engine opens with `errors='replace'`, so the
 * damage was unrecoverable on the far side too.
 *
 * A corrupted candidate does not announce itself. It simply never matches, and
 * the run reports that the password was not in the list — which is a false
 * negative in a tool whose entire output is claims about what it did and did not
 * find.
 *
 * `TextDecoder` with `stream: true` holds an incomplete sequence back and
 * prepends it to the next chunk. That fix is one argument long and invisible in
 * review, and `tsc` cannot tell the two apart, so the test puts a Thai character
 * exactly across the boundary and reassembles what the engine was sent.
 */
import { describe, expect, test, beforeEach } from 'vitest';
import { render } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { SettingsPage } from '../../src/pages/SettingsPage';
import { engineIPC } from '../../src/lib/ipc';
import { whenSql, resetSqlStub } from './stubs/plugin-sql';

/** Matches CHUNK_SIZE in `handleFileUpload`. */
const CHUNK = 512 * 1024;

/** Every chunk the page handed to the engine, in order. */
const uploads: { content: string; append: boolean; is_final: boolean; filename: string }[] = [];

function engineRecords() {
  uploads.length = 0;
  (engineIPC as unknown as { send: unknown }).send = async (cmd: string, data: Record<string, unknown>) => {
    if (cmd === 'upload_wordlist') {
      uploads.push({
        content: String(data.content),
        append: Boolean(data.append),
        is_final: Boolean(data.is_final),
        filename: String(data.filename),
      });
    }
  };
}

function scriptSql() {
  whenSql({ match: 'journal_mode', rows: [{ journal_mode: 'wal' }] });
  whenSql({ match: 'engagement_scope', rows: [] });
  whenSql({ match: 'scope_targets', rows: [] });
  whenSql({ match: 'audit_log', rows: [] });
  whenSql({ match: 'FROM evidence_files', rows: [] });
  whenSql({ match: 'benchmark', rows: [] });
  whenSql({ match: 'antenna_benchmarks', rows: [] });
  whenSql({ match: 'SELECT', rows: [] });
  whenSql({ match: 'UPDATE', rows: [] });
  whenSql({ match: 'INSERT', rows: [] });
  whenSql({ match: 'DELETE', rows: [] });
  whenSql({ match: 'PRAGMA', rows: [] });
}

/**
 * A file whose text crosses the chunk boundary mid-character.
 *
 * `ก` (Thai KO KAI) is three bytes in UTF-8. The padding is sized so that
 * one of those three bytes is the last in the first slice — which is the whole
 * point: a boundary that falls between characters would pass with the defect
 * still present.
 */
function straddlingFile() {
  const THAI = 'ก';                 // 3 bytes: E0 B8 81
  const head = 'a'.repeat(CHUNK - 1);    // one byte short of the boundary
  const text = head + THAI + 'b'.repeat(16);
  const bytes = new TextEncoder().encode(text);
  // The character really does straddle: its first byte is the slice's last.
  if (bytes.length <= CHUNK) throw new Error('fixture does not reach a second chunk');
  return { file: new File([bytes], 'thai.txt', { type: 'text/plain' }), text };
}

function fileInput(container: HTMLElement): HTMLInputElement {
  const inputs = [...container.querySelectorAll('input[type="file"]')] as HTMLInputElement[];
  const input = inputs.find(i => (i.getAttribute('accept') || '').includes('.txt'));
  if (!input) throw new Error('no wordlist file input on the page');
  return input;
}

/** The uploads are async per chunk; wait until the page says it has finished. */
async function waitForFinal(timeoutMs = 15000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    if (uploads.some(u => u.is_final)) return;
    await new Promise(r => setTimeout(r, 20));
  }
  throw new Error(`no final chunk after ${timeoutMs}ms (got ${uploads.length} chunk(s))`);
}

beforeEach(() => {
  resetSqlStub();
  scriptSql();
  engineRecords();
});

describe('uploading a wordlist', () => {
  test('a character straddling the chunk boundary survives intact', async () => {
    /*
      The defect, stated as an assertion: U+FFFD anywhere means a candidate was
      silently replaced. There is no legitimate reason for one to appear — the
      fixture contains none.
    */
    const { file, text } = straddlingFile();
    const { container } = render(<SettingsPage />);
    await userEvent.upload(fileInput(container), file);
    await waitForFinal();

    const received = uploads.map(u => u.content).join('');
    expect(received).not.toMatch(/�/);
    expect(received).toBe(text);
  });

  test('it really is split across more than one chunk', async () => {
    // Without this the test above would pass on a one-chunk file, which is the
    // case that never had the bug. The harness check for this file.
    const { file } = straddlingFile();
    const { container } = render(<SettingsPage />);
    await userEvent.upload(fileInput(container), file);
    await waitForFinal();

    expect(uploads.length).toBeGreaterThan(1);
  });

  test('the first chunk writes and the rest append', async () => {
    /*
      `append: false` on anything but the first chunk truncates the file the
      engine is assembling, so a list would arrive holding only its last slice —
      which looks like a smaller wordlist rather than like a failure.
    */
    const { file } = straddlingFile();
    const { container } = render(<SettingsPage />);
    await userEvent.upload(fileInput(container), file);
    await waitForFinal();

    expect(uploads[0].append).toBe(false);
    expect(uploads.slice(1).every(u => u.append)).toBe(true);
  });

  test('exactly one chunk is marked final', async () => {
    // The engine closes the file on `is_final`. Two would close it early and
    // append the remainder to a closed list; none would leave it open.
    const { file } = straddlingFile();
    const { container } = render(<SettingsPage />);
    await userEvent.upload(fileInput(container), file);
    await waitForFinal();

    expect(uploads.filter(u => u.is_final)).toHaveLength(1);
    expect(uploads[uploads.length - 1].is_final).toBe(true);
  });

  test('the filename travels with every chunk', async () => {
    const { file } = straddlingFile();
    const { container } = render(<SettingsPage />);
    await userEvent.upload(fileInput(container), file);
    await waitForFinal();

    expect(uploads.every(u => u.filename === 'thai.txt')).toBe(true);
  });
});
