/**
 * Shared setup for the component tests.
 *
 * Three things a browser gives a page and jsdom does not, each of which this application
 * touches at module scope or on first render — so without them an import throws before
 * a single assertion runs, and the failure looks like a broken test rather than a
 * missing environment.
 */
import '@testing-library/dom';
import { afterEach, beforeEach } from 'vitest';
import { cleanup } from '@testing-library/react';
import { resetSqlStub } from './stubs/plugin-sql';
import { resetShellStub } from './stubs/plugin-shell';
import { resetDialogStub } from './stubs/plugin-dialog';
import { resetInvokeStub } from './stubs/api-core';

// 1. `matchMedia`. The layout reads it for reduced-motion and for width breakpoints.
if (!window.matchMedia) {
  window.matchMedia = ((query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
}

// 2. `ResizeObserver`. MapLibre and the KPI grid both construct one.
if (!('ResizeObserver' in globalThis)) {
  (globalThis as unknown as { ResizeObserver: unknown }).ResizeObserver = class {
    observe() {}
    unobserve() {}
    disconnect() {}
  };
}

/*
  3. Object URLs, recorded.

  This said jsdom implements neither and installed a recorder only when the
  function was absent. It is not absent — this jsdom has a real
  `createObjectURL` — so the guard never fired, `objectUrls` stayed empty for
  every test, and any assertion about the blob-URL lifecycle would have passed by
  observing nothing. That is the vacuous-test shape this project has been caught
  by before, and here it was sitting in the shared setup where it would have
  quietly undermined whatever was written next.

  Wrapped unconditionally now, delegating to the real implementation where there
  is one, so the recording is a fact about what the page did rather than a fact
  about what jsdom happens to be missing this year.
*/
export const objectUrls = { created: [] as string[], revoked: [] as string[] };
let urlCounter = 0;

const realCreate = typeof URL.createObjectURL === 'function' ? URL.createObjectURL.bind(URL) : null;
URL.createObjectURL = ((blob: Blob) => {
  // The real one when jsdom has it, so anything that later fetches the URL still
  // resolves; a synthetic string otherwise.
  const url = realCreate ? realCreate(blob) : `blob:lockon/${++urlCounter}`;
  objectUrls.created.push(url);
  return url;
}) as typeof URL.createObjectURL;

const realRevoke = typeof URL.revokeObjectURL === 'function' ? URL.revokeObjectURL.bind(URL) : null;
URL.revokeObjectURL = ((url: string) => {
  objectUrls.revoked.push(url);
  realRevoke?.(url);
}) as typeof URL.revokeObjectURL;

beforeEach(() => {
  objectUrls.created.length = 0;
  objectUrls.revoked.length = 0;
  resetSqlStub();
  resetShellStub();
  resetDialogStub();
  resetInvokeStub();
});

afterEach(() => {
  // Unmount between tests. Several components register engine listeners in an effect,
  // and a component left mounted would keep receiving events in the next test.
  cleanup();
});
