/**
 * LOCKON EWAC — component test configuration.
 *
 * Why this is separate from the existing suites.
 *
 * Everything in `tests/` drives pure modules, stores and real SQLite through
 * `node --test` with esbuild prebundling, and that is the right shape for them: no DOM,
 * no framework, and a database that behaves like the shipped one. It cannot render a
 * component, so a fix that lives in a page was held up by `tsc` and nothing else —
 * about a dozen of them, listed in the engineering log's gaps section.
 *
 * The two runners stay side by side rather than one replacing the other. `npm test`
 * keeps its speed and its real-SQLite guarantee; `npm run test:components` adds a DOM.
 * Merging them would mean putting jsdom under the database suites, which would make the
 * thing those suites exist to prove — that the SQL is right against a real engine —
 * harder to trust rather than easier.
 *
 * What is deliberately NOT mocked here: the risk rule set, the archive readers, the
 * severity and signal palettes, `escapeHtml`. A component test that stubs the rule set
 * proves the component calls something, which is the kind of test this project has
 * already been bitten by. What *is* stubbed is the Tauri boundary — the SQL plugin, the
 * shell plugin, the dialog — because those are the parts a browser cannot provide, and
 * the existing `tests/stubs/` already models them.
 */
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  plugins: [react()],
  define: {
    // The app reads these at module scope; without them an import throws before a
    // single assertion runs.
    'import.meta.env.VITE_APP_VERSION': JSON.stringify('0.0.0-test'),
    'import.meta.env.VITE_BUILD_DATE': JSON.stringify('1970-01-01T00:00:00.000Z'),
  },
  resolve: {
    alias: [
      /*
        MapLibre, which needs WebGL. jsdom has no canvas context, so the real
        thing throws on construction and every page holding a map was untestable
        for that reason alone -- which is why the two maps had no component test
        between them while being the surfaces an operator acts on.

        It is in the same category as the Tauri boundary below: a thing a browser
        cannot provide, not a part of this application being mocked away. The stub
        records calls and draws nothing, so the tests assert what the component
        told the map to draw. Whether it then appears correctly is not knowable
        here and is not claimed.

        Stylesheet imports are emptied for the same reason the archive suite does
        it: a CSS file is not a module.
      */
      {
        find: /^maplibre-gl$/,
        replacement: fileURLToPath(new URL('./tests/components/stubs/maplibre-gl.ts', import.meta.url)),
      },
      {
        find: /maplibre-gl\/dist\/maplibre-gl\.css$/,
        replacement: fileURLToPath(new URL('./tests/components/stubs/empty.css', import.meta.url)),
      },
      // The Tauri boundary. A browser has no IPC, no sidecar and no SQL plugin, so
      // these are the only things a component test may stand in for.
      {
        find: '@tauri-apps/plugin-sql',
        replacement: fileURLToPath(new URL('./tests/components/stubs/plugin-sql.ts', import.meta.url)),
      },
      {
        find: '@tauri-apps/plugin-shell',
        replacement: fileURLToPath(new URL('./tests/components/stubs/plugin-shell.ts', import.meta.url)),
      },
      {
        find: '@tauri-apps/plugin-dialog',
        replacement: fileURLToPath(new URL('./tests/components/stubs/plugin-dialog.ts', import.meta.url)),
      },
      {
        find: '@tauri-apps/api/core',
        replacement: fileURLToPath(new URL('./tests/components/stubs/api-core.ts', import.meta.url)),
      },
    ],
  },
  test: {
    environment: 'jsdom',
    globals: false,
    include: ['tests/components/**/*.test.tsx'],
    setupFiles: ['tests/components/setup.ts'],
    // Each file gets a fresh module registry, so a store that one test mutated cannot
    // reach the next one. The stores here are module-level singletons; without this,
    // test order would decide outcomes.
    isolate: true,
    restoreMocks: true,
    clearMocks: true,
  },
});
