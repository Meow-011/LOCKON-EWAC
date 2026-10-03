#!/usr/bin/env node
/**
 * With the tile hosts blocked, the installed archive is readable by the shipped app.
 *
 *     npm run test:basemap:runtime      (needs a release build and an archive installed)
 *
 * What this establishes, and what it does not.
 *
 * PROVEN: the host finds the archive, serves byte ranges from it, and the
 * PMTiles reader parses its header through the `pmtiles://` protocol — the whole
 * chain from disk to the map's data source, with every tile CDN blocked and the
 * HTTP cache disabled. That is what the `[basemap] archive ready` line reports,
 * logged by the one place in the application that knows.
 *
 * NOT PROVEN: that the style reached the canvas. Two attempts at that failed, and
 * both are recorded here because the second one looked like it had worked.
 *
 * Glyph requests were the first idea: if the offline style renders labels it
 * fetches glyph blocks from the app's own origin, and nothing else requests those
 * paths. But labels only exist where the archive has tiles, so an extract that
 * does not cover where the map is pointing requests no glyphs at all — which is
 * indistinguishable from the style never being applied.
 *
 * A screenshot pixel was the second, on the reasoning that the PMTiles style
 * paints `#0b0f14` under everything and the flat grid paints `#f1f5f9`. It
 * reported a dark pixel and passed. Then the archive was moved aside, and it
 * reported a *darker* pixel and would have passed again — the map area is dark in
 * both states, so the measurement separated nothing. A check that passes for the
 * right reason and the wrong reason alike is worse than no check, because it gets
 * quoted.
 *
 * Settling it needs the map to be over ground the archive covers, and moving the
 * map needs a handle on it that this application deliberately does not expose:
 * `withGlobalTauri` is off, which is right for a renderer holding
 * `sql:allow-execute`. So the glyph finding is reported conditionally rather than
 * asserted — stated when it happened, and stated as not established when it did
 * not.
 */
import { waitForDebugger, launchApp, shutdownApp, connect, cdp, APP_URL_HINTS } from './cdp.mjs';

const PORT = 9227;
const log = (m) => console.log(`[basemap:runtime] ${m}`);

/** Everything the online basemap needs, so the offline path is the only one left. */
const BLOCKED = [
  '*basemaps.cartocdn.com*',
  '*server.arcgisonline.com*',
  '*s3.amazonaws.com*',
];

const problems = [];
const app = launchApp(PORT, 'release');
try {
  await waitForDebugger(PORT, 120000);
  const pages = await cdp(PORT, '/json/list');
  const page = pages.find(p => p.type === 'page' && APP_URL_HINTS.some(h => (p.url || '').includes(h)))
    ?? pages.find(p => p.type === 'page');
  if (!page) throw new Error('no page to attach to');
  const session = await connect(page);

  const requests = [];
  const logged = [];
  session.onEvent = (msg) => {
    if (msg.method === 'Network.requestWillBeSent') requests.push(msg.params?.request?.url ?? '');
    if (msg.method === 'Runtime.consoleAPICalled') {
      logged.push((msg.params?.args ?? []).map(a => a.value ?? a.description ?? '').join(' '));
    }
  };
  await session.send('Runtime.enable', {});
  await session.send('Network.enable', {});
  await session.send('Network.setBlockedURLs', { urls: BLOCKED });
  /*
    And the cache, which otherwise makes this pass over the thing it is for.

    The first run looked like a failure of the offline basemap and was not: the
    CARTO style came back from the HTTP cache, so the style load succeeded, the
    fatal error path never ran, and the map stayed online-ish — rendering cached
    tiles while glyph requests failed one codepoint at a time. Reasonable
    behaviour, and useless to test against, because it is not the state a rig is
    in when it is carried into a building with no signal and opened cold.
  */
  await session.send('Network.setCacheDisabled', { cacheDisabled: true });
  log(`blocked ${BLOCKED.length} tile host pattern(s), cache off, reloading`);

  await session.evaluate('location.reload()').catch(() => {});
  // The map has to fail its remote tiles, fall back, and read the archive header.
  // Generous, because this is the slowest path in the application.
  await new Promise(r => setTimeout(r, 25000));

  const tileRequests = requests.filter(u => /cartocdn|arcgisonline|amazonaws/.test(u));
  const glyphRequests = requests.filter(u => u.includes('/basemap-glyphs/'));
  log(`${requests.length} request(s): ${tileRequests.length} to a blocked tile host, ${glyphRequests.length} for glyphs`);

  const said = logged.filter(l => l.includes('[basemap]'));
  for (const line of [...new Set(said)].slice(0, 4)) log(`app: ${line.slice(0, 200)}`);

  if (!said.some(l => l.includes('archive ready'))) {
    problems.push(
      'the host never reported a readable archive — install one at the path the '
      + 'Settings card shows, or read there why it was refused'
    );
  } else {
    log('PROVEN: the archive is readable through the host and the pmtiles protocol');
    if (glyphRequests.length > 0) {
      const sample = decodeURIComponent(glyphRequests[0].split('/basemap-glyphs/')[1] ?? '');
      log(`PROVEN: labels rendered from the app's own glyphs (${sample})`);
    } else {
      log('NOT ESTABLISHED: no glyph was requested, so the archive covers no part of');
      log('  the current view, and whether the style reached the canvas is unknown.');
      log('  Install an extract covering MAP_DEFAULT_CENTER to make that assertion.');
    }
  }
} finally {
  await shutdownApp(app);
}

if (problems.length > 0) {
  console.error('[basemap:runtime] FAIL');
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
log('PASS');
