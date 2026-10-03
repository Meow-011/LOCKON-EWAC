/**
 * The offline basemap must be offline — every byte of it inside the application.
 *
 *     npm run test:basemap
 *
 * Why this exists.
 *
 * With no network the map has been a flat grey background: `MAP_STYLES.OFFLINE`
 * is one `background` layer and nothing else. The markers and the track still
 * draw, so the tool works — but an operator looking at a survey has no coastline,
 * no roads and no place names to locate it against, on a rig whose own
 * documentation says it is "offline in the field and opened occasionally".
 *
 * A basemap is easy to make *almost* offline. A style is a JSON document full of
 * URLs — tiles, glyphs, sprites — and one of them left pointing at a CDN produces
 * a map that is perfect on a desk and missing its labels, or missing entirely, in
 * the field. Nothing in the application would say so: MapLibre logs a failed
 * glyph request to a console nobody is reading in a vehicle.
 *
 * So the assertion that matters is the negative one: no host appears anywhere in
 * the style. The rest of this file checks that the pieces it does name are real.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, statSync, readdirSync } from 'node:fs';

import { offlineBasemapStyle, describeBounds, BASEMAP_GLYPHS, BASEMAP_SOURCE, GLYPH_RANGES } from '../.test-build/basemapStyle.mjs';

test('no part of the style names a host', () => {
  /*
    Checked over the serialised document rather than over the fields this file
    knows about. The layer definitions come from `protomaps-themes-base`, so a
    future version of that package could introduce a URL in a property nothing
    here enumerates — and it would work on every machine with a connection.
  */
  const serialised = JSON.stringify(offlineBasemapStyle(15));
  assert.ok(!/https?:\/\//.test(serialised), 'the style contains an http(s) URL');
  assert.ok(!/\/\/[a-z0-9-]+\.[a-z]{2,}/i.test(serialised), 'the style contains what looks like a hostname');
});

test('tiles come from the pmtiles protocol, not from a URL', () => {
  const style = offlineBasemapStyle(15);
  const source = style.sources[BASEMAP_SOURCE];
  assert.deepEqual(source.tiles, ['pmtiles://basemap/{z}/{x}/{y}']);
  // `url` would make MapLibre fetch a TileJSON document, which there is nobody
  // to serve.
  assert.equal(source.url, undefined);
});

test('the maxzoom is the archive\'s, not a guess', () => {
  /*
    An extract built to z12 and a style claiming z15 makes MapLibre request tiles
    the archive does not hold, and the map goes blank on zoom-in rather than
    staying at its last real detail level.
  */
  assert.equal(offlineBasemapStyle(12).sources[BASEMAP_SOURCE].maxzoom, 12);
  assert.equal(offlineBasemapStyle(15).sources[BASEMAP_SOURCE].maxzoom, 15);
});

test('every glyph range the style can request is committed', () => {
  /*
    The glyphs are the half that fails quietly. A missing range does not break
    the map; it drops the labels that needed it, which looks like an area with no
    place names rather than like a missing file.
  */
  // Read from disk rather than listed here. A hand-written list was wrong on its
  // first attempt -- it named a stack the theme does not ask for and missed one
  // it does -- and a list a test has to be told about is not a check.
  const fontstacks = readdirSync('public/basemap-glyphs');
  assert.ok(fontstacks.length > 0, 'no glyphs are committed at all');
  for (const stack of fontstacks) {
    for (const range of GLYPH_RANGES) {
      const file = `public/basemap-glyphs/${stack}/${range}.pbf`;
      assert.ok(existsSync(file), `${file} is missing`);
      // 16 bytes is below any real glyph block; an error page committed as one
      // would pass an existence check and render nothing.
      assert.ok(statSync(file).size >= 16, `${file} is too small to be a glyph block`);
    }
  }
});

test('the glyph template is same-origin and matches where the files are', () => {
  assert.equal(BASEMAP_GLYPHS, '/basemap-glyphs/{fontstack}/{range}.pbf');
  const style = offlineBasemapStyle(15);
  assert.equal(style.glyphs, BASEMAP_GLYPHS);
});

test('every font the layers ask for is a fontstack that was fetched', () => {
  /*
    The theme names its fonts in `text-font`, sometimes as a literal array and
    sometimes inside an expression. A stack that was never fetched produces
    labels that silently do not render, so the names are pulled out of the
    serialised layers rather than from a list kept by hand.
  */
  const style = offlineBasemapStyle(15);
  const names = new Set();
  const walk = (node) => {
    if (Array.isArray(node)) { node.forEach(walk); return; }
    if (node && typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) {
        if (k === 'text-font') walk(v);
        else walk(v);
      }
      return;
    }
    if (typeof node === 'string' && /^Noto Sans /.test(node)) names.add(node);
  };
  walk(style.layers);

  assert.ok(names.size > 0, 'no font names were found, so this test proves nothing');
  for (const name of names) {
    assert.ok(
      existsSync(`public/basemap-glyphs/${name}`),
      `the style asks for "${name}" and no glyphs were fetched for it`
    );
  }
});

test('no layer depends on a sprite', () => {
  // Exactly one of the theme's layers uses `icon-image`, and no sprite is
  // shipped. A layer referencing a sprite that is not there logs an error for
  // every tile, so it is removed rather than left to fail quietly-but-loudly.
  const serialised = JSON.stringify(offlineBasemapStyle(15));
  assert.ok(!serialised.includes('icon-image'), 'a layer still asks for a sprite icon');
  assert.equal(offlineBasemapStyle(15).sprite, undefined);
});

test('a background layer sits under everything', () => {
  /*
    An archive is an extract: it covers a city or a country and nothing beyond
    it. Without a background, the uncovered area is whatever the canvas happens
    to be, which reads as a map that failed to load rather than as the edge of
    the data.
  */
  const style = offlineBasemapStyle(15);
  assert.equal(style.layers[0].type, 'background');
});

// ── describeBounds ─────────────────────────────────────────────────────────
//
// The Settings card printed `11.22, 43.75, 11.29, 43.79` — four bare floats in
// the order PMTiles stores them, with nothing saying which was which. The one
// question that figure exists to answer is "does this cover where I am
// working", and a reader cannot get there from a list of numbers whose meaning
// they have to look up. Displayed that way it was not information.

test('the four numbers become a readable box', () => {
  const d = describeBounds([11.2215, 43.7452, 11.2886, 43.7890]);
  assert.equal(d.lon, '11.22°E to 11.29°E');
  assert.equal(d.lat, '43.75°N to 43.79°N');
});

test('negative degrees are hemispheres, not minus signs', () => {
  /*
    A sign is a convention the reader has to know; a letter is not. This is also
    the case a careless formatter gets wrong by printing "-0.13°E", which reads
    as a contradiction.
  */
  const d = describeBounds([-0.51, 51.28, 0.33, 51.69]);
  assert.equal(d.lon, '0.51°W to 0.33°E');
  assert.equal(d.lat, '51.28°N to 51.69°N');

  const south = describeBounds([-70.8, -33.6, -70.4, -33.3]);
  assert.equal(south.lat, '33.60°S to 33.30°S');
});

test('the extent is given in kilometres, approximately and labelled so', () => {
  /*
    "about 6 × 5 km" answers "is this the right extract" in the time it takes to
    read. The figure is the equirectangular approximation and is wrong by a
    fraction of a percent over a city, which is why it is prefixed with "about"
    rather than stated flat.
  */
  const d = describeBounds([11.2215, 43.7452, 11.2886, 43.7890]);
  assert.match(d.extent, /^about /);
  // Florence: roughly 5 km across and 5 km tall.
  assert.match(d.extent, /^about [45]\.\d × [45]\.\d km$/);
});

test('longitude is scaled by latitude, or a polar extract reads as huge', () => {
  // A degree of longitude is 111 km at the equator and nearly nothing near the
  // pole. Ignoring the cosine makes a small northern extract look continental.
  const equator = describeBounds([0, 0, 1, 1]);
  const north = describeBounds([0, 70, 1, 71]);
  const widthOf = (s) => Number(s.match(/about ([\d.]+) ×/)[1]);
  assert.ok(widthOf(equator.extent) > widthOf(north.extent) * 2,
    `${equator.extent} should be far wider than ${north.extent}`);
});

test('a zero-area box has no extent rather than "0 × 0 km"', () => {
  // A single-point bound is a degenerate archive, and "about 0 × 0 km" reads as
  // a measurement of nothing rather than as an absence.
  const d = describeBounds([11.2, 43.7, 11.2, 43.7]);
  assert.equal(d.extent, null);
});

test('numbers that are not numbers say so', () => {
  // Rather than rendering "NaN°E", which looks like a reading.
  const d = describeBounds([NaN, 43.7, 11.2, 43.7]);
  assert.equal(d.lon, 'not reported');
  assert.equal(d.extent, null);
});
