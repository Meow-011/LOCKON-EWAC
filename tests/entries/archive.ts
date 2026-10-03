/**
 * Bundle entry for the report-archive helpers.
 *
 * `archive.ts` cannot be handed to esbuild directly the way `csv.ts` and
 * `numbers.ts` are: it pulls in `maplibre-gl`'s stylesheet, the Tauri shell
 * plugin (through `engineIPC`) and the SQL plugin (through `scopeDB`). The npm
 * script aliases those away; this file exists so the alias list has one entry
 * point to resolve.
 *
 * `downloadBlob` is deliberately not re-exported — it needs a DOM, and what it
 * does (create an anchor, click it, revoke the object URL) is the browser's
 * behaviour rather than this project's judgment.
 */
export * from '../../src/lib/report/archive';

/*
  The survey figure's arithmetic, which is where the KEY disagreed with the
  "N plotted" sentence beneath it. `captureSurveyMap` needs a canvas and a MapLibre
  instance; `featuresFor` needs neither, and it is the part that counts.
*/
export { featuresFor, plottedCount } from '../../src/lib/report/surveyMap';

/*
  The path-loss exponent, so a test can hold the printed method description to the
  number the estimator actually used. The description quoted an exponent and a
  formula that the documentation had already retracted; a prose claim about a
  constant should fail with the constant.
*/
export { PATH_LOSS_EXPONENT } from '../../src/lib/localization';
