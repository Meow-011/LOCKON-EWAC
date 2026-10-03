/**
 * Bundle entry for the live map's uncertainty overlay.
 *
 * `mapUncertainty.ts` is now plain: it reaches `src/lib/position.ts` and nothing
 * else, so esbuild could take it directly. The entry stays because the tests also
 * assert against `RING_LIMIT_M` and because the aliases in the npm script are
 * what make a mistake here loud -- if a future import drags the Tauri bridge back
 * into this module, the bundle fails rather than quietly pulling a stub in.
 *
 * It used to be necessary: through `report/archive` the module reached the shell
 * and SQL plugins, and through `report/surveyMap` it reached MapLibre's
 * stylesheet, for four helpers and one constant.
 */
export * from '../../src/lib/mapUncertainty';
