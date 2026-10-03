/**
 * Bundle entry for the three text exports.
 *
 * They reach `report/archive.ts` for `apsOf`, `xmlEscape` and the host helpers,
 * which pulls the Tauri shell and SQL plugins; the npm script aliases those away,
 * exactly as the archive suite does. The builders themselves touch nothing but
 * their inputs -- that is what makes them testable at all, and it is new.
 */
export { apExportRows, positionedRows, exportBaseName } from '../../src/lib/report/exports/apRows';
export { buildCsv } from '../../src/lib/report/exports/csv';
export { buildKml } from '../../src/lib/report/exports/kml';
export { buildGeoJson } from '../../src/lib/report/exports/geojson';
