-- LOCKON EWAC: WPS becomes a measurement instead of an assumption
-- Version: 13
--
-- `wps_enabled` and `wps_locked` were added in migration 008 as
-- `INTEGER NOT NULL DEFAULT 0`. That schema cannot express "not measured", and
-- until now nothing ever measured it: the only producer of WPS data is the
-- engine's `scan_wps` command, and no code path in the UI sent it. Every access
-- point ever recorded therefore carries a hard zero that came from the column
-- default.
--
-- The report read that zero as an observation. Each AP row printed
-- "WPS: not advertised", and a green callout stated that no access point
-- advertised WPS "in its beacon" — describing a beacon information-element parse
-- that never ran, with a careful "this is an observation, not a guarantee"
-- underneath that made the fabrication read as rigour. That is the worst thing
-- this tool can do: a positive measurement claim with no measurement behind it.
--
-- SQLite cannot drop NOT NULL from an existing column without rebuilding the
-- table, and rebuilding `access_points` would mean recreating its indexes and
-- every foreign key that references it for the sake of two columns. A separate
-- nullable timestamp carries the same information with none of that risk:
--
--     wps_scanned_at IS NULL      -> never measured. wps_enabled/wps_locked
--                                    are meaningless; do not read them.
--     wps_scanned_at IS NOT NULL  -> measured at that time. wps_enabled is then
--                                    a real observation, including when it is 0.
--
-- Nothing is backfilled, deliberately. Every existing row is genuinely
-- unmeasured, and leaving `wps_scanned_at` NULL is exactly how that is now
-- recorded.

-- When the WPS scan last produced a result for this access point, ISO-8601.
-- NULL means no WPS scan has ever covered it.
ALTER TABLE access_points ADD COLUMN wps_scanned_at TEXT;

-- Lets the report count measured-versus-unmeasured access points without a
-- table scan, which is what the WPS section needs to state its denominator.
CREATE INDEX IF NOT EXISTS idx_ap_wps_measured
    ON access_points(wps_scanned_at, wps_enabled);
