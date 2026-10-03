-- LOCKON EWAC: Location uncertainty
-- Version: 11
--
-- A coordinate without a stated uncertainty is not evidence, and until now the
-- app stored only the point. Worse, the one number it did store came from the
-- GPR module's `100 - sigma*5`, which reported 69% confidence on a position
-- measured 225 m from truth.
--
-- The estimators now produce an error radius in metres and, where the route was
-- too straight to determine which side of it the transmitter lies on, the
-- mirrored candidate position. Both belong in the record: a report that shows a
-- single dot for a position that is genuinely one of two, 80 m apart, is making
-- a claim the data does not support.

-- Radius in metres containing roughly 95% of the posterior mass.
ALTER TABLE access_points ADD COLUMN location_error_m REAL;

-- Spread about the chosen mode alone. When a mirror exists the posterior is
-- bimodal: tight around each of two well-separated positions, so one number
-- cannot describe it honestly.
ALTER TABLE access_points ADD COLUMN location_mode_error_m REAL;

-- The equally good position on the other side of the line of travel.
ALTER TABLE access_points ADD COLUMN location_mirror_lat REAL;
ALTER TABLE access_points ADD COLUMN location_mirror_lon REAL;
ALTER TABLE access_points ADD COLUMN location_mirror_distance_m REAL;

-- Route geometry at the time of the estimate: how much the survey path deviated
-- from a straight line, which is what decides whether the side is knowable.
ALTER TABLE access_points ADD COLUMN geometry_cross_track_m REAL;
ALTER TABLE access_points ADD COLUMN geometry_along_track_m REAL;
ALTER TABLE access_points ADD COLUMN geometry_ambiguous INTEGER NOT NULL DEFAULT 0;

-- Caveats attached to this specific estimate, as a JSON array of strings. These
-- print in the report next to the coordinate.
ALTER TABLE access_points ADD COLUMN location_notes TEXT;

CREATE INDEX IF NOT EXISTS idx_ap_location_quality
    ON access_points(geometry_ambiguous, location_error_m);
