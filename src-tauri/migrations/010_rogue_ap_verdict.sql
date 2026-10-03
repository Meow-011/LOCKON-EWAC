-- LOCKON EWAC: Rogue AP verdict persistence
-- Version: 10
--
-- The engine scores rogue-AP indicators (engine/scanner/evil_twin.py) and emits
-- a verdict, a score and the individual reasons. None of it was being stored:
-- access_points carried only the boolean `is_evil_twin`, and the frontend store
-- recomputed that boolean from its own weaker same-SSID/different-encryption
-- rule, overwriting the engine's answer.
--
-- The effect was that the report could only ever say "evil twin: yes/no" with no
-- reason attached, and the reason is the entire value of the finding — "this AP
-- is on different vendor hardware to the rest of the SSID and is 30 dB stronger"
-- is actionable, "is_evil_twin = 1" is not.

ALTER TABLE access_points ADD COLUMN rogue_verdict    TEXT;
ALTER TABLE access_points ADD COLUMN rogue_score      INTEGER NOT NULL DEFAULT 0;
-- JSON array of {code, weight, detail} — the human-readable reasons the report
-- prints so a reader can judge the verdict rather than trust it.
ALTER TABLE access_points ADD COLUMN rogue_indicators TEXT;

CREATE INDEX IF NOT EXISTS idx_ap_rogue ON access_points(rogue_verdict);
