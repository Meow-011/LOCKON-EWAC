-- LOCKON EWAC: Wardriving GPS Path Schema
-- Version: 3

-- This table tracks continuous GPS breadcrumbs even when no APs are found
CREATE TABLE IF NOT EXISTS gps_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    latitude REAL NOT NULL,
    longitude REAL NOT NULL,
    heading REAL,
    speed REAL,
    timestamp DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Index for efficient path retrieval by mission
CREATE INDEX IF NOT EXISTS idx_gps_mission_time
    ON gps_logs(mission_id, timestamp);
