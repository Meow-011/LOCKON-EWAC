-- LOCKON EWAC: Initial Database Schema
-- Version: 1

CREATE TABLE IF NOT EXISTS missions (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT,
    start_time  DATETIME NOT NULL DEFAULT (datetime('now')),
    end_time    DATETIME,
    status      TEXT NOT NULL DEFAULT 'ACTIVE'
        CHECK (status IN ('ACTIVE', 'COMPLETED', 'SYNCED')),
    operator    TEXT,
    vehicle_id  TEXT,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS access_points (
    bssid        TEXT PRIMARY KEY,
    ssid         TEXT,
    vendor       TEXT,
    encryption   TEXT NOT NULL DEFAULT 'UNKNOWN',
    cipher       TEXT,
    auth_type    TEXT,
    is_vulnerable INTEGER NOT NULL DEFAULT 0,
    channel      INTEGER,
    first_seen   DATETIME NOT NULL DEFAULT (datetime('now')),
    last_seen    DATETIME NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id  TEXT NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    bssid       TEXT NOT NULL REFERENCES access_points(bssid),
    timestamp   DATETIME NOT NULL DEFAULT (datetime('now')),
    rssi        INTEGER NOT NULL,
    channel     INTEGER,
    frequency   INTEGER,
    latitude    REAL,
    longitude   REAL,
    altitude    REAL,
    speed       REAL,
    hdop        REAL,
    satellites  INTEGER
);

-- Composite index for efficient map queries
CREATE INDEX IF NOT EXISTS idx_scan_mission_time
    ON scan_logs(mission_id, timestamp);

-- Index for AP lookup
CREATE INDEX IF NOT EXISTS idx_scan_bssid
    ON scan_logs(bssid);

-- Spatial-like index for coordinate queries
CREATE INDEX IF NOT EXISTS idx_scan_coords
    ON scan_logs(latitude, longitude);

CREATE TABLE IF NOT EXISTS vulnerability_results (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid       TEXT NOT NULL REFERENCES access_points(bssid),
    risk_score  INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_level  TEXT NOT NULL DEFAULT 'LOW'
        CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    summary     TEXT,
    created_at  DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Enable WAL mode for concurrent read/write
PRAGMA journal_mode = WAL;
