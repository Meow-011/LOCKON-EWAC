-- LOCKON EWAC — Antenna Benchmark Schema

CREATE TABLE IF NOT EXISTS antenna_benchmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL,
    interface_name TEXT NOT NULL,
    total_aps INTEGER NOT NULL DEFAULT 0,
    aps_2g INTEGER NOT NULL DEFAULT 0,
    aps_5g INTEGER NOT NULL DEFAULT 0,
    aps_6g INTEGER NOT NULL DEFAULT 0,
    min_rssi INTEGER,
    max_rssi INTEGER,
    avg_rssi REAL,
    band_excellent INTEGER NOT NULL DEFAULT 0,
    band_good INTEGER NOT NULL DEFAULT 0,
    band_fair INTEGER NOT NULL DEFAULT 0,
    band_weak INTEGER NOT NULL DEFAULT 0,
    scan_duration_ms INTEGER,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
