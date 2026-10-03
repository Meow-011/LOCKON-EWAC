-- LOCKON EWAC: Intrusion Module Schema
-- Version: 2

-- Scan sessions: one row per INITIATE SWEEP execution
CREATE TABLE IF NOT EXISTS scan_sessions (
    id           TEXT PRIMARY KEY,
    subnet       TEXT NOT NULL,
    scan_mode    TEXT NOT NULL DEFAULT 'QUICK',
    host_count   INTEGER NOT NULL DEFAULT 0,
    started_at   DATETIME NOT NULL DEFAULT (datetime('now')),
    completed_at DATETIME
);

-- Discovered hosts: historical log of every host ever seen
CREATE TABLE IF NOT EXISTS intrusion_hosts (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE CASCADE,
    ip            TEXT NOT NULL,
    hostname      TEXT,
    os            TEXT,
    mac           TEXT,
    vendor        TEXT,
    is_gateway    INTEGER NOT NULL DEFAULT 0,
    discovered_at DATETIME NOT NULL DEFAULT (datetime('now'))
);

-- Port history: every open port per discovery
CREATE TABLE IF NOT EXISTS intrusion_ports (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id  INTEGER NOT NULL REFERENCES intrusion_hosts(id) ON DELETE CASCADE,
    port     INTEGER NOT NULL,
    service  TEXT,
    banner   TEXT
);

CREATE INDEX IF NOT EXISTS idx_sessions_started ON scan_sessions(started_at);
CREATE INDEX IF NOT EXISTS idx_hosts_session ON intrusion_hosts(session_id);
CREATE INDEX IF NOT EXISTS idx_hosts_mac ON intrusion_hosts(mac);
CREATE INDEX IF NOT EXISTS idx_hosts_ip ON intrusion_hosts(ip);
CREATE INDEX IF NOT EXISTS idx_ports_host ON intrusion_ports(host_id);
