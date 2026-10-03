-- LOCKON EWAC — Credential Vault Schema
-- Phase 6 Sprint C: Stores credentials discovered via brute force, default check, or manual entry.

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    service TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual',  -- 'bruteforce' | 'default_check' | 'manual'
    session_id TEXT,
    hostname TEXT,
    notes TEXT,
    discovered_at TEXT DEFAULT (datetime('now'))
);

-- Index for quick lookups by target
CREATE INDEX IF NOT EXISTS idx_credentials_target ON credentials(target_ip, port);
-- Index for session-based queries
CREATE INDEX IF NOT EXISTS idx_credentials_session ON credentials(session_id);
