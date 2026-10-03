-- LOCKON EWAC: Evidence Integrity + Engagement Scope
-- Version: 8
--
-- Two concerns, both required before a report from this tool can be handed to
-- anyone who will act on it:
--
--   1. Provenance. Simulated runs used to be written into the same rows as real
--      field data with nothing to tell them apart, so a PDF built from a
--      simulator session was indistinguishable from evidence. Every table that
--      feeds a report now carries is_simulated.
--   2. Authorization. Offensive modules had no notion of an engagement scope,
--      so auto-attack would happily work through whatever the rig drove past.
--      The scope lives here, the engine enforces it, and audit_log records
--      every allow and every block so the report can prove the operator stayed
--      inside what they were authorized to touch.

-- ── 1. Provenance flags ──────────────────────────────────────────────────────

ALTER TABLE missions        ADD COLUMN is_simulated INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_points   ADD COLUMN is_simulated INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_logs       ADD COLUMN is_simulated INTEGER NOT NULL DEFAULT 0;
ALTER TABLE scan_sessions   ADD COLUMN is_simulated INTEGER NOT NULL DEFAULT 0;
ALTER TABLE intel_reports   ADD COLUMN is_simulated INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cracking_history ADD COLUMN is_simulated INTEGER NOT NULL DEFAULT 0;

-- ── 2. AP columns the app already had in its types but never persisted ───────
-- latitude/longitude were being UPDATEd by the GPR post-processing step against
-- columns that did not exist, so every deep-analysis result was silently lost.
-- location_method records which estimator produced the fix, which is what makes
-- a coordinate defensible in a report rather than just a dot on a map.

ALTER TABLE access_points ADD COLUMN latitude        REAL;
ALTER TABLE access_points ADD COLUMN longitude       REAL;
ALTER TABLE access_points ADD COLUMN location_method TEXT;
ALTER TABLE access_points ADD COLUMN location_confidence REAL;
ALTER TABLE access_points ADD COLUMN frequency       INTEGER;
ALTER TABLE access_points ADD COLUMN band            TEXT;
ALTER TABLE access_points ADD COLUMN is_evil_twin    INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_points ADD COLUMN wps_enabled     INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_points ADD COLUMN wps_locked      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE access_points ADD COLUMN wps_version     TEXT;

CREATE INDEX IF NOT EXISTS idx_ap_coords ON access_points(latitude, longitude);

-- ── 3. Engagement scope ─────────────────────────────────────────────────────
-- One row per authorized engagement. Exactly one is_active row is expected;
-- the application enforces that, since SQLite has no clean partial-unique
-- constraint for it across all supported versions.

CREATE TABLE IF NOT EXISTS engagement_scope (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_name TEXT NOT NULL,
    authorized_by   TEXT NOT NULL,
    -- Who ran it. Stamped onto every audit row, so an audit trail is signed
    -- rather than anonymous.
    operator        TEXT,
    reference       TEXT,
    mode            TEXT NOT NULL DEFAULT 'ALLOWLIST'
        CHECK (mode IN ('ALLOWLIST', 'UNRESTRICTED')),
    unrestricted_ack TEXT,
    valid_from      TEXT NOT NULL DEFAULT (datetime('now')),
    valid_until     TEXT,
    is_active       INTEGER NOT NULL DEFAULT 0,
    notes           TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

-- The allowlist itself. kind tells the engine how to match:
--   BSSID -> exact MAC, separator/case insensitive
--   SSID  -> exact network name
--   IP    -> exact address
--   CIDR  -> address inside the range, and a requested subnet must be a subset
CREATE TABLE IF NOT EXISTS engagement_targets (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scope_id INTEGER NOT NULL REFERENCES engagement_scope(id) ON DELETE CASCADE,
    kind     TEXT NOT NULL CHECK (kind IN ('BSSID', 'SSID', 'IP', 'CIDR')),
    value    TEXT NOT NULL,
    note     TEXT
);

CREATE INDEX IF NOT EXISTS idx_targets_scope ON engagement_targets(scope_id);
CREATE INDEX IF NOT EXISTS idx_scope_active  ON engagement_scope(is_active);

-- ── 4. Audit trail ──────────────────────────────────────────────────────────
-- Written by the frontend from audit_event messages the engine emits. The
-- engine deliberately does not write here itself: the SQLite file has a single
-- writer (the Tauri SQL plugin) and keeping it that way avoids lock contention.

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT NOT NULL DEFAULT (datetime('now')),
    scope_id        INTEGER,
    engagement_name TEXT,
    command         TEXT NOT NULL,
    target          TEXT,
    target_kind     TEXT,
    decision        TEXT NOT NULL CHECK (decision IN ('ALLOWED', 'BLOCKED')),
    reason          TEXT,
    operator        TEXT,
    mission_id      TEXT,
    session_id      TEXT,
    details         TEXT
);

CREATE INDEX IF NOT EXISTS idx_audit_ts       ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_log(decision);
CREATE INDEX IF NOT EXISTS idx_audit_command  ON audit_log(command);
