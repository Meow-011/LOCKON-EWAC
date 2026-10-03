-- LOCKON EWAC: Findings, Evidence, Clients, Coverage
-- Version: 9
--
-- Closes the gap between what the tool observes and what its report can defend.
--
-- Until now: risk was recomputed ad hoc in the UI from five disagreeing rule
-- sets (one PDF could call a network vulnerable in its headline and LOW in its
-- table on the same page); `vulnerability_results` existed but nothing ever
-- wrote to it; captures were loose unhashed files; client devices were observed
-- and discarded; and nothing recorded how much ground a drive actually covered,
-- so "no findings here" was indistinguishable from "never went there".

-- ── 1. Findings: one durable row per assessed risk, with its reasoning ──────
-- Replaces recomputing severity at render time. A finding records the rule that
-- produced it and why, so two exports of the same mission cannot disagree and a
-- reader can audit any label in the document.

CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    -- What the finding is about
    subject_type  TEXT NOT NULL CHECK (subject_type IN ('AP', 'HOST', 'CLIENT', 'NETWORK')),
    subject_id    TEXT NOT NULL,          -- BSSID, IP, or MAC
    mission_id    TEXT,
    session_id    TEXT,
    -- The assessment
    category      TEXT NOT NULL,          -- 'encryption', 'rogue_ap', 'wps', 'service_cve', ...
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL CHECK (severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    risk_score    INTEGER NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    confidence    TEXT NOT NULL DEFAULT 'CONFIRMED'
        CHECK (confidence IN ('SUSPECTED', 'LIKELY', 'CONFIRMED')),
    -- Why. Without this a severity label is not evidence.
    rationale     TEXT NOT NULL,
    methodology   TEXT,                   -- rule set name + version that produced it
    evidence_refs TEXT,                   -- JSON array of evidence_files.id
    remediation   TEXT,
    -- Lifecycle, for the retest loop
    status        TEXT NOT NULL DEFAULT 'OPEN'
        CHECK (status IN ('OPEN', 'FIXED', 'ACCEPTED', 'REGRESSED', 'FALSE_POSITIVE')),
    first_seen    TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen     TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at   TEXT,
    is_simulated  INTEGER NOT NULL DEFAULT 0,
    -- Stable identity across assessments, so the same issue is recognised on a
    -- retest instead of being reported as new every time.
    fingerprint   TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
CREATE INDEX IF NOT EXISTS idx_findings_subject  ON findings(subject_type, subject_id);
CREATE INDEX IF NOT EXISTS idx_findings_mission  ON findings(mission_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status   ON findings(status);

-- ── 2. Evidence files: artifacts tied to findings, with digests ─────────────
-- A pcap that backs a "handshake captured" claim has to be identifiable and
-- verifiable, not a loose file in whatever directory the sidecar started in.

CREATE TABLE IF NOT EXISTS evidence_files (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL,           -- 'handshake_pcap', 'pmkid_hc22000', 'report_pdf', ...
    path         TEXT NOT NULL,
    filename     TEXT NOT NULL,
    sha256       TEXT,
    size_bytes   INTEGER,
    bssid        TEXT,
    ssid         TEXT,
    mission_id   TEXT,
    session_id   TEXT,
    recorded_at  TEXT NOT NULL DEFAULT (datetime('now')),
    last_verified_at TEXT,
    verify_status    TEXT CHECK (verify_status IN ('MATCH', 'MISMATCH', 'MISSING')),
    notes        TEXT,
    error        TEXT
);

CREATE INDEX IF NOT EXISTS idx_evidence_sha    ON evidence_files(sha256);
CREATE INDEX IF NOT EXISTS idx_evidence_bssid  ON evidence_files(bssid);
CREATE INDEX IF NOT EXISTS idx_evidence_kind   ON evidence_files(kind);

-- ── 3. Client / station inventory ──────────────────────────────────────────
-- `probed_ssids` is what a device was looking for; `associated_bssid` is what it
-- actually connected to. Only the latter may be reported as a connection, and
-- the schema keeps them apart so the report cannot blur the two.

CREATE TABLE IF NOT EXISTS clients (
    mac              TEXT PRIMARY KEY,
    vendor           TEXT,
    -- Locally administered MAC: an ephemeral identifier, not a stable device id.
    is_randomized    INTEGER NOT NULL DEFAULT 0,
    probe_count      INTEGER NOT NULL DEFAULT 0,
    probed_ssids     TEXT,                -- JSON array
    associated_bssid TEXT,
    associated_ssid  TEXT,
    strongest_rssi   INTEGER,
    sources          TEXT,                -- JSON array: probe_request, data_frame, ...
    mission_id       TEXT,
    first_seen       TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen        TEXT NOT NULL DEFAULT (datetime('now')),
    is_simulated     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_clients_assoc   ON clients(associated_bssid);
CREATE INDEX IF NOT EXISTS idx_clients_mission ON clients(mission_id);

-- ── 4. Survey coverage ─────────────────────────────────────────────────────
-- What was actually surveyed, so the report can distinguish "nothing here" from
-- "never went here". Derived from gps_logs/scan_logs at archive time and frozen,
-- because the source rows can be purged while the report must remain defensible.

CREATE TABLE IF NOT EXISTS mission_coverage (
    mission_id        TEXT PRIMARY KEY REFERENCES missions(id) ON DELETE CASCADE,
    computed_at       TEXT NOT NULL DEFAULT (datetime('now')),
    duration_seconds  INTEGER,
    distance_metres   REAL,
    point_count       INTEGER,
    -- Bounding box of the surveyed area
    bbox_min_lat      REAL,
    bbox_min_lon      REAL,
    bbox_max_lat      REAL,
    bbox_max_lon      REAL,
    -- Fix quality, so a thin patch of results can be explained
    avg_hdop          REAL,
    worst_hdop        REAL,
    avg_satellites    REAL,
    gap_count         INTEGER,            -- GPS dropouts over the gap threshold
    max_gap_seconds   INTEGER,
    gap_threshold_seconds INTEGER NOT NULL DEFAULT 30,
    -- Per-band counts, so "no 6 GHz APs" can be read alongside adapter capability
    aps_2g            INTEGER NOT NULL DEFAULT 0,
    aps_5g            INTEGER NOT NULL DEFAULT 0,
    aps_6g            INTEGER NOT NULL DEFAULT 0,
    aps_unknown_band  INTEGER NOT NULL DEFAULT 0,
    channels_seen     TEXT,               -- JSON array
    notes             TEXT
);

-- ── 5. Report integrity + provenance ───────────────────────────────────────
-- A report that someone acts on has to be shown to be the one the tool produced.

ALTER TABLE intel_reports ADD COLUMN sha256          TEXT;
ALTER TABLE intel_reports ADD COLUMN exported_at     TEXT;
ALTER TABLE intel_reports ADD COLUMN exported_by     TEXT;
ALTER TABLE intel_reports ADD COLUMN export_filename TEXT;
ALTER TABLE intel_reports ADD COLUMN app_version     TEXT;
ALTER TABLE intel_reports ADD COLUMN engine_version  TEXT;
ALTER TABLE intel_reports ADD COLUMN cve_data_date   TEXT;
ALTER TABLE intel_reports ADD COLUMN methodology     TEXT;   -- JSON snapshot
ALTER TABLE intel_reports ADD COLUMN origin          TEXT NOT NULL DEFAULT 'LOCAL'
    CHECK (origin IN ('LOCAL', 'IMPORTED'));

CREATE INDEX IF NOT EXISTS idx_reports_sha ON intel_reports(sha256);

-- ── 6. Host findings that were previously thrown away ──────────────────────
-- vuln_engine produces severities that only ever survived inside a report's JSON
-- blob; these let a host's assessment be queried and compared between runs.

ALTER TABLE intrusion_hosts ADD COLUMN risk_score  INTEGER NOT NULL DEFAULT 0;
ALTER TABLE intrusion_hosts ADD COLUMN risk_level  TEXT;
ALTER TABLE intrusion_hosts ADD COLUMN last_status TEXT;

-- ── 7. Baselines, for the retest loop ──────────────────────────────────────
-- Marks an assessment as the reference point a later run is compared against.

CREATE TABLE IF NOT EXISTS assessment_baselines (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    label        TEXT NOT NULL,
    mission_id   TEXT,
    session_id   TEXT,
    scope_id     INTEGER,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    finding_count INTEGER NOT NULL DEFAULT 0,
    notes        TEXT
);

CREATE INDEX IF NOT EXISTS idx_baselines_created ON assessment_baselines(created_at);
