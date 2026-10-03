-- LOCKON EWAC: make the app's hot lookups use an index
-- Version: 16
--
-- Measured with EXPLAIN QUERY PLAN against the real schema. Six of the seven
-- queries the app runs most were full table scans.
--
-- Three causes, and the fix differs for each.
--
-- 1. `UPPER(col) = UPPER(?)` cannot use an ordinary index on `col`, because the
--    index stores the column's value and the query asks about a function of it.
--    `recordWpsMeasurements`, `getEvidenceForBssid` and `getClientsForBssid` all
--    do this, defensively, because `access_points.bssid` is a BINARY-collated
--    TEXT PRIMARY KEY and nothing in the schema stops `AA:BB` and `aa:bb`
--    being two different access points.
--
--    The textbook answer is `COLLATE NOCASE` on the column, which would remove
--    both the risk and the reason for the UPPER(). It also needs a full table
--    rebuild of `access_points` — recreating every index and every foreign key
--    that references it — to change a primary key's collation. SQLite has
--    supported indexes *on expressions* since 3.9, and one of those gives the
--    same query plan with none of that risk. The defensive queries stay
--    defensive and become fast.
--
-- 2. `idx_findings_subject` is `(subject_type, subject_id)`, so a query that
--    filters on `subject_id` alone cannot use it: the leading column is
--    missing. That is the query the Findings view actually runs.
--
-- 3. `audit_log` is indexed on `ts`, `decision` and `command` but not on
--    `scope_id`, which is the one column the audit-trail export filters by —
--    so it scanned the whole log through the timestamp index.

-- ── 1. Expression indexes for the case-insensitive lookups ────────────────

CREATE INDEX IF NOT EXISTS idx_ap_bssid_upper
    ON access_points(UPPER(bssid));

CREATE INDEX IF NOT EXISTS idx_evidence_bssid_upper
    ON evidence_files(UPPER(bssid));

CREATE INDEX IF NOT EXISTS idx_clients_assoc_upper
    ON clients(UPPER(associated_bssid));

CREATE INDEX IF NOT EXISTS idx_findings_subject_upper
    ON findings(UPPER(subject_id));

-- ── 2 and 3. The columns the app filters on ───────────────────────────────

-- Findings for one subject, newest risk first. Covers the ORDER BY too, so the
-- temp b-tree sort goes away.
CREATE INDEX IF NOT EXISTS idx_findings_subject_score
    ON findings(subject_id, risk_score DESC);

CREATE INDEX IF NOT EXISTS idx_audit_scope
    ON audit_log(scope_id, ts DESC);

-- `getMissions()` and the archive list count distinct BSSIDs per mission. With
-- `(mission_id)` alone that needs a table fetch per row of the largest table in
-- the database; adding bssid makes it index-only.
CREATE INDEX IF NOT EXISTS idx_scan_mission_bssid
    ON scan_logs(mission_id, bssid);

-- ── 4. Drop indexes no query can use ──────────────────────────────────────
--
-- Each of these costs write throughput on every insert and returns nothing.
-- `idx_scan_coords` is the expensive one: `scan_logs` is the highest-volume
-- insert path in the application — one row per access-point sighting per scan
-- cycle — and nothing ever filters on latitude as a leading column. The
-- position queries filter `mission_id` first.
--
-- The two audit indexes are on near-zero-cardinality columns (`decision` is
-- ALLOWED or BLOCKED), where an index cannot help and the planner will not
-- choose it.

DROP INDEX IF EXISTS idx_scan_coords;
DROP INDEX IF EXISTS idx_ap_coords;
DROP INDEX IF EXISTS idx_audit_command;
DROP INDEX IF EXISTS idx_audit_decision;
DROP INDEX IF EXISTS idx_evidence_sha;
DROP INDEX IF EXISTS idx_evidence_kind;
DROP INDEX IF EXISTS idx_reports_sha;
DROP INDEX IF EXISTS idx_hosts_mac;

-- Superseded by the expression indexes above, which serve the queries these
-- were created for.
DROP INDEX IF EXISTS idx_evidence_bssid;
DROP INDEX IF EXISTS idx_clients_assoc;
