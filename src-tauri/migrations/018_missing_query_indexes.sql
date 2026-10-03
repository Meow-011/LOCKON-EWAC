-- The three columns 016 audited around and did not index.
--
-- Measured with EXPLAIN QUERY PLAN against the schema these migrations produce, for
-- the queries the application actually issues. Each of these was a full table scan,
-- and two of them scan a table that carries a blob per row.
--
-- 016 was a careful pass: it added the UPPER() expression indexes the case-insensitive
-- lookups need and dropped four indexes nothing filtered by. These three were simply
-- missed, and one of them is on a table 016 touched — it removed
-- `idx_evidence_sha`/`idx_evidence_kind` from `evidence_files` without adding the
-- column the evidence register actually reads by.

-- 1. The evidence register's only read.
--
-- `getEvidence()` is `WHERE mission_id IN (...) ORDER BY recorded_at DESC`, and it was
-- `SCAN evidence_files` plus a temp b-tree for the sort. `recorded_at` is in the index
-- so the ordering comes out of it rather than out of a sort of the whole table.
CREATE INDEX IF NOT EXISTS idx_evidence_mission
    ON evidence_files(mission_id, recorded_at DESC);

-- 2. Findings by session.
--
-- 009 indexed `findings(mission_id)` and not `session_id`, though both are written and
-- both are filtered: `listFindings` reads by session, and `deleteSession` issues
-- `DELETE FROM findings WHERE session_id = ?`. A delete that scans is the worse of the
-- two, because it holds a write lock for the length of the scan.
CREATE INDEX IF NOT EXISTS idx_findings_session
    ON findings(session_id);

-- 3. The archive list.
--
-- `SELECT * FROM intel_reports ORDER BY timestamp DESC` was a scan plus a temp b-tree,
-- and every row of that table carries `raw_data` — the entire report as JSON. Sorting
-- without an index therefore materialises every blob in the archive to order a list
-- that only displays summary fields. The index makes the ordering free; narrowing the
-- SELECT would make the read free too, and that is a separate change in the TypeScript.
CREATE INDEX IF NOT EXISTS idx_reports_timestamp
    ON intel_reports(timestamp DESC);

-- `cracking_history ORDER BY created_at DESC` is also a scan plus a sort, and is
-- deliberately left alone: it holds one row per cracking run, so the table is small
-- enough that an index costs more in write time than it saves in read time. Noted here
-- so the omission reads as a decision rather than an oversight.
