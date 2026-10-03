"""Tests that the app's hot queries use an index.

    python engine/tests/test_query_plans.py
    python -m pytest engine/tests/test_query_plans.py

This lives on the engine side because it needs nothing but `sqlite3` and the
migration files. The TypeScript suites run against a stubbed `plugin-sql` and
cannot see a query plan at all.

Why it exists.

Six of the seven queries the application runs most were full table scans,
measured with EXPLAIN QUERY PLAN against the real schema. Three separate causes:

  * `UPPER(col) = UPPER(?)` cannot use an ordinary index on `col`. Three
    lookups do this — WPS measurement writes, evidence-by-BSSID and
    clients-by-BSSID — defensively, because `access_points.bssid` is a
    BINARY-collated TEXT PRIMARY KEY and nothing in the schema stops `AA:BB`
    and `aa:bb` being two different access points. Worse, two indexes existed
    *specifically* to serve those queries and could never be used by them, so
    they were pure write cost.
  * `idx_findings_subject` leads with `subject_type`, so filtering on
    `subject_id` alone could not use it — and that is the query the Findings
    view runs.
  * `audit_log` was indexed on `ts`, `decision` and `command`, but not on
    `scope_id`, the one column the audit-trail export filters by.

A WPS scan returning 300 access points against an inventory of 5,000 was
1.5 million row reads. These assert the plans directly, so a future schema
change that silently reintroduces a scan fails here instead of being discovered
as "the app got slow".
"""
import glob
import os
import sqlite3
import sys
import tempfile

MIGRATIONS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "src-tauri", "migrations",
)



def _db():
    """A fresh database with every migration applied, the way sqlx applies them."""
    d = tempfile.mkdtemp()
    con = sqlite3.connect(os.path.join(d, "plans.db"))
    for f in sorted(glob.glob(os.path.join(MIGRATIONS_DIR, "*.sql"))):
        con.executescript("BEGIN;" + open(f, encoding="utf-8").read() + ";COMMIT;")
    return con


def _plan(con, sql):
    return " | ".join(r[3] for r in con.execute("EXPLAIN QUERY PLAN " + sql))


def _assert_indexed(con, label, sql):
    plan = _plan(con, sql)
    assert plan.startswith("SEARCH") or "COVERING INDEX" in plan, (
        f"{label} is not using an index:\n    {plan}"
    )
    return plan


def _assert_no_temp_btree(con, label, sql):
    plan = _plan(con, sql)
    assert "TEMP B-TREE" not in plan, (
        f"{label} still needs a temporary sort:\n    {plan}"
    )


# ── The case-insensitive lookups ───────────────────────────────────────────

def test_wps_measurement_writes_use_an_index():
    # `recordWpsMeasurements` runs one of these per measured access point.
    con = _db()
    _assert_indexed(
        con, "recordWpsMeasurements",
        "UPDATE access_points SET wps_enabled = 1 WHERE UPPER(bssid) = UPPER('AA:BB')",
    )
    con.close()


def test_evidence_by_bssid_uses_an_index():
    con = _db()
    _assert_indexed(
        con, "getEvidenceForBssid",
        "SELECT * FROM evidence_files WHERE UPPER(bssid) = UPPER('AA:BB')",
    )
    con.close()


def test_clients_by_bssid_uses_an_index():
    con = _db()
    _assert_indexed(
        con, "getClientsForBssid",
        "SELECT * FROM clients WHERE UPPER(associated_bssid) = UPPER('AA:BB')",
    )
    con.close()


def test_the_evidence_link_lookup_uses_an_index():
    # `linkEvidenceToFindings`, which runs once per distinct AP subject on every
    # assessment write.
    con = _db()
    _assert_indexed(
        con, "linkEvidenceToFindings",
        "SELECT id FROM evidence_files WHERE UPPER(bssid) = 'AA:BB' ORDER BY id",
    )
    con.close()


def test_an_ordinary_index_cannot_serve_an_upper_query():
    # The premise. If this ever stops being true, the expression indexes are
    # unnecessary and should go, because every index costs write throughput.
    con = _db()
    con.execute("CREATE TABLE _probe (v TEXT)")
    con.execute("CREATE INDEX _probe_plain ON _probe(v)")
    plan = _plan(con, "SELECT * FROM _probe WHERE UPPER(v) = 'X'")
    assert plan.startswith("SCAN"), f"expected a scan, got: {plan}"
    con.close()


# ── The columns the app filters on ─────────────────────────────────────────

def test_findings_by_subject_uses_an_index_and_needs_no_sort():
    con = _db()
    sql = "SELECT * FROM findings WHERE subject_id = 'AA:BB' ORDER BY risk_score DESC"
    _assert_indexed(con, "getFindings by subject", sql)
    # The index carries the ordering, so the temp b-tree sort is gone too.
    _assert_no_temp_btree(con, "getFindings by subject", sql)
    con.close()


def test_the_audit_export_filter_uses_an_index():
    con = _db()
    _assert_indexed(
        con, "getAuditLogForScope",
        "SELECT * FROM audit_log WHERE scope_id = 1 ORDER BY ts DESC",
    )
    con.close()


def test_distinct_bssids_per_mission_is_index_only():
    # The archive list does this over `scan_logs`, the highest-volume table.
    con = _db()
    plan = _plan(con, "SELECT DISTINCT bssid FROM scan_logs WHERE mission_id = 'M'")
    assert "COVERING INDEX" in plan, f"expected an index-only scan, got: {plan}"
    assert "TEMP B-TREE" not in plan, f"still sorting: {plan}"
    con.close()


# ── Indexes that no query can use are gone ────────────────────────────────

def test_indexes_no_query_can_use_were_dropped():
    # Each cost write throughput and returned nothing. `idx_scan_coords` is the
    # expensive one: one row per sighting per scan cycle, and nothing ever
    # filters on latitude as a leading column.
    con = _db()
    names = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    for dead in ("idx_scan_coords", "idx_ap_coords", "idx_audit_command",
                 "idx_audit_decision", "idx_evidence_sha", "idx_evidence_kind",
                 "idx_reports_sha", "idx_hosts_mac",
                 "idx_evidence_bssid", "idx_clients_assoc"):
        assert dead not in names, f"{dead} is still present"
    con.close()


def test_the_indexes_the_app_relies_on_are_present():
    con = _db()
    names = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='index'")}
    for needed in ("idx_ap_bssid_upper", "idx_evidence_bssid_upper",
                   "idx_clients_assoc_upper", "idx_findings_subject_upper",
                   "idx_findings_subject_score", "idx_audit_scope",
                   "idx_scan_mission_bssid"):
        assert needed in names, f"{needed} is missing"
    con.close()


def test_every_migration_still_applies_cleanly():
    con = _db()
    con.execute("PRAGMA foreign_keys=ON")
    assert con.execute("PRAGMA foreign_key_check").fetchall() == []
    con.close()


def _main():
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"  PASS  {name}")
        except AssertionError as e:
            failed.append(name)
            print(f"  FAIL  {name}: {e or 'assertion failed'}")
        except Exception as e:
            failed.append(name)
            print(f"  ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
