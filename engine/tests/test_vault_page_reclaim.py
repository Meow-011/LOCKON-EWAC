"""Tests that sealing the credential vault actually removes the cleartext.

    python engine/tests/test_vault_page_reclaim.py
    python -m pytest engine/tests/test_vault_page_reclaim.py

This lives on the engine side because it needs nothing but `sqlite3` and the
migration files, and because it asserts a property of the *database file* rather
than of any one module. The TypeScript vault suite runs against a stubbed
`plugin-sql`, so it cannot see this at all.

Why it exists.

Migration 012 gave the vault AES-256-GCM at rest and the UI reports the result
to the operator as protected. That report was false.

SQLite marks deleted pages free **with their contents intact** —
`secure_delete` is off by default, and it is a per-connection pragma that cannot
be relied on through a connection pool. 012 copies the cleartext `password`
column into a new table and then `DROP TABLE credentials`;
`sealLegacyCredentials()` nulls the column row by row. Neither reclaims a byte,
and there was no `VACUUM` anywhere in the project.

Measured before the fix: of 300 seeded credentials, **all 300 were still
recoverable as raw bytes from the .db file** after migration 012 and after
sealing (312 byte matches, because the INSERT…SELECT leaves a second copy).

The operator's experience was: set a passphrase, seal the vault, watch the
banner report no unprotected rows, and carry a laptop off the engagement with
every recovered credential readable by `strings ewac.db`. That is the exact
scenario 012's own header gives as its reason for existing.

These tests assert the property directly against the real migrations, so the
guarantee cannot quietly lapse again — if someone removes the VACUUM, the first
test fails with a count instead of a passing suite and a false banner.
"""
import glob
import os
import re
import sqlite3
import sys
import tempfile

MIGRATIONS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "src-tauri", "migrations",
)

MARKER = "PLAINTEXT_SECRET_%04d_ZZ"
MARKER_RE = rb"PLAINTEXT_SECRET_[0-9]{4}_ZZ"
SEEDED = 300


def _migrations():
    files = sorted(glob.glob(os.path.join(MIGRATIONS_DIR, "*.sql")))
    assert files, f"no migrations found in {MIGRATIONS_DIR}"
    return files


def _apply(con, files):
    for f in files:
        # sqlx applies each migration in its own transaction.
        con.executescript("BEGIN;" + open(f, encoding="utf-8").read() + ";COMMIT;")


def _seeded_vault(path):
    """A database as it looked before encryption existed: cleartext passwords."""
    files = _migrations()
    m012 = next(f for f in files if os.path.basename(f).startswith("012"))
    con = sqlite3.connect(path)
    _apply(con, files[: files.index(m012)])
    for i in range(SEEDED):
        con.execute(
            "INSERT INTO credentials (target_ip, port, service, username, password)"
            " VALUES (?,?,?,?,?)",
            (f"10.0.0.{i % 254 + 1}", 22, "ssh", f"user{i}", MARKER % i),
        )
    con.commit()
    _apply(con, files[files.index(m012):])   # 012 onwards, including 014
    return con


def _seal(con):
    """What sealLegacyCredentials() does to the cleartext column."""
    con.execute("UPDATE credentials SET password = NULL")
    con.commit()


def _recoverable(path):
    with open(path, "rb") as fh:
        return len(re.findall(MARKER_RE, fh.read()))


# ── The premise ─────────────────────────────────────────────────────────────

def test_the_premise_cleartext_survives_a_seal_without_a_reclaim():
    # If this ever stops being true, the rest of this file is guarding a problem
    # that no longer exists, and that should be visible rather than assumed.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "v.db")
        con = _seeded_vault(path)
        _seal(con)
        con.close()
        leaked = _recoverable(path)
        assert leaked > 0, (
            "nulling the password column now erases it; this suite's premise is stale"
        )


def test_secure_delete_is_off_by_default():
    # The reason the reclaim is needed at all, and the reason the pragma alone is
    # not a fix: it is per-connection, and the app uses a pool.
    with tempfile.TemporaryDirectory() as d:
        con = sqlite3.connect(os.path.join(d, "s.db"))
        assert con.execute("PRAGMA secure_delete").fetchone()[0] == 0
        con.close()


# ── The guarantee ───────────────────────────────────────────────────────────

def test_a_vacuum_after_sealing_leaves_nothing_recoverable():
    # The whole point. `reclaimVaultPages()` in src/lib/credentialDB.ts runs this
    # whenever anything was sealed.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "v.db")
        con = _seeded_vault(path)
        _seal(con)
        con.execute("VACUUM")
        con.commit()
        con.close()
        leaked = _recoverable(path)
        assert leaked == 0, f"{leaked} cleartext credentials still readable after the reclaim"


def test_migration_012_alone_leaves_the_copied_cleartext_behind():
    # 012 copies `password` into a new table and drops the old one. The dropped
    # table's pages keep their bytes, so the migration is a second source of
    # exposure independent of the sealing step.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "v.db")
        con = _seeded_vault(path)   # 012 has run; nothing sealed yet
        con.close()
        assert _recoverable(path) > SEEDED, (
            "expected two copies of each secret after the INSERT...SELECT"
        )


def test_the_reclaim_is_idempotent():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "v.db")
        con = _seeded_vault(path)
        _seal(con)
        for _ in range(3):
            con.execute("VACUUM")
        con.commit()
        con.close()
        assert _recoverable(path) == 0


# ── The one-time catch-up for databases sealed before the fix ──────────────

def test_vault_meta_records_whether_pages_were_reclaimed():
    # Migration 014. Without this column an install that sealed before the
    # reclaim existed would never be cleaned: its cleartext is in the free pages
    # and it has no `enc_version = 0` rows left to trigger a re-seal.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "v.db")
        con = _seeded_vault(path)
        cols = [r[1] for r in con.execute("PRAGMA table_info(vault_meta)")]
        con.close()
        assert "pages_reclaimed_at" in cols, cols


def test_pages_reclaimed_at_starts_unset():
    # Every existing database genuinely has not been reclaimed, and NULL is how
    # that is recorded. Backfilling it would mark dirty files clean.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "v.db")
        con = _seeded_vault(path)
        con.execute(
            "INSERT OR IGNORE INTO vault_meta"
            " (id, kdf, iterations, salt, verifier_cipher, verifier_iv)"
            " VALUES (1, 'PBKDF2-SHA256', 600000, 'c2FsdA==', 'Y2lwaGVy', 'aXY=')"
        )
        con.commit()
        row = con.execute("SELECT pages_reclaimed_at FROM vault_meta WHERE id = 1").fetchone()
        con.close()
        assert row is not None and row[0] is None


# ── PURGE must erase, not just delete ──────────────────────────────────────

def test_purge_without_a_vacuum_leaves_credentials_readable():
    # `credentials` is in PURGEABLE_TABLES, and a purge is the single most likely
    # moment for an operator to believe the data is gone.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "v.db")
        con = _seeded_vault(path)
        con.execute("DELETE FROM credentials")
        con.commit()
        con.close()
        assert _recoverable(path) > 0, "this suite's premise for the purge path is stale"


def test_purge_with_a_vacuum_leaves_nothing_readable():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "v.db")
        con = _seeded_vault(path)
        con.execute("DELETE FROM credentials")
        con.commit()
        con.execute("VACUUM")
        con.close()
        assert _recoverable(path) == 0


# ── Migration hygiene this file can cheaply confirm ────────────────────────

def test_every_migration_applies_cleanly_in_order():
    with tempfile.TemporaryDirectory() as d:
        con = sqlite3.connect(os.path.join(d, "m.db"))
        con.execute("PRAGMA foreign_keys=ON")
        _apply(con, _migrations())
        assert con.execute("PRAGMA foreign_key_check").fetchall() == []
        con.close()


# ── The second table (migration 017) ────────────────────────────────────────
#
# `cracking_history.cracked_password` holds the WPA passphrase hashcat
# recovered, in cleartext, and sealing the vault never touched it. So the
# banner could report "no unprotected rows" while every cracked passphrase sat
# in the file — the same defect as above, one table over, and the one an
# operator would least expect after setting a passphrase.

CRACK_MARKER = "CRACKED_WPA_%04d_ZZ"
CRACK_MARKER_RE = rb"CRACKED_WPA_[0-9]{4}_ZZ"
CRACKED_SEEDED = 40


def _seeded_cracking_history(path):
    """A database with cracking runs written before migration 017."""
    files = _migrations()
    m017 = next(f for f in files if os.path.basename(f).startswith("017"))
    con = sqlite3.connect(path)
    _apply(con, files[: files.index(m017)])
    for i in range(CRACKED_SEEDED):
        con.execute(
            "INSERT INTO cracking_history"
            " (pcap_file, ssid, wordlist, result, cracked_password,"
            "  passwords_tested, passwords_total, duration_seconds)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (f"cap{i}.pcap", f"NET-{i}", "rockyou.txt", "SUCCESS",
             CRACK_MARKER % i, 1000, 10000, 42),
        )
    # A run that cracked nothing, which must never be counted as unprotected.
    con.execute(
        "INSERT INTO cracking_history"
        " (pcap_file, wordlist, result, cracked_password,"
        "  passwords_tested, passwords_total, duration_seconds)"
        " VALUES (?,?,?,?,?,?,?)",
        ("empty.pcap", "rockyou.txt", "FAILED", None, 10000, 10000, 99),
    )
    con.commit()
    _apply(con, files[files.index(m017):])
    return con


def _cracked_recoverable(path):
    with open(path, "rb") as fh:
        return len(re.findall(CRACK_MARKER_RE, fh.read()))


def test_migration_017_adds_the_columns_without_losing_a_row():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "c.db")
        con = _seeded_cracking_history(path)
        cols = {r[1] for r in con.execute("PRAGMA table_info(cracking_history)")}
        assert {"password_cipher", "password_iv", "enc_version"} <= cols, cols
        n = con.execute("SELECT COUNT(*) FROM cracking_history").fetchone()[0]
        assert n == CRACKED_SEEDED + 1
        con.close()


def test_a_run_that_cracked_nothing_is_not_counted_as_unprotected():
    # Otherwise the banner is permanently alarming for the normal case, and an
    # alarm that is always on is an alarm nobody reads.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "c.db")
        con = _seeded_cracking_history(path)
        unprotected = con.execute(
            "SELECT COUNT(*) FROM cracking_history"
            " WHERE enc_version = 0 AND cracked_password IS NOT NULL"
            "   AND cracked_password <> ''"
        ).fetchone()[0]
        assert unprotected == CRACKED_SEEDED, unprotected
        con.close()


def test_the_premise_a_cracked_passphrase_survives_in_the_file():
    # The measurement this fix was written from. If nulling the column ever
    # erases it, this suite is guarding something that no longer exists.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "c.db")
        con = _seeded_cracking_history(path)
        con.execute("UPDATE cracking_history SET cracked_password = NULL")
        con.commit()
        con.close()
        assert _cracked_recoverable(path) > 0


def test_sealing_the_cracking_history_leaves_nothing_recoverable():
    """What sealLegacyCrackingHistory() does, asserted against the file.

    Ciphertext written, cleartext nulled, then a VACUUM. Without the VACUUM the
    passphrases are still there, which is what made the old banner false.
    """
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "c.db")
        con = _seeded_cracking_history(path)
        rows = con.execute(
            "SELECT id, cracked_password FROM cracking_history WHERE enc_version = 0"
        ).fetchall()
        for row_id, secret in rows:
            # A stand-in for AES-GCM: the test is about what stays in the file,
            # not about the cipher, which the TypeScript vault suite covers.
            con.execute(
                "UPDATE cracking_history"
                "   SET password_cipher = ?, password_iv = ?, enc_version = 1,"
                "       cracked_password = NULL"
                " WHERE id = ?",
                (f"sealed-{row_id}", f"iv-{row_id}", row_id),
            )
        con.commit()
        assert _cracked_recoverable(path) > 0, "still in the free pages before the VACUUM"
        con.execute("VACUUM")
        con.commit()
        con.close()
        assert _cracked_recoverable(path) == 0


def test_deleting_a_cracking_row_without_a_vacuum_leaves_it_readable():
    # Why `deleteCrackingRecord` reclaims rather than leaving it for later:
    # deleting a cracked passphrase is the moment an operator expects it gone.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "c.db")
        con = _seeded_cracking_history(path)
        con.execute("DELETE FROM cracking_history")
        con.commit()
        assert _cracked_recoverable(path) > 0
        con.execute("VACUUM")
        con.commit()
        con.close()
        assert _cracked_recoverable(path) == 0


def test_a_purge_clears_the_cracking_history_table():
    # `cracking_history` is in PURGEABLE_TABLES; this pins that the table it
    # names still exists under that name after 017.
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "c.db")
        con = _seeded_cracking_history(path)
        con.execute("DELETE FROM cracking_history")
        con.commit()
        assert con.execute("SELECT COUNT(*) FROM cracking_history").fetchone()[0] == 0
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
