"""Tests for evidence integrity and CVE provenance.

    python engine/tests/test_evidence_and_cve.py
    python -m pytest engine/tests/test_evidence_and_cve.py

Both of these exist so a report can be trusted: the digest is what lets someone
show a capture file is unaltered, and the snapshot age is what lets a reader
judge how much a CVE finding is worth. Nothing here touches the network.
"""
import contextlib
import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cve_feed  # noqa: E402
import evidence  # noqa: E402


# ── evidence ────────────────────────────────────────────────────────────────

def test_sha256_matches_hashlib():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "capture.pcap")
        payload = b"\xd4\xc3\xb2\xa1" + os.urandom(4096)
        with open(path, "wb") as f:
            f.write(payload)
        assert evidence.sha256_file(path) == hashlib.sha256(payload).hexdigest()


def test_sha256_streams_large_files():
    """Digest must not depend on reading the file in one go."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "big.pcap")
        chunk = os.urandom(1024 * 512)
        with open(path, "wb") as f:
            for _ in range(5):
                f.write(chunk)
        assert evidence.sha256_file(path) == hashlib.sha256(chunk * 5).hexdigest()


def test_register_produces_a_verifiable_record():
    events = []
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "handshake.pcap")
        with open(path, "wb") as f:
            f.write(b"frames")
        rec = evidence.register(path, "handshake_pcap",
                                emit=lambda e, p: events.append((e, p)),
                                bssid="AA:BB:CC:DD:EE:FF")
        assert rec["sha256"] == hashlib.sha256(b"frames").hexdigest()
        assert rec["size_bytes"] == 6
        assert rec["kind"] == "handshake_pcap"
        assert rec["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert rec["error"] is None
        assert events and events[0][0] == "evidence_recorded"


def test_register_never_raises_on_a_missing_file():
    """A failed hash must not lose a capture that succeeded."""
    rec = evidence.register("/nonexistent/nope.pcap", "handshake_pcap")
    assert rec["sha256"] is None
    assert rec["error"], "the failure has to be visible, not silent"


def test_verify_detects_tampering():
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "evidence.pcap")
        with open(path, "wb") as f:
            f.write(b"original")
        digest = evidence.sha256_file(path)

        assert evidence.verify(path, digest)["matches"] is True

        with open(path, "wb") as f:
            f.write(b"tampered")
        result = evidence.verify(path, digest)
        assert result["matches"] is False
        assert result["actual"] != digest


def test_verify_reports_a_missing_artifact():
    result = evidence.verify("/nonexistent/gone.pcap", "abc")
    assert result["exists"] is False
    assert result["matches"] is False
    assert result["error"]


def test_safe_name_cannot_escape_the_directory():
    for hostile in ("../../etc/passwd", r"..\..\windows\system32", "a/b/c", "C:/Windows/win.ini"):
        cleaned = evidence.safe_name(hostile)
        assert "/" not in cleaned and "\\" not in cleaned and ".." not in cleaned, cleaned


def test_build_path_stays_inside_the_evidence_dir():
    path = evidence.build_path("handshake", "../../escape", ".pcap")
    assert os.path.dirname(os.path.abspath(path)) == os.path.abspath(evidence.evidence_dir())


# ── CVE provenance ──────────────────────────────────────────────────────────

@contextlib.contextmanager
def no_snapshot():
    """Run with no downloaded snapshot in force, whatever this machine has.

    `describe()` reads the real `_data_dir()`, so a test asserting the *builtin*
    branch passes only on a machine where nobody has ever run a successful CVE
    update. Two tests below did exactly that, and they went red the first time a
    snapshot actually landed in `%LOCALAPPDATA%` — a failure that says nothing
    about the code under test. An empty temp directory makes the premise
    explicit instead of inherited from the environment.
    """
    original = cve_feed._data_dir
    cached = cve_feed._snapshot_cache
    with tempfile.TemporaryDirectory() as d:
        cve_feed._data_dir = lambda: d
        cve_feed._snapshot_cache = None
        try:
            yield
        finally:
            cve_feed._data_dir = original
            cve_feed._snapshot_cache = cached


def test_age_and_staleness_are_computed_from_the_snapshot_date():
    with no_snapshot():
        fresh = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        info = cve_feed.describe(seed_entry_count=10, seed_generated_at=fresh)
        assert info["age_days"] == 3
        assert info["stale"] is False

        old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        info = cve_feed.describe(seed_entry_count=10, seed_generated_at=old)
        assert info["age_days"] == 400
        assert info["stale"] is True


def test_unknown_date_is_treated_as_stale():
    """Failing closed: data of unknown vintage must not read as current."""
    with no_snapshot():
        info = cve_feed.describe(seed_entry_count=10, seed_generated_at=None)
        assert info["age_days"] is None
        assert info["stale"] is True


def test_description_always_states_its_coverage_limits():
    info = cve_feed.describe(seed_entry_count=10, seed_generated_at=None)
    assert info["coverage_note"]
    # The report must never be able to imply full NVD coverage.
    assert "not evidence" in info["coverage_note"].lower()


def test_save_and_load_roundtrip(monkeypatch=None):
    """A saved snapshot takes precedence over the seed and reports its own date."""
    with tempfile.TemporaryDirectory() as d:
        original = cve_feed._data_dir
        cve_feed._data_dir = lambda: d
        cve_feed._snapshot_cache = None
        try:
            matrix = {"apache": {"2.4.49": [{"cve": "CVE-2021-41773", "severity": "CRITICAL", "description": "x"}]}}
            info = cve_feed.save_snapshot(matrix, source="unit-test")
            assert info["origin"] == "snapshot"
            assert info["entry_count"] == 1
            assert info["stale"] is False  # just generated

            cve_feed._snapshot_cache = None
            loaded = cve_feed.load_snapshot(force=True)
            assert loaded["matrix"] == matrix
            assert loaded["source"] == "unit-test"
        finally:
            cve_feed._data_dir = original
            cve_feed._snapshot_cache = None


def test_corrupt_snapshot_degrades_to_the_seed():
    """A broken file must not take the engine down at import time."""
    with tempfile.TemporaryDirectory() as d:
        original = cve_feed._data_dir
        cve_feed._data_dir = lambda: d
        cve_feed._snapshot_cache = None
        try:
            with open(os.path.join(d, "cve_snapshot.json"), "w", encoding="utf-8") as f:
                f.write("{ this is not json")
            assert cve_feed.load_snapshot(force=True) is None
            info = cve_feed.describe(seed_entry_count=27, seed_generated_at="2023-12-31T00:00:00+00:00")
            assert info["origin"] == "builtin"
            assert info["entry_count"] == 27
        finally:
            cve_feed._data_dir = original
            cve_feed._snapshot_cache = None


def test_snapshot_missing_matrix_is_rejected():
    with tempfile.TemporaryDirectory() as d:
        original = cve_feed._data_dir
        cve_feed._data_dir = lambda: d
        cve_feed._snapshot_cache = None
        try:
            with open(os.path.join(d, "cve_snapshot.json"), "w", encoding="utf-8") as f:
                json.dump({"schema": 1, "generated_at": "2026-01-01T00:00:00+00:00"}, f)
            assert cve_feed.load_snapshot(force=True) is None
        finally:
            cve_feed._data_dir = original
            cve_feed._snapshot_cache = None


def test_lookup_returns_copies_not_shared_state():
    """The matrix is read by up to 100 scan threads; findings must not alias it."""
    from scanner.cve_db import lookup_cves, CVE_MATRIX
    first = lookup_cves("apache", "2.4.49")
    assert first, "expected a seeded match"
    first[0]["description"] = "MUTATED BY CALLER"
    first[0]["injected"] = True

    second = lookup_cves("apache", "2.4.49")
    assert second[0]["description"] != "MUTATED BY CALLER"
    assert "injected" not in second[0]
    # And the module-level matrix itself is untouched.
    assert all("injected" not in e for v in CVE_MATRIX["apache"].values() for e in v)


# ── NVD extraction ──────────────────────────────────────────────────────────
#
# The pull used to ask NVD for `keywordSearch=apache` and file every version
# literal it found under `apache`, without checking the CPE described Apache. It
# produced, against the real API:
#
#     apache 2.4.6  -> CVE-2004-0700  "mod_ssl before 2.8.19"
#     apache 2.4.29 -> CVE-2004-0492  "mod_proxy in Apache 1.3.25 to 1.3.31"
#
# and a cPanel advisory filed under `apache`. 2.4.6 is stock RHEL/CentOS 7, so
# that is a false HIGH in an ordinary report. These tests run against recorded
# payload shapes, with no network.

APACHE = {"apache:http_server"}


def _cve(cve_id, nodes, severity="HIGH", text="A described flaw."):
    return {"cve": {
        "id": cve_id,
        "descriptions": [{"lang": "en", "value": text}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseSeverity": severity}}]},
        "configurations": [{"nodes": nodes}],
    }}


def _match(criteria, vulnerable=True, **bounds):
    m = {"criteria": criteria, "vulnerable": vulnerable}
    m.update(bounds)
    return m


def test_a_cpe_for_another_product_is_ignored():
    """The whole defect in one assertion: NVD returns a CVE when *any* of its
    configurations matches, and the others describe different software."""
    item = _cve("CVE-2004-0490", [{"cpeMatch": [
        _match("cpe:2.3:a:cpanel:cpanel:9.1.0_r85:*:*:*:*:*:*:*"),
    ]}])
    assert cve_feed.entries_from_cve(item, APACHE) == []


def test_only_the_asked_for_product_is_kept_from_a_mixed_cve():
    item = _cve("CVE-2021-41773", [{"cpeMatch": [
        _match("cpe:2.3:a:cpanel:cpanel:9.2:*:*:*:*:*:*:*"),
        _match("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
    ]}])
    got = cve_feed.entries_from_cve(item, APACHE)
    assert [k for k, _ in got] == ["2.4.49"]


def test_a_concrete_cpe_version_becomes_an_exact_key():
    item = _cve("CVE-2021-41773", [{"cpeMatch": [
        _match("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
    ]}])
    (key, entry), = cve_feed.entries_from_cve(item, APACHE)
    assert key == "2.4.49"
    assert "fixed_in" not in entry      # an exact version needs no upper bound
    assert entry["severity"] == "HIGH"


def test_a_range_becomes_a_line_key_with_a_fixed_in():
    item = _cve("CVE-2022-31813", [{"cpeMatch": [
        _match("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
               versionStartIncluding="2.4.0", versionEndExcluding="2.4.54"),
    ]}])
    (key, entry), = cve_feed.entries_from_cve(item, APACHE)
    assert key == "2.4"
    assert entry["fixed_in"] == "2.4.54"


def test_an_inclusive_upper_bound_is_converted_exactly():
    """`<= 2.4.53` and `fixed_in` are different claims; one bump reconciles them."""
    item = _cve("CVE-2022-0001", [{"cpeMatch": [
        _match("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
               versionStartIncluding="2.4.0", versionEndIncluding="2.4.53"),
    ]}])
    (_, entry), = cve_feed.entries_from_cve(item, APACHE)
    assert entry["fixed_in"] == "2.4.54"


def test_a_range_with_no_lower_bound_is_skipped():
    """"Everything before 1.21.0" spans an unknown number of lines.

    Anchoring such a range on its *upper* bound produced an entry that excluded
    its own line: nginx came back keyed to `1.21` with `fixed_in: 1.21.0`, so
    every 1.21.x host was already "fixed" and the key existed only to shadow
    others. Skipping errs toward missing, which `coverage_note` declares.
    """
    item = _cve("CVE-2021-3618", [{"cpeMatch": [
        _match("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
               versionEndExcluding="1.21.0"),
    ]}])
    assert cve_feed.entries_from_cve(item, APACHE) == []


def test_a_range_with_only_a_lower_bound_keeps_no_upper_bound():
    """An unfixed flaw: affected from here on, with nothing to exclude."""
    item = _cve("CVE-2024-0001", [{"cpeMatch": [
        _match("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
               versionStartIncluding="2.4.50"),
    ]}])
    (key, entry), = cve_feed.entries_from_cve(item, APACHE)
    assert key == "2.4"
    assert "fixed_in" not in entry


def test_an_unbounded_product_wide_match_is_skipped():
    """Affecting "all versions" cannot be pinned to a build, so it is not a
    finding anyone could check. The old code skipped these too — correctly."""
    item = _cve("CVE-2020-0000", [{"cpeMatch": [
        _match("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
    ]}])
    assert cve_feed.entries_from_cve(item, APACHE) == []


def test_a_non_vulnerable_match_is_not_an_assertion():
    """`vulnerable: false` names the platform a flaw runs *on*, not the flaw."""
    item = _cve("CVE-2020-0001", [{"cpeMatch": [
        _match("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", vulnerable=False),
    ]}])
    assert cve_feed.entries_from_cve(item, APACHE) == []


def test_the_recorded_false_positives_cannot_come_back():
    """The two measured against the live API, by name."""
    mod_ssl = _cve("CVE-2004-0700", [{"cpeMatch": [
        _match("cpe:2.3:a:modssl:mod_ssl:2.8.18:*:*:*:*:*:*:*"),
    ]}])
    mod_proxy = _cve("CVE-2004-0492", [{"cpeMatch": [
        _match("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
               versionStartIncluding="1.3.25", versionEndIncluding="1.3.31"),
    ]}])
    assert cve_feed.entries_from_cve(mod_ssl, APACHE) == [], "mod_ssl is not httpd"
    # This one *is* an httpd advisory, so it is kept — but keyed to 1.3, which is
    # where it belongs, so a 2.4.29 host never matches it.
    keys = [k for k, _ in cve_feed.entries_from_cve(mod_proxy, APACHE)]
    assert keys == ["1.3"], keys


def test_severity_prefers_the_newest_metric():
    item = {"cve": {
        "id": "CVE-2021-0001",
        "descriptions": [{"lang": "en", "value": "x"}],
        "metrics": {
            "cvssMetricV2": [{"baseSeverity": "LOW"}],
            "cvssMetricV31": [{"cvssData": {"baseSeverity": "CRITICAL"}}],
        },
        "configurations": [{"nodes": [{"cpeMatch": [
            _match("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")]}]}],
    }}
    (_, entry), = cve_feed.entries_from_cve(item, APACHE)
    assert entry["severity"] == "CRITICAL"


def test_every_product_an_update_pulls_has_a_cpe_name():
    """A product with no CPE name silently returns nothing, which reads as "no
    known vulnerabilities" — the failure mode that looks like success."""
    missing = [p for p in cve_feed.tracked_products()
               if p not in cve_feed._CPE_PRODUCTS]
    assert not missing, f"tracked products with no CPE mapping: {missing}"


def test_what_the_pull_could_not_establish_reaches_the_report():
    with no_snapshot():
        matrix = {"apache": {"2.4.49": [{"cve": "CVE-2021-41773",
                                         "severity": "CRITICAL", "description": "x"}]}}
        info = cve_feed.save_snapshot(
            matrix, source="unit-test",
            empty_products=["exim"], unmapped_products=["lighttpd"],
            truncated_cpes=["apache:http_server"])
        assert info["empty_products"] == ["exim"]
        assert info["unmapped_products"] == ["lighttpd"]
        # The coverage note is what the PDF prints, so the gap has to be in it.
        assert "exim" in info["coverage_note"]
        assert "lighttpd" in info["coverage_note"]
        assert "partial" in info["coverage_note"]


def _main():
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in tests:
        try:
            fn(); print(f"  PASS  {name}")
        except AssertionError as e:
            failed.append(name); print(f"  FAIL  {name}: {e or 'assertion failed'}")
        except Exception as e:
            failed.append(name); print(f"  ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
