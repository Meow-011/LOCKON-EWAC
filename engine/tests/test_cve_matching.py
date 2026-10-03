"""Tests for CVE-to-service matching.

    python engine/tests/test_cve_matching.py
    python -m pytest engine/tests/test_cve_matching.py

Why this exists.

`lookup_cves` used to end in a substring test on the version string:

    for known_svc in matrix:
        if known_svc in svc:
            for known_ver in matrix[known_svc]:
                if known_ver in ver:            # <-- this
                    cves.extend(matrix[known_svc][known_ver])

`"5.0" in "6.5.0"` is True, so a current Redis 6.5.0 was asserted vulnerable to
a CVE keyed to 5.0. Four such assertions were confirmed against the shipped seed
list:

    Redis 6.5.0          -> CVE-2022-0543 CRITICAL   (keyed to 5.0)
    Samba 4.6.16         -> CVE-2017-7494 CRITICAL   (fixed in 4.6.4)
    MySQL 5.5.62         -> CVE-2012-2122 HIGH       (fixed in 5.5.24)
    Elasticsearch 6.1.4  -> CVE-2015-1427 CRITICAL   (keyed to 1.4)

Each reached the report's headline CRITICAL+HIGH figure at LIKELY confidence,
with a rationale reading "Matched from the service banner on port N" — wording
that tells the reader a version matched. A manager who has one of these checked
by a sysadmin discards every other number in the document, so the cost of a
false assertion here is the whole report, not one row.

A *missed* CVE is a gap the tool already declares in `coverage_note`: absence of
a CVE is not evidence a host is unaffected. So this matching errs toward
missing, and these tests hold it there.
"""
import contextlib
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.cve_db import (  # noqa: E402
    lookup_cves, active_matrix, _merge_matrix, describe_source, CVE_MATRIX,
    _version_match, _is_fixed,
)


def _ids(results):
    return [c.get("cve") for c in results]


@contextlib.contextmanager
def seed_only():
    """Run with only the hand-curated seed in force, whatever this machine has.

    The tests below derive their cases *from* the matrix and then assert a
    property of the matcher over it. That is only meaningful against data this
    project controls. Against a 41,596-entry NVD pull they assert NVD's internal
    consistency instead, and it does not hold: NVD describes OpenSSH
    CVE-2003-0190 both as a range fixed before 3.6.1 and as exact version 3.6.1
    affected, so "the fixing release is never reported" has a counter-example in
    the data rather than in the code.

    Merged-snapshot behaviour is covered deliberately and separately, further
    down, against synthetic snapshots — so nothing is left unchecked by scoping
    these to the seed. What is gained is that they mean the same thing on every
    machine, which the first run with a real snapshot in force proved they did
    not.
    """
    import cve_feed
    from scanner import cve_db
    original = cve_feed.load_snapshot
    cve_feed.load_snapshot = lambda force=False: None
    cve_db._ACTIVE_CACHE["snapshot"] = None
    try:
        yield
    finally:
        cve_feed.load_snapshot = original
        cve_db._ACTIVE_CACHE["snapshot"] = None


# ── The premise ─────────────────────────────────────────────────────────────

def test_the_matrix_has_data_to_match_against():
    with seed_only():
        # If this fails, every other test here is passing vacuously.
        m = active_matrix()
        assert m, "the CVE matrix is empty"
        assert any(table for table in m.values()), "no service in the matrix has any version keyed"


# ── The bug that motivated this file ────────────────────────────────────────

def test_a_version_that_merely_contains_a_key_never_matches():
    with seed_only():
        # The general shape of the Redis 6.5.0 defect: "9.5.0" contains "5.0" but is
        # not in the 5.0 line. Derived from the live matrix so it cannot rot as the
        # seed list changes.
        m = active_matrix()
        checked = 0
        for svc, table in m.items():
            for key in table:
                probe = "9." + key      # contains `key`, does not start with it
                # Skip any probe some *other* key in this table legitimately claims,
                # by an exact hit or as a line prefix. `"9." + key` is synthetic, and
                # against a large table it collides with real data: a downloaded
                # snapshot gives `apache` 440 version keys including `9.2`, which
                # `9.2.4.49` prefix-matches correctly. Testing only for an exact
                # collision reported that correct match as the substring defect.
                if any(_version_match(probe, other) for other in table):
                    continue
                hits = lookup_cves(svc, probe)
                assert hits == [], (
                    f"{svc} {probe} matched {_ids(hits)} keyed to {key} by substring"
                )
                checked += 1
        assert checked > 0, "no version keys were exercised"


def test_a_later_major_version_is_not_accused_of_an_older_lines_cve():
    with seed_only():
        # The four confirmed false positives, by name. Each asserts its premise
        # first, so a seed-list change shows up as a premise failure rather than as a
        # test that quietly stops checking anything.
        cases = [
            ("redis", "6.5.0", "CVE-2022-0543"),
            ("samba", "4.6.16", "CVE-2017-7494"),
            ("mysql", "5.5.62", "CVE-2012-2122"),
            ("elasticsearch", "6.1.4", "CVE-2015-1427"),
        ]
        m = active_matrix()
        exercised = 0
        for svc, ver, cve in cases:
            keys = [k for k in m if k in svc or svc in k]
            if not keys:
                continue            # that service is not in this matrix build
            exercised += 1
            got = _ids(lookup_cves(svc, ver))
            assert cve not in got, f"{svc} {ver} is still asserted vulnerable to {cve}"
        assert exercised > 0, "none of the four documented cases could be exercised"


# ── What must still match ───────────────────────────────────────────────────

def test_every_exact_version_in_the_matrix_still_matches():
    with seed_only():
        # Removing the substring fallback must not cost a single genuine detection.
        m = active_matrix()
        checked = 0
        for svc, table in m.items():
            for key, entries in table.items():
                if not entries:
                    continue
                hits = lookup_cves(svc, key)
                assert hits, f"{svc} {key} is in the matrix but no longer matches itself"
                checked += 1
        assert checked > 0


def test_an_exact_match_is_labelled_exact():
    """An exact key's own entries are labelled exact.

    A lookup now collects *every* matching key rather than only the most specific
    one, so an exact version can also inherit advisories from the wider line it
    sits in, labelled `version_prefix`. Both appear; what this holds is that the
    label tells the truth about which one it was, because the report prints it.
    """
    with seed_only():
        m = active_matrix()
        svc = next(iter(m))
        key = next(iter(m[svc]))
        hits = lookup_cves(svc, key)
        assert hits, f"{svc} {key} matched nothing"
        for entry in hits:
            assert entry["version_match"] in ("exact", "version_prefix")
        assert any(e["version_match"] == "exact" for e in hits)


def _with_snapshot(matrix):
    """A context manager putting a synthetic snapshot in force."""
    import cve_feed
    from scanner import cve_db

    @contextlib.contextmanager
    def ctx():
        original = cve_feed.load_snapshot
        snap = {"matrix": matrix}
        cve_feed.load_snapshot = lambda force=False: snap
        cve_db._ACTIVE_CACHE["snapshot"] = None
        try:
            yield
        finally:
            cve_feed.load_snapshot = original
            cve_db._ACTIVE_CACHE["snapshot"] = None
    return ctx()


def test_an_exact_version_also_inherits_its_lines_advisories():
    """A narrower key must not shadow a wider one it sits inside.

    Found with real data: `apache` carried CVE-1999-1199 at line `1.3` and a
    separate exact key `1.3.1`. A host reporting 1.3.1 matched only `1.3.1`, so
    the 1.3-line advisory was dropped — a refresh that merely *added* the exact
    key therefore *removed* a finding, which is the one thing the merge exists to
    prevent.
    """
    with _with_snapshot({"apache": {
        "1.3": [{"cve": "CVE-1999-1199", "severity": "HIGH", "description": "line"}],
        "1.3.1": [{"cve": "CVE-2000-1205", "severity": "LOW", "description": "exact"}],
    }}):
        got = {e["cve"]: e["version_match"] for e in lookup_cves("apache", "1.3.1")}
        assert got.get("CVE-1999-1199") == "version_prefix", got
        assert got.get("CVE-2000-1205") == "exact", got


def test_a_fix_bound_governs_every_entry_for_that_cve_in_its_line():
    """NVD contradicts itself, and the safe reading has to win.

    It describes OpenSSH CVE-2003-0190 both as a range fixed before 3.6.1 *and*
    as exact version 3.6.1 affected. Taking the unbounded entry reports a host
    running the release that contains the fix — the class of false assertion that
    discredits every other number in the document.
    """
    matrix = {"openssh": {
        "3.6": [{"cve": "CVE-2003-0190", "severity": "MEDIUM",
                 "description": "range", "fixed_in": "3.6.1"}],
        "3.6.1": [{"cve": "CVE-2003-0190", "severity": "MEDIUM",
                   "description": "exact, unbounded"}],
    }}
    with _with_snapshot(matrix):
        assert "CVE-2003-0190" not in _ids(lookup_cves("openssh", "3.6.1")),             "the fixing release was reported vulnerable to the bug it fixes"
        # A release genuinely before the fix is still reported.
        assert "CVE-2003-0190" in _ids(lookup_cves("openssh", "3.6"))


def test_a_fix_bound_does_not_leak_into_another_line():
    """Scoped to the line, because a flaw often spans lines with a different fix.

    A product-wide rule would apply the 1.0.5 bound to the exact 2.0.3 entry and
    delete a genuine finding — over-correcting the previous test's fix.
    """
    with _with_snapshot({"nginx": {
        "1.0": [{"cve": "CVE-2010-0001", "severity": "HIGH",
                 "description": "old line", "fixed_in": "1.0.5"}],
        "2.0.3": [{"cve": "CVE-2010-0001", "severity": "HIGH",
                   "description": "also affects 2.0.3"}],
    }}):
        assert "CVE-2010-0001" in _ids(lookup_cves("nginx", "2.0.3"))
        assert "CVE-2010-0001" not in _ids(lookup_cves("nginx", "1.0.5"))


def test_a_patch_release_matches_its_line_and_is_labelled_a_prefix():
    with seed_only():
        # A key of "5.0" stands for the 5.0.x line, so 5.0.99 is in it — unless the
        # entry declares the release that fixed it, which is the next test.
        m = active_matrix()
        for svc, table in m.items():
            for key, entries in table.items():
                if not entries or any(e.get("fixed_in") for e in entries):
                    continue
                probe = key + ".99"
                if probe in table:
                    continue
                hits = lookup_cves(svc, probe)
                assert hits, f"{svc} {probe} should fall in the {key} line"
                for entry in hits:
                    assert entry["version_match"] == "version_prefix"
                return
        raise AssertionError("no unbounded service/version pair was available to exercise")


# ── Upper bounds: a patched release inside a keyed line ─────────────────────

def test_a_release_at_or_past_its_fix_is_not_reported():
    with seed_only():
        # A matrix key names a whole line, which is too coarse for any CVE patched
        # within that line. `fixed_in` is the bound; without it Samba 4.6.16 and
        # MySQL 5.5.62 were both asserted vulnerable to bugs they carry the patch for.
        m = active_matrix()
        checked = 0
        for svc, table in m.items():
            for key, entries in table.items():
                for entry in entries:
                    fixed_in = entry.get("fixed_in")
                    if not fixed_in:
                        continue
                    checked += 1
                    got = _ids(lookup_cves(svc, fixed_in))
                    assert entry["cve"] not in got, (
                        f"{svc} {fixed_in} is the fixing release and must not be reported "
                        f"vulnerable to {entry['cve']}"
                    )
                    # And anything after it.
                    later = fixed_in + ".99"
                    assert entry["cve"] not in _ids(lookup_cves(svc, later)), (
                        f"{svc} {later} is past the fix for {entry['cve']}"
                    )
        assert checked > 0, "no entry in the matrix declares a fixing release"


def test_a_release_before_the_fix_is_still_reported():
    with seed_only():
        # The bound must not silence the versions that are genuinely affected.
        m = active_matrix()
        checked = 0
        for svc, table in m.items():
            for key, entries in table.items():
                for entry in entries:
                    fixed_in = entry.get("fixed_in")
                    if not fixed_in:
                        continue
                    parts = fixed_in.split(".")
                    if not parts[-1].isdigit() or int(parts[-1]) == 0:
                        continue
                    earlier = ".".join(parts[:-1] + [str(int(parts[-1]) - 1)])
                    assert entry["cve"] in _ids(lookup_cves(svc, earlier)), (
                        f"{svc} {earlier} is before the fix for {entry['cve']} and must "
                        "still be reported"
                    )
                    checked += 1
        assert checked > 0


def test_a_distribution_suffix_does_not_break_the_comparison():
    # Banners routinely carry one: "4.6.16-Debian", "5.5.62-0ubuntu0.14.04.1".
    m = active_matrix()
    for svc, table in m.items():
        for key, entries in table.items():
            for entry in entries:
                fixed_in = entry.get("fixed_in")
                if not fixed_in:
                    continue
                assert entry["cve"] not in _ids(lookup_cves(svc, fixed_in + "-Debian")), (
                    f"a distribution suffix on {fixed_in} defeated the fixed_in bound"
                )
                return
    raise AssertionError("no bounded entry was available to exercise")


def test_a_digit_glued_onto_a_key_is_a_different_version():
    # "5.09" is not in the "5.0" line, though it starts with those characters.
    # This is what separates a component-aware prefix from a string prefix.
    m = active_matrix()
    for svc, table in m.items():
        for key in table:
            if not table[key] or not key[-1].isdigit():
                continue
            probe = key + "9"
            if probe in table or any(probe.startswith(k + ".") for k in table):
                continue
            assert lookup_cves(svc, probe) == [], (
                f"{svc} {probe} must not match the {key} line"
            )
            return
    raise AssertionError("no suitable version key was available to exercise")


def test_a_banner_that_names_the_service_with_extra_words_still_matches():
    # Banners are not canonical: "apache httpd" and "apache" are one daemon.
    # Service matching stays deliberately loose; only the version is strict.
    m = active_matrix()
    svc = next(iter(m))
    key = next(iter(m[svc]))
    if not m[svc][key]:
        return
    assert lookup_cves(f"{svc} httpd", key), (
        f"a banner naming '{svc}' with extra words should still reach its version table"
    )


# ── Every result states how it was matched ──────────────────────────────────

def test_every_result_records_how_the_version_was_matched():
    with seed_only():
        # Without this a report cannot tell a reader whether a version matched
        # exactly or by line, which is the difference between a fact and an
        # inference.
        m = active_matrix()
        seen = 0
        for svc, table in m.items():
            for key in table:
                for entry in lookup_cves(svc, key):
                    assert entry.get("version_match") in ("exact", "version_prefix"), entry
                    seen += 1
        assert seen > 0


def test_no_result_lists_the_same_cve_twice():
    # Two service keys can point at one advisory; the report must not count it
    # twice in its severity rollup.
    m = active_matrix()
    for svc, table in m.items():
        for key in table:
            ids = _ids(lookup_cves(svc, key))
            assert len(ids) == len(set(ids)), f"{svc} {key} returned duplicates: {ids}"


# ── Absence and isolation ───────────────────────────────────────────────────

def test_a_missing_service_or_version_returns_nothing():
    assert lookup_cves(None, "1.0") == []
    assert lookup_cves("redis", None) == []
    assert lookup_cves("", "") == []
    assert lookup_cves("definitely-not-a-real-daemon", "1.2.3") == []


def test_a_result_is_a_copy_and_never_aliases_the_matrix():
    with seed_only():
        # Up to 100 scan threads annotate these entries. The matrix is module-level
        # global state; handing out references made every emitted finding alias it.
        m = active_matrix()
        svc = next(iter(m))
        key = next(iter(m[svc]))
        first = lookup_cves(svc, key)
        if not first:
            return
        first[0]["cve"] = "MUTATED"
        first[0]["severity"] = "MUTATED"
        second = lookup_cves(svc, key)
        assert second[0]["cve"] != "MUTATED", "lookup_cves handed back a reference into the matrix"
        assert m[svc][key][0].get("version_match") is None, (
            "annotating a result wrote back into the shared matrix"
        )


def test_case_is_not_significant_in_a_banner():
    with seed_only():
        m = active_matrix()
        svc = next(iter(m))
        key = next(iter(m[svc]))
        if not m[svc][key]:
            return
        assert _ids(lookup_cves(svc.upper(), key.upper())) == _ids(lookup_cves(svc, key))


# ---------------------------------------------------------------------------
# A refresh may only ever ADD coverage.
#
# `active_matrix()` used to return a downloaded snapshot *instead of* the seed.
# Measured against a real NVD pull on 2026-10-01, that lost 14 of the seed's 23
# entries, because NVD's version-pinned results simply do not contain them:
#
#     openssl 1.0.1 -> CVE-2014-0160  Heartbleed
#     apache 2.4.49 -> CVE-2021-41773 path traversal -> RCE
#     apache 2.4.50 -> CVE-2021-42013 path traversal -> RCE
#     iis 6.0/7.5   -> CVE-2017-7269  WebDAV RCE
#     redis 5.0     -> CVE-2022-0543  Lua sandbox escape
#     ... and nine more
#
# The pull reported `age_days: 0` and `stale: false` while doing it, so the
# report would have looked *more* authoritative while detecting less. That is
# the exact failure this project is built to prevent, so these tests hold the
# merge in place.
# ---------------------------------------------------------------------------

def _snapshot_without_openssl():
    """A snapshot shaped like NVD's real answer: broad, but missing the seed's."""
    return {
        "nginx": {"1.18.0": [{"cve": "CVE-2021-23017", "severity": "CRITICAL",
                              "description": "Resolver off-by-one."}]},
        "postfix": {"3.4.0": [{"cve": "CVE-2023-51764", "severity": "MEDIUM",
                               "description": "SMTP smuggling."}]},
    }


def test_a_snapshot_never_removes_a_seed_entry():
    merged = _merge_matrix(CVE_MATRIX, _snapshot_without_openssl())
    for product, versions in CVE_MATRIX.items():
        assert product in merged, f"snapshot dropped seed product {product}"
        for version, entries in versions.items():
            assert version in merged[product], f"dropped {product} {version}"
            kept = {e["cve"] for e in merged[product][version]}
            for entry in entries:
                assert entry["cve"] in kept, f"dropped {entry['cve']}"


def test_heartbleed_survives_a_snapshot_that_has_no_openssl():
    """The single most recognisable finding this tool can make."""
    merged = _merge_matrix(CVE_MATRIX, _snapshot_without_openssl())
    assert "CVE-2014-0160" in {e["cve"] for e in merged["openssl"]["1.0.1"]}


def test_merge_adds_what_the_seed_does_not_have():
    merged = _merge_matrix(CVE_MATRIX, _snapshot_without_openssl())
    assert "postfix" in merged
    assert "CVE-2023-51764" in {e["cve"] for e in merged["postfix"]["3.4.0"]}
    assert "CVE-2021-23017" in {e["cve"] for e in merged["nginx"]["1.18.0"]}


def test_the_same_cve_id_is_not_listed_twice():
    """A report that lists one CVE twice is a report nobody trusts the count in."""
    dup = {"openssl": {"1.0.1": [{"cve": "CVE-2014-0160", "severity": "HIGH",
                                 "description": "NVD wording."}]}}
    merged = _merge_matrix(CVE_MATRIX, dup)
    entries = [e for e in merged["openssl"]["1.0.1"] if e["cve"] == "CVE-2014-0160"]
    assert len(entries) == 1
    # The seed's own entry is the one kept: it is hand-curated and keyed to the
    # version string the scanner actually reads off a banner.
    assert entries[0]["severity"] == "CRITICAL"


def test_merge_does_not_mutate_the_seed():
    before = copy.deepcopy(CVE_MATRIX)
    _merge_matrix(CVE_MATRIX, {"openssl": {"1.0.1": [
        {"cve": "CVE-9999-0001", "severity": "LOW", "description": "x"}]}})
    assert CVE_MATRIX == before, "the seed was edited in place"


def test_active_matrix_merges_rather_than_replaces():
    """The integration path, with the snapshot loader standing in for a real pull."""
    import cve_feed
    original = cve_feed.load_snapshot
    cve_feed.load_snapshot = lambda force=False: {
        "matrix": _snapshot_without_openssl()}
    try:
        m = active_matrix()
        assert "CVE-2014-0160" in {e["cve"] for e in m["openssl"]["1.0.1"]}
        assert "postfix" in m
    finally:
        cve_feed.load_snapshot = original


def test_lookup_still_finds_heartbleed_with_a_snapshot_in_force():
    """End to end: what a scan would actually report for an OpenSSL 1.0.1 banner."""
    import cve_feed
    original = cve_feed.load_snapshot
    cve_feed.load_snapshot = lambda force=False: {
        "matrix": _snapshot_without_openssl()}
    try:
        assert "CVE-2014-0160" in _ids(lookup_cves("openssl", "1.0.1"))
    finally:
        cve_feed.load_snapshot = original


def test_every_seed_product_is_updatable():
    """`openssl` and `iis` were in the seed but absent from the update list.

    So the two OpenSSL CVEs and both IIS WebDAV RCEs could never be refreshed,
    no matter how often the operator ran an update.
    """
    from cve_feed import tracked_products
    tracked = set(tracked_products())
    missing = sorted(set(CVE_MATRIX) - tracked)
    assert not missing, f"seed products no update can cover: {missing}"


def test_describe_source_counts_the_merged_set_not_the_snapshot():
    import cve_feed
    original = cve_feed.load_snapshot
    snap = _snapshot_without_openssl()
    cve_feed.load_snapshot = lambda force=False: {
        "matrix": snap, "generated_at": "2026-10-01T00:00:00+00:00",
        "source": "NVD CVE API 2.0", "entry_count": 2,
    }
    try:
        info = describe_source()
        merged = _merge_matrix(CVE_MATRIX, snap)
        expected = sum(len(v) for versions in merged.values() for v in versions.values())
        assert info["entry_count"] == expected, (
            f"reported {info['entry_count']}, in force {expected}")
        assert info["product_count"] == len(merged)
        # Said out loud, because this string is printed in the method appendix.
        assert info["origin"] == "snapshot+seed"
        assert "merged over the built-in seed" in info["source"]
    finally:
        cve_feed.load_snapshot = original


def test_the_merged_matrix_is_not_rebuilt_on_every_lookup():
    """Merging deepcopies the seed; `lookup_cves` is called per service per host.

    Measured at 0.195 s per merge against a 41,596-entry snapshot, so without the
    cache a LAN sweep paid that for every lookup and the matrix-derived tests in
    this file took eleven minutes. Identity is the assertion: a second call must
    hand back the very same object, not an equal one.
    """
    import cve_feed
    from scanner import cve_db
    original = cve_feed.load_snapshot
    snap = {"matrix": _snapshot_without_openssl()}
    cve_feed.load_snapshot = lambda force=False: snap
    cve_db._ACTIVE_CACHE["snapshot"] = None
    try:
        first = active_matrix()
        assert active_matrix() is first, "the merge was recomputed"
    finally:
        cve_feed.load_snapshot = original
        cve_db._ACTIVE_CACHE["snapshot"] = None


def test_a_reloaded_snapshot_invalidates_the_cache():
    """Serving stale CVE data would be worse than being slow, so a new snapshot
    object must rebuild rather than hit."""
    import cve_feed
    from scanner import cve_db
    original = cve_feed.load_snapshot
    cve_db._ACTIVE_CACHE["snapshot"] = None
    try:
        cve_feed.load_snapshot = lambda force=False: {
            "matrix": {"postfix": {"3.4.0": [{"cve": "CVE-1111-1111",
                                             "severity": "LOW", "description": "x"}]}}}
        assert "CVE-1111-1111" in {e["cve"] for e in active_matrix()["postfix"]["3.4.0"]}
        # A different snapshot object, with different contents.
        cve_feed.load_snapshot = lambda force=False: {
            "matrix": {"postfix": {"3.4.0": [{"cve": "CVE-2222-2222",
                                             "severity": "LOW", "description": "y"}]}}}
        ids = {e["cve"] for e in active_matrix()["postfix"]["3.4.0"]}
        assert "CVE-2222-2222" in ids, "a reloaded snapshot was served from cache"
        assert "CVE-1111-1111" not in ids
    finally:
        cve_feed.load_snapshot = original
        cve_db._ACTIVE_CACHE["snapshot"] = None


def test_a_release_letter_orders_within_its_patch_level():
    """OpenSSL numbers patch releases with a letter, and it is not noise.

    Dropping it made `1.0.1g` compare equal to `1.0.1`, so a host on 1.0.1f was
    read as sitting at the fixing release and **Heartbleed went unreported** —
    the single most recognisable finding this tool can make.
    """
    from scanner.cve_db import _version_tuple as vt
    assert vt("1.0.1") < vt("1.0.1a") < vt("1.0.1f") < vt("1.0.1g") < vt("1.0.2")
    assert _is_fixed("1.0.1g", "1.0.1g") is True
    assert _is_fixed("1.0.1f", "1.0.1g") is False, "a vulnerable release read as patched"


def test_a_packaging_suffix_is_still_noise():
    """The opposite case, and the reason the letter rule has to be narrow.

    `4.6.16-Debian` is upstream 4.6.16 with a distribution tag; treating the tag
    as a release ordinal would put it above 4.6.16 and un-exclude a patched host.
    """
    from scanner.cve_db import _version_tuple as vt
    assert vt("4.6.16-Debian") == vt("4.6.16")
    assert _is_fixed("4.6.16-Debian", "4.6.4") is True
    for noisy in ("1.2.3+deb11u1", "1.2.3~rc1", "1.2.3-1ubuntu2"):
        assert vt(noisy) == vt("1.2.3"), noisy


def test_a_seed_entry_is_immune_to_a_downloaded_fix_bound():
    """The seed is a floor, and the absence of a `fixed_in` on it is deliberate.

    Found the hard way: NVD carries Heartbleed as a range over line `1.0` fixed in
    `1.0.1g`. Applying that bound to the seed's own `openssl 1.0.1` entry made
    CVE-2014-0160 stop being reported altogether — a downloaded bound deleting the
    most famous curated finding in the file.
    """
    with _with_snapshot({"openssl": {
        "1.0": [{"cve": "CVE-2014-0160", "severity": "CRITICAL",
                 "description": "range", "fixed_in": "1.0.1g"}],
    }}):
        assert "CVE-2014-0160" in _ids(lookup_cves("openssl", "1.0.1")),             "a snapshot bound was applied to the seed's own entry"
        # The snapshot's own entry still carries its bound, so a patched host in
        # that line is still excluded.
        assert "CVE-2014-0160" not in _ids(lookup_cves("openssl", "1.0.1g"))


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
