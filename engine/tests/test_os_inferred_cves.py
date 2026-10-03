"""
Advisories that cannot be matched from a banner, and must not be asserted as if
they were.

SMB and RDP do not publish a patch level, so EternalBlue and BlueKeep can only
be inferred from an operating-system fingerprint plus an open port. That is a
weaker claim than a version match, and the difference has to survive to the
report: a fully patched Windows 7 is not vulnerable to either, and this check
cannot tell the difference.

This knowledge used to live in `IntrusionPage.tsx` as a private table. An
operator saw "CVE-2019-0708 BlueKeep CRITICAL" on screen and the exported report
said nothing about it, because the engine's matcher never produced it. These
tests exist so it stays here, stays flagged, and stays narrow.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.cve_db import (  # noqa: E402
    OS_INFERRED_CVES,
    annotate_host_inferences,
    infer_os_cves,
)


def test_a_legacy_windows_with_smb_open_is_flagged():
    hits = infer_os_cves("Windows 7 / Server 2008 R2", 445)
    assert [h["cve"] for h in hits] == ["CVE-2017-0144"]


def test_a_legacy_windows_with_rdp_open_is_flagged():
    hits = infer_os_cves("Windows XP", 3389)
    assert [h["cve"] for h in hits] == ["CVE-2019-0708"]


def test_a_modern_windows_is_not_flagged():
    assert infer_os_cves("Windows 10/11", 445) == []
    assert infer_os_cves("Windows Server 2019", 3389) == []


def test_a_non_windows_host_is_not_flagged():
    assert infer_os_cves("Linux 5.x", 445) == []
    assert infer_os_cves("FreeBSD", 3389) == []


def test_an_undetermined_os_is_never_flagged():
    # Guessing here would put a CRITICAL advisory against every host whose
    # fingerprint failed, which is the opposite of what an unknown means.
    for value in (None, "", "   ", "Unknown", "unknown device", "UNKNOWN"):
        assert infer_os_cves(value, 445) == [], repr(value)


def test_a_port_with_no_inference_rule_yields_nothing():
    assert infer_os_cves("Windows 7", 22) == []
    assert infer_os_cves("Windows 7", 80) == []


def test_every_hit_is_marked_inferred_and_says_what_it_rests_on():
    # The flag is what the risk rule set reads to report SUSPECTED instead of
    # LIKELY; the basis is what a reader needs to judge it.
    for port in OS_INFERRED_CVES:
        for hit in infer_os_cves("Windows 7", port):
            assert hit["inferred"] is True
            assert hit["inferred_from"] == "Windows 7"
            assert len(hit.get("basis", "")) > 60
            # The property, not a particular word: the basis has to state that a
            # host which took the fix is not affected, because that is the whole
            # limitation of inferring from a fingerprint. MS17-010 says "patched",
            # BlueKeep says "the May 2019 update, or NLA enforced" — both state it.
            assert "not affected" in hit["basis"].lower()


def test_the_os_patterns_do_not_leak_into_the_emitted_entry():
    # `os_patterns` is matching machinery, not a finding field, and it would
    # otherwise travel into the archive and the report payload.
    for hit in infer_os_cves("Windows 7", 445):
        assert "os_patterns" not in hit


def test_the_shared_table_is_never_mutated():
    before = OS_INFERRED_CVES[445][0].copy()
    hit = infer_os_cves("Windows 7", 445)[0]
    hit["severity"] = "MUTATED"
    hit["cve"] = "CVE-0000-0000"
    assert OS_INFERRED_CVES[445][0] == before


def test_annotate_adds_to_the_right_port_only():
    host = {
        "os": "Windows 7",
        "open_ports": [{"port": 445}, {"port": 3389}, {"port": 22}, {"port": 80}],
    }
    annotate_host_inferences(host)
    by_port = {p["port"]: [c["cve"] for c in p.get("cves", [])] for p in host["open_ports"]}
    assert by_port == {
        445: ["CVE-2017-0144"],
        3389: ["CVE-2019-0708"],
        22: [],
        80: [],
    }


def test_annotate_keeps_a_real_banner_match_and_does_not_duplicate_it():
    # A version match is the stronger statement. If the matcher already produced
    # the same advisory, the inference must not be appended beside it.
    host = {
        "os": "Windows 7",
        "open_ports": [{
            "port": 445,
            "cves": [{"cve": "CVE-2017-0144", "severity": "CRITICAL", "version_match": "exact"}],
        }],
    }
    annotate_host_inferences(host)
    cves = host["open_ports"][0]["cves"]
    assert len(cves) == 1
    assert cves[0].get("version_match") == "exact"
    assert "inferred" not in cves[0]


def test_annotate_appends_beside_an_unrelated_banner_match():
    host = {
        "os": "Windows 7",
        "open_ports": [{
            "port": 445,
            "cves": [{"cve": "CVE-2020-1472", "severity": "CRITICAL"}],
        }],
    }
    annotate_host_inferences(host)
    assert [c["cve"] for c in host["open_ports"][0]["cves"]] == ["CVE-2020-1472", "CVE-2017-0144"]


def test_a_udp_port_is_not_inferred_against():
    # The inference is about a reachable SMB or RDP service; the UDP sweep's
    # results are a different observation and 445/UDP is not that service.
    host = {"os": "Windows 7", "open_ports": [{"port": 445, "protocol": "UDP"}]}
    annotate_host_inferences(host)
    assert "cves" not in host["open_ports"][0]


def test_annotate_survives_a_host_with_nothing_in_it():
    for host in ({}, {"os": None}, {"os": "Windows 7", "open_ports": None}, {"open_ports": []}):
        annotate_host_inferences(host)  # must not raise


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
