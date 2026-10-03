"""Tests for rogue AP / evil twin scoring.

    python engine/tests/test_evil_twin.py
    python -m pytest engine/tests/test_evil_twin.py

The false-positive tests matter more than the detection tests. The heuristic this
replaced would have labelled any WPA3 transition deployment an evil twin, which
in a report handed to the organisation running that deployment is a false
accusation. Those cases are locked down first.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.evil_twin import analyze, describe_methodology  # noqa: E402


def ap(bssid, ssid, encryption="WPA2", vendor="Cisco", channel=6, rssi=-60):
    return {"bssid": bssid, "ssid": ssid, "encryption": encryption,
            "vendor": vendor, "channel": channel, "rssi": rssi}


# ── must NOT fire ───────────────────────────────────────────────────────────

def test_wpa3_transition_mode_is_not_an_evil_twin():
    """The exact false positive the previous heuristic guaranteed."""
    aps = [
        ap("AA:BB:CC:00:00:01", "CORP-WIFI", "WPA2", "Cisco", 1),
        ap("AA:BB:CC:00:00:02", "CORP-WIFI", "WPA3", "Cisco", 6),
    ]
    r = analyze(aps)
    assert all(not v["is_evil_twin"] for v in r.values()), r
    assert all(v["verdict"] == "CLEAR" for v in r.values()), r


def test_legacy_mixed_mode_is_not_an_evil_twin():
    aps = [
        ap("AA:BB:CC:00:00:01", "OFFICE", "WPA", "Aruba", 1),
        ap("AA:BB:CC:00:00:02", "OFFICE", "WPA2", "Aruba", 11),
    ]
    r = analyze(aps)
    assert all(not v["is_evil_twin"] for v in r.values()), r


def test_same_ssid_same_vendor_many_aps_is_a_normal_deployment():
    """A corporate estate: one SSID, many APs, same vendor, spaced channels."""
    aps = [ap(f"AA:BB:CC:00:00:0{i}", "CAMPUS", "WPA2", "Ubiquiti", ch, -55)
           for i, ch in enumerate([1, 6, 11, 1, 6], start=1)]
    r = analyze(aps)
    assert all(not v["is_evil_twin"] for v in r.values()), r


def test_single_ap_never_flagged():
    r = analyze([ap("AA:BB:CC:00:00:01", "HOME", "WPA2")])
    v = r["AA:BB:CC:00:00:01"]
    assert v["verdict"] == "CLEAR" and v["score"] == 0


def test_hidden_and_blank_ssids_are_not_grouped():
    aps = [
        ap("AA:BB:CC:00:00:01", "", "WPA2", "Cisco"),
        ap("AA:BB:CC:00:00:02", "", "OPEN", "TP-Link"),
        ap("AA:BB:CC:00:00:03", "<Hidden>", "OPEN", "Netgear"),
    ]
    r = analyze(aps)
    assert all(not v["is_evil_twin"] for v in r.values()), r


def test_different_ssids_are_never_peers():
    aps = [
        ap("AA:BB:CC:00:00:01", "NET-A", "WPA2", "Cisco"),
        ap("AA:BB:CC:00:00:02", "NET-B", "OPEN", "TP-Link"),
    ]
    r = analyze(aps)
    assert all(v["peers"] == [] for v in r.values())
    assert all(not v["is_evil_twin"] for v in r.values())


# ── must fire ───────────────────────────────────────────────────────────────

def test_open_clone_of_a_secured_network_is_flagged():
    """Classic captive/karma setup — and only the open one is accused."""
    aps = [
        ap("AA:BB:CC:00:00:01", "CORP-WIFI", "WPA2", "Cisco", 1, -70),
        ap("11:22:33:00:00:99", "CORP-WIFI", "OPEN", "Espressif", 1, -40),
    ]
    r = analyze(aps)
    rogue = r["11:22:33:00:00:99"]
    legit = r["AA:BB:CC:00:00:01"]

    assert rogue["is_evil_twin"] is True, rogue
    assert rogue["verdict"] in ("LIKELY", "CONFIRMED"), rogue
    assert legit["is_evil_twin"] is False, "the legitimate AP must not be accused"
    codes = {i["code"] for i in rogue["indicators"]}
    assert "open_clone_of_secured" in codes


def test_vendor_mismatch_clone_is_detected():
    """The attack the old encryption-only rule could not see at all."""
    aps = [
        ap("AA:BB:CC:00:00:01", "GUEST-NET", "WPA2", "Cisco", 6, -65),
        ap("11:22:33:00:00:01", "GUEST-NET", "WPA2", "Espressif", 6, -35),
    ]
    r = analyze(aps)
    suspect = r["11:22:33:00:00:01"]
    codes = {i["code"] for i in suspect["indicators"]}
    assert "vendor_mismatch" in codes, suspect
    assert suspect["verdict"] != "CLEAR", suspect


def test_encryption_downgrade_is_flagged():
    aps = [
        ap("AA:BB:CC:00:00:01", "SECURE-NET", "WPA3", "Cisco", 36),
        ap("11:22:33:00:00:01", "SECURE-NET", "WEP", "Realtek", 36),
    ]
    r = analyze(aps)
    codes = {i["code"] for i in r["11:22:33:00:00:01"]["indicators"]}
    assert "encryption_downgrade" in codes


def test_spoofed_mac_contributes():
    # 0x02 second nibble => locally administered
    aps = [
        ap("AA:BB:CC:00:00:01", "CORP", "WPA2", "Cisco", 1, -65),
        ap("02:11:22:33:44:55", "CORP", "WPA2", "Unknown", 1, -60),
    ]
    r = analyze(aps)
    codes = {i["code"] for i in r["02:11:22:33:44:55"]["indicators"]}
    assert "oui_randomized" in codes


def test_signal_outlier_contributes():
    aps = [
        ap("AA:BB:CC:00:00:01", "CORP", "WPA2", "Cisco", 1, -80),
        ap("AA:BB:CC:00:00:02", "CORP", "WPA2", "Cisco", 6, -78),
        ap("11:22:33:00:00:01", "CORP", "WPA2", "Espressif", 11, -30),
    ]
    r = analyze(aps)
    codes = {i["code"] for i in r["11:22:33:00:00:01"]["indicators"]}
    assert "signal_outlier" in codes


# ── reporting contract ──────────────────────────────────────────────────────

def test_every_finding_carries_a_human_readable_reason():
    """A severity with no stated reason is not usable as evidence."""
    aps = [
        ap("AA:BB:CC:00:00:01", "CORP-WIFI", "WPA2", "Cisco", 1, -70),
        ap("11:22:33:00:00:99", "CORP-WIFI", "OPEN", "Espressif", 1, -40),
    ]
    r = analyze(aps)
    for entry in r.values():
        for indicator in entry["indicators"]:
            assert indicator["detail"], "indicator without an explanation"
            assert indicator["weight"] > 0
            assert indicator["code"]


def test_score_equals_sum_of_indicator_weights():
    aps = [
        ap("AA:BB:CC:00:00:01", "CORP", "WPA2", "Cisco", 1, -70),
        ap("02:11:22:33:44:55", "CORP", "OPEN", "Espressif", 1, -35),
    ]
    r = analyze(aps)
    for entry in r.values():
        assert entry["score"] == sum(i["weight"] for i in entry["indicators"])


def test_weak_evidence_stays_suspected_not_confirmed():
    """One mild indicator must not produce a confident accusation."""
    aps = [
        ap("AA:BB:CC:00:00:01", "CORP", "WPA2", "Cisco", 6, -60),
        ap("02:BB:CC:00:00:02", "CORP", "WPA2", "Cisco", 6, -58),
    ]
    r = analyze(aps)
    for entry in r.values():
        assert entry["verdict"] in ("CLEAR", "SUSPECTED"), entry


def test_methodology_is_self_describing():
    m = describe_methodology()
    assert m["reported_as_evil_twin_at"] == "LIKELY"
    assert m["thresholds"]["LIKELY"] < m["thresholds"]["CONFIRMED"]
    assert m["limitations"], "the report needs the limitations stated"
    assert any("transition" in s.lower() for s in m["limitations"])


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
