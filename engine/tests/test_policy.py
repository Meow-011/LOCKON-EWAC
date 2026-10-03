"""Tests for the engagement scope gate.

Runnable two ways, so it works with or without pytest installed:
    python engine/tests/test_policy.py
    python -m pytest engine/tests/test_policy.py

This is the one module in the engine where a silent regression is a legal
problem rather than a bug, so the deny paths are tested as carefully as the
allow paths.
"""
import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from policy import ScopePolicy, normalize_mac, GATED_COMMANDS  # noqa: E402


class Recorder:
    """Collects emitted events so assertions can inspect them."""

    def __init__(self):
        self.events = []

    def __call__(self, event, data=None):
        self.events.append((event, data or {}))

    def names(self):
        return [e for e, _ in self.events]

    def of(self, name):
        return [d for e, d in self.events if e == name]

    def reset(self):
        self.events = []


def make_policy(**overrides):
    rec = Recorder()
    policy = ScopePolicy(rec)
    scope = {
        "scope_id": 1,
        "engagement_name": "HQ Floor 3 Audit",
        "authorized_by": "IT Manager",
        "operator": "operator-a",
        "mode": "ALLOWLIST",
        "targets": [
            {"kind": "BSSID", "value": "AA:BB:CC:DD:EE:FF"},
            {"kind": "SSID", "value": "CORP-WIFI"},
            {"kind": "IP", "value": "192.168.1.10"},
            {"kind": "CIDR", "value": "192.168.1.0/24"},
        ],
    }
    scope.update(overrides)
    policy.load(scope)
    rec.reset()
    return policy, rec


# ── default posture ─────────────────────────────────────────────────────────

def test_denies_everything_before_a_scope_is_loaded():
    rec = Recorder()
    policy = ScopePolicy(rec)
    assert policy.authorize("start_strike", [("bssid", "AA:BB:CC:DD:EE:FF")]) is False
    assert "scope_denied" in rec.names()
    assert rec.of("audit_event")[0]["decision"] == "BLOCKED"


def test_ungated_commands_pass_without_a_scope():
    rec = Recorder()
    policy = ScopePolicy(rec)
    # Passive listening and local queries are not gated and must not be
    # blocked by the absence of an engagement.
    for cmd in ("start_passive", "start_probe_monitor", "get_status", "start_scan"):
        assert cmd not in GATED_COMMANDS
        assert policy.authorize(cmd, [("bssid", "AA:BB:CC:DD:EE:FF")]) is True
    assert rec.names() == []


def test_clearing_the_scope_returns_to_deny():
    policy, rec = make_policy()
    assert policy.authorize("start_strike", [("bssid", "AA:BB:CC:DD:EE:FF")]) is True
    policy.load({})
    assert policy.loaded is False
    assert policy.authorize("start_strike", [("bssid", "AA:BB:CC:DD:EE:FF")]) is False


# ── matching ────────────────────────────────────────────────────────────────

def test_bssid_match_ignores_separators_and_case():
    policy, _ = make_policy()
    for variant in ("AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabbccddeeff", "AA.BB.CC.DD.EE.FF"):
        assert policy.authorize("start_strike", [("bssid", variant)]) is True


def test_bssid_outside_the_allowlist_is_refused():
    policy, rec = make_policy()
    assert policy.authorize("start_strike", [("bssid", "11:22:33:44:55:66")]) is False
    denied = rec.of("scope_denied")[0]
    assert denied["target"] == "11:22:33:44:55:66"
    assert "not in the engagement allowlist" in denied["reason"]


def test_ip_inside_an_allowlisted_cidr_passes():
    policy, _ = make_policy()
    assert policy.authorize("start_bruteforce", [("ip", "192.168.1.55")]) is True


def test_ip_outside_every_range_is_refused():
    policy, _ = make_policy()
    assert policy.authorize("start_bruteforce", [("ip", "10.0.0.5")]) is False


def test_a_requested_subnet_must_be_a_subset_not_merely_overlapping():
    policy, _ = make_policy()
    assert policy.authorize("start_mitm", [("cidr", "192.168.1.0/25")]) is True
    # The classic mistake: allowing 10.0.0.0/8 because 192.168.1.0/24 overlaps
    # something inside it. A supernet must never pass on a subnet's authority.
    assert policy.authorize("start_mitm", [("cidr", "192.168.0.0/16")]) is False
    assert policy.authorize("start_mitm", [("cidr", "0.0.0.0/0")]) is False


def test_malformed_targets_are_refused_not_ignored():
    policy, _ = make_policy()
    assert policy.authorize("start_bruteforce", [("ip", "not-an-ip")]) is False
    assert policy.authorize("start_mitm", [("cidr", "192.168.1.0/99")]) is False


def test_every_target_must_pass_not_just_the_first():
    policy, _ = make_policy()
    # A MITM authorized for the victim but not the gateway is still out of scope.
    assert policy.authorize("start_mitm", [("ip", "192.168.1.10"), ("ip", "8.8.8.8")]) is False
    assert policy.authorize("start_mitm", [("ip", "192.168.1.10"), ("ip", "192.168.1.1")]) is True


def test_a_command_with_no_identifiable_target_is_refused():
    policy, rec = make_policy()
    assert policy.authorize("start_strike", []) is False
    assert "cannot be checked" in rec.of("scope_denied")[0]["reason"]


# ── expiry ──────────────────────────────────────────────────────────────────

def test_an_expired_engagement_blocks_everything():
    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
    policy, rec = make_policy(valid_until=yesterday)
    assert policy.authorize("start_strike", [("bssid", "AA:BB:CC:DD:EE:FF")]) is False
    assert "expired" in rec.of("scope_denied")[0]["reason"]


def test_a_future_expiry_still_allows():
    tomorrow = (datetime.now() + timedelta(days=1)).isoformat()
    policy, _ = make_policy(valid_until=tomorrow)
    assert policy.authorize("start_strike", [("bssid", "AA:BB:CC:DD:EE:FF")]) is True


def test_an_unparseable_expiry_fails_closed():
    policy, _ = make_policy(valid_until="next tuesday, probably")
    assert policy.authorize("start_strike", [("bssid", "AA:BB:CC:DD:EE:FF")]) is False


# ── unrestricted mode ───────────────────────────────────────────────────────

def test_unrestricted_mode_allows_but_still_audits():
    policy, rec = make_policy(mode="UNRESTRICTED", targets=[])
    assert policy.authorize("start_mitm", [("ip", "10.1.2.3")]) is True
    audits = rec.of("audit_event")
    assert len(audits) == 1
    assert audits[0]["decision"] == "ALLOWED"
    assert "UNRESTRICTED" in audits[0]["reason"]


def test_unrestricted_mode_is_still_bound_by_expiry():
    yesterday = (datetime.now() - timedelta(days=1)).isoformat()
    policy, _ = make_policy(mode="UNRESTRICTED", targets=[], valid_until=yesterday)
    assert policy.authorize("start_mitm", [("ip", "10.1.2.3")]) is False


# ── auto-attack fan-out ─────────────────────────────────────────────────────

def test_filter_bssids_keeps_only_in_scope_aps_and_logs_the_rest():
    policy, rec = make_policy()
    aps = [
        {"bssid": "AA:BB:CC:DD:EE:FF", "ssid": "HQ-AP"},
        {"bssid": "11:22:33:44:55:66", "ssid": "NEIGHBOUR-WIFI"},
        {"bssid": "99:88:77:66:55:44", "ssid": "CORP-WIFI"},  # in scope via SSID
    ]
    allowed = policy.filter_bssids("auto_attack", aps)
    assert [a["bssid"] for a in allowed] == ["AA:BB:CC:DD:EE:FF", "99:88:77:66:55:44"]

    decisions = [(a["target"], a["decision"]) for a in rec.of("audit_event")]
    assert ("11:22:33:44:55:66", "BLOCKED") in decisions
    assert ("AA:BB:CC:DD:EE:FF", "ALLOWED") in decisions


def test_filter_bssids_returns_nothing_without_a_scope():
    rec = Recorder()
    policy = ScopePolicy(rec)
    assert policy.filter_bssids("auto_attack", [{"bssid": "AA:BB:CC:DD:EE:FF"}]) == []
    assert "scope_denied" in rec.names()


# ── audit payload ───────────────────────────────────────────────────────────

def test_audit_events_carry_the_engagement_and_context():
    policy, rec = make_policy()
    policy.authorize("start_bruteforce", [("ip", "192.168.1.10")],
                     {"session_id": "sess-1", "mission_id": "m-1"})
    audit = rec.of("audit_event")[0]
    assert audit["engagement_name"] == "HQ Floor 3 Audit"
    assert audit["operator"] == "operator-a"
    assert audit["command"] == "start_bruteforce"
    assert audit["target_kind"] == "IP"
    assert audit["session_id"] == "sess-1"
    assert audit["mission_id"] == "m-1"
    assert audit["decision"] == "ALLOWED"


def test_malformed_scope_entries_are_reported_not_silently_dropped():
    rec = Recorder()
    policy = ScopePolicy(rec)
    policy.load({
        "engagement_name": "Sloppy",
        "authorized_by": "x",
        "targets": [
            {"kind": "IP", "value": "999.1.1.1"},
            {"kind": "CIDR", "value": "hello/24"},
        ],
    })
    warnings = rec.of("scope_warning")
    assert len(warnings) == 2


def test_normalize_mac():
    assert normalize_mac("aa:bb:cc:dd:ee:ff") == "AABBCCDDEEFF"
    assert normalize_mac("AA-BB-CC-DD-EE-FF") == "AABBCCDDEEFF"
    assert normalize_mac("") == ""
    assert normalize_mac(None) == ""


# ── one access point, two ways to name it ───────────────────────────────────
#
# authorize_ap() exists because authorize() requires *every* entry to pass,
# which is correct when the entries are different subjects (a MITM victim and
# its gateway) and wrong when they are two names for one access point. Before
# it, capture and PMKID passed only a BSSID, so an SSID entry in the allowlist
# authorized nothing for them and an estate of 300 APs sharing one SSID had to
# be listed MAC by MAC.


def test_ap_in_scope_by_its_own_bssid():
    policy, rec = make_policy()
    assert policy.authorize_ap("start_strike", "AA:BB:CC:DD:EE:FF") is True
    assert rec.of("audit_event")[0]["decision"] == "ALLOWED"


def test_ap_in_scope_by_its_ssid_even_when_the_bssid_is_unknown():
    """The fix. One SSID entry covers every AP broadcasting it."""
    policy, rec = make_policy()
    assert policy.authorize_ap(
        "start_strike", "11:22:33:44:55:66", ssid="CORP-WIFI") is True
    audit = rec.of("audit_event")[0]
    assert audit["decision"] == "ALLOWED"
    # Recorded against the thing actually touched, not against the SSID.
    assert audit["target"] == "11:22:33:44:55:66"
    assert audit["target_kind"] == "BSSID"
    assert "CORP-WIFI" in audit["reason"]


def test_an_ap_matching_neither_is_refused():
    policy, rec = make_policy()
    assert policy.authorize_ap(
        "start_strike", "11:22:33:44:55:66", ssid="NEIGHBOUR-WIFI") is False
    assert rec.of("audit_event")[0]["decision"] == "BLOCKED"


def test_bssid_separators_and_case_are_ignored():
    policy, _ = make_policy()
    assert policy.authorize_ap("start_strike", "aa-bb-cc-dd-ee-ff") is True
    assert policy.authorize_ap("start_strike", "aabbccddeeff") is True


def test_ssid_match_is_exact_not_a_prefix():
    """A loose match here would silently widen the engagement."""
    policy, _ = make_policy()
    assert policy.authorize_ap("start_strike", "11:22:33:44:55:66",
                               ssid="CORP-WIFI-GUEST") is False
    assert policy.authorize_ap("start_strike", "11:22:33:44:55:66",
                               ssid="corp-wifi") is False


def test_authorize_ap_denies_before_any_scope_is_loaded():
    rec = Recorder()
    policy = ScopePolicy(rec)
    assert policy.authorize_ap("start_strike", "AA:BB:CC:DD:EE:FF",
                               ssid="CORP-WIFI") is False
    assert rec.of("audit_event")[0]["decision"] == "BLOCKED"


def test_authorize_ap_fails_closed_on_an_expired_engagement():
    past = (datetime.now() - timedelta(days=1)).isoformat()
    policy, rec = make_policy(valid_until=past)
    assert policy.authorize_ap("start_strike", "AA:BB:CC:DD:EE:FF") is False
    assert "expired" in rec.of("scope_denied")[0]["reason"].lower()


def test_authorize_ap_in_unrestricted_mode_allows_but_still_audits():
    policy, rec = make_policy(mode="UNRESTRICTED",
                              unrestricted_ack="I HAVE WRITTEN AUTHORIZATION FOR EVERY REACHABLE TARGET")
    assert policy.authorize_ap("start_strike", "99:99:99:99:99:99") is True
    audit = rec.of("audit_event")[0]
    assert audit["decision"] == "ALLOWED"
    assert "UNRESTRICTED" in audit["reason"]


def test_authorize_ap_leaves_ungated_commands_alone():
    policy, _ = make_policy()
    assert policy.authorize_ap("get_status", "99:99:99:99:99:99") is True


def test_authorize_ap_refuses_a_target_it_cannot_identify():
    policy, rec = make_policy()
    assert policy.authorize_ap("start_strike", "", ssid=None) is False
    assert "cannot be checked" in rec.of("scope_denied")[0]["reason"]


def test_scanning_is_not_gated_at_all():
    """The scope never limits what a survey can see, only what it may touch."""
    for command in ("start_scan", "start_passive", "start_probe_monitor",
                    "get_interfaces", "get_net_context"):
        assert command not in GATED_COMMANDS, command


# ── where the boundary is drawn ─────────────────────────────────────────────
#
# The gated set is deliberately narrower than "everything that emits a packet".
# It covers the commands that can disrupt a network, authenticate against it, or
# intercept its traffic — the acts that do real damage when aimed at the wrong
# target. These tests pin that decision so it cannot be widened or narrowed by
# accident, and so the report's generated claim about refusals stays true.

def test_everything_that_can_disrupt_authenticate_or_intercept_is_gated():
    # Narrowing this set is a deliberate act with consequences in the delivered
    # document, which generates its refusal claim from GATED_COMMANDS. If you
    # are here because this failed, update the report prose in the same change.
    must_be_gated = {
        "auto_attack",      # the only command that picks its own targets
        "start_strike",     # deauthentication — drops somebody's connection
        "start_mitm",       # ARP spoofing — redirects somebody's traffic
        "start_spray",      # authentication attempts across many hosts
        "start_bruteforce", # authentication attempts against one
    }
    missing = must_be_gated - GATED_COMMANDS
    assert not missing, f"these can cause real harm and must stay gated: {sorted(missing)}"


def test_reconnaissance_is_not_gated():
    # A misdirected port sweep or TLS enumeration inconveniences nobody and
    # leaves nothing behind. Gating these was friction without a safety return,
    # and it made the audit trail noisy enough to obscure the entries that
    # matter. They still emit packets, which the report states plainly.
    for command in ("start_intrusion", "start_vuln_scan", "start_smb_enum",
                    "start_deep_ssl_scan", "start_vlan_detect",
                    "start_traceroute", "start_dirbuster"):
        assert command not in GATED_COMMANDS, command


def test_capture_is_not_gated():
    # Capture listens for frames the radio was already receiving. It is closer
    # to passive observation than to an act against a target.
    for command in ("start_capture", "start_pmkid_capture"):
        assert command not in GATED_COMMANDS, command


def test_an_ungated_command_writes_no_audit_row():
    # The consequence of the tiering that a reader of the report has to know:
    # the audit trail is evidence about the gated set, not a complete log of
    # everything the tool did. The report's appendix says so.
    rec = Recorder()
    policy = ScopePolicy(rec)
    assert policy.authorize("start_vuln_scan", [("ip", "10.0.0.5")]) is True
    assert rec.names() == [], "an ungated command must not write an audit row"


def test_the_gated_set_is_published_for_the_report():
    # The report generates its claim about refusals from this, rather than
    # asserting a blanket one. If describe() stops publishing it, the document
    # falls back to a weaker sentence instead of an untrue one — but the list
    # should be there.
    policy, _ = make_policy()
    published = policy.describe().get("gated_commands")
    assert published is not None, "describe() must publish the gated set"
    assert sorted(published) == sorted(GATED_COMMANDS)


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
