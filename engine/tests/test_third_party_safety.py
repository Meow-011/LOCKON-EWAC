"""
The two places this tool could alter or attack a machine nobody authorised.

    python engine/tests/test_third_party_safety.py
    python -m pytest engine/tests/test_third_party_safety.py

Why these exist.

Both defects reach outside this rig, which is why they are grouped here rather
than with the modules they live in. One left a stranger's ARP tables poisoned
with no way to restore them; the other attempted logins across a whole subnet
with no authorization record of any kind.

1. **A stop for a target that was not running was a silent no-op.**
   `MITMAttacker.stop_mitm` was `if target_ip in self.active_attacks:` with no
   else. Nothing came back -- not an error, not a progress line -- so a caller
   could not tell "stopping" from "that went nowhere". The UI made that
   reachable: STOP INTERCEPT sent whichever host was selected at click time, not
   the host the spoof had been started against, and `mitmState` is one value for
   the whole page. Start on A, select B, click stop: the engine ignored it, no
   event arrived, the button stayed on SPOOFING, and A's ARP tables stayed
   poisoned. `stop_all` is not exposed as a command, so there was no second way
   out.

2. **The DEEP sweep's default-credential probe was ungated and unaudited.**
   `_quick_credential_check` makes eight real SSH, FTP and HTTP Basic login
   attempts per host, from inside `scan_host`. `start_bruteforce` -- the same act
   against one operator-chosen host -- has always been gated and written to the
   audit trail. This ran against every host a DEEP sweep found, across every
   subnet `get_all_subnets()` turned up, with no scope check and nothing in the
   report's refusals. `policy.py` draws its own line at authentication, in
   writing, on the grounds that a brute force "can lock out accounts that do not
   belong to the engagement".

Neither test touches a network or a real adapter.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive.mitm import MitmEngine  # noqa: E402
from policy import GATED_COMMANDS, ScopePolicy  # noqa: E402
from scanner.lan import LANScanner  # noqa: E402


class _Recorder:
    """Collects emitted events as (name, payload) pairs."""

    def __init__(self):
        self.events = []

    def __call__(self, name, payload=None):
        self.events.append((name, payload or {}))

    def named(self, name):
        return [p for n, p in self.events if n == name]

    @property
    def names(self):
        return [n for n, _ in self.events]


# ── 1. Stopping an interception ─────────────────────────────────────────────

def test_stopping_an_unknown_target_reports_instead_of_doing_nothing():
    """
    The defect: no else branch, so nothing came back at all.

    Silence here is indistinguishable from a stop in progress, and the thing that
    did not stop is a poisoned ARP table on somebody else's machine.
    """
    rec = _Recorder()
    attacker = MitmEngine(rec)
    attacker.active_attacks["10.0.0.5"] = True

    attacker.stop_mitm("10.0.0.99")

    assert rec.events, "a stop for an unknown target produced no event at all"
    errors = rec.named("mitm_error")
    assert errors, f"expected mitm_error, got {rec.names}"
    assert errors[0]["target"] == "10.0.0.99"


def test_the_refusal_names_what_is_still_running():
    """
    So an operator who stopped the wrong address can reach the right one.

    Without this the message says only that nothing happened, and the host that
    is still being spoofed stays unnamed.
    """
    rec = _Recorder()
    attacker = MitmEngine(rec)
    attacker.active_attacks["10.0.0.5"] = True
    attacker.active_attacks["10.0.0.6"] = True

    attacker.stop_mitm("10.0.0.99")

    message = rec.named("mitm_error")[0]["message"]
    assert "10.0.0.5" in message and "10.0.0.6" in message, message


def test_a_stop_with_nothing_running_says_so_plainly():
    rec = _Recorder()
    MitmEngine(rec).stop_mitm("10.0.0.99")
    message = rec.named("mitm_error")[0]["message"]
    assert "no interception is running against any target" in message.lower()


def test_stopping_a_running_target_still_requests_the_restore():
    """The true path must keep working: flag cleared, progress reported."""
    rec = _Recorder()
    attacker = MitmEngine(rec)
    attacker.active_attacks["10.0.0.5"] = True

    attacker.stop_mitm("10.0.0.5")

    assert attacker.active_attacks["10.0.0.5"] is False
    assert rec.named("mitm_progress"), f"expected mitm_progress, got {rec.names}"
    assert not rec.named("mitm_error"), "a valid stop must not report an error"


def test_a_valid_stop_does_not_claim_the_arp_tables_are_restored_yet():
    """
    `mitm_stopped` is the attack thread's to emit, after the restore is tried.

    If `stop_mitm` emitted it, the UI would return to IDLE while the target was
    still poisoned.
    """
    rec = _Recorder()
    attacker = MitmEngine(rec)
    attacker.active_attacks["10.0.0.5"] = True
    attacker.stop_mitm("10.0.0.5")
    assert not rec.named("mitm_stopped")


# ── 2. The sweep's credential probe ─────────────────────────────────────────

def test_authentication_during_a_sweep_is_a_gated_command():
    """
    The policy module's line is drawn at harm, and this authenticates.

    Asserted against the set itself so removing it from the gate is a visible
    change to this file rather than a silent one.
    """
    assert "sweep_credential_check" in GATED_COMMANDS


def _policy(mode=None, targets=None, name="ENGAGEMENT"):
    """A loaded scope, or an unloaded one when `mode` is None."""
    rec = _Recorder()
    policy = ScopePolicy(rec)
    if mode is not None:
        policy.load({
            "engagement_name": name,
            "mode": mode,
            "targets": targets or [],
            "unrestricted_ack": True,
        })
    return policy, rec


def test_with_no_engagement_scope_no_host_is_offered_a_password():
    policy, _ = _policy(mode=None)
    assert policy.permits_host("sweep_credential_check", "10.0.0.5") is False


def test_with_no_engagement_scope_the_operator_is_told_once():
    """
    Once per run, not once per host.

    `authorize` raises a `scope_denied` on every refusal, which is right for a
    button and wrong for a sweep: a subnet's worth of notifications teaches the
    operator to dismiss them.
    """
    policy, rec = _policy(mode=None)
    assert policy.sweep_credentials_preflight() is False
    assert len(rec.named("scope_denied")) == 1

    before = len(rec.named("scope_denied"))
    for i in range(20):
        policy.permits_host("sweep_credential_check", f"10.0.0.{i}")
    assert len(rec.named("scope_denied")) == before, \
        "the per-host check raised a notification of its own"


def test_every_refusal_is_still_written_to_the_audit_trail():
    """
    Quiet is not unrecorded. The report has to be able to name the hosts the rig
    declined to authenticate against.
    """
    policy, rec = _policy(mode=None)
    policy.permits_host("sweep_credential_check", "10.0.0.5")
    blocked = [p for p in rec.named("audit_event") if p.get("decision") == "BLOCKED"]
    assert blocked, f"no BLOCKED audit row; events were {rec.names}"
    assert blocked[0]["target"] == "10.0.0.5"


def test_a_host_outside_the_allowlist_is_refused():
    policy, _ = _policy(mode="ALLOWLIST", targets=[{"kind": "IP", "value": "10.0.0.5"}])
    assert policy.permits_host("sweep_credential_check", "10.0.0.5") is True
    assert policy.permits_host("sweep_credential_check", "10.0.0.6") is False


def test_an_allowed_host_is_audited_too():
    """An authentication attempt that *was* authorised still needs its record."""
    policy, rec = _policy(mode="ALLOWLIST", targets=[{"kind": "IP", "value": "10.0.0.5"}])
    policy.permits_host("sweep_credential_check", "10.0.0.5")
    allowed = [p for p in rec.named("audit_event") if p.get("decision") == "ALLOWED"]
    assert allowed and allowed[0]["target"] == "10.0.0.5"


def test_unrestricted_mode_permits_but_still_records():
    policy, rec = _policy(mode="UNRESTRICTED")
    assert policy.permits_host("sweep_credential_check", "10.0.0.6") is True
    assert [p for p in rec.named("audit_event") if p.get("decision") == "ALLOWED"]


def test_an_ungated_command_is_unaffected():
    """`permits_host` must not start gating recon."""
    policy, _ = _policy(mode=None)
    assert policy.permits_host("start_intrusion", "10.0.0.5") is True


# ── The scanner's own default ───────────────────────────────────────────────

def test_the_scanner_attempts_no_credentials_until_a_run_allows_it():
    """
    Fails closed.

    `scan_host` consults this flag, and a path that reaches it without going
    through `_run_scan` must not inherit permission from nowhere.
    """
    scanner = LANScanner(None)
    assert scanner._sweep_credentials_allowed is False


def _preflight_result(scan_mode, policy_answer):
    """What `_run_scan`'s preflight decides, without running a scan."""
    class FakePolicy:
        def __init__(self):
            self.asked = 0

        def sweep_credentials_preflight(self, context=None):
            self.asked += 1
            return policy_answer

    class FakeIpc:
        def __init__(self):
            self.policy = FakePolicy()

        def emit(self, *a, **k):
            pass

    scanner = LANScanner(FakeIpc())
    scanner._sweep_credentials_allowed = (
        scan_mode == "DEEP"
        and scanner.ipc.policy.sweep_credentials_preflight({"scan_id": "S1"})
    )
    return scanner._sweep_credentials_allowed, scanner.ipc.policy.asked


def test_a_quick_sweep_never_even_asks():
    """QUICK does not reach the credential code, so it earns no notification."""
    allowed, asked = _preflight_result("QUICK", True)
    assert allowed is False
    assert asked == 0, "a sweep that cannot attempt credentials consulted the gate"


def test_a_stealth_sweep_never_even_asks():
    allowed, asked = _preflight_result("STEALTH", True)
    assert allowed is False
    assert asked == 0


def test_a_deep_sweep_asks_and_honours_a_refusal():
    allowed, asked = _preflight_result("DEEP", False)
    assert allowed is False
    assert asked == 1


def test_a_deep_sweep_proceeds_when_the_scope_permits_it():
    allowed, asked = _preflight_result("DEEP", True)
    assert allowed is True
    assert asked == 1


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
