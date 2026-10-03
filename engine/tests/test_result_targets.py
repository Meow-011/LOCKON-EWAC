"""Tests that a result event names the host it is about.

    python engine/tests/test_result_targets.py
    python -m pytest engine/tests/test_result_targets.py

Why this exists.

An event that carries a result but not its subject forces the receiver to guess,
and the only thing the receiver has to guess with is whichever host the operator
happens to have selected at that moment. Both of these modules used to do that.

1. **`smb_enum_completed` carried no `target`.** The frontend listener that
   persists SMB findings to the database read `msg.data.target`, found nothing,
   and returned early — so the persistence was dead code from the day it was
   written. The report page, which had no such guard, instead labelled the
   result with the currently selected host. Enumerate 10.0.0.7, click 10.0.0.9,
   export: the document says 10.0.0.9 runs SMBv1. That is a factual claim about
   the wrong machine, in a report someone is going to act on.

2. **`dirbuster_completed` carried only a message.** The batched hits could not
   be matched to the scan that produced them.

The other half of the same fix lives in the frontend (`hostOfUrl`, and the path
as a fingerprint discriminator rather than as the subject). These tests cover the
engine side: the payload must be self-describing, and the completion event must
say whether the wordlist was exhausted — because "no other paths respond" is a
statement about the server only if the scan actually finished.

No networking: the probes are stubbed and only the emitted payloads are read.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.smb_enum import SMBEnumerator  # noqa: E402
from offensive.dirbuster import DirBuster  # noqa: E402


class Recorder:
    """Collects emitted events so a payload can be inspected."""

    def __init__(self):
        self.events = []

    def __call__(self, name, data=None):
        self.events.append((name, data))

    def payload(self, name):
        for n, d in self.events:
            if n == name:
                return d
        raise AssertionError(f"no {name} event was emitted; got {[n for n, _ in self.events]}")

    def names(self):
        return [n for n, _ in self.events]


def _enumerator(rec):
    e = SMBEnumerator(rec)
    # Every probe stubbed out: this test is about the shape of the payload, not
    # about talking to a host.
    e._check_smbv1 = lambda ip, port: (None, None)
    e._get_ntlm_info = lambda ip, port: None
    e._check_smb_signing = lambda ip, port: None
    # A tuple, because `_run_enum` unpacks one. A bare None raised
    # `TypeError: cannot unpack non-iterable NoneType` into `_run_enum`'s
    # `except Exception`, which recorded it in `results["error"]` while never
    # assigning `shares` -- so the tri-state test below passed on an exception
    # rather than on None propagating, and would have kept passing if the probe
    # had started returning [] for an unanswered question.
    e._enumerate_shares = lambda ip, port: (None, "not determined")
    return e


# ── SMB enumeration ─────────────────────────────────────────────────────────

def test_smb_result_names_its_own_target():
    rec = Recorder()
    _enumerator(rec)._run_enum("10.0.0.7", 445)
    d = rec.payload("smb_enum_completed")
    assert d["target"] == "10.0.0.7", d.get("target")


def test_smb_result_names_the_port_it_used():
    rec = Recorder()
    _enumerator(rec)._run_enum("10.0.0.7", 139)
    assert rec.payload("smb_enum_completed")["port"] == 139


def test_smb_started_and_completed_agree_on_the_target():
    # The frontend keys state off `smb_enum_started` and files the result from
    # `smb_enum_completed`. If the two disagreed the result would be attached to
    # a scan that was never started.
    rec = Recorder()
    _enumerator(rec)._run_enum("192.168.1.50", 445)
    assert rec.payload("smb_enum_started")["target"] == "192.168.1.50"
    assert rec.payload("smb_enum_completed")["target"] == "192.168.1.50"


def test_smb_unanswered_checks_stay_none_and_are_listed():
    # The tri-state is the whole defence against reading a firewalled host as a
    # hardened one. None must survive to the payload, and be named.
    rec = Recorder()
    _enumerator(rec)._run_enum("10.0.0.7", 445)
    d = rec.payload("smb_enum_completed")
    assert d["smbv1_enabled"] is None
    assert d["signing_required"] is None
    # `shares` joined this set: the null-session enumeration used to emit `[]`,
    # which reads as "this host exposes no accessible shares" rather than "the
    # enumeration never got an answer". See test_incomplete_claims.py.
    assert d["shares"] is None
    assert set(d["inconclusive"]) == {"smbv1_enabled", "signing_required", "shares"}
    # No swallowed exception. This test used to pass because a bad stub raised a
    # TypeError that `_run_enum` recorded in `error` while never assigning `shares`,
    # which is not the same thing as the probe propagating None.
    assert "error" not in d, d.get("error")


def test_smb_answered_checks_are_not_listed_as_inconclusive():
    rec = Recorder()
    e = _enumerator(rec)
    e._check_smbv1 = lambda ip, port: (True, None)
    e._check_smb_signing = lambda ip, port: False
    # An enumeration that read an NT status and found nothing accessible. `[]` is a
    # real result here, as against the None the probe returns when nothing answered.
    e._enumerate_shares = lambda ip, port: ([], None)
    e._run_enum("10.0.0.7", 445)
    d = rec.payload("smb_enum_completed")
    assert d["smbv1_enabled"] is True
    assert d["signing_required"] is False
    assert d["shares"] == []
    assert d["inconclusive"] == []


def test_smb_reports_its_target_even_when_a_probe_raises():
    # A partial result is still worth reporting, and it is still about a
    # specific host. The error must not cost the payload its identity.
    rec = Recorder()
    e = _enumerator(rec)

    def boom(ip, port):
        raise OSError("connection reset")

    e._check_smbv1 = boom
    e._run_enum("10.0.0.7", 445)
    d = rec.payload("smb_enum_completed")
    assert d["target"] == "10.0.0.7"
    assert "connection reset" in d["error"]


def test_smb_refuses_a_second_concurrent_enum_of_the_same_host():
    rec = Recorder()
    e = SMBEnumerator(rec)
    with e._active_lock:
        e._active.add("10.0.0.7")
    e.start_enum("10.0.0.7")
    d = rec.payload("smb_enum_error")
    assert d["target"] == "10.0.0.7"


def test_smb_releases_the_host_after_the_run():
    rec = Recorder()
    e = _enumerator(rec)
    with e._active_lock:
        e._active.add("10.0.0.7")
    e._run_enum("10.0.0.7", 445)
    assert "10.0.0.7" not in e._active, "a finished host must be enumerable again"


# ── Directory enumeration ───────────────────────────────────────────────────

def test_dirbuster_completion_names_its_target():
    rec = Recorder()
    d = DirBuster(rec)
    d._base_url = "http://10.0.0.9:8080"
    d._running = True
    d._monitor()
    p = rec.payload("dirbuster_completed")
    assert p["target"] == "http://10.0.0.9:8080"


def test_dirbuster_exhausted_wordlist_is_marked_complete():
    rec = Recorder()
    d = DirBuster(rec)
    d._base_url = "http://10.0.0.9:8080"
    d._running = True
    # The server has to have answered something. `complete` used to be an
    # unconditional True, so a host whose port was closed -- every request raising
    # URLError into a bare `pass` -- reported the wordlist as exhausted with no
    # findings, which is the one reading that licenses "these paths are not here".
    d._answered = 120
    d._monitor()
    assert rec.payload("dirbuster_completed")["complete"] is True


def test_dirbuster_halted_scan_is_not_marked_complete():
    # "Nothing else responded" is a statement about the server only if the
    # wordlist was exhausted. A scan the operator stopped proves nothing about
    # the paths it never requested, and the report needs to be able to tell.
    rec = Recorder()
    d = DirBuster(rec)
    d._base_url = "http://10.0.0.9:8080"
    d.stop_attack()
    p = rec.payload("dirbuster_completed")
    assert p["complete"] is False
    assert p["target"] == "http://10.0.0.9:8080"


def test_dirbuster_completion_target_is_none_before_any_scan():
    # Never a stale URL from a previous scan: None is honest, a wrong host is
    # not, and the frontend already treats an unnamed target as "flush all".
    rec = Recorder()
    d = DirBuster(rec)
    d.stop_attack()
    assert rec.payload("dirbuster_completed")["target"] is None


def test_dirbuster_monitor_stays_quiet_when_already_stopped():
    # stop_attack() clears _running and emits the completion itself. The monitor
    # thread must not emit a second one, or the frontend flushes twice.
    rec = Recorder()
    d = DirBuster(rec)
    d._base_url = "http://10.0.0.9:8080"
    d._running = False
    d._monitor()
    assert "dirbuster_completed" not in rec.names()


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
