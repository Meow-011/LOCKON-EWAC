"""Tests for credential spraying — the rate limit and the denominators.

    python engine/tests/test_sprayer.py
    python -m pytest engine/tests/test_sprayer.py

Why this exists.

Spraying exists to *avoid* account lockout: one credential against many hosts,
slowly. This module did the opposite.

1. **Every target was hit at the same instant.** `start_spray` started one
   thread per target and the only delay in the file was a `time.sleep(0.5)` at
   the *end* of each worker — after the attempt. Since each worker handled
   exactly one target, the sleep only kept a finished thread alive and no
   attempt was ever spaced from another. On a domain that trips every lockout
   policy simultaneously, which is the outcome the technique is chosen to
   prevent; on a /24 it was also 254 operating-system threads.

2. **A malformed target vanished.** `target["ip"]` raised `KeyError` inside a
   daemon thread, which dies with no event and no log line. `join()` returned
   normally and the run reported success.

3. **The completion event carried no counts.** "Credential spray finished." —
   so a spray where no host ever evaluated the credential was indistinguishable
   from one where every host evaluated it and rejected it. Those are opposite
   findings, and the second one is the one a report would state.

The bruteforcer is stubbed throughout; nothing here opens a socket.
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive.sprayer import CredentialSprayer  # noqa: E402


class Result:
    def __init__(self, success=False, unreachable=False, unsupported=False, detail=""):
        self.success = success
        self.unreachable = unreachable
        self.unsupported = unsupported
        self.detail = detail


class FakeBruteforcer:
    """Records when each attempt happened, so pacing is observable."""

    def __init__(self, answer=None, raises=False):
        self.answer = answer or (lambda ip, port, svc: Result())
        self.raises = raises
        self.attempts = []
        self._lock = threading.Lock()
        self.max_concurrent = 0
        self._in_flight = 0

    def test_credential(self, ip, port, svc, username, password):
        with self._lock:
            self._in_flight += 1
            self.max_concurrent = max(self.max_concurrent, self._in_flight)
            self.attempts.append((time.monotonic(), ip, port, svc))
        try:
            time.sleep(0.01)
            if self.raises:
                raise OSError("connection reset")
            return self.answer(ip, port, svc)
        finally:
            with self._lock:
                self._in_flight -= 1


class Recorder:
    def __init__(self):
        self.events = []
        self._lock = threading.Lock()
        self.completed = threading.Event()

    def __call__(self, name, data=None):
        with self._lock:
            self.events.append((name, data or {}))
        if name == "spray_completed":
            self.completed.set()

    def of(self, name):
        with self._lock:
            return [d for n, d in self.events if n == name]

    def names(self):
        with self._lock:
            return [n for n, _ in self.events]


def targets(n, start=1):
    return [{"ip": f"10.0.0.{i}", "port": 445, "service_type": "SMB"}
            for i in range(start, start + n)]


def run(rec, sprayer, target_list, username="admin", password="Summer2026!"):
    sprayer.start_spray(username, password, target_list)
    assert rec.completed.wait(30), "the spray never emitted a completion event"
    return rec.of("spray_completed")[0]


def _sprayer(rec, bf, workers=None, delay=None):
    s = CredentialSprayer(rec, bf)
    if workers is not None:
        s.MAX_WORKERS = workers
    if delay is not None:
        s.DELAY_BETWEEN_ATTEMPTS = delay
    return s


# ── Concurrency and pacing ──────────────────────────────────────────────────

def test_the_number_of_threads_does_not_grow_with_the_target_list():
    # One thread per target meant a /24 was 254 OS threads.
    rec = Recorder()
    bf = FakeBruteforcer()
    s = _sprayer(rec, bf, workers=4, delay=0)
    run(rec, s, targets(60))
    assert bf.max_concurrent <= 4, bf.max_concurrent
    assert len(bf.attempts) == 60


def test_attempts_are_spaced_rather_than_fired_at_once():
    """The defect: every host was contacted in the same instant.

    With one worker and a real delay, the gap between consecutive attempts has
    to be at least that delay. The old code's sleep ran *after* the last
    attempt's result, so this gap was zero however long the sleep was.
    """
    rec = Recorder()
    bf = FakeBruteforcer()
    s = _sprayer(rec, bf, workers=1, delay=0.08)
    run(rec, s, targets(4))
    times = [t for t, *_ in bf.attempts]
    gaps = [b - a for a, b in zip(times, times[1:])]
    assert len(gaps) == 3
    assert all(g >= 0.07 for g in gaps), gaps


def test_the_started_event_states_the_pacing_it_will_use():
    # The operator is choosing between spraying and brute forcing; the rate is
    # the difference, so it belongs in the event rather than only in the source.
    rec = Recorder()
    s = _sprayer(Recorder() and rec, FakeBruteforcer(), workers=3, delay=0)
    run(rec, s, targets(5))
    started = rec.of("spray_started")[0]
    assert started["workers"] == 3
    assert started["delay_between_attempts"] == 0
    assert started["total_targets"] == 5
    assert started["usable_targets"] == 5


def test_every_target_is_attempted_exactly_once():
    rec = Recorder()
    bf = FakeBruteforcer()
    s = _sprayer(rec, bf, workers=4, delay=0)
    run(rec, s, targets(25))
    ips = sorted(ip for _t, ip, _p, _s in bf.attempts)
    assert len(ips) == 25
    assert len(set(ips)) == 25, "a queue-based pool must not hand one target to two workers"


# ── Denominators ────────────────────────────────────────────────────────────

def test_a_run_where_nothing_was_judged_does_not_read_as_a_rejection():
    """The finding this protects.

    Every host unreachable means the credential was never evaluated anywhere.
    The old completion event said only "Credential spray finished.", which reads
    as "the password does not work on any of these hosts" — a claim about the
    estate produced by a run that learned nothing about it.
    """
    rec = Recorder()
    bf = FakeBruteforcer(answer=lambda *a: Result(unreachable=True, detail="refused"))
    s = _sprayer(rec, bf, workers=4, delay=0)
    done = run(rec, s, targets(10))
    assert done["judged"] == 0
    assert done["unreachable"] == 10
    assert done["never_judged"] == 10
    assert "No absence of a success applies" in done["caveat"]


def test_a_run_where_every_host_rejected_says_exactly_that():
    rec = Recorder()
    bf = FakeBruteforcer(answer=lambda *a: Result())
    s = _sprayer(rec, bf, workers=4, delay=0)
    done = run(rec, s, targets(10))
    assert done["judged"] == 10
    assert done["never_judged"] == 0
    assert done["succeeded"] == 0
    assert done["caveat"] == "Every target evaluated the credential and rejected it."


def test_a_success_is_counted_and_reported_with_its_host():
    rec = Recorder()
    bf = FakeBruteforcer(answer=lambda ip, port, svc: Result(success=(ip == "10.0.0.3")))
    s = _sprayer(rec, bf, workers=2, delay=0)
    done = run(rec, s, targets(5))
    assert done["succeeded"] == 1
    hits = rec.of("spray_success")
    assert len(hits) == 1
    assert hits[0]["ip"] == "10.0.0.3"
    assert hits[0]["username"] == "admin"


def test_an_unsupported_service_is_not_counted_as_a_rejection():
    # The host never evaluated anything; the tool could not speak its protocol.
    rec = Recorder()
    bf = FakeBruteforcer(answer=lambda *a: Result(unsupported=True, detail="no handler for VNC"))
    s = _sprayer(rec, bf, workers=2, delay=0)
    done = run(rec, s, targets(3))
    assert done["judged"] == 0
    assert done["unreachable"] == 3
    assert rec.of("spray_unreachable")[0]["reason"] == "no handler for VNC"


def test_an_attempt_that_raises_is_counted_and_reported():
    # It used to `return` from the worker with an event but no count, so the
    # target silently left the denominator.
    rec = Recorder()
    bf = FakeBruteforcer(raises=True)
    s = _sprayer(rec, bf, workers=2, delay=0)
    done = run(rec, s, targets(4))
    assert done["errored"] == 4
    assert done["judged"] == 0
    assert done["never_judged"] == 4
    assert len(rec.of("spray_error")) == 4


def test_the_counts_add_up_to_the_targets_that_were_tried():
    rec = Recorder()

    def mixed(ip, port, svc):
        last = int(ip.rsplit(".", 1)[1])
        if last % 3 == 0:
            return Result(unreachable=True)
        return Result(success=(last == 1))

    s = _sprayer(rec, FakeBruteforcer(answer=mixed), workers=4, delay=0)
    done = run(rec, s, targets(9))
    assert done["attempted"] == 9
    assert done["judged"] + done["unreachable"] + done["errored"] == 9
    assert done["succeeded"] <= done["judged"]


# ── Malformed targets ───────────────────────────────────────────────────────

def test_a_malformed_target_is_named_rather_than_silently_dropped():
    rec = Recorder()
    bf = FakeBruteforcer()
    s = _sprayer(rec, bf, workers=2, delay=0)
    mixed = targets(2) + [
        {"ip": "10.0.0.50"},                                  # no port, no service
        {"port": 445, "service_type": "SMB"},                 # no ip
        {"ip": "10.0.0.51", "port": "not-a-port", "service_type": "SMB"},
        {"ip": "10.0.0.52", "port": 70000, "service_type": "SMB"},
        "10.0.0.53",                                          # not a dict at all
    ]
    done = run(rec, s, mixed)
    assert done["malformed"] == 5, done
    assert done["attempted"] == 2
    assert done["never_judged"] >= 5
    assert any("did not name a host" in e["message"] for e in rec.of("spray_error"))
    # And a KeyError never reached a worker thread, where it would have died
    # without an event.
    assert len(bf.attempts) == 2


def test_a_list_of_only_malformed_targets_reports_that_nothing_was_sprayed():
    rec = Recorder()
    bf = FakeBruteforcer()
    s = _sprayer(rec, bf, workers=2, delay=0)
    s.start_spray("admin", "pw", [{"ip": ""}, {"nonsense": True}])
    assert "spray_completed" not in rec.names()
    assert any("nothing was sprayed" in e["message"] for e in rec.of("spray_error"))
    assert bf.attempts == []


def test_a_port_given_as_a_numeric_string_is_accepted():
    # The frontend does not always type its JSON the way this expects.
    rec = Recorder()
    bf = FakeBruteforcer()
    s = _sprayer(rec, bf, workers=1, delay=0)
    run(rec, s, [{"ip": "10.0.0.5", "port": "445", "service_type": "SMB"}])
    assert bf.attempts[0][2] == 445
    assert isinstance(bf.attempts[0][2], int)


# ── Guards ──────────────────────────────────────────────────────────────────

def test_an_empty_target_list_is_refused_without_a_completion():
    rec = Recorder()
    s = _sprayer(rec, FakeBruteforcer(), workers=2, delay=0)
    s.start_spray("admin", "pw", [])
    assert rec.of("spray_error")
    assert "spray_completed" not in rec.names()


def test_a_string_where_a_list_belongs_is_refused():
    rec = Recorder()
    s = _sprayer(rec, FakeBruteforcer(), workers=2, delay=0)
    s.start_spray("admin", "pw", "10.0.0.5")
    assert rec.of("spray_error")
    assert "spray_started" not in rec.names()


def test_a_second_spray_while_one_is_running_is_refused():
    rec = Recorder()
    bf = FakeBruteforcer()
    s = _sprayer(rec, bf, workers=1, delay=0.05)
    s.start_spray("admin", "pw", targets(6))
    time.sleep(0.05)
    s.start_spray("admin", "pw", targets(6, start=100))
    assert any("already running" in e["message"] for e in rec.of("spray_error"))
    assert rec.completed.wait(30)
    assert len(rec.of("spray_started")) == 1


def test_completion_is_emitted_exactly_once():
    rec = Recorder()
    s = _sprayer(rec, FakeBruteforcer(), workers=3, delay=0)
    run(rec, s, targets(8))
    time.sleep(0.2)
    assert len(rec.of("spray_completed")) == 1


# ── Stopping ────────────────────────────────────────────────────────────────

def test_a_stopped_run_counts_what_it_never_reached():
    """The reason `stop_spray` no longer emits the completion itself.

    It used to, and its payload could not include the queued targets nobody
    had touched — so `never_judged` omitted them and the caveat would have
    read "every target evaluated the credential and rejected it" about hosts
    the tool never contacted.
    """
    rec = Recorder()
    slow = FakeBruteforcer()
    original = slow.test_credential

    def deliberate(ip, port, svc, username, password):
        time.sleep(0.05)
        return original(ip, port, svc, username, password)

    slow.test_credential = deliberate
    s = _sprayer(rec, slow, workers=1, delay=0)
    s.start_spray("admin", "pw", targets(40))
    time.sleep(0.15)
    s.stop_spray()

    assert rec.completed.wait(30)
    done = rec.of("spray_completed")[0]
    assert done["not_attempted"] > 0, done
    assert done["never_judged"] >= done["not_attempted"]
    assert done["attempted"] < 40
    assert "No absence of a success applies" in done["caveat"]


def test_a_stop_ends_the_run_rather_than_draining_the_queue():
    rec = Recorder()
    bf = FakeBruteforcer()
    s = _sprayer(rec, bf, workers=2, delay=0.02)
    s.start_spray("admin", "pw", targets(200))
    time.sleep(0.1)
    s.stop_spray()
    assert rec.completed.wait(30)
    assert len(bf.attempts) < 200, "a stop that still contacts every host is not a stop"


def test_the_stop_watchdog_still_answers_if_the_run_never_reports():
    # The UI must get a terminal event even when the monitor thread is gone,
    # and when it comes from the watchdog it must say the counts are a floor.
    rec = Recorder()
    s = _sprayer(rec, FakeBruteforcer(), workers=1, delay=0)
    s.STOP_GRACE_SECONDS = 0.05
    # A run that exists only as state: no monitor thread was ever started.
    s._running = True
    s._completed = False
    s._counts = {"total_targets": 5, "attempted": 1, "judged": 1,
                 "succeeded": 0, "unreachable": 0, "errored": 0,
                 "malformed": 0, "not_attempted": 0}
    s.stop_spray()
    assert rec.completed.wait(5)
    done = rec.of("spray_completed")[0]
    assert done["counts_complete"] is False
    assert "floor, not a total" in done["caveat"]


def test_a_finished_run_reports_its_counts_as_complete():
    rec = Recorder()
    s = _sprayer(rec, FakeBruteforcer(), workers=2, delay=0)
    done = run(rec, s, targets(6))
    assert done["counts_complete"] is True


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
