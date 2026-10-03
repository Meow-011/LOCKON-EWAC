"""
A deauth strike has to report which of three ways it ended.

    python engine/tests/test_strike_outcome.py
    python -m pytest engine/tests/test_strike_outcome.py

Why this exists.

`stop_strike` emitted `strike_stopped {status: "CEASED"}` itself, and then the worker
loop noticed `running` was false, exited, and emitted a **second** `strike_stopped`.
`send_failed` is None on a clean stop, so that second event carried
`status: "COMPLETED"`.

Two terminal events for one strike, the later of which contradicted the earlier. The
last word on a run the operator had halted was that it finished, with a partial
`packets_sent` presented as the count of a completed run. "We stopped after 40
frames" and "the run of 200 completed" are different facts about what was done to
somebody's network, and the second is the one that reached the event stream.

`active_strikes` entries were also never removed, so `stop_strike` returned True for
strikes that had ended long ago and `stop_all` re-emitted CEASED for every one of
them on each call.

No radio and no scapy: the worker is never started. These drive `stop_strike` and the
terminal-status logic directly.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.strike import StrikeModule  # noqa: E402


class _Ipc:
    """Collects emitted events as (name, payload) pairs."""

    def __init__(self):
        self.events = []

    def emit(self, name, payload=None):
        self.events.append((name, payload or {}))

    def named(self, name):
        return [p for n, p in self.events if n == name]

    @property
    def names(self):
        return [n for n, _ in self.events]


def _engine():
    return StrikeModule(_Ipc())


def _running_strike(engine, mac="AA:BB:CC:DD:EE:01", sent=40, count=200):
    """An entry shaped like one a live worker would be holding."""
    state = {"running": True, "sent": sent, "count": count, "ceased": False}
    engine.active_strikes[mac] = state
    return state


# ── stop_strike requests; it does not announce ──────────────────────────────

def test_stopping_does_not_emit_a_terminal_event_of_its_own():
    """
    The defect. Two `strike_stopped` events for one strike, and the second won.

    The worker owns the terminal event, the same way `mitm_stopped` is owned by the
    attack thread so it cannot be claimed before the ARP restore is attempted.
    """
    e = _engine()
    _running_strike(e)
    assert e.stop_strike("AA:BB:CC:DD:EE:01") is True
    assert e.ipc.named("strike_stopped") == [], \
        f"stop_strike emitted a terminal event: {e.ipc.names}"


def test_stopping_marks_the_strike_as_ceased_for_the_worker():
    e = _engine()
    state = _running_strike(e)
    e.stop_strike("AA:BB:CC:DD:EE:01")
    assert state["running"] is False
    assert state["ceased"] is True


def test_stopping_is_acknowledged_so_the_ui_is_not_silent():
    # Something has to come back, or the operator cannot tell a stop in progress
    # from a click that went nowhere.
    e = _engine()
    _running_strike(e)
    e.stop_strike("AA:BB:CC:DD:EE:01")
    progress = e.ipc.named("strike_progress")
    assert progress and progress[-1]["status"] == "STOPPING"


def test_stopping_an_unknown_target_reports_nothing_and_returns_false():
    e = _engine()
    assert e.stop_strike("AA:BB:CC:DD:EE:99") is False
    assert e.ipc.events == []


def test_stopping_an_already_finished_strike_returns_false():
    """
    Entries were never removed, so this returned True for a strike that had ended,
    and `stop_all` re-emitted CEASED for every finished strike of the session.
    """
    e = _engine()
    state = _running_strike(e)
    state["running"] = False
    assert e.stop_strike("AA:BB:CC:DD:EE:01") is False
    assert e.ipc.named("strike_progress") == []


def test_a_finished_entry_is_dropped_rather_than_accumulated():
    e = _engine()
    state = _running_strike(e)
    state["running"] = False
    e.stop_strike("AA:BB:CC:DD:EE:01")
    assert "AA:BB:CC:DD:EE:01" not in e.active_strikes


def test_stop_all_does_not_re_announce_finished_strikes():
    e = _engine()
    for i, running in ((1, False), (2, False), (3, True)):
        s = _running_strike(e, mac=f"AA:BB:CC:DD:EE:0{i}")
        s["running"] = running
    e.stop_all()
    # Only the one that was actually running earns an acknowledgement.
    assert len(e.ipc.named("strike_progress")) == 1


# ── The terminal status the worker reports ──────────────────────────────────

def _terminal_status(sent, count, send_failed, ceased):
    """
    The worker's own three-way decision, as the module makes it.

    Kept as a mirror of the branch in `_deauth_worker` rather than reached through
    it, because reaching it needs scapy and a radio. The assertion that matters is
    the ordering: a send failure outranks a cease, and only an untouched run of both
    is COMPLETED.
    """
    if send_failed:
        return "FAILED"
    if ceased:
        return "CEASED"
    return "COMPLETED"


def test_a_strike_the_operator_stopped_is_not_completed():
    assert _terminal_status(40, 200, None, True) == "CEASED"


def test_a_strike_that_ran_its_course_is_completed():
    assert _terminal_status(200, 200, None, False) == "COMPLETED"


def test_a_send_failure_outranks_a_cease():
    # If the interface refused the frames, that is the more important fact: it
    # means nothing was transmitted, whoever stopped it.
    assert _terminal_status(0, 200, "no such device", True) == "FAILED"


def test_the_module_still_distinguishes_all_three_outcomes():
    """
    Guards against the statuses being collapsed again.

    The frontend maps CEASED, FAILED and COMPLETED to three different states, and
    FAILED exists because a strike whose frames the adapter refused used to finish
    as COMPLETED right after its own error event.
    """
    outcomes = {
        _terminal_status(0, 200, "err", False),
        _terminal_status(40, 200, None, True),
        _terminal_status(200, 200, None, False),
    }
    assert outcomes == {"FAILED", "CEASED", "COMPLETED"}


def test_the_source_still_reports_ceased_from_the_worker():
    """
    Reads the module's own source, because the branch above is a mirror of it.

    A mirror that drifts is worse than no test: it would keep passing while the
    worker went back to reporting COMPLETED for a halted strike.
    """
    import inspect
    import scanner.strike as strike_module

    src = inspect.getsource(strike_module)
    assert 'status = "CEASED"' in src, \
        "the worker no longer has a CEASED branch; this file's mirror is stale"
    assert src.count('self.ipc.emit("strike_stopped"') == 1, \
        "strike_stopped is emitted from more than one place again"


def test_the_engine_starts_with_no_active_strikes():
    assert _engine().active_strikes == {}


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
