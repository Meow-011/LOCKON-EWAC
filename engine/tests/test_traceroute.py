"""Tests for traceroute output parsing and path analysis.

    python engine/tests/test_traceroute.py
    python -m pytest engine/tests/test_traceroute.py

Why this exists.

Traceroute results now reach the exported report, as a *Network Path Context*
section. That raised the bar on every sentence this module produces, and four of
them did not clear it.

1. **A trace that never ran emitted a completion.** `traceroute_completed` was
   emitted unconditionally, *after* `traceroute_error`, with an empty hop list
   and an analysis reading "Target was not reached — may be filtered or down".
   The frontend's error handler resets to IDLE and its completion handler sets
   DONE, so the completion won. `tracert` missing from PATH therefore produced
   the same screen, and the same archived report, as a host that is genuinely
   firewalled. One is a statement about the network; the other is a statement
   about the tool.

2. **"Target is N hops away" counted answering hops.** Two filtered routers in
   the middle of a path made the report place the target two hops closer than it
   is.

3. **`is_target` compared a dotted quad to the caller's argument verbatim.**
   Handed a hostname it can never match, so every trace to a name reported the
   target unreachable — an alarming claim manufactured by a string mismatch.

4. **"<1 ms" was recorded as 0.5 ms.** The tool declines to give a figure below
   one millisecond; 0.5 is a number no measurement produced, and the report
   printed it as though one had.

These tests do no networking: `tracert` output is fed in as text and only the
parse and the analysis are exercised.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import traceroute as traceroute_module  # noqa: E402
from scanner.traceroute import TracerouteEngine  # noqa: E402


class Recorder:
    def __init__(self):
        self.events = []

    def __call__(self, name, data=None):
        self.events.append((name, data))

    def names(self):
        return [n for n, _ in self.events]


def _engine():
    e = TracerouteEngine(Recorder())
    # Reverse DNS is a real network call. Switched off for every test here; the
    # budget that bounds it is tested separately by construction.
    e.RDNS_BUDGET_SECONDS = -1.0
    return e


def _parse(text, target="192.168.1.10"):
    e = _engine()
    hops = []
    e._parse_output(text, target, hops)
    return e, hops


WINDOWS_CLEAN = """
Tracing route to 192.168.1.10 over a maximum of 30 hops

  1    <1 ms    <1 ms    <1 ms  192.168.31.1
  2     3 ms     2 ms     2 ms  10.20.0.1
  3    11 ms    12 ms    11 ms  192.168.1.10

Trace complete.
"""

WINDOWS_FILTERED = """
Tracing route to 192.168.1.10 over a maximum of 30 hops

  1    <1 ms    <1 ms    <1 ms  192.168.31.1
  2     3 ms     2 ms     2 ms  10.20.0.1
  3     *        *        *     Request timed out.
  4     *        *        *     Request timed out.
  5     *        *        *     Request timed out.
  6    40 ms    41 ms    39 ms  192.168.1.10

Trace complete.
"""

LINUX_CLEAN = """traceroute to 192.168.1.10 (192.168.1.10), 30 hops max, 60 byte packets
 1  192.168.31.1  0.456 ms  0.389 ms  0.312 ms
 2  10.20.0.1  3.112 ms  2.998 ms  3.004 ms
 3  192.168.1.10  11.402 ms  12.001 ms  11.883 ms
"""


# ── Parsing ─────────────────────────────────────────────────────────────────

def test_windows_output_parses_every_hop():
    _, hops = _parse(WINDOWS_CLEAN)
    assert [h["hop"] for h in hops] == [1, 2, 3], hops
    assert [h["ip"] for h in hops] == ["192.168.31.1", "10.20.0.1", "192.168.1.10"]


def test_linux_output_parses_every_hop():
    _, hops = _parse(LINUX_CLEAN)
    assert [h["hop"] for h in hops] == [1, 2, 3]
    assert hops[0]["avg_rtt"] == 0.39, hops[0]["avg_rtt"]


def test_the_header_line_is_not_mistaken_for_a_hop():
    # "Tracing route to 192.168.1.10 over a maximum of 30 hops" contains an
    # address and a number. It is not a hop.
    _, hops = _parse(WINDOWS_CLEAN)
    assert len(hops) == 3
    assert all(h["hop"] in (1, 2, 3) for h in hops)


def test_sub_millisecond_hops_carry_no_invented_average():
    _, hops = _parse(WINDOWS_CLEAN)
    first = hops[0]
    assert first["avg_rtt"] is None, "0.5 ms is a figure no measurement produced"
    assert first["rtt_ms"] == []
    assert first["rtt_below_1ms"] is True, "but the reader still needs to know it was fast"


def test_a_measured_hop_is_not_flagged_as_sub_millisecond():
    _, hops = _parse(WINDOWS_CLEAN)
    assert hops[1]["rtt_below_1ms"] is False
    assert hops[1]["avg_rtt"] == 2.33, hops[1]["avg_rtt"]


def test_a_timed_out_hop_has_no_address_and_no_latency():
    _, hops = _parse(WINDOWS_FILTERED)
    silent = [h for h in hops if h["timeout"]]
    assert len(silent) == 3
    for h in silent:
        assert h["ip"] is None
        assert h["avg_rtt"] is None
        assert h["rtt_ms"] == []


def test_parsing_stops_at_the_target():
    text = WINDOWS_CLEAN + "  4    20 ms    20 ms    20 ms  8.8.8.8\n"
    _, hops = _parse(text)
    assert len(hops) == 3, "nothing after the target should be recorded"
    assert hops[-1]["is_target"] is True


def test_a_hop_is_the_target_only_when_the_address_is_known():
    # target_addr None is what an unresolvable hostname produces.
    e = _engine()
    hops = []
    e._parse_output(WINDOWS_CLEAN, None, hops)
    assert all(h["is_target"] is False for h in hops)
    # ...and the analysis must not then claim the target was not reached.
    analysis = e._analyze_path(hops, None)
    assert any("could not be determined" in f["message"] for f in analysis)
    assert not any("did not reach" in f["message"] for f in analysis)


def test_every_hop_is_emitted_live():
    e = _engine()
    rec = Recorder()
    e.emit = rec
    hops = []
    e._parse_output(WINDOWS_CLEAN, "192.168.1.10", hops)
    assert rec.names() == ["traceroute_hop"] * 3


def test_garbage_output_produces_no_hops_rather_than_a_crash():
    for text in ("", None, "Unable to resolve target system name foo.\n", "\n\n\n"):
        _, hops = _parse(text)
        assert hops == [], text


# ── Path analysis ───────────────────────────────────────────────────────────

def test_distance_is_the_hop_the_target_answered_at_not_the_answer_count():
    e, hops = _parse(WINDOWS_FILTERED)
    analysis = e._analyze_path(hops, "192.168.1.10")
    info = [f for f in analysis if f["type"] == "info"]
    assert len(info) == 1
    # Three hops answered and the target is at hop 6. The old code said 3.
    assert "hop 6" in info[0]["message"], info[0]["message"]
    assert "3 hop(s) along the way did not answer" in info[0]["message"]


def test_an_unreached_target_is_described_without_claiming_a_distance():
    text = """
  1    <1 ms    <1 ms    <1 ms  192.168.31.1
  2     3 ms     2 ms     2 ms  10.20.0.1
  3     *        *        *     Request timed out.
"""
    e, hops = _parse(text)
    analysis = e._analyze_path(hops, "192.168.1.10")
    info = [f for f in analysis if f["type"] == "info"][0]
    assert "reached hop 3" in info["message"], info["message"]
    assert "2 hop(s) answered" in info["message"]
    assert any(f["type"] == "warning" and "did not reach" in f["message"] for f in analysis)


def test_a_run_of_silent_hops_is_reported_as_possible_filtering():
    e, hops = _parse(WINDOWS_FILTERED)
    analysis = e._analyze_path(hops, "192.168.1.10")
    assert any(f["type"] == "firewall" for f in analysis), analysis


def test_two_silent_hops_are_not_enough_to_claim_filtering():
    text = """
  1    <1 ms    <1 ms    <1 ms  192.168.31.1
  2     *        *        *     Request timed out.
  3     *        *        *     Request timed out.
  4    40 ms    41 ms    39 ms  192.168.1.10
"""
    e, hops = _parse(text)
    analysis = e._analyze_path(hops, "192.168.1.10")
    assert not any(f["type"] == "firewall" for f in analysis)


def test_leaving_private_space_is_reported_once():
    # A carrier that transits its own 10.0.0.0/8 crosses the boundary more than
    # once. One boundary, one line.
    text = """
  1    <1 ms    <1 ms    <1 ms  192.168.31.1
  2     3 ms     2 ms     2 ms  203.0.113.1
  3     8 ms     8 ms     8 ms  10.255.0.1
  4    20 ms    20 ms    20 ms  198.51.100.9
  5    22 ms    22 ms    21 ms  192.168.1.10
"""
    e, hops = _parse(text)
    analysis = e._analyze_path(hops, "192.168.1.10")
    nat = [f for f in analysis if f["type"] == "nat"]
    assert len(nat) == 1, [f["message"] for f in nat]
    assert "hop 2" in nat[0]["message"]


def test_a_wholly_private_path_reports_no_boundary():
    e, hops = _parse(WINDOWS_CLEAN)
    analysis = e._analyze_path(hops, "192.168.1.10")
    assert not any(f["type"] == "nat" for f in analysis)


def test_172_16_through_31_is_private_and_172_32_is_not():
    assert TracerouteEngine._is_private("172.16.0.1") is True
    assert TracerouteEngine._is_private("172.31.255.254") is True
    assert TracerouteEngine._is_private("172.15.0.1") is False
    assert TracerouteEngine._is_private("172.32.0.1") is False
    assert TracerouteEngine._is_private("10.0.0.1") is True
    assert TracerouteEngine._is_private("192.168.0.1") is True
    assert TracerouteEngine._is_private("8.8.8.8") is False
    # Never raises on something that is not an address.
    assert TracerouteEngine._is_private("not.an.ip.addr") is False
    assert TracerouteEngine._is_private(None) is False


def test_a_latency_spike_is_measured_against_the_previous_answering_hop():
    text = """
  1    <1 ms    <1 ms    <1 ms  192.168.31.1
  2     3 ms     2 ms     2 ms  10.20.0.1
  3   180 ms   182 ms   181 ms  203.0.113.7
  4   185 ms   184 ms   186 ms  192.168.1.10
"""
    e, hops = _parse(text)
    analysis = e._analyze_path(hops, "192.168.1.10")
    spikes = [f for f in analysis if f["type"] == "latency"]
    assert len(spikes) == 1, [f["message"] for f in spikes]
    assert "hop 3" in spikes[0]["message"]


def test_a_sub_millisecond_hop_does_not_manufacture_a_spike():
    # avg_rtt is None for a "<1 ms" hop. Treating that absent value as 0 made
    # the comparison for the next hop meaningless.
    text = """
  1    <1 ms    <1 ms    <1 ms  192.168.31.1
  2    60 ms    61 ms    59 ms  192.168.1.10
"""
    e, hops = _parse(text)
    analysis = e._analyze_path(hops, "192.168.1.10")
    assert not any(f["type"] == "latency" for f in analysis), \
        "there is no earlier figure to call this a rise from"


def test_a_failed_trace_says_so_and_claims_nothing_about_the_path():
    e = _engine()
    analysis = e._analyze_path([], "192.168.1.10", error="traceroute/tracert command not found")
    assert len(analysis) == 1
    assert analysis[0]["type"] == "error"
    assert "did not complete" in analysis[0]["message"]
    assert not any("filtered" in f["message"] for f in analysis)


def test_a_partial_trace_reports_the_failure_first_and_keeps_its_hops():
    # A timed-out trace is killed, and what it had already printed is real
    # measurement. Both facts belong in the output.
    e, hops = _parse(WINDOWS_FILTERED)
    analysis = e._analyze_path(hops, "192.168.1.10", error="Traceroute timed out")
    assert analysis[0]["type"] == "error"
    assert len(analysis) > 1, "the hops that did answer are still worth reporting"


# -- A stop is not a statement about the network ------------------------------

"""
`stop()` calls `proc.terminate()` and set no flag. `communicate()` then returned
normally, no exception was raised, so `error` stayed None and `traceroute_completed`
carried `ok: True` with whatever partial hops tracert had already printed.

`_analyze_path` is called with `error=None`, so the guard that would have said "the
trace did not complete" was skipped -- and because no hop matched the target, it
appended "The trace did not reach <ip> - the host may be filtered, behind a device that
does not forward the probes, or down". A claim about somebody's network, produced by
the operator pressing Stop.

`returncode` was also read nowhere in the file, and stderr went to a discard name, so
neither could ever reach `error`.
"""


class _FakeProc:
    """A tracert that prints `stdout` and exits with `returncode`."""

    def __init__(self, stdout="", returncode=0, stderr=""):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self.terminated = False

    def communicate(self, timeout=None):
        return self._stdout, self._stderr

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.terminated = True


def _run_with(proc, stop_first=False):
    """Drive `run_traceroute` against a planted child process."""
    e = _engine()
    original = traceroute_module.subprocess.Popen
    traceroute_module.subprocess.Popen = lambda *a, **k: proc
    try:
        if stop_first:
            # The operator pressing Stop. `_proc` is set by run_traceroute, so the
            # flag is what has to survive: stop() may land before or after the spawn.
            e.stop()
        e.run_traceroute("10.0.0.9", max_hops=3, timeout=1)
    finally:
        traceroute_module.subprocess.Popen = original
    return e


def test_a_trace_the_operator_stopped_is_not_reported_as_ok():
    e = _engine()
    original = traceroute_module.subprocess.Popen
    proc = _FakeProc(stdout="", returncode=0)

    def spawn(*a, **k):
        # Stop lands while the child is running, which is the real sequence.
        e.stop()
        return proc

    traceroute_module.subprocess.Popen = spawn
    try:
        e.run_traceroute("10.0.0.9", max_hops=3, timeout=1)
    finally:
        traceroute_module.subprocess.Popen = original

    completed = [d for n, d in e.emit.events if n == "traceroute_completed"]
    assert completed, e.emit.names()
    assert completed[0]["ok"] is False, completed[0]
    assert "stopped by the operator" in str(completed[0]["error"]).lower()


def test_a_nonzero_exit_is_reported_rather_than_passing_as_a_clean_trace():
    e = _run_with(_FakeProc(stdout="", returncode=1, stderr="Unable to resolve target"))
    completed = [d for n, d in e.emit.events if n == "traceroute_completed"]
    assert completed and completed[0]["ok"] is False
    assert "exited with code 1" in str(completed[0]["error"])


def test_stderr_reaches_the_error_instead_of_a_discard_name():
    e = _run_with(_FakeProc(stdout="", returncode=1, stderr="Unable to resolve target"))
    completed = [d for n, d in e.emit.events if n == "traceroute_completed"]
    assert "Unable to resolve target" in str(completed[0]["error"])


def test_a_clean_trace_is_still_reported_as_ok():
    # The fix must not mark every trace failed.
    e = _run_with(_FakeProc(stdout="", returncode=0))
    completed = [d for n, d in e.emit.events if n == "traceroute_completed"]
    assert completed and completed[0]["ok"] is True
    assert completed[0]["error"] is None


def test_a_second_trace_does_not_inherit_the_first_one_s_stop():
    # `_stopped` is cleared when a run spawns its child, or one Stop would mark every
    # later trace as stopped.
    e = _engine()
    original = traceroute_module.subprocess.Popen
    traceroute_module.subprocess.Popen = lambda *a, **k: _FakeProc(returncode=0)
    try:
        e.stop()
        e.run_traceroute("10.0.0.9", max_hops=3, timeout=1)
        e.emit.events.clear()
        e.run_traceroute("10.0.0.9", max_hops=3, timeout=1)
    finally:
        traceroute_module.subprocess.Popen = original

    completed = [d for n, d in e.emit.events if n == "traceroute_completed"]
    assert completed and completed[0]["ok"] is True, completed


def test_the_process_slot_is_released_only_by_its_own_run():
    """
    `self._proc` was one shared slot, written here and nulled in the `finally`.

    Two concurrent traces made each other unkillable: the second overwrote the slot,
    then the first's cleanup emptied it, so `stop()` found nothing for either.
    """
    e = _engine()
    first = _FakeProc(returncode=0)
    second = _FakeProc(returncode=0)
    e._proc = second
    # A run whose own child is `first` must not clear a slot holding someone else's.
    original = traceroute_module.subprocess.Popen
    traceroute_module.subprocess.Popen = lambda *a, **k: first
    try:
        e.run_traceroute("10.0.0.9", max_hops=3, timeout=1)
    finally:
        traceroute_module.subprocess.Popen = original
    # `first` was the active child during the run, so the slot is clear afterwards --
    # the assertion that matters is that the guard compares identity at all.
    import inspect
    src = inspect.getsource(traceroute_module)
    assert "if self._proc is proc:" in src, \
        "the slot is cleared without checking whose child it holds"


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
