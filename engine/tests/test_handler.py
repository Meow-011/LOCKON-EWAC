"""Tests for the IPC boundary — the one place untrusted input enters the engine.

    python engine/tests/test_handler.py
    python -m pytest engine/tests/test_handler.py

Why this exists.

`handler.py` is 1300 lines and was the largest untested file in the project. It
is also the only door into the engine: every value it reads came over a pipe,
and the shipped frontend being well behaved is not a property of the channel.

`_bounded_int` was written for exactly this, and its docstring names the reason —
`max_hops` of 10,000 is an eight-hour blocking subprocess nothing in the app can
interrupt. Then ten more numeric parameters were found still going straight
through, and the worst of them was `count` on `start_strike`: frames per
deauthentication burst, unbounded, on the most disruptive capability the tool
has. Ten million frames at the module's 0.05 s interval is a flood that only
killing the process ends.

Two required ports were also passed through as whatever arrived. `dirbuster`
interpolates its port into the URL it requests (`f"{proto}://{ip}:{port}"`), so a
value like `80/..%2fadmin` is not a port at all — it is a request path chosen by
whoever sent the message.

These tests construct a handler with every scanner replaced by a recorder, so no
adapter is touched, no socket opened and no subprocess spawned. What is exercised
is the routing, the validation, and which event comes back.
"""
import math
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ipc.handler import IPCHandler  # noqa: E402


class Recorder:
    """Stands in for a scanner: records every call, performs none of them."""

    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def capture(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return None
        return capture

    def last(self, name):
        for called, args, kwargs in reversed(self.calls):
            if called == name:
                return args, kwargs
        raise AssertionError(f"{name} was never called; got {[c[0] for c in self.calls]}")

    def called(self, name):
        return any(c[0] == name for c in self.calls)


class AllowAll:
    """A scope policy that authorises everything, so gating is not under test here."""

    def __init__(self):
        self.asked = []

    def authorize(self, command, targets=None):
        self.asked.append(command)
        return True

    def authorize_ap(self, command, bssid, ssid=None):
        self.asked.append(command)
        return True

    def load(self, data):
        self.loaded = data

    def describe(self):
        return {"active": False, "gated_commands": ["auto_attack"]}


class DenyAll(AllowAll):
    def authorize(self, command, targets=None):
        self.asked.append(command)
        return False

    def authorize_ap(self, command, bssid, ssid=None):
        self.asked.append(command)
        return False


def make_handler(policy=None):
    """A handler with no hardware behind it.

    Built with `object.__new__` rather than `IPCHandler()` so that nothing in
    `__init__` touches a radio, a serial port or the network. Only what the
    tests below actually reach is populated; anything else raises an
    AttributeError, which is the behaviour a test wants when it strays outside
    what it set up.
    """
    import threading

    h = object.__new__(IPCHandler)
    h.emitted = []
    h.emit = lambda event, data=None: h.emitted.append((event, data or {}))
    h.policy = policy or AllowAll()
    h.scanning = False
    h.simulating = False
    h.simulator = None
    h.sim_tracker = None
    h._emit_lock = threading.Lock()
    h._gps_state_lock = threading.Lock()
    h._last_valid_lat = None
    h._last_valid_lon = None
    h._last_valid_time = None
    h._max_speed_ms = 55.6
    h._gps_rejects = 0
    h._gps_reject_reported = False
    h._ap_peaks = {}
    h._ap_cache = {}
    for name in ("wifi", "lan", "strike", "probe_monitor", "passive", "smb_enum",
                 "capture", "bruteforce", "sprayer", "decryptor", "dirbuster",
                 "vuln_engine", "mitm", "traceroute", "vlan_detector",
                 "wps_detector", "hashcat", "auto_attack", "gps", "clients"):
        setattr(h, name, Recorder())
    return h


def events(h, name):
    return [d for e, d in h.emitted if e == name]


# ── Bounded integers ────────────────────────────────────────────────────────

def test_a_number_in_range_passes_through():
    assert IPCHandler._bounded_int(30, 10, 1, 100) == 30


def test_a_number_out_of_range_is_clamped_to_the_edge():
    assert IPCHandler._bounded_int(10000, 30, 1, 30) == 30
    assert IPCHandler._bounded_int(-5, 30, 1, 30) == 1


def test_a_string_that_looks_like_a_number_is_accepted():
    # JSON from the frontend is not always typed the way the handler expects,
    # and `str(timeout * 1000)` on "2" raises TypeError deep in a worker thread.
    assert IPCHandler._bounded_int("42", 10, 1, 100) == 42
    assert IPCHandler._bounded_int("3.7", 10, 1, 100) == 3


def test_anything_unparseable_falls_back_to_the_default():
    for value in (None, "", "abc", [], {}, object()):
        assert IPCHandler._bounded_int(value, 7, 1, 100) == 7, repr(value)


def test_a_fractional_bound_survives_as_a_fraction():
    # `scan_interval` of 0.5 s is a legitimate request; an integer floor of 1
    # would silently double it.
    assert IPCHandler._bounded_float(0.5, 3.0, 0.5, 300.0) == 0.5
    assert IPCHandler._bounded_float("1.75", 3.0, 0.5, 300.0) == 1.75


def test_infinity_and_nan_fall_back_rather_than_reaching_sleep():
    # Both survive float(). `time.sleep(inf)` is a scan loop that never ticks
    # again, with a Stop button that has nothing to stop.
    for value in (float("inf"), float("-inf"), float("nan"), "inf", "nan"):
        assert IPCHandler._bounded_float(value, 3.0, 0.5, 300.0) == 3.0, repr(value)


def test_a_negative_interval_cannot_reach_sleep():
    # sleep(-1) raises ValueError, on the scan thread, killing the loop.
    assert IPCHandler._bounded_float(-1, 3.0, 0.5, 300.0) == 0.5


# ── Ports ───────────────────────────────────────────────────────────────────

def test_a_valid_port_is_accepted():
    assert IPCHandler._port_or_none(445) == 445
    assert IPCHandler._port_or_none("8080") == 8080
    assert IPCHandler._port_or_none(" 443 ") == 443


def test_a_port_outside_the_range_is_refused_rather_than_clamped():
    # Clamping would attack a port nobody named. For a required target, "do the
    # normal thing" is not an available answer.
    for value in (0, -1, 65536, 999999):
        assert IPCHandler._port_or_none(value) is None, value


def test_a_port_that_is_not_a_number_is_refused():
    # dirbuster interpolates this into a URL, so this is a path-injection guard
    # and not only a type check.
    for value in ("80/../../admin", "80;ls", "80%2f", "http://x", None, "", "0x50"):
        assert IPCHandler._port_or_none(value) is None, repr(value)


# ── Routing ─────────────────────────────────────────────────────────────────

def test_an_unknown_command_is_reported_rather_than_ignored():
    h = make_handler()
    h.handle({"cmd": "definitely_not_a_command"})
    assert events(h, "error"), h.emitted
    assert "Unknown command" in events(h, "error")[0]["message"]


def test_a_message_with_no_command_is_reported():
    h = make_handler()
    h.handle({})
    assert events(h, "error")


def test_a_handler_that_raises_does_not_take_the_command_loop_down():
    h = make_handler()

    def explode(data):
        raise RuntimeError("boom")

    # Routed through `handle`, which is what the read loop calls. An exception
    # escaping here ends the loop and the engine stops answering anything.
    h._handle_ping = explode
    h.handle({"cmd": "ping"})
    errors = events(h, "error")
    assert errors and errors[0]["command"] == "ping"
    assert "boom" in errors[0]["message"]
    # And the handler is still usable afterwards.
    h.handle({"cmd": "definitely_not_a_command"})
    assert len(events(h, "error")) == 2


def test_a_missing_data_block_is_treated_as_an_empty_one():
    h = make_handler()
    h.handle({"cmd": "get_scope"})
    assert events(h, "scope_status")


# ── Deauthentication frame count ────────────────────────────────────────────

def test_a_deauth_burst_cannot_be_asked_for_ten_million_frames():
    h = make_handler()
    h.handle({"cmd": "start_strike", "data": {
        "target_mac": "AA:BB:CC:DD:EE:FF", "gateway_bssid": "11:22:33:44:55:66",
        "count": 10_000_000,
    }})
    _args, kwargs = h.strike.last("start_strike")
    assert kwargs["count"] == 10000, kwargs


def test_a_continuous_deauth_is_still_expressible():
    # 0 is a documented mode — run until stopped — so the floor is 0, not 1.
    h = make_handler()
    h.handle({"cmd": "start_strike", "data": {
        "target_mac": "AA:BB:CC:DD:EE:FF", "gateway_bssid": "11:22:33:44:55:66", "count": 0,
    }})
    _args, kwargs = h.strike.last("start_strike")
    assert kwargs["count"] == 0


def test_a_deauth_without_both_ends_is_refused():
    h = make_handler()
    h.handle({"cmd": "start_strike", "data": {"target_mac": "AA:BB:CC:DD:EE:FF"}})
    assert events(h, "strike_error")
    assert not h.strike.called("start_strike")


def test_an_out_of_scope_deauth_never_reaches_the_module():
    h = make_handler(DenyAll())
    h.handle({"cmd": "start_strike", "data": {
        "target_mac": "AA:BB:CC:DD:EE:FF", "gateway_bssid": "11:22:33:44:55:66",
    }})
    assert not h.strike.called("start_strike")


# ── Other bounded parameters ────────────────────────────────────────────────

def test_a_directory_scan_cannot_ask_for_a_hundred_thousand_threads():
    h = make_handler()
    h.handle({"cmd": "start_dirbuster", "data": {
        "target_ip": "10.0.0.5", "port": 80, "threads": 100000,
    }})
    args, kwargs = h.dirbuster.last("start_attack")
    passed = kwargs.get("threads", args[4] if len(args) > 4 else None)
    assert passed == 64, (args, kwargs)


def test_a_directory_scan_with_an_injected_port_is_refused():
    h = make_handler()
    h.handle({"cmd": "start_dirbuster", "data": {
        "target_ip": "10.0.0.5", "port": "80/..%2fadmin",
    }})
    assert events(h, "dirbuster_error"), h.emitted
    assert not h.dirbuster.called("start_attack")


def test_a_bruteforce_with_an_out_of_range_port_is_refused():
    h = make_handler()
    h.handle({"cmd": "start_bruteforce", "data": {
        "target_ip": "10.0.0.5", "port": 70000, "service_type": "SSH",
    }})
    assert events(h, "bruteforce_error")
    assert not h.bruteforce.called("start_attack")


def test_an_smb_port_outside_the_range_falls_back_to_445():
    # Optional with a sensible default, unlike the two above, so clamping is the
    # right behaviour: the caller did not name this as the target, the IP did.
    h = make_handler()
    h.handle({"cmd": "start_smb_enum", "data": {"target_ip": "10.0.0.5", "port": 999999}})
    args, _kwargs = h.smb_enum.last("start_enum")
    assert args[1] == 65535, args


def test_a_pmkid_capture_cannot_hold_the_adapter_indefinitely():
    h = make_handler()
    h.handle({"cmd": "start_pmkid_capture", "data": {
        "bssid": "AA:BB:CC:DD:EE:FF", "timeout": 999999,
    }})
    _args, kwargs = h.capture.last("start_pmkid_capture")
    assert kwargs["timeout"] == 600, kwargs


def test_a_wps_scan_duration_is_bounded_at_the_boundary_too():
    # The detector clamps it as well. Bounded here because this is where the
    # untrusted value arrives, and one guard is not defence in depth.
    h = make_handler()
    h.handle({"cmd": "scan_wps", "data": {"duration": 36000}})
    _args, kwargs = h.wps_detector.last("scan")
    assert kwargs["duration"] == 120


def test_a_gpr_grid_cannot_be_asked_for_a_hundred_million_cells():
    # The grid search is O(n^2) in this number: 100 is 10,000 cells and the
    # ceiling is 160,000. 10,000 would have been a hundred million — an
    # out-of-memory on a worker thread, reported to the operator as a failed
    # analysis rather than as a bad request.
    import threading
    import scanner.gpr_engine as gpr_engine

    seen = {}
    done = threading.Event()

    def spy(measurements, grid_resolution=None, **kwargs):
        seen["grid_resolution"] = grid_resolution
        done.set()
        return None

    original = gpr_engine.calculate_gpr_location
    gpr_engine.calculate_gpr_location = spy
    try:
        h = make_handler()
        h.handle({"cmd": "run_gpr", "data": {
            "bssid": "AA:BB:CC:DD:EE:FF",
            "measurements": [{"lat": 13.1, "lon": 100.1, "rssi": -55}],
            "grid_resolution": 10000,
        }})
        assert done.wait(10), "the GPR thread never reached the engine"
    finally:
        gpr_engine.calculate_gpr_location = original

    assert seen["grid_resolution"] == 400, seen


def test_a_gpr_request_with_no_measurements_is_refused():
    h = make_handler()
    h.handle({"cmd": "run_gpr", "data": {"bssid": "AA:BB:CC:DD:EE:FF", "measurements": []}})
    assert events(h, "gpr_error")


# ── Hashcat export path handling ────────────────────────────────────────────

def test_an_export_to_a_path_that_is_not_hc22000_is_refused():
    # `output_path` was opened with mode 'w', so this used to truncate whatever
    # it named — and the engine may be elevated for capture.
    h = make_handler()
    h.handle({"cmd": "export_hashcat", "data": {
        "pcap_path": "x.pcap", "output_path": r"C:\Windows\System32\drivers\etc\hosts",
    }})
    assert events(h, "hashcat_export_error")
    assert not h.hashcat.called("export")


def test_an_export_refuses_to_overwrite_an_existing_file():
    h = make_handler()
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "existing.hc22000")
        with open(target, "w", encoding="utf-8") as fh:
            fh.write("previous work")
        h.handle({"cmd": "export_hashcat", "data": {"pcap_path": "x.pcap", "output_path": target}})
        assert events(h, "hashcat_export_error")
        assert not h.hashcat.called("export")
        with open(target, encoding="utf-8") as fh:
            assert fh.read() == "previous work", "the existing file must be untouched"


def test_an_export_to_a_new_hc22000_path_is_allowed():
    h = make_handler()
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "new.hc22000")
        h.handle({"cmd": "export_hashcat", "data": {"pcap_path": "x.pcap", "output_path": target}})
        assert not events(h, "hashcat_export_error"), h.emitted
        assert h.hashcat.called("export")


def test_an_export_with_no_output_path_uses_the_default():
    # The shipped UI sends no output_path; the exporter derives one from the
    # capture. That path must stay unaffected by the validation above.
    h = make_handler()
    h.handle({"cmd": "export_hashcat", "data": {"pcap_path": "x.pcap"}})
    assert not events(h, "hashcat_export_error")
    args, _kwargs = h.hashcat.last("export")
    assert args == ("x.pcap", None)


# ── Evidence verification path confinement ──────────────────────────────────

def test_verifying_a_file_outside_the_evidence_directory_is_refused():
    h = make_handler()
    h.handle({"cmd": "verify_evidence", "data": {
        "id": 7, "path": os.path.join(tempfile.gettempdir(), "not-evidence.bin"),
    }})
    results = events(h, "evidence_verified")
    assert results, h.emitted
    assert results[0]["matches"] is False
    assert "outside the evidence directory" in results[0]["error"]
    assert results[0]["id"] == 7, "the caller has to be able to match answers to rows"


def test_a_traversal_out_of_the_evidence_directory_is_refused():
    import evidence
    h = make_handler()
    escape = os.path.join(evidence.evidence_dir(), "..", "..", "secrets.txt")
    h.handle({"cmd": "verify_evidence", "data": {"id": 1, "path": escape}})
    results = events(h, "evidence_verified")
    assert results[0]["matches"] is False
    assert "outside the evidence directory" in results[0]["error"]


def test_a_sibling_directory_with_a_shared_prefix_is_refused():
    # The check was a `startswith`, which passes for a sibling whose name merely
    # begins with the same characters. commonpath does not.
    import evidence
    h = make_handler()
    root = os.path.realpath(evidence.evidence_dir())
    h.handle({"cmd": "verify_evidence", "data": {"id": 2, "path": root + "-stolen/x.pcap"}})
    results = events(h, "evidence_verified")
    assert results[0]["matches"] is False
    assert "outside the evidence directory" in results[0]["error"]


def test_verifying_with_no_path_answers_rather_than_going_quiet():
    h = make_handler()
    h.handle({"cmd": "verify_evidence", "data": {"id": 3}})
    results = events(h, "evidence_verified")
    assert results[0]["id"] == 3
    assert results[0]["matches"] is False
    assert results[0]["error"] == "No path supplied"


# ── GPS validation ──────────────────────────────────────────────────────────

def test_a_missing_fix_yields_no_position():
    h = make_handler()
    assert h._validate_gps(None, None) == (None, None)
    assert h._validate_gps(13.7, None) == (None, None)


def test_a_poor_fix_is_rejected_rather_than_recorded_imprecisely():
    h = make_handler()
    assert h._validate_gps(13.7, 100.5, hdop=9.0) == (None, None)


def test_an_unreported_hdop_does_not_reject_the_fix():
    # Some receivers do not report HDOP at all; 0 means "not stated", and
    # treating it as a bad fix would discard every position from that receiver.
    h = make_handler()
    assert h._validate_gps(13.7, 100.5, hdop=0) == (13.7, 100.5)


def test_an_impossible_jump_is_rejected():
    h = make_handler()
    assert h._validate_gps(13.7, 100.5, 1.0) == (13.7, 100.5)
    h._last_valid_time -= 1.0  # one second ago
    # ~11 km away, one second later: 40,000 km/h.
    assert h._validate_gps(13.8, 100.5, 1.0) == (None, None)


def test_a_rejected_jump_does_not_become_the_new_reference():
    # If it did, one bad fix would make every subsequent good one look like a
    # jump back, and the whole remainder of the survey would lose its position.
    h = make_handler()
    h._validate_gps(13.7000, 100.5, 1.0)
    h._last_valid_time -= 1.0
    h._validate_gps(50.0, 100.5, 1.0)  # rejected
    h._last_valid_time -= 1.0
    assert h._validate_gps(13.7005, 100.5, 1.0) == (13.7005, 100.5)


def test_a_plausible_drive_is_accepted():
    h = make_handler()
    h._validate_gps(13.7000, 100.5, 1.0)
    h._last_valid_time -= 5.0
    # ~55 m in 5 s = 40 km/h.
    result = h._validate_gps(13.7005, 100.5, 1.0)
    assert result == (13.7005, 100.5)


def test_two_fixes_in_the_same_instant_are_not_divided_by_zero():
    h = make_handler()
    h._validate_gps(13.7, 100.5, 1.0)
    assert h._validate_gps(13.70001, 100.5, 1.0) == (13.70001, 100.5)


def test_the_distance_maths_is_right_to_within_a_percent():
    # One degree of latitude is about 111.2 km. A wrong radius or a swapped
    # argument here changes what counts as an impossible jump.
    d = IPCHandler._haversine(13.0, 100.0, 14.0, 100.0)
    assert abs(d - 111195) < 1200, d
    assert IPCHandler._haversine(13.0, 100.0, 13.0, 100.0) == 0


# ── Status ──────────────────────────────────────────────────────────────────

def test_the_simulator_never_reports_itself_as_hardware_readiness():
    h = make_handler()
    h.simulating = True
    h.handle({"cmd": "get_status"})
    status = events(h, "status")[0]
    # True here is the simulator's own answer, which is why the report has to
    # carry the simulated flag separately — this event cannot distinguish them.
    assert status["gps_locked"] is True
    assert status["wifi_ready"] is True


def test_status_reports_what_the_hardware_says_when_not_simulating():
    h = make_handler()
    h.gps.has_fix = lambda: False
    h.wifi.has_interface = lambda: False
    h.handle({"cmd": "get_status"})
    status = events(h, "status")[0]
    assert status["gps_locked"] is False
    assert status["wifi_ready"] is False


# ── Emission ────────────────────────────────────────────────────────────────

def test_every_emitted_message_is_one_json_line():
    """The pipe is line-delimited, so an embedded newline splits a record.

    Uses the real `emit`, with stdout replaced, because the newline handling is
    the thing under test.
    """
    import io as _io
    import json
    import threading

    h = object.__new__(IPCHandler)
    h._emit_lock = threading.Lock()
    buffer = _io.StringIO()
    original = sys.stdout
    sys.stdout = buffer
    try:
        h.emit("scan_error", {"message": "line one\nline two", "ssid": "café — networks"})
    finally:
        sys.stdout = original

    text = buffer.getvalue()
    assert text.endswith("\n")
    assert text.count("\n") == 1, "an embedded newline must not split the record"
    parsed = json.loads(text)
    assert parsed["event"] == "scan_error"
    assert parsed["data"]["message"] == "line one\nline two"
    assert parsed["data"]["ssid"] == "café — networks"
    assert parsed["ts"]


def test_concurrent_emission_never_splices_two_records():
    """The defect this guards is silent and non-deterministic.

    Up to a hundred LAN workers, the scan loop, the GPS loop and every command
    handler emit through one `TextIOWrapper`. Write-then-flush is two operations,
    so without the lock two emitters interleave, Tauri fails to parse the spliced
    line, and a discovered host or an evidence record simply never appears.
    """
    import io as _io
    import json
    import threading

    h = object.__new__(IPCHandler)
    h._emit_lock = threading.Lock()
    buffer = _io.StringIO()
    original = sys.stdout
    sys.stdout = buffer
    try:
        threads = [
            threading.Thread(target=lambda i=i: [
                h.emit("host_found", {"ip": f"10.0.0.{i}", "pad": "x" * 400})
                for _ in range(20)
            ])
            for i in range(12)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    finally:
        sys.stdout = original

    lines = [ln for ln in buffer.getvalue().split("\n") if ln]
    assert len(lines) == 240, len(lines)
    for line in lines:
        # A spliced line raises here, which is exactly what the Tauri side does.
        record = json.loads(line)
        assert record["event"] == "host_found"
        assert len(record["data"]["pad"]) == 400



# ── The GPS baseline that outlived its run ──────────────────────────────────

"""
`_last_valid_lat/lon/time` were written in `__init__` and in `_validate_gps`, and
nowhere else. No handler reset them -- not `_handle_start_scan`, not
`_handle_stop_scan`, not `_handle_purge_data`, which clears `_ap_cache` and
`clients` -- so a reference position survived from one run into the next.

That was reachable from the UI in two clicks, because the simulator's origin is
hard-coded to Bangkok: rehearse with a simulated survey, stop, then start a real
scan anywhere else, and the simulated coordinate is the baseline every true fix is
measured against. Each one implies an impossible speed and is refused.

And nothing said so. No event was emitted on rejection, `_handle_status` still
reported `gps_locked` from `has_fix()`, and `gps_update` simply never fired -- so a
whole drive produced access points with `latitude: None` and no explanation
anywhere for why.
"""


def _accept_one(h, lat=13.7000, lon=100.5, age=1.0):
    """Seed an accepted baseline and age it, so the next fix is comparable."""
    assert h._validate_gps(lat, lon, 1.0) == (lat, lon)
    h._last_valid_time -= age


def test_starting_a_scan_forgets_the_previous_run_s_reference():
    # The simulator-then-live case, which is the one an operator hits.
    h = make_handler()
    _accept_one(h, 13.7563, 100.5018)          # a simulated survey in Bangkok
    with h._gps_state_lock:
        h._reset_gps_baseline()

    assert h._last_valid_lat is None
    assert h._last_valid_lon is None
    assert h._last_valid_time is None

    # A real scan on another continent now establishes its own baseline instead of
    # being measured against Bangkok.
    assert h._validate_gps(51.5074, -0.1278, 1.0) == (51.5074, -0.1278)


def test_a_rejection_tells_the_operator_something():
    # The symptom was total silence: no event of any kind on the path that stops
    # every access point from getting a position.
    h = make_handler()
    _accept_one(h)
    h.emitted.clear()
    h._validate_gps(50.0, 100.5, 1.0)

    errors = [d for e, d in h.emitted if e == "gps_error"]
    assert errors, f"a rejected fix emitted nothing; events were {[e for e, _ in h.emitted]}"
    assert "implied_speed_kmh" in errors[0]


def test_a_run_of_rejections_is_reported_once_not_once_per_fix():
    # At roughly a fix a second, one message per rejection is a flood, and a
    # flood is dismissed.
    h = make_handler()
    _accept_one(h)
    h.emitted.clear()
    for _ in range(5):
        h._validate_gps(50.0, 100.5, 1.0)
        h._last_valid_time -= 1.0

    assert len([d for e, d in h.emitted if e == "gps_error"]) == 1


def test_one_bad_fix_still_does_not_move_the_reference():
    # The existing guarantee has to survive the recovery path: a single outlier
    # must not become the baseline, or one bad reading poisons the run.
    h = make_handler()
    _accept_one(h)
    h._validate_gps(50.0, 100.5, 1.0)
    assert round(h._last_valid_lat, 4) == 13.7000
    h._last_valid_time -= 1.0
    assert h._validate_gps(13.7005, 100.5, 1.0) == (13.7005, 100.5)


def test_an_accepted_fix_clears_the_rejection_run():
    h = make_handler()
    _accept_one(h)
    for _ in range(3):
        h._validate_gps(50.0, 100.5, 1.0)
        h._last_valid_time -= 1.0
    assert h._gps_rejects == 3

    h._validate_gps(13.7005, 100.5, 1.0)
    assert h._gps_rejects == 0
    assert h._gps_reject_reported is False, \
        "a later episode would be silent if this flag stayed set"


def test_a_long_run_of_rejections_rebuilds_the_reference():
    """
    Twenty consecutive refusals say the baseline is wrong, not the receiver.

    Without this, escape from a stale baseline depended only on elapsed time:
    `_last_valid_time` is frozen while rejections continue, so recovery needed
    `distance / elapsed <= 55.6 m/s` -- about 45 hours for a continental
    displacement, and still two and a half hours at 500 km.
    """
    h = make_handler()
    _accept_one(h, 13.7563, 100.5018)

    result = (None, None)
    for _ in range(h._GPS_REJECTS_BEFORE_REBASELINE):
        result = h._validate_gps(51.5074, -0.1278, 1.0)
        h._last_valid_time -= 1.0

    assert result == (51.5074, -0.1278), "the baseline was never rebuilt"
    assert round(h._last_valid_lat, 4) == 51.5074
    assert h._gps_rejects == 0


def test_the_rebuild_is_announced_rather_than_done_quietly():
    # Access points found during the episode have no position, and the report
    # calls them unresolved. The operator needs to know that window existed.
    h = make_handler()
    _accept_one(h, 13.7563, 100.5018)
    h.emitted.clear()
    for _ in range(h._GPS_REJECTS_BEFORE_REBASELINE):
        h._validate_gps(51.5074, -0.1278, 1.0)
        h._last_valid_time -= 1.0

    rebaselined = [d for e, d in h.emitted if e == "gps_error" and d.get("rebaselined")]
    assert rebaselined, "the reference was rebuilt without saying so"


def test_the_reference_can_be_seeded_directly():
    h = make_handler()
    with h._gps_state_lock:
        h._reset_gps_baseline(1.5, 2.5, 1000.0)
    assert (h._last_valid_lat, h._last_valid_lon, h._last_valid_time) == (1.5, 2.5, 1000.0)
    assert h._gps_rejects == 0


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
