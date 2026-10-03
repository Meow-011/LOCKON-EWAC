"""Tests for the ARP-populating UDP ping sweep.

    python engine/tests/test_udp_sweep.py
    python -m pytest engine/tests/test_udp_sweep.py

Why this exists.

The sweep used to derive its target list like this:

    subnet_prefix = '.'.join(target_cidr.split('/')[0].split('.')[:3])
    for i in range(1, 255):
        s.sendto(b'', (f"{subnet_prefix}.{i}", 53))

It took the first three octets and swept 1-254 regardless of the prefix length
it had been handed. Three separate problems, none of them visible from outside:

1. **It sent packets outside the range it was given.** For `192.168.1.0/25` —
   which is .0 to .127 — it also sent datagrams to .128 through .254.
2. **It under-covered anything larger than a /24.** On a /16 it touched 254 of
   65,534 addresses, so the ARP pre-filter could only ever find hosts inside
   that one slice, and the sweep reported a clean result for the 65,280
   addresses it had never asked about.
3. **`except Exception: pass` wrapped the whole thing**, so a sweep that failed
   outright looked exactly like a quiet network, and the socket leaked on the
   way out.

Naively fixing (2) by enumerating the whole range replaces it with a worse
problem: 65,534 datagrams to unused addresses is 65,534 ARP broadcasts that
every station on the segment has to process. A tool that degrades the network it
is assessing has failed at something more important than coverage, so the sweep
is capped and reports the cap.

No packets are sent by these tests: the socket is replaced with one that records
destinations.
"""
import os
import socket as _socket
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import IPy  # noqa: E402
from scanner import lan  # noqa: E402
from scanner.lan import LANScanner, MAX_UDP_SWEEP_ADDRESSES  # noqa: E402


class _FakeIPC:
    def emit(self, *a, **k):
        pass


class _RecordingSocket:
    """A UDP socket that records where it was told to send, and sends nothing."""

    instances = []

    def __init__(self, *a, **k):
        self.sent = []
        self.closed = False
        _RecordingSocket.instances.append(self)

    def setsockopt(self, *a, **k):
        pass

    def settimeout(self, *a, **k):
        pass

    def sendto(self, payload, dest):
        self.sent.append(dest[0])

    def close(self):
        self.closed = True


class _FailingSocket(_RecordingSocket):
    def sendto(self, payload, dest):
        raise OSError("network is unreachable")


def _sweep(cidr, local_ip="10.255.255.255", socket_cls=_RecordingSocket):
    """Run the sweep against a recording socket and return (stats, destinations)."""
    _RecordingSocket.instances = []
    scanner = LANScanner(_FakeIPC())
    scanner.scanning = True
    scanner.get_local_ip = lambda: local_ip

    original = _socket.socket
    try:
        _socket.socket = socket_cls
        stats = scanner._udp_ping_sweep(cidr)
    finally:
        _socket.socket = original

    sent = _RecordingSocket.instances[0].sent if _RecordingSocket.instances else []
    return stats, sent


# ── The range is the range ──────────────────────────────────────────────────

def test_a_24_sweeps_exactly_its_own_hosts():
    stats, sent = _sweep("192.168.1.0/24")
    assert stats["addresses_in_range"] == 254
    assert len(sent) == 254
    assert sent[0] == "192.168.1.1"
    assert sent[-1] == "192.168.1.254"


def test_a_25_does_not_leave_its_own_half_of_the_range():
    # The exact regression. The old sweep sent to .128-.254 as well, which are
    # outside the subnet the operator asked for.
    stats, sent = _sweep("192.168.1.0/25")
    assert stats["addresses_in_range"] == 126
    assert len(sent) == 126
    network = IPy.IP("192.168.1.0/25")
    for dest in sent:
        assert IPy.IP(dest) in network, f"{dest} is outside 192.168.1.0/25"
    assert not any(int(d.split('.')[-1]) > 126 for d in sent), \
        "the sweep reached into the upper half of the /24 again"


def test_the_upper_half_of_a_split_24_is_swept_on_its_own_terms():
    stats, sent = _sweep("192.168.1.128/25")
    assert stats["addresses_in_range"] == 126
    assert sent[0] == "192.168.1.129"
    assert sent[-1] == "192.168.1.254"
    assert not any(int(d.split('.')[-1]) < 129 for d in sent)


def test_the_network_and_broadcast_addresses_are_never_targeted():
    for cidr in ("192.168.1.0/24", "192.168.1.0/25", "10.0.5.0/28"):
        _, sent = _sweep(cidr)
        net = IPy.IP(cidr)
        assert str(net.net()) not in sent, f"{cidr}: sent to the network address"
        assert str(net.broadcast()) not in sent, f"{cidr}: sent to the broadcast address"


def test_a_28_sweeps_fourteen_hosts_not_two_hundred_and_fifty_four():
    stats, sent = _sweep("10.0.5.0/28")
    assert stats["addresses_in_range"] == 14
    assert len(sent) == 14


def test_a_range_with_no_usable_hosts_sends_nothing():
    for cidr in ("192.168.1.1/32", "192.168.1.0/31"):
        stats, sent = _sweep(cidr)
        assert sent == [], f"{cidr} has no host addresses to sweep"
        assert stats["error"] is None


# ── The cap, and saying so ──────────────────────────────────────────────────

def test_a_16_is_capped_rather_than_flooding_the_segment():
    stats, sent = _sweep("10.0.0.0/16")
    assert stats["addresses_in_range"] == 65534, "the true size must still be reported"
    assert len(sent) <= MAX_UDP_SWEEP_ADDRESSES
    assert stats["truncated"] is True, "a capped sweep must say it was capped"
    assert stats["cap"] == MAX_UDP_SWEEP_ADDRESSES


def test_a_capped_sweep_still_stays_inside_the_range():
    _, sent = _sweep("10.0.0.0/16")
    network = IPy.IP("10.0.0.0/16")
    for dest in sent:
        assert IPy.IP(dest) in network, f"{dest} is outside 10.0.0.0/16"


def test_a_sweep_that_fits_under_the_cap_is_not_marked_truncated():
    stats, _ = _sweep("192.168.1.0/24")
    assert stats["truncated"] is False


def test_the_reported_size_is_the_range_not_what_was_swept():
    # This is what lets the caller say "N of M addresses were never contacted"
    # instead of presenting the swept slice as the whole subnet.
    stats, sent = _sweep("10.0.0.0/16")
    assert stats["addresses_in_range"] > len(sent)
    assert stats["attempted"] == len(sent) or stats["attempted"] == len(sent) + 1


# ── Failures are reported, never swallowed ─────────────────────────────────

def test_an_invalid_cidr_is_reported_rather_than_silently_skipped():
    stats, _ = _sweep("not-a-cidr")
    assert stats["error"], "a malformed range must be reported"
    assert stats["sent"] == 0


def test_every_send_failing_is_visible_in_the_counts():
    # A sweep where nothing could be sent used to be indistinguishable from a
    # quiet network, because the caller only ever saw the ARP table afterwards.
    stats, _ = _sweep("192.168.1.0/24", socket_cls=_FailingSocket)
    assert stats["sent"] == 0
    assert stats["failed"] == 254
    assert stats["attempted"] == 254


def test_the_socket_is_closed_even_when_sending_fails():
    _sweep("192.168.1.0/24", socket_cls=_FailingSocket)
    assert _RecordingSocket.instances[0].closed is True


def test_the_socket_is_closed_on_the_normal_path():
    _sweep("192.168.1.0/24")
    assert _RecordingSocket.instances[0].closed is True


# ── Cooperation with the rest of the scan ──────────────────────────────────

def test_the_local_address_is_not_swept():
    _, sent = _sweep("192.168.1.0/24", local_ip="192.168.1.50")
    assert "192.168.1.50" not in sent
    assert len(sent) == 253


def test_the_local_address_is_counted_as_attempted_even_though_it_is_skipped():
    stats, _ = _sweep("192.168.1.0/24", local_ip="192.168.1.50")
    # `attempted` is what the caller compares against the range size to decide
    # how many addresses were never contacted, so skipping our own address must
    # not look like a gap in coverage.
    assert stats["attempted"] == 254
    assert stats["sent"] == 253


def test_a_stopped_scan_abandons_the_sweep():
    _RecordingSocket.instances = []
    scanner = LANScanner(_FakeIPC())
    scanner.scanning = False
    scanner.get_local_ip = lambda: "10.255.255.255"
    original = _socket.socket
    try:
        _socket.socket = _RecordingSocket
        stats = scanner._udp_ping_sweep("192.168.1.0/24")
    finally:
        _socket.socket = original
    assert stats["sent"] == 0, "stop() must be honoured before anything goes on the wire"


# -- The ARP read's own error handler used to raise ---------------------------

"""
`_read_arp_cache`'s `except Exception` handler called `logger.debug`, and `lan.py`
had no `logger`. A NameError raised inside an `except` block is not caught by that
block, so it escaped the function -- past the `return arp_cache` it never reached
-- and on out through `_run_scan` into `run_scan`'s handler.

The whole sweep therefore aborted with
`intrusion_error: "Scan failed: name 'logger' is not defined"`, and the
`arp_read_error` the handler had written one line earlier was discarded with the
object. The one path all of that reporting exists for -- `arp.exe` failing with
anything other than a timeout, which on a localised Windows includes a decode
error -- was the path on which none of it ran.
"""


class _RaisingRun:
    """Stands in for `subprocess.run`, raising what a failing `arp.exe` raises."""

    def __init__(self, exc):
        self.exc = exc

    def __call__(self, *a, **k):
        raise self.exc


def _arp_read_with(exc):
    """`(result, arp_read_error)` from a read whose subprocess raised `exc`."""
    scanner = LANScanner(None)
    original = lan.subprocess.run
    lan.subprocess.run = _RaisingRun(exc)
    try:
        return scanner._read_arp_cache(), scanner.arp_read_error
    finally:
        lan.subprocess.run = original


def test_a_failing_arp_read_returns_a_table_instead_of_raising():
    # The caller assigns this straight into `self.arp_cache`. A raise here took
    # the entire sweep down.
    result, _ = _arp_read_with(UnicodeDecodeError("charmap", bytes([0x90]), 0, 1, "bad"))
    assert isinstance(result, dict)


def test_a_decode_failure_is_recorded_as_the_reason():
    # The localised-Windows case, and the reason the field exists at all.
    _, error = _arp_read_with(UnicodeDecodeError("charmap", bytes([0x90]), 0, 1, "bad"))
    assert error, "the read failed and said nothing about why"
    assert "UnicodeDecodeError" in error


def test_a_timeout_is_still_reported_with_its_own_wording():
    _, error = _arp_read_with(lan.subprocess.TimeoutExpired(cmd="arp", timeout=5))
    assert error and "timed out" in error


def test_a_missing_arp_binary_is_reported_rather_than_fatal():
    result, error = _arp_read_with(FileNotFoundError("arp.exe"))
    assert isinstance(result, dict)
    assert error and "FileNotFoundError" in error


def test_a_permission_error_is_reported_rather_than_fatal():
    result, error = _arp_read_with(PermissionError("denied"))
    assert isinstance(result, dict)
    assert error and "PermissionError" in error


# -- A failed ARP read is not the whole LAN leaving the network ---------------

"""
The device diff is built from the ARP cache, and `_read_arp_cache` returns {} on every
failure path while setting `arp_read_error`. The diff block had no guard, so
`current_ips` was empty and `disappeared_devices` became *every device seen last
sweep*: an `intrusion_diff {type: "disappeared"}` naming the whole LAN, emitted while
the sibling `intrusion_scope` event was correctly reporting that the table could not
be read.

The history was overwritten with {} as well. Because the emit is gated on
`if self.previous_scan:` and {} is falsy, the *next* sweep then emitted no diff at all
-- so one failed read also cost a second sweep's worth of detection, and a genuinely
new device arriving on it went unannounced.
"""


class _DiffIpc:
    def __init__(self):
        self.events = []

    def emit(self, name, payload=None):
        self.events.append((name, payload or {}))

    def named(self, name):
        return [p for n, p in self.events if n == name]


def _diff_after(previous, arp_cache, arp_error):
    """
    Run the diff block for one completed sweep.

    Reaching it through `_run_scan` would need a real sweep, so the state it reads is
    set directly and the method is called with the scan it belongs to.
    """
    ipc = _DiffIpc()
    scanner = LANScanner(ipc)
    scanner.previous_scan = dict(previous)
    scanner.arp_cache = dict(arp_cache)
    scanner.arp_read_error = arp_error
    scanner.current_scan_id = "S1"
    scanner.scanning = True
    scanner._emit_terminal = lambda *a, **k: None
    scanner._emit_scan_diff("S1")
    return ipc, scanner


def test_a_failed_arp_read_claims_nothing_about_devices_leaving():
    # The defect in one assertion.
    ipc, _ = _diff_after(
        previous={"10.0.0.1": "aa", "10.0.0.2": "bb", "10.0.0.3": "cc"},
        arp_cache={}, arp_error="the ARP table read timed out after 5s")
    assert ipc.named("intrusion_diff") and all(
        d["type"] != "disappeared" for d in ipc.named("intrusion_diff")), ipc.named("intrusion_diff")


def test_a_failed_arp_read_says_the_comparison_could_not_be_made():
    ipc, _ = _diff_after(
        previous={"10.0.0.1": "aa"}, arp_cache={}, arp_error="arp.exe exited 1")
    diffs = ipc.named("intrusion_diff")
    assert diffs and diffs[0]["type"] == "unavailable"
    assert "arp.exe exited 1" in diffs[0]["reason"]


def test_a_failed_arp_read_does_not_destroy_the_history():
    # Overwriting it with {} cost the next sweep its diff too, because the emit is
    # gated on the previous scan being non-empty.
    _, scanner = _diff_after(
        previous={"10.0.0.1": "aa"}, arp_cache={}, arp_error="timed out")
    assert scanner.previous_scan == {"10.0.0.1": "aa"}


def test_a_successful_read_still_reports_devices_that_left():
    # The feature has to keep working, or the guard is just a mute.
    ipc, _ = _diff_after(
        previous={"10.0.0.1": "aa", "10.0.0.2": "bb"},
        arp_cache={"10.0.0.1": "aa"}, arp_error=None)
    gone = [d for d in ipc.named("intrusion_diff") if d["type"] == "disappeared"]
    assert gone and gone[0]["devices"] == ["10.0.0.2"]


def test_a_successful_read_still_reports_new_devices():
    ipc, _ = _diff_after(
        previous={"10.0.0.1": "aa"},
        arp_cache={"10.0.0.1": "aa", "10.0.0.9": "zz"}, arp_error=None)
    new = [d for d in ipc.named("intrusion_diff") if d["type"] == "new"]
    assert new and new[0]["devices"] == ["10.0.0.9"]


def test_a_successful_read_updates_the_history():
    _, scanner = _diff_after(
        previous={"10.0.0.1": "aa"},
        arp_cache={"10.0.0.1": "aa", "10.0.0.9": "zz"}, arp_error=None)
    assert set(scanner.previous_scan) == {"10.0.0.1", "10.0.0.9"}


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
