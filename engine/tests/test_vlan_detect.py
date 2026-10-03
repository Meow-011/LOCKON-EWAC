"""Tests for VLAN detection: the DHCP probe and the liveness test.

    python engine/tests/test_vlan_detect.py
    python -m pytest engine/tests/test_vlan_detect.py

Why this exists.

Two defects in this module produced confident statements about a network from
checks that could not work. Neither could be noticed by an operator, because
both failed toward a clean-looking result.

1. **The rogue-DHCP check could never fire.** Its payload began with fourteen
   bytes of Ethernet header — broadcast destination, zero source, the IPv4
   EtherType — inside what was then sent as a *UDP* datagram. Every BOOTP field
   was therefore shifted by fourteen bytes and no server could parse it. The
   socket was also never bound to UDP/68, so a DHCP OFFER (which is sent to port
   68) could not have been received even had the Discover been valid. An outer
   `except Exception: pass` covered the rest. `len(servers) > 1` was never true,
   so "DHCP snooping check: clean" was the only outcome the function had — on
   every network, including one with a live rogue DHCP server.

2. **`_ping_host` trusted `returncode == 0`.** Windows `ping.exe` exits 0 when a
   router replies with ICMP Destination Unreachable on the target's behalf, so a
   gateway that does not exist read as alive. Its one caller converts that into
   "Inter-VLAN routing detected — subnets can communicate", a finding in the
   report about a device that is not there.

These tests do no networking. They check the structure of what would go on the
wire and the decision logic around it.
"""
import ipaddress
import os
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.vlan_detect import VLANDetector  # noqa: E402

BOOTP_FIXED_LEN = 236
MAGIC_COOKIE = b'\x63\x82\x53\x63'


def _detector():
    return VLANDetector(lambda *a, **k: None)


# ── The DHCP Discover that goes into a UDP datagram ─────────────────────────

def test_the_payload_does_not_begin_with_an_ethernet_header():
    # The exact regression. If these fourteen bytes ever come back, every field
    # after them is misaligned and no DHCP server will answer.
    pkt = _detector()._build_dhcp_discover(0x11223344, bytes([2, 0, 1, 2, 3, 4]))
    assert not pkt.startswith(b'\xff' * 6), "Ethernet broadcast destination is back in a UDP payload"
    assert pkt[:2] != b'\xff\xff'
    assert pkt[12:14] != b'\x08\x00', "IPv4 EtherType is back in a UDP payload"


def test_the_first_byte_is_a_bootrequest():
    pkt = _detector()._build_dhcp_discover(1, bytes([2, 0, 0, 0, 0, 1]))
    assert pkt[0] == 1, "op must be BOOTREQUEST"
    assert pkt[1] == 1, "htype must be Ethernet"
    assert pkt[2] == 6, "hlen must be 6"
    assert pkt[3] == 0, "hops must be 0"


def test_the_magic_cookie_lands_where_a_server_looks_for_it():
    # RFC 2131: the cookie follows the 236-byte fixed part. This is the single
    # assertion that would have caught the original bug.
    pkt = _detector()._build_dhcp_discover(0xDEADBEEF, bytes([2, 0, 9, 9, 9, 9]))
    assert pkt[BOOTP_FIXED_LEN:BOOTP_FIXED_LEN + 4] == MAGIC_COOKIE


def test_the_transaction_id_is_carried_verbatim():
    # Replies are matched on this, so a mangled xid means every OFFER is ignored.
    for xid in (0, 1, 0x7FFFFFFF, 0xFFFFFFFF):
        pkt = _detector()._build_dhcp_discover(xid, bytes([2, 0, 0, 0, 0, 0]))
        assert struct.unpack('!I', pkt[4:8])[0] == xid


def test_the_broadcast_flag_is_set():
    # Without it a server may unicast the reply to an address we do not hold yet.
    pkt = _detector()._build_dhcp_discover(7, bytes([2, 0, 0, 0, 0, 0]))
    assert struct.unpack('!H', pkt[10:12])[0] == 0x8000


def test_the_message_type_option_says_discover():
    pkt = _detector()._build_dhcp_discover(7, bytes([2, 0, 0, 0, 0, 0]))
    opts = pkt[BOOTP_FIXED_LEN + 4:]
    assert opts[:3] == b'\x35\x01\x01', "option 53 must be present and say DHCPDISCOVER"
    assert opts.endswith(b'\xff'), "the option list must be terminated"


def test_the_client_hardware_address_is_padded_to_sixteen_bytes():
    pkt = _detector()._build_dhcp_discover(7, bytes([2, 0, 1, 2, 3, 4]))
    chaddr = pkt[28:44]
    assert len(chaddr) == 16
    assert chaddr[:6] == bytes([2, 0, 1, 2, 3, 4])
    assert chaddr[6:] == b'\x00' * 10


def test_the_addresses_a_client_does_not_know_yet_are_zero():
    pkt = _detector()._build_dhcp_discover(7, bytes([2, 0, 0, 0, 0, 0]))
    assert pkt[12:28] == b'\x00' * 16, "ciaddr/yiaddr/siaddr/giaddr must all be zero in a Discover"


def test_the_payload_is_long_enough_to_be_a_dhcp_message():
    pkt = _detector()._build_dhcp_discover(7, bytes([2, 0, 0, 0, 0, 0]))
    assert len(pkt) >= BOOTP_FIXED_LEN + 4 + 4


# ── Liveness: an exit code is not an echo reply ─────────────────────────────

class _FakeCompleted:
    def __init__(self, returncode, stdout):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = ""


def _with_ping(monkey_output, returncode=0):
    """Run _ping_host against a canned ping.exe result."""
    d = _detector()
    original = subprocess.run
    try:
        subprocess.run = lambda *a, **k: _FakeCompleted(returncode, monkey_output)
        return d._ping_host("10.0.0.1")
    finally:
        subprocess.run = original


def test_an_echo_reply_counts_as_alive():
    assert _with_ping("Reply from 10.0.0.1: bytes=32 time<1ms TTL=64") is True


def test_a_destination_unreachable_does_not_count_as_alive():
    # ping.exe exits 0 here. This is the case that invented gateways.
    assert _with_ping("Reply from 10.0.0.9: Destination host unreachable.") is False


def test_a_nonzero_exit_is_not_alive():
    assert _with_ping("Request timed out.", returncode=1) is False


def test_a_success_exit_with_no_ttl_is_not_alive():
    # Exit code says fine, output shows no echo reply. Do not invent a host.
    assert _with_ping("", returncode=0) is False


def test_a_lowercase_ttl_is_still_a_ttl():
    # Some platforms print "ttl=64".
    assert _with_ping("64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.5 ms") is True


def test_a_ping_that_raises_is_not_alive():
    d = _detector()
    original = subprocess.run
    try:
        def boom(*a, **k):
            raise OSError("no such executable")
        subprocess.run = boom
        assert d._ping_host("10.0.0.1") is False
    finally:
        subprocess.run = original


# ── The check reports "could not tell" rather than passing silently ─────────

def test_an_unbindable_port_68_is_reported_as_inconclusive():
    # Binding 68 legitimately fails: the OS DHCP client normally holds it, and it
    # is a privileged port. That must not read as "no rogue DHCP found".
    import socket as _socket

    d = _detector()
    original = _socket.socket

    class _NoBind:
        def __init__(self, *a, **k):
            pass

        def setsockopt(self, *a, **k):
            pass

        def bind(self, *a, **k):
            raise OSError("address already in use")

        def settimeout(self, *a, **k):
            pass

        def close(self):
            pass

    try:
        _socket.socket = _NoBind
        findings = d._check_rogue_dhcp(["10.0.0.0/24"])
    finally:
        _socket.socket = original

    assert len(findings) == 1
    f = findings[0]
    assert f["type"] == "rogue_dhcp"
    assert f["inconclusive"] is True
    assert f["severity"] == "INFO", "an unrun check must not carry a risk severity"
    assert "not a result" in f["detail"]["caveat"].lower() or "not tested" in f["detail"]["caveat"].lower()


def test_the_check_never_returns_an_empty_list():
    # An empty list is how this used to say "clean". Every path now states its
    # outcome, so a caller can never mistake silence for a pass.
    import socket as _socket

    d = _detector()
    original = _socket.socket

    class _Exploding:
        def __init__(self, *a, **k):
            raise OSError("no socket for you")

    try:
        _socket.socket = _Exploding
        findings = d._check_rogue_dhcp(["10.0.0.0/24"])
    finally:
        _socket.socket = original

    assert findings, "a failed check must report that it failed"
    assert findings[0]["inconclusive"] is True


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



# ── The subnet arithmetic, and what the map claims ──────────────────────────
#
# None of this was tested. The module's tests covered the DHCP discover packet
# and the ping liveness reader -- both of which had been wrong before -- and
# stopped at the edge of the arithmetic that builds the map itself, which was
# also wrong and had nobody looking at it.
#
# `gateway` and `broadcast` were each assembled as "<first three octets>.1" and
# "<first three octets>.255" from the CIDR string, whatever the prefix length.
# For a /24 that is right. For anything else the gateway is merely unlikely and
# the broadcast address is simply false.

def test_the_broadcast_address_of_a_slash_eight_is_not_in_the_first_block():
    # The case that made this worth fixing: 10.0.0.0/8 reported 10.0.0.255.
    # The broadcast address of that network is 10.255.255.255.
    assert str(ipaddress.ip_network("10.0.0.0/8").broadcast_address) == "10.255.255.255"
    gw = VLANDetector._assumed_gateway("10.0.0.0/8")
    assert gw == "10.0.0.1", gw  # first usable, which for /8 is still x.0.0.1


def test_a_slash_sixteen_gateway_is_the_first_usable_address():
    assert VLANDetector._assumed_gateway("172.16.0.0/16") == "172.16.0.1"


def test_a_slash_twenty_five_gateway_is_not_always_dot_one():
    # 192.168.1.128/25 covers .128-.255. The old string arithmetic produced
    # 192.168.1.1, which is not in this network at all -- it is in the other
    # half of the /24, quite possibly a different segment.
    assert VLANDetector._assumed_gateway("192.168.1.128/25") == "192.168.1.129"


def test_a_point_to_point_link_has_no_first_usable_host_to_name():
    # A /31 has two addresses and no network or broadcast address; either end
    # can be the router. Returning None gives the caller nothing to ping rather
    # than a plausible invention, and `gateway_alive` stays None rather than
    # becoming a False that reads as "the gateway did not answer".
    assert VLANDetector._assumed_gateway("10.0.0.0/31") is None
    assert VLANDetector._assumed_gateway("10.0.0.1/32") is None


def test_an_unparseable_subnet_yields_nothing_rather_than_a_guess():
    assert VLANDetector._assumed_gateway("not a subnet") is None
    assert VLANDetector._assumed_gateway("") is None


def test_a_host_address_is_accepted_and_reduced_to_its_network():
    # `get_all_subnets` is not guaranteed to hand over a network address, and
    # strict parsing would reject "192.168.1.57/24" outright -- losing a real
    # segment from the map because of how it was spelled.
    assert VLANDetector._assumed_gateway("192.168.1.57/24") == "192.168.1.1"


def test_the_vlan_id_travels_with_the_basis_that_produced_it():
    """The guess must not reach the operator looking like a measurement.

    `_guess_vlan_id` reads the third octet and calls the result a VLAN ID. That
    is a convention in some networks and meaningless in others, and "VLAN 20" on
    a screen is indistinguishable from something that was observed. The payload
    now carries the basis alongside the number so the UI can render the one with
    the other, and so that this stays true of any future consumer.
    """
    emitted = []
    det = VLANDetector(lambda ev, data: emitted.append((ev, data)))
    det._ping_host = lambda ip, timeout=1: False
    det._check_inter_vlan_routing = lambda subnets: None
    det._check_vlan_hopping_vectors = lambda subnets: []
    det._check_rogue_dhcp = lambda subnets: []

    det.detect_vlans(["192.168.20.0/24"])
    completed = [d for ev, d in emitted if ev == "vlan_scan_completed"]
    assert len(completed) == 1, emitted
    entry = completed[0]["vlan_map"][0]
    assert entry["vlan_id"] == 20
    assert entry["vlan_id_basis"] == "inferred from the third octet"
    assert entry["gateway"] == "192.168.20.1"
    assert entry["gateway_basis"] == "assumed: first usable address in the prefix"
    assert entry["broadcast"] == "192.168.20.255"
    assert entry["prefix_length"] == 24


def test_a_subnet_that_will_not_parse_stays_in_the_map_as_an_error():
    """Not dropped.

    A map that silently omits a segment reads as a network with fewer segments
    than it has, which is the kind of absence this project treats as a finding
    in its own right.
    """
    emitted = []
    det = VLANDetector(lambda ev, data: emitted.append((ev, data)))
    det._ping_host = lambda ip, timeout=1: False
    det._check_inter_vlan_routing = lambda subnets: None
    det._check_vlan_hopping_vectors = lambda subnets: []
    det._check_rogue_dhcp = lambda subnets: []

    det.detect_vlans(["192.168.1.0/24", "garbage"])
    entry = [d for ev, d in emitted if ev == "vlan_scan_completed"][0]
    assert len(entry["vlan_map"]) == 2
    bad = [e for e in entry["vlan_map"] if e["subnet"] == "garbage"][0]
    assert "error" in bad
    assert bad["gateway"] is None
    # Not False. Nothing was pinged, so nothing failed to answer.
    assert bad["gateway_alive"] is None


if __name__ == "__main__":
    sys.exit(_main())
