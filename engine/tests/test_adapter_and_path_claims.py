"""
Statements about adapters, routes and third-party hosts that nothing had checked.

    python engine/tests/test_adapter_and_path_claims.py
    python -m pytest engine/tests/test_adapter_and_path_claims.py

Why these exist.

Each of these joined two facts that were measured separately, or made a claim about a
network out of something that happened on this machine.

1. **`netsh wlan show interfaces` was parsed into one flat dict.** It prints one block
   per wireless adapter, and a disconnected block carries Name/Description/GUID/
   Physical address/State and *no* SSID or AP BSSID lines. So a disconnected block
   arriving after the connected one set `connected: false` while `ssid`, `bssid`,
   `band`, `channel`, `auth_type`, `cipher` and `rssi` persisted from the connected
   adapter. `net_context.describe()` consumes this and emitted "Not associated with any
   access point" while the payload carried that BSSID. `scan_networks` in the same file
   already resets per block and explains why.

2. **`default_route()` took the first matching row and ignored the metric**, although
   its docstring claims "the routing table says which one traffic actually takes". It
   had no section awareness either, so with no active default route it fell through to
   a *persistent* (configured) route and published a gateway this machine has no route
   to.

3. **`describe()` combined the Wi-Fi BSSID with the default-route gateway** with no
   check they belong to the same adapter — so with Wi-Fi associated and Ethernet or a
   VPN holding the route, it asserted the machine reaches the Ethernet gateway
   "through" the Wi-Fi BSSID.

4. **An unclassifiable AKM was published as WPA3 and not vulnerable.** pywifi's
   `const` stops at `AKM_TYPE_UNKNOWN = 5`; SAE (6) and OWE (8) do not exist in it, so
   the only literal that could ever match was the UNKNOWN sentinel.

5. **Teardown of one MITM session disabled IP forwarding machine-wide**, cutting the
   route out from under every other session still poisoning.

6. **A traceroute the operator stopped reported `ok: True`**, whereupon the analysis
   appended a claim that the host "may be filtered ... or down".

No radio, no network: the command output is planted and the subprocesses are replaced.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive.mitm import MitmEngine  # noqa: E402
from scanner import net_context, netsh_wlan  # noqa: E402


class _Recorder:
    def __init__(self):
        self.events = []

    def __call__(self, name, payload=None):
        self.events.append((name, payload or {}))

    def named(self, name):
        return [p for n, p in self.events if n == name]


# ── 1. One result per adapter ───────────────────────────────────────────────

#: Two blocks: a connected Wi-Fi radio, then a disconnected one. The order is the
#: one that used to corrupt the result.
TWO_ADAPTERS = """
There are 2 interfaces on the system:

    Name                   : Wi-Fi
    Description            : Intel BE200
    GUID                   : 1111
    Physical address       : aa:bb:cc:dd:ee:00
    State                  : connected
    SSID                   : CORP-WIFI
    AP BSSID               : 00:00:5e:00:53:48
    Band                   : 5 GHz
    Channel                : 149
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Rssi                   : -52

    Name                   : Wi-Fi 2
    Description            : Intel BE200 #2
    GUID                   : 2222
    Physical address       : aa:bb:cc:dd:ee:01
    State                  : disconnected
"""

#: The same two the other way round, so the fix cannot be an ordering accident.
DISCONNECTED_FIRST = """
There are 2 interfaces on the system:

    Name                   : Wi-Fi 2
    Description            : Intel BE200 #2
    GUID                   : 2222
    Physical address       : aa:bb:cc:dd:ee:01
    State                  : disconnected

    Name                   : Wi-Fi
    Description            : Intel BE200
    GUID                   : 1111
    Physical address       : aa:bb:cc:dd:ee:00
    State                  : connected
    SSID                   : CORP-WIFI
    AP BSSID               : 00:00:5e:00:53:48
    Channel                : 149
"""

ONLY_DISCONNECTED = """
    Name                   : Wi-Fi
    State                  : disconnected
"""


def _connection_from(text):
    original_run = netsh_wlan._run
    original_avail = netsh_wlan.available
    netsh_wlan._run = lambda *a, **k: text
    netsh_wlan.available = lambda: True
    try:
        return netsh_wlan.connection_info()
    finally:
        netsh_wlan._run = original_run
        netsh_wlan.available = original_avail


def test_a_disconnected_adapter_does_not_overwrite_the_connected_one():
    # The defect: `connected: false` beside a populated BSSID.
    info = _connection_from(TWO_ADAPTERS)
    assert info["connected"] is True
    assert info["bssid"] == "00:00:5E:00:53:48"
    assert info["interface"] == "Wi-Fi"


def test_the_connected_adapter_is_found_whichever_order_it_arrives_in():
    info = _connection_from(DISCONNECTED_FIRST)
    assert info["connected"] is True
    assert info["ssid"] == "CORP-WIFI"
    assert info["interface"] == "Wi-Fi"


def test_a_result_never_mixes_two_adapters():
    """
    Every field has to come from the adapter `interface` names.

    The old loop could hand back the disconnected adapter's name beside the connected
    one's SSID, which is a row describing a machine state that did not exist.
    """
    info = _connection_from(DISCONNECTED_FIRST)
    assert info["interface"] == "Wi-Fi"
    assert info["channel"] == 149


def test_no_connected_adapter_yields_no_network_fields():
    info = _connection_from(ONLY_DISCONNECTED)
    assert info["connected"] is False
    assert info["ssid"] is None
    assert info["bssid"] is None


def test_no_adapters_at_all_is_an_empty_result():
    info = _connection_from("There are 0 interfaces on the system:")
    assert info["connected"] is False
    assert info["interface"] is None


# ── 2. The route that traffic actually takes ────────────────────────────────

ROUTE_TWO_DEFAULTS = """
IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.50.1    192.168.50.20     45
          0.0.0.0          0.0.0.0       10.20.0.32      10.20.0.237     35
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      10.250.32.1  Default
===========================================================================
"""

ROUTE_ONLY_PERSISTENT = """
IPv4 Route Table
===========================================================================
Active Routes:
  None
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      10.250.32.1  Default
===========================================================================
"""


def _route_from(text):
    original = net_context._run
    net_context._run = lambda *a, **k: text
    try:
        return net_context.default_route()
    finally:
        net_context._run = original


def test_the_lowest_metric_default_route_wins():
    # Not the first one printed. `route print` does not contract an ordering within a
    # destination, and a docked rig has several default routes at once.
    if sys.platform != "win32":
        return
    route = _route_from(ROUTE_TWO_DEFAULTS)
    assert route["gateway_ip"] == "10.20.0.32"
    assert route["local_ip"] == "10.20.0.237"
    assert route["metric"] == 35


def test_a_configured_route_is_not_reported_as_the_live_one():
    """
    Persistent Routes rows satisfy the same text shape and carry "Default" as a metric.

    They were shadowed only because an Active Routes row usually comes first. With the
    adapter down or the VPN dropped, the parser fell through and published a gateway
    this machine has no route to.
    """
    if sys.platform != "win32":
        return
    route = _route_from(ROUTE_ONLY_PERSISTENT)
    assert route["gateway_ip"] is None, route


# ── 3. Two adapters are not one path ───────────────────────────────────────

def _describe_with(wireless, route):
    orig_conn = netsh_wlan.connection_info
    orig_route = net_context.default_route
    orig_arp = net_context.arp_lookup
    net_context.netsh_wlan.connection_info = lambda: wireless
    net_context.default_route = lambda: route
    net_context.arp_lookup = lambda ip: "99:99:99:99:99:99"
    try:
        return net_context.describe()
    finally:
        net_context.netsh_wlan.connection_info = orig_conn
        net_context.default_route = orig_route
        net_context.arp_lookup = orig_arp


def test_a_route_on_another_adapter_makes_no_claim_about_the_access_point():
    """
    Wi-Fi on 192.168.1.x while the default route goes out 10.20.0.x.

    The note used to read "This machine reaches <ethernet gateway> through <wifi
    bssid>", and `gateway_is_ap` compared a MAC from one adapter with a BSSID from
    another.
    """
    out = _describe_with(
        {"connected": True, "ssid": "CORP", "bssid": "00:00:5E:00:53:48",
         "local_ip": "192.168.1.50"},
        {"gateway_ip": "10.20.0.32", "local_ip": "10.20.0.237", "metric": 35},
    )
    assert out["same_adapter"] is False
    assert out["gateway_is_ap"] is None, "a verdict was reached across two adapters"
    assert "different interface" in out["note"]


def test_one_adapter_still_gets_its_normal_verdict():
    # The fix must not suppress the case the module exists for.
    out = _describe_with(
        {"connected": True, "ssid": "CORP", "bssid": "99:99:99:99:99:99",
         "local_ip": "10.20.0.237"},
        {"gateway_ip": "10.20.0.32", "local_ip": "10.20.0.237", "metric": 35},
    )
    assert out["same_adapter"] is True
    assert out["gateway_is_ap"] is True



def test_the_route_metric_reaches_the_payload():
    """
    The metric is what chose this route among several, so it is worth printing.

    `default_route()` measures it and `describe()` was dropping it -- a value computed
    and then discarded, which an end-to-end smoke test of the engine's stdio protocol
    surfaced as `metric: None` beside a working `same_adapter`.
    """
    out = _describe_with(
        {"connected": True, "ssid": "CORP", "bssid": "99:99:99:99:99:99",
         "local_ip": "10.20.0.237"},
        {"gateway_ip": "10.20.0.32", "local_ip": "10.20.0.237", "metric": 35},
    )
    assert out["metric"] == 35


def test_the_metric_survives_the_different_adapter_path_too():
    # The early return for two adapters is a separate dict literal, so it can drift
    # from the main one -- which is how the field came to be missing in the first place.
    out = _describe_with(
        {"connected": True, "ssid": "CORP", "bssid": "00:00:5E:00:53:48",
         "local_ip": "192.168.1.50"},
        {"gateway_ip": "10.20.0.32", "local_ip": "10.20.0.237", "metric": 45},
    )
    assert out["same_adapter"] is False
    assert out["metric"] == 45



def test_without_the_wireless_address_no_agreement_is_claimed():
    """
    The test fixture used to be richer than the producer, which hid the real defect.

    `describe()` read `wireless.get("local_ip")` -- a key `connection_info()` never
    sets, because `netsh wlan show interfaces` reports no layer-3 address -- so the
    strong comparison never ran. Control fell to a weak test comparing the route's own
    local address against its own gateway's subnet, which is true for essentially every
    default route, and `same_adapter: true` was published as a positive claim nothing
    had measured.

    Here the wireless side has no address and the lookup finds none either, so the only
    honest answer is None.
    """
    original = netsh_wlan.adapter_ipv4
    netsh_wlan.adapter_ipv4 = lambda name: None
    try:
        out = _describe_with(
            {"connected": True, "ssid": "CORP", "bssid": "00:00:5E:00:53:48",
             "interface": "Wi-Fi"},
            {"gateway_ip": "10.20.0.32", "local_ip": "10.20.0.237", "metric": 35},
        )
    finally:
        netsh_wlan.adapter_ipv4 = original
    assert out["same_adapter"] is None, out["same_adapter"]


def test_the_wireless_address_is_looked_up_by_adapter_name():
    # The fallback that makes the strong test reachable at all in production.
    original = netsh_wlan.adapter_ipv4
    asked = []
    netsh_wlan.adapter_ipv4 = lambda name: asked.append(name) or "192.168.1.50"
    try:
        out = _describe_with(
            {"connected": True, "ssid": "CORP", "bssid": "00:00:5E:00:53:48",
             "interface": "Wi-Fi 2"},
            {"gateway_ip": "10.20.0.32", "local_ip": "10.20.0.237", "metric": 35},
        )
    finally:
        netsh_wlan.adapter_ipv4 = original
    assert asked == ["Wi-Fi 2"], asked
    # Different subnets, so this is the two-adapter case the check exists for.
    assert out["same_adapter"] is False
    assert out["gateway_is_ap"] is None


# ── 4. An unknown AKM is unknown ────────────────────────────────────────────

def test_pywifi_has_no_sae_or_owe_constant():
    """
    The premise of the old branch, checked against the installed library.

    `const` stops at `AKM_TYPE_UNKNOWN = 5`, so the literals 6 and 8 could never
    match and the only one that ever did was the UNKNOWN sentinel -- which the branch
    mapped to WPA3, not vulnerable.
    """
    from pywifi import const
    assert const.AKM_TYPE_UNKNOWN == 5
    assert not hasattr(const, "AKM_TYPE_SAE")
    assert not hasattr(const, "AKM_TYPE_OWE")


def test_an_unknown_akm_is_no_longer_called_wpa3():
    import inspect
    import scanner.wifi as wifi_module

    src = inspect.getsource(wifi_module)
    assert "if 5 in akm_types" not in src, \
        "the UNKNOWN sentinel is being read as WPA3 again"
    assert "const.AKM_TYPE_UNKNOWN in akm_types" in src, \
        "UNKNOWN is no longer handled as its own case"


# ── 5. IP forwarding is shared ─────────────────────────────────────────────

def _mitm():
    rec = _Recorder()
    m = MitmEngine(rec)
    # The real call shells out to PowerShell; only the bookkeeping is under test.
    m._set_ip_forwarding = lambda enable: (True, f"forwarding {enable}")
    m.ipc = rec
    return m, rec


def test_forwarding_stays_on_while_another_target_still_needs_it():
    # Two sessions. Stopping the first used to run
    # `Set-NetIPInterface -Forwarding Disabled` machine-wide, blackholing the second
    # victim's traffic while that session kept poisoning and kept emitting packets.
    m, _ = _mitm()
    m._enable_ip_forwarding("10.0.0.5")
    m._enable_ip_forwarding("10.0.0.6")

    ok, message = m._disable_ip_forwarding("10.0.0.5")
    assert ok is True
    assert "10.0.0.6" in message, message
    assert m._forwarding_for == {"10.0.0.6"}


def test_the_last_target_out_turns_forwarding_off():
    m, _ = _mitm()
    m._enable_ip_forwarding("10.0.0.5")
    m._enable_ip_forwarding("10.0.0.6")
    m._disable_ip_forwarding("10.0.0.5")

    calls = []
    m._set_ip_forwarding = lambda enable: (calls.append(enable), (True, ""))[1]
    m._disable_ip_forwarding("10.0.0.6")
    assert calls == [False], "forwarding was not turned off for the last target"
    assert m._forwarding_for == set()


def test_a_failed_enable_claims_nothing():
    # If forwarding could not be turned on, this target must not hold a claim on it.
    m, _ = _mitm()
    m._set_ip_forwarding = lambda enable: (False, "not elevated")
    ok, _ = m._enable_ip_forwarding("10.0.0.5")
    assert ok is False
    assert m._forwarding_for == set()


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
