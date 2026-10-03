"""Tests for the `netsh wlan` parser and the network-context rules.

    python engine/tests/test_netsh_wlan.py
    python -m pytest engine/tests/test_netsh_wlan.py

Needs no third-party packages and never shells out: the netsh output is a
fixture, so these run identically on a machine with no wireless adapter.

Why these exist.

This parser is load-bearing in a way that is easy to miss. PyWiFi's Windows
backend reports `cipher` as NONE for *every* network and calls a WPA3-Personal
access point "WPA2", so cipher and auth_type were dead fields and the scanner
understated a correctly-secured network in the report. netsh is where the real
answers come from — which makes its failure modes the tool's failure modes:

  * **Localization.** `netsh` output is translated. On a Thai or German Windows
    the labels differ and the parse yields nothing. That has to produce an empty
    result, not a half-filled one: a scan that silently loses the encryption of
    some access points and keeps it for others is worse than one that never had
    it, because the gaps look like findings.
  * **Per-SSID values leaking across networks.** Authentication and Encryption
    are printed once per SSID and apply to the BSSIDs beneath it. If they are
    not cleared at each new SSID block, an open network inherits the previous
    network's WPA2 and is reported as secure.
  * **"Connected Stations" being absent vs. zero.** Only APs advertising BSS
    Load publish a client count. Absent must stay None — "nobody is on this AP"
    and "this AP does not say" are different findings.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import netsh_wlan

# A real `netsh wlan show networks mode=bssid` excerpt: a WPA2 network with two
# BSSIDs and BSS Load, an open network with none, and a hidden SSID.
FIXTURE = """
Interface name : Wi-Fi
There are 3 networks currently visible.

SSID 1 : 3BB_315 5GHz
    Network type            : Infrastructure
    Authentication          : WPA2-Personal
    Encryption              : CCMP
    BSSID 1                 : 28:41:c6:62:45:f4
         Signal             : 5%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 149
         Bss Load:
             Connected Stations:         3
             Channel Utilization:        68 (26 %)
         Basic rates (Mbps) : 6 12 24
    BSSID 2                 : 28:41:c6:62:45:f5
         Signal             : 40%
         Radio type         : 802.11ax
         Band               : 2.4 GHz
         Channel            : 6
         Basic rates (Mbps) : 1 2 5.5 11

SSID 2 : @NBU-WIFI
    Network type            : Infrastructure
    Authentication          : Open
    Encryption              : None
    BSSID 1                 : 14:46:58:44:a9:10
         Signal             : 5%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 52
         Bss Load:
             Connected Stations:         0
             Channel Utilization:        2 (0 %)

SSID 3 :
    Network type            : Infrastructure
    Authentication          : WPA3-Personal
    Encryption              : CCMP
    BSSID 1                 : 00:00:5e:00:53:ba
         Signal             : 81%
         Radio type         : 802.11ac
         Band               : 5 GHz
         Channel            : 149
"""

INTERFACE_FIXTURE = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : MediaTek Wi-Fi 6 MT7921
    Physical address       : e0:0a:f6:b8:4e:ad
    State                  : connected
    SSID                   : CORP-WIFI
    AP BSSID               : 00:00:5e:00:53:ba
    Band                   : 5 GHz
    Channel                : 149
    Authentication         : WPA3-Personal
    Cipher                 : CCMP
    Radio type             : 802.11ac
    Receive rate (Mbps)    : 866.7
    Transmit rate (Mbps)   : 866.7
    Signal                 : 81%
    Rssi                   : -44
"""

# What a localized Windows produces. Same structure, translated labels.
LOCALIZED_FIXTURE = """
Schnittstellenname : WLAN
Es sind derzeit 1 Netzwerke sichtbar.

SSID 1 : Fritzbox
    Netzwerktyp             : Infrastruktur
    Authentifizierung       : WPA2-Personal
    Verschluesselung        : CCMP
    BSSID 1                 : aa:bb:cc:dd:ee:ff
         Signal             : 70%
"""


def _parse(text, monkey_output=None):
    """Run scan_networks() against fixture text instead of a real netsh call."""
    original_run = netsh_wlan._run
    original_available = netsh_wlan.available
    netsh_wlan._run = lambda *a, **k: text
    netsh_wlan.available = lambda: True
    try:
        return netsh_wlan.scan_networks()
    finally:
        netsh_wlan._run = original_run
        netsh_wlan.available = original_available


def _parse_interface(text):
    original_run = netsh_wlan._run
    original_available = netsh_wlan.available
    netsh_wlan._run = lambda *a, **k: text
    netsh_wlan.available = lambda: True
    try:
        return netsh_wlan.connection_info()
    finally:
        netsh_wlan._run = original_run
        netsh_wlan.available = original_available


# Parsing.

def test_every_bssid_is_found():
    nets = _parse(FIXTURE)
    assert set(nets) == {
        "28:41:C6:62:45:F4", "28:41:C6:62:45:F5",
        "14:46:58:44:A9:10", "00:00:5E:00:53:BA",
    }, sorted(nets)


def test_bssids_are_normalized_so_they_match_the_scanner():
    """PyWiFi hands back a trailing colon; netsh does not.

    The two keys have to agree or every lookup misses and the enrichment
    silently does nothing — which is exactly what happened first time.
    """
    nets = _parse(FIXTURE)
    for bssid in nets:
        assert bssid == bssid.upper()
        assert len(bssid) == 17, bssid
        assert not bssid.endswith(":")
    assert netsh_wlan.normalize_bssid("00:00:5e:00:53:ba:") == "00:00:5E:00:53:BA"
    assert netsh_wlan.normalize_bssid("00005E0053BA") == "00:00:5E:00:53:BA"
    assert netsh_wlan.normalize_bssid("not a mac") == ""


def test_per_ssid_security_applies_to_all_of_its_bssids():
    nets = _parse(FIXTURE)
    for bssid in ("28:41:C6:62:45:F4", "28:41:C6:62:45:F5"):
        assert nets[bssid]["encryption"] == "WPA2"
        assert nets[bssid]["cipher"] == "CCMP"
        assert nets[bssid]["auth_type"] == "WPA2-Personal"


def test_security_does_not_leak_into_the_next_network():
    """The open network must not inherit the WPA2 printed above it."""
    nets = _parse(FIXTURE)
    open_ap = nets["14:46:58:44:A9:10"]
    assert open_ap["encryption"] == "OPEN"
    assert open_ap["cipher"] == "None"
    assert open_ap["is_vulnerable"] is True


def test_wpa3_is_distinguished_from_wpa2():
    """The whole reason this module exists: PyWiFi calls this one WPA2."""
    nets = _parse(FIXTURE)
    assert nets["00:00:5E:00:53:BA"]["encryption"] == "WPA3"
    assert nets["00:00:5E:00:53:BA"]["is_vulnerable"] is False


def test_a_hidden_ssid_still_yields_its_bssid():
    nets = _parse(FIXTURE)
    assert nets["00:00:5E:00:53:BA"]["ssid"] == ""


def test_radio_band_and_channel_are_per_bssid():
    nets = _parse(FIXTURE)
    a = nets["28:41:C6:62:45:F4"]
    b = nets["28:41:C6:62:45:F5"]
    assert (a["channel"], a["band"], a["radio_type"]) == (149, "5 GHz", "802.11ac")
    assert (b["channel"], b["band"], b["radio_type"]) == (6, "2.4 GHz", "802.11ax")


def test_station_counts_are_read_including_a_real_zero():
    nets = _parse(FIXTURE)
    assert nets["28:41:C6:62:45:F4"]["connected_stations"] == 3
    # A reported zero is a measurement and must survive as 0, not become None.
    assert nets["14:46:58:44:A9:10"]["connected_stations"] == 0


def test_a_missing_bss_load_is_none_not_zero():
    """"No clients" and "this AP does not publish a count" are different."""
    nets = _parse(FIXTURE)
    assert nets["28:41:C6:62:45:F5"]["connected_stations"] is None
    assert nets["00:00:5E:00:53:BA"]["connected_stations"] is None


def test_channel_utilization_is_read_as_a_percentage():
    nets = _parse(FIXTURE)
    assert nets["28:41:C6:62:45:F4"]["channel_utilization_pct"] == 26
    assert nets["28:41:C6:62:45:F5"]["channel_utilization_pct"] is None


# Failure modes.

def test_localized_output_yields_nothing_rather_than_half_a_record():
    """A partial parse would put gaps in the report that look like findings."""
    nets = _parse(LOCALIZED_FIXTURE)
    for row in nets.values():
        # The BSSID line is not localized, so the row may exist — but it must
        # never carry a security claim derived from a label it could not read.
        assert row["encryption"] is None
        assert row["auth_type"] is None
        assert row["is_vulnerable"] is None


def test_empty_or_failed_netsh_returns_an_empty_dict():
    assert _parse("") == {}
    assert _parse(None) == {}


def test_unknown_authentication_is_not_guessed_into_a_family():
    assert netsh_wlan.auth_to_family("Something Unheard Of") is None
    assert netsh_wlan.auth_to_family("") is None
    assert netsh_wlan.auth_to_family(None) is None


def test_known_authentication_strings_map_to_families():
    cases = {
        "Open": "OPEN",
        "WEP": "WEP",
        "WPA-Personal": "WPA",
        "WPA2-Personal": "WPA2",
        "WPA2-Enterprise": "WPA2",
        "WPA3-Personal": "WPA3",
        "WPA3-Enterprise": "WPA3",
    }
    for text, family in cases.items():
        assert netsh_wlan.auth_to_family(text) == family, text


def test_a_transition_mode_resolves_to_the_strongest_family():
    """An AP offering both must not be reported as the weaker one."""
    assert netsh_wlan.auth_to_family("WPA3-Personal, WPA2-Personal") == "WPA3"


# Connection info.

def test_connection_info_reads_the_associated_ap():
    info = _parse_interface(INTERFACE_FIXTURE)
    assert info["connected"] is True
    assert info["ssid"] == "CORP-WIFI"
    assert info["bssid"] == "00:00:5E:00:53:BA"
    assert info["auth_type"] == "WPA3-Personal"
    assert info["cipher"] == "CCMP"
    assert info["channel"] == 149
    assert info["rssi"] == -44


def test_a_disconnected_adapter_claims_nothing():
    info = _parse_interface(
        "    Name                   : Wi-Fi\n"
        "    State                  : disconnected\n"
    )
    assert info["connected"] is False
    assert info["bssid"] is None
    assert info["ssid"] is None


def test_a_trailing_separator_is_stripped():
    """PyWiFi returns the BSSID with a trailing separator on Windows.

    `wifi.py` used to normalise only the bare twelve-character form and pass
    anything else through, so every address was stored and printed as
    `00:00:5E:00:53:48:` — it reached the telemetry table and the evidence
    register looking like a truncated MAC. It also meant the stored key and the
    key used to match netsh enrichment were different strings.
    """
    assert netsh_wlan.normalize_bssid("00:00:5E:00:53:48:") == "00:00:5E:00:53:48"
    assert netsh_wlan.normalize_bssid("00-00-5E-00-53-48") == "00:00:5E:00:53:48"
    assert netsh_wlan.normalize_bssid("00005e005348") == "00:00:5E:00:53:48"
    assert netsh_wlan.normalize_bssid(" 00:00:5e:00:53:48 ") == "00:00:5E:00:53:48"


def test_an_address_that_is_not_one_is_refused_rather_than_padded():
    """Returning a short string would put a half-MAC in the report."""
    for bad in ("", None, "00:00:5E", "not a mac", "00:00:5E:00:53:48:99"):
        assert netsh_wlan.normalize_bssid(bad) == "", repr(bad)


def _main():
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in tests:
        try:
            fn(); print(f"  PASS  {name}")
        except AssertionError as e:
            failed.append(name); print(f"  FAIL  {name}: {e or 'assertion failed'}")
        except Exception as e:
            failed.append(name); print(f"  ERROR {name}: {type(e).__name__}: {e}")
    print(f"\n{len(tests) - len(failed)}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
