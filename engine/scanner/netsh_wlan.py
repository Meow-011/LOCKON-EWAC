"""LOCKON EWAC — Windows `netsh wlan` enrichment.

Why this exists.

PyWiFi is the scanner's source of truth for what is on the air, but its Windows
backend does not fill in everything the driver actually knows:

  * `profile.cipher` is **always 0** (CIPHER_TYPE_NONE), for every network,
    including WPA3 ones. So `cipher` and `auth_type` were declared in the schema,
    in the database and in the frontend types, and were never once populated.
  * `profile.akm` reports `[4]` (WPA2PSK) for a WPA3-Personal network, so the
    scanner labelled WPA3 access points as WPA2. That is not cosmetic: it
    understates a correctly-secured network in a report, and it is the same
    field the rogue-AP scorer uses to decide what a transition pair looks like.

`netsh wlan show networks mode=bssid` asks the same driver and gets the answers
PyWiFi drops — per-SSID Authentication and Encryption, per-BSSID radio type,
band, channel, and (when the AP advertises BSS Load) the number of stations
currently associated. That last one is a client count without monitor mode.

Nothing here transmits. It reads the OS's existing scan cache.

**Failure is silent and total, never partial.** `netsh` output is localized: on a
Thai or German Windows the field labels differ and the parse yields nothing.
That is handled by returning an empty dict, so the caller keeps PyWiFi's values
rather than receiving half-filled records — a scan that quietly loses the
encryption of some access points and not others is worse than one that never
had it.
"""
import platform
import re
import subprocess
import sys

#: Authentication strings seen from netsh, mapped to the encryption family the
#: rest of the tool uses. Ordered strongest-first so a transition mode that
#: lists more than one ("WPA3-Personal, WPA2-Personal") resolves to the
#: strongest the AP actually offers.
_AUTH_FAMILIES = [
    ("WPA3", ("WPA3",)),
    ("WPA2", ("WPA2", "RSNA")),
    ("WPA", ("WPA",)),
    ("WEP", ("WEP", "SHARED")),
    ("OPEN", ("OPEN", "NONE")),
]

#: Families the tool treats as exploitable, matching the live scanner's rule.
_VULNERABLE = {"OPEN", "WEP", "WPA"}


def _no_window_kwargs():
    if sys.platform == "win32":
        return {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
    return {}


def available() -> bool:
    return sys.platform == "win32"


def normalize_bssid(value: str) -> str:
    """Upper-case colon-separated MAC, so netsh and PyWiFi keys always match."""
    clean = "".join(c for c in (value or "").upper() if c in "0123456789ABCDEF")
    if len(clean) != 12:
        return ""
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


def auth_to_family(auth: str):
    """Map a netsh Authentication string to OPEN/WEP/WPA/WPA2/WPA3.

    Returns None for anything unrecognised — an unknown authentication string is
    reported as unknown rather than guessed into the nearest family, because the
    guess would land in the report as a security posture.
    """
    text = (auth or "").upper()
    if not text:
        return None
    for family, needles in _AUTH_FAMILIES:
        if any(n in text for n in needles):
            return family
    return None


def _run(args, timeout=8):
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=timeout, **_no_window_kwargs())
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return result.stdout or ""


def _field(line):
    """Split a `Label : value` line. Returns (label, value) or None."""
    if ":" not in line:
        return None
    label, _, value = line.partition(":")
    return label.strip(), value.strip()


def scan_networks() -> dict:
    """Per-BSSID enrichment from the OS's current scan cache.

    Returns `{bssid: {...}}`, empty when netsh is unavailable or its output
    could not be parsed.
    """
    if not available():
        return {}
    out = _run(["netsh", "wlan", "show", "networks", "mode=bssid"])
    if not out:
        return {}

    networks = {}
    ssid = None
    auth = None
    cipher = None
    current = None

    for raw in out.splitlines():
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        # `SSID 7 : name` — starts a new network block and clears the per-SSID
        # security values so they can never leak into the following network.
        m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", stripped)
        if m:
            ssid = m.group(1).strip()
            auth = None
            cipher = None
            current = None
            continue

        m = re.match(r"^BSSID\s+\d+\s*:\s*(.+)$", stripped)
        if m:
            bssid = normalize_bssid(m.group(1))
            if not bssid:
                current = None
                continue
            family = auth_to_family(auth)
            current = {
                "ssid": ssid,
                "auth_type": auth,
                "cipher": cipher,
                "encryption": family,
                "is_vulnerable": (family in _VULNERABLE) if family else None,
                "radio_type": None,
                "band": None,
                "channel": None,
                "connected_stations": None,
                "channel_utilization_pct": None,
                "source": "netsh",
            }
            networks[bssid] = current
            continue

        parsed = _field(stripped)
        if not parsed:
            continue
        label, value = parsed

        if current is None:
            # Still in the per-SSID header.
            if label == "Authentication":
                auth = value
            elif label == "Encryption":
                cipher = value
            continue

        if label == "Radio type":
            current["radio_type"] = value or None
        elif label == "Band":
            current["band"] = value or None
        elif label == "Channel":
            try:
                current["channel"] = int(value)
            except ValueError:
                pass
        elif label == "Connected Stations":
            # Only meaningful when the AP advertises BSS Load; absent otherwise,
            # and absent is left as None rather than 0 — "no clients" and "the
            # AP does not report client counts" are different findings.
            try:
                current["connected_stations"] = int(value)
            except ValueError:
                pass
        elif label == "Channel Utilization":
            m = re.search(r"\((\d+)\s*%\)", value)
            if m:
                current["channel_utilization_pct"] = int(m.group(1))

    return networks


#: One adapter's worth of connection fields, all unset.
#:
#: Hoisted so `connection_info` can build one of these per block instead of filling a
#: single shared dict. A disconnected block carries no SSID or BSSID lines, so with a
#: shared dict its State overwrote a connected adapter's while that adapter's SSID,
#: BSSID, band, channel, auth and cipher stayed behind -- `connected: false` beside a
#: populated BSSID.
EMPTY_CONNECTION = {
    "connected": False,
    "ssid": None,
    "bssid": None,
    "auth_type": None,
    "cipher": None,
    "radio_type": None,
    "band": None,
    "channel": None,
    "rssi": None,
    "rx_mbps": None,
    "tx_mbps": None,
    "interface": None,
    "state": None,
}


def adapter_ipv4(interface_name):
    """
    The IPv4 address configured on a named adapter, or None.

    `netsh wlan show interfaces` reports no layer-3 address at all, which is why this
    exists separately. `net_context.describe()` needs it to answer whether the wireless
    adapter and the default route are the same path -- and without it that check read
    `wireless.get("local_ip")`, a key no producer ever set, so the strong test never
    ran and `same_adapter` came out True on the weak one for essentially every route.

    English-label parsing, like the rest of this module, and the module docstring
    already records that as a deliberate limitation: on a localised Windows this returns
    None, and the caller must treat None as "not established" rather than as agreement.
    """
    if not interface_name:
        return None
    out = _run(["netsh", "interface", "ip", "show", "address", str(interface_name)],
               timeout=6)
    if not out:
        return None
    for raw in out.splitlines():
        parsed = _field(raw.strip())
        if not parsed:
            continue
        label, value = parsed
        # "IP Address" on Windows 10/11; "IP-Address" has appeared in older builds.
        if label.replace("-", " ") == "IP Address" and value.count(".") == 3:
            return value
    return None


def connection_info() -> dict:
    """What the adapter is currently associated with, if anything.

    The connected BSSID is the one access point for which an IP address can
    honestly be reported: it is the network this machine is actually on. For
    every other access point in a scan there is no IP to know — a beacon frame
    carries no layer 3 address.
    """
    if not available():
        return dict(EMPTY_CONNECTION)
    out = _run(["netsh", "wlan", "show", "interfaces"], timeout=6)
    if not out:
        return dict(EMPTY_CONNECTION)

    # One result per adapter, then the connected one is chosen.
    #
    # This was a single flat dict filled by a single flat loop, with "Name" treated as
    # just another field. `netsh wlan show interfaces` prints one block per wireless
    # adapter, and a disconnected block prints Name/Description/GUID/Physical
    # address/State and *no* SSID or AP BSSID lines. So with two radios -- this machine
    # reports three -- a disconnected block arriving after the connected one overwrote
    # `state` and `connected` to false while `ssid`, `bssid`, `band`, `channel`,
    # `auth_type`, `cipher` and `rssi` persisted from the connected adapter, and
    # `interface` was misattributed to the disconnected one.
    #
    # `net_context.describe()` consumes this, so it emitted "Not associated with any
    # access point" while the payload carried that BSSID, SSID and channel.
    blocks = []
    current = None
    for raw in out.splitlines():
        parsed = _field(raw.strip())
        if not parsed:
            continue
        label, value = parsed
        if label == "Name":
            # A block boundary, not just another field. `scan_networks` in this same
            # file resets per block and says why; this loop did not.
            current = dict(EMPTY_CONNECTION)
            current["interface"] = value
            blocks.append(current)
            continue
        if current is None:
            # Fields before the first Name: not attributable to an adapter.
            continue
        info = current
        if label == "State":
            info["state"] = value
            info["connected"] = value.lower() == "connected"
        elif label == "SSID":
            info["ssid"] = value
        elif label == "AP BSSID":
            info["bssid"] = normalize_bssid(value) or None
        elif label == "Authentication":
            info["auth_type"] = value
        elif label == "Cipher":
            info["cipher"] = value
        elif label == "Radio type":
            info["radio_type"] = value
        elif label == "Band":
            info["band"] = value
        elif label == "Channel":
            try:
                info["channel"] = int(value)
            except ValueError:
                pass
        elif label == "Rssi":
            try:
                info["rssi"] = int(value)
            except ValueError:
                pass
        elif label == "Receive rate (Mbps)":
            info["rx_mbps"] = value
        elif label == "Transmit rate (Mbps)":
            info["tx_mbps"] = value

    if not blocks:
        return dict(EMPTY_CONNECTION)
    # The connected adapter, or the first one when none is connected -- so the result
    # always describes exactly one adapter rather than a blend of several.
    for block in blocks:
        if block.get("connected"):
            return block
    return blocks[0]


def describe() -> dict:
    """Whether this enrichment is in force, for the report's method appendix."""
    networks = scan_networks() if available() else {}
    return {
        "available": available(),
        "platform": platform.system(),
        "networks_enriched": len(networks),
        "note": (
            "Authentication, cipher and associated-station counts come from "
            "`netsh wlan show networks mode=bssid`. PyWiFi's Windows backend "
            "reports cipher as NONE for every network and misreports WPA3 as "
            "WPA2, so those fields would otherwise be absent or wrong."
            if available() else
            "netsh is Windows-only. On this platform encryption comes from the "
            "scanner backend alone, and cipher/auth_type are not available."
        ),
    }
