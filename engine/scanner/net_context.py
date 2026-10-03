"""LOCKON EWAC — which network this machine is actually on.

Why this exists, and what it deliberately does not claim.

A Wi-Fi scan reads beacon and probe-response frames. Those are layer 2: they
carry a BSSID, an SSID and a security advertisement, and **no IP address**. An
access point across the street has no IP that this machine could know, and a
column promising one would be empty forever.

There is exactly one access point for which an IP can be stated honestly: the
one this machine is associated with. For that AP the default gateway is a real,
verifiable address on a real network, and the ARP entry for it gives a MAC that
can be compared against the BSSID.

That comparison has three outcomes and they are reported as three different
things, because collapsing them would turn a guess into a claim:

  * **The gateway MAC equals the connected BSSID.** The AP is the gateway. This
    is common on consumer routers and is the strongest statement available.
  * **They differ.** Also normal — an AP bridging its radio and its LAN often
    uses adjacent MACs, and in an enterprise deployment the gateway is an
    entirely different box behind the AP. This machine is on the network reached
    through that AP, which is all that can be said.
  * **No association, or no default route.** Nothing is claimed at all.

Everything here is read-only: `netsh`, `route print` and the existing ARP cache.
Nothing is transmitted, and no address is probed.
"""
import re
import subprocess
import sys

from . import netsh_wlan


def _no_window_kwargs():
    if sys.platform == "win32":
        return {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
    return {}


def _run(args, timeout=6):
    try:
        result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=timeout, **_no_window_kwargs())
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return result.stdout or ""


def default_route() -> dict:
    """The active default route: which gateway, out of which local address.

    `route print 0.0.0.0` is used rather than scraping `ipconfig` because this
    machine has VPN, VMware and Wi-Fi Direct adapters that all report gateways;
    the routing table says which one traffic actually takes.
    """
    out = {"gateway_ip": None, "local_ip": None, "metric": None}
    if sys.platform == "win32":
        text = _run(["route", "print", "0.0.0.0"])
        if not text:
            return out
        # Lowest metric wins, and only rows under "Active Routes".
        #
        # This took the first textually matching row and broke, while the docstring
        # above claims "the routing table says which one traffic actually takes" --
        # which selecting by print order does not implement. The metric column was
        # named in the inline comment and never read. With concurrent VPN, VMware and
        # Wi-Fi Direct default routes, the row this landed on was whichever Windows
        # happened to print first, and `route print` does not contract an ordering
        # within a destination.
        #
        # It had no section awareness either. `route print 0.0.0.0` ends with a
        # "Persistent Routes:" block whose rows satisfy the same shape, and whose
        # metric column reads "Default" rather than a number. Those were shadowed only
        # because an Active Routes row usually appears first and broke the loop -- so
        # with no active default route (adapter down, VPN dropped, no lease) the parser
        # fell through to a *configured* gateway and published it as the live one,
        # with `local_ip` None. `describe()` would then say this machine reaches a
        # gateway it has no route to.
        in_active = False
        best = None
        for line in text.splitlines():
            stripped = line.strip()
            lowered = stripped.lower()
            if lowered.startswith("active routes"):
                in_active = True
                continue
            # Any other section heading ends the active block: "Persistent Routes:",
            # and on a dual-stack machine "IPv6 Route Table".
            if in_active and lowered.endswith("routes:") and not lowered.startswith("active"):
                break
            if in_active and lowered.startswith("persistent"):
                break
            if not in_active:
                continue

            parts = stripped.split()
            # "0.0.0.0  0.0.0.0  <gateway>  <interface>  <metric>"
            if len(parts) < 5 or parts[0] != "0.0.0.0" or parts[1] != "0.0.0.0":
                continue
            gateway, local, metric_text = parts[2], parts[3], parts[4]
            if gateway.count(".") != 3 or gateway == "0.0.0.0":
                continue
            try:
                metric = int(metric_text)
            except ValueError:
                # "Default", or anything else non-numeric, is not an active-route
                # metric. Skipped rather than ranked as metric 0.
                continue
            if best is None or metric < best[0]:
                best = (metric, gateway, local if local.count(".") == 3 else None)

        if best is not None:
            out["metric"], out["gateway_ip"], out["local_ip"] = best
        return out

    text = _run(["ip", "route", "show", "default"])
    if text:
        m = re.search(r"default via (\d+\.\d+\.\d+\.\d+).*?src (\d+\.\d+\.\d+\.\d+)", text)
        if m:
            out["gateway_ip"], out["local_ip"] = m.group(1), m.group(2)
        else:
            m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", text)
            if m:
                out["gateway_ip"] = m.group(1)
    return out


def arp_lookup(ip: str):
    """MAC for an IP from the OS ARP cache, or None. Sends nothing itself."""
    if not ip:
        return None
    if sys.platform == "win32":
        text = _run(["arp", "-a", ip], timeout=4)
        if not text:
            return None
        m = re.search(
            re.escape(ip) + r"\s+([0-9a-fA-F]{2}(?:[-:][0-9a-fA-F]{2}){5})", text)
        return netsh_wlan.normalize_bssid(m.group(1)) if m else None

    text = _run(["ip", "neigh", "show", ip], timeout=4)
    if not text:
        return None
    m = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", text)
    return netsh_wlan.normalize_bssid(m.group(1)) if m else None


def _subnet_of(ip: str):
    """The /24 the address sits in. A display aid, not a real netmask read."""
    if not ip or ip.count(".") != 3:
        return None
    a, b, c, _d = ip.split(".")
    return f"{a}.{b}.{c}.0/24"


def describe() -> dict:
    """Full picture of the network this machine is on, for the UI and report."""
    wireless = netsh_wlan.connection_info()
    route = default_route()
    gateway_ip = route.get("gateway_ip")
    local_ip = route.get("local_ip")
    gateway_mac = arp_lookup(gateway_ip) if gateway_ip else None
    bssid = wireless.get("bssid")

    gateway_is_ap = None
    if gateway_mac and bssid:
        gateway_is_ap = gateway_mac == bssid

    # Do the two halves even describe the same adapter?
    #
    # `wireless` comes from `netsh wlan show interfaces` and `route` from the routing
    # table, and nothing compared them. With Wi-Fi associated while Ethernet or a VPN
    # holds the default route -- the ordinary state on a docked rig, and this machine
    # has an OpenVPN TAP, a Tailscale interface and two VMnets -- the note below
    # asserted that the machine "reaches <ethernet gateway> through <wifi bssid>", and
    # `gateway_is_ap` compared a MAC from one adapter against a BSSID from another.
    #
    # The module docstring stakes its whole purpose on this being the one access point
    # for which an IP can be stated honestly, which is exactly what the missing check
    # broke. The subnet is the available evidence: a gateway on a different subnet from
    # the wireless adapter's own address is not reached through it.
    # The wireless adapter's own IPv4, asked for by name.
    #
    # This read `wireless.get("local_ip")`, which no producer sets -- `netsh wlan show
    # interfaces` reports no layer-3 address -- so the strong test never ran. Control
    # always fell to a weak test comparing the route's local address against its own
    # gateway's subnet, which is true for essentially every default route by
    # construction. `same_adapter: true` was therefore published as a positive claim
    # that nothing had measured, and the docked-rig case this check exists for still
    # asserted that the machine reaches an Ethernet gateway "through" a Wi-Fi BSSID.
    wireless_ip = (wireless.get("local_ip")
                   or netsh_wlan.adapter_ipv4(wireless.get("interface")))
    same_path = None
    if local_ip and wireless_ip:
        same_path = _subnet_of(local_ip) == _subnet_of(wireless_ip)
    # No weak fallback. Without the wireless adapter's address there is nothing to
    # compare, and `None` says so -- where a guess that happens to be True would
    # license the cross-adapter note below.

    if same_path is False:
        # Stated, not guessed at. Two adapters, two facts, no claim joining them.
        gateway_is_ap = None
        note = (f"This machine is associated with {bssid}, and its default route goes "
                f"to {gateway_ip} from {local_ip} — a different interface. No "
                f"statement is made about reaching that gateway through the access "
                f"point, because the two were measured on different adapters.")
        return {
            "connected": bool(wireless.get("connected")),
            "ssid": wireless.get("ssid"),
            "bssid": bssid,
            "auth_type": wireless.get("auth_type"),
            "cipher": wireless.get("cipher"),
            "radio_type": wireless.get("radio_type"),
            "channel": wireless.get("channel"),
            "rssi": wireless.get("rssi"),
            "rx_mbps": wireless.get("rx_mbps"),
            "tx_mbps": wireless.get("tx_mbps"),
            "interface": wireless.get("interface"),
            "gateway_ip": gateway_ip,
            "gateway_mac": gateway_mac,
            "gateway_is_ap": None,
            "local_ip": local_ip,
            "subnet": _subnet_of(local_ip),
            "metric": route.get("metric"),
            "same_adapter": False,
            "note": note,
        }

    if not wireless.get("connected"):
        note = ("Not associated with any access point, so no IP can be attributed "
                "to one. A beacon frame carries no layer 3 address.")
    elif not gateway_ip:
        note = (f"Associated with {bssid}, but this machine has no default route, "
                "so there is no gateway to report.")
    elif gateway_is_ap:
        note = (f"The gateway {gateway_ip} answers on {gateway_mac}, which is the "
                f"BSSID this machine is associated with. This access point is the "
                f"gateway.")
    elif gateway_mac:
        note = (f"This machine reaches {gateway_ip} through {bssid}, but the "
                f"gateway answers on {gateway_mac} — a different interface. The "
                f"access point is the way in, not necessarily the gateway itself.")
    else:
        note = (f"Associated with {bssid} and routing through {gateway_ip}, but "
                "that address has no ARP entry yet, so it cannot be tied to a MAC.")

    return {
        "connected": bool(wireless.get("connected")),
        "ssid": wireless.get("ssid"),
        "bssid": bssid,
        "auth_type": wireless.get("auth_type"),
        "cipher": wireless.get("cipher"),
        "radio_type": wireless.get("radio_type"),
        "channel": wireless.get("channel"),
        "rssi": wireless.get("rssi"),
        "rx_mbps": wireless.get("rx_mbps"),
        "tx_mbps": wireless.get("tx_mbps"),
        "interface": wireless.get("interface"),
        "local_ip": local_ip,
        "subnet": _subnet_of(local_ip),
        # The route's metric, which is what chose it among the default routes on
        # this machine. Carried through so the method appendix can say *which*
        # route the sweep's subnet was derived from, rather than asserting there
        # was only one.
        "metric": route.get("metric"),
        # True when the wireless adapter and the default route were measured on the
        # same path, None when there was not enough to tell. See the check above.
        "same_adapter": same_path,
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac,
        # None means "could not be determined", which is not the same as False.
        "gateway_is_ap": gateway_is_ap,
        "note": note,
    }
