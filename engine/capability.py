"""LOCKON EWAC — Hardware capability probe

Why this exists.

The 802.11 modules (STRIKE, handshake capture, PMKID, probe monitor, passive
SIGINT) all need Npcap and, for most of them, an adapter that can enter monitor
mode. Until now the only precondition anything checked was "can I import
scapy", which succeeds on a machine with no Npcap at all.

That is the one gap in this tool that can produce a *confidently wrong report*:
a deauth that silently sends nothing, or a ten-minute capture on a managed-mode
adapter, looks exactly like "the target resisted the attack". A null result that
cannot be distinguished from evidence of security is worse than no result, so
the operator has to be told what their hardware cannot do *before* they run it.

The pattern is copied from detect_hashcat(), which already does this correctly
for the cracking side.

Every probe is read-only. Nothing here transmits, and nothing here changes
adapter state — a capability check that reconfigured the radio would be its own
kind of surprise.
"""
import os
import platform
import subprocess
import sys


def _no_window_kwargs():
    if sys.platform == "win32":
        return {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
    return {}


def is_admin() -> bool:
    """Elevation state. Raw injection and IP forwarding need it on Windows."""
    try:
        if sys.platform == "win32":
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False


def check_scapy() -> dict:
    try:
        import scapy
        version = getattr(scapy, "__version__", "unknown")
        return {"available": True, "version": version}
    except Exception as e:
        return {"available": False, "error": str(e),
                "hint": "pip install scapy  (required for all 802.11 features)"}


def check_npcap() -> dict:
    """Detect Npcap / WinPcap on Windows.

    Checked three ways because any one of them can be misleading on its own:
    the driver files, the registry service entry, and whether scapy's L2 socket
    can actually be constructed.
    """
    if sys.platform != "win32":
        # On Linux/macOS raw capture is a kernel + privileges question, not a
        # driver install, so report accordingly rather than claiming "missing".
        return {
            "available": None,
            "platform": platform.system(),
            "note": "Npcap is Windows-only. On this platform raw capture depends on privileges (root/CAP_NET_RAW).",
        }

    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    driver_paths = [
        os.path.join(system_root, "System32", "Npcap", "npcap.sys"),
        os.path.join(system_root, "System32", "drivers", "npcap.sys"),
        os.path.join(system_root, "System32", "wpcap.dll"),
        os.path.join(system_root, "SysWOW64", "wpcap.dll"),
    ]
    found_files = [p for p in driver_paths if os.path.exists(p)]

    service_present = False
    service_state = None
    try:
        result = subprocess.run(["sc", "query", "npcap"], capture_output=True,
                                text=True, encoding="utf-8", errors="replace", timeout=5, **_no_window_kwargs())
        if result.returncode == 0:
            service_present = True
            for line in result.stdout.splitlines():
                if "STATE" in line:
                    service_state = line.split(":", 1)[-1].strip()
                    break
    except Exception:
        pass

    # A registered service is not a running one.
    #
    # This was `bool(found_files) or service_present`, where `service_present`
    # means only that `sc query npcap` exited 0 -- true for a service that is
    # installed and stopped. `service_state` was parsed directly above and then
    # never read by anything. So a stopped Npcap, or a leftover WinPcap
    # `wpcap.dll` from an old install, reported `npcap.available: true`.
    service_running = bool(service_state and "RUNNING" in service_state.upper())
    available = bool(found_files) or service_running
    out = {
        "available": available,
        "driver_files": found_files,
        "service_present": service_present,
        "service_state": service_state,
        "service_running": service_running,
    }
    if service_present and not service_running:
        out["note"] = (
            f"The Npcap service is installed but its state is {service_state or 'unknown'}. "
            "Raw capture will fail until it is running."
        )
    if not available:
        out["hint"] = ("Npcap is not installed. Install it from https://npcap.com "
                       "with 'Support raw 802.11 traffic' enabled, then restart LOCKON.")
    return out


def check_raw_socket(interface: str = None) -> dict:
    """Can scapy actually open a layer-2 socket on `interface`?

    Npcap files can be present while the install is broken or lacks the raw
    802.11 option, so probe the capability itself rather than trusting the
    driver's presence.

    `interface` is the adapter the capture will really use, and it matters.
    This took no argument, so `conf.L2socket()` bound `conf.iface` -- whatever
    carries the default route, typically the Ethernet port on a docked rig. The
    result then drove `ready` for passive_sigint, probe_monitor,
    handshake_capture, pmkid_capture, strike_deauth and mitm, every one of which
    sniffs the operator-selected adapter instead (`offensive/capture.py` passes
    `iface=interface`).

    So with the capture dongle unplugged, or on the wrong driver, while Npcap
    worked fine on Ethernet, the probe reported every feature `ready: true`. The
    cost of that is in this module's own caveats: "Without monitor mode a capture
    returns no EAPOL. That is NOT evidence the target is secure." The gate meant
    to tell the operator that in advance was answering about a different adapter.

    The interface actually probed is returned either way, so a `ready` can be
    attributed to something rather than taken on trust.
    """
    try:
        from scapy.all import conf
        sock_cls = getattr(conf, "L2socket", None)
        if sock_cls is None:
            return {"available": False, "error": "scapy has no L2socket configured",
                    "probed_interface": interface}
        # Constructing and immediately closing is enough: it fails loudly when
        # the capture driver is missing, and it puts nothing on the wire.
        probed = interface or getattr(conf, "iface", None)
        s = sock_cls(iface=interface) if interface else sock_cls()
        try:
            s.close()
        except Exception:
            pass
        return {"available": True, "probed_interface": str(probed) if probed else None}
    except Exception as e:
        return {"available": False, "error": str(e),
                "probed_interface": interface or str(getattr(_scapy_conf(), "iface", None) or ""),
                "hint": ("Raw layer-2 capture is unavailable on "
                         f"{interface or 'the default interface'}. "
                         "Usually Npcap missing, the wrong adapter selected, or LOCKON not elevated.")}


def _scapy_conf():
    """scapy's conf, or a stand-in, so the error path above cannot itself raise."""
    try:
        from scapy.all import conf
        return conf
    except Exception:
        return type("_NoConf", (), {"iface": None})()


def list_interfaces() -> list:
    """Interfaces scapy can see, with whatever detail it exposes."""
    try:
        from scapy.all import get_working_ifaces
        out = []
        for iface in get_working_ifaces():
            out.append({
                "name": getattr(iface, "name", str(iface)),
                "description": getattr(iface, "description", None),
                "mac": getattr(iface, "mac", None),
                "index": getattr(iface, "index", None),
            })
        return out
    except Exception:
        try:
            from scapy.all import get_if_list
            return [{"name": n} for n in get_if_list()]
        except Exception:
            return []


def check_wifi_scan() -> dict:
    """Can the managed-mode scanner run at all?

    `probe()` reported `wifi_scan: {"ready": True}` as a constant, which is the
    one kind of statement this module exists to stop. Managed-mode scanning does
    not need Npcap, but it does need pywifi to import and it does need at least
    one WLAN interface — on a machine with no wireless adapter, or with the
    WLAN AutoConfig service stopped, the scan returns nothing while the
    capability report says it is ready. An empty scan that reads as "no access
    points here" is the same failure mode as a capture that finds no EAPOL.
    """
    try:
        import pywifi
    except Exception as e:
        return {"ready": False, "error": f"pywifi is unavailable: {type(e).__name__}: {e}",
                "hint": "pip install pywifi comtypes"}
    try:
        interfaces = pywifi.PyWiFi().interfaces()
    except Exception as e:
        return {"ready": False, "error": f"the WLAN interface list could not be read: {type(e).__name__}: {e}",
                "hint": "On Windows this usually means the WLAN AutoConfig service is stopped."}
    if not interfaces:
        return {"ready": False, "error": "no wireless interface was found",
                "hint": "Managed-mode scanning needs a Wi-Fi adapter. A scan would return nothing, "
                        "which is not the same as there being no access points nearby."}
    return {"ready": True, "interface_count": len(interfaces),
            "interfaces": [getattr(i, "name", lambda: str(i))() if callable(getattr(i, "name", None))
                           else str(getattr(i, "name", i)) for i in interfaces]}


def check_monitor_mode() -> dict:
    """Report monitor-mode support as honestly as the platform allows.

    On Windows this genuinely cannot be determined reliably without attempting
    to switch the adapter, which is intrusive and can drop the operator's own
    connection. So this does NOT claim a yes/no. It reports what can be checked
    — Npcap's raw-802.11 option and the adapter list — and says plainly that
    confirmation requires a test capture.

    Claiming "monitor mode: supported" on a guess would recreate exactly the
    problem this module exists to prevent.
    """
    if sys.platform != "win32":
        supported = None
        note = "On Linux, check with `iw list` for 'monitor' under supported interface modes."
        return {"supported": supported, "determinable": False, "note": note}

    npcap = check_npcap()
    raw = check_raw_socket()

    if not npcap.get("available"):
        return {
            "supported": False,
            "determinable": True,
            "reason": "Npcap is not installed, so raw 802.11 capture is impossible regardless of the adapter.",
        }
    if not raw.get("available"):
        return {
            "supported": False,
            "determinable": True,
            "reason": f"Raw layer-2 socket could not be opened: {raw.get('error')}",
        }
    return {
        "supported": None,
        "determinable": False,
        "note": ("Npcap and raw capture are available. Whether this specific adapter can enter "
                 "monitor mode cannot be confirmed without a live test capture — most built-in "
                 "Windows adapters cannot. Run a short capture against a known AP to confirm."),
    }


def probe(interface: str = None) -> dict:
    """Full capability report, and what each shortfall actually blocks.

    `interface` is the adapter the operator has selected for capture. Without it
    the raw-socket test binds whatever carries the default route and then answers
    on behalf of six features that use a different adapter entirely; see
    `check_raw_socket`.
    """
    scapy_info = check_scapy()
    npcap = check_npcap() if scapy_info["available"] else {"available": False, "error": "scapy unavailable"}
    raw = check_raw_socket(interface) if scapy_info["available"] else {"available": False, "error": "scapy unavailable"}
    monitor = check_monitor_mode() if scapy_info["available"] else {"supported": False, "determinable": True,
                                                                    "reason": "scapy unavailable"}
    admin = is_admin()

    raw_ok = bool(raw.get("available"))
    wifi_scan = check_wifi_scan()

    # What the operator is actually allowed to trust, per feature.
    features = {
        "wifi_scan": {
            "ready": bool(wifi_scan.get("ready")),
            "requires": "Windows Wi-Fi API (PyWiFi) and a wireless adapter",
            "note": "Managed-mode scanning works without Npcap.",
            "caveat": "Without an adapter a scan returns an empty list, which is not "
                      "evidence that no access points are present.",
            **({"error": wifi_scan["error"]} if wifi_scan.get("error") else {}),
            **({"hint": wifi_scan["hint"]} if wifi_scan.get("hint") else {}),
        },
        "passive_sigint": {
            "ready": raw_ok,
            "requires": "Npcap (managed mode is sufficient for broadcast traffic)",
        },
        "probe_monitor": {
            "ready": raw_ok,
            "requires": "Npcap + monitor-mode adapter",
            "caveat": "Without monitor mode this will capture nothing and report zero clients.",
        },
        "handshake_capture": {
            "ready": raw_ok,
            "requires": "Npcap + monitor-mode adapter",
            "caveat": "Without monitor mode a capture returns no EAPOL. That is NOT evidence the target is secure.",
        },
        "pmkid_capture": {
            "ready": raw_ok,
            "requires": "Npcap + monitor-mode adapter",
            "caveat": "Without monitor mode this times out. That is NOT evidence the target is secure.",
        },
        "strike_deauth": {
            "ready": raw_ok and admin,
            "requires": "Npcap + monitor-mode adapter + Administrator",
            "caveat": "Frames may be silently dropped without monitor mode or elevation.",
        },
        "mitm": {
            "ready": raw_ok and admin,
            "requires": "Npcap + Administrator (IP forwarding needs elevation)",
            "caveat": "Without elevation IP forwarding fails and the victim's traffic is blackholed.",
        },
    }

    blocking = [name for name, f in features.items() if not f["ready"]]

    return {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "python": platform.python_version(),
        "elevated": admin,
        "scapy": scapy_info,
        "npcap": npcap,
        "raw_socket": raw,
        # What the raw-socket answer is about. A `ready` with no adapter named is
        # an answer about the default route, which is how an unplugged capture
        # dongle used to report every feature as available.
        "capture_interface": raw.get("probed_interface"),
        "capture_interface_requested": interface,
        "monitor_mode": monitor,
        "wifi_scan": wifi_scan,
        "interfaces": list_interfaces() if scapy_info["available"] else [],
        "features": features,
        "unavailable_features": blocking,
        "summary": (
            "Every feature this probe can check is available." if not blocking
            else f"{len(blocking)} feature(s) unavailable on this hardware/privilege level."
        ),
    }
