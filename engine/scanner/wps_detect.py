"""LOCKON EWAC — WPS Detection Module

Uses Scapy to sniff 802.11 Beacon frames and extract WPS Information
Elements (Vendor Specific IE with WPS OUI 00:50:F2:04).

Requirements: Npcap installed on Windows.
"""
import threading
import time
import logging

logger = logging.getLogger(__name__)

# WPS OUI: Microsoft WPS (00:50:F2 type 4)
WPS_OUI = b'\x00\x50\xf2\x04'

# WPS Attribute IDs
WPS_ATTR_STATE = 0x1044
WPS_ATTR_LOCKED = 0x1057
WPS_ATTR_VERSION = 0x104A
WPS_ATTR_CONFIG_METHODS = 0x1008
WPS_ATTR_DEVICE_NAME = 0x1011


def _parse_wps_ie(ie_data: bytes) -> dict:
    """Parse WPS Information Element attributes from raw bytes."""
    result = {
        "wps_enabled": True,
        "wps_locked": False,
        "wps_version": None,
        "wps_config_methods": None,
        "wps_device_name": None,
    }
    
    offset = 0
    while offset + 4 <= len(ie_data):
        attr_id = int.from_bytes(ie_data[offset:offset+2], 'big')
        attr_len = int.from_bytes(ie_data[offset+2:offset+4], 'big')
        attr_data = ie_data[offset+4:offset+4+attr_len]
        
        if attr_id == WPS_ATTR_STATE and len(attr_data) >= 1:
            # 0x01 = Not Configured, 0x02 = Configured
            result["wps_enabled"] = attr_data[0] in (0x01, 0x02)
            
        elif attr_id == WPS_ATTR_LOCKED and len(attr_data) >= 1:
            result["wps_locked"] = attr_data[0] == 0x01
            
        elif attr_id == WPS_ATTR_VERSION and len(attr_data) >= 1:
            major = (attr_data[0] >> 4) & 0x0F
            minor = attr_data[0] & 0x0F
            result["wps_version"] = f"{major}.{minor}"
            
        elif attr_id == WPS_ATTR_CONFIG_METHODS and len(attr_data) >= 2:
            methods = int.from_bytes(attr_data[:2], 'big')
            method_names = []
            if methods & 0x0001: method_names.append("USB")
            if methods & 0x0004: method_names.append("Label")
            if methods & 0x0008: method_names.append("Display")
            if methods & 0x0080: method_names.append("Keypad")
            if methods & 0x0100: method_names.append("PBC")
            if methods & 0x4000: method_names.append("Virtual PBC")
            if methods & 0x8000: method_names.append("Physical PBC")
            result["wps_config_methods"] = ", ".join(method_names) if method_names else "Unknown"
            
        elif attr_id == WPS_ATTR_DEVICE_NAME:
            try:
                result["wps_device_name"] = attr_data.decode('utf-8', errors='ignore')
            except Exception:
                pass
        
        offset += 4 + attr_len
    
    return result


class WPSDetector:
    """Scans nearby beacons to detect WPS-enabled access points."""

    def __init__(self, emit_fn):
        self.emit = emit_fn
        self.scanning = False
        self._thread = None
        self._results = {}  # bssid -> wps_info

    def scan(self, interface=None, duration=8):
        """
        Start a WPS detection scan in a background thread.

        WPS presence is read from the beacon information element, which means
        this needs an adapter that hands us other stations' beacons — monitor
        mode. On a managed-mode Windows adapter, which is most of them, not one
        frame arrives and `_results` stays empty.

        "Zero beacons" and "beacons seen, none advertising WPS" are completely
        different statements and the summary now separates them, because the
        report prints this as an observation about the environment. The first is
        an observation about the rig.
        """
        if self.scanning:
            self.emit("wps_error", {"message": "WPS scan already in progress"})
            return

        # Frontend-supplied and previously unvalidated; it bounds a blocking
        # sniff, so a bad value is a hang.
        try:
            duration = float(duration)
        except (TypeError, ValueError):
            duration = 8.0
        duration = max(1.0, min(120.0, duration))

        self.scanning = True
        self._results = {}

        def _scan_worker():
            try:
                from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Elt
            except ImportError:
                self.emit("wps_error", {"message": "Scapy not available. Install Npcap."})
                self.scanning = False
                return

            self.emit("wps_scan_started", {"duration": duration})

            # Every frame the interface hands us, before any filtering.
            stats = {"frames": 0, "beacons": 0}

            def _handle_packet(pkt):
                if not self.scanning:
                    return True  # Stop sniffing

                stats["frames"] += 1
                if not pkt.haslayer(Dot11Beacon):
                    return
                stats["beacons"] += 1

                try:
                    bssid = pkt[Dot11].addr2
                    if not bssid:
                        return
                    bssid = bssid.upper()
                    
                    # Skip if we already have WPS info for this BSSID
                    if bssid in self._results:
                        return
                    
                    # Extract SSID
                    ssid = ""
                    elt = pkt[Dot11Elt]
                    while elt:
                        if elt.ID == 0:  # SSID
                            try:
                                ssid = elt.info.decode('utf-8', errors='ignore')
                            except Exception:
                                pass
                        elt = elt.payload if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt) else None
                    
                    # Search for WPS IE (Vendor Specific, ID=221)
                    elt = pkt[Dot11Elt]
                    wps_found = False
                    while elt:
                        if elt.ID == 221 and hasattr(elt, 'info'):  # Vendor Specific
                            ie_data = bytes(elt.info)
                            if ie_data[:4] == WPS_OUI:
                                wps_info = _parse_wps_ie(ie_data[4:])
                                wps_info["bssid"] = bssid
                                wps_info["ssid"] = ssid
                                self._results[bssid] = wps_info
                                self.emit("wps_ap_found", wps_info)
                                wps_found = True
                                break
                        
                        # Navigate IE chain
                        next_elt = elt.payload if hasattr(elt, 'payload') else None
                        if isinstance(next_elt, Dot11Elt):
                            elt = next_elt
                        else:
                            break
                    
                    # If no WPS IE found, this AP doesn't have WPS
                    if not wps_found and bssid not in self._results:
                        self._results[bssid] = {
                            "bssid": bssid,
                            "ssid": ssid,
                            "wps_enabled": False,
                            "wps_locked": False,
                            "wps_version": None,
                            "wps_config_methods": None,
                            "wps_device_name": None,
                        }
                        
                except Exception as e:
                    logger.debug(f"WPS parse error for packet: {e}")
            
            sniff_error = None
            try:
                # Sniff in one-second slices rather than one long call.
                #
                # `stop_filter` is only evaluated when a packet arrives, so on a
                # quiet link — which is exactly the managed-mode case — the old
                # single `sniff(timeout=duration)` ignored stop() completely and
                # blocked for the full duration. `passive.py` already solved this
                # the same way.
                deadline = time.monotonic() + duration
                while self.scanning and time.monotonic() < deadline:
                    slice_s = min(1.0, deadline - time.monotonic())
                    if slice_s <= 0:
                        break
                    sniff(
                        iface=interface,
                        prn=_handle_packet,
                        stop_filter=lambda _: not self.scanning,
                        timeout=slice_s,
                        store=0
                    )
            except Exception as e:
                sniff_error = str(e)
                self.emit("wps_error", {"message": f"Sniff failed: {sniff_error}"})
            finally:
                self.scanning = False
                wps_enabled_count = sum(
                    1 for r in self._results.values() if r.get("wps_enabled")
                )
                wps_locked_count = sum(
                    1 for r in self._results.values()
                    if r.get("wps_enabled") and r.get("wps_locked")
                )
                # An access point is only *measured* for WPS if its beacon was
                # parsed. Zero beacons means the radio told us nothing, and the
                # summary has to say which of the two happened — otherwise the
                # report prints "no access point advertised WPS" about a scan
                # that never saw an access point at all.
                inconclusive = stats["beacons"] == 0
                payload = {
                    "total_aps": len(self._results),
                    "wps_enabled": wps_enabled_count,
                    "wps_locked": wps_locked_count,
                    "results": list(self._results.values()),
                    "frames_seen": stats["frames"],
                    "beacons_seen": stats["beacons"],
                    "inconclusive": inconclusive,
                    "error": sniff_error,
                }
                if inconclusive:
                    payload["reason"] = (
                        f"No 802.11 beacon was captured in {duration:g}s"
                        + (" — not one frame of any kind arrived." if stats["frames"] == 0
                           else f" (out of {stats['frames']} frame(s) seen).")
                    )
                    payload["caveat"] = (
                        "WPS is read from the beacon information element, so this scan needs an "
                        "adapter in monitor mode. Nothing here describes the networks around you: "
                        "it is not evidence that WPS is disabled anywhere. Re-run with a "
                        "monitor-mode adapter before recording any conclusion."
                    )
                else:
                    payload["caveat"] = (
                        f"{len(self._results)} access point(s) had a beacon parsed and are the only "
                        "ones this result covers. An access point whose beacon was not captured in "
                        "this window is unmeasured, not WPS-free."
                    )
                self.emit("wps_scan_complete", payload)

        self._thread = threading.Thread(target=_scan_worker, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the WPS scan."""
        self.scanning = False

    def get_results(self) -> dict:
        """Return current WPS detection results."""
        return self._results
