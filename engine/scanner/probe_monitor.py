"""LOCKON EWAC — WiFi Client Probe Request Monitor
Monitors 802.11 Probe Request frames to identify client devices
and the SSIDs they are searching for.
Requires: Monitor-mode Wi-Fi adapter + Npcap
"""
import threading
from datetime import datetime


class ProbeMonitor:
    def __init__(self, ipc_handler):
        self.ipc = ipc_handler
        self.monitoring = False
        self.monitor_thread = None
        self.clients = {}        # MAC → {"ssids": set(), "first_seen": str, "last_seen": str, "count": int}
        self._lock = threading.Lock()

    def start(self, interface=None):
        """Start monitoring for probe requests."""
        if self.monitoring:
            return

        self.monitoring = True
        self.clients = {}
        self.ipc.emit("probe_monitor_started", {"interface": interface})

        def _monitor_loop():
            try:
                self._run_monitor(interface)
            finally:
                self.monitoring = False
                self.ipc.emit("probe_monitor_stopped", {
                    "total_clients": len(self.clients)
                })

        self.monitor_thread = threading.Thread(target=_monitor_loop, daemon=True)
        self.monitor_thread.start()

    def _run_monitor(self, interface=None):
        """Sniff probe requests in short slices until stopped.

        Sniffing in bounded slices means ``stop()`` is honoured within ~1s
        even on a completely quiet channel, where ``stop_filter`` alone would
        never be evaluated.
        """
        try:
            from scapy.all import sniff, Dot11, Dot11ProbeReq, Dot11Elt
        except ImportError:
            self.ipc.emit("probe_monitor_error", {
                "message": "Scapy not available. Install with: pip install scapy"
            })
            return

        def _handle_packet(pkt):
            if not self.monitoring:
                return

            if pkt.haslayer(Dot11ProbeReq):
                client_mac = pkt.addr2
                if not client_mac:
                    return

                # Extract SSID from Dot11Elt (Element ID 0 = SSID)
                ssid = ""
                elt = pkt.getlayer(Dot11Elt)
                if elt and elt.ID == 0 and elt.info:
                    try:
                        ssid = elt.info.decode('utf-8', errors='ignore').strip()
                    except Exception:
                        pass

                # Skip broadcast probes (empty SSID)
                if not ssid:
                    return

                now = datetime.now().isoformat()
                is_new_client = False
                is_new_ssid = False

                with self._lock:
                    if client_mac not in self.clients:
                        self.clients[client_mac] = {
                            "ssids": set(),
                            "first_seen": now,
                            "last_seen": now,
                            "count": 0,
                        }
                        is_new_client = True

                    client = self.clients[client_mac]
                    client["last_seen"] = now
                    client["count"] += 1

                    if ssid not in client["ssids"]:
                        client["ssids"].add(ssid)
                        is_new_ssid = True

                    # Snapshot counters while still holding the lock
                    total_ssids = len(client["ssids"])
                    probe_count = client["count"]

                # Feed the durable station inventory. Probe requests prove the
                # device was present and looking for that SSID — not that it
                # connected — and the inventory keeps that distinction.
                inventory = getattr(self.ipc, "clients", None)
                if inventory is not None:
                    try:
                        inventory.observe_probe(client_mac, ssid=ssid, source="probe_request")
                    except Exception:
                        pass

                # Emit events
                if is_new_client or is_new_ssid:
                    self.ipc.emit("probe_detected", {
                        "client_mac": client_mac,
                        "ssid": ssid,
                        "is_new_client": is_new_client,
                        "timestamp": now,
                        "total_ssids": total_ssids,
                        "probe_count": probe_count,
                    })

        # Sniff in short slices so stop() is honoured promptly on a quiet channel
        while self.monitoring:
            try:
                sniff(
                    iface=interface,
                    prn=_handle_packet,
                    stop_filter=lambda p: not self.monitoring,
                    store=False,
                    timeout=1,
                )
            except PermissionError:
                self.ipc.emit("probe_monitor_error", {
                    "message": "Permission denied. Npcap with raw 802.11 capture required."
                })
                return
            except Exception as e:
                self.ipc.emit("probe_monitor_error", {
                    "message": f"Monitor failed: {str(e)[:200]}"
                })
                return

    def stop(self):
        """Stop monitoring."""
        self.monitoring = False

    def get_summary(self):
        """Return a summary of all discovered clients and their probed SSIDs."""
        with self._lock:
            summary = []
            for mac, info in self.clients.items():
                summary.append({
                    "client_mac": mac,
                    "ssids": list(info["ssids"]),
                    "first_seen": info["first_seen"],
                    "last_seen": info["last_seen"],
                    "probe_count": info["count"],
                })
            return summary
