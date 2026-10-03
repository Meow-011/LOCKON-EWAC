"""LOCKON EWAC — Client / station inventory

The probe monitor and passive analyser already see client devices, but nothing
kept them: there was no station table and no client data in any report. So the
most obvious follow-up question a reader has about a rogue AP finding — "who was
connected to it?" — could not be answered by the tool that produced the finding.

This aggregates what the passive collectors observe into a durable inventory,
and it is emitted for the app to persist rather than written here (the Tauri SQL
plugin is the single writer).

Two things this deliberately does NOT do:

  - It does not claim association. Seeing a probe request proves the device was
    present and looking for that SSID; it does not prove it connected. The record
    distinguishes `probed_ssids` from `associated_bssid`, and only the latter is
    stated as a connection.
  - It does not try to identify a person. A randomised MAC is marked as such, so
    a report cannot present an ephemeral identifier as a stable device identity.

Privacy note: probe requests reveal the networks a device has previously joined,
which is sensitive. The inventory keeps what the assessment needs and the report
should present it at the aggregate level unless a specific device is the finding.
"""
import threading
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


def is_randomized_mac(mac: str) -> bool:
    """Locally administered bit set — a randomised/rotating address."""
    clean = "".join(c for c in (mac or "").upper() if c in "0123456789ABCDEF")
    if len(clean) < 2:
        return False
    return clean[1] in ("2", "6", "A", "E")


def normalize_mac(mac: str) -> str:
    clean = "".join(c for c in (mac or "").upper() if c in "0123456789ABCDEF")
    if len(clean) != 12:
        return (mac or "").upper()
    return ":".join(clean[i:i + 2] for i in range(0, 12, 2))


class ClientInventory:
    """Thread-safe station inventory built from passive observations."""

    def __init__(self, emit=None):
        self.emit = emit
        self._lock = threading.Lock()
        self._clients = {}

    def _blank(self, mac):
        return {
            "mac": mac,
            "randomized": is_randomized_mac(mac),
            "vendor": None,
            "first_seen": _now(),
            "last_seen": _now(),
            "probe_count": 0,
            "probed_ssids": [],
            "associated_bssid": None,
            "associated_ssid": None,
            "strongest_rssi": None,
            "sources": [],
        }

    def observe_probe(self, client_mac, ssid=None, rssi=None, vendor=None, source="probe_request"):
        """Record a probe request. Presence and interest — not a connection."""
        mac = normalize_mac(client_mac)
        if not mac:
            return None

        with self._lock:
            entry = self._clients.setdefault(mac, self._blank(mac))
            entry["last_seen"] = _now()
            entry["probe_count"] += 1
            if vendor and not entry["vendor"]:
                entry["vendor"] = vendor
            if ssid and ssid not in entry["probed_ssids"]:
                entry["probed_ssids"].append(ssid)
            if isinstance(rssi, (int, float)):
                if entry["strongest_rssi"] is None or rssi > entry["strongest_rssi"]:
                    entry["strongest_rssi"] = rssi
            if source not in entry["sources"]:
                entry["sources"].append(source)
            snapshot = dict(entry)
            snapshot["probed_ssids"] = list(entry["probed_ssids"])

        self._announce(snapshot)
        return snapshot

    def observe_association(self, client_mac, bssid, ssid=None, rssi=None, source="data_frame"):
        """Record an actual association. This is the one that means 'connected'."""
        mac = normalize_mac(client_mac)
        if not mac:
            return None

        with self._lock:
            entry = self._clients.setdefault(mac, self._blank(mac))
            entry["last_seen"] = _now()
            entry["associated_bssid"] = normalize_mac(bssid)
            if ssid:
                entry["associated_ssid"] = ssid
            if isinstance(rssi, (int, float)):
                if entry["strongest_rssi"] is None or rssi > entry["strongest_rssi"]:
                    entry["strongest_rssi"] = rssi
            if source not in entry["sources"]:
                entry["sources"].append(source)
            snapshot = dict(entry)
            snapshot["probed_ssids"] = list(entry["probed_ssids"])

        self._announce(snapshot)
        return snapshot

    def _announce(self, snapshot):
        if not self.emit:
            return
        try:
            self.emit("client_observed", snapshot)
        except Exception:
            pass

    def clients_for_bssid(self, bssid):
        """Stations associated with one AP — the 'who was on the rogue AP' answer."""
        target = normalize_mac(bssid)
        with self._lock:
            return [dict(c) for c in self._clients.values() if c["associated_bssid"] == target]

    def summary(self) -> dict:
        with self._lock:
            clients = [dict(c) for c in self._clients.values()]
        randomized = sum(1 for c in clients if c["randomized"])
        associated = sum(1 for c in clients if c["associated_bssid"])
        return {
            "total": len(clients),
            "randomized": randomized,
            "identifiable": len(clients) - randomized,
            "associated": associated,
            "probe_only": len(clients) - associated,
            "clients": clients,
            "caveat": ("Probe requests prove presence and interest, not association. "
                       "Only 'associated' counts represent observed connections."),
        }

    def reset(self):
        with self._lock:
            self._clients = {}
