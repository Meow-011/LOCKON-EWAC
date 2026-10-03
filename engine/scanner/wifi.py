"""LOCKON EWAC — WiFi Scanner Module (PyWiFi / Windows Native API)

Uses PyWiFi to leverage built-in Windows WiFi cards (Managed Mode)
instead of requiring Npcap/Monitor Mode adapters.
"""
import logging
import time
import pywifi
from pywifi import const
from datetime import datetime

logger = logging.getLogger("ewac.wifi")
from .oui import lookup_vendor
from .ap_track import ApTracker
from . import netsh_wlan


def repair_ssid(ssid: str) -> str:
    """Undo pywifi's byte-by-byte Latin-1 decoding of the SSID.

    An 802.11 SSID is 32 raw octets with no declared encoding; in practice
    everything non-ASCII uses UTF-8. pywifi builds the string one byte at a
    time (`_wifiutil_win.py`):

        ssid += "%c" % networks[i].dot11Ssid.ucSSID[j]

    `"%c" % n` is `chr(n)`, which is Latin-1 decoding. So the three octets
    `E0 B8 9F` — UTF-8 for `ฟ` — arrive as the three characters
    `U+00E0 U+00B8 U+009F`, and the network `ฟุฟุฟ` is displayed as
    `à¸Ÿà¸¸à¸Ÿ`. Every non-ASCII SSID is affected: Thai, Chinese, Japanese,
    Cyrillic, and any Latin name with an accent.

    This is not cosmetic. The SSID is what the report names the network by, it
    is what the CSV and the audit trail record, and it is one of the two things
    an engagement scope can authorise an access point by — so a mangled SSID
    means an allowlist entry typed in Thai never matches the access point it
    was written for.

    The repair is exact where it applies: re-encoding to Latin-1 recovers the
    original octets, and decoding them as UTF-8 recovers the name. Where it
    does not apply it changes nothing:

      * pure ASCII round-trips to itself;
      * an SSID whose octets are not valid UTF-8 (a different encoding, or
        binary) fails to decode and the original is kept — a guess at some
        other codepage would be inventing a name;
      * a string containing anything above U+00FF cannot have come from that
        byte-by-byte path, so it is left alone rather than mangled by an
        encode that would fail.
    """
    if not ssid or ssid.isascii():
        return ssid
    try:
        return ssid.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        # Either not from pywifi's path, or not UTF-8 underneath. Either way
        # the bytes we have are the best available answer.
        return ssid

class WiFiScanner:
    """Captures nearby WiFi access points using native OS scan.
    
    Compatible with standard Windows/Linux built-in wireless cards.
    """

    def __init__(self, target_iface_name: str = None):
        self.wifi = pywifi.PyWiFi()
        self.iface = None
        self.running = False
        # Smoothing, trend and first/last-seen bookkeeping live in ApTracker so
        # the simulator drives the same code a real scan does.
        self.tracker = ApTracker()

        # Why the last get_results() came back empty, when it was not simply
        # that nothing was in range. Read by the scan loop so a broken radio
        # backend is reported instead of looking like a quiet spectrum.
        self.last_error = None

        # Cache for the netsh enrichment. The call costs ~0.25 s, which is cheap
        # but not free at a 1.5 s scan interval, and the OS scan cache behind it
        # does not change faster than this anyway.
        self._netsh_cache = {}
        self._netsh_cached_at = 0.0

        self.set_interface(target_iface_name)

    def get_available_interfaces(self) -> list:
        """Return a list of string names for all found interfaces"""
        return [iface.name() for iface in self.wifi.interfaces()]

    def set_interface(self, name: str = None) -> bool:
        """Select a specific interface by name or fallback to first available"""
        interfaces = self.wifi.interfaces()
        if not interfaces:
            self.iface = None
            return False

        if name:
            for iface in interfaces:
                if iface.name() == name:
                    self.iface = iface
                    return True
        
        # Fallback to first
        self.iface = interfaces[0]
        return True

    def has_interface(self) -> bool:
        return self.iface is not None

    def start(self):
        """Start the scanning state"""
        self.running = True

    def stop(self):
        """Stop the scanning state"""
        self.running = False

    def trigger_scan(self):
        """Trigger an active OS scan."""
        if self.iface and self.running:
            self.iface.scan()

    NETSH_TTL_SECONDS = 2.0

    def _netsh_enrichment(self) -> dict:
        """Per-BSSID data PyWiFi does not provide, refreshed on a short TTL.

        Never fatal: if netsh is missing, localized or slow, this returns what it
        has (possibly nothing) and the scan falls back to PyWiFi's own values.
        """
        now = time.time()
        if now - self._netsh_cached_at < self.NETSH_TTL_SECONDS:
            return self._netsh_cache
        try:
            self._netsh_cache = netsh_wlan.scan_networks()
        except Exception:
            self._netsh_cache = {}
        self._netsh_cached_at = now
        return self._netsh_cache

    def get_results(self) -> list:
        """
        Fetch results from the last OS scan and parse them.

        `last_error` is set instead of the failure being swallowed. This
        returned `[]` on any exception from `scan_results()`, and the caller
        publishes results only when the list is non-empty — so a driver or COM
        hiccup produced a scan that ran for as long as the operator left it,
        showing zero access points, with `wifi_ready: true` and no error
        anywhere. "No access points in range" and "the radio backend is broken"
        were the same observation.
        """
        self.last_error = None

        if not self.iface or not self.running:
            return []

        try:
            results = self.iface.scan_results()
        except Exception as e:
            # The interface object survives, so this recurs every cycle; the
            # caller is responsible for not repeating itself.
            self.last_error = f"{type(e).__name__}: {e}"
            logger.debug("scan_results() failed: %s", e)
            return []

        enrichment = self._netsh_enrichment()
        parsed_results = []
        for profile in results:
            # Map PyWiFi AKM to Lockon Encryption display
            encryption = "OPEN"
            is_vulnerable = True

            if hasattr(profile, "akm") and profile.akm:
                akm_types = profile.akm

                # SAE (6) and OWE (8) are WPA3. pywifi defines neither.
                #
                # `pywifi.const` goes up to `AKM_TYPE_UNKNOWN = 5` and stops, so
                # 6 and 8 can never appear and the only one of the three literals
                # that could ever match was the UNKNOWN sentinel -- which this
                # branch mapped to `encryption = "WPA3", is_vulnerable = False`,
                # conceding in its own comment that it was a guess ("often maps
                # to WPA3").
                #
                # So every AKM the backend could not classify was published as
                # the strongest security this tool recognises, and as not
                # vulnerable, into `tracker.build` and from there into the report
                # and the rogue-AP scorer. A fail-open misclassification, and the
                # netsh override that was the only thing able to correct it
                # matches English labels only -- on a Thai or German Windows it
                # yields no `encryption` at all and the guess stood unmoderated.
                #
                # UNKNOWN is now what it says it is: unknown. It is checked last,
                # so a recognised AKM in the same list wins -- it used to lose,
                # because UNKNOWN was tested first.
                if 6 in akm_types or 8 in akm_types:
                    encryption = "WPA3"
                    is_vulnerable = False
                elif const.AKM_TYPE_WPA2PSK in akm_types or const.AKM_TYPE_WPA2 in akm_types:
                    encryption = "WPA2"
                    is_vulnerable = False
                elif const.AKM_TYPE_WPAPSK in akm_types or const.AKM_TYPE_WPA in akm_types:
                    encryption = "WPA" # WPA1 is considered vulnerable
                    is_vulnerable = True
                elif const.AKM_TYPE_UNKNOWN in akm_types:
                    # Not WPA3, not OPEN, and not assessable. `None` is what the
                    # risk rule set reads as "unread", which raises nothing rather
                    # than manufacturing a label from absence -- and the netsh
                    # override, where it works, replaces it with a measurement.
                    encryption = None
                    is_vulnerable = False
            
            # WEP check (often represented by NONE akm but SHARED auth)
            if hasattr(profile, "auth") and profile.auth == const.AUTH_ALG_SHARED:
                encryption = "WEP"
                is_vulnerable = True

            # Normalize BSSID format (upper case, colon separated).
            #
            # Through `netsh_wlan.normalize_bssid`, which strips every character
            # that is not a hex digit before regrouping. The old code only
            # handled the bare twelve-character case and passed anything else
            # through untouched — and PyWiFi hands back a trailing separator on
            # this platform, so every address was stored and printed as
            # `00:00:5E:00:53:48:`. It reached the report's telemetry table and
            # the evidence register looking like a truncated address.
            #
            # It also meant the stored key and the key used to match netsh
            # enrichment were different strings, with only the lookup side
            # normalised. Anything joining on the stored value had to know to
            # normalise first, and nothing said so.
            raw_bssid = (profile.bssid or "").upper()
            bssid = netsh_wlan.normalize_bssid(raw_bssid) or raw_bssid

            # Vendor lookup via OUI (MAC prefix)
            vendor = lookup_vendor(bssid)

            # Clean SSID. The old test looked for the literal four characters
            # \x00 rather than a NUL byte, so NUL-padded and hidden SSIDs were
            # passed through verbatim and rendered as mojibake.
            ssid = repair_ssid(profile.ssid or "")
            if "\x00" in ssid:
                ssid = ssid.split("\x00", 1)[0]
            ssid = ssid.strip()

            # Some drivers omit `signal` entirely. This read sits outside the
            # per-profile try below, so an AttributeError here used to kill the
            # whole scan thread.
            current_rssi = getattr(profile, "signal", None)
            if current_rssi is None:
                continue
            
            # Frequency as the driver reports it; ApTracker normalizes kHz and
            # derives band/channel so the simulator cannot drift from this.
            frequency = getattr(profile, 'freq', None) or getattr(profile, 'frequency', None)

            # netsh knows things PyWiFi does not, and is right where the two
            # disagree: PyWiFi reports cipher as NONE for every network and
            # calls a WPA3-Personal AP "WPA2", which understates a correctly
            # secured network in the report and feeds the wrong encryption to
            # the rogue-AP scorer. Only override when netsh actually resolved a
            # family — an unrecognised (or localized) Authentication string
            # leaves PyWiFi's answer in place rather than blanking it.
            # Looked up on a normalized key: PyWiFi hands back BSSIDs with a
            # trailing colon ("00:00:5E:00:53:BA:") while netsh does not, so a
            # direct lookup silently matched nothing and every AP came back
            # unenriched.
            netsh_row = enrichment.get(netsh_wlan.normalize_bssid(bssid))
            extra = None
            if netsh_row:
                if netsh_row.get("encryption"):
                    encryption = netsh_row["encryption"]
                    if netsh_row.get("is_vulnerable") is not None:
                        is_vulnerable = netsh_row["is_vulnerable"]
                extra = {
                    "cipher": netsh_row.get("cipher"),
                    "auth_type": netsh_row.get("auth_type"),
                    "radio_type": netsh_row.get("radio_type"),
                    "connected_stations": netsh_row.get("connected_stations"),
                    "channel_utilization_pct": netsh_row.get("channel_utilization_pct"),
                }

            ap_data = self.tracker.build(
                bssid=bssid,
                ssid=ssid,
                vendor=vendor,
                encryption=encryption,
                is_vulnerable=is_vulnerable,
                rssi=current_rssi,
                frequency=frequency,
                extra=extra,
            )
            parsed_results.append(ap_data)

        return parsed_results

    @property
    def discovered_aps(self) -> dict:
        return self.tracker.discovered_aps

    def get_discovered_aps(self) -> dict:
        """Return all unique discovered access points over time"""
        return self.tracker.discovered_aps

    def clear_data(self):
        """Purge all discovered targets"""
        self.tracker.clear()
