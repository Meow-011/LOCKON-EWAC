"""IPC message handler for Tauri sidecar communication"""
import os
import sys
import json
import time
import math
import logging
import threading
from datetime import datetime

logger = logging.getLogger("ewac.ipc")
from scanner.wifi import WiFiScanner
from scanner.lan import LANScanner
from scanner.strike import StrikeModule
from scanner.probe_monitor import ProbeMonitor
from scanner.passive import PassiveAnalyzer
from scanner.smb_enum import SMBEnumerator
from scanner.vuln_engine import VulnEngine
from scanner.traceroute import TracerouteEngine
from scanner.vlan_detect import VLANDetector
from scanner.wps_detect import WPSDetector
from offensive.mitm import MitmEngine
from offensive.capture import HandshakeCapture
from offensive.bruteforce import BruteForcer
from offensive.decryptor import DecryptorModule
from offensive.dirbuster import DirBuster
from offensive.sprayer import CredentialSprayer
from offensive.hashcat_export import HashcatExporter
from offensive.auto_attack import AutoAttackChain
from gps.reader import GPSReader
from scanner.clients import ClientInventory
from scanner import evil_twin
from policy import ScopePolicy
from rf import freq_to_channel

class IPCHandler:
    def __init__(self):
        self.scanning = False
        # The scope gate is constructed first: every offensive handler below
        # consults it, and it must exist even if a scanner fails to initialize.
        self.policy = ScopePolicy(self.emit)
        self.wifi = WiFiScanner()
        self.lan = LANScanner(self)
        self.strike = StrikeModule(self)
        self.probe_monitor = ProbeMonitor(self)
        self.passive = PassiveAnalyzer(self)
        self.smb_enum = SMBEnumerator(self.emit)
        self.capture = HandshakeCapture(self)
        self.bruteforce = BruteForcer(self)
        self.sprayer = CredentialSprayer(self.emit, self.bruteforce)
        self.decryptor = DecryptorModule(self)
        self.dirbuster = DirBuster(self.emit)
        self.vuln_engine = VulnEngine(self.emit)
        self.mitm = MitmEngine(self.emit)
        self.traceroute = TracerouteEngine(self.emit)
        self.vlan_detector = VLANDetector(self.emit)
        self.wps_detector = WPSDetector(self.emit)
        self.hashcat = HashcatExporter(self.emit)
        self.auto_attack = AutoAttackChain(self.emit, self.wps_detector, self.capture, self.hashcat, self.policy)
        self.gps = GPSReader()
        # Station inventory, so "who was connected to the rogue AP" is answerable.
        self.clients = ClientInventory(self.emit)

        self.wifi_thread = None
        self.gps_thread = None
        self.simulating = False
        #: Set while a simulated survey is running (see scanner/simulator.py).
        self.simulator = None
        self.sim_tracker = None
        self._ap_peaks = {}  # BSSID → peak raw RSSI (for Vistumbler-style location tracking)
        # Every AP seen this session, so rogue-AP scoring can compare an AP
        # against peers that appeared in an earlier scan cycle.
        self._ap_cache = {}
        
        # GPS Outlier Detection state
        self._last_valid_lat = None
        self._last_valid_lon = None
        self._last_valid_time = None
        self._max_speed_ms = 55.6  # 200 km/h in m/s (max believable speed)
        #: Consecutive fixes rejected as jumps. See _validate_gps: a baseline that
        #: is itself wrong rejects every true fix forever, so the run of
        #: rejections is counted and eventually believed.
        self._gps_rejects = 0
        #: Set while rejections are being reported, so one episode produces one
        #: message instead of one per fix.
        self._gps_reject_reported = False

        # Serializes writes to stdout. See emit().
        self._emit_lock = threading.Lock()

        # Guards the GPS outlier-detection state above, which the Wi-Fi loop and
        # the GPS loop both read and write. An interleaved read/write pair made
        # _haversine compare a latitude from one fix against a longitude and
        # timestamp from another, which either rejected a valid fix as a
        # >200 km/h jump (the AP is then stamped with no position at all) or
        # accepted a real jump.
        self._gps_state_lock = threading.Lock()

    @staticmethod
    def _bounded_int(value, default, low, high):
        """
        A frontend-supplied number, forced into a range the engine can survive.

        Numeric parameters arrived from the IPC message untyped and unchecked and
        went straight into subprocess arguments, sleeps and loop bounds. The
        worst of them was `max_hops`: `traceroute.py` derives its subprocess
        timeout as `max_hops * (timeout + 1) + 10`, so `max_hops = 10000` is an
        eight-hour blocking `subprocess.run` that nothing in the app can
        interrupt. A JSON *string* where a number was expected was equally bad —
        `str(timeout * 1000)` on `"2"` produces a 2000-character argument, and
        the arithmetic raises `TypeError` deep inside a worker thread rather
        than as a validation error at the boundary.

        Out-of-range and unparseable both fall back to the default rather than
        raising: a request with a silly number is a request to do the normal
        thing, not a reason to strand the UI waiting for an event that never
        comes.
        """
        try:
            n = int(float(value))
        except (TypeError, ValueError):
            return default
        return max(low, min(high, n))

    @staticmethod
    def _bounded_float(value, default, low, high):
        """As `_bounded_int`, where a fraction is meaningful.

        `scan_interval` is the case: it goes straight into `time.sleep()` in the
        scan loop, and 0.5 s is a legitimate request while an integer floor of 1
        would not be. Rounding it to an int would silently change behaviour the
        operator asked for, so the two helpers exist separately rather than one
        pretending to cover both.

        NaN and infinity fall back to the default: both survive `float()`, and
        `sleep(inf)` is a scan loop that never ticks again.
        """
        try:
            n = float(value)
        except (TypeError, ValueError):
            return default
        if not math.isfinite(n):
            return default
        return max(low, min(high, n))

    @staticmethod
    def _port_or_none(value):
        """A TCP port, or None when the value is not one.

        Refuses rather than clamps, unlike the two helpers above, because this
        is a *required* argument naming a target. Clamping 99999 to 65535 would
        quietly attack a port nobody asked about — for a missing optional knob
        "do the normal thing" is right, but for a target it is not.

        It also has to reject a non-numeric string, not merely a number out of
        range: `dirbuster` interpolates the port into a URL
        (`f"{protocol}://{ip}:{port}"`), so a value like `80/..%2f` is a request
        path of the caller's choosing rather than a port at all.
        """
        try:
            n = int(str(value).strip())
        except (TypeError, ValueError):
            return None
        return n if 1 <= n <= 65535 else None

    def emit(self, event: str, data: dict = None):
        """
        Send one JSON message to Tauri via stdout.

        The lock is not optional. Every thread in this process emits through
        here: up to 100 LAN host workers, the Wi-Fi scan loop, the GPS loop, the
        three advanced-intel listeners, the passive sniffer, and every
        command handler that runs in its own thread.

        `TextIOWrapper.write` is not atomic with respect to its internal buffer,
        and write-then-flush is two operations regardless. Without this lock two
        emitters interleave and the pipe carries a spliced line; the Tauri side
        fails to parse it and drops that record entirely. The failure is silent
        and non-deterministic — a discovered host, or an evidence record, simply
        never appears — which makes it the worst class of defect for a tool whose
        output is evidence.

        Held only around the write, so no scanner is ever blocked on anything
        but the pipe.
        """
        message = {
            "event": event,
            "data": data or {},
            "ts": datetime.now().isoformat(),
        }
        line = json.dumps(message) + "\n"
        with self._emit_lock:
            sys.stdout.write(line)
            sys.stdout.flush()

    def handle(self, message: dict):
        """Route incoming commands"""
        cmd = message.get("cmd")
        data = message.get("data", {})

        handlers = {
            "ping": self._handle_ping,
            "start_scan": self._handle_start_scan,
            "stop_scan": self._handle_stop_scan,
            "get_status": self._handle_status,
            "get_interfaces": self._handle_get_interfaces,
            "purge_data": self._handle_purge_data,
            "start_intrusion": self._handle_start_intrusion,
            "stop_intrusion": self._handle_stop_intrusion,
            "start_strike": self._handle_start_strike,
            "stop_strike": self._handle_stop_strike,
            "stop_all_strikes": self._handle_stop_all_strikes,
            "start_capture": self._handle_start_capture,
            "start_bruteforce": self._handle_start_bruteforce,
            "stop_bruteforce": self._handle_stop_bruteforce,
            "start_spray": self._handle_start_spray,
            "stop_spray": self._handle_stop_spray,
            "start_decrypt": self._handle_start_decrypt,
            "stop_decrypt": self._handle_stop_decrypt,
            "start_mitm": self._handle_start_mitm,
            "stop_mitm": self._handle_stop_mitm,
            "start_dirbuster": self._handle_start_dirbuster,
            "stop_dirbuster": self._handle_stop_dirbuster,
            "start_smb_enum": self._handle_start_smb_enum,
            "start_vuln_scan": self._handle_start_vuln_scan,
            "get_wordlists": self._handle_get_wordlists,
            "upload_wordlist": self._handle_upload_wordlist,
            "delete_wordlist": self._handle_delete_wordlist,
            "test_hardware": self._handle_test_hardware,
            "run_benchmark": self._handle_run_benchmark,
            # Phase 6 Sprint D: Advanced WiFi Intelligence
            "start_probe_monitor": self._handle_start_probe_monitor,
            "stop_probe_monitor": self._handle_stop_probe_monitor,
            "get_probe_summary": self._handle_get_probe_summary,
            "start_passive": self._handle_start_passive,
            "stop_passive": self._handle_stop_passive,
            "get_passive_summary": self._handle_get_passive_summary,
            # Phase 7: Advanced Recon
            "start_traceroute": self._handle_start_traceroute,
            "stop_traceroute": self._handle_stop_traceroute,
            "start_vlan_detect": self._handle_start_vlan_detect,
            "start_deep_ssl_scan": self._handle_start_deep_ssl_scan,
            "run_gpr": self._handle_run_gpr,
            # Phase 8: WiFi Attack Enhancement
            "scan_wps": self._handle_scan_wps,
            "stop_wps": self._handle_stop_wps,
            "export_hashcat": self._handle_export_hashcat,
            "check_hashcat": self._handle_check_hashcat,
            "start_pmkid_capture": self._handle_start_pmkid_capture,
            "stop_pmkid": self._handle_stop_pmkid,
            # Phase 9: Auto-Attack & 5GHz
            "set_auto_attack": self._handle_set_auto_attack,
            "reset_auto_attack": self._handle_reset_auto_attack,
            # Engagement scope & audit
            "set_scope": self._handle_set_scope,
            "get_scope": self._handle_get_scope,
            # Hardware capability, CVE provenance, diagnostics, evidence
            "check_capabilities": self._handle_check_capabilities,
            "get_cve_info": self._handle_get_cve_info,
            "update_cve_db": self._handle_update_cve_db,
            "get_engine_log": self._handle_get_engine_log,
            "verify_evidence": self._handle_verify_evidence,
            "get_client_summary": self._handle_get_client_summary,
            "get_net_context": self._handle_get_net_context,
            "get_methodology": self._handle_get_methodology,
        }

        handler = handlers.get(cmd)
        if handler:
            # A handler that raises must not take the command loop down with it,
            # and must not leave the UI waiting for an event that never comes.
            try:
                handler(data)
            except Exception as e:
                self.emit("error", {
                    "message": f"Command '{cmd}' failed: {e}",
                    "command": cmd,
                })
        else:
            self.emit("error", {"message": f"Unknown command: {cmd}"})

    # ── Engagement scope ────────────────────────────────────────────────────

    def _handle_set_scope(self, data):
        """Load the active engagement scope sent by the frontend."""
        self.policy.load(data)

    def _handle_get_scope(self, data):
        self.emit("scope_status", self.policy.describe())

    # ── Hardware capability, provenance, diagnostics ────────────────────────

    def _handle_check_capabilities(self, data):
        """Report what this hardware and privilege level can actually do.

        The UI gates the 802.11 controls on this. A capture that cannot succeed
        returns a null result indistinguishable from "the target is secure", so
        the operator has to know before they run it, not after.
        """
        # The adapter the operator selected, so the raw-socket test answers about
        # the interface the capture will really use rather than about whatever
        # carries the default route. See capability.check_raw_socket.
        interface_name = data.get("interface_name") or None

        def run():
            # No bare thread body.
            #
            # This had no try/except, so any raise -- a comtypes fault from the
            # `i.name()` calls in `check_monitor_mode`, which sit outside every
            # guard, is the realistic one -- killed the thread silently. No
            # `capabilities` event was ever emitted and the UI's 802.11 gates
            # stayed at whatever they held before, which on first run is the
            # permissive default.
            try:
                import capability
                self.emit("capabilities", capability.probe(interface_name))
            except Exception as e:
                logger.exception("capability probe failed")
                self.emit("capabilities_error", {
                    "message": (
                        f"The hardware capability probe failed: {e}. "
                        "The 802.11 controls stay disabled, because a probe that "
                        "did not finish is not evidence the hardware is ready."
                    ),
                    "interface_name": interface_name,
                })
        threading.Thread(target=run, daemon=True).start()

    def _handle_get_cve_info(self, data):
        from scanner.cve_db import describe_source
        self.emit("cve_info", describe_source())

    def _handle_update_cve_db(self, data):
        """Operator-initiated CVE refresh. Never automatic — see cve_feed.py."""
        api_key = data.get("api_key")

        def run():
            from scanner.cve_db import describe_source
            try:
                import cve_feed
                self.emit("cve_update_started", {"source": "NVD CVE API 2.0"})
                info = cve_feed.fetch_from_nvd(emit=self.emit, api_key=api_key)
                self.emit("cve_update_complete", info)
            except Exception as e:
                # The previous snapshot stays in force; say so rather than
                # leaving the operator unsure what data they are now using.
                self.emit("cve_update_error", {
                    "message": str(e),
                    "retained": describe_source(),
                })
        threading.Thread(target=run, daemon=True).start()

    def _handle_get_engine_log(self, data):
        import logging_setup
        # Bounded: the tail is serialised into a single JSON line on the pipe,
        # so an unbounded request is a request to put the whole log file through
        # stdout in one write.
        self.emit("engine_log", logging_setup.tail(self._bounded_int(data.get("lines"), 200, 1, 5000)))

    def _handle_verify_evidence(self, data):
        """
        Re-hash a stored artifact so the operator can show it is unaltered.

        `path` is confined to the evidence directory. It used to be hashed
        wherever it pointed, so an IPC message could have the engine read any
        file it can reach — and the engine may be running elevated for capture.
        Reading a file to hash it is less damaging than writing one, but it is
        still a capability the sidecar's stdin should not confer, and the only
        paths this command has any business verifying are the ones this tool
        wrote.

        `id` is echoed back untouched so the caller can match a result to the
        row it asked about: the frontend verifies a whole register and needs to
        know which answer belongs to which artifact.
        """
        import evidence
        path = data.get("path")
        expected = data.get("sha256")
        row_id = data.get("id")

        if not path:
            self.emit("evidence_verified", {
                "id": row_id, "error": "No path supplied", "matches": False,
            })
            return

        try:
            root = os.path.realpath(evidence.evidence_dir())
            target = os.path.realpath(str(path))
            # commonpath rather than startswith: the string comparison passes
            # for a sibling directory whose name merely begins with the same
            # characters.
            inside = os.path.commonpath([root, target]) == root
        except (ValueError, OSError) as e:
            self.emit("evidence_verified", {
                "id": row_id, "path": path, "matches": False,
                "error": f"Path could not be resolved: {e}",
            })
            return

        if not inside:
            self.emit("evidence_verified", {
                "id": row_id, "path": path, "matches": False,
                "error": "Refusing to hash a file outside the evidence directory.",
            })
            return

        result = evidence.verify(target, expected)
        result["id"] = row_id
        self.emit("evidence_verified", result)

    def _handle_get_client_summary(self, data):
        self.emit("client_summary", self.clients.summary())

    def _handle_get_net_context(self, data):
        """Which network this machine is on, and whether an AP can carry an IP.

        Only the associated access point can: a beacon frame has no layer 3
        address, so for every other AP in a scan there is no IP to know. The
        payload says which case applies rather than leaving the UI to infer it.
        """
        def run():
            from scanner import net_context
            try:
                self.emit("net_context", net_context.describe())
            except Exception as e:
                # Never fatal: this is context, not a measurement. Saying it
                # could not be read is better than a half-filled panel.
                self.emit("net_context", {
                    "connected": False,
                    "error": str(e),
                    "note": "The network context could not be read on this machine.",
                })
        threading.Thread(target=run, daemon=True).start()

    def _handle_get_methodology(self, data):
        """Everything the report's method appendix needs to state."""
        from scanner.cve_db import describe_source
        import build_stamp
        import capability

        # The build, not the marketing version.
        #
        # This used to answer a hardcoded "0.1.0", which names every build ever
        # made. The report prefers whatever the engine reports over its own
        # fallback, so the build stamp added for exactly this purpose — git
        # describe, build time, frozen or from source — was shadowed in the
        # normal case where the engine is reachable, and the method appendix
        # printed "0.1.0" for a sidecar compiled days apart from the one that
        # produced the findings.
        #
        # A severity traced to a rule set is auditable only if the software that
        # applied it can be named. This names it.
        stamp = build_stamp.describe()
        identity = " · ".join(part for part in (
            stamp.get("version"),
            stamp.get("git_describe"),
            f"built {stamp['built_at']}" if stamp.get("built_at") else None,
            None if stamp.get("frozen") else "from source",
        ) if part)

        self.emit("methodology", {
            "engine_version": identity,
            "engine_build": stamp,
            "platform": sys.platform,
            "cve_data": describe_source(),
            "evil_twin": evil_twin.describe_methodology(),
            "scope": self.policy.describe(),
            "capabilities": capability.probe(),
        })

    def _handle_start_intrusion(self, data):
        """
        Start a LAN sweep over the subnets the operator chose.

        Two things used to go wrong here.

        The subnet list was resolved and then discarded: `self.lan.start()` was
        called with no arguments, so `LANScanner` rediscovered the list itself
        and swept everything it found. The operator's selection in the UI had no
        effect whatsoever, and `get_all_subnets()` ran twice per sweep — two
        calls that could disagree if an adapter came up between them.

        There was also a scope filter here whose result was thrown away in the
        same statement. It is gone rather than repaired: `start_intrusion` is
        deliberately not in `GATED_COMMANDS`. A port sweep aimed at the wrong
        subnet inconveniences nobody, and gating it made the audit trail noisy
        enough to bury the entries that matter. See the rationale in
        `engine/policy.py`; the commands that can disrupt, authenticate or
        intercept are still gated, and the report says which those are.
        """
        scan_mode = data.get("scan_mode", "QUICK")

        subnets = data.get("subnets") or self.lan.get_all_subnets()
        if not subnets:
            self.emit("intrusion_error", {"message": "No local subnet detected — nothing to sweep."})
            self.emit("intrusion_complete", {"aborted": True, "host_count": 0})
            return

        self.lan.start(
            target_cidr=subnets[0],
            extra_subnets=subnets[1:],
            scan_mode=scan_mode,
        )

    def _handle_stop_intrusion(self, data):
        self.lan.stop()

    def _handle_start_strike(self, data):
        target_mac = data.get("target_mac")
        gateway_bssid = data.get("gateway_bssid")
        iface = data.get("interface")
        # Frames per burst. 0 is a documented mode — continuous until stopped —
        # so the floor is 0 rather than 1. The ceiling is the point: this is the
        # most disruptive thing the tool does, and the loop bound arrived from
        # the IPC channel unchecked, so `count` of ten million was a deauth
        # flood that only killing the process would end.
        count = self._bounded_int(data.get("count"), 100, 0, 10000)
        if not target_mac or not gateway_bssid:
            self.emit("strike_error", {"message": "Missing target_mac or gateway_bssid"})
            return
        # Both ends are targets: a deauth authorized for the client but not for
        # the AP it is associated with is still out of scope.
        if not self.policy.authorize("start_strike",
                                     [("bssid", target_mac), ("bssid", gateway_bssid)]):
            return
        self.strike.start_strike(target_mac, gateway_bssid, iface=iface, count=count)

    def _handle_stop_strike(self, data):
        target_mac = data.get("target_mac")
        if not target_mac:
            self.emit("strike_error", {"message": "Missing target_mac"})
            return
        self.strike.stop_strike(target_mac)

    def _handle_stop_all_strikes(self, data):
        self.strike.stop_all()

    def _ssid_for(self, bssid, data=None):
        """The SSID this BSSID was last seen broadcasting.

        Taken from the caller when it supplies one, otherwise from the scan
        cache. It exists so an SSID entry in the engagement scope can authorize
        an access point the operator identified by MAC — without it, scoping an
        estate by its SSID authorized nothing at all for these commands.
        """
        if data:
            supplied = (data.get("ssid") or "").strip()
            if supplied:
                return supplied
        ap = self._ap_cache.get(bssid)
        if not ap:
            # The cache is keyed exactly as the scanner emits it; a caller may
            # have normalized the separators away.
            wanted = "".join(c for c in str(bssid).upper() if c in "0123456789ABCDEF")
            for key, cached in self._ap_cache.items():
                if "".join(c for c in str(key).upper() if c in "0123456789ABCDEF") == wanted:
                    ap = cached
                    break
        return (ap or {}).get("ssid") or None

    def _handle_start_capture(self, data):
        bssid = data.get("bssid")
        interface = data.get("interface")
        if not bssid:
            self.emit("capture_error", {"message": "Missing bssid"})
            return
        if not self.policy.authorize_ap("start_capture", bssid,
                                        ssid=self._ssid_for(bssid, data)):
            return
        self.capture.start_capture(bssid, interface)

    def _handle_start_bruteforce(self, data):
        target_ip = data.get("target_ip")
        port = self._port_or_none(data.get("port"))
        service_type = data.get("service_type")
        wordlist_name = data.get("wordlist_name", "default-passwords.txt")
        target_user = data.get("target_user", "admin")
        if not target_ip or not port:
            self.emit("bruteforce_error", {
                "message": "A target IP and a TCP port between 1 and 65535 are required."
            })
            return
        if not self.policy.authorize("start_bruteforce", [("ip", target_ip)]):
            return
        self.bruteforce.start_attack(target_ip, port, service_type, wordlist_name, target_user)

    def _handle_stop_bruteforce(self, data):
        target_ip = data.get("target_ip")
        port = data.get("port")
        if target_ip and port:
            self.bruteforce.stop_attack(target_ip, port)

    def _handle_start_spray(self, data):
        username = data.get("username")
        password = data.get("password")
        targets = data.get("targets", [])
        if not username or not password or not targets:
            self.emit("spray_error", {"message": "Missing username, password, or targets"})
            return
        # A list, explicitly. A bare string iterates as characters, and `t.get`
        # on a character raises AttributeError from inside the scope check —
        # which the dispatcher reports as "command failed" without saying why.
        if not isinstance(targets, (list, tuple)):
            self.emit("spray_error", {"message": "`targets` must be a list of host objects."})
            return
        # A spray fans out across many hosts, so every one of them has to clear
        # the scope before the first packet goes out.
        #
        # Every entry is checked, including the ones the sprayer will later
        # reject as malformed: an entry this code cannot read an IP out of must
        # not be able to slip past the gate on its way to being discarded.
        if not self.policy.authorize(
                "start_spray",
                [("ip", t.get("ip") if isinstance(t, dict) else None) for t in targets]):
            return
        self.sprayer.start_spray(username, password, targets)

    def _handle_stop_spray(self, data):
        self.sprayer.stop_spray()

    def _handle_start_decrypt(self, data):
        pcap_file = data.get("pcap_file")
        wordlist_name = data.get("wordlist_name", "default-passwords.txt")
        mangling = data.get("mangling")
        if not pcap_file:
            self.emit("decrypt_error", {"message": "No capture file selected"})
            return
        # Offline work against a file the operator already holds — no traffic is
        # generated, so this is not scope-gated. The capture that produced the
        # file was gated when it was taken.
        self.decryptor.start_decrypt(pcap_file, wordlist_name, mangling)

    def _handle_stop_decrypt(self, data):
        # The decryptor emits decrypt_aborted itself once the cracking process
        # has actually been killed; emitting it here too told the UI the run had
        # stopped while hashcat was still running.
        self.decryptor.stop_decrypt()

    def _handle_start_mitm(self, data):
        target_ip = data.get("target_ip")
        gateway_ip = data.get("gateway_ip")
        interface = data.get("interface")
        save_pcap = data.get("save_pcap", False)
        if not target_ip or not gateway_ip:
            self.emit("mitm_error", {"message": "Missing target_ip or gateway_ip"})
            return
        if not self.policy.authorize("start_mitm",
                                     [("ip", target_ip), ("ip", gateway_ip)]):
            return
        self.mitm.start_mitm(target_ip, gateway_ip, interface, save_pcap)

    def _handle_stop_mitm(self, data):
        target_ip = data.get("target_ip")
        if target_ip:
            self.mitm.stop_mitm(target_ip)
        else:
            self.mitm.stop_all()

    def _handle_start_vuln_scan(self, data):
        target_ip = data.get("target_ip")
        open_ports = data.get("open_ports", [])
        if not target_ip:
            self.emit("vuln_scan_completed", {"target": None, "findings": [],
                                              "error": "Missing target_ip"})
            return
        if not self.policy.authorize("start_vuln_scan", [("ip", target_ip)]):
            return
        # The LAN scanner reports open ports as {"port": n, "service": s} dicts
        # while the vuln engine compares against bare ints, so normalize here
        # rather than letting every check silently fail to match.
        self.vuln_engine.start_scan(target_ip, self._normalize_ports(open_ports))

    @staticmethod
    def _normalize_ports(open_ports):
        normalized = []
        for entry in open_ports or []:
            if isinstance(entry, dict):
                value = entry.get("port")
            else:
                value = entry
            try:
                normalized.append(int(value))
            except (TypeError, ValueError):
                continue
        return normalized

    def _handle_start_dirbuster(self, data):
        target_ip = data.get("target_ip")
        # Validated, not clamped: this port is interpolated into the URL the
        # scan requests, so anything that is not a port is a caller-chosen
        # request path.
        port = self._port_or_none(data.get("port"))
        is_https = data.get("is_https", False)
        wordlist_name = data.get("wordlist_name", "common-dirs.txt")
        # One real OS thread each, so this is a process-wide resource bound and
        # not a tuning knob to be trusted from a message.
        threads = self._bounded_int(data.get("threads"), 10, 1, 64)
        if not target_ip or not port:
            self.emit("dirbuster_error", {
                "message": "A target IP and a TCP port between 1 and 65535 are required."
            })
            return
        if not self.policy.authorize("start_dirbuster", [("ip", target_ip)]):
            return
        self.dirbuster.start_attack(target_ip, port, is_https, wordlist_name, threads)

    def _handle_stop_dirbuster(self, data):
        self.dirbuster.stop_attack()

    def _handle_start_smb_enum(self, data):
        target_ip = data.get("target_ip")
        # A port outside 1..65535 raises OverflowError inside socket.connect,
        # on a worker thread, where it becomes a scan that never reports.
        port = self._bounded_int(data.get("port"), 445, 1, 65535)
        if not target_ip:
            self.emit("smb_enum_error", {"message": "Missing target_ip"})
            return
        if not self.policy.authorize("start_smb_enum", [("ip", target_ip)]):
            return
        self.smb_enum.start_enum(target_ip, port)

    # ── Phase 6 Sprint D: Advanced WiFi Intelligence ──

    def _handle_start_probe_monitor(self, data):
        interface = data.get("interface")
        self.probe_monitor.start(interface=interface)

    def _handle_stop_probe_monitor(self, data):
        self.probe_monitor.stop()

    def _handle_get_probe_summary(self, data):
        summary = self.probe_monitor.get_summary()
        self.emit("probe_summary", {
            "clients": summary,
            "total": len(summary),
        })

    def _handle_start_passive(self, data):
        interface = data.get("interface")
        duration = data.get("duration")  # None = unlimited
        self.passive.start(interface=interface, duration=duration)

    def _handle_stop_passive(self, data):
        self.passive.stop()

    def _handle_get_passive_summary(self, data):
        summary = self.passive.get_summary()
        # The live feed is rate limited per host, so it says how much it held
        # back. Otherwise a quiet feed on a busy link reads as a quiet network.
        self.emit("passive_summary", {
            "hosts": summary,
            "total": len(summary),
            "feed": self.passive.get_feed_stats(),
        })

    def _get_wordlists_dir(self):
        """Resolve the wordlists directory path (handles Tauri dev vs prod).

        Delegates to the shared resolver so the handler, the bruteforcer, the
        decryptor and DirBuster can never disagree about where the lists are —
        they used to, which is how the UI ended up offering lists that the
        attack modules could not open.
        """
        from wordlists_path import get_wordlists_dir
        return get_wordlists_dir()

    @staticmethod
    def _safe_wordlist_name(filename):
        """Reduce a client-supplied name to a bare filename.

        Without this, a crafted `filename` containing `..\\` let a caller write
        to or delete any path on disk through the wordlist commands.
        """
        import os
        name = os.path.basename(str(filename or "").strip().replace("\\", "/"))
        if not name or name in (".", ".."):
            return None
        return name

    def _handle_get_wordlists(self, data):
        """Every readable list, from the build and from this operator's uploads.

        Reads two directories now. The bundled one is read-only on an installed
        copy, so uploads live in a per-user directory — see
        `wordlists_path.writable_wordlists_dir()`. Each entry says which it came
        from, because the UI offers a delete and only one of them can be deleted.
        """
        from wordlists_path import list_wordlists, writable_wordlists_dir
        lists = [{"name": w["name"], "size": w["size"], "origin": w["origin"]}
                 for w in list_wordlists()]
        # Always an object: emit() coerces a falsy payload to {}, so sending a
        # bare list meant an empty wordlists folder arrived as {} and the UI's
        # .map() threw.
        self.emit("wordlists_list", {
            "wordlists": lists,
            "total": len(lists),
            "upload_dir": writable_wordlists_dir(),
        })

    def _handle_upload_wordlist(self, data):
        import os
        filename = self._safe_wordlist_name(data.get("filename"))
        content = data.get("content")
        append = data.get("append", False)
        is_final = data.get("is_final", True)

        if not filename or content is None:
            self.emit("error", {"message": "Filename or content missing"})
            return
        if not filename.endswith(".txt"):
            self.emit("error", {"message": "Wordlists must be .txt files"})
            return

        # Never the bundled directory: on an installed copy it is under
        # %ProgramFiles% and this write needs elevation, so the upload button did
        # not work at all for an ordinary operator.
        from wordlists_path import writable_wordlists_dir
        wordlists_dir = writable_wordlists_dir()

        filepath = os.path.join(wordlists_dir, filename)
        try:
            os.makedirs(wordlists_dir, exist_ok=True)
            mode = 'a' if append else 'w'
            with open(filepath, mode, encoding='utf-8', errors='replace') as f:
                f.write(content)
            if is_final:
                self.emit("wordlist_saved", {"name": filename, "path": filepath})
                self._handle_get_wordlists({})
        except Exception as e:
            self.emit("wordlist_error", {
                "name": filename,
                "message": f"Failed to save wordlist to {wordlists_dir}: {str(e)}",
            })

    def _handle_delete_wordlist(self, data):
        import os
        filename = self._safe_wordlist_name(data.get("filename"))
        if not filename:
            self.emit("wordlist_error", {"message": "No wordlist name given"})
            return

        # Only an uploaded list can be deleted. A bundled one is part of the
        # installation: removing it would need elevation, and the operator would
        # read the resulting permission error as a bug rather than as a refusal.
        # Saying which it is costs one branch and answers the question.
        from wordlists_path import writable_wordlists_dir, get_wordlists_dir
        wordlists_dir = writable_wordlists_dir()
        filepath = os.path.join(wordlists_dir, filename)
        if not os.path.exists(filepath):
            if os.path.exists(os.path.join(get_wordlists_dir(), filename)):
                self.emit("wordlist_error", {
                    "name": filename,
                    "message": ("This list ships with the application and cannot be "
                                "deleted. Only lists you uploaded can be removed."),
                })
            else:
                self.emit("wordlist_error", {"name": filename, "message": "Wordlist not found"})
            return
        try:
            os.remove(filepath)
            self._handle_get_wordlists({})
        except Exception as e:
            self.emit("wordlist_error", {"name": filename, "message": f"Failed to delete wordlist: {str(e)}"})

    def _handle_get_interfaces(self, data):
        interfaces = []
        try:
            interfaces = self.wifi.get_available_interfaces()
        except Exception as e:
            self.emit("error", {"message": f"WiFi Error: {str(e)}"})
            
        com_ports = []
        try:
            com_ports = GPSReader.get_available_ports()
        except Exception as e:
            self.emit("error", {"message": f"Serial Error: {str(e)}"})
            
        self.emit("interfaces_list", {
            "interfaces": interfaces,
            "com_ports": com_ports
        })

    def _handle_test_hardware(self, data):
        """Run a temporary diagnostic test for GPS and Wi-Fi"""
        com_port = data.get("com_port", "COM3")
        baud_rate = self._bounded_int(data.get("baud_rate"), 9600, 300, 921600)
        interface_name = data.get("interface_name", None)
        
        def run_test():
            self.emit("diagnostic_log", {"message": f"[SYSTEM] Initiating hardware diagnostic..."})
            self.emit("diagnostic_log", {"message": f"----------------------------------------"})
            
            # 1. Test GPS
            #
            # A serial port is exclusive on Windows, so opening a second handle
            # to one this engine already holds fails with "Access is denied" —
            # the diagnostic was competing with our own running scan and blaming
            # the hardware for it. If the scan already owns the port, read from
            # the handle it has instead of fighting for a new one.
            import serial
            from gps.reader import describe_serial_error

            if self.gps.is_connected() and self.gps.port == com_port:
                self.emit("diagnostic_log", {"message": f"[GPS] {com_port} is already open for the active scan - reading from that connection."})
                lines_read = 0
                deadline = time.time() + 6
                while lines_read < 8 and time.time() < deadline:
                    try:
                        raw = self.gps.serial.readline().decode('ascii', errors='ignore').strip()
                    except Exception as e:
                        self.emit("diagnostic_log", {"message": f"[GPS ERROR] Read failed: {e}"})
                        break
                    if raw:
                        self.emit("diagnostic_log", {"message": f"[GPS RAW] {raw}"})
                        lines_read += 1
                if lines_read == 0:
                    self.emit("diagnostic_log", {"message": f"[GPS WARNING] Port is open but silent. The receiver may still be acquiring, or it has no sky view."})
            else:
                self.emit("diagnostic_log", {"message": f"[GPS] Opening port {com_port} at {baud_rate} baud..."})
                try:
                    with serial.Serial(com_port, baud_rate, timeout=1) as ser:
                        self.emit("diagnostic_log", {"message": f"[GPS] Port opened successfully. Reading NMEA stream..."})
                        lines_read = 0
                        for _ in range(8): # Read a few lines
                            line = ser.readline().decode('ascii', errors='ignore').strip()
                            if line:
                                self.emit("diagnostic_log", {"message": f"[GPS RAW] {line}"})
                                lines_read += 1
                        if lines_read == 0:
                            self.emit("diagnostic_log", {"message": f"[GPS WARNING] No data received from {com_port}. Device might be initializing or indoors."})
                except Exception as e:
                    # Report the cause, not the errno. "Access is denied" tells
                    # the operator nothing they can act on.
                    self.emit("diagnostic_log", {"message": f"[GPS ERROR] {describe_serial_error(com_port, e)}"})
                    if self.scanning:
                        self.emit("diagnostic_log", {"message": f"[GPS HINT] A scan is currently running. Stop it and test again."})
                
            self.emit("diagnostic_log", {"message": f"----------------------------------------"})
            
            # 2. Test Wi-Fi
            import pywifi
            self.emit("diagnostic_log", {"message": f"[WIFI] Initializing PyWiFi adapter..."})
            try:
                wifi = pywifi.PyWiFi()
                interfaces = wifi.interfaces()
                iface = None
                
                if interfaces:
                    if interface_name:
                        for i in interfaces:
                            if i.name() == interface_name:
                                iface = i
                                break
                    if not iface:
                        iface = interfaces[0]
                        
                    self.emit("diagnostic_log", {"message": f"[WIFI] Selected interface: {iface.name()}"})
                    self.emit("diagnostic_log", {"message": f"[WIFI] Triggering active scan (3 seconds)..."})
                    iface.scan()
                    time.sleep(3)
                    results = iface.scan_results()
                    self.emit("diagnostic_log", {"message": f"[WIFI SUCCESS] Discovered {len(results)} access points nearby."})
                else:
                    self.emit("diagnostic_log", {"message": f"[WIFI WARNING] No Wi-Fi interfaces found on this system."})
            except Exception as e:
                self.emit("diagnostic_log", {"message": f"[WIFI ERROR] {str(e)}"})
                
            self.emit("diagnostic_log", {"message": f"----------------------------------------"})
            self.emit("diagnostic_log", {"message": f"[SYSTEM] Diagnostic complete."})
            self.emit("diagnostic_complete", {})

        threading.Thread(target=run_test, daemon=True).start()

    def _handle_run_benchmark(self, data):
        """Run a full Wi-Fi environment scan for antenna benchmarking"""
        interface_name = data.get("interface_name", None)

        def run_benchmark():
            start_time = time.time()
            try:
                import pywifi
                wifi = pywifi.PyWiFi()
                interfaces = wifi.interfaces()
                iface = None

                if interfaces:
                    if interface_name:
                        for i in interfaces:
                            if i.name() == interface_name:
                                iface = i
                                break
                    if not iface:
                        iface = interfaces[0]

                    # Multi-pass scan for thorough coverage
                    seen = {}  # bssid -> {rssi, freq}
                    NUM_PASSES = 3
                    PASS_WAIT = 4  # seconds per pass

                    for scan_pass in range(NUM_PASSES):
                        iface.scan()
                        time.sleep(PASS_WAIT)
                        results = iface.scan_results()

                        for r in results:
                            bssid = getattr(r, 'bssid', '') or ''
                            if not bssid:
                                continue
                            rssi = getattr(r, 'signal', -100) or -100
                            # Try multiple attribute names for frequency
                            freq = getattr(r, 'freq', 0) or getattr(r, 'frequency', 0) or 0

                            # Keep strongest RSSI per BSSID
                            if bssid not in seen or rssi > seen[bssid]['rssi']:
                                seen[bssid] = {'rssi': rssi, 'freq': freq}

                        self.emit("benchmark_progress", {"aps_found": len(seen)})

                    # Build final results
                    rssi_values = []
                    channels = []
                    for info in seen.values():
                        rssi_values.append(info['rssi'])
                        channels.append(freq_to_channel(info['freq']))

                    duration_ms = int((time.time() - start_time) * 1000)
                    self.emit("benchmark_result", {
                        "rssi_values": rssi_values,
                        "channels": channels,
                        "total_aps": len(rssi_values),
                        "duration_ms": duration_ms
                    })
                else:
                    self.emit("benchmark_error", {"message": "No Wi-Fi interfaces found."})
            except Exception as e:
                self.emit("benchmark_error", {"message": str(e)})

        threading.Thread(target=run_benchmark, daemon=True).start()

    def _handle_purge_data(self, data):
        self.wifi.clear_data()
        self._ap_cache = {}
        self.clients.reset()
        self.emit("data_purged", {})

    def _handle_ping(self, data):
        self.emit("pong", {"status": "alive"})

    # _handle_status is defined below (after _gps_loop) with full GPS/WiFi status

    def _handle_start_scan(self, data):
        if self.scanning:
            # Returning silently here made the Start button look broken whenever
            # a scan thread had died but self.scanning was still True.
            self.emit("scan_error", {"message": "A scan is already running. Stop it before starting another."})
            return

        # A new run is a new baseline.
        #
        # Nothing reset these between runs, so the reference position survived
        # from one scan to the next and from the simulator into a live survey --
        # where it rejected every real fix, silently, for the rest of the process.
        with self._gps_state_lock:
            self._reset_gps_baseline()

        mission_id = data.get("mission_id", "unknown")
        com_port = data.get("com_port", "COM3")
        baud_rate = self._bounded_int(data.get("baud_rate"), 9600, 300, 921600)
        use_simulator = data.get("simulate", False)
        interface_name = data.get("interface_name", None)
        # Straight into time.sleep() in the scan loop. A negative value raises
        # ValueError there and kills the loop; infinity or a very large one is a
        # scan that never ticks again and a Stop button with nothing to stop.
        self.scan_interval = self._bounded_float(data.get("scan_interval"), 3.0, 0.5, 300.0)
        
        self.scanning = True
        self.simulating = use_simulator

        if not use_simulator:
            # The operator is about to look at real access points; tell the UI
            # straight away which one (if any) this machine is actually on.
            self._handle_get_net_context({})

        if self.simulating:
            # A scenario, not a single mock AP: a rehearsal has to exercise
            # localization, rogue scoring and coverage or it cannot show the
            # operator what their own report will look like.
            from scanner.simulator import Simulator
            from scanner.ap_track import ApTracker
            self.simulator = Simulator()
            # Its own tracker, so a rehearsal never mixes trend state into the
            # live scanner's.
            self.sim_tracker = ApTracker()
            self.emit("simulation_started", self.simulator.describe())

        # Start Hardware
        if not self.simulating:
            # Note: PyWiFi MUST be initialized and started inside the background thread!
            self.target_interface_name = interface_name
            gps_ok, gps_message = self.gps.start(port=com_port, baudrate=baud_rate)
            if not gps_ok:
                # This used to fail silently: the exception was swallowed, the
                # port stayed None, and the operator drove with the indicator on
                # "NO FIX" — indistinguishable from a receiver still acquiring.
                # Scanning continues, because Wi-Fi data without coordinates is
                # still worth collecting, but say plainly what was lost.
                self.emit("gps_error", {"message": gps_message, "port": com_port})
                self.emit("diagnostic_log", {"message": f"[GPS ERROR] {gps_message}"})
                logger.warning("GPS unavailable: %s", gps_message)
            else:
                logger.info("GPS: %s", gps_message)

        self.emit("scan_started", {"mission_id": mission_id, "mode": "simulator" if use_simulator else "hardware"})

        # Start background loop threads
        self.wifi_thread = threading.Thread(target=self._wifi_loop, daemon=True)
        self.gps_thread = threading.Thread(target=self._gps_loop, daemon=True)
        self.wifi_thread.start()
        self.gps_thread.start()

    def _handle_stop_scan(self, data):
        was_simulating = self.simulating
        self.scanning = False
        self.wifi.stop()
        self.gps.stop()
        
        if self.wifi_thread:
            self.wifi_thread.join(timeout=2)
        if self.gps_thread:
            self.gps_thread.join(timeout=2)

        # A simulated survey never touches the live scanner's tracker, so
        # counting that one reported 0 access points at the end of a rehearsal.
        if was_simulating and self.sim_tracker is not None:
            total = len(self.sim_tracker.discovered_aps)
        else:
            total = len(self.wifi.get_discovered_aps())

        self.emit("scan_stopped", {"total_aps": total, "simulated": was_simulating})
        self.simulator = None
        self.sim_tracker = None

    def _wifi_loop(self):
        """Background loop for OS Wi-Fi Scans.

        Wrapped so a single exception cannot silently kill scanning: the loop
        used to die without a trace while self.scanning stayed True, which made
        every later Start look like a dead button.
        """
        try:
            self._wifi_loop_inner()
        except Exception as e:
            self.scanning = False
            self.emit("scan_error", {"message": f"Wi-Fi scan loop stopped: {e}"})
            self.emit("scan_stopped", {"total_aps": len(self.wifi.get_discovered_aps()), "aborted": True})

    def _gps_loop(self):
        """Background loop for reading Serial Port (see _wifi_loop on wrapping)."""
        try:
            self._gps_loop_inner()
        except Exception as e:
            self.emit("gps_error", {"message": f"GPS loop stopped: {e}"})

    def _wifi_loop_inner(self):
        if not self.simulating:
            # FIX: Initialize PyWiFi inside the thread context to avoid Windows COM threading issues!
            import pywifi
            self.wifi.wifi = pywifi.PyWiFi()
            self.wifi.set_interface(getattr(self, 'target_interface_name', None))
            self.wifi.start()
            
        while self.scanning:
            if self.simulating:
                # The scenario drives both position and signal. Fixes go through
                # _validate_gps like a real receiver's so the rehearsal exercises
                # the same quality gate.
                sim_fix = self.simulator.fix()
                lat, lon = self._validate_gps(
                    sim_fix["latitude"], sim_fix["longitude"], sim_fix["hdop"]
                )
                results = []
                for raw in self.simulator.observe():
                    # Built by the same tracker the live scanner uses, so trend —
                    # which is what pins an AP on the map — behaves identically.
                    results.append(self.sim_tracker.build(
                        bssid=raw["bssid"],
                        ssid=raw["ssid"],
                        vendor=raw["vendor"],
                        encryption=raw["encryption"],
                        is_vulnerable=raw["is_vulnerable"],
                        rssi=raw["rssi"],
                        frequency=raw["frequency"],
                    ))
                if self.scanning and results:
                    self._publish_aps(results, lat, lon, simulated=True)
                time.sleep(getattr(self, 'scan_interval', 2.0))
                continue

            # Hardware Mode
            if not self.wifi.has_interface():
                self.emit("error", {"message": "No Wi-Fi interface found. Enable simulator."})
                time.sleep(5)
                continue

            self.wifi.trigger_scan()
            time.sleep(getattr(self, 'scan_interval', 1.5)) # 1.5s = ~16m at 40km/h (was 3s = ~33m)
            
            # Fetch GPS *AFTER* the scan so coordinates aren't behind the car!
            fix = self.gps.get_position()
            raw_lat = fix['latitude'] if fix else None
            raw_lon = fix['longitude'] if fix else None
            hdop = (fix.get('hdop') if fix else None)
            
            # GPS QUALITY + OUTLIER DETECTION
            lat, lon = self._validate_gps(raw_lat, raw_lon, hdop)
            
            results = self.wifi.get_results()

            # A scan that could not read the radio is not a scan that found
            # nothing. Reported once per transition rather than every cycle, so
            # a persistent driver fault does not bury the feed.
            wifi_error = getattr(self.wifi, "last_error", None)
            if wifi_error:
                if getattr(self, "_wifi_error_reported", None) != wifi_error:
                    self._wifi_error_reported = wifi_error
                    self.emit("scan_error", {
                        "message": (
                            f"The wireless interface returned no scan results: {wifi_error}. "
                            "This is a fault in the adapter or its driver, not an observation "
                            "about the networks around you — nothing here means the spectrum is "
                            "empty."
                        ),
                        "recoverable": True,
                    })
            elif getattr(self, "_wifi_error_reported", None):
                self._wifi_error_reported = None
                self.emit("scan_error", {
                    "message": "The wireless interface is returning scan results again.",
                    "recovered": True,
                })

            if self.scanning and results:
                self._publish_aps(results, lat, lon, simulated=False)

            time.sleep(0.5)

    def _publish_aps(self, results, lat, lon, simulated):
        """Stamp position, score for rogue APs and emit one batch.

        Shared by the live scan and the simulator on purpose: a rehearsal that
        went through a different publish path would not rehearse the verdicts,
        the position stamping or the batch shape the report is built from.
        """
        for ap in results:
            # Always stamp validated GPS on every AP.
            # Frontend handles peak tracking to pin at closest approach.
            ap['latitude'] = lat
            ap['longitude'] = lon
            ap['simulated'] = simulated

        # Rogue-AP scoring runs in the engine over every AP seen so far,
        # not just this batch: a twin is only visible relative to its
        # peers, so a per-batch view would miss pairs split across scans.
        for ap in results:
            if ap.get('bssid'):
                self._ap_cache[ap['bssid']] = ap
        try:
            verdicts = evil_twin.analyze(list(self._ap_cache.values()))
            for ap in results:
                verdict = verdicts.get(ap.get('bssid'))
                if verdict:
                    ap['is_evil_twin'] = verdict['is_evil_twin']
                    ap['rogue_verdict'] = verdict['verdict']
                    ap['rogue_score'] = verdict['score']
                    ap['rogue_indicators'] = verdict['indicators']
        except Exception as e:
            # Analysis must never take the scan down with it.
            self.emit("error", {"message": f"Rogue AP analysis failed: {e}"})

        self.emit("aps_batch", {"aps": results, "total": len(results)})

        # Trigger auto-attack chain if enabled. Never on simulated APs: the
        # chain puts real frames on the air, and the BSSIDs in a scenario
        # belong to nobody — attacking them would be both pointless and the
        # one way a rehearsal could reach outside itself.
        if self.auto_attack.enabled and not simulated:
            self.auto_attack.on_scan_complete(results)

    def _gps_loop_inner(self):
        while self.scanning:
             if self.simulating:
                 # The vehicle actually moves, so the GPS trail on the map is a
                 # route rather than a single dot. A stationary trail cannot
                 # rehearse coverage, and localization needs the baseline that
                 # only movement provides.
                 if self.simulator is None:
                     time.sleep(0.5)
                     continue
                 sim_fix = self.simulator.fix()
                 valid_lat, valid_lon = self._validate_gps(
                     sim_fix["latitude"], sim_fix["longitude"], sim_fix["hdop"]
                 )
                 if valid_lat is not None:
                     self.emit("gps_update", {
                         **sim_fix,
                         "latitude": valid_lat,
                         "longitude": valid_lon,
                         "simulated": True,
                     })
                 time.sleep(1)
                 continue

             # Hardware Mode
             if not self.gps.is_connected():
                 # Don't spam errors, just wait
                 time.sleep(2)
                 continue
                 
             # A receiver that stopped sending does not report an error — the
             # serial handle stays open, so is_connected() above is still true.
             # Say it once per transition rather than every loop, and say it
             # plainly: a silent GPS is why a whole drive can end up pinned to
             # one coordinate.
             if self.gps.is_stale():
                 if not getattr(self, "_gps_stale_reported", False):
                     self._gps_stale_reported = True
                     age = round(self.gps.fix_age_seconds(), 1)
                     self.emit("gps_error", {
                         "message": (
                             f"No GPS fix for {age}s — the receiver has stopped sending. "
                             "Access points found from now on will be recorded with no position "
                             "rather than with the last known one."
                         ),
                         "stale": True,
                         "fix_age_seconds": age,
                     })
             elif getattr(self, "_gps_stale_reported", False):
                 self._gps_stale_reported = False
                 self.emit("gps_error", {
                     "message": "GPS fix recovered.",
                     "stale": False,
                     "recovered": True,
                 })

             if self.gps.update(): # Returns True if new NMEA was parsed
                 fix = self.gps.get_position()
                 if fix:
                     # Apply quality + outlier detection to GPS trail too
                     hdop = fix.get('hdop')
                     valid_lat, valid_lon = self._validate_gps(
                         fix.get('latitude'), fix.get('longitude'), hdop
                     )
                     if valid_lat is not None:
                         self.emit("gps_update", {
                             **fix,
                             "latitude": valid_lat,
                             "longitude": valid_lon,
                         })
             else:
                 time.sleep(0.1) # Small sleep to prevent CPU hogging if no data

    def _handle_status(self, data):
        self.emit(
            "status",
            {
                "scanning": self.scanning,
                "gps_locked": self.gps.has_fix() if not self.simulating else True,
                "wifi_ready": self.wifi.has_interface() if not self.simulating else True,
            },
        )

    @staticmethod
    def _haversine(lat1, lon1, lat2, lon2) -> float:
        """Calculate distance in meters between two GPS coordinates."""
        R = 6371000  # Earth radius in meters
        phi1 = math.radians(lat1)
        phi2 = math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlam = math.radians(lon2 - lon1)
        
        a = math.sin(dphi / 2) ** 2 + \
            math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2) ** 2
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    #: Consecutive rejected fixes after which the stored reference is rebuilt
    #: rather than trusted. At roughly one fix a second this is a few seconds of
    #: refusals -- long enough that a single bad reading cannot move the baseline,
    #: short enough that a survey is not lost to one stale reference.
    _GPS_REJECTS_BEFORE_REBASELINE = 20

    def _reset_gps_baseline(self, lat=None, lon=None, when=None):
        """
        Forget the stored reference position, optionally seeding a new one.

        Called with no arguments at the start of every scan, because a new run is
        a new baseline: the rig may have been driven to another city, or the
        previous run may have been the simulator, whose origin is hard-coded to
        Bangkok. Called with a fix from `_validate_gps` when a long run of
        rejections has shown the stored reference to be the thing that is wrong.

        Assumes the caller holds `_gps_state_lock`, or that no scan is running.
        """
        self._last_valid_lat = lat
        self._last_valid_lon = lon
        self._last_valid_time = when if lat is not None else None
        self._gps_rejects = 0
        self._gps_reject_reported = False

    def _validate_gps(self, lat, lon, hdop=0):
        """Validate GPS reading against quality and outlier detection.
        
        Returns (lat, lon) if valid, (None, None) if rejected.
        Two-stage validation:
          1. HDOP Quality: reject readings with HDOP > 5.0 (poor satellite geometry)
          2. Speed Check: reject readings implying > 200 km/h movement

        Called from two threads — the Wi-Fi scan loop and the GPS loop — so the
        whole comparison runs under a lock. The three `_last_valid_*` fields are
        one value, not three: reading a latitude from one fix against a longitude
        and a timestamp from another produces a meaningless distance, and the
        consequence is silent either way (a good fix discarded as a jump, so the
        AP is recorded with no position, or a real jump waved through).
        """
        if lat is None or lon is None:
            return None, None

        # Stage 1: HDOP Quality Filter
        # HDOP = Horizontal Dilution of Precision (lower = better)
        #   <1: Ideal  |  1-2: Excellent  |  2-5: Good  |  >5: Reject
        #
        # None, and 0, both mean "not reported" — accept, because some receivers
        # do not state it and refusing every fix from those would discard the whole
        # survey. None is the honest absence: `gps/reader.py` writes `hdop` only in
        # the GGA branch, and an RMC-only receiver used to leave the key missing,
        # which the caller read as `.get('hdop', 0)` — a measured, ideal zero. So
        # this gate could never fire for such a receiver, and the engine reported a
        # quality it had never measured.
        if hdop is not None and hdop > 5.0:
            return None, None

        now = time.time()

        with self._gps_state_lock:
            # First valid reading: accept and initialize tracking
            if self._last_valid_lat is None:
                self._last_valid_lat = lat
                self._last_valid_lon = lon
                self._last_valid_time = now
                return lat, lon

            # Stage 2: Speed-based Outlier Detection
            time_diff = now - self._last_valid_time
            if time_diff < 0.1:  # Avoid division by near-zero
                return lat, lon  # Accept if timestamps are too close

            distance = self._haversine(
                self._last_valid_lat, self._last_valid_lon, lat, lon
            )
            implied_speed = distance / time_diff  # m/s

            if implied_speed > self._max_speed_ms:
                # GPS JUMP DETECTED. Reject the reading, but count the run.
                #
                # This used to be an unqualified `return None, None`, and the
                # baseline was never refreshed or reset anywhere: the three fields
                # were written in __init__ and here, and nothing in
                # _handle_start_scan, _handle_stop_scan or _handle_purge_data
                # touched them. So one wrong baseline voided positioning for the
                # rest of the process.
                #
                # It was reachable from the UI in two clicks. The simulator's
                # origin is hard-coded to Bangkok, so a rehearsal followed by a
                # real scan anywhere else left the simulated coordinate as the
                # baseline, and every true fix implied an impossible speed. The
                # field version is a receiver's first post-cold-start fix landing
                # at a stale almanac position.
                #
                # The operator saw nothing at all: no event was emitted here,
                # _handle_status still reported gps_locked via has_fix(), and
                # gps_update simply never fired, so a whole drive produced access
                # points with latitude None and no explanation.
                #
                # A long run of rejections is now taken as evidence about the
                # baseline rather than about the fixes. After
                # _GPS_REJECTS_BEFORE_REBASELINE consecutive refusals the receiver
                # is believed and the baseline is rebuilt from the current fix,
                # which is also the honest reading: one reading disagreeing with
                # the baseline is suspect, twenty consecutive ones mean the
                # baseline is.
                self._gps_rejects += 1

                if not self._gps_reject_reported:
                    self._gps_reject_reported = True
                    self.emit("gps_error", {
                        "message": (
                            f"GPS fixes are being rejected as impossible jumps: this one implies "
                            f"{implied_speed * 3.6:.0f} km/h from the last accepted position. "
                            "Access points found now are recorded with no position. If the rig "
                            "was moved, or a simulated survey ran before this one, the reference "
                            "position is stale and will be rebuilt automatically."
                        ),
                        "implied_speed_kmh": round(implied_speed * 3.6, 1),
                        "rejected_lat": lat,
                        "rejected_lon": lon,
                    })

                if self._gps_rejects >= self._GPS_REJECTS_BEFORE_REBASELINE:
                    self._reset_gps_baseline(lat, lon, now)
                    self.emit("gps_error", {
                        "message": (
                            f"{self._gps_rejects} consecutive GPS fixes disagreed with the stored "
                            "reference position, so the reference has been rebuilt from the "
                            "current fix. Positions are being recorded again. Access points found "
                            "while this was happening have no position and are reported as "
                            "unresolved."
                        ),
                        "rebaselined": True,
                    })
                    return lat, lon

                return None, None

            # Valid reading: update tracking state
            self._gps_rejects = 0
            self._gps_reject_reported = False
            self._last_valid_lat = lat
            self._last_valid_lon = lon
            self._last_valid_time = now
            return lat, lon

    # ── Phase 7: Advanced Recon Handlers ──

    def _handle_start_traceroute(self, data):
        target_ip = data.get("target_ip")
        # 30 hops is the platform default and 64 is the protocol's ceiling;
        # beyond that the extra hops cannot exist, they only extend the timeout.
        max_hops = self._bounded_int(data.get("max_hops"), 30, 1, 64)
        timeout = self._bounded_int(data.get("timeout"), 2, 1, 10)
        if not target_ip:
            self.emit("traceroute_error", {"message": "Missing target_ip"})
            return
        # An argument that begins with '-' is read by tracert as an option, not
        # as a destination. There is no shell here, so this is the residual
        # injection surface and it is closed at the boundary.
        if str(target_ip).startswith("-"):
            self.emit("traceroute_error", {"message": "Invalid target_ip"})
            return
        if not self.policy.authorize("start_traceroute", [("ip", target_ip)]):
            return
        self.traceroute.start_traceroute(target_ip, max_hops, timeout)

    def _handle_stop_traceroute(self, data):
        """Kill a running traceroute. It is a single blocking subprocess."""
        self.traceroute.stop()

    def _handle_start_vlan_detect(self, data):
        subnets = data.get("subnets", [])
        arp_cache = data.get("arp_cache")
        if not subnets:
            # Auto-detect subnets from LAN scanner
            subnets = self.lan.get_all_subnets()
        subnets = [s for s in subnets
                   if self.policy.authorize("start_vlan_detect", [("cidr", s)])]
        if not subnets:
            self.emit("vlan_scan_completed", {
                "subnets_analyzed": 0,
                "vlan_map": [],
                "findings": [{"type": "error", "severity": "INFO", "message": "No subnets detected"}]
            })
            return
        # Use LAN scanner's ARP cache if available
        if not arp_cache and hasattr(self.lan, 'arp_cache'):
            arp_cache = self.lan.arp_cache
        self.vlan_detector.start_detection(subnets, arp_cache)

    def _handle_start_deep_ssl_scan(self, data):
        target_ip = data.get("target_ip")
        port = self._bounded_int(data.get("port"), 443, 1, 65535)
        if not target_ip:
            self.emit("ssl_scan_error", {"message": "Missing target_ip"})
            return
        if not self.policy.authorize("start_deep_ssl_scan", [("ip", target_ip)]):
            return
        import threading

        def run():
            # The thread body had no try/except at all. `deep_ssl_scan` parses
            # certificate structures from a remote host, so a malformed
            # issuer/subject RDN is enough to raise — and then
            # `deep_ssl_scan_completed` never fires and the panel waits
            # indefinitely with no error anywhere. Compare `_handle_run_gpr`,
            # which was already guarded; this is the same shape.
            try:
                from scanner.ssl_check import deep_ssl_scan
                result = deep_ssl_scan(target_ip, port)
                self.emit("deep_ssl_scan_completed", {
                    "target": target_ip, "port": port, **result
                })
            except Exception as e:
                logger.exception("deep SSL scan failed for %s:%s", target_ip, port)
                self.emit("ssl_scan_error", {
                    "target": target_ip,
                    "port": port,
                    "message": f"The TLS inspection could not complete: {type(e).__name__}: {e}",
                })

        threading.Thread(target=run, daemon=True).start()

    def _handle_run_gpr(self, data):
        """
        Receives raw RSSI measurements from the frontend and runs GPR analysis.
        data format:
        {
            "bssid": "00:11:...",
            "measurements": [{"lat": 13.1, "lon": 100.1, "rssi": -55}, ...],
            "grid_resolution": 100
        }
        """
        bssid = data.get("bssid")
        measurements = data.get("measurements", [])
        # The search is O(n^2) in this number: the default is 10,000 cells and
        # the ceiling is 160,000. 10,000 would have been a hundred million.
        grid_res = self._bounded_int(data.get("grid_resolution"), 100, 10, 400)

        if not bssid or not measurements:
            self.emit("gpr_error", {"message": "Missing BSSID or measurements"})
            return

        import threading
        def run():
            from scanner.gpr_engine import calculate_gpr_location
            try:
                self.emit("diagnostic_log", {"message": f"[GPR] Initiating matrix for {bssid} with {len(measurements)} points..."})
                result = calculate_gpr_location(measurements, grid_resolution=grid_res)
                if result:
                    self.emit("gpr_result", {"bssid": bssid, **result})
                    self.emit("diagnostic_log", {"message": f"[GPR] Analysis complete for {bssid}. Peak RSSI: {result['peak_rssi']:.1f}"})
                else:
                    self.emit("gpr_error", {"bssid": bssid, "message": "GPR analysis failed or insufficient data"})
            except Exception as e:
                self.emit("gpr_error", {"bssid": bssid, "message": str(e)})

        threading.Thread(target=run, daemon=True).start()

    # ── Phase 8: WiFi Attack Enhancement ────────────────────
    def _handle_scan_wps(self, data):
        """Scan nearby beacons for WPS Information Elements."""
        interface = data.get("interface")
        # Also clamped inside the detector. Bounded here as well because this
        # is where the untrusted value arrives, and the detector should not be
        # the only thing standing between a message and a 10-hour sniff.
        duration = self._bounded_int(data.get("duration"), 8, 1, 120)
        self.wps_detector.scan(interface=interface, duration=duration)

    def _handle_stop_wps(self, data):
        """Stop an active WPS scan."""
        self.wps_detector.stop()

    def _handle_export_hashcat(self, data):
        """
        Export a PCAP file to Hashcat .hc22000 format.

        `output_path` used to be passed through untouched and opened with mode
        `'w'` — no extension check, no refusal to overwrite — so an IPC message
        could truncate any file the engine can write, and the engine may be
        running elevated for capture. The shipped UI never sends it, which is
        why it went unnoticed; the sidecar's stdin is not a trusted channel just
        because the bundled frontend happens to be well behaved.
        """
        pcap_path = data.get("pcap_path", "")
        output_path = data.get("output_path")

        if output_path is not None:
            candidate = str(output_path)
            # One extension, and no directory traversal. The default (derived
            # from the capture's own path) is what the UI uses and is unaffected.
            if not candidate.lower().endswith(".hc22000"):
                self.emit("hashcat_export_error", {
                    "message": "Refusing to write a hashcat export to a path that is not "
                               "a .hc22000 file.",
                    "output_path": candidate,
                })
                return
            if os.path.exists(candidate):
                self.emit("hashcat_export_error", {
                    "message": "Refusing to overwrite an existing file. Remove it first or "
                               "choose another name.",
                    "output_path": candidate,
                })
                return

        self.hashcat.export(pcap_path, output_path)

    def _handle_check_hashcat(self, data):
        """Check if hashcat is installed on the system."""
        self.hashcat.check_hashcat()

    def _handle_start_pmkid_capture(self, data):
        """Start PMKID capture on a target BSSID."""
        bssid = data.get("bssid", "")
        interface = data.get("interface")
        # Ten minutes is already a long wait for a PMKID; unbounded is a capture
        # thread that holds the adapter until the app is killed.
        timeout = self._bounded_int(data.get("timeout"), 30, 5, 600)
        if not bssid:
            self.emit("pmkid_error", {"message": "Missing bssid"})
            return
        if not self.policy.authorize_ap("start_pmkid_capture", bssid,
                                        ssid=self._ssid_for(bssid, data)):
            return
        self.capture.start_pmkid_capture(bssid, interface=interface, timeout=timeout)

    def _handle_stop_pmkid(self, data):
        """Stop an active PMKID capture."""
        self.capture.stop_pmkid()

    # ── Phase 9: Auto-Attack Chain ──────────────────────────
    def _handle_set_auto_attack(self, data):
        """Enable or disable automatic attack chain."""
        enabled = data.get("enabled", False)
        self.auto_attack.set_enabled(enabled)

    def _handle_reset_auto_attack(self, data):
        """Reset attacked targets list."""
        self.auto_attack.reset()
