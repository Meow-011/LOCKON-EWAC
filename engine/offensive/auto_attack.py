"""LOCKON EWAC — Auto-Attack Chain Module

Orchestrates automated offensive operations:
  1. Scope filter → keep only APs inside the active engagement
  2. Candidate filter → WPA/WPA2, signal fair or better, not already attempted
  3. PMKID Capture → attempt a PMKID on each remaining target

The capture module writes the .hc22000 itself when a PMKID lands, so there is
no separate export step here. (The earlier docstring claimed one; it never ran.)

The chain is triggered when the operator has 'enableAutoAttack' enabled
in settings. It runs after each normal WiFi scan cycle completes.

Scope is not optional here. This is the one module that picks its own targets,
so without an engagement allowlist it would work through every network the rig
drives past. Every candidate goes through ScopePolicy.filter_bssids first, and
what it declines to touch is recorded in the audit trail alongside what it did.
"""
import threading
import time
import logging

logger = logging.getLogger(__name__)


class AutoAttackChain:
    """Automated attack chain orchestrator."""

    def __init__(self, emit_fn, wps_detector, capture, hashcat, policy):
        self.emit = emit_fn
        self.wps = wps_detector
        self.capture = capture
        self.hashcat = hashcat
        self.policy = policy
        self.enabled = False
        self.running = False
        self._attacked_bssids = set()  # Track already-attacked targets

    def set_enabled(self, enabled: bool):
        """Toggle auto-attack mode."""
        self.enabled = enabled
        if enabled:
            self.emit("auto_attack_enabled", {})
            self.emit("diagnostic_log", {"message": "[AUTO-ATTACK] Chain ARMED. Awaiting scan data..."})
        else:
            self.emit("auto_attack_disabled", {})
            self.emit("diagnostic_log", {"message": "[AUTO-ATTACK] Chain DISARMED."})

    def on_scan_complete(self, scan_results: list):
        """Called after each WiFi scan cycle.
        
        Evaluates discovered APs and launches attack chain
        on viable targets that haven't been attacked yet.
        """
        if not self.enabled or self.running:
            return

        # Filter for WPA/WPA2 targets we haven't attacked yet
        candidates = []
        for ap in scan_results:
            bssid = ap.get("bssid", "")
            encryption = ap.get("encryption", "")
            if bssid in self._attacked_bssids:
                continue
            if encryption in ("WPA", "WPA2"):
                # Prefer strong signals for better capture success
                rssi = ap.get("rssi", -100)
                if rssi >= -75:  # Only attack if signal is fair or better
                    candidates.append(ap)

        if not candidates:
            return

        # Scope gate. Anything not in the engagement is dropped here, before a
        # single frame is sent, and logged as BLOCKED.
        targets = self.policy.filter_bssids("auto_attack", candidates)
        if not targets:
            return

        # Sort by signal strength (strongest first)
        targets.sort(key=lambda x: x.get("rssi", -100), reverse=True)

        # Limit to top 3 targets per cycle to avoid overload
        targets = targets[:3]

        self.running = True
        threading.Thread(target=self._run_chain, args=(targets,), daemon=True).start()

    def _run_chain(self, targets: list):
        """Execute the attack chain on selected targets."""
        try:
            total = len(targets)
            self.emit("auto_attack_started", {
                "target_count": total,
                "targets": [{"bssid": t["bssid"], "ssid": t.get("ssid", ""), "rssi": t.get("rssi", -100)} for t in targets]
            })

            for idx, target in enumerate(targets, 1):
                bssid = target["bssid"]
                ssid = target.get("ssid", "(Hidden)")

                self.emit("auto_attack_progress", {
                    "step": "PMKID_CAPTURE",
                    "target": bssid,
                    "ssid": ssid,
                    "current": idx,
                    "total": total,
                })

                # Mark as attacked immediately to avoid re-attack
                self._attacked_bssids.add(bssid)

                # Attempt PMKID capture (short timeout for auto mode)
                self.capture.start_pmkid_capture(bssid, timeout=15)

                # Wait for capture to finish
                wait_start = time.time()
                while self.capture.pmkid_capturing and (time.time() - wait_start) < 18:
                    time.sleep(0.5)

                # Small delay between targets
                time.sleep(1)

            self.emit("auto_attack_complete", {
                "targets_attempted": total,
                "total_attacked": len(self._attacked_bssids),
            })

        except Exception as e:
            self.emit("auto_attack_error", {"message": str(e)})
        finally:
            self.running = False

    def reset(self):
        """Clear attacked targets list (allows re-attack)."""
        self._attacked_bssids.clear()
        self.emit("diagnostic_log", {"message": "[AUTO-ATTACK] Target history cleared."})

    def get_status(self) -> dict:
        """Return current auto-attack status."""
        return {
            "enabled": self.enabled,
            "running": self.running,
            "attacked_count": len(self._attacked_bssids),
        }
