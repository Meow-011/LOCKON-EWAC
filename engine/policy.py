"""LOCKON EWAC — Engagement Scope Policy & Audit Trail

Every command that puts unsolicited traffic on the air or on the wire has to
clear ScopePolicy.authorize() before the module that performs it is reached.
The gate lives in the engine rather than in the UI on purpose: the UI can be
bypassed by anything that can write to the sidecar's stdin, and "the operator
clicked the right button" is not something a report can stand on.

Default posture is deny. With no scope loaded nothing is authorized, which
means a freshly started rig will refuse every offensive command until the
operator states what they were authorized to touch. That is the intended
behaviour for a wardriving tool — the alternative is a device that attacks
whatever it drives past.

Two modes:
  ALLOWLIST     — the normal engagement. A target must match an entry.
  UNRESTRICTED  — lab / own-network use. Still audited, still requires the
                  operator to have typed an acknowledgement, and the report
                  says plainly that no allowlist was in force.

Matching is deliberately strict:
  BSSID  exact MAC, separator and case insensitive
  SSID   exact network name
  IP     exact address, or inside any allowed CIDR
  CIDR   the requested range must be a *subset* of an allowed CIDR, so
         asking to sweep 10.0.0.0/8 does not pass on the strength of an
         allowlisted 10.0.5.0/24
"""
import ipaddress
from datetime import datetime, timezone

# Commands that can disrupt a network, attempt authentication against it, or
# intercept somebody else's traffic. Anything listed here is gated: it is
# checked against the engagement scope, and both the decision and the target are
# written to the audit trail.
#
# The line is drawn at *harm*, not at *emission*.
#
# Recon commands emit packets too — a port sweep, an SMB enumeration, a
# traceroute — but a misdirected one inconveniences nobody and leaves nothing
# behind. A misdirected command from this set does real damage: a deauth drops
# somebody's connection, an ARP spoof redirects their traffic through this
# machine, and a spray or a brute force can lock out accounts that do not belong
# to the engagement. Those are the acts that need an authorization record behind
# them, and they are the ones whose refusals a reader of the report needs to see.
#
# `auto_attack` is here for a second reason on top of that: it is the only entry
# that selects its own targets. Every other command is aimed by an operator who
# is looking at the target when they click. The chain picks from whatever is in
# range, so the gate is the only thing standing between it and a neighbour's
# access point.
#
# Deliberately NOT gated: the recon and capture commands (`start_intrusion`,
# `start_vuln_scan`, `start_smb_enum`, `start_deep_ssl_scan`,
# `start_vlan_detect`, `start_traceroute`, `start_dirbuster`, `start_capture`,
# `start_pmkid_capture`), passive listening (`probe_monitor`, passive SIGINT),
# and read-only local queries.
#
# If you widen this set, `describe()` publishes it and the report prints it, so
# the document follows automatically. If you narrow it, check what the report
# claims about refusals before you ship — that prose is generated from this set
# precisely so the two cannot drift.
GATED_COMMANDS = {
    "auto_attack",
    "start_strike",
    "start_mitm",
    "start_spray",
    "start_bruteforce",
    # The DEEP sweep's default-credential probe.
    #
    # `start_intrusion` itself is deliberately not gated, on the reasoning above:
    # a port sweep aimed at the wrong subnet inconveniences nobody. That holds
    # for the sweep, and it does not hold for this. Inside `scan_host`,
    # `LANScanner._quick_credential_check` makes eight real SSH, FTP and HTTP
    # Basic login attempts against every host it finds with one of those ports
    # open -- the same act as `start_bruteforce`, which is gated and audited for
    # a single operator-chosen host, spread instead across a whole subnet and
    # every neighbour subnet `get_all_subnets()` turned up.
    #
    # By the line this file draws, that belongs here: it can lock out accounts
    # that do not belong to the engagement, and a reader of the report needs to
    # see which hosts were refused.
    "sweep_credential_check",
}


def normalize_mac(value: str) -> str:
    """Strip separators and upper-case a MAC so AA-BB-cc:dd:ee:ff all match."""
    if not value:
        return ""
    return "".join(c for c in str(value).upper() if c in "0123456789ABCDEF")


class ScopeDenied(Exception):
    """Raised internally when a target falls outside the engagement."""

    def __init__(self, target, kind, reason):
        super().__init__(reason)
        self.target = target
        self.kind = kind
        self.reason = reason


class ScopePolicy:
    """Holds the active engagement scope and decides what may be targeted."""

    def __init__(self, emit):
        self.emit = emit
        self.loaded = False
        self.scope_id = None
        self.engagement_name = None
        self.authorized_by = None
        self.operator = None
        self.reference = None
        self.mode = "ALLOWLIST"
        self.valid_until = None
        self._bssids = set()
        self._ssids = set()
        self._ips = set()
        self._networks = []

    # ── configuration ───────────────────────────────────────────────────────

    def load(self, data: dict):
        """Apply a scope sent by the frontend via the `set_scope` command.

        Passing an empty/None scope clears it, which returns the engine to the
        deny-everything default. That is the correct response to "no active
        engagement" — it is not an error.
        """
        if not data or not data.get("engagement_name"):
            self.__init__(self.emit)
            self.emit("scope_updated", self.describe())
            return

        self.scope_id = data.get("scope_id")
        self.engagement_name = data.get("engagement_name")
        self.authorized_by = data.get("authorized_by")
        self.operator = data.get("operator")
        self.reference = data.get("reference")
        self.mode = "UNRESTRICTED" if data.get("mode") == "UNRESTRICTED" else "ALLOWLIST"
        self.valid_until = data.get("valid_until")

        self._bssids = set()
        self._ssids = set()
        self._ips = set()
        self._networks = []

        for entry in data.get("targets", []) or []:
            kind = str(entry.get("kind", "")).upper()
            value = str(entry.get("value", "")).strip()
            if not value:
                continue
            if kind == "BSSID":
                self._bssids.add(normalize_mac(value))
            elif kind == "SSID":
                self._ssids.add(value)
            elif kind == "IP":
                try:
                    self._ips.add(str(ipaddress.ip_address(value)))
                except ValueError:
                    self.emit("scope_warning", {"message": f"Ignoring malformed IP in scope: {value}"})
            elif kind == "CIDR":
                try:
                    self._networks.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    self.emit("scope_warning", {"message": f"Ignoring malformed CIDR in scope: {value}"})

        self.loaded = True
        self.emit("scope_updated", self.describe())

    def describe(self) -> dict:
        """Current scope, for the UI status strip and the report cover page."""
        return {
            "loaded": self.loaded,
            "scope_id": self.scope_id,
            "engagement_name": self.engagement_name,
            "authorized_by": self.authorized_by,
            "operator": self.operator,
            "reference": self.reference,
            "mode": self.mode,
            "valid_until": self.valid_until,
            "expired": self._is_expired(),
            "counts": {
                "bssid": len(self._bssids),
                "ssid": len(self._ssids),
                "ip": len(self._ips),
                "cidr": len(self._networks),
            },
            "gated_commands": sorted(GATED_COMMANDS),
        }

    # ── decision ────────────────────────────────────────────────────────────

    def authorize(self, command: str, targets, context: dict = None) -> bool:
        """Gate `command` against every target it will touch.

        `targets` is a list of (kind, value) pairs, e.g.
        [("bssid", "AA:BB:..."), ("ip", "192.168.1.10")]. All of them must pass:
        a MITM that is authorized for the victim but not the gateway is still
        out of scope.

        Emits one `audit_event` per target either way, and a single
        `scope_denied` when it refuses, then returns False. Callers must treat
        False as "do not proceed" and must not emit their own started event.
        """
        context = context or {}
        targets = [t for t in (targets or []) if t and t[1]]

        if command not in GATED_COMMANDS:
            return True

        if not self.loaded:
            self._deny(command, targets, "No active engagement scope. Define one in Settings before running offensive modules.", context)
            return False

        if self._is_expired():
            self._deny(command, targets, f"Engagement '{self.engagement_name}' expired on {self.valid_until}.", context)
            return False

        if not targets:
            self._deny(command, targets, "Command carried no identifiable target, so it cannot be checked against the scope.", context)
            return False

        if self.mode == "UNRESTRICTED":
            for kind, value in targets:
                self._audit("ALLOWED", command, kind, value, "UNRESTRICTED mode — no allowlist in force", context)
            return True

        for kind, value in targets:
            ok, reason = self._match(kind, value)
            if not ok:
                self._deny(command, targets, reason, context, failed=(kind, value))
                return False

        for kind, value in targets:
            self._audit("ALLOWED", command, kind, value, f"In scope for '{self.engagement_name}'", context)
        return True

    def authorize_ap(self, command: str, bssid: str, ssid: str = None,
                     context: dict = None) -> bool:
        """Gate a command against one access point, identified either way.

        A BSSID and an SSID are two names for the same subject, so either
        matching is enough. `authorize()` cannot express that — it requires
        *every* entry to pass, which is right when the entries are genuinely
        different subjects (a MITM victim and its gateway) and wrong here.

        This existed as a gap rather than a decision: `filter_bssids()` already
        fell back to the SSID for the auto-attack chain, but capture, PMKID and
        the other per-AP commands passed only a BSSID. An SSID entry in the
        allowlist therefore matched nothing for them, so an estate of 300 access
        points sharing one SSID had to be authorized MAC by MAC — which is
        exactly the friction that makes an operator want to switch the gate off.
        """
        context = context or {}
        if command not in GATED_COMMANDS:
            return True

        if not self.loaded:
            self._deny(command, [("bssid", bssid)],
                       "No active engagement scope. Define one in Settings before running offensive modules.",
                       context)
            return False

        if self._is_expired():
            self._deny(command, [("bssid", bssid)],
                       f"Engagement '{self.engagement_name}' expired on {self.valid_until}.",
                       context)
            return False

        if not bssid and not ssid:
            self._deny(command, [], "Command carried no identifiable target, so it cannot be checked against the scope.", context)
            return False

        if self.mode == "UNRESTRICTED":
            self._audit("ALLOWED", command, "bssid", bssid,
                        "UNRESTRICTED mode — no allowlist in force", context)
            return True

        reason = None
        if bssid:
            ok, reason = self._match("bssid", bssid)
            if ok:
                self._audit("ALLOWED", command, "bssid", bssid,
                            f"In scope for '{self.engagement_name}'", context)
                return True
        if ssid:
            ok, ssid_reason = self._match("ssid", ssid)
            if ok:
                # Recorded against the BSSID, because that is the thing actually
                # touched; the reason says which entry let it through.
                self._audit("ALLOWED", command, "bssid", bssid,
                            f"SSID '{ssid}' is in scope for '{self.engagement_name}'", context)
                return True
            reason = ssid_reason if not bssid else f"{reason} {ssid_reason}"

        self._deny(command, [("bssid", bssid)],
                   reason or "Not in the engagement allowlist.", context,
                   failed=("bssid", bssid))
        return False

    def filter_bssids(self, command: str, aps: list, context: dict = None) -> list:
        """Return only the APs that are in scope.

        Used by the auto-attack chain, which evaluates a whole scan result at
        once: one out-of-scope neighbour should be skipped quietly rather than
        aborting the run, but it is still recorded as BLOCKED so the audit trail
        shows what the rig chose not to touch.
        """
        context = context or {}
        if not self.loaded or self._is_expired():
            if aps:
                self._deny(command, [("bssid", aps[0].get("bssid", ""))],
                           "No active (or non-expired) engagement scope; auto-attack refuses to select targets.", context)
            return []

        allowed = []
        for ap in aps:
            bssid = ap.get("bssid", "")
            ssid = ap.get("ssid", "")
            if self.mode == "UNRESTRICTED":
                allowed.append(ap)
                self._audit("ALLOWED", command, "bssid", bssid, "UNRESTRICTED mode — no allowlist in force", context)
                continue
            ok, reason = self._match("bssid", bssid)
            if not ok and ssid:
                ok, reason = self._match("ssid", ssid)
            if ok:
                allowed.append(ap)
                self._audit("ALLOWED", command, "bssid", bssid, f"In scope for '{self.engagement_name}'", context)
            else:
                self._audit("BLOCKED", command, "bssid", bssid, reason, context)
        return allowed

    def permits_host(self, command: str, ip: str, context: dict = None) -> bool:
        """
        Is `ip` in scope for `command`? Audited, but never toasted.

        The quiet counterpart to `authorize`, for a command issued once per host
        across a whole sweep rather than once per operator click. `authorize`
        emits a `scope_denied` on every refusal, which is right for a button and
        wrong here -- a sweep across a subnet would raise one notification per
        out-of-scope host, and the operator would learn to dismiss them.

        A refusal still earns a BLOCKED audit row, so the report can name the
        hosts the rig declined to authenticate against. The caller is responsible
        for telling the operator *once* that the gate is closed; see
        `sweep_credentials_preflight`.
        """
        context = context or {}
        if command not in GATED_COMMANDS:
            return True
        if not self.loaded or self._is_expired():
            self._audit("BLOCKED", command, "ip", ip,
                        "No active (or non-expired) engagement scope.", context)
            return False
        if self.mode == "UNRESTRICTED":
            self._audit("ALLOWED", command, "ip", ip,
                        "UNRESTRICTED mode — no allowlist in force", context)
            return True
        ok, reason = self._match("ip", ip)
        self._audit("ALLOWED" if ok else "BLOCKED", command, "ip", ip,
                    reason if not ok else f"In scope for '{self.engagement_name}'",
                    context)
        return ok

    def sweep_credentials_preflight(self, context: dict = None) -> bool:
        """
        May the sweep attempt credentials at all this run? Reported once.

        Separated from the per-host check so "there is no engagement scope" is
        stated a single time at the start of a sweep instead of once per host
        found. Returns False with one `scope_denied` when there is nothing to
        check against; the sweep itself continues, because recon is not gated.
        """
        context = context or {}
        command = "sweep_credential_check"
        if command not in GATED_COMMANDS:
            return True
        if not self.loaded:
            self._deny(command, [("ip", "")],
                       "No active engagement scope, so the sweep will not attempt "
                       "default credentials against any host. Port and service "
                       "discovery continues. Define a scope in Settings to enable it.",
                       context)
            return False
        if self._is_expired():
            self._deny(command, [("ip", "")],
                       f"Engagement '{self.engagement_name}' expired on {self.valid_until}, "
                       "so the sweep will not attempt default credentials. Port and "
                       "service discovery continues.",
                       context)
            return False
        return True

    # ── internals ───────────────────────────────────────────────────────────

    def _match(self, kind, value):
        kind = (kind or "").lower()
        value = str(value).strip()

        if kind == "bssid":
            if normalize_mac(value) in self._bssids:
                return True, "BSSID allowlisted"
            return False, f"BSSID {value} is not in the engagement allowlist."

        if kind == "ssid":
            if value in self._ssids:
                return True, "SSID allowlisted"
            return False, f"SSID '{value}' is not in the engagement allowlist."

        if kind == "ip":
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                return False, f"'{value}' is not a valid IP address."
            if str(addr) in self._ips:
                return True, "IP allowlisted"
            for net in self._networks:
                if addr.version == net.version and addr in net:
                    return True, f"IP inside allowlisted {net}"
            return False, f"IP {value} is not in the engagement allowlist."

        if kind == "cidr":
            try:
                requested = ipaddress.ip_network(value, strict=False)
            except ValueError:
                return False, f"'{value}' is not a valid subnet."
            for net in self._networks:
                if requested.version == net.version and requested.subnet_of(net):
                    return True, f"Subnet inside allowlisted {net}"
            return False, f"Subnet {value} is not fully contained in any allowlisted range."

        return False, f"Unknown target kind '{kind}'."

    def _is_expired(self) -> bool:
        if not self.valid_until:
            return False
        raw = str(self.valid_until).strip().replace("Z", "+00:00")
        try:
            deadline = datetime.fromisoformat(raw)
        except ValueError:
            # An unparseable expiry is treated as expired rather than ignored:
            # failing closed is the only safe reading of a broken date here.
            return True
        now = datetime.now(deadline.tzinfo) if deadline.tzinfo else datetime.now()
        return now > deadline

    def _deny(self, command, targets, reason, context, failed=None):
        # Record the target that actually failed. When the refusal is not about
        # a specific target (no scope loaded, expired, nothing to check) fall
        # back to the first one so the audit row still names what was attempted.
        kind, value = failed if failed else (targets[0] if targets else ("", ""))
        self._audit("BLOCKED", command, kind, value, reason, context)
        self.emit("scope_denied", {
            "command": command,
            "target": value,
            "target_kind": (kind or "").upper() or None,
            "reason": reason,
            "engagement_name": self.engagement_name,
            "mode": self.mode if self.loaded else None,
        })

    def _audit(self, decision, command, kind, value, reason, context):
        self.emit("audit_event", {
            "ts": datetime.now(timezone.utc).isoformat(),
            "scope_id": self.scope_id,
            "engagement_name": self.engagement_name,
            "command": command,
            "target": value,
            "target_kind": (kind or "").upper() or None,
            "decision": decision,
            "reason": reason,
            "operator": self.operator,
            "mission_id": context.get("mission_id"),
            "session_id": context.get("session_id"),
            "details": context.get("details"),
        })
