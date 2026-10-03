"""LOCKON EWAC — VLAN / Subnet Boundary Detection Module

Analyzes network topology to detect VLAN segmentation, inter-VLAN routing,
and potential VLAN hopping vectors in enterprise networks.
"""

import ipaddress
import logging
import os
import random
import re
import socket
import struct
import subprocess
import threading
import platform
import time

logger = logging.getLogger("ewac.vlan")


class VLANDetector:
    def __init__(self, emit_cb):
        self.emit = emit_cb

    def detect_vlans(self, subnets, arp_cache=None):
        """Analyze subnets and ARP data to infer VLAN segmentation.

        Args:
            subnets: list of CIDR strings (e.g. ["192.168.1.0/24", "10.0.0.0/24"])
            arp_cache: dict of ip -> mac from the LAN scanner
        """
        self.emit("vlan_scan_started", {
            "message": f"Analyzing {len(subnets)} subnets for VLAN boundaries..."
        })

        findings = []
        vlan_map = []

        # 1. Subnet-based VLAN inference
        #
        # Everything in this block except `gateway_alive` is derived from the
        # CIDR string, not measured, and the payload now says so per field. It
        # previously did not, and the arithmetic was wrong as well as unlabelled:
        # `gateway` was built as "<first three octets>.1" and `broadcast` as
        # "<first three octets>.255" regardless of the prefix length, so for
        # 10.0.0.0/8 it reported a gateway of 10.0.0.1 and a broadcast of
        # 10.0.0.255 -- the first merely unlikely, the second simply false; the
        # broadcast address of that network is 10.255.255.255. Nothing tested
        # either value.
        for i, subnet in enumerate(subnets):
            try:
                net = ipaddress.ip_network(str(subnet).strip(), strict=False)
            except ValueError as e:
                # A subnet that will not parse is reported, not skipped silently
                # and not guessed at. A map that quietly omits a segment reads as
                # a network with fewer segments than it has.
                logger.warning("unparseable subnet %r: %s", subnet, e)
                vlan_map.append({
                    "subnet": subnet,
                    "error": f"not a valid CIDR: {e}",
                    "vlan_id": None,
                    "vlan_id_basis": None,
                    "network_class": None,
                    "gateway": None,
                    "gateway_basis": None,
                    "gateway_alive": None,
                    "broadcast": None,
                })
                continue

            parts = str(net.network_address).split('.')
            vlan_id = self._guess_vlan_id(parts) if net.version == 4 else None

            # The first usable address. Still a convention rather than an
            # observation -- nothing here asks the host which router it uses --
            # but it is now the right address for the prefix rather than for an
            # assumed /24.
            gateway = None
            if net.num_addresses > 2:
                gateway = str(net.network_address + 1)
            elif net.num_addresses == 2:
                # /31: a point-to-point link has no network or broadcast address
                # and either end can be the router. There is no first usable
                # host to name, so none is named.
                gateway = None

            vlan_info = {
                "subnet": str(net),
                "vlan_id": vlan_id,
                # Carried on the wire so a reader cannot mistake it for an
                # observation. The frontend renders this, not the bare number:
                # labelling a segment "VLAN 20" because its third octet is 20 is
                # a guess with a convincing shape, and an operator who writes it
                # into a report has recorded something nobody measured.
                "vlan_id_basis": "inferred from the third octet" if vlan_id is not None else None,
                "network_class": self._classify_network(parts),
                "gateway": gateway,
                "gateway_basis": "assumed: first usable address in the prefix" if gateway else None,
                "broadcast": str(net.broadcast_address) if net.version == 4 and net.num_addresses > 2 else None,
                "prefix_length": net.prefixlen,
            }

            # The one measured field in the entry. None, not False, when there
            # was no address to try: a /31 that was never pinged must not read as
            # a gateway that failed to answer.
            vlan_info["gateway_alive"] = self._ping_host(gateway) if gateway else None
            vlan_map.append(vlan_info)

        # 2. Inter-VLAN routing detection
        if len(subnets) >= 2:
            inter_vlan = self._check_inter_vlan_routing(subnets)
            if inter_vlan:
                findings.append({
                    "type": "inter_vlan",
                    "severity": "INFO",
                    "message": "This host reached the assumed gateway of another subnet. That shows this machine has a route between them — it does not establish that hosts on one subnet can reach the other, which would have to be tested from one of them.",
                    "detail": inter_vlan
                })

        # 3. MAC-based VLAN analysis (if ARP data available)
        if arp_cache and len(arp_cache) > 0:
            mac_analysis = self._analyze_mac_patterns(arp_cache, subnets)
            findings.extend(mac_analysis)

        # 4. Check for common VLAN hopping indicators
        vlan_hopping = self._check_vlan_hopping_vectors(subnets)
        findings.extend(vlan_hopping)

        # 5. DHCP snooping check — test if multiple DHCP servers respond
        dhcp_findings = self._check_rogue_dhcp(subnets)
        findings.extend(dhcp_findings)

        self.emit("vlan_scan_completed", {
            "subnets_analyzed": len(subnets),
            "vlan_map": vlan_map,
            "findings": findings,
        })

        return {"vlan_map": vlan_map, "findings": findings}

    def _guess_vlan_id(self, ip_parts):
        """Heuristic: guess VLAN ID from the third octet (common in enterprise setups)."""
        try:
            third = int(ip_parts[2])
            # Common patterns: 192.168.10.0 → VLAN 10, 10.0.20.0 → VLAN 20
            if third > 0 and third < 255:
                return third
            return 1  # Default VLAN
        except (IndexError, ValueError):
            return None

    def _classify_network(self, parts):
        """Classify the network based on RFC 1918 ranges."""
        first = int(parts[0])
        second = int(parts[1])
        if first == 10:
            return "Class A Private (10.0.0.0/8)"
        elif first == 172 and 16 <= second <= 31:
            return "Class B Private (172.16.0.0/12)"
        elif first == 192 and second == 168:
            return "Class C Private (192.168.0.0/16)"
        elif first == 169 and second == 254:
            return "Link-Local (APIPA)"
        else:
            return "Public / Routable"

    def _ping_host(self, ip, timeout=1):
        """
        Quick ICMP ping to check if a host is alive.

        `returncode == 0` is not that test on Windows. `ping.exe` exits 0 when a
        router answers with ICMP *Destination Unreachable* on the target's
        behalf, so a gateway that does not exist read as alive — and this
        function's only caller turns that into "Inter-VLAN routing detected:
        subnets can communicate", a finding in the report about a device that is
        not there. `lan.py` has always done this correctly by looking for the TTL
        in the output; this is the same test.

        `encoding`/`errors` are set explicitly because the default decodes the
        console's bytes as the ANSI codepage, strictly, and a single byte outside
        it raises inside `subprocess.run` — which the caller would read as "host
        is down".
        """
        try:
            kwargs = {}
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
                kwargs["creationflags"] = 0x08000000
            else:
                cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

            result = subprocess.run(
                cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout + 2, **kwargs
            )
            if result.returncode != 0:
                return False
            out = (result.stdout or "")
            # An echo reply carries a TTL. A Destination Unreachable does not.
            # Matching the field name rather than a phrase keeps this working on
            # a localized Windows, where "Reply from" is translated but "TTL" is
            # not.
            if re.search(r"TTL[=:]\s*\d+", out, re.IGNORECASE):
                return True
            if re.search(r"ttl[=:]\s*\d+", out):
                return True
            # Exit code said success but nothing in the output shows an echo
            # reply. Treat that as not-alive rather than inventing a host.
            return False
        except Exception as e:
            logger.debug("ping to %s failed: %s", ip, e)
            return False

    @staticmethod
    def _assumed_gateway(subnet):
        """First usable address of a CIDR, or None when there is not one.

        The gateway is a convention, not a measurement: nothing here asks a host
        which router it uses. What this fixes is the arithmetic. Three call sites
        each built "<first three octets>.1" from the string, which is the right
        address only for a /24 -- on 10.0.0.0/8 it names 10.0.0.1, an address
        with no particular standing in that network.

        Returns None for a /31 or /32, where there is no first usable host to
        name, so a caller gets nothing to ping rather than a plausible invention.
        """
        try:
            net = ipaddress.ip_network(str(subnet).strip(), strict=False)
        except ValueError:
            return None
        if net.num_addresses <= 2:
            return None
        return str(net.network_address + 1)

    def _check_inter_vlan_routing(self, subnets):
        """Test whether THIS host can reach the assumed gateway of another subnet.

        What it does not establish, despite how the finding used to read: that
        hosts on one subnet can reach another. Every ping leaves this machine, so
        a reply proves this machine has a route -- which it may well have because
        it is multi-homed, or because it sits on the segment that routes. The
        finding wording now matches what the measurement supports.
        """
        results = []
        for subnet in subnets[:4]:  # Limit to avoid too many pings
            for other_subnet in subnets:
                if other_subnet == subnet:
                    continue
                other_gw = self._assumed_gateway(other_subnet)
                if not other_gw:
                    continue

                if self._ping_host(other_gw, timeout=1):
                    results.append({
                        "from_subnet": subnet,
                        "to_gateway": other_gw,
                        "reachable": True
                    })

        return results if results else None

    def _analyze_mac_patterns(self, arp_cache, subnets):
        """Analyze MAC addresses to detect shared gateway MACs across subnets (L3 switch indicator)."""
        findings = []
        gateway_macs = {}

        for subnet in subnets:
            gw_ip = self._assumed_gateway(subnet)
            if gw_ip and gw_ip in arp_cache:
                mac = arp_cache[gw_ip]
                if mac not in gateway_macs:
                    gateway_macs[mac] = []
                gateway_macs[mac].append(subnet)

        for mac, nets in gateway_macs.items():
            if len(nets) > 1:
                findings.append({
                    "type": "shared_gateway",
                    "severity": "INFO",
                    "message": f"Shared gateway MAC ({mac}) across {len(nets)} subnets — likely L3 switch / router-on-a-stick",
                    "detail": {"mac": mac, "subnets": nets}
                })

        return findings

    def _check_vlan_hopping_vectors(self, subnets):
        """Identify potential VLAN hopping risks based on network layout."""
        findings = []

        # If there's only 1 subnet, VLAN hopping is not applicable
        if len(subnets) <= 1:
            return findings

        # Check for subnets in the same /16 (potential flat network / hopping risk)
        by_class_b = {}
        for subnet in subnets:
            prefix = subnet.split('/')[0]
            parts = prefix.split('.')
            class_b = f"{parts[0]}.{parts[1]}"
            if class_b not in by_class_b:
                by_class_b[class_b] = []
            by_class_b[class_b].append(subnet)

        for class_b, nets in by_class_b.items():
            if len(nets) >= 3:
                findings.append({
                    "type": "flat_network",
                    "severity": "LOW",
                    "message": f"{len(nets)} subnets share the {class_b}.x.x range — verify trunk port security and 802.1Q tagging",
                    "detail": {"range": class_b, "subnets": nets}
                })

        return findings

    #: Fixed part of a BOOTP message, before the magic cookie.
    _BOOTP_FIXED_LEN = 236

    def _build_dhcp_discover(self, xid, chaddr):
        """
        A DHCP Discover as it belongs in a UDP datagram.

        The previous payload began with fourteen bytes of *Ethernet* header —
        `ff:ff:ff:ff:ff:ff`, a zero source MAC and the IPv4 EtherType — inside
        what was then sent as a UDP datagram. Every BOOTP field after it was
        therefore offset by fourteen bytes: `op` read as part of a MAC address,
        the magic cookie landed nowhere a server looks, and no DHCP server on
        earth would have replied. The check could not have worked, in any
        environment, ever.
        """
        return (
            b'\x01'                       # op: BOOTREQUEST
            + b'\x01'                     # htype: Ethernet
            + b'\x06'                     # hlen
            + b'\x00'                     # hops
            + struct.pack('!I', xid)      # transaction id
            + struct.pack('!H', 0)        # secs
            + struct.pack('!H', 0x8000)   # flags: broadcast reply requested
            + b'\x00' * 4                 # ciaddr
            + b'\x00' * 4                 # yiaddr
            + b'\x00' * 4                 # siaddr
            + b'\x00' * 4                 # giaddr
            + chaddr + b'\x00' * (16 - len(chaddr))   # chaddr, padded to 16
            + b'\x00' * 64                # sname
            + b'\x00' * 128               # file
            + b'\x63\x82\x53\x63'         # magic cookie
            + b'\x35\x01\x01'             # option 53: DHCPDISCOVER
            + b'\x37\x03\x01\x03\x06'     # option 55: subnet mask, router, DNS
            + b'\xff'                     # end
        )

    def _check_rogue_dhcp(self, subnets):
        """
        Look for more than one DHCP server answering on this link.

        Every outcome here is reported explicitly, including "could not tell",
        because this check has three failure modes that all used to look
        identical to a clean result:

          1. The payload was malformed (see `_build_dhcp_discover`), so nothing
             ever replied.
          2. The socket was never bound to UDP/68. A DHCP OFFER is sent to port
             68, so even a valid Discover could not have been heard.
          3. `except Exception: pass` wrapped the whole function and `servers`
             stayed empty, so `len(servers) > 1` was never true.

        The result was a DHCP snooping check that reported clean on every network
        it was ever pointed at — a false negative that is structurally impossible
        for an operator to notice. A real rogue DHCP server was reported as
        absent.

        Binding port 68 is the part that legitimately fails: on Windows the DHCP
        Client service normally holds it, and binding a privileged port needs
        elevation. That is now an inconclusive result rather than a silent pass.
        """
        findings = []
        xid = random.getrandbits(32)
        # A locally-administered, unicast MAC. An all-zero chaddr is ignored by
        # some servers, which would have been another silent way to see nothing.
        chaddr = bytes([0x02, 0x00]) + os.urandom(4)

        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                # Without this the OFFERs, which are addressed to port 68, go to
                # whoever does hold that port — normally the OS DHCP client.
                s.bind(('', 68))
            except OSError as e:
                findings.append({
                    "type": "rogue_dhcp",
                    "severity": "INFO",
                    "inconclusive": True,
                    "message": "Rogue DHCP check could not run: UDP port 68 is unavailable",
                    "detail": {
                        "error": str(e),
                        "caveat": (
                            "DHCP replies are sent to port 68, which is normally held by the "
                            "operating system's own DHCP client and requires elevation to bind. "
                            "This is not a result: the network was not tested for additional "
                            "DHCP servers, and nothing here indicates that none are present."
                        ),
                    },
                })
                return findings

            s.settimeout(1.0)
            try:
                s.sendto(self._build_dhcp_discover(xid, chaddr), ('255.255.255.255', 67))
            except OSError as e:
                findings.append({
                    "type": "rogue_dhcp",
                    "severity": "INFO",
                    "inconclusive": True,
                    "message": "Rogue DHCP check could not run: the Discover could not be sent",
                    "detail": {
                        "error": str(e),
                        "caveat": "No probe left this host, so no conclusion about DHCP servers is available.",
                    },
                })
                return findings

            servers = {}
            deadline = time.time() + 4.0
            while time.time() < deadline:
                try:
                    data, addr = s.recvfrom(2048)
                except socket.timeout:
                    continue
                except OSError:
                    break
                # Only count a real DHCP reply to *our* Discover. Without these
                # checks any stray broadcast on port 68 would be counted as a
                # DHCP server and manufacture a rogue-DHCP finding.
                if len(data) < self._BOOTP_FIXED_LEN + 4:
                    continue
                if data[0] != 2:                                  # op: BOOTREPLY
                    continue
                if struct.unpack('!I', data[4:8])[0] != xid:       # our transaction
                    continue
                if data[self._BOOTP_FIXED_LEN:self._BOOTP_FIXED_LEN + 4] != b'\x63\x82\x53\x63':
                    continue
                # siaddr, falling back to the sender — a relay rewrites one but
                # not the other.
                siaddr = socket.inet_ntoa(data[20:24])
                key = siaddr if siaddr != '0.0.0.0' else addr[0]
                servers.setdefault(key, {"responder": addr[0], "siaddr": siaddr})

            if len(servers) > 1:
                findings.append({
                    "type": "rogue_dhcp",
                    "severity": "HIGH",
                    "inconclusive": False,
                    "message": f"{len(servers)} DHCP servers answered on this link — one of them may be unauthorised",
                    "detail": {
                        "servers": sorted(servers.keys()),
                        "responders": sorted({v["responder"] for v in servers.values()}),
                        "caveat": (
                            "More than one server offering leases is worth explaining, but it is "
                            "not proof of an attack: DHCP relays, redundant server pairs and "
                            "virtualisation hosts all produce this. Identify each address before "
                            "recording a conclusion."
                        ),
                    },
                })
            elif len(servers) == 0:
                # On a network with working DHCP, silence means the probe did not
                # work rather than that there is no server.
                findings.append({
                    "type": "rogue_dhcp",
                    "severity": "INFO",
                    "inconclusive": True,
                    "message": "No DHCP server answered, so the number of DHCP servers is unknown",
                    "detail": {
                        "caveat": (
                            "A Discover was broadcast and nothing replied within the window. On a "
                            "network that hands out leases this points at the probe rather than at "
                            "the network — a wireless client isolation rule, a firewall, or replies "
                            "arriving after the timeout. Treat the DHCP server count as "
                            "unestablished, not as zero."
                        ),
                    },
                })

        except Exception as e:
            # Never a silent pass. An error here is a check that did not run.
            logger.debug("rogue DHCP check failed: %s", e)
            findings.append({
                "type": "rogue_dhcp",
                "severity": "INFO",
                "inconclusive": True,
                "message": "Rogue DHCP check failed",
                "detail": {
                    "error": str(e),
                    "caveat": "This check did not complete. It is not a statement about the network.",
                },
            })
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass

        return findings

    def start_detection(self, subnets, arp_cache=None):
        """Run VLAN detection in a background thread."""
        t = threading.Thread(
            target=self.detect_vlans,
            args=(subnets, arp_cache),
            daemon=True
        )
        t.start()
