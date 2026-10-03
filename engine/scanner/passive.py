"""LOCKON EWAC — Passive Traffic Analyzer
Listens to broadcast/multicast network traffic to gather intelligence
without performing any active scanning.
Captures: ARP requests, DHCP hostname leaks, mDNS announcements.
Requires: Npcap (managed mode is sufficient for broadcast traffic)
"""
import threading
import time
from datetime import datetime


#: Shortest gap between two `passive_host` events for the same host, in seconds.
#:
#: Every observed packet used to emit one event. On a busy link that is thousands
#: of writes a second onto a single pipe, and now that `IPCHandler.emit` holds a
#: lock the cost is paid by every other thread that wants to report something —
#: the flood would throttle the scanners it shares the pipe with.
#:
#: A repeat sighting of a host already on screen carries almost nothing: the
#: record is kept in `discovered` either way and the summary is authoritative.
#: What must never be dropped is the *first* sighting of a host, so `is_new`
#: always emits regardless of this interval.
_HOST_EVENT_MIN_INTERVAL_S = 2.0


class PassiveAnalyzer:
    def __init__(self, ipc_handler):
        self.ipc = ipc_handler
        self.analyzing = False
        self.analysis_thread = None
        self.discovered = {}    # IP → {"mac": str, "hostname": str, "source": str, "first_seen": str}
        self._lock = threading.Lock()
        # IP → monotonic time of the last emitted passive_host event.
        self._last_emit = {}
        # Counts what the rate limit held back, so the summary can say so rather
        # than leaving the operator to infer it from a quiet feed.
        self._suppressed_events = 0

    def start(self, interface=None, duration=None):
        """Start passive traffic analysis.
        
        Args:
            interface: Network interface to sniff on (None = default)
            duration: How long to sniff in seconds (None = until stopped)
        """
        if self.analyzing:
            return

        self.analyzing = True
        self.discovered = {}
        # Reset alongside `discovered`, or a previous run's rate-limit timers
        # would suppress the opening sightings of this one.
        self._last_emit = {}
        self._suppressed_events = 0
        self.ipc.emit("passive_started", {"interface": interface, "duration": duration})

        def _analyze_loop():
            try:
                self._run_analysis(interface, duration)
            finally:
                # Single terminal event on every path (success, error, abort)
                self.analyzing = False
                self.ipc.emit("passive_stopped", {
                    "total_hosts": len(self.discovered)
                })

        self.analysis_thread = threading.Thread(target=_analyze_loop, daemon=True)
        self.analysis_thread.start()

    def _run_analysis(self, interface=None, duration=None):
        """Sniff broadcast traffic in short slices until stopped or expired.

        Bounded slices mean ``stop()`` is honoured within ~1s even on a silent
        link, where ``stop_filter`` alone would never be evaluated.
        """
        try:
            from scapy.all import sniff, ARP, DHCP, DNS, IP, Ether, DNSRR
        except ImportError:
            self.ipc.emit("passive_error", {
                "message": "Scapy not available. Install with: pip install scapy"
            })
            return

        def _handle_packet(pkt):
            if not self.analyzing:
                return

            now = datetime.now().isoformat()

            # ── ARP: who-has requests reveal active devices ──
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                if arp.op == 1:  # who-has (request)
                    self._register_host(
                        ip=arp.psrc,
                        mac=arp.hwsrc,
                        hostname=None,
                        source="ARP",
                        detail=f"Looking for {arp.pdst}",
                        timestamp=now,
                    )
                elif arp.op == 2:  # is-at (reply)
                    self._register_host(
                        ip=arp.psrc,
                        mac=arp.hwsrc,
                        hostname=None,
                        source="ARP-Reply",
                        detail=f"Resolved {arp.psrc}",
                        timestamp=now,
                    )

            # ── DHCP: hostname field reveals device name ──
            if pkt.haslayer(DHCP):
                try:
                    options = {}
                    for opt in pkt[DHCP].options:
                        if isinstance(opt, tuple) and len(opt) >= 2:
                            options[opt[0]] = opt[1]

                    hostname = None
                    if 'hostname' in options:
                        raw = options['hostname']
                        if isinstance(raw, bytes):
                            hostname = raw.decode('utf-8', errors='ignore')
                        elif isinstance(raw, str):
                            hostname = raw

                    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
                    src_ip = pkt[IP].src if pkt.haslayer(IP) else None

                    if hostname and hostname.strip():
                        self._register_host(
                            ip=src_ip,
                            mac=src_mac,
                            hostname=hostname.strip(),
                            source="DHCP",
                            detail=f"Hostname: {hostname.strip()}",
                            timestamp=now,
                        )
                except Exception:
                    pass

            # ── mDNS: .local name announcements ──
            if pkt.haslayer(DNS) and pkt.haslayer(IP):
                dns = pkt[DNS]
                src_ip = pkt[IP].src

                # Check for mDNS responses (answers)
                if dns.qr == 1 and dns.ancount > 0:
                    try:
                        for i in range(dns.ancount):
                            rr = dns.an[i]
                            if hasattr(rr, 'rrname'):
                                name = rr.rrname
                                if isinstance(name, bytes):
                                    name = name.decode('utf-8', errors='ignore')
                                if '.local' in name.lower():
                                    clean_name = name.rstrip('.').replace('.local', '')
                                    src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
                                    self._register_host(
                                        ip=src_ip,
                                        mac=src_mac,
                                        hostname=clean_name,
                                        source="mDNS",
                                        detail=f"Announced: {name.rstrip('.')}",
                                        timestamp=now,
                                    )
                    except Exception:
                        pass

        # Sniff in short slices so stop() is honoured promptly on a quiet link
        deadline = (time.time() + duration) if duration else None
        while self.analyzing:
            if deadline is not None:
                remaining = deadline - time.time()
                if remaining <= 0:
                    return
                slice_timeout = min(1, remaining)
            else:
                slice_timeout = 1
            try:
                sniff(
                    iface=interface,
                    prn=_handle_packet,
                    stop_filter=lambda p: not self.analyzing,
                    store=False,
                    timeout=slice_timeout,
                    filter="arp or port 67 or port 68 or port 5353",
                )
            except PermissionError:
                self.ipc.emit("passive_error", {
                    "message": "Permission denied. Npcap required for passive sniffing."
                })
                return
            except Exception as e:
                self.ipc.emit("passive_error", {
                    "message": f"Passive analysis failed: {str(e)[:200]}"
                })
                return

    def _register_host(self, ip, mac, hostname, source, detail, timestamp):
        """Register or update a passively discovered host."""
        if not ip or ip.startswith("0.0.0") or ip == "255.255.255.255":
            return

        is_new = False
        with self._lock:
            if ip not in self.discovered:
                self.discovered[ip] = {
                    "mac": mac,
                    "hostname": hostname,
                    "source": source,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "events": [],
                }
                is_new = True
            else:
                entry = self.discovered[ip]
                entry["last_seen"] = timestamp
                if mac and not entry["mac"]:
                    entry["mac"] = mac
                if hostname and not entry["hostname"]:
                    entry["hostname"] = hostname

            self.discovered[ip]["events"].append({
                "source": source,
                "detail": detail,
                "time": timestamp,
            })
            # Keep only last 20 events per host
            if len(self.discovered[ip]["events"]) > 20:
                self.discovered[ip]["events"] = self.discovered[ip]["events"][-20:]

        # Emit event for real-time UI.
        #
        # A first sighting always goes out. A repeat is rate limited per host:
        # the record is already kept in `discovered` and returned by
        # get_summary(), so what is dropped here is a duplicate line in a feed,
        # never an observation.
        if is_new:
            should_emit = True
        else:
            now = time.monotonic()
            with self._lock:
                last = self._last_emit.get(ip)
                should_emit = last is None or (now - last) >= _HOST_EVENT_MIN_INTERVAL_S
                if should_emit:
                    self._last_emit[ip] = now
                else:
                    self._suppressed_events += 1

        if not should_emit:
            return

        if is_new:
            with self._lock:
                self._last_emit[ip] = time.monotonic()

        self.ipc.emit("passive_host", {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "source": source,
            "detail": detail,
            "is_new": is_new,
            "timestamp": timestamp,
        })

    def stop(self):
        """Stop passive analysis."""
        self.analyzing = False

    def get_summary(self):
        """
        Return a summary of all passively discovered hosts.

        This, not the live feed, is the authoritative record: the feed is rate
        limited per host, so `event_count` here can exceed the number of lines
        that reached the UI.
        """
        with self._lock:
            summary = []
            for ip, info in self.discovered.items():
                summary.append({
                    "ip": ip,
                    "mac": info["mac"],
                    "hostname": info["hostname"],
                    "source": info["source"],
                    "first_seen": info["first_seen"],
                    "last_seen": info["last_seen"],
                    "event_count": len(info["events"]),
                })
            return summary

    def get_feed_stats(self):
        """
        How much of the live feed the rate limit held back.

        Reported so a quiet feed is never read as a quiet network. Every
        suppressed event was a repeat sighting of a host already in the summary;
        no host is ever hidden by this.
        """
        with self._lock:
            return {
                "suppressed_repeat_events": self._suppressed_events,
                "min_interval_seconds": _HOST_EVENT_MIN_INTERVAL_S,
            }
